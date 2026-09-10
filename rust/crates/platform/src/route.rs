//! Owned route bookkeeping for TUN auto-route.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Command, Output};

use ipnet::IpNet;

use crate::PlatformError;

/// OS flavor used by TUN auto-route defaults and device-name rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutePlatform {
    Linux,
    Darwin,
    Windows,
    Other,
}

/// Returns the compile-target route platform.
#[must_use]
pub fn current_route_platform() -> RoutePlatform {
    if cfg!(target_os = "linux") {
        RoutePlatform::Linux
    } else if cfg!(target_os = "macos") {
        RoutePlatform::Darwin
    } else if cfg!(target_os = "windows") {
        RoutePlatform::Windows
    } else {
        RoutePlatform::Other
    }
}

/// A route installed by this process that must be removed on stop/failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedRoute {
    pub destination: IpNet,
    pub device: String,
    pub gateway: Option<IpAddr>,
    pub table: Option<u32>,
}

#[derive(Default)]
pub struct RouteOwner {
    routes: Vec<OwnedRoute>,
}

impl RouteOwner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn routes(&self) -> &[OwnedRoute] {
        &self.routes
    }

    /// Records a route as owned after a successful install.
    pub fn record(&mut self, route: OwnedRoute) {
        self.routes.push(route);
    }

    /// Removes host /32 and /128 loop-avoidance routes so they can be rebuilt
    /// after a physical default-interface change.
    ///
    /// # Errors
    ///
    /// Returns the first failure after attempting all host-route removals.
    pub fn revert_host_routes(&mut self) -> Result<(), PlatformError> {
        let routes = std::mem::take(&mut self.routes);
        let mut first_error = None;
        for route in routes {
            if is_host_prefix(route.destination) {
                if let Err(error) = remove_owned_route(&route) {
                    first_error.get_or_insert(error);
                }
            } else {
                self.routes.push(route);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Removes owned routes whose device is not `device`, keeping TUN
    /// split-defaults in place across a physical-default change.
    ///
    /// # Errors
    ///
    /// Returns the first failure after attempting all non-matching removals.
    pub fn revert_not_on_device(&mut self, device: &str) -> Result<(), PlatformError> {
        let routes = std::mem::take(&mut self.routes);
        let mut first_error = None;
        for route in routes {
            if !device.is_empty() && route.device.eq_ignore_ascii_case(device) {
                self.routes.push(route);
            } else if let Err(error) = remove_owned_route(&route) {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Removes every owned route. Continues after individual failures.
    ///
    /// # Errors
    ///
    /// Returns the first failure after attempting all removals.
    pub fn revert_all(&mut self) -> Result<(), PlatformError> {
        let mut first_error = None;
        while let Some(route) = self.routes.pop() {
            if let Err(error) = remove_owned_route(&route) {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for RouteOwner {
    fn drop(&mut self) {
        let _ = self.revert_all();
    }
}

/// Default split-default destinations when `route-address` is empty.
///
/// Darwin uses Go/sing-tun sub-ranges so `0.0.0.0/8` stays on the physical
/// interface. Linux keeps the 8A `0.0.0.0/1` + `128.0.0.0/1` pair.
///
/// # Panics
///
/// Panics only if a static prefix in this function is not valid CIDR. Those
/// strings are compile-time constants.
#[must_use]
pub fn default_auto_route_destinations(platform: RoutePlatform) -> Vec<IpNet> {
    let prefixes = match platform {
        RoutePlatform::Darwin => [
            "1.0.0.0/8",
            "2.0.0.0/7",
            "4.0.0.0/6",
            "8.0.0.0/5",
            "16.0.0.0/4",
            "32.0.0.0/3",
            "64.0.0.0/2",
            "128.0.0.0/1",
        ]
        .as_slice(),
        RoutePlatform::Linux | RoutePlatform::Windows | RoutePlatform::Other => {
            ["0.0.0.0/1", "128.0.0.0/1"].as_slice()
        }
    };
    prefixes
        .iter()
        .map(|value| value.parse::<IpNet>().expect("static auto-route prefix"))
        .collect()
}

/// Rejects Darwin names that are not `utunN`. Empty names (kernel assign) pass.
///
/// Rust does not remap `tun0` / `utun` to a valid utun index.
///
/// # Errors
///
/// Returns [`PlatformError::Unsupported`] for a Darwin name that is not `utun`
/// plus a decimal index.
pub fn validate_tun_device_name(name: &str, platform: RoutePlatform) -> Result<(), PlatformError> {
    if name.is_empty() || platform != RoutePlatform::Darwin {
        return Ok(());
    }
    let Some(index) = name.strip_prefix("utun") else {
        return Err(PlatformError::Unsupported(format!(
            "tun.device `{name}` is not a utunN name on macOS; Rust does not remap it"
        )));
    };
    if index.is_empty() || index.parse::<u32>().is_err() {
        return Err(PlatformError::Unsupported(format!(
            "tun.device `{name}` is not a utunN name on macOS; Rust does not remap it"
        )));
    }
    Ok(())
}

/// Planned auto-route prefixes after applying `route-exclude-address`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoRoutePlan {
    /// Prefixes installed on the TUN device.
    pub tun: Vec<IpNet>,
    /// More-specific prefixes installed on the physical default (exceptions).
    pub physical_exceptions: Vec<IpNet>,
}

/// Splits include prefixes against excludes.
///
/// An exclude that fully covers an include drops that TUN prefix. An exclude
/// contained in a remaining TUN prefix becomes a physical exception route, so
/// `route-exclude-address: 8.8.8.0/24` works against the default `/1` pair.
#[must_use]
pub fn plan_auto_route_prefixes(includes: &[IpNet], excludes: &[IpNet]) -> AutoRoutePlan {
    let mut tun = Vec::new();
    for include in includes {
        if excludes
            .iter()
            .any(|exclude| prefix_contains(*exclude, *include))
        {
            continue;
        }
        tun.push(*include);
    }
    let mut physical_exceptions = Vec::new();
    for exclude in excludes {
        if tun
            .iter()
            .any(|include| prefix_contains(*include, *exclude) && include != exclude)
        {
            physical_exceptions.push(*exclude);
        }
    }
    AutoRoutePlan {
        tun,
        physical_exceptions,
    }
}

fn prefix_contains(outer: IpNet, inner: IpNet) -> bool {
    outer.addr().is_ipv4() == inner.addr().is_ipv4()
        && outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.addr())
}

/// Host `/32` or `/128` for `host`.
///
/// # Errors
///
/// Returns when `IpNet::new` rejects the prefix length.
pub fn host_route_prefix(host: IpAddr) -> Result<IpNet, PlatformError> {
    let prefix = if host.is_ipv4() { 32 } else { 128 };
    IpNet::new(host, prefix)
        .map_err(|error| PlatformError::Command(format!("host route prefix: {error}")))
}

/// Installs a destination route via the given device.
///
/// Linux uses `ip route add` (not `replace`). Existing exact prefixes on a
/// different device are refused so other VPNs are not overwritten. A leftover
/// on this TUN device is treated as already owned (crash recovery).
///
/// # Errors
///
/// Returns command failures, unsupported-platform errors, or a foreign-route
/// conflict.
pub fn install_device_route(route: &OwnedRoute) -> Result<(), PlatformError> {
    match lookup_exact_route(route.destination)? {
        Some(existing) if same_route_device(&existing, &route.device) => Ok(()),
        Some(existing) => Err(foreign_route_conflict(&existing)),
        None => add_device_route_allowing_ours(route),
    }
}

fn same_route_device(route: &OwnedRoute, device: &str) -> bool {
    !device.is_empty() && route.device.eq_ignore_ascii_case(device)
}

fn foreign_route_conflict(existing: &OwnedRoute) -> PlatformError {
    PlatformError::Command(format!(
        "refusing to replace existing route {} via {}; TUN does not overwrite foreign routes",
        existing.destination, existing.device
    ))
}

fn add_device_route(route: &OwnedRoute) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        run_ip_route("add", route)
    }
    #[cfg(target_os = "macos")]
    {
        match run_darwin_route("add", route) {
            Ok(()) => Ok(()),
            Err(error) if looks_like_route_exists(&error.to_string()) => {
                match lookup_exact_route(route.destination)? {
                    Some(existing) if same_route_device(&existing, &route.device) => Ok(()),
                    Some(existing) => Err(foreign_route_conflict(&existing)),
                    None => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(target_os = "windows")]
    {
        match run_windows_route("add", route) {
            Ok(()) => Ok(()),
            Err(error) if looks_like_route_exists(&error.to_string()) => {
                match lookup_exact_route(route.destination)? {
                    Some(existing) if same_route_device(&existing, &route.device) => Ok(()),
                    Some(existing) => Err(foreign_route_conflict(&existing)),
                    None => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = route;
        Err(PlatformError::Unsupported(
            "TUN auto-route install is only implemented for Linux (8A), macOS (8B), and Windows (8C)"
                .to_owned(),
        ))
    }
}

fn remove_owned_route(route: &OwnedRoute) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        match run_ip_route("del", route) {
            Ok(()) => Ok(()),
            Err(PlatformError::Command(message))
                if message.contains("No such process")
                    || message.contains("Cannot find device")
                    || message.contains("No such file") =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match run_darwin_route("delete", route) {
            Ok(()) => Ok(()),
            Err(PlatformError::Command(message))
                if message.contains("not in table")
                    || message.contains("No such process")
                    || message.contains("not found") =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(target_os = "windows")]
    {
        match run_windows_route("delete", route) {
            Ok(()) => Ok(()),
            Err(PlatformError::Command(message))
                if message.to_ascii_lowercase().contains("element not found")
                    || message.to_ascii_lowercase().contains("not found")
                    || message.to_ascii_lowercase().contains("no matching") =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = route;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn run_ip_route(action: &str, route: &OwnedRoute) -> Result<(), PlatformError> {
    let mut command = Command::new("ip");
    command.arg("route").arg(action);
    command.arg(route.destination.to_string());
    if let Some(gateway) = route.gateway {
        command.arg("via").arg(gateway.to_string());
    }
    command.arg("dev").arg(&route.device);
    if let Some(table) = route.table {
        command.arg("table").arg(table.to_string());
    }
    let output = command.output().map_err(PlatformError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    Err(command_error(&format!("ip route {action}"), &output))
}

#[cfg(target_os = "macos")]
fn run_darwin_route(action: &str, route: &OwnedRoute) -> Result<(), PlatformError> {
    let args = darwin_route_args(action, route);
    let mut command = Command::new("route");
    command.args(&args);
    let output = command.output().map_err(PlatformError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    Err(command_error(&format!("route {action}"), &output))
}

/// Builds Darwin `route -n {add|delete}` arguments (without the binary name).
#[must_use]
pub fn darwin_route_args(action: &str, route: &OwnedRoute) -> Vec<String> {
    let mut args = vec!["-n".to_owned(), action.to_owned()];
    args.push(if route.destination.addr().is_ipv6() {
        "-inet6".to_owned()
    } else {
        "-inet".to_owned()
    });
    if is_host_prefix(route.destination) {
        args.push("-host".to_owned());
        args.push(route.destination.addr().to_string());
    } else {
        args.push("-net".to_owned());
        args.push(route.destination.to_string());
    }
    if let Some(gateway) = route.gateway {
        args.push(gateway.to_string());
    } else {
        args.push("-interface".to_owned());
        args.push(route.device.clone());
    }
    args
}

fn is_host_prefix(destination: IpNet) -> bool {
    match destination {
        IpNet::V4(_) => destination.prefix_len() == 32,
        IpNet::V6(_) => destination.prefix_len() == 128,
    }
}

fn looks_like_route_exists(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("file exists")
        || lower.contains("already exists")
        || lower.contains("object already exists")
        || lower.contains("the object exists")
}

fn lookup_exact_route(destination: IpNet) -> Result<Option<OwnedRoute>, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "show", "exact", &destination.to_string()])
            .output()
            .map_err(PlatformError::Io)?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(parse_linux_exact_route(
            &String::from_utf8_lossy(&output.stdout),
            destination,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let family = if destination.addr().is_ipv6() {
            "-inet6"
        } else {
            "-inet"
        };
        let output = Command::new("route")
            .args(["-n", "get", family, &destination.addr().to_string()])
            .output()
            .map_err(PlatformError::Io)?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(parse_darwin_exact_route(
            &String::from_utf8_lossy(&output.stdout),
            destination,
        ))
    }
    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "@(Get-NetRoute -DestinationPrefix '{destination}' -ErrorAction SilentlyContinue | \
              Select-Object DestinationPrefix, NextHop, InterfaceAlias) | ConvertTo-Json -Compress"
        );
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .map_err(PlatformError::Io)?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(parse_windows_exact_route(
            &String::from_utf8_lossy(&output.stdout),
            destination,
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = destination;
        Ok(None)
    }
}

/// Parses `ip route show exact` stdout.
#[must_use]
pub fn parse_linux_exact_route(stdout: &str, destination: IpNet) -> Option<OwnedRoute> {
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let Some(dest) = words.next() else {
            continue;
        };
        let Some(parsed) = parse_linux_route_destination(dest) else {
            continue;
        };
        if parsed != destination {
            continue;
        }
        let mut via = None;
        let mut device = None;
        while let Some(word) = words.next() {
            match word {
                "via" => via = words.next(),
                "dev" => device = words.next(),
                _ => {}
            }
        }
        let device = device?;
        return Some(OwnedRoute {
            destination,
            device: device.to_owned(),
            gateway: via.and_then(|value| value.parse().ok()),
            table: None,
        });
    }
    None
}

fn parse_linux_route_destination(token: &str) -> Option<IpNet> {
    if token == "default" {
        return "0.0.0.0/0".parse().ok();
    }
    if let Ok(prefix) = token.parse::<IpNet>() {
        return Some(prefix);
    }
    token
        .parse::<IpAddr>()
        .ok()
        .and_then(|addr| host_route_prefix(addr).ok())
}

/// Parses `Get-NetRoute -DestinationPrefix` JSON.
#[must_use]
pub fn parse_windows_exact_route(json: &str, destination: IpNet) -> Option<OwnedRoute> {
    for chunk in json.split('{').skip(1) {
        let body = format!("{{{chunk}");
        let prefix = json_object_string(&body, "DestinationPrefix");
        if prefix
            .as_deref()
            .is_none_or(|value| value.parse::<IpNet>().ok() != Some(destination))
        {
            continue;
        }
        let device = json_object_string(&body, "InterfaceAlias").filter(|name| !name.is_empty())?;
        let next_hop = json_object_string(&body, "NextHop");
        let gateway = match next_hop.as_deref() {
            None | Some("" | "0.0.0.0" | "::") => None,
            Some(value) => value.parse().ok(),
        };
        return Some(OwnedRoute {
            destination,
            device,
            gateway,
            table: None,
        });
    }
    None
}

fn add_device_route_allowing_ours(route: &OwnedRoute) -> Result<(), PlatformError> {
    match add_device_route(route) {
        Ok(()) => Ok(()),
        Err(error) if looks_like_route_exists(&error.to_string()) => {
            match lookup_exact_route(route.destination)? {
                Some(existing) if same_route_device(&existing, &route.device) => Ok(()),
                Some(existing) => Err(foreign_route_conflict(&existing)),
                None => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

/// Installs a host/exception route via the physical default.
///
/// Existing routes on `tun_device` are removed and replaced. Existing routes
/// on any other device are left untouched (already a TUN bypass).
///
/// # Errors
///
/// Returns when `device` is empty, equals `tun_device`, or install fails.
pub fn install_bypass_host_route(
    route: &OwnedRoute,
    tun_device: &str,
    owner: &mut RouteOwner,
) -> Result<(), PlatformError> {
    if route.device.is_empty() {
        return Err(PlatformError::Command(
            "no physical default interface; refusing TUN loop-avoidance route".to_owned(),
        ));
    }
    if same_route_device(route, tun_device) {
        return Err(PlatformError::Command(format!(
            "refusing to install loop-avoidance route {} via TUN device {tun_device}",
            route.destination
        )));
    }
    if let Some(existing) = lookup_exact_route(route.destination)? {
        if same_route_device(&existing, tun_device) {
            let _ = remove_owned_route(&existing);
        } else {
            return Ok(());
        }
    }
    add_device_route_allowing_ours(route)?;
    owner.record(route.clone());
    Ok(())
}

/// Builds a loop-avoidance host route via the physical default snapshot.
///
/// # Errors
///
/// Returns when the physical default is missing or is the TUN device.
pub fn bypass_host_route(
    host: IpAddr,
    device: &str,
    gateway: Option<IpAddr>,
    tun_device: &str,
) -> Result<OwnedRoute, PlatformError> {
    if device.is_empty() {
        return Err(PlatformError::Command(
            "no physical default interface; refusing TUN loop-avoidance route".to_owned(),
        ));
    }
    if !tun_device.is_empty() && device.eq_ignore_ascii_case(tun_device) {
        return Err(PlatformError::Command(format!(
            "refusing to install loop-avoidance route for {host} via TUN device {tun_device}"
        )));
    }
    Ok(OwnedRoute {
        destination: host_route_prefix(host)?,
        device: device.to_owned(),
        gateway,
        table: None,
    })
}

/// Installs a host route via the physical default so TUN auto-route cannot
/// capture DIRECT, DNS upstream, or proxy-server packets.
///
/// # Errors
///
/// Returns command failures or a request to install the host route via TUN.
pub fn protect_host_route(
    host: IpAddr,
    device: &str,
    gateway: Option<IpAddr>,
    tun_device: &str,
    owner: &mut RouteOwner,
) -> Result<(), PlatformError> {
    let route = bypass_host_route(host, device, gateway, tun_device)?;
    install_bypass_host_route(&route, tun_device, owner)
}

/// Parses `ip route get` stdout.
///
/// # Errors
///
/// Returns when the output has no `dev` token.
pub fn parse_linux_route_get(stdout: &str) -> Result<(Option<IpAddr>, String), PlatformError> {
    let mut via = None;
    let mut device = None;
    let mut words = stdout.split_whitespace();
    while let Some(word) = words.next() {
        match word {
            "via" => via = words.next(),
            "dev" => device = words.next(),
            _ => {}
        }
    }
    let device = device.ok_or_else(|| {
        PlatformError::Command("route get has no device; refusing TUN auto-route".to_owned())
    })?;
    let gateway = via
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|error| PlatformError::Command(format!("route gateway: {error}")))
        })
        .transpose()?;
    Ok((gateway, device.to_owned()))
}

/// Parses Darwin `route -n get` stdout.
///
/// # Errors
///
/// Returns when the output has no `interface:` line.
pub fn parse_darwin_route_get(stdout: &str) -> Result<(Option<IpAddr>, String), PlatformError> {
    let mut gateway = None;
    let mut device = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("gateway:") {
            let value = value.trim();
            if value != "default" && !value.is_empty() {
                gateway =
                    Some(value.parse::<IpAddr>().map_err(|error| {
                        PlatformError::Command(format!("route gateway: {error}"))
                    })?);
            }
        }
        if let Some(value) = trimmed.strip_prefix("interface:") {
            device = Some(value.trim().to_owned());
        }
    }
    let device = device.ok_or_else(|| {
        PlatformError::Command("route get has no interface; refusing TUN auto-route".to_owned())
    })?;
    Ok((gateway, device))
}

/// Parses Darwin `route -n get` and keeps the row only when destination+mask
/// match `wanted` exactly. Covering defaults or TUN `/1` routes are ignored.
#[must_use]
pub fn parse_darwin_exact_route(stdout: &str, wanted: IpNet) -> Option<OwnedRoute> {
    let mut destination = None;
    let mut mask = None;
    let mut gateway = None;
    let mut device = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("destination:") {
            destination = Some(value.trim().to_owned());
        }
        if let Some(value) = trimmed.strip_prefix("mask:") {
            mask = Some(value.trim().to_owned());
        }
        if let Some(value) = trimmed.strip_prefix("gateway:") {
            let value = value.trim();
            if value != "default" && !value.is_empty() {
                gateway = value.parse().ok();
            }
        }
        if let Some(value) = trimmed.strip_prefix("interface:") {
            device = Some(value.trim().to_owned());
        }
    }
    let device = device?;
    let parsed = parse_darwin_destination_prefix(destination.as_deref(), mask.as_deref())?;
    if parsed != wanted {
        return None;
    }
    Some(OwnedRoute {
        destination: wanted,
        device,
        gateway,
        table: None,
    })
}

fn parse_darwin_destination_prefix(destination: Option<&str>, mask: Option<&str>) -> Option<IpNet> {
    let destination = destination.unwrap_or("default");
    if destination == "default" {
        return "0.0.0.0/0".parse().ok();
    }
    let addr: IpAddr = destination.parse().ok()?;
    let prefix_len = match (addr, mask) {
        (_, None | Some("" | "default")) if addr.is_ipv4() => 32,
        (_, None | Some("" | "default")) => 128,
        (IpAddr::V4(_), Some(mask)) => ipv4_netmask_prefix_len(mask.parse::<Ipv4Addr>().ok()?)?,
        (IpAddr::V6(_), Some(mask)) => ipv6_netmask_prefix_len(mask.parse::<Ipv6Addr>().ok()?)?,
    };
    IpNet::new(addr, prefix_len).ok()
}

fn ipv4_netmask_prefix_len(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let leading = bits.leading_ones();
    if leading == 0 {
        return (bits == 0).then_some(0);
    }
    (bits == u32::MAX << (32 - leading)).then_some(u8::try_from(leading).ok()?)
}

fn ipv6_netmask_prefix_len(mask: Ipv6Addr) -> Option<u8> {
    let bits = u128::from(mask);
    let leading = bits.leading_ones();
    if leading == 0 {
        return (bits == 0).then_some(0);
    }
    (bits == u128::MAX << (128 - leading)).then_some(u8::try_from(leading).ok()?)
}

#[cfg(target_os = "windows")]
fn run_windows_route(action: &str, route: &OwnedRoute) -> Result<(), PlatformError> {
    let args = windows_netsh_route_args(action, route);
    let output = Command::new("netsh")
        .args(&args)
        .output()
        .map_err(PlatformError::Io)?;
    if output.status.success() {
        return Ok(());
    }
    let error = command_error(&format!("netsh route {action}"), &output);
    Err(error)
}

/// Builds `netsh interface ipv4 {add|delete} route` arguments.
#[must_use]
pub fn windows_netsh_route_args(action: &str, route: &OwnedRoute) -> Vec<String> {
    let mut args = vec![
        "interface".to_owned(),
        "ipv4".to_owned(),
        action.to_owned(),
        "route".to_owned(),
        format!("prefix={}", route.destination),
        format!("interface={}", route.device),
    ];
    if action == "add" {
        if let Some(gateway) = route.gateway {
            args.push(format!("nexthop={gateway}"));
        }
        args.push("store=active".to_owned());
    }
    args
}

/// Parses PowerShell `Find-NetRoute` JSON (`NextHop`, `InterfaceAlias`).
///
/// # Errors
///
/// Returns when the JSON has no interface alias.
pub fn parse_windows_find_netroute(json: &str) -> Result<(Option<IpAddr>, String), PlatformError> {
    let trimmed = json.trim();
    let body = match (trimmed.find('{'), trimmed.rfind('}')) {
        (Some(start), Some(end)) if end >= start => &trimmed[start..=end],
        _ => trimmed,
    };
    let next_hop = json_object_string(body, "NextHop");
    let device = json_object_string(body, "InterfaceAlias").ok_or_else(|| {
        PlatformError::Command(
            "Find-NetRoute has no InterfaceAlias; refusing TUN auto-route".to_owned(),
        )
    })?;
    let gateway = match next_hop.as_deref() {
        None | Some("" | "0.0.0.0" | "::") => None,
        Some(value) => Some(
            value
                .parse::<IpAddr>()
                .map_err(|error| PlatformError::Command(format!("route gateway: {error}")))?,
        ),
    };
    Ok((gateway, device))
}

fn json_object_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let rest = body.split(&needle).nth(1)?;
    let rest = rest.trim().trim_start_matches(':').trim();
    if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next().map(ToOwned::to_owned)
    } else {
        rest.split([',', '}'])
            .next()
            .map(|value| value.trim().trim_matches('"').to_owned())
            .filter(|value| !value.is_empty())
    }
}

/// Parses `netsh interface show interface` names (last column).
#[must_use]
pub fn parse_netsh_interface_names(stdout: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in stdout.lines() {
        for kind in ["Dedicated", "Internal", "Loopback", "Unbound"] {
            if let Some((_, rest)) = line.split_once(kind) {
                let name = rest.trim();
                if !name.is_empty() && name != "Interface Name" {
                    names.push(name.to_owned());
                }
                break;
            }
        }
    }
    names
}

/// Refuses to open a named Windows adapter that already exists (other VPN).
///
/// # Errors
///
/// Returns when the named adapter is already present, or when `netsh` cannot
/// list interfaces on Windows.
pub fn reject_existing_windows_tun_device(name: &str) -> Result<(), PlatformError> {
    if name.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netsh")
            .args(["interface", "show", "interface"])
            .output()
            .map_err(PlatformError::Io)?;
        if !output.status.success() {
            return Err(command_error("netsh interface show interface", &output));
        }
        let names = parse_netsh_interface_names(&String::from_utf8_lossy(&output.stdout));
        if names
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(name))
        {
            return Err(PlatformError::Unsupported(format!(
                "tun.device `{name}` already exists; refusing to take over another adapter"
            )));
        }
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = name;
        Ok(())
    }
}

fn command_error(operation: &str, output: &Output) -> PlatformError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let trimmed = stderr.trim();
    if trimmed.contains("Operation not permitted")
        || trimmed.contains("Permission denied")
        || trimmed.contains("must be root")
        || trimmed.contains("Access is denied")
        || trimmed.contains("requires elevation")
        || trimmed.contains("The requested operation requires elevation")
    {
        return PlatformError::Command(format!(
            "{operation} requires Administrator/root; refusing to skip: {trimmed}"
        ));
    }
    PlatformError::Command(format!("{operation} failed: {trimmed}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_records_and_clears_without_routes() {
        let mut owner = RouteOwner::new();
        assert!(owner.routes().is_empty());
        owner.revert_all().expect("empty revert");
        owner.revert_host_routes().expect("empty host revert");
        owner
            .revert_not_on_device("tun0")
            .expect("empty device revert");
    }

    #[test]
    fn darwin_names_must_be_utun_plus_index() {
        validate_tun_device_name("", RoutePlatform::Darwin).expect("empty auto name");
        validate_tun_device_name("utun8", RoutePlatform::Darwin).expect("utun8");
        validate_tun_device_name("tun0", RoutePlatform::Linux).expect("linux tun0");
        let error = validate_tun_device_name("tun0", RoutePlatform::Darwin).expect_err("tun0");
        assert!(error.to_string().contains("does not remap"));
        let bare = validate_tun_device_name("utun", RoutePlatform::Darwin).expect_err("bare utun");
        assert!(bare.to_string().contains("does not remap"));
    }

    #[test]
    fn darwin_auto_route_skips_zero_slash_eight() {
        let dests = default_auto_route_destinations(RoutePlatform::Darwin);
        assert_eq!(dests.len(), 8);
        assert!(!dests.iter().any(|prefix| prefix.to_string() == "0.0.0.0/1"));
        assert!(dests.iter().any(|prefix| prefix.to_string() == "1.0.0.0/8"));
        assert!(
            dests
                .iter()
                .any(|prefix| prefix.to_string() == "128.0.0.0/1")
        );
        let linux = default_auto_route_destinations(RoutePlatform::Linux);
        assert_eq!(
            linux.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["0.0.0.0/1".to_owned(), "128.0.0.0/1".to_owned()]
        );
    }

    #[test]
    fn darwin_route_args_use_interface_without_gateway() {
        let route = OwnedRoute {
            destination: "1.0.0.0/8".parse().expect("prefix"),
            device: "utun8".to_owned(),
            gateway: None,
            table: None,
        };
        assert_eq!(
            darwin_route_args("add", &route),
            vec![
                "-n",
                "add",
                "-inet",
                "-net",
                "1.0.0.0/8",
                "-interface",
                "utun8"
            ]
        );
    }

    #[test]
    fn darwin_host_route_args_use_gateway() {
        let route = OwnedRoute {
            destination: "8.8.8.8/32".parse().expect("host"),
            device: "en0".to_owned(),
            gateway: Some("192.168.1.1".parse().expect("gw")),
            table: None,
        };
        assert_eq!(
            darwin_route_args("delete", &route),
            vec!["-n", "delete", "-inet", "-host", "8.8.8.8", "192.168.1.1"]
        );
    }

    #[test]
    fn parses_linux_route_get_via_and_local() {
        let (gateway, device) =
            parse_linux_route_get("8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.10 uid 1000\n")
                .expect("via");
        assert_eq!(gateway, Some("192.168.1.1".parse().expect("gw")));
        assert_eq!(device, "eth0");
        let (local_gw, local_dev) =
            parse_linux_route_get("local 192.0.2.1 dev lo table local src 192.0.2.1\n")
                .expect("local");
        assert_eq!(local_gw, None);
        assert_eq!(local_dev, "lo");
    }

    #[test]
    fn parses_darwin_route_get_gateway_and_on_link() {
        let sample = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
";
        let (gateway, device) = parse_darwin_route_get(sample).expect("default");
        assert_eq!(gateway, Some("192.168.1.1".parse().expect("gw")));
        assert_eq!(device, "en0");
        let on_link = "\
   route to: 192.0.2.1
destination: 192.0.2.1
  interface: lo0
";
        let (gw, iface) = parse_darwin_route_get(on_link).expect("lo0");
        assert_eq!(gw, None);
        assert_eq!(iface, "lo0");
    }

    #[test]
    fn windows_auto_route_matches_linux_split_default() {
        let windows = default_auto_route_destinations(RoutePlatform::Windows);
        assert_eq!(
            windows.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["0.0.0.0/1".to_owned(), "128.0.0.0/1".to_owned()]
        );
    }

    #[test]
    fn windows_netsh_route_args_keep_routes_on_named_adapter() {
        let route = OwnedRoute {
            destination: "0.0.0.0/1".parse().expect("prefix"),
            device: "mihomo".to_owned(),
            gateway: None,
            table: None,
        };
        assert_eq!(
            windows_netsh_route_args("add", &route),
            vec![
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=0.0.0.0/1",
                "interface=mihomo",
                "store=active"
            ]
        );
        let host = OwnedRoute {
            destination: "8.8.8.8/32".parse().expect("host"),
            device: "Ethernet".to_owned(),
            gateway: Some("192.168.1.1".parse().expect("gw")),
            table: None,
        };
        assert_eq!(
            windows_netsh_route_args("add", &host),
            vec![
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=8.8.8.8/32",
                "interface=Ethernet",
                "nexthop=192.168.1.1",
                "store=active"
            ]
        );
    }

    #[test]
    fn parses_windows_find_netroute_json() {
        let (gateway, device) =
            parse_windows_find_netroute(r#"{"NextHop":"192.168.1.1","InterfaceAlias":"Ethernet"}"#)
                .expect("via");
        assert_eq!(gateway, Some("192.168.1.1".parse().expect("gw")));
        assert_eq!(device, "Ethernet");
        let (on_link, loopback) = parse_windows_find_netroute(
            r#"{"NextHop":"0.0.0.0","InterfaceAlias":"Loopback Pseudo-Interface 1"}"#,
        )
        .expect("lo");
        assert_eq!(on_link, None);
        assert_eq!(loopback, "Loopback Pseudo-Interface 1");
        let (noisy_gw, noisy_dev) = parse_windows_find_netroute(
            "warning\n{\"NextHop\":\"10.0.0.1\",\"InterfaceAlias\":\"Wi-Fi\"}\n",
        )
        .expect("noise");
        assert_eq!(noisy_gw, Some("10.0.0.1".parse().expect("gw")));
        assert_eq!(noisy_dev, "Wi-Fi");
    }

    #[test]
    fn empty_windows_device_name_is_not_takeover() {
        reject_existing_windows_tun_device("").expect("empty auto name");
    }

    #[test]
    fn parses_netsh_interface_names() {
        let stdout = "\
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Connected      Dedicated        Ethernet
Enabled        Connected      Loopback         Loopback Pseudo-Interface 1
Enabled        Disconnected   Dedicated        WireGuard Tunnel
";
        assert_eq!(
            parse_netsh_interface_names(stdout),
            vec![
                "Ethernet".to_owned(),
                "Loopback Pseudo-Interface 1".to_owned(),
                "WireGuard Tunnel".to_owned()
            ]
        );
    }

    #[test]
    fn exclude_more_specific_than_split_default_becomes_physical_exception() {
        let includes = default_auto_route_destinations(RoutePlatform::Linux);
        let excludes = vec!["8.8.8.0/24".parse().expect("exclude")];
        let plan = plan_auto_route_prefixes(&includes, &excludes);
        assert_eq!(
            plan.tun.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec!["0.0.0.0/1".to_owned(), "128.0.0.0/1".to_owned()]
        );
        assert_eq!(
            plan.physical_exceptions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["8.8.8.0/24".to_owned()]
        );
        let equal = plan_auto_route_prefixes(
            &["0.0.0.0/1".parse().expect("inc")],
            &["0.0.0.0/1".parse().expect("exc")],
        );
        assert!(equal.tun.is_empty());
        assert!(equal.physical_exceptions.is_empty());
        let covered = plan_auto_route_prefixes(
            &["192.0.2.0/24".parse().expect("inc")],
            &["192.0.2.0/16".parse().expect("exc")],
        );
        assert!(covered.tun.is_empty());
        let v6 = plan_auto_route_prefixes(
            &["2001:db8::/32".parse().expect("inc6")],
            &["2001:db8:1::/48".parse().expect("exc6")],
        );
        assert_eq!(v6.tun.len(), 1);
        assert_eq!(v6.physical_exceptions[0].to_string(), "2001:db8:1::/48");
    }

    #[test]
    fn parse_linux_exact_route_skips_other_prefixes() {
        let stdout = "\
0.0.0.0/1 via 10.0.0.1 dev wg0 proto static metric 50
128.0.0.0/1 dev tun0 scope link
";
        let tun = parse_linux_exact_route(stdout, "128.0.0.0/1".parse().expect("tun"));
        assert_eq!(
            tun.as_ref().map(|route| route.device.as_str()),
            Some("tun0")
        );
        let foreign = parse_linux_exact_route(stdout, "0.0.0.0/1".parse().expect("wg"));
        assert_eq!(
            foreign.as_ref().map(|route| route.device.as_str()),
            Some("wg0")
        );
        assert!(parse_linux_exact_route(stdout, "8.8.8.0/24".parse().expect("miss")).is_none());
        let host = parse_linux_exact_route(
            "192.0.2.1 via 10.66.8.1 dev p8na00001 \n",
            "192.0.2.1/32".parse().expect("host"),
        );
        assert_eq!(
            host.as_ref().map(|route| route.device.as_str()),
            Some("p8na00001")
        );
        assert_eq!(
            host.as_ref().and_then(|route| route.gateway),
            Some("10.66.8.1".parse().expect("gw"))
        );
    }

    #[test]
    fn bypass_host_route_refuses_missing_and_tun_device() {
        let host = "8.8.8.8".parse().expect("host");
        let missing = bypass_host_route(host, "", None, "tun0").expect_err("empty");
        assert!(missing.to_string().contains("no physical default"));
        let via_tun = bypass_host_route(host, "tun0", None, "tun0").expect_err("tun");
        assert!(via_tun.to_string().contains("via TUN device"));
        let ok = bypass_host_route(
            host,
            "eth0",
            Some("192.168.1.1".parse().expect("gw")),
            "tun0",
        )
        .expect("physical");
        assert_eq!(ok.device, "eth0");
        assert_eq!(ok.destination.to_string(), "8.8.8.8/32");
    }

    #[test]
    fn parse_windows_exact_route_matches_prefix() {
        let json = r#"[{"DestinationPrefix":"0.0.0.0/1","NextHop":"0.0.0.0","InterfaceAlias":"WireGuard"},{"DestinationPrefix":"128.0.0.0/1","NextHop":"0.0.0.0","InterfaceAlias":"p8c"}]"#;
        let found = parse_windows_exact_route(json, "0.0.0.0/1".parse().expect("split"));
        assert_eq!(
            found.as_ref().map(|route| route.device.as_str()),
            Some("WireGuard")
        );
    }

    #[test]
    fn parse_darwin_exact_route_ignores_covering_tun_and_default() {
        let covering = "\
   route to: 8.8.8.8
destination: 0.0.0.0
       mask: 128.0.0.0
    gateway: link#12
  interface: utun8
";
        assert!(parse_darwin_exact_route(covering, "8.8.8.8/32".parse().expect("host")).is_none());
        let default = "\
   route to: 1.0.0.0
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
";
        assert!(parse_darwin_exact_route(default, "1.0.0.0/8".parse().expect("net")).is_none());
        let exact = "\
   route to: 8.8.8.8
destination: 8.8.8.8
       mask: 255.255.255.255
    gateway: 192.168.1.1
  interface: en0
";
        let found = parse_darwin_exact_route(exact, "8.8.8.8/32".parse().expect("host"))
            .expect("exact host");
        assert_eq!(found.device, "en0");
        assert_eq!(found.gateway, Some("192.168.1.1".parse().expect("gw")));
        let split = "\
destination: 0.0.0.0
       mask: 128.0.0.0
  interface: utun8
";
        let tun = parse_darwin_exact_route(split, "0.0.0.0/1".parse().expect("split")).expect("/1");
        assert_eq!(tun.device, "utun8");
        let v6 = "\
destination: 2001:db8::
       mask: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
  interface: en0
";
        let host6 =
            parse_darwin_exact_route(v6, "2001:db8::/128".parse().expect("v6")).expect("v6");
        assert_eq!(host6.device, "en0");
    }
}
