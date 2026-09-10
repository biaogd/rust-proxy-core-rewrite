//! Owned route bookkeeping for TUN auto-route.

use std::net::IpAddr;
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

/// Installs a destination route via the given device.
///
/// Linux (8A) uses `ip route replace`. Darwin (8B) uses `route -n add`.
/// Windows (8C) uses `netsh interface ipv4 add route` on this adapter only.
/// Other platforms return a clear unsupported error.
///
/// # Errors
///
/// Returns command failures or unsupported-platform errors.
pub fn install_device_route(route: &OwnedRoute) -> Result<(), PlatformError> {
    #[cfg(target_os = "linux")]
    {
        run_ip_route("replace", route)
    }
    #[cfg(target_os = "macos")]
    {
        run_darwin_route("add", route)
    }
    #[cfg(target_os = "windows")]
    {
        run_windows_route("add", route)
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    if action == "add" && stderr.contains("File exists") {
        let _ = run_darwin_route("delete", route);
        let mut retry = Command::new("route");
        retry.args(&args);
        let retry_output = retry.output().map_err(PlatformError::Io)?;
        if retry_output.status.success() {
            return Ok(());
        }
        return Err(command_error("route add", &retry_output));
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

/// Installs a host route via the currently used path so TUN auto-route cannot
/// capture DIRECT, DNS upstream, or proxy-server packets.
///
/// # Errors
///
/// Returns command failures, missing route, or unsupported-platform errors.
pub fn protect_host_route(host: IpAddr, owner: &mut RouteOwner) -> Result<(), PlatformError> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let (gateway, device) = current_route_to(host)?;
        let destination = match host {
            IpAddr::V4(_) => IpNet::new(host, 32),
            IpAddr::V6(_) => IpNet::new(host, 128),
        }
        .map_err(|error| PlatformError::Command(format!("host route prefix: {error}")))?;
        let route = OwnedRoute {
            destination,
            device,
            gateway,
            table: None,
        };
        install_device_route(&route)?;
        owner.record(route);
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = host;
        let _ = owner;
        Err(PlatformError::Unsupported(
            "TUN loop-avoidance host routes are only implemented for Linux (8A), macOS (8B), and Windows (8C)"
                .to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn current_route_to(host: IpAddr) -> Result<(Option<IpAddr>, String), PlatformError> {
    let output = Command::new("ip")
        .args(["route", "get", &host.to_string()])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(command_error("ip route get", &output));
    }
    parse_linux_route_get(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "macos")]
fn current_route_to(host: IpAddr) -> Result<(Option<IpAddr>, String), PlatformError> {
    let family = if host.is_ipv6() { "-inet6" } else { "-inet" };
    let output = Command::new("route")
        .args(["-n", "get", family, &host.to_string()])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(command_error("route get", &output));
    }
    parse_darwin_route_get(&String::from_utf8_lossy(&output.stdout))
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

#[cfg(target_os = "windows")]
fn current_route_to(host: IpAddr) -> Result<(Option<IpAddr>, String), PlatformError> {
    let script = format!(
        "$rows = @(Find-NetRoute -RemoteIPAddress '{host}' -ErrorAction Stop); \
         $row = $rows | Where-Object {{ $_.InterfaceAlias }} | Select-Object -First 1; \
         if (-not $row) {{ $row = $rows | Select-Object -First 1 }}; \
         @{{ NextHop = $row.NextHop; InterfaceAlias = $row.InterfaceAlias }} | ConvertTo-Json -Compress"
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(command_error("Find-NetRoute", &output));
    }
    parse_windows_find_netroute(&String::from_utf8_lossy(&output.stdout))
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
    if action == "add" && looks_like_route_exists(&error.to_string()) {
        let _ = run_windows_route("delete", route);
        let retry = Command::new("netsh")
            .args(&args)
            .output()
            .map_err(PlatformError::Io)?;
        if retry.status.success() {
            return Ok(());
        }
        return Err(command_error("netsh route add", &retry));
    }
    Err(error)
}

#[cfg(target_os = "windows")]
fn looks_like_route_exists(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("already exists")
        || lower.contains("object already exists")
        || lower.contains("the object exists")
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
}
