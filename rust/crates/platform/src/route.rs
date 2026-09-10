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
    Other,
}

/// Returns the compile-target route platform.
#[must_use]
pub fn current_route_platform() -> RoutePlatform {
    if cfg!(target_os = "linux") {
        RoutePlatform::Linux
    } else if cfg!(target_os = "macos") {
        RoutePlatform::Darwin
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
        RoutePlatform::Linux | RoutePlatform::Other => ["0.0.0.0/1", "128.0.0.0/1"].as_slice(),
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = route;
        Err(PlatformError::Unsupported(
            "TUN auto-route install is only implemented for Linux (8A) and macOS (8B)".to_owned(),
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = host;
        let _ = owner;
        Err(PlatformError::Unsupported(
            "TUN loop-avoidance host routes are only implemented for Linux (8A) and macOS (8B)"
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

fn command_error(operation: &str, output: &Output) -> PlatformError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let trimmed = stderr.trim();
    if trimmed.contains("Operation not permitted")
        || trimmed.contains("Permission denied")
        || trimmed.contains("must be root")
    {
        return PlatformError::Command(format!(
            "{operation} requires root; refusing to skip: {trimmed}"
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
}
