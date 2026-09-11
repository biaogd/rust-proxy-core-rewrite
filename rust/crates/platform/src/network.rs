//! Default-interface snapshots and TUN network-change planning (Phase 8F).
//!
//! Go watches sing-tun `NetworkUpdateMonitor` / `DefaultInterfaceMonitor`.
//! This crate does not call netlink, `SystemConfiguration`, or IP Helper FFI.
//! Linux/Darwin/Windows parse `ip route show default`, `route -n get default`,
//! and `Get-NetRoute 0.0.0.0/0` (or equivalent netsh JSON) instead.
//!
//! The TUN device is excluded so split auto-route cannot be mistaken for the
//! physical default after 8A/8C `0.0.0.0/1` + `128.0.0.0/1`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use ipnet::IpNet;

use crate::PlatformError;
use crate::route::{
    OwnedRoute, RouteOwner, bypass_host_route, install_bypass_host_route, parse_darwin_route_get,
};

/// How often TUN polls the physical default route.
pub const NETWORK_CHANGE_POLL: Duration = Duration::from_millis(500);

struct AutoDetectBind {
    inet4: Option<String>,
    inet6: Option<String>,
}

static AUTO_DETECT_BIND: Mutex<Option<AutoDetectBind>> = Mutex::new(None);
const DYNAMIC_BYPASS_CAP: usize = 1024;

struct OutboundBypass {
    tun_device: String,
    physical: DefaultInterfaceSnapshot,
    capture_ipv4: bool,
    capture_ipv6: bool,
    skip: Vec<IpNet>,
    hosts: Vec<IpAddr>,
    owner: RouteOwner,
}

static OUTBOUND_BYPASS: Mutex<Option<OutboundBypass>> = Mutex::new(None);

/// Physical default route used for loop-avoidance refresh and auto-detect bind.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DefaultInterfaceSnapshot {
    pub device: Option<String>,
    pub gateway: Option<IpAddr>,
    pub inet6_device: Option<String>,
    pub inet6_gateway: Option<IpAddr>,
}

impl DefaultInterfaceSnapshot {
    #[must_use]
    pub fn lost() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_lost(&self) -> bool {
        self.device.is_none() && self.inet6_device.is_none()
    }

    /// IPv4 device, IPv6 device, or `v4/v6` when they differ.
    #[must_use]
    pub fn display_name(&self) -> String {
        match (self.device.as_deref(), self.inet6_device.as_deref()) {
            (Some(v4), Some(v6)) if v4 != v6 => format!("{v4}/{v6}"),
            (Some(v4), _) => v4.to_owned(),
            (_, Some(v6)) => v6.to_owned(),
            _ => "unknown".to_owned(),
        }
    }

    /// Device and gateway for `host`'s address family.
    #[must_use]
    pub fn nexthop(&self, host: IpAddr) -> Option<(&str, Option<IpAddr>)> {
        if host.is_ipv6() {
            Some((self.inet6_device.as_deref()?, self.inet6_gateway))
        } else {
            Some((self.device.as_deref()?, self.gateway))
        }
    }

    /// Copies IPv4 `device`/`gateway` from `other` into the IPv6 slots.
    #[must_use]
    pub fn with_inet6(mut self, other: Self) -> Self {
        self.inet6_device = other.device;
        self.inet6_gateway = other.gateway;
        self
    }
}

/// True when auto-route destinations include `host`'s address family.
#[must_use]
pub fn auto_route_covers_family(destinations: &[IpNet], host: IpAddr) -> bool {
    destinations
        .iter()
        .any(|prefix| prefix.addr().is_ipv4() == host.is_ipv4())
}

/// Host route via the matching-family physical default, or `None` when that
/// family is not captured by TUN auto-route.
///
/// # Errors
///
/// Returns when the family is captured but has no physical default, the
/// default is the TUN device, or the gateway family does not match `host`.
pub fn planned_bypass_host_route(
    host: IpAddr,
    physical: &DefaultInterfaceSnapshot,
    tun_device: &str,
    capture_ipv4: bool,
    capture_ipv6: bool,
) -> Result<Option<OwnedRoute>, PlatformError> {
    let captured = if host.is_ipv6() {
        capture_ipv6
    } else {
        capture_ipv4
    };
    if !captured {
        return Ok(None);
    }
    let (device, gateway) = physical.nexthop(host).ok_or_else(|| {
        PlatformError::Command(format!(
            "no physical {} default interface; refusing TUN loop-avoidance route",
            if host.is_ipv6() { "IPv6" } else { "IPv4" }
        ))
    })?;
    Ok(Some(bypass_host_route(host, device, gateway, tun_device)?))
}

/// Planned TUN reaction to a physical default-interface change.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // Independent Go callback side effects.
pub struct NetworkChangePlan {
    pub reprotect_hosts: bool,
    pub reapply_system_dns: bool,
    pub reset_resolver: bool,
    pub update_detected_interface: bool,
    pub log: String,
}

/// Classifies `before` → `after` for TUN. `None` means no work.
#[must_use]
pub fn plan_network_change(
    before: &DefaultInterfaceSnapshot,
    after: &DefaultInterfaceSnapshot,
    tun_device: &str,
    auto_detect_interface: bool,
    dns_follows_primary: bool,
) -> Option<NetworkChangePlan> {
    let before = exclude_tun_device(before, tun_device);
    let after = exclude_tun_device(after, tun_device);
    if before == after {
        return None;
    }
    if after.is_lost() {
        return Some(NetworkChangePlan {
            reprotect_hosts: false,
            reapply_system_dns: false,
            reset_resolver: true,
            update_detected_interface: auto_detect_interface,
            log: "[TUN] default interface lost by monitor".to_owned(),
        });
    }
    let name = after.display_name();
    Some(NetworkChangePlan {
        reprotect_hosts: true,
        reapply_system_dns: dns_follows_primary,
        reset_resolver: true,
        update_detected_interface: auto_detect_interface,
        log: format!("[TUN] default interface changed by monitor, => {name}"),
    })
}

/// Drops a snapshot that points at the TUN adapter itself.
#[must_use]
pub fn exclude_tun_device(
    snapshot: &DefaultInterfaceSnapshot,
    tun_device: &str,
) -> DefaultInterfaceSnapshot {
    if tun_device.is_empty() {
        return snapshot.clone();
    }
    let mut snapshot = snapshot.clone();
    if snapshot
        .device
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(tun_device))
    {
        snapshot.device = None;
        snapshot.gateway = None;
    }
    if snapshot
        .inet6_device
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(tun_device))
    {
        snapshot.inet6_device = None;
        snapshot.inet6_gateway = None;
    }
    snapshot
}

/// Stores per-family auto-detect bind targets used when `interface-name` is empty.
pub fn set_auto_detect_bind_interface(physical: Option<&DefaultInterfaceSnapshot>) {
    let mut slot = AUTO_DETECT_BIND
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = physical.and_then(|snapshot| {
        let inet4 = nonempty_iface(snapshot.device.as_deref());
        let inet6 = nonempty_iface(snapshot.inet6_device.as_deref());
        if inet4.is_none() && inet6.is_none() {
            None
        } else {
            Some(AutoDetectBind { inet4, inet6 })
        }
    });
}

fn nonempty_iface(name: Option<&str>) -> Option<String> {
    name.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// Returns the auto-detect bind target for `remote`'s address family.
#[must_use]
pub fn auto_detect_bind_interface(remote: SocketAddr) -> Option<String> {
    let slot = AUTO_DETECT_BIND
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let bind = slot.as_ref()?;
    if remote.is_ipv6() {
        bind.inet6.clone()
    } else {
        bind.inet4.clone()
    }
}

/// Explicit `interface-name` wins; otherwise the auto-detect bind for `remote`.
#[must_use]
pub fn resolve_outbound_bind_interface(explicit: &str, remote: SocketAddr) -> String {
    if !explicit.is_empty() {
        return explicit.to_owned();
    }
    auto_detect_bind_interface(remote).unwrap_or_default()
}

/// Cache identity for QUIC clients: explicit name, or `v4|v6` auto-detect slots.
#[must_use]
pub fn resolve_outbound_bind_identity(explicit: &str) -> String {
    if !explicit.is_empty() {
        return explicit.to_owned();
    }
    let slot = AUTO_DETECT_BIND
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match slot.as_ref() {
        None => String::new(),
        Some(bind) => format!(
            "{}|{}",
            bind.inet4.as_deref().unwrap_or(""),
            bind.inet6.as_deref().unwrap_or("")
        ),
    }
}

/// Starts per-destination physical bypass used when TUN auto-route is on.
pub fn install_outbound_bypass(
    tun_device: &str,
    physical: &DefaultInterfaceSnapshot,
    skip: Vec<IpNet>,
    capture_ipv4: bool,
    capture_ipv6: bool,
) {
    let mut slot = OUTBOUND_BYPASS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(current) = slot.as_mut() {
        let _ = current.owner.revert_all();
    }
    *slot = Some(OutboundBypass {
        tun_device: tun_device.to_owned(),
        physical: physical.clone(),
        capture_ipv4,
        capture_ipv6,
        skip,
        hosts: Vec::new(),
        owner: RouteOwner::new(),
    });
}

/// Rebuilds dynamic bypass after the physical default changes.
pub fn update_outbound_bypass(physical: &DefaultInterfaceSnapshot) {
    let mut slot = OUTBOUND_BYPASS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(current) = slot.as_mut() else {
        return;
    };
    let _ = current.owner.revert_all();
    current.physical = physical.clone();
    let hosts = current.hosts.clone();
    let tun_device = current.tun_device.clone();
    let capture_ipv4 = current.capture_ipv4;
    let capture_ipv6 = current.capture_ipv6;
    for host in hosts {
        let Ok(Some(route)) = planned_bypass_host_route(
            host,
            &current.physical,
            &tun_device,
            capture_ipv4,
            capture_ipv6,
        ) else {
            continue;
        };
        let _ = install_bypass_host_route(&route, &tun_device, &mut current.owner);
    }
}

/// Drops dynamic bypass host routes on TUN stop.
pub fn clear_outbound_bypass() {
    let mut slot = OUTBOUND_BYPASS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(mut current) = slot.take() {
        let _ = current.owner.revert_all();
    }
}

/// Installs a physical host route for an infrastructure destination (DNS
/// upstream or proxy server) when TUN auto-route is on.
///
/// Ordinary DIRECT dials must not call this: a host route would make every
/// later flow to that IP bypass TUN and skip per-port/per-rule matching.
/// DIRECT and proxy sockets bind the physical interface instead.
///
/// Fake-IP / TUN prefixes in `skip` are ignored. Missing bypass state is a
/// no-op so non-TUN dials stay unchanged.
///
/// # Errors
///
/// Returns when the physical default is the TUN device, route install fails,
/// or the 1024-entry dynamic host-route cap is exhausted.
pub fn protect_outbound_destination(host: IpAddr) -> Result<(), PlatformError> {
    if host.is_loopback() || host.is_unspecified() || host.is_multicast() {
        return Ok(());
    }
    let mut slot = OUTBOUND_BYPASS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(current) = slot.as_mut() else {
        return Ok(());
    };
    if current.skip.iter().any(|prefix| prefix.contains(&host)) {
        return Ok(());
    }
    let tracked = current.hosts.contains(&host);
    if tracked
        && current
            .owner
            .routes()
            .iter()
            .any(|route| route.destination.addr() == host)
    {
        return Ok(());
    }
    if !tracked && current.hosts.len() >= DYNAMIC_BYPASS_CAP {
        return Err(PlatformError::Command(format!(
            "outbound bypass host-route cap ({DYNAMIC_BYPASS_CAP}) exhausted; refusing unprotected dial"
        )));
    }
    let Some(route) = planned_bypass_host_route(
        host,
        &current.physical,
        &current.tun_device,
        current.capture_ipv4,
        current.capture_ipv6,
    )?
    else {
        return Ok(());
    };
    install_bypass_host_route(&route, &current.tun_device, &mut current.owner)?;
    if !tracked {
        current.hosts.push(host);
    }
    Ok(())
}

/// Parses `ip route show default` and keeps the lowest-metric non-TUN row.
#[must_use]
pub fn parse_linux_default_routes(stdout: &str, exclude: Option<&str>) -> DefaultInterfaceSnapshot {
    let mut best: Option<(u32, DefaultInterfaceSnapshot)> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("default") {
            continue;
        }
        let mut via = None;
        let mut device = None;
        let mut metric = 0_u32;
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            match word {
                "via" => via = words.next(),
                "dev" => device = words.next(),
                "metric" => {
                    metric = words
                        .next()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                }
                _ => {}
            }
        }
        let Some(device) = device else {
            continue;
        };
        if exclude.is_some_and(|name| name.eq_ignore_ascii_case(device)) {
            continue;
        }
        let snapshot = DefaultInterfaceSnapshot {
            device: Some(device.to_owned()),
            gateway: via.and_then(|value| value.parse().ok()),
            ..Default::default()
        };
        if best
            .as_ref()
            .is_none_or(|(best_metric, _)| metric < *best_metric)
        {
            best = Some((metric, snapshot));
        }
    }
    best.map_or_else(DefaultInterfaceSnapshot::lost, |(_, snapshot)| snapshot)
}

/// Parses Darwin `route -n get default`.
#[must_use]
pub fn parse_darwin_default_route(stdout: &str, exclude: Option<&str>) -> DefaultInterfaceSnapshot {
    match parse_darwin_route_get(stdout) {
        Ok((gateway, device)) => {
            if exclude.is_some_and(|name| name.eq_ignore_ascii_case(&device)) {
                DefaultInterfaceSnapshot::lost()
            } else {
                DefaultInterfaceSnapshot {
                    device: Some(device),
                    gateway,
                    ..Default::default()
                }
            }
        }
        Err(_) => DefaultInterfaceSnapshot::lost(),
    }
}

/// Parses PowerShell `Get-NetRoute -DestinationPrefix 0.0.0.0/0` JSON rows.
#[must_use]
pub fn parse_windows_default_routes(json: &str, exclude: Option<&str>) -> DefaultInterfaceSnapshot {
    let mut best: Option<(u32, DefaultInterfaceSnapshot)> = None;
    for chunk in json.split('{').skip(1) {
        let body = format!("{{{chunk}");
        let alias = json_string(&body, "InterfaceAlias");
        let Some(device) = alias.filter(|name| !name.is_empty()) else {
            continue;
        };
        if exclude.is_some_and(|name| name.eq_ignore_ascii_case(&device)) {
            continue;
        }
        let metric = json_string(&body, "RouteMetric")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let next_hop = json_string(&body, "NextHop");
        let gateway = match next_hop.as_deref() {
            None | Some("" | "0.0.0.0" | "::") => None,
            Some(value) => value.parse().ok(),
        };
        let snapshot = DefaultInterfaceSnapshot {
            device: Some(device),
            gateway,
            ..Default::default()
        };
        if best
            .as_ref()
            .is_none_or(|(best_metric, _)| metric < *best_metric)
        {
            best = Some((metric, snapshot));
        }
    }
    best.map_or_else(DefaultInterfaceSnapshot::lost, |(_, snapshot)| snapshot)
}

fn json_string(body: &str, key: &str) -> Option<String> {
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

#[cfg(target_os = "linux")]
fn ip_route_show_default(args: &[&str]) -> Result<String, PlatformError> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn darwin_default_snapshot(
    args: &[&str],
    tun_device: Option<&str>,
) -> Result<DefaultInterfaceSnapshot, PlatformError> {
    let output = std::process::Command::new("route")
        .args(args)
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Ok(DefaultInterfaceSnapshot::lost());
    }
    Ok(parse_darwin_default_route(
        &String::from_utf8_lossy(&output.stdout),
        tun_device,
    ))
}

#[cfg(target_os = "windows")]
fn windows_default_snapshot(
    prefix: &str,
    tun_device: Option<&str>,
) -> Result<DefaultInterfaceSnapshot, PlatformError> {
    let family = if prefix.contains(':') { "IPv6" } else { "IPv4" };
    let script = format!(
        "@(Get-NetRoute -AddressFamily {family} -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue | \
          Select-Object NextHop, InterfaceAlias, RouteMetric) | ConvertTo-Json -Compress"
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script.as_str()])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Ok(DefaultInterfaceSnapshot::lost());
    }
    Ok(parse_windows_default_routes(
        &String::from_utf8_lossy(&output.stdout),
        tun_device,
    ))
}

/// Reads the current physical default interface, excluding `tun_device`.
///
/// # Errors
///
/// Returns command failures. Missing defaults are [`DefaultInterfaceSnapshot::lost`].
pub fn current_default_interface(
    tun_device: Option<&str>,
) -> Result<DefaultInterfaceSnapshot, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        let v4 = parse_linux_default_routes(
            &ip_route_show_default(&["route", "show", "default"])?,
            tun_device,
        );
        let v6 = parse_linux_default_routes(
            &ip_route_show_default(&["-6", "route", "show", "default"])?,
            tun_device,
        );
        Ok(v4.with_inet6(v6))
    }
    #[cfg(target_os = "macos")]
    {
        let v4 = darwin_default_snapshot(&["-n", "get", "default"], tun_device)?;
        let v6 = darwin_default_snapshot(&["-n", "get", "-inet6", "default"], tun_device)?;
        Ok(v4.with_inet6(v6))
    }
    #[cfg(target_os = "windows")]
    {
        let v4 = windows_default_snapshot("0.0.0.0/0", tun_device)?;
        let v6 = windows_default_snapshot("::/0", tun_device)?;
        Ok(v4.with_inet6(v6))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = tun_device;
        Err(PlatformError::Unsupported(
            "TUN network-change monitor is Linux/macOS/Windows in Phase 8F".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_default_prefers_lowest_metric_and_skips_tun() {
        let stdout = "\
default via 10.66.8.1 dev p8n00001 proto static metric 100
default via 10.66.9.1 dev p8b00001 proto static metric 200
";
        let snapshot = parse_linux_default_routes(stdout, None);
        assert_eq!(snapshot.device.as_deref(), Some("p8n00001"));
        assert_eq!(snapshot.gateway, Some("10.66.8.1".parse().expect("gw")));
        let skipped = parse_linux_default_routes(stdout, Some("p8n00001"));
        assert_eq!(skipped.device.as_deref(), Some("p8b00001"));
        assert_eq!(
            parse_linux_default_routes("default via 1.1.1.1 dev tun0\n", Some("tun0")).device,
            None
        );
    }

    #[test]
    fn darwin_default_excludes_utun() {
        let sample = "\
   route to: default
destination: default
    gateway: 192.168.1.1
  interface: en0
";
        let snapshot = parse_darwin_default_route(sample, None);
        assert_eq!(snapshot.device.as_deref(), Some("en0"));
        assert_eq!(parse_darwin_default_route(sample, Some("en0")).device, None);
    }

    #[test]
    fn windows_default_skips_wintun_adapter() {
        let json = r#"[{"NextHop":"0.0.0.0","InterfaceAlias":"p8cr00001","RouteMetric":1},{"NextHop":"192.168.1.1","InterfaceAlias":"Ethernet","RouteMetric":25}]"#;
        let snapshot = parse_windows_default_routes(json, Some("p8cr00001"));
        assert_eq!(snapshot.device.as_deref(), Some("Ethernet"));
        assert_eq!(snapshot.gateway, Some("192.168.1.1".parse().expect("gw")));
    }

    #[test]
    fn plan_ignores_identical_and_treats_loss_as_sleep_analog() {
        let wifi = DefaultInterfaceSnapshot {
            device: Some("wlan0".to_owned()),
            gateway: Some("192.168.1.1".parse().expect("gw")),
            ..Default::default()
        };
        let eth = DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            gateway: Some("10.0.0.1".parse().expect("gw")),
            ..Default::default()
        };
        assert!(plan_network_change(&wifi, &wifi, "tun0", true, true).is_none());
        let lost =
            plan_network_change(&wifi, &DefaultInterfaceSnapshot::lost(), "tun0", true, true)
                .expect("lost");
        assert!(lost.reset_resolver);
        assert!(!lost.reprotect_hosts);
        assert!(lost.log.contains("lost"));
        let changed = plan_network_change(&wifi, &eth, "tun0", true, true).expect("changed");
        assert!(changed.reprotect_hosts);
        assert!(changed.reapply_system_dns);
        assert!(changed.update_detected_interface);
        assert!(changed.log.contains("eth0"));
        let no_dns = plan_network_change(&wifi, &eth, "tun0", false, false).expect("linux");
        assert!(!no_dns.reapply_system_dns);
        assert!(!no_dns.update_detected_interface);
        let tun_as_default = DefaultInterfaceSnapshot {
            device: Some("tun0".to_owned()),
            gateway: None,
            ..Default::default()
        };
        assert!(plan_network_change(&wifi, &tun_as_default, "tun0", true, false).is_some());
    }

    #[test]
    fn explicit_interface_name_wins_over_auto_detect() {
        let v4: SocketAddr = "1.1.1.1:53".parse().expect("v4");
        let v6: SocketAddr = "[2001:db8::1]:53".parse().expect("v6");
        set_auto_detect_bind_interface(Some(&DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            inet6_device: Some("eth1".to_owned()),
            ..Default::default()
        }));
        assert_eq!(resolve_outbound_bind_interface("wlan0", v4), "wlan0");
        assert_eq!(resolve_outbound_bind_interface("", v4), "eth0");
        assert_eq!(resolve_outbound_bind_interface("", v6), "eth1");
        assert_eq!(resolve_outbound_bind_identity(""), "eth0|eth1");
        set_auto_detect_bind_interface(None);
        assert_eq!(resolve_outbound_bind_interface("", v4), "");
        assert_eq!(resolve_outbound_bind_interface("", v6), "");
        assert_eq!(resolve_outbound_bind_identity(""), "");
    }

    #[test]
    fn auto_detect_bind_follows_remote_family_and_ipv6_only_is_not_lost() {
        let v4: SocketAddr = "192.0.2.1:443".parse().expect("v4");
        let v6: SocketAddr = "[2001:db8::1]:443".parse().expect("v6");
        let v4_only = DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            gateway: Some("192.168.1.1".parse().expect("gw")),
            ..Default::default()
        };
        set_auto_detect_bind_interface(Some(&v4_only));
        assert_eq!(auto_detect_bind_interface(v4).as_deref(), Some("eth0"));
        assert_eq!(auto_detect_bind_interface(v6), None);
        assert!(!v4_only.is_lost());

        let v6_only = DefaultInterfaceSnapshot {
            inet6_device: Some("eth1".to_owned()),
            inet6_gateway: Some("fe80::1".parse().expect("ll")),
            ..Default::default()
        };
        assert!(!v6_only.is_lost());
        assert!(DefaultInterfaceSnapshot::lost().is_lost());
        set_auto_detect_bind_interface(Some(&v6_only));
        assert_eq!(auto_detect_bind_interface(v4), None);
        assert_eq!(auto_detect_bind_interface(v6).as_deref(), Some("eth1"));
        assert_eq!(resolve_outbound_bind_identity(""), "|eth1");

        let appeared = plan_network_change(
            &DefaultInterfaceSnapshot::lost(),
            &v6_only,
            "tun0",
            true,
            false,
        )
        .expect("ipv6-only default is a restore, not a loss");
        assert!(appeared.reprotect_hosts);
        assert!(appeared.update_detected_interface);
        assert!(!appeared.log.contains("lost"));
        assert!(appeared.log.contains("eth1"));

        let dual = DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            gateway: Some("192.168.1.1".parse().expect("gw")),
            inet6_device: Some("eth1".to_owned()),
            inet6_gateway: Some("fe80::1".parse().expect("ll")),
        };
        set_auto_detect_bind_interface(Some(&dual));
        assert_eq!(resolve_outbound_bind_interface("", v4), "eth0");
        assert_eq!(resolve_outbound_bind_interface("", v6), "eth1");
        assert_eq!(dual.display_name(), "eth0/eth1");

        let tun_v4_physical_v6 = DefaultInterfaceSnapshot {
            device: Some("tun0".to_owned()),
            inet6_device: Some("eth1".to_owned()),
            ..Default::default()
        };
        let excluded = exclude_tun_device(&tun_v4_physical_v6, "tun0");
        assert!(excluded.device.is_none());
        assert_eq!(excluded.inet6_device.as_deref(), Some("eth1"));
        assert!(!excluded.is_lost());
        set_auto_detect_bind_interface(None);
    }

    #[test]
    fn dynamic_bypass_cap_returns_error_instead_of_silent_ok() {
        let physical = DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            gateway: Some("192.168.1.1".parse().expect("gw")),
            ..Default::default()
        };
        install_outbound_bypass("tun0", &physical, Vec::new(), true, false);
        {
            let mut slot = OUTBOUND_BYPASS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let current = slot.as_mut().expect("bypass");
            current.hosts = (0..DYNAMIC_BYPASS_CAP)
                .map(|index| {
                    std::net::Ipv4Addr::new(
                        10,
                        0,
                        u8::try_from(index / 256).expect("hi"),
                        u8::try_from(index % 256).expect("lo"),
                    )
                    .into()
                })
                .collect();
        }
        let error =
            protect_outbound_destination("1.2.3.4".parse().expect("host")).expect_err("cap");
        assert!(
            error.to_string().contains("1024"),
            "unexpected cap error: {error}"
        );
        assert!(error.to_string().contains("refusing unprotected dial"));
        clear_outbound_bypass();
    }

    #[test]
    fn ipv6_host_is_not_routed_via_ipv4_gateway() {
        let physical = DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            gateway: Some("192.168.1.1".parse().expect("v4gw")),
            ..Default::default()
        };
        let host = "2001:db8::1".parse().expect("v6");
        assert!(
            planned_bypass_host_route(host, &physical, "tun0", true, false)
                .expect("uncaptured family")
                .is_none()
        );
        let missing = planned_bypass_host_route(host, &physical, "tun0", true, true)
            .expect_err("captured without v6 default");
        assert!(missing.to_string().contains("IPv6"));
        let dual = DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            gateway: Some("192.168.1.1".parse().expect("v4gw")),
            inet6_device: Some("eth0".to_owned()),
            inet6_gateway: Some("fe80::1".parse().expect("v6gw")),
        };
        let route = planned_bypass_host_route(host, &dual, "tun0", true, true)
            .expect("v6 nexthop")
            .expect("installed");
        assert_eq!(route.gateway, dual.inet6_gateway);
        assert_eq!(route.destination.to_string(), "2001:db8::1/128");
    }

    #[test]
    fn linux_inet6_default_is_parsed_separately() {
        let v6 = parse_linux_default_routes(
            "default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n",
            None,
        );
        let snapshot = DefaultInterfaceSnapshot::lost().with_inet6(v6);
        assert_eq!(snapshot.device, None);
        assert!(!snapshot.is_lost());
        assert_eq!(snapshot.inet6_device.as_deref(), Some("eth0"));
        assert_eq!(snapshot.inet6_gateway, Some("fe80::1".parse().expect("ll")));
    }
}
