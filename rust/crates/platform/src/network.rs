//! Default-interface snapshots and TUN network-change planning (Phase 8F).
//!
//! Go watches sing-tun `NetworkUpdateMonitor` / `DefaultInterfaceMonitor`.
//! This crate does not call netlink, `SystemConfiguration`, or IP Helper FFI.
//! Linux/Darwin/Windows parse `ip route show default`, `route -n get default`,
//! and `Get-NetRoute 0.0.0.0/0` (or equivalent netsh JSON) instead.
//!
//! The TUN device is excluded so split auto-route cannot be mistaken for the
//! physical default after 8A/8C `0.0.0.0/1` + `128.0.0.0/1`.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use crate::PlatformError;
use crate::route::parse_darwin_route_get;

/// How often TUN polls the physical default route.
pub const NETWORK_CHANGE_POLL: Duration = Duration::from_millis(500);

static AUTO_DETECT_BIND: Mutex<Option<String>> = Mutex::new(None);

/// Physical default route used for loop-avoidance refresh and auto-detect bind.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DefaultInterfaceSnapshot {
    pub device: Option<String>,
    pub gateway: Option<IpAddr>,
}

impl DefaultInterfaceSnapshot {
    #[must_use]
    pub fn lost() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_lost(&self) -> bool {
        self.device.is_none()
    }
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
    let name = after.device.as_deref().unwrap_or("unknown");
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
    if snapshot
        .device
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case(tun_device))
    {
        return DefaultInterfaceSnapshot::lost();
    }
    snapshot.clone()
}

/// Stores the auto-detect bind target used when `interface-name` is empty.
pub fn set_auto_detect_bind_interface(name: Option<&str>) {
    let mut slot = AUTO_DETECT_BIND
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
}

/// Returns the auto-detect bind target, if TUN installed one.
#[must_use]
pub fn auto_detect_bind_interface() -> Option<String> {
    AUTO_DETECT_BIND
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Explicit `interface-name` wins; otherwise the auto-detect bind target.
#[must_use]
pub fn resolve_outbound_bind_interface(explicit: &str) -> String {
    if !explicit.is_empty() {
        return explicit.to_owned();
    }
    auto_detect_bind_interface().unwrap_or_default()
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
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(PlatformError::Io)?;
        if !output.status.success() {
            return Ok(DefaultInterfaceSnapshot::lost());
        }
        Ok(parse_linux_default_routes(
            &String::from_utf8_lossy(&output.stdout),
            tun_device,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("route")
            .args(["-n", "get", "default"])
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
    {
        let script = "\
@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
  Select-Object NextHop, InterfaceAlias, RouteMetric) | ConvertTo-Json -Compress";
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
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
        };
        let eth = DefaultInterfaceSnapshot {
            device: Some("eth0".to_owned()),
            gateway: Some("10.0.0.1".parse().expect("gw")),
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
        };
        assert!(plan_network_change(&wifi, &tun_as_default, "tun0", true, false).is_some());
    }

    #[test]
    fn explicit_interface_name_wins_over_auto_detect() {
        set_auto_detect_bind_interface(Some("eth0"));
        assert_eq!(resolve_outbound_bind_interface("wlan0"), "wlan0");
        assert_eq!(resolve_outbound_bind_interface(""), "eth0");
        set_auto_detect_bind_interface(None);
        assert_eq!(resolve_outbound_bind_interface(""), "");
    }
}
