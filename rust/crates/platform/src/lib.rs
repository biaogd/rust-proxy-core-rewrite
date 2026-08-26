//! Small, testable operating-system boundaries used by the Rust rewrite.

mod dhcp;

pub use dhcp::{
    DHCP_TIMEOUT, DHCP_TTL, DhcpInterfaceSnapshot, DhcpOffer, DhcpRefreshDecision,
    DhcpRefreshTracker, INTERFACE_TTL, build_dhcp_discover, dhcp_interface_snapshot,
    parse_dhcp_offer, resolve_dns_from_dhcp,
};

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};

/// Number of missed refreshes retained by the Go system resolver.
pub const SYSTEM_DNS_DELETE_TIMES: u32 = 12;

/// A platform-neutral Windows adapter observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsAdapterSnapshot {
    pub is_up: bool,
    pub has_gateway: bool,
    pub dns_servers: Vec<IpAddr>,
}

/// Parses the subset of `resolv.conf` consumed by the Go oracle.
#[must_use]
pub fn parse_resolv_conf(contents: &str) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter(|line| !matches!(line.as_bytes().first(), Some(b';' | b'#')))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next())
                .flatten()
                .and_then(|value| value.parse::<IpAddr>().ok())
                .map(|address| SocketAddr::new(address, 53))
        })
        .collect()
}

/// Applies the adapter eligibility, legacy IPv6 and deduplication rules used
/// by the Windows Go implementation.
#[must_use]
pub fn filter_windows_adapters(adapters: &[WindowsAdapterSnapshot]) -> Vec<SocketAddr> {
    let mut seen = BTreeSet::new();
    let mut servers = Vec::new();
    for adapter in adapters
        .iter()
        .filter(|adapter| adapter.is_up && adapter.has_gateway)
    {
        for address in &adapter.dns_servers {
            if matches!(address, IpAddr::V6(address) if address.octets()[..2] == [0xfe, 0xc0]) {
                continue;
            }
            let server = SocketAddr::new(*address, 53);
            if seen.insert(server) {
                servers.push(server);
            }
        }
    }
    servers
}

/// Refresh lifecycle for a configured `system://` client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SystemDnsTracker {
    entries: BTreeMap<SocketAddr, u32>,
}

/// Injectable resolver list used by the Android-CMFA host integration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AndroidSystemDns {
    servers: Vec<SocketAddr>,
}

impl AndroidSystemDns {
    /// Replaces the resolver list. An empty list clears it.
    pub fn update(&mut self, servers: Vec<SocketAddr>) {
        self.servers = servers;
    }

    /// Returns the currently injected resolvers.
    #[must_use]
    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }
}

impl SystemDnsTracker {
    /// Reconciles one successful platform discovery and returns active servers.
    pub fn refresh(&mut self, discovered: &[SocketAddr]) -> Vec<SocketAddr> {
        for server in discovered {
            self.entries.entry(*server).or_insert(0);
        }
        self.entries.retain(|server, disabled| {
            if discovered.contains(server) {
                *disabled = 0;
                true
            } else if *disabled > SYSTEM_DNS_DELETE_TIMES {
                false
            } else {
                *disabled += 1;
                true
            }
        });
        self.active()
    }

    /// Returns servers enabled by the last successful refresh.
    #[must_use]
    pub fn active(&self) -> Vec<SocketAddr> {
        self.entries
            .iter()
            .filter_map(|(server, disabled)| (*disabled == 0).then_some(*server))
            .collect()
    }
}

/// Reads the native resolver list for the current platform.
///
/// # Errors
///
/// Returns an I/O error when the platform resolver source cannot be read.
#[cfg(all(
    not(windows),
    not(all(target_os = "android", feature = "android-cmfa"))
))]
pub fn discover_system_dns() -> io::Result<Vec<SocketAddr>> {
    std::fs::read_to_string("/etc/resolv.conf").map(|contents| parse_resolv_conf(&contents))
}

#[cfg(windows)]
/// Reads DNS servers from eligible Windows adapters.
///
/// # Errors
///
/// Returns an I/O error when `GetAdaptersAddresses` cannot be queried.
pub fn discover_system_dns() -> io::Result<Vec<SocketAddr>> {
    let adapters = ipconfig::get_adapters().map_err(io::Error::other)?;
    let snapshots = adapters
        .iter()
        .map(|adapter| WindowsAdapterSnapshot {
            is_up: adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp,
            has_gateway: !adapter.gateways().is_empty(),
            dns_servers: adapter.dns_servers().to_vec(),
        })
        .collect::<Vec<_>>();
    Ok(filter_windows_adapters(&snapshots))
}

#[cfg(all(target_os = "android", feature = "android-cmfa"))]
mod android_cmfa {
    use super::AndroidSystemDns;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::{Mutex, OnceLock};

    fn injected() -> &'static Mutex<AndroidSystemDns> {
        static INJECTED: OnceLock<Mutex<AndroidSystemDns>> = OnceLock::new();
        INJECTED.get_or_init(|| Mutex::new(AndroidSystemDns::default()))
    }

    pub fn discover() -> io::Result<Vec<SocketAddr>> {
        injected()
            .lock()
            .map(|servers| servers.servers().to_vec())
            .map_err(|_| io::Error::other("Android system DNS lock poisoned"))
    }

    pub fn update(servers: Vec<SocketAddr>) {
        if let Ok(mut current) = injected().lock() {
            current.update(servers);
        }
    }
}

#[cfg(all(target_os = "android", feature = "android-cmfa"))]
pub use android_cmfa::discover as discover_system_dns;

/// Replaces the Android-CMFA resolver list. An empty list clears it.
#[cfg(all(target_os = "android", feature = "android-cmfa"))]
pub fn update_android_system_dns(servers: Vec<SocketAddr>) {
    android_cmfa::update(servers);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_parser_matches_oracle_rules() {
        let parsed = parse_resolv_conf(
            "# comment\n ; indented comment\nnameserver 1.1.1.1 trailing\n\
             nameserver 2001:db8::1\nnameserver invalid\nnameserver 1.1.1.1\nsearch example\n",
        );
        assert_eq!(
            parsed,
            vec![
                "1.1.1.1:53".parse().expect("IPv4 resolver"),
                "[2001:db8::1]:53".parse().expect("IPv6 resolver"),
                "1.1.1.1:53".parse().expect("duplicate resolver"),
            ]
        );
    }

    #[test]
    fn windows_filter_requires_up_gateway_and_deduplicates() {
        let adapters = vec![
            WindowsAdapterSnapshot {
                is_up: false,
                has_gateway: true,
                dns_servers: vec!["192.0.2.1".parse().expect("address")],
            },
            WindowsAdapterSnapshot {
                is_up: true,
                has_gateway: false,
                dns_servers: vec!["192.0.2.2".parse().expect("address")],
            },
            WindowsAdapterSnapshot {
                is_up: true,
                has_gateway: true,
                dns_servers: vec![
                    "192.0.2.3".parse().expect("address"),
                    "fec0::ffff".parse().expect("legacy resolver"),
                    "192.0.2.3".parse().expect("duplicate"),
                ],
            },
        ];
        assert_eq!(
            filter_windows_adapters(&adapters),
            vec!["192.0.2.3:53".parse().expect("eligible resolver")]
        );
    }

    #[test]
    fn refresh_disables_restores_and_eventually_deletes() {
        let first = "192.0.2.53:53".parse().expect("resolver");
        let second = "[2001:db8::53]:53".parse().expect("resolver");
        let mut tracker = SystemDnsTracker::default();
        assert_eq!(tracker.refresh(&[first, second]), vec![first, second]);
        assert_eq!(tracker.refresh(&[second]), vec![second]);
        assert_eq!(tracker.refresh(&[first, second]), vec![first, second]);
        for _ in 0..=SYSTEM_DNS_DELETE_TIMES {
            assert!(tracker.refresh(&[]).is_empty());
        }
        assert!(tracker.entries.contains_key(&first));
        assert!(tracker.refresh(&[]).is_empty());
        assert!(tracker.entries.is_empty());
    }

    #[test]
    fn android_updates_replace_and_empty_updates_clear() {
        let server = "192.0.2.53:1053".parse().expect("resolver");
        let mut injected = AndroidSystemDns::default();
        injected.update(vec![server]);
        assert_eq!(injected.servers(), &[server]);
        injected.update(Vec::new());
        assert!(injected.servers().is_empty());
    }

    #[cfg(not(all(target_os = "android", feature = "android-cmfa")))]
    #[test]
    fn native_discovery_smoke_test() {
        let discovered = discover_system_dns().expect("native resolver discovery");
        assert!(discovered.iter().all(|server| server.port() == 53));
    }
}
