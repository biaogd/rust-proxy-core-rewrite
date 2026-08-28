//! Small, testable operating-system boundaries used by the Rust rewrite.

mod dhcp;

pub use dhcp::{
    DHCP_TIMEOUT, DHCP_TTL, DhcpInterfaceSnapshot, DhcpOffer, DhcpRefreshDecision,
    DhcpRefreshTracker, INTERFACE_TTL, build_dhcp_discover, dhcp_interface_snapshot,
    parse_dhcp_offer, resolve_dns_from_dhcp,
};

use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos"
))]
use std::num::NonZeroU32;
use std::time::Duration;

/// Number of missed refreshes retained by the Go system resolver.
pub const SYSTEM_DNS_DELETE_TIMES: u32 = 12;

/// Binds a nonblocking TCP listener and applies the Linux/Android socket mark
/// before bind, matching the controller listen boundary.
///
/// # Errors
///
/// Returns the socket option, bind, listen or nonblocking error.
pub fn bind_marked_tcp_listener(
    address: SocketAddr,
    routing_mark: i64,
) -> io::Result<std::net::TcpListener> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if routing_mark != 0 {
        socket.set_mark(u32::try_from(routing_mark).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "routing mark is out of range")
        })?)?;
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let _ = routing_mark;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Binds a nonblocking local TCP listener, optionally accepting IPv4 through
/// an IPv6 wildcard socket.
///
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalTcpOptions {
    pub dual_stack: bool,
    pub multipath: bool,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
}

/// Binds a local TCP listener with Mihomo's socket policy.
///
/// # Errors
///
/// Returns the socket option, bind, listen or nonblocking error.
pub fn bind_local_tcp_listener(
    address: SocketAddr,
    options: LocalTcpOptions,
) -> io::Result<std::net::TcpListener> {
    match bind_local_tcp_listener_inner(address, options) {
        Ok(listener) => Ok(listener),
        #[cfg(target_os = "linux")]
        Err(_) if options.multipath => bind_local_tcp_listener_inner(
            address,
            LocalTcpOptions {
                multipath: false,
                ..options
            },
        ),
        Err(error) => Err(error),
    }
}

fn bind_local_tcp_listener_inner(
    address: SocketAddr,
    options: LocalTcpOptions,
) -> io::Result<std::net::TcpListener> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    #[cfg(target_os = "linux")]
    let protocol = if options.multipath {
        Protocol::MPTCP
    } else {
        Protocol::TCP
    };
    #[cfg(not(target_os = "linux"))]
    let protocol = Protocol::TCP;
    let socket = Socket::new(domain, Type::STREAM, Some(protocol))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(!options.dual_stack)?;
    }
    configure_tcp_keepalive(&socket, options)?;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn configure_tcp_keepalive(socket: &Socket, options: LocalTcpOptions) -> io::Result<()> {
    if options.disable_keep_alive || cfg!(target_os = "android") {
        return socket.set_keepalive(false);
    }
    let mut keepalive = TcpKeepalive::new();
    if let Ok(seconds) = u64::try_from(options.keep_alive_idle)
        && seconds != 0
    {
        keepalive = keepalive.with_time(Duration::from_secs(seconds));
    }
    if let Ok(seconds) = u64::try_from(options.keep_alive_interval)
        && seconds != 0
    {
        keepalive = keepalive.with_interval(Duration::from_secs(seconds));
    }
    socket.set_tcp_keepalive(&keepalive)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OutboundTcpOptions<'a> {
    pub interface: &'a str,
    pub routing_mark: i64,
    pub keep_alive_idle: i64,
    pub keep_alive_interval: i64,
    pub disable_keep_alive: bool,
}

/// Connects a TCP socket after applying the global interface, mark and
/// keepalive policy used by DIRECT and proxy dials.
///
/// # Errors
///
/// Returns interface discovery, socket-option, connect or readiness errors.
pub async fn connect_tcp(
    address: SocketAddr,
    options: OutboundTcpOptions<'_>,
) -> io::Result<tokio::net::TcpStream> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    configure_tcp_keepalive(
        &socket,
        LocalTcpOptions {
            keep_alive_idle: options.keep_alive_idle,
            keep_alive_interval: options.keep_alive_interval,
            disable_keep_alive: options.disable_keep_alive,
            ..LocalTcpOptions::default()
        },
    )?;
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if options.routing_mark != 0 && is_global_unicast(address.ip()) {
        socket.set_mark(u32::try_from(options.routing_mark).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "routing mark is out of range")
        })?)?;
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let _ = options.routing_mark;
    bind_outbound_interface(&socket, address, options.interface)?;
    socket.set_nonblocking(true)?;
    if let Err(error) = socket.connect(&SockAddr::from(address))
        && error.kind() != io::ErrorKind::WouldBlock
        && !error
            .raw_os_error()
            .is_some_and(|code| matches!(code, 36 | 115 | 10_035))
    {
        return Err(error);
    }
    let stream = tokio::net::TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}

/// Binds a nonblocking outbound UDP socket with global interface and routing
/// mark policy.
///
/// # Errors
///
/// Returns interface discovery, socket-option or bind errors.
pub fn bind_outbound_udp(
    address: SocketAddr,
    interface: &str,
    routing_mark: i64,
) -> io::Result<std::net::UdpSocket> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(any(target_os = "android", target_os = "linux"))]
    if routing_mark != 0 {
        socket.set_mark(u32::try_from(routing_mark).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "routing mark is out of range")
        })?)?;
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let _ = routing_mark;
    bind_outbound_interface(&socket, address, interface)?;
    socket.bind(&SockAddr::from(address))?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn bind_outbound_interface(socket: &Socket, address: SocketAddr, name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Ok(());
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        if !is_global_unicast(address.ip()) {
            return Ok(());
        }
        socket.bind_device(Some(name.as_bytes()))
    }
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))]
    {
        use network_interface::{NetworkInterface, NetworkInterfaceConfig};
        let interface = NetworkInterface::show()
            .map_err(|error| io::Error::other(error.to_string()))?
            .into_iter()
            .find(|interface| interface.name == name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;
        let index = NonZeroU32::new(interface.index).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface index is zero")
        })?;
        if !is_global_unicast(address.ip()) {
            return Ok(());
        }
        if address.is_ipv4() {
            socket.bind_device_by_index_v4(Some(index))
        } else {
            socket.bind_device_by_index_v6(Some(index))
        }
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    )))]
    {
        let _ = (socket, address);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "interface binding is not supported on this platform",
        ))
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos"
))]
fn is_global_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_link_local()
                && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

/// Binds a nonblocking local UDP socket with the same dual-stack policy as the
/// fixed TCP listener sharing its address.
///
/// # Errors
///
/// Returns the socket option, bind or nonblocking error.
pub fn bind_local_udp_socket(
    address: SocketAddr,
    dual_stack: bool,
) -> io::Result<std::net::UdpSocket> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(!dual_stack)?;
    }
    socket.bind(&SockAddr::from(address))?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

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

    #[test]
    fn marked_listener_boundary_binds_with_zero_mark() {
        let listener =
            bind_marked_tcp_listener("127.0.0.1:0".parse().expect("loopback socket address"), 0)
                .expect("controller listener");
        assert!(listener.local_addr().expect("bound address").port() > 0);
        assert!(listener.accept().is_err(), "listener must be nonblocking");
    }

    #[test]
    fn local_listener_applies_keepalive_policy() {
        let disabled = bind_local_tcp_listener(
            "127.0.0.1:0".parse().expect("loopback"),
            LocalTcpOptions {
                disable_keep_alive: true,
                ..LocalTcpOptions::default()
            },
        )
        .expect("disabled keepalive listener");
        assert!(
            !socket2::SockRef::from(&disabled)
                .keepalive()
                .expect("keepalive flag")
        );

        if !cfg!(target_os = "android") {
            let enabled = bind_local_tcp_listener(
                "127.0.0.1:0".parse().expect("loopback"),
                LocalTcpOptions {
                    keep_alive_idle: 17,
                    keep_alive_interval: 9,
                    ..LocalTcpOptions::default()
                },
            )
            .expect("enabled keepalive listener");
            assert!(
                socket2::SockRef::from(&enabled)
                    .keepalive()
                    .expect("keepalive flag")
            );
        }
    }

    #[cfg(not(all(target_os = "android", feature = "android-cmfa")))]
    #[test]
    fn native_discovery_smoke_test() {
        let discovered = discover_system_dns().expect("native resolver discovery");
        assert!(discovered.iter().all(|server| server.port() == 53));
    }
}
