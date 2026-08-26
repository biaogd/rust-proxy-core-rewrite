use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(any(
    target_os = "android",
    target_os = "illumos",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "solaris",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos"
))]
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub const INTERFACE_TTL: Duration = Duration::from_secs(20);
pub const DHCP_TTL: Duration = Duration::from_hours(1);
pub const DHCP_TIMEOUT: Duration = Duration::from_mins(1);

const BOOTP_FIXED_LENGTH: usize = 236;
const DHCP_OPTIONS_OFFSET: usize = 240;
const BOOTP_MINIMUM_LENGTH: usize = 300;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
const OPTION_PAD: u8 = 0;
const OPTION_DNS: u8 = 6;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
const OPTION_END: u8 = 255;
const MESSAGE_DISCOVER: u8 = 1;
const MESSAGE_OFFER: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DhcpInterfaceSnapshot {
    pub index: u32,
    pub ipv4: Ipv4Addr,
    pub hardware_address: [u8; 6],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DhcpOffer {
    Ignored,
    MissingDns,
    DnsServers(Vec<Ipv4Addr>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhcpRefreshDecision {
    Cached,
    Refresh,
    InterfaceError,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DhcpRefreshTracker {
    interface_valid_until: Duration,
    dns_valid_until: Duration,
    interface_address: Option<Ipv4Addr>,
}

impl DhcpRefreshTracker {
    #[must_use]
    pub fn observe(
        &mut self,
        now: Duration,
        interface_address: Option<Ipv4Addr>,
    ) -> DhcpRefreshDecision {
        if now < self.interface_valid_until {
            return DhcpRefreshDecision::Cached;
        }
        self.interface_valid_until = now.saturating_add(INTERFACE_TTL);
        let Some(interface_address) = interface_address else {
            return DhcpRefreshDecision::InterfaceError;
        };
        if now < self.dns_valid_until && self.interface_address == Some(interface_address) {
            return DhcpRefreshDecision::Cached;
        }
        self.dns_valid_until = now.saturating_add(DHCP_TTL);
        self.interface_address = Some(interface_address);
        DhcpRefreshDecision::Refresh
    }
}

/// Finds the interface metadata required by a DHCP discovery.
///
/// # Errors
///
/// Returns an error when the interface, a non-link-local IPv4 address, or a
/// six-byte hardware address cannot be found.
pub fn dhcp_interface_snapshot(name: &str) -> io::Result<DhcpInterfaceSnapshot> {
    let interface = NetworkInterface::show()
        .map_err(io::Error::other)?
        .into_iter()
        .find(|interface| interface.name == name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;
    snapshot_from_interface(&interface)
}

fn snapshot_from_interface(interface: &NetworkInterface) -> io::Result<DhcpInterfaceSnapshot> {
    let ipv4 = interface
        .addr
        .iter()
        .find_map(|address| match address {
            Addr::V4(address) if !address.ip.is_link_local() => Some(address.ip),
            _ => None,
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 address not found"))?;
    let hardware_address = interface
        .mac_addr
        .as_deref()
        .and_then(parse_hardware_address)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "hardware address not found",
            )
        })?;
    Ok(DhcpInterfaceSnapshot {
        index: interface.index,
        ipv4,
        hardware_address,
    })
}

fn parse_hardware_address(value: &str) -> Option<[u8; 6]> {
    let mut result = [0_u8; 6];
    let mut parts = value.split([':', '-']);
    for byte in &mut result {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(result)
}

#[must_use]
pub fn build_dhcp_discover(transaction_id: u32, hardware_address: [u8; 6]) -> Vec<u8> {
    let mut packet = vec![0_u8; BOOTP_FIXED_LENGTH];
    packet[0] = 1;
    packet[1] = 1;
    packet[2] = 6;
    packet[4..8].copy_from_slice(&transaction_id.to_be_bytes());
    packet[10..12].copy_from_slice(&0x8000_u16.to_be_bytes());
    packet[28..34].copy_from_slice(&hardware_address);
    packet.extend_from_slice(&DHCP_MAGIC_COOKIE);
    packet.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, MESSAGE_DISCOVER]);
    packet.extend_from_slice(&[OPTION_PARAMETER_REQUEST_LIST, 4, 1, 3, 15, OPTION_DNS]);
    packet.push(OPTION_END);
    packet.resize(BOOTP_MINIMUM_LENGTH, OPTION_PAD);
    packet
}

#[must_use]
pub fn parse_dhcp_offer(packet: &[u8], transaction_id: u32) -> DhcpOffer {
    if packet.len() < DHCP_OPTIONS_OFFSET
        || packet[0] != 2
        || packet[4..8] != transaction_id.to_be_bytes()
        || packet[BOOTP_FIXED_LENGTH..DHCP_OPTIONS_OFFSET] != DHCP_MAGIC_COOKIE
    {
        return DhcpOffer::Ignored;
    }
    let mut message_type = None;
    let mut dns = None;
    let mut found_end = false;
    let mut offset = DHCP_OPTIONS_OFFSET;
    while offset < packet.len() {
        let code = packet[offset];
        offset += 1;
        if code == OPTION_END {
            found_end = true;
            break;
        }
        if code == OPTION_PAD {
            continue;
        }
        let Some(&length) = packet.get(offset) else {
            return DhcpOffer::Ignored;
        };
        offset += 1;
        let end = offset.saturating_add(usize::from(length));
        let Some(value) = packet.get(offset..end) else {
            return DhcpOffer::Ignored;
        };
        match code {
            OPTION_MESSAGE_TYPE if value.len() == 1 => message_type = value.first().copied(),
            OPTION_DNS => {
                if value.is_empty() || value.len() % 4 != 0 {
                    dns = None;
                    offset = end;
                    continue;
                }
                dns = Some(
                    value
                        .chunks_exact(4)
                        .map(|address| {
                            Ipv4Addr::new(address[0], address[1], address[2], address[3])
                        })
                        .collect::<Vec<_>>(),
                );
            }
            _ => {}
        }
        offset = end;
    }
    if !found_end || message_type != Some(MESSAGE_OFFER) {
        return DhcpOffer::Ignored;
    }
    dns.map_or(DhcpOffer::MissingDns, DhcpOffer::DnsServers)
}

/// Broadcasts one DHCPDISCOVER and returns DNS option 6 from the matching
/// DHCPOFFER.
///
/// # Errors
///
/// Returns an error for socket/interface failures, a matching offer without
/// DNS servers, or when no matching offer arrives within one minute.
pub fn resolve_dns_from_dhcp(interface: &DhcpInterfaceSnapshot) -> io::Result<Vec<SocketAddr>> {
    let socket = dhcp_socket(interface)?;
    let transaction_id = next_transaction_id();
    let discovery = build_dhcp_discover(transaction_id, interface.hardware_address);
    socket.send_to(&discovery, SocketAddr::from(([255, 255, 255, 255], 67)))?;
    let started = std::time::Instant::now();
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = DHCP_TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DHCP not responding",
            ));
        }
        socket.set_read_timeout(Some(remaining))?;
        let length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DHCP not responding",
                ));
            }
            Err(error) => return Err(error),
        };
        match parse_dhcp_offer(&buffer[..length], transaction_id) {
            DhcpOffer::Ignored => {}
            DhcpOffer::MissingDns => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "DNS option not found",
                ));
            }
            DhcpOffer::DnsServers(servers) => {
                return Ok(servers
                    .into_iter()
                    .map(|address| SocketAddr::from((address, 53)))
                    .collect());
            }
        }
    }
}

fn dhcp_socket(interface: &DhcpInterfaceSnapshot) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    #[cfg(any(
        target_os = "android",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))]
    socket.bind_device_by_index_v4(NonZeroU32::new(interface.index))?;
    #[cfg(not(any(
        target_os = "android",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    )))]
    let _ = interface;
    let bind_address = if cfg!(any(target_os = "linux", target_os = "android")) {
        SocketAddr::from(([255, 255, 255, 255], 68))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 68))
    };
    socket.bind(&SockAddr::from(bind_address))?;
    Ok(socket.into())
}

fn next_transaction_id() -> u32 {
    static SEQUENCE: AtomicU32 = AtomicU32::new(1);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    time ^ std::process::id() ^ SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(transaction_id: u32, message_type: u8, dns: Option<&[u8]>) -> Vec<u8> {
        let mut packet = vec![0_u8; BOOTP_FIXED_LENGTH];
        packet[0] = 2;
        packet[4..8].copy_from_slice(&transaction_id.to_be_bytes());
        packet.extend_from_slice(&DHCP_MAGIC_COOKIE);
        packet.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, message_type]);
        if let Some(dns) = dns {
            packet
                .extend_from_slice(&[OPTION_DNS, u8::try_from(dns.len()).expect("option length")]);
            packet.extend_from_slice(dns);
        }
        packet.push(OPTION_END);
        packet
    }

    #[test]
    fn discover_matches_oracle_defaults_and_sets_broadcast_flag() {
        let transaction_id = 0x1234_5678;
        let hardware_address = [0, 1, 2, 3, 4, 5];
        let packet = build_dhcp_discover(transaction_id, hardware_address);
        assert_eq!(&packet[4..8], &transaction_id.to_be_bytes());
        assert_eq!(&packet[10..12], &0x8000_u16.to_be_bytes());
        assert_eq!(&packet[28..34], &hardware_address);
        assert_eq!(packet.len(), BOOTP_MINIMUM_LENGTH);
        assert_eq!(
            &packet[BOOTP_FIXED_LENGTH..DHCP_OPTIONS_OFFSET + 10],
            &[99, 130, 83, 99, 53, 1, 1, 55, 4, 1, 3, 15, 6, 255]
        );
    }

    #[test]
    fn offer_requires_type_transaction_and_dns_option() {
        let transaction_id = 0x0102_0304;
        assert_eq!(
            parse_dhcp_offer(
                &offer(
                    transaction_id,
                    MESSAGE_OFFER,
                    Some(&[1, 1, 1, 1, 8, 8, 8, 8])
                ),
                transaction_id,
            ),
            DhcpOffer::DnsServers(vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)])
        );
        assert_eq!(
            parse_dhcp_offer(&offer(transaction_id, MESSAGE_OFFER, None), transaction_id),
            DhcpOffer::MissingDns
        );
        assert_eq!(
            parse_dhcp_offer(
                &offer(transaction_id, MESSAGE_OFFER, Some(&[1, 1, 1, 1])),
                transaction_id + 1,
            ),
            DhcpOffer::Ignored
        );
        assert_eq!(
            parse_dhcp_offer(
                &offer(transaction_id, 5, Some(&[1, 1, 1, 1])),
                transaction_id,
            ),
            DhcpOffer::Ignored
        );
    }

    #[test]
    fn refresh_tracks_twenty_seconds_one_hour_and_address_changes() {
        let first = Ipv4Addr::new(192, 0, 2, 10);
        let second = Ipv4Addr::new(192, 0, 2, 11);
        let mut tracker = DhcpRefreshTracker::default();
        assert_eq!(
            tracker.observe(Duration::ZERO, Some(first)),
            DhcpRefreshDecision::Refresh
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(19), Some(second)),
            DhcpRefreshDecision::Cached
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(20), Some(first)),
            DhcpRefreshDecision::Cached
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(40), Some(second)),
            DhcpRefreshDecision::Refresh
        );
        assert_eq!(
            tracker.observe(Duration::from_mins(1), None),
            DhcpRefreshDecision::InterfaceError
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(61), Some(second)),
            DhcpRefreshDecision::Cached
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(3_640), Some(second)),
            DhcpRefreshDecision::Refresh
        );
    }

    #[test]
    fn interface_snapshot_uses_first_non_link_local_ipv4_and_mac() {
        let interface = NetworkInterface {
            name: "fixture0".to_owned(),
            addr: vec![
                Addr::V4(network_interface::V4IfAddr {
                    ip: Ipv4Addr::new(169, 254, 1, 2),
                    broadcast: None,
                    netmask: None,
                }),
                Addr::V4(network_interface::V4IfAddr {
                    ip: Ipv4Addr::new(192, 0, 2, 10),
                    broadcast: None,
                    netmask: None,
                }),
            ],
            mac_addr: Some("00:11:22:33:44:55".to_owned()),
            index: 7,
            internal: false,
        };
        assert_eq!(
            snapshot_from_interface(&interface).expect("interface snapshot"),
            DhcpInterfaceSnapshot {
                index: 7,
                ipv4: Ipv4Addr::new(192, 0, 2, 10),
                hardware_address: [0, 17, 34, 51, 68, 85],
            }
        );
    }
}
