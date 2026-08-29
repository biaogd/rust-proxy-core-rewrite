use std::fmt;
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

impl fmt::Display for Host {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(formatter),
            Self::Domain(domain) => domain.fmt(formatter),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    pub host: Host,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShadowsocksPluginConfig {
    SimpleObfsHttp { host: String },
    SimpleObfsTls { host: String },
}

impl Destination {
    #[must_use]
    pub fn authority(&self) -> String {
        match self.host {
            Host::Ip(IpAddr::V6(address)) => format!("[{address}]:{}", self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundProtocol {
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub destination: Destination,
    pub inbound: InboundProtocol,
    pub network: Network,
    pub host: String,
    pub sniff_host: String,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub source_port: u16,
    pub inbound_port: u16,
    pub inbound_name: String,
    pub inbound_user: String,
    pub dscp: u8,
    pub rematch_name: String,
    pub special_rules: String,
}

impl Metadata {
    #[must_use]
    pub fn new(mut destination: Destination, inbound: InboundProtocol) -> Self {
        let (host, destination_ip) = match destination.host.clone() {
            Host::Ip(address) => {
                let address = unmap_ip(address);
                destination.host = Host::Ip(address);
                (String::new(), Some(address))
            }
            Host::Domain(domain) => (domain, None),
        };
        Self {
            destination,
            inbound,
            network: Network::Tcp,
            host,
            sniff_host: String::new(),
            source_ip: None,
            destination_ip,
            source_port: 0,
            inbound_port: 0,
            inbound_name: String::new(),
            inbound_user: String::new(),
            dscp: 0,
            rematch_name: String::new(),
            special_rules: String::new(),
        }
    }

    #[must_use]
    pub fn rule_host(&self) -> &str {
        if self.sniff_host.is_empty() {
            &self.host
        } else {
            &self.sniff_host
        }
    }
}

/// Converts an IPv4-mapped IPv6 address to its IPv4 form, matching the Go
/// tunnel metadata boundary. Other addresses are returned unchanged.
#[must_use]
pub fn unmap_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address @ IpAddr::V4(_) => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn metadata_unmaps_ipv4_mapped_destinations() {
        let mapped = "::ffff:127.0.0.1".parse().expect("mapped IPv6");
        let metadata = Metadata::new(
            Destination {
                host: Host::Ip(mapped),
                port: 80,
            },
            InboundProtocol::Https,
        );
        assert_eq!(
            metadata.destination.host,
            Host::Ip(Ipv4Addr::LOCALHOST.into())
        );
        assert_eq!(metadata.destination_ip, Some(Ipv4Addr::LOCALHOST.into()));
    }
}
