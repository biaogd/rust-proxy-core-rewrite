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
    pub inbound_user: String,
    pub rematch_name: String,
    pub special_rules: String,
}

impl Metadata {
    #[must_use]
    pub fn new(destination: Destination, inbound: InboundProtocol) -> Self {
        let (host, destination_ip) = match &destination.host {
            Host::Ip(address) => (String::new(), Some(*address)),
            Host::Domain(domain) => (domain.clone(), None),
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
            inbound_user: String::new(),
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
