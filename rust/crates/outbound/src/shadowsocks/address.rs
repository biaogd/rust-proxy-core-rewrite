use std::net::IpAddr;

use rewrite_model::{Destination, Host};

pub(crate) fn serialize_socks_addr(destination: &Destination) -> Vec<u8> {
    match &destination.host {
        Host::Domain(domain) => {
            let domain = domain.as_bytes();
            let mut buf = Vec::with_capacity(1 + 1 + domain.len() + 2);
            buf.push(3);
            buf.push(
                u8::try_from(domain.len()).expect("domain length validated by upstream routing"),
            );
            buf.extend_from_slice(domain);
            buf.extend_from_slice(&destination.port.to_be_bytes());
            buf
        }
        Host::Ip(IpAddr::V4(address)) => {
            let mut buf = Vec::with_capacity(1 + 4 + 2);
            buf.push(1);
            buf.extend_from_slice(&address.octets());
            buf.extend_from_slice(&destination.port.to_be_bytes());
            buf
        }
        Host::Ip(IpAddr::V6(address)) => {
            let mut buf = Vec::with_capacity(1 + 16 + 2);
            buf.push(4);
            buf.extend_from_slice(&address.octets());
            buf.extend_from_slice(&destination.port.to_be_bytes());
            buf
        }
    }
}
