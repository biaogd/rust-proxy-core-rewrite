use std::net::Ipv4Addr;

use rewrite_platform::{DhcpOffer, build_dhcp_discover, parse_dhcp_offer};

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command] if command == "discover" => {
            let packet =
                build_dhcp_discover(0x1234_5678, [0, 1, 2, 3, 4, 5]).expect("fixed DHCPDISCOVER");
            println!("{}", encode_hex(&packet));
        }
        [command, wire] if command == "parse" => {
            let Ok(packet) = decode_hex(wire) else {
                eprintln!("invalid hex packet");
                std::process::exit(2);
            };
            match parse_dhcp_offer(&packet, 0x1234_5678) {
                DhcpOffer::Ignored => println!("ignored"),
                DhcpOffer::MissingDns => println!("missing-dns"),
                DhcpOffer::DnsServers(servers) => println!("servers:{}", render_servers(&servers)),
            }
        }
        _ => {
            eprintln!("usage: dhcp-contract discover | parse HEX");
            std::process::exit(2);
        }
    }
}

fn render_servers(servers: &[Ipv4Addr]) -> String {
    servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or(())?;
            let low = hex_digit(pair[1]).ok_or(())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
