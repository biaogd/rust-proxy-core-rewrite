use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine;
use rewrite_model::{AuthUser, Destination, Host, InboundProtocol, Metadata, Network};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

const MAX_HTTP_HEADER: usize = 64 * 1024;

struct ParsedHttpHead {
    method: String,
    target: String,
    version: &'static str,
    headers: Vec<(String, Vec<u8>)>,
    body_offset: usize,
}

pub struct AcceptedTcp {
    pub client: TcpStream,
    pub metadata: Metadata,
    pub preface: Vec<u8>,
    pub command: InboundCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundCommand {
    Connect,
    UdpAssociate,
}

pub struct AcceptedUdp<'a> {
    pub metadata: Metadata,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerProtocol {
    Http,
    Socks,
    Mixed,
}

#[derive(Debug, Error)]
pub enum InboundError {
    #[error("inbound I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid HTTP proxy request: {0}")]
    Http(&'static str),
    #[error("invalid SOCKS5 request: {0}")]
    Socks(&'static str),
    #[error("proxy authentication rejected")]
    Authentication,
    #[error("unsupported mixed inbound protocol")]
    UnsupportedProtocol,
}

/// Detects and decodes one Phase 1 HTTP or SOCKS5 TCP inbound connection.
///
/// # Errors
///
/// Returns [`InboundError`] for I/O failures, malformed handshakes, unsupported
/// SOCKS4 input, or HTTP behavior outside the Phase 1 surface.
pub async fn accept_mixed(client: TcpStream) -> Result<AcceptedTcp, InboundError> {
    accept(client, ListenerProtocol::Mixed, &[]).await
}

/// Decodes one authenticated Phase 3A local TCP proxy connection.
///
/// # Errors
///
/// Returns [`InboundError`] for I/O failures, malformed HTTP/SOCKS handshakes,
/// unsupported commands or rejected credentials.
pub async fn accept(
    client: TcpStream,
    protocol: ListenerProtocol,
    users: &[AuthUser],
) -> Result<AcceptedTcp, InboundError> {
    match protocol {
        ListenerProtocol::Http => accept_http(client, users).await,
        ListenerProtocol::Socks => accept_socks(client, users).await,
        ListenerProtocol::Mixed => accept_detected(client, users).await,
    }
}

/// Decodes an RFC 1928 SOCKS5 UDP request with fragmentation disabled.
///
/// # Errors
///
/// Returns [`InboundError`] for truncated packets, nonzero FRAG or unsupported
/// address types.
pub fn decode_socks5_udp(
    packet: &[u8],
    source: SocketAddr,
    inbound_port: u16,
) -> Result<AcceptedUdp<'_>, InboundError> {
    if packet.len() < 4 || packet[..2] != [0, 0] || packet[2] != 0 {
        return Err(InboundError::Socks("invalid UDP header"));
    }
    let (host, port, address_len) = decode_socks_address(&packet[3..])?;
    let payload_start = 3 + address_len;
    let mut metadata = Metadata::new(Destination { host, port }, InboundProtocol::Socks5);
    metadata.network = Network::Udp;
    metadata.source_ip = Some(source.ip());
    metadata.source_port = source.port();
    metadata.inbound_port = inbound_port;
    Ok(AcceptedUdp {
        metadata,
        payload: &packet[payload_start..],
    })
}

#[must_use]
pub fn encode_socks5_udp(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match source.ip() {
        IpAddr::V4(address) => {
            packet.push(1);
            packet.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            packet.push(4);
            packet.extend_from_slice(&address.octets());
        }
    }
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn decode_socks_address(packet: &[u8]) -> Result<(Host, u16, usize), InboundError> {
    match packet.first().copied() {
        Some(1) if packet.len() >= 7 => Ok((
            Host::Ip(IpAddr::V4(Ipv4Addr::new(
                packet[1], packet[2], packet[3], packet[4],
            ))),
            u16::from_be_bytes([packet[5], packet[6]]),
            7,
        )),
        Some(4) if packet.len() >= 19 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&packet[1..17]);
            Ok((
                Host::Ip(IpAddr::V6(Ipv6Addr::from(octets))),
                u16::from_be_bytes([packet[17], packet[18]]),
                19,
            ))
        }
        Some(3) if packet.len() >= 2 => {
            let length = usize::from(packet[1]);
            if packet.len() < length + 4 {
                return Err(InboundError::Socks("truncated UDP domain"));
            }
            let domain = std::str::from_utf8(&packet[2..(2 + length)])
                .map_err(|_| InboundError::Socks("UDP domain is not UTF-8"))?;
            Ok((
                Host::Domain(domain.trim_end_matches('.').to_owned()),
                u16::from_be_bytes([packet[2 + length], packet[3 + length]]),
                length + 4,
            ))
        }
        _ => Err(InboundError::Socks("unsupported UDP address")),
    }
}

async fn accept_detected(
    client: TcpStream,
    users: &[AuthUser],
) -> Result<AcceptedTcp, InboundError> {
    let mut first = [0_u8; 1];
    let read = client.peek(&mut first).await?;
    if read == 0 {
        return Err(InboundError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        )));
    }
    match first[0] {
        0x04 | 0x05 => accept_socks(client, users).await,
        _ => accept_http(client, users).await,
    }
}

async fn accept_socks(client: TcpStream, users: &[AuthUser]) -> Result<AcceptedTcp, InboundError> {
    let mut first = [0_u8; 1];
    if client.peek(&mut first).await? == 0 {
        return Err(InboundError::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        )));
    }
    match first[0] {
        0x04 => accept_socks4(client, users).await,
        0x05 => accept_socks5(client, users).await,
        _ => Err(InboundError::UnsupportedProtocol),
    }
}

async fn accept_socks5(
    mut client: TcpStream,
    users: &[AuthUser],
) -> Result<AcceptedTcp, InboundError> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        return Err(InboundError::Socks("invalid version"));
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;

    // Preserve the oracle's method-selection behavior. Configured credentials
    // force username/password even when the client did not advertise it; with
    // no credentials, a sole 0x02 offer installs an always-valid authenticator.
    let selected_method = if !users.is_empty() || methods.as_slice() == [2] {
        2
    } else {
        0
    };
    client.write_all(&[5, selected_method]).await?;
    let inbound_user = if selected_method == 2 {
        authenticate_socks5(&mut client, users).await?
    } else {
        String::new()
    };

    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await?;
    if request[0] != 5 || !matches!(request[1], 1 | 3) || request[2] != 0 {
        return Err(InboundError::Socks("unsupported command"));
    }
    let command = if request[1] == 3 {
        InboundCommand::UdpAssociate
    } else {
        InboundCommand::Connect
    };

    let host = match request[3] {
        1 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        3 => {
            let length = client.read_u8().await?;
            let mut domain = vec![0_u8; usize::from(length)];
            client.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain)
                .map_err(|_| InboundError::Socks("domain is not UTF-8"))?;
            Host::Domain(domain.trim_end_matches('.').to_owned())
        }
        4 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => return Err(InboundError::Socks("unsupported address type")),
    };
    let port = client.read_u16().await?;

    let local = client.local_addr()?;
    let mut reply = vec![5, 0, 0];
    match local.ip() {
        IpAddr::V4(address) => {
            reply.push(1);
            reply.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            reply.push(4);
            reply.extend_from_slice(&address.octets());
        }
    }
    reply.extend_from_slice(&local.port().to_be_bytes());
    client.write_all(&reply).await?;

    let mut metadata =
        socket_metadata(&client, Destination { host, port }, InboundProtocol::Socks5);
    metadata.inbound_user = inbound_user;
    Ok(AcceptedTcp {
        metadata,
        client,
        preface: Vec::new(),
        command,
    })
}

async fn authenticate_socks5(
    client: &mut TcpStream,
    users: &[AuthUser],
) -> Result<String, InboundError> {
    let mut header = [0_u8; 2];
    client.read_exact(&mut header).await?;
    let user_len = usize::from(header[1]);
    if user_len == 0 {
        client.write_all(&[1, 1]).await?;
        return Err(InboundError::Authentication);
    }
    let mut username = vec![0_u8; user_len];
    client.read_exact(&mut username).await?;
    let pass_len = usize::from(client.read_u8().await?);
    if pass_len == 0 {
        client.write_all(&[1, 1]).await?;
        return Err(InboundError::Authentication);
    }
    let mut password = vec![0_u8; pass_len];
    client.read_exact(&mut password).await?;
    let accepted = users.is_empty()
        || users.iter().any(|candidate| {
            candidate.username.as_bytes() == username && candidate.password.as_bytes() == password
        });
    client.write_all(&[1, u8::from(!accepted)]).await?;
    if accepted {
        Ok(String::from_utf8_lossy(&username).into_owned())
    } else {
        Err(InboundError::Authentication)
    }
}

async fn accept_socks4(
    mut client: TcpStream,
    users: &[AuthUser],
) -> Result<AcceptedTcp, InboundError> {
    let mut request = [0_u8; 8];
    client.read_exact(&mut request).await?;
    if request[0] != 4 || request[1] != 1 {
        return Err(InboundError::Socks("unsupported SOCKS4 command"));
    }
    let port = u16::from_be_bytes([request[2], request[3]]);
    let address = Ipv4Addr::new(request[4], request[5], request[6], request[7]);
    let username = read_nul_terminated(&mut client).await?;
    let host = if request[4..7] == [0, 0, 0] && request[7] != 0 {
        let domain = read_nul_terminated(&mut client).await?;
        let domain = String::from_utf8(domain)
            .map_err(|_| InboundError::Socks("SOCKS4a domain is not UTF-8"))?;
        Host::Domain(domain.trim_end_matches('.').to_owned())
    } else {
        Host::Ip(IpAddr::V4(address))
    };
    let accepted = users.is_empty()
        || users.iter().any(|candidate| {
            candidate.username.as_bytes() == username && candidate.password.is_empty()
        });
    let mut reply = request;
    reply[0] = 0;
    reply[1] = if accepted { 0x5a } else { 0x5d };
    client.write_all(&reply).await?;
    if !accepted {
        return Err(InboundError::Authentication);
    }
    let inbound_user = String::from_utf8_lossy(&username).into_owned();
    let mut metadata =
        socket_metadata(&client, Destination { host, port }, InboundProtocol::Socks4);
    metadata.inbound_user = inbound_user;
    Ok(AcceptedTcp {
        metadata,
        client,
        preface: Vec::new(),
        command: InboundCommand::Connect,
    })
}

async fn read_nul_terminated(client: &mut TcpStream) -> Result<Vec<u8>, InboundError> {
    let mut value = Vec::new();
    loop {
        let byte = client.read_u8().await?;
        if byte == 0 {
            return Ok(value);
        }
        if value.len() == 255 {
            return Err(InboundError::Socks("SOCKS4 field is too long"));
        }
        value.push(byte);
    }
}

async fn accept_http(
    mut client: TcpStream,
    users: &[AuthUser],
) -> Result<AcceptedTcp, InboundError> {
    let (bytes, request) = read_http_head(&mut client).await?;
    let inbound_user =
        authenticate_http(&mut client, request.version, &request.headers, users).await?;

    if request.method.eq_ignore_ascii_case("CONNECT") {
        let destination = parse_authority(&request.target, None)?;
        client
            .write_all(format!("{} 200 Connection established\r\n\r\n", request.version).as_bytes())
            .await?;
        let mut metadata = socket_metadata(&client, destination, InboundProtocol::Https);
        metadata.inbound_user = inbound_user;
        return Ok(AcceptedTcp {
            metadata,
            client,
            preface: bytes[request.body_offset..].to_vec(),
            command: InboundCommand::Connect,
        });
    }

    let url = Url::parse(&request.target)
        .map_err(|_| InboundError::Http("target is not absolute-form"))?;
    if url.scheme() != "http" {
        return Err(InboundError::Http("only http absolute-form is in Phase 1"));
    }
    let host = url
        .host_str()
        .ok_or(InboundError::Http("URL has no host"))?;
    let destination = parse_authority(host, Some(url.port().unwrap_or(80)))?;
    let origin = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };

    let mut rewritten = format!("{} {origin} {}\r\n", request.method, request.version).into_bytes();
    let mut saw_host = false;
    for (name, value) in request.headers {
        if name.eq_ignore_ascii_case("host") {
            saw_host = true;
        }
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        rewritten.extend_from_slice(name.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(&value);
        rewritten.extend_from_slice(b"\r\n");
    }
    if !saw_host {
        rewritten.extend_from_slice(format!("Host: {}\r\n", destination.authority()).as_bytes());
    }
    rewritten.extend_from_slice(b"\r\n");
    rewritten.extend_from_slice(&bytes[request.body_offset..]);

    let mut metadata = socket_metadata(&client, destination, InboundProtocol::Http);
    metadata.inbound_user = inbound_user;
    Ok(AcceptedTcp {
        metadata,
        client,
        preface: rewritten,
        command: InboundCommand::Connect,
    })
}

async fn authenticate_http(
    client: &mut TcpStream,
    version: &str,
    headers: &[(String, Vec<u8>)],
    users: &[AuthUser],
) -> Result<String, InboundError> {
    if users.is_empty() {
        return Ok(String::new());
    }
    let credential = headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("proxy-authorization")
            .then(|| std::str::from_utf8(value).ok())
            .flatten()
    });
    let basic_credential = credential.and_then(|value| {
        value
            .get(..6)
            .filter(|prefix| prefix.eq_ignore_ascii_case("Basic "))
            .map(|_| &value[6..])
    });
    let Some(basic_credential) = basic_credential else {
        client
            .write_all(
                format!(
                    "{version} 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n"
                )
                .as_bytes(),
            )
            .await?;
        return Err(InboundError::Authentication);
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(basic_credential)
        .ok()
        .and_then(|plain| {
            let split = plain.iter().position(|byte| *byte == b':')?;
            Some((plain[..split].to_vec(), plain[(split + 1)..].to_vec()))
        });
    let authenticated = decoded.and_then(|(username, password)| {
        users.iter().find_map(|candidate| {
            (candidate.username.as_bytes() == username && candidate.password.as_bytes() == password)
                .then(|| candidate.username.clone())
        })
    });
    if let Some(username) = authenticated {
        Ok(username)
    } else {
        client
            .write_all(format!("{version} 403 Forbidden\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await?;
        Err(InboundError::Authentication)
    }
}

fn socket_metadata(
    client: &TcpStream,
    destination: Destination,
    inbound: InboundProtocol,
) -> Metadata {
    let mut metadata = Metadata::new(destination, inbound);
    if let Ok(peer) = client.peer_addr() {
        metadata.source_ip = Some(peer.ip());
        metadata.source_port = peer.port();
    }
    if let Ok(local) = client.local_addr() {
        metadata.inbound_port = local.port();
    }
    metadata
}

async fn read_http_head(client: &mut TcpStream) -> Result<(Vec<u8>, ParsedHttpHead), InboundError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(request) = parse_http_head(&bytes)? {
            return Ok((bytes, request));
        }
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(InboundError::Http("unexpected EOF"));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_HTTP_HEADER {
            return Err(InboundError::Http("header is too large"));
        }
    }
}

fn parse_http_head(bytes: &[u8]) -> Result<Option<ParsedHttpHead>, InboundError> {
    let capacity = (bytes.len() / 2).max(1);
    let mut headers = vec![httparse::EMPTY_HEADER; capacity];
    let mut request = httparse::Request::new(&mut headers);
    let status = request
        .parse(bytes)
        .map_err(|_| InboundError::Http("malformed HTTP request"))?;
    let httparse::Status::Complete(body_offset) = status else {
        return Ok(None);
    };
    std::str::from_utf8(&bytes[..body_offset])
        .map_err(|_| InboundError::Http("header is not UTF-8"))?;
    let method = request
        .method
        .ok_or(InboundError::Http("missing method"))?
        .to_owned();
    let target = request
        .path
        .ok_or(InboundError::Http("missing target"))?
        .to_owned();
    let version = match request.version {
        Some(0) => "HTTP/1.0",
        Some(1) => "HTTP/1.1",
        _ => return Err(InboundError::Http("unsupported HTTP version")),
    };
    let headers = request
        .headers
        .iter()
        .map(|header| (header.name.to_owned(), header.value.to_vec()))
        .collect();
    Ok(Some(ParsedHttpHead {
        method,
        target,
        version,
        headers,
        body_offset,
    }))
}

fn parse_authority(
    authority: &str,
    default_port: Option<u16>,
) -> Result<Destination, InboundError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or(InboundError::Http("malformed IPv6 authority"))?;
        let port = suffix
            .strip_prefix(':')
            .map(str::parse)
            .transpose()
            .map_err(|_| InboundError::Http("invalid port"))?
            .or(default_port)
            .ok_or(InboundError::Http("missing port"))?;
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse()
            .map_err(|_| InboundError::Http("invalid port"))?;
        (host, port)
    } else {
        (
            authority,
            default_port.ok_or(InboundError::Http("missing port"))?,
        )
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err(InboundError::Http("empty host"));
    }
    Ok(Destination {
        host: host
            .parse::<IpAddr>()
            .map_or_else(|_| Host::Domain(host.to_owned()), Host::Ip),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_and_ipv6_authorities() {
        assert_eq!(
            parse_authority("example.com:443", None)
                .expect("domain authority")
                .authority(),
            "example.com:443"
        );
        assert_eq!(
            parse_authority("[::1]:80", None)
                .expect("IPv6 authority")
                .authority(),
            "[::1]:80"
        );
    }

    #[test]
    fn parses_http_head_with_library_and_preserves_body_offset() {
        let bytes = b"POST http://example.com/a HTTP/1.1\r\nHost: example.com\r\nX-Test: value\r\n\r\npayload";
        let request = parse_http_head(bytes)
            .expect("valid HTTP request")
            .expect("complete HTTP request");
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "http://example.com/a");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(&bytes[request.body_offset..], b"payload");
        assert_eq!(request.headers[1].1, b"value");
    }

    #[test]
    fn decodes_udp_rule_metadata_without_tcp_auth_identity() {
        let source = SocketAddr::from(([127, 0, 0, 1], 40_001));
        let packet = [0, 0, 0, 1, 127, 0, 0, 1, 0x20, 0x21, b'u', b'd', b'p'];
        let accepted = decode_socks5_udp(&packet, source, 10_800).expect("UDP packet");
        assert_eq!(accepted.metadata.network, Network::Udp);
        assert_eq!(accepted.metadata.inbound, InboundProtocol::Socks5);
        assert_eq!(accepted.metadata.source_ip, Some(source.ip()));
        assert_eq!(accepted.metadata.source_port, source.port());
        assert_eq!(accepted.metadata.destination.port, 0x2021);
        assert_eq!(accepted.metadata.inbound_port, 10_800);
        assert_eq!(accepted.metadata.dscp, 0);
        assert!(accepted.metadata.inbound_user.is_empty());
        assert_eq!(accepted.payload, b"udp");
    }
}
