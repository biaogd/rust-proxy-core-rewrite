//! IN-D basic VLESS server-side request decoding.
//!
//! Vision, REALITY, and any XUDP/packet-addr UDP packet mode stay out of this
//! slice: only the version-zero, no-addon TCP/UDP request shapes that
//! `stream.rs` / `packet.rs` already produce on the client side are accepted
//! here. A non-empty addon list is rejected rather than silently accepted,
//! since Vision negotiation is deferred.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use rewrite_model::{Destination, Host};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use uuid::Uuid;

use crate::VlessProtocolError;

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessCommand {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessServerRequest {
    pub command: VlessCommand,
    pub destination: Destination,
    pub username: String,
}

/// Maps a configured `uuid` field to the 16-byte VLESS identifier.
///
/// Matches the outbound `parse_vless` behavior: a valid UUID string is used
/// as-is, otherwise the text is folded into a stable v5 UUID (namespace nil)
/// so non-UUID identifiers still produce a deterministic 16-byte value.
#[must_use]
pub fn map_uuid(text: &str) -> [u8; 16] {
    Uuid::parse_str(text)
        .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), text.as_bytes()))
        .into_bytes()
}

/// Builds a lookup table from configured users to their 16-byte VLESS UUIDs.
#[must_use]
pub fn uuid_table<'a>(
    users: impl IntoIterator<Item = (&'a str, String)>,
) -> HashMap<[u8; 16], String> {
    users
        .into_iter()
        .map(|(uuid, username)| (map_uuid(uuid), username))
        .collect()
}

/// Reads and authenticates one VLESS request header, then writes the
/// response header (`[0, 0]`) immediately, matching the Go server which
/// replies before relaying any data.
///
/// # Errors
///
/// Returns [`VlessProtocolError::Protocol`] for an unsupported version,
/// non-empty addons (Vision deferred), unknown UUID, unsupported command, or
/// malformed address; returns [`VlessProtocolError::Io`] for transport
/// failures.
pub async fn accept_vless_request<S>(
    stream: &mut S,
    users: &HashMap<[u8; 16], String>,
) -> Result<VlessServerRequest, VlessProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut version = [0_u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != VERSION {
        return Err(VlessProtocolError::Protocol(format!(
            "unsupported VLESS request version {}",
            version[0]
        )));
    }

    let mut uuid = [0_u8; 16];
    stream.read_exact(&mut uuid).await?;
    let username = users
        .get(&uuid)
        .cloned()
        .ok_or_else(|| VlessProtocolError::Protocol("unknown VLESS uuid".to_owned()))?;

    let mut addon_length = [0_u8; 1];
    stream.read_exact(&mut addon_length).await?;
    if addon_length[0] != 0 {
        let mut discard = vec![0_u8; usize::from(addon_length[0])];
        stream.read_exact(&mut discard).await?;
        return Err(VlessProtocolError::Protocol(
            "VLESS request addons are not supported (Vision deferred)".to_owned(),
        ));
    }

    let mut command = [0_u8; 1];
    stream.read_exact(&mut command).await?;
    let command = match command[0] {
        COMMAND_TCP => VlessCommand::Tcp,
        COMMAND_UDP => VlessCommand::Udp,
        other => {
            return Err(VlessProtocolError::Protocol(format!(
                "unsupported VLESS command {other}"
            )));
        }
    };

    let mut port = [0_u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    let mut address_type = [0_u8; 1];
    stream.read_exact(&mut address_type).await?;
    let host = match address_type[0] {
        ADDRESS_IPV4 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::Ip(Ipv4Addr::from(octets).into())
        }
        ADDRESS_IPV6 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::Ip(Ipv6Addr::from(octets).into())
        }
        ADDRESS_DOMAIN => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut domain = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| {
                VlessProtocolError::Protocol("VLESS request domain is not UTF-8".to_owned())
            })?;
            Host::Domain(domain)
        }
        other => {
            return Err(VlessProtocolError::Protocol(format!(
                "unsupported VLESS address type {other}"
            )));
        }
    };

    stream.write_all(&[VERSION, 0]).await?;

    Ok(VlessServerRequest {
        command,
        destination: Destination { host, port },
        username,
    })
}

/// Reads one standard-mode VLESS UDP payload: a 2-byte big-endian length
/// prefix followed by the payload body.
///
/// # Errors
///
/// Returns [`VlessProtocolError::Io`] when the transport closes or fails
/// before the framed payload is fully read.
pub async fn read_vless_udp_payload<S>(stream: &mut S) -> Result<Vec<u8>, VlessProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    stream.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Writes one standard-mode VLESS UDP payload as a 2-byte big-endian length
/// prefix followed by the payload body.
///
/// # Errors
///
/// Returns [`VlessProtocolError::Protocol`] when the payload exceeds 65535
/// bytes, or [`VlessProtocolError::Io`] for transport failures.
pub async fn write_vless_udp_payload<S>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), VlessProtocolError>
where
    S: AsyncWrite + Unpin,
{
    let length = u16::try_from(payload.len())
        .map_err(|_| VlessProtocolError::Protocol("VLESS UDP payload exceeds 65535 bytes".to_owned()))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn users() -> HashMap<[u8; 16], String> {
        uuid_table([(UUID_TEXT, "alice".to_owned())])
    }

    #[test]
    fn map_uuid_parses_valid_uuid() {
        let mapped = map_uuid(UUID_TEXT);
        assert_eq!(mapped, Uuid::parse_str(UUID_TEXT).unwrap().into_bytes());
    }

    #[test]
    fn map_uuid_folds_non_uuid_text_deterministically() {
        let first = map_uuid("not-a-uuid");
        let second = map_uuid("not-a-uuid");
        assert_eq!(first, second);
        assert_ne!(first, map_uuid("also-not-a-uuid"));
    }

    #[tokio::test]
    async fn accepts_tcp_request_and_writes_response_immediately() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        let request_task = tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(0); // addon length
            request.push(COMMAND_TCP);
            request.extend_from_slice(&443_u16.to_be_bytes());
            request.push(ADDRESS_DOMAIN);
            request.push(7);
            request.extend_from_slice(b"example");
            client.write_all(&request).await.unwrap();
            let mut response = [0_u8; 2];
            client.read_exact(&mut response).await.unwrap();
            response
        });
        let request = accept_vless_request(&mut server, &users())
            .await
            .expect("valid request");
        assert_eq!(request.command, VlessCommand::Tcp);
        assert_eq!(request.username, "alice");
        assert_eq!(
            request.destination,
            Destination {
                host: Host::Domain("example".to_owned()),
                port: 443,
            }
        );
        let response = request_task.await.unwrap();
        assert_eq!(response, [0, 0]);
    }

    #[tokio::test]
    async fn accepts_udp_command_and_ipv4_address() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(0);
            request.push(COMMAND_UDP);
            request.extend_from_slice(&53_u16.to_be_bytes());
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&[192, 0, 2, 7]);
            client.write_all(&request).await.unwrap();
            let mut response = [0_u8; 2];
            client.read_exact(&mut response).await.unwrap();
        });
        let request = accept_vless_request(&mut server, &users())
            .await
            .expect("valid udp request");
        assert_eq!(request.command, VlessCommand::Udp);
        assert_eq!(
            request.destination,
            Destination {
                host: Host::Ip(Ipv4Addr::new(192, 0, 2, 7).into()),
                port: 53,
            }
        );
    }

    #[tokio::test]
    async fn accepts_ipv6_address() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(0);
            request.push(COMMAND_TCP);
            request.extend_from_slice(&443_u16.to_be_bytes());
            request.push(ADDRESS_IPV6);
            request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            client.write_all(&request).await.unwrap();
            let mut response = [0_u8; 2];
            client.read_exact(&mut response).await.unwrap();
        });
        let request = accept_vless_request(&mut server, &users())
            .await
            .expect("valid ipv6 request");
        assert_eq!(
            request.destination.host,
            Host::Ip(Ipv6Addr::LOCALHOST.into())
        );
    }

    #[tokio::test]
    async fn rejects_unknown_uuid() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&[0xff; 16]);
            request.push(0);
            request.push(COMMAND_TCP);
            request.extend_from_slice(&443_u16.to_be_bytes());
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&[127, 0, 0, 1]);
            let _ = client.write_all(&request).await;
        });
        let error = accept_vless_request(&mut server, &users())
            .await
            .expect_err("unknown uuid must be rejected");
        assert!(matches!(error, VlessProtocolError::Protocol(_)));
    }

    #[tokio::test]
    async fn rejects_nonempty_addons() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(1);
            request.push(0xaa);
            let _ = client.write_all(&request).await;
        });
        let error = accept_vless_request(&mut server, &users())
            .await
            .expect_err("addons must be rejected in this slice");
        assert!(matches!(error, VlessProtocolError::Protocol(_)));
    }

    #[tokio::test]
    async fn rejects_unsupported_command() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(0);
            request.push(3); // COMMAND_MUX
            let _ = client.write_all(&request).await;
        });
        let error = accept_vless_request(&mut server, &users())
            .await
            .expect_err("mux must be rejected in this slice");
        assert!(matches!(error, VlessProtocolError::Protocol(_)));
    }

    #[tokio::test]
    async fn udp_payload_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let payload = b"vless-udp-payload".to_vec();
        let write_payload = payload.clone();
        tokio::spawn(async move {
            write_vless_udp_payload(&mut client, &write_payload)
                .await
                .expect("write payload");
        });
        let read = read_vless_udp_payload(&mut server)
            .await
            .expect("read payload");
        assert_eq!(read, payload);
    }
}
