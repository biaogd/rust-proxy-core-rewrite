//! IN-D VLESS server-side request decoding.
//!
//! Accepts version-zero TCP, standard UDP, and mux/XUDP commands with optional
//! Vision flow addons. REALITY stays out of the request decoder.

use std::any::Any;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_model::{Destination, Host};
use rewrite_transport::GunStream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use uuid::Uuid;

use crate::VlessFlow;
use crate::VlessProtocolError;
use crate::addons::decode_flow_addon;

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;
const COMMAND_MUX: u8 = 3;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;
const VISION_FLOW: &str = "xtls-rprx-vision";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessCommand {
    Tcp,
    Udp,
    /// XUDP / mux UDP association (no address in the VLESS request header).
    Mux,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessUserEntry {
    pub username: String,
    pub flow: Option<VlessFlow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VlessServerRequest {
    pub command: VlessCommand,
    pub destination: Destination,
    pub username: String,
    pub uuid: [u8; 16],
    pub flow: Option<VlessFlow>,
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

fn user_flow_str(flow: Option<VlessFlow>) -> &'static str {
    match flow {
        Some(VlessFlow::XtlsRprxVision) => VISION_FLOW,
        None => "",
    }
}

fn parse_request_flow(flow: &str) -> Result<Option<VlessFlow>, VlessProtocolError> {
    if flow.is_empty() {
        return Ok(None);
    }
    let truncated = if flow.len() >= 16 { &flow[..16] } else { flow };
    if truncated == VISION_FLOW {
        Ok(Some(VlessFlow::XtlsRprxVision))
    } else {
        Err(VlessProtocolError::Protocol(format!(
            "unknown VLESS flow: {flow}"
        )))
    }
}

/// Builds a lookup table from configured users to their 16-byte VLESS UUIDs.
#[must_use]
pub fn uuid_table<'a>(
    users: impl IntoIterator<Item = (&'a str, VlessUserEntry)>,
) -> HashMap<[u8; 16], VlessUserEntry> {
    users
        .into_iter()
        .map(|(uuid, entry)| (map_uuid(uuid), entry))
        .collect()
}

/// Reads and authenticates one VLESS request header.
///
/// The response header (`[VERSION, 0]`) is **not** written here. Wrap the
/// accepted stream in [`VlessServerStream`] (matching Go `serverConn`) so the
/// response is coalesced with the first application write — critical for Gun
/// framing where an eager 2-byte write becomes its own h2 DATA frame.
///
/// # Errors
///
/// Returns [`VlessProtocolError::Protocol`] for an unsupported version,
/// flow mismatch, unknown UUID, unsupported command, or malformed address;
/// returns [`VlessProtocolError::Io`] for transport failures.
pub async fn accept_vless_request<S, H>(
    stream: &mut S,
    users: &HashMap<[u8; 16], VlessUserEntry, H>,
) -> Result<VlessServerRequest, VlessProtocolError>
where
    S: AsyncRead + Unpin,
    H: BuildHasher,
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
    let user = users
        .get(&uuid)
        .cloned()
        .ok_or_else(|| VlessProtocolError::Protocol("unknown VLESS uuid".to_owned()))?;

    let mut addon_length = [0_u8; 1];
    stream.read_exact(&mut addon_length).await?;
    let request_flow = if addon_length[0] == 0 {
        None
    } else {
        let mut addon_bytes = vec![0_u8; usize::from(addon_length[0])];
        stream.read_exact(&mut addon_bytes).await?;
        decode_flow_addon(&addon_bytes).map_err(VlessProtocolError::Protocol)?
    };
    let request_flow_str = request_flow.as_deref().unwrap_or("");
    let configured_flow_str = user_flow_str(user.flow);
    if request_flow_str != configured_flow_str && !request_flow_str.is_empty() {
        return Err(VlessProtocolError::Protocol(format!(
            "flow mismatch: expected {configured_flow_str}, but got {request_flow_str}"
        )));
    }
    let effective_flow = parse_request_flow(request_flow_str)?;

    let mut command = [0_u8; 1];
    stream.read_exact(&mut command).await?;
    let command = match command[0] {
        COMMAND_TCP => VlessCommand::Tcp,
        COMMAND_UDP => VlessCommand::Udp,
        COMMAND_MUX => VlessCommand::Mux,
        other => {
            return Err(VlessProtocolError::Protocol(format!(
                "unsupported VLESS command {other}"
            )));
        }
    };

    if effective_flow == Some(VlessFlow::XtlsRprxVision)
        && matches!(command, VlessCommand::Udp | VlessCommand::Mux)
    {
        return Err(VlessProtocolError::Protocol(format!(
            "{VISION_FLOW} flow does not support UDP"
        )));
    }

    let destination = if command == VlessCommand::Mux {
        // XUDP carries destinations inside mux frames; the request header has
        // no address field (matching Go sing-vless CommandMux).
        Destination {
            host: Host::Ip(Ipv4Addr::UNSPECIFIED.into()),
            port: 0,
        }
    } else {
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
        Destination { host, port }
    };

    Ok(VlessServerRequest {
        command,
        destination,
        username: user.username,
        uuid,
        flow: effective_flow,
    })
}

/// Server-side stream that lazily emits the VLESS response header.
///
/// Matches Go `sing_vless.serverConn`: the first `poll_write` prepends
/// `[VERSION, 0]` to the payload so Gun/TLS see one frame instead of a
/// solo 2-byte response DATA frame followed by bulk traffic.
pub struct VlessServerStream<S> {
    inner: S,
    /// `None` once the response header has been fully written.
    pending: Option<PendingResponseWrite>,
}

enum PendingResponseWrite {
    /// Response header not started; coalesce on the next non-empty write.
    Idle,
    /// GunStream accepted `prefix||payload` as one frame; drain in progress.
    GunPrefixed,
    /// Combined `[VERSION, 0] || payload` partially flushed (non-Gun carriers).
    Flushing {
        combined: Vec<u8>,
        offset: usize,
        /// Bytes of application payload represented by `combined[2..]`.
        payload_len: usize,
    },
}

impl<S> VlessServerStream<S> {
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending: Some(PendingResponseWrite::Idle),
        }
    }

    /// Returns true once the VLESS response header has been fully written.
    #[must_use]
    pub fn response_written(&self) -> bool {
        self.pending.is_none()
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessServerStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin + 'static> AsyncWrite for VlessServerStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        loop {
            match self.pending.take() {
                None => {
                    return Pin::new(&mut self.inner).poll_write(cx, buf);
                }
                Some(PendingResponseWrite::Idle) => {
                    // Empty writes must not emit a solo `[VERSION, 0]` frame
                    // (matches Go: header only rides with a real WriteBuffer).
                    if buf.is_empty() {
                        self.pending = Some(PendingResponseWrite::Idle);
                        return Poll::Ready(Ok(0));
                    }
                    // Probe: detect Gun without using prefix write — if this
                    // alone regresses, the Any downcast is the problem.
                    let _is_gun =
                        (&mut self.inner as &mut dyn Any).downcast_mut::<GunStream>().is_some();
                    let mut combined = Vec::with_capacity(2 + buf.len());
                    combined.extend_from_slice(&[VERSION, 0]);
                    combined.extend_from_slice(buf);
                    self.pending = Some(PendingResponseWrite::Flushing {
                        combined,
                        offset: 0,
                        payload_len: buf.len(),
                    });
                }
                Some(PendingResponseWrite::GunPrefixed) => {
                    // Kept for ABI stability if re-enabled; should be unreachable.
                    match Pin::new(&mut self.inner).poll_write(cx, buf) {
                        Poll::Pending => {
                            self.pending = Some(PendingResponseWrite::GunPrefixed);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(error)) => {
                            self.pending = None;
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(written)) => {
                            self.pending = None;
                            return Poll::Ready(Ok(written));
                        }
                    }
                }
                Some(PendingResponseWrite::Flushing {
                    combined,
                    mut offset,
                    payload_len,
                }) => {
                    while offset < combined.len() {
                        match Pin::new(&mut self.inner).poll_write(cx, &combined[offset..]) {
                            Poll::Pending => {
                                self.pending = Some(PendingResponseWrite::Flushing {
                                    combined,
                                    offset,
                                    payload_len,
                                });
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(error)) => {
                                self.pending = None;
                                return Poll::Ready(Err(error));
                            }
                            Poll::Ready(Ok(0)) => {
                                self.pending = None;
                                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                            }
                            Poll::Ready(Ok(written)) => offset += written,
                        }
                    }
                    self.pending = None;
                    return Poll::Ready(Ok(payload_len));
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // Do not emit the response header on flush alone (Go serverConn only
        // writes it from Write/WriteBuffer). An early copy_bidirectional flush
        // would otherwise recreate the solo 2-byte Gun DATA frame.
        if matches!(
            self.pending.as_ref(),
            Some(PendingResponseWrite::Flushing { .. })
        ) {
            let Some(PendingResponseWrite::Flushing {
                combined,
                mut offset,
                payload_len,
            }) = self.pending.take()
            else {
                unreachable!();
            };
            while offset < combined.len() {
                match Pin::new(&mut self.inner).poll_write(cx, &combined[offset..]) {
                    Poll::Pending => {
                        self.pending = Some(PendingResponseWrite::Flushing {
                            combined,
                            offset,
                            payload_len,
                        });
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => {
                        self.pending = None;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(0)) => {
                        self.pending = None;
                        return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Ready(Ok(written)) => offset += written,
                }
            }
            self.pending = None;
        } else if matches!(self.pending.as_ref(), Some(PendingResponseWrite::GunPrefixed)) {
            // Drain the in-flight prefixed frame but keep GunPrefixed so the
            // pending poll_write observes completion (does not re-frame).
            return Pin::new(&mut self.inner).poll_flush(cx);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
    let length = u16::try_from(payload.len()).map_err(|_| {
        VlessProtocolError::Protocol("VLESS UDP payload exceeds 65535 bytes".to_owned())
    })?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addons::encode_flow_addon;

    const UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn users(flow: Option<VlessFlow>) -> HashMap<[u8; 16], VlessUserEntry> {
        uuid_table([(
            UUID_TEXT,
            VlessUserEntry {
                username: "alice".to_owned(),
                flow,
            },
        )])
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
    async fn accepts_tcp_request_and_coalesces_lazy_response() {
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
            let mut payload = [0_u8; 5];
            client.read_exact(&mut payload).await.unwrap();
            (response, payload)
        });
        let request = accept_vless_request(&mut server, &users(None))
            .await
            .expect("valid request");
        assert_eq!(request.command, VlessCommand::Tcp);
        assert_eq!(request.username, "alice");
        assert_eq!(request.uuid, uuid);
        assert_eq!(request.flow, None);
        assert_eq!(
            request.destination,
            Destination {
                host: Host::Domain("example".to_owned()),
                port: 443,
            }
        );
        let mut server = VlessServerStream::new(server);
        server.write_all(b"hello").await.unwrap();
        let (response, payload) = request_task.await.unwrap();
        assert_eq!(response, [0, 0]);
        assert_eq!(&payload, b"hello");
    }

    #[tokio::test]
    async fn accepts_vision_flow_when_user_configured() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        let addons = encode_flow_addon(VISION_FLOW);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(u8::try_from(addons.len()).expect("addon length"));
            request.extend_from_slice(&addons);
            request.push(COMMAND_TCP);
            request.extend_from_slice(&443_u16.to_be_bytes());
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&[127, 0, 0, 1]);
            client.write_all(&request).await.unwrap();
            let mut response = [0_u8; 2];
            client.read_exact(&mut response).await.unwrap();
        });
        let request = accept_vless_request(&mut server, &users(Some(VlessFlow::XtlsRprxVision)))
            .await
            .expect("vision request");
        assert_eq!(request.flow, Some(VlessFlow::XtlsRprxVision));
        let mut server = VlessServerStream::new(server);
        server.write_all(b".").await.unwrap();
    }

    #[tokio::test]
    async fn rejects_vision_flow_mismatch() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        let addons = encode_flow_addon(VISION_FLOW);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(u8::try_from(addons.len()).expect("addon length"));
            request.extend_from_slice(&addons);
            request.push(COMMAND_TCP);
            request.extend_from_slice(&443_u16.to_be_bytes());
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&[127, 0, 0, 1]);
            let _ = client.write_all(&request).await;
        });
        let error = accept_vless_request(&mut server, &users(None))
            .await
            .expect_err("flow mismatch");
        assert!(matches!(error, VlessProtocolError::Protocol(_)));
    }

    #[tokio::test]
    async fn rejects_udp_with_vision_flow() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        let addons = encode_flow_addon(VISION_FLOW);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(u8::try_from(addons.len()).expect("addon length"));
            request.extend_from_slice(&addons);
            request.push(COMMAND_UDP);
            request.extend_from_slice(&53_u16.to_be_bytes());
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&[127, 0, 0, 1]);
            let _ = client.write_all(&request).await;
        });
        let error = accept_vless_request(&mut server, &users(Some(VlessFlow::XtlsRprxVision)))
            .await
            .expect_err("vision udp");
        assert!(matches!(error, VlessProtocolError::Protocol(_)));
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
        let request = accept_vless_request(&mut server, &users(None))
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
        let mut server = VlessServerStream::new(server);
        server.write_all(b".").await.unwrap();
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
        let request = accept_vless_request(&mut server, &users(None))
            .await
            .expect("valid ipv6 request");
        assert_eq!(
            request.destination.host,
            Host::Ip(Ipv6Addr::LOCALHOST.into())
        );
        let mut server = VlessServerStream::new(server);
        server.write_all(b".").await.unwrap();
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
        let error = accept_vless_request(&mut server, &users(None))
            .await
            .expect_err("unknown uuid must be rejected");
        assert!(matches!(error, VlessProtocolError::Protocol(_)));
    }

    #[tokio::test]
    async fn rejects_unknown_addon_fields() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(1);
            request.push(0xaa);
            let _ = client.write_all(&request).await;
        });
        let error = accept_vless_request(&mut server, &users(None))
            .await
            .expect_err("unknown addon must be rejected");
        assert!(matches!(error, VlessProtocolError::Protocol(_)));
    }

    #[tokio::test]
    async fn accepts_mux_command_without_address() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(0);
            request.push(COMMAND_MUX);
            let _ = client.write_all(&request).await;
            let mut response = [0_u8; 2];
            let _ = client.read_exact(&mut response).await;
        });
        let request = accept_vless_request(&mut server, &users(None))
            .await
            .expect("mux must be accepted for XUDP");
        assert_eq!(request.command, VlessCommand::Mux);
        assert_eq!(request.destination.port, 0);
        let mut server = VlessServerStream::new(server);
        server.write_all(b".").await.unwrap();
    }

    #[tokio::test]
    async fn rejects_unknown_command() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let uuid = map_uuid(UUID_TEXT);
        tokio::spawn(async move {
            let mut request = vec![VERSION];
            request.extend_from_slice(&uuid);
            request.push(0);
            request.push(9);
            let _ = client.write_all(&request).await;
        });
        let error = accept_vless_request(&mut server, &users(None))
            .await
            .expect_err("unknown commands must be rejected");
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
