//! Transport-independent VLESS protocol implementation.
//!
//! Phase 6E-A owns the version-zero, no-addon TCP client wire boundary. Socket
//! dialing, outer transports, routing and configuration stay outside this
//! crate so later inbound and outbound adapters can share the framing code.

mod addons;
mod packet;
mod server;
mod stream;
mod vision;

use rewrite_io::{BoxedStream, VisionDirectControl};
use rewrite_model::Destination;
use thiserror::Error;

pub use addons::decode_flow_addon;
pub use packet::{
    VlessPacketMode, VlessUdpAssociation, associate_vless_udp_on_stream, read_xudp_client_packet,
    write_xudp_server_packet,
};
pub use server::{
    VlessCommand, VlessServerRequest, VlessServerStream, VlessUserEntry, accept_vless_request,
    map_uuid, read_vless_udp_payload, uuid_table, write_vless_udp_payload,
};
pub use stream::{VlessResponsePendingStream, VlessTcpStream};
pub use vision::VisionStream;

/// Go-style replaceable unwrap for VLESS outbound.
///
/// Matches Go `WriterReplaceable` / `ReaderReplaceable` separately:
/// - after the request is sent, peel writes onto a thin
///   [`VlessResponsePendingStream`] (bare carrier for writes);
/// - after the response is consumed, peel to the bare upstream carrier.
///
/// Returns `true` once the write side is replaceable (Go `sent`) so relays can
/// enter sized `copy_bidirectional` for the bulk upload instead of staying on
/// the handshake select loop for a full sendall-before-recv exchange.
pub fn peel_replaceable_vless(stream: &mut BoxedStream) -> bool {
    if let Some(pending) = stream
        .as_any_mut()
        .downcast_mut::<VlessResponsePendingStream>()
    {
        if let Some(inner) = pending.take_inner_if_done() {
            *stream = inner;
        }
        // Already writer-peeled (and maybe fully bare): fast path is fine.
        return true;
    }

    let Some(vless) = stream.as_any_mut().downcast_mut::<VlessTcpStream>() else {
        return false;
    };
    if let Some(inner) = vless.take_inner_if_done() {
        *stream = inner;
        return true;
    }
    if let Some(pending) = vless.take_for_writer_peel() {
        *stream = Box::new(pending);
        return true;
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VlessFlow {
    XtlsRprxVision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlessClientOptions {
    pub uuid: [u8; 16],
    pub flow: Option<VlessFlow>,
}

#[derive(Debug, Error)]
pub enum VlessProtocolError {
    #[error("{0}")]
    Transport(String),
    #[error("VLESS I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("VLESS protocol failed: {0}")]
    Protocol(String),
}

/// Starts a VLESS TCP session over an established outer stream.
///
/// The request remains lazy like the Go oracle: the VLESS header and first
/// application payload are emitted by the same first relay write. Non-Vision
/// sessions use [`stream::VlessTcpStream`] in-place (no duplex relay copy).
///
/// # Errors
///
/// Returns an error when the destination cannot be represented by the VLESS
/// version-zero address format.
pub fn connect_vless_on_stream(
    remote: BoxedStream,
    destination: &Destination,
    options: VlessClientOptions,
) -> Result<BoxedStream, VlessProtocolError> {
    connect_vless_on_stream_with_vision_control(remote, destination, options, None)
}

/// Starts VLESS over a carrier that can promote XTLS Vision to raw TCP.
///
/// # Errors
///
/// Returns an error when the destination cannot be represented by the VLESS
/// version-zero address format.
pub fn connect_vless_on_stream_with_vision_control(
    remote: BoxedStream,
    destination: &Destination,
    options: VlessClientOptions,
    vision_control: Option<VisionDirectControl>,
) -> Result<BoxedStream, VlessProtocolError> {
    let vless = stream::VlessTcpStream::new(remote, destination, options)?;
    if options.flow == Some(VlessFlow::XtlsRprxVision) {
        return Ok(Box::new(vision::VisionStream::new(
            Box::new(vless),
            options.uuid,
            vision_control,
        )));
    }
    Ok(Box::new(vless))
}

#[cfg(test)]
fn request_header(
    destination: &Destination,
    options: VlessClientOptions,
) -> Result<Vec<u8>, VlessProtocolError> {
    stream::request_header(destination, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rewrite_model::Host;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    fn options() -> VlessClientOptions {
        VlessClientOptions {
            uuid: UUID,
            flow: None,
        }
    }

    #[test]
    fn request_header_matches_go_address_shapes() {
        let domain = request_header(
            &Destination {
                host: Host::Domain("vless.example".to_owned()),
                port: 443,
            },
            options(),
        )
        .expect("domain header");
        assert_eq!(&domain[..19], &[&[0], UUID.as_slice(), &[0, 1]].concat());
        assert_eq!(&domain[19..], b"\x01\xbb\x02\rvless.example");

        let ipv4 = request_header(
            &Destination {
                host: Host::Ip(Ipv4Addr::new(192, 0, 2, 7).into()),
                port: 8443,
            },
            options(),
        )
        .expect("IPv4 header");
        assert_eq!(&ipv4[19..], b" \xfb\x01\xc0\x00\x02\x07");

        let ipv6 = request_header(
            &Destination {
                host: Host::Ip(Ipv6Addr::LOCALHOST.into()),
                port: 53,
            },
            options(),
        )
        .expect("IPv6 header");
        assert_eq!(ipv6[21], 3);
        assert_eq!(&ipv6[22..], &Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn vision_request_header_includes_flow_addon() {
        let header = request_header(
            &Destination {
                host: Host::Domain("vision.example".to_owned()),
                port: 443,
            },
            VlessClientOptions {
                uuid: UUID,
                flow: Some(VlessFlow::XtlsRprxVision),
            },
        )
        .expect("vision header");
        assert_eq!(header[17], 0x12, "addon length for xtls-rprx-vision");
        assert_eq!(&header[18..36], b"\x0a\x10xtls-rprx-vision");
        assert_eq!(header[36], 1);
    }

    #[tokio::test]
    async fn lazy_first_write_and_response_addon_round_trip() {
        let (client, mut authority) = tokio::io::duplex(4096);
        let destination = Destination {
            host: Host::Domain("roundtrip.example".to_owned()),
            port: 443,
        };
        let expected_header = request_header(&destination, options()).expect("request header");
        let authority_task = tokio::spawn(async move {
            let mut observed = vec![0_u8; expected_header.len() + 7];
            authority
                .read_exact(&mut observed)
                .await
                .expect("request and first payload");
            assert_eq!(&observed[..expected_header.len()], expected_header);
            assert_eq!(&observed[expected_header.len()..], b"request");
            authority
                .write_all(b"\0\x03abcresponse")
                .await
                .expect("response");
            authority.shutdown().await.expect("shutdown");
        });
        let mut stream = connect_vless_on_stream(Box::new(client), &destination, options())
            .expect("VLESS stream");
        stream.write_all(b"request").await.expect("request");
        stream.shutdown().await.expect("half close");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("response");
        assert_eq!(response, b"response");
        authority_task.await.expect("authority task");
    }

    #[tokio::test]
    async fn malformed_response_corpus_is_bounded_and_never_panics() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut corpus = vec![vec![], vec![0], vec![1, 0], vec![0, 1], vec![0, 255]];
        for length in 0..=64_usize {
            corpus.push(
                (0..length)
                    .map(|index| {
                        u8::try_from((index * 73 + length * 19) & 0xff)
                            .expect("corpus byte is masked to u8")
                    })
                    .collect(),
            );
        }

        let destination = Destination {
            host: Host::Domain("corpus.example".to_owned()),
            port: 443,
        };
        for response in corpus {
            let (remote, mut authority) = tokio::io::duplex(1024);
            let mut stream = connect_vless_on_stream(Box::new(remote), &destination, options())
                .expect("VLESS stream");
            let task = tokio::spawn(async move {
                let _ = stream.write_all(b"x").await;
                let mut sink = Vec::new();
                let _ = stream.read_to_end(&mut sink).await;
            });
            let mut observed = vec![0_u8; 64];
            let _ = authority.read(&mut observed).await;
            let _ = authority.write_all(&response).await;
            let _ = authority.shutdown().await;
            let joined = tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .expect("malformed response handling is bounded");
            assert!(joined.is_ok(), "malformed response task panicked");
        }
    }
}
