//! Transport-independent VLESS protocol implementation.
//!
//! Phase 6E-A owns the version-zero, no-addon TCP client wire boundary. Socket
//! dialing, outer transports, routing and configuration stay outside this
//! crate so later inbound and outbound adapters can share the framing code.

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlessClientOptions {
    pub uuid: [u8; 16],
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
/// application payload are emitted by the same first relay write.
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
    let request = request_header(destination, options)?;
    let (application, relay) = tokio::io::duplex(64 * 1024);
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = task_cancellation.cancelled() => {}
            _ = relay_session(remote, relay, &request) => {}
        }
    });
    Ok(Box::new(VlessRelayStream {
        inner: application,
        cancellation,
    }))
}

fn request_header(
    destination: &Destination,
    options: VlessClientOptions,
) -> Result<Vec<u8>, VlessProtocolError> {
    let mut request = Vec::with_capacity(38);
    request.push(VERSION);
    request.extend_from_slice(&options.uuid);
    request.push(0); // protobuf addon length
    request.push(COMMAND_TCP);
    request.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.host {
        Host::Ip(std::net::IpAddr::V4(address)) => {
            request.push(ADDRESS_IPV4);
            request.extend_from_slice(&address.octets());
        }
        Host::Ip(std::net::IpAddr::V6(address)) => {
            request.push(ADDRESS_IPV6);
            request.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                VlessProtocolError::Protocol("destination domain exceeds 255 bytes".to_owned())
            })?;
            request.extend_from_slice(&[ADDRESS_DOMAIN, length]);
            request.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(request)
}

async fn relay_session(
    mut remote: BoxedStream,
    mut relay: tokio::io::DuplexStream,
    request: &[u8],
) -> Result<(), VlessProtocolError> {
    let mut initial = vec![0_u8; 64 * 1024];
    let size = relay.read(&mut initial).await?;
    if size == 0 {
        remote.shutdown().await?;
        return Ok(());
    }
    let mut first_write = Vec::with_capacity(request.len() + size);
    first_write.extend_from_slice(request);
    first_write.extend_from_slice(&initial[..size]);
    remote.write_all(&first_write).await?;

    let mut response = [0_u8; 2];
    remote.read_exact(&mut response).await?;
    if response[0] != VERSION {
        return Err(VlessProtocolError::Protocol(format!(
            "unexpected response version {}",
            response[0]
        )));
    }
    if response[1] != 0 {
        let mut addons = vec![0_u8; usize::from(response[1])];
        remote.read_exact(&mut addons).await?;
    }
    tokio::io::copy_bidirectional(&mut relay, &mut remote).await?;
    Ok(())
}

struct VlessRelayStream {
    inner: tokio::io::DuplexStream,
    cancellation: CancellationToken,
}

impl Drop for VlessRelayStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl AsyncRead for VlessRelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for VlessRelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    fn options() -> VlessClientOptions {
        VlessClientOptions { uuid: UUID }
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
        assert_eq!(ipv6[21], ADDRESS_IPV6);
        assert_eq!(&ipv6[22..], &Ipv6Addr::LOCALHOST.octets());
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
}
