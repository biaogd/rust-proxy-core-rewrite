//! Transport-independent Trojan framing shared by outbound and future inbound adapters.

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use sha2::{Digest as _, Sha224};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod packet;

pub use packet::{TrojanUdpAssociation, associate_trojan_udp_on_stream};

const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 3;

#[derive(Debug, Error)]
pub enum TrojanProtocolError {
    #[error("Trojan destination domain exceeds 255 bytes")]
    DomainTooLong,
    #[error("Trojan I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Trojan protocol failed: {0}")]
    Protocol(String),
}

/// Wraps an established carrier with a lazy Trojan TCP request.
///
/// # Errors
///
/// Returns [`TrojanProtocolError::DomainTooLong`] when a domain cannot fit in
/// the SOCKS address used by the Trojan wire format.
pub fn connect_trojan_on_stream(
    remote: BoxedStream,
    destination: &Destination,
    password: &str,
) -> Result<BoxedStream, TrojanProtocolError> {
    Ok(Box::new(TrojanStream {
        inner: remote,
        request: request_header(destination, password)?,
        offset: 0,
    }))
}

fn request_header(
    destination: &Destination,
    password: &str,
) -> Result<Vec<u8>, TrojanProtocolError> {
    request_header_with_command(destination, password, COMMAND_TCP)
}

fn request_header_with_command(
    destination: &Destination,
    password: &str,
    command: u8,
) -> Result<Vec<u8>, TrojanProtocolError> {
    let mut request = Vec::with_capacity(80);
    request.extend_from_slice(hex::encode(Sha224::digest(password.as_bytes())).as_bytes());
    request.extend_from_slice(b"\r\n");
    request.push(command);
    append_socks_address(&mut request, destination)?;
    request.extend_from_slice(b"\r\n");
    Ok(request)
}

fn append_socks_address(
    request: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), TrojanProtocolError> {
    match &destination.host {
        Host::Ip(std::net::IpAddr::V4(address)) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length =
                u8::try_from(domain.len()).map_err(|_| TrojanProtocolError::DomainTooLong)?;
            request.extend_from_slice(&[3, length]);
            request.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V6(address)) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

struct TrojanStream {
    inner: BoxedStream,
    request: Vec<u8>,
    offset: usize,
}

impl AsyncRead for TrojanStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for TrojanStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        while self.offset < self.request.len() {
            let request = self.request.clone();
            let offset = self.offset;
            match Pin::new(&mut self.inner).poll_write(context, &request[offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => self.offset += written,
            }
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_go_trojan_wire_format() {
        let destination = Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 443,
        };
        let header = request_header(&destination, "password").expect("header");
        assert_eq!(
            &header[..56],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(&header[56..], b"\r\n\x01\x03\x0bexample.com\x01\xbb\r\n");

        let ipv4 = request_header(
            &Destination {
                host: Host::Ip("192.0.2.7".parse().expect("IPv4")),
                port: 80,
            },
            "password",
        )
        .expect("IPv4 header");
        assert_eq!(&ipv4[56..], b"\r\n\x01\x01\xc0\x00\x02\x07\x00\x50\r\n");

        let ipv6 = request_header(
            &Destination {
                host: Host::Ip("2001:db8::1".parse().expect("IPv6")),
                port: 8080,
            },
            "password",
        )
        .expect("IPv6 header");
        assert_eq!(
            &ipv6[56..],
            b"\r\n\x01\x04\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f\x90\r\n"
        );
    }
}
