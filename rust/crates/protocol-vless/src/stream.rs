use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::addons::encode_flow_addon;
use crate::{VlessClientOptions, VlessFlow, VlessProtocolError};

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;

pub(crate) fn request_header(
    destination: &Destination,
    options: VlessClientOptions,
) -> Result<Vec<u8>, VlessProtocolError> {
    let addons = match options.flow {
        Some(VlessFlow::XtlsRprxVision) => encode_flow_addon("xtls-rprx-vision"),
        None => Vec::new(),
    };
    let addon_length = u8::try_from(addons.len())
        .map_err(|_| VlessProtocolError::Protocol("VLESS addons exceed 255 bytes".to_owned()))?;
    let mut request = Vec::with_capacity(38 + addons.len());
    request.push(VERSION);
    request.extend_from_slice(&options.uuid);
    request.push(addon_length);
    request.extend_from_slice(&addons);
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

/// VLESS TCP stream with lazy request/response handling.
pub struct VlessTcpStream {
    inner: BoxedStream,
    request: Vec<u8>,
    request_offset: usize,
    response_header: [u8; 2],
    response_header_offset: usize,
    response_addons_remaining: usize,
    response_header_validated: bool,
}

impl VlessTcpStream {
    pub(crate) fn new(
        inner: BoxedStream,
        destination: &Destination,
        options: VlessClientOptions,
    ) -> Result<Self, VlessProtocolError> {
        Ok(Self {
            inner,
            request: request_header(destination, options)?,
            request_offset: 0,
            response_header: [0; 2],
            response_header_offset: 0,
            response_addons_remaining: 0,
            response_header_validated: false,
        })
    }
}

impl AsyncRead for VlessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        while self.response_header_offset < self.response_header.len() {
            let mut response = self.response_header;
            let offset = self.response_header_offset;
            let mut read_buf = ReadBuf::new(&mut response[offset..]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "short VLESS response header",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    let read = read_buf.filled().len();
                    self.response_header = response;
                    self.response_header_offset += read;
                }
            }
        }
        if !self.response_header_validated {
            if self.response_header[0] != VERSION {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "unexpected VLESS response version {}",
                        self.response_header[0]
                    ),
                )));
            }
            self.response_addons_remaining = usize::from(self.response_header[1]);
            self.response_header_validated = true;
        }
        while self.response_addons_remaining > 0 {
            let mut addons = [0_u8; 256];
            let length = self.response_addons_remaining.min(addons.len());
            let mut addon_buf = ReadBuf::new(&mut addons[..length]);
            match Pin::new(&mut self.inner).poll_read(cx, &mut addon_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if addon_buf.filled().is_empty() => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "short VLESS response addons",
                    )));
                }
                Poll::Ready(Ok(())) => {
                    self.response_addons_remaining -= addon_buf.filled().len();
                }
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        while self.request_offset < self.request.len() {
            let request = self.request.clone();
            let offset = self.request_offset;
            match Pin::new(&mut self.inner).poll_write(cx, &request[offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => self.request_offset += written,
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use rewrite_model::Host;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    #[tokio::test]
    async fn handles_one_byte_transport_fragments() {
        let destination = Destination {
            host: Host::Domain("fragmented.example".to_owned()),
            port: 443,
        };
        let options = VlessClientOptions {
            uuid: UUID,
            flow: Some(VlessFlow::XtlsRprxVision),
        };
        let expected_header = request_header(&destination, options).expect("request header");
        let (client, mut authority) = tokio::io::duplex(1);
        let authority_task = tokio::spawn(async move {
            let mut request = vec![0; expected_header.len() + 7];
            authority
                .read_exact(&mut request)
                .await
                .expect("fragmented request");
            assert_eq!(&request[..expected_header.len()], expected_header);
            assert_eq!(&request[expected_header.len()..], b"request");
            authority
                .write_all(b"\0\x03abcresponse")
                .await
                .expect("fragmented response");
            authority.shutdown().await.expect("authority shutdown");
        });

        let mut stream =
            VlessTcpStream::new(Box::new(client), &destination, options).expect("VLESS stream");
        stream.write_all(b"request").await.expect("request");
        stream.shutdown().await.expect("client shutdown");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("fragmented response");
        assert_eq!(response, b"response");
        authority_task.await.expect("authority task");
    }
}
