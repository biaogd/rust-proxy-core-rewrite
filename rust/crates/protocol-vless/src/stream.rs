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
    let addon_length = u8::try_from(addons.len()).map_err(|_| {
        VlessProtocolError::Protocol("VLESS addons exceed 255 bytes".to_owned())
    })?;
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
    handshake_sent: bool,
    response_read: bool,
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
            handshake_sent: false,
            response_read: false,
        })
    }
}

impl AsyncRead for VlessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.response_read {
            let mut response = [0_u8; 2];
            let mut read_buf = ReadBuf::new(&mut response);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if read_buf.filled().len() < 2 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "short VLESS response header",
                        )));
                    }
                }
            }
            if response[0] != VERSION {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected VLESS response version {}", response[0]),
                )));
            }
            if response[1] != 0 {
                let addon_length = usize::from(response[1]);
                let mut addons = vec![0_u8; addon_length];
                let mut addon_buf = ReadBuf::new(&mut addons);
                loop {
                    match Pin::new(&mut self.inner).poll_read(cx, &mut addon_buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {
                            if addon_buf.filled().len() == addon_length {
                                break;
                            }
                            if addon_buf.filled().is_empty() {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "short VLESS response addons",
                                )));
                            }
                        }
                    }
                }
            }
            self.response_read = true;
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
        if !self.handshake_sent {
            let mut first = Vec::with_capacity(self.request.len() + buf.len());
            first.extend_from_slice(&self.request);
            first.extend_from_slice(buf);
            self.handshake_sent = true;
            match Pin::new(&mut self.inner).poll_write(cx, &first) {
                Poll::Pending => {
                    self.handshake_sent = false;
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result.map(|_| buf.len())),
            }
        } else {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
