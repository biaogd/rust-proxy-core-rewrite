use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::{BoxedStream, DuplexStream};
use rewrite_model::{Destination, Host};
use rewrite_transport::GunStream;
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

enum HandshakeState {
    /// Request not fully sent and/or response not fully consumed (Go Conn).
    Active {
        request: Vec<u8>,
        request_offset: usize,
        /// Stashed `header || payload` with `(buffer, offset, header_len)` so a
        /// Pending/partial first write does not rebuild the coalesce buffer.
        pending_first_write: Option<(Vec<u8>, usize, usize)>,
        response_header: [u8; 2],
        response_header_offset: usize,
        response_addons_remaining: usize,
        response_header_validated: bool,
    },
    /// Both directions finished handshake — bulk path is a bare forward
    /// (Go `WriterReplaceable` + `ReaderReplaceable`).
    Done,
}

/// VLESS TCP stream with lazy request/response handling.
pub struct VlessTcpStream {
    inner: Option<BoxedStream>,
    handshake: HandshakeState,
}

impl VlessTcpStream {
    pub(crate) fn new(
        inner: BoxedStream,
        destination: &Destination,
        options: VlessClientOptions,
    ) -> Result<Self, VlessProtocolError> {
        Ok(Self {
            inner: Some(inner),
            handshake: HandshakeState::Active {
                request: request_header(destination, options)?,
                request_offset: 0,
                pending_first_write: None,
                response_header: [0; 2],
                response_header_offset: 0,
                response_addons_remaining: 0,
                response_header_validated: false,
            },
        })
    }

    /// Go `ReaderReplaceable && WriterReplaceable`: both handshake directions done.
    #[must_use]
    pub fn is_replaceable(&self) -> bool {
        matches!(self.handshake, HandshakeState::Done)
    }

    /// Peel the bare carrier once the handshake is finished (Go unwrap).
    pub fn take_inner_if_done(&mut self) -> Option<BoxedStream> {
        if self.is_replaceable() {
            self.inner.take()
        } else {
            None
        }
    }

    fn inner_mut(&mut self) -> std::io::Result<&mut BoxedStream> {
        self.inner.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "VLESS stream already peeled to upstream",
            )
        })
    }

    fn maybe_finish_handshake(&mut self) {
        let HandshakeState::Active {
            request,
            request_offset,
            pending_first_write,
            response_header_offset,
            response_addons_remaining,
            response_header_validated,
            ..
        } = &self.handshake
        else {
            return;
        };
        if *request_offset >= request.len()
            && pending_first_write.is_none()
            && *response_header_validated
            && *response_header_offset >= 2
            && *response_addons_remaining == 0
        {
            self.handshake = HandshakeState::Done;
        }
    }

    fn poll_flush_first_write(
        &mut self,
        cx: &mut Context<'_>,
        combined: Vec<u8>,
        mut offset: usize,
        header_len: usize,
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = match self.inner_mut() {
            Ok(inner) => inner,
            Err(error) => return Poll::Ready(Err(error)),
        };
        while offset < combined.len() {
            match Pin::new(&mut *inner).poll_write(cx, &combined[offset..]) {
                Poll::Pending => {
                    if let HandshakeState::Active {
                        pending_first_write,
                        ..
                    } = &mut self.handshake
                    {
                        *pending_first_write = Some((combined, offset, header_len));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => offset += written,
            }
        }
        let payload_written = combined.len().saturating_sub(header_len);
        if let HandshakeState::Active {
            request,
            request_offset,
            pending_first_write,
            ..
        } = &mut self.handshake
        {
            *request_offset = header_len;
            request.clear();
            *pending_first_write = None;
        }
        self.maybe_finish_handshake();
        Poll::Ready(Ok(payload_written))
    }
}

impl AsyncRead for VlessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if matches!(self.handshake, HandshakeState::Done) {
            let inner = match self.inner_mut() {
                Ok(inner) => inner,
                Err(error) => return Poll::Ready(Err(error)),
            };
            return Pin::new(inner).poll_read(cx, buf);
        }
        loop {
            let HandshakeState::Active {
                response_header,
                response_header_offset,
                response_addons_remaining,
                response_header_validated,
                ..
            } = &mut self.handshake
            else {
                let inner = match self.inner_mut() {
                    Ok(inner) => inner,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                return Pin::new(inner).poll_read(cx, buf);
            };

            if *response_header_offset < response_header.len() {
                let mut response = *response_header;
                let offset = *response_header_offset;
                let mut read_buf = ReadBuf::new(&mut response[offset..]);
                let inner = match self.inner_mut() {
                    Ok(inner) => inner,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                match Pin::new(inner).poll_read(cx, &mut read_buf) {
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
                        if let HandshakeState::Active {
                            response_header,
                            response_header_offset,
                            ..
                        } = &mut self.handshake
                        {
                            *response_header = response;
                            *response_header_offset += read;
                        }
                        continue;
                    }
                }
            }

            if !*response_header_validated {
                if response_header[0] != VERSION {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "unexpected VLESS response version {}",
                            response_header[0]
                        ),
                    )));
                }
                *response_addons_remaining = usize::from(response_header[1]);
                *response_header_validated = true;
            }

            if *response_addons_remaining > 0 {
                let mut addons = [0_u8; 256];
                let length = (*response_addons_remaining).min(addons.len());
                let mut addon_buf = ReadBuf::new(&mut addons[..length]);
                let inner = match self.inner_mut() {
                    Ok(inner) => inner,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                match Pin::new(inner).poll_read(cx, &mut addon_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) if addon_buf.filled().is_empty() => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "short VLESS response addons",
                        )));
                    }
                    Poll::Ready(Ok(())) => {
                        if let HandshakeState::Active {
                            response_addons_remaining,
                            ..
                        } = &mut self.handshake
                        {
                            *response_addons_remaining -= addon_buf.filled().len();
                        }
                        continue;
                    }
                }
            }

            self.maybe_finish_handshake();
            let inner = match self.inner_mut() {
                Ok(inner) => inner,
                Err(error) => return Poll::Ready(Err(error)),
            };
            return Pin::new(inner).poll_read(cx, buf);
        }
    }
}

impl AsyncWrite for VlessTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if matches!(self.handshake, HandshakeState::Done) {
            let inner = match self.inner_mut() {
                Ok(inner) => inner,
                Err(error) => return Poll::Ready(Err(error)),
            };
            return Pin::new(inner).poll_write(cx, buf);
        }

        // Resume a stashed header||payload coalesce before accepting new buf.
        if let HandshakeState::Active {
            pending_first_write: Some((combined, offset, header_len)),
            ..
        } = &mut self.handshake
        {
            let combined = std::mem::take(combined);
            let offset = *offset;
            let header_len = *header_len;
            if let HandshakeState::Active {
                pending_first_write,
                ..
            } = &mut self.handshake
            {
                *pending_first_write = None;
            }
            // Empty combined marks a Gun-prefixed write whose frame is already
            // buffered; resume by draining via poll_write.
            if combined.is_empty() {
                let inner = match self.inner_mut() {
                    Ok(inner) => inner,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                match Pin::new(inner).poll_write(cx, buf) {
                    Poll::Pending => {
                        if let HandshakeState::Active {
                            pending_first_write,
                            ..
                        } = &mut self.handshake
                        {
                            *pending_first_write = Some((Vec::new(), 0, header_len));
                        }
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(written)) => {
                        if let HandshakeState::Active { request, .. } = &mut self.handshake {
                            request.clear();
                        }
                        self.maybe_finish_handshake();
                        return Poll::Ready(Ok(written));
                    }
                }
            }
            return self.poll_flush_first_write(cx, combined, offset, header_len);
        }

        // Coalesce header + first payload (Go sendRequest) into one Gun/TLS frame.
        let coalesce = if let HandshakeState::Active {
            request,
            request_offset,
            pending_first_write,
            ..
        } = &self.handshake
            && *request_offset == 0
            && !request.is_empty()
            && !buf.is_empty()
            && pending_first_write.is_none()
        {
            Some((request.clone(), request.len()))
        } else {
            None
        };
        if let Some((header, header_len)) = coalesce {
            // Gun FrontHeadroom: one frame, one copy into the Gun buffer.
            let inner = match self.inner_mut() {
                Ok(inner) => inner,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if let Some(gun) = inner.as_mut().as_any_mut().downcast_mut::<GunStream>() {
                match gun.poll_write_with_prefix(cx, &header, buf) {
                    Poll::Pending => {
                        if let HandshakeState::Active {
                            request_offset,
                            pending_first_write,
                            ..
                        } = &mut self.handshake
                        {
                            *request_offset = header_len;
                            *pending_first_write = Some((Vec::new(), 0, header_len));
                        }
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(written)) => {
                        if let HandshakeState::Active {
                            request,
                            request_offset,
                            pending_first_write,
                            ..
                        } = &mut self.handshake
                        {
                            *request_offset = header_len;
                            request.clear();
                            *pending_first_write = None;
                        }
                        self.maybe_finish_handshake();
                        return Poll::Ready(Ok(written));
                    }
                }
            }
            let mut combined = Vec::with_capacity(header_len + buf.len());
            combined.extend_from_slice(&header);
            combined.extend_from_slice(buf);
            return self.poll_flush_first_write(cx, combined, 0, header_len);
        }

        while let HandshakeState::Active {
            request,
            request_offset,
            ..
        } = &self.handshake
            && *request_offset < request.len()
        {
            let offset = *request_offset;
            let to_write = request[offset..].to_vec();
            let inner = match self.inner_mut() {
                Ok(inner) => inner,
                Err(error) => return Poll::Ready(Err(error)),
            };
            match Pin::new(inner).poll_write(cx, &to_write) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(written)) => {
                    if let HandshakeState::Active {
                        request_offset, ..
                    } = &mut self.handshake
                    {
                        *request_offset += written;
                    }
                }
            }
        }

        if let HandshakeState::Active {
            request,
            request_offset,
            ..
        } = &mut self.handshake
            && *request_offset >= request.len()
            && !request.is_empty()
        {
            request.clear();
        }
        self.maybe_finish_handshake();
        let inner = match self.inner_mut() {
            Ok(inner) => inner,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = match self.inner_mut() {
            Ok(inner) => inner,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = match self.inner_mut() {
            Ok(inner) => inner,
            Err(error) => return Poll::Ready(Err(error)),
        };
        Pin::new(inner).poll_shutdown(cx)
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
            VlessTcpStream::new(Box::new(client), &destination, options).expect("stream");
        stream.write_all(b"request").await.expect("request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("response");
        assert_eq!(response, b"response");
        authority_task.await.expect("authority");
    }
}
