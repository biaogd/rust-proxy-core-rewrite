use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf as _, BytesMut};
use http::{Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedOutboundStream;
use crate::vmess_h2::connect_h2_request;

/// Establishes one pinned-oracle `VMess` Gun stream over HTTP/2.
///
/// # Errors
///
/// Returns an I/O error when the URI, HTTP/2 handshake or response-header
/// exchange is invalid.
pub async fn connect_vmess_grpc(
    stream: BoxedOutboundStream,
    host: &str,
    service_name: &str,
    user_agent: &str,
) -> io::Result<BoxedOutboundStream> {
    let path = service_name_to_path(service_name);
    let uri: Uri = format!("https://{host}{path}")
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("user-agent", user_agent)
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let stream = connect_h2_request(stream, request).await?;
    Ok(Box::new(GunStream::new(stream)))
}

fn service_name_to_path(service_name: &str) -> String {
    if service_name.starts_with('/') {
        service_name.to_owned()
    } else {
        format!("/{service_name}/Tun")
    }
}

struct GunStream {
    inner: BoxedOutboundStream,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
    read_buffer: BytesMut,
    payload_remaining: Option<usize>,
}

impl GunStream {
    fn new(inner: BoxedOutboundStream) -> Self {
        Self {
            inner,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
            read_buffer: BytesMut::new(),
            payload_remaining: None,
        }
    }

    fn frame(payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut encoded_length = [0_u8; 10];
        let varint_length = encode_uvarint(payload.len() as u64, &mut encoded_length);
        let grpc_length = 1_usize
            .checked_add(varint_length)
            .and_then(|length| length.checked_add(payload.len()))
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Gun frame is too large"))?;
        let mut frame = Vec::with_capacity(5 + grpc_length as usize);
        frame.push(0);
        frame.extend_from_slice(&grpc_length.to_be_bytes());
        frame.push(0x0a);
        frame.extend_from_slice(&encoded_length[..varint_length]);
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_buffer.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buffer[self.write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_offset += written;
        }
        self.write_buffer.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GunStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(remaining) = this.payload_remaining {
                if remaining == 0 {
                    this.payload_remaining = None;
                    continue;
                }
                if !this.read_buffer.is_empty() {
                    let length = remaining
                        .min(this.read_buffer.len())
                        .min(output.remaining());
                    output.put_slice(&this.read_buffer[..length]);
                    this.read_buffer.advance(length);
                    this.payload_remaining = Some(remaining - length);
                    return Poll::Ready(Ok(()));
                }
            } else if this.read_buffer.len() >= 6 {
                match decode_uvarint(&this.read_buffer[6..])? {
                    Some((payload_length, varint_length)) => {
                        let payload_length = usize::try_from(payload_length).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "Gun payload is too large")
                        })?;
                        this.read_buffer.advance(6 + varint_length);
                        this.payload_remaining = Some(payload_length);
                        continue;
                    }
                    None if this.read_buffer.len() >= 16 => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid Gun payload length",
                        )));
                    }
                    None => {}
                }
            }

            let mut temporary = [0_u8; 4096];
            let mut input = ReadBuf::new(&mut temporary);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() {
                if this.read_buffer.is_empty() && this.payload_remaining.is_none() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.read_buffer.extend_from_slice(input.filled());
        }
    }
}

impl AsyncWrite for GunStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_input)));
        }
        this.write_buffer = Self::frame(input)?;
        this.pending_input = input.len();
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_input)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn encode_uvarint(mut value: u64, output: &mut [u8; 10]) -> usize {
    let mut length = 0;
    while value >= 0x80 {
        output[length] = u8::try_from(value & 0x7f).expect("masked uvarint byte") | 0x80;
        value >>= 7;
        length += 1;
    }
    output[length] = u8::try_from(value).expect("terminal uvarint byte");
    length + 1
}

fn decode_uvarint(input: &[u8]) -> io::Result<Option<(u64, usize)>> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().copied().take(10).enumerate() {
        if index == 9 && byte > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Gun payload length",
            ));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte < 0x80 {
            return Ok(Some((value, index + 1)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{GunStream, service_name_to_path};
    use crate::BoxedOutboundStream;

    #[tokio::test]
    async fn frames_each_write_and_removes_response_envelopes() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut client = GunStream::new(Box::new(client) as BoxedOutboundStream);
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 19];
            server.read_exact(&mut request).await.expect("Gun request");
            server
                .write_all(&[
                    0, 0, 0, 0, 10, 0x0a, 8, b'r', b'e', b's', b'p', b'o', b'n', b's', b'e',
                ])
                .await
                .expect("Gun response");
            request
        });
        client.write_all(b"vmess-header").await.expect("Gun write");
        let mut response = [0_u8; 8];
        client.read_exact(&mut response).await.expect("Gun read");
        assert_eq!(&response, b"response");
        assert_eq!(
            server_task.await.expect("server task"),
            [
                0, 0, 0, 0, 14, 0x0a, 12, b'v', b'm', b'e', b's', b's', b'-', b'h', b'e', b'a',
                b'd', b'e', b'r',
            ]
        );
    }

    #[test]
    fn maps_default_named_and_custom_services() {
        assert_eq!(service_name_to_path("GunService"), "/GunService/Tun");
        assert_eq!(service_name_to_path("example"), "/example/Tun");
        assert_eq!(service_name_to_path("/custom/path"), "/custom/path");
    }
}
