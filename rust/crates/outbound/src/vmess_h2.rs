use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedOutboundStream;

/// Establishes the pinned oracle's single bidirectional `VMess` HTTP/2 stream.
///
/// # Errors
///
/// Returns an I/O error when the HTTP/2 handshake, request construction or
/// response-header exchange fails.
pub async fn connect_vmess_h2(
    stream: BoxedOutboundStream,
    host: &str,
    path: &str,
) -> io::Result<BoxedOutboundStream> {
    let (mut client, connection) = h2::client::handshake(stream).await.map_err(h2_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client = client.ready().await.map_err(h2_error)?;
    // The pinned Go transport always emits `:scheme = https`, including over
    // its explicit h2c connection mode.
    let mut encoded = url::Url::parse("https://vmess.invalid/")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    encoded.set_path(path);
    let uri: Uri = format!("https://{host}{}", encoded.path())
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let request = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header("accept-encoding", "identity")
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let (response, sender) = client.send_request(request, false).map_err(h2_error)?;
    let response = response.await.map_err(h2_error)?;
    Ok(Box::new(VmessH2Stream {
        sender,
        receiver: response.into_body(),
        read_chunk: Bytes::new(),
        read_offset: 0,
        write_closed: false,
    }))
}

struct VmessH2Stream {
    sender: SendStream<Bytes>,
    receiver: RecvStream,
    read_chunk: Bytes,
    read_offset: usize,
    write_closed: bool,
}

impl AsyncRead for VmessH2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_offset < this.read_chunk.len() {
                let available = &this.read_chunk[this.read_offset..];
                let length = available.len().min(output.remaining());
                output.put_slice(&available[..length]);
                this.read_offset += length;
                this.receiver
                    .flow_control()
                    .release_capacity(length)
                    .map_err(h2_error)?;
                return Poll::Ready(Ok(()));
            }
            match ready!(this.receiver.poll_data(cx)) {
                Some(Ok(chunk)) => {
                    this.read_chunk = chunk;
                    this.read_offset = 0;
                }
                Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for VmessH2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.sender.reserve_capacity(input.len());
        let capacity = match ready!(this.sender.poll_capacity(cx)) {
            Some(Ok(capacity)) => capacity,
            Some(Err(error)) => return Poll::Ready(Err(h2_error(error))),
            None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        };
        let length = capacity.min(input.len());
        this.sender
            .send_data(Bytes::copy_from_slice(&input[..length]), false)
            .map_err(h2_error)?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            // Go's h2Conn.Close closes the whole underlying connection rather
            // than preserving the response direction after a TCP half-close.
            this.sender.send_reset(h2::Reason::CANCEL);
            this.write_closed = true;
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "VMess HTTP/2 does not preserve TCP half-close",
        )))
    }
}

fn h2_error(error: h2::Error) -> io::Error {
    io::Error::other(error)
}
