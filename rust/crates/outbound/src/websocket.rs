use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::HOST;
use tokio_tungstenite::tungstenite::{Error, Message};

pub struct WebSocketIo<S> {
    stream: WebSocketStream<S>,
    read_buffer: Bytes,
    read_offset: usize,
    pending_write: usize,
}

impl<S> WebSocketIo<S> {
    pub fn new(stream: WebSocketStream<S>) -> Self {
        Self {
            stream,
            read_buffer: Bytes::new(),
            read_offset: 0,
            pending_write: 0,
        }
    }
}

/// Upgrades an already-connected transport to a binary WebSocket byte stream.
///
/// # Errors
///
/// Returns a Tungstenite error when the request cannot be constructed or the
/// peer rejects or violates the WebSocket handshake.
pub async fn connect_websocket<S>(
    stream: S,
    host: &str,
    port: u16,
    path: &str,
) -> Result<WebSocketIo<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let uri = format!("ws://{host}:{port}{path}");
    let mut request = uri.into_client_request()?;
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(host)?);
    let (stream, _) = tokio_tungstenite::client_async(request, stream).await?;
    Ok(WebSocketIo::new(stream))
}

impl<S> AsyncRead for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_offset < this.read_buffer.len() {
                let available = &this.read_buffer[this.read_offset..];
                let length = available.len().min(output.remaining());
                output.put_slice(&available[..length]);
                this.read_offset += length;
                return Poll::Ready(Ok(()));
            }
            this.read_buffer = Bytes::new();
            this.read_offset = 0;
            match ready!(Pin::new(&mut this.stream).poll_next(cx)) {
                Some(Ok(Message::Binary(payload))) => this.read_buffer = payload,
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v2ray-plugin WebSocket received a non-binary data message",
                    )));
                }
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write != 0 {
            ready!(Pin::new(&mut this.stream).poll_flush(cx)).map_err(io::Error::other)?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_write)));
        }
        ready!(Pin::new(&mut this.stream).poll_ready(cx)).map_err(io::Error::other)?;
        Pin::new(&mut this.stream)
            .start_send(Message::Binary(Bytes::copy_from_slice(input)))
            .map_err(io::Error::other)?;
        this.pending_write = input.len();
        ready!(Pin::new(&mut this.stream).poll_flush(cx)).map_err(io::Error::other)?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_write)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}
