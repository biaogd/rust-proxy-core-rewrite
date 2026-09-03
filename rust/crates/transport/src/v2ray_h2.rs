use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedStream;

/// Establishes the pinned oracle's single bidirectional `V2Ray` HTTP/2 stream.
///
/// # Errors
///
/// Returns an I/O error when the HTTP/2 handshake, request construction or
/// response-header exchange fails.
pub async fn connect_v2ray_h2(
    stream: BoxedStream,
    host: &str,
    path: &str,
) -> io::Result<BoxedStream> {
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
    connect_h2_request(stream, request).await
}

pub(crate) async fn connect_h2_request(
    stream: BoxedStream,
    request: Request<()>,
) -> io::Result<BoxedStream> {
    let (client, connection) = h2::client::handshake(stream).await.map_err(h2_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    open_h2_request(client, request).await
}

pub(crate) async fn connect_h2(stream: BoxedStream) -> io::Result<SendRequest<Bytes>> {
    let (client, connection) = h2::client::handshake(stream).await.map_err(h2_error)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

pub(crate) async fn open_h2_download(
    mut client: SendRequest<Bytes>,
    request: Request<()>,
) -> io::Result<H2ReadStream> {
    client = client.ready().await.map_err(h2_error)?;
    let (response, _) = client.send_request(request, true).map_err(h2_error)?;
    let response = response.await.map_err(h2_error)?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "HTTP/2 download returned {}",
            response.status()
        )));
    }
    Ok(H2ReadStream::new(response.into_body()))
}

pub(crate) async fn open_h2_upload(
    mut client: SendRequest<Bytes>,
    request: Request<()>,
) -> io::Result<H2WriteStream> {
    client = client.ready().await.map_err(h2_error)?;
    let (response, sender) = client.send_request(request, false).map_err(h2_error)?;
    tokio::spawn(async move {
        let _ = response.await;
    });
    Ok(H2WriteStream::new(sender))
}

pub(crate) async fn send_h2_packet(
    mut client: SendRequest<Bytes>,
    request: Request<()>,
    payload: Bytes,
) -> io::Result<()> {
    client = client.ready().await.map_err(h2_error)?;
    let (response, mut sender) = client.send_request(request, false).map_err(h2_error)?;
    sender.send_data(payload, true).map_err(h2_error)?;
    let response = response.await.map_err(h2_error)?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "HTTP/2 upload returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(crate) async fn open_h2_request(
    client: SendRequest<Bytes>,
    request: Request<()>,
) -> io::Result<BoxedStream> {
    let mut client = client.ready().await.map_err(h2_error)?;
    let (response, sender) = client.send_request(request, false).map_err(h2_error)?;
    let response = response.await.map_err(h2_error)?;
    Ok(Box::new(H2DataStream {
        sender,
        receiver: response.into_body(),
        read_chunk: Bytes::new(),
        read_offset: 0,
        write_closed: false,
    }))
}

struct H2DataStream {
    sender: SendStream<Bytes>,
    receiver: RecvStream,
    read_chunk: Bytes,
    read_offset: usize,
    write_closed: bool,
}

pub(crate) struct H2ReadStream {
    receiver: RecvStream,
    read_chunk: Bytes,
    read_offset: usize,
}

impl H2ReadStream {
    fn new(receiver: RecvStream) -> Self {
        Self {
            receiver,
            read_chunk: Bytes::new(),
            read_offset: 0,
        }
    }
}

impl AsyncRead for H2ReadStream {
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

pub(crate) struct H2WriteStream {
    sender: SendStream<Bytes>,
    write_closed: bool,
}

impl H2WriteStream {
    fn new(sender: SendStream<Bytes>) -> Self {
        Self {
            sender,
            write_closed: false,
        }
    }
}

impl AsyncWrite for H2WriteStream {
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
            this.sender
                .send_data(Bytes::new(), true)
                .map_err(h2_error)?;
            this.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for H2DataStream {
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

impl AsyncWrite for H2DataStream {
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
            "outer HTTP/2 stream does not preserve TCP half-close",
        )))
    }
}

pub(crate) fn h2_error(error: h2::Error) -> io::Error {
    io::Error::other(error)
}
