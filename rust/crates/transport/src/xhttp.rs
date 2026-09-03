use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request, Uri};
use rand::RngExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::BoxedStream;
use crate::v2ray_h2::{
    H2ReadStream, H2WriteStream, connect_h2, connect_h2_request, open_h2_download, open_h2_upload,
    send_h2_packet,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XHttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XHttpOptions {
    pub mode: XHttpMode,
    pub host: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub no_grpc_header: bool,
    pub padding_min: usize,
    pub padding_max: usize,
    pub max_each_post_min: usize,
    pub max_each_post_max: usize,
}

pub type XHttpStreamOneOptions = XHttpOptions;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XHttpReuseOptions {
    pub max_concurrency_min: usize,
    pub max_concurrency_max: usize,
    pub max_connections_min: usize,
    pub max_connections_max: usize,
}

#[derive(Debug)]
pub struct XHttpClient {
    options: XHttpOptions,
    max_concurrency: usize,
    max_connections: usize,
    transports: Mutex<Vec<Arc<XHttpTransport>>>,
}

impl XHttpClient {
    #[must_use]
    pub fn new(options: XHttpOptions, reuse: XHttpReuseOptions) -> Self {
        Self {
            options,
            max_concurrency: choose_range(reuse.max_concurrency_min, reuse.max_concurrency_max),
            max_connections: choose_range(reuse.max_connections_min, reuse.max_connections_max),
            transports: Mutex::new(Vec::new()),
        }
    }

    /// Opens one logical xHTTP session on a reusable physical HTTP/2 pool.
    ///
    /// # Errors
    ///
    /// Returns an error when the physical connection, H2 handshake, or xHTTP
    /// request cannot be established.
    pub async fn connect<F, Fut>(&self, connector: F) -> io::Result<BoxedStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxedStream>>,
    {
        let transport = {
            let mut transports = self.transports.lock().await;
            transports.retain(|transport| !transport.is_closed());
            let must_grow = transports.is_empty()
                || (self.max_connections > 0 && transports.len() < self.max_connections);
            let selected = if must_grow {
                None
            } else {
                transports
                    .iter()
                    .filter(|transport| {
                        self.max_concurrency == 0 || transport.active() < self.max_concurrency
                    })
                    .min_by_key(|transport| transport.active())
                    .cloned()
            };
            if let Some(selected) = selected {
                selected
            } else {
                let stream = connector().await?;
                let transport = Arc::new(XHttpTransport::connect(stream).await?);
                transports.push(Arc::clone(&transport));
                transport
            }
        };
        transport.acquire();
        match connect_xhttp_on_client(transport.sender.clone(), &self.options).await {
            Ok(stream) => Ok(Box::new(XHttpLeaseStream { stream, transport })),
            Err(error) => {
                transport.release();
                transport.close();
                Err(error)
            }
        }
    }

    pub async fn retire(&self) {
        for transport in self.transports.lock().await.iter() {
            transport.retire();
        }
    }
}

fn choose_range(minimum: usize, maximum: usize) -> usize {
    if minimum == maximum {
        minimum
    } else {
        rand::rng().random_range(minimum..=maximum)
    }
}

#[derive(Debug)]
struct XHttpTransport {
    sender: SendRequest<Bytes>,
    active: AtomicUsize,
    closed: Arc<AtomicBool>,
    retired: AtomicBool,
    cancellation: CancellationToken,
}

impl XHttpTransport {
    async fn connect(stream: BoxedStream) -> io::Result<Self> {
        let (sender, mut connection) = h2::client::handshake(stream)
            .await
            .map_err(crate::v2ray_h2::h2_error)?;
        let cancellation = CancellationToken::new();
        let connection_cancellation = cancellation.clone();
        let closed = Arc::new(AtomicBool::new(false));
        let connection_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            tokio::select! {
                () = connection_cancellation.cancelled() => {}
                _ = &mut connection => {}
            }
            connection_closed.store(true, Ordering::Release);
        });
        Ok(Self {
            sender,
            active: AtomicUsize::new(0),
            closed,
            retired: AtomicBool::new(false),
            cancellation,
        })
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn acquire(&self) {
        self.active.fetch_add(1, Ordering::AcqRel);
    }

    fn release(&self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "xHTTP transport lease underflow");
        if previous == 1 && self.retired.load(Ordering::Acquire) {
            self.close();
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancellation.cancel();
    }

    fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        if self.active() == 0 {
            self.close();
        }
    }
}

struct XHttpLeaseStream {
    stream: BoxedStream,
    transport: Arc<XHttpTransport>,
}

impl Drop for XHttpLeaseStream {
    fn drop(&mut self) {
        self.transport.release();
    }
}

impl AsyncRead for XHttpLeaseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, output)
    }
}

impl AsyncWrite for XHttpLeaseStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Opens one xHTTP carrier over an established HTTP/2 connection.
///
/// `stream-up` and `packet-up` share one physical H2 connection for their
/// upload and download requests. Cross-session XMUX is owned by the caller.
///
/// # Errors
///
/// Returns an error for invalid request metadata, an HTTP status failure, or
/// an HTTP/2 handshake failure.
pub async fn connect_xhttp(stream: BoxedStream, options: &XHttpOptions) -> io::Result<BoxedStream> {
    let client = connect_h2(stream).await?;
    connect_xhttp_on_client(client, options).await
}

async fn connect_xhttp_on_client(
    client: SendRequest<Bytes>,
    options: &XHttpOptions,
) -> io::Result<BoxedStream> {
    match options.mode {
        XHttpMode::StreamOne => {
            crate::v2ray_h2::open_h2_request(
                client,
                request(options, Method::POST, "", None, true)?,
            )
            .await
        }
        XHttpMode::StreamUp => connect_xhttp_split(client, options, false).await,
        XHttpMode::PacketUp => connect_xhttp_split(client, options, true).await,
    }
}

/// Opens the xHTTP `stream-one` carrier over an established HTTP/2 connection.
///
/// # Errors
///
/// Returns an error for invalid request metadata or an HTTP/2 failure.
pub async fn connect_xhttp_stream_one(
    stream: BoxedStream,
    options: &XHttpStreamOneOptions,
) -> io::Result<BoxedStream> {
    let request = request(options, Method::POST, "", None, true)?;
    connect_h2_request(stream, request).await
}

async fn connect_xhttp_split(
    client: SendRequest<Bytes>,
    options: &XHttpOptions,
    packet_up: bool,
) -> io::Result<BoxedStream> {
    let session = hex::encode(rand::random::<[u8; 16]>());
    let download = open_h2_download(
        client.clone(),
        request(options, Method::GET, &session, None, false)?,
    )
    .await?;
    let writer = if packet_up {
        XHttpWriter::Packet(PacketUpWriter::new(client, options.clone(), session))
    } else {
        let upload = open_h2_upload(
            client,
            request(options, Method::POST, &session, None, true)?,
        )
        .await?;
        XHttpWriter::Stream(upload)
    };
    Ok(Box::new(XHttpSplitStream { download, writer }))
}

fn request(
    options: &XHttpOptions,
    method: Method,
    session: &str,
    sequence: Option<u64>,
    streaming_body: bool,
) -> io::Result<Request<()>> {
    let mut path = options.path.clone();
    if !session.is_empty() {
        path.push_str(session);
    }
    if let Some(sequence) = sequence {
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(&sequence.to_string());
    }
    let uri: Uri = format!("https://{}{path}", options.host)
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in &options.headers {
        request = request.header(name, value);
    }
    if streaming_body && !options.no_grpc_header {
        request = request.header("content-type", "application/grpc");
    }
    let padding_length = if options.padding_min == options.padding_max {
        options.padding_min
    } else {
        rand::rng().random_range(options.padding_min..=options.padding_max)
    };
    request = request.header(
        "referer",
        format!(
            "https://{}{}?x_padding={}",
            options.host,
            options.path,
            "X".repeat(padding_length)
        ),
    );
    request
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

struct XHttpSplitStream {
    download: H2ReadStream,
    writer: XHttpWriter,
}

impl AsyncRead for XHttpSplitStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.download).poll_read(cx, output)
    }
}

impl AsyncWrite for XHttpSplitStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

enum XHttpWriter {
    Stream(H2WriteStream),
    Packet(PacketUpWriter),
}

impl AsyncWrite for XHttpWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Stream(stream) => Pin::new(stream).poll_write(cx, input),
            Self::Packet(stream) => Pin::new(stream).poll_write(cx, input),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Stream(stream) => Pin::new(stream).poll_flush(cx),
            Self::Packet(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Stream(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Packet(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

type PacketFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

struct PacketUpWriter {
    client: SendRequest<Bytes>,
    options: XHttpOptions,
    session: String,
    sequence: u64,
    post_limit: usize,
    pending: Option<PacketFuture>,
    closed: bool,
}

impl PacketUpWriter {
    fn new(client: SendRequest<Bytes>, options: XHttpOptions, session: String) -> Self {
        let post_limit = if options.max_each_post_min == options.max_each_post_max {
            options.max_each_post_min
        } else {
            rand::rng().random_range(options.max_each_post_min..=options.max_each_post_max)
        };
        Self {
            client,
            options,
            session,
            sequence: 0,
            post_limit,
            pending: None,
            closed: false,
        }
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let result = ready!(
            self.pending
                .as_mut()
                .expect("packet future exists")
                .as_mut()
                .poll(cx)
        );
        self.pending = None;
        Poll::Ready(result)
    }
}

impl AsyncWrite for PacketUpWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.pending.is_some() {
            return self.poll_pending(cx);
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = input.len().min(self.post_limit.max(1));
        let payload = Bytes::copy_from_slice(&input[..length]);
        let request = match request(
            &self.options,
            Method::POST,
            &self.session,
            Some(self.sequence),
            false,
        ) {
            Ok(request) => request,
            Err(error) => return Poll::Ready(Err(error)),
        };
        self.sequence = self.sequence.wrapping_add(1);
        let client = self.client.clone();
        self.pending = Some(Box::pin(async move {
            send_h2_packet(client, request, payload).await?;
            Ok(length)
        }));
        self.poll_pending(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending.is_some() {
            ready!(self.poll_pending(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}
