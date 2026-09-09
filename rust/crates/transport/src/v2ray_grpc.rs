use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf as _, Bytes, BytesMut};
use h2::Ping;
use h2::client::SendRequest;
use http::{Method, Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::BoxedStream;
use crate::v2ray_h2::{connect_h2_request, h2_error, open_h2_request};

const PING_ACK_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2rayGrpcClientOptions {
    pub host: String,
    pub service_name: String,
    pub user_agent: String,
    pub ping_interval: i64,
    pub max_connections: i64,
    pub min_streams: i64,
    pub max_streams: i64,
}

/// A reusable `VMess` Gun client matching Mihomo's transport-selection policy.
#[derive(Debug)]
pub struct V2rayGrpcClient {
    options: V2rayGrpcClientOptions,
    transports: Mutex<Vec<Arc<GrpcTransport>>>,
}

impl V2rayGrpcClient {
    #[must_use]
    pub fn new(mut options: V2rayGrpcClientOptions) -> Self {
        if options.max_connections == 0 && options.min_streams == 0 && options.max_streams == 0 {
            options.max_connections = 1;
        }
        Self {
            options,
            transports: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn options(&self) -> &V2rayGrpcClientOptions {
        &self.options
    }

    /// Opens one Gun stream, creating a physical HTTP/2 connection only when
    /// the pinned Go pool policy requires it.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the physical connection, HTTP/2 handshake, or
    /// Gun request cannot be established.
    pub async fn connect<F, Fut>(&self, connector: F) -> io::Result<BoxedStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxedStream>>,
    {
        let transport = {
            let mut transports = self.transports.lock().await;
            transports.retain(|transport| !transport.is_closed());
            let selected = transports
                .iter()
                .min_by_key(|transport| transport.active())
                .cloned();
            let create = selected.as_ref().is_none_or(|transport| {
                should_create_transport(transports.len(), transport.active(), &self.options)
            });
            if create {
                let stream = connector().await?;
                let transport =
                    Arc::new(GrpcTransport::connect(stream, self.options.ping_interval).await?);
                transports.push(Arc::clone(&transport));
                transport
            } else {
                let Some(selected) = selected else {
                    unreachable!("a reusable gRPC transport was selected")
                };
                selected
            }
        };

        let lease = ActiveGrpcLease::new(transport);
        let request = grpc_request(&self.options)?;
        match open_h2_request(lease.transport().sender.clone(), request).await {
            Ok(stream) => Ok(Box::new(GunStream::with_transport(
                stream,
                lease.into_held(),
            ))),
            Err(error) => Err(error),
        }
    }

    pub async fn retire(&self) {
        for transport in self.transports.lock().await.iter() {
            transport.retire();
        }
    }

    #[cfg(test)]
    async fn transport_active_counts(&self) -> Vec<usize> {
        self.transports
            .lock()
            .await
            .iter()
            .map(|transport| transport.active())
            .collect()
    }
}

/// Holds one pool `active` lease until the Gun stream is established or the
/// dial is cancelled/fails. Dropping during `open_h2_request` must release so
/// timeouts cannot permanently inflate the pool counter.
struct ActiveGrpcLease {
    transport: Option<Arc<GrpcTransport>>,
}

impl ActiveGrpcLease {
    fn new(transport: Arc<GrpcTransport>) -> Self {
        transport.acquire();
        Self {
            transport: Some(transport),
        }
    }

    fn transport(&self) -> &Arc<GrpcTransport> {
        self.transport
            .as_ref()
            .expect("gRPC lease is alive until transferred or dropped")
    }

    fn into_held(mut self) -> Arc<GrpcTransport> {
        self.transport
            .take()
            .expect("gRPC lease is alive until transferred or dropped")
    }
}

impl Drop for ActiveGrpcLease {
    fn drop(&mut self) {
        if let Some(transport) = self.transport.take() {
            // Cancelling one request is not a physical-connection failure.
            // open_h2_request drops its per-stream handles (h2 resets that
            // stream); other Gun streams may still be using this transport.
            // The connection driver handles physical failures independently.
            transport.release();
        }
    }
}

fn should_create_transport(
    transport_count: usize,
    active: usize,
    options: &V2rayGrpcClientOptions,
) -> bool {
    if active == 0 {
        return false;
    }
    let transport_count = i64::try_from(transport_count).unwrap_or(i64::MAX);
    let active = i64::try_from(active).unwrap_or(i64::MAX);
    if options.max_connections > 0 {
        !(transport_count >= options.max_connections || active < options.min_streams)
    } else {
        !(options.max_streams > 0 && active < options.max_streams)
    }
}

#[derive(Debug)]
struct GrpcTransport {
    sender: SendRequest<Bytes>,
    active: AtomicUsize,
    closed: Arc<AtomicBool>,
    retired: AtomicBool,
    cancellation: CancellationToken,
}

impl GrpcTransport {
    async fn connect(stream: BoxedStream, ping_interval: i64) -> io::Result<Self> {
        let (sender, mut connection) = h2::client::handshake(stream).await.map_err(h2_error)?;
        let ping_duration = ping_duration(ping_interval);
        let ping_pong = ping_duration
            .is_some()
            .then(|| connection.ping_pong())
            .flatten();
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
            connection_cancellation.cancel();
        });

        if let Some(mut ping_pong) = ping_pong {
            let interval = ping_duration.expect("PING was enabled by a positive duration");
            let ping_cancellation = cancellation.clone();
            let ping_closed = Arc::clone(&closed);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = ping_cancellation.cancelled() => break,
                        () = tokio::time::sleep(interval) => {}
                    }
                    let ping = ping_pong.ping(Ping::opaque());
                    if !matches!(
                        tokio::time::timeout(PING_ACK_TIMEOUT, ping).await,
                        Ok(Ok(_))
                    ) {
                        ping_closed.store(true, Ordering::Release);
                        ping_cancellation.cancel();
                        break;
                    }
                }
            });
        }

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
        debug_assert!(previous > 0, "gRPC transport lease underflow");
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

fn ping_duration(seconds: i64) -> Option<Duration> {
    // Go converts the signed integer seconds to time.Duration with wrapping
    // multiplication before deciding whether health checks are enabled.
    let nanoseconds = seconds.wrapping_mul(1_000_000_000);
    (nanoseconds > 0).then(|| Duration::from_nanos(nanoseconds.cast_unsigned()))
}

/// Establishes one pinned-oracle `VMess` Gun stream over HTTP/2.
///
/// # Errors
///
/// Returns an I/O error when the URI, HTTP/2 handshake or response-header
/// exchange is invalid.
pub async fn connect_v2ray_grpc(
    stream: BoxedStream,
    host: &str,
    service_name: &str,
    user_agent: &str,
) -> io::Result<BoxedStream> {
    let request = grpc_request(&V2rayGrpcClientOptions {
        host: host.to_owned(),
        service_name: service_name.to_owned(),
        user_agent: user_agent.to_owned(),
        ping_interval: 0,
        max_connections: 0,
        min_streams: 0,
        max_streams: 0,
    })?;
    let stream = connect_h2_request(stream, request).await?;
    Ok(Box::new(GunStream::new(stream)))
}

fn grpc_request(options: &V2rayGrpcClientOptions) -> io::Result<Request<()>> {
    let path = service_name_to_path(&options.service_name);
    let uri: Uri = format!("https://{}{path}", options.host)
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("user-agent", &options.user_agent)
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn service_name_to_path(service_name: &str) -> String {
    if service_name.starts_with('/') {
        service_name.to_owned()
    } else {
        format!("/{service_name}/Tun")
    }
}

struct GunStream {
    inner: BoxedStream,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
    read_buffer: BytesMut,
    payload_remaining: Option<usize>,
    transport: Option<Arc<GrpcTransport>>,
}

impl GunStream {
    fn new(inner: BoxedStream) -> Self {
        Self {
            inner,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
            read_buffer: BytesMut::new(),
            payload_remaining: None,
            transport: None,
        }
    }

    fn with_transport(inner: BoxedStream, transport: Arc<GrpcTransport>) -> Self {
        Self {
            inner,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
            read_buffer: BytesMut::new(),
            payload_remaining: None,
            transport: Some(transport),
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

impl Drop for GunStream {
    fn drop(&mut self) {
        if let Some(transport) = self.transport.take() {
            transport.release();
        }
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
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::{
        GunStream, V2rayGrpcClient, V2rayGrpcClientOptions, ping_duration, service_name_to_path,
        should_create_transport,
    };
    use crate::BoxedStream;

    #[tokio::test]
    async fn frames_each_write_and_removes_response_envelopes() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut client = GunStream::new(Box::new(client) as BoxedStream);
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

    #[tokio::test]
    async fn cancelling_response_header_wait_releases_active_lease() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("silent gRPC listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("client dial");
            let mut connection = h2::server::handshake(stream)
                .await
                .expect("server HTTP/2 handshake");
            // Accept the Gun request but never send response headers so the
            // client stays parked after acquire().
            if let Some(result) = connection.accept().await {
                let (_request, _respond) = result.expect("Gun request");
                std::future::pending::<()>().await;
            }
        });

        let client = V2rayGrpcClient::new(V2rayGrpcClientOptions {
            host: "dot.phase4.test".to_owned(),
            service_name: "udp".to_owned(),
            user_agent: "phase6d-udp/1.0".to_owned(),
            ping_interval: 0,
            max_connections: 1,
            min_streams: 0,
            max_streams: 0,
        });
        let connect = client.connect(|| async {
            let stream = TcpStream::connect(address).await?;
            Ok(Box::new(stream) as BoxedStream)
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), connect)
                .await
                .is_err(),
            "silent response headers must keep connect pending"
        );
        assert_eq!(
            client.transport_active_counts().await,
            vec![0],
            "cancelled response-header wait must release the pool lease"
        );
        server.abort();
    }

    #[tokio::test]
    async fn cancelling_one_request_preserves_another_stream_and_pool_reuse() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(65_536);
            let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::channel(4);
            let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
            let shutdown = tokio_util::sync::CancellationToken::new();
            let server_shutdown = shutdown.clone();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server_io).await.unwrap();
                let mut workers = tokio::task::JoinSet::new();
                let mut count = 0;
                let mut reset_tx = Some(reset_tx);
                loop {
                    tokio::select! {
                        () = server_shutdown.cancelled() => break,
                        request = connection.accept() => {
                            let Some(request) = request else { break };
                            let (request, mut respond) = request.unwrap();
                            count += 1;
                            let index = count;
                            let reset_tx = if index == 2 { reset_tx.take() } else { None };
                            let done = server_shutdown.clone();
                            workers.spawn(async move {
                                let mut body = request.into_body();
                                if index == 2 {
                                    // Hold only this response. Reset must arrive on
                                    // cancellation without closing stream 1.
                                    tokio::select! {
                                        () = done.cancelled() => {}
                                        reset = std::future::poll_fn(|cx| respond.poll_reset(cx)) => {
                                            assert_eq!(reset.unwrap(), h2::Reason::CANCEL);
                                            reset_tx.unwrap().send(()).unwrap();
                                        }
                                    }
                                } else {
                                    let response = http::Response::builder().status(200).body(()).unwrap();
                                    let mut sender = respond.send_response(response, false).unwrap();
                                    loop {
                                        tokio::select! {
                                            () = done.cancelled() => break,
                                            data = body.data() => {
                                                let Some(Ok(data)) = data else { break };
                                                body.flow_control().release_capacity(data.len()).unwrap();
                                                sender.send_data(data, false).unwrap();
                                            }
                                        }
                                    }
                                }
                            });
                            accepted_tx.send(index).await.unwrap();
                        }
                    }
                }
                while let Some(result) = workers.join_next().await {
                    result.unwrap();
                }
            });
            let client = V2rayGrpcClient::new(V2rayGrpcClientOptions {
                host: "localhost".to_owned(),
                service_name: "udp".to_owned(),
                user_agent: "cancel-regression".to_owned(),
                ping_interval: 0,
                max_connections: 1,
                min_streams: 0,
                max_streams: 0,
            });
            let mut first = client.connect(|| async { Ok(Box::new(client_io) as BoxedStream) })
                .await.unwrap();
            assert_eq!(accepted_rx.recv().await, Some(1));
            first.write_all(b"before").await.unwrap();
            first.flush().await.unwrap();
            let mut before = [0; 6];
            first.read_exact(&mut before).await.unwrap();
            assert_eq!(&before, b"before");

            let mut second = Box::pin(client.connect(|| async {
                panic!("must reuse the physical connection")
            }));
            tokio::select! {
                result = &mut second => panic!("response must remain pending: {}", result.is_ok()),
                accepted = accepted_rx.recv() => assert_eq!(accepted, Some(2)),
            }
            assert_eq!(client.transport_active_counts().await, vec![2]);
            drop(second);
            assert_eq!(client.transport_active_counts().await, vec![1]);
            reset_rx.await.expect("cancelled stream must receive RST_STREAM");
            first.write_all(b"after").await.unwrap();
            first.flush().await.unwrap();
            let mut after = [0; 5];
            first.read_exact(&mut after).await.unwrap();
            assert_eq!(&after, b"after");
            let third = client.connect(|| async {
                panic!("cancel must not evict a healthy physical connection")
            }).await.unwrap();
            assert_eq!(accepted_rx.recv().await, Some(3));
            assert_eq!(client.transport_active_counts().await, vec![2]);
            drop(third);
            drop(first);
            assert_eq!(client.transport_active_counts().await, vec![0]);
            client.retire().await;
            shutdown.cancel();
            server.await.unwrap();
        }).await.expect("bounded cancellation regression");
    }

    #[test]
    fn maps_default_named_and_custom_services() {
        assert_eq!(service_name_to_path("GunService"), "/GunService/Tun");
        assert_eq!(service_name_to_path("example"), "/example/Tun");
        assert_eq!(service_name_to_path("/custom/path"), "/custom/path");
    }

    #[test]
    fn matches_go_transport_selection_thresholds() {
        let mut options = V2rayGrpcClientOptions {
            host: "example.com".to_owned(),
            service_name: "GunService".to_owned(),
            user_agent: "mihomo".to_owned(),
            ping_interval: 0,
            max_connections: 2,
            min_streams: 2,
            max_streams: 0,
        };
        assert!(!should_create_transport(1, 0, &options));
        assert!(!should_create_transport(1, 1, &options));
        assert!(should_create_transport(1, 2, &options));
        assert!(!should_create_transport(2, 2, &options));

        options.max_connections = 0;
        options.min_streams = 0;
        options.max_streams = 2;
        assert!(!should_create_transport(1, 1, &options));
        assert!(should_create_transport(1, 2, &options));
    }

    #[test]
    fn matches_go_signed_ping_duration_conversion() {
        assert_eq!(ping_duration(0), None);
        assert_eq!(ping_duration(-1), None);
        assert_eq!(ping_duration(1), Some(std::time::Duration::from_secs(1)));
        assert_eq!(ping_duration(i64::MAX), None);
    }
}
