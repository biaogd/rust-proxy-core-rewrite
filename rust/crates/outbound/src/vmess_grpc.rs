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

use crate::BoxedOutboundStream;
use crate::vmess_h2::{connect_h2_request, h2_error, open_h2_request};

const PING_ACK_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessGrpcClientOptions {
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
pub struct VmessGrpcClient {
    options: VmessGrpcClientOptions,
    transports: Mutex<Vec<Arc<GrpcTransport>>>,
}

impl VmessGrpcClient {
    #[must_use]
    pub fn new(mut options: VmessGrpcClientOptions) -> Self {
        if options.max_connections == 0 && options.min_streams == 0 && options.max_streams == 0 {
            options.max_connections = 1;
        }
        Self {
            options,
            transports: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn options(&self) -> &VmessGrpcClientOptions {
        &self.options
    }

    /// Opens one Gun stream, creating a physical HTTP/2 connection only when
    /// the pinned Go pool policy requires it.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the physical connection, HTTP/2 handshake, or
    /// Gun request cannot be established.
    pub async fn connect<F, Fut>(&self, connector: F) -> io::Result<BoxedOutboundStream>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<BoxedOutboundStream>>,
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

        transport.acquire();
        let request = grpc_request(&self.options)?;
        match open_h2_request(transport.sender.clone(), request).await {
            Ok(stream) => Ok(Box::new(GunStream::with_transport(stream, transport))),
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

fn should_create_transport(
    transport_count: usize,
    active: usize,
    options: &VmessGrpcClientOptions,
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
    async fn connect(stream: BoxedOutboundStream, ping_interval: i64) -> io::Result<Self> {
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
pub async fn connect_vmess_grpc(
    stream: BoxedOutboundStream,
    host: &str,
    service_name: &str,
    user_agent: &str,
) -> io::Result<BoxedOutboundStream> {
    let request = grpc_request(&VmessGrpcClientOptions {
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

fn grpc_request(options: &VmessGrpcClientOptions) -> io::Result<Request<()>> {
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
    inner: BoxedOutboundStream,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
    read_buffer: BytesMut,
    payload_remaining: Option<usize>,
    transport: Option<Arc<GrpcTransport>>,
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
            transport: None,
        }
    }

    fn with_transport(inner: BoxedOutboundStream, transport: Arc<GrpcTransport>) -> Self {
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
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{
        GunStream, VmessGrpcClientOptions, ping_duration, service_name_to_path,
        should_create_transport,
    };
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

    #[test]
    fn matches_go_transport_selection_thresholds() {
        let mut options = VmessGrpcClientOptions {
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
