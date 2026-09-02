//! Mekya's HTTP request/response packet carrier layered below mKCP.

#![allow(clippy::module_name_repetitions, clippy::struct_excessive_bools)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::RngExt as _;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tower::Service;

use crate::BoxedStream;
use crate::mkcp::{MkcpConfig, PacketEndpoint, PacketFuture, connect_mkcp_endpoint};

const BUNDLE_OVERHEAD: usize = 2;

pub struct MekyaConnection {
    pub stream: BoxedStream,
    pub negotiated_h2: bool,
}

pub type MekyaConnectFuture =
    Pin<Box<dyn Future<Output = io::Result<MekyaConnection>> + Send + 'static>>;

pub trait MekyaConnector: Send + Sync + 'static {
    fn connect(&self) -> MekyaConnectFuture;
}

impl<F, Fut> MekyaConnector for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<MekyaConnection>> + Send + 'static,
{
    fn connect(&self) -> MekyaConnectFuture {
        Box::pin(self())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MekyaOptions {
    pub url: String,
    pub h2_pool_size: i64,
    pub max_write_delay: i64,
    pub max_request_size: i64,
    pub polling_interval_initial: i64,
    pub max_write_size: i64,
    pub max_write_duration_ms: i64,
    pub max_simultaneous_write_connection: i64,
    pub packet_writing_buffer: i64,
    pub kcp: MkcpConfig,
}

/// Opens one Mekya session and exposes its embedded mKCP byte stream.
///
/// The connector must return a stream that has already applied the configured
/// TLS policy and report whether ALPN selected HTTP/2.
///
/// # Errors
///
/// Returns an error for an invalid URL, HTTP client construction or mKCP
/// security configuration.
pub fn connect_mekya(
    connector: &Arc<dyn MekyaConnector>,
    options: MekyaOptions,
) -> io::Result<BoxedStream> {
    let uri = normalize_url(&options.url)?;
    let pool_count = usize::try_from(options.h2_pool_size.max(1)).unwrap_or(1);
    let clients = (0..pool_count)
        .map(|_| {
            let mut builder = Client::builder(TokioExecutor::new());
            builder.pool_max_idle_per_host(1);
            builder.build(MekyaHyperConnector {
                connector: Arc::clone(connector),
            })
        })
        .collect::<Vec<_>>();
    let cancellation = CancellationToken::new();
    let (outgoing, outgoing_rx) = mpsc::channel(256);
    let incoming_capacity = usize::try_from(options.packet_writing_buffer.max(16))
        .unwrap_or(1024)
        .clamp(16, 65_536);
    let (incoming_tx, incoming) = mpsc::channel(incoming_capacity);
    let mut session_id = [0_u8; 16];
    rand::rng().fill(&mut session_id);
    let endpoint = Arc::new(MekyaEndpoint {
        outgoing,
        incoming: Mutex::new(incoming),
        cancellation: cancellation.clone(),
    });
    tokio::spawn(run_polling_session(
        cancellation,
        uri,
        session_id,
        options.clone(),
        clients,
        outgoing_rx,
        incoming_tx,
    ));
    connect_mkcp_endpoint(endpoint, options.kcp)
}

type MekyaHttpClient = Client<MekyaHyperConnector, Full<Bytes>>;

#[derive(Clone)]
struct MekyaHyperConnector {
    connector: Arc<dyn MekyaConnector>,
}

impl Service<Uri> for MekyaHyperConnector {
    type Response = MekyaIo;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<MekyaIo>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let connector = Arc::clone(&self.connector);
        Box::pin(async move {
            let connection = connector.connect().await?;
            Ok(MekyaIo {
                stream: TokioIo::new(connection.stream),
                negotiated_h2: connection.negotiated_h2,
            })
        })
    }
}

struct MekyaIo {
    stream: TokioIo<BoxedStream>,
    negotiated_h2: bool,
}

impl Connection for MekyaIo {
    fn connected(&self) -> Connected {
        if self.negotiated_h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}

impl hyper::rt::Read for MekyaIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl hyper::rt::Write for MekyaIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }
}

struct MekyaEndpoint {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    cancellation: CancellationToken,
}

impl Drop for MekyaEndpoint {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl PacketEndpoint for MekyaEndpoint {
    fn send<'a>(&'a self, packet: &'a [u8]) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let packet = packet.to_vec();
            let length = packet.len();
            tokio::select! {
                () = self.cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::BrokenPipe, "Mekya session closed")),
                result = self.outgoing.send(packet) => result
                    .map(|()| length)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "Mekya request loop closed")),
            }
        })
    }

    fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketFuture<'a, usize> {
        Box::pin(async move {
            let mut incoming = self.incoming.lock().await;
            let received = tokio::select! {
                () = self.cancellation.cancelled() => None,
                packet = incoming.recv() => packet,
            }
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "Mekya response loop closed")
            })?;
            let length = received.len().min(packet.len());
            packet[..length].copy_from_slice(&received[..length]);
            Ok(length)
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_polling_session(
    cancellation: CancellationToken,
    uri: Uri,
    session_id: [u8; 16],
    options: MekyaOptions,
    clients: Vec<MekyaHttpClient>,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
    incoming: mpsc::Sender<Vec<u8>>,
) {
    let next_client = Arc::new(AtomicUsize::new(0));
    let session_header = URL_SAFE_NO_PAD.encode(session_id);
    let mut pending = None;
    while !cancellation.is_cancelled() {
        let initial = millis(options.polling_interval_initial).max(Duration::from_millis(1));
        let first = if let Some(packet) = pending.take() {
            Some(packet)
        } else {
            tokio::select! {
                () = cancellation.cancelled() => return,
                packet = outgoing.recv() => packet,
                () = tokio::time::sleep(initial) => None,
            }
        };
        let mut body = Vec::new();
        if let Some(packet) = first {
            if !append_bundle(&mut body, &packet, options.max_request_size) {
                pending = Some(packet);
            }
            let deadline = tokio::time::sleep(millis(options.max_write_delay));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => return,
                    () = &mut deadline => break,
                    packet = outgoing.recv() => {
                        let Some(packet) = packet else { break };
                        if !append_bundle(&mut body, &packet, options.max_request_size) {
                            pending = Some(packet);
                            break;
                        }
                    }
                }
            }
        }
        let client_index = next_client.fetch_add(1, Ordering::Relaxed) % clients.len();
        let client = clients[client_index].clone();
        let request_uri = uri.clone();
        let header = session_header.clone();
        let response_packets = incoming.clone();
        let request_cancellation = cancellation.clone();
        tokio::spawn(async move {
            let _ = round_trip(
                &client,
                request_uri,
                &header,
                body,
                response_packets,
                request_cancellation,
            )
            .await;
        });
    }
}

fn append_bundle(body: &mut Vec<u8>, packet: &[u8], maximum: i64) -> bool {
    let Ok(packet_length) = u16::try_from(packet.len()) else {
        return false;
    };
    let additional = BUNDLE_OVERHEAD + packet.len();
    if maximum > 0
        && usize::try_from(maximum).is_ok_and(|limit| body.len().saturating_add(additional) > limit)
    {
        return false;
    }
    body.extend_from_slice(&packet_length.to_be_bytes());
    body.extend_from_slice(packet);
    true
}

async fn round_trip(
    client: &MekyaHttpClient,
    uri: Uri,
    session_header: &str,
    body: Vec<u8>,
    packets: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("x-session-id", session_header)
        .header("accept-encoding", "identity")
        .body(Full::new(Bytes::from(body)))
        .map_err(io::Error::other)?;
    let response = client.request(request).await.map_err(io::Error::other)?;
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "Mekya server returned {}",
            response.status()
        )));
    }
    read_response_bundles(response.into_body(), packets, cancellation).await
}

async fn read_response_bundles(
    mut body: Incoming,
    packets: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
) -> io::Result<()> {
    let mut buffered = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(io::Error::other)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buffered.extend_from_slice(&data);
        loop {
            if buffered.len() < BUNDLE_OVERHEAD {
                break;
            }
            let length = usize::from(u16::from_be_bytes([buffered[0], buffered[1]]));
            if buffered.len() < BUNDLE_OVERHEAD + length {
                break;
            }
            let packet = buffered[BUNDLE_OVERHEAD..BUNDLE_OVERHEAD + length].to_vec();
            buffered.drain(..BUNDLE_OVERHEAD + length);
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                result = packets.send(packet) => {
                    if result.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
    if buffered.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Mekya response ended inside a packet bundle",
        ))
    }
}

fn normalize_url(raw: &str) -> io::Result<Uri> {
    if raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mekya URL is empty",
        ));
    }
    let mut parsed = url::Url::parse(raw).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Mekya URL: {error}"),
        )
    })?;
    if parsed.scheme() != "https" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported Mekya URL scheme {}", parsed.scheme()),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mekya URL host is empty",
        ));
    }
    if parsed.path().is_empty() {
        parsed.set_path("/");
    }
    parsed
        .as_str()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

fn millis(value: i64) -> Duration {
    Duration::from_millis(u64::try_from(value.max(0)).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_absolute_https_urls() {
        assert_eq!(
            normalize_url("https://example.test/mekya").unwrap().path(),
            "/mekya"
        );
        assert!(normalize_url("").is_err());
        assert!(normalize_url("http://example.test/mekya").is_err());
        assert!(normalize_url("/mekya").is_err());
    }

    #[test]
    fn bundles_packets_with_go_compatible_u16_lengths() {
        let mut body = Vec::new();
        assert!(append_bundle(&mut body, b"one", 0));
        assert!(append_bundle(&mut body, b"two", 12));
        assert!(!append_bundle(&mut body, b"overflow", 12));
        assert_eq!(body, b"\0\x03one\0\x03two");
    }
}
