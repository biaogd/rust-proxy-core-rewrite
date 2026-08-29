use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, Request, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::serve::Listener;
use axum::{Router, body::Body};
use base64::Engine;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::ProxyServerStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::server::TlsStream;

#[derive(Clone)]
struct AuthorityState {
    context: SharedContext,
    method: CipherKind,
    key: Arc<Vec<u8>>,
    host: Arc<str>,
    path: Arc<str>,
    options: Arc<AuthorityOptions>,
}

/// Optional final JSON argument for advanced v2ray-plugin fixtures.
///
/// CLI forms remain compatible with the original authority:
///
/// ```text
/// authority LISTEN PASSWORD CIPHER HOST PATH
/// authority LISTEN PASSWORD CIPHER HOST PATH CERT KEY
/// authority LISTEN PASSWORD CIPHER HOST PATH OPTIONS.json
/// authority LISTEN PASSWORD CIPHER HOST PATH CERT KEY OPTIONS.json
/// ```
///
/// `expected_headers` checks request headers, `early_data_header` decodes
/// base64url data and prepends it to the upgraded byte stream, `mux` unwraps
/// the v2ray-plugin mux envelope, and `raw_http_upgrade` selects the raw HTTP
/// 101 transport without WebSocket framing. `client_ca_certificate` enables
/// mandatory mTLS verification for TLS listeners.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AuthorityOptions {
    expected_headers: BTreeMap<String, String>,
    early_data_header: Option<String>,
    mux: bool,
    raw_http_upgrade: bool,
    client_ca_certificate: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut arguments = std::env::args().skip(1);
    let listen = arguments
        .next()
        .ok_or("missing listen address")?
        .parse::<SocketAddr>()?;
    let password = arguments.next().ok_or("missing password")?;
    let cipher = arguments.next().ok_or("missing cipher")?;
    let host = arguments.next().ok_or("missing expected Host")?;
    let path = arguments.next().ok_or("missing expected path")?;
    let trailing = arguments.collect::<Vec<_>>();
    let (certificate, private_key, options_path) = match trailing.as_slice() {
        [] => (None, None, None),
        [options] => (None, None, Some(options.clone())),
        [certificate, private_key] => (Some(certificate.clone()), Some(private_key.clone()), None),
        [certificate, private_key, options] => (
            Some(certificate.clone()),
            Some(private_key.clone()),
            Some(options.clone()),
        ),
        _ => return Err("unexpected argument".into()),
    };
    if certificate.is_some() != private_key.is_some() {
        return Err("certificate and private key must be supplied together".into());
    }
    let options: AuthorityOptions = options_path
        .map(fs::read)
        .transpose()?
        .map(|contents| serde_json::from_slice(&contents))
        .transpose()?
        .unwrap_or_default();
    if options.client_ca_certificate.is_some() && certificate.is_none() {
        return Err("client CA certificate requires a TLS listener".into());
    }
    let method = CipherKind::from_str(&cipher).map_err(|_| "unsupported cipher")?;
    let server = ServerConfig::new(listen, password, method)?;
    let state = AuthorityState {
        context: Context::new_shared(ServerType::Server),
        method,
        key: Arc::new(server.key().to_vec()),
        host: host.into(),
        path: path.into(),
        options: Arc::new(options),
    };
    let listener = TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;
    let listener = if let (Some(certificate), Some(private_key)) = (certificate, private_key) {
        AuthorityListener::tls(
            listener,
            &certificate,
            &private_key,
            state.options.client_ca_certificate.as_deref(),
        )?
    } else {
        AuthorityListener::Plain(listener)
    };
    println!("READY {local_addr}");
    let router = if state.options.raw_http_upgrade {
        Router::new().fallback(raw_upgrade).with_state(state)
    } else {
        Router::new().fallback(upgrade).with_state(state)
    };
    axum::serve(listener, router).await?;
    Ok(())
}

enum AuthorityListener {
    Plain(TcpListener),
    Tls {
        listener: TcpListener,
        acceptor: TlsAcceptor,
    },
}

impl AuthorityListener {
    fn tls(
        listener: TcpListener,
        certificate: &str,
        private_key: &str,
        client_ca_certificate: Option<&str>,
    ) -> Result<Self, Box<dyn Error>> {
        let certificates = rustls_pemfile::certs(&mut BufReader::new(fs::File::open(certificate)?))
            .collect::<Result<Vec<_>, _>>()?;
        let private_key =
            rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(private_key)?))?
                .ok_or("private key is missing")?;
        let builder = TlsServerConfig::builder();
        let builder = if let Some(client_ca_certificate) = client_ca_certificate {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            let client_certificates =
                rustls_pemfile::certs(&mut BufReader::new(fs::File::open(client_ca_certificate)?))
                    .collect::<Result<Vec<_>, _>>()?;
            let (accepted, _) = roots.add_parsable_certificates(client_certificates);
            if accepted == 0 {
                return Err("client CA certificate is empty".into());
            }
            let verifier =
                tokio_rustls::rustls::server::WebPkiClientVerifier::builder(roots.into())
                    .build()?;
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        let config = builder.with_single_cert(certificates, private_key)?;
        Ok(Self::Tls {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }
}

enum AuthorityIo {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for AuthorityIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, output),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, output),
        }
    }
}

impl AsyncWrite for AuthorityIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, input),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, input),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Listener for AuthorityListener {
    type Io = AuthorityIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self {
                Self::Plain(listener) => match TcpListener::accept(listener).await {
                    Ok((stream, address)) => return (AuthorityIo::Plain(stream), address),
                    Err(error) => eprintln!("WebSocket authority accept failed: {error}"),
                },
                Self::Tls { listener, acceptor } => {
                    let Ok((stream, address)) = TcpListener::accept(listener).await else {
                        continue;
                    };
                    match acceptor.accept(stream).await {
                        Ok(stream) => return (AuthorityIo::Tls(Box::new(stream)), address),
                        Err(error) => eprintln!("WebSocket authority TLS failed: {error}"),
                    }
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        match self {
            Self::Plain(listener) | Self::Tls { listener, .. } => listener.local_addr(),
        }
    }
}

async fn upgrade(
    State(state): State<AuthorityState>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Response {
    if let Err(status) = validate_request(&state, &headers, &uri) {
        return status.into_response();
    }
    let early_data = match decode_early_data(&state, &headers) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("rejected WebSocket early data: {error}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    websocket
        .on_upgrade(move |socket| {
            serve_connection(AxumWebSocketIo::with_prefix(socket, early_data), state)
        })
        .into_response()
}

async fn raw_upgrade(State(state): State<AuthorityState>, mut request: Request<Body>) -> Response {
    if let Err(status) = validate_request(&state, request.headers(), request.uri()) {
        return status.into_response();
    }
    if !header_contains_token(request.headers(), header::CONNECTION, "upgrade")
        || !header_contains_token(request.headers(), header::UPGRADE, "websocket")
        || request.headers().contains_key(header::SEC_WEBSOCKET_KEY)
    {
        eprintln!("rejected raw HTTP upgrade: invalid upgrade headers");
        return StatusCode::BAD_REQUEST.into_response();
    }
    let early_data = match decode_early_data(&state, request.headers()) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("rejected raw HTTP upgrade early data: {error}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let upgraded = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        match upgraded.await {
            Ok(stream) => {
                serve_connection(PrefixedIo::new(TokioIo::new(stream), early_data), state).await;
            }
            Err(error) => eprintln!("raw HTTP upgrade failed: {error}"),
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket")
        .body(Body::empty())
        .expect("static raw upgrade response is valid")
}

fn validate_request(
    state: &AuthorityState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<(), StatusCode> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    if host != Some(&state.host) || uri.path() != &*state.path {
        eprintln!(
            "rejected v2ray-plugin upgrade: host={host:?} path={} expected_host={} expected_path={}",
            uri.path(),
            state.host,
            state.path
        );
        return Err(StatusCode::BAD_REQUEST);
    }
    for (name, expected) in &state.options.expected_headers {
        let actual = headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok());
        if actual != Some(expected) {
            eprintln!(
                "rejected v2ray-plugin upgrade: header={name} actual={actual:?} expected={expected:?}"
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    Ok(())
}

fn decode_early_data(state: &AuthorityState, headers: &HeaderMap) -> io::Result<Bytes> {
    let Some(name) = state.options.early_data_header.as_deref() else {
        return Ok(Bytes::new());
    };
    let Some(encoded) = headers.get(name) else {
        return Ok(Bytes::new());
    };
    let encoded = encoded
        .to_str()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded.replace('+', "-").replace('/', "_").replace('=', ""))
        .map(Bytes::from)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn header_contains_token(headers: &HeaderMap, name: header::HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

async fn serve_connection<T>(transport: T, state: AuthorityState)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if state.options.mux {
        serve_shadowsocks(V2rayMuxIo::new(transport), state).await;
    } else {
        serve_shadowsocks(transport, state).await;
    }
}

async fn serve_shadowsocks<T>(transport: T, state: AuthorityState)
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut inbound =
        ProxyServerStream::from_stream(state.context, transport, state.method, &state.key);
    let result = async {
        let destination = inbound.handshake().await?;
        let mut outbound = connect_destination(&destination).await?;
        copy_bidirectional(&mut inbound, &mut outbound).await?;
        Ok::<(), io::Error>(())
    }
    .await;
    if let Err(error) = result {
        eprintln!("WebSocket Shadowsocks connection failed: {error}");
    }
}

async fn connect_destination(destination: &Address) -> io::Result<TcpStream> {
    match destination {
        Address::SocketAddress(address) => TcpStream::connect(address).await,
        Address::DomainNameAddress(domain, port) => {
            TcpStream::connect((domain.as_str(), *port)).await
        }
    }
}

struct AxumWebSocketIo {
    socket: WebSocket,
    read_buffer: Bytes,
    read_offset: usize,
    pending_write: usize,
}

impl AxumWebSocketIo {
    fn with_prefix(socket: WebSocket, prefix: Bytes) -> Self {
        Self {
            socket,
            read_buffer: prefix,
            read_offset: 0,
            pending_write: 0,
        }
    }
}

impl AsyncRead for AxumWebSocketIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
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
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(payload))) => this.read_buffer = payload,
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v2ray-plugin authority received non-binary data",
                    )));
                }
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            }
        }
    }
}

impl AsyncWrite for AxumWebSocketIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write != 0 {
            ready!(Pin::new(&mut this.socket).poll_flush(cx)).map_err(io::Error::other)?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_write)));
        }
        ready!(Pin::new(&mut this.socket).poll_ready(cx)).map_err(io::Error::other)?;
        Pin::new(&mut this.socket)
            .start_send(Message::Binary(Bytes::copy_from_slice(input)))
            .map_err(io::Error::other)?;
        this.pending_write = input.len();
        ready!(Pin::new(&mut this.socket).poll_flush(cx)).map_err(io::Error::other)?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_write)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

struct PrefixedIo<T> {
    inner: T,
    prefix: Bytes,
    prefix_offset: usize,
}

impl<T> PrefixedIo<T> {
    fn new(inner: T, prefix: Bytes) -> Self {
        Self {
            inner,
            prefix,
            prefix_offset: 0,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PrefixedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_offset < this.prefix.len() {
            let available = &this.prefix[this.prefix_offset..];
            let length = available.len().min(output.remaining());
            output.put_slice(&available[..length]);
            this.prefix_offset += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Minimal server direction of v2ray-plugin's mux envelope. The Go oracle's
/// client uses one logical stream (ID 0) rather than a general multiplexer.
struct V2rayMuxIo<T> {
    inner: T,
    wire_buffer: Vec<u8>,
    payload: Bytes,
    payload_offset: usize,
    stream_id: Option<[u8; 2]>,
    ended: bool,
    pending_write: Vec<u8>,
    pending_write_offset: usize,
    pending_source_length: usize,
    shutdown_frame_queued: bool,
}

impl<T> V2rayMuxIo<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            wire_buffer: Vec::new(),
            payload: Bytes::new(),
            payload_offset: 0,
            stream_id: None,
            ended: false,
            pending_write: Vec::new(),
            pending_write_offset: 0,
            pending_source_length: 0,
            shutdown_frame_queued: false,
        }
    }

    fn parse_frame(&mut self) -> io::Result<bool> {
        const STATUS_NEW: u8 = 0x01;
        const STATUS_END: u8 = 0x03;
        const STATUS_KEEP_ALIVE: u8 = 0x04;
        const OPTION_NONE: u8 = 0x00;
        const OPTION_DATA: u8 = 0x01;

        if self.wire_buffer.len() < 2 {
            return Ok(false);
        }
        let metadata_length = usize::from(u16::from_be_bytes([
            self.wire_buffer[0],
            self.wire_buffer[1],
        ]));
        if !(4..=512).contains(&metadata_length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid v2ray-plugin mux metadata length",
            ));
        }
        let metadata_end = 2 + metadata_length;
        if self.wire_buffer.len() < metadata_end {
            return Ok(false);
        }
        let stream_id = [self.wire_buffer[2], self.wire_buffer[3]];
        if self.stream_id.is_some_and(|expected| expected != stream_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected v2ray-plugin mux stream ID",
            ));
        }
        let status = self.wire_buffer[4];
        let option = self.wire_buffer[5];
        if status == STATUS_NEW {
            if option != OPTION_NONE || metadata_length < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid v2ray-plugin mux new-stream frame",
                ));
            }
            self.stream_id = Some(stream_id);
        }
        if status == STATUS_END {
            self.ended = true;
        }
        if status == STATUS_KEEP_ALIVE {
            self.wire_buffer.drain(..metadata_end);
            return Ok(true);
        }
        if option == OPTION_DATA {
            if self.wire_buffer.len() < metadata_end + 2 {
                return Ok(false);
            }
            let data_length = usize::from(u16::from_be_bytes([
                self.wire_buffer[metadata_end],
                self.wire_buffer[metadata_end + 1],
            ]));
            let frame_end = metadata_end + 2 + data_length;
            if self.wire_buffer.len() < frame_end {
                return Ok(false);
            }
            self.payload = Bytes::copy_from_slice(&self.wire_buffer[metadata_end + 2..frame_end]);
            self.payload_offset = 0;
            self.wire_buffer.drain(..frame_end);
        } else {
            self.wire_buffer.drain(..metadata_end);
        }
        Ok(true)
    }

    fn queue_data_frame(&mut self, input: &[u8]) -> io::Result<usize> {
        let Some(id) = self.stream_id else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v2ray-plugin mux stream was not opened",
            ));
        };
        let length = input.len().min(usize::from(u16::MAX));
        self.pending_write.reserve(8 + length);
        self.pending_write.extend_from_slice(&4_u16.to_be_bytes());
        self.pending_write.extend_from_slice(&id);
        self.pending_write.extend_from_slice(&[0x02, 0x01]);
        let length = u16::try_from(length).expect("mux frame length is bounded to u16::MAX");
        self.pending_write.extend_from_slice(&length.to_be_bytes());
        self.pending_write
            .extend_from_slice(&input[..usize::from(length)]);
        self.pending_source_length = usize::from(length);
        Ok(usize::from(length))
    }

    fn queue_end_frame(&mut self) {
        if let Some(id) = self.stream_id {
            self.pending_write.extend_from_slice(&4_u16.to_be_bytes());
            self.pending_write.extend_from_slice(&id);
            self.pending_write.extend_from_slice(&[0x03, 0x00]);
        }
        self.shutdown_frame_queued = true;
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for V2rayMuxIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.payload_offset < this.payload.len() {
                let available = &this.payload[this.payload_offset..];
                let length = available.len().min(output.remaining());
                output.put_slice(&available[..length]);
                this.payload_offset += length;
                return Poll::Ready(Ok(()));
            }
            this.payload = Bytes::new();
            this.payload_offset = 0;
            while this.parse_frame()? {
                if !this.payload.is_empty() {
                    break;
                }
                if this.ended {
                    return Poll::Ready(Ok(()));
                }
            }
            if !this.payload.is_empty() {
                continue;
            }
            if this.ended {
                return Poll::Ready(Ok(()));
            }
            let mut buffer = [0_u8; 8192];
            let mut read = ReadBuf::new(&mut buffer);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                if this.wire_buffer.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated v2ray-plugin mux frame",
                )));
            }
            this.wire_buffer.extend_from_slice(read.filled());
        }
    }
}

impl<T: AsyncWrite + Unpin> V2rayMuxIo<T> {
    fn poll_pending_write(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        while self.pending_write_offset < self.pending_write.len() {
            let written = ready!(
                Pin::new(&mut self.inner)
                    .poll_write(cx, &self.pending_write[self.pending_write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write v2ray-plugin mux frame",
                )));
            }
            self.pending_write_offset += written;
        }
        Poll::Ready(Ok(()))
    }

    fn clear_pending_write(&mut self) {
        self.pending_write.clear();
        self.pending_write_offset = 0;
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for V2rayMuxIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write.is_empty() {
            this.queue_data_frame(input)?;
        }
        ready!(this.poll_pending_write(cx))?;
        let length = this.pending_source_length;
        this.pending_source_length = 0;
        this.clear_pending_write();
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending_write(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_pending_write(cx))?;
        if !this.shutdown_frame_queued {
            this.clear_pending_write();
            this.queue_end_frame();
            ready!(this.poll_pending_write(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
