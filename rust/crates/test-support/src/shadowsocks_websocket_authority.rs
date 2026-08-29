use std::error::Error;
use std::fs;
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::serve::Listener;
use bytes::Bytes;
use futures_util::{Sink, Stream};
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let listen = arguments
        .next()
        .ok_or("missing listen address")?
        .parse::<SocketAddr>()?;
    let password = arguments.next().ok_or("missing password")?;
    let cipher = arguments.next().ok_or("missing cipher")?;
    let host = arguments.next().ok_or("missing expected Host")?;
    let path = arguments.next().ok_or("missing expected path")?;
    let certificate = arguments.next();
    let private_key = arguments.next();
    if certificate.is_some() != private_key.is_some() {
        return Err("certificate and private key must be supplied together".into());
    }
    if arguments.next().is_some() {
        return Err("unexpected argument".into());
    }
    let method = CipherKind::from_str(&cipher).map_err(|_| "unsupported cipher")?;
    let server = ServerConfig::new(listen, password, method)?;
    let state = AuthorityState {
        context: Context::new_shared(ServerType::Server),
        method,
        key: Arc::new(server.key().to_vec()),
        host: host.into(),
        path: path.into(),
    };
    let listener = TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;
    let listener = if let (Some(certificate), Some(private_key)) = (certificate, private_key) {
        AuthorityListener::tls(listener, &certificate, &private_key)?
    } else {
        AuthorityListener::Plain(listener)
    };
    println!("READY {local_addr}");
    let router = Router::new().fallback(upgrade).with_state(state);
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
    ) -> Result<Self, Box<dyn Error>> {
        let certificates = rustls_pemfile::certs(&mut BufReader::new(fs::File::open(certificate)?))
            .collect::<Result<Vec<_>, _>>()?;
        let private_key =
            rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(private_key)?))?
                .ok_or("private key is missing")?;
        let config = TlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)?;
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
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    if host != Some(&state.host) || uri.path() != &*state.path {
        eprintln!(
            "rejected WebSocket upgrade: host={host:?} path={} expected_host={} expected_path={}",
            uri.path(),
            state.host,
            state.path
        );
        return StatusCode::BAD_REQUEST.into_response();
    }
    websocket
        .on_upgrade(move |socket| serve_connection(socket, state))
        .into_response()
}

async fn serve_connection(socket: WebSocket, state: AuthorityState) {
    let mut inbound = ProxyServerStream::from_stream(
        state.context,
        AxumWebSocketIo::new(socket),
        state.method,
        &state.key,
    );
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
    fn new(socket: WebSocket) -> Self {
        Self {
            socket,
            read_buffer: Bytes::new(),
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
