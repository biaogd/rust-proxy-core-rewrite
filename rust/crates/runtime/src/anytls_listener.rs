use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use rewrite_config::{AnyTlsInboundConfig, Config, ControllerTls};
use rewrite_inbound::BoxedInboundStream;
use rewrite_model::{Destination, Host, InboundProtocol, Metadata, Network, unmap_ip};
use rewrite_protocol_anytls::{
    AnyTlsProtocolError, PaddingFactory, ServerSession, ServerStream, SharedPadding,
    authenticate_connection, decode_socks_address, default_shared_padding, password_digest_table,
};
use rewrite_state::RuntimeState;
use rewrite_transport::BoxedStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::tcp::serve_shadowsocks_connection;
use crate::types::RuntimeError;

const ANYTLS_MAX_INBOUND_CONNECTIONS: usize = 1024;
const ANYTLS_MAX_STREAMS_PER_CONN: usize = 256;
const ANYTLS_MAX_ADDRESS_BYTES: usize = 260;
const ANYTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const ANYTLS_ADDRESS_TIMEOUT: Duration = Duration::from_secs(10);
const ANYTLS_SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

pub(crate) struct AnyTlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    passwords: HashMap<[u8; 32], String>,
    padding: SharedPadding,
    inbound_name: String,
    listen: SocketAddr,
}

impl AnyTlsListener {
    pub(crate) async fn bind(
        config: &AnyTlsInboundConfig,
        clock: Arc<rewrite_services::AdjustedClock>,
    ) -> Result<Self, RuntimeError> {
        let tls = rewrite_controller::prepare_tls_config(
            &ControllerTls {
                certificate: config.certificate.clone(),
                private_key: config.private_key.clone(),
                client_auth_type: String::new(),
                client_auth_cert: String::new(),
                ech_key: String::new(),
            },
            clock,
        )
        .map_err(RuntimeError::Listener)?;
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(RuntimeError::Listener)?;
        let padding = build_shared_padding(config.padding_scheme.as_deref())?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            passwords: password_digest_table(
                config
                    .users
                    .iter()
                    .map(|user| (user.username.as_str(), user.password.as_str())),
            ),
            padding,
            inbound_name: config.name.clone(),
            listen: config.listen,
        })
    }
}

fn build_shared_padding(scheme: Option<&str>) -> Result<SharedPadding, RuntimeError> {
    match scheme {
        None => Ok(default_shared_padding()),
        Some(raw) => PaddingFactory::new(raw.as_bytes())
            .map(|factory| Arc::new(std::sync::Mutex::new(Arc::new(factory))))
            .ok_or_else(|| {
                RuntimeError::Listener(std::io::Error::other(format!(
                    "anytls inbound padding-scheme is invalid: {raw}"
                )))
            }),
    }
}

struct AnyTlsInboundStream {
    inner: ServerStream,
    prefix: Cursor<Vec<u8>>,
    local: SocketAddr,
    peer: SocketAddr,
}

impl AnyTlsInboundStream {
    fn new(inner: ServerStream, prefix: Vec<u8>, local: SocketAddr, peer: SocketAddr) -> Self {
        Self {
            inner,
            prefix: Cursor::new(prefix),
            local,
            peer,
        }
    }
}

impl AsyncRead for AnyTlsInboundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let position = self.prefix.position() as usize;
        let prefix_len = self.prefix.get_ref().len();
        if position < prefix_len {
            let amount = (prefix_len - position).min(buf.remaining());
            buf.put_slice(&self.prefix.get_ref()[position..position + amount]);
            self.prefix.set_position((position + amount) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AnyTlsInboundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl rewrite_inbound::InboundStream for AnyTlsInboundStream {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }
}

pub(super) async fn run_anytls_listener(
    listener: AnyTlsListener,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let AnyTlsListener {
        listener,
        acceptor,
        passwords,
        padding,
        inbound_name,
        listen,
    } = listener;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else {
                    state.log("error", "anytls inbound accept failed");
                    break;
                };
                let connection_config = Arc::clone(&*config.borrow());
                if !connection_config.permits_inbound(peer.ip()) {
                    continue;
                }
                if connections.len() >= ANYTLS_MAX_INBOUND_CONNECTIONS {
                    state.log(
                        "warning",
                        format!(
                            "anytls inbound connection limit reached ({ANYTLS_MAX_INBOUND_CONNECTIONS})"
                        ),
                    );
                    continue;
                }
                let local = tcp.local_addr().unwrap_or(listen);
                let acceptor = acceptor.clone();
                let passwords = passwords.clone();
                let padding = padding.clone();
                let connection_state = Arc::clone(&state);
                let connection_dns = Arc::clone(&dns_service);
                let connection_shutdown = shutdown.child_token();
                let connection_inbound_name = inbound_name.clone();
                connections.spawn(async move {
                    Box::pin(handle_anytls_inbound(
                        tcp,
                        peer,
                        local,
                        acceptor,
                        passwords,
                        padding,
                        connection_config,
                        connection_state,
                        connection_dns,
                        connection_shutdown,
                        connection_inbound_name,
                    ))
                    .await;
                });
            }
            Some(result) = connections.join_next() => {
                if let Err(error) = result {
                    state.log("error", format!("anytls inbound task failed: {error}"));
                }
            }
        }
    }
    // Child tokens already cancelled; give connection tasks time to close
    // sessions before aborting stragglers.
    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(ANYTLS_SHUTDOWN_DRAIN, drain)
        .await
        .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_anytls_inbound(
    tcp: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    acceptor: TlsAcceptor,
    passwords: HashMap<[u8; 32], String>,
    padding: SharedPadding,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
    inbound_name: String,
) {
    let mut tls = match tokio::time::timeout(ANYTLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            state.log(
                "error",
                format!("anytls inbound TLS handshake failed: {error}"),
            );
            return;
        }
        Err(_) => {
            state.log("error", "anytls inbound TLS handshake timed out");
            return;
        }
    };

    let username = match tokio::time::timeout(
        ANYTLS_HANDSHAKE_TIMEOUT,
        authenticate_connection(&mut tls, &passwords),
    )
    .await
    {
        Ok(Ok(Some(username))) => username,
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            state.log(
                "error",
                format!("anytls inbound authentication failed: {error}"),
            );
            return;
        }
        Err(_) => {
            state.log("error", "anytls inbound authentication timed out");
            return;
        }
    };

    let (session, mut stream_rx) = ServerSession::start(Box::new(tls) as BoxedStream, padding);
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => {
                session.close();
                break;
            }
            () = session.wait_closed() => break,
            Some(result) = streams.join_next(), if !streams.is_empty() => {
                if let Err(error) = result {
                    state.log("error", format!("anytls inbound stream task failed: {error}"));
                }
            }
            stream = stream_rx.recv() => {
                match stream {
                    Some(stream) => {
                        if streams.len() >= ANYTLS_MAX_STREAMS_PER_CONN {
                            state.log(
                                "warning",
                                format!(
                                    "anytls inbound stream limit reached ({ANYTLS_MAX_STREAMS_PER_CONN})"
                                ),
                            );
                            // Dropping the stream sends FIN and frees the session map slot.
                            continue;
                        }
                        let config = Arc::clone(&config);
                        let state = Arc::clone(&state);
                        let dns_service = Arc::clone(&dns_service);
                        let shutdown = shutdown.child_token();
                        let inbound_name = inbound_name.clone();
                        let username = username.clone();
                        streams.spawn(async move {
                            handle_anytls_stream(
                                stream,
                                peer,
                                local,
                                username,
                                inbound_name,
                                config,
                                state,
                                dns_service,
                                shutdown,
                            )
                            .await;
                        });
                    }
                    None => break,
                }
            }
        }
    }
    session.close();
    let _ = tokio::time::timeout(ANYTLS_SHUTDOWN_DRAIN, session.wait_closed()).await;
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

#[allow(clippy::too_many_arguments)]
async fn handle_anytls_stream(
    mut stream: ServerStream,
    peer: SocketAddr,
    local: SocketAddr,
    username: String,
    inbound_name: String,
    config: Arc<Config>,
    state: Arc<RuntimeState>,
    dns_service: Arc<rewrite_dns::DnsService>,
    shutdown: CancellationToken,
) {
    let (destination, prefix) = match read_socks_destination(&mut stream, &shutdown).await {
        Ok(parsed) => parsed,
        Err(error) => {
            state.log(
                "error",
                format!("anytls inbound destination read failed: {error}"),
            );
            return;
        }
    };

    if let Err(error) = stream.handshake_success().await {
        state.log(
            "error",
            format!("anytls inbound stream handshake failed: {error}"),
        );
        return;
    }

    if is_anytls_uot_destination(&destination) {
        state.log(
            "error",
            format!(
                "anytls inbound UDP-over-TCP destination {} is not supported in IN-G first slice",
                destination.authority()
            ),
        );
        return;
    }

    serve_anytls_tcp(
        stream,
        prefix,
        peer,
        local,
        destination,
        username,
        inbound_name,
        &config,
        &state,
        &dns_service,
        &shutdown,
    )
    .await;
}

async fn read_socks_destination(
    stream: &mut ServerStream,
    shutdown: &CancellationToken,
) -> Result<(Destination, Vec<u8>), AnyTlsProtocolError> {
    let read = async {
        let mut buffer = Vec::with_capacity(64);
        let mut chunk = [0_u8; 64];
        loop {
            if buffer.len() > ANYTLS_MAX_ADDRESS_BYTES {
                return Err(AnyTlsProtocolError::Protocol(
                    "AnyTLS socks address exceeds maximum length".to_owned(),
                ));
            }
            let read = tokio::select! {
                () = shutdown.cancelled() => {
                    return Err(AnyTlsProtocolError::Protocol(
                        "AnyTLS destination read cancelled".to_owned(),
                    ));
                }
                result = stream.read(&mut chunk) => result?,
            };
            if read == 0 {
                return Err(AnyTlsProtocolError::Protocol(
                    "AnyTLS stream closed before destination address".to_owned(),
                ));
            }
            buffer.extend_from_slice(&chunk[..read]);
            match decode_socks_address(&buffer) {
                Ok((destination, consumed)) => {
                    let prefix = buffer.split_off(consumed);
                    return Ok((destination, prefix));
                }
                Err(AnyTlsProtocolError::Protocol(message))
                    if message.contains("truncated") || message.contains("empty") => {}
                Err(error) => return Err(error),
            }
        }
    };
    match tokio::time::timeout(ANYTLS_ADDRESS_TIMEOUT, read).await {
        Ok(result) => result,
        Err(_) => Err(AnyTlsProtocolError::Protocol(
            "AnyTLS destination read timed out".to_owned(),
        )),
    }
}

fn is_anytls_uot_destination(destination: &Destination) -> bool {
    matches!(
        (&destination.host, destination.port),
        (Host::Domain(domain), 0)
            if domain == "sp.v2.udp-over-tcp.arpa" || domain == "sp.udp-over-tcp.arpa"
    )
}

#[allow(clippy::too_many_arguments)]
async fn serve_anytls_tcp(
    stream: ServerStream,
    prefix: Vec<u8>,
    peer: SocketAddr,
    local: SocketAddr,
    destination: Destination,
    username: String,
    inbound_name: String,
    config: &Config,
    state: &Arc<RuntimeState>,
    dns_service: &Arc<rewrite_dns::DnsService>,
    shutdown: &CancellationToken,
) {
    let mut metadata = Metadata::new(destination, InboundProtocol::AnyTls);
    metadata.network = Network::Tcp;
    metadata.source_ip = Some(unmap_ip(peer.ip()));
    metadata.source_port = peer.port();
    metadata.inbound_port = local.port();
    inbound_name.clone_into(&mut metadata.inbound_name);
    metadata.inbound_user = username;
    let client: BoxedInboundStream =
        Box::new(AnyTlsInboundStream::new(stream, prefix, local, peer));
    serve_shadowsocks_connection(client, metadata, config, state, dns_service, shutdown).await;
}
