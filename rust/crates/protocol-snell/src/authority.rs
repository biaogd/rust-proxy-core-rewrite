use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use rewrite_transport::{HttpObfsServer, TlsObfsServer};

use crate::aead::{CipherKind, SnellStream};
use crate::header::{COMMAND_TUNNEL, ClientCommand, encode_command_error, parse_client_command};
use crate::packet::{encode_udp_response, parse_udp_request};
use crate::{DEFAULT_VERSION, SnellProtocolError};

/// Simple-obfs wrap for the 7E-C test authority (not a product inbound).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityObfs {
    Http,
    Tls,
}

/// Listen options for the 7E test authority (not a product inbound).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityOptions {
    /// Bind address.
    pub listen: SocketAddr,
    /// Pre-shared key (`psk`).
    pub psk: Vec<u8>,
    /// Clash `version`. `0` means [`DEFAULT_VERSION`].
    pub version: u8,
    /// Optional simple-obfs HTTP/TLS wrap before AEAD.
    pub obfs: Option<AuthorityObfs>,
}

/// Running test authority. Dropping it stops the accept loop.
pub struct Authority {
    /// Address the listener actually bound.
    pub local_addr: SocketAddr,
    /// TCP accepts (one increment per carrier, including reused sessions).
    pub accepted: Arc<AtomicU64>,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl Authority {
    /// Stops accepting and detaches in-flight splices.
    pub fn abort(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Binds a Snell authority that splices TCP Connect and v3 UDP to destinations.
///
/// # Errors
///
/// Returns when the version is unsupported or the listener cannot bind.
pub async fn spawn_authority(options: AuthorityOptions) -> Result<Authority, SnellProtocolError> {
    let version = if options.version == 0 {
        DEFAULT_VERSION
    } else {
        options.version
    };
    let kind = CipherKind::for_version(version)?;
    let listener = TcpListener::bind(options.listen).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let psk = options.psk;
    let obfs = options.obfs;
    let accepted = Arc::new(AtomicU64::new(0));
    let accepted_for_loop = Arc::clone(&accepted);
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = async {
                    let _ = (&mut shutdown_rx).await;
                } => break,
                incoming = listener.accept() => {
                    let Ok((stream, _)) = incoming else {
                        break;
                    };
                    accepted_for_loop.fetch_add(1, Ordering::Relaxed);
                    eprintln!("ACCEPTED");
                    let psk = psk.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_accepted(stream, &psk, kind, obfs).await {
                            eprintln!("Snell authority connection failed: {error}");
                        }
                    });
                }
            }
        }
    });
    Ok(Authority {
        local_addr,
        accepted,
        shutdown: Some(shutdown_tx),
        join: Some(join),
    })
}

async fn serve_accepted(
    stream: TcpStream,
    psk: &[u8],
    kind: CipherKind,
    obfs: Option<AuthorityObfs>,
) -> Result<(), SnellProtocolError> {
    match obfs {
        None => serve_connection(stream, psk, kind).await,
        Some(AuthorityObfs::Http) => {
            serve_connection(HttpObfsServer::new(stream, None), psk, kind).await
        }
        Some(AuthorityObfs::Tls) => {
            serve_connection(TlsObfsServer::new(stream, None), psk, kind).await
        }
    }
}

async fn serve_connection<S>(
    stream: S,
    psk: &[u8],
    kind: CipherKind,
) -> Result<(), SnellProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut inbound = SnellStream::server(stream, psk, kind).await?;
    loop {
        match read_client_command(&mut inbound).await? {
            ClientCommand::Connect { host, port, reuse } => {
                if reuse {
                    inbound.set_hold_inner_shutdown(true);
                }
                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(mut outbound) => {
                        inbound.write_plain(&[COMMAND_TUNNEL]).await?;
                        let copied = copy_bidirectional(&mut inbound, &mut outbound).await;
                        let _ = outbound.shutdown().await;
                        if reuse {
                            if !inbound.zero_chunk_written() {
                                inbound.write_plain(&[]).await?;
                            }
                            inbound.clear_read_after_request();
                            let _ = copied;
                            continue;
                        }
                        copied?;
                        return Ok(());
                    }
                    Err(error) => {
                        if reuse {
                            inbound
                                .write_plain(&encode_command_error(0x65, "Remote EOF"))
                                .await?;
                            continue;
                        }
                        return Err(error.into());
                    }
                }
            }
            ClientCommand::Udp => {
                inbound.write_plain(&[COMMAND_TUNNEL]).await?;
                serve_udp(&mut inbound).await?;
                return Ok(());
            }
        }
    }
}

async fn serve_udp<S>(inbound: &mut SnellStream<S>) -> Result<(), SnellProtocolError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let packet = match inbound.read_plain(0x3FFF).await {
            Ok(packet) => packet,
            Err(SnellProtocolError::Protocol(message)) if message.contains("zero chunk") => {
                return Ok(());
            }
            Err(SnellProtocolError::Io(error))
                if error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if packet.is_empty() {
            return Ok(());
        }
        let (destination, payload) = parse_udp_request(&packet)?;
        let remote = resolve_udp_destination(&destination).await?;
        let bind = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.send_to(&payload, remote).await?;
        let mut response = vec![0_u8; 65_536];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut response))
                .await
                .map_err(|_| {
                    SnellProtocolError::Protocol("Snell UDP authority dest timed out".to_owned())
                })??;
        inbound
            .write_plain(&encode_udp_response(source, &response[..length])?)
            .await?;
    }
}

async fn resolve_udp_destination(
    destination: &rewrite_model::Destination,
) -> Result<SocketAddr, SnellProtocolError> {
    match &destination.host {
        rewrite_model::Host::Ip(address) => Ok(SocketAddr::new(*address, destination.port)),
        rewrite_model::Host::Domain(domain) => {
            tokio::net::lookup_host((domain.as_str(), destination.port))
                .await?
                .find(SocketAddr::is_ipv4)
                .ok_or_else(|| {
                    SnellProtocolError::Protocol(
                        "no IPv4 Snell UDP destination resolved".to_owned(),
                    )
                })
        }
    }
}

async fn read_client_command<S>(
    inbound: &mut SnellStream<S>,
) -> Result<ClientCommand, SnellProtocolError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let chunk = inbound.read_plain(0x3FFF).await?;
        if chunk.is_empty() {
            return Err(SnellProtocolError::Protocol(
                "Snell header ended early".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk);
        if let Some(parsed) = parse_client_command(&buffer)? {
            return Ok(parsed);
        }
    }
}
