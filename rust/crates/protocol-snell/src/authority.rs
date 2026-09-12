use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::aead::{CipherKind, SnellStream};
use crate::header::{COMMAND_TUNNEL, ClientCommand, parse_client_command};
use crate::packet::{encode_udp_response, parse_udp_request};
use crate::{DEFAULT_VERSION, SnellProtocolError};

/// Listen options for the 7E test authority (not a product inbound).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityOptions {
    /// Bind address.
    pub listen: SocketAddr,
    /// Pre-shared key (`psk`).
    pub psk: Vec<u8>,
    /// Clash `version`. `0` means [`DEFAULT_VERSION`].
    pub version: u8,
}

/// Running test authority. Dropping it stops the accept loop.
pub struct Authority {
    /// Address the listener actually bound.
    pub local_addr: SocketAddr,
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
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = async {
                    let _ = (&mut shutdown_rx).await;
                } => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    let psk = psk.clone();
                    tokio::spawn(async move {
                        if let Err(error) = serve_connection(stream, &psk, kind).await {
                            eprintln!("Snell authority connection failed: {error}");
                        }
                    });
                }
            }
        }
    });
    Ok(Authority {
        local_addr,
        shutdown: Some(shutdown_tx),
        join: Some(join),
    })
}

async fn serve_connection(
    stream: TcpStream,
    psk: &[u8],
    kind: CipherKind,
) -> Result<(), SnellProtocolError> {
    let mut inbound = SnellStream::server(stream, psk, kind).await?;
    match read_client_command(&mut inbound).await? {
        ClientCommand::Connect { host, port } => {
            let mut outbound = TcpStream::connect((host.as_str(), port)).await?;
            inbound.write_plain(&[COMMAND_TUNNEL]).await?;
            copy_bidirectional(&mut inbound, &mut outbound).await?;
            let _ = outbound.shutdown().await;
        }
        ClientCommand::Udp => {
            inbound.write_plain(&[COMMAND_TUNNEL]).await?;
            serve_udp(&mut inbound).await?;
        }
    }
    Ok(())
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
