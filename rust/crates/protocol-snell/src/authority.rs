use std::net::SocketAddr;

use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::aead::{CipherKind, SnellStream};
use crate::header::{COMMAND_TUNNEL, parse_connect_header};
use crate::{DEFAULT_VERSION, SnellProtocolError};

/// Listen options for the 7E-A test authority (not a product inbound).
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

/// Binds a Snell TCP authority that splices Connect/ConnectV2 to the requested dest.
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
    let (host, port) = read_connect_header(&mut inbound).await?;
    let mut outbound = TcpStream::connect((host.as_str(), port)).await?;
    inbound.write_plain(&[COMMAND_TUNNEL]).await?;
    copy_bidirectional(&mut inbound, &mut outbound).await?;
    let _ = outbound.shutdown().await;
    Ok(())
}

async fn read_connect_header<S>(
    inbound: &mut SnellStream<S>,
) -> Result<(String, u16), SnellProtocolError>
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
        if let Some(parsed) = parse_connect_header(&buffer)? {
            return Ok(parsed);
        }
    }
}
