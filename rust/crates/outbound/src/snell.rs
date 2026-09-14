use std::sync::Arc;

use rewrite_config::SnellObfs;
use rewrite_model::Destination;
use thiserror::Error;

use crate::{
    BoxedOutboundStream, DirectError, DirectTcpOptions, HttpObfsClient, TlsObfsClient,
    connect_with_options,
};

pub use rewrite_protocol_snell::{PooledSnellStream, SnellSessionPool, SnellUdpAssociation};

/// Product-facing v2 `ConnectV2` pool over a boxed TCP/obfs carrier.
pub type BoxedSnellSessionPool = SnellSessionPool<BoxedOutboundStream>;

#[derive(Debug, Error)]
pub enum SnellProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    ProtocolCore(#[from] rewrite_protocol_snell::SnellProtocolError),
}

/// Opens the upstream TCP socket, then writes the Snell AEAD connect header.
///
/// # Errors
///
/// Returns when the server cannot be dialed or the Snell handshake cannot start.
#[allow(clippy::too_many_arguments)]
pub async fn connect_snell_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    psk: &[u8],
    version: u8,
    obfs: Option<&SnellObfs>,
    options: DirectTcpOptions<'_>,
    pool: Option<Arc<BoxedSnellSessionPool>>,
) -> Result<BoxedOutboundStream, SnellProxyError> {
    let client = rewrite_protocol_snell::ClientOptions {
        psk: psk.to_vec(),
        version,
    };
    if let Some(pool) = pool {
        let mut stream = if let Some(existing) = pool.take() {
            existing
        } else {
            let raw = apply_snell_obfs(
                Box::new(connect_with_options(server, allow_ipv6, options).await?),
                server,
                obfs,
            );
            rewrite_protocol_snell::open_tcp(raw, &client).await?
        };
        rewrite_protocol_snell::write_connect(&mut stream, destination, version).await?;
        return Ok(Box::new(PooledSnellStream::new(stream, pool)));
    }
    let stream = apply_snell_obfs(
        Box::new(connect_with_options(server, allow_ipv6, options).await?),
        server,
        obfs,
    );
    let wrapped = rewrite_protocol_snell::connect_tcp(stream, destination, &client).await?;
    Ok(Box::new(wrapped))
}

/// Completes Snell obfs + AEAD connect on an established stream (no pool take).
///
/// Version 2 still enables `ConnectV2` zero-chunk half-close even without pool
/// reuse: client `shutdown` must send the protocol end record instead of FIN.
///
/// # Errors
///
/// Returns when the Snell handshake cannot start.
pub async fn connect_snell_on_stream(
    stream: BoxedOutboundStream,
    destination: &Destination,
    psk: &[u8],
    version: u8,
    obfs: Option<&SnellObfs>,
    server: &Destination,
) -> Result<BoxedOutboundStream, SnellProxyError> {
    let client = rewrite_protocol_snell::ClientOptions {
        psk: psk.to_vec(),
        version,
    };
    let stream = apply_snell_obfs(stream, server, obfs);
    let mut wrapped = rewrite_protocol_snell::connect_tcp(stream, destination, &client).await?;
    if version == 2 {
        // Chained dials stay outside the session pool, but ConnectV2 still
        // requires zero-chunk half-close so destinations that wait for EOF
        // can reply on the retained read half.
        wrapped.set_hold_inner_shutdown(true);
    }
    Ok(Box::new(wrapped))
}

/// Opens the upstream TCP socket, then writes the Snell v3 UDP association header.
///
/// # Errors
///
/// Returns when the server cannot be dialed, the version is below 3, or the
/// association header cannot be written.
pub async fn associate_snell_udp_with_options(
    server: &Destination,
    allow_ipv6: bool,
    psk: &[u8],
    version: u8,
    obfs: Option<&SnellObfs>,
    options: DirectTcpOptions<'_>,
) -> Result<SnellUdpAssociation<BoxedOutboundStream>, SnellProxyError> {
    let stream = apply_snell_obfs(
        Box::new(connect_with_options(server, allow_ipv6, options).await?),
        server,
        obfs,
    );
    Ok(rewrite_protocol_snell::associate_udp(
        stream,
        &rewrite_protocol_snell::ClientOptions {
            psk: psk.to_vec(),
            version,
        },
    )
    .await?)
}

fn apply_snell_obfs(
    stream: BoxedOutboundStream,
    server: &Destination,
    obfs: Option<&SnellObfs>,
) -> BoxedOutboundStream {
    match obfs {
        None => stream,
        Some(SnellObfs::Http { host }) => {
            Box::new(HttpObfsClient::new(stream, host.clone(), server.port))
        }
        Some(SnellObfs::Tls { host }) => Box::new(TlsObfsClient::new(stream, host.clone())),
    }
}

#[cfg(test)]
mod tests {
    use rewrite_model::{Destination, Host};
    use rewrite_protocol_snell::{AuthorityOptions, spawn_authority};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::connect_snell_on_stream;

    #[tokio::test]
    async fn chained_v2_path_preserves_protocol_half_close() {
        let half = spawn_half_close().await;
        let authority = spawn_authority(AuthorityOptions {
            listen: "127.0.0.1:0".parse().expect("listen"),
            psk: b"password".to_vec(),
            version: 2,
            obfs: None,
        })
        .await
        .expect("authority");
        let carrier = TcpStream::connect(authority.local_addr)
            .await
            .expect("pre-dial as dialer-proxy would");
        let server = Destination {
            host: Host::Ip(authority.local_addr.ip()),
            port: authority.local_addr.port(),
        };
        let mut stream = connect_snell_on_stream(
            Box::new(carrier),
            &half.destination,
            b"password",
            2,
            None,
            &server,
        )
        .await
        .expect("snell on stream");
        stream.write_all(b"chain-half").await.expect("write");
        stream.shutdown().await.expect("protocol half-close");
        let mut got = Vec::new();
        stream
            .read_to_end(&mut got)
            .await
            .expect("read after half-close");
        assert_eq!(got, b"after:chain-half");
    }

    struct HalfCloseServer {
        destination: Destination,
    }

    async fn spawn_half_close() -> HalfCloseServer {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("half-close bind");
        let local = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut received = Vec::new();
                    let mut buf = vec![0_u8; 65_536];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => received.extend_from_slice(&buf[..n]),
                            Err(_) => return,
                        }
                    }
                    let mut reply = b"after:".to_vec();
                    reply.extend_from_slice(&received);
                    let _ = stream.write_all(&reply).await;
                });
            }
        });
        HalfCloseServer {
            destination: Destination {
                host: Host::Ip(local.ip()),
                port: local.port(),
            },
        }
    }
}
