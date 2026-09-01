use std::sync::Arc;
use std::time::Duration;

use fast_socks5::util::target_addr::{TargetAddr, ToTargetAddr, read_address};
use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::BoxedOutboundStream;
use crate::direct::{DirectError, DirectTcpOptions};
use rewrite_transport::ClientTlsOptions as HttpProxyTls;

use super::auth::password_auth;
use super::{Socks5ProxyError, connect_control};

/// Opens a TCP stream through a SOCKS5 proxy using remote target addressing.
///
/// # Errors
///
/// Returns [`Socks5ProxyError`] when proxy connection, authentication or the
/// CONNECT request fails.
pub async fn connect_socks5(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
) -> Result<BoxedOutboundStream, Socks5ProxyError> {
    connect_socks5_with_options(
        server,
        destination,
        allow_ipv6,
        credentials,
        None,
        None,
        DirectTcpOptions::default(),
    )
    .await
}

/// Opens a SOCKS5 tunnel with global platform socket policy.
///
/// # Errors
///
/// Returns [`Socks5ProxyError`] under the same conditions as [`connect_socks5`].
pub async fn connect_socks5_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    credentials: Option<(&str, &str)>,
    tls: Option<HttpProxyTls<'_>>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, Socks5ProxyError> {
    let mut stream = connect_control(server, allow_ipv6, tls, clock, options).await?;
    tokio::time::timeout(
        Duration::from_secs(5),
        command_handshake(&mut stream, destination, 1, credentials),
    )
    .await
    .map_err(|_| Socks5ProxyError::HandshakeTimeout)??;
    Ok(stream)
}

pub(super) async fn command_handshake<S>(
    stream: &mut S,
    destination: &Destination,
    command: u8,
    credentials: Option<(&str, &str)>,
) -> Result<TargetAddr, Socks5ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method = if credentials.is_some() { 2 } else { 0 };
    stream
        .write_all(&[5, 1, method])
        .await
        .map_err(DirectError::Io)?;
    let mut selection = [0_u8; 2];
    stream
        .read_exact(&mut selection)
        .await
        .map_err(DirectError::Io)?;
    if selection[0] != 5 {
        return Err(Socks5ProxyError::UnsupportedVersion);
    }
    if selection[1] == 2 {
        let Some((username, password)) = credentials else {
            return Err(Socks5ProxyError::AuthenticationRejected);
        };
        password_auth(stream, username, password).await?;
    } else if selection[1] != 0 {
        return Err(Socks5ProxyError::AuthenticationRejected);
    }

    let target = destination.host.to_string();
    let address = (target.as_str(), destination.port)
        .to_target_addr()
        .map_err(DirectError::Io)?;
    let address = address
        .to_be_bytes()
        .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
    let mut request = Vec::with_capacity(address.len() + 3);
    request.extend_from_slice(&[5, command, 0]);
    request.extend_from_slice(&address);
    stream.write_all(&request).await.map_err(DirectError::Io)?;

    // The pinned Go client intentionally ignores VER, REP and RSV here and
    // accepts the tunnel when the returned bind address is well-formed.
    let mut response = [0_u8; 4];
    stream
        .read_exact(&mut response)
        .await
        .map_err(DirectError::Io)?;
    let address = read_address(stream, response[3])
        .await
        .map_err(|error| Socks5ProxyError::InvalidAddress(error.to_string()))?;
    Ok(address)
}
