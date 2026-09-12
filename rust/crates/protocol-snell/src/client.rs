use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::aead::{CipherKind, SnellStream};
use crate::header::encode_connect_header;
use crate::{DEFAULT_VERSION, SnellProtocolError};

/// Options for a single Snell TCP dial. No session pool in 7E-A.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientOptions {
    /// Pre-shared key (`psk`).
    pub psk: Vec<u8>,
    /// Clash `version`. `0` means [`DEFAULT_VERSION`].
    pub version: u8,
}

/// Wraps an established TCP socket with Snell AEAD and writes the connect header.
///
/// The peer salt and `CommandTunnel` reply are consumed on the first read so this
/// function does not wait for destination data (matches Go outbound Dial).
///
/// # Errors
///
/// Returns when the version is unsupported, the destination host is too long, or
/// the header cannot be written.
pub async fn connect_tcp<S>(
    stream: S,
    destination: &Destination,
    options: &ClientOptions,
) -> Result<SnellStream<S>, SnellProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = if options.version == 0 {
        DEFAULT_VERSION
    } else {
        options.version
    };
    let kind = CipherKind::for_version(version)?;
    let header = encode_connect_header(destination, version)?;
    SnellStream::client(stream, &options.psk, kind, &header).await
}
