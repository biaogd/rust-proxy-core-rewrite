use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::aead::{CipherKind, SnellStream};
use crate::header::{encode_connect_header, encode_udp_header};
use crate::packet::{encode_udp_request, parse_udp_response};
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

/// UDP association over one Snell TCP/AEAD session (v3+).
pub struct SnellUdpAssociation<S> {
    stream: SnellStream<S>,
}

/// Wraps an established TCP socket with Snell AEAD and writes the UDP header.
///
/// # Errors
///
/// Returns when the version is below 3 or the header cannot be written.
pub async fn associate_udp<S>(
    stream: S,
    options: &ClientOptions,
) -> Result<SnellUdpAssociation<S>, SnellProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = if options.version == 0 {
        DEFAULT_VERSION
    } else {
        options.version
    };
    if version < 3 {
        return Err(SnellProtocolError::Protocol(format!(
            "Snell version {version} does not support UDP"
        )));
    }
    let kind = CipherKind::for_version(version)?;
    let stream = SnellStream::client(stream, &options.psk, kind, &encode_udp_header()).await?;
    Ok(SnellUdpAssociation { stream })
}

impl<S> SnellUdpAssociation<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Sends one Snell UDP request frame.
    ///
    /// # Errors
    ///
    /// Returns when the destination cannot be encoded or the AEAD write fails.
    pub async fn send(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), SnellProtocolError> {
        let packet = encode_udp_request(destination, payload)?;
        self.stream.write_plain(&packet).await
    }

    /// Receives one Snell UDP response frame, consuming `CommandTunnel` first.
    ///
    /// # Errors
    ///
    /// Returns when the reply is an error, the frame is truncated, or I/O fails.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), SnellProtocolError> {
        let packet = self.stream.read_plain(0x3FFF).await?;
        parse_udp_response(&packet)
    }
}
