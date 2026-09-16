//! Transport-independent `VMess` protocol implementation.
//!
//! No maintained, narrowly scoped embeddable client crate was available at
//! this phase boundary. `RustCrypto` owns every cryptographic primitive.
//! Socket dialing, outer transports, routing and configuration parsing remain
//! outside this crate so inbound and outbound adapters can share the wire code.

mod body;
mod header;
mod kdf;
mod packet;
mod server;
mod stream;

use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use thiserror::Error;
use tokio::io::AsyncWriteExt as _;

use body::{BodyOptions, BodyReader, BodyWriter};
use header::{SealRequestOptions, command_key, seal_request_header};
use stream::VmessTcpStream;

pub use header::{DEFAULT_TIMESTAMP_SKEW_SECS, VmessCommand, timestamp_within_skew};
pub use packet::{
    VmessPacketMode, VmessUdpAssociation, VmessXudpReadBuffer, associate_vmess_udp_on_stream,
    encode_xudp_server_frame,
};
pub use server::{
    AuthIdReplayCache, DEFAULT_AUTH_ID_REPLAY_GLOBAL, DEFAULT_AUTH_ID_REPLAY_PER_USER,
    VmessAcceptOptions, VmessServerReader, VmessServerRequest, VmessServerSession,
    VmessServerWriter, VmessUserEntry, accept_vmess_request, map_uuid, uuid_table,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmessSecurity {
    Auto,
    None,
    Aes128Cfb,
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl VmessSecurity {
    const fn resolved(self) -> Self {
        match self {
            Self::Auto
                if cfg!(any(
                    target_arch = "x86_64",
                    target_arch = "aarch64",
                    target_arch = "s390x"
                )) =>
            {
                Self::Aes128Gcm
            }
            Self::Auto => Self::ChaCha20Poly1305,
            explicit => explicit,
        }
    }
}

fn fnv1a32(input: &[u8]) -> u32 {
    input.iter().fold(0x811c_9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmessClientOptions {
    pub uuid: [u8; 16],
    pub alter_id: i64,
    pub security: VmessSecurity,
    pub global_padding: bool,
    pub authenticated_length: bool,
}

#[derive(Debug, Error)]
pub enum VmessProtocolError {
    #[error("{0}")]
    Transport(String),
    #[error("VMess I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("VMess protocol failed: {0}")]
    Protocol(String),
}

/// Starts a `VMess` TCP session over an already established outer transport.
///
/// This boundary lets TLS and WebSocket remain shared transport adapters while
/// the `VMess` module owns only its authenticated header and body records.
///
/// After WriteHeader the returned stream encodes/decodes body records in place
/// (no duplex relay copy), matching the VLESS TCP path.
///
/// # Errors
///
/// Returns an error when the request header cannot be built or written.
pub async fn connect_vmess_on_stream(
    remote: BoxedStream,
    destination: &Destination,
    options: VmessClientOptions,
) -> Result<BoxedStream, VmessProtocolError> {
    let connected =
        connect_protocol_on_stream(remote, destination, options, VmessCommand::Tcp, false).await?;
    let ConnectedVmess {
        remote,
        body_reader,
        body_writer,
        response_key,
        response_iv,
        response_verification,
        legacy_header,
        ..
    } = connected;
    Ok(Box::new(VmessTcpStream::client(
        remote,
        body_reader,
        body_writer,
        response_key,
        response_iv,
        response_verification,
        legacy_header,
    )))
}

pub(crate) struct ConnectedVmess {
    pub(crate) remote: BoxedStream,
    pub(crate) body_reader: BodyReader,
    pub(crate) body_writer: BodyWriter,
    pub(crate) response_key: [u8; 16],
    pub(crate) response_iv: [u8; 16],
    pub(crate) response_verification: u8,
    pub(crate) legacy_header: bool,
    pub(crate) response_header_read: bool,
}

pub(crate) async fn connect_protocol_on_stream(
    mut remote: BoxedStream,
    destination: &Destination,
    options: VmessClientOptions,
    command: VmessCommand,
    chunked_none: bool,
) -> Result<ConnectedVmess, VmessProtocolError> {
    let security = options.security.resolved();
    let sealed = seal_request_header(
        &options.uuid,
        &command_key(&options.uuid),
        destination,
        SealRequestOptions {
            alter_id: options.alter_id,
            security,
            command,
            global_padding: options.global_padding,
            authenticated_length: options.authenticated_length,
            chunk_masking: true,
        },
    )?;
    remote.write_all(&sealed.wire).await?;

    let (body_reader, body_writer, response_key, response_iv) = body::pair(
        security,
        &sealed.request_key,
        &sealed.request_iv,
        BodyOptions {
            legacy_header: options.alter_id > 0,
            chunked_none,
            // Product AEAD clients always set ChunkStream|ChunkMasking; CFB uses
            // ChunkStream only (no length XOR).
            chunk_masking: matches!(
                security,
                VmessSecurity::Aes128Gcm | VmessSecurity::ChaCha20Poly1305
            ),
            global_padding: options.global_padding,
            authenticated_length: options.authenticated_length,
        },
    );
    Ok(ConnectedVmess {
        remote,
        body_reader,
        body_writer,
        response_key,
        response_iv,
        response_verification: sealed.response_verification,
        legacy_header: options.alter_id > 0,
        response_header_read: false,
    })
}
