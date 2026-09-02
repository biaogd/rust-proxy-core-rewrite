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

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

use body::{BodyOptions, BodyReader, BodyWriter};
use header::{
    SealRequestOptions, VmessCommand, command_key, read_response_header, seal_request_header,
};

pub use packet::{VmessPacketMode, VmessUdpAssociation, associate_vmess_udp_on_stream};

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
/// # Errors
///
/// Returns an error when the request header cannot be built or written. Relay
/// failures after setup close the returned application stream.
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
    let cancellation = CancellationToken::new();
    let (application, relay) = tokio::io::duplex(64 * 1024);
    let task_cancellation = cancellation.clone();
    tokio::spawn(async move {
        run_relay(
            remote,
            relay,
            body_reader,
            body_writer,
            response_key,
            response_iv,
            response_verification,
            legacy_header,
            task_cancellation,
        )
        .await;
    });
    Ok(Box::new(VmessRelayStream {
        inner: application,
        cancellation,
    }))
}

struct ConnectedVmess {
    remote: BoxedStream,
    body_reader: BodyReader,
    body_writer: BodyWriter,
    response_key: [u8; 16],
    response_iv: [u8; 16],
    response_verification: u8,
    legacy_header: bool,
    response_header_read: bool,
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

struct VmessRelayStream {
    inner: tokio::io::DuplexStream,
    cancellation: CancellationToken,
}

impl Drop for VmessRelayStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl AsyncRead for VmessRelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for VmessRelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_relay(
    remote: BoxedStream,
    relay: tokio::io::DuplexStream,
    mut body_reader: BodyReader,
    mut body_writer: BodyWriter,
    response_key: [u8; 16],
    response_iv: [u8; 16],
    response_verification: u8,
    legacy_header: bool,
    cancellation: CancellationToken,
) {
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
    let (mut plain_read, mut plain_write) = tokio::io::split(relay);
    let read_cancellation = cancellation.clone();
    let write_cancellation = cancellation.clone();

    let read_loop = async move {
        if legacy_header {
            tokio::select! {
                () = read_cancellation.cancelled() => return Ok(()),
                result = body_reader.read_legacy_response_header(
                    &mut remote_read,
                    &response_key,
                    &response_iv,
                    response_verification,
                ) => result?,
            }
        } else {
            tokio::select! {
                () = read_cancellation.cancelled() => return Ok(()),
                result = read_response_header(
                    &mut remote_read,
                    &response_key,
                    &response_iv,
                    response_verification,
                ) => result?,
            }
        }
        loop {
            let plaintext = tokio::select! {
                () = read_cancellation.cancelled() => break,
                result = body_reader.read_record(&mut remote_read) => match result {
                    Ok(plaintext) => plaintext,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error),
                },
            };
            plain_write.write_all(&plaintext).await?;
        }
        plain_write.shutdown().await
    };

    let write_loop = async move {
        let mut buffer = vec![0_u8; BodyWriter::maximum_plaintext()];
        loop {
            let size = tokio::select! {
                () = write_cancellation.cancelled() => return Ok::<(), std::io::Error>(()),
                result = plain_read.read(&mut buffer) => result?,
            };
            if size == 0 {
                remote_write.shutdown().await?;
                return Ok(());
            }
            body_writer
                .write_record(&mut remote_write, &buffer[..size])
                .await?;
        }
    };

    tokio::pin!(read_loop);
    tokio::pin!(write_loop);
    tokio::select! {
        () = cancellation.cancelled() => {}
        _ = &mut read_loop => cancellation.cancel(),
        write_result = &mut write_loop => {
            if write_result.is_err() {
                cancellation.cancel();
            } else {
                tokio::select! {
                    () = cancellation.cancelled() => {}
                    _ = &mut read_loop => {}
                }
            }
        }
    }
}
