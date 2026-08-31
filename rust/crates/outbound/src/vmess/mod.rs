//! Minimal `VMess` AEAD client for the Phase 6D-A native-TCP boundary.
//!
//! No maintained, narrowly scoped embeddable client crate was available at
//! this phase boundary. Protocol framing is kept here while `RustCrypto` owns
//! every cryptographic primitive. Transport and routing policy remain outside
//! this module.

mod body;
mod header;
mod kdf;

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_model::Destination;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

use crate::{BoxedOutboundStream, DirectError, DirectTcpOptions, connect_with_options};
use body::{BodyReader, BodyWriter};
use header::{auto_security, command_key, read_response_header, seal_request_header};

#[derive(Debug, Error)]
pub enum VmessProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error("VMess I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("VMess protocol failed: {0}")]
    Protocol(String),
}

/// Connects a `VMess` AEAD client over native TCP.
///
/// Phase 6D-A intentionally accepts only `AlterID` zero and the oracle's `auto`
/// security selection; configuration validation owns those restrictions.
///
/// # Errors
///
/// Returns an error when the upstream TCP connection, request header write, or
/// local protocol setup fails. Relay errors after setup close the returned
/// stream and are observable by the caller as I/O failure or EOF.
pub async fn connect_vmess_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    uuid: &[u8; 16],
    socket_options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, VmessProxyError> {
    let mut remote = connect_with_options(server, allow_ipv6, socket_options).await?;
    let security = auto_security();
    let sealed = seal_request_header(&command_key(uuid), security, destination)?;
    remote.write_all(&sealed.wire).await?;

    let (body_reader, body_writer, response_key, response_iv) =
        body::pair(security, &sealed.request_key, &sealed.request_iv);
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
            sealed.response_verification,
            task_cancellation,
        )
        .await;
    });
    Ok(Box::new(VmessRelayStream {
        inner: application,
        cancellation,
    }))
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
    remote: tokio::net::TcpStream,
    relay: tokio::io::DuplexStream,
    mut body_reader: BodyReader,
    mut body_writer: BodyWriter,
    response_key: [u8; 16],
    response_iv: [u8; 16],
    response_verification: u8,
    cancellation: CancellationToken,
) {
    let (mut remote_read, mut remote_write) = remote.into_split();
    let (mut plain_read, mut plain_write) = tokio::io::split(relay);
    let read_cancellation = cancellation.clone();
    let write_cancellation = cancellation.clone();

    let read_loop = async move {
        tokio::select! {
            () = read_cancellation.cancelled() => return Ok(()),
            result = read_response_header(
                &mut remote_read,
                &response_key,
                &response_iv,
                response_verification,
            ) => result?,
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
