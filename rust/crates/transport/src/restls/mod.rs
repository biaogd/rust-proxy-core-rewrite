//! Restls TLS 1.3 client carrier. TLS 1.2 remains explicitly unsupported.
mod codec;

use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use futures_util::StreamExt;
use shadow_rustls::{ClientConnection, client::Resumption, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::oneshot;
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

use crate::{BoxedStream, ClientTlsOptions, shadow_tls_config::shadow_client_config};
use codec::{Records, invalid};

/// Options for a Restls carrier. Certificate policy remains caller-owned.
pub struct RestlsConnectOptions<'a> {
    pub tls: ClientTlsOptions<'a>,
    pub password: &'a str,
    pub version_hint: &'a str,
    pub script: &'a str,
    pub client_fingerprint: Option<&'a str>,
}

type Reader = FramedRead<tokio::io::ReadHalf<BoxedStream>, LengthDelimitedCodec>;
type Writer = tokio::io::WriteHalf<BoxedStream>;

/// Authenticates Restls over TLS 1.3 before releasing any application bytes.
///
/// # Errors
/// Rejects unsupported versions, invalid scripts, TLS/certificate failures, and
/// unauthenticated camouflage peers. Handshakes have a 15-second deadline.
pub async fn connect_restls(
    stream: BoxedStream,
    mut options: RestlsConnectOptions<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> io::Result<BoxedStream> {
    if !options.version_hint.eq_ignore_ascii_case("tls13") {
        return Err(invalid(
            "Restls TLS 1.2 is not implemented; version-hint must be tls13",
        ));
    }
    let script = codec::parse_script(options.script)?;
    let key = blake3::derive_key("restls-traffic-key", options.password.as_bytes());
    let server_name =
        ServerName::try_from(options.tls.server_name.to_owned()).map_err(io::Error::other)?;
    options.tls.tls12_only = false;
    options.tls.tls13_only = true;
    let mut config = shadow_client_config(
        options.tls,
        options.client_fingerprint.or(Some("chrome")),
        true,
        clock,
    )
    .map_err(io::Error::other)?;
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    let random = Arc::new(Mutex::new([0; 32]));
    let captured_random = Arc::clone(&random);
    let hello_error = Arc::new(Mutex::new(false));
    let capture_error = Arc::clone(&hello_error);
    let mut session = ClientConnection::new_with_tls13_record_auth(
        Arc::new(config),
        server_name,
        move |hello| {
            if let Ok(sid) = codec::session_id(&key, hello) {
                sid
            } else {
                *capture_error
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                [0; 32]
            }
        },
        move |server_random| {
            *captured_random
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = *server_random;
            let hash = blake3::keyed_hash(&key, server_random);
            let mut mask = [0; 16];
            mask.copy_from_slice(&hash.as_bytes()[..16]);
            mask
        },
    )
    .map_err(io::Error::other)?;
    if *hello_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return Err(invalid(
            "Restls ClientHello authentication construction failed",
        ));
    }
    let (read, mut write) = tokio::io::split(stream);
    let codec = LengthDelimitedCodec::builder()
        .length_field_offset(3)
        .length_field_length(2)
        .length_adjustment(5)
        .num_skip(0)
        .max_frame_length(18432)
        .new_codec();
    let mut read = FramedRead::new(read, codec);
    let finished = tokio::time::timeout(
        Duration::from_secs(15),
        handshake(&mut session, &mut read, &mut write),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Restls handshake timeout"))??;
    if !session.tls13_record_authenticated() {
        return Err(invalid("Restls server authentication failed"));
    }
    let records = Records {
        key,
        random: *random
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        sent: 0,
        received: 0,
        finished,
        script,
    };
    Ok(start_relay(read, write, session, records))
}

fn start_relay(
    read: Reader,
    write: Writer,
    session: ClientConnection,
    records: Records,
) -> BoxedStream {
    let (app, mut endpoint) = tokio::io::duplex(64 * 1024);
    let (cancel, cancelled) = oneshot::channel();
    let failure = Arc::new(Mutex::new(None));
    let task_failure = Arc::clone(&failure);
    tokio::spawn(async move {
        let result = tokio::select! {
            _ = cancelled => Ok(()),
            result = relay(&mut endpoint, read, write, session, records) => result,
        };
        if let Err(error) = result {
            *task_failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((error.kind(), error.to_string()));
        }
    });
    Box::new(RestlsStream {
        app,
        cancel: Some(cancel),
        failure,
    })
}

async fn next_record(read: &mut Reader) -> io::Result<BytesMut> {
    read.next()
        .await
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
}

async fn handshake(
    session: &mut ClientConnection,
    read: &mut Reader,
    write: &mut Writer,
) -> io::Result<Vec<u8>> {
    loop {
        let mut flight = Vec::new();
        while session.wants_write() {
            session.write_tls(&mut flight)?;
        }
        write.write_all(&flight).await?;
        write.flush().await?;
        if !session.is_handshaking() {
            // No client certificate or early data is requested by this carrier.
            // The final encrypted record is ClientFinished, including its TLS header.
            let mut last = Vec::new();
            let mut remaining = flight.as_slice();
            while remaining.len() >= 5 {
                let length = 5 + usize::from(u16::from_be_bytes([remaining[3], remaining[4]]));
                if length > remaining.len() {
                    return Err(invalid("truncated outgoing TLS flight"));
                }
                if remaining[0] == 23 {
                    last = remaining[..length].to_vec();
                }
                remaining = &remaining[length..];
            }
            if last.is_empty() {
                return Err(invalid("missing TLS ClientFinished"));
            }
            return Ok(last);
        }
        let record = next_record(read).await?;
        session.read_tls(&mut Cursor::new(&record[..]))?;
        session.process_new_packets().map_err(io::Error::other)?;
    }
}

async fn send(
    write: &mut Writer,
    records: &mut Records,
    pending: &mut BytesMut,
    response: bool,
) -> io::Result<bool> {
    let (record, used, wait) = records.encode(pending, response)?;
    // A failed/abandoned write ends the worker and drops the entire carrier.
    tokio::time::timeout(Duration::from_secs(30), write.write_all(&record))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Restls carrier write timeout"))??;
    let _ = pending.split_to(used);
    Ok(wait)
}

async fn relay(
    app: &mut tokio::io::DuplexStream,
    mut read: Reader,
    mut write: Writer,
    mut session: ClientConnection,
    mut records: Records,
) -> io::Result<()> {
    let mut pending = BytesMut::new();
    let mut buffer = [0; 16372];
    let mut wait = false;
    let mut app_eof = false;
    loop {
        if !wait && !pending.is_empty() {
            wait = send(&mut write, &mut records, &mut pending, false).await?;
            continue;
        }
        tokio::select! {
            result = app.read(&mut buffer), if pending.is_empty() && !wait && !app_eof => {
                let n = result?;
                if n == 0 { app_eof = true; write.shutdown().await?; }
                else { pending.extend_from_slice(&buffer[..n]); }
            }
            record = read.next() => {
                let Some(record) = record else { return Ok(()); };
                let record = record?;
                if let Ok((data, responses)) = records.decode(&record) {
                        // Go flushes interrupted writes before honoring response commands.
                        let mut sent = false;
                        if wait {
                            wait = false;
                            while !pending.is_empty() && !wait {
                                wait = send(&mut write, &mut records, &mut pending, false).await?;
                                sent = true;
                            }
                        }
                        records.received = records.received.checked_add(1).ok_or_else(|| invalid("Restls counter overflow"))?;
                        for _ in 0..responses.saturating_sub(u8::from(sent)) {
                            if app_eof { return Err(invalid("Restls response requested after local write shutdown")); }
                            send(&mut write, &mut records, &mut BytesMut::new(), true).await?;
                        }
                        if !data.is_empty() { app.write_all(&data).await?; }
                    } else {
                        // Camouflage NewSessionTicket records remain real TLS records.
                        // Never release ordinary TLS application bytes as proxy data.
                        session.read_tls(&mut Cursor::new(&record[..]))?;
                        let state = session.process_new_packets().map_err(io::Error::other)?;
                        records.received = records.received.checked_add(1).ok_or_else(|| invalid("Restls counter overflow"))?;
                        if state.plaintext_bytes_to_read() != 0 { return Err(invalid("unexpected TLS application data after Restls authentication")); }
                        if state.peer_has_closed() { return Ok(()); }
                }
            }
        }
    }
}

type Failure = Arc<Mutex<Option<(io::ErrorKind, String)>>>;
struct RestlsStream {
    app: tokio::io::DuplexStream,
    cancel: Option<oneshot::Sender<()>>,
    failure: Failure,
}
impl RestlsStream {
    fn failure(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }
}
impl Drop for RestlsStream {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}
impl AsyncRead for RestlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.app).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && before == buf.filled().len()
            && buf.remaining() > 0
            && let Some(error) = self.failure()
        {
            return Poll::Ready(Err(error));
        }
        result
    }
}
impl AsyncWrite for RestlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = self.failure() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.app).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.app).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
