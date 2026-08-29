use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use hmac::{Hmac, Mac};
use rand::RngExt;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::tls::{HttpProxyTls, client_config};
use crate::{BoxedOutboundStream, HttpProxyError};

type HmacSha1 = Hmac<Sha1>;

const TLS_HEADER_SIZE: usize = 5;
const TLS_SESSION_ID_SIZE: usize = 32;
const HMAC_SIZE: usize = 4;
const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const ALERT: u8 = 21;
const SERVER_HELLO: u8 = 2;
const SERVER_RANDOM_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
const SESSION_ID_LENGTH_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + 32;
const SESSION_ID_START: usize = 1 + 3 + 2 + 32 + 1;
const MAX_TLS_PLAINTEXT: usize = 16_384;

#[derive(Debug, thiserror::Error)]
pub enum ShadowTlsError {
    #[error(transparent)]
    Tls(#[from] HttpProxyError),
    #[error("shadow-tls: {0}")]
    Protocol(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct ShadowTlsConnectOptions<'a> {
    pub host: &'a str,
    pub password: &'a str,
    pub version: u8,
    pub skip_certificate_verification: bool,
    pub verification_name: Option<&'a str>,
    pub certificate_fingerprint: Option<&'a str>,
    pub certificate: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub custom_roots: &'a [String],
    pub alpn: &'a [String],
    /// Browser fingerprint label from the proxy-level `client-fingerprint` field.
    ///
    /// Go Clash feeds this into uTLS (`UClient` / `GetFingerprint`). The vendored
    /// rustls session-id hook can only rewrite the 32-byte session-id; it cannot
    /// impersonate browser `ClientHello` shape (cipher suites, extensions, GREASE).
    /// Full uTLS parity needs a different TLS stack and is intentionally not claimed.
    pub client_fingerprint: Option<&'a str>,
}

/// Completes the `ShadowTLS` camouflage handshake, then returns the post-handshake
/// stream that carries inner Shadowsocks bytes.
///
/// # Errors
///
/// Returns [`ShadowTlsError`] when the protocol version is unsupported, TLS
/// configuration or handshake fails, or the camouflage server rejects the session.
pub async fn connect_shadow_tls(
    stream: BoxedOutboundStream,
    options: ShadowTlsConnectOptions<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<BoxedOutboundStream, ShadowTlsError> {
    if !matches!(options.version, 1..=3) {
        return Err(ShadowTlsError::Protocol(format!(
            "unknown protocol version: {}",
            options.version
        )));
    }
    let _ = options.client_fingerprint;
    let alpn: Vec<Vec<u8>> = options
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    let alpn_refs: Vec<&[u8]> = alpn.iter().map(Vec::as_slice).collect();
    let config = Arc::new(client_config(
        HttpProxyTls {
            server_name: options.host,
            verification_name: options.verification_name,
            skip_certificate_verification: options.skip_certificate_verification,
            fingerprint: options.certificate_fingerprint,
            certificate: options.certificate,
            private_key: options.private_key,
            custom_roots: options.custom_roots,
            ech_config: None,
            alpn_protocols: &alpn_refs,
            tls12_only: options.version == 1,
            tls13_only: false,
        },
        clock,
    )?);
    let server_name = ServerName::try_from(options.host.to_owned()).map_err(|error| {
        ShadowTlsError::Tls(HttpProxyError::TlsConfiguration(error.to_string()))
    })?;
    let password = options.password.to_owned();
    let io = ShadowTlsIo::new(stream, options.version, password.clone());
    let connector = TlsConnector::from(config);
    let session_id_password = password;
    let tls = if options.version == 3 {
        let generator = move |client_hello: &[u8]| {
            generate_session_id_bytes(&session_id_password, client_hello)
        };
        connector
            .connect_with_session_id_generator(server_name, io, generator)
            .await
    } else {
        connector.connect(server_name, io).await
    }
    .map_err(|error| {
        ShadowTlsError::Tls(HttpProxyError::TlsHandshake(io::Error::new(
            io::ErrorKind::InvalidData,
            error,
        )))
    })?;
    let (io, _) = tls.into_inner();
    io.finish(options.version)
}

enum ReadPhase {
    Header {
        header: [u8; TLS_HEADER_SIZE],
        filled: usize,
    },
    Body {
        header: [u8; TLS_HEADER_SIZE],
        buf: Vec<u8>,
        filled: usize,
    },
}

enum WriteState {
    Idle,
    Active {
        frame: Vec<u8>,
        offset: usize,
        consumed: usize,
    },
}

struct ShadowTlsIo {
    inner: BoxedOutboundStream,
    version: u8,
    password: String,
    pending_read: Vec<u8>,
    server_random: Option<[u8; 32]>,
    read_hmac: Option<HmacSha1>,
    read_hmac_key: Option<Vec<u8>>,
    is_tls13: bool,
    authorized: bool,
    read_hash: Option<HmacSha1>,
    read_phase: Option<ReadPhase>,
}

impl ShadowTlsIo {
    fn new(inner: BoxedOutboundStream, version: u8, password: String) -> Self {
        let read_hash = if version == 2 {
            Some(HmacSha1::new_from_slice(password.as_bytes()).expect("HMAC key"))
        } else {
            None
        };
        Self {
            inner,
            version,
            password,
            pending_read: Vec::new(),
            server_random: None,
            read_hmac: None,
            read_hmac_key: None,
            is_tls13: false,
            authorized: false,
            read_hash,
            read_phase: None,
        }
    }

    fn finish(self, version: u8) -> Result<BoxedOutboundStream, ShadowTlsError> {
        match version {
            1 => Ok(Box::new(self.inner)),
            2 => {
                let mut stream = V2ClientStream::new(
                    self.inner,
                    self.read_hash
                        .map(|mac| mac.finalize().into_bytes()[..8].to_vec())
                        .unwrap_or_default(),
                );
                stream.take_read_phase(self.read_phase);
                Ok(Box::new(stream))
            }
            3 => {
                if !self.authorized {
                    return Err(ShadowTlsError::Protocol("traffic hijacked".to_owned()));
                }
                let server_random = self
                    .server_random
                    .ok_or_else(|| ShadowTlsError::Protocol("missing server random".to_owned()))?;
                let mut hmac_add = HmacSha1::new_from_slice(self.password.as_bytes())
                    .map_err(|error| ShadowTlsError::Protocol(format!("HMAC key: {error}")))?;
                hmac_add.update(&server_random);
                hmac_add.update(b"C");
                let mut hmac_verify = HmacSha1::new_from_slice(self.password.as_bytes())
                    .map_err(|error| ShadowTlsError::Protocol(format!("HMAC key: {error}")))?;
                hmac_verify.update(&server_random);
                hmac_verify.update(b"S");
                let (read_buffer, read_offset) = read_phase_to_verified(self.read_phase);
                Ok(Box::new(VerifiedStream {
                    inner: self.inner,
                    hmac_add,
                    hmac_verify,
                    hmac_ignore: self.read_hmac,
                    pending: Vec::new(),
                    read_buffer,
                    read_offset,
                    write_state: WriteState::Idle,
                }))
            }
            _ => unreachable!("validated above"),
        }
    }

    fn take_pending(&mut self, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pending_read.is_empty() {
            return Poll::Pending;
        }
        let to_copy = buf.remaining().min(self.pending_read.len());
        buf.put_slice(&self.pending_read[..to_copy]);
        self.pending_read.drain(..to_copy);
        Poll::Ready(Ok(()))
    }

    fn process_server_frame(&mut self, frame: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        if self.version == 3 {
            return self.process_server_frame_v3(frame);
        }
        if self.version == 2
            && let Some(read_hash) = self.read_hash.as_mut()
        {
            read_hash.update(&frame);
        }
        Ok(frame)
    }

    fn process_server_frame_v3(&mut self, frame: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        match frame.first().copied() {
            Some(HANDSHAKE)
                if frame.len() >= SERVER_RANDOM_INDEX + 32
                    && frame[TLS_HEADER_SIZE] == SERVER_HELLO
                    && self.read_hmac.is_none() =>
            {
                let mut server_random = [0_u8; 32];
                server_random
                    .copy_from_slice(&frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32]);
                self.server_random = Some(server_random);
                let mut read_hmac =
                    HmacSha1::new_from_slice(self.password.as_bytes()).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
                read_hmac.update(&server_random);
                self.read_hmac = Some(read_hmac);
                self.read_hmac_key = Some(kdf(&self.password, &server_random));
                self.is_tls13 = is_server_hello_tls13(&frame);
                self.authorized = !self.is_tls13;
            }
            Some(APPLICATION_DATA)
                if frame.len() > TLS_HMAC_HEADER_SIZE
                    && let Some(read_hmac) = self.read_hmac.as_mut() =>
            {
                self.authorized = false;
                let payload = &frame[TLS_HMAC_HEADER_SIZE..];
                read_hmac.update(payload);
                let expected = read_hmac.clone().finalize().into_bytes();
                let expected = &expected[..HMAC_SIZE];
                let got = &frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE];
                if expected != got {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "shadow-tls v3: HMAC mismatch, possible data corruption",
                    ));
                }
                let mut payload = payload.to_vec();
                if let Some(key) = self.read_hmac_key.as_ref() {
                    xor_slice(&mut payload, key);
                }
                let mut unwrapped = Vec::with_capacity(TLS_HEADER_SIZE + payload.len());
                unwrapped.extend_from_slice(&frame[..TLS_HEADER_SIZE]);
                unwrapped.extend_from_slice(&payload);
                set_tls_record_length(&mut unwrapped, payload.len())?;
                self.authorized = true;
                return Ok(unwrapped);
            }
            _ => {}
        }
        Ok(frame)
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            match self.read_phase.take() {
                None => {
                    self.read_phase = Some(ReadPhase::Header {
                        header: [0_u8; TLS_HEADER_SIZE],
                        filled: 0,
                    });
                }
                Some(ReadPhase::Header {
                    mut header,
                    mut filled,
                }) => {
                    while filled < TLS_HEADER_SIZE {
                        let mut buf = ReadBuf::new(&mut header[filled..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut buf) {
                            Poll::Ready(Ok(())) => {
                                let read = buf.filled().len();
                                if read == 0 {
                                    return if filled == 0 {
                                        Poll::Ready(Ok(None))
                                    } else {
                                        self.read_phase =
                                            Some(ReadPhase::Header { header, filled });
                                        Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::UnexpectedEof,
                                            "shadow-tls: truncated TLS header",
                                        )))
                                    };
                                }
                                filled += read;
                            }
                            Poll::Pending => {
                                self.read_phase = Some(ReadPhase::Header { header, filled });
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        }
                    }
                    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                    self.read_phase = Some(ReadPhase::Body {
                        header,
                        buf: vec![0_u8; length],
                        filled: 0,
                    });
                }
                Some(ReadPhase::Body {
                    header,
                    mut buf,
                    mut filled,
                }) => {
                    while filled < buf.len() {
                        let mut read_buf = ReadBuf::new(&mut buf[filled..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let read = read_buf.filled().len();
                                if read == 0 {
                                    self.read_phase = Some(ReadPhase::Body {
                                        header,
                                        buf,
                                        filled,
                                    });
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "shadow-tls: truncated TLS body",
                                    )));
                                }
                                filled += read;
                            }
                            Poll::Pending => {
                                self.read_phase = Some(ReadPhase::Body {
                                    header,
                                    buf,
                                    filled,
                                });
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        }
                    }
                    let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + buf.len());
                    frame.extend_from_slice(&header);
                    frame.extend_from_slice(&buf);
                    return Poll::Ready(Ok(Some(frame)));
                }
            }
        }
    }
}

impl AsyncRead for ShadowTlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending_read.is_empty() {
            return self.take_pending(buf);
        }
        if self.version == 1 {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        let frame = ready!(self.poll_read_frame(cx))?;
        let Some(frame) = frame else {
            return Poll::Ready(Ok(()));
        };
        match self.process_server_frame(frame) {
            Ok(frame) => {
                self.pending_read = frame;
                self.take_pending(buf)
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for ShadowTlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct V2ClientStream {
    inner: BoxedOutboundStream,
    hash: Vec<u8>,
    prefix_sent: bool,
    write_state: WriteState,
    read_remaining: usize,
    read_header: [u8; TLS_HEADER_SIZE],
    read_header_filled: usize,
    pending: Vec<u8>,
}

impl V2ClientStream {
    fn new(inner: BoxedOutboundStream, hash: Vec<u8>) -> Self {
        Self {
            inner,
            hash,
            prefix_sent: false,
            write_state: WriteState::Idle,
            read_remaining: 0,
            read_header: [0_u8; TLS_HEADER_SIZE],
            read_header_filled: 0,
            pending: Vec::new(),
        }
    }

    fn take_read_phase(&mut self, phase: Option<ReadPhase>) {
        match phase {
            Some(ReadPhase::Header { header, filled }) => {
                self.read_header = header;
                self.read_header_filled = filled;
            }
            Some(ReadPhase::Body {
                header,
                buf,
                filled,
            }) => {
                self.read_header = header;
                self.read_header_filled = 0;
                self.pending = buf[..filled].to_vec();
                self.read_remaining = buf.len().saturating_sub(filled);
            }
            None => {}
        }
    }

    fn encode_tls_record(payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + payload.len());
        frame.resize(TLS_HEADER_SIZE, 0);
        frame[0] = APPLICATION_DATA;
        frame[1] = 3;
        frame[2] = 3;
        set_tls_record_length(&mut frame, payload.len())?;
        frame.extend_from_slice(payload);
        Ok(frame)
    }
}

impl AsyncRead for V2ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.pending.is_empty() {
            let to_copy = buf.remaining().min(this.pending.len());
            buf.put_slice(&this.pending[..to_copy]);
            this.pending.drain(..to_copy);
            return Poll::Ready(Ok(()));
        }
        if this.read_remaining > 0 {
            let limit = buf.remaining().min(this.read_remaining);
            let mut scratch = ReadBuf::new(&mut buf.initialize_unfilled()[..limit]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut scratch))?;
            let read = scratch.filled().len();
            if read == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            buf.advance(read);
            this.read_remaining -= read;
            return Poll::Ready(Ok(()));
        }
        while this.read_header_filled < TLS_HEADER_SIZE {
            let mut header_buf =
                ReadBuf::new(&mut this.read_header[this.read_header_filled..TLS_HEADER_SIZE]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut header_buf) {
                Poll::Ready(Ok(())) => {
                    let read = header_buf.filled().len();
                    if read == 0 {
                        return if this.read_header_filled == 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "shadow-tls v2: truncated TLS header",
                            )))
                        };
                    }
                    this.read_header_filled += read;
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
        if this.read_header[0] != APPLICATION_DATA {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "shadow-tls v2: unexpected TLS record type: {}",
                    this.read_header[0]
                ),
            )));
        }
        let length = u16::from_be_bytes([this.read_header[3], this.read_header[4]]) as usize;
        this.read_header_filled = 0;
        let limit = buf.remaining().min(length);
        let mut body_buf = ReadBuf::new(&mut buf.initialize_unfilled()[..limit]);
        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut body_buf))?;
        let read = body_buf.filled().len();
        if read == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "shadow-tls v2: truncated TLS body",
            )));
        }
        buf.advance(read);
        this.read_remaining = length - read;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for V2ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            if let WriteState::Active {
                frame,
                offset,
                consumed,
            } = std::mem::replace(&mut this.write_state, WriteState::Idle)
            {
                let written = ready!(poll_write_all(
                    Pin::new(&mut this.inner),
                    cx,
                    &frame,
                    offset
                ))?;
                if written < frame.len() {
                    this.write_state = WriteState::Active {
                        frame,
                        offset: written,
                        consumed,
                    };
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(consumed));
            }
            if data.is_empty() {
                // Go shadowConn writes an empty application-data record for zero-length writes.
                let frame = match Self::encode_tls_record(&[]) {
                    Ok(frame) => frame,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                this.write_state = WriteState::Active {
                    frame,
                    offset: 0,
                    consumed: 0,
                };
                continue;
            }
            let chunk = if this.prefix_sent {
                data.len().min(MAX_TLS_PLAINTEXT)
            } else {
                data.len()
                    .min(MAX_TLS_PLAINTEXT.saturating_sub(this.hash.len()))
            };
            let payload = if this.prefix_sent {
                &data[..chunk]
            } else {
                this.prefix_sent = true;
                let mut prefixed = Vec::with_capacity(this.hash.len() + chunk);
                prefixed.extend_from_slice(&this.hash);
                prefixed.extend_from_slice(&data[..chunk]);
                let frame = match Self::encode_tls_record(&prefixed) {
                    Ok(frame) => frame,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                this.write_state = WriteState::Active {
                    frame,
                    offset: 0,
                    consumed: chunk,
                };
                continue;
            };
            let frame = match Self::encode_tls_record(payload) {
                Ok(frame) => frame,
                Err(error) => return Poll::Ready(Err(error)),
            };
            this.write_state = WriteState::Active {
                frame,
                offset: 0,
                consumed: chunk,
            };
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(drain_write_state(
            &mut this.write_state,
            &mut this.inner,
            cx
        ))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(drain_write_state(
            &mut this.write_state,
            &mut this.inner,
            cx
        ))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

struct VerifiedStream {
    inner: BoxedOutboundStream,
    hmac_add: HmacSha1,
    hmac_verify: HmacSha1,
    hmac_ignore: Option<HmacSha1>,
    pending: Vec<u8>,
    read_buffer: Option<Vec<u8>>,
    read_offset: usize,
    write_state: WriteState,
}

impl VerifiedStream {
    fn take_pending(&mut self, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pending.is_empty() {
            return Poll::Pending;
        }
        let to_copy = buf.remaining().min(self.pending.len());
        buf.put_slice(&self.pending[..to_copy]);
        self.pending.drain(..to_copy);
        Poll::Ready(Ok(()))
    }

    fn poll_read_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        if self.read_buffer.is_none() {
            self.read_buffer = Some(vec![0_u8; TLS_HEADER_SIZE]);
            self.read_offset = 0;
        }
        let buffer = self.read_buffer.as_mut().expect("buffer");
        while self.read_offset < TLS_HEADER_SIZE {
            let mut read_buf = ReadBuf::new(&mut buffer[self.read_offset..TLS_HEADER_SIZE]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            let read = read_buf.filled().len();
            if read == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "shadow-tls: unexpected EOF reading record header",
                )));
            }
            self.read_offset += read;
        }
        let length = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
        if buffer.len() < TLS_HEADER_SIZE + length {
            buffer.resize(TLS_HEADER_SIZE + length, 0);
        }
        while self.read_offset < TLS_HEADER_SIZE + length {
            let mut read_buf =
                ReadBuf::new(&mut buffer[self.read_offset..TLS_HEADER_SIZE + length]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            let read = read_buf.filled().len();
            if read == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "shadow-tls: unexpected EOF reading record body",
                )));
            }
            self.read_offset += read;
        }
        let frame = buffer.clone();
        self.read_buffer = None;
        self.read_offset = 0;
        Poll::Ready(Ok(frame))
    }

    fn read_fail(&mut self, cx: &mut Context<'_>, error: io::Error) -> Poll<io::Result<()>> {
        send_alert(Pin::new(&mut self.inner), cx);
        Poll::Ready(Err(error))
    }
}

impl AsyncRead for VerifiedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending.is_empty() {
            return self.take_pending(buf);
        }
        loop {
            let frame = match self.poll_read_record(cx) {
                Poll::Ready(Ok(frame)) => frame,
                Poll::Ready(Err(error)) => {
                    return self.read_fail(cx, error);
                }
                Poll::Pending => return Poll::Pending,
            };
            match frame.first().copied() {
                Some(ALERT) => {
                    return self.read_fail(
                        cx,
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "shadow-tls: remote alert",
                        ),
                    );
                }
                Some(APPLICATION_DATA) => {
                    let ignore_frame = self.hmac_ignore.as_mut().is_some_and(|hmac_ignore| {
                        verify_application_data(&frame, hmac_ignore, false)
                    });
                    if ignore_frame {
                        continue;
                    }
                    if self.hmac_ignore.is_some() {
                        self.hmac_ignore = None;
                    }
                    if !verify_application_data(&frame, &mut self.hmac_verify, true) {
                        return self.read_fail(
                            cx,
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "shadow-tls: application data verification failed",
                            ),
                        );
                    }
                    self.pending
                        .extend_from_slice(&frame[TLS_HMAC_HEADER_SIZE..]);
                    return self.take_pending(buf);
                }
                Some(other) => {
                    return self.read_fail(
                        cx,
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("shadow-tls: unexpected TLS record type: {other}"),
                        ),
                    );
                }
                None => {
                    return self.read_fail(
                        cx,
                        io::Error::new(io::ErrorKind::InvalidData, "shadow-tls: empty TLS record"),
                    );
                }
            }
        }
    }
}

impl AsyncWrite for VerifiedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            if let WriteState::Active {
                frame,
                offset,
                consumed,
            } = std::mem::replace(&mut this.write_state, WriteState::Idle)
            {
                let written = ready!(poll_write_all(
                    Pin::new(&mut this.inner),
                    cx,
                    &frame,
                    offset
                ))?;
                if written < frame.len() {
                    this.write_state = WriteState::Active {
                        frame,
                        offset: written,
                        consumed,
                    };
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(consumed));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let chunk = data.len().min(MAX_TLS_PLAINTEXT);
            let frame = match encode_application_data_frame(&mut this.hmac_add, &data[..chunk]) {
                Ok(frame) => frame,
                Err(error) => return Poll::Ready(Err(error)),
            };
            this.write_state = WriteState::Active {
                frame,
                offset: 0,
                consumed: chunk,
            };
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(drain_write_state(
            &mut this.write_state,
            &mut this.inner,
            cx
        ))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(drain_write_state(
            &mut this.write_state,
            &mut this.inner,
            cx
        ))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn set_tls_record_length(header: &mut [u8], payload_len: usize) -> io::Result<()> {
    let length = u16::try_from(payload_len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "TLS record too large"))?;
    header[3] = (length >> 8) as u8;
    header[4] = (length & 0xff) as u8;
    Ok(())
}

fn poll_write_all(
    mut inner: Pin<&mut BoxedOutboundStream>,
    cx: &mut Context<'_>,
    buffer: &[u8],
    offset: usize,
) -> Poll<io::Result<usize>> {
    if offset >= buffer.len() {
        return Poll::Ready(Ok(offset));
    }
    let written = ready!(inner.as_mut().poll_write(cx, &buffer[offset..]))?;
    if written == 0 {
        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
    }
    Poll::Ready(Ok(offset + written))
}

fn send_alert(mut writer: Pin<&mut BoxedOutboundStream>, cx: &mut Context<'_>) {
    const RECORD_SIZE: usize = 31;
    let mut record = [0_u8; RECORD_SIZE];
    record[0] = ALERT;
    record[1] = 3;
    record[2] = 3;
    record[4] = 26;
    rand::rng().fill(&mut record[TLS_HEADER_SIZE..]);
    let mut offset = 0;
    while offset < RECORD_SIZE {
        match writer.as_mut().poll_write(cx, &record[offset..]) {
            Poll::Ready(Ok(written)) if written > 0 => offset += written,
            _ => break,
        }
    }
}

fn drain_write_state(
    write_state: &mut WriteState,
    inner: &mut BoxedOutboundStream,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if let WriteState::Active {
        frame,
        offset,
        consumed,
    } = std::mem::replace(write_state, WriteState::Idle)
    {
        let written = ready!(poll_write_all(Pin::new(inner), cx, &frame, offset))?;
        if written < frame.len() {
            *write_state = WriteState::Active {
                frame,
                offset: written,
                consumed,
            };
            return Poll::Pending;
        }
    }
    Poll::Ready(Ok(()))
}

fn read_phase_to_verified(phase: Option<ReadPhase>) -> (Option<Vec<u8>>, usize) {
    match phase {
        Some(ReadPhase::Header { header, filled }) => (Some(header.to_vec()), filled),
        Some(ReadPhase::Body {
            header,
            buf,
            filled,
        }) => {
            let mut buffer = Vec::with_capacity(TLS_HEADER_SIZE + buf.len());
            buffer.extend_from_slice(&header);
            buffer.extend_from_slice(&buf);
            (Some(buffer), TLS_HEADER_SIZE + filled)
        }
        None => (None, 0),
    }
}

fn encode_application_data_frame(hmac_add: &mut HmacSha1, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(TLS_HMAC_HEADER_SIZE + payload.len());
    frame.resize(TLS_HMAC_HEADER_SIZE, 0);
    frame[0] = APPLICATION_DATA;
    frame[1] = 3;
    frame[2] = 3;
    set_tls_record_length(&mut frame, HMAC_SIZE + payload.len())?;
    hmac_add.update(payload);
    let hmac_hash = hmac_add.clone().finalize().into_bytes()[..HMAC_SIZE].to_vec();
    hmac_add.update(&hmac_hash);
    frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE].copy_from_slice(&hmac_hash);
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn generate_session_id_bytes(password: &str, client_hello: &[u8]) -> [u8; 32] {
    let mut session_id = [0_u8; TLS_SESSION_ID_SIZE];
    if client_hello.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
        return session_id;
    }
    rand::rng().fill(&mut session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);
    let mut mac = HmacSha1::new_from_slice(password.as_bytes()).expect("HMAC key");
    mac.update(&client_hello[..SESSION_ID_START]);
    mac.update(&session_id);
    mac.update(&client_hello[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
    session_id[TLS_SESSION_ID_SIZE - HMAC_SIZE..]
        .copy_from_slice(&mac.finalize().into_bytes()[..HMAC_SIZE]);
    session_id
}

fn kdf(password: &str, server_random: &[u8; 32]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    hasher.finalize().to_vec()
}

fn xor_slice(data: &mut [u8], key: &[u8]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn is_server_hello_tls13(frame: &[u8]) -> bool {
    if frame.len() <= SESSION_ID_LENGTH_INDEX || frame.first() != Some(&HANDSHAKE) {
        return false;
    }
    if frame[TLS_HEADER_SIZE] != SERVER_HELLO {
        return false;
    }
    let mut offset = SESSION_ID_LENGTH_INDEX;
    let session_id_length = frame[offset] as usize;
    offset += 1 + session_id_length + 3;
    if offset + 2 > frame.len() {
        return false;
    }
    let extensions_length = u16::from_be_bytes([frame[offset], frame[offset + 1]]) as usize;
    offset += 2;
    if offset + extensions_length > frame.len() {
        return false;
    }
    let extensions = &frame[offset..offset + extensions_length];
    let mut cursor = extensions;
    while cursor.len() >= 4 {
        let ext_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let ext_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        if ext_len > cursor.len() {
            return false;
        }
        if ext_type == 43 {
            return ext_len == 2 && cursor[0] == 0x03 && cursor[1] == 0x04;
        }
        cursor = &cursor[ext_len..];
    }
    false
}

fn verify_application_data(frame: &[u8], hmac: &mut HmacSha1, update: bool) -> bool {
    if frame.len() < TLS_HMAC_HEADER_SIZE
        || frame[0] != APPLICATION_DATA
        || frame[1] != 3
        || frame[2] != 3
    {
        return false;
    }
    hmac.update(&frame[TLS_HMAC_HEADER_SIZE..]);
    let hmac_hash = hmac.clone().finalize().into_bytes()[..HMAC_SIZE].to_vec();
    if update {
        hmac.update(&hmac_hash);
    }
    hmac_hash == frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    use super::*;

    #[test]
    fn generate_session_id_hmac_tail_matches_password_binding() {
        let mut client_hello = vec![0_u8; 120];
        client_hello[0] = HANDSHAKE;
        client_hello[38] = u8::try_from(TLS_SESSION_ID_SIZE).expect("session id size");
        client_hello[39..39 + TLS_SESSION_ID_SIZE].fill(0);
        let session_id = generate_session_id_bytes("phase6c-shadow-tls-password", &client_hello);
        assert_ne!(session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE], [0_u8; 28]);
        let mut session_id_for_hmac = [0_u8; TLS_SESSION_ID_SIZE];
        session_id_for_hmac[..TLS_SESSION_ID_SIZE - HMAC_SIZE]
            .copy_from_slice(&session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);
        let mut mac = HmacSha1::new_from_slice(b"phase6c-shadow-tls-password").expect("HMAC key");
        mac.update(&client_hello[..SESSION_ID_START]);
        mac.update(&session_id_for_hmac);
        mac.update(&client_hello[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
        assert_eq!(
            session_id[TLS_SESSION_ID_SIZE - HMAC_SIZE..],
            mac.finalize().into_bytes()[..HMAC_SIZE]
        );
    }

    #[test]
    fn tls12_server_hello_authorizes_v3_handshake() {
        let mut frame = vec![0_u8; 90];
        frame[0] = HANDSHAKE;
        frame[5] = SERVER_HELLO;
        frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32].fill(7);
        frame[SESSION_ID_LENGTH_INDEX] = 0;
        let mut io = ShadowTlsIo {
            inner: Box::new(tokio::io::empty()),
            version: 3,
            password: "pw".to_owned(),
            pending_read: Vec::new(),
            server_random: None,
            read_hmac: None,
            read_hmac_key: None,
            is_tls13: false,
            authorized: false,
            read_hash: None,
            read_phase: None,
        };
        let processed = io.process_server_frame(frame).expect("process frame");
        assert!(io.authorized);
        assert!(!io.is_tls13);
        assert_eq!(processed.len(), 90);
    }

    struct LimitedWriter {
        inner: tokio::io::DuplexStream,
        max_write: usize,
    }

    impl AsyncRead for LimitedWriter {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for LimitedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let limit = buf.len().min(self.max_write);
            Pin::new(&mut self.inner).poll_write(cx, &buf[..limit])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[test]
    fn verified_stream_write_flushes_full_frame_before_reporting_progress() {
        use std::task::{Context, Poll};

        let (client, mut peer) = tokio::io::duplex(4096);
        let server_random = [9_u8; 32];
        let mut hmac_add = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_add.update(&server_random);
        hmac_add.update(b"C");
        let mut hmac_verify = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_verify.update(&server_random);
        hmac_verify.update(b"S");
        let mut stream = VerifiedStream {
            inner: Box::new(LimitedWriter {
                inner: client,
                max_write: 1,
            }),
            hmac_add,
            hmac_verify,
            hmac_ignore: None,
            pending: Vec::new(),
            read_buffer: None,
            read_offset: 0,
            write_state: WriteState::Idle,
        };
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let payload = b"abc";
        let mut consumed = 0;
        while consumed < payload.len() {
            match Pin::new(&mut stream).poll_write(&mut cx, &payload[consumed..]) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(written)) => consumed += written,
                Poll::Ready(Err(error)) => panic!("write failed: {error}"),
                Poll::Pending => {
                    let mut drain = [0_u8; 64];
                    let _ = std::future::poll_fn(|cx| {
                        Pin::new(&mut peer).poll_read(cx, &mut ReadBuf::new(&mut drain))
                    })
                    .now_or_never();
                }
            }
        }
        assert_eq!(consumed, payload.len());
    }

    #[test]
    fn verified_stream_flush_drains_pending_frame_before_completing() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let server_random = [3_u8; 32];
        let mut hmac_add = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_add.update(&server_random);
        hmac_add.update(b"C");
        let mut hmac_verify = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_verify.update(&server_random);
        hmac_verify.update(b"S");
        let mut stream = VerifiedStream {
            inner: Box::new(LimitedWriter {
                inner: client,
                max_write: 1,
            }),
            hmac_add,
            hmac_verify,
            hmac_ignore: None,
            pending: Vec::new(),
            read_buffer: None,
            read_offset: 0,
            write_state: WriteState::Idle,
        };
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"xy"),
            Poll::Pending
        ));
        assert!(matches!(stream.write_state, WriteState::Active { .. }));
        loop {
            match Pin::new(&mut stream).poll_flush(&mut cx) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(error)) => panic!("flush failed: {error}"),
                Poll::Pending => {
                    let mut drain = [0_u8; 64];
                    let _ = std::future::poll_fn(|cx| {
                        Pin::new(&mut peer).poll_read(cx, &mut ReadBuf::new(&mut drain))
                    })
                    .now_or_never();
                }
            }
        }
        assert!(matches!(stream.write_state, WriteState::Idle));
    }

    #[test]
    fn verified_stream_read_survives_partial_record() {
        let (client, server) = tokio::io::duplex(4096);
        let server_random = [4_u8; 32];
        let mut hmac_add = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_add.update(&server_random);
        hmac_add.update(b"S");
        let payload = b"hello";
        let frame = encode_application_data_frame(&mut hmac_add, payload).expect("frame");
        let mut peer = client;
        // Deliver only the TLS header first via a non-blocking short write pattern.
        let header = frame[..TLS_HEADER_SIZE].to_vec();
        let body = frame[TLS_HEADER_SIZE..].to_vec();
        let mut hmac_verify = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_verify.update(&server_random);
        hmac_verify.update(b"S");
        let mut hmac_client = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_client.update(&server_random);
        hmac_client.update(b"C");
        let mut stream = VerifiedStream {
            inner: Box::new(server),
            hmac_add: hmac_client,
            hmac_verify,
            hmac_ignore: None,
            pending: Vec::new(),
            read_buffer: None,
            read_offset: 0,
            write_state: WriteState::Idle,
        };
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        // Inject header bytes into the stream's read_buffer to simulate a partial record
        // that arrived before finish() handed off state — then deliver the remainder.
        stream.read_buffer = Some(header);
        stream.read_offset = TLS_HEADER_SIZE;
        let mut offset = 0;
        while offset < body.len() {
            match Pin::new(&mut peer).poll_write(&mut cx, &body[offset..]) {
                Poll::Ready(Ok(written)) if written > 0 => offset += written,
                Poll::Ready(Err(error)) => panic!("peer write failed: {error}"),
                _ => break,
            }
        }
        let mut buf = [0_u8; 16];
        let mut read_buf = ReadBuf::new(&mut buf);
        for _ in 0..8 {
            match Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf) {
                Poll::Ready(Ok(())) => break,
                Poll::Ready(Err(error)) => panic!("read failed: {error}"),
                Poll::Pending => {}
            }
        }
        assert_eq!(&read_buf.filled()[..payload.len()], payload);
    }

    #[test]
    fn finish_transfers_partial_read_phase_into_verified_stream() {
        let (read_buffer, read_offset) = read_phase_to_verified(Some(ReadPhase::Header {
            header: [APPLICATION_DATA, 3, 3, 0, 9],
            filled: 3,
        }));
        assert_eq!(read_offset, 3);
        assert_eq!(
            read_buffer.as_deref(),
            Some([APPLICATION_DATA, 3, 3, 0, 9].as_slice())
        );
        let (read_buffer, read_offset) = read_phase_to_verified(Some(ReadPhase::Body {
            header: [APPLICATION_DATA, 3, 3, 0, 4],
            buf: vec![1, 2, 3, 4],
            filled: 2,
        }));
        assert_eq!(read_offset, TLS_HEADER_SIZE + 2);
        assert_eq!(
            read_buffer.as_deref(),
            Some([APPLICATION_DATA, 3, 3, 0, 4, 1, 2, 3, 4].as_slice())
        );
    }

    #[tokio::test]
    async fn poll_read_frame_survives_partial_header_read() {
        let (mut client, server) = tokio::io::duplex(4096);
        let payload = b"abc";
        let mut frame = vec![0_u8; TLS_HEADER_SIZE + payload.len()];
        frame[0] = APPLICATION_DATA;
        frame[1] = 3;
        frame[2] = 3;
        set_tls_record_length(&mut frame, payload.len()).expect("length");
        frame[TLS_HEADER_SIZE..].copy_from_slice(payload);
        client.write_all(&frame[..2]).await.expect("partial header");
        let mut io = ShadowTlsIo {
            inner: Box::new(server),
            version: 2,
            password: String::new(),
            pending_read: Vec::new(),
            server_random: None,
            read_hmac: None,
            read_hmac_key: None,
            is_tls13: false,
            authorized: false,
            read_hash: Some(HmacSha1::new_from_slice(b"x").expect("HMAC key")),
            read_phase: None,
        };
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut buf = [0_u8; 32];
        let mut read_buf = ReadBuf::new(&mut buf);
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut read_buf),
            Poll::Pending
        ));
        client.write_all(&frame[2..]).await.expect("rest of frame");
        read_buf = ReadBuf::new(&mut buf);
        for _ in 0..8 {
            if matches!(
                Pin::new(&mut io).poll_read(&mut cx, &mut read_buf),
                Poll::Ready(Ok(()))
            ) {
                break;
            }
        }
        assert!(read_buf.filled().len() >= payload.len());
        assert!(
            read_buf
                .filled()
                .windows(payload.len())
                .any(|window| window == payload)
        );
    }

    #[tokio::test]
    async fn verified_stream_sends_alert_on_hmac_failure() {
        let (client, peer) = tokio::io::duplex(4096);
        let server_random = [1_u8; 32];
        let mut hmac_add = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_add.update(&server_random);
        hmac_add.update(b"C");
        let mut hmac_verify = HmacSha1::new_from_slice(b"pw").expect("HMAC key");
        hmac_verify.update(&server_random);
        hmac_verify.update(b"S");
        let mut stream = VerifiedStream {
            inner: Box::new(client),
            hmac_add,
            hmac_verify,
            hmac_ignore: None,
            pending: Vec::new(),
            read_buffer: None,
            read_offset: 0,
            write_state: WriteState::Idle,
        };
        let mut bad = vec![0_u8; TLS_HMAC_HEADER_SIZE + 4];
        bad[0] = APPLICATION_DATA;
        bad[1] = 3;
        bad[2] = 3;
        set_tls_record_length(&mut bad, HMAC_SIZE + 4).expect("length");
        let mut peer = peer;
        peer.write_all(&bad).await.expect("write bad frame");
        let result = tokio::io::AsyncReadExt::read(&mut stream, &mut [0_u8; 1]).await;
        assert!(result.is_err());
        let mut alert = [0_u8; 31];
        let read = peer.read(&mut alert).await.expect("read alert");
        assert_eq!(read, 31);
        assert_eq!(alert[0], ALERT);
    }
}
