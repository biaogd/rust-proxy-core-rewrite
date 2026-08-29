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
}

/// Completes the ShadowTLS camouflage handshake, then returns the post-handshake
/// stream that carries inner Shadowsocks bytes.
pub async fn connect_shadow_tls(
    stream: BoxedOutboundStream,
    options: ShadowTlsConnectOptions<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<BoxedOutboundStream, ShadowTlsError> {
    match options.version {
        1 | 2 | 3 => {}
        _ => {
            return Err(ShadowTlsError::Protocol(format!(
                "unknown protocol version: {}",
                options.version
            )));
        }
    }
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
            tls13_only: options.version == 3,
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
    Body {
        header: [u8; TLS_HEADER_SIZE],
        buf: Vec<u8>,
        filled: usize,
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
            2 => Ok(Box::new(V2ClientStream {
                inner: self.inner,
                hash: self
                    .read_hash
                    .map(|mac| mac.finalize().into_bytes()[..8].to_vec())
                    .unwrap_or_default(),
                sent_prefix: false,
            })),
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
                Ok(Box::new(VerifiedStream {
                    inner: self.inner,
                    hmac_add,
                    hmac_verify,
                    hmac_ignore: self.read_hmac,
                    pending: Vec::new(),
                    read_buffer: None,
                    read_offset: 0,
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
            match frame.first().copied() {
                Some(HANDSHAKE) => {
                    if frame.len() >= SERVER_RANDOM_INDEX + 32
                        && frame[TLS_HEADER_SIZE] == SERVER_HELLO
                        && self.read_hmac.is_none()
                    {
                        let mut server_random = [0_u8; 32];
                        server_random
                            .copy_from_slice(&frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32]);
                        self.server_random = Some(server_random);
                        let mut read_hmac = HmacSha1::new_from_slice(self.password.as_bytes())
                            .map_err(|error| {
                                io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                            })?;
                        read_hmac.update(&server_random);
                        self.read_hmac = Some(read_hmac);
                        self.read_hmac_key = Some(kdf(&self.password, &server_random));
                        self.is_tls13 = is_server_hello_tls13(&frame);
                        self.authorized = !self.is_tls13;
                    }
                }
                Some(APPLICATION_DATA) => {
                    self.authorized = false;
                    if frame.len() > TLS_HMAC_HEADER_SIZE {
                        if let Some(read_hmac) = self.read_hmac.as_mut() {
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
                            let length = unwrapped.len() - TLS_HEADER_SIZE;
                            unwrapped[3] = (length >> 8) as u8;
                            unwrapped[4] = length as u8;
                            self.authorized = true;
                            return Ok(unwrapped);
                        }
                    }
                }
                _ => {}
            }
            return Ok(frame);
        }
        if self.version == 2 {
            if let Some(read_hash) = self.read_hash.as_mut() {
                read_hash.update(&frame);
            }
        }
        Ok(frame)
    }

    fn poll_read_frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            match self.read_phase.take() {
                None => {
                    let mut header = [0_u8; TLS_HEADER_SIZE];
                    let mut filled = 0;
                    while filled < TLS_HEADER_SIZE {
                        let mut buf = ReadBuf::new(&mut header[filled..]);
                        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
                        filled += buf.filled().len();
                        if buf.filled().is_empty() {
                            return Poll::Ready(Ok(None));
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
                        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
                        filled += read_buf.filled().len();
                        if read_buf.filled().is_empty() {
                            self.read_phase = Some(ReadPhase::Body {
                                header,
                                buf,
                                filled,
                            });
                            return Poll::Pending;
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
    sent_prefix: bool,
}

impl AsyncRead for V2ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for V2ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.sent_prefix {
            return Pin::new(&mut self.inner).poll_write(cx, data);
        }
        self.sent_prefix = true;
        let mut prefixed = Vec::with_capacity(8 + data.len());
        prefixed.extend_from_slice(&self.hash);
        prefixed.extend_from_slice(data);
        match Pin::new(&mut self.inner).poll_write(cx, &prefixed) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(data.len())),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
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
            self.read_offset += read_buf.filled().len();
            if read_buf.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "shadow-tls: unexpected EOF reading record header",
                )));
            }
        }
        let length = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
        if buffer.len() < TLS_HEADER_SIZE + length {
            buffer.resize(TLS_HEADER_SIZE + length, 0);
        }
        while self.read_offset < TLS_HEADER_SIZE + length {
            let mut read_buf =
                ReadBuf::new(&mut buffer[self.read_offset..TLS_HEADER_SIZE + length]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            self.read_offset += read_buf.filled().len();
            if read_buf.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "shadow-tls: unexpected EOF reading record body",
                )));
            }
        }
        let frame = buffer.clone();
        self.read_buffer = None;
        self.read_offset = 0;
        Poll::Ready(Ok(frame))
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
            let frame = ready!(self.poll_read_record(cx))?;
            match frame.first().copied() {
                Some(ALERT) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "shadow-tls: remote alert",
                    )));
                }
                Some(APPLICATION_DATA) => {
                    if let Some(hmac_ignore) = self.hmac_ignore.as_mut() {
                        if verify_application_data(&frame, hmac_ignore, false) {
                            continue;
                        }
                        self.hmac_ignore = None;
                    }
                    if !verify_application_data(&frame, &mut self.hmac_verify, true) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "shadow-tls: application data verification failed",
                        )));
                    }
                    self.pending
                        .extend_from_slice(&frame[TLS_HMAC_HEADER_SIZE..]);
                    return self.take_pending(buf);
                }
                Some(other) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("shadow-tls: unexpected TLS record type: {other}"),
                    )));
                }
                None => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "shadow-tls: empty TLS record",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for VerifiedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = data.len().min(MAX_TLS_PLAINTEXT);
        let mut header = [0_u8; TLS_HMAC_HEADER_SIZE];
        header[0] = APPLICATION_DATA;
        header[1] = 3;
        header[2] = 3;
        header[3] = ((HMAC_SIZE + chunk) >> 8) as u8;
        header[4] = (HMAC_SIZE + chunk) as u8;
        self.hmac_add.update(&data[..chunk]);
        let hmac_hash = self.hmac_add.clone().finalize().into_bytes()[..HMAC_SIZE].to_vec();
        self.hmac_add.update(&hmac_hash);
        header[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE].copy_from_slice(&hmac_hash);
        ready!(Pin::new(&mut self.inner).poll_write(cx, &header))?;
        ready!(Pin::new(&mut self.inner).poll_write(cx, &data[..chunk]))?;
        Poll::Ready(Ok(chunk))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
        let extension_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let extension_length = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        if extension_length > cursor.len() {
            return false;
        }
        if extension_type == 43 {
            return extension_length == 2 && cursor[0] == 0x03 && cursor[1] == 0x04;
        }
        cursor = &cursor[extension_length..];
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
    use super::*;

    #[test]
    fn generate_session_id_matches_go_oracle_layout() {
        let mut client_hello = vec![0_u8; 120];
        client_hello[0] = 1;
        client_hello[38] = TLS_SESSION_ID_SIZE as u8;
        client_hello[39..39 + TLS_SESSION_ID_SIZE].fill(0);
        let session_id = generate_session_id_bytes("phase6c-shadow-tls-password", &client_hello);
        assert_ne!(session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE], [0_u8; 28]);
    }
}
