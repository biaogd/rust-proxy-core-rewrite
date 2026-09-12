use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use rand::RngExt as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::SnellProtocolError;
use crate::header::{COMMAND_ERROR, COMMAND_TUNNEL};

pub(crate) const SALT_SIZE: usize = 16;
const PAYLOAD_SIZE_MASK: usize = 0x3FFF;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const SIZE_RECORD_LEN: usize = 2 + TAG_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CipherKind {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl CipherKind {
    pub(crate) fn for_version(version: u8) -> Result<Self, SnellProtocolError> {
        match version {
            1 => Ok(Self::ChaCha20Poly1305),
            2 | 3 => Ok(Self::Aes128Gcm),
            other => Err(SnellProtocolError::Protocol(format!(
                "unsupported Snell version {other}"
            ))),
        }
    }

    fn key_size(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::ChaCha20Poly1305 => 32,
        }
    }
}

#[derive(Clone)]
enum AeadKey {
    Aes(Box<Aes128Gcm>),
    ChaCha(ChaCha20Poly1305),
}

impl AeadKey {
    fn seal(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SnellProtocolError> {
        let payload = Payload {
            msg: plaintext,
            aad: b"",
        };
        match self {
            Self::Aes(cipher) => cipher
                .encrypt(AesNonce::from_slice(nonce), payload)
                .map_err(|error| SnellProtocolError::Protocol(error.to_string())),
            Self::ChaCha(cipher) => cipher
                .encrypt(ChaNonce::from_slice(nonce), payload)
                .map_err(|error| SnellProtocolError::Protocol(error.to_string())),
        }
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SnellProtocolError> {
        let payload = Payload {
            msg: ciphertext,
            aad: b"",
        };
        match self {
            Self::Aes(cipher) => cipher
                .decrypt(AesNonce::from_slice(nonce), payload)
                .map_err(|error| SnellProtocolError::Protocol(error.to_string())),
            Self::ChaCha(cipher) => cipher
                .decrypt(ChaNonce::from_slice(nonce), payload)
                .map_err(|error| SnellProtocolError::Protocol(error.to_string())),
        }
    }
}

fn derive_key(psk: &[u8], salt: &[u8], kind: CipherKind) -> Result<AeadKey, SnellProtocolError> {
    let params = argon2::Params::new(8, 3, 1, Some(32))
        .map_err(|error| SnellProtocolError::Protocol(format!("Snell Argon2 params: {error}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut material = [0_u8; 32];
    argon
        .hash_password_into(psk, salt, &mut material)
        .map_err(|error| SnellProtocolError::Protocol(format!("Snell Argon2id failed: {error}")))?;
    let key = material
        .get(..kind.key_size())
        .ok_or_else(|| SnellProtocolError::Protocol("Snell key slice failed".to_owned()))?;
    match kind {
        CipherKind::Aes128Gcm => Ok(AeadKey::Aes(Box::new(
            Aes128Gcm::new_from_slice(key)
                .map_err(|error| SnellProtocolError::Protocol(error.to_string()))?,
        ))),
        CipherKind::ChaCha20Poly1305 => Ok(AeadKey::ChaCha(
            ChaCha20Poly1305::new_from_slice(key)
                .map_err(|error| SnellProtocolError::Protocol(error.to_string()))?,
        )),
    }
}

fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    aead: &AeadKey,
    nonce: &mut [u8; NONCE_SIZE],
    payload: &[u8],
) -> Result<(), SnellProtocolError> {
    if payload.is_empty() {
        let size = [0_u8; 2];
        let size_record = aead.seal(nonce, &size)?;
        increment_nonce(nonce);
        writer.write_all(&size_record).await?;
        return Ok(());
    }
    let mut remaining = payload;
    while !remaining.is_empty() {
        let take = remaining.len().min(PAYLOAD_SIZE_MASK);
        let chunk = remaining.get(..take).unwrap_or(&[]);
        let size = [
            u8::try_from(take >> 8).unwrap_or(0),
            u8::try_from(take & 0xFF).unwrap_or(0),
        ];
        let size_record = aead.seal(nonce, &size)?;
        increment_nonce(nonce);
        writer.write_all(&size_record).await?;
        let body = aead.seal(nonce, chunk)?;
        increment_nonce(nonce);
        writer.write_all(&body).await?;
        remaining = remaining.get(take..).unwrap_or(&[]);
    }
    Ok(())
}

async fn read_record<R: AsyncRead + Unpin>(
    reader: &mut R,
    aead: &AeadKey,
    nonce: &mut [u8; NONCE_SIZE],
) -> Result<Vec<u8>, SnellProtocolError> {
    let mut size_record = vec![0_u8; SIZE_RECORD_LEN];
    reader.read_exact(&mut size_record).await?;
    let size_plain = aead.open(nonce, &size_record)?;
    increment_nonce(nonce);
    if size_plain.len() != 2 {
        return Err(SnellProtocolError::Protocol(
            "Snell AEAD length record was truncated".to_owned(),
        ));
    }
    let size = ((usize::from(size_plain[0]) << 8) | usize::from(size_plain[1])) & PAYLOAD_SIZE_MASK;
    if size == 0 {
        return Err(SnellProtocolError::Protocol("Snell zero chunk".to_owned()));
    }
    let mut body = vec![0_u8; size + TAG_SIZE];
    reader.read_exact(&mut body).await?;
    let plain = aead.open(nonce, &body)?;
    increment_nonce(nonce);
    Ok(plain)
}

#[derive(Debug)]
enum ReadPhase {
    Salt {
        buf: [u8; SALT_SIZE],
        filled: usize,
    },
    Idle,
    Size {
        buf: [u8; SIZE_RECORD_LEN],
        filled: usize,
    },
    Payload {
        buf: Vec<u8>,
        filled: usize,
    },
}

/// Bidirectional Snell AEAD stream. Client salts are written with the header;
/// the peer salt and `CommandTunnel` reply are consumed on the first read.
pub struct SnellStream<S> {
    inner: S,
    psk: Vec<u8>,
    kind: CipherKind,
    write_aead: Option<AeadKey>,
    read_aead: Option<AeadKey>,
    write_nonce: [u8; NONCE_SIZE],
    read_nonce: [u8; NONCE_SIZE],
    leftover: Vec<u8>,
    leftover_off: usize,
    pending: Vec<u8>,
    pending_off: usize,
    read_phase: ReadPhase,
    reply_pending: bool,
}

impl<S> SnellStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn client(
        mut inner: S,
        psk: &[u8],
        kind: CipherKind,
        header: &[u8],
    ) -> Result<Self, SnellProtocolError> {
        let mut write_salt = [0_u8; SALT_SIZE];
        rand::rng().fill(&mut write_salt);
        let write_aead = derive_key(psk, &write_salt, kind)?;
        inner.write_all(&write_salt).await?;
        let mut write_nonce = [0_u8; NONCE_SIZE];
        write_record(&mut inner, &write_aead, &mut write_nonce, header).await?;
        Ok(Self {
            inner,
            psk: psk.to_vec(),
            kind,
            write_aead: Some(write_aead),
            read_aead: None,
            write_nonce,
            read_nonce: [0_u8; NONCE_SIZE],
            leftover: Vec::new(),
            leftover_off: 0,
            pending: Vec::new(),
            pending_off: 0,
            read_phase: ReadPhase::Salt {
                buf: [0_u8; SALT_SIZE],
                filled: 0,
            },
            reply_pending: true,
        })
    }

    pub(crate) async fn server(
        mut inner: S,
        psk: &[u8],
        kind: CipherKind,
    ) -> Result<Self, SnellProtocolError> {
        let mut read_salt = [0_u8; SALT_SIZE];
        inner.read_exact(&mut read_salt).await?;
        let read_aead = derive_key(psk, &read_salt, kind)?;
        Ok(Self {
            inner,
            psk: psk.to_vec(),
            kind,
            write_aead: None,
            read_aead: Some(read_aead),
            write_nonce: [0_u8; NONCE_SIZE],
            read_nonce: [0_u8; NONCE_SIZE],
            leftover: Vec::new(),
            leftover_off: 0,
            pending: Vec::new(),
            pending_off: 0,
            read_phase: ReadPhase::Idle,
            reply_pending: false,
        })
    }

    pub(crate) async fn read_plain(&mut self, max: usize) -> Result<Vec<u8>, SnellProtocolError> {
        if let Some(available) = self.take_leftover_bytes(max) {
            return Ok(available);
        }
        let aead = self.read_aead.as_ref().ok_or_else(|| {
            SnellProtocolError::Protocol("Snell reader is not initialized".to_owned())
        })?;
        let record = read_record(&mut self.inner, aead, &mut self.read_nonce).await?;
        if record.len() <= max {
            Ok(record)
        } else {
            let kept = record.get(..max).unwrap_or(&[]).to_vec();
            self.leftover = record.get(max..).unwrap_or(&[]).to_vec();
            self.leftover_off = 0;
            Ok(kept)
        }
    }

    pub(crate) async fn write_plain(&mut self, payload: &[u8]) -> Result<(), SnellProtocolError> {
        self.ensure_writer_async().await?;
        let aead = self.write_aead.as_ref().ok_or_else(|| {
            SnellProtocolError::Protocol("Snell writer is not initialized".to_owned())
        })?;
        write_record(&mut self.inner, aead, &mut self.write_nonce, payload).await
    }

    async fn ensure_writer_async(&mut self) -> Result<(), SnellProtocolError> {
        if self.write_aead.is_some() {
            return Ok(());
        }
        let mut write_salt = [0_u8; SALT_SIZE];
        rand::rng().fill(&mut write_salt);
        let write_aead = derive_key(&self.psk, &write_salt, self.kind)?;
        self.inner.write_all(&write_salt).await?;
        self.write_aead = Some(write_aead);
        Ok(())
    }

    fn take_leftover_bytes(&mut self, max: usize) -> Option<Vec<u8>> {
        if self.leftover_off >= self.leftover.len() {
            return None;
        }
        let available = self.leftover.len() - self.leftover_off;
        let take = available.min(max);
        let start = self.leftover_off;
        let end = start + take;
        let copied = self.leftover.get(start..end).unwrap_or(&[]).to_vec();
        self.leftover_off = end;
        if self.leftover_off == self.leftover.len() {
            self.leftover.clear();
            self.leftover_off = 0;
        }
        Some(copied)
    }

    fn copy_leftover(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.leftover_off >= self.leftover.len() || buf.remaining() == 0 {
            return false;
        }
        let available = self.leftover.len() - self.leftover_off;
        let take = available.min(buf.remaining());
        let start = self.leftover_off;
        let end = start + take;
        buf.put_slice(self.leftover.get(start..end).unwrap_or(&[]));
        self.leftover_off = end;
        if self.leftover_off == self.leftover.len() {
            self.leftover.clear();
            self.leftover_off = 0;
        }
        true
    }

    fn consume_reply(&mut self) -> Result<(), std::io::Error> {
        if !self.reply_pending {
            return Ok(());
        }
        if self.leftover_off >= self.leftover.len() {
            return Ok(());
        }
        let command = *self
            .leftover
            .get(self.leftover_off)
            .ok_or_else(|| std::io::Error::other("Snell leftover reply index is out of range"))?;
        self.leftover_off += 1;
        if self.leftover_off == self.leftover.len() {
            self.leftover.clear();
            self.leftover_off = 0;
        }
        self.reply_pending = false;
        if command == COMMAND_TUNNEL {
            return Ok(());
        }
        if command != COMMAND_ERROR {
            return Err(std::io::Error::other(format!(
                "Snell command not supported: {command}"
            )));
        }
        Err(std::io::Error::other("Snell server reported an error"))
    }

    fn encrypt_payload(&mut self, buf: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut pending = Vec::new();
        if self.write_aead.is_none() {
            let mut write_salt = [0_u8; SALT_SIZE];
            rand::rng().fill(&mut write_salt);
            let write_aead = derive_key(&self.psk, &write_salt, self.kind)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            pending.extend_from_slice(&write_salt);
            self.write_aead = Some(write_aead);
        }
        let aead = self
            .write_aead
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Snell writer is not initialized"))?;
        let mut remaining = buf;
        while !remaining.is_empty() {
            let take = remaining.len().min(PAYLOAD_SIZE_MASK);
            let chunk = remaining.get(..take).unwrap_or(&[]);
            let size = [
                u8::try_from(take >> 8).unwrap_or(0),
                u8::try_from(take & 0xFF).unwrap_or(0),
            ];
            let size_record = aead
                .seal(&self.write_nonce, &size)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            increment_nonce(&mut self.write_nonce);
            pending.extend_from_slice(&size_record);
            let body = aead
                .seal(&self.write_nonce, chunk)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            increment_nonce(&mut self.write_nonce);
            pending.extend_from_slice(&body);
            remaining = remaining.get(take..).unwrap_or(&[]);
        }
        Ok(pending)
    }

    fn flush_pending(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.pending_off < this.pending.len() {
            let rest = this.pending.get(this.pending_off..).unwrap_or(&[]);
            match Pin::new(&mut this.inner).poll_write(cx, rest) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Snell transport write returned zero",
                    )));
                }
                Poll::Ready(Ok(written)) => this.pending_off += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.pending.clear();
        this.pending_off = 0;
        Poll::Ready(Ok(()))
    }
}

fn poll_fill<S: AsyncRead + Unpin>(
    inner: &mut S,
    cx: &mut Context<'_>,
    dest: &mut [u8],
    filled: &mut usize,
) -> Poll<std::io::Result<bool>> {
    while *filled < dest.len() {
        let mut read_buf = ReadBuf::new(dest.get_mut(*filled..).unwrap_or(&mut []));
        match Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(false));
                }
                *filled += n;
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(true))
}

impl<S> AsyncRead for SnellStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    #[allow(clippy::too_many_lines)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            {
                let this = self.as_mut().get_mut();
                this.consume_reply()?;
                if this.copy_leftover(buf) {
                    return Poll::Ready(Ok(()));
                }
            }
            let this = self.as_mut().get_mut();
            match &mut this.read_phase {
                ReadPhase::Salt { buf: salt, filled } => {
                    match poll_fill(&mut this.inner, cx, salt, filled) {
                        Poll::Ready(Ok(false)) => {
                            if *filled == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Snell salt ended early",
                            )));
                        }
                        Poll::Ready(Ok(true)) => {
                            let read_aead = derive_key(&this.psk, salt, this.kind)
                                .map_err(|error| std::io::Error::other(error.to_string()))?;
                            this.read_aead = Some(read_aead);
                            this.read_phase = ReadPhase::Idle;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReadPhase::Idle => {
                    this.read_phase = ReadPhase::Size {
                        buf: [0_u8; SIZE_RECORD_LEN],
                        filled: 0,
                    };
                }
                ReadPhase::Size {
                    buf: size_buf,
                    filled,
                } => match poll_fill(&mut this.inner, cx, size_buf, filled) {
                    Poll::Ready(Ok(false)) => {
                        if *filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "Snell length record ended early",
                        )));
                    }
                    Poll::Ready(Ok(true)) => {
                        let aead = this.read_aead.as_ref().ok_or_else(|| {
                            std::io::Error::other("Snell reader is not initialized")
                        })?;
                        let size_plain = aead
                            .open(&this.read_nonce, size_buf)
                            .map_err(|error| std::io::Error::other(error.to_string()))?;
                        increment_nonce(&mut this.read_nonce);
                        if size_plain.len() != 2 {
                            return Poll::Ready(Err(std::io::Error::other(
                                "Snell AEAD length record was truncated",
                            )));
                        }
                        let size = ((usize::from(size_plain[0]) << 8) | usize::from(size_plain[1]))
                            & PAYLOAD_SIZE_MASK;
                        if size == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Snell zero chunk",
                            )));
                        }
                        this.read_phase = ReadPhase::Payload {
                            buf: vec![0_u8; size + TAG_SIZE],
                            filled: 0,
                        };
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                },
                ReadPhase::Payload { buf: body, filled } => {
                    match poll_fill(&mut this.inner, cx, body, filled) {
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Snell payload ended early",
                            )));
                        }
                        Poll::Ready(Ok(true)) => {
                            let aead = this.read_aead.as_ref().ok_or_else(|| {
                                std::io::Error::other("Snell reader is not initialized")
                            })?;
                            let plain = aead
                                .open(&this.read_nonce, body)
                                .map_err(|error| std::io::Error::other(error.to_string()))?;
                            increment_nonce(&mut this.read_nonce);
                            this.leftover = plain;
                            this.leftover_off = 0;
                            this.read_phase = ReadPhase::Idle;
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl<S> AsyncWrite for SnellStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.as_mut().flush_pending(cx).is_pending() {
            return Poll::Pending;
        }
        let pending = self
            .as_mut()
            .get_mut()
            .encrypt_payload(buf)
            .map_err(std::io::Error::other)?;
        let this = self.as_mut().get_mut();
        this.pending = pending;
        this.pending_off = 0;
        match Pin::new(this).flush_pending(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self;
        if this.as_mut().flush_pending(cx).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.as_mut().flush_pending(cx).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{CipherKind, derive_key};

    #[test]
    fn argon2id_key_is_deterministic() {
        let first = derive_key(
            b"password",
            b"0123456789abcdef",
            CipherKind::ChaCha20Poly1305,
        )
        .expect("kdf");
        let second = derive_key(
            b"password",
            b"0123456789abcdef",
            CipherKind::ChaCha20Poly1305,
        )
        .expect("kdf");
        let nonce = [0_u8; 12];
        let sealed = first.seal(&nonce, b"ping").expect("seal");
        let opened = second.open(&nonce, &sealed).expect("open");
        assert_eq!(opened, b"ping");
    }
}
