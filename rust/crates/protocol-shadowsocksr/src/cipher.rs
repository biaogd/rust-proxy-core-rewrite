//! Stream-cipher helpers shared by the SSR TCP stack.
//!
//! Reuses `shadowsocks-crypto` `EVP_BytesToKey` + AES-CFB primitives (same as
//! classic SS stream). Does not wrap the full Shadowsocks client.

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use shadowsocks_crypto::CipherKind;
use shadowsocks_crypto::v1::{Cipher, openssl_bytes_to_key};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ShadowsocksRProtocolError;

/// SSR-A stream ciphers (AES-CFB only).
pub(crate) fn parse_stream_cipher(name: &str) -> Result<CipherKind, ShadowsocksRProtocolError> {
    match name {
        "aes-128-cfb" => Ok(CipherKind::AES_128_CFB128),
        "aes-256-cfb" => Ok(CipherKind::AES_256_CFB128),
        other => Err(ShadowsocksRProtocolError::Cipher(format!(
            "{other} (SSR-A supports aes-128-cfb / aes-256-cfb only; AEAD/SS2022 are not SSR)"
        ))),
    }
}

pub(crate) fn derive_key(password: &str, kind: CipherKind) -> Vec<u8> {
    let mut key = vec![0_u8; kind.key_len()];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

/// TCP carrier wrapped with SS-stream style IV + CFB.
///
/// First write prepends a fresh IV; first read consumes the peer IV.
pub(crate) struct StreamCipherConn {
    inner: BoxedStream,
    key: Vec<u8>,
    kind: CipherKind,
    write_iv: Option<Vec<u8>>,
    /// Remaining cleartext IV bytes still to send before ciphertext.
    pending_iv_out: Vec<u8>,
    /// Ciphertext already produced that still needs to be written.
    ///
    /// Required so a `Poll::Pending` after encrypt does not re-encrypt the same
    /// plaintext (stream ciphers are not rewindable).
    pending_ct_out: Vec<u8>,
    pending_ct_offset: usize,
    enc: Option<Cipher>,
    /// Bytes of the peer IV already buffered while reading.
    pending_iv_in: Vec<u8>,
    dec: Option<Cipher>,
}

impl StreamCipherConn {
    pub(crate) fn new(
        inner: BoxedStream,
        kind: CipherKind,
        key: Vec<u8>,
    ) -> Result<Self, ShadowsocksRProtocolError> {
        if key.len() != kind.key_len() {
            return Err(ShadowsocksRProtocolError::Configuration(format!(
                "key length {} does not match cipher {}",
                key.len(),
                kind
            )));
        }
        Ok(Self {
            inner,
            key,
            kind,
            write_iv: None,
            pending_iv_out: Vec::new(),
            pending_ct_out: Vec::new(),
            pending_ct_offset: 0,
            enc: None,
            pending_iv_in: Vec::new(),
            dec: None,
        })
    }

    /// Returns (and lazily generates) the write IV before the first encrypt.
    pub(crate) fn obtain_write_iv(&mut self) -> &[u8] {
        if self.write_iv.is_none() {
            let mut iv = vec![0_u8; self.kind.iv_len()];
            rand::fill(iv.as_mut_slice());
            self.write_iv = Some(iv);
        }
        self.write_iv.as_ref().expect("write IV initialized")
    }

    fn ensure_encrypter(&mut self) {
        if self.enc.is_some() {
            return;
        }
        let iv = self.obtain_write_iv().to_vec();
        self.enc = Some(Cipher::new(self.kind, &self.key, &iv));
        self.pending_iv_out = iv;
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        while !self.pending_iv_out.is_empty() {
            let pending = self.pending_iv_out.clone();
            match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write ShadowsocksR stream IV",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.pending_iv_out.drain(..n);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        while self.pending_ct_offset < self.pending_ct_out.len() {
            let slice = &self.pending_ct_out[self.pending_ct_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, slice) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write ShadowsocksR ciphertext",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    self.pending_ct_offset += n;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_ct_out.clear();
        self.pending_ct_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for StreamCipherConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.dec.is_none() {
            let need = self.kind.iv_len();
            while self.pending_iv_in.len() < need {
                let mut scratch = [0_u8; 64];
                let mut tmp = ReadBuf::new(&mut scratch[..need - self.pending_iv_in.len()]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut tmp) {
                    Poll::Ready(Ok(())) => {
                        let filled = tmp.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "EOF while reading ShadowsocksR stream IV",
                            )));
                        }
                        self.pending_iv_in.extend_from_slice(filled);
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let iv = self.pending_iv_in.clone();
            self.dec = Some(Cipher::new(self.kind, &self.key, &iv));
        }

        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled_mut();
                if filled.len() > before {
                    let chunk = &mut filled[before..];
                    let Some(dec) = self.dec.as_mut() else {
                        return Poll::Ready(Err(std::io::Error::other(
                            "ShadowsocksR decryptor missing",
                        )));
                    };
                    let _ = dec.decrypt_packet(chunk);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for StreamCipherConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.as_mut().get_mut();
        this.ensure_encrypter();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut encrypted = buf.to_vec();
        let Some(enc) = this.enc.as_mut() else {
            return Poll::Ready(Err(std::io::Error::other("ShadowsocksR encryptor missing")));
        };
        enc.encrypt_packet(&mut encrypted);
        this.pending_ct_out = encrypted;
        this.pending_ct_offset = 0;
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks_crypto::v1::Cipher;

    #[test]
    fn derives_known_aes128_key_length() {
        let kind = parse_stream_cipher("aes-128-cfb").expect("cipher");
        let key = derive_key("ssr-a-password", kind);
        assert_eq!(key.len(), 16);
        assert_eq!(kind.iv_len(), 16);
    }

    #[test]
    fn rejects_aead_as_not_ssr() {
        let err = parse_stream_cipher("aes-128-gcm").expect_err("aead");
        assert!(err.to_string().contains("AEAD"));
    }

    #[test]
    fn go_contract_aes128_cfb_vector() {
        // Fixed IV/password/payload — must match compat/helpers/ssr_stream_vector.
        let kind = CipherKind::AES_128_CFB128;
        let key = derive_key("phase7a-ssr-password", kind);
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut body = b"ssr-contract".to_vec();
        let mut enc = Cipher::new(kind, &key, &iv);
        enc.encrypt_packet(&mut body);
        let mut out = iv.to_vec();
        out.extend_from_slice(&body);
        let mut got = String::with_capacity(out.len() * 2);
        for byte in &out {
            use std::fmt::Write as _;
            let _ = write!(got, "{byte:02x}");
        }
        // go run ./compat/helpers/ssr_stream_vector -password phase7a-ssr-password \
        //   -cipher aes-128-cfb -iv 000102030405060708090a0b0c0d0e0f -payload ssr-contract
        assert_eq!(
            got,
            "000102030405060708090a0b0c0d0e0f57b974d250363444a5cc1112"
        );
    }
}
