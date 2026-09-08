//! Stream-cipher helpers shared by the SSR TCP/UDP stack.
//!
//! Reuses `shadowsocks-crypto` `EVP_BytesToKey` + stream primitives (same as
//! classic SS stream). Does not wrap the full Shadowsocks client.

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use shadowsocks_crypto::CipherKind;
use shadowsocks_crypto::v1::{Cipher, openssl_bytes_to_key};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ShadowsocksRProtocolError;

/// Parsed SSR method: stream cipher or transparent `none`/`dummy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SsrStreamCipher {
    None,
    Stream(CipherKind),
}

impl SsrStreamCipher {
    pub(crate) fn parse(name: &str) -> Result<Self, ShadowsocksRProtocolError> {
        let lower = name.trim().to_ascii_lowercase();
        match lower.as_str() {
            "none" | "dummy" => Ok(Self::None),
            "aes-128-cfb" => Ok(Self::Stream(CipherKind::AES_128_CFB128)),
            "aes-192-cfb" => Ok(Self::Stream(CipherKind::AES_192_CFB128)),
            "aes-256-cfb" => Ok(Self::Stream(CipherKind::AES_256_CFB128)),
            "aes-128-ctr" => Ok(Self::Stream(CipherKind::AES_128_CTR)),
            "aes-192-ctr" => Ok(Self::Stream(CipherKind::AES_192_CTR)),
            "aes-256-ctr" => Ok(Self::Stream(CipherKind::AES_256_CTR)),
            "rc4-md5" => Ok(Self::Stream(CipherKind::SS_RC4_MD5)),
            // shadowsocks-crypto exposes IETF ChaCha20 as `CHACHA20` / `chacha20-ietf`.
            // Go also lists legacy `chacha20` and `xchacha20`; map IETF alias and reject
            // unsupported stream names loudly (no silent downgrade).
            "chacha20-ietf" => Ok(Self::Stream(CipherKind::CHACHA20)),
            "chacha20" | "xchacha20" => Err(ShadowsocksRProtocolError::Cipher(format!(
                "{name} (SSR-C supports chacha20-ietf via shadowsocks-crypto; legacy chacha20/xchacha20 are not mapped)"
            ))),
            other
                if other.contains("gcm")
                    || other.contains("poly1305")
                    || other.contains("2022")
                    || other.contains("blake3")
                    || other.starts_with("aead_") =>
            {
                Err(ShadowsocksRProtocolError::Cipher(format!(
                    "{name} (AEAD/SS2022 are not SSR; use stream ciphers or none/dummy)"
                )))
            }
            other => Err(ShadowsocksRProtocolError::Cipher(format!(
                "{other} (SSR-C supports none/dummy, aes-*-cfb/ctr, rc4-md5, chacha20-ietf)"
            ))),
        }
    }

    pub(crate) fn iv_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Stream(kind) => kind.iv_len(),
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::None => 16,
            Self::Stream(kind) => kind.key_len(),
        }
    }

    pub(crate) fn kind(self) -> Option<CipherKind> {
        match self {
            Self::None => None,
            Self::Stream(kind) => Some(kind),
        }
    }
}

/// Backward-compatible alias used by TCP dial.
pub(crate) fn parse_stream_cipher(
    name: &str,
) -> Result<SsrStreamCipher, ShadowsocksRProtocolError> {
    SsrStreamCipher::parse(name)
}

/// Protocol-layer key (`none`/`dummy` uses a 16-byte password digest like Go `core.Kdf`).
pub(crate) fn derive_key(password: &str, cipher: SsrStreamCipher) -> Vec<u8> {
    match cipher {
        SsrStreamCipher::None => {
            let mut key = vec![0_u8; 16];
            openssl_bytes_to_key(password.as_bytes(), &mut key);
            key
        }
        SsrStreamCipher::Stream(kind) => {
            let mut key = vec![0_u8; kind.key_len()];
            openssl_bytes_to_key(password.as_bytes(), &mut key);
            key
        }
    }
}

/// TCP carrier wrapped with SS-stream style IV + stream cipher (or passthrough for `none`).
///
/// First write prepends a fresh IV; first read consumes the peer IV.
pub(crate) struct StreamCipherConn {
    inner: BoxedStream,
    key: Vec<u8>,
    cipher: SsrStreamCipher,
    write_iv: Option<Vec<u8>>,
    /// Remaining cleartext IV bytes still to send before ciphertext.
    pending_iv_out: Vec<u8>,
    /// Ciphertext already produced that still needs to be written.
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
        cipher: SsrStreamCipher,
        key: Vec<u8>,
    ) -> Result<Self, ShadowsocksRProtocolError> {
        if key.len() != cipher.key_len() {
            return Err(ShadowsocksRProtocolError::Configuration(format!(
                "key length {} does not match cipher {:?}",
                key.len(),
                cipher
            )));
        }
        Ok(Self {
            inner,
            key,
            cipher,
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
            let mut iv = vec![0_u8; self.cipher.iv_len()];
            if !iv.is_empty() {
                rand::fill(iv.as_mut_slice());
            }
            self.write_iv = Some(iv);
        }
        self.write_iv.as_ref().expect("write IV initialized")
    }

    fn ensure_encrypter(&mut self) {
        if self.enc.is_some() || matches!(self.cipher, SsrStreamCipher::None) {
            let _ = self.obtain_write_iv();
            return;
        }
        let iv = self.obtain_write_iv().to_vec();
        let kind = self.cipher.kind().expect("stream kind");
        self.enc = Some(Cipher::new(kind, &self.key, &iv));
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
        if matches!(self.cipher, SsrStreamCipher::None) {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if self.dec.is_none() {
            let need = self.cipher.iv_len();
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
            let kind = self.cipher.kind().expect("stream kind");
            self.dec = Some(Cipher::new(kind, &self.key, &iv));
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
        if matches!(this.cipher, SsrStreamCipher::None) {
            let _ = this.obtain_write_iv();
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
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
        if matches!(this.cipher, SsrStreamCipher::None) {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
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
        if matches!(this.cipher, SsrStreamCipher::None) {
            return Pin::new(&mut this.inner).poll_shutdown(cx);
        }
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Pack one UDP datagram: `[IV][stream-encrypt(payload)]` (or raw for `none`).
pub(crate) fn pack_udp(cipher: SsrStreamCipher, key: &[u8], payload: &[u8]) -> Vec<u8> {
    match cipher {
        SsrStreamCipher::None => payload.to_vec(),
        SsrStreamCipher::Stream(kind) => {
            let iv_len = kind.iv_len();
            let mut iv = vec![0_u8; iv_len];
            if !iv.is_empty() {
                rand::fill(iv.as_mut_slice());
            }
            let mut enc = Cipher::new(kind, key, &iv);
            let mut body = payload.to_vec();
            enc.encrypt_packet(&mut body);
            let mut out = iv;
            out.extend_from_slice(&body);
            out
        }
    }
}

/// Unpack one UDP datagram.
pub(crate) fn unpack_udp(
    cipher: SsrStreamCipher,
    key: &[u8],
    packet: &[u8],
) -> Result<Vec<u8>, ShadowsocksRProtocolError> {
    match cipher {
        SsrStreamCipher::None => Ok(packet.to_vec()),
        SsrStreamCipher::Stream(kind) => {
            let iv_len = kind.iv_len();
            if packet.len() < iv_len {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "UDP packet shorter than IV".into(),
                ));
            }
            let iv = &packet[..iv_len];
            let mut body = packet[iv_len..].to_vec();
            let mut dec = Cipher::new(kind, key, iv);
            let _ = dec.decrypt_packet(&mut body);
            Ok(body)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_known_aes128_key_length() {
        let kind = parse_stream_cipher("aes-128-cfb").expect("cipher");
        let key = derive_key("ssr-a-password", kind);
        assert_eq!(key.len(), 16);
        assert_eq!(kind.iv_len(), 16);
    }

    #[test]
    fn accepts_ssr_c_stream_ciphers_and_none() {
        assert_eq!(parse_stream_cipher("none").unwrap(), SsrStreamCipher::None);
        assert_eq!(parse_stream_cipher("dummy").unwrap(), SsrStreamCipher::None);
        assert!(matches!(
            parse_stream_cipher("aes-192-cfb").unwrap(),
            SsrStreamCipher::Stream(CipherKind::AES_192_CFB128)
        ));
        assert!(matches!(
            parse_stream_cipher("rc4-md5").unwrap(),
            SsrStreamCipher::Stream(CipherKind::SS_RC4_MD5)
        ));
        assert!(matches!(
            parse_stream_cipher("chacha20-ietf").unwrap(),
            SsrStreamCipher::Stream(CipherKind::CHACHA20)
        ));
        assert!(matches!(
            parse_stream_cipher("aes-128-ctr").unwrap(),
            SsrStreamCipher::Stream(CipherKind::AES_128_CTR)
        ));
    }

    #[test]
    fn rejects_aead_as_not_ssr() {
        let err = parse_stream_cipher("aes-128-gcm").expect_err("aead");
        assert!(err.to_string().contains("AEAD"));
    }

    #[test]
    fn rejects_unmapped_legacy_chacha_loudly() {
        assert!(parse_stream_cipher("chacha20").is_err());
        assert!(parse_stream_cipher("xchacha20").is_err());
    }

    #[test]
    fn none_udp_roundtrip() {
        let p = b"hello-udp";
        let packed = pack_udp(SsrStreamCipher::None, &[], p);
        assert_eq!(packed, p);
        assert_eq!(unpack_udp(SsrStreamCipher::None, &[], &packed).unwrap(), p);
    }

    #[test]
    fn aes_udp_roundtrip() {
        let c = parse_stream_cipher("aes-128-cfb").unwrap();
        let key = derive_key("secret", c);
        let p = b"udp-payload-bytes";
        let packed = pack_udp(c, &key, p);
        assert!(packed.len() > p.len());
        assert_eq!(unpack_udp(c, &key, &packed).unwrap(), p);
    }

    #[test]
    fn go_contract_aes128_cfb_vector() {
        // Fixed IV/password/payload — must match compat/helpers/ssr_stream_vector.
        let cipher = SsrStreamCipher::Stream(CipherKind::AES_128_CFB128);
        let key = derive_key("phase7a-ssr-password", cipher);
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut body = b"ssr-contract".to_vec();
        let mut enc = Cipher::new(CipherKind::AES_128_CFB128, &key, &iv);
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
