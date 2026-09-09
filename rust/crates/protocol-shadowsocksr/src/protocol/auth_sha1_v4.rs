//! `auth_sha1_v4` protocol plugin (SSR-C).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BytesMut};
use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ShadowsocksRProtocolError;
use crate::client_state::AuthState;
use crate::crypto_util::{
    adler32_checksum, append_rand, crc32_ieee, hmac_sha1, random_u32_bounded, unix_timestamp,
};

const AUTH_OVERHEAD: usize = 7;
const MAX_CHUNK: usize = 8100;
const SALT: &[u8] = b"auth_sha1_v4";

fn get_head_size(data: &[u8], default: usize) -> usize {
    if data.len() < 2 {
        return default;
    }
    match data[0] & 7 {
        1 => 7,
        4 => 19,
        3 => 4 + usize::from(data[1]),
        _ => default,
    }
}

fn get_data_length(data: &[u8]) -> usize {
    let want = get_head_size(data, 30) + random_u32_bounded(32) as usize;
    want.min(data.len())
}

/// Framed `auth_sha1_v4` stream over an already-ciphered carrier.
pub(crate) struct AuthSha1V4Conn {
    inner: BoxedStream,
    stream_key: Vec<u8>,
    iv: Vec<u8>,
    auth: AuthState,
    #[allow(dead_code)]
    overhead: usize,
    has_sent_header: bool,
    raw_trans: bool,
    decoded: BytesMut,
    under_decoded: BytesMut,
    pending_write: Vec<u8>,
    pending_offset: usize,
}

impl AuthSha1V4Conn {
    pub(crate) fn with_state(mut self, state: &crate::SsrClientState) -> Self {
        self.auth = state.next();
        self
    }

    pub(crate) fn new(
        inner: BoxedStream,
        stream_key: Vec<u8>,
        iv: Vec<u8>,
        obfs_overhead: usize,
    ) -> Self {
        Self {
            inner,
            stream_key,
            iv,
            auth: AuthState::next_connection(),
            overhead: obfs_overhead + AUTH_OVERHEAD,
            has_sent_header: false,
            raw_trans: false,
            decoded: BytesMut::new(),
            under_decoded: BytesMut::new(),
            pending_write: Vec::new(),
            pending_offset: 0,
        }
    }

    fn pack_rand_data(buf: &mut Vec<u8>, size: usize) {
        if size < 128 {
            buf.push((size + 1) as u8);
            append_rand(buf, size);
            return;
        }
        buf.push(255);
        buf.extend_from_slice(&((size + 3) as u16).to_be_bytes());
        append_rand(buf, size);
    }

    fn rand_data_length(size: usize) -> usize {
        if size > 1200 {
            0
        } else if size > 400 {
            random_u32_bounded(256) as usize
        } else {
            random_u32_bounded(512) as usize
        }
    }

    fn pack_data(out: &mut Vec<u8>, data: &[u8]) {
        let data_length = data.len();
        let rand_data_length = Self::rand_data_length(data_length);
        let mut packed = 2 + 2 + 3 + rand_data_length + data_length + 4;
        if rand_data_length < 128 {
            packed -= 2;
        }

        let start = out.len();
        out.extend_from_slice(&(packed as u16).to_be_bytes());
        let crc = (crc32_ieee(&out[out.len() - 2..]) & 0xffff) as u16;
        out.extend_from_slice(&crc.to_le_bytes());
        Self::pack_rand_data(out, rand_data_length);
        out.extend_from_slice(data);
        // Go: adler32 over the whole frame so far (length+crc+pad+data), then append.
        let adler = adler32_checksum(&out[start..]);
        out.extend_from_slice(&adler.to_le_bytes());
        debug_assert_eq!(out.len() - start, packed);
    }

    fn put_auth_data(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&unix_timestamp().to_le_bytes());
        out.extend_from_slice(&self.auth.client_id);
        out.extend_from_slice(&self.auth.connection_id.to_le_bytes());
    }

    fn pack_auth_data(&self, out: &mut Vec<u8>, data: &[u8]) {
        let data_length = data.len();
        let rand_data_length = Self::rand_data_length(12 + data_length);
        let mut packed = 2 + 4 + 3 + rand_data_length + 12 + data_length + 10;
        if rand_data_length < 128 {
            packed -= 2;
        }

        let mut crc_data = Vec::with_capacity(2 + SALT.len() + self.stream_key.len());
        crc_data.extend_from_slice(&(packed as u16).to_be_bytes());
        crc_data.extend_from_slice(SALT);
        crc_data.extend_from_slice(&self.stream_key);

        let mut mac_key = Vec::with_capacity(self.iv.len() + self.stream_key.len());
        mac_key.extend_from_slice(&self.iv);
        mac_key.extend_from_slice(&self.stream_key);

        let start = out.len();
        out.extend_from_slice(&crc_data[..2]);
        out.extend_from_slice(&crc32_ieee(&crc_data).to_le_bytes());
        Self::pack_rand_data(out, rand_data_length);
        self.put_auth_data(out);
        out.extend_from_slice(data);
        let mac = hmac_sha1(&mac_key, &out[start..]);
        out.extend_from_slice(&mac[..10]);
        debug_assert_eq!(out.len() - start, packed);
    }

    fn encode(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + 64);
        let mut rest = plaintext;
        if !self.has_sent_header {
            let first = get_data_length(rest);
            self.pack_auth_data(&mut out, &rest[..first]);
            rest = &rest[first..];
            self.has_sent_header = true;
        }
        while rest.len() > MAX_CHUNK {
            Self::pack_data(&mut out, &rest[..MAX_CHUNK]);
            rest = &rest[MAX_CHUNK..];
        }
        if !rest.is_empty() {
            Self::pack_data(&mut out, rest);
        }
        out
    }

    fn decode_available(&mut self) -> Result<(), ShadowsocksRProtocolError> {
        if self.raw_trans {
            self.decoded.extend_from_slice(&self.under_decoded);
            self.under_decoded.clear();
            return Ok(());
        }
        while self.under_decoded.len() > 4 {
            let crc = (crc32_ieee(&self.under_decoded[..2]) & 0xffff) as u16;
            let got = u16::from_le_bytes([self.under_decoded[2], self.under_decoded[3]]);
            if crc != got {
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_sha1_v4 length CRC mismatch".into(),
                ));
            }
            let length =
                u16::from_be_bytes([self.under_decoded[0], self.under_decoded[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw_trans = true;
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_sha1_v4 invalid length".into(),
                ));
            }
            if length > self.under_decoded.len() {
                break;
            }
            let adler = adler32_checksum(&self.under_decoded[..length - 4]);
            let got_adler = u32::from_le_bytes(
                self.under_decoded[length - 4..length]
                    .try_into()
                    .expect("4 bytes"),
            );
            if adler != got_adler {
                self.raw_trans = true;
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_sha1_v4 adler32 mismatch".into(),
                ));
            }
            let pos = {
                let first = self.under_decoded[4] as usize;
                if first < 255 {
                    4 + first
                } else {
                    4 + u16::from_be_bytes([self.under_decoded[5], self.under_decoded[6]]) as usize
                }
            };
            // Allow empty payload: pos == length-4. Only reject overrun with `>`.
            if pos > length - 4 {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_sha1_v4 padding overrun".into(),
                ));
            }
            self.decoded
                .extend_from_slice(&self.under_decoded[pos..length - 4]);
            self.under_decoded.advance(length);
        }
        Ok(())
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        while self.pending_offset < self.pending_write.len() {
            let slice = &self.pending_write[self.pending_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, slice) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "auth_sha1_v4 write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_offset += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_write.clear();
        self.pending_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for AuthSha1V4Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.decoded.is_empty() {
            let n = buf.remaining().min(self.decoded.len());
            buf.put_slice(&self.decoded[..n]);
            self.decoded.advance(n);
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0_u8; 16 * 1024];
        let mut tmp = ReadBuf::new(&mut scratch);
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(())) => {
                let filled = tmp.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                self.under_decoded.extend_from_slice(filled);
                self.decode_available().map_err(std::io::Error::other)?;
                if self.decoded.is_empty() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let n = buf.remaining().min(self.decoded.len());
                buf.put_slice(&self.decoded[..n]);
                self.decoded.advance(n);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for AuthSha1V4Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.pending_write = this.encode(buf);
        this.pending_offset = 0;
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

    #[test]
    fn empty_payload_frame_is_not_padding_overrun() {
        // Empty data + 0 rand → packed length 9 (2+2+1+0+4); pos=5 == length-4.
        let mut frame = vec![0_u8, 9];
        let crc = (crc32_ieee(&frame) & 0xffff) as u16;
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.push(1); // size+1 with size=0
        let adler = adler32_checksum(&frame);
        frame.extend_from_slice(&adler.to_le_bytes());
        assert_eq!(frame.len(), 9);

        let mut conn = AuthSha1V4Conn::new(
            Box::new(tokio::io::duplex(64).0),
            vec![0; 16],
            vec![0; 16],
            0,
        );
        conn.under_decoded.extend_from_slice(&frame);
        conn.decode_available().expect("empty frame");
        assert!(conn.decoded.is_empty());
    }
}
