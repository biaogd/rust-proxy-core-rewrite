//! `auth_aes128_md5` / `auth_aes128_sha1` protocol plugins (SSR-B).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BytesMut};
use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ShadowsocksRProtocolError;
use crate::client_state::AuthState;
use crate::crypto_util::{
    HashKind, aes128_cbc_encrypt_block, append_rand, kdf, random_u32_bounded, trapezoid_random,
    unix_timestamp,
};

const AUTH_OVERHEAD: usize = 9;
const MAX_CHUNK: usize = 8100;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthAes128Kind {
    pub salt: &'static str,
    pub hash: HashKind,
}

pub(crate) const AUTH_AES128_MD5: AuthAes128Kind = AuthAes128Kind {
    salt: "auth_aes128_md5",
    hash: HashKind::Md5,
};

pub(crate) const AUTH_AES128_SHA1: AuthAes128Kind = AuthAes128Kind {
    salt: "auth_aes128_sha1",
    hash: HashKind::Sha1,
};

struct UserData {
    user_key: Vec<u8>,
    user_id: [u8; 4],
}

fn parse_user(param: &str, kind: AuthAes128Kind, stream_key: &[u8]) -> UserData {
    if let Some((uid, passwd)) = param.split_once(':')
        && let Ok(user_id_num) = uid.parse::<u32>()
    {
        let mut user_id = [0_u8; 4];
        user_id.copy_from_slice(&user_id_num.to_le_bytes());
        return UserData {
            user_key: kind.hash.digest(passwd.as_bytes()),
            user_id,
        };
    }
    let mut user_id = [0_u8; 4];
    rand::fill(&mut user_id);
    UserData {
        user_key: stream_key.to_vec(),
        user_id,
    }
}

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

/// Framed auth_aes128 stream over an already-ciphered carrier.
pub(crate) struct AuthAes128Conn {
    inner: BoxedStream,
    kind: AuthAes128Kind,
    stream_key: Vec<u8>,
    iv: Vec<u8>,
    user: UserData,
    auth: AuthState,
    overhead: usize,
    has_sent_header: bool,
    raw_trans: bool,
    pack_id: u32,
    recv_id: u32,
    decoded: BytesMut,
    under_decoded: BytesMut,
    pending_write: Vec<u8>,
    pending_offset: usize,
}

impl AuthAes128Conn {
    pub(crate) fn with_state(mut self, state: &crate::SsrClientState) -> Self {
        self.auth = state.next();
        self
    }

    pub(crate) fn new(
        inner: BoxedStream,
        kind: AuthAes128Kind,
        stream_key: Vec<u8>,
        iv: Vec<u8>,
        protocol_param: &str,
        obfs_overhead: usize,
    ) -> Self {
        let user = parse_user(protocol_param, kind, &stream_key);
        Self {
            inner,
            kind,
            stream_key,
            iv,
            user,
            auth: AuthState::next_connection(),
            overhead: obfs_overhead + AUTH_OVERHEAD,
            has_sent_header: false,
            raw_trans: false,
            pack_id: 1,
            recv_id: 1,
            decoded: BytesMut::new(),
            under_decoded: BytesMut::new(),
            pending_write: Vec::new(),
            pending_offset: 0,
        }
    }

    fn mac_key_pack(&self, pack_id: u32) -> Vec<u8> {
        let mut key = self.user.user_key.clone();
        key.extend_from_slice(&pack_id.to_le_bytes());
        key
    }

    fn mac_key_iv(&self) -> Vec<u8> {
        let mut key = self.iv.clone();
        key.extend_from_slice(&self.stream_key);
        key
    }

    fn pack_rand_data(buf: &mut Vec<u8>, size: usize) {
        if size < 128 {
            buf.push((size + 1) as u8);
            append_rand(buf, size);
            return;
        }
        buf.push(255);
        buf.extend_from_slice(&((size + 3) as u16).to_le_bytes());
        append_rand(buf, size);
    }

    fn rand_len_for_pack_data(&self, data_length: usize, full_data_length: usize) -> usize {
        if full_data_length >= 32 * 1024 - self.overhead {
            return 0;
        }
        let rev_length = 1460_i32 - data_length as i32 - 9;
        if rev_length == 0 {
            return 0;
        }
        if rev_length < 0 {
            if rev_length > -1460 {
                return trapezoid_random(rev_length + 1460, -0.3).max(0) as usize;
            }
            return random_u32_bounded(32) as usize;
        }
        if data_length > 900 {
            return random_u32_bounded(rev_length as u32) as usize;
        }
        trapezoid_random(rev_length, -0.3).max(0) as usize
    }

    fn rand_len_for_auth(size: usize) -> usize {
        if size > 400 {
            random_u32_bounded(512) as usize
        } else {
            random_u32_bounded(1024) as usize
        }
    }

    fn pack_data(&mut self, out: &mut Vec<u8>, data: &[u8], full_data_length: usize) {
        let data_length = data.len();
        let rand_data_length = self.rand_len_for_pack_data(data_length, full_data_length);
        let mut packed = 2 + 2 + 3 + rand_data_length + data_length + 4;
        if rand_data_length < 128 {
            packed -= 2;
        }
        let mac_key = self.mac_key_pack(self.pack_id);
        self.pack_id = self.pack_id.wrapping_add(1);

        let start = out.len();
        out.extend_from_slice(&(packed as u16).to_le_bytes());
        let hmac_len = self.kind.hash.hmac(&mac_key, &out[out.len() - 2..]);
        out.extend_from_slice(&hmac_len[..2]);
        Self::pack_rand_data(out, rand_data_length);
        out.extend_from_slice(data);
        let hmac_body = self.kind.hash.hmac(&mac_key, &out[start..]);
        out.extend_from_slice(&hmac_body[..4]);
        debug_assert_eq!(out.len() - start, packed);
    }

    fn pack_auth_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let data_length = data.len();
        let rand_data_length = Self::rand_len_for_auth(data_length);
        let packed = 7 + 4 + 16 + 4 + rand_data_length + data_length + 4;
        let mac_key = self.mac_key_iv();

        let start = out.len();
        out.push(random_u32_bounded(256) as u8);
        let head_mac = self.kind.hash.hmac(&mac_key, &out[start..]);
        out.extend_from_slice(&head_mac[..6]);
        out.extend_from_slice(&self.user.user_id);

        let mut block = [0_u8; 16];
        block[..4].copy_from_slice(&unix_timestamp().to_le_bytes());
        block[4..8].copy_from_slice(&self.auth.client_id);
        block[8..12].copy_from_slice(&self.auth.connection_id.to_le_bytes());
        block[12..14].copy_from_slice(&(packed as u16).to_le_bytes());
        block[14..16].copy_from_slice(&(rand_data_length as u16).to_le_bytes());

        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &self.user.user_key,
        );
        let cipher_key_vec = kdf(&format!("{}{}", b64, self.kind.salt), 16);
        let mut cipher_key = [0_u8; 16];
        cipher_key.copy_from_slice(&cipher_key_vec);
        aes128_cbc_encrypt_block(&cipher_key, &mut block);
        out.extend_from_slice(&block);

        let mid_mac = self.kind.hash.hmac(&mac_key, &out[start + 7..]);
        out.extend_from_slice(&mid_mac[..4]);
        append_rand(out, rand_data_length);
        out.extend_from_slice(data);
        let trail = self.kind.hash.hmac(&self.user.user_key, &out[start..]);
        out.extend_from_slice(&trail[..4]);
        debug_assert_eq!(out.len() - start, packed);
    }

    fn encode(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + 64);
        let full = plaintext.len();
        let mut rest = plaintext;
        if !self.has_sent_header {
            let first = get_data_length(rest);
            self.pack_auth_data(&mut out, &rest[..first]);
            rest = &rest[first..];
            self.has_sent_header = true;
        }
        while rest.len() > MAX_CHUNK {
            self.pack_data(&mut out, &rest[..MAX_CHUNK], full);
            rest = &rest[MAX_CHUNK..];
        }
        if !rest.is_empty() {
            self.pack_data(&mut out, rest, full);
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
            let mac_key = self.mac_key_pack(self.recv_id);
            let len_mac = self.kind.hash.hmac(&mac_key, &self.under_decoded[..2]);
            if len_mac[..2] != self.under_decoded[2..4] {
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_aes128 length MAC mismatch".into(),
                ));
            }
            let length =
                u16::from_le_bytes([self.under_decoded[0], self.under_decoded[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw_trans = true;
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_aes128 invalid length".into(),
                ));
            }
            if length > self.under_decoded.len() {
                break;
            }
            let chunk_mac = self
                .kind
                .hash
                .hmac(&mac_key, &self.under_decoded[..length - 4]);
            if chunk_mac[..4] != self.under_decoded[length - 4..length] {
                self.raw_trans = true;
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_aes128 chunk checksum mismatch".into(),
                ));
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            let pos = {
                let first = self.under_decoded[4] as usize;
                if first < 255 {
                    4 + first
                } else {
                    4 + u16::from_le_bytes([self.under_decoded[5], self.under_decoded[6]]) as usize
                }
            };
            if pos > length - 4 {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_aes128 padding overrun".into(),
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
                        "auth_aes128 write returned 0",
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

impl AsyncRead for AuthAes128Conn {
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

impl AsyncWrite for AuthAes128Conn {
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

/// UDP `EncodePacket` / `DecodePacket` for `auth_aes128_*` (Go parity).
pub(crate) struct AuthAes128Udp {
    kind: AuthAes128Kind,
    stream_key: Vec<u8>,
    user: UserData,
}

impl AuthAes128Udp {
    pub(crate) fn new(kind: AuthAes128Kind, stream_key: Vec<u8>, protocol_param: &str) -> Self {
        let user = parse_user(protocol_param, kind, &stream_key);
        Self {
            kind,
            stream_key,
            user,
        }
    }

    pub(crate) fn encode_packet(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + 8);
        out.extend_from_slice(plaintext);
        out.extend_from_slice(&self.user.user_id);
        let mac = self.kind.hash.hmac(&self.user.user_key, &out);
        out.extend_from_slice(&mac[..4]);
        out
    }

    pub(crate) fn decode_packet(
        &self,
        packet: &[u8],
    ) -> Result<Vec<u8>, ShadowsocksRProtocolError> {
        if packet.len() < 4 {
            return Err(ShadowsocksRProtocolError::Protocol(
                "auth_aes128 udp packet too short".into(),
            ));
        }
        let body = &packet[..packet.len() - 4];
        let mac = self.kind.hash.hmac(&self.stream_key, body);
        if mac[..4] != packet[packet.len() - 4..] {
            return Err(ShadowsocksRProtocolError::Protocol(
                "auth_aes128 udp checksum mismatch".into(),
            ));
        }
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_util::HashKind;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    #[test]
    fn aes_key_matches_go_kdf_shape() {
        let user_key = HashKind::Md5.digest(b"passwd");
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &user_key);
        let key = kdf(&format!("{b64}auth_aes128_md5"), 16);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn protocol_param_sets_user_id_and_hashed_key() {
        let stream_key = vec![9_u8; 16];
        let user = parse_user("1001:phase7b", AUTH_AES128_MD5, &stream_key);
        assert_eq!(user.user_id, 1001_u32.to_le_bytes());
        assert_eq!(user.user_key, HashKind::Md5.digest(b"phase7b"));
        let fallback = parse_user("", AUTH_AES128_MD5, &stream_key);
        assert_eq!(fallback.user_key, stream_key);
    }

    #[test]
    fn empty_sendback_frame_is_not_padding_overrun() {
        // pos == length-4 (empty payload) must succeed — server sendback uses this.
        let user_key = decode_hex("4bf7b0ca7ec640dd7e79a2cf793b5fd4");
        let mut conn = AuthAes128Conn::new(
            Box::new(tokio::io::duplex(64).0),
            AUTH_AES128_MD5,
            user_key.clone(),
            vec![0; 16],
            "",
            0,
        );
        // length=9, pad prefix size+1=1 → pos=5 == length-4; HMAC over first 5 bytes.
        let mac_key = {
            let mut key = user_key.clone();
            key.extend_from_slice(&1_u32.to_le_bytes());
            key
        };
        let mut frame = vec![9_u8, 0];
        let len_mac = HashKind::Md5.hmac(&mac_key, &frame);
        frame.extend_from_slice(&len_mac[..2]);
        frame.push(1); // size+1 with size=0
        let body_mac = HashKind::Md5.hmac(&mac_key, &frame);
        frame.extend_from_slice(&body_mac[..4]);
        assert_eq!(frame.len(), 9);
        conn.under_decoded.extend_from_slice(&frame);
        conn.decode_available().expect("empty frame");
        assert!(conn.decoded.is_empty());
        assert_eq!(conn.recv_id, 2);
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&input[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn decodes_python_pack_data_hello_frame() {
        // Generated by pinned shadowsocksrr auth_aes128_md5.pack_data(b"hello", 5)
        // with user_key = EVP_BytesToKey("phase7a-ssr-password").
        let frame = decode_hex(
            "fc00f9bfffef00fff359588cdfae02b69d743b7a8c5f093fcbe00bf95a10fe8a84ecc2599d1573ad61a24f6a30efb13f7aaf2ae4cc442acf980ada308b736abb2489de30175be79528790c60026c64bd99df37b3a7f47334ec1d9b059d0f780a7b6f79d9a606d0fb3d233fc860518e997d64e96a2284809bac2fcc89e6d958dffe92a9b254d5249268b97059d48402873bc5c7e1940cde607f08ff4d47384ec64c5e2202e15974dcf519632d1342e3a1b13b0404cc67ae0117f9e463bc23ce11ab0c42dfcabce7441cdac16b508de41e431e8d4d792ab8f622a93dbd8a73945cbc74c545c1438de9c1d12d0f85368862338ab068656c6c6f78e8eaf4",
        );
        let user_key = decode_hex("4bf7b0ca7ec640dd7e79a2cf793b5fd4");
        let (client, mut server) = duplex(4096);
        let mut conn = AuthAes128Conn::new(
            Box::new(client),
            AUTH_AES128_MD5,
            user_key.clone(),
            vec![0; 16],
            "",
            0,
        );
        // Force user_key (empty protocol-param uses stream_key, which we passed).
        assert_eq!(conn.user.user_key, user_key);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            server.write_all(&frame).await.unwrap();
            server.shutdown().await.unwrap();
            let mut got = Vec::new();
            conn.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"hello");
        });
    }
}
