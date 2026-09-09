//! `auth_chain_a` / `auth_chain_b` protocol plugins (SSR-C).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BytesMut};
use rc4::{Key, KeyInit, StreamCipher, consts::U16};
use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ShadowsocksRProtocolError;
use crate::crypto_util::{
    HashKind, XorShift128Plus, aes128_cbc_encrypt_block, append_rand, kdf, random_u32_bounded,
    unix_timestamp,
};

const AUTH_OVERHEAD: usize = 4;
const MAX_CHUNK: usize = 2800;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthChainKind {
    A,
    B,
}

impl AuthChainKind {
    fn salt(self) -> &'static str {
        match self {
            Self::A => "auth_chain_a",
            Self::B => "auth_chain_b",
        }
    }
}

struct UserData {
    user_key: Vec<u8>,
    user_id: [u8; 4],
}

struct AuthState {
    client_id: [u8; 4],
    connection_id: u32,
}

impl AuthState {
    fn next_connection() -> Self {
        let mut client_id = [0_u8; 4];
        rand::fill(&mut client_id);
        let connection_id = random_u32_bounded(0x0100_0000);
        Self {
            client_id,
            connection_id: connection_id.saturating_add(1).max(1),
        }
    }
}

fn parse_user(param: &str, stream_key: &[u8]) -> UserData {
    // protocol-param `uid:passwd` → user_id LE u32, user_key = raw password bytes (NOT hashed).
    if let Some((uid, passwd)) = param.split_once(':')
        && let Ok(user_id_num) = uid.parse::<u32>()
    {
        let mut user_id = [0_u8; 4];
        user_id.copy_from_slice(&user_id_num.to_le_bytes());
        return UserData {
            user_key: passwd.as_bytes().to_vec(),
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

fn b64(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
}

fn get_rand_start_pos(length: usize, random: &mut XorShift128Plus) -> usize {
    if length == 0 {
        return 0;
    }
    (random.next() % 8_589_934_609) as usize % length
}

fn udp_get_rand_length(last_hash: &[u8], random: &mut XorShift128Plus) -> usize {
    random.init_from_bin(last_hash);
    (random.next() % 127) as usize
}

fn new_rc4(key: &[u8]) -> rc4::Rc4<U16> {
    let mut key_arr = [0_u8; 16];
    key_arr.copy_from_slice(key);
    rc4::Rc4::<U16>::new(Key::<U16>::from_slice(&key_arr))
}

/// Shared `auth_chain_a` / `auth_chain_b` stream framing.
pub(crate) struct AuthChainConn {
    inner: BoxedStream,
    kind: AuthChainKind,
    stream_key: Vec<u8>,
    iv: Vec<u8>,
    user: UserData,
    auth: AuthState,
    overhead: usize,
    has_sent_header: bool,
    raw_trans: bool,
    last_client_hash: Vec<u8>,
    last_server_hash: Vec<u8>,
    encrypter: Option<rc4::Rc4<U16>>,
    decrypter: Option<rc4::Rc4<U16>>,
    random_client: XorShift128Plus,
    random_server: XorShift128Plus,
    data_size_list: Vec<usize>,
    data_size_list2: Vec<usize>,
    pack_id: u32,
    recv_id: u32,
    decoded: BytesMut,
    under_decoded: BytesMut,
    pending_write: Vec<u8>,
    pending_offset: usize,
}

impl AuthChainConn {
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn new(
        inner: BoxedStream,
        kind: AuthChainKind,
        stream_key: Vec<u8>,
        iv: Vec<u8>,
        protocol_param: &str,
        obfs_overhead: usize,
    ) -> Self {
        let user = parse_user(protocol_param, &stream_key);
        let overhead = obfs_overhead + AUTH_OVERHEAD;
        let mut conn = Self {
            inner,
            kind,
            stream_key: stream_key.clone(),
            iv,
            user,
            auth: AuthState::next_connection(),
            overhead,
            has_sent_header: false,
            raw_trans: false,
            last_client_hash: Vec::new(),
            last_server_hash: Vec::new(),
            encrypter: None,
            decrypter: None,
            random_client: XorShift128Plus::default(),
            random_server: XorShift128Plus::default(),
            data_size_list: Vec::new(),
            data_size_list2: Vec::new(),
            pack_id: 1,
            recv_id: 1,
            decoded: BytesMut::new(),
            under_decoded: BytesMut::new(),
            pending_write: Vec::new(),
            pending_offset: 0,
        };
        if kind == AuthChainKind::B {
            conn.init_data_size();
        }
        conn
    }

    fn init_data_size(&mut self) {
        self.data_size_list.clear();
        self.data_size_list2.clear();
        self.random_server.init_from_bin(&self.stream_key);
        let mut length = (self.random_server.next() % 8) + 4;
        while length > 0 {
            self.data_size_list
                .push((self.random_server.next() % 2340 % 2040 % 1440) as usize);
            length -= 1;
        }
        self.data_size_list.sort_unstable();

        let mut length = (self.random_server.next() % 16) + 8;
        while length > 0 {
            self.data_size_list2
                .push((self.random_server.next() % 2340 % 2040 % 1440) as usize);
            length -= 1;
        }
        self.data_size_list2.sort_unstable();
    }

    fn get_rand_length_a(length: usize, last_hash: &[u8], random: &mut XorShift128Plus) -> usize {
        if length > 1440 {
            return 0;
        }
        random.init_from_bin_and_length(last_hash, length);
        if length > 1300 {
            (random.next() % 31) as usize
        } else if length > 900 {
            (random.next() % 127) as usize
        } else if length > 400 {
            (random.next() % 521) as usize
        } else {
            (random.next() % 1021) as usize
        }
    }

    fn get_rand_length_b(&mut self, length: usize, last_hash: &[u8], client: bool) -> usize {
        if length >= 1440 {
            return 0;
        }
        let random = if client {
            &mut self.random_client
        } else {
            &mut self.random_server
        };
        random.init_from_bin_and_length(last_hash, length);

        let pos = self
            .data_size_list
            .partition_point(|&item| item < length + self.overhead);
        let list_len = self.data_size_list.len();
        let final_pos = pos + (random.next() % list_len as u64) as usize;
        if final_pos < list_len {
            return self.data_size_list[final_pos] - length - self.overhead;
        }

        let pos2 = self
            .data_size_list2
            .partition_point(|&item| item < length + self.overhead);
        let list2_count = self.data_size_list2.len();
        let final_pos2 = pos2 + (random.next() % list2_count as u64) as usize;
        if final_pos2 < list2_count {
            return self.data_size_list2[final_pos2] - length - self.overhead;
        }
        if final_pos2 < pos2 + list2_count - 1 {
            return 0;
        }
        if length > 1300 {
            (random.next() % 31) as usize
        } else if length > 900 {
            (random.next() % 127) as usize
        } else if length > 400 {
            (random.next() % 521) as usize
        } else {
            (random.next() % 1021) as usize
        }
    }

    fn rand_data_length(&mut self, length: usize, last_hash: &[u8], client: bool) -> usize {
        match self.kind {
            AuthChainKind::A => {
                let random = if client {
                    &mut self.random_client
                } else {
                    &mut self.random_server
                };
                Self::get_rand_length_a(length, last_hash, random)
            }
            AuthChainKind::B => self.get_rand_length_b(length, last_hash, client),
        }
    }

    fn init_rc4_cipher(&mut self) {
        let password = format!(
            "{}{}",
            b64(&self.user.user_key),
            b64(&self.last_client_hash)
        );
        let key = kdf(&password, 16);
        self.encrypter = Some(new_rc4(&key));
        self.decrypter = Some(new_rc4(&key));
    }

    fn put_encrypted_data(&self, out: &mut Vec<u8>, paddings: [usize; 2]) {
        let mut block = [0_u8; 16];
        block[..4].copy_from_slice(&unix_timestamp().to_le_bytes());
        block[4..8].copy_from_slice(&self.auth.client_id);
        block[8..12].copy_from_slice(&self.auth.connection_id.to_le_bytes());
        block[12..14].copy_from_slice(&(paddings[0] as u16).to_le_bytes());
        block[14..16].copy_from_slice(&(paddings[1] as u16).to_le_bytes());

        let cipher_key_vec = kdf(
            &format!("{}{}", b64(&self.user.user_key), self.kind.salt()),
            16,
        );
        let mut cipher_key = [0_u8; 16];
        cipher_key.copy_from_slice(&cipher_key_vec);
        aes128_cbc_encrypt_block(&cipher_key, &mut block);
        out.extend_from_slice(&block);
    }

    fn put_mixed_rand_data_and_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let last_hash = self.last_client_hash.clone();
        let rand_data_length = self.rand_data_length(data.len(), &last_hash, true);
        if data.is_empty() {
            append_rand(out, rand_data_length);
            return;
        }
        if rand_data_length > 0 {
            let start_pos = get_rand_start_pos(rand_data_length, &mut self.random_client);
            append_rand(out, start_pos);
            out.extend_from_slice(data);
            append_rand(out, rand_data_length - start_pos);
            return;
        }
        out.extend_from_slice(data);
    }

    fn pack_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let mut encrypted = data.to_vec();
        if let Some(enc) = self.encrypter.as_mut() {
            enc.apply_keystream(&mut encrypted);
        }

        let mut mac_key = self.user.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id = self.pack_id.wrapping_add(1);

        let length = (encrypted.len() as u16)
            ^ u16::from_le_bytes([self.last_client_hash[14], self.last_client_hash[15]]);

        let original_length = out.len();
        out.extend_from_slice(&length.to_le_bytes());
        self.put_mixed_rand_data_and_data(out, &encrypted);
        self.last_client_hash = HashKind::Md5.hmac(&mac_key, &out[original_length..]);
        out.extend_from_slice(&self.last_client_hash[..2]);
    }

    fn pack_auth_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let mut mac_key = Vec::with_capacity(self.iv.len() + self.stream_key.len());
        mac_key.extend_from_slice(&self.iv);
        mac_key.extend_from_slice(&self.stream_key);

        // check head
        let start = out.len();
        append_rand(out, 4);
        self.last_client_hash = HashKind::Md5.hmac(&mac_key, &out[start..]);
        self.init_rc4_cipher();
        out.extend_from_slice(&self.last_client_hash[..8]);

        // uid ^ hash[8:12]
        let uid = u32::from_le_bytes(self.user.user_id)
            ^ u32::from_le_bytes(self.last_client_hash[8..12].try_into().expect("4 bytes"));
        out.extend_from_slice(&uid.to_le_bytes());

        // encrypted auth data
        self.put_encrypted_data(out, [self.overhead, 0]);

        // last server hash
        self.last_server_hash = HashKind::Md5.hmac(&self.user.user_key, &out[start + 12..]);
        out.extend_from_slice(&self.last_server_hash[..4]);

        self.pack_data(out, data);
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
            self.pack_data(&mut out, &rest[..MAX_CHUNK]);
            rest = &rest[MAX_CHUNK..];
        }
        if !rest.is_empty() {
            self.pack_data(&mut out, rest);
        }
        out
    }

    fn decode_available(&mut self) -> Result<(), ShadowsocksRProtocolError> {
        if self.raw_trans {
            self.decoded.extend_from_slice(&self.under_decoded);
            self.under_decoded.clear();
            return Ok(());
        }
        if self.last_server_hash.len() < 16 {
            return Ok(());
        }
        while self.under_decoded.len() > 4 {
            let mut mac_key = self.user.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());

            let data_length = (u16::from_le_bytes([self.under_decoded[0], self.under_decoded[1]])
                ^ u16::from_le_bytes([self.last_server_hash[14], self.last_server_hash[15]]))
                as usize;
            let last_hash = self.last_server_hash.clone();
            let rand_data_length = self.rand_data_length(data_length, &last_hash, false);
            let length = data_length.saturating_add(rand_data_length);

            if length >= 4096 {
                self.raw_trans = true;
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_chain invalid length".into(),
                ));
            }
            if 4 + length > self.under_decoded.len() {
                break;
            }

            let server_hash = HashKind::Md5.hmac(&mac_key, &self.under_decoded[..length + 2]);
            if server_hash[..2] != self.under_decoded[length + 2..length + 4] {
                self.raw_trans = true;
                self.under_decoded.clear();
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_chain checksum mismatch".into(),
                ));
            }
            self.last_server_hash = server_hash;

            let mut pos = 2;
            if data_length > 0 && rand_data_length > 0 {
                pos += get_rand_start_pos(rand_data_length, &mut self.random_server);
            }

            let end = pos + data_length;
            if end > length + 2 {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "auth_chain payload overrun".into(),
                ));
            }
            let mut wanted = self.under_decoded[pos..end].to_vec();
            if let Some(dec) = self.decrypter.as_mut() {
                dec.apply_keystream(&mut wanted);
            }
            if self.recv_id == 1 {
                if wanted.len() >= 2 {
                    self.decoded.extend_from_slice(&wanted[2..]);
                }
            } else {
                self.decoded.extend_from_slice(&wanted);
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            self.under_decoded.advance(length + 4);
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
                        "auth_chain write returned 0",
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

impl AsyncRead for AuthChainConn {
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

impl AsyncWrite for AuthChainConn {
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

/// UDP helpers for `auth_chain_*` (`EncodePacket` / `DecodePacket`).
pub(crate) struct AuthChainUdp {
    stream_key: Vec<u8>,
    user: UserData,
    random_client: XorShift128Plus,
    random_server: XorShift128Plus,
}

impl AuthChainUdp {
    pub(crate) fn new(stream_key: Vec<u8>, protocol_param: &str) -> Self {
        Self {
            user: parse_user(protocol_param, &stream_key),
            stream_key,
            random_client: XorShift128Plus::default(),
            random_server: XorShift128Plus::default(),
        }
    }

    pub(crate) fn encode_packet(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut auth_data = [0_u8; 3];
        rand::fill(&mut auth_data);
        let md5_data = HashKind::Md5.hmac(&self.stream_key, &auth_data);
        let rand_data_length = udp_get_rand_length(&md5_data, &mut self.random_client);

        let password = format!("{}{}", b64(&self.user.user_key), b64(&md5_data));
        let key = kdf(&password, 16);
        let mut cipher = new_rc4(&key);
        let mut encrypted = plaintext.to_vec();
        cipher.apply_keystream(&mut encrypted);

        let mut out = Vec::with_capacity(encrypted.len() + rand_data_length + 8);
        out.extend_from_slice(&encrypted);
        append_rand(&mut out, rand_data_length);
        out.extend_from_slice(&auth_data);
        let uid = u32::from_le_bytes(self.user.user_id)
            ^ u32::from_le_bytes(md5_data[..4].try_into().expect("4 bytes"));
        out.extend_from_slice(&uid.to_le_bytes());
        let mac = HashKind::Md5.hmac(&self.user.user_key, &out);
        out.push(mac[0]);
        out
    }

    pub(crate) fn decode_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<Vec<u8>, ShadowsocksRProtocolError> {
        if packet.len() < 9 {
            return Err(ShadowsocksRProtocolError::Protocol(
                "auth_chain udp packet too short".into(),
            ));
        }
        let mac = HashKind::Md5.hmac(&self.user.user_key, &packet[..packet.len() - 1]);
        if mac[..1] != packet[packet.len() - 1..] {
            return Err(ShadowsocksRProtocolError::Protocol(
                "auth_chain udp checksum mismatch".into(),
            ));
        }
        let md5_data = HashKind::Md5.hmac(
            &self.stream_key,
            &packet[packet.len() - 8..packet.len() - 1],
        );
        let rand_data_length = udp_get_rand_length(&md5_data, &mut self.random_server);
        if packet.len() < 8 + rand_data_length {
            return Err(ShadowsocksRProtocolError::Protocol(
                "auth_chain udp rand overrun".into(),
            ));
        }
        let password = format!("{}{}", b64(&self.user.user_key), b64(&md5_data));
        let key = kdf(&password, 16);
        let mut cipher = new_rc4(&key);
        let mut wanted = packet[..packet.len() - 8 - rand_data_length].to_vec();
        cipher.apply_keystream(&mut wanted);
        Ok(wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_param_uses_raw_password_bytes() {
        let stream_key = vec![9_u8; 16];
        let user = parse_user("1001:phase7c", &stream_key);
        assert_eq!(user.user_id, 1001_u32.to_le_bytes());
        assert_eq!(user.user_key, b"phase7c");
        let fallback = parse_user("", &stream_key);
        assert_eq!(fallback.user_key, stream_key);
    }

    #[test]
    fn xorshift_init_from_bin_and_length_uses_copy() {
        let bin = [1_u8; 16];
        let original = bin;
        let mut rng = XorShift128Plus::default();
        rng.init_from_bin_and_length(&bin, 42);
        assert_eq!(bin, original);
        let _ = rng.next();
    }

    #[test]
    fn udp_encode_packet_has_valid_trailer_mac() {
        let key = vec![0x11_u8; 16];
        let mut udp = AuthChainUdp::new(key, "7:secret");
        let encoded = udp.encode_packet(b"ping");
        assert!(encoded.len() >= 9);
        // Encode (client→server) and Decode (server→client) are directional; only
        // check the trailing HMAC-MD5 byte that both directions share.
        let mac = HashKind::Md5.hmac(b"secret", &encoded[..encoded.len() - 1]);
        assert_eq!(mac[0], encoded[encoded.len() - 1]);
        assert!(udp.decode_packet(&encoded[..8]).is_err());
    }
}
