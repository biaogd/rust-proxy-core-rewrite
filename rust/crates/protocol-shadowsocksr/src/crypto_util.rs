//! Shared SSR crypto helpers (`HMAC` / digests / AES block / `EVP_BytesToKey`).

#![allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as _};
use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use sha1::Sha1;
use shadowsocks_crypto::v1::openssl_bytes_to_key;

type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HashKind {
    Md5,
    Sha1,
}

impl HashKind {
    pub(crate) fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => {
                let mut mac =
                    <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha1 => {
                let mut mac = <HmacSha1 as Mac>::new_from_slice(key)
                    .expect("HMAC-SHA1 accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => Md5::digest(data).to_vec(),
            Self::Sha1 => Sha1::digest(data).to_vec(),
        }
    }
}

pub(crate) fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    HashKind::Sha1.hmac(key, data)
}

pub(crate) fn kdf(password: &str, key_len: usize) -> Vec<u8> {
    let mut key = vec![0_u8; key_len];
    openssl_bytes_to_key(password.as_bytes(), &mut key);
    key
}

/// AES-128-CBC with a zero IV over a single 16-byte block (== AES-ECB for one block).
pub(crate) fn aes128_cbc_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = Aes128::new_from_slice(key).expect("AES-128 key length");
    // Zero IV ⇒ first CBC block is plain AES encrypt.
    cipher.encrypt_block(aes::Block::from_mut_slice(block));
}

pub(crate) fn unix_timestamp() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

pub(crate) fn append_rand(buf: &mut Vec<u8>, len: usize) {
    let start = buf.len();
    buf.resize(start + len, 0);
    rand::fill(&mut buf[start..]);
}

pub(crate) fn random_u32_bounded(max_exclusive: u32) -> u32 {
    if max_exclusive == 0 {
        return 0;
    }
    rand::random_range(0..max_exclusive)
}

pub(crate) fn trapezoid_random(max: i32, d: f64) -> i32 {
    if max <= 0 {
        return 0;
    }
    let mut base: f64 = rand::random();
    if (d - 0.0).abs() > 1e-6 {
        let a = 1.0 - d;
        base = ((a * a + 4.0 * d * base).sqrt() - a) / (2.0 * d);
    }
    (base * f64::from(max)) as i32
}

/// IEEE CRC-32 (`hash/crc32` ChecksumIEEE).
pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Adler-32 checksum (`hash/adler32`).
pub(crate) fn adler32_checksum(data: &[u8]) -> u32 {
    adler2::adler32_slice(data)
}

/// XorShift128+ PRNG matching Go `tools.XorShift128Plus`.
#[derive(Clone, Debug, Default)]
pub(crate) struct XorShift128Plus {
    s: [u64; 2],
}

impl XorShift128Plus {
    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.s[0];
        let y = self.s[1];
        self.s[0] = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.s[1] = x;
        x.wrapping_add(y)
    }

    pub(crate) fn init_from_bin(&mut self, bin: &[u8]) {
        let mut full = [0_u8; 16];
        let n = bin.len().min(16);
        full[..n].copy_from_slice(&bin[..n]);
        self.s[0] = u64::from_le_bytes(full[0..8].try_into().expect("8 bytes"));
        self.s[1] = u64::from_le_bytes(full[8..16].try_into().expect("8 bytes"));
    }

    /// Init from a **copy** of `bin` with `length` written as u16 LE at offset 0, then 4× `Next`.
    ///
    /// HMAC-MD5 inputs are always 16 bytes; shorter bins are zero-padded like Go.
    pub(crate) fn init_from_bin_and_length(&mut self, bin: &[u8], length: usize) {
        let mut full = [0_u8; 16];
        let n = bin.len().min(16);
        full[..n].copy_from_slice(&bin[..n]);
        let len_u16 = u16::try_from(length).unwrap_or(u16::MAX);
        full[0..2].copy_from_slice(&len_u16.to_le_bytes());
        self.s[0] = u64::from_le_bytes(full[0..8].try_into().expect("8 bytes"));
        self.s[1] = u64::from_le_bytes(full[8..16].try_into().expect("8 bytes"));
        for _ in 0..4 {
            let _ = self.next();
        }
    }
}
