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
