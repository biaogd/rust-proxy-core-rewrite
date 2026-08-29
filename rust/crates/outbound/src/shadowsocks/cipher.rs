use std::io;

use ::cipher::{KeyInit, KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use cfb_mode::{BufDecryptor, BufEncryptor};
use ctr::Ctr128BE;
use md5::{Digest, Md5};
use thiserror::Error;

use super::kdf::kdf;

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("unsupported cipher: {0}")]
    Unsupported(String),
    #[error("cipher initialization failed: {0}")]
    Initialization(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamCipherKind {
    Dummy,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Rc4Md5,
    ChaCha20,
    ChaCha20Ietf,
    XChaCha20,
}

pub(crate) struct StreamCipherSpec {
    pub key: Vec<u8>,
    pub iv_size: usize,
    pub kind: StreamCipherKind,
}

pub(crate) enum StreamCipherEngine {
    Dummy,
    Aes128CfbEnc(BufEncryptor<Aes128>),
    Aes128CfbDec(BufDecryptor<Aes128>),
    Aes192CfbEnc(BufEncryptor<Aes192>),
    Aes192CfbDec(BufDecryptor<Aes192>),
    Aes256CfbEnc(BufEncryptor<Aes256>),
    Aes256CfbDec(BufDecryptor<Aes256>),
    Aes128CtrEnc(Ctr128BE<Aes128>),
    Aes128CtrDec(Ctr128BE<Aes128>),
    Aes192CtrEnc(Ctr128BE<Aes192>),
    Aes192CtrDec(Ctr128BE<Aes192>),
    Aes256CtrEnc(Ctr128BE<Aes256>),
    Aes256CtrDec(Ctr128BE<Aes256>),
    Rc4Md5(rc4::Rc4<typenum::U16>),
    ChaCha20(chacha20::ChaCha20Legacy),
    ChaCha20Ietf(chacha20::ChaCha20),
    XChaCha20(chacha20::XChaCha20),
}

impl StreamCipherEngine {
    pub(crate) fn encrypt(&mut self, data: &mut [u8]) {
        match self {
            Self::Dummy => {}
            Self::Aes128CfbEnc(c) => c.encrypt(data),
            Self::Aes192CfbEnc(c) => c.encrypt(data),
            Self::Aes256CfbEnc(c) => c.encrypt(data),
            Self::Aes128CtrEnc(c) => c.apply_keystream(data),
            Self::Aes192CtrEnc(c) => c.apply_keystream(data),
            Self::Aes256CtrEnc(c) => c.apply_keystream(data),
            Self::Rc4Md5(c) => c.apply_keystream(data),
            Self::ChaCha20(c) => c.apply_keystream(data),
            Self::ChaCha20Ietf(c) => c.apply_keystream(data),
            Self::XChaCha20(c) => c.apply_keystream(data),
            Self::Aes128CfbDec(_)
            | Self::Aes192CfbDec(_)
            | Self::Aes256CfbDec(_)
            | Self::Aes128CtrDec(_)
            | Self::Aes192CtrDec(_)
            | Self::Aes256CtrDec(_) => {
                unreachable!("encrypt called on decrypt engine");
            }
        }
    }

    pub(crate) fn decrypt(&mut self, data: &mut [u8]) {
        match self {
            Self::Dummy => {}
            Self::Aes128CfbDec(c) => c.decrypt(data),
            Self::Aes192CfbDec(c) => c.decrypt(data),
            Self::Aes256CfbDec(c) => c.decrypt(data),
            Self::Aes128CtrDec(c) => c.apply_keystream(data),
            Self::Aes192CtrDec(c) => c.apply_keystream(data),
            Self::Aes256CtrDec(c) => c.apply_keystream(data),
            Self::Rc4Md5(c) => c.apply_keystream(data),
            Self::ChaCha20(c) => c.apply_keystream(data),
            Self::ChaCha20Ietf(c) => c.apply_keystream(data),
            Self::XChaCha20(c) => c.apply_keystream(data),
            Self::Aes128CfbEnc(_)
            | Self::Aes192CfbEnc(_)
            | Self::Aes256CfbEnc(_)
            | Self::Aes128CtrEnc(_)
            | Self::Aes192CtrEnc(_)
            | Self::Aes256CtrEnc(_) => {
                unreachable!("decrypt called on encrypt engine");
            }
        }
    }
}

pub(crate) fn pick_stream_cipher(
    name: &str,
    password: &str,
) -> Result<StreamCipherSpec, CipherError> {
    let kind = parse_stream_kind(name)?;
    let key_size = stream_key_size(kind);
    Ok(StreamCipherSpec {
        key: kdf(password, key_size),
        iv_size: stream_iv_size(kind),
        kind,
    })
}

pub(crate) fn new_encrypt_engine(
    spec: &StreamCipherSpec,
    iv: &[u8],
) -> Result<StreamCipherEngine, CipherError> {
    new_engine(spec, iv, true)
}

pub(crate) fn new_decrypt_engine(
    spec: &StreamCipherSpec,
    iv: &[u8],
) -> Result<StreamCipherEngine, CipherError> {
    new_engine(spec, iv, false)
}

fn new_engine(
    spec: &StreamCipherSpec,
    iv: &[u8],
    encrypt: bool,
) -> Result<StreamCipherEngine, CipherError> {
    if spec.kind == StreamCipherKind::Dummy {
        return Ok(StreamCipherEngine::Dummy);
    }
    if iv.len() != spec.iv_size {
        return Err(CipherError::Initialization(format!(
            "expected iv length {}, got {}",
            spec.iv_size,
            iv.len()
        )));
    }
    let key = &spec.key;
    let engine = match (spec.kind, encrypt) {
        (StreamCipherKind::Aes128Cfb, true) => StreamCipherEngine::Aes128CfbEnc(
            BufEncryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes128Cfb, false) => StreamCipherEngine::Aes128CfbDec(
            BufDecryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes192Cfb, true) => StreamCipherEngine::Aes192CfbEnc(
            BufEncryptor::<Aes192>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes192Cfb, false) => StreamCipherEngine::Aes192CfbDec(
            BufDecryptor::<Aes192>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes256Cfb, true) => StreamCipherEngine::Aes256CfbEnc(
            BufEncryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes256Cfb, false) => StreamCipherEngine::Aes256CfbDec(
            BufDecryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes128Ctr, true) => StreamCipherEngine::Aes128CtrEnc(
            Ctr128BE::<Aes128>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes128Ctr, false) => StreamCipherEngine::Aes128CtrDec(
            Ctr128BE::<Aes128>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes192Ctr, true) => StreamCipherEngine::Aes192CtrEnc(
            Ctr128BE::<Aes192>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes192Ctr, false) => StreamCipherEngine::Aes192CtrDec(
            Ctr128BE::<Aes192>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes256Ctr, true) => StreamCipherEngine::Aes256CtrEnc(
            Ctr128BE::<Aes256>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Aes256Ctr, false) => StreamCipherEngine::Aes256CtrDec(
            Ctr128BE::<Aes256>::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Rc4Md5, _) => {
            StreamCipherEngine::Rc4Md5(rc4::Rc4::new(&rc4_md5_key(key, iv).into()))
        }
        (StreamCipherKind::ChaCha20, _) => StreamCipherEngine::ChaCha20(
            chacha20::ChaCha20Legacy::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::ChaCha20Ietf, _) => StreamCipherEngine::ChaCha20Ietf(
            chacha20::ChaCha20::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::XChaCha20, _) => StreamCipherEngine::XChaCha20(
            chacha20::XChaCha20::new_from_slices(key, iv)
                .map_err(|error| CipherError::Initialization(error.to_string()))?,
        ),
        (StreamCipherKind::Dummy, _) => StreamCipherEngine::Dummy,
    };
    Ok(engine)
}

pub(crate) fn stream_iv_size(kind: StreamCipherKind) -> usize {
    match kind {
        StreamCipherKind::Dummy => 0,
        StreamCipherKind::Rc4Md5
        | StreamCipherKind::Aes128Cfb
        | StreamCipherKind::Aes192Cfb
        | StreamCipherKind::Aes256Cfb
        | StreamCipherKind::Aes128Ctr
        | StreamCipherKind::Aes192Ctr
        | StreamCipherKind::Aes256Ctr => 16,
        StreamCipherKind::ChaCha20 => 8,
        StreamCipherKind::ChaCha20Ietf => 12,
        StreamCipherKind::XChaCha20 => 24,
    }
}

fn stream_key_size(kind: StreamCipherKind) -> usize {
    match kind {
        StreamCipherKind::Dummy
        | StreamCipherKind::Rc4Md5
        | StreamCipherKind::Aes128Cfb
        | StreamCipherKind::Aes128Ctr => 16,
        StreamCipherKind::Aes192Cfb | StreamCipherKind::Aes192Ctr => 24,
        StreamCipherKind::Aes256Cfb
        | StreamCipherKind::Aes256Ctr
        | StreamCipherKind::ChaCha20
        | StreamCipherKind::ChaCha20Ietf
        | StreamCipherKind::XChaCha20 => 32,
    }
}

fn parse_stream_kind(name: &str) -> Result<StreamCipherKind, CipherError> {
    match name.to_ascii_lowercase().as_str() {
        "dummy" | "none" => Ok(StreamCipherKind::Dummy),
        "aes-128-cfb" => Ok(StreamCipherKind::Aes128Cfb),
        "aes-192-cfb" => Ok(StreamCipherKind::Aes192Cfb),
        "aes-256-cfb" => Ok(StreamCipherKind::Aes256Cfb),
        "aes-128-ctr" => Ok(StreamCipherKind::Aes128Ctr),
        "aes-192-ctr" => Ok(StreamCipherKind::Aes192Ctr),
        "aes-256-ctr" => Ok(StreamCipherKind::Aes256Ctr),
        "rc4-md5" => Ok(StreamCipherKind::Rc4Md5),
        "chacha20" => Ok(StreamCipherKind::ChaCha20),
        "chacha20-ietf" => Ok(StreamCipherKind::ChaCha20Ietf),
        "xchacha20" => Ok(StreamCipherKind::XChaCha20),
        other => Err(CipherError::Unsupported(other.to_owned())),
    }
}

fn rc4_md5_key(derived_key: &[u8], iv: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(derived_key);
    hasher.update(iv);
    hasher.finalize().into()
}

impl From<CipherError> for io::Error {
    fn from(error: CipherError) -> Self {
        Self::other(error.to_string())
    }
}
