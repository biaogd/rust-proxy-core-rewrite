use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as _, Md5};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput as _, Update as _, XofReader as _};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::header::{Security, response_body_material};

const MAX_WRITE_PLAINTEXT: usize = 15_000;
const MAX_READ_CIPHERTEXT: usize = 16_384;

enum RecordCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl RecordCipher {
    fn new(security: Security, key: &[u8; 16]) -> Self {
        match security {
            Security::Aes128Gcm => Self::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).expect("VMess AES key is 16 bytes"),
            )),
            Security::ChaCha20Poly1305 => {
                let first: [u8; 16] = Md5::digest(key).into();
                let second: [u8; 16] = Md5::digest(first).into();
                let mut expanded = [0_u8; 32];
                expanded[..16].copy_from_slice(&first);
                expanded[16..].copy_from_slice(&second);
                Self::ChaCha20Poly1305(Box::new(
                    ChaCha20Poly1305::new_from_slice(&expanded)
                        .expect("VMess ChaCha20 key is 32 bytes"),
                ))
            }
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|_| std::io::Error::other("VMess AES-GCM encryption failed")),
            Self::ChaCha20Poly1305(cipher) => cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), plaintext)
                .map_err(|_| std::io::Error::other("VMess ChaCha20 encryption failed")),
        }
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Aes128Gcm(cipher) => cipher
                .decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| std::io::Error::other("VMess AES-GCM authentication failed")),
            Self::ChaCha20Poly1305(cipher) => cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| std::io::Error::other("VMess ChaCha20 authentication failed")),
        }
    }
}

struct LengthMask(sha3::Shake128Reader);

impl LengthMask {
    fn new(iv: &[u8; 16]) -> Self {
        let mut shake = Shake128::default();
        shake.update(iv);
        Self(shake.finalize_xof())
    }

    fn next(&mut self) -> u16 {
        let mut output = [0_u8; 2];
        self.0.read(&mut output);
        u16::from_be_bytes(output)
    }
}

fn record_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce: [u8; 12] = iv[..12]
        .try_into()
        .expect("VMess record IV has at least 12 bytes");
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub(super) struct BodyWriter {
    cipher: RecordCipher,
    iv: [u8; 16],
    counter: u16,
    mask: LengthMask,
}

impl BodyWriter {
    pub(super) fn new(security: Security, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: RecordCipher::new(security, key),
            iv: *iv,
            counter: 0,
            mask: LengthMask::new(iv),
        }
    }

    pub(super) async fn write_record<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        let nonce = record_nonce(&self.iv, self.counter);
        self.counter = self.counter.wrapping_add(1);
        let ciphertext = self.cipher.seal(&nonce, plaintext)?;
        let length = u16::try_from(ciphertext.len())
            .map_err(|_| std::io::Error::other("VMess body record is too large"))?
            ^ self.mask.next();
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(&ciphertext).await?;
        writer.flush().await
    }

    pub(super) const fn maximum_plaintext() -> usize {
        MAX_WRITE_PLAINTEXT
    }
}

pub(super) struct BodyReader {
    cipher: RecordCipher,
    iv: [u8; 16],
    counter: u16,
    mask: LengthMask,
}

impl BodyReader {
    pub(super) fn new(security: Security, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: RecordCipher::new(security, key),
            iv: *iv,
            counter: 0,
            mask: LengthMask::new(iv),
        }
    }

    pub(super) async fn read_record<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<Vec<u8>> {
        let mut length = [0_u8; 2];
        reader.read_exact(&mut length).await?;
        let length = usize::from(u16::from_be_bytes(length) ^ self.mask.next());
        if !(16..=MAX_READ_CIPHERTEXT).contains(&length) {
            return Err(std::io::Error::other("invalid VMess body record length"));
        }
        let mut ciphertext = vec![0_u8; length];
        reader.read_exact(&mut ciphertext).await?;
        let nonce = record_nonce(&self.iv, self.counter);
        self.counter = self.counter.wrapping_add(1);
        self.cipher.open(&nonce, &ciphertext)
    }
}

pub(super) fn pair(
    security: Security,
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
) -> (BodyReader, BodyWriter, [u8; 16], [u8; 16]) {
    let (response_key, response_iv) = response_body_material(request_key, request_iv);
    (
        BodyReader::new(security, &response_key, &response_iv),
        BodyWriter::new(security, request_key, request_iv),
        response_key,
        response_iv,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_and_length_mask_match_protocol_shape() {
        let iv = [0xaa, 0xbb, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(
            record_nonce(&iv, 0x1234),
            [0x12, 0x34, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        );
        let mut first = LengthMask::new(&iv);
        let mut second = LengthMask::new(&iv);
        assert_eq!(first.next(), second.next());
        assert_eq!(first.next(), second.next());
    }

    #[tokio::test]
    async fn request_records_round_trip_with_independent_reader() {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            let mut writer = BodyWriter::new(security, &key, &iv);
            let mut wire = Vec::new();
            writer
                .write_record(&mut wire, b"phase6d VMess body")
                .await
                .unwrap();
            let mut reader = BodyReader::new(security, &key, &iv);
            assert_eq!(
                reader
                    .read_record(&mut std::io::Cursor::new(wire))
                    .await
                    .unwrap(),
                b"phase6d VMess body"
            );
        }
    }

    #[tokio::test]
    async fn response_direction_uses_sha256_material() {
        let request_key = [0x31; 16];
        let request_iv = [0x42; 16];
        let (response_key, response_iv) = response_body_material(&request_key, &request_iv);
        let mut server_writer = BodyWriter::new(Security::Aes128Gcm, &response_key, &response_iv);
        let mut wire = Vec::new();
        server_writer
            .write_record(&mut wire, b"response")
            .await
            .unwrap();
        let (mut client_reader, _, _, _) = pair(Security::Aes128Gcm, &request_key, &request_iv);
        assert_eq!(
            client_reader
                .read_record(&mut std::io::Cursor::new(wire))
                .await
                .unwrap(),
            b"response"
        );
    }
}
