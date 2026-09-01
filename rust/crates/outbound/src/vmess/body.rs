use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes128Gcm, Nonce};
use cfb_mode::cipher::KeyIvInit as _;
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as _, Md5};
use rand::RngExt as _;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput as _, Update as _, XofReader as _};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::header::response_body_material;
use super::kdf::derive_16;
use super::{VmessSecurity, fnv1a32};

const MAX_WRITE_PLAINTEXT: usize = 15_000;
const MAX_READ_CIPHERTEXT: usize = 16_384;
const AEAD_OVERHEAD: usize = 16;

#[derive(Clone, Copy)]
struct DirectionKeys {
    body_key: [u8; 16],
    body_iv: [u8; 16],
    authenticated_length_key: [u8; 16],
    authenticated_length_iv: [u8; 16],
}

impl DirectionKeys {
    const fn request(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            body_key: *key,
            body_iv: *iv,
            authenticated_length_key: *key,
            authenticated_length_iv: *iv,
        }
    }

    const fn response(
        request_key: &[u8; 16],
        request_iv: &[u8; 16],
        response_key: &[u8; 16],
        response_iv: &[u8; 16],
    ) -> Self {
        Self {
            body_key: *response_key,
            body_iv: *response_iv,
            authenticated_length_key: *request_key,
            authenticated_length_iv: *request_iv,
        }
    }
}

enum RecordCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl RecordCipher {
    fn new(security: VmessSecurity, key: &[u8; 16]) -> Self {
        match security {
            VmessSecurity::Aes128Gcm => Self::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).expect("VMess AES key is 16 bytes"),
            )),
            VmessSecurity::ChaCha20Poly1305 => {
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
            VmessSecurity::Auto | VmessSecurity::None | VmessSecurity::Aes128Cfb => unreachable!(),
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

struct Framing {
    shake: sha3::Shake128Reader,
    global_padding: bool,
    authenticated_length: Option<RecordCipher>,
    authenticated_length_iv: [u8; 16],
}

impl Framing {
    fn new(
        security: VmessSecurity,
        authenticated_length_key: &[u8; 16],
        authenticated_length_iv: &[u8; 16],
        padding_iv: &[u8; 16],
        global_padding: bool,
        authenticated_length: bool,
    ) -> Self {
        let mut shake = Shake128::default();
        shake.update(padding_iv);
        Self {
            shake: shake.finalize_xof(),
            global_padding,
            authenticated_length: authenticated_length.then(|| {
                RecordCipher::new(
                    security,
                    &derive_16(authenticated_length_key, &[b"auth_len"]),
                )
            }),
            authenticated_length_iv: *authenticated_length_iv,
        }
    }

    fn next_u16(&mut self) -> u16 {
        let mut output = [0_u8; 2];
        self.shake.read(&mut output);
        u16::from_be_bytes(output)
    }

    fn padding_length(&mut self) -> usize {
        if self.global_padding {
            usize::from(self.next_u16() % 64)
        } else {
            0
        }
    }

    fn mask_length(&mut self, length: u16) -> u16 {
        length ^ self.next_u16()
    }

    fn authenticated_length_nonce(&self, counter: u16) -> [u8; 12] {
        record_nonce(&self.authenticated_length_iv, counter)
    }
}

fn record_nonce(iv: &[u8; 16], counter: u16) -> [u8; 12] {
    let mut nonce: [u8; 12] = iv[..12]
        .try_into()
        .expect("VMess record IV has at least 12 bytes");
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce
}

struct AeadWriter {
    cipher: RecordCipher,
    iv: [u8; 16],
    counter: u16,
    framing: Framing,
}

enum WriterMode {
    None,
    Aes128Cfb(Box<cfb_mode::BufEncryptor<aes::Aes128>>),
    Aead(Box<AeadWriter>),
}

pub(super) struct BodyWriter {
    mode: WriterMode,
}

impl BodyWriter {
    fn new(
        security: VmessSecurity,
        keys: DirectionKeys,
        global_padding: bool,
        authenticated_length: bool,
    ) -> Self {
        let mode = match security {
            VmessSecurity::None => WriterMode::None,
            VmessSecurity::Aes128Cfb => {
                WriterMode::Aes128Cfb(Box::new(cfb_mode::BufEncryptor::<aes::Aes128>::new(
                    &keys.body_key.into(),
                    &keys.body_iv.into(),
                )))
            }
            VmessSecurity::Aes128Gcm | VmessSecurity::ChaCha20Poly1305 => {
                WriterMode::Aead(Box::new(AeadWriter {
                    cipher: RecordCipher::new(security, &keys.body_key),
                    iv: keys.body_iv,
                    counter: 0,
                    framing: Framing::new(
                        security,
                        &keys.authenticated_length_key,
                        &keys.authenticated_length_iv,
                        &keys.body_iv,
                        global_padding,
                        authenticated_length,
                    ),
                }))
            }
            VmessSecurity::Auto => unreachable!(),
        };
        Self { mode }
    }

    pub(super) async fn write_record<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        match &mut self.mode {
            WriterMode::None => writer.write_all(plaintext).await?,
            WriterMode::Aes128Cfb(cipher) => {
                let framed_length = plaintext
                    .len()
                    .checked_add(4)
                    .and_then(|length| u16::try_from(length).ok())
                    .ok_or_else(|| std::io::Error::other("VMess body record is too large"))?;
                let mut wire = Vec::with_capacity(2 + usize::from(framed_length));
                wire.extend_from_slice(&framed_length.to_be_bytes());
                wire.extend_from_slice(&fnv1a32(plaintext).to_be_bytes());
                wire.extend_from_slice(plaintext);
                cipher.encrypt(&mut wire);
                writer.write_all(&wire).await?;
            }
            WriterMode::Aead(aead) => {
                let nonce = record_nonce(&aead.iv, aead.counter);
                let ciphertext = aead.cipher.seal(&nonce, plaintext)?;
                let padding_length = aead.framing.padding_length();
                let framed_length = ciphertext
                    .len()
                    .checked_add(padding_length)
                    .ok_or_else(|| std::io::Error::other("VMess body record is too large"))?;

                if let Some(length_cipher) = &aead.framing.authenticated_length {
                    let plaintext_length = framed_length
                        .checked_sub(AEAD_OVERHEAD)
                        .and_then(|length| u16::try_from(length).ok())
                        .ok_or_else(|| std::io::Error::other("VMess body record is too large"))?;
                    writer
                        .write_all(&length_cipher.seal(
                            &aead.framing.authenticated_length_nonce(aead.counter),
                            &plaintext_length.to_be_bytes(),
                        )?)
                        .await?;
                } else {
                    let length = u16::try_from(framed_length)
                        .map_err(|_| std::io::Error::other("VMess body record is too large"))?;
                    let masked = aead.framing.mask_length(length);
                    writer.write_all(&masked.to_be_bytes()).await?;
                }
                writer.write_all(&ciphertext).await?;
                if padding_length != 0 {
                    let mut padding = vec![0_u8; padding_length];
                    rand::rng().fill(padding.as_mut_slice());
                    writer.write_all(&padding).await?;
                }
                aead.counter = aead.counter.wrapping_add(1);
            }
        }
        writer.flush().await
    }

    pub(super) const fn maximum_plaintext() -> usize {
        MAX_WRITE_PLAINTEXT
    }
}

struct AeadReader {
    cipher: RecordCipher,
    iv: [u8; 16],
    counter: u16,
    framing: Framing,
}

enum ReaderMode {
    None,
    Aes128Cfb(Box<cfb_mode::BufDecryptor<aes::Aes128>>),
    Aead(Box<AeadReader>),
}

pub(super) struct BodyReader {
    mode: ReaderMode,
}

impl BodyReader {
    fn new(
        security: VmessSecurity,
        keys: DirectionKeys,
        global_padding: bool,
        authenticated_length: bool,
    ) -> Self {
        let mode = match security {
            VmessSecurity::None => ReaderMode::None,
            VmessSecurity::Aes128Cfb => {
                ReaderMode::Aes128Cfb(Box::new(cfb_mode::BufDecryptor::<aes::Aes128>::new(
                    &keys.body_key.into(),
                    &keys.body_iv.into(),
                )))
            }
            VmessSecurity::Aes128Gcm | VmessSecurity::ChaCha20Poly1305 => {
                ReaderMode::Aead(Box::new(AeadReader {
                    cipher: RecordCipher::new(security, &keys.body_key),
                    iv: keys.body_iv,
                    counter: 0,
                    framing: Framing::new(
                        security,
                        &keys.authenticated_length_key,
                        &keys.authenticated_length_iv,
                        &keys.body_iv,
                        global_padding,
                        authenticated_length,
                    ),
                }))
            }
            VmessSecurity::Auto => unreachable!(),
        };
        Self { mode }
    }

    pub(super) async fn read_record<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> std::io::Result<Vec<u8>> {
        match &mut self.mode {
            ReaderMode::None => {
                let mut plaintext = vec![0_u8; MAX_READ_CIPHERTEXT];
                let length = reader.read(&mut plaintext).await?;
                if length == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "VMess raw body ended",
                    ));
                }
                plaintext.truncate(length);
                Ok(plaintext)
            }
            ReaderMode::Aes128Cfb(cipher) => {
                let mut encrypted_length = [0_u8; 2];
                reader.read_exact(&mut encrypted_length).await?;
                cipher.decrypt(&mut encrypted_length);
                let framed_length = usize::from(u16::from_be_bytes(encrypted_length));
                if !(4..=MAX_READ_CIPHERTEXT).contains(&framed_length) {
                    return Err(std::io::Error::other(
                        "invalid VMess CFB body record length",
                    ));
                }
                let mut framed = vec![0_u8; framed_length];
                reader.read_exact(&mut framed).await?;
                cipher.decrypt(&mut framed);
                let expected = u32::from_be_bytes(
                    framed[..4]
                        .try_into()
                        .expect("VMess CFB record checksum is four bytes"),
                );
                let plaintext = framed.split_off(4);
                if fnv1a32(&plaintext) != expected {
                    return Err(std::io::Error::other("VMess CFB body checksum failed"));
                }
                Ok(plaintext)
            }
            ReaderMode::Aead(aead) => {
                let nonce = record_nonce(&aead.iv, aead.counter);
                let padding_length = aead.framing.padding_length();
                let framed_length = if let Some(length_cipher) = &aead.framing.authenticated_length
                {
                    let mut sealed_length = [0_u8; 2 + AEAD_OVERHEAD];
                    reader.read_exact(&mut sealed_length).await?;
                    let length = length_cipher.open(
                        &aead.framing.authenticated_length_nonce(aead.counter),
                        &sealed_length,
                    )?;
                    let [high, low] = length.as_slice() else {
                        return Err(std::io::Error::other("invalid VMess authenticated length"));
                    };
                    usize::from(u16::from_be_bytes([*high, *low])) + AEAD_OVERHEAD
                } else {
                    let mut length = [0_u8; 2];
                    reader.read_exact(&mut length).await?;
                    usize::from(aead.framing.mask_length(u16::from_be_bytes(length)))
                };
                let ciphertext_length = framed_length
                    .checked_sub(padding_length)
                    .ok_or_else(|| std::io::Error::other("invalid VMess body padding length"))?;
                if !(AEAD_OVERHEAD..=MAX_READ_CIPHERTEXT).contains(&ciphertext_length) {
                    return Err(std::io::Error::other("invalid VMess body record length"));
                }
                let mut ciphertext = vec![0_u8; ciphertext_length];
                reader.read_exact(&mut ciphertext).await?;
                if padding_length != 0 {
                    let mut padding = vec![0_u8; padding_length];
                    reader.read_exact(&mut padding).await?;
                }
                aead.counter = aead.counter.wrapping_add(1);
                aead.cipher.open(&nonce, &ciphertext)
            }
        }
    }
}

pub(super) fn pair(
    security: VmessSecurity,
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
    global_padding: bool,
    authenticated_length: bool,
) -> (BodyReader, BodyWriter, [u8; 16], [u8; 16]) {
    let (response_key, response_iv) = response_body_material(request_key, request_iv);
    (
        BodyReader::new(
            security,
            DirectionKeys::response(request_key, request_iv, &response_key, &response_iv),
            global_padding,
            authenticated_length,
        ),
        BodyWriter::new(
            security,
            DirectionKeys::request(request_key, request_iv),
            global_padding,
            authenticated_length,
        ),
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
        let key = [0x11; 16];
        let mut first = Framing::new(VmessSecurity::Aes128Gcm, &key, &iv, &iv, false, false);
        let mut second = Framing::new(VmessSecurity::Aes128Gcm, &key, &iv, &iv, false, false);
        assert_eq!(first.next_u16(), second.next_u16());
        assert_eq!(first.next_u16(), second.next_u16());
    }

    #[tokio::test]
    async fn explicit_aead_framing_options_round_trip() {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        for security in [VmessSecurity::Aes128Gcm, VmessSecurity::ChaCha20Poly1305] {
            for (global_padding, authenticated_length) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                let keys = DirectionKeys::request(&key, &iv);
                let mut writer =
                    BodyWriter::new(security, keys, global_padding, authenticated_length);
                let mut wire = Vec::new();
                writer
                    .write_record(&mut wire, b"phase6d VMess body")
                    .await
                    .unwrap();
                let mut reader =
                    BodyReader::new(security, keys, global_padding, authenticated_length);
                assert_eq!(
                    reader
                        .read_record(&mut std::io::Cursor::new(wire))
                        .await
                        .unwrap(),
                    b"phase6d VMess body"
                );
            }
        }
    }

    #[tokio::test]
    async fn none_is_raw_and_cfb_is_checksum_framed_across_records() {
        let key = [0x71; 16];
        let iv = [0x82; 16];
        let keys = DirectionKeys::request(&key, &iv);

        let mut none_writer = BodyWriter::new(VmessSecurity::None, keys, true, true);
        let mut none_wire = Vec::new();
        none_writer
            .write_record(&mut none_wire, b"raw-")
            .await
            .unwrap();
        none_writer
            .write_record(&mut none_wire, b"stream")
            .await
            .unwrap();
        assert_eq!(none_wire, b"raw-stream");

        let mut cfb_writer = BodyWriter::new(VmessSecurity::Aes128Cfb, keys, true, true);
        let mut cfb_wire = Vec::new();
        cfb_writer
            .write_record(&mut cfb_wire, b"first record")
            .await
            .unwrap();
        cfb_writer
            .write_record(&mut cfb_wire, b"second record")
            .await
            .unwrap();
        assert!(
            !cfb_wire
                .windows(b"first record".len())
                .any(|window| window == b"first record")
        );
        let mut reader = BodyReader::new(VmessSecurity::Aes128Cfb, keys, true, true);
        let mut cursor = std::io::Cursor::new(cfb_wire);
        assert_eq!(
            reader.read_record(&mut cursor).await.unwrap(),
            b"first record"
        );
        assert_eq!(
            reader.read_record(&mut cursor).await.unwrap(),
            b"second record"
        );
    }

    #[tokio::test]
    async fn authenticated_length_rejects_tampering() {
        let key = [0x51; 16];
        let iv = [0x62; 16];
        let keys = DirectionKeys::request(&key, &iv);
        let mut writer = BodyWriter::new(VmessSecurity::Aes128Gcm, keys, true, true);
        let mut wire = Vec::new();
        writer
            .write_record(&mut wire, b"authenticated length")
            .await
            .unwrap();
        wire[0] ^= 0x01;
        let mut reader = BodyReader::new(VmessSecurity::Aes128Gcm, keys, true, true);
        assert!(
            reader
                .read_record(&mut std::io::Cursor::new(wire))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn combined_framing_matches_go_prefix_vector() {
        let key = [0x11; 16];
        let iv = [0x22; 16];
        let mut writer = BodyWriter::new(
            VmessSecurity::Aes128Gcm,
            DirectionKeys::request(&key, &iv),
            true,
            true,
        );
        let mut wire = Vec::new();
        writer
            .write_record(&mut wire, b"phase6d VMess body")
            .await
            .unwrap();
        assert_eq!(
            hex::encode(&wire[..52]),
            "c68036f360f886a9255a83a637089de91ec3ecc2637944e73fff63204979fcc546287770a4248364d21c42b1c25a10cd7669a0e2"
        );
        assert_eq!(wire.len(), 111);
    }

    #[tokio::test]
    async fn response_direction_uses_sha256_material() {
        let request_key = [0x31; 16];
        let request_iv = [0x42; 16];
        let (response_key, response_iv) = response_body_material(&request_key, &request_iv);
        let mut server_writer = BodyWriter::new(
            VmessSecurity::Aes128Gcm,
            DirectionKeys::response(&request_key, &request_iv, &response_key, &response_iv),
            true,
            true,
        );
        let mut wire = Vec::new();
        server_writer
            .write_record(&mut wire, b"response")
            .await
            .unwrap();
        let (mut client_reader, _, _, _) = pair(
            VmessSecurity::Aes128Gcm,
            &request_key,
            &request_iv,
            true,
            true,
        );
        assert_eq!(
            client_reader
                .read_record(&mut std::io::Cursor::new(wire))
                .await
                .unwrap(),
            b"response"
        );
    }
}
