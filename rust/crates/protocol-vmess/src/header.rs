use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use aes::cipher::{AsyncStreamCipher as _, BlockEncrypt, KeyInit as _, KeyIvInit as _};
use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hmac::{Hmac, Mac as _};
use md5::{Digest as _, Md5};
use rand::RngExt as _;
use rewrite_model::{Destination, Host};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::kdf::{derive_12, derive_16};
use super::{VmessProtocolError, VmessSecurity, fnv1a32};

const VMESS_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const VMESS_ALTER_ID_MAGIC: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";
const VMESS_ALTER_ID_COLLISION_MAGIC: &[u8] = b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2";
const OPTION_CHUNK_STREAM_AND_MASKING: u8 = 0x01 | 0x04;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x02;
const ADDRESS_IPV6: u8 = 0x03;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VmessCommand {
    Tcp,
    Udp,
    Mux,
}

impl VmessCommand {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
            Self::Mux => 3,
        }
    }
}

impl VmessSecurity {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Aes128Cfb => 0x01,
            Self::Aes128Gcm => 0x03,
            Self::ChaCha20Poly1305 => 0x04,
            Self::None => 0x05,
            Self::Auto => unreachable!(),
        }
    }
}

pub(super) struct SealedHeader {
    pub(super) wire: Vec<u8>,
    pub(super) request_key: [u8; 16],
    pub(super) request_iv: [u8; 16],
    pub(super) response_verification: u8,
}

#[derive(Clone, Copy)]
struct RequestPlaintextOptions {
    response_verification: u8,
    security: VmessSecurity,
    command: VmessCommand,
    global_padding: bool,
    authenticated_length: bool,
}

#[derive(Clone, Copy)]
pub(super) struct SealRequestOptions {
    pub alter_id: i64,
    pub security: VmessSecurity,
    pub command: VmessCommand,
    pub global_padding: bool,
    pub authenticated_length: bool,
}

pub(super) fn command_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(uuid);
    digest.update(VMESS_MAGIC);
    digest.finalize().into()
}

pub(super) fn seal_request_header(
    uuid: &[u8; 16],
    command_key: &[u8; 16],
    destination: &Destination,
    options: SealRequestOptions,
) -> Result<SealedHeader, VmessProtocolError> {
    let mut random = rand::rng();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    let mut request_key = [0_u8; 16];
    let mut request_iv = [0_u8; 16];
    let mut connection_nonce = [0_u8; 8];
    random.fill(&mut request_key);
    random.fill(&mut request_iv);
    random.fill(&mut connection_nonce);
    let response_verification = random.random();
    let plaintext = build_request_plaintext(
        &request_key,
        &request_iv,
        destination,
        RequestPlaintextOptions {
            response_verification,
            security: options.security,
            command: options.command,
            global_padding: options.global_padding,
            authenticated_length: options.authenticated_length,
        },
        &mut random,
    )?;

    if options.alter_id > 0 {
        return seal_legacy_request_header(
            uuid,
            command_key,
            now,
            plaintext,
            request_key,
            request_iv,
            response_verification,
        );
    }

    let auth_id = build_auth_id(command_key, now, &mut random)?;

    let length_key = derive_16(
        command_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &connection_nonce],
    );
    let length_nonce = derive_12(
        command_key,
        &[
            b"VMess Header AEAD Nonce_Length",
            &auth_id,
            &connection_nonce,
        ],
    );
    let header_key = derive_16(
        command_key,
        &[b"VMess Header AEAD Key", &auth_id, &connection_nonce],
    );
    let header_nonce = derive_12(
        command_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &connection_nonce],
    );
    let plaintext_length = u16::try_from(plaintext.len())
        .map_err(|_| VmessProtocolError::Protocol("request header is too large".to_owned()))?;
    let encrypted_length = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|error| VmessProtocolError::Protocol(error.to_string()))?
        .encrypt(
            Nonce::from_slice(&length_nonce),
            Payload {
                msg: &plaintext_length.to_be_bytes(),
                aad: &auth_id,
            },
        )
        .map_err(|error| VmessProtocolError::Protocol(error.to_string()))?;
    let encrypted_header = Aes128Gcm::new_from_slice(&header_key)
        .map_err(|error| VmessProtocolError::Protocol(error.to_string()))?
        .encrypt(
            Nonce::from_slice(&header_nonce),
            Payload {
                msg: &plaintext,
                aad: &auth_id,
            },
        )
        .map_err(|error| VmessProtocolError::Protocol(error.to_string()))?;

    let mut wire = Vec::with_capacity(
        auth_id.len() + encrypted_length.len() + connection_nonce.len() + encrypted_header.len(),
    );
    wire.extend_from_slice(&auth_id);
    wire.extend_from_slice(&encrypted_length);
    wire.extend_from_slice(&connection_nonce);
    wire.extend_from_slice(&encrypted_header);
    Ok(SealedHeader {
        wire,
        request_key,
        request_iv,
        response_verification,
    })
}

fn seal_legacy_request_header(
    uuid: &[u8; 16],
    command_key: &[u8; 16],
    now: u64,
    mut plaintext: Vec<u8>,
    request_key: [u8; 16],
    request_iv: [u8; 16],
    response_verification: u8,
) -> Result<SealedHeader, VmessProtocolError> {
    let alter_id = first_alter_id(uuid);
    let mut authenticator = <Hmac<Md5> as hmac::Mac>::new_from_slice(&alter_id)
        .map_err(|error| VmessProtocolError::Protocol(error.to_string()))?;
    authenticator.update(&now.to_be_bytes());
    let authentication = authenticator.finalize().into_bytes();

    let mut timestamp_material = [0_u8; 32];
    for chunk in timestamp_material.chunks_exact_mut(8) {
        chunk.copy_from_slice(&now.to_be_bytes());
    }
    let timestamp_iv: [u8; 16] = Md5::digest(timestamp_material).into();
    cfb_mode::Encryptor::<Aes128>::new(command_key.into(), (&timestamp_iv).into())
        .encrypt(&mut plaintext);

    let mut wire = Vec::with_capacity(16 + plaintext.len());
    wire.extend_from_slice(&authentication);
    wire.extend_from_slice(&plaintext);
    Ok(SealedHeader {
        wire,
        request_key,
        request_iv,
        response_verification,
    })
}

fn first_alter_id(uuid: &[u8; 16]) -> [u8; 16] {
    let mut material = Vec::with_capacity(
        uuid.len() + VMESS_ALTER_ID_MAGIC.len() + VMESS_ALTER_ID_COLLISION_MAGIC.len(),
    );
    material.extend_from_slice(uuid);
    material.extend_from_slice(VMESS_ALTER_ID_MAGIC);
    loop {
        let candidate: [u8; 16] = Md5::digest(&material).into();
        if &candidate != uuid {
            return candidate;
        }
        material.extend_from_slice(VMESS_ALTER_ID_COLLISION_MAGIC);
    }
}

fn build_auth_id(
    command_key: &[u8; 16],
    now: u64,
    random: &mut impl rand::Rng,
) -> Result<[u8; 16], VmessProtocolError> {
    let mut block = [0_u8; 16];
    block[..8].copy_from_slice(&now.to_be_bytes());
    random.fill(&mut block[8..12]);
    let checksum = crc32fast::hash(&block[..12]);
    block[12..].copy_from_slice(&checksum.to_be_bytes());

    let key = derive_16(command_key, &[b"AES Auth ID Encryption"]);
    let cipher = Aes128::new_from_slice(&key)
        .map_err(|error| VmessProtocolError::Protocol(error.to_string()))?;
    let mut encrypted = aes::Block::from(block);
    cipher.encrypt_block(&mut encrypted);
    Ok(encrypted.into())
}

fn build_request_plaintext(
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
    destination: &Destination,
    options: RequestPlaintextOptions,
    random: &mut impl rand::Rng,
) -> Result<Vec<u8>, VmessProtocolError> {
    let padding_length = random.random_range(0_u8..16);
    let mut header = Vec::with_capacity(80);
    header.push(0x01);
    header.extend_from_slice(request_iv);
    header.extend_from_slice(request_key);
    header.push(options.response_verification);
    let request_options = match options.security {
        VmessSecurity::None if options.command == VmessCommand::Udp => 0x01,
        VmessSecurity::None => 0,
        VmessSecurity::Aes128Cfb => 0x01,
        VmessSecurity::Aes128Gcm | VmessSecurity::ChaCha20Poly1305 => {
            let mut request_options = OPTION_CHUNK_STREAM_AND_MASKING;
            if options.global_padding {
                request_options |= 0x08;
            }
            if options.authenticated_length {
                request_options |= 0x10;
            }
            request_options
        }
        VmessSecurity::Auto => unreachable!(),
    };
    header.push(request_options);
    header.push((padding_length << 4) | options.security.wire_value());
    header.push(0x00);
    header.push(options.command.wire_value());
    if options.command != VmessCommand::Mux {
        header.extend_from_slice(&destination.port.to_be_bytes());
        encode_address(&mut header, &destination.host)?;
    }
    if padding_length != 0 {
        let mut padding = [0_u8; 15];
        random.fill(&mut padding[..usize::from(padding_length)]);
        header.extend_from_slice(&padding[..usize::from(padding_length)]);
    }
    header.extend_from_slice(&fnv1a32(&header).to_be_bytes());
    Ok(header)
}

fn encode_address(output: &mut Vec<u8>, host: &Host) -> Result<(), VmessProtocolError> {
    match host {
        Host::Ip(std::net::IpAddr::V4(address)) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&address.octets());
        }
        Host::Ip(std::net::IpAddr::V6(address)) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                VmessProtocolError::Protocol(
                    "VMess destination domain exceeds 255 bytes".to_owned(),
                )
            })?;
            if length == 0 {
                return Err(VmessProtocolError::Protocol(
                    "VMess destination domain is empty".to_owned(),
                ));
            }
            output.push(ADDRESS_DOMAIN);
            output.push(length);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

pub(super) fn response_body_material(
    request_key: &[u8; 16],
    request_iv: &[u8; 16],
    legacy_header: bool,
) -> ([u8; 16], [u8; 16]) {
    if legacy_header {
        return (
            Md5::digest(request_key).into(),
            Md5::digest(request_iv).into(),
        );
    }
    let key: [u8; 32] = Sha256::digest(request_key).into();
    let iv: [u8; 32] = Sha256::digest(request_iv).into();
    (
        key[..16].try_into().expect("SHA-256 output has 16 bytes"),
        iv[..16].try_into().expect("SHA-256 output has 16 bytes"),
    )
}

pub(super) async fn read_response_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    expected_verification: u8,
) -> std::io::Result<()> {
    let mut encrypted_length = [0_u8; 18];
    reader.read_exact(&mut encrypted_length).await?;
    let length_key = derive_16(response_key, &[b"AEAD Resp Header Len Key"]);
    let length_iv = derive_12(response_iv, &[b"AEAD Resp Header Len IV"]);
    let length = Aes128Gcm::new_from_slice(&length_key)
        .map_err(std::io::Error::other)?
        .decrypt(Nonce::from_slice(&length_iv), encrypted_length.as_slice())
        .map_err(|_| std::io::Error::other("VMess response length authentication failed"))?;
    let length = match length.as_slice() {
        [high, low] => usize::from(u16::from_be_bytes([*high, *low])),
        _ => {
            return Err(std::io::Error::other(
                "invalid VMess response header length",
            ));
        }
    };
    if !(4..=4096).contains(&length) {
        return Err(std::io::Error::other("invalid VMess response header size"));
    }

    let mut encrypted_header = vec![0_u8; length + 16];
    reader.read_exact(&mut encrypted_header).await?;
    let header_key = derive_16(response_key, &[b"AEAD Resp Header Key"]);
    let header_iv = derive_12(response_iv, &[b"AEAD Resp Header IV"]);
    let header = Aes128Gcm::new_from_slice(&header_key)
        .map_err(std::io::Error::other)?
        .decrypt(Nonce::from_slice(&header_iv), encrypted_header.as_slice())
        .map_err(|_| std::io::Error::other("VMess response header authentication failed"))?;
    if header.first() != Some(&expected_verification) {
        return Err(std::io::Error::other(
            "VMess response verification byte mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::Aead as _;
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    fn open_request_header(command_key: &[u8; 16], wire: &[u8]) -> Vec<u8> {
        let auth_id = &wire[..16];
        let encrypted_length = &wire[16..34];
        let connection_nonce = &wire[34..42];
        let length_key = derive_16(
            command_key,
            &[b"VMess Header AEAD Key_Length", auth_id, connection_nonce],
        );
        let length_nonce = derive_12(
            command_key,
            &[b"VMess Header AEAD Nonce_Length", auth_id, connection_nonce],
        );
        let length = Aes128Gcm::new_from_slice(&length_key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&length_nonce),
                Payload {
                    msg: encrypted_length,
                    aad: auth_id,
                },
            )
            .unwrap();
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        assert_eq!(wire.len() - 42, length + 16);
        let header_key = derive_16(
            command_key,
            &[b"VMess Header AEAD Key", auth_id, connection_nonce],
        );
        let header_nonce = derive_12(
            command_key,
            &[b"VMess Header AEAD Nonce", auth_id, connection_nonce],
        );
        Aes128Gcm::new_from_slice(&header_key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&header_nonce),
                Payload {
                    msg: &wire[42..],
                    aad: auth_id,
                },
            )
            .unwrap()
    }

    #[test]
    fn request_header_is_independently_openable() {
        let uuid = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        let key = command_key(&uuid);
        let destination = Destination {
            host: Host::Domain("phase6d.example".to_owned()),
            port: 443,
        };
        let sealed = seal_request_header(
            &uuid,
            &key,
            &destination,
            SealRequestOptions {
                alter_id: 0,
                security: VmessSecurity::Aes128Gcm,
                command: VmessCommand::Tcp,
                global_padding: false,
                authenticated_length: false,
            },
        )
        .unwrap();
        let plaintext = open_request_header(&key, &sealed.wire);
        assert_eq!(plaintext[0], 1);
        assert_eq!(&plaintext[1..17], &sealed.request_iv);
        assert_eq!(&plaintext[17..33], &sealed.request_key);
        assert_eq!(plaintext[33], sealed.response_verification);
        assert_eq!(plaintext[34], OPTION_CHUNK_STREAM_AND_MASKING);
        assert_eq!(plaintext[35] & 0x0f, 3);
        assert_eq!(plaintext[37], VmessCommand::Tcp.wire_value());
        assert_eq!(&plaintext[38..40], &443_u16.to_be_bytes());
        assert_eq!(plaintext[40], ADDRESS_DOMAIN);
        assert_eq!(plaintext[41], 15);
        assert_eq!(&plaintext[42..57], b"phase6d.example");
        let checksum_offset = plaintext.len() - 4;
        assert_eq!(
            u32::from_be_bytes(plaintext[checksum_offset..].try_into().unwrap()),
            fnv1a32(&plaintext[..checksum_offset])
        );
    }

    #[test]
    fn non_aead_security_modes_use_oracle_wire_options() {
        let uuid = [0x31; 16];
        let key = command_key(&uuid);
        let destination = Destination {
            host: Host::Ip("192.0.2.44".parse().unwrap()),
            port: 8443,
        };
        for (security, expected_option, expected_security) in [
            (VmessSecurity::None, 0, 5),
            (VmessSecurity::Aes128Cfb, 1, 1),
        ] {
            let sealed = seal_request_header(
                &uuid,
                &key,
                &destination,
                SealRequestOptions {
                    alter_id: 0,
                    security,
                    command: VmessCommand::Tcp,
                    global_padding: true,
                    authenticated_length: true,
                },
            )
            .unwrap();
            let plaintext = open_request_header(&key, &sealed.wire);
            assert_eq!(plaintext[34], expected_option);
            assert_eq!(plaintext[35] & 0x0f, expected_security);
        }
    }

    #[test]
    fn udp_and_mux_commands_use_oracle_header_shapes() {
        let destination = Destination {
            host: Host::Ip("192.0.2.45".parse().unwrap()),
            port: 5353,
        };
        let mut random = rand::rng();
        let udp = build_request_plaintext(
            &[0x11; 16],
            &[0x22; 16],
            &destination,
            RequestPlaintextOptions {
                response_verification: 0x33,
                security: VmessSecurity::None,
                command: VmessCommand::Udp,
                global_padding: false,
                authenticated_length: false,
            },
            &mut random,
        )
        .unwrap();
        assert_eq!(udp[34], 1);
        assert_eq!(udp[37], VmessCommand::Udp.wire_value());
        assert_eq!(&udp[38..40], &5353_u16.to_be_bytes());
        assert_eq!(udp[40], ADDRESS_IPV4);
        assert_eq!(&udp[41..45], &[192, 0, 2, 45]);

        let mux = build_request_plaintext(
            &[0x44; 16],
            &[0x55; 16],
            &destination,
            RequestPlaintextOptions {
                response_verification: 0x66,
                security: VmessSecurity::Aes128Gcm,
                command: VmessCommand::Mux,
                global_padding: false,
                authenticated_length: false,
            },
            &mut random,
        )
        .unwrap();
        let padding_length = usize::from(mux[35] >> 4);
        assert_eq!(mux[37], VmessCommand::Mux.wire_value());
        assert_eq!(mux.len(), 38 + padding_length + 4);
    }

    #[test]
    fn legacy_request_header_uses_first_alter_id_and_timestamp_cfb() {
        let uuid = [0x41; 16];
        let key = command_key(&uuid);
        let destination = Destination {
            host: Host::Domain("legacy.phase6d".to_owned()),
            port: 9443,
        };
        let sealed = seal_request_header(
            &uuid,
            &key,
            &destination,
            SealRequestOptions {
                alter_id: 64,
                security: VmessSecurity::Aes128Gcm,
                command: VmessCommand::Tcp,
                global_padding: false,
                authenticated_length: false,
            },
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let alter_id = first_alter_id(&uuid);
        let timestamp = (now.saturating_sub(2)..=now + 1)
            .find(|timestamp| {
                let mut authenticator =
                    <Hmac<Md5> as hmac::Mac>::new_from_slice(&alter_id).unwrap();
                authenticator.update(&timestamp.to_be_bytes());
                authenticator.verify_slice(&sealed.wire[..16]).is_ok()
            })
            .expect("legacy authentication timestamp");
        let mut timestamp_material = [0_u8; 32];
        for chunk in timestamp_material.chunks_exact_mut(8) {
            chunk.copy_from_slice(&timestamp.to_be_bytes());
        }
        let timestamp_iv: [u8; 16] = Md5::digest(timestamp_material).into();
        let mut plaintext = sealed.wire[16..].to_vec();
        cfb_mode::Decryptor::<Aes128>::new((&key).into(), (&timestamp_iv).into())
            .decrypt(&mut plaintext);
        assert_eq!(plaintext[0], 1);
        assert_eq!(&plaintext[1..17], &sealed.request_iv);
        assert_eq!(&plaintext[17..33], &sealed.request_key);
        assert_eq!(plaintext[33], sealed.response_verification);
        assert_eq!(plaintext[35] & 0x0f, 3);
        assert_eq!(plaintext[37], VmessCommand::Tcp.wire_value());
        assert_eq!(&plaintext[38..40], &9443_u16.to_be_bytes());
        assert_eq!(plaintext[40], ADDRESS_DOMAIN);
    }

    #[tokio::test]
    async fn response_header_verification_is_enforced() {
        let request_key = [0x11; 16];
        let request_iv = [0x22; 16];
        let expected = 0x5a;
        let (response_key, response_iv) = response_body_material(&request_key, &request_iv, false);
        let plaintext = [expected, 0, 0, 0];
        let length_key = derive_16(&response_key, &[b"AEAD Resp Header Len Key"]);
        let length_iv = derive_12(&response_iv, &[b"AEAD Resp Header Len IV"]);
        let header_key = derive_16(&response_key, &[b"AEAD Resp Header Key"]);
        let header_iv = derive_12(&response_iv, &[b"AEAD Resp Header IV"]);
        let mut wire = Aes128Gcm::new_from_slice(&length_key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&length_iv),
                &u16::try_from(plaintext.len()).unwrap().to_be_bytes()[..],
            )
            .unwrap();
        wire.extend(
            Aes128Gcm::new_from_slice(&header_key)
                .unwrap()
                .encrypt(Nonce::from_slice(&header_iv), plaintext.as_slice())
                .unwrap(),
        );
        let (mut client, mut server) = tokio::io::duplex(128);
        server.write_all(&wire).await.unwrap();
        read_response_header(&mut client, &response_key, &response_iv, expected)
            .await
            .unwrap();
    }
}
