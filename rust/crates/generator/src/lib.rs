//! Cryptographic material generation used by compatibility CLI slices.

/// One clamped X25519 private key and its corresponding public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

/// VLESS X25519 material derived from one clamped private key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlessX25519Material {
    pub pair: X25519KeyPair,
    pub hash32: [u8; 32],
}

/// One encoded `ECHConfigList` and its matching PEM key record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EchKeyPair {
    pub config_list: Vec<u8>,
    pub key_pem: String,
}

#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    #[error("ECH public name is longer than 255 bytes")]
    PublicNameTooLong,
    #[error("ECH record is longer than 65535 bytes")]
    RecordTooLong,
}

/// Generates an X25519 keypair with the oracle's explicit private-key clamp.
#[must_use]
pub fn x25519_keypair() -> X25519KeyPair {
    let mut private = [0_u8; 32];
    rand::fill(&mut private);
    x25519_from_private(private)
}

/// Clamps an X25519 private key and derives its public key.
#[must_use]
pub fn x25519_from_private(mut private: [u8; 32]) -> X25519KeyPair {
    private[0] &= 0xf8;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    X25519KeyPair { private, public }
}

/// Generates or derives VLESS X25519 material and hashes the public password.
#[must_use]
pub fn vless_x25519(private: Option<[u8; 32]>) -> VlessX25519Material {
    let pair = private.map_or_else(x25519_keypair, x25519_from_private);
    let hash32 = *blake3::hash(&pair.public).as_bytes();
    VlessX25519Material { pair, hash32 }
}

/// Generates an X25519 `ECHConfigList` and matching `ECH KEYS` PEM record.
///
/// # Errors
///
/// Returns [`GeneratorError`] when a length-prefixed field cannot represent
/// the supplied public name or record.
pub fn ech_keypair(public_name: &str) -> Result<EchKeyPair, GeneratorError> {
    let public_name = public_name.as_bytes();
    let public_name_length =
        u8::try_from(public_name.len()).map_err(|_| GeneratorError::PublicNameTooLong)?;
    let mut private = [0_u8; 32];
    rand::fill(&mut private);
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);

    let mut body = Vec::new();
    body.push(0);
    body.extend(0x0020_u16.to_be_bytes());
    push_u16_record(&mut body, &public)?;
    let mut suites = Vec::new();
    for aead in [1_u16, 2, 3] {
        suites.extend(1_u16.to_be_bytes());
        suites.extend(aead.to_be_bytes());
    }
    push_u16_record(&mut body, &suites)?;
    body.push(0);
    body.push(public_name_length);
    body.extend(public_name);
    body.extend(0_u16.to_be_bytes());

    let mut config = Vec::new();
    config.extend(0xfe0d_u16.to_be_bytes());
    push_u16_record(&mut config, &body)?;
    let mut config_list = Vec::new();
    push_u16_record(&mut config_list, &config)?;
    let mut key_record = Vec::new();
    push_u16_record(&mut key_record, &private)?;
    push_u16_record(&mut key_record, &config)?;
    let key_pem = pem::encode(&pem::Pem::new("ECH KEYS", key_record));
    Ok(EchKeyPair {
        config_list,
        key_pem,
    })
}

fn push_u16_record(output: &mut Vec<u8>, record: &[u8]) -> Result<(), GeneratorError> {
    output.extend(
        u16::try_from(record.len())
            .map_err(|_| GeneratorError::RecordTooLong)?
            .to_be_bytes(),
    );
    output.extend(record);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_clamped_related_keypair() {
        let pair = x25519_keypair();
        assert_eq!(pair.private[0] & 7, 0);
        assert_eq!(pair.private[31] & 0x80, 0);
        assert_eq!(pair.private[31] & 0x40, 0x40);
        assert_eq!(
            pair.public,
            x25519_dalek::x25519(pair.private, x25519_dalek::X25519_BASEPOINT_BYTES)
        );
    }

    #[test]
    fn derives_repeatable_vless_material() {
        let material = vless_x25519(Some([0x5a; 32]));
        assert_eq!(material.pair.private[0], 0x58);
        assert_eq!(material.pair.private[31], 0x5a);
        assert_eq!(
            material.hash32,
            *blake3::hash(&material.pair.public).as_bytes()
        );
        assert_eq!(material, vless_x25519(Some([0x5a; 32])));
    }

    #[test]
    fn encodes_ech_public_name_and_matching_key() {
        let pair = ech_keypair("public.example").unwrap();
        assert!(
            pair.config_list
                .windows(14)
                .any(|window| window == b"public.example")
        );
        let key = pem::parse(pair.key_pem).unwrap();
        assert_eq!(key.tag(), "ECH KEYS");
        assert_eq!(key.contents().len(), pair.config_list.len() + 34);
    }
}
