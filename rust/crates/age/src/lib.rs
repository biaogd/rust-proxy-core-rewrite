//! Narrow age compatibility helpers for encrypted Mihomo configuration.

use age::x25519;
use thiserror::Error;

const ARMOR_HEADER: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Debug, Error)]
pub enum AgeError {
    #[error("decrypt config error: invalid X25519 age identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("decrypt config error: {0}")]
    Decrypt(#[from] age::DecryptError),
}

/// Validates one native X25519 age identity.
///
/// # Errors
///
/// Returns [`AgeError::InvalidIdentity`] for malformed or unsupported keys.
pub fn validate_x25519_identity(secret_key: &str) -> Result<(), AgeError> {
    parse_identity(secret_key).map(drop)
}

/// Decrypts an ASCII-armored age configuration, or returns plain input unchanged.
///
/// # Errors
///
/// Returns [`AgeError`] when the identity is invalid or cannot decrypt an age
/// armored input.
pub fn decrypt_config(data: &[u8], secret_key: &str) -> Result<Vec<u8>, AgeError> {
    if !data.starts_with(ARMOR_HEADER) {
        return Ok(data.to_vec());
    }
    let identity = parse_identity(secret_key)?;
    age::decrypt(&identity, data).map_err(AgeError::from)
}

fn parse_identity(secret_key: &str) -> Result<x25519::Identity, AgeError> {
    secret_key.parse().map_err(AgeError::InvalidIdentity)
}

#[cfg(test)]
mod tests {
    use age::secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn leaves_plain_configuration_unchanged_without_a_key() {
        assert_eq!(
            decrypt_config(b"mixed-port: 7890", "").unwrap(),
            b"mixed-port: 7890"
        );
    }

    #[test]
    fn decrypts_armored_x25519_configuration() {
        let identity = x25519::Identity::generate();
        let encrypted = age::encrypt_and_armor(&identity.to_public(), b"mixed-port: 7890")
            .expect("encrypt fixture");
        assert_eq!(
            decrypt_config(encrypted.as_bytes(), identity.to_string().expose_secret()).unwrap(),
            b"mixed-port: 7890"
        );
    }
}
