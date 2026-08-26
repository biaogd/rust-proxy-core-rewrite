//! Narrow age compatibility helpers for encrypted Mihomo configuration.

use age::secrecy::ExposeSecret;
use age::x25519;
use thiserror::Error;

const ARMOR_HEADER: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Debug, Error)]
pub enum AgeError {
    #[error("invalid X25519 age identity: {0}")]
    InvalidIdentity(&'static str),
    #[error("invalid X25519 age recipient: {0}")]
    InvalidRecipient(&'static str),
    #[error("age decryption failed: {0}")]
    Decrypt(#[from] age::DecryptError),
    #[error("age encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
}

/// Validates one native X25519 age identity.
///
/// # Errors
///
/// Returns [`AgeError::InvalidIdentity`] for malformed or unsupported keys.
pub fn validate_x25519_identity(secret_key: &str) -> Result<(), AgeError> {
    parse_identity(secret_key).map(drop)
}

/// Converts one native X25519 identity to its public recipient.
///
/// # Errors
///
/// Returns [`AgeError::InvalidIdentity`] for malformed or unsupported keys.
pub fn recipient_for_x25519_identity(secret_key: &str) -> Result<String, AgeError> {
    Ok(parse_identity(secret_key)?.to_public().to_string())
}

/// Generates one native X25519 identity and its public recipient.
#[must_use]
pub fn generate_x25519_key_pair() -> (String, String) {
    let identity = x25519::Identity::generate();
    (
        identity.to_string().expose_secret().to_owned(),
        identity.to_public().to_string(),
    )
}

/// Encrypts bytes to one native X25519 recipient using ASCII armor.
///
/// # Errors
///
/// Returns [`AgeError`] for an invalid recipient or encryption failure.
pub fn encrypt_x25519_armor(data: &[u8], public_key: &str) -> Result<String, AgeError> {
    let recipient = public_key
        .parse::<x25519::Recipient>()
        .map_err(AgeError::InvalidRecipient)?;
    age::encrypt_and_armor(&recipient, data).map_err(AgeError::from)
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

    #[test]
    fn encrypts_and_decrypts_x25519_armor() {
        let identity = x25519::Identity::generate();
        let encrypted =
            encrypt_x25519_armor(b"phase 5a4c", &identity.to_public().to_string()).unwrap();
        assert_eq!(
            decrypt_config(encrypted.as_bytes(), identity.to_string().expose_secret()).unwrap(),
            b"phase 5a4c"
        );
    }

    #[test]
    fn generated_key_pair_converts_to_the_same_recipient() {
        let (secret, public) = generate_x25519_key_pair();
        assert_eq!(recipient_for_x25519_identity(&secret).unwrap(), public);
    }
}
