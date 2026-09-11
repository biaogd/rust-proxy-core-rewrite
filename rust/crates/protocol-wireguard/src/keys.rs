//! Standard-Base64 32-byte `WireGuard` keys (Go `encoding/base64.StdEncoding`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::WireGuardProtocolError;

/// Decodes a standard-Base64 `WireGuard` key to 32 bytes.
///
/// # Errors
///
/// Returns when the text is not standard Base64 or is not 32 bytes.
pub fn decode_key(text: &str) -> Result<[u8; 32], WireGuardProtocolError> {
    let trimmed = text.trim();
    let decoded = STANDARD
        .decode(trimmed)
        .map_err(|error| WireGuardProtocolError::protocol(format!("decode key: {error}")))?;
    let key: [u8; 32] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        WireGuardProtocolError::protocol(format!(
            "WireGuard key must be 32 bytes, got {}",
            decoded.len()
        ))
    })?;
    Ok(key)
}

/// Encodes 32 bytes as padded standard Base64 (Go `PrivateKey:` / `PublicKey:` shape).
#[must_use]
pub fn encode_key(key: &[u8; 32]) -> String {
    STANDARD.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_standard_base64() {
        let key = [0x11_u8; 32];
        let encoded = encode_key(&key);
        assert_eq!(encoded.len(), 44);
        assert!(encoded.ends_with('='));
        assert_eq!(decode_key(&encoded).expect("decode"), key);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_key("c2hvcnQ=").is_err());
    }
}
