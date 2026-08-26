//! Cryptographic material generation used by compatibility CLI slices.

/// One clamped X25519 private key and its corresponding public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X25519KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

/// Generates an X25519 keypair with the oracle's explicit private-key clamp.
#[must_use]
pub fn x25519_keypair() -> X25519KeyPair {
    let mut private = [0_u8; 32];
    rand::fill(&mut private);
    private[0] &= 0xf8;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    X25519KeyPair { private, public }
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
}
