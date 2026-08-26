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
}
