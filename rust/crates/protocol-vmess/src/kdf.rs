use sha2::{Digest, Sha256};

const SHA256_BLOCK_SIZE: usize = 64;

fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

// VMess defines a recursively nested HMAC construction. This is deliberately
// kept local instead of pretending it is a normal HKDF/HMAC invocation.
fn nested_hmac(keys: &[&[u8]], message: &[u8]) -> [u8; 32] {
    let Some((key, inner_keys)) = keys.split_last() else {
        return sha256(message);
    };

    let mut key_block = [0_u8; SHA256_BLOCK_SIZE];
    if key.len() > SHA256_BLOCK_SIZE {
        key_block[..32].copy_from_slice(&nested_hmac(inner_keys, key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(SHA256_BLOCK_SIZE + message.len());
    inner.extend(key_block.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let inner_digest = nested_hmac(inner_keys, &inner);

    let mut outer = Vec::with_capacity(SHA256_BLOCK_SIZE + inner_digest.len());
    outer.extend(key_block.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner_digest);
    nested_hmac(inner_keys, &outer)
}

pub(super) fn derive(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys = Vec::with_capacity(path.len() + 1);
    keys.push(b"VMess AEAD KDF".as_slice());
    keys.extend_from_slice(path);
    nested_hmac(&keys, key)
}

pub(super) fn derive_16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    derive(key, path)[..16]
        .try_into()
        .expect("the VMess KDF output is 32 bytes")
}

pub(super) fn derive_12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    derive(key, path)[..12]
        .try_into()
        .expect("the VMess KDF output is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::derive;

    #[test]
    fn matches_go_reference_vectors() {
        assert_eq!(
            hex::encode(derive(b"key", &[b"label"])),
            "c9cebf77e859ffcbe78619d4e503b0df707f1d7ac98a189c418763940880e3eb"
        );
        assert_eq!(
            hex::encode(derive(
                b"Demo Key for KDF Value Test",
                &[
                    b"Demo Path for KDF Value Test",
                    b"Demo Path for KDF Value Test2",
                    b"Demo Path for KDF Value Test3",
                ],
            )),
            "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"
        );
    }
}
