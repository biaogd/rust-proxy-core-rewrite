use md5::{Digest, Md5};

/// Mirrors the Go oracle's Shadowsocks/SSR password KDF.
pub(crate) fn kdf(password: &str, key_len: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let mut previous = Vec::new();
    while output.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        output.extend_from_slice(&digest);
        previous = digest.to_vec();
    }
    output.truncate(key_len);
    output
}
