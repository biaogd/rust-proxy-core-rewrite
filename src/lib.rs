//! TinyRLE: a small PackBits-style compressor.
//!
//! On `x86_64`, the hot path is pure assembly (`asm_x86_64`).
//! Other targets use the Rust reference implementation.

mod format;
mod rle_rust;

#[cfg(target_arch = "x86_64")]
mod asm_x86_64;

pub use format::{max_compressed_size, MAX_LITERAL, MAX_RUN, MIN_RUN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressError {
    OutputTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressError {
    Truncated,
    OutputTooSmall,
    OutputTooLarge,
    Corrupt,
}

impl std::fmt::Display for CompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutputTooSmall => write!(f, "compressed output buffer too small"),
        }
    }
}

impl std::error::Error for CompressError {}

impl std::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated compressed input"),
            Self::OutputTooSmall => write!(f, "decompressed output buffer too small"),
            Self::OutputTooLarge => write!(f, "decompressed output too large"),
            Self::Corrupt => write!(f, "corrupt compressed stream"),
        }
    }
}

impl std::error::Error for DecompressError {}

/// Compress with the architecture-native backend.
pub fn compress(src: &[u8]) -> Result<Vec<u8>, CompressError> {
    let mut dst = vec![0u8; max_compressed_size(src.len())];
    let n = compress_into(src, &mut dst)?;
    dst.truncate(n);
    Ok(dst)
}

pub fn compress_into(src: &[u8], dst: &mut [u8]) -> Result<usize, CompressError> {
    #[cfg(target_arch = "x86_64")]
    {
        let n = unsafe {
            asm_x86_64::tinyrle_compress(src.as_ptr(), src.len(), dst.as_mut_ptr(), dst.len())
        };
        if n < 0 {
            return Err(CompressError::OutputTooSmall);
        }
        Ok(n as usize)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        rle_rust::compress_into(src, dst)
    }
}

/// Decompress with the architecture-native backend.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, DecompressError> {
    // Bound output size using a Rust scan so asm only fills a sized buffer.
    let out_len = uncompressed_len(src)?;
    let mut dst = vec![0u8; out_len];
    let n = decompress_into(src, &mut dst)?;
    if n != out_len {
        return Err(DecompressError::Corrupt);
    }
    Ok(dst)
}

pub fn decompress_into(src: &[u8], dst: &mut [u8]) -> Result<usize, DecompressError> {
    #[cfg(target_arch = "x86_64")]
    {
        let n = unsafe {
            asm_x86_64::tinyrle_decompress(src.as_ptr(), src.len(), dst.as_mut_ptr(), dst.len())
        };
        if n < 0 {
            // Distinguish truncated vs too-small when possible.
            if uncompressed_len(src).is_err() {
                return Err(DecompressError::Truncated);
            }
            return Err(DecompressError::OutputTooSmall);
        }
        Ok(n as usize)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        rle_rust::decompress_into(src, dst)
    }
}

fn uncompressed_len(src: &[u8]) -> Result<usize, DecompressError> {
    let mut out_len = 0usize;
    let mut i = 0usize;
    while i < src.len() {
        let ctrl = src[i];
        i += 1;
        if ctrl < 128 {
            let n = (ctrl as usize) + 1;
            if i + n > src.len() {
                return Err(DecompressError::Truncated);
            }
            out_len = out_len
                .checked_add(n)
                .ok_or(DecompressError::OutputTooLarge)?;
            i += n;
        } else {
            let n = (ctrl as usize - 0x80) + MIN_RUN;
            if i >= src.len() {
                return Err(DecompressError::Truncated);
            }
            out_len = out_len
                .checked_add(n)
                .ok_or(DecompressError::OutputTooLarge)?;
            i += 1;
        }
    }
    Ok(out_len)
}

/// Always-available Rust reference (useful for cross-checking the asm path).
pub mod reference {
    pub use crate::rle_rust::{compress, compress_into, decompress, decompress_into};
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8]) {
        let c = compress(data).expect("compress");
        let d = decompress(&c).expect("decompress");
        assert_eq!(d, data);

        let c2 = reference::compress(data).expect("ref compress");
        assert_eq!(c, c2, "asm and rust compressors must match");
        let d2 = reference::decompress(&c).expect("ref decompress");
        assert_eq!(d2, data);
    }

    #[test]
    fn empty() {
        roundtrip(b"");
    }

    #[test]
    fn literals_only() {
        roundtrip(b"abcdef");
        roundtrip(&(0u8..200).collect::<Vec<_>>());
    }

    #[test]
    fn long_runs() {
        roundtrip(&vec![b'A'; 3]);
        roundtrip(&vec![b'B'; 130]);
        roundtrip(&vec![b'C'; 300]);
    }

    #[test]
    fn mixed() {
        let mut v = Vec::new();
        v.extend_from_slice(b"hi");
        v.extend(std::iter::repeat(b'z').take(40));
        v.extend_from_slice(b"xy");
        v.extend(std::iter::repeat(0u8).take(5));
        roundtrip(&v);
    }

    #[test]
    fn compressible_demo_payload() {
        let text = b"Hello!!! Hello!!! Hello!!! Rust+ASM RLE demo......";
        let c = compress(text).unwrap();
        assert!(c.len() < text.len());
        assert_eq!(decompress(&c).unwrap(), text);
    }
}
