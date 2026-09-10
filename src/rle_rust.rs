//! Pure-Rust TinyRLE reference implementation (also used on non-x86_64).

use crate::format::{max_compressed_size, MAX_LITERAL, MAX_RUN, MIN_RUN};
use crate::{CompressError, DecompressError};

pub fn compress(src: &[u8]) -> Result<Vec<u8>, CompressError> {
    let mut dst = vec![0u8; max_compressed_size(src.len())];
    let n = compress_into(src, &mut dst)?;
    dst.truncate(n);
    Ok(dst)
}

pub fn compress_into(src: &[u8], dst: &mut [u8]) -> Result<usize, CompressError> {
    let mut si = 0usize;
    let mut di = 0usize;

    while si < src.len() {
        let b = src[si];
        let mut run = 1usize;
        while si + run < src.len() && src[si + run] == b && run < MAX_RUN {
            run += 1;
        }

        if run >= MIN_RUN {
            if di + 2 > dst.len() {
                return Err(CompressError::OutputTooSmall);
            }
            dst[di] = 0x80 | ((run - MIN_RUN) as u8);
            dst[di + 1] = b;
            di += 2;
            si += run;
            continue;
        }

        let lit_start = si;
        let mut lit_len = 0usize;
        while lit_len < MAX_LITERAL && si < src.len() {
            let mut peek = 1usize;
            let cur = src[si];
            while si + peek < src.len() && src[si + peek] == cur && peek < MAX_RUN {
                peek += 1;
            }
            if peek >= MIN_RUN {
                break;
            }
            si += 1;
            lit_len += 1;
        }

        if lit_len == 0 {
            // Should not happen, but keep progress safe.
            si += 1;
            continue;
        }

        if di + 1 + lit_len > dst.len() {
            return Err(CompressError::OutputTooSmall);
        }
        dst[di] = (lit_len - 1) as u8;
        di += 1;
        dst[di..di + lit_len].copy_from_slice(&src[lit_start..lit_start + lit_len]);
        di += lit_len;
    }

    Ok(di)
}

pub fn decompress(src: &[u8]) -> Result<Vec<u8>, DecompressError> {
    // First pass: compute output length.
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

    let mut dst = vec![0u8; out_len];
    let written = decompress_into(src, &mut dst)?;
    debug_assert_eq!(written, out_len);
    Ok(dst)
}

pub fn decompress_into(src: &[u8], dst: &mut [u8]) -> Result<usize, DecompressError> {
    let mut si = 0usize;
    let mut di = 0usize;

    while si < src.len() {
        let ctrl = src[si];
        si += 1;
        if ctrl < 128 {
            let n = (ctrl as usize) + 1;
            if si + n > src.len() {
                return Err(DecompressError::Truncated);
            }
            if di + n > dst.len() {
                return Err(DecompressError::OutputTooSmall);
            }
            dst[di..di + n].copy_from_slice(&src[si..si + n]);
            si += n;
            di += n;
        } else {
            let n = (ctrl as usize - 0x80) + MIN_RUN;
            if si >= src.len() {
                return Err(DecompressError::Truncated);
            }
            if di + n > dst.len() {
                return Err(DecompressError::OutputTooSmall);
            }
            let b = src[si];
            si += 1;
            dst[di..di + n].fill(b);
            di += n;
        }
    }

    Ok(di)
}
