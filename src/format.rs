//! TinyRLE wire format (PackBits-style).
//!
//! Stream of records:
//! - Literal: `len-1` in `0..=127`, then `len` raw bytes (`len` in 1..=128)
//! - Run:     `0x80 | (count-3)` in `0x80..=0xFF`, then 1 repeated byte
//!            (`count` in 3..=130)

pub const MAX_LITERAL: usize = 128;
pub const MIN_RUN: usize = 3;
pub const MAX_RUN: usize = 130;

/// Worst-case compressed size for `src_len` input bytes.
pub fn max_compressed_size(src_len: usize) -> usize {
    // Every byte as its own literal record: 1 control + 1 data.
    src_len.saturating_mul(2).saturating_add(16)
}
