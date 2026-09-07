//! `AnyTLS` padding-scheme parsing and record-size generation.

use std::collections::BTreeMap;
use std::sync::Arc;

use md5::{Digest, Md5};
use rand::RngExt;

/// Sentinel meaning "stop padding this write if no payload remains".
pub const CHECK_MARK: i32 = -1;

/// Default padding scheme used by the Go `AnyTLS` client on first connect.
pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// Shared padding pointer matching Go `atomic.Pointer[PaddingFactory]` on Client.
pub type SharedPadding = std::sync::Arc<std::sync::Mutex<std::sync::Arc<PaddingFactory>>>;

/// Builds a shared default padding factory.
#[must_use]
pub fn default_shared_padding() -> SharedPadding {
    std::sync::Arc::new(std::sync::Mutex::new(PaddingFactory::default_factory()))
}

/// Parsed padding factory matching Go `padding.PaddingFactory`.
#[derive(Clone, Debug)]
pub struct PaddingFactory {
    scheme: BTreeMap<String, String>,
    raw_scheme: Vec<u8>,
    stop: u32,
    md5: String,
}

impl PaddingFactory {
    /// Parses a raw padding scheme. Returns `None` when the scheme is invalid.
    #[must_use]
    pub fn new(raw_scheme: &[u8]) -> Option<Self> {
        let scheme = string_map_from_bytes(raw_scheme);
        if scheme.is_empty() {
            return None;
        }
        let stop = scheme.get("stop")?.parse::<u32>().ok()?;
        let md5 = format!("{:x}", Md5::digest(raw_scheme));
        Some(Self {
            scheme,
            raw_scheme: raw_scheme.to_vec(),
            stop,
            md5,
        })
    }

    /// Builds the default factory.
    ///
    /// # Panics
    ///
    /// Panics only if the embedded default scheme is malformed.
    #[must_use]
    pub fn default_factory() -> Arc<Self> {
        Arc::new(Self::new(DEFAULT_PADDING_SCHEME).expect("default AnyTLS padding scheme"))
    }

    #[must_use]
    pub fn stop(&self) -> u32 {
        self.stop
    }

    #[must_use]
    pub fn md5(&self) -> &str {
        &self.md5
    }

    #[must_use]
    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    /// Generates TLS-plaintext sizes for the given packet index.
    #[must_use]
    pub fn generate_record_payload_sizes(&self, pkt: u32) -> Vec<i32> {
        let Some(spec) = self.scheme.get(&pkt.to_string()) else {
            return Vec::new();
        };
        let mut sizes = Vec::new();
        for range in spec.split(',') {
            if range == "c" {
                sizes.push(CHECK_MARK);
                continue;
            }
            let Some((min_text, max_text)) = range.split_once('-') else {
                continue;
            };
            let Ok(mut min) = min_text.parse::<i64>() else {
                continue;
            };
            let Ok(mut max) = max_text.parse::<i64>() else {
                continue;
            };
            if min > max {
                std::mem::swap(&mut min, &mut max);
            }
            if min <= 0 || max <= 0 {
                continue;
            }
            if min == max {
                sizes.push(i32::try_from(min).unwrap_or(i32::MAX));
            } else {
                let span = max - min;
                let offset = rand::rng().random_range(0..span);
                sizes.push(i32::try_from(min + offset).unwrap_or(i32::MAX));
            }
        }
        sizes
    }
}

fn string_map_from_bytes(raw: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(raw).lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        map.insert(key.to_owned(), value.to_owned());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_parses_and_pads_auth_packet() {
        let factory = PaddingFactory::default_factory();
        assert_eq!(factory.stop(), 8);
        assert_eq!(factory.generate_record_payload_sizes(0), vec![30]);
        assert_eq!(factory.md5().len(), 32);
    }
}
