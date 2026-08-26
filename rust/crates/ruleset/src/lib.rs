//! MRS conversion helpers, introduced one behavior and direction at a time.

use std::fmt::Write as _;
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;

const MRS_MAGIC: &[u8; 4] = b"MRS\x01";
const DOMAIN_BEHAVIOR: u8 = 0;
const IPCIDR_BEHAVIOR: u8 = 1;
const IPCIDR_SET_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum RulesetError {
    #[error("MRS I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid MRS: {0}")]
    Invalid(&'static str),
    #[error("invalid YAML rule set: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("file must have a `payload` field")]
    MissingPayload,
    #[error("empty rule")]
    Empty,
}

/// Source syntax accepted by [`ipcidr_to_mrs`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceFormat {
    Text,
    Yaml,
}

#[derive(Debug, Default, Deserialize)]
struct RulePayload {
    #[serde(default)]
    payload: Vec<String>,
    #[serde(default)]
    rules: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpRange {
    V4(u32, u32),
    V6(u128, u128),
}

/// Converts newline-delimited or YAML IP-CIDR rules to an MRS v1 zstd frame.
///
/// Invalid IP-CIDR entries are ignored like the oracle. At least one valid
/// entry is required.
///
/// # Errors
///
/// Returns [`RulesetError`] for malformed YAML, an absent YAML payload, an
/// empty valid rule set or an encoding failure.
pub fn ipcidr_to_mrs(source: &[u8], format: SourceFormat) -> Result<Vec<u8>, RulesetError> {
    let rules = parse_rules(source, format)?;
    let mut ranges = Vec::new();
    let mut count = 0_i64;
    for rule in rules {
        if let Ok(network) = rule.parse::<IpNet>() {
            ranges.push(range_of(network));
            count += 1;
        }
    }
    if count == 0 {
        return Err(RulesetError::Empty);
    }
    let ranges = merge_ranges(ranges);
    let mut plain = Vec::new();
    plain.extend(MRS_MAGIC);
    plain.push(IPCIDR_BEHAVIOR);
    plain.extend(count.to_be_bytes());
    plain.extend(0_i64.to_be_bytes());
    plain.push(IPCIDR_SET_VERSION);
    plain.extend(
        i64::try_from(ranges.len())
            .map_err(|_| RulesetError::Invalid("too many IP ranges"))?
            .to_be_bytes(),
    );
    for range in ranges {
        match range {
            IpRange::V4(start, end) => {
                plain.extend(mapped_v4_bytes(start));
                plain.extend(mapped_v4_bytes(end));
            }
            IpRange::V6(start, end) => {
                plain.extend(start.to_be_bytes());
                plain.extend(end.to_be_bytes());
            }
        }
    }
    Ok(zstd::stream::encode_all(plain.as_slice(), 0)?)
}

fn parse_rules(source: &[u8], format: SourceFormat) -> Result<Vec<String>, RulesetError> {
    match format {
        SourceFormat::Text => Ok(String::from_utf8_lossy(source)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
            .map(ToOwned::to_owned)
            .collect()),
        SourceFormat::Yaml => {
            let payload: RulePayload = serde_yaml_ng::from_slice(source)?;
            if !payload.payload.is_empty() {
                Ok(payload.payload)
            } else if !payload.rules.is_empty() {
                Ok(payload.rules)
            } else {
                Err(RulesetError::MissingPayload)
            }
        }
    }
}

fn range_of(network: IpNet) -> IpRange {
    match (network.network(), network.broadcast()) {
        (IpAddr::V4(start), IpAddr::V4(end)) => IpRange::V4(start.into(), end.into()),
        (IpAddr::V6(start), IpAddr::V6(end)) => IpRange::V6(start.into(), end.into()),
        _ => unreachable!("an IP network has one address family"),
    }
}

fn merge_ranges(mut ranges: Vec<IpRange>) -> Vec<IpRange> {
    ranges.sort_unstable();
    let mut merged = Vec::with_capacity(ranges.len());
    for range in ranges {
        match (merged.last_mut(), range) {
            (Some(IpRange::V4(_, previous_end)), IpRange::V4(start, end))
                if start <= previous_end.saturating_add(1) =>
            {
                *previous_end = (*previous_end).max(end);
            }
            (Some(IpRange::V6(_, previous_end)), IpRange::V6(start, end))
                if start <= previous_end.saturating_add(1) =>
            {
                *previous_end = (*previous_end).max(end);
            }
            (_, range) => merged.push(range),
        }
    }
    merged
}

fn mapped_v4_bytes(address: u32) -> [u8; 16] {
    let mut mapped = [0; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..].copy_from_slice(&address.to_be_bytes());
    mapped
}

/// Converts an IP-CIDR MRS v1 payload to canonical newline-delimited prefixes.
///
/// # Errors
///
/// Returns [`RulesetError`] for invalid zstd, header, behavior or range data.
pub fn ipcidr_mrs_to_text(source: &[u8]) -> Result<Vec<u8>, RulesetError> {
    let decoded = zstd::stream::decode_all(source)?;
    let mut reader = Cursor::new(decoded);
    read_mrs_header(&mut reader, IPCIDR_BEHAVIOR)?;
    if read_u8(&mut reader)? != IPCIDR_SET_VERSION {
        return Err(RulesetError::Invalid("IP-CIDR set version"));
    }
    let range_count = read_i64(&mut reader)?;
    let range_count = usize::try_from(range_count)
        .ok()
        .filter(|count| *count > 0)
        .ok_or(RulesetError::Invalid("IP range count"))?;
    let mut output = String::new();
    for _ in 0..range_count {
        let start = read_array::<16>(&mut reader)?;
        let end = read_array::<16>(&mut reader)?;
        append_range(&mut output, start, end)?;
    }
    Ok(output.into_bytes())
}

/// Converts a domain MRS v1 payload to sorted newline-delimited patterns.
///
/// # Errors
///
/// Returns [`RulesetError`] for invalid zstd, header, behavior or succinct trie
/// data.
pub fn domain_mrs_to_text(source: &[u8]) -> Result<Vec<u8>, RulesetError> {
    let decoded = zstd::stream::decode_all(source)?;
    let mut reader = Cursor::new(decoded);
    read_mrs_header(&mut reader, DOMAIN_BEHAVIOR)?;
    if read_u8(&mut reader)? != 1 {
        return Err(RulesetError::Invalid("domain set version"));
    }
    let leaves = read_words(&mut reader, "domain leaves")?;
    let label_bitmap = read_words(&mut reader, "domain label bitmap")?;
    let label_length = read_positive_length(&mut reader, "domain labels")?;
    let mut labels = vec![0; label_length];
    reader.read_exact(&mut labels)?;

    let mut reversed_keys = Vec::new();
    traverse_domain_set(
        &leaves,
        &label_bitmap,
        &labels,
        0,
        0,
        &mut Vec::new(),
        &mut reversed_keys,
    )?;
    let mut keys = reversed_keys
        .into_iter()
        .map(|key| {
            String::from_utf8(key)
                .map(|key| key.chars().rev().collect::<String>())
                .map_err(|_| RulesetError::Invalid("domain label UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort_unstable();
    let mut output = String::new();
    for key in &keys {
        if keys.binary_search(&format!("+.{key}")).is_ok() {
            continue;
        }
        writeln!(output, "{key}").expect("writing to String cannot fail");
    }
    Ok(output.into_bytes())
}

fn read_mrs_header(reader: &mut impl Read, behavior: u8) -> Result<i64, RulesetError> {
    if read_array::<4>(reader)? != *MRS_MAGIC {
        return Err(RulesetError::Invalid("magic bytes"));
    }
    if read_u8(reader)? != behavior {
        return Err(RulesetError::Invalid("behavior"));
    }
    let count = read_i64(reader)?;
    if count < 1 {
        return Err(RulesetError::Invalid("rule count"));
    }
    let extra_length = read_positive_or_zero_length(reader, "extra length")?;
    let mut extra = vec![0; extra_length];
    reader.read_exact(&mut extra)?;
    Ok(count)
}

fn read_positive_or_zero_length(
    reader: &mut impl Read,
    description: &'static str,
) -> Result<usize, RulesetError> {
    usize::try_from(read_i64(reader)?).map_err(|_| RulesetError::Invalid(description))
}

fn read_positive_length(
    reader: &mut impl Read,
    description: &'static str,
) -> Result<usize, RulesetError> {
    read_positive_or_zero_length(reader, description).and_then(|length| {
        (length > 0)
            .then_some(length)
            .ok_or(RulesetError::Invalid(description))
    })
}

fn read_words(reader: &mut impl Read, description: &'static str) -> Result<Vec<u64>, RulesetError> {
    let length = read_positive_length(reader, description)?;
    (0..length)
        .map(|_| Ok(u64::from_be_bytes(read_array(reader)?)))
        .collect()
}

fn traverse_domain_set(
    leaves: &[u64],
    label_bitmap: &[u64],
    labels: &[u8],
    node_id: usize,
    mut bitmap_index: usize,
    current: &mut Vec<u8>,
    keys: &mut Vec<Vec<u8>>,
) -> Result<(), RulesetError> {
    if bit(leaves, node_id)? {
        keys.push(current.clone());
    }
    loop {
        if bit(label_bitmap, bitmap_index)? {
            return Ok(());
        }
        let label_index = bitmap_index
            .checked_sub(node_id)
            .filter(|index| *index < labels.len())
            .ok_or(RulesetError::Invalid("domain label index"))?;
        current.push(labels[label_index]);
        let next_node_id = count_zero_bits(label_bitmap, bitmap_index + 1)?;
        let next_bitmap_index = select_one_bit(label_bitmap, next_node_id - 1)? + 1;
        traverse_domain_set(
            leaves,
            label_bitmap,
            labels,
            next_node_id,
            next_bitmap_index,
            current,
            keys,
        )?;
        current.pop();
        bitmap_index += 1;
    }
}

fn bit(words: &[u64], index: usize) -> Result<bool, RulesetError> {
    let word = words
        .get(index / 64)
        .ok_or(RulesetError::Invalid("domain bitmap index"))?;
    Ok(word & (1_u64 << (index % 64)) != 0)
}

fn count_zero_bits(words: &[u64], end: usize) -> Result<usize, RulesetError> {
    let mut zeroes = 0;
    for index in 0..end {
        if !bit(words, index)? {
            zeroes += 1;
        }
    }
    Ok(zeroes)
}

fn select_one_bit(words: &[u64], ordinal: usize) -> Result<usize, RulesetError> {
    let mut seen = 0;
    for index in 0..words.len() * 64 {
        if bit(words, index)? {
            if seen == ordinal {
                return Ok(index);
            }
            seen += 1;
        }
    }
    Err(RulesetError::Invalid("domain bitmap terminator"))
}

fn append_range(output: &mut String, start: [u8; 16], end: [u8; 16]) -> Result<(), RulesetError> {
    if let (Some(start), Some(end)) = (mapped_ipv4(start), mapped_ipv4(end)) {
        append_v4_range(output, start, end)
    } else {
        append_v6_range(output, u128::from_be_bytes(start), u128::from_be_bytes(end))
    }
}

fn mapped_ipv4(address: [u8; 16]) -> Option<u32> {
    (address[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        .then(|| u32::from_be_bytes(address[12..].try_into().expect("four-byte suffix")))
}

fn append_v4_range(output: &mut String, start: u32, end: u32) -> Result<(), RulesetError> {
    if start > end {
        return Err(RulesetError::Invalid("descending IPv4 range"));
    }
    let mut current = u64::from(start);
    let end = u64::from(end);
    while current <= end {
        let alignment = if current == 0 {
            32
        } else {
            current.trailing_zeros().min(32)
        };
        let remaining = end - current + 1;
        let capacity = remaining.ilog2();
        let host_bits = alignment.min(capacity);
        let prefix = 32 - host_bits;
        let current_v4 = u32::try_from(current).expect("IPv4 cursor remains within 32 bits");
        writeln!(output, "{}/{}", Ipv4Addr::from(current_v4), prefix)
            .expect("writing to String cannot fail");
        current += 1_u64 << host_bits;
    }
    Ok(())
}

fn append_v6_range(output: &mut String, start: u128, end: u128) -> Result<(), RulesetError> {
    if start > end {
        return Err(RulesetError::Invalid("descending IPv6 range"));
    }
    let mut current = start;
    loop {
        let alignment = if current == 0 {
            128
        } else {
            current.trailing_zeros()
        };
        let capacity = if current == 0 && end == u128::MAX {
            128
        } else {
            let remaining = end - current + 1;
            remaining.ilog2()
        };
        let host_bits = alignment.min(capacity);
        let prefix = 128 - host_bits;
        writeln!(output, "{}/{}", Ipv6Addr::from(current), prefix)
            .expect("writing to String cannot fail");
        if host_bits == 128 {
            break;
        }
        let block = 1_u128 << host_bits;
        if end - current < block {
            break;
        }
        current += block;
    }
    Ok(())
}

fn read_u8(reader: &mut impl Read) -> Result<u8, std::io::Error> {
    Ok(read_array::<1>(reader)?[0])
}

fn read_i64(reader: &mut impl Read) -> Result<i64, std::io::Error> {
    Ok(i64::from_be_bytes(read_array(reader)?))
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], std::io::Error> {
    let mut bytes = [0; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ipcidr_ranges_to_minimal_prefixes() {
        let mut plain = Vec::new();
        plain.extend(MRS_MAGIC);
        plain.push(IPCIDR_BEHAVIOR);
        plain.extend(3_i64.to_be_bytes());
        plain.extend(0_i64.to_be_bytes());
        plain.push(IPCIDR_SET_VERSION);
        plain.extend(2_i64.to_be_bytes());
        plain.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 0]);
        plain.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 3]);
        plain.extend(u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)).to_be_bytes());
        plain.extend(u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)).to_be_bytes());
        let encoded = zstd::stream::encode_all(plain.as_slice(), 0).unwrap();
        assert_eq!(
            ipcidr_mrs_to_text(&encoded).unwrap(),
            b"192.0.2.0/30\n2001:db8::/127\n"
        );
    }

    #[test]
    fn encodes_text_and_yaml_as_merged_ipcidr_ranges() {
        for (source, format) in [
            (
                b"# comment\n192.0.2.0/25\n192.0.2.128/25\n2001:db8::/127\n".as_slice(),
                SourceFormat::Text,
            ),
            (
                b"payload:\n  - 192.0.2.0/25\n  - 192.0.2.128/25\n  - 2001:db8::/127\n".as_slice(),
                SourceFormat::Yaml,
            ),
        ] {
            let encoded = ipcidr_to_mrs(source, format).unwrap();
            assert_eq!(
                ipcidr_mrs_to_text(&encoded).unwrap(),
                b"192.0.2.0/24\n2001:db8::/127\n"
            );
            let decoded = zstd::stream::decode_all(encoded.as_slice()).unwrap();
            assert_eq!(&decoded[5..13], 3_i64.to_be_bytes());
        }
    }

    #[test]
    fn decodes_single_key_domain_set() {
        let mut plain = Vec::new();
        plain.extend(MRS_MAGIC);
        plain.push(DOMAIN_BEHAVIOR);
        plain.extend(1_i64.to_be_bytes());
        plain.extend(0_i64.to_be_bytes());
        plain.push(1);
        plain.extend(1_i64.to_be_bytes());
        plain.extend(2_u64.to_be_bytes());
        plain.extend(1_i64.to_be_bytes());
        plain.extend(6_u64.to_be_bytes());
        plain.extend(1_i64.to_be_bytes());
        plain.push(b'a');
        let encoded = zstd::stream::encode_all(plain.as_slice(), 0).unwrap();
        assert_eq!(domain_mrs_to_text(&encoded).unwrap(), b"a\n");
    }
}
