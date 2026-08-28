use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::model::{
    DOMAIN_BEHAVIOR, IPCIDR_BEHAVIOR, IPCIDR_SET_VERSION, MRS_MAGIC, RulesetError, SourceFormat,
};
use crate::source::parse_rules;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpRange {
    V4(u32, u32),
    V6(u128, u128),
}

struct DomainSetEncoding {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
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

/// Converts newline-delimited or YAML domain rules to an MRS v1 zstd frame.
///
/// Invalid domain entries are ignored like the oracle. At least one valid
/// entry is required.
///
/// # Errors
///
/// Returns [`RulesetError`] for malformed YAML, an absent YAML payload, an
/// empty valid rule set or an encoding failure.
pub fn domain_to_mrs(source: &[u8], format: SourceFormat) -> Result<Vec<u8>, RulesetError> {
    let rules = parse_rules(source, format)?;
    let mut count = 0_i64;
    let mut domains = BTreeSet::new();
    for rule in rules {
        if let Some(keys) = normalized_domain_keys(&rule) {
            count += 1;
            domains.extend(keys);
        }
    }
    if count == 0 {
        return Err(RulesetError::Empty);
    }
    let mut reversed = domains
        .into_iter()
        .map(|domain| domain.chars().rev().collect::<String>().into_bytes())
        .collect::<Vec<_>>();
    reversed.sort_unstable();
    let domain_set = build_domain_set(&reversed)?;

    let mut plain = Vec::new();
    plain.extend(MRS_MAGIC);
    plain.push(DOMAIN_BEHAVIOR);
    plain.extend(count.to_be_bytes());
    plain.extend(0_i64.to_be_bytes());
    plain.push(1);
    write_words(&mut plain, &domain_set.leaves)?;
    write_words(&mut plain, &domain_set.label_bitmap)?;
    plain.extend(
        i64::try_from(domain_set.labels.len())
            .map_err(|_| RulesetError::Invalid("too many domain labels"))?
            .to_be_bytes(),
    );
    plain.extend(domain_set.labels);
    Ok(zstd::stream::encode_all(plain.as_slice(), 0)?)
}

fn normalized_domain_keys(rule: &str) -> Option<Vec<String>> {
    if rule.is_empty() || rule.contains('/') || rule.ends_with('.') || rule.trim() != rule {
        return None;
    }
    let normalized = rule.to_lowercase();
    let parts = normalized.split('.').collect::<Vec<_>>();
    if parts.len() == 1 && parts[0].is_empty()
        || parts.len() > 1 && parts[1..].iter().any(|part| part.is_empty())
    {
        return None;
    }
    for (index, part) in parts.iter().enumerate() {
        if part.contains('+') && (*part != "+" || index != 0 || parts.len() == 1) {
            return None;
        }
        if part.contains('*') && *part != "*" {
            return None;
        }
    }
    if parts[0] == "+" {
        let suffix = parts[1..].join(".");
        Some(vec![suffix, normalized])
    } else if parts[0].is_empty() {
        Some(vec![format!("+{normalized}")])
    } else {
        Some(vec![normalized])
    }
}

fn build_domain_set(keys: &[Vec<u8>]) -> Result<DomainSetEncoding, RulesetError> {
    if keys.is_empty() {
        return Err(RulesetError::Empty);
    }
    let mut leaves = Vec::new();
    let mut label_bitmap = Vec::new();
    let mut labels = Vec::new();
    let mut bitmap_index = 0;
    let mut queue = vec![(0_usize, keys.len(), 0_usize)];
    let mut node_index = 0;
    while node_index < queue.len() {
        let (mut start, end, column) = queue[node_index];
        if column == keys[start].len() {
            start += 1;
            set_bitmap_bit(&mut leaves, node_index, true);
        }
        let mut cursor = start;
        while cursor < end {
            let first = cursor;
            let label = *keys[cursor]
                .get(column)
                .ok_or(RulesetError::Invalid("domain trie column"))?;
            while cursor < end && keys[cursor].get(column) == Some(&label) {
                cursor += 1;
            }
            queue.push((first, cursor, column + 1));
            labels.push(label);
            set_bitmap_bit(&mut label_bitmap, bitmap_index, false);
            bitmap_index += 1;
        }
        set_bitmap_bit(&mut label_bitmap, bitmap_index, true);
        bitmap_index += 1;
        node_index += 1;
    }
    Ok(DomainSetEncoding {
        leaves,
        label_bitmap,
        labels,
    })
}

fn set_bitmap_bit(words: &mut Vec<u64>, index: usize, value: bool) {
    while index / 64 >= words.len() {
        words.push(0);
    }
    if value {
        words[index / 64] |= 1_u64 << (index % 64);
    }
}

fn write_words(output: &mut Vec<u8>, words: &[u64]) -> Result<(), RulesetError> {
    output.extend(
        i64::try_from(words.len())
            .map_err(|_| RulesetError::Invalid("domain bitmap too large"))?
            .to_be_bytes(),
    );
    for word in words {
        output.extend(word.to_be_bytes());
    }
    Ok(())
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
