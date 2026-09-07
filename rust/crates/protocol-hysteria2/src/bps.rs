//! Clash/Go `up`/`down` bandwidth string parsing (`utils.StringToBps`).

/// Parses a Clash bandwidth string into bytes/sec.
///
/// Bare integers are treated as Mbps. Empty string → `0`. Invalid → `None`.
#[must_use]
pub fn parse_bps(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(0);
    }
    if let Ok(value) = trimmed.parse::<u64>() {
        // Go: bare integer → N Mbps → bytes/sec.
        return Some(value.saturating_mul(1_000_000 / 8));
    }
    // ^(\d+)\s*([KMGT]?)([Bb])ps$
    let bytes = trimmed.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == 0 {
        return None;
    }
    let number: u64 = trimmed[..index].parse().ok()?;
    let mut rest = trimmed[index..].trim_start();
    let mut scale: u64 = 1;
    if let Some(prefix) = rest.chars().next() {
        match prefix {
            'K' => {
                scale = 1_000;
                rest = rest[1..].trim_start();
            }
            'M' => {
                scale = 1_000_000;
                rest = rest[1..].trim_start();
            }
            'G' => {
                scale = 1_000_000_000;
                rest = rest[1..].trim_start();
            }
            'T' => {
                scale = 1_000_000_000_000;
                rest = rest[1..].trim_start();
            }
            _ => {}
        }
    }
    let is_bits = match rest {
        "bps" => true,
        "Bps" => false,
        _ => return None,
    };
    let mut n = number.saturating_mul(scale);
    if is_bits {
        n /= 8;
    }
    Some(n)
}

/// Parse ports list (`443,8443,9000-9002`). Rejects `*` / `all` (unbounded).
#[must_use]
pub fn parse_ports(spec: &str) -> Option<Vec<u16>> {
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.eq_ignore_ascii_case("all") {
        return None;
    }
    let mut ports = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        if let Some((start, end)) = part.split_once('-') {
            let mut lo: u16 = start.trim().parse().ok()?;
            let mut hi: u16 = end.trim().parse().ok()?;
            if lo > hi {
                std::mem::swap(&mut lo, &mut hi);
            }
            if u32::from(hi) - u32::from(lo) > 4096 {
                return None;
            }
            ports.extend(lo..=hi);
        } else {
            ports.push(part.parse().ok()?);
        }
    }
    if ports.is_empty() {
        return None;
    }
    ports.sort_unstable();
    ports.dedup();
    Some(ports)
}

/// Parse hop-interval as seconds (`15` or `10-30`).
#[must_use]
pub fn parse_hop_interval(spec: &str) -> Option<(u64, u64)> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Some((0, 0));
    }
    if let Some((lo, hi)) = trimmed.split_once('-') {
        let min: u64 = lo.trim().parse().ok()?;
        let max: u64 = hi.trim().parse().ok()?;
        if min == 0 || max == 0 {
            return None;
        }
        return Some((min.min(max), min.max(max)));
    }
    let value: u64 = trimmed.parse().ok()?;
    if value == 0 {
        return None;
    }
    Some((value, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mbps_and_bare() {
        assert_eq!(parse_bps("30 Mbps"), Some(30_000_000 / 8));
        assert_eq!(parse_bps("30"), Some(30_000_000 / 8));
        assert_eq!(parse_bps("800 Kbps"), Some(800_000 / 8));
        assert_eq!(parse_bps(""), Some(0));
        assert_eq!(parse_bps("nope"), None);
    }

    #[test]
    fn parses_port_lists() {
        assert_eq!(parse_ports("443,445"), Some(vec![443, 445]));
        assert_eq!(parse_ports("100-103"), Some(vec![100, 101, 102, 103]));
        assert!(parse_ports("*").is_none());
    }
}
