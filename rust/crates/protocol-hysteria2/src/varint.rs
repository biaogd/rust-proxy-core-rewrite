//! QUIC varint helpers matching quic-go / Hysteria framing.

use crate::Hysteria2ProtocolError;

pub(crate) fn write_into(out: &mut Vec<u8>, value: u64) -> Result<(), Hysteria2ProtocolError> {
    if value <= 63 {
        out.push(u8::try_from(value).expect("fits"));
    } else if value <= 16_383 {
        out.push(0x40 | u8::try_from(value >> 8).expect("fits"));
        out.push(u8::try_from(value & 0xff).expect("fits"));
    } else if value <= 1_073_741_823 {
        out.push(0x80 | u8::try_from(value >> 24).expect("fits"));
        out.push(u8::try_from((value >> 16) & 0xff).expect("fits"));
        out.push(u8::try_from((value >> 8) & 0xff).expect("fits"));
        out.push(u8::try_from(value & 0xff).expect("fits"));
    } else if value <= 4_611_686_018_427_387_903 {
        out.push(0xc0 | u8::try_from(value >> 56).expect("fits"));
        out.push(u8::try_from((value >> 48) & 0xff).expect("fits"));
        out.push(u8::try_from((value >> 40) & 0xff).expect("fits"));
        out.push(u8::try_from((value >> 32) & 0xff).expect("fits"));
        out.push(u8::try_from((value >> 24) & 0xff).expect("fits"));
        out.push(u8::try_from((value >> 16) & 0xff).expect("fits"));
        out.push(u8::try_from((value >> 8) & 0xff).expect("fits"));
        out.push(u8::try_from(value & 0xff).expect("fits"));
    } else {
        return Err(Hysteria2ProtocolError::Protocol(
            "varint value exceeds QUIC maximum".to_owned(),
        ));
    }
    Ok(())
}

/// Decode one QUIC varint from `buf`. Returns `(value, bytes_consumed)`.
pub(crate) fn read_from(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let prefix = first >> 6;
    let remaining = match prefix {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 7,
        _ => return None,
    };
    if buf.len() < 1 + remaining {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    if remaining > 0 {
        for byte in &buf[1..=remaining] {
            value = (value << 8) | u64::from(*byte);
        }
    }
    Some((value, 1 + remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_known_widths() {
        let mut out = Vec::new();
        write_into(&mut out, 0x401).unwrap();
        assert_eq!(out, vec![0x44, 0x01]);
    }
}
