//! VLESS protobuf addons (flow field).

const FLOW_FIELD_TAG: u8 = 0x0a; // (field 1 << 3) | wire type 2

fn write_varint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        let byte = u8::try_from(value & 0x7f).expect("masked protobuf varint byte");
        buffer.push(byte | 0x80);
        value >>= 7;
    }
    buffer.push(u8::try_from(value).expect("final protobuf varint byte"));
}

fn read_varint(bytes: &[u8]) -> Result<(u64, usize), String> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for (index, byte) in bytes.iter().enumerate() {
        let chunk = u64::from(byte & 0x7f);
        value |= chunk << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err("protobuf varint exceeds u64".to_owned());
        }
    }
    Err("truncated protobuf varint".to_owned())
}

/// Encodes the `flow` addon for VLESS request headers.
pub fn encode_flow_addon(flow: &str) -> Vec<u8> {
    let flow_bytes = flow.as_bytes();
    let mut buffer = Vec::with_capacity(2 + flow_bytes.len());
    buffer.push(FLOW_FIELD_TAG);
    write_varint(&mut buffer, flow_bytes.len() as u64);
    buffer.extend_from_slice(flow_bytes);
    buffer
}

/// Decodes the `flow` addon from protobuf field 1 (tag `0x0a`).
///
/// Returns `Ok(None)` when the addon bytes are empty or omit the flow field.
///
/// # Errors
///
/// Returns an error when the protobuf framing is malformed or the flow string
/// is not valid UTF-8.
pub fn decode_flow_addon(bytes: &[u8]) -> Result<Option<String>, String> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut offset = 0;
    let mut flow = None;
    while offset < bytes.len() {
        let tag = bytes[offset];
        offset += 1;
        let (length, consumed) = read_varint(&bytes[offset..])?;
        offset += consumed;
        let length = usize::try_from(length).map_err(|_| "VLESS addon length exceeds usize")?;
        if offset + length > bytes.len() {
            return Err("truncated VLESS addon field".to_owned());
        }
        let value = &bytes[offset..offset + length];
        offset += length;
        if tag == FLOW_FIELD_TAG {
            let text = std::str::from_utf8(value)
                .map_err(|_| "VLESS flow addon is not UTF-8".to_owned())?;
            flow = Some(text.to_owned());
        }
    }
    Ok(flow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_xtls_rprx_vision_addon() {
        let encoded = encode_flow_addon("xtls-rprx-vision");
        assert_eq!(
            encoded,
            b"\x0a\x10xtls-rprx-vision".to_vec(),
            "protobuf field 1 length-delimited flow string"
        );
    }

    #[test]
    fn decodes_xtls_rprx_vision_addon() {
        let encoded = encode_flow_addon("xtls-rprx-vision");
        assert_eq!(
            decode_flow_addon(&encoded).expect("decode"),
            Some("xtls-rprx-vision".to_owned())
        );
    }

    #[test]
    fn empty_addon_has_no_flow() {
        assert_eq!(decode_flow_addon(&[]).expect("empty"), None);
    }
}
