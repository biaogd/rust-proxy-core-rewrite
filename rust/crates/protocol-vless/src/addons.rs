//! VLESS protobuf addons (flow field).

const FLOW_FIELD_TAG: u8 = 0x0a; // (field 1 << 3) | wire type 2

fn write_varint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buffer.push((value as u8) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
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
}
