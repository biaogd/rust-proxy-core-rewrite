//! TLS ClientHello SNI extractor (mirrors Go `SniffTLS` / `ReadClientHello`).

use super::SniffError;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_MAX_PLAINTEXT: usize = 1 << 14;

pub(super) fn sniff_tls(bytes: &[u8]) -> Result<String, SniffError> {
    let mut client_hello = Vec::new();
    let mut wire_offset = 0;

    loop {
        if bytes.len().saturating_sub(wire_offset) < TLS_RECORD_HEADER_LEN {
            return Err(SniffError::Need(wire_offset + TLS_RECORD_HEADER_LEN));
        }
        let header = &bytes[wire_offset..wire_offset + TLS_RECORD_HEADER_LEN];
        if header[0] != TLS_RECORD_TYPE_HANDSHAKE || header[1] != 3 {
            return Err(SniffError::Fatal);
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len > TLS_MAX_PLAINTEXT || record_len == 0 {
            return Err(SniffError::Fatal);
        }
        let payload_offset = wire_offset + TLS_RECORD_HEADER_LEN;
        let record_end = payload_offset + record_len;
        let payload_end = bytes.len().min(record_end).max(payload_offset);
        let payload = &bytes[payload_offset..payload_end];
        if wire_offset == 0 {
            client_hello.clear();
            client_hello.extend_from_slice(payload);
        } else {
            client_hello.extend_from_slice(payload);
        }

        match read_client_hello(&client_hello) {
            Ok(name) => return Ok(name),
            Err(SniffError::Need(need)) => {
                if payload_end < record_end {
                    let missing = need.saturating_sub(client_hello.len());
                    let remaining = record_end - payload_end;
                    let advance = missing.min(remaining);
                    return Err(SniffError::Need(payload_end + advance));
                }
                wire_offset = record_end;
            }
            Err(other) => return Err(other),
        }
    }
}

fn read_client_hello(data: &[u8]) -> Result<String, SniffError> {
    if data.is_empty() {
        return Err(SniffError::Need(1));
    }
    if data[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SniffError::Fatal);
    }
    if data.len() < TLS_HANDSHAKE_HEADER_LEN {
        return Err(SniffError::Need(TLS_HANDSHAKE_HEADER_LEN));
    }
    let hello_size = client_hello_size(data)?;
    let data = if data.len() > hello_size {
        &data[..hello_size]
    } else {
        data
    };
    let need = |length: usize| -> Result<(), SniffError> {
        if length > hello_size {
            return Err(SniffError::Fatal);
        }
        if data.len() < length {
            return Err(SniffError::Need(length));
        }
        Ok(())
    };

    let mut offset = TLS_HANDSHAKE_HEADER_LEN + 2 + 32;
    need(offset + 1)?;
    let session_id_len = usize::from(data[offset]);
    if session_id_len > 32 {
        return Err(SniffError::Fatal);
    }
    offset += 1;
    need(offset + session_id_len)?;
    offset += session_id_len;

    need(offset + 2)?;
    let cipher_suite_len = usize::from(data[offset]) << 8 | usize::from(data[offset + 1]);
    if cipher_suite_len % 2 == 1 {
        return Err(SniffError::Fatal);
    }
    offset += 2;
    need(offset + cipher_suite_len)?;
    offset += cipher_suite_len;

    need(offset + 1)?;
    let compression_methods_len = usize::from(data[offset]);
    offset += 1;
    need(offset + compression_methods_len)?;
    offset += compression_methods_len;

    if offset == hello_size {
        return Err(SniffError::Fatal);
    }
    need(offset + 2)?;
    let extensions_length = usize::from(data[offset]) << 8 | usize::from(data[offset + 1]);
    offset += 2;
    let extensions_end = offset + extensions_length;
    if extensions_end != hello_size {
        return Err(SniffError::Fatal);
    }

    while offset < extensions_end {
        need(offset + 4)?;
        let extension = u16::from(data[offset]) << 8 | u16::from(data[offset + 1]);
        let length = usize::from(data[offset + 2]) << 8 | usize::from(data[offset + 3]);
        offset += 4;
        let extension_end = offset + length;
        if extension_end > extensions_end {
            return Err(SniffError::Fatal);
        }

        if extension == 0x00 {
            if length < 2 {
                return Err(SniffError::Fatal);
            }
            need(offset + 2)?;
            let names_len = usize::from(data[offset]) << 8 | usize::from(data[offset + 1]);
            offset += 2;
            let names_end = offset + names_len;
            if names_end != extension_end {
                return Err(SniffError::Fatal);
            }
            while offset < names_end {
                need(offset + 3)?;
                let name_type = data[offset];
                let name_len = usize::from(data[offset + 1]) << 8 | usize::from(data[offset + 2]);
                offset += 3;
                let name_end = offset + name_len;
                if name_end > names_end {
                    return Err(SniffError::Fatal);
                }
                need(name_end)?;
                if name_type == 0 {
                    let server_name = std::str::from_utf8(&data[offset..name_end])
                        .map_err(|_| SniffError::Fatal)?;
                    if server_name.ends_with('.') {
                        return Err(SniffError::Fatal);
                    }
                    return Ok(server_name.to_owned());
                }
                offset = name_end;
            }
        } else {
            if extension_end == extensions_end {
                return Err(SniffError::Fatal);
            }
            need(extension_end)?;
            offset = extension_end;
        }
    }

    Err(SniffError::Fatal)
}

fn client_hello_size(data: &[u8]) -> Result<usize, SniffError> {
    if data.len() < TLS_HANDSHAKE_HEADER_LEN {
        return Err(SniffError::Need(TLS_HANDSHAKE_HEADER_LEN));
    }
    if data[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SniffError::Fatal);
    }
    let body_len =
        usize::from(data[1]) << 16 | usize::from(data[2]) << 8 | usize::from(data[3]);
    Ok(TLS_HANDSHAKE_HEADER_LEN + body_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello_with_sni(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let mut extensions = Vec::new();
        // server_name extension
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&(sni_bytes.len() as u16 + 3).to_be_bytes()); // names len
        server_name.push(0); // host_name
        server_name.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        server_name.extend_from_slice(sni_bytes);

        extensions.extend_from_slice(&0u16.to_be_bytes()); // type server_name
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1); // compression methods len
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = body.len();
        handshake.push(((len >> 16) & 0xff) as u8);
        handshake.push(((len >> 8) & 0xff) as u8);
        handshake.push((len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_RECORD_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni() {
        let bytes = client_hello_with_sni("www.example.com");
        assert_eq!(sniff_tls(&bytes).expect("sni"), "www.example.com");
    }

    #[test]
    fn needs_more_data() {
        let bytes = client_hello_with_sni("example.com");
        let err = sniff_tls(&bytes[..10]).expect_err("partial");
        assert!(matches!(err, SniffError::Need(_)));
    }
}
