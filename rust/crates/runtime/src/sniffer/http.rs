//! HTTP/1 Host extractor (HTTP/2 deferred to a later W2.2 slice).

use std::net::IpAddr;

use super::SniffError;

const HTTP_METHODS: &[&[u8]] = &[
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"PATCH", b"TRACE",
];

const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub(super) fn sniff_http(bytes: &[u8]) -> Result<String, SniffError> {
    if bytes.len() < H2_CLIENT_PREFACE.len() {
        if H2_CLIENT_PREFACE.starts_with(bytes) {
            return Err(SniffError::Need(bytes.len() + 1));
        }
        return sniff_http1(bytes);
    }
    if bytes.starts_with(H2_CLIENT_PREFACE) {
        // HTTP/2 authority sniffing deferred; do not block TLS on the same port.
        return Err(SniffError::Fatal);
    }
    sniff_http1(bytes)
}

fn sniff_http1(bytes: &[u8]) -> Result<String, SniffError> {
    let Some((method, _rest)) = split_once(bytes, b" ") else {
        if is_http_method_prefix(bytes) {
            return Err(SniffError::Need(bytes.len() + 1));
        }
        return Err(SniffError::Fatal);
    };
    if !is_http_method(method) {
        return Err(SniffError::Fatal);
    }
    let Some((req_line, _)) = split_once(bytes, b"\r\n") else {
        return Err(SniffError::Need(bytes.len() + 1));
    };
    if req_line.len() < 14 {
        return Err(SniffError::Fatal);
    }
    let Some((_, after_method)) = split_once(req_line, b" ") else {
        return Err(SniffError::Fatal);
    };
    let Some((uri, _)) = split_once(after_method, b" ") else {
        return Err(SniffError::Fatal);
    };
    if uri.is_empty() {
        return Err(SniffError::Fatal);
    }

    match uri[0] {
        b'/' | b'*' => parse_header_host_h1(bytes),
        _ => {
            let mut uri = uri;
            if let Some((_, after_scheme)) = split_once(uri, b"://") {
                uri = after_scheme;
            }
            if let Some(idx) = uri.iter().position(|b| matches!(b, b'/' | b'?' | b'#')) {
                uri = &uri[..idx];
            }
            if let Some((_, after_at)) = split_once(uri, b"@") {
                uri = after_at;
            }
            match parse_host(uri) {
                Ok(host) => Ok(host),
                Err(SniffError::Fatal) => parse_header_host_h1(bytes),
                Err(other) => Err(other),
            }
        }
    }
}

fn parse_header_host_h1(bytes: &[u8]) -> Result<String, SniffError> {
    let mut rest = bytes;
    loop {
        let Some((line, tail)) = split_once(rest, b"\r\n") else {
            return Err(SniffError::Need(bytes.len() + 1));
        };
        if line.is_empty() {
            return Err(SniffError::Fatal);
        }
        rest = tail;
        let Some((key, val)) = split_once(line, b":") else {
            continue;
        };
        if !eq_ignore_ascii_case(key, b"host") {
            continue;
        }
        return parse_host(trim_ascii(val));
    }
}

fn parse_host(raw: &[u8]) -> Result<String, SniffError> {
    if raw.is_empty() {
        return Err(SniffError::Fatal);
    }
    let mut hs = String::from_utf8_lossy(raw).into_owned();
    if let Some((host, _port)) = split_host_port(&hs) {
        hs = host.to_owned();
    }
    if hs.starts_with('[') && hs.ends_with(']') {
        hs = hs[1..hs.len() - 1].to_owned();
    }
    hs = hs.trim_end_matches('.').to_ascii_lowercase();
    if hs.is_empty() {
        return Err(SniffError::Fatal);
    }
    if hs.parse::<IpAddr>().is_ok() {
        return Err(SniffError::Fatal);
    }
    Ok(hs)
}

fn split_host_port(value: &str) -> Option<(&str, &str)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host, port));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    Some((host, port))
}

fn is_http_method(method: &[u8]) -> bool {
    HTTP_METHODS
        .iter()
        .any(|candidate| eq_ignore_ascii_case(method, candidate))
}

fn is_http_method_prefix(prefix: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|method| {
        prefix.len() <= method.len() && eq_ignore_ascii_case(prefix, &method[..prefix.len()])
    })
}

fn split_once<'a>(input: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    input
        .windows(sep.len())
        .position(|window| window == sep)
        .map(|idx| (&input[..idx], &input[idx + sep.len()..]))
}

fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |idx| idx + 1);
    if start >= end {
        &[]
    } else {
        &value[start..end]
    }
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: www.Example.com.\r\n\r\n";
        assert_eq!(sniff_http(req).expect("host"), "www.example.com");
    }

    #[test]
    fn extracts_absolute_uri_host() {
        let req = b"GET http://docs.example.org/path HTTP/1.1\r\n\r\n";
        assert_eq!(sniff_http(req).expect("host"), "docs.example.org");
    }

    #[test]
    fn needs_more_for_partial_request() {
        let req = b"GET / HTTP/1.1\r\nHo";
        assert!(matches!(sniff_http(req), Err(SniffError::Need(_))));
    }
}
