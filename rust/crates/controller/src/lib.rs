use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rewrite_config::Config;
use rewrite_dns::DnsService;
use rewrite_state::RuntimeState;
use serde::Serialize;
use serde_json::json;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const MAX_REQUEST_HEAD: usize = 64 * 1024;
const MAX_DNS_MESSAGE: usize = 65_535;
const MAX_CHUNKED_BODY_WIRE: usize = 128 * 1024;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("controller I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("controller JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid controller request")]
    InvalidRequest,
}

struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// Serves the declared REST subset and Phase 4F15 DNS control surface.
pub async fn serve(
    listener: TcpListener,
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    state: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let config = Arc::clone(&config.borrow());
                        let dns_service = Arc::clone(&dns_service);
                        let state = Arc::clone(&state);
                        let connection_shutdown = shutdown.child_token();
                        tasks.spawn(async move {
                            tokio::select! {
                                () = connection_shutdown.cancelled() => {}
                                _ = handle(stream, &dns_service, &config, &state) => {}
                            }
                        });
                    }
                    Err(error) => {
                        state.log("error", format!("controller accept failed: {error}"));
                        break;
                    }
                }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    drop(listener);
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
}

async fn handle(
    mut stream: TcpStream,
    dns_service: &DnsService,
    config: &Config,
    state: &RuntimeState,
) -> Result<(), ControllerError> {
    let request = read_request(&mut stream).await?;
    let path = request.path.split('?').next().unwrap_or(&request.path);
    if is_doh_path(path, &config.external_doh_server) {
        return handle_doh(&mut stream, &request, dns_service, config, state).await;
    }
    if !config.secret.is_empty()
        && request.headers.get("authorization") != Some(&format!("Bearer {}", config.secret))
    {
        return write_json(&mut stream, 401, &json!({"message": "Unauthorized"})).await;
    }
    if request.method == "POST" && path == "/cache/dns/flush" {
        dns_service.clear_cache().await;
        return write_empty(&mut stream, 204).await;
    }
    if request.method == "POST" && path == "/cache/fakeip/flush" {
        if let Some(fake) = config.dns.as_ref().and_then(|dns| dns.fake_ip.as_ref()) {
            state.flush_fake_ips(fake.ipv4_range, fake.ipv6_range, config.store_fake_ip);
        }
        return write_empty(&mut stream, 204).await;
    }
    if matches!(path, "/cache/dns/flush" | "/cache/fakeip/flush") {
        return write_empty(&mut stream, 405).await;
    }
    if path == "/dns/query" && request.method != "GET" {
        return write_empty(&mut stream, 405).await;
    }
    if request.method != "GET" {
        return write_json(&mut stream, 405, &json!({"message": "Method Not Allowed"})).await;
    }
    match path {
        "/" => write_json(&mut stream, 200, &json!({"hello": "mihomo"})).await,
        "/version" => {
            write_json(
                &mut stream,
                200,
                &json!({"meta": true, "version": env!("CARGO_PKG_VERSION")}),
            )
            .await
        }
        "/configs" | "/configs/" => write_json(&mut stream, 200, &config_snapshot(config)).await,
        "/connections" | "/connections/" => {
            write_json(&mut stream, 200, &state.connections()).await
        }
        "/traffic" => stream_traffic(&mut stream, state).await,
        "/logs" => stream_logs(&mut stream, state, &request.path).await,
        "/dns/query" => {
            let Some(dns) = config.dns.as_ref() else {
                return write_json(
                    &mut stream,
                    500,
                    &json!({"message": "DNS section is disabled"}),
                )
                .await;
            };
            let parameters: BTreeMap<_, _> = request
                .path
                .split_once('?')
                .map(|(_, query)| {
                    url::form_urlencoded::parse(query.as_bytes())
                        .into_owned()
                        .collect()
                })
                .unwrap_or_default();
            let name = parameters.get("name").map_or("", String::as_str);
            let record_type = parameters
                .get("type")
                .map_or(Some(1), |value| dns_record_type(value));
            let Some(record_type) = record_type else {
                return write_json(&mut stream, 400, &json!({"message": "invalid query type"}))
                    .await;
            };
            match dns_service.rest_query(dns, name, record_type).await {
                Ok(response) => write_json(&mut stream, 200, &response).await,
                Err(error) => {
                    write_json(&mut stream, 500, &json!({"message": error.to_string()})).await
                }
            }
        }
        _ => write_json(&mut stream, 404, &json!({"message": "Not Found"})).await,
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<Request, ControllerError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 2048];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await?;
        if read == 0 || bytes.len() + read > MAX_REQUEST_HEAD {
            return Err(ControllerError::InvalidRequest);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let head_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ControllerError::InvalidRequest)?
        + 4;
    let text =
        std::str::from_utf8(&bytes[..head_end]).map_err(|_| ControllerError::InvalidRequest)?;
    let mut lines = text.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or(ControllerError::InvalidRequest)?
        .split_whitespace();
    let method = request_line
        .next()
        .ok_or(ControllerError::InvalidRequest)?
        .to_owned();
    let path = request_line
        .next()
        .ok_or(ControllerError::InvalidRequest)?
        .to_owned();
    if request_line.next().is_none() || request_line.next().is_some() {
        return Err(ControllerError::InvalidRequest);
    }
    let headers: BTreeMap<_, _> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_lowercase(), value.trim().to_owned()))
        .collect();
    let content_length = headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| ControllerError::InvalidRequest)
        })
        .transpose()?
        .unwrap_or(0)
        .min(MAX_DNS_MESSAGE);
    let mut body = bytes[head_end..].to_vec();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        loop {
            if let Some(decoded) = decode_chunked_body(&body)? {
                body = decoded;
                break;
            }
            if body.len() > MAX_CHUNKED_BODY_WIRE {
                return Err(ControllerError::InvalidRequest);
            }
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(ControllerError::InvalidRequest);
            }
            body.extend_from_slice(&chunk[..read]);
        }
    } else {
        while body.len() < content_length {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(ControllerError::InvalidRequest);
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(content_length);
    }
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn decode_chunked_body(bytes: &[u8]) -> Result<Option<Vec<u8>>, ControllerError> {
    let mut offset = 0;
    let mut body = Vec::new();
    loop {
        let Some(line_end) = bytes[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|position| offset + position)
        else {
            return Ok(None);
        };
        let size_text = std::str::from_utf8(&bytes[offset..line_end])
            .map_err(|_| ControllerError::InvalidRequest)?;
        let size_text = size_text.split(';').next().unwrap_or(size_text).trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| ControllerError::InvalidRequest)?;
        offset = line_end + 2;
        if size == 0 {
            if bytes.len() < offset + 2 {
                return Ok(None);
            }
            if &bytes[offset..offset + 2] == b"\r\n"
                || bytes[offset..]
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
            {
                return Ok(Some(body));
            }
            return Ok(None);
        }
        let chunk_end = offset
            .checked_add(size)
            .ok_or(ControllerError::InvalidRequest)?;
        if bytes.len() < chunk_end + 2 {
            return Ok(None);
        }
        if &bytes[chunk_end..chunk_end + 2] != b"\r\n" {
            return Err(ControllerError::InvalidRequest);
        }
        let remaining = MAX_DNS_MESSAGE.saturating_sub(body.len());
        body.extend_from_slice(&bytes[offset..chunk_end.min(offset + remaining)]);
        if body.len() == MAX_DNS_MESSAGE {
            return Ok(Some(body));
        }
        offset = chunk_end + 2;
    }
}

fn is_doh_path(path: &str, mount: &str) -> bool {
    mount.starts_with('/')
        && (path == mount
            || path
                .strip_prefix(mount)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

async fn handle_doh(
    stream: &mut TcpStream,
    request: &Request,
    dns_service: &DnsService,
    config: &Config,
    state: &RuntimeState,
) -> Result<(), ControllerError> {
    if config.dns.is_none() {
        return write_plain(stream, 500, "DNS section is disabled").await;
    }
    let packet = match request.method.as_str() {
        "GET" => {
            let parameters: BTreeMap<_, _> = request
                .path
                .split_once('?')
                .map(|(_, query)| {
                    url::form_urlencoded::parse(query.as_bytes())
                        .into_owned()
                        .collect()
                })
                .unwrap_or_default();
            let encoded = parameters.get("dns").map_or("", String::as_str);
            match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(packet) => packet,
                Err(error) => return write_plain(stream, 500, &error.to_string()).await,
            }
        }
        "POST" => {
            if request.headers.get("content-type").map(String::as_str)
                != Some("application/dns-message")
            {
                return write_plain(stream, 500, "invalid content-type").await;
            }
            request.body.clone()
        }
        _ => return write_plain(stream, 405, "method not allowed").await,
    };
    match dns_service.relay_query(config, state, &packet).await {
        Ok(response) => write_dns_message(stream, &response).await,
        Err(error) => write_plain(stream, 500, &error.to_string()).await,
    }
}

fn dns_record_type(value: &str) -> Option<u16> {
    if value.is_empty() {
        return Some(1);
    }
    Some(match value {
        "None" => 0,
        "A" => 1,
        "NS" => 2,
        "MD" => 3,
        "MF" => 4,
        "CNAME" => 5,
        "SOA" => 6,
        "MB" => 7,
        "MG" => 8,
        "MR" => 9,
        "NULL" => 10,
        "PTR" => 12,
        "HINFO" => 13,
        "MINFO" => 14,
        "MX" => 15,
        "TXT" => 16,
        "RP" => 17,
        "AFSDB" => 18,
        "X25" => 19,
        "ISDN" => 20,
        "RT" => 21,
        "NSAP-PTR" => 23,
        "SIG" => 24,
        "KEY" => 25,
        "PX" => 26,
        "GPOS" => 27,
        "AAAA" => 28,
        "LOC" => 29,
        "NXT" => 30,
        "EID" => 31,
        "NIMLOC" => 32,
        "SRV" => 33,
        "ATMA" => 34,
        "NAPTR" => 35,
        "KX" => 36,
        "CERT" => 37,
        "DNAME" => 39,
        "OPT" => 41,
        "APL" => 42,
        "DS" => 43,
        "SSHFP" => 44,
        "IPSECKEY" => 45,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "DHCID" => 49,
        "NSEC3" => 50,
        "NSEC3PARAM" => 51,
        "TLSA" => 52,
        "SMIMEA" => 53,
        "HIP" => 55,
        "NINFO" => 56,
        "RKEY" => 57,
        "TALINK" => 58,
        "CDS" => 59,
        "CDNSKEY" => 60,
        "OPENPGPKEY" => 61,
        "CSYNC" => 62,
        "ZONEMD" => 63,
        "SVCB" => 64,
        "HTTPS" => 65,
        "SPF" => 99,
        "UINFO" => 100,
        "UID" => 101,
        "GID" => 102,
        "UNSPEC" => 103,
        "NID" => 104,
        "L32" => 105,
        "L64" => 106,
        "LP" => 107,
        "EUI48" => 108,
        "EUI64" => 109,
        "NXNAME" => 128,
        "TKEY" => 249,
        "TSIG" => 250,
        "IXFR" => 251,
        "AXFR" => 252,
        "MAILB" => 253,
        "MAILA" => 254,
        "ANY" => 255,
        "URI" => 256,
        "CAA" => 257,
        "AVC" => 258,
        "AMTRELAY" => 260,
        "TA" => 32768,
        "DLV" => 32769,
        "Reserved" => 65535,
        _ => return None,
    })
}

fn config_snapshot(config: &Config) -> serde_json::Value {
    let authentication: Vec<_> = config
        .authentication
        .iter()
        .map(|user| format!("{}:{}", user.username, user.password))
        .collect();
    json!({
        "port": config.port,
        "socks-port": config.socks_port,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": config.mixed_port,
        "authentication": authentication,
        "allow-lan": false,
        "bind-address": "*",
        "mode": config.mode,
        "log-level": config.log_level,
        "ipv6": config.ipv6,
        "interface-name": "",
        "routing-mark": 0,
        "tcp-concurrent": false,
        "etag-support": true,
        "keep-alive-idle": 0,
        "keep-alive-interval": 0,
        "disable-keep-alive": false
    })
}

async fn write_json<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    value: &T,
) -> Result<(), ControllerError> {
    let body = serde_json::to_vec(value)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Error",
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(&body).await?;
    Ok(())
}

async fn write_empty(stream: &mut TcpStream, status: u16) -> Result<(), ControllerError> {
    let reason = match status {
        204 => "No Content",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    stream
        .write_all(
            format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    Ok(())
}

async fn write_plain(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), ControllerError> {
    let reason = match status {
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Error",
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
                message.len()
            )
            .as_bytes(),
        )
        .await?;
    Ok(())
}

async fn write_dns_message(stream: &mut TcpStream, message: &[u8]) -> Result<(), ControllerError> {
    stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                message.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(message).await?;
    Ok(())
}

async fn write_stream_head(stream: &mut TcpStream) -> Result<(), ControllerError> {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await?;
    Ok(())
}

async fn write_chunk<T: Serialize>(
    stream: &mut TcpStream,
    value: &T,
) -> Result<(), ControllerError> {
    let mut body = serde_json::to_vec(value)?;
    body.push(b'\n');
    stream
        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .await?;
    stream.write_all(&body).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}

async fn stream_traffic(
    stream: &mut TcpStream,
    state: &RuntimeState,
) -> Result<(), ControllerError> {
    write_stream_head(stream).await?;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await;
    loop {
        interval.tick().await;
        write_chunk(stream, &state.traffic()).await?;
    }
}

async fn stream_logs(
    stream: &mut TcpStream,
    state: &RuntimeState,
    path: &str,
) -> Result<(), ControllerError> {
    if path.contains("level=invalid") {
        return write_json(stream, 400, &json!({"message": "Body invalid"})).await;
    }
    let mut receiver = state.subscribe_logs();
    write_stream_head(stream).await?;
    loop {
        match receiver.recv().await {
            Ok(event) => write_chunk(stream, &event).await?,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_go_dns_record_type_names() {
        assert_eq!(dns_record_type(""), Some(1));
        assert_eq!(dns_record_type("SOA"), Some(6));
        assert_eq!(dns_record_type("HTTPS"), Some(65));
        assert_eq!(dns_record_type("NSAP-PTR"), Some(23));
        assert_eq!(dns_record_type("Reserved"), Some(u16::MAX));
        assert_eq!(dns_record_type("soa"), None);
        assert_eq!(dns_record_type("TYPE65"), None);
    }

    #[test]
    fn external_doh_mount_has_segment_boundary() {
        assert!(is_doh_path("/dns-query", "/dns-query"));
        assert!(is_doh_path("/dns-query/child", "/dns-query"));
        assert!(!is_doh_path("/dns-query-other", "/dns-query"));
        assert!(!is_doh_path("/dns-query", "dns-query"));
    }

    #[test]
    fn decodes_chunked_dns_bodies_and_trailers() {
        assert_eq!(
            decode_chunked_body(b"3;fixture=yes\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
                .expect("valid chunks"),
            Some(b"abcde".to_vec())
        );
        assert_eq!(
            decode_chunked_body(b"1\r\na\r\n0\r\nFixture: yes\r\n\r\n").expect("valid trailer"),
            Some(b"a".to_vec())
        );
        assert!(
            decode_chunked_body(b"3\r\nab")
                .expect("incomplete chunks are not malformed")
                .is_none()
        );
    }
}
