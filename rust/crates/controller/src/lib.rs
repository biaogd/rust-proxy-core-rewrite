use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{any, get};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{StreamExt, stream};
use rewrite_config::Config;
use rewrite_dns::DnsService;
use rewrite_state::RuntimeState;
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const MAX_DNS_MESSAGE: usize = 65_535;

#[derive(Clone)]
struct ControllerState {
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    shutdown: CancellationToken,
}

impl ControllerState {
    fn current_config(&self) -> Arc<Config> {
        Arc::clone(&self.config.borrow())
    }
}

/// Serves the declared REST subset and Phase 4F15 DNS control surface.
pub async fn serve(
    listener: TcpListener,
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    shutdown: CancellationToken,
) {
    let state = ControllerState {
        dns_service,
        config,
        runtime: Arc::clone(&runtime),
        shutdown: shutdown.clone(),
    };
    let app = controller_router(state.clone()).layer(middleware::from_fn_with_state(
        state,
        authenticate_or_serve_doh,
    ));
    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
    {
        runtime.log("error", format!("controller server failed: {error}"));
    }
}

fn controller_router(state: ControllerState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/version", get(version))
        .route("/configs", get(configs))
        .route("/configs/", get(configs))
        .route("/connections", get(connections))
        .route("/connections/", get(connections))
        .route("/traffic", get(traffic))
        .route("/logs", get(logs))
        .route("/cache/dns/flush", any(flush_dns_cache))
        .route("/cache/fakeip/flush", any(flush_fake_ip_cache))
        .route("/dns/query", any(dns_query))
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
        .with_state(state)
}

async fn authenticate_or_serve_doh(
    State(state): State<ControllerState>,
    request: Request,
    next: Next,
) -> Response {
    let config = state.current_config();
    if is_doh_path(request.uri().path(), &config.external_doh_server) {
        return handle_doh(request, &state, &config).await;
    }
    let expected = format!("Bearer {}", config.secret);
    if !config.secret.is_empty()
        && request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            != Some(expected.as_str())
    {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({"message": "Unauthorized"}),
        );
    }
    next.run(request).await
}

fn is_doh_path(path: &str, mount: &str) -> bool {
    mount.starts_with('/')
        && (path == mount
            || path
                .strip_prefix(mount)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

async fn handle_doh(request: Request, state: &ControllerState, config: &Config) -> Response {
    if config.dns.is_none() {
        return plain_response(StatusCode::INTERNAL_SERVER_ERROR, "DNS section is disabled");
    }
    let packet = match *request.method() {
        Method::GET => {
            let parameters = query_parameters(request.uri());
            let encoded = parameters.get("dns").map_or("", String::as_str);
            match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(packet) => packet,
                Err(error) => {
                    return plain_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
                }
            }
        }
        Method::POST => {
            if request
                .headers()
                .get(header::CONTENT_TYPE)
                .map(axum::http::HeaderValue::as_bytes)
                != Some(b"application/dns-message".as_slice())
            {
                return plain_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid content-type");
            }
            match read_limited_body(request.into_body()).await {
                Ok(packet) => packet,
                Err(error) => return plain_response(StatusCode::INTERNAL_SERVER_ERROR, &error),
            }
        }
        _ => return plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    };
    match state
        .dns_service
        .relay_query(config, &state.runtime, &packet)
        .await
    {
        Ok(response) => dns_message_response(response),
        Err(error) => plain_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn read_limited_body(body: Body) -> Result<Vec<u8>, String> {
    let mut stream = body.into_data_stream();
    let mut result = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        let remaining = MAX_DNS_MESSAGE.saturating_sub(result.len());
        if remaining == 0 {
            break;
        }
        if chunk.len() <= remaining {
            result.extend_from_slice(&chunk);
        } else {
            result.extend_from_slice(&chunk[..remaining]);
            break;
        }
    }
    Ok(result)
}

async fn root() -> Response {
    json_response(StatusCode::OK, &json!({"hello": "mihomo"}))
}

async fn version() -> Response {
    json_response(
        StatusCode::OK,
        &json!({"meta": true, "version": env!("CARGO_PKG_VERSION")}),
    )
}

async fn configs(State(state): State<ControllerState>) -> Response {
    json_response(StatusCode::OK, &config_snapshot(&state.current_config()))
}

async fn connections(State(state): State<ControllerState>) -> Response {
    json_response(StatusCode::OK, &state.runtime.connections())
}

async fn flush_dns_cache(State(state): State<ControllerState>, method: Method) -> Response {
    if method != Method::POST {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    state.dns_service.clear_cache().await;
    empty_response(StatusCode::NO_CONTENT)
}

async fn flush_fake_ip_cache(State(state): State<ControllerState>, method: Method) -> Response {
    if method != Method::POST {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let config = state.current_config();
    if let Some(fake) = config.dns.as_ref().and_then(|dns| dns.fake_ip.as_ref()) {
        state
            .runtime
            .flush_fake_ips(fake.ipv4_range, fake.ipv6_range, config.store_fake_ip);
    }
    empty_response(StatusCode::NO_CONTENT)
}

async fn dns_query(State(state): State<ControllerState>, method: Method, uri: Uri) -> Response {
    if method != Method::GET {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let config = state.current_config();
    let Some(dns) = config.dns.as_ref() else {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": "DNS section is disabled"}),
        );
    };
    let parameters = query_parameters(&uri);
    let name = parameters.get("name").map_or("", String::as_str);
    let record_type = parameters
        .get("type")
        .map_or(Some(1), |value| dns_record_type(value));
    let Some(record_type) = record_type else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": "invalid query type"}),
        );
    };
    match state.dns_service.rest_query(dns, name, record_type).await {
        Ok(response) => json_response(StatusCode::OK, &response),
        Err(error) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": error.to_string()}),
        ),
    }
}

async fn traffic(State(state): State<ControllerState>) -> Response {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await;
    let runtime = Arc::clone(&state.runtime);
    let shutdown = state.shutdown.clone();
    let body = Body::from_stream(stream::unfold(
        (interval, runtime, shutdown),
        |(mut interval, runtime, shutdown)| async move {
            tokio::select! {
                () = shutdown.cancelled() => None,
                _ = interval.tick() => {
                    let line = json_line(&runtime.traffic());
                    Some((Ok::<Bytes, Infallible>(line), (interval, runtime, shutdown)))
                }
            }
        },
    ));
    typed_response(StatusCode::OK, "application/json", body)
}

async fn logs(State(state): State<ControllerState>, uri: Uri) -> Response {
    if uri
        .query()
        .is_some_and(|query| query.contains("level=invalid"))
    {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    }
    let receiver = state.runtime.subscribe_logs();
    let shutdown = state.shutdown.clone();
    let body = Body::from_stream(stream::unfold(
        (receiver, shutdown),
        |(mut receiver, shutdown)| async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return None,
                    result = receiver.recv() => match result {
                        Ok(event) => {
                            let line = json_line(&event);
                            return Some((Ok::<Bytes, Infallible>(line), (receiver, shutdown)));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }
        },
    ));
    typed_response(StatusCode::OK, "application/json", body)
}

async fn method_not_allowed() -> Response {
    json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        &json!({"message": "Method Not Allowed"}),
    )
}

async fn not_found(method: Method) -> Response {
    if method == Method::GET {
        json_response(StatusCode::NOT_FOUND, &json!({"message": "Not Found"}))
    } else {
        method_not_allowed().await
    }
}

fn query_parameters(uri: &Uri) -> BTreeMap<String, String> {
    uri.query()
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

fn json_line<T: Serialize>(value: &T) -> Bytes {
    let mut body = serde_json::to_vec(value)
        .unwrap_or_else(|_| br#"{"message":"controller JSON error"}"#.to_vec());
    body.push(b'\n');
    Bytes::from(body)
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => typed_response(status, "application/json", Body::from(body)),
        Err(error) => plain_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

fn plain_response(status: StatusCode, message: &str) -> Response {
    typed_response(
        status,
        "text/plain; charset=utf-8",
        Body::from(message.to_owned()),
    )
}

fn dns_message_response(message: Vec<u8>) -> Response {
    typed_response(
        StatusCode::OK,
        "application/dns-message",
        Body::from(message),
    )
}

fn typed_response(status: StatusCode, content_type: &'static str, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn empty_response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
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
}
