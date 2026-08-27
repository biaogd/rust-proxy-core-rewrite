use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{any, delete, get};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{StreamExt, stream};
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rewrite_config::Config;
use rewrite_dns::DnsService;
use rewrite_state::RuntimeState;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

const MAX_DNS_MESSAGE: usize = 65_535;

#[derive(Clone)]
struct ControllerState {
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    shutdown: CancellationToken,
    config_updates: mpsc::Sender<ConfigUpdate>,
}

/// Transactional runtime configuration request initiated by the controller.
pub struct ConfigUpdate {
    pub config: Config,
    pub completion: oneshot::Sender<Result<(), String>>,
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
    config_updates: mpsc::Sender<ConfigUpdate>,
    shutdown: CancellationToken,
) {
    let state = ControllerState {
        dns_service,
        config,
        runtime: Arc::clone(&runtime),
        shutdown: shutdown.clone(),
        config_updates,
    };
    let app = controller_router(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate_or_serve_doh,
        ))
        .layer(middleware::from_fn_with_state(state, apply_dynamic_cors));
    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
    {
        runtime.log("error", format!("controller server failed: {error}"));
    }
}

async fn apply_dynamic_cors(
    State(state): State<ControllerState>,
    mut request: Request,
    next: Next,
) -> Response {
    let preflight = is_preflight(&request);
    if preflight && !valid_preflight_contract(&request) {
        return denied_preflight_response();
    }
    if preflight {
        normalize_preflight_request(&mut request);
    }
    let cors = cors_layer(&state.current_config().controller_cors);
    let mut service = cors.layer(next);
    let mut response = match service.call(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    normalize_cors_vary(&mut response, preflight);
    response
}

fn normalize_preflight_request(request: &mut Request) {
    if let Some(method) = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .map(str::to_ascii_uppercase)
        .and_then(|value| HeaderValue::from_str(&value).ok())
    {
        request
            .headers_mut()
            .insert(header::ACCESS_CONTROL_REQUEST_METHOD, method);
    }
    let headers = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .filter_map(|name| match name.trim().to_ascii_lowercase().as_str() {
                    "authorization" => Some("Authorization"),
                    "content-type" => Some("Content-Type"),
                    "origin" => Some("Origin"),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(", ")
        });
    match headers {
        Some(headers) if !headers.is_empty() => {
            if let Ok(headers) = HeaderValue::from_str(&headers) {
                request
                    .headers_mut()
                    .insert(header::ACCESS_CONTROL_REQUEST_HEADERS, headers);
            }
        }
        _ => {
            request
                .headers_mut()
                .remove(header::ACCESS_CONTROL_REQUEST_HEADERS);
        }
    }
}

fn is_preflight(request: &Request) -> bool {
    request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
        && request.headers().contains_key(header::ORIGIN)
}

fn valid_preflight_contract(request: &Request) -> bool {
    let method = request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return false;
    }
    request
        .headers()
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|headers| {
            headers
                .split(',')
                .filter(|name| !name.trim().is_empty())
                .all(|name| {
                    matches!(
                        name.trim().to_ascii_lowercase().as_str(),
                        "content-type" | "authorization" | "origin"
                    )
                })
        })
}

fn denied_preflight_response() -> Response {
    let mut response = empty_response(StatusCode::OK);
    normalize_cors_vary(&mut response, true);
    response
}

fn normalize_cors_vary(response: &mut Response, preflight: bool) {
    response.headers_mut().remove(header::VARY);
    let values = if preflight {
        &[
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
        ][..]
    } else {
        &["Origin"][..]
    };
    for value in values {
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static(value));
    }
}

fn cors_layer(config: &rewrite_config::ControllerCors) -> CorsLayer {
    let origins = config
        .allow_origins
        .iter()
        .map(|origin| origin.to_lowercase())
        .collect::<Vec<_>>();
    let allow_origin = if origins.is_empty() || origins.iter().any(|origin| origin == "*") {
        AllowOrigin::any()
    } else {
        AllowOrigin::predicate(move |origin, _| {
            let Ok(origin) = origin.to_str() else {
                return false;
            };
            let origin = origin.to_lowercase();
            origins
                .iter()
                .any(|allowed| wildcard_origin_matches(allowed, &origin))
        })
    };
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
        .allow_private_network(config.allow_private_network)
        .max_age(Duration::from_mins(5))
}

fn wildcard_origin_matches(allowed: &str, origin: &str) -> bool {
    allowed.split_once('*').map_or_else(
        || allowed == origin,
        |(prefix, suffix)| origin.starts_with(prefix) && origin.ends_with(suffix),
    )
}

fn controller_router(state: ControllerState) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/version", get(version))
        .route(
            "/configs",
            get(configs).put(update_configs).patch(patch_configs),
        )
        .route(
            "/configs/",
            get(configs).put(update_configs).patch(patch_configs),
        )
        .route("/rules", get(rules))
        .route("/rules/", get(rules))
        .route("/rules/disable", axum::routing::patch(disable_rules))
        .route(
            "/storage/{key}",
            get(get_storage).put(set_storage).delete(delete_storage),
        )
        .route("/proxies", get(proxies))
        .route("/proxies/", get(proxies))
        .route("/proxies/{name}/delay", get(proxy_delay))
        .route(
            "/proxies/{name}",
            get(proxy).put(select_proxy).delete(unfix_proxy),
        )
        .route("/group", get(groups))
        .route("/group/", get(groups))
        .route("/group/{name}/delay", get(group_delay))
        .route("/group/{name}", get(group))
        .route("/providers/proxies", get(proxy_providers))
        .route("/providers/proxies/", get(proxy_providers))
        .route(
            "/providers/proxies/{provider}",
            get(proxy_provider).put(update_proxy_provider),
        )
        .route(
            "/providers/proxies/{provider}/healthcheck",
            get(healthcheck_proxy_provider),
        )
        .route(
            "/providers/proxies/{provider}/{name}",
            get(proxy_provider_member),
        )
        .route("/providers/rules", get(rule_providers))
        .route("/providers/rules/", get(rule_providers))
        .route(
            "/providers/rules/{name}",
            axum::routing::put(missing_rule_provider),
        )
        .route(
            "/connections",
            get(connections).delete(close_all_connections),
        )
        .route(
            "/connections/",
            get(connections).delete(close_all_connections),
        )
        .route("/connections/{id}", delete(close_connection))
        .route("/traffic", get(traffic))
        .route("/memory", get(memory))
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
    if !config.secret.is_empty() && !is_authorized(&request, &config.secret) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({"message": "Unauthorized"}),
        );
    }
    next.run(request).await
}

fn is_authorized(request: &Request, secret: &str) -> bool {
    let websocket_token = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        .then(|| query_parameters(request.uri()).remove("token"))
        .flatten()
        .filter(|token| !token.is_empty());
    if let Some(token) = websocket_token {
        return token == secret;
    }
    let expected = format!("Bearer {secret}");
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(expected.as_str())
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

async fn rules(State(state): State<ControllerState>) -> Response {
    let rules: Vec<_> = state
        .current_config()
        .rules
        .snapshots()
        .into_iter()
        .map(|rule| {
            json!({
                "index": rule.index,
                "type": rule.kind,
                "payload": rule.payload,
                "proxy": rule.target,
                "size": -1,
                "extra": {
                    "disabled": rule.disabled,
                    "hitCount": rule.hit_count,
                    "hitAt": rule_timestamp(rule.hit_at_unix_nanos),
                    "missCount": rule.miss_count,
                    "missAt": rule_timestamp(rule.miss_at_unix_nanos),
                }
            })
        })
        .collect();
    json_response(StatusCode::OK, &json!({"rules": rules}))
}

async fn disable_rules(State(state): State<ControllerState>, request: Request) -> Response {
    let Ok(updates) = decode_json_body::<BTreeMap<i64, bool>>(request).await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let config = state.current_config();
    for (index, disabled) in updates {
        if let Ok(index) = usize::try_from(index) {
            config.rules.set_disabled(index, disabled);
        }
    }
    empty_response(StatusCode::NO_CONTENT)
}

fn rule_timestamp(unix_nanos: i64) -> String {
    if unix_nanos == 0 {
        return "1970-01-01T00:00:00Z".to_owned();
    }
    if let Ok(timestamp) = OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_nanos))
        && let Ok(formatted) = timestamp.format(&Rfc3339)
    {
        return formatted;
    }
    "1970-01-01T00:00:00Z".to_owned()
}

async fn get_storage(State(state): State<ControllerState>, Path(key): Path<String>) -> Response {
    state.runtime.storage_get(&key).map_or_else(
        || typed_response(StatusCode::OK, "application/json", Body::from("null")),
        |value| typed_response(StatusCode::OK, "application/json", Body::from(value)),
    )
}

async fn set_storage(
    State(state): State<ControllerState>,
    Path(key): Path<String>,
    request: Request,
) -> Response {
    const MAX_REQUEST: usize = 16 * 1024 * 1024;
    const MAX_STORAGE_VALUE: usize = 1024 * 1024;
    let Ok(value) = axum::body::to_bytes(request.into_body(), MAX_REQUEST).await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    if serde_json::from_slice::<serde_json::Value>(&value).is_err() {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    }
    if value.len() > MAX_STORAGE_VALUE {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            &json!({"message": "payload exceeds 1MB limit"}),
        );
    }
    state.runtime.storage_set(key, value.to_vec());
    empty_response(StatusCode::NO_CONTENT)
}

async fn delete_storage(State(state): State<ControllerState>, Path(key): Path<String>) -> Response {
    state.runtime.storage_delete(&key);
    empty_response(StatusCode::NO_CONTENT)
}

const PROXY_NAMES: [&str; 7] = [
    "COMPATIBLE",
    "DIRECT",
    "GLOBAL",
    "PASS",
    "PASS-RULE",
    "REJECT",
    "REJECT-DROP",
];

async fn proxies(State(state): State<ControllerState>) -> Response {
    let config = state.current_config();
    let mut proxies: serde_json::Map<String, serde_json::Value> = PROXY_NAMES
        .into_iter()
        .map(|name| (name.to_owned(), proxy_snapshot(name, &state.runtime)))
        .collect();
    for proxy in &config.proxies {
        proxies.insert(
            proxy.name.clone(),
            configured_proxy_snapshot(proxy, &state.runtime),
        );
    }
    for group in &config.proxy_groups {
        proxies.insert(group.name.clone(), selector_snapshot(group, &state.runtime));
    }
    json_response(StatusCode::OK, &json!({"proxies": proxies}))
}

async fn proxy(State(state): State<ControllerState>, Path(name): Path<String>) -> Response {
    if PROXY_NAMES.contains(&name.as_str()) {
        return json_response(StatusCode::OK, &proxy_snapshot(&name, &state.runtime));
    }
    let config = state.current_config();
    if let Some(proxy) = config.proxies.iter().find(|proxy| proxy.name == name) {
        return json_response(
            StatusCode::OK,
            &configured_proxy_snapshot(proxy, &state.runtime),
        );
    }
    if let Some(group) = config.proxy_groups.iter().find(|group| group.name == name) {
        return json_response(StatusCode::OK, &selector_snapshot(group, &state.runtime));
    }
    proxy_not_found()
}

async fn groups(State(state): State<ControllerState>) -> Response {
    let config = state.current_config();
    let mut groups = vec![proxy_snapshot("GLOBAL", &state.runtime)];
    groups.extend(
        config
            .proxy_groups
            .iter()
            .map(|group| selector_snapshot(group, &state.runtime)),
    );
    json_response(StatusCode::OK, &json!({"proxies": groups}))
}

async fn group(State(state): State<ControllerState>, Path(name): Path<String>) -> Response {
    if name == "GLOBAL" {
        return json_response(StatusCode::OK, &proxy_snapshot("GLOBAL", &state.runtime));
    }
    let config = state.current_config();
    config
        .proxy_groups
        .iter()
        .find(|group| group.name == name)
        .map_or_else(proxy_not_found, |group| {
            json_response(StatusCode::OK, &selector_snapshot(group, &state.runtime))
        })
}

async fn proxy_delay(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
    uri: Uri,
) -> Response {
    let config = state.current_config();
    let configured_group = config.proxy_groups.iter().find(|group| group.name == name);
    if !PROXY_NAMES.contains(&name.as_str()) && configured_group.is_none() {
        return proxy_not_found();
    }
    let parameters = query_parameters(&uri);
    let Some(timeout) = parameters
        .get("timeout")
        .and_then(|value| value.parse::<i16>().ok())
    else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let Some(expected) = parameters
        .get("expected")
        .map_or(Some(Vec::new()), |value| parse_status_ranges(value))
    else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let url = parameters.get("url").map_or("", String::as_str);
    let tested_name = if name == "GLOBAL" {
        state.runtime.global_proxy()
    } else {
        name.clone()
    };
    if timeout <= 0 {
        state.runtime.record_proxy_delay(&name, url, 0, false);
        return json_response(StatusCode::GATEWAY_TIMEOUT, &json!({"message": "Timeout"}));
    }
    let result = tokio::time::timeout(
        Duration::from_millis(u64::try_from(timeout).unwrap_or_default()),
        measure_http_delay(&tested_name, url, &expected),
    )
    .await;
    match result {
        Ok(Ok(delay)) if delay > 0 => {
            state.runtime.record_proxy_delay(&name, url, delay, true);
            json_response(StatusCode::OK, &json!({"delay": delay}))
        }
        Err(_) => {
            state.runtime.record_proxy_delay(&name, url, 0, false);
            json_response(StatusCode::GATEWAY_TIMEOUT, &json!({"message": "Timeout"}))
        }
        _ => {
            state.runtime.record_proxy_delay(&name, url, 0, false);
            json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"message": "An error occurred in the delay test"}),
            )
        }
    }
}

async fn group_delay(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
    uri: Uri,
) -> Response {
    if name != "GLOBAL" {
        return proxy_not_found();
    }
    let parameters = query_parameters(&uri);
    let Some(timeout) = parameters
        .get("timeout")
        .and_then(|value| value.parse::<i32>().ok())
    else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let Some(expected) = parameters
        .get("expected")
        .map_or(Some(Vec::new()), |value| parse_status_ranges(value))
    else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let url = parameters.get("url").map_or("", String::as_str);
    if timeout <= 0 {
        return json_response(
            StatusCode::GATEWAY_TIMEOUT,
            &json!({"message": "get delay: all proxies timeout"}),
        );
    }
    let result = tokio::time::timeout(
        Duration::from_millis(u64::try_from(timeout).unwrap_or_default()),
        measure_http_delay("DIRECT", url, &expected),
    )
    .await;
    match result {
        Ok(Ok(delay)) if delay > 0 => {
            state.runtime.record_proxy_delay("DIRECT", url, delay, true);
            state.runtime.record_proxy_delay("REJECT", url, 0, false);
            json_response(StatusCode::OK, &json!({"DIRECT": delay}))
        }
        _ => json_response(
            StatusCode::GATEWAY_TIMEOUT,
            &json!({"message": "get delay: all proxies timeout"}),
        ),
    }
}

async fn measure_http_delay(name: &str, raw_url: &str, expected: &[(u16, u16)]) -> Result<u16, ()> {
    if !matches!(name, "DIRECT" | "COMPATIBLE") {
        return Err(());
    }
    let url = url::Url::parse(raw_url).map_err(|_| ())?;
    if url.scheme() != "http" {
        return Err(());
    }
    let host = url.host_str().ok_or(())?;
    let port = url.port_or_known_default().ok_or(())?;
    let started = tokio::time::Instant::now();
    let stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|_| ())?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| ())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut target = url.path().to_owned();
    if target.is_empty() {
        target.push('/');
    }
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    let authority = url
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    let request = hyper::Request::builder()
        .method(hyper::Method::HEAD)
        .uri(target)
        .header(hyper::header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .map_err(|_| ())?;
    let response = sender.send_request(request).await.map_err(|_| ())?;
    let status = response.status().as_u16();
    if !expected.is_empty()
        && !expected
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&status))
    {
        return Err(());
    }
    u16::try_from(started.elapsed().as_millis()).map_err(|_| ())
}

fn parse_status_ranges(value: &str) -> Option<Vec<(u16, u16)>> {
    let value = value.trim();
    if value.is_empty() || value == "*" {
        return Some(Vec::new());
    }
    let parts: Vec<_> = value
        .replace(',', "/")
        .split('/')
        .map(str::to_owned)
        .collect();
    if parts.len() > 28 {
        return None;
    }
    parts
        .into_iter()
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut bounds = part.split('-');
            let start = bounds.next()?.trim().parse::<u16>().ok()?;
            let end = bounds
                .next()
                .map_or(Some(start), |value| value.trim().parse::<u16>().ok())?;
            if bounds.next().is_some() || start > end {
                return None;
            }
            Some((start, end))
        })
        .collect()
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ProxySelection {
    name: String,
}

async fn select_proxy(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let config = state.current_config();
    let configured_group = config.proxy_groups.iter().find(|group| group.name == name);
    if !PROXY_NAMES.contains(&name.as_str()) && configured_group.is_none() {
        return proxy_not_found();
    }
    let Ok(selection) = decode_json_body::<ProxySelection>(request).await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    if name != "GLOBAL" && configured_group.is_none() {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": "Must be a Selector"}),
        );
    }
    let updated = if name == "GLOBAL" {
        state.runtime.set_global_proxy(&selection.name)
    } else {
        let group = configured_group.expect("configured group was checked");
        state
            .runtime
            .set_selector_proxy(&name, &selection.name, &group.proxies)
    };
    if !updated {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": "Selector update error: proxy not exist"}),
        );
    }
    empty_response(StatusCode::NO_CONTENT)
}

async fn unfix_proxy(Path(name): Path<String>) -> Response {
    if !PROXY_NAMES.contains(&name.as_str()) {
        return proxy_not_found();
    }
    json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}))
}

fn proxy_snapshot(name: &str, runtime: &RuntimeState) -> serde_json::Value {
    let kind = match name {
        "DIRECT" => "Direct",
        "REJECT" => "Reject",
        "REJECT-DROP" => "RejectDrop",
        "COMPATIBLE" => "Compatible",
        "PASS" => "Pass",
        "PASS-RULE" => "PassRule",
        "GLOBAL" => "Selector",
        _ => "Unknown",
    };
    let health = runtime.proxy_health(name);
    let mut value = json!({
        "alive": health.alive,
        "dialer-proxy": "",
        "extra": health.extra,
        "history": health.history,
        "id": proxy_id(name),
        "interface": "",
        "mptcp": false,
        "name": name,
        "provider-name": "",
        "routing-mark": 0,
        "smux": false,
        "tfo": false,
        "type": kind,
        "udp": true,
        "uot": false,
        "xudp": false,
    });
    if name == "GLOBAL" {
        let object = value.as_object_mut().expect("proxy snapshot is an object");
        object.remove("id");
        object.insert("all".to_owned(), json!(["DIRECT", "REJECT"]));
        object.insert("emptyFallback".to_owned(), json!("COMPATIBLE"));
        object.insert("hidden".to_owned(), json!(false));
        object.insert("icon".to_owned(), json!(""));
        object.insert("now".to_owned(), json!(runtime.global_proxy()));
        object.insert("testUrl".to_owned(), json!(""));
    }
    value
}

fn configured_proxy_snapshot(
    proxy: &rewrite_config::ProxyConfig,
    runtime: &RuntimeState,
) -> serde_json::Value {
    let health = runtime.proxy_health(&proxy.name);
    let kind = match proxy.kind {
        rewrite_config::ProxyKind::Http => "Http",
        rewrite_config::ProxyKind::Socks5 => "Socks5",
    };
    json!({
        "alive": health.alive,
        "dialer-proxy": "",
        "extra": health.extra,
        "history": health.history,
        "id": "00000000-0000-4000-8000-000000000100",
        "interface": "",
        "mptcp": false,
        "name": proxy.name,
        "provider-name": "",
        "routing-mark": 0,
        "smux": false,
        "tfo": false,
        "type": kind,
        "udp": false,
        "uot": false,
        "xudp": false,
    })
}

fn selector_snapshot(
    group: &rewrite_config::ProxyGroupConfig,
    runtime: &RuntimeState,
) -> serde_json::Value {
    let health = runtime.proxy_health(&group.name);
    let selected = runtime.selector_proxy(&group.name).unwrap_or_default();
    let udp = matches!(selected.as_str(), "DIRECT" | "REJECT" | "REJECT-DROP");
    json!({
        "alive": health.alive,
        "all": group.proxies,
        "dialer-proxy": "",
        "emptyFallback": "COMPATIBLE",
        "extra": health.extra,
        "hidden": false,
        "history": health.history,
        "icon": "",
        "interface": "",
        "mptcp": false,
        "name": group.name,
        "now": selected,
        "provider-name": "",
        "routing-mark": 0,
        "smux": false,
        "testUrl": "",
        "tfo": false,
        "type": "Selector",
        "udp": udp,
        "uot": false,
        "xudp": false,
    })
}

fn proxy_id(name: &str) -> &'static str {
    match name {
        "DIRECT" => "00000000-0000-4000-8000-000000000001",
        "REJECT" => "00000000-0000-4000-8000-000000000002",
        "REJECT-DROP" => "00000000-0000-4000-8000-000000000003",
        "COMPATIBLE" => "00000000-0000-4000-8000-000000000004",
        "PASS" | "PASS-RULE" => "00000000-0000-0000-0000-000000000000",
        "GLOBAL" => "00000000-0000-4000-8000-000000000007",
        _ => "00000000-0000-4000-8000-000000000000",
    }
}

fn proxy_not_found() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        &json!({"message": "Resource not found"}),
    )
}

async fn proxy_providers(State(state): State<ControllerState>) -> Response {
    let config = state.current_config();
    json_response(
        StatusCode::OK,
        &json!({"providers": {"default": proxy_provider_snapshot(&config, &state.runtime)}}),
    )
}

async fn proxy_provider(
    State(state): State<ControllerState>,
    Path(provider): Path<String>,
) -> Response {
    if provider != "default" {
        return proxy_not_found();
    }
    let config = state.current_config();
    json_response(
        StatusCode::OK,
        &proxy_provider_snapshot(&config, &state.runtime),
    )
}

async fn update_proxy_provider(Path(provider): Path<String>) -> Response {
    if provider != "default" {
        return proxy_not_found();
    }
    empty_response(StatusCode::NO_CONTENT)
}

async fn healthcheck_proxy_provider(Path(provider): Path<String>) -> Response {
    if provider != "default" {
        return proxy_not_found();
    }
    empty_response(StatusCode::NO_CONTENT)
}

async fn proxy_provider_member(
    State(state): State<ControllerState>,
    Path((provider, name)): Path<(String, String)>,
) -> Response {
    if provider != "default" {
        return proxy_not_found();
    }
    if matches!(name.as_str(), "DIRECT" | "REJECT") {
        return json_response(StatusCode::OK, &proxy_snapshot(&name, &state.runtime));
    }
    let config = state.current_config();
    if let Some(proxy) = config.proxies.iter().find(|proxy| proxy.name == name) {
        return json_response(
            StatusCode::OK,
            &configured_proxy_snapshot(proxy, &state.runtime),
        );
    }
    config
        .proxy_groups
        .iter()
        .find(|group| group.name == name)
        .map_or_else(proxy_not_found, |group| {
            json_response(StatusCode::OK, &selector_snapshot(group, &state.runtime))
        })
}

async fn rule_providers() -> Response {
    json_response(
        StatusCode::OK,
        &json!({"providers": serde_json::Map::<String, serde_json::Value>::new()}),
    )
}

async fn missing_rule_provider() -> Response {
    proxy_not_found()
}

fn proxy_provider_snapshot(config: &Config, runtime: &RuntimeState) -> serde_json::Value {
    let mut proxies = vec![
        proxy_snapshot("DIRECT", runtime),
        proxy_snapshot("REJECT", runtime),
    ];
    proxies.extend(
        config
            .proxies
            .iter()
            .map(|proxy| configured_proxy_snapshot(proxy, runtime)),
    );
    proxies.extend(
        config
            .proxy_groups
            .iter()
            .map(|group| selector_snapshot(group, runtime)),
    );
    json!({
        "name": "default",
        "type": "Proxy",
        "vehicleType": "Compatible",
        "proxies": proxies,
        "testUrl": "",
        "expectedStatus": "*",
        "updatedAt": "0001-01-01T00:00:00Z",
    })
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ConfigPatch {
    port: Option<i64>,
    socks_port: Option<i64>,
    mixed_port: Option<i64>,
    log_level: Option<rewrite_config::LogLevel>,
    ipv6: Option<bool>,
    mode: Option<rewrite_config::Mode>,
}

#[derive(Default, Deserialize)]
struct ConfigReplacement {
    path: String,
    payload: String,
}

async fn patch_configs(State(state): State<ControllerState>, request: Request) -> Response {
    let Ok(patch) = decode_json_body::<ConfigPatch>(request).await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let mut config = (*state.current_config()).clone();
    if let Some(port) = patch.port {
        config.port = port;
    }
    if let Some(port) = patch.socks_port {
        config.socks_port = port;
    }
    if let Some(port) = patch.mixed_port {
        config.mixed_port = port;
    }
    if let Some(log_level) = patch.log_level {
        config.log_level = log_level;
    }
    if let Some(ipv6) = patch.ipv6 {
        config.ipv6 = ipv6;
    }
    if let Some(mode) = patch.mode {
        config.mode = mode;
    }
    apply_config_update(&state, config).await
}

async fn update_configs(State(state): State<ControllerState>, request: Request) -> Response {
    let Ok(replacement) = decode_json_body::<ConfigReplacement>(request).await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    if replacement.payload.is_empty() {
        let message = if replacement.path.is_empty() {
            "path-based controller reload is not available for this input source".to_owned()
        } else if !std::path::Path::new(&replacement.path).is_absolute() {
            "path is not a absolute path".to_owned()
        } else {
            "path-based controller reload requires a declared safe root".to_owned()
        };
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": message}));
    }
    let mut config = match Config::from_yaml(&replacement.payload) {
        Ok(config) => config,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({"message": error.to_string()}),
            );
        }
    };
    // Go ApplyConfig intentionally excludes the external controller. A PUT
    // updates the data plane without moving or re-keying the request's server.
    let current = state.current_config();
    config
        .external_controller
        .clone_from(&current.external_controller);
    config
        .external_doh_server
        .clone_from(&current.external_doh_server);
    config.secret.clone_from(&current.secret);
    config.controller_cors.clone_from(&current.controller_cors);
    apply_config_update(&state, config).await
}

async fn decode_json_body<T: for<'de> Deserialize<'de>>(request: Request) -> Result<T, ()> {
    const MAX_CONFIG_REQUEST: usize = 16 * 1024 * 1024;
    let bytes = axum::body::to_bytes(request.into_body(), MAX_CONFIG_REQUEST)
        .await
        .map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

async fn apply_config_update(state: &ControllerState, config: Config) -> Response {
    let (completion, result) = oneshot::channel();
    if state
        .config_updates
        .send(ConfigUpdate { config, completion })
        .await
        .is_err()
    {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": "runtime configuration channel is closed"}),
        );
    }
    match result.await {
        Ok(Ok(())) => empty_response(StatusCode::NO_CONTENT),
        Ok(Err(error)) => json_response(StatusCode::BAD_REQUEST, &json!({"message": error})),
        Err(_) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": "runtime configuration result was dropped"}),
        ),
    }
}

async fn connections(
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<ControllerState>,
    uri: Uri,
) -> Response {
    let Ok(websocket) = websocket else {
        return json_response(StatusCode::OK, &state.runtime.connections());
    };
    let interval = query_parameters(&uri)
        .get("interval")
        .map_or(Ok(1_000_u64), |value| value.parse::<u64>());
    let Ok(interval) = interval else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    websocket.on_upgrade(move |socket| connections_websocket(socket, state, interval))
}

async fn close_connection(
    State(state): State<ControllerState>,
    Path(public_id): Path<String>,
) -> Response {
    state.runtime.close_connection(&public_id);
    empty_response(StatusCode::NO_CONTENT)
}

async fn close_all_connections(State(state): State<ControllerState>) -> Response {
    state.runtime.close_all_connections();
    empty_response(StatusCode::NO_CONTENT)
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

async fn traffic(
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<ControllerState>,
) -> Response {
    if let Ok(websocket) = websocket {
        return websocket.on_upgrade(move |socket| traffic_websocket(socket, state));
    }
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

async fn memory(
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<ControllerState>,
) -> Response {
    if let Ok(websocket) = websocket {
        return websocket.on_upgrade(move |socket| memory_websocket(socket, state));
    }
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await;
    let shutdown = state.shutdown.clone();
    let body = Body::from_stream(stream::unfold(
        (interval, shutdown),
        |(mut interval, shutdown)| async move {
            tokio::select! {
                () = shutdown.cancelled() => None,
                _ = interval.tick() => {
                    let line = json_line(&MemorySnapshot { inuse: 0, oslimit: 0 });
                    Some((Ok::<Bytes, Infallible>(line), (interval, shutdown)))
                }
            }
        },
    ));
    typed_response(StatusCode::OK, "application/json", body)
}

async fn logs(
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<ControllerState>,
    uri: Uri,
) -> Response {
    let parameters = query_parameters(&uri);
    let Some(level) = LogFilter::parse(parameters.get("level").map_or("info", String::as_str))
    else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    if let Ok(websocket) = websocket {
        return websocket.on_upgrade(move |socket| logs_websocket(socket, state, level));
    }
    let receiver = state.runtime.subscribe_logs();
    let shutdown = state.shutdown.clone();
    let body = Body::from_stream(stream::unfold(
        (receiver, shutdown),
        move |(mut receiver, shutdown)| async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return None,
                    result = receiver.recv() => match result {
                        Ok(event) if level.includes(&event.level) => {
                            let line = json_line(&event);
                            return Some((Ok::<Bytes, Infallible>(line), (receiver, shutdown)));
                        }
                        Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }
        },
    ));
    typed_response(StatusCode::OK, "application/json", body)
}

#[derive(Clone, Copy, Debug, Serialize)]
struct MemorySnapshot {
    inuse: u64,
    oslimit: u64,
}

#[derive(Clone, Copy)]
enum LogFilter {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

impl LogFilter {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "debug" => Some(Self::Debug),
            "info" | "" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "silent" => Some(Self::Silent),
            _ => None,
        }
    }

    fn includes(self, level: &str) -> bool {
        let event = match level {
            "debug" => 0,
            "warning" => 2,
            "error" => 3,
            _ => 1,
        };
        let minimum = match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Warning => 2,
            Self::Error => 3,
            Self::Silent => 4,
        };
        event >= minimum
    }
}

async fn connections_websocket(
    mut socket: WebSocket,
    state: ControllerState,
    interval_millis: u64,
) {
    if send_json_message(&mut socket, &state.runtime.connections())
        .await
        .is_err()
    {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_millis(interval_millis.max(1)));
    interval.tick().await;
    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => break,
            message = socket.recv() => if websocket_closed(message.as_ref()) { break },
            _ = interval.tick() => if send_json_message(&mut socket, &state.runtime.connections()).await.is_err() { break },
        }
    }
}

async fn traffic_websocket(mut socket: WebSocket, state: ControllerState) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await;
    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => break,
            message = socket.recv() => if websocket_closed(message.as_ref()) { break },
            _ = interval.tick() => if send_json_message(&mut socket, &state.runtime.traffic()).await.is_err() { break },
        }
    }
}

async fn memory_websocket(mut socket: WebSocket, state: ControllerState) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await;
    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => break,
            message = socket.recv() => if websocket_closed(message.as_ref()) { break },
            _ = interval.tick() => {
                if send_json_message(&mut socket, &MemorySnapshot { inuse: 0, oslimit: 0 }).await.is_err() { break }
            },
        }
    }
}

async fn logs_websocket(mut socket: WebSocket, state: ControllerState, level: LogFilter) {
    let mut receiver = state.runtime.subscribe_logs();
    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => break,
            message = socket.recv() => if websocket_closed(message.as_ref()) { break },
            result = receiver.recv() => match result {
                Ok(event) if level.includes(&event.level) => {
                    if send_json_message(&mut socket, &event).await.is_err() { break }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
        }
    }
}

async fn send_json_message<T: Serialize>(socket: &mut WebSocket, value: &T) -> Result<(), ()> {
    let message = String::from_utf8(json_line(value).to_vec()).map_err(|_| ())?;
    socket
        .send(Message::Text(message.into()))
        .await
        .map_err(|_| ())
}

fn websocket_closed(message: Option<&Result<Message, axum::Error>>) -> bool {
    matches!(message, None | Some(Ok(Message::Close(_)) | Err(_)))
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
        "geodata-mode": config.geodata_mode,
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

    #[test]
    fn mirrors_go_single_wildcard_origin_matching() {
        assert!(wildcard_origin_matches(
            "https://*.example.test",
            "https://app.example.test"
        ));
        assert!(!wildcard_origin_matches(
            "https://*.example.test",
            "http://app.example.test"
        ));
        assert!(wildcard_origin_matches(
            "https://exact.example.test",
            "https://exact.example.test"
        ));
        assert!(!wildcard_origin_matches(
            "https://exact.example.test",
            "https://other.example.test"
        ));
    }

    #[test]
    fn parses_controller_expected_status_ranges() {
        assert_eq!(parse_status_ranges(""), Some(Vec::new()));
        assert_eq!(parse_status_ranges("*"), Some(Vec::new()));
        assert_eq!(
            parse_status_ranges("200/204,301-303"),
            Some(vec![(200, 200), (204, 204), (301, 303)])
        );
        assert_eq!(parse_status_ranges("invalid"), None);
        assert_eq!(parse_status_ranges("303-301"), None);
    }
}
