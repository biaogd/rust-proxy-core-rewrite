use super::{
    BTreeMap, Body, Config, ControllerState, Engine, HeaderValue, MAX_DNS_MESSAGE, Method, Next,
    OffsetDateTime, Path, Request, Response, Rfc3339, Router, State, StatusCode, StreamExt,
    URL_SAFE_NO_PAD, any, close_all_connections, close_connection, config_snapshot, connections,
    debug_gc, decode_json_body, delete, dns_message_response, dns_query, empty_response,
    flush_dns_cache, flush_fake_ip_cache, get, group, group_delay, groups, header,
    healthcheck_proxy_provider, json, json_response, logs, memory, method_not_allowed, not_found,
    patch_configs, plain_response, proxies, proxy, proxy_delay, proxy_provider,
    proxy_provider_member, proxy_providers, query_parameters, restart, rule_providers,
    select_proxy, traffic, typed_response, unfix_proxy, update_configs, update_geo,
    update_proxy_provider, update_rule_provider, update_ui,
};

pub(super) fn controller_router(state: ControllerState) -> Router {
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
            axum::routing::put(update_rule_provider),
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
        .route("/upgrade/ui", axum::routing::post(update_ui))
        .route("/upgrade/geo", axum::routing::post(update_geo))
        .route("/configs/geo", axum::routing::post(update_geo))
        .route("/restart", axum::routing::post(restart))
        .route("/restart/", axum::routing::post(restart))
        .route("/debug/gc", axum::routing::put(debug_gc))
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
        .with_state(state)
}

pub(super) async fn authenticate_or_serve_public(
    State(state): State<ControllerState>,
    request: Request,
    next: Next,
) -> Response {
    let config = state.current_config();
    if is_doh_path(request.uri().path(), &config.external_doh_server) {
        return handle_doh(request, &state, &config).await;
    }
    if config.external_ui_path().is_some()
        && (request.uri().path() == "/ui" || request.uri().path().starts_with("/ui/"))
    {
        if request.uri().path() == "/ui" {
            let mut response = typed_response(
                StatusCode::TEMPORARY_REDIRECT,
                "text/html; charset=utf-8",
                Body::from("<a href=\"/ui/\">Temporary Redirect</a>.\n\n"),
            );
            response
                .headers_mut()
                .insert(header::LOCATION, HeaderValue::from_static("/ui/"));
            return response;
        }
        let mut response = next.run(request).await;
        if let Some(content_type) = response.headers().get(header::CONTENT_TYPE)
            && let Ok(value) = content_type.to_str()
            && value.starts_with("text/")
            && !value.contains("charset=")
            && let Ok(value) = HeaderValue::from_str(&format!("{value}; charset=utf-8"))
        {
            response.headers_mut().insert(header::CONTENT_TYPE, value);
        }
        return response;
    }
    // Mihomo mounts diagnostics outside the authenticated controller group.
    // Keep that ordering even when debug is disabled, so a missing debug route
    // is a public 404 rather than an authentication challenge.
    if request.uri().path() == "/debug" || request.uri().path().starts_with("/debug/") {
        return next.run(request).await;
    }
    if state.require_auth && !config.secret.is_empty() && !is_authorized(&request, &config.secret) {
        return json_response(
            StatusCode::UNAUTHORIZED,
            &json!({"message": "Unauthorized"}),
        );
    }
    next.run(request).await
}

pub(super) fn is_authorized(request: &Request, secret: &str) -> bool {
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

pub(super) fn is_doh_path(path: &str, mount: &str) -> bool {
    mount.starts_with('/')
        && (path == mount
            || path
                .strip_prefix(mount)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

pub(super) async fn handle_doh(
    request: Request,
    state: &ControllerState,
    config: &Config,
) -> Response {
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

pub(super) async fn read_limited_body(body: Body) -> Result<Vec<u8>, String> {
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

pub(super) async fn root() -> Response {
    json_response(StatusCode::OK, &json!({"hello": "mihomo"}))
}

pub(super) async fn version() -> Response {
    json_response(
        StatusCode::OK,
        &json!({"meta": true, "version": env!("CARGO_PKG_VERSION")}),
    )
}

pub(super) async fn configs(State(state): State<ControllerState>) -> Response {
    json_response(StatusCode::OK, &config_snapshot(&state.current_config()))
}

pub(super) async fn rules(State(state): State<ControllerState>) -> Response {
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
                "size": rule.size,
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

pub(super) async fn disable_rules(
    State(state): State<ControllerState>,
    request: Request,
) -> Response {
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

pub(super) fn rule_timestamp(unix_nanos: i64) -> String {
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

pub(super) async fn get_storage(
    State(state): State<ControllerState>,
    Path(key): Path<String>,
) -> Response {
    state.runtime.storage_get(&key).map_or_else(
        || typed_response(StatusCode::OK, "application/json", Body::from("null")),
        |value| typed_response(StatusCode::OK, "application/json", Body::from(value)),
    )
}

pub(super) async fn set_storage(
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
    state.runtime.storage_set(&key, value.to_vec());
    empty_response(StatusCode::NO_CONTENT)
}

pub(super) async fn delete_storage(
    State(state): State<ControllerState>,
    Path(key): Path<String>,
) -> Response {
    state.runtime.storage_delete(&key);
    empty_response(StatusCode::NO_CONTENT)
}
