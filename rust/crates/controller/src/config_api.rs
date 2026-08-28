use super::{
    Config, ConfigUpdate, ConfigUpdateKind, ControllerState, Deserialize, Duration, Request,
    Response, State, StatusCode, empty_response, json, json_response, oneshot,
};

#[derive(Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) struct ConfigPatch {
    port: Option<i64>,
    socks_port: Option<i64>,
    mixed_port: Option<i64>,
    log_level: Option<rewrite_config::LogLevel>,
    ipv6: Option<bool>,
    mode: Option<rewrite_config::Mode>,
    allow_lan: Option<bool>,
    bind_address: Option<String>,
    skip_auth_prefixes: Option<Vec<String>>,
    lan_allowed_ips: Option<Vec<String>>,
    lan_disallowed_ips: Option<Vec<String>>,
    tcp_concurrent: Option<bool>,
    interface_name: Option<String>,
}

#[derive(Default, Deserialize)]
pub(super) struct ConfigReplacement {
    path: String,
    payload: String,
}

pub(super) async fn patch_configs(
    State(state): State<ControllerState>,
    request: Request,
) -> Response {
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
    if let Some(allow_lan) = patch.allow_lan {
        config.allow_lan = allow_lan;
    }
    if let Some(bind_address) = patch.bind_address {
        config.bind_address = bind_address;
    }
    if let Err(error) = config.update_inbound_prefixes(
        patch.skip_auth_prefixes,
        patch.lan_allowed_ips,
        patch.lan_disallowed_ips,
    ) {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": error.to_string()}),
        );
    }
    if let Some(tcp_concurrent) = patch.tcp_concurrent {
        config.tcp_concurrent = tcp_concurrent;
    }
    if let Some(interface_name) = patch.interface_name {
        config.interface_name = interface_name;
    }
    apply_config_update(&state, config).await
}

pub(super) async fn update_configs(
    State(state): State<ControllerState>,
    request: Request,
) -> Response {
    let Ok(replacement) = decode_json_body::<ConfigReplacement>(request).await else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let current = state.current_config();
    let mut config = match if replacement.payload.is_empty() {
        let path = (!replacement.path.is_empty()).then(|| std::path::Path::new(&replacement.path));
        current.replacement_from_safe_path(path)
    } else {
        current.replacement_from_yaml(&replacement.payload)
    } {
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
    preserve_controller_configuration(&mut config, &current);
    apply_config_update(&state, config).await
}

pub(super) fn preserve_controller_configuration(config: &mut Config, current: &Config) {
    config
        .external_controller
        .clone_from(&current.external_controller);
    config
        .external_controller_tls
        .clone_from(&current.external_controller_tls);
    config
        .external_controller_unix
        .clone_from(&current.external_controller_unix);
    config
        .external_controller_pipe
        .clone_from(&current.external_controller_pipe);
    config.external_controller_routing_mark = current.external_controller_routing_mark;
    config.external_ui.clone_from(&current.external_ui);
    config.external_ui_url.clone_from(&current.external_ui_url);
    config
        .external_ui_name
        .clone_from(&current.external_ui_name);
    config
        .external_doh_server
        .clone_from(&current.external_doh_server);
    config.secret.clone_from(&current.secret);
    config.controller_cors.clone_from(&current.controller_cors);
    config.controller_tls.clone_from(&current.controller_tls);
}

pub(super) async fn restart(State(state): State<ControllerState>) -> Response {
    if let Err(error) = std::env::current_exe() {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": format!("getting path: {error}")}),
        );
    }
    let updates = state.config_updates.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (completion, result) = oneshot::channel();
        if updates
            .send(ConfigUpdate {
                kind: ConfigUpdateKind::Restart,
                completion,
            })
            .await
            .is_ok()
        {
            let _ = result.await;
        }
    });
    json_response(StatusCode::OK, &json!({"status": "ok"}))
}

pub(super) async fn update_ui(State(state): State<ControllerState>) -> Response {
    match rewrite_services::update_ui(&state.current_config()).await {
        Ok(()) => json_response(StatusCode::OK, &json!({"status": "ok"})),
        Err(error) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": error.to_string()}),
        ),
    }
}

pub(super) async fn update_geo(State(state): State<ControllerState>) -> Response {
    match rewrite_services::update_geodata(&state.current_config()).await {
        Ok(()) => empty_response(StatusCode::NO_CONTENT),
        Err(error) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": error.to_string()}),
        ),
    }
}

pub(super) async fn debug_gc(State(state): State<ControllerState>) -> Response {
    if state.current_config().log_level != rewrite_config::LogLevel::Debug {
        return json_response(StatusCode::NOT_FOUND, &json!({"message": "Not Found"}));
    }
    // Rust allocators do not expose a portable equivalent of Go's
    // debug.FreeOSMemory. The route and lifecycle contract are preserved; the
    // allocator-specific release semantic remains explicitly tracked in 5E.
    empty_response(StatusCode::OK)
}

pub(super) async fn decode_json_body<T: for<'de> Deserialize<'de>>(
    request: Request,
) -> Result<T, ()> {
    const MAX_CONFIG_REQUEST: usize = 16 * 1024 * 1024;
    let bytes = axum::body::to_bytes(request.into_body(), MAX_CONFIG_REQUEST)
        .await
        .map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

pub(super) async fn apply_config_update(state: &ControllerState, config: Config) -> Response {
    apply_update(
        state,
        ConfigUpdateKind::Replace(Box::new(config)),
        StatusCode::BAD_REQUEST,
    )
    .await
}

pub(super) async fn apply_provider_refresh(state: &ControllerState, provider: String) -> Response {
    apply_update(
        state,
        ConfigUpdateKind::RefreshProxyProvider(provider),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await
}

pub(super) async fn apply_update(
    state: &ControllerState,
    kind: ConfigUpdateKind,
    failure_status: StatusCode,
) -> Response {
    let (completion, result) = oneshot::channel();
    if state
        .config_updates
        .send(ConfigUpdate { kind, completion })
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
        Ok(Err(error)) => json_response(failure_status, &json!({"message": error})),
        Err(_) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"message": "runtime configuration result was dropped"}),
        ),
    }
}
