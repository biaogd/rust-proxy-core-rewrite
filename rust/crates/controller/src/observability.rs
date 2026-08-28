use super::{
    Arc, Body, Bytes, ControllerState, Duration, Infallible, Message, Method, OffsetDateTime, Path,
    Response, Serialize, State, StatusCode, Uri, WebSocket, WebSocketUpgrade,
    WebSocketUpgradeRejection, dns_record_type, empty_response, json, json_line, json_response,
    query_parameters, stream, typed_response,
};

pub(super) async fn connections(
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

pub(super) async fn close_connection(
    State(state): State<ControllerState>,
    Path(public_id): Path<String>,
) -> Response {
    state.runtime.close_connection(&public_id);
    empty_response(StatusCode::NO_CONTENT)
}

pub(super) async fn close_all_connections(State(state): State<ControllerState>) -> Response {
    state.runtime.close_all_connections();
    empty_response(StatusCode::NO_CONTENT)
}

pub(super) async fn flush_dns_cache(
    State(state): State<ControllerState>,
    method: Method,
) -> Response {
    if method != Method::POST {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    state.dns_service.clear_cache().await;
    empty_response(StatusCode::NO_CONTENT)
}

pub(super) async fn flush_fake_ip_cache(
    State(state): State<ControllerState>,
    method: Method,
) -> Response {
    if method != Method::POST {
        return empty_response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let config = state.current_config();
    if let Some(fake) = config.dns.as_ref().and_then(|dns| dns.fake_ip.as_ref()) {
        state.runtime.flush_fake_ips(
            fake.ipv4_range,
            fake.ipv6_range,
            config.profile.store_fake_ip,
        );
    }
    empty_response(StatusCode::NO_CONTENT)
}

pub(super) async fn dns_query(
    State(state): State<ControllerState>,
    method: Method,
    uri: Uri,
) -> Response {
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

pub(super) async fn traffic(
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

pub(super) async fn memory(
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<ControllerState>,
) -> Response {
    if let Ok(websocket) = websocket {
        return websocket.on_upgrade(move |socket| memory_websocket(socket, state));
    }
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await;
    let shutdown = state.shutdown.clone();
    let runtime = Arc::clone(&state.runtime);
    let body = Body::from_stream(stream::unfold(
        (interval, shutdown, runtime, true),
        |(mut interval, shutdown, runtime, first)| async move {
            tokio::select! {
                () = shutdown.cancelled() => None,
                _ = interval.tick() => {
                    let inuse = if first { 0 } else { runtime.process_memory() };
                    let line = json_line(&MemorySnapshot { inuse, oslimit: 0 });
                    Some((Ok::<Bytes, Infallible>(line), (interval, shutdown, runtime, false)))
                }
            }
        },
    ));
    typed_response(StatusCode::OK, "application/json", body)
}

pub(super) async fn logs(
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<ControllerState>,
    uri: Uri,
) -> Response {
    let parameters = query_parameters(&uri);
    let Some(level) = LogFilter::parse(parameters.get("level").map_or("info", String::as_str))
    else {
        return json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}));
    };
    let format = LogFormat::parse(parameters.get("format").map_or("", String::as_str));
    if let Ok(websocket) = websocket {
        return websocket.on_upgrade(move |socket| logs_websocket(socket, state, level, format));
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
                            let line = json_line(&render_log_event(&event, format));
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
pub(super) struct MemorySnapshot {
    inuse: u64,
    oslimit: u64,
}

#[derive(Clone, Copy)]
pub(super) enum LogFilter {
    Debug,
    Info,
    Warning,
    Error,
    Silent,
}

#[derive(Clone, Copy)]
pub(super) enum LogFormat {
    Simple,
    Structured,
}

impl LogFormat {
    fn parse(value: &str) -> Self {
        if value == "structured" {
            Self::Structured
        } else {
            Self::Simple
        }
    }
}

pub(super) fn render_log_event(
    event: &rewrite_state::LogEvent,
    format: LogFormat,
) -> serde_json::Value {
    match format {
        LogFormat::Simple => json!({"type": event.level, "payload": event.payload}),
        LogFormat::Structured => {
            let now = OffsetDateTime::now_utc();
            let level = if event.level == "warning" {
                "warn"
            } else {
                &event.level
            };
            json!({
                "time": format!("{:02}:{:02}:{:02}", now.hour(), now.minute(), now.second()),
                "level": level,
                "message": event.payload,
                "fields": [],
            })
        }
    }
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

pub(super) async fn connections_websocket(
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

pub(super) async fn traffic_websocket(mut socket: WebSocket, state: ControllerState) {
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

pub(super) async fn memory_websocket(mut socket: WebSocket, state: ControllerState) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await;
    let mut first = true;
    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => break,
            message = socket.recv() => if websocket_closed(message.as_ref()) { break },
            _ = interval.tick() => {
                let inuse = if first { 0 } else { state.runtime.process_memory() };
                first = false;
                if send_json_message(&mut socket, &MemorySnapshot { inuse, oslimit: 0 }).await.is_err() { break }
            },
        }
    }
}

pub(super) async fn logs_websocket(
    mut socket: WebSocket,
    state: ControllerState,
    level: LogFilter,
    format: LogFormat,
) {
    let mut receiver = state.runtime.subscribe_logs();
    loop {
        tokio::select! {
            () = state.shutdown.cancelled() => break,
            message = socket.recv() => if websocket_closed(message.as_ref()) { break },
            result = receiver.recv() => match result {
                Ok(event) if level.includes(&event.level) => {
                    if send_json_message(&mut socket, &render_log_event(&event, format)).await.is_err() { break }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            },
        }
    }
}

pub(super) async fn send_json_message<T: Serialize>(
    socket: &mut WebSocket,
    value: &T,
) -> Result<(), ()> {
    let message = String::from_utf8(json_line(value).to_vec()).map_err(|_| ())?;
    socket
        .send(Message::Text(message.into()))
        .await
        .map_err(|_| ())
}

pub(super) fn websocket_closed(message: Option<&Result<Message, axum::Error>>) -> bool {
    matches!(message, None | Some(Ok(Message::Close(_)) | Err(_)))
}
