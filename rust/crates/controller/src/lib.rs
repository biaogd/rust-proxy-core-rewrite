use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

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
}

/// Serves the declared Phase 3B read APIs and Phase 4D4 DNS control subset.
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
    if !config.secret.is_empty()
        && request.headers.get("authorization") != Some(&format!("Bearer {}", config.secret))
    {
        return write_json(&mut stream, 401, &json!({"message": "Unauthorized"})).await;
    }
    let path = request.path.split('?').next().unwrap_or(&request.path);
    if request.method == "POST" && path == "/cache/dns/flush" {
        dns_service.clear_cache().await;
        return write_empty(&mut stream, 204).await;
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
            let record_type = match parameters.get("type").map_or("A", String::as_str) {
                "" | "A" => 1,
                "CNAME" => 5,
                "AAAA" => 28,
                _ => {
                    return write_json(&mut stream, 400, &json!({"message": "invalid query type"}))
                        .await;
                }
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
    let text = std::str::from_utf8(&bytes).map_err(|_| ControllerError::InvalidRequest)?;
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
    let headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_lowercase(), value.trim().to_owned()))
        .collect();
    Ok(Request {
        method,
        path,
        headers,
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
