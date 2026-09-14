use super::{ControllerState, group_delay};
use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use http_body_util::BodyExt;
use rewrite_config::Config;
use rewrite_dns::DnsService;
use rewrite_state::RuntimeState;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

// Go GroupBase.URLTest accepts a successful zero-millisecond sample.
#[tokio::test(start_paused = true)]
async fn successful_zero_millisecond_group_probe_is_not_a_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.expect("request"));
            assert!(request.len() <= 2048, "unexpected oversized request");
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .expect("response");
    });
    // Keep the paused clock from auto-advancing while socket I/O is pending.
    let stop = CancellationToken::new();
    let clock_stop = stop.clone();
    let clock_guard = tokio::spawn(async move {
        let wall_start = Instant::now();
        while !clock_stop.is_cancelled() && wall_start.elapsed() < Duration::from_secs(5) {
            tokio::task::yield_now().await;
        }
    });
    let config = Config::from_yaml("proxy-groups:\n  - name: probe\n    type: url-test\n    proxies: [DIRECT]\n    url: http://localhost/\n    interval: 3600\nrules: ['MATCH,DIRECT']\n").expect("config");
    let (_sender, config) = watch::channel(Arc::new(config));
    let (config_updates, _updates) = mpsc::channel(1);
    let runtime = Arc::new(RuntimeState::default());
    let state = ControllerState {
        dns_service: Arc::new(DnsService::new()),
        config,
        runtime: Arc::clone(&runtime),
        shutdown: CancellationToken::new(),
        config_updates,
        require_auth: false,
    };
    let uri: Uri = format!("/group/probe/delay?url=http://127.0.0.1:{port}/&timeout=5000")
        .parse()
        .expect("uri");
    let response = group_delay(State(state), Path("probe".to_owned()), uri).await;
    stop.cancel();
    clock_guard.await.expect("clock guard");
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("server must finish")
        .expect("server");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
        serde_json::json!({"DIRECT": 0})
    );
    assert!(runtime.proxy_alive_for_url("DIRECT", &format!("http://127.0.0.1:{port}/")));
}
