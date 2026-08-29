use std::collections::BTreeMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use futures_util::future::join_all;
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rewrite_config::Config;
use rewrite_model::{Destination, Host};
use rewrite_state::RuntimeState;
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config_api::{
    apply_config_update, apply_provider_refresh, apply_update, decode_json_body,
};
use crate::context::{ConfigUpdateKind, ControllerState};
use crate::response::{empty_response, json_response, query_parameters};

pub(super) const PROXY_NAMES: [&str; 7] = [
    "COMPATIBLE",
    "DIRECT",
    "GLOBAL",
    "PASS",
    "PASS-RULE",
    "REJECT",
    "REJECT-DROP",
];

pub(super) async fn proxies(State(state): State<ControllerState>) -> Response {
    let config = state.current_config();
    let mut proxies: serde_json::Map<String, serde_json::Value> = PROXY_NAMES
        .into_iter()
        .map(|name| (name.to_owned(), proxy_snapshot(name, &state.runtime)))
        .collect();
    if !config.has_custom_global_group() {
        proxies.insert(
            "GLOBAL".to_owned(),
            default_global_snapshot(&config, &state.runtime),
        );
    }
    for proxy in &config.proxies {
        proxies.insert(
            proxy.name.clone(),
            configured_proxy_snapshot(proxy, &state.runtime),
        );
    }
    for group in &config.proxy_groups {
        proxies.insert(
            group.name.clone(),
            selector_snapshot(group, &config, &state.runtime),
        );
    }
    json_response(StatusCode::OK, &json!({"proxies": proxies}))
}

pub(super) async fn proxy(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
) -> Response {
    let config = state.current_config();
    if let Some(proxy) = config.proxies.iter().find(|proxy| proxy.name == name) {
        return json_response(
            StatusCode::OK,
            &configured_proxy_snapshot(proxy, &state.runtime),
        );
    }
    if let Some(group) = config.proxy_groups.iter().find(|group| group.name == name) {
        return json_response(
            StatusCode::OK,
            &selector_snapshot(group, &config, &state.runtime),
        );
    }
    if PROXY_NAMES.contains(&name.as_str()) {
        let snapshot = if name == "GLOBAL" {
            default_global_snapshot(&config, &state.runtime)
        } else {
            proxy_snapshot(&name, &state.runtime)
        };
        return json_response(StatusCode::OK, &snapshot);
    }
    proxy_not_found()
}

pub(super) async fn groups(State(state): State<ControllerState>) -> Response {
    let config = state.current_config();
    let mut groups = if config.has_custom_global_group() {
        Vec::new()
    } else {
        vec![default_global_snapshot(&config, &state.runtime)]
    };
    groups.extend(
        config
            .proxy_groups
            .iter()
            .map(|group| selector_snapshot(group, &config, &state.runtime)),
    );
    json_response(StatusCode::OK, &json!({"proxies": groups}))
}

pub(super) async fn group(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
) -> Response {
    let config = state.current_config();
    if let Some(group) = config.proxy_groups.iter().find(|group| group.name == name) {
        return json_response(
            StatusCode::OK,
            &selector_snapshot(group, &config, &state.runtime),
        );
    }
    if name == "GLOBAL" {
        return json_response(
            StatusCode::OK,
            &default_global_snapshot(&config, &state.runtime),
        );
    }
    proxy_not_found()
}

pub(super) async fn proxy_delay(
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
        configured_group.map_or_else(
            || state.runtime.global_proxy(),
            |group| group_selected_proxy(group, &state.runtime),
        )
    } else {
        name.clone()
    };
    if timeout <= 0 {
        state.runtime.record_proxy_delay(&name, url, 0, false);
        return json_response(StatusCode::GATEWAY_TIMEOUT, &json!({"message": "Timeout"}));
    }
    let result = tokio::time::timeout(
        Duration::from_millis(u64::try_from(timeout).unwrap_or_default()),
        measure_http_delay(&tested_name, url, &expected, &config),
    )
    .await;
    match result {
        Ok(Ok(measurement)) if measurement.delay > 0 => {
            state
                .runtime
                .record_proxy_delay(&name, url, measurement.delay, measurement.satisfied);
            json_response(StatusCode::OK, &json!({"delay": measurement.delay}))
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

#[allow(clippy::too_many_lines)]
pub(super) async fn group_delay(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
    uri: Uri,
) -> Response {
    let config = state.current_config();
    let configured_group = config.proxy_groups.iter().find(|group| group.name == name);
    let automatic_group = configured_group
        .filter(|group| name == "GLOBAL" || group.kind != rewrite_config::ProxyGroupKind::Select);
    if name != "GLOBAL" && automatic_group.is_none() {
        return proxy_not_found();
    }
    if automatic_group.is_some_and(|group| {
        matches!(
            group.kind,
            rewrite_config::ProxyGroupKind::Fallback | rewrite_config::ProxyGroupKind::UrlTest
        )
    }) {
        state.runtime.clear_group_choice(&name, true);
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
    if let Some(group) = automatic_group {
        let timeout = Duration::from_millis(u64::try_from(timeout).unwrap_or_default());
        let config = config.as_ref();
        let results = join_all(group.proxies.iter().map(|member| {
            let expected = &expected;
            async move {
                let result = tokio::time::timeout(
                    timeout,
                    measure_http_delay(member, url, expected, config),
                )
                .await;
                (member, result)
            }
        }))
        .await;
        let mut delays = BTreeMap::new();
        for (member, result) in results {
            match result {
                Ok(Ok(measurement)) if measurement.delay > 0 => {
                    state.runtime.record_proxy_delay(
                        member,
                        url,
                        measurement.delay,
                        measurement.satisfied,
                    );
                    delays.insert(member.clone(), measurement.delay);
                }
                _ => state.runtime.record_proxy_delay(member, url, 0, false),
            }
        }
        return if delays.is_empty() {
            json_response(
                StatusCode::GATEWAY_TIMEOUT,
                &json!({"message": "get delay: all proxies timeout"}),
            )
        } else {
            json_response(StatusCode::OK, &delays)
        };
    }
    let result = tokio::time::timeout(
        Duration::from_millis(u64::try_from(timeout).unwrap_or_default()),
        measure_http_delay("DIRECT", url, &expected, &config),
    )
    .await;
    match result {
        Ok(Ok(measurement)) if measurement.delay > 0 => {
            state.runtime.record_proxy_delay(
                "DIRECT",
                url,
                measurement.delay,
                measurement.satisfied,
            );
            state.runtime.record_proxy_delay("REJECT", url, 0, false);
            json_response(StatusCode::OK, &json!({"DIRECT": measurement.delay}))
        }
        _ => json_response(
            StatusCode::GATEWAY_TIMEOUT,
            &json!({"message": "get delay: all proxies timeout"}),
        ),
    }
}

#[derive(Clone, Copy)]
pub(super) struct DelayMeasurement {
    delay: u16,
    satisfied: bool,
}

#[allow(clippy::too_many_lines)]
pub(super) async fn measure_http_delay(
    name: &str,
    raw_url: &str,
    expected: &[(u16, u16)],
    config: &Config,
) -> Result<DelayMeasurement, ()> {
    let url = url::Url::parse(raw_url).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(());
    }
    let host = url.host_str().ok_or(())?;
    let port = url.port_or_known_default().ok_or(())?;
    let destination_host = host.parse().map_or_else(
        |_| match config.hosts.resolve(host) {
            Some(rewrite_config::HostEntry::Addresses(addresses)) => addresses
                .into_iter()
                .next()
                .map_or_else(|| Host::Domain(host.to_owned()), Host::Ip),
            _ => Host::Domain(host.to_owned()),
        },
        Host::Ip,
    );
    let destination = Destination {
        host: destination_host,
        port,
    };
    let started = tokio::time::Instant::now();
    let mut stream: rewrite_outbound::BoxedOutboundStream =
        if matches!(name, "DIRECT" | "COMPATIBLE") {
            Box::new(
                rewrite_outbound::connect_with_options(
                    &destination,
                    config.ipv6,
                    controller_socket_options(config),
                )
                .await
                .map_err(|_| ())?,
            )
        } else {
            let proxy = config
                .proxies
                .iter()
                .chain(
                    config
                        .proxy_providers
                        .iter()
                        .flat_map(|provider| provider.proxies.iter()),
                )
                .find(|proxy| proxy.name == name)
                .ok_or(())?;
            let server = Destination {
                host: proxy
                    .server
                    .parse()
                    .map_or_else(|_| Host::Domain(proxy.server.clone()), Host::Ip),
                port: proxy.port,
            };
            match proxy.kind {
                rewrite_config::ProxyKind::Direct => rewrite_outbound::connect_with_options(
                    &destination,
                    config.ipv6,
                    controller_socket_options(config),
                )
                .await
                .map(|stream| Box::new(stream) as rewrite_outbound::BoxedOutboundStream)
                .map_err(|_| ())?,
                rewrite_config::ProxyKind::Http => {
                    let credentials = proxy.http_credentials();
                    let tls = proxy.tls.then_some(rewrite_outbound::HttpProxyTls {
                        server_name: proxy.sni.as_deref().unwrap_or(&proxy.server),
                        verification_name: proxy.name_cert_verify.as_deref(),
                        skip_certificate_verification: proxy.skip_cert_verify,
                        fingerprint: proxy.fingerprint.as_deref(),
                        certificate: proxy.certificate.as_deref(),
                        private_key: proxy.private_key.as_deref(),
                        custom_roots: &config.trust_certificates,
                        ech_config: None,
                        alpn_protocols: &[],
                    });
                    rewrite_outbound::connect_http_with_options(
                        &server,
                        &destination,
                        config.ipv6,
                        credentials,
                        &proxy.headers,
                        tls,
                        None,
                        controller_socket_options(config),
                    )
                    .await
                    .map_err(|_| ())?
                }
                rewrite_config::ProxyKind::Socks5 => {
                    let tls = proxy.tls.then_some(rewrite_outbound::HttpProxyTls {
                        server_name: &proxy.server,
                        verification_name: proxy.name_cert_verify.as_deref(),
                        skip_certificate_verification: proxy.skip_cert_verify,
                        fingerprint: proxy.fingerprint.as_deref(),
                        certificate: proxy.certificate.as_deref(),
                        private_key: proxy.private_key.as_deref(),
                        custom_roots: &config.trust_certificates,
                        ech_config: None,
                        alpn_protocols: &[],
                    });
                    rewrite_outbound::connect_socks5_with_options(
                        &server,
                        &destination,
                        config.ipv6,
                        proxy.socks5_credentials(),
                        tls,
                        None,
                        controller_socket_options(config),
                    )
                    .await
                    .map_err(|_| ())?
                }
                rewrite_config::ProxyKind::Shadowsocks => {
                    let resolved_ech = match proxy.shadowsocks_plugin.as_ref() {
                        Some(rewrite_model::ShadowsocksPluginConfig::V2rayWebSocket {
                            ech: Some(rewrite_model::V2rayEchConfig::Dns { query_server_name }),
                            host,
                            ..
                        }) => {
                            let dns = config.dns.as_ref().ok_or(())?;
                            let query = query_server_name.as_deref().unwrap_or(host);
                            Some(
                                rewrite_dns::resolve_proxy_ech(dns, query)
                                    .await
                                    .map_err(|_| ())?,
                            )
                        }
                        _ => None,
                    };
                    let inline_ech = match proxy.shadowsocks_plugin.as_ref() {
                        Some(rewrite_model::ShadowsocksPluginConfig::V2rayWebSocket {
                            ech: Some(rewrite_model::V2rayEchConfig::Inline(bytes)),
                            ..
                        }) => Some(bytes.as_slice()),
                        _ => None,
                    };
                    rewrite_outbound::connect_shadowsocks_with_plugin_options(
                        &server,
                        &destination,
                        config.ipv6,
                        proxy.password.as_deref().unwrap_or_default(),
                        proxy.cipher.as_deref().unwrap_or_default(),
                        rewrite_outbound::ShadowsocksTcpOptions {
                            socket: controller_socket_options(config),
                            plugin: proxy.shadowsocks_plugin.as_ref(),
                            clock: None,
                            custom_roots: &config.trust_certificates,
                            ech_config: resolved_ech.as_deref().or(inline_ech),
                        },
                    )
                    .await
                    .map_err(|_| ())?
                }
                rewrite_config::ProxyKind::Reject
                | rewrite_config::ProxyKind::Dns
                | rewrite_config::ProxyKind::Rematch => return Err(()),
            }
        };
    if url.scheme() == "https" {
        stream = rewrite_outbound::wrap_client_tls(
            stream,
            host,
            false,
            &config.trust_certificates,
            None,
        )
        .await
        .map_err(|_| ())?;
    }
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
    let satisfied = expected.is_empty()
        || expected
            .iter()
            .any(|(start, end)| (*start..=*end).contains(&status));
    Ok(DelayMeasurement {
        delay: u16::try_from(started.elapsed().as_millis()).map_err(|_| ())?,
        satisfied,
    })
}

pub(super) fn controller_socket_options(config: &Config) -> rewrite_outbound::DirectTcpOptions<'_> {
    rewrite_outbound::DirectTcpOptions {
        interface: &config.interface_name,
        routing_mark: config.routing_mark,
        keep_alive_idle: config.keep_alive_idle,
        keep_alive_interval: config.keep_alive_interval,
        disable_keep_alive: config.disable_keep_alive,
        tcp_concurrent: config.tcp_concurrent,
    }
}

pub(super) fn parse_status_ranges(value: &str) -> Option<Vec<(u16, u16)>> {
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
pub(super) struct ProxySelection {
    name: String,
}

pub(super) async fn select_proxy(
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
    if configured_group
        .is_some_and(|group| group.kind == rewrite_config::ProxyGroupKind::LoadBalance)
    {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": "Must be a Selector"}),
        );
    }
    let updated = if let Some(group) = configured_group {
        state
            .runtime
            .set_selector_proxy(&name, &selection.name, &group.proxies)
    } else if name == "GLOBAL" {
        state
            .runtime
            .set_global_proxy(&selection.name, &config.default_global_proxies())
    } else {
        false
    };
    if !updated {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": "Selector update error: proxy not exist"}),
        );
    }
    empty_response(StatusCode::NO_CONTENT)
}

pub(super) async fn unfix_proxy(Path(name): Path<String>) -> Response {
    if !PROXY_NAMES.contains(&name.as_str()) {
        return proxy_not_found();
    }
    json_response(StatusCode::BAD_REQUEST, &json!({"message": "Body invalid"}))
}

pub(super) fn proxy_snapshot(name: &str, runtime: &RuntimeState) -> serde_json::Value {
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

pub(super) fn default_global_snapshot(
    config: &Config,
    runtime: &RuntimeState,
) -> serde_json::Value {
    let mut value = proxy_snapshot("GLOBAL", runtime);
    let object = value.as_object_mut().expect("GLOBAL snapshot is an object");
    object.insert("all".to_owned(), json!(config.default_global_proxies()));
    object.insert(
        "udp".to_owned(),
        json!(selector_supports_udp(
            &runtime.global_proxy(),
            config,
            runtime,
            &mut Vec::new(),
        )),
    );
    value
}

pub(super) fn configured_proxy_snapshot(
    proxy: &rewrite_config::ProxyConfig,
    runtime: &RuntimeState,
) -> serde_json::Value {
    configured_proxy_snapshot_with_provider(proxy, "", runtime)
}

pub(super) fn configured_proxy_snapshot_with_provider(
    proxy: &rewrite_config::ProxyConfig,
    provider: &str,
    runtime: &RuntimeState,
) -> serde_json::Value {
    let health = runtime.proxy_health(&proxy.name);
    let kind = match proxy.kind {
        rewrite_config::ProxyKind::Http => "Http",
        rewrite_config::ProxyKind::Socks5 => "Socks5",
        rewrite_config::ProxyKind::Shadowsocks => "Shadowsocks",
        rewrite_config::ProxyKind::Direct => "Direct",
        rewrite_config::ProxyKind::Reject => "Reject",
        rewrite_config::ProxyKind::Dns => "Dns",
        rewrite_config::ProxyKind::Rematch => "Rematch",
    };
    let udp = match proxy.kind {
        rewrite_config::ProxyKind::Socks5 | rewrite_config::ProxyKind::Shadowsocks => proxy.udp,
        rewrite_config::ProxyKind::Direct
        | rewrite_config::ProxyKind::Reject
        | rewrite_config::ProxyKind::Dns
        | rewrite_config::ProxyKind::Rematch => true,
        rewrite_config::ProxyKind::Http => false,
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
        "provider-name": provider,
        "routing-mark": 0,
        "smux": false,
        "tfo": false,
        "type": kind,
        "udp": udp,
        "uot": proxy.kind == rewrite_config::ProxyKind::Shadowsocks && proxy.udp_over_tcp,
        "xudp": false,
    })
}

pub(super) fn selector_snapshot(
    group: &rewrite_config::ProxyGroupConfig,
    config: &Config,
    runtime: &RuntimeState,
) -> serde_json::Value {
    let health = runtime.proxy_health(&group.name);
    let selected = group_selected_proxy(group, runtime);
    let udp = !group.disable_udp
        && (group.kind == rewrite_config::ProxyGroupKind::LoadBalance
            || selector_supports_udp(&selected, config, runtime, &mut Vec::new()));
    let (kind, test_url) = match group.kind {
        rewrite_config::ProxyGroupKind::Select => (
            "Selector",
            if group.test_url == "https://www.gstatic.com/generate_204" {
                ""
            } else {
                group.test_url.as_str()
            },
        ),
        rewrite_config::ProxyGroupKind::Fallback => ("Fallback", group.test_url.as_str()),
        rewrite_config::ProxyGroupKind::UrlTest => ("URLTest", group.test_url.as_str()),
        rewrite_config::ProxyGroupKind::LoadBalance => ("LoadBalance", group.test_url.as_str()),
    };
    let mut snapshot = json!({
        "alive": health.alive,
        "all": group.proxies,
        "dialer-proxy": "",
        "emptyFallback": group.empty_fallback,
        "extra": health.extra,
        "hidden": group.hidden,
        "history": health.history,
        "icon": group.icon,
        "interface": "",
        "mptcp": false,
        "name": group.name,
        "now": selected,
        "provider-name": "",
        "routing-mark": 0,
        "smux": false,
        "testUrl": test_url,
        "tfo": false,
        "type": kind,
        "udp": udp,
        "uot": false,
        "xudp": false,
    });
    if group.kind != rewrite_config::ProxyGroupKind::Select {
        snapshot
            .as_object_mut()
            .expect("group snapshot object")
            .insert("expectedStatus".to_owned(), json!(group.expected_status));
    }
    if matches!(
        group.kind,
        rewrite_config::ProxyGroupKind::Fallback | rewrite_config::ProxyGroupKind::UrlTest
    ) {
        let object = snapshot.as_object_mut().expect("group snapshot object");
        object.insert(
            "fixed".to_owned(),
            json!(runtime.selector_proxy(&group.name).unwrap_or_default()),
        );
    }
    if group.kind == rewrite_config::ProxyGroupKind::LoadBalance {
        snapshot
            .as_object_mut()
            .expect("group snapshot object")
            .remove("now");
    }
    snapshot
}

pub(super) fn group_selected_proxy(
    group: &rewrite_config::ProxyGroupConfig,
    runtime: &RuntimeState,
) -> String {
    match group.kind {
        rewrite_config::ProxyGroupKind::Select => {
            runtime.selector_proxy(&group.name).unwrap_or_default()
        }
        rewrite_config::ProxyGroupKind::Fallback => runtime
            .fallback_proxy(&group.name, &group.proxies, &group.test_url)
            .unwrap_or_default(),
        rewrite_config::ProxyGroupKind::UrlTest => runtime
            .url_test_proxy(
                &group.name,
                &group.proxies,
                &group.test_url,
                group.tolerance,
            )
            .unwrap_or_default(),
        rewrite_config::ProxyGroupKind::LoadBalance => String::new(),
    }
}

pub(super) fn selector_supports_udp(
    selected: &str,
    config: &Config,
    runtime: &RuntimeState,
    visited: &mut Vec<String>,
) -> bool {
    if matches!(
        selected,
        "DIRECT" | "COMPATIBLE" | "REJECT" | "REJECT-DROP" | "PASS" | "PASS-RULE"
    ) {
        return true;
    }
    if let Some(proxy) = config
        .proxies
        .iter()
        .chain(
            config
                .proxy_providers
                .iter()
                .flat_map(|provider| provider.proxies.iter()),
        )
        .find(|proxy| proxy.name == selected)
    {
        return match proxy.kind {
            rewrite_config::ProxyKind::Socks5 | rewrite_config::ProxyKind::Shadowsocks => proxy.udp,
            rewrite_config::ProxyKind::Direct
            | rewrite_config::ProxyKind::Reject
            | rewrite_config::ProxyKind::Dns
            | rewrite_config::ProxyKind::Rematch => true,
            rewrite_config::ProxyKind::Http => false,
        };
    }
    let Some(group) = config
        .proxy_groups
        .iter()
        .find(|group| group.name == selected)
    else {
        return false;
    };
    if visited.iter().any(|name| name == selected) {
        return false;
    }
    visited.push(selected.to_owned());
    let nested = group_selected_proxy(group, runtime);
    let nested = !group.disable_udp && selector_supports_udp(&nested, config, runtime, visited);
    visited.pop();
    nested
}

pub(super) fn proxy_id(name: &str) -> &'static str {
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

pub(super) fn proxy_not_found() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        &json!({"message": "Resource not found"}),
    )
}

pub(super) async fn proxy_providers(State(state): State<ControllerState>) -> Response {
    let config = state.current_config();
    let mut providers = serde_json::Map::new();
    providers.insert(
        "default".to_owned(),
        proxy_provider_snapshot(&config, &state.runtime),
    );
    for provider in &config.proxy_providers {
        providers.insert(
            provider.name.clone(),
            file_proxy_provider_snapshot(provider, &state.runtime),
        );
    }
    for group in config
        .proxy_groups
        .iter()
        .filter(|group| !group.compatible_proxies.is_empty())
    {
        providers.insert(
            group.name.clone(),
            group_compatible_provider_snapshot(group, &config, &state.runtime),
        );
    }
    json_response(StatusCode::OK, &json!({"providers": providers}))
}

pub(super) async fn proxy_provider(
    State(state): State<ControllerState>,
    Path(provider): Path<String>,
) -> Response {
    let config = state.current_config();
    if provider == "default" {
        return json_response(
            StatusCode::OK,
            &proxy_provider_snapshot(&config, &state.runtime),
        );
    }
    config
        .proxy_providers
        .iter()
        .find(|candidate| candidate.name == provider)
        .map_or_else(
            || {
                config
                    .proxy_groups
                    .iter()
                    .find(|group| group.name == provider && !group.compatible_proxies.is_empty())
                    .map_or_else(proxy_not_found, |group| {
                        json_response(
                            StatusCode::OK,
                            &group_compatible_provider_snapshot(group, &config, &state.runtime),
                        )
                    })
            },
            |provider| {
                json_response(
                    StatusCode::OK,
                    &file_proxy_provider_snapshot(provider, &state.runtime),
                )
            },
        )
}

pub(super) async fn update_proxy_provider(
    State(state): State<ControllerState>,
    Path(provider): Path<String>,
) -> Response {
    let config = state.current_config();
    if provider == "default"
        || config
            .proxy_groups
            .iter()
            .any(|candidate| candidate.name == provider && !candidate.compatible_proxies.is_empty())
    {
        return empty_response(StatusCode::NO_CONTENT);
    }
    let Some(configured) = config
        .proxy_providers
        .iter()
        .find(|candidate| candidate.name == provider)
    else {
        return proxy_not_found();
    };
    if configured.vehicle == rewrite_config::ProxyProviderVehicle::Http {
        return apply_provider_refresh(&state, provider).await;
    }
    let next = match config.reload_proxy_provider(&provider) {
        Ok(next) => next,
        Err(error) => {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"message": error.to_string()}),
            );
        }
    };
    apply_config_update(&state, next).await
}

pub(super) async fn healthcheck_proxy_provider(
    State(state): State<ControllerState>,
    Path(provider): Path<String>,
) -> Response {
    let config = state.current_config();
    if provider != "default"
        && !config
            .proxy_providers
            .iter()
            .any(|candidate| candidate.name == provider)
        && !config
            .proxy_groups
            .iter()
            .any(|candidate| candidate.name == provider && !candidate.compatible_proxies.is_empty())
    {
        return proxy_not_found();
    }
    if let Some(configured) = config
        .proxy_providers
        .iter()
        .find(|candidate| candidate.name == provider)
    {
        healthcheck_proxy_provider_config(configured, &config, &state.runtime).await;
    } else if let Some(group) = config.proxy_groups.iter().find(|candidate| {
        candidate.name == provider && candidate.kind != rewrite_config::ProxyGroupKind::Select
    }) {
        healthcheck_proxy_group(group, &config, &state.runtime).await;
    }
    empty_response(StatusCode::NO_CONTENT)
}

/// Measures every member of one configured proxy provider.
pub async fn healthcheck_proxy_provider_config(
    provider: &rewrite_config::ProxyProviderConfig,
    config: &Config,
    state: &RuntimeState,
) {
    if !provider.health_check.enabled {
        return;
    }
    let expected = parse_status_ranges(&provider.health_check.expected_status).unwrap_or_default();
    let timeout = Duration::from_millis(provider.health_check.timeout);
    let results = join_all(provider.proxies.iter().map(|member| {
        let expected = &expected;
        async move {
            let result = tokio::time::timeout(
                timeout,
                measure_http_delay(&member.name, &provider.health_check.url, expected, config),
            )
            .await;
            (&member.name, result)
        }
    }))
    .await;
    for (member, result) in results {
        match result {
            Ok(Ok(measurement)) if measurement.delay > 0 => {
                state.record_proxy_delay(
                    member,
                    &provider.health_check.url,
                    measurement.delay,
                    measurement.satisfied,
                );
            }
            _ => state.record_proxy_delay(member, &provider.health_check.url, 0, false),
        }
    }
}

/// Measures every member of one automatic group and publishes per-URL health.
pub async fn healthcheck_proxy_group(
    group: &rewrite_config::ProxyGroupConfig,
    config: &Config,
    state: &RuntimeState,
) {
    let expected = parse_status_ranges(&group.expected_status).unwrap_or_default();
    let timeout = Duration::from_millis(group.health.timeout);
    let results = join_all(group.proxies.iter().map(|member| {
        let expected = &expected;
        async move {
            let result = tokio::time::timeout(
                timeout,
                measure_http_delay(member, &group.test_url, expected, config),
            )
            .await;
            (member, result)
        }
    }))
    .await;
    for (member, result) in results {
        match result {
            Ok(Ok(measurement)) if measurement.delay > 0 => {
                state.record_proxy_delay(
                    member,
                    &group.test_url,
                    measurement.delay,
                    measurement.satisfied,
                );
            }
            _ => state.record_proxy_delay(member, &group.test_url, 0, false),
        }
    }
}

pub(super) async fn proxy_provider_member(
    State(state): State<ControllerState>,
    Path((provider, name)): Path<(String, String)>,
) -> Response {
    if provider == "default" && matches!(name.as_str(), "DIRECT" | "REJECT") {
        return json_response(StatusCode::OK, &proxy_snapshot(&name, &state.runtime));
    }
    let config = state.current_config();
    if provider == "default"
        && let Some(proxy) = config.proxies.iter().find(|proxy| proxy.name == name)
    {
        return json_response(
            StatusCode::OK,
            &configured_proxy_snapshot(proxy, &state.runtime),
        );
    }
    if provider == "default" {
        return config
            .proxy_groups
            .iter()
            .find(|group| group.name == name)
            .map_or_else(proxy_not_found, |group| {
                json_response(
                    StatusCode::OK,
                    &selector_snapshot(group, &config, &state.runtime),
                )
            });
    }
    config
        .proxy_providers
        .iter()
        .find(|candidate| candidate.name == provider)
        .and_then(|provider| {
            provider
                .proxies
                .iter()
                .find(|proxy| proxy.name == name)
                .map(|proxy| (provider, proxy))
        })
        .map_or_else(
            || group_provider_member(&config, &state.runtime, &provider, &name),
            |(provider, proxy)| {
                json_response(
                    StatusCode::OK,
                    &configured_proxy_snapshot_with_provider(proxy, &provider.name, &state.runtime),
                )
            },
        )
}

pub(super) async fn rule_providers(State(state): State<ControllerState>) -> Response {
    let config = state.current_config();
    let providers: BTreeMap<_, _> = config
        .rule_providers
        .iter()
        .map(|(name, provider)| (name.clone(), rule_provider_snapshot(provider)))
        .collect();
    json_response(StatusCode::OK, &json!({"providers": providers}))
}

pub(super) async fn update_rule_provider(
    State(state): State<ControllerState>,
    Path(name): Path<String>,
) -> Response {
    if !state.current_config().rule_providers.contains_key(&name) {
        return proxy_not_found();
    }
    apply_update(
        &state,
        ConfigUpdateKind::RefreshRuleProvider(name),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await
}

pub(super) fn rule_provider_snapshot(
    provider: &rewrite_config::RuleProviderConfig,
) -> serde_json::Value {
    let behavior = match provider.behavior {
        rewrite_config::ProviderBehavior::Domain => "Domain",
        rewrite_config::ProviderBehavior::IpCidr => "IPCIDR",
        rewrite_config::ProviderBehavior::Classical => "Classical",
    };
    let vehicle = match provider.vehicle {
        rewrite_config::RuleProviderVehicle::Inline => "Inline",
        rewrite_config::RuleProviderVehicle::File => "File",
        rewrite_config::RuleProviderVehicle::Http => "HTTP",
    };
    let format = match provider.vehicle {
        rewrite_config::RuleProviderVehicle::Inline => "",
        _ => match provider.format {
            rewrite_config::RuleProviderFormat::Yaml => "YamlRule",
            rewrite_config::RuleProviderFormat::Text => "TextRule",
            rewrite_config::RuleProviderFormat::Mrs => "MrsRule",
        },
    };
    let updated_at = provider
        .cache_modified
        .and_then(|modified| OffsetDateTime::from(modified).format(&Rfc3339).ok())
        .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_owned());
    let mut snapshot = json!({
        "behavior": behavior,
        "format": format,
        "name": provider.name,
        "ruleCount": provider.payload.len(),
        "type": "Rule",
        "updatedAt": updated_at,
        "vehicleType": vehicle,
    });
    if provider.vehicle == rewrite_config::RuleProviderVehicle::Inline {
        snapshot
            .as_object_mut()
            .expect("rule provider snapshot object")
            .insert("payload".to_owned(), json!(provider.payload));
    }
    snapshot
}

pub(super) fn proxy_provider_snapshot(
    config: &Config,
    runtime: &RuntimeState,
) -> serde_json::Value {
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
            .map(|group| selector_snapshot(group, config, runtime)),
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

pub(super) fn file_proxy_provider_snapshot(
    provider: &rewrite_config::ProxyProviderConfig,
    runtime: &RuntimeState,
) -> serde_json::Value {
    let proxies: Vec<_> = provider
        .proxies
        .iter()
        .map(|proxy| configured_proxy_snapshot_with_provider(proxy, &provider.name, runtime))
        .collect();
    let updated_at = provider
        .cache_modified
        .or_else(|| {
            std::fs::metadata(&provider.path)
                .and_then(|metadata| metadata.modified())
                .ok()
        })
        .and_then(|modified| OffsetDateTime::from(modified).format(&Rfc3339).ok())
        .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_owned());
    let vehicle_type = match provider.vehicle {
        rewrite_config::ProxyProviderVehicle::Inline => "Inline",
        rewrite_config::ProxyProviderVehicle::File => "File",
        rewrite_config::ProxyProviderVehicle::Http => "HTTP",
    };
    json!({
        "name": provider.name,
        "type": "Proxy",
        "vehicleType": vehicle_type,
        "proxies": proxies,
        "testUrl": provider.health_check.url,
        "expectedStatus": provider.health_check.expected_status,
        "updatedAt": updated_at,
    })
}

pub(super) fn group_compatible_provider_snapshot(
    group: &rewrite_config::ProxyGroupConfig,
    config: &Config,
    runtime: &RuntimeState,
) -> serde_json::Value {
    let proxies: Vec<_> = group
        .compatible_proxies
        .iter()
        .filter_map(|name| named_proxy_snapshot(config, runtime, name))
        .collect();
    json!({
        "name": group.name,
        "type": "Proxy",
        "vehicleType": "Compatible",
        "proxies": proxies,
        "testUrl": "https://www.gstatic.com/generate_204",
        "expectedStatus": "*",
        "updatedAt": "0001-01-01T00:00:00Z",
    })
}

pub(super) fn group_provider_member(
    config: &Config,
    runtime: &RuntimeState,
    provider: &str,
    name: &str,
) -> Response {
    let Some(group) = config
        .proxy_groups
        .iter()
        .find(|group| group.name == provider)
    else {
        return proxy_not_found();
    };
    if !group.compatible_proxies.iter().any(|member| member == name) {
        return proxy_not_found();
    }
    named_proxy_snapshot(config, runtime, name).map_or_else(proxy_not_found, |snapshot| {
        json_response(StatusCode::OK, &snapshot)
    })
}

pub(super) fn named_proxy_snapshot(
    config: &Config,
    runtime: &RuntimeState,
    name: &str,
) -> Option<serde_json::Value> {
    if PROXY_NAMES.contains(&name) {
        return Some(proxy_snapshot(name, runtime));
    }
    config
        .proxies
        .iter()
        .find(|proxy| proxy.name == name)
        .map(|proxy| configured_proxy_snapshot(proxy, runtime))
        .or_else(|| {
            config
                .proxy_groups
                .iter()
                .find(|group| group.name == name)
                .map(|group| selector_snapshot(group, config, runtime))
        })
}
