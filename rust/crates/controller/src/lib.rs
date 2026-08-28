use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{BufReader, Cursor};
use std::path::Path as FsPath;
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
use futures_util::{StreamExt, future::join_all, stream};
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use rewrite_config::Config;
use rewrite_dns::DnsService;
use rewrite_model::{Destination, Host};
use rewrite_state::RuntimeState;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;

const MAX_DNS_MESSAGE: usize = 65_535;

mod config_api;
mod cors;
mod observability;
mod proxy;
mod response;
mod routes;
mod server;
mod tls;

use config_api::{
    apply_config_update, apply_provider_refresh, apply_update, debug_gc, decode_json_body,
    patch_configs, restart, update_configs, update_geo, update_ui,
};
use cors::apply_dynamic_cors;
use observability::{
    close_all_connections, close_connection, connections, dns_query, flush_dns_cache,
    flush_fake_ip_cache, logs, memory, traffic,
};
use proxy::{
    group, group_delay, groups, healthcheck_proxy_provider, proxies, proxy, proxy_delay,
    proxy_provider, proxy_provider_member, proxy_providers, rule_providers, select_proxy,
    unfix_proxy, update_proxy_provider, update_rule_provider,
};
pub use proxy::{healthcheck_proxy_group, healthcheck_proxy_provider_config};
use response::{
    config_snapshot, dns_message_response, dns_record_type, empty_response, json_line,
    json_response, method_not_allowed, not_found, plain_response, query_parameters, typed_response,
};
use routes::{authenticate_or_serve_public, controller_router};
#[cfg(unix)]
pub use server::serve_unix;
#[cfg(windows)]
pub use server::{prepare_named_pipe, serve_named_pipe};
pub use server::{serve, serve_tcp, serve_tls};
pub use tls::prepare_tls_config;

#[derive(Clone)]
struct ControllerState {
    dns_service: Arc<DnsService>,
    config: watch::Receiver<Arc<Config>>,
    runtime: Arc<RuntimeState>,
    shutdown: CancellationToken,
    config_updates: mpsc::Sender<ConfigUpdate>,
    require_auth: bool,
}

/// Transactional runtime configuration request initiated by the controller.
pub struct ConfigUpdate {
    pub kind: ConfigUpdateKind,
    pub completion: oneshot::Sender<Result<(), String>>,
}

pub enum ConfigUpdateKind {
    Replace(Box<Config>),
    RefreshProxyProvider(String),
    RefreshRuleProvider(String),
    Restart,
}

impl ControllerState {
    fn current_config(&self) -> Arc<Config> {
        Arc::clone(&self.config.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cors::wildcard_origin_matches;
    use crate::proxy::parse_status_ranges;
    use crate::routes::is_doh_path;

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
