//! Protocol-independent byte-stream transports.
//!
//! Protocol crates depend on this crate for the common duplex stream boundary.
//! Concrete carriers are added here as they are detached from adapter policy.

mod http_upgrade;
mod shadow_tls;
mod shadow_tls_config;
mod shadow_tls_server;
mod simple_obfs;
mod tls;
mod v2ray_grpc;
mod v2ray_h2;
mod v2ray_http;
mod v2ray_mux;
mod websocket;

pub use http_upgrade::{connect_http_upgrade_with_early_data, connect_v2ray_http_upgrade};
pub use shadow_tls::{ShadowTlsConnectOptions, ShadowTlsError, connect_shadow_tls};
pub use shadow_tls_server::{
    ShadowTlsAcceptResult, ShadowTlsHandshakeDial, ShadowTlsServerConfig, accept_shadow_tls_v3,
};
pub use simple_obfs::{HttpObfsClient, HttpObfsServer, TlsObfsClient, TlsObfsServer};
pub use tls::{ClientTlsOptions, TlsClientError, client_config};
pub use v2ray_grpc::{V2rayGrpcClient, V2rayGrpcClientOptions, connect_v2ray_grpc};
pub use v2ray_h2::connect_v2ray_h2;
pub use v2ray_http::connect_v2ray_http;
pub use v2ray_mux::{V2rayMux, V2rayMuxNetwork, V2rayMuxOptions};
pub use websocket::{
    WebSocketIo, connect_v2ray_websocket, connect_websocket, connect_websocket_with_early_data,
    connect_websocket_with_headers,
};

pub use rewrite_io::{BoxedStream, DuplexStream};
