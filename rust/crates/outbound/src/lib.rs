use tokio::io::{AsyncRead, AsyncWrite};

mod direct;
mod http;
mod http_upgrade;
mod shadow_tls;
mod shadow_tls_config;
mod shadow_tls_server;
mod shadowsocks;
mod simple_obfs;
mod socks5;
mod tls;
mod v2ray_mux;
mod vmess;
mod websocket;

pub use direct::{DirectError, DirectTcpOptions, connect, connect_with_options};
pub use http::{
    HttpProxyError, connect_http, connect_http_with_options, wrap_client_tls,
    wrap_client_tls_with_options,
};
pub use http_upgrade::{connect_http_upgrade_with_early_data, connect_v2ray_http_upgrade};
pub use shadow_tls::{ShadowTlsConnectOptions, ShadowTlsError, connect_shadow_tls};
pub use shadow_tls_server::{
    ShadowTlsAcceptResult, ShadowTlsHandshakeDial, ShadowTlsServerConfig, accept_shadow_tls_v3,
};
pub use shadowsocks::{
    ShadowsocksProxyError, ShadowsocksTcpOptions, ShadowsocksUdpAssociation,
    ShadowsocksUotAssociation, associate_shadowsocks_udp_with_options,
    associate_shadowsocks_uot_with_options, connect_shadowsocks_with_options,
    connect_shadowsocks_with_plugin_options,
};
pub use simple_obfs::{HttpObfsClient, HttpObfsServer, TlsObfsClient, TlsObfsServer};
pub use socks5::{
    Socks5ProxyError, Socks5UdpAssociation, associate_socks5_udp_with_options, connect_socks5,
    connect_socks5_with_options,
};
pub use tls::HttpProxyTls;
pub use v2ray_mux::{V2rayMux, V2rayMuxNetwork, V2rayMuxOptions};
pub use vmess::{
    VmessPacketMode, VmessProxyError, VmessSecurity, VmessTcpOptions, VmessUdpAssociation,
    associate_vmess_udp_with_options, connect_vmess_on_stream, connect_vmess_with_options,
};
pub use websocket::{
    WebSocketIo, connect_v2ray_websocket, connect_websocket, connect_websocket_with_early_data,
    connect_websocket_with_headers,
};

pub trait OutboundStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> OutboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedOutboundStream = Box<dyn OutboundStream>;
