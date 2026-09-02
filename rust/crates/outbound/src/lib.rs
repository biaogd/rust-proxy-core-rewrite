mod direct;
mod http;
mod shadowsocks;
mod socks5;
mod vless;
mod vmess;

pub use direct::{
    DirectError, DirectTcpOptions, connect, connect_udp_with_options, connect_with_options,
};
pub use http::{
    HttpProxyError, connect_http, connect_http_with_options, wrap_client_tls,
    wrap_client_tls_with_alpn, wrap_client_tls_with_options,
};
pub use rewrite_transport::BoxedStream as BoxedOutboundStream;
pub use rewrite_transport::ClientTlsOptions as HttpProxyTls;
pub use rewrite_transport::{
    HttpObfsClient, HttpObfsServer, ShadowTlsAcceptResult, ShadowTlsConnectOptions, ShadowTlsError,
    ShadowTlsHandshakeDial, ShadowTlsServerConfig, TlsObfsClient, TlsObfsServer, V2rayMux,
    V2rayMuxNetwork, V2rayMuxOptions, WebSocketIo, accept_shadow_tls_v3,
    connect_http_upgrade_with_early_data, connect_shadow_tls, connect_v2ray_http_upgrade,
    connect_v2ray_websocket, connect_websocket, connect_websocket_with_early_data,
    connect_websocket_with_headers,
};
pub use rewrite_transport::{
    MekyaConnection, MekyaConnector, MekyaOptions, MkcpConfig, connect_mekya, connect_mkcp,
};
pub use rewrite_transport::{
    V2rayGrpcClient as VmessGrpcClient, V2rayGrpcClientOptions as VmessGrpcClientOptions,
    connect_v2ray_grpc as connect_vmess_grpc, connect_v2ray_h2 as connect_vmess_h2,
    connect_v2ray_http as connect_vmess_http,
};
pub use shadowsocks::{
    ShadowsocksProxyError, ShadowsocksTcpOptions, ShadowsocksUdpAssociation,
    ShadowsocksUotAssociation, associate_shadowsocks_udp_with_options,
    associate_shadowsocks_uot_with_options, connect_shadowsocks_with_options,
    connect_shadowsocks_with_plugin_options,
};
pub use socks5::{
    Socks5ProxyError, Socks5UdpAssociation, associate_socks5_udp_with_options, connect_socks5,
    connect_socks5_with_options,
};
pub use vless::{VlessProxyError, VlessTcpOptions, connect_vless_with_options};
pub use vmess::{
    VmessPacketMode, VmessProxyError, VmessSecurity, VmessTcpOptions, VmessUdpAssociation,
    associate_vmess_udp_with_options, connect_vmess_on_stream, connect_vmess_with_options,
};
