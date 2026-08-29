use tokio::io::{AsyncRead, AsyncWrite};

mod direct;
mod http;
mod shadowsocks;
mod simple_obfs;
mod socks5;
mod tls;
mod websocket;

pub use direct::{DirectError, DirectTcpOptions, connect, connect_with_options};
pub use http::{HttpProxyError, connect_http, connect_http_with_options, wrap_client_tls};
pub use shadowsocks::{
    ShadowsocksProxyError, ShadowsocksUdpAssociation, ShadowsocksUotAssociation,
    associate_shadowsocks_udp_with_options, associate_shadowsocks_uot_with_options,
    connect_shadowsocks_with_options, connect_shadowsocks_with_plugin_options,
};
pub use simple_obfs::{HttpObfsClient, HttpObfsServer, TlsObfsClient, TlsObfsServer};
pub use socks5::{
    Socks5ProxyError, Socks5UdpAssociation, associate_socks5_udp_with_options, connect_socks5,
    connect_socks5_with_options,
};
pub use tls::HttpProxyTls;
pub use websocket::{WebSocketIo, connect_websocket};

pub trait OutboundStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> OutboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedOutboundStream = Box<dyn OutboundStream>;
