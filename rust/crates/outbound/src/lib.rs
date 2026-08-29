mod direct;
mod http;
mod shadowsocks;
mod socks5;
mod tls;

pub use direct::{DirectError, DirectTcpOptions, connect, connect_with_options};
pub use http::{HttpProxyError, connect_http, connect_http_with_options, wrap_client_tls};
pub use shadowsocks::{ShadowsocksError, connect_shadowsocks_with_options};
pub use socks5::{
    Socks5ProxyError, Socks5UdpAssociation, associate_socks5_udp_with_options, connect_socks5,
    connect_socks5_with_options,
};
pub use tls::HttpProxyTls;

pub trait OutboundStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> OutboundStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

pub type BoxedOutboundStream = Box<dyn OutboundStream>;
