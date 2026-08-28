use tokio::io::{AsyncRead, AsyncWrite};

mod direct;
mod http;
mod socks5;
mod tls;

pub use direct::{DirectError, DirectTcpOptions, connect, connect_with_options};
pub use http::{HttpProxyError, connect_http, connect_http_with_options, wrap_client_tls};
pub use socks5::{
    Socks5ProxyError, Socks5UdpAssociation, associate_socks5_udp_with_options, connect_socks5,
    connect_socks5_with_options,
};
pub use tls::HttpProxyTls;

pub trait OutboundStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> OutboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedOutboundStream = Box<dyn OutboundStream>;
