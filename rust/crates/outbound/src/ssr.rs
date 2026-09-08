use rewrite_model::Destination;
use thiserror::Error;

use crate::{BoxedOutboundStream, DirectError, DirectTcpOptions, connect_with_options};

#[derive(Debug, Error)]
pub enum SsrProxyError {
    #[error(transparent)]
    Direct(#[from] DirectError),
    #[error(transparent)]
    ProtocolCore(#[from] rewrite_protocol_shadowsocksr::ShadowsocksRProtocolError),
}

/// Opens the upstream TCP socket, then stacks SSR obfs → cipher → protocol.
///
/// # Errors
///
/// Returns when the dial fails or SSR options are unimplemented.
#[allow(clippy::too_many_arguments)]
pub async fn connect_ssr_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    password: &str,
    cipher: &str,
    protocol: &str,
    protocol_param: &str,
    obfs: &str,
    obfs_param: &str,
    options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, SsrProxyError> {
    let stream = connect_with_options(server, allow_ipv6, options).await?;
    let options = rewrite_protocol_shadowsocksr::SsrClientOptions {
        password: password.to_owned(),
        cipher: cipher.to_owned(),
        protocol: protocol.to_owned(),
        protocol_param: protocol_param.to_owned(),
        obfs: obfs.to_owned(),
        obfs_param: obfs_param.to_owned(),
        server_host: server.host.to_string(),
        server_port: server.port,
    };
    rewrite_protocol_shadowsocksr::connect_tcp_on_stream(Box::new(stream), destination, &options)
        .await
        .map_err(Into::into)
}
