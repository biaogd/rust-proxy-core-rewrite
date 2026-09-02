//! VLESS outbound adapter.
//!
//! Socket policy remains here while wire framing lives in
//! `rewrite-protocol-vless` for reuse by future inbound support.

use rewrite_model::Destination;

use crate::{BoxedOutboundStream, DirectTcpOptions, connect_with_options};

pub use rewrite_protocol_vless::{
    VlessClientOptions as VlessTcpOptions, VlessFlow, VlessPacketMode,
    VlessProtocolError as VlessProxyError, VlessUdpAssociation, associate_vless_udp_on_stream,
};

/// Opens a VLESS client over native TCP using outbound socket policy.
///
/// # Errors
///
/// Returns a dial or VLESS protocol error.
pub async fn connect_vless_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    options: VlessTcpOptions,
    socket_options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, VlessProxyError> {
    let remote = connect_with_options(server, allow_ipv6, socket_options)
        .await
        .map_err(|error| VlessProxyError::Transport(error.to_string()))?;
    connect_vless_on_stream(Box::new(remote), destination, options)
}

/// Starts VLESS over an established protocol-independent carrier.
///
/// # Errors
///
/// Returns a VLESS framing error when the destination cannot be represented.
pub fn connect_vless_on_stream(
    remote: BoxedOutboundStream,
    destination: &Destination,
    options: VlessTcpOptions,
) -> Result<BoxedOutboundStream, VlessProxyError> {
    rewrite_protocol_vless::connect_vless_on_stream(remote, destination, options)
}

/// Opens a VLESS UDP association over native TCP using outbound socket policy.
///
/// # Errors
///
/// Returns a dial or VLESS protocol error.
pub async fn associate_vless_udp_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    options: VlessTcpOptions,
    mode: VlessPacketMode,
    socket_options: DirectTcpOptions<'_>,
) -> Result<VlessUdpAssociation, VlessProxyError> {
    let remote = connect_with_options(server, allow_ipv6, socket_options)
        .await
        .map_err(|error| VlessProxyError::Transport(error.to_string()))?;
    associate_vless_udp_on_stream(Box::new(remote), destination, options, mode).await
}
