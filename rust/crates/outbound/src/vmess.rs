//! `VMess` outbound adapter.
//!
//! Socket policy stays in this crate; wire framing lives in
//! `rewrite-protocol-vmess` so a future inbound adapter can reuse it.

use rewrite_model::Destination;

use crate::{BoxedOutboundStream, DirectTcpOptions, connect_with_options};

pub use rewrite_protocol_vmess::{
    VmessClientOptions as VmessTcpOptions, VmessPacketMode, VmessProtocolError as VmessProxyError,
    VmessSecurity, VmessUdpAssociation,
};

/// Opens a `VMess` client over native TCP using outbound socket policy.
///
/// # Errors
///
/// Returns a dial or `VMess` protocol error.
pub async fn connect_vmess_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    options: VmessTcpOptions,
    socket_options: DirectTcpOptions<'_>,
) -> Result<BoxedOutboundStream, VmessProxyError> {
    let remote = connect_with_options(server, allow_ipv6, socket_options)
        .await
        .map_err(|error| VmessProxyError::Transport(error.to_string()))?;
    connect_vmess_on_stream(Box::new(remote), destination, options).await
}

/// Starts `VMess` over an established protocol-independent carrier.
///
/// # Errors
///
/// Returns a `VMess` handshake or framing error.
pub async fn connect_vmess_on_stream(
    remote: BoxedOutboundStream,
    destination: &Destination,
    options: VmessTcpOptions,
) -> Result<BoxedOutboundStream, VmessProxyError> {
    rewrite_protocol_vmess::connect_vmess_on_stream(remote, destination, options).await
}

/// Opens a native-TCP `VMess` UDP association.
///
/// # Errors
///
/// Returns a dial, `VMess` handshake or packet framing error.
pub async fn associate_vmess_udp_with_options(
    server: &Destination,
    destination: &Destination,
    allow_ipv6: bool,
    options: VmessTcpOptions,
    mode: VmessPacketMode,
    socket_options: DirectTcpOptions<'_>,
) -> Result<VmessUdpAssociation, VmessProxyError> {
    let remote = connect_with_options(server, allow_ipv6, socket_options)
        .await
        .map_err(|error| VmessProxyError::Transport(error.to_string()))?;
    rewrite_protocol_vmess::associate_vmess_udp_on_stream(
        Box::new(remote),
        destination,
        options,
        mode,
    )
    .await
}
