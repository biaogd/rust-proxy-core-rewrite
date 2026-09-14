//! Shared TCP dial entry for Phase 7T1-A `dialer-proxy` chains.
//!
//! Protocol crates stay free of runtime/group dependencies: they only handshake
//! on the bidirectional stream this module produces to the selected proxy's
//! `server:port`.

use std::collections::BTreeSet;

use rewrite_config::{Config, ProxyKind};
use rewrite_model::{InboundProtocol, Metadata, Network};
use rewrite_state::RuntimeState;

use crate::tcp::{
    configured_proxy, connect_configured_proxy_with_chain, direct_tcp_options, proxy_server,
    resolve_proxy_dial_server, resolve_selector_target,
};

/// Visited leaf proxy names while resolving a dialer-proxy chain.
#[derive(Clone, Debug, Default)]
pub(super) struct DialChain {
    visited: BTreeSet<String>,
}

impl DialChain {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn enter(&mut self, name: &str) -> Result<(), String> {
        if !self.visited.insert(name.to_owned()) {
            return Err(format!(
                "proxy [{name}] has circular dialer-proxy dependency"
            ));
        }
        Ok(())
    }
}

/// Dials `proxy.server:port`, optionally through `proxy.dialer_proxy`.
///
/// When a dialer-proxy is configured, B's host string is preserved for A (no
/// PSN pre-resolution). Failures never fall back to a DIRECT dial of B.
pub(super) async fn dial_proxy_server(
    proxy: &rewrite_config::ProxyConfig,
    config: &Config,
    state: &RuntimeState,
    socket_options: rewrite_outbound::DirectTcpOptions<'_>,
    chain: &mut DialChain,
) -> Result<rewrite_outbound::BoxedOutboundStream, String> {
    chain.enter(&proxy.name)?;
    let server = proxy_server(proxy);
    let Some(dialer_name) = proxy
        .dialer_proxy
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        let resolved =
            resolve_proxy_dial_server(server, &config.hosts, config.dns.as_ref(), config.ipv6)
                .await?;
        return rewrite_outbound::connect_with_options(&resolved, config.ipv6, socket_options)
            .await
            .map(|stream| Box::new(stream) as rewrite_outbound::BoxedOutboundStream)
            .map_err(|error| format!("{} outer TCP connection failed: {error}", proxy.name));
    };

    let mut metadata = Metadata::new(server.clone(), InboundProtocol::Inner);
    metadata.network = Network::Tcp;
    let (leaf, _) =
        resolve_selector_target(dialer_name, &metadata, config, state).ok_or_else(|| {
            format!(
                "proxy [{}] dialer-proxy [{dialer_name}] not found",
                proxy.name
            )
        })?;

    match leaf.as_str() {
        "DIRECT" => {
            let resolved =
                resolve_proxy_dial_server(server, &config.hosts, config.dns.as_ref(), config.ipv6)
                    .await?;
            rewrite_outbound::connect_with_options(&resolved, config.ipv6, socket_options)
                .await
                .map(|stream| Box::new(stream) as rewrite_outbound::BoxedOutboundStream)
                .map_err(|error| format!("{} outer TCP connection failed: {error}", proxy.name))
        }
        "REJECT" | "REJECT-DROP" => Err(format!(
            "proxy [{}] dialer-proxy [{dialer_name}] rejected the hop",
            proxy.name
        )),
        _ => {
            let dialer = configured_proxy(config, &leaf).ok_or_else(|| {
                format!(
                    "proxy [{}] dialer-proxy [{dialer_name}] resolved to unknown [{leaf}]",
                    proxy.name
                )
            })?;
            if matches!(
                dialer.kind,
                ProxyKind::Hysteria2 | ProxyKind::Tuic | ProxyKind::WireGuard | ProxyKind::Ssh
            ) {
                return Err(format!(
                    "proxy [{}] dialer-proxy [{leaf}] cannot dial TCP server hops in 7T1-A",
                    proxy.name
                ));
            }
            // A dials B's server address; do not re-enter ordinary rule matching.
            Box::pin(connect_configured_proxy_with_chain(
                dialer,
                &server,
                config,
                state,
                socket_options,
                chain,
            ))
            .await
        }
    }
}

/// Convenience for call sites that do not already own a [`DialChain`].
#[allow(dead_code)]
pub(super) async fn dial_proxy_server_fresh(
    proxy: &rewrite_config::ProxyConfig,
    config: &Config,
    state: &RuntimeState,
) -> Result<rewrite_outbound::BoxedOutboundStream, String> {
    let mut chain = DialChain::new();
    dial_proxy_server(proxy, config, state, direct_tcp_options(config), &mut chain).await
}

#[cfg(test)]
mod tests {
    use super::DialChain;

    #[test]
    fn dial_chain_rejects_reentry() {
        let mut chain = DialChain::new();
        chain.enter("a").expect("first");
        assert!(chain.enter("a").unwrap_err().contains("circular"));
    }
}
