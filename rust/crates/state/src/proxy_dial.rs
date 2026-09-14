//! Optional TCP dial hook so delay / health probes share the runtime chain path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rewrite_config::Config;
use rewrite_model::Destination;

use crate::RuntimeState;

/// Future returned by [`ProxyTcpDialer::dial_proxy_tcp`].
pub type ProxyTcpDialFuture<'a> = Pin<
    Box<dyn Future<Output = Result<rewrite_outbound::BoxedOutboundStream, String>> + Send + 'a>,
>;

/// Installed by `rewrite-runtime` so controller delay/health checks dial through
/// the same `dialer-proxy` entry as business traffic.
pub trait ProxyTcpDialer: Send + Sync {
    /// Dials `proxy_name` toward `destination` using the configured chain.
    fn dial_proxy_tcp<'a>(
        &'a self,
        config: &'a Config,
        state: &'a RuntimeState,
        proxy_name: &'a str,
        destination: &'a Destination,
    ) -> ProxyTcpDialFuture<'a>;
}

/// Slot that keeps [`RuntimeState`]'s `Debug` derive working.
#[derive(Default)]
pub(crate) struct ProxyTcpDialerSlot(std::sync::Mutex<Option<Arc<dyn ProxyTcpDialer>>>);

impl std::fmt::Debug for ProxyTcpDialerSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let installed = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some();
        f.debug_struct("ProxyTcpDialerSlot")
            .field("installed", &installed)
            .finish()
    }
}

impl ProxyTcpDialerSlot {
    pub(crate) fn set(&self, dialer: Option<Arc<dyn ProxyTcpDialer>>) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = dialer;
    }

    pub(crate) fn get(&self) -> Option<Arc<dyn ProxyTcpDialer>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
