use std::sync::Arc;

use rewrite_config::Config;
use rewrite_dns::DnsService;
use rewrite_state::RuntimeState;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub(crate) struct ControllerState {
    pub(crate) dns_service: Arc<DnsService>,
    pub(crate) config: watch::Receiver<Arc<Config>>,
    pub(crate) runtime: Arc<RuntimeState>,
    pub(crate) shutdown: CancellationToken,
    pub(crate) config_updates: mpsc::Sender<ConfigUpdate>,
    pub(crate) require_auth: bool,
}

impl ControllerState {
    pub(crate) fn current_config(&self) -> Arc<Config> {
        Arc::clone(&self.config.borrow())
    }
}

/// Transactional runtime configuration request initiated by the controller.
pub struct ConfigUpdate {
    pub kind: ConfigUpdateKind,
    pub completion: oneshot::Sender<Result<(), String>>,
}

pub enum ConfigUpdateKind {
    Replace(Box<Config>),
    RefreshProxyProvider(String),
    RefreshRuleProvider(String),
    Restart,
}
