mod connections;
mod dns_state;
mod groups;
mod model;
mod storage;
#[cfg(test)]
mod tests;

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use lru::LruCache;
use tokio::sync::{Mutex as AsyncMutex, Notify, broadcast};

pub use connections::ConnectionGuard;
pub use model::{
    ConnectionInfo, ConnectionSnapshot, LogEvent, MetadataSnapshot, ProxyDelayHistory,
    ProxyHealthSnapshot, ProxyUrlHealth, TrafficSnapshot,
};

use connections::ActiveConnection;
use dns_state::{DnsMappingCache, FakeIpRegistry};
use groups::{GroupDialHealth, ProxyHealth, StickySession};
use storage::StorageEntry;

#[derive(Debug)]
pub struct RuntimeState {
    next_id: AtomicU64,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    connections: Mutex<BTreeMap<u64, ActiveConnection>>,
    logs: broadcast::Sender<LogEvent>,
    system: Mutex<sysinfo::System>,
    storage: Mutex<BTreeMap<String, StorageEntry>>,
    storage_persistent: AtomicBool,
    global_proxy: Mutex<String>,
    selectors: Mutex<BTreeMap<String, String>>,
    automatic_groups: Mutex<BTreeMap<String, String>>,
    round_robin_groups: Mutex<BTreeMap<String, usize>>,
    sticky_groups: Mutex<BTreeMap<String, LruCache<u64, StickySession>>>,
    load_balance_hasher: RandomState,
    group_touches: Mutex<BTreeMap<String, Instant>>,
    group_dial_health: Mutex<BTreeMap<String, GroupDialHealth>>,
    group_health_pending: Mutex<BTreeSet<String>>,
    group_health_notify: Notify,
    selectors_loaded: AtomicBool,
    store_selected: AtomicBool,
    proxy_health: Mutex<BTreeMap<String, ProxyHealth>>,
    dns_mappings: Mutex<DnsMappingCache>,
    fake_ips: Mutex<FakeIpRegistry>,
    grpc_clients: AsyncMutex<BTreeMap<String, (String, Arc<rewrite_outbound::GrpcClient>)>>,
    xhttp_clients: AsyncMutex<BTreeMap<String, (String, Arc<rewrite_outbound::XHttpClient>)>>,
    clock: Arc<rewrite_services::AdjustedClock>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        let (logs, _) = broadcast::channel(1024);
        Self {
            next_id: AtomicU64::new(1),
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
            connections: Mutex::new(BTreeMap::new()),
            logs,
            system: Mutex::new(sysinfo::System::new()),
            storage: Mutex::new(BTreeMap::new()),
            storage_persistent: AtomicBool::new(false),
            global_proxy: Mutex::new("DIRECT".to_owned()),
            selectors: Mutex::new(BTreeMap::new()),
            automatic_groups: Mutex::new(BTreeMap::new()),
            round_robin_groups: Mutex::new(BTreeMap::new()),
            sticky_groups: Mutex::new(BTreeMap::new()),
            load_balance_hasher: RandomState::new(),
            group_touches: Mutex::new(BTreeMap::new()),
            group_dial_health: Mutex::new(BTreeMap::new()),
            group_health_pending: Mutex::new(BTreeSet::new()),
            group_health_notify: Notify::new(),
            selectors_loaded: AtomicBool::new(false),
            store_selected: AtomicBool::new(true),
            proxy_health: Mutex::new(BTreeMap::new()),
            dns_mappings: Mutex::new(DnsMappingCache::default()),
            fake_ips: Mutex::new(FakeIpRegistry::default()),
            grpc_clients: AsyncMutex::new(BTreeMap::new()),
            xhttp_clients: AsyncMutex::new(BTreeMap::new()),
            clock: Arc::new(rewrite_services::AdjustedClock::default()),
        }
    }
}

impl RuntimeState {
    pub async fn grpc_client(
        &self,
        name: &str,
        identity: String,
        options: rewrite_outbound::GrpcClientOptions,
    ) -> Arc<rewrite_outbound::GrpcClient> {
        let previous = {
            let mut clients = self.grpc_clients.lock().await;
            if let Some((current_identity, client)) = clients.get(name)
                && current_identity == &identity
            {
                return Arc::clone(client);
            }
            let previous = clients.remove(name).map(|(_, client)| client);
            let client = Arc::new(rewrite_outbound::GrpcClient::new(options));
            clients.insert(name.to_owned(), (identity, Arc::clone(&client)));
            (client, previous)
        };
        if let Some(old) = previous.1 {
            old.retire().await;
        }
        previous.0
    }

    pub async fn clear_grpc_clients(&self) {
        let clients = {
            let mut clients = self.grpc_clients.lock().await;
            std::mem::take(&mut *clients)
        };
        for (_, client) in clients.into_values() {
            client.retire().await;
        }
    }

    pub async fn xhttp_client(
        &self,
        name: &str,
        identity: String,
        options: rewrite_outbound::XHttpOptions,
        reuse: rewrite_outbound::XHttpReuseOptions,
    ) -> Arc<rewrite_outbound::XHttpClient> {
        let previous = {
            let mut clients = self.xhttp_clients.lock().await;
            if let Some((current_identity, client)) = clients.get(name)
                && current_identity == &identity
            {
                return Arc::clone(client);
            }
            let previous = clients.remove(name).map(|(_, client)| client);
            let client = Arc::new(rewrite_outbound::XHttpClient::new(options, reuse));
            clients.insert(name.to_owned(), (identity, Arc::clone(&client)));
            (client, previous)
        };
        if let Some(old) = previous.1 {
            old.retire().await;
        }
        previous.0
    }

    pub async fn clear_xhttp_clients(&self) {
        let clients = {
            let mut clients = self.xhttp_clients.lock().await;
            std::mem::take(&mut *clients)
        };
        for (_, client) in clients.into_values() {
            client.retire().await;
        }
    }
}
