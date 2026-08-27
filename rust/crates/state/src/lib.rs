use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bbolt_rs::{
    Bolt, BucketApi, BucketRwApi, CursorApi, DbApi, DbRwAPI, Error as BoltError, TxApi, TxRwRefApi,
};
use ipnet::IpNet;
use lru::LruCache;
use rewrite_model::{Host, InboundProtocol, Metadata, Network};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Notify, broadcast};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataSnapshot {
    pub network: String,
    #[serde(rename = "type")]
    pub inbound_type: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(rename = "sourceGeoIP")]
    pub source_geo_ip: Option<Vec<String>>,
    #[serde(rename = "destinationGeoIP")]
    pub destination_geo_ip: Option<Vec<String>>,
    #[serde(rename = "sourceIPASN")]
    pub source_ipasn: String,
    #[serde(rename = "destinationIPASN")]
    pub destination_ipasn: String,
    pub source_port: String,
    pub destination_port: String,
    #[serde(rename = "inboundIP")]
    pub inbound_ip: String,
    pub inbound_port: String,
    pub inbound_name: String,
    pub inbound_user: String,
    pub rematch_name: String,
    pub host: String,
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
    pub uid: u32,
    pub process: String,
    pub process_path: String,
    pub special_proxy: String,
    pub special_rules: String,
    pub remote_destination: String,
    pub dscp: u8,
    pub sniff_host: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionInfo {
    pub id: String,
    pub metadata: MetadataSnapshot,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub provider_chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub download_total: u64,
    pub upload_total: u64,
    pub connections: Option<Vec<ConnectionInfo>>,
    pub memory: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSnapshot {
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyDelayHistory {
    pub time: String,
    pub delay: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyUrlHealth {
    pub alive: bool,
    pub history: Vec<ProxyDelayHistory>,
}

#[derive(Clone, Debug)]
pub struct ProxyHealthSnapshot {
    pub alive: bool,
    pub history: Vec<ProxyDelayHistory>,
    pub extra: BTreeMap<String, ProxyUrlHealth>,
}

#[derive(Debug)]
struct ProxyHealth {
    alive: bool,
    history: Vec<ProxyDelayHistory>,
    extra: BTreeMap<String, ProxyUrlHealth>,
}

#[derive(Debug, Default)]
struct GroupDialHealth {
    failed_times: u64,
    failed_at: Option<Instant>,
    testing: bool,
}

#[derive(Debug)]
pub struct RuntimeState {
    next_id: AtomicU64,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    connections: Mutex<BTreeMap<u64, ActiveConnection>>,
    logs: broadcast::Sender<LogEvent>,
    storage: Mutex<BTreeMap<String, Vec<u8>>>,
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
}

#[derive(Clone, Debug)]
struct DnsMapping {
    host: String,
    recency: u64,
}

#[derive(Debug)]
struct ActiveConnection {
    info: ConnectionInfo,
    cancellation: CancellationToken,
}

#[derive(Clone, Copy, Debug)]
struct StickySession {
    index: usize,
    touched: Instant,
}

fn jump_hash(mut key: u64, buckets: usize) -> usize {
    let mut previous = -1_i64;
    let mut candidate = 0_i64;
    let bucket_limit = i64::try_from(buckets).unwrap_or(i64::MAX);
    while candidate < bucket_limit {
        previous = candidate;
        key = key.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(1);
        let numerator = u64::try_from(previous + 1)
            .unwrap_or_default()
            .saturating_mul(1_u64 << 31);
        candidate = i64::try_from(numerator / ((key >> 33) + 1)).unwrap_or(i64::MAX);
    }
    usize::try_from(previous).unwrap_or_default()
}

#[derive(Debug, Default)]
struct DnsMappingCache {
    entries: BTreeMap<IpAddr, DnsMapping>,
    clock: u64,
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
            storage: Mutex::new(BTreeMap::new()),
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
        }
    }
}

impl RuntimeState {
    #[must_use]
    pub fn register(
        self: &Arc<Self>,
        metadata: &Metadata,
        target: &str,
        rule: Option<&str>,
    ) -> ConnectionGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let info = ConnectionInfo {
            id: format!("rust-{id}"),
            metadata: MetadataSnapshot::from(metadata),
            upload: 0,
            download: 0,
            start: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            chains: vec![target.to_owned()],
            provider_chains: vec![String::new()],
            rule: rule.unwrap_or_default().to_owned(),
            rule_payload: String::new(),
        };
        let cancellation = CancellationToken::new();
        self.connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                id,
                ActiveConnection {
                    info,
                    cancellation: cancellation.clone(),
                },
            );
        ConnectionGuard {
            id,
            state: Arc::clone(self),
            cancellation,
        }
    }

    #[must_use]
    pub fn connections(&self) -> ConnectionSnapshot {
        let connections: Vec<_> = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(|connection| connection.info.clone())
            .collect();
        ConnectionSnapshot {
            download_total: self.downloaded.load(Ordering::Relaxed),
            upload_total: self.uploaded.load(Ordering::Relaxed),
            connections: (!connections.is_empty()).then_some(connections),
            memory: 0,
        }
    }

    #[must_use]
    pub fn traffic(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            up: 0,
            down: 0,
            up_total: self.uploaded.load(Ordering::Relaxed),
            down_total: self.downloaded.load(Ordering::Relaxed),
        }
    }

    /// Cancels one live connection by its public controller identifier.
    pub fn close_connection(&self, public_id: &str) {
        let cancellation = {
            let mut connections = self
                .connections
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let id = connections
                .iter()
                .find_map(|(id, connection)| (connection.info.id == public_id).then_some(*id));
            id.and_then(|id| connections.remove(&id))
                .map(|connection| connection.cancellation)
        };
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }

    /// Cancels every connection present at the start of this operation.
    pub fn close_all_connections(&self) {
        let cancellations: Vec<_> = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extract_if(.., |_, _| true)
            .map(|(_, connection)| connection.cancellation)
            .collect();
        for cancellation in cancellations {
            cancellation.cancel();
        }
    }

    pub fn log(&self, level: &str, payload: impl Into<String>) {
        let _ = self.logs.send(LogEvent {
            level: level.to_owned(),
            payload: payload.into(),
        });
    }

    #[must_use]
    pub fn storage_get(&self, key: &str) -> Option<Vec<u8>> {
        self.storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    pub fn storage_set(&self, key: String, value: Vec<u8>) {
        self.storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, value);
    }

    pub fn storage_delete(&self, key: &str) {
        self.storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }

    #[must_use]
    pub fn global_proxy(&self) -> String {
        self.global_proxy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn set_global_proxy(&self, name: &str) -> bool {
        if !matches!(name, "DIRECT" | "REJECT") {
            return false;
        }
        name.clone_into(
            &mut self
                .global_proxy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        true
    }

    pub fn sync_group_choices<'a>(
        &self,
        groups: impl IntoIterator<Item = (&'a str, &'a [String], Option<&'a str>, bool)>,
        store_selected: bool,
    ) {
        self.store_selected.store(store_selected, Ordering::Release);
        let mut selectors = self
            .selectors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if store_selected && !self.selectors_loaded.swap(true, Ordering::AcqRel) {
            selectors.extend(load_selected_state());
        }
        let mut current = BTreeMap::new();
        for (name, members, default, allow_empty) in groups {
            let selected = match (selectors.get(name), allow_empty) {
                (Some(previous), true) if previous.is_empty() || members.contains(previous) => {
                    Some(previous.clone())
                }
                (Some(_) | None, true) => Some(String::new()),
                (Some(previous), false) if members.contains(previous) => Some(previous.clone()),
                (Some(_), false) => members.first().cloned(),
                (None, false) => default
                    .filter(|selected| members.iter().any(|member| member == selected))
                    .map(str::to_owned)
                    .or_else(|| members.first().cloned()),
            };
            if let Some(selected) = selected {
                current.insert(name.to_owned(), selected);
            }
        }
        *selectors = current;
    }

    #[must_use]
    pub fn selector_proxy(&self, name: &str) -> Option<String> {
        self.selectors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    pub fn set_selector_proxy(&self, name: &str, selected: &str, members: &[String]) -> bool {
        if !members.iter().any(|member| member == selected) {
            return false;
        }
        let mut selectors = self
            .selectors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(value) = selectors.get_mut(name) else {
            return false;
        };
        selected.clone_into(value);
        drop(selectors);
        if self.store_selected.load(Ordering::Acquire) {
            store_selected_state(name, selected);
        }
        true
    }

    pub fn clear_group_choice(&self, name: &str, persist: bool) -> bool {
        let mut selectors = self
            .selectors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(value) = selectors.get_mut(name) else {
            return false;
        };
        value.clear();
        drop(selectors);
        if persist && self.store_selected.load(Ordering::Acquire) {
            store_selected_state(name, "");
        }
        true
    }

    #[must_use]
    pub fn fallback_proxy(&self, name: &str, members: &[String], url: &str) -> Option<String> {
        let fixed = self.selector_proxy(name).unwrap_or_default();
        if !fixed.is_empty() && self.proxy_alive_for_url(&fixed, url) {
            return Some(fixed);
        }
        if !fixed.is_empty() {
            self.clear_group_choice(name, false);
        }
        members
            .iter()
            .find(|member| self.proxy_alive_for_url(member, url))
            .or_else(|| members.first())
            .cloned()
    }

    #[must_use]
    pub fn url_test_proxy(
        &self,
        name: &str,
        members: &[String],
        url: &str,
        tolerance: u16,
    ) -> Option<String> {
        let fixed = self.selector_proxy(name).unwrap_or_default();
        if !fixed.is_empty() && self.proxy_alive_for_url(&fixed, url) {
            return Some(fixed);
        }
        if !fixed.is_empty() {
            self.clear_group_choice(name, false);
        }

        let health = self
            .proxy_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let candidates: Vec<_> = members
            .iter()
            .filter_map(|member| {
                let status = health.get(member).and_then(|health| health.extra.get(url));
                if status.is_some_and(|status| !status.alive) {
                    return None;
                }
                let delay = status
                    .and_then(|status| status.history.last())
                    .map_or(0, |record| record.delay);
                Some((member, delay))
            })
            .collect();
        drop(health);
        let (fastest, fastest_delay) = candidates
            .iter()
            .min_by_key(|(_, delay)| *delay)
            .map(|(member, delay)| ((*member).clone(), *delay))
            .or_else(|| members.first().cloned().map(|member| (member, 0)))?;

        let mut automatic = self
            .automatic_groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(current) = automatic.get(name)
            && let Some((_, current_delay)) = candidates
                .iter()
                .find(|(member, _)| member.as_str() == current)
            && *current_delay <= fastest_delay.saturating_add(tolerance)
        {
            return Some(current.clone());
        }
        automatic.insert(name.to_owned(), fastest.clone());
        Some(fastest)
    }

    #[must_use]
    pub fn round_robin_proxy(&self, name: &str, members: &[String], url: &str) -> Option<String> {
        if members.is_empty() {
            return None;
        }
        let mut positions = self
            .round_robin_groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let position = positions.entry(name.to_owned()).or_default();
        for offset in 0..members.len() {
            let index = (*position + offset) % members.len();
            if self.proxy_alive_for_url(&members[index], url) {
                *position = (index + 1) % members.len();
                return Some(members[index].clone());
            }
        }
        Some(members[0].clone())
    }

    pub fn touch_proxy_group(&self, name: &str) {
        self.group_touches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(name.to_owned(), Instant::now());
    }

    pub fn retain_proxy_groups<'a>(&self, names: impl IntoIterator<Item = &'a str>) {
        let names: std::collections::BTreeSet<_> = names.into_iter().collect();
        self.group_touches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|name, _| names.contains(name.as_str()));
        self.group_dial_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|name, _| names.contains(name.as_str()));
        self.group_health_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|name| names.contains(name.as_str()));
    }

    pub fn record_group_dial_failure(
        &self,
        name: &str,
        timeout: Duration,
        max_failed_times: u64,
        connection_refused: bool,
    ) {
        let now = Instant::now();
        let mut groups = self
            .group_dial_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let group = groups.entry(name.to_owned()).or_default();
        let trigger = if connection_refused {
            !group.testing
        } else {
            group.failed_times = group.failed_times.saturating_add(1);
            if group.failed_times == 1 {
                group.failed_at = Some(now);
                false
            } else if group
                .failed_at
                .is_some_and(|failed_at| now.duration_since(failed_at) > timeout)
            {
                group.failed_times = 0;
                group.failed_at = None;
                false
            } else {
                group.failed_times >= max_failed_times && !group.testing
            }
        };
        if trigger {
            group.testing = true;
        }
        drop(groups);
        if trigger {
            self.group_health_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(name.to_owned());
            self.group_health_notify.notify_one();
        }
    }

    pub async fn next_group_health_trigger(&self) -> String {
        loop {
            let notified = self.group_health_notify.notified();
            if let Some(name) = self
                .group_health_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_first()
            {
                return name;
            }
            notified.await;
        }
    }

    #[must_use]
    pub fn begin_group_health_check(&self, name: &str) -> bool {
        let mut groups = self
            .group_dial_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let group = groups.entry(name.to_owned()).or_default();
        if group.testing {
            return false;
        }
        group.testing = true;
        true
    }

    pub fn finish_group_health_check(&self, name: &str) {
        let mut groups = self
            .group_dial_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(group) = groups.get_mut(name) {
            group.testing = false;
            group.failed_times = 0;
            group.failed_at = None;
        }
    }

    #[must_use]
    pub fn proxy_group_touched_within(&self, name: &str, interval: Duration) -> bool {
        self.group_touches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .is_some_and(|touched| touched.elapsed() < interval)
    }

    #[must_use]
    pub fn consistent_hash_proxy(
        &self,
        members: &[String],
        url: &str,
        key: &str,
    ) -> Option<String> {
        let hash = self.load_balance_hasher.hash_one(key);
        self.hashed_healthy_proxy(members, url, hash)
    }

    #[must_use]
    pub fn sticky_session_proxy(
        &self,
        name: &str,
        members: &[String],
        url: &str,
        key: &str,
    ) -> Option<String> {
        if members.is_empty() {
            return None;
        }
        let hash = self.load_balance_hasher.hash_one(key);
        let now = Instant::now();
        let mut groups = self
            .sticky_groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sessions = groups
            .entry(name.to_owned())
            .or_insert_with(|| LruCache::new(NonZeroUsize::new(1000).unwrap_or(NonZeroUsize::MIN)));
        if let Some(session) = sessions.get(&hash).copied()
            && now.duration_since(session.touched) < Duration::from_mins(10)
            && session.index < members.len()
            && self.proxy_alive_for_url(&members[session.index], url)
        {
            return Some(members[session.index].clone());
        }
        let selected = self.hashed_healthy_index(members, url, hash).unwrap_or(0);
        sessions.put(
            hash,
            StickySession {
                index: selected,
                touched: now,
            },
        );
        Some(members[selected].clone())
    }

    fn hashed_healthy_proxy(&self, members: &[String], url: &str, hash: u64) -> Option<String> {
        let selected = self.hashed_healthy_index(members, url, hash)?;
        Some(members[selected].clone())
    }

    fn hashed_healthy_index(&self, members: &[String], url: &str, hash: u64) -> Option<usize> {
        if members.is_empty() {
            return None;
        }
        for attempt in 0..5_u64 {
            let index = jump_hash(hash.wrapping_add(attempt), members.len());
            if self.proxy_alive_for_url(&members[index], url) {
                return Some(index);
            }
        }
        members
            .iter()
            .position(|member| self.proxy_alive_for_url(member, url))
            .or(Some(0))
    }

    #[must_use]
    pub fn proxy_health(&self, name: &str) -> ProxyHealthSnapshot {
        self.proxy_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .map_or_else(
                || ProxyHealthSnapshot {
                    alive: true,
                    history: Vec::new(),
                    extra: BTreeMap::new(),
                },
                |health| ProxyHealthSnapshot {
                    alive: health.alive,
                    history: health.history.clone(),
                    extra: health.extra.clone(),
                },
            )
    }

    #[must_use]
    pub fn proxy_alive_for_url(&self, name: &str, url: &str) -> bool {
        self.proxy_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .and_then(|health| health.extra.get(url))
            .is_none_or(|health| health.alive)
    }

    pub fn record_proxy_delay(&self, name: &str, url: &str, delay: u16, alive: bool) {
        const HISTORY_LIMIT: usize = 10;
        let record = ProxyDelayHistory {
            time: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            delay: if alive { delay } else { 0 },
        };
        let mut health = self
            .proxy_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let health = health
            .entry(name.to_owned())
            .or_insert_with(|| ProxyHealth {
                alive: true,
                history: Vec::new(),
                extra: BTreeMap::new(),
            });
        health.alive = alive;
        health.history.push(record.clone());
        if health.history.len() > HISTORY_LIMIT {
            health.history.remove(0);
        }
        let url_health = health
            .extra
            .entry(url.to_owned())
            .or_insert_with(|| ProxyUrlHealth {
                alive: true,
                history: Vec::new(),
            });
        url_health.alive = alive;
        url_health.history.push(record);
        if url_health.history.len() > HISTORY_LIMIT {
            url_health.history.remove(0);
        }
    }

    #[must_use]
    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEvent> {
        self.logs.subscribe()
    }

    pub fn insert_dns_mapping(&self, address: IpAddr, host: &str, _ttl: u32) {
        const CAPACITY: usize = 4096;
        // The pinned Go enhancer calls SetWithExpire but constructs this cache
        // with WithSize only. Its LRU therefore never consults the timestamp;
        // preserve that observable size-only behavior until the oracle moves.
        let mut mappings = self
            .dns_mappings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let address = address.to_canonical();
        if mappings.entries.len() >= CAPACITY
            && !mappings.entries.contains_key(&address)
            && let Some(least_recent) = mappings
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.recency)
                .map(|(address, _)| *address)
        {
            mappings.entries.remove(&least_recent);
        }
        mappings.clock = mappings.clock.wrapping_add(1);
        let recency = mappings.clock;
        mappings.entries.insert(
            address,
            DnsMapping {
                host: host.to_owned(),
                recency,
            },
        );
    }

    #[must_use]
    pub fn lookup_dns_mapping(&self, address: IpAddr) -> Option<String> {
        let address = address.to_canonical();
        let mut mappings = self
            .dns_mappings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mappings.clock = mappings.clock.wrapping_add(1);
        let recency = mappings.clock;
        mappings.entries.get_mut(&address).map(|entry| {
            entry.recency = recency;
            entry.host.clone()
        })
    }

    #[must_use]
    pub fn allocate_fake_ip(&self, network: IpNet, host: &str, persistent: bool) -> IpAddr {
        let mut registry = self
            .fake_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.pool_mut(network, persistent).lookup(host)
    }

    #[must_use]
    pub fn lookup_fake_ip(
        &self,
        network: IpNet,
        address: IpAddr,
        persistent: bool,
    ) -> Option<String> {
        let mut registry = self
            .fake_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .pool_mut(network, persistent)
            .look_back(address.to_canonical())
    }

    pub fn flush_fake_ips(&self, ipv4: Option<IpNet>, ipv6: Option<IpNet>, persistent: bool) {
        let mut registry = self
            .fake_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for network in ipv4.into_iter().chain(ipv6) {
            registry.pool_mut(network, persistent).flush();
        }
    }

    pub fn store_fake_ip_state(&self) {
        let mut registry = self
            .fake_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pool) = registry.ipv4.as_mut() {
            pool.store_state();
        }
        if let Some(pool) = registry.ipv6.as_mut() {
            pool.store_state();
        }
    }
}

const FAKE_IP_MEMORY_CAPACITY: usize = 1000;

#[derive(Debug, Default)]
struct FakeIpRegistry {
    ipv4: Option<FakeIpPool>,
    ipv6: Option<FakeIpPool>,
}

impl FakeIpRegistry {
    fn pool_mut(&mut self, network: IpNet, persistent: bool) -> &mut FakeIpPool {
        let slot = match network {
            IpNet::V4(_) => &mut self.ipv4,
            IpNet::V6(_) => &mut self.ipv6,
        };
        if slot
            .as_ref()
            .is_none_or(|pool| pool.network != network || pool.persistent != persistent)
        {
            let mut replacement = FakeIpPool::new(network, persistent);
            if !persistent && let Some(previous) = slot.as_ref().filter(|pool| !pool.persistent) {
                replacement.clone_memory_from(previous);
            }
            *slot = Some(replacement);
        }
        slot.as_mut().expect("fake-IP pool was initialized")
    }
}

#[derive(Debug)]
struct FakeIpPool {
    network: IpNet,
    first: u128,
    last: u128,
    offset: u128,
    cycle: bool,
    persistent: bool,
    tick: u64,
    by_host: BTreeMap<String, FakeIpEntry>,
    by_ip: BTreeMap<IpAddr, String>,
}

#[derive(Clone, Debug)]
struct FakeIpEntry {
    address: IpAddr,
    touched: u64,
}

impl FakeIpPool {
    fn new(network: IpNet, persistent: bool) -> Self {
        let (network_number, last) = network_bounds(network);
        let first = network_number + 4;
        let mut pool = Self {
            network,
            first,
            last,
            offset: first - 1,
            cycle: false,
            persistent,
            tick: 0,
            by_host: BTreeMap::new(),
            by_ip: BTreeMap::new(),
        };
        pool.restore();
        pool
    }

    fn clone_memory_from(&mut self, previous: &Self) {
        self.tick = previous.tick;
        self.by_host.clone_from(&previous.by_host);
        self.by_ip.clone_from(&previous.by_ip);
    }

    fn lookup(&mut self, host: &str) -> IpAddr {
        let host = host.to_lowercase();
        if let Some(address) = self.by_host.get(&host).map(|entry| entry.address) {
            self.touch(&host);
            return address;
        }

        let mut next = self.offset + 1;
        if next >= self.last {
            self.cycle = true;
            next = self.first;
        }
        self.offset = next;
        let address = number_to_ip(next, self.network);
        if self.cycle || self.by_ip.contains_key(&address) {
            self.remove_address(address);
        }
        self.tick = self.tick.wrapping_add(1);
        self.by_ip.insert(address, host.clone());
        self.by_host.insert(
            host,
            FakeIpEntry {
                address,
                touched: self.tick,
            },
        );
        if !self.persistent && self.by_host.len() > FAKE_IP_MEMORY_CAPACITY {
            self.evict_lru();
        }
        self.persist();
        address
    }

    fn look_back(&mut self, address: IpAddr) -> Option<String> {
        let host = self.by_ip.get(&address)?.clone();
        self.touch(&host);
        Some(host)
    }

    fn touch(&mut self, host: &str) {
        self.tick = self.tick.wrapping_add(1);
        if let Some(entry) = self.by_host.get_mut(host) {
            entry.touched = self.tick;
        }
    }

    fn evict_lru(&mut self) {
        if let Some((host, address)) = self
            .by_host
            .iter()
            .min_by_key(|(_, entry)| entry.touched)
            .map(|(host, entry)| (host.clone(), entry.address))
        {
            self.by_host.remove(&host);
            self.by_ip.remove(&address);
        }
    }

    fn remove_address(&mut self, address: IpAddr) {
        if let Some(host) = self.by_ip.remove(&address) {
            self.by_host.remove(&host);
        }
    }

    fn flush(&mut self) {
        self.offset = self.first - 1;
        self.cycle = false;
        self.tick = 0;
        self.by_host.clear();
        self.by_ip.clear();
        if self.persistent {
            flush_fake_ip_bucket(self.network);
        }
    }

    fn restore(&mut self) {
        if !self.persistent {
            return;
        }
        let path = fake_ip_state_path();
        let database = match Bolt::open(&path) {
            Ok(database) => database,
            Err(
                BoltError::InvalidDatabase(_)
                | BoltError::ChecksumMismatch
                | BoltError::VersionMismatch
                | BoltError::FileSizeTooSmall(_),
            ) => {
                let _ = std::fs::remove_file(path);
                return;
            }
            Err(_) => return,
        };
        let mut incompatible = false;
        let bucket_name = fake_ip_bucket(self.network);
        let _ = database.view(|transaction| {
            let Some(bucket) = transaction.bucket(bucket_name) else {
                return Ok(());
            };
            if let Some(bytes) = bucket.get(FAKE_IP_OFFSET_KEY) {
                if let Some(address) = address_from_bytes(bytes) {
                    let number = ip_to_number(address);
                    if self.network.contains(&address) && number >= self.first && number < self.last
                    {
                        self.offset = number;
                        self.cycle = bucket.get(FAKE_IP_CYCLE_KEY).is_some();
                    } else {
                        incompatible = true;
                    }
                } else if bucket
                    .get(ip_bytes(number_to_ip(self.first, self.network)))
                    .is_some()
                {
                    incompatible = true;
                }
            } else if bucket
                .get(ip_bytes(number_to_ip(self.first, self.network)))
                .is_some()
            {
                incompatible = true;
            }
            if incompatible {
                return Ok(());
            }
            let mut cursor = bucket.cursor();
            let mut item = cursor.first();
            while let Some((key, Some(value))) = item {
                if key != FAKE_IP_OFFSET_KEY
                    && key != FAKE_IP_CYCLE_KEY
                    && address_from_bytes(key).is_none()
                    && let Ok(host) = std::str::from_utf8(key)
                    && let Some(address) = address_from_bytes(value)
                {
                    let host = host.to_owned();
                    self.tick = self.tick.wrapping_add(1);
                    self.by_ip.insert(address, host.clone());
                    self.by_host.insert(
                        host,
                        FakeIpEntry {
                            address,
                            touched: self.tick,
                        },
                    );
                }
                item = cursor.next();
            }
            Ok(())
        });
        drop(database);
        if incompatible {
            self.flush();
        }
    }

    fn persist(&self) {
        if !self.persistent {
            return;
        }
        let path = fake_ip_state_path();
        let Some(parent) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(mut database) = Bolt::open(path) else {
            return;
        };
        let bucket_name = fake_ip_bucket(self.network);
        let _ = database.update(|mut transaction| {
            let saved_offset = transaction
                .bucket(bucket_name)
                .and_then(|bucket| bucket.get(FAKE_IP_OFFSET_KEY).map(<[u8]>::to_vec));
            let saved_cycle = transaction
                .bucket(bucket_name)
                .and_then(|bucket| bucket.get(FAKE_IP_CYCLE_KEY).map(<[u8]>::to_vec));
            if transaction.bucket(bucket_name).is_some() {
                transaction.delete_bucket(bucket_name)?;
            }
            let mut bucket = transaction.create_bucket(bucket_name)?;
            for (host, entry) in &self.by_host {
                let address = ip_bytes(entry.address);
                bucket.put(host.as_bytes(), &address)?;
                bucket.put(&address, host.as_bytes())?;
            }
            if let Some(offset) = saved_offset {
                bucket.put(FAKE_IP_OFFSET_KEY, offset)?;
            }
            if let Some(cycle) = saved_cycle {
                bucket.put(FAKE_IP_CYCLE_KEY, cycle)?;
            }
            Ok(())
        });
    }

    fn store_state(&mut self) {
        if !self.persistent {
            return;
        }
        let path = fake_ip_state_path();
        let Some(parent) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(mut database) = Bolt::open(path) else {
            return;
        };
        let bucket_name = fake_ip_bucket(self.network);
        let offset = ip_bytes(number_to_ip(self.offset, self.network));
        let _ = database.update(|mut transaction| {
            let mut bucket = transaction.create_bucket_if_not_exists(bucket_name)?;
            bucket.put(FAKE_IP_OFFSET_KEY, &offset)?;
            if self.cycle {
                bucket.put(FAKE_IP_CYCLE_KEY, &offset)?;
            }
            Ok(())
        });
    }
}

const FAKE_IP_OFFSET_KEY: &[u8] = b"key-offset-fake-ip";
const FAKE_IP_CYCLE_KEY: &[u8] = b"key-cycle-fake-ip";
const SELECTED_BUCKET: &[u8] = b"selected";

fn load_selected_state() -> BTreeMap<String, String> {
    let path = fake_ip_state_path();
    if !path.exists() {
        return BTreeMap::new();
    }
    let Ok(database) = Bolt::open(path) else {
        return BTreeMap::new();
    };
    let mut selected = BTreeMap::new();
    let _ = database.view(|transaction| {
        let Some(bucket) = transaction.bucket(SELECTED_BUCKET) else {
            return Ok(());
        };
        let mut cursor = bucket.cursor();
        let mut item = cursor.first();
        while let Some((key, Some(value))) = item {
            if let (Ok(group), Ok(proxy)) = (std::str::from_utf8(key), std::str::from_utf8(value)) {
                selected.insert(group.to_owned(), proxy.to_owned());
            }
            item = cursor.next();
        }
        Ok(())
    });
    selected
}

fn store_selected_state(group: &str, selected: &str) {
    let path = fake_ip_state_path();
    let Some(parent) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let Ok(mut database) = Bolt::open(path) else {
        return;
    };
    let _ = database.update(|mut transaction| {
        let mut bucket = transaction.create_bucket_if_not_exists(SELECTED_BUCKET)?;
        bucket.put(group.as_bytes(), selected.as_bytes())?;
        Ok(())
    });
}

fn fake_ip_state_path() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    home.join(".config").join("mihomo").join("cache.db")
}

fn fake_ip_bucket(network: IpNet) -> &'static [u8] {
    if network.addr().is_ipv4() {
        b"fakeip"
    } else {
        b"fakeip6"
    }
}

fn flush_fake_ip_bucket(network: IpNet) {
    let path = fake_ip_state_path();
    if !path.exists() {
        return;
    }
    let Ok(mut database) = Bolt::open(path) else {
        return;
    };
    let bucket_name = fake_ip_bucket(network);
    let _ = database.update(|mut transaction| {
        if transaction.bucket(bucket_name).is_some() {
            transaction.delete_bucket(bucket_name)?;
        }
        Ok(())
    });
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn address_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => <[u8; 16]>::try_from(bytes)
            .ok()
            .map(Ipv6Addr::from)
            .map(IpAddr::V6),
        _ => None,
    }
}

fn network_bounds(network: IpNet) -> (u128, u128) {
    match network {
        IpNet::V4(network) => (
            u128::from(u32::from(network.network())),
            u128::from(u32::from(network.broadcast())),
        ),
        IpNet::V6(network) => {
            let start = u128::from(network.network());
            let host_bits = 128 - u32::from(network.prefix_len());
            let mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1_u128 << host_bits) - 1
            };
            (start, start | mask)
        }
    }
}

fn ip_to_number(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u128::from(u32::from(address)),
        IpAddr::V6(address) => u128::from(address),
    }
}

fn number_to_ip(number: u128, network: IpNet) -> IpAddr {
    match network {
        IpNet::V4(_) => IpAddr::V4(Ipv4Addr::from(
            u32::try_from(number).expect("IPv4 pool number fits in u32"),
        )),
        IpNet::V6(_) => IpAddr::V6(Ipv6Addr::from(number)),
    }
}

#[derive(Debug)]
pub struct ConnectionGuard {
    id: u64,
    state: Arc<RuntimeState>,
    cancellation: CancellationToken,
}

impl ConnectionGuard {
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    pub fn finish(&self, uploaded: u64, downloaded: u64) {
        self.state.uploaded.fetch_add(uploaded, Ordering::Relaxed);
        self.state
            .downloaded
            .fetch_add(downloaded, Ordering::Relaxed);
        if let Some(info) = self
            .state
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&self.id)
        {
            info.info.upload = uploaded;
            info.info.download = downloaded;
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl From<&Metadata> for MetadataSnapshot {
    fn from(metadata: &Metadata) -> Self {
        let inbound_type = match metadata.inbound {
            InboundProtocol::Http => "HTTP",
            InboundProtocol::Https => "HTTPS",
            InboundProtocol::Socks4 => "Socks4",
            InboundProtocol::Socks5 => "Socks5",
        };
        let network = match metadata.network {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        };
        let destination_ip = metadata
            .destination_ip
            .map_or_else(String::new, |address| address.to_string());
        let remote_destination = match &metadata.destination.host {
            Host::Ip(address) => format!("{address}:{}", metadata.destination.port),
            Host::Domain(domain) => format!("{domain}:{}", metadata.destination.port),
        };
        Self {
            network: network.to_owned(),
            inbound_type: inbound_type.to_owned(),
            source_ip: metadata
                .source_ip
                .map_or_else(String::new, |address| address.to_string()),
            destination_ip,
            source_geo_ip: None,
            destination_geo_ip: None,
            source_ipasn: String::new(),
            destination_ipasn: String::new(),
            source_port: metadata.source_port.to_string(),
            destination_port: metadata.destination.port.to_string(),
            inbound_ip: "127.0.0.1".to_owned(),
            inbound_port: metadata.inbound_port.to_string(),
            inbound_name: metadata.inbound_name.clone(),
            inbound_user: metadata.inbound_user.clone(),
            rematch_name: metadata.rematch_name.clone(),
            host: metadata.host.clone(),
            dns_mode: "normal".to_owned(),
            uid: 0,
            process: String::new(),
            process_path: String::new(),
            special_proxy: String::new(),
            special_rules: metadata.special_rules.clone(),
            remote_destination,
            dscp: metadata.dscp,
            sniff_host: metadata.sniff_host.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping_address(index: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(
            10,
            ((index >> 16) & 0xff) as u8,
            ((index >> 8) & 0xff) as u8,
            (index & 0xff) as u8,
        ))
    }

    #[test]
    fn redir_host_mapping_uses_the_go_size_only_lru_contract() {
        let state = RuntimeState::default();
        let first = mapping_address(1);
        let second = mapping_address(2);
        state.insert_dns_mapping(first, "first.test", 1);
        state.insert_dns_mapping(second, "second.test", 1);
        for index in 3..=4096 {
            state.insert_dns_mapping(mapping_address(index), "filler.test", 1);
        }

        assert_eq!(
            state.lookup_dns_mapping(first).as_deref(),
            Some("first.test")
        );
        state.insert_dns_mapping(mapping_address(4097), "overflow.test", 1);

        assert_eq!(
            state.lookup_dns_mapping(first).as_deref(),
            Some("first.test")
        );
        assert!(state.lookup_dns_mapping(second).is_none());
    }

    #[test]
    fn controller_storage_replaces_and_deletes_exact_bytes() {
        let state = RuntimeState::default();
        assert!(state.storage_get("ui/key").is_none());
        state.storage_set("ui/key".to_owned(), b" {\"enabled\":true} \n".to_vec());
        assert_eq!(
            state.storage_get("ui/key").as_deref(),
            Some(b" {\"enabled\":true} \n".as_slice())
        );
        state.storage_set("ui/key".to_owned(), b"null".to_vec());
        assert_eq!(
            state.storage_get("ui/key").as_deref(),
            Some(b"null".as_slice())
        );
        state.storage_delete("ui/key");
        state.storage_delete("ui/key");
        assert!(state.storage_get("ui/key").is_none());
    }

    #[test]
    fn controller_proxy_selection_and_health_share_runtime_state() {
        let state = RuntimeState::default();
        assert_eq!(state.global_proxy(), "DIRECT");
        assert!(!state.set_global_proxy("missing"));
        assert!(state.set_global_proxy("REJECT"));
        assert_eq!(state.global_proxy(), "REJECT");

        let initial = state.proxy_health("DIRECT");
        assert!(initial.alive);
        assert!(initial.history.is_empty());
        state.record_proxy_delay("DIRECT", "http://health.test/", 42, true);
        let healthy = state.proxy_health("DIRECT");
        assert!(healthy.alive);
        assert_eq!(healthy.history[0].delay, 42);
        assert!(healthy.extra["http://health.test/"].alive);
        state.record_proxy_delay("DIRECT", "http://health.test/", 0, false);
        let failed = state.proxy_health("DIRECT");
        assert!(!failed.alive);
        assert_eq!(failed.history[1].delay, 0);
        assert_eq!(failed.extra["http://health.test/"].history.len(), 2);
    }

    #[test]
    fn group_dial_failures_trigger_health_checks_at_the_go_boundaries() {
        let state = RuntimeState::default();
        let window = Duration::from_secs(1);
        let take_trigger = || {
            state
                .group_health_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_first()
        };

        state.record_group_dial_failure("fallback", window, 2, false);
        assert_eq!(take_trigger(), None);
        state.record_group_dial_failure("fallback", window, 2, false);
        assert_eq!(take_trigger().as_deref(), Some("fallback"));
        state.finish_group_health_check("fallback");

        state.record_group_dial_failure("fallback", Duration::ZERO, 2, false);
        std::thread::sleep(Duration::from_millis(1));
        state.record_group_dial_failure("fallback", Duration::ZERO, 2, false);
        state.record_group_dial_failure("fallback", window, 2, false);
        assert_eq!(take_trigger(), None);
        state.record_group_dial_failure("fallback", window, 2, false);
        assert_eq!(take_trigger().as_deref(), Some("fallback"));
        state.finish_group_health_check("fallback");

        state.record_group_dial_failure("fallback", window, 99, true);
        assert_eq!(take_trigger().as_deref(), Some("fallback"));
    }

    #[test]
    fn fallback_choice_starts_dynamic_and_can_be_fixed_or_cleared() {
        let state = RuntimeState::default();
        let members = vec!["proxy-a".to_owned(), "DIRECT".to_owned()];
        state.sync_group_choices([("recovery", members.as_slice(), None, true)], false);
        assert_eq!(state.selector_proxy("recovery").as_deref(), Some(""));
        assert!(state.set_selector_proxy("recovery", "DIRECT", &members));
        assert_eq!(state.selector_proxy("recovery").as_deref(), Some("DIRECT"));
        assert!(state.clear_group_choice("recovery", false));
        assert_eq!(state.selector_proxy("recovery").as_deref(), Some(""));
    }

    #[test]
    fn url_test_chooses_fastest_healthy_or_fixed_member() {
        let state = RuntimeState::default();
        let members = vec!["slow".to_owned(), "fast".to_owned()];
        let url = "http://health.test/";
        state.sync_group_choices([("speed", members.as_slice(), None, true)], false);
        state.record_proxy_delay("slow", url, 200, true);
        state.record_proxy_delay("fast", url, 50, true);
        assert_eq!(
            state.url_test_proxy("speed", &members, url, 10).as_deref(),
            Some("fast")
        );
        assert!(state.set_selector_proxy("speed", "slow", &members));
        assert_eq!(
            state.url_test_proxy("speed", &members, url, 10).as_deref(),
            Some("slow")
        );
        state.record_proxy_delay("slow", url, 0, false);
        assert_eq!(
            state.url_test_proxy("speed", &members, url, 10).as_deref(),
            Some("fast")
        );
        assert_eq!(state.selector_proxy("speed").as_deref(), Some(""));
    }

    #[test]
    fn round_robin_skips_unhealthy_members() {
        let state = RuntimeState::default();
        let members = vec!["proxy-a".to_owned(), "proxy-b".to_owned()];
        let url = "http://health.test/";
        assert_eq!(
            state
                .round_robin_proxy("balanced", &members, url)
                .as_deref(),
            Some("proxy-a")
        );
        assert_eq!(
            state
                .round_robin_proxy("balanced", &members, url)
                .as_deref(),
            Some("proxy-b")
        );
        state.record_proxy_delay("proxy-a", url, 0, false);
        assert_eq!(
            state
                .round_robin_proxy("balanced", &members, url)
                .as_deref(),
            Some("proxy-b")
        );
    }

    #[test]
    fn consistent_hashing_is_key_stable_and_skips_unhealthy_members() {
        let state = RuntimeState::default();
        let members = vec!["proxy-a".to_owned(), "proxy-b".to_owned()];
        let url = "http://health.test/";
        let selected = state
            .consistent_hash_proxy(&members, url, "example.test")
            .expect("selected member");
        assert_eq!(
            state.consistent_hash_proxy(&members, url, "example.test"),
            Some(selected.clone())
        );
        state.record_proxy_delay(&selected, url, 0, false);
        assert_ne!(
            state.consistent_hash_proxy(&members, url, "example.test"),
            Some(selected)
        );
    }

    #[test]
    fn sticky_sessions_cache_a_healthy_member_and_replace_a_failed_one() {
        let state = RuntimeState::default();
        let members = vec!["proxy-a".to_owned(), "proxy-b".to_owned()];
        let url = "http://health.test/";
        let selected = state
            .sticky_session_proxy("sticky", &members, url, "source.example.test")
            .expect("selected member");
        assert_eq!(
            state.sticky_session_proxy("sticky", &members, url, "source.example.test"),
            Some(selected.clone())
        );
        state.record_proxy_delay(&selected, url, 0, false);
        let replacement = state
            .sticky_session_proxy("sticky", &members, url, "source.example.test")
            .expect("replacement member");
        assert_ne!(replacement, selected);
        assert_eq!(
            state.sticky_session_proxy("sticky", &members, url, "source.example.test"),
            Some(replacement)
        );
    }

    #[test]
    fn fake_ip_pool_starts_at_four_and_wraps_before_last() {
        let network = "198.19.0.1/29".parse().expect("prefix");
        let mut pool = FakeIpPool::new(network, false);
        assert_eq!(pool.lookup("one.test").to_string(), "198.19.0.4");
        assert_eq!(pool.lookup("two.test").to_string(), "198.19.0.5");
        assert_eq!(pool.lookup("three.test").to_string(), "198.19.0.6");
        assert_eq!(pool.lookup("four.test").to_string(), "198.19.0.4");
        assert!(
            pool.look_back("198.19.0.4".parse().expect("address"))
                .is_some()
        );
        assert!(
            pool.look_back("198.19.0.5".parse().expect("address"))
                .is_some()
        );
    }

    #[test]
    fn fake_ip_pool_is_case_insensitive_and_memory_bounded() {
        let network = "198.19.0.1/16".parse().expect("prefix");
        let mut pool = FakeIpPool::new(network, false);
        let first = pool.lookup("First.Test");
        assert_eq!(pool.lookup("first.test"), first);
        for index in 0..FAKE_IP_MEMORY_CAPACITY {
            pool.lookup(&format!("{index}.test"));
        }
        assert_eq!(pool.by_host.len(), FAKE_IP_MEMORY_CAPACITY);
        assert!(!pool.by_host.contains_key("first.test"));
        assert_ne!(pool.lookup("FIRST.TEST"), first);
    }
}
