use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use rewrite_model::{Host, InboundProtocol, Metadata, Network};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::broadcast;

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

#[derive(Debug)]
pub struct RuntimeState {
    next_id: AtomicU64,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    connections: Mutex<BTreeMap<u64, ConnectionInfo>>,
    logs: broadcast::Sender<LogEvent>,
    dns_mappings: Mutex<BTreeMap<IpAddr, DnsMapping>>,
    fake_ips: Mutex<FakeIpRegistry>,
}

#[derive(Clone, Debug)]
struct DnsMapping {
    host: String,
    expires_at: Instant,
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
            dns_mappings: Mutex::new(BTreeMap::new()),
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
        self.connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, info);
        ConnectionGuard {
            id,
            state: Arc::clone(self),
        }
    }

    #[must_use]
    pub fn connections(&self) -> ConnectionSnapshot {
        let connections: Vec<_> = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
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

    pub fn log(&self, level: &str, payload: impl Into<String>) {
        let _ = self.logs.send(LogEvent {
            level: level.to_owned(),
            payload: payload.into(),
        });
    }

    #[must_use]
    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEvent> {
        self.logs.subscribe()
    }

    pub fn insert_dns_mapping(&self, address: IpAddr, host: &str, ttl: u32) {
        const CAPACITY: usize = 4096;
        let now = Instant::now();
        let mut mappings = self
            .dns_mappings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mappings.retain(|_, entry| entry.expires_at > now);
        let address = address.to_canonical();
        if mappings.len() >= CAPACITY
            && !mappings.contains_key(&address)
            && let Some(expiring_first) = mappings
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(address, _)| *address)
        {
            mappings.remove(&expiring_first);
        }
        mappings.insert(
            address,
            DnsMapping {
                host: host.to_owned(),
                expires_at: now + Duration::from_secs(u64::from(ttl.max(1))),
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
        if mappings
            .get(&address)
            .is_some_and(|entry| entry.expires_at <= Instant::now())
        {
            mappings.remove(&address);
        }
        mappings.get(&address).map(|entry| entry.host.clone())
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
        if !network.contains(&address) {
            return None;
        }
        let mut registry = self
            .fake_ips
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .pool_mut(network, persistent)
            .look_back(address.to_canonical())
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
            *slot = Some(FakeIpPool::new(
                network,
                persistent,
                persistent.then(|| fake_ip_state_path(network)),
            ));
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
    path: Option<PathBuf>,
    tick: u64,
    by_host: BTreeMap<String, FakeIpEntry>,
    by_ip: BTreeMap<IpAddr, String>,
}

#[derive(Clone, Debug)]
struct FakeIpEntry {
    address: IpAddr,
    touched: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct PersistedFakeIpPool {
    prefix: String,
    offset: String,
    cycle: bool,
    mappings: BTreeMap<String, String>,
}

impl FakeIpPool {
    fn new(network: IpNet, persistent: bool, path: Option<PathBuf>) -> Self {
        let (network_number, last) = network_bounds(network);
        let first = network_number + 4;
        let mut pool = Self {
            network,
            first,
            last,
            offset: first - 1,
            cycle: false,
            persistent,
            path,
            tick: 0,
            by_host: BTreeMap::new(),
            by_ip: BTreeMap::new(),
        };
        pool.restore();
        pool
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

    fn restore(&mut self) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let Ok(contents) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(saved) = serde_json::from_str::<PersistedFakeIpPool>(&contents) else {
            return;
        };
        if saved.prefix != self.network.to_string() {
            return;
        }
        if let Ok(address) = saved.offset.parse::<IpAddr>() {
            let number = ip_to_number(address);
            if self.network.contains(&address) && number >= self.first && number < self.last {
                self.offset = number;
                self.cycle = saved.cycle;
            }
        }
        for (host, address) in saved.mappings {
            let Ok(address) = address.parse::<IpAddr>() else {
                continue;
            };
            let address = address.to_canonical();
            if !self.network.contains(&address) {
                continue;
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
        }
    }

    fn persist(&self) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let saved = PersistedFakeIpPool {
            prefix: self.network.to_string(),
            offset: number_to_ip(self.offset, self.network).to_string(),
            cycle: self.cycle,
            mappings: self
                .by_host
                .iter()
                .map(|(host, entry)| (host.clone(), entry.address.to_string()))
                .collect(),
        };
        let Ok(contents) = serde_json::to_vec(&saved) else {
            return;
        };
        let Some(parent) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let temporary = path.with_extension("json.tmp");
        if std::fs::write(&temporary, contents).is_ok() {
            let _ = std::fs::rename(temporary, path);
        }
    }
}

fn fake_ip_state_path(network: IpNet) -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    let family = if network.addr().is_ipv4() { "v4" } else { "v6" };
    home.join(".config")
        .join("mihomo")
        .join(format!("rust-fakeip-{family}.json"))
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
}

impl ConnectionGuard {
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
            info.upload = uploaded;
            info.download = downloaded;
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
            InboundProtocol::Http => "HTTPS",
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
            inbound_name: String::new(),
            inbound_user: String::new(),
            rematch_name: metadata.rematch_name.clone(),
            host: metadata.host.clone(),
            dns_mode: "normal".to_owned(),
            uid: 0,
            process: String::new(),
            process_path: String::new(),
            special_proxy: String::new(),
            special_rules: metadata.special_rules.clone(),
            remote_destination,
            dscp: 0,
            sniff_host: metadata.sniff_host.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ip_pool_starts_at_four_and_wraps_before_last() {
        let network = "198.19.0.1/29".parse().expect("prefix");
        let mut pool = FakeIpPool::new(network, false, None);
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
        let mut pool = FakeIpPool::new(network, false, None);
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
