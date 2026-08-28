use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bbolt::{Db, Error as BoltError};
use ipnet::IpNet;

use crate::RuntimeState;
use crate::storage::fake_ip_state_path;

#[derive(Clone, Debug)]
pub(crate) struct DnsMapping {
    host: String,
    recency: u64,
}

#[derive(Debug, Default)]
pub(crate) struct DnsMappingCache {
    entries: BTreeMap<IpAddr, DnsMapping>,
    clock: u64,
}

impl RuntimeState {
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

pub(crate) const FAKE_IP_MEMORY_CAPACITY: usize = 1000;

#[derive(Debug, Default)]
pub(crate) struct FakeIpRegistry {
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
pub(crate) struct FakeIpPool {
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
    #[cfg(test)]
    pub(crate) fn host_count(&self) -> usize {
        self.by_host.len()
    }

    #[cfg(test)]
    pub(crate) fn contains_host(&self, host: &str) -> bool {
        self.by_host.contains_key(host)
    }

    pub(crate) fn new(network: IpNet, persistent: bool) -> Self {
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

    pub(crate) fn lookup(&mut self, host: &str) -> IpAddr {
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

    pub(crate) fn look_back(&mut self, address: IpAddr) -> Option<String> {
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
        let database = match Db::open(&path, 0o600, None) {
            Ok(database) => database,
            Err(
                BoltError::Invalid
                | BoltError::Checksum
                | BoltError::VersionMismatch
                | BoltError::Corrupt(_),
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
                if let Some(address) = address_from_bytes(&bytes) {
                    let number = ip_to_number(address);
                    if self.network.contains(&address) && number >= self.first && number < self.last
                    {
                        self.offset = number;
                        self.cycle = bucket.get(FAKE_IP_CYCLE_KEY).is_some();
                    } else {
                        incompatible = true;
                    }
                } else if bucket
                    .get(&ip_bytes(number_to_ip(self.first, self.network)))
                    .is_some()
                {
                    incompatible = true;
                }
            } else if bucket
                .get(&ip_bytes(number_to_ip(self.first, self.network)))
                .is_some()
            {
                incompatible = true;
            }
            if incompatible {
                return Ok(());
            }
            let mut cursor = bucket.cursor();
            let mut item = cursor.first()?;
            while let (Some(key), Some(value)) = item {
                if key.as_slice() != FAKE_IP_OFFSET_KEY
                    && key.as_slice() != FAKE_IP_CYCLE_KEY
                    && address_from_bytes(&key).is_none()
                    && let Ok(host) = std::str::from_utf8(&key)
                    && let Some(address) = address_from_bytes(&value)
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
                item = cursor.next()?;
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
        let Ok(database) = Db::open(path, 0o600, None) else {
            return;
        };
        let bucket_name = fake_ip_bucket(self.network);
        let _ = database.update(|transaction| {
            let saved_offset = transaction
                .bucket(bucket_name)
                .and_then(|bucket| bucket.get(FAKE_IP_OFFSET_KEY));
            let saved_cycle = transaction
                .bucket(bucket_name)
                .and_then(|bucket| bucket.get(FAKE_IP_CYCLE_KEY));
            if transaction.bucket(bucket_name).is_some() {
                transaction.delete_bucket(bucket_name)?;
            }
            let bucket = transaction.create_bucket(bucket_name)?;
            for (host, entry) in &self.by_host {
                let address = ip_bytes(entry.address);
                bucket.put(host.as_bytes(), &address)?;
                bucket.put(&address, host.as_bytes())?;
            }
            if let Some(offset) = saved_offset {
                bucket.put(FAKE_IP_OFFSET_KEY, &offset)?;
            }
            if let Some(cycle) = saved_cycle {
                bucket.put(FAKE_IP_CYCLE_KEY, &cycle)?;
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
        let Ok(database) = Db::open(path, 0o600, None) else {
            return;
        };
        let bucket_name = fake_ip_bucket(self.network);
        let offset = ip_bytes(number_to_ip(self.offset, self.network));
        let _ = database.update(|transaction| {
            let bucket = transaction.create_bucket_if_not_exists(bucket_name)?;
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
    let Ok(database) = Db::open(path, 0o600, None) else {
        return;
    };
    let bucket_name = fake_ip_bucket(network);
    let _ = database.update(|transaction| {
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
