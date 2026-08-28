use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use rewrite_config::DnsCacheAlgorithm;

use crate::{DNS_HEADER_LENGTH, DnsError};

#[derive(Clone)]
pub(crate) struct CacheEntry {
    response: Vec<u8>,
    stored_at: Instant,
    lifetime: Duration,
}

pub(crate) enum CacheLookup {
    Fresh(Vec<u8>),
    Stale(Vec<u8>),
}

pub(crate) struct LruCache {
    entries: BTreeMap<Vec<u8>, CacheEntry>,
    order: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl LruCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub(crate) fn get(
        &mut self,
        key: &[u8],
        identifier: [u8; 2],
        now: Instant,
    ) -> Option<CacheLookup> {
        let entry = self.entries.get(key)?.clone();
        touch(&mut self.order, key);
        Some(cache_lookup(entry, identifier, now))
    }

    pub(crate) fn insert(&mut self, key: Vec<u8>, response: Vec<u8>, ttl: u32, now: Instant) {
        if !self.entries.contains_key(&key)
            && self.entries.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        touch(&mut self.order, &key);
        self.entries.insert(key, cache_entry(response, ttl, now));
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ArcList {
    T1,
    T2,
    B1,
    B2,
}

pub(crate) struct ArcRecord {
    entry: Option<CacheEntry>,
    list: ArcList,
}

pub(crate) struct ArcCache {
    records: BTreeMap<Vec<u8>, ArcRecord>,
    t1: VecDeque<Vec<u8>>,
    t2: VecDeque<Vec<u8>>,
    b1: VecDeque<Vec<u8>>,
    b2: VecDeque<Vec<u8>>,
    target_t1: usize,
    capacity: usize,
}

impl ArcCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            target_t1: 0,
            capacity,
        }
    }

    pub(crate) fn get(
        &mut self,
        key: &[u8],
        identifier: [u8; 2],
        now: Instant,
    ) -> Option<CacheLookup> {
        let entry = self.records.get(key)?.entry.clone();
        self.request(key);
        entry.map(|entry| cache_lookup(entry, identifier, now))
    }

    pub(crate) fn insert(&mut self, key: &[u8], response: Vec<u8>, ttl: u32, now: Instant) {
        if let Some(record) = self.records.get_mut(key) {
            record.entry = Some(cache_entry(response, ttl, now));
            self.request(key);
            return;
        }
        self.records.insert(
            key.to_owned(),
            ArcRecord {
                entry: Some(cache_entry(response, ttl, now)),
                list: ArcList::T1,
            },
        );
        self.request_new(key);
    }

    pub(crate) fn request(&mut self, key: &[u8]) {
        let Some(list) = self.records.get(key).map(|record| record.list) else {
            return;
        };
        match list {
            ArcList::T1 | ArcList::T2 => self.move_to(key, ArcList::T2),
            ArcList::B1 => {
                let delta = if self.b1.len() >= self.b2.len() {
                    1
                } else {
                    self.b2.len() / self.b1.len().max(1)
                };
                self.target_t1 = self.target_t1.saturating_add(delta).min(self.capacity);
                self.replace(Some(ArcList::B1));
                self.move_to(key, ArcList::T2);
            }
            ArcList::B2 => {
                let delta = if self.b2.len() >= self.b1.len() {
                    1
                } else {
                    self.b1.len() / self.b2.len().max(1)
                };
                self.target_t1 = self.target_t1.saturating_sub(delta);
                self.replace(Some(ArcList::B2));
                self.move_to(key, ArcList::T2);
            }
        }
    }

    pub(crate) fn request_new(&mut self, key: &[u8]) {
        if self.t1.len() + self.b1.len() == self.capacity {
            if self.t1.len() < self.capacity {
                self.remove_lru(ArcList::B1);
                self.replace(None);
            } else {
                self.remove_lru(ArcList::T1);
            }
        } else if self.t1.len() + self.b1.len() < self.capacity {
            let total = self.t1.len() + self.t2.len() + self.b1.len() + self.b2.len();
            if total >= self.capacity {
                if total == self.capacity.saturating_mul(2) {
                    self.remove_lru(ArcList::B2);
                }
                self.replace(None);
            }
        }
        self.move_to(key, ArcList::T1);
    }

    pub(crate) fn replace(&mut self, incoming: Option<ArcList>) {
        if !self.t1.is_empty()
            && (self.t1.len() > self.target_t1
                || (incoming == Some(ArcList::B2) && self.t1.len() == self.target_t1))
        {
            if let Some(key) = self.t1.pop_back() {
                self.make_ghost(&key, ArcList::B1);
            }
        } else if let Some(key) = self.t2.pop_back() {
            self.make_ghost(&key, ArcList::B2);
        }
    }

    pub(crate) fn make_ghost(&mut self, key: &[u8], list: ArcList) {
        if let Some(record) = self.records.get_mut(key) {
            record.entry = None;
            record.list = list;
        }
        self.list_mut(list).push_front(key.to_vec());
    }

    pub(crate) fn move_to(&mut self, key: &[u8], target: ArcList) {
        if let Some(current) = self.records.get(key).map(|record| record.list) {
            remove_key(self.list_mut(current), key);
        }
        self.list_mut(target).push_front(key.to_vec());
        if let Some(record) = self.records.get_mut(key) {
            record.list = target;
        }
    }

    pub(crate) fn remove_lru(&mut self, list: ArcList) {
        if let Some(key) = self.list_mut(list).pop_back() {
            self.records.remove(&key);
        }
    }

    pub(crate) fn list_mut(&mut self, list: ArcList) -> &mut VecDeque<Vec<u8>> {
        match list {
            ArcList::T1 => &mut self.t1,
            ArcList::T2 => &mut self.t2,
            ArcList::B1 => &mut self.b1,
            ArcList::B2 => &mut self.b2,
        }
    }
}

pub(crate) enum Cache {
    Lru(LruCache),
    Arc(ArcCache),
}

impl Cache {
    pub(crate) fn new(algorithm: DnsCacheAlgorithm, capacity: usize) -> Self {
        match algorithm {
            DnsCacheAlgorithm::Lru => Self::Lru(LruCache::new(capacity)),
            DnsCacheAlgorithm::Arc => Self::Arc(ArcCache::new(capacity)),
        }
    }

    pub(crate) fn matches(&self, algorithm: DnsCacheAlgorithm, capacity: usize) -> bool {
        match self {
            Self::Lru(cache) => algorithm == DnsCacheAlgorithm::Lru && cache.capacity == capacity,
            Self::Arc(cache) => algorithm == DnsCacheAlgorithm::Arc && cache.capacity == capacity,
        }
    }

    pub(crate) fn get(
        &mut self,
        key: &[u8],
        identifier: [u8; 2],
        now: Instant,
    ) -> Option<CacheLookup> {
        match self {
            Self::Lru(cache) => cache.get(key, identifier, now),
            Self::Arc(cache) => cache.get(key, identifier, now),
        }
    }

    pub(crate) fn insert(&mut self, key: Vec<u8>, response: Vec<u8>, ttl: u32, now: Instant) {
        match self {
            Self::Lru(cache) => cache.insert(key, response, ttl, now),
            Self::Arc(cache) => cache.insert(&key, response, ttl, now),
        }
    }

    pub(crate) fn clear(&mut self) {
        match self {
            Self::Lru(cache) => *cache = LruCache::new(cache.capacity),
            Self::Arc(cache) => *cache = ArcCache::new(cache.capacity),
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new(DnsCacheAlgorithm::Lru, 4096)
    }
}

pub(crate) fn cache_entry(response: Vec<u8>, ttl: u32, now: Instant) -> CacheEntry {
    CacheEntry {
        response,
        stored_at: now,
        lifetime: Duration::from_secs(u64::from(ttl)),
    }
}

pub(crate) fn cache_lookup(entry: CacheEntry, identifier: [u8; 2], now: Instant) -> CacheLookup {
    let elapsed = now.saturating_duration_since(entry.stored_at);
    let mut response = entry.response;
    response[..2].copy_from_slice(&identifier);
    if elapsed >= entry.lifetime {
        set_ttls(&mut response, 1).ok();
        return CacheLookup::Stale(response);
    }
    let rounded_seconds = elapsed
        .as_secs()
        .saturating_add(u64::from(elapsed.subsec_nanos() != 0));
    let elapsed_seconds = u32::try_from(rounded_seconds).unwrap_or(u32::MAX);
    let _ = age_ttls(&mut response, elapsed_seconds);
    CacheLookup::Fresh(response)
}

pub(crate) fn touch(order: &mut VecDeque<Vec<u8>>, key: &[u8]) {
    remove_key(order, key);
    order.push_back(key.to_vec());
}

pub(crate) fn remove_key(order: &mut VecDeque<Vec<u8>>, key: &[u8]) {
    if let Some(position) = order.iter().position(|candidate| candidate == key) {
        order.remove(position);
    }
}

#[cfg(test)]
pub(crate) fn positive_ttl(response: &[u8]) -> Result<Option<u32>, DnsError> {
    if response[3] & 0x0f != 0 || u16::from_be_bytes([response[6], response[7]]) == 0 {
        return Ok(None);
    }
    Ok(resource_ttls(response)?
        .into_iter()
        .map(|(_, ttl)| ttl)
        .min())
}

pub(crate) fn cache_ttl(response: &[u8]) -> Result<Option<u32>, DnsError> {
    if response.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    if response[3] & 0x0f == 2 {
        return Ok(Some(5));
    }
    Ok(resource_ttls(response)?
        .into_iter()
        .map(|(_, ttl)| ttl)
        .min()
        .filter(|ttl| *ttl > 0))
}

pub(crate) fn age_ttls(response: &mut [u8], elapsed: u32) -> Result<(), DnsError> {
    for (offset, ttl) in resource_ttls(response)? {
        let aged = ttl.saturating_sub(elapsed).max(1).min(ttl);
        response[offset..offset + 4].copy_from_slice(&aged.to_be_bytes());
    }
    Ok(())
}

pub(crate) fn set_ttls(response: &mut [u8], ttl: u32) -> Result<(), DnsError> {
    for (offset, _) in resource_ttls(response)? {
        response[offset..offset + 4].copy_from_slice(&ttl.to_be_bytes());
    }
    Ok(())
}

pub(crate) fn without_opt_records(message: &[u8]) -> Result<Vec<u8>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let section_counts = [
        usize::from(u16::from_be_bytes([message[6], message[7]])),
        usize::from(u16::from_be_bytes([message[8], message[9]])),
        usize::from(u16::from_be_bytes([message[10], message[11]])),
    ];
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("question is truncated"))?;
    }
    let question_end = offset;
    let mut records = Vec::new();
    for (section, count) in section_counts.into_iter().enumerate() {
        for _ in 0..count {
            let start = offset;
            offset = skip_name(message, offset)?;
            if offset + 10 > message.len() {
                return Err(DnsError::InvalidMessage("resource record is truncated"));
            }
            let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
            let data_length = usize::from(u16::from_be_bytes([
                message[offset + 8],
                message[offset + 9],
            ]));
            offset = offset
                .checked_add(10 + data_length)
                .filter(|end| *end <= message.len())
                .ok_or(DnsError::InvalidMessage("resource data is truncated"))?;
            records.push((section, record_type, start, offset));
        }
    }
    if !records
        .iter()
        .any(|(_, record_type, _, _)| *record_type == 41)
    {
        return Ok(message.to_vec());
    }
    let first_opt = records
        .iter()
        .position(|(_, record_type, _, _)| *record_type == 41)
        .expect("OPT presence checked");
    if records[first_opt..]
        .iter()
        .any(|(_, record_type, _, _)| *record_type != 41)
    {
        return Ok(message.to_vec());
    }
    let mut response = message[..question_end].to_vec();
    let mut kept = [0_u16; 3];
    for (section, record_type, start, end) in records {
        if record_type != 41 {
            response.extend_from_slice(&message[start..end]);
            kept[section] = kept[section].saturating_add(1);
        }
    }
    for (index, count) in kept.into_iter().enumerate() {
        let count_offset = 6 + index * 2;
        response[count_offset..count_offset + 2].copy_from_slice(&count.to_be_bytes());
    }
    Ok(response)
}

pub(crate) fn resource_ttls(message: &[u8]) -> Result<Vec<(usize, u32)>, DnsError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(DnsError::InvalidMessage("header is truncated"));
    }
    let questions = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let records = usize::from(u16::from_be_bytes([message[6], message[7]]))
        + usize::from(u16::from_be_bytes([message[8], message[9]]))
        + usize::from(u16::from_be_bytes([message[10], message[11]]));
    let mut offset = DNS_HEADER_LENGTH;
    for _ in 0..questions {
        offset = skip_name(message, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("question is truncated"))?;
    }

    let mut ttls = Vec::new();
    for _ in 0..records {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(DnsError::InvalidMessage("resource record is truncated"));
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let ttl_offset = offset + 4;
        let ttl = u32::from_be_bytes([
            message[ttl_offset],
            message[ttl_offset + 1],
            message[ttl_offset + 2],
            message[ttl_offset + 3],
        ]);
        let data_length = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        offset = offset
            .checked_add(10 + data_length)
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("resource data is truncated"))?;
        if record_type != 41 {
            ttls.push((ttl_offset, ttl));
        }
    }
    Ok(ttls)
}

pub(crate) fn skip_name(message: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    loop {
        let length = *message
            .get(offset)
            .ok_or(DnsError::InvalidMessage("name is truncated"))?;
        if length & 0xc0 == 0xc0 {
            if offset + 2 > message.len() {
                return Err(DnsError::InvalidMessage("name pointer is truncated"));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::InvalidMessage("invalid name label"));
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|end| *end <= message.len())
            .ok_or(DnsError::InvalidMessage("name label is truncated"))?;
    }
}
