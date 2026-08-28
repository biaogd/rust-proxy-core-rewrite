use std::collections::BTreeMap;
use std::hash::BuildHasher;
use std::num::NonZeroUsize;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use lru::LruCache;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::RuntimeState;
use crate::model::{ProxyDelayHistory, ProxyHealthSnapshot, ProxyUrlHealth};
use crate::storage::{load_selected_state, store_selected_state};

#[derive(Debug)]
pub(crate) struct ProxyHealth {
    alive: bool,
    history: Vec<ProxyDelayHistory>,
    extra: BTreeMap<String, ProxyUrlHealth>,
}

#[derive(Debug, Default)]
pub(crate) struct GroupDialHealth {
    failed_times: u64,
    failed_at: Option<Instant>,
    testing: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StickySession {
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

impl RuntimeState {
    #[must_use]
    pub fn global_proxy(&self) -> String {
        self.global_proxy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn set_global_proxy(&self, name: &str, available: &[String]) -> bool {
        if !available.iter().any(|candidate| candidate == name) {
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

    pub fn sync_global_proxy(&self, available: &[String]) {
        let mut selected = self
            .global_proxy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !available.iter().any(|candidate| candidate == &*selected) {
            *selected = available
                .first()
                .cloned()
                .unwrap_or_else(|| "DIRECT".to_owned());
        }
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

    pub fn retain_proxy_health<'a>(&self, names: impl IntoIterator<Item = &'a str>) {
        let names: std::collections::BTreeSet<_> = names.into_iter().collect();
        self.proxy_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|name, _| names.contains(name.as_str()));
    }
}
