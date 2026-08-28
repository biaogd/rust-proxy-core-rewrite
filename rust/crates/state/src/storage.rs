use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use bbolt::Db;
use time::OffsetDateTime;

use crate::RuntimeState;

#[derive(Clone, Debug)]
pub(crate) struct StorageEntry {
    data: Vec<u8>,
    timestamp: i128,
}

const STORAGE_BUCKET: &[u8] = b"storage";
const STORAGE_SIZE_LIMIT: usize = 1024 * 1024;
const STORAGE_KEY_SIZE_LIMIT: usize = 64;
const MAX_STORAGE_ENTRIES: usize = STORAGE_SIZE_LIMIT / STORAGE_KEY_SIZE_LIMIT;

impl RuntimeState {
    #[must_use]
    pub fn storage_get(&self, key: &str) -> Option<Vec<u8>> {
        self.storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .map(|entry| entry.data.clone())
    }

    pub fn storage_set(&self, key: &str, value: Vec<u8>) {
        if key.len() > STORAGE_KEY_SIZE_LIMIT || value.len() > STORAGE_SIZE_LIMIT {
            return;
        }
        let timestamp = current_unix_nanos();
        let mut storage = self
            .storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut used = storage
            .iter()
            .filter(|(candidate, _)| candidate.as_str() != key)
            .map(|(_, entry)| entry.data.len())
            .sum::<usize>();
        while used.saturating_add(value.len()) > STORAGE_SIZE_LIMIT
            || storage.len() >= MAX_STORAGE_ENTRIES && !storage.contains_key(key)
        {
            let oldest = storage
                .iter()
                .filter(|(candidate, _)| candidate.as_str() != key)
                .min_by(|(left_key, left), (right_key, right)| {
                    left.timestamp
                        .cmp(&right.timestamp)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(candidate, entry)| (candidate.clone(), entry.data.len()));
            let Some((oldest, size)) = oldest else {
                break;
            };
            storage.remove(&oldest);
            used = used.saturating_sub(size);
        }
        storage.insert(
            key.to_owned(),
            StorageEntry {
                data: value,
                timestamp,
            },
        );
        if self.storage_persistent.load(Ordering::Acquire) {
            persist_storage(&storage, Some(key));
        }
    }

    pub fn storage_delete(&self, key: &str) {
        let mut storage = self
            .storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        storage.remove(key);
        if self.storage_persistent.load(Ordering::Acquire) {
            delete_persistent_storage(key);
        }
    }

    /// Loads the controller storage bucket once and enables durable updates.
    pub fn enable_storage_persistence(&self) {
        if self.storage_persistent.swap(true, Ordering::AcqRel) {
            return;
        }
        let loaded = load_storage_state();
        *self
            .storage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = loaded;
    }
}

const SELECTED_BUCKET: &[u8] = b"selected";

fn current_unix_nanos() -> i128 {
    OffsetDateTime::now_utc().unix_timestamp_nanos()
}

fn load_storage_state() -> BTreeMap<String, StorageEntry> {
    let path = fake_ip_state_path();
    if !path.exists() {
        return BTreeMap::new();
    }
    let Ok(database) = Db::open(path, 0o600, None) else {
        return BTreeMap::new();
    };
    let mut storage = BTreeMap::new();
    let mut corrupted = Vec::new();
    let _ = database.view(|transaction| {
        let Some(bucket) = transaction.bucket(STORAGE_BUCKET) else {
            return Ok(());
        };
        let mut cursor = bucket.cursor();
        let mut item = cursor.first()?;
        while let (Some(key), Some(value)) = item {
            match std::str::from_utf8(&key)
                .ok()
                .zip(decode_storage_entry(&value))
            {
                Some((key, entry)) => {
                    storage.insert(key.to_owned(), entry);
                }
                None => corrupted.push(key),
            }
            item = cursor.next()?;
        }
        Ok(())
    });
    drop(database);
    if !corrupted.is_empty() {
        delete_corrupted_storage(&corrupted);
    }
    storage
}

fn decode_storage_entry(payload: &[u8]) -> Option<StorageEntry> {
    let value = rmpv::decode::read_value(&mut Cursor::new(payload)).ok()?;
    let rmpv::Value::Map(fields) = value else {
        return None;
    };
    let mut data = None;
    let mut timestamp = None;
    for (key, value) in fields {
        match key.as_str()? {
            "Data" => match value {
                rmpv::Value::Binary(bytes) => data = Some(bytes),
                _ => return None,
            },
            "Time" => timestamp = decode_timestamp(value),
            _ => {}
        }
    }
    Some(StorageEntry {
        data: data?,
        timestamp: timestamp?,
    })
}

fn decode_timestamp(value: rmpv::Value) -> Option<i128> {
    let rmpv::Value::Ext(-1, bytes) = value else {
        return None;
    };
    match bytes.len() {
        4 => {
            let encoded = <[u8; 4]>::try_from(bytes.as_slice()).ok()?;
            Some(i128::from(u32::from_be_bytes(encoded)) * 1_000_000_000)
        }
        8 => {
            let encoded = <[u8; 8]>::try_from(bytes.as_slice()).ok()?;
            let packed = u64::from_be_bytes(encoded);
            let nanos = packed >> 34;
            let seconds = packed & 0x3_ffff_ffff;
            Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos))
        }
        12 => {
            let nanos = u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[..4]).ok()?);
            let seconds = i64::from_be_bytes(<[u8; 8]>::try_from(&bytes[4..]).ok()?);
            Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos))
        }
        _ => None,
    }
}

fn encode_storage_entry(entry: &StorageEntry) -> Option<Vec<u8>> {
    let seconds = entry.timestamp.div_euclid(1_000_000_000);
    let nanos = u32::try_from(entry.timestamp.rem_euclid(1_000_000_000)).ok()?;
    let timestamp = if nanos == 0 && (0..=i128::from(u32::MAX)).contains(&seconds) {
        u32::try_from(seconds).ok()?.to_be_bytes().to_vec()
    } else if (0..(1_i128 << 34)).contains(&seconds) {
        ((u64::from(nanos) << 34) | u64::try_from(seconds).ok()?)
            .to_be_bytes()
            .to_vec()
    } else {
        let mut value = nanos.to_be_bytes().to_vec();
        value.extend_from_slice(&i64::try_from(seconds).ok()?.to_be_bytes());
        value
    };
    let value = rmpv::Value::Map(vec![
        (
            rmpv::Value::String("Data".into()),
            rmpv::Value::Binary(entry.data.clone()),
        ),
        (
            rmpv::Value::String("Time".into()),
            rmpv::Value::Ext(-1, timestamp),
        ),
    ]);
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, &value).ok()?;
    Some(payload)
}

fn persist_storage(storage: &BTreeMap<String, StorageEntry>, _updated: Option<&str>) {
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
    let _ = database.update(|transaction| {
        if transaction.bucket(STORAGE_BUCKET).is_some() {
            transaction.delete_bucket(STORAGE_BUCKET)?;
        }
        let bucket = transaction.create_bucket(STORAGE_BUCKET)?;
        for (key, entry) in storage {
            if let Some(payload) = encode_storage_entry(entry) {
                bucket.put(key.as_bytes(), &payload)?;
            }
        }
        Ok(())
    });
}

fn delete_persistent_storage(key: &str) {
    let path = fake_ip_state_path();
    if !path.exists() {
        return;
    }
    let Ok(database) = Db::open(path, 0o600, None) else {
        return;
    };
    let _ = database.update(|transaction| {
        let Some(bucket) = transaction.bucket(STORAGE_BUCKET) else {
            return Ok(());
        };
        bucket.delete(key.as_bytes())
    });
}

fn delete_corrupted_storage(keys: &[Vec<u8>]) {
    let path = fake_ip_state_path();
    let Ok(database) = Db::open(path, 0o600, None) else {
        return;
    };
    let _ = database.update(|transaction| {
        let Some(bucket) = transaction.bucket(STORAGE_BUCKET) else {
            return Ok(());
        };
        for key in keys {
            bucket.delete(key)?;
        }
        Ok(())
    });
}

pub(crate) fn load_selected_state() -> BTreeMap<String, String> {
    let path = fake_ip_state_path();
    if !path.exists() {
        return BTreeMap::new();
    }
    let Ok(database) = Db::open(path, 0o600, None) else {
        return BTreeMap::new();
    };
    let mut selected = BTreeMap::new();
    let _ = database.view(|transaction| {
        let Some(bucket) = transaction.bucket(SELECTED_BUCKET) else {
            return Ok(());
        };
        let mut cursor = bucket.cursor();
        let mut item = cursor.first()?;
        while let (Some(key), Some(value)) = item {
            if let (Ok(group), Ok(proxy)) = (std::str::from_utf8(&key), std::str::from_utf8(&value))
            {
                selected.insert(group.to_owned(), proxy.to_owned());
            }
            item = cursor.next()?;
        }
        Ok(())
    });
    selected
}

pub(crate) fn store_selected_state(group: &str, selected: &str) {
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
    let _ = database.update(|transaction| {
        let bucket = transaction.create_bucket_if_not_exists(SELECTED_BUCKET)?;
        bucket.put(group.as_bytes(), selected.as_bytes())?;
        Ok(())
    });
}

pub(crate) fn fake_ip_state_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from);
    home.join(".config").join("mihomo").join("cache.db")
}
