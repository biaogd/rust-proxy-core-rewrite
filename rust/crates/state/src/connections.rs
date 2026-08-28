use std::sync::Arc;
use std::sync::atomic::Ordering;

use rewrite_model::Metadata;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::{
    ConnectionInfo, ConnectionSnapshot, LogEvent, MetadataSnapshot, RuntimeState, TrafficSnapshot,
};

#[derive(Debug)]
pub(crate) struct ActiveConnection {
    info: ConnectionInfo,
    cancellation: CancellationToken,
}

impl RuntimeState {
    /// Returns the process-wide clock adjusted by the configured NTP service.
    #[must_use]
    pub fn clock(&self) -> Arc<rewrite_services::AdjustedClock> {
        Arc::clone(&self.clock)
    }

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

    /// Refreshes and returns this process's resident set size in bytes.
    #[must_use]
    pub fn process_memory(&self) -> u64 {
        let Ok(pid) = sysinfo::get_current_pid() else {
            return 0;
        };
        let mut system = self
            .system
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            false,
            sysinfo::ProcessRefreshKind::nothing().with_memory(),
        );
        system.process(pid).map_or(0, sysinfo::Process::memory)
    }

    #[must_use]
    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEvent> {
        self.logs.subscribe()
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
