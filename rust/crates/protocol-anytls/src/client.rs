//! Session pool matching Go `transport/anytls/session.Client`.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

use crate::padding::PaddingFactory;
use crate::session::{Session, StreamCloseHook};
use crate::{AnyTlsProtocolError, authentication_blob};

/// Async dialer that returns an authenticated TLS carrier ready for session frames.
pub type DialOut = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<BoxedStream, AnyTlsProtocolError>> + Send>>
        + Send
        + Sync,
>;

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub client_metadata: String,
    pub idle_session_check_interval: Duration,
    pub idle_session_timeout: Duration,
    pub min_idle_session: usize,
    pub disable_reuse: bool,
    pub password: String,
}

struct IdleEntry {
    session: Session,
    idle_since: Instant,
    seq: u64,
}

struct ClientInner {
    dial_out: DialOut,
    padding: Arc<PaddingFactory>,
    options: ClientOptions,
    closed: AtomicBool,
    session_counter: AtomicU64,
    idle: Mutex<VecDeque<IdleEntry>>,
    sessions: Mutex<BTreeMap<u64, Session>>,
    wake: Notify,
}

/// Long-lived `AnyTLS` client with optional idle session reuse.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    #[must_use]
    pub fn new(dial_out: DialOut, options: ClientOptions) -> Self {
        let mut options = options;
        if options.idle_session_check_interval <= Duration::from_secs(5) {
            options.idle_session_check_interval = Duration::from_secs(30);
        }
        if options.idle_session_timeout <= Duration::from_secs(5) {
            options.idle_session_timeout = Duration::from_secs(30);
        }
        let inner = Arc::new(ClientInner {
            dial_out,
            padding: PaddingFactory::default_factory(),
            options,
            closed: AtomicBool::new(false),
            session_counter: AtomicU64::new(0),
            idle: Mutex::new(VecDeque::new()),
            sessions: Mutex::new(BTreeMap::new()),
            wake: Notify::new(),
        });
        if !inner.options.disable_reuse {
            let janitor = Arc::clone(&inner);
            tokio::spawn(async move {
                idle_cleanup_loop(janitor).await;
            });
        }
        Self { inner }
    }

    /// Opens a proxy stream to `destination`, reusing an idle session when allowed.
    ///
    /// # Errors
    ///
    /// Returns dial, authentication, or session errors.
    pub async fn create_proxy(
        &self,
        destination: &Destination,
    ) -> Result<BoxedStream, AnyTlsProtocolError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(AnyTlsProtocolError::Protocol(
                "AnyTLS client is closed".to_owned(),
            ));
        }

        // Prefer an idle session. If opening on it fails (peer gone while idle),
        // close that session and dial a fresh one; observable recovery matches
        // Go after the failed attempt is retried by the caller / wait loop.
        if !self.inner.options.disable_reuse
            && let Some(idle) = self.take_idle_session()
            && let Ok(stream) = self.open_on_session(idle, destination).await
        {
            return Ok(stream);
        }

        let session = self.create_session().await?;
        self.open_on_session(session, destination).await
    }

    async fn open_on_session(
        &self,
        session: Session,
        destination: &Destination,
    ) -> Result<BoxedStream, AnyTlsProtocolError> {
        let client = Arc::clone(&self.inner);
        let session_for_hook = session.clone();
        let close_hook: StreamCloseHook = Box::new(move || {
            if session_for_hook.is_closed() {
                return;
            }
            if client.options.disable_reuse || client.closed.load(Ordering::Acquire) {
                let session = session_for_hook.clone();
                tokio::spawn(async move {
                    session.close().await;
                });
                return;
            }
            let mut idle = client
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.push_front(IdleEntry {
                seq: session_for_hook.seq(),
                idle_since: Instant::now(),
                session: session_for_hook,
            });
        });

        match session.open_proxy(destination, Some(close_hook)).await {
            Ok(stream) => Ok(Box::new(stream)),
            Err(error) => {
                session.close().await;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn test_idle_len(&self) -> usize {
        self.inner
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[cfg(test)]
    fn test_age_idle_sessions(&self, age: Duration) {
        let past = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        let mut idle = self
            .inner
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in idle.iter_mut() {
            entry.idle_since = past;
        }
    }

    #[cfg(test)]
    fn test_run_idle_cleanup(&self) {
        idle_cleanup_once(&self.inner);
    }

    #[cfg(test)]
    async fn test_push_closed_idle_session(&self) {
        let Some(session) = self.take_idle_session() else {
            return;
        };
        session.close().await;
        let mut idle = self
            .inner
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        idle.push_front(IdleEntry {
            seq: session.seq(),
            idle_since: Instant::now(),
            session,
        });
    }

    pub async fn close(&self) {
        if self
            .inner
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.inner.wake.notify_waiters();
        let sessions: Vec<Session> = {
            let mut guard = self
                .inner
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *guard).into_values().collect()
        };
        {
            let mut idle = self
                .inner
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            idle.clear();
        }
        for session in sessions {
            session.close().await;
        }
    }

    async fn create_session(&self) -> Result<Session, AnyTlsProtocolError> {
        let mut remote = (self.inner.dial_out)().await?;
        let auth = authentication_blob(&self.inner.options.password, &self.inner.padding);
        remote.write_all(&auth).await?;
        remote.flush().await?;

        let seq = self.inner.session_counter.fetch_add(1, Ordering::AcqRel) + 1;
        let session = Session::start(
            remote,
            &self.inner.options.client_metadata,
            Arc::clone(&self.inner.padding),
            seq,
        )
        .await?;

        let client = Arc::clone(&self.inner);
        let session_seq = seq;
        session.set_close_hook(Box::new(move || {
            if !client.options.disable_reuse {
                let mut idle = client
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                idle.retain(|entry| entry.seq != session_seq);
            }
            client
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&session_seq);
        }));

        self.inner
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(seq, session.clone());
        Ok(session)
    }

    fn take_idle_session(&self) -> Option<Session> {
        let mut idle = self
            .inner
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(entry) = idle.pop_front() {
            if entry.session.is_closed() {
                continue;
            }
            return Some(entry.session);
        }
        None
    }
}

async fn idle_cleanup_loop(client: Arc<ClientInner>) {
    let interval = client.options.idle_session_check_interval;
    loop {
        tokio::select! {
            () = client.wake.notified() => {
                if client.closed.load(Ordering::Acquire) {
                    break;
                }
            }
            () = tokio::time::sleep(interval) => {
                if client.closed.load(Ordering::Acquire) {
                    break;
                }
                idle_cleanup_once(&client);
            }
        }
    }
}

fn idle_cleanup_once(client: &ClientInner) {
    let exp_time = Instant::now()
        .checked_sub(client.options.idle_session_timeout)
        .unwrap_or_else(Instant::now);
    let mut active_count = 0usize;
    let mut to_close = Vec::new();
    {
        let mut idle = client
            .idle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut kept = VecDeque::new();
        while let Some(mut entry) = idle.pop_front() {
            if entry.idle_since >= exp_time {
                active_count += 1;
                kept.push_back(entry);
                continue;
            }
            if active_count < client.options.min_idle_session {
                entry.idle_since = Instant::now();
                active_count += 1;
                kept.push_back(entry);
                continue;
            }
            to_close.push(entry.session);
        }
        *idle = kept;
    }
    for session in to_close {
        tokio::spawn(async move {
            session.close().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rewrite_model::{Destination, Host};
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, duplex};

    #[tokio::test]
    async fn sequential_create_proxy_reuses_idle_session() {
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_ref = Arc::clone(&dials);
        let dial_out: DialOut = Arc::new(move || {
            let dials_ref = Arc::clone(&dials_ref);
            Box::pin(async move {
                dials_ref.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = duplex(64 * 1024);
                tokio::spawn(async move {
                    // Consume auth blob then speak enough frames to keep the
                    // session reader alive until the test finishes.
                    let mut auth = [0_u8; 64];
                    let _ = server.read(&mut auth).await;
                    let mut buffer = vec![0_u8; 4096];
                    loop {
                        match server.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
                Ok(Box::new(client) as BoxedStream)
            })
        });
        let client = Client::new(
            dial_out,
            ClientOptions {
                client_metadata: "test".to_owned(),
                idle_session_check_interval: Duration::from_secs(30),
                idle_session_timeout: Duration::from_secs(30),
                min_idle_session: 0,
                disable_reuse: false,
                password: "pw".to_owned(),
            },
        );
        let destination = Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 443,
        };
        let stream1 = client.create_proxy(&destination).await.expect("stream1");
        drop(stream1);
        tokio::task::yield_now().await;
        let stream2 = client.create_proxy(&destination).await.expect("stream2");
        drop(stream2);
        assert_eq!(dials.load(Ordering::SeqCst), 1, "expected one TLS dial");
        client.close().await;
    }

    #[tokio::test]
    async fn idle_cleanup_evicts_expired_when_min_idle_is_zero() {
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_ref = Arc::clone(&dials);
        let dial_out: DialOut = Arc::new(move || {
            let dials_ref = Arc::clone(&dials_ref);
            Box::pin(async move {
                dials_ref.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut auth = [0_u8; 64];
                    let _ = server.read(&mut auth).await;
                    let mut buffer = vec![0_u8; 4096];
                    loop {
                        match server.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
                Ok(Box::new(client) as BoxedStream)
            })
        });
        let client = Client::new(
            dial_out,
            ClientOptions {
                client_metadata: "idle-evict".to_owned(),
                idle_session_check_interval: Duration::from_secs(6),
                idle_session_timeout: Duration::from_secs(6),
                min_idle_session: 0,
                disable_reuse: false,
                password: "pw".to_owned(),
            },
        );
        let destination = Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 443,
        };
        let stream = client.create_proxy(&destination).await.expect("stream");
        drop(stream);
        tokio::task::yield_now().await;
        assert_eq!(client.test_idle_len(), 1);
        client.test_age_idle_sessions(Duration::from_mins(1));
        client.test_run_idle_cleanup();
        assert_eq!(
            client.test_idle_len(),
            0,
            "expired idle session must be closed"
        );
        let stream = client.create_proxy(&destination).await.expect("fresh");
        drop(stream);
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        client.close().await;
    }

    #[tokio::test]
    async fn idle_cleanup_keeps_min_idle_sessions() {
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_ref = Arc::clone(&dials);
        let dial_out: DialOut = Arc::new(move || {
            let dials_ref = Arc::clone(&dials_ref);
            Box::pin(async move {
                dials_ref.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut auth = [0_u8; 64];
                    let _ = server.read(&mut auth).await;
                    let mut buffer = vec![0_u8; 4096];
                    loop {
                        match server.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
                Ok(Box::new(client) as BoxedStream)
            })
        });
        let client = Client::new(
            dial_out,
            ClientOptions {
                client_metadata: "idle-keep".to_owned(),
                idle_session_check_interval: Duration::from_secs(6),
                idle_session_timeout: Duration::from_secs(6),
                min_idle_session: 1,
                disable_reuse: false,
                password: "pw".to_owned(),
            },
        );
        let destination = Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 443,
        };
        // Hold both streams open so the second dial cannot reuse the first session.
        let stream1 = client.create_proxy(&destination).await.expect("stream1");
        let stream2 = client.create_proxy(&destination).await.expect("stream2");
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        drop(stream1);
        drop(stream2);
        tokio::task::yield_now().await;
        assert_eq!(client.test_idle_len(), 2);
        client.test_age_idle_sessions(Duration::from_mins(1));
        client.test_run_idle_cleanup();
        assert_eq!(
            client.test_idle_len(),
            1,
            "min_idle_session keeps one session"
        );
        let stream = client.create_proxy(&destination).await.expect("reused");
        drop(stream);
        assert_eq!(
            dials.load(Ordering::SeqCst),
            2,
            "kept idle session must be reused without a new dial"
        );
        client.close().await;
    }

    #[tokio::test]
    async fn create_proxy_skips_closed_idle_session_and_redials() {
        let dials = Arc::new(AtomicUsize::new(0));
        let dials_ref = Arc::clone(&dials);
        let dial_out: DialOut = Arc::new(move || {
            let dials_ref = Arc::clone(&dials_ref);
            Box::pin(async move {
                dials_ref.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut auth = [0_u8; 64];
                    let _ = server.read(&mut auth).await;
                    let mut buffer = vec![0_u8; 4096];
                    loop {
                        match server.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
                Ok(Box::new(client) as BoxedStream)
            })
        });
        let client = Client::new(
            dial_out,
            ClientOptions {
                client_metadata: "recover".to_owned(),
                idle_session_check_interval: Duration::from_secs(30),
                idle_session_timeout: Duration::from_secs(30),
                min_idle_session: 0,
                disable_reuse: false,
                password: "pw".to_owned(),
            },
        );
        let destination = Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 443,
        };
        let stream = client.create_proxy(&destination).await.expect("stream");
        drop(stream);
        tokio::task::yield_now().await;
        client.test_push_closed_idle_session().await;
        let stream = client.create_proxy(&destination).await.expect("recovered");
        drop(stream);
        assert!(dials.load(Ordering::SeqCst) >= 2);
        client.close().await;
    }
}
