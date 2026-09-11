//! Long-lived `WireGuard` client: UDP bind, handshake, smoltcp TCP/UDP dials.

use std::future::Future;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use rand::RngExt as _;
use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use smoltcp::iface::SocketHandle;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio_util::sync::CancellationToken;

use crate::stack::{IpStack, WgTcpStream, WgUdpSocket, lock_stack};
use crate::tunnel::{NoiseTunnel, TunnelAction};
use crate::{DEFAULT_MTU, HANDSHAKE_TIMEOUT, WireGuardProtocolError};

const PEER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_REFRESH_BACKOFF: Duration = Duration::from_secs(1);

/// Construction options for a single-peer `WireGuard` outbound.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub local_v4: Option<(Ipv4Addr, u8)>,
    pub local_v6: Option<(Ipv6Addr, u8)>,
    pub mtu: u16,
    pub persistent_keepalive: Option<u16>,
    pub reserved: [u8; 3],
    pub bind_interface: String,
    pub routing_mark: i64,
    /// `ZERO` means resolve the peer hostname only at first connect (Go).
    pub refresh_server_ip_interval: Duration,
    /// Optional first hop for the outer UDP bind (PSN-resolved IP). Refresh
    /// still re-resolves [`Self::server`] through [`Self::resolve_peer`].
    pub initial_endpoint: Option<SocketAddr>,
    /// Peer hostname resolver. Product path supplies hosts + PSN (same policy
    /// as first connect). When set, refresh never falls back to `lookup_host`.
    pub resolve_peer: Option<PeerResolveHook>,
}

/// Resolves the configured `WireGuard` server name (DDNS refresh and tests).
#[derive(Clone)]
pub struct PeerResolveHook(Arc<ResolvePeerFn>);

type PeerResolveFuture = Pin<Box<dyn Future<Output = Option<SocketAddr>> + Send>>;
type ResolvePeerFn = dyn Fn(String, u16) -> PeerResolveFuture + Send + Sync;

impl PeerResolveHook {
    pub fn new<F, Fut>(hook: F) -> Self
    where
        F: Fn(String, u16) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<SocketAddr>> + Send + 'static,
    {
        Self(Arc::new(move |host, port| Box::pin(hook(host, port))))
    }
}

impl std::fmt::Debug for PeerResolveHook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PeerResolveHook")
    }
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 51820,
            private_key: [0; 32],
            peer_public_key: [0; 32],
            preshared_key: None,
            local_v4: Some((Ipv4Addr::new(10, 0, 0, 2), 32)),
            local_v6: None,
            mtu: DEFAULT_MTU,
            persistent_keepalive: None,
            reserved: [0; 3],
            bind_interface: String::new(),
            routing_mark: 0,
            refresh_server_ip_interval: Duration::ZERO,
            initial_endpoint: None,
            resolve_peer: None,
        }
    }
}

struct ClientInner {
    tunnel: NoiseTunnel,
    stack: Arc<Mutex<IpStack>>,
    udp: RwLock<Arc<UdpSocket>>,
    udp_changed: Notify,
    endpoint: Mutex<SocketAddr>,
    server: String,
    port: u16,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<u16>,
    refresh_server_ip_interval: Duration,
    next_refresh_at: Mutex<Instant>,
    refresh_inflight: AtomicBool,
    refresh_backoff_ms: AtomicU64,
    resolve_peer: Option<PeerResolveHook>,
    notify: Arc<Notify>,
    shutdown: CancellationToken,
    handshake: AsyncMutex<()>,
    established: AtomicBool,
    datagrams_sent: AtomicU64,
    bind_interface: String,
    routing_mark: i64,
    has_v4: bool,
    has_v6: bool,
    /// `Client` clones only. Reactor and refresh tasks hold `Arc` but do not
    /// increment this, so Drop can cancel when the last handle is released.
    client_handles: AtomicUsize,
}

/// Userspace `WireGuard` client matching Go `adapter/outbound.WireGuard` for 6I-C.
pub struct Client {
    inner: Arc<ClientInner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WireGuardClient")
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        self.inner.client_handles.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if self.inner.client_handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.shutdown.cancel();
            self.inner.notify.notify_waiters();
        }
    }
}

impl Client {
    /// Binds the UDP socket and starts the packet reactor. Handshake completes
    /// on the first TCP dial.
    ///
    /// # Errors
    ///
    /// Returns UDP bind / endpoint resolution failures.
    pub async fn new(options: ClientOptions) -> Result<Self, WireGuardProtocolError> {
        let endpoint = if let Some(initial) = options.initial_endpoint {
            initial
        } else {
            resolve_peer_endpoint(&options.server, options.port, options.resolve_peer.as_ref())
                .await?
        };
        protect_peer_endpoint(endpoint)?;
        let mtu = if options.mtu == 0 {
            DEFAULT_MTU
        } else {
            options.mtu
        };
        if options.local_v4.is_none() && options.local_v6.is_none() {
            return Err(WireGuardProtocolError::protocol(
                "WireGuard requires ip or ipv6",
            ));
        }
        let local = SocketAddr::new(
            match endpoint.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            0,
        );
        let std_socket = rewrite_platform::bind_outbound_udp(
            local,
            endpoint,
            &options.bind_interface,
            options.routing_mark,
        )?;
        std_socket.set_nonblocking(true)?;
        let udp = Arc::new(UdpSocket::from_std(std_socket)?);
        let index = rand::rng().random::<u32>();
        let tunnel = NoiseTunnel::new(
            options.private_key,
            options.peer_public_key,
            options.preshared_key,
            options.persistent_keepalive,
            options.reserved,
            index,
        )?;
        let stack = Arc::new(Mutex::new(IpStack::new(
            options.local_v4,
            options.local_v6,
            usize::from(mtu),
        )));
        let notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let inner = Arc::new(ClientInner {
            tunnel,
            stack,
            udp: RwLock::new(udp),
            udp_changed: Notify::new(),
            endpoint: Mutex::new(endpoint),
            server: options.server,
            port: options.port,
            private_key: options.private_key,
            peer_public_key: options.peer_public_key,
            preshared_key: options.preshared_key,
            persistent_keepalive: options.persistent_keepalive,
            refresh_server_ip_interval: options.refresh_server_ip_interval,
            next_refresh_at: Mutex::new(Instant::now() + options.refresh_server_ip_interval),
            refresh_inflight: AtomicBool::new(false),
            refresh_backoff_ms: AtomicU64::new(0),
            resolve_peer: options.resolve_peer,
            notify,
            shutdown,
            handshake: AsyncMutex::new(()),
            established: AtomicBool::new(false),
            datagrams_sent: AtomicU64::new(0),
            bind_interface: options.bind_interface,
            routing_mark: options.routing_mark,
            has_v4: options.local_v4.is_some(),
            has_v6: options.local_v6.is_some(),
            client_handles: AtomicUsize::new(1),
        });
        let reactor = Arc::clone(&inner);
        tokio::spawn(async move {
            run_reactor(reactor).await;
        });
        Ok(Self { inner })
    }

    /// Opens a TCP stream to `destination` through the tunnel.
    ///
    /// Destination TCP failures never reset the shared Noise session. Recovery
    /// happens from tunnel events (`ConnectionExpired` / incoming handshake).
    ///
    /// # Errors
    ///
    /// Returns handshake, family, or stack connect failures.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> Result<BoxedStream, WireGuardProtocolError> {
        schedule_endpoint_refresh(&self.inner);
        self.open_tcp_once(destination).await
    }

    /// Opens a connectionless UDP socket through the tunnel (Go `ListenPacketContext`).
    ///
    /// # Errors
    ///
    /// Returns handshake or stack bind failures.
    pub async fn open_udp(&self) -> Result<WgUdpSocket, WireGuardProtocolError> {
        schedule_endpoint_refresh(&self.inner);
        self.ensure_handshake().await?;
        let handle = {
            let mut stack = lock_stack(&self.inner.stack);
            stack.bind_udp()?
        };
        self.inner.notify.notify_one();
        Ok(WgUdpSocket::new(
            handle,
            Arc::clone(&self.inner.stack),
            Arc::clone(&self.inner.notify),
        ))
    }

    /// Replaces the peer UDP endpoint (Go `updateServerAddr`).
    ///
    /// Socket bind/connect is prepared first; the previous endpoint is kept if
    /// the new socket cannot be used (including address-family changes).
    ///
    /// # Errors
    ///
    /// Returns when TUN loop-avoidance cannot install a host route for a
    /// non-loopback destination, or when the UDP socket cannot be updated.
    pub async fn replace_endpoint(
        &self,
        endpoint: SocketAddr,
    ) -> Result<(), WireGuardProtocolError> {
        apply_endpoint(&self.inner, endpoint).await
    }

    /// UDP datagrams written to the peer (handshake, keepalive, and transport).
    #[must_use]
    pub fn datagrams_sent(&self) -> u64 {
        self.inner.datagrams_sent.load(Ordering::Relaxed)
    }

    /// Live userspace TCP/UDP sockets (tests assert cleanup after fail/cancel).
    #[must_use]
    pub fn live_socket_count(&self) -> usize {
        lock_stack(&self.inner.stack).live_socket_count()
    }

    #[must_use]
    pub fn has_ipv4(&self) -> bool {
        self.inner.has_v4
    }

    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.inner.has_v6
    }

    /// Stops the packet reactor. Outstanding streams fail subsequent I/O.
    #[allow(clippy::unused_async)] // matches TUIC/Hysteria2 retire/close shape
    pub async fn close(&self) {
        self.inner.shutdown.cancel();
        self.inner.notify.notify_waiters();
    }

    async fn open_tcp_once(
        &self,
        destination: &Destination,
    ) -> Result<BoxedStream, WireGuardProtocolError> {
        let dest = self.destination_addr(destination)?;
        self.ensure_handshake().await?;
        let handle = {
            let mut stack = lock_stack(&self.inner.stack);
            stack.connect(dest).map_err(|error| {
                if error.kind() == ErrorKind::AddrNotAvailable {
                    WireGuardProtocolError::UnsupportedFamily
                } else {
                    error.into()
                }
            })?
        };
        let connecting = ConnectingTcp {
            handle: Some(handle),
            stack: Arc::clone(&self.inner.stack),
            notify: Arc::clone(&self.inner.notify),
        };
        self.inner.notify.notify_one();
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        loop {
            {
                let stack = lock_stack(&self.inner.stack);
                match stack.state(handle) {
                    Some(smoltcp::socket::tcp::State::Established) => {
                        drop(stack);
                        return Ok(Box::new(connecting.into_stream()));
                    }
                    Some(
                        smoltcp::socket::tcp::State::Closed
                        | smoltcp::socket::tcp::State::TimeWait
                        | smoltcp::socket::tcp::State::Listen,
                    ) => {
                        return Err(WireGuardProtocolError::protocol(
                            "WireGuard TCP connect closed before establish",
                        ));
                    }
                    _ => {}
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(WireGuardProtocolError::protocol(
                    "WireGuard TCP connect timed out",
                ));
            }
            tokio::select! {
                () = self.inner.shutdown.cancelled() => {
                    return Err(WireGuardProtocolError::protocol("WireGuard client retired"));
                }
                () = self.inner.notify.notified() => {}
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
    }

    async fn ensure_handshake(&self) -> Result<(), WireGuardProtocolError> {
        if self.inner.established.load(Ordering::Acquire) {
            return Ok(());
        }
        let _guard = self.inner.handshake.lock().await;
        self.complete_handshake().await
    }

    async fn complete_handshake(&self) -> Result<(), WireGuardProtocolError> {
        if self.inner.established.load(Ordering::Acquire) {
            return Ok(());
        }
        self.send_action(self.inner.tunnel.format_handshake(true))
            .await?;
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        while !self.inner.established.load(Ordering::Acquire) {
            if tokio::time::Instant::now() >= deadline {
                return Err(WireGuardProtocolError::protocol(
                    "WireGuard handshake timed out",
                ));
            }
            probe_established(&self.inner).await;
            if self.inner.established.load(Ordering::Acquire) {
                return Ok(());
            }
            tokio::select! {
                () = self.inner.shutdown.cancelled() => {
                    return Err(WireGuardProtocolError::protocol("WireGuard client retired"));
                }
                () = self.inner.notify.notified() => {}
                () = tokio::time::sleep(Duration::from_millis(50)) => {
                    self.send_action(self.inner.tunnel.format_handshake(false))
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn send_action(&self, action: TunnelAction) -> Result<(), WireGuardProtocolError> {
        dispatch_action(&self.inner, action).await
    }

    fn destination_addr(
        &self,
        destination: &Destination,
    ) -> Result<SocketAddr, WireGuardProtocolError> {
        match &destination.host {
            Host::Ip(addr) => {
                let supported = match addr {
                    IpAddr::V4(_) => self.inner.has_v4,
                    IpAddr::V6(_) => self.inner.has_v6,
                };
                if supported {
                    Ok(SocketAddr::new(*addr, destination.port))
                } else {
                    Err(WireGuardProtocolError::UnsupportedFamily)
                }
            }
            Host::Domain(_) => Err(WireGuardProtocolError::protocol(
                "WireGuard destination must be resolved before dial",
            )),
        }
    }
}

async fn run_reactor(inner: Arc<ClientInner>) {
    let mut buf = vec![0_u8; 65_535];
    let mut timers = tokio::time::interval(Duration::from_millis(100));
    timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let delay = lock_stack(&inner.stack)
            .poll_delay()
            .unwrap_or(Duration::from_millis(100));
        let udp_changed = inner.udp_changed.notified();
        tokio::pin!(udp_changed);
        let udp = clone_udp(&inner);
        tokio::select! {
            () = inner.shutdown.cancelled() => break,
            result = udp.recv_from(&mut buf) => {
                let Ok((n, from)) = result else { break };
                handle_incoming(&inner, Some(from), &buf[..n]).await;
            }
            () = udp_changed => {}
            () = inner.notify.notified() => {
                pump_stack(&inner).await;
            }
            () = tokio::time::sleep(delay) => {
                pump_stack(&inner).await;
            }
            _ = timers.tick() => {
                let action = inner.tunnel.update_timers();
                let _ = dispatch_action(&inner, action).await;
                schedule_endpoint_refresh(&inner);
                pump_stack(&inner).await;
            }
        }
    }
    {
        let mut stack = lock_stack(&inner.stack);
        stack.shutdown_all();
        stack.poll();
    }
    inner.notify.notify_waiters();
}

async fn handle_incoming(inner: &ClientInner, from: Option<SocketAddr>, datagram: &[u8]) {
    let mut packet: &[u8] = datagram;
    loop {
        match inner.tunnel.decapsulate(from, packet) {
            TunnelAction::Done => break,
            TunnelAction::Expired => {
                handle_expired(inner).await;
                break;
            }
            TunnelAction::SendUdp(reply) => {
                let _ = send_udp(inner, &reply).await;
                packet = &[];
            }
            TunnelAction::RecvIp(ip) => {
                inner.established.store(true, Ordering::Release);
                lock_stack(&inner.stack).ingest_ip(ip);
                inner.notify.notify_waiters();
                packet = &[];
            }
        }
    }
    probe_established(inner).await;
    pump_stack(inner).await;
}

async fn pump_stack(inner: &ClientInner) {
    let packets = {
        let mut stack = lock_stack(&inner.stack);
        stack.poll();
        stack.take_ip()
    };
    for packet in packets {
        match inner.tunnel.encapsulate(&packet) {
            TunnelAction::SendUdp(datagram) => {
                if is_transport(&datagram) {
                    inner.established.store(true, Ordering::Release);
                    inner.notify.notify_waiters();
                }
                let _ = send_udp(inner, &datagram).await;
            }
            TunnelAction::Expired => handle_expired(inner).await,
            TunnelAction::Done | TunnelAction::RecvIp(_) => {}
        }
        // Drain handshake follow-ups.
        loop {
            match inner.tunnel.decapsulate(None, &[]) {
                TunnelAction::SendUdp(extra) => {
                    let _ = send_udp(inner, &extra).await;
                }
                TunnelAction::RecvIp(ip) => {
                    inner.established.store(true, Ordering::Release);
                    lock_stack(&inner.stack).ingest_ip(ip);
                    inner.notify.notify_waiters();
                }
                TunnelAction::Expired => {
                    handle_expired(inner).await;
                    break;
                }
                TunnelAction::Done => break,
            }
        }
    }
}

async fn probe_established(inner: &ClientInner) {
    if inner.established.load(Ordering::Acquire) {
        return;
    }
    match inner.tunnel.encapsulate(&[]) {
        TunnelAction::SendUdp(datagram) if is_transport(&datagram) => {
            inner.established.store(true, Ordering::Release);
            inner.notify.notify_waiters();
            let _ = send_udp(inner, &datagram).await;
        }
        TunnelAction::SendUdp(datagram) => {
            let _ = send_udp(inner, &datagram).await;
        }
        TunnelAction::Expired => handle_expired(inner).await,
        TunnelAction::Done | TunnelAction::RecvIp(_) => {}
    }
}

fn is_transport(datagram: &[u8]) -> bool {
    datagram.first().copied() == Some(4)
}

async fn dispatch_action(
    inner: &ClientInner,
    action: TunnelAction,
) -> Result<(), WireGuardProtocolError> {
    match action {
        TunnelAction::Done | TunnelAction::RecvIp(_) => Ok(()),
        TunnelAction::Expired => {
            handle_expired(inner).await;
            Ok(())
        }
        TunnelAction::SendUdp(datagram) => {
            if is_transport(&datagram) {
                inner.established.store(true, Ordering::Release);
                inner.notify.notify_waiters();
            }
            send_udp(inner, &datagram).await
        }
    }
}

async fn handle_expired(inner: &ClientInner) {
    reset_session(inner);
    inner.notify.notify_waiters();
    match inner.tunnel.format_handshake(true) {
        TunnelAction::SendUdp(datagram) => {
            let _ = send_udp(inner, &datagram).await;
        }
        TunnelAction::Expired | TunnelAction::Done | TunnelAction::RecvIp(_) => {}
    }
}

fn reset_session(inner: &ClientInner) {
    inner.established.store(false, Ordering::Release);
    inner.tunnel.reset(
        inner.private_key,
        inner.peer_public_key,
        inner.preshared_key,
        inner.persistent_keepalive,
        rand::rng().random::<u32>(),
    );
}

async fn send_udp(inner: &ClientInner, datagram: &[u8]) -> Result<(), WireGuardProtocolError> {
    let (udp, endpoint) = {
        let udp = inner
            .udp
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let endpoint = *inner
            .endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (Arc::clone(&udp), endpoint)
    };
    udp.send_to(datagram, endpoint).await?;
    inner.datagrams_sent.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

async fn apply_endpoint(
    inner: &ClientInner,
    endpoint: SocketAddr,
) -> Result<(), WireGuardProtocolError> {
    protect_peer_endpoint(endpoint)?;
    let current = *inner
        .endpoint
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if current == endpoint {
        *inner
            .next_refresh_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Instant::now() + inner.refresh_server_ip_interval;
        inner.refresh_backoff_ms.store(0, Ordering::Relaxed);
        return Ok(());
    }
    let udp = bind_peer_udp(inner, endpoint).await?;
    {
        let mut socket = inner
            .udp
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut slot = inner
            .endpoint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *socket = Arc::new(udp);
        *slot = endpoint;
    }
    *inner
        .next_refresh_at
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Instant::now() + inner.refresh_server_ip_interval;
    inner.refresh_backoff_ms.store(0, Ordering::Relaxed);
    inner.udp_changed.notify_waiters();
    inner.notify.notify_waiters();
    Ok(())
}

async fn bind_peer_udp(
    inner: &ClientInner,
    endpoint: SocketAddr,
) -> Result<UdpSocket, WireGuardProtocolError> {
    let local = SocketAddr::new(
        match endpoint.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        0,
    );
    let std_socket = rewrite_platform::bind_outbound_udp(
        local,
        endpoint,
        &inner.bind_interface,
        inner.routing_mark,
    )?;
    std_socket.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(std_socket)?;
    udp.connect(endpoint).await?;
    Ok(udp)
}

fn clone_udp(inner: &ClientInner) -> Arc<UdpSocket> {
    Arc::clone(
        &inner
            .udp
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

fn protect_peer_endpoint(endpoint: SocketAddr) -> Result<(), WireGuardProtocolError> {
    rewrite_platform::protect_outbound_destination(endpoint.ip()).map_err(|error| {
        WireGuardProtocolError::protocol(format!("WireGuard loop-avoidance: {error}"))
    })
}

fn schedule_endpoint_refresh(inner: &Arc<ClientInner>) {
    if inner.refresh_server_ip_interval.is_zero() {
        return;
    }
    let due = Instant::now()
        >= *inner
            .next_refresh_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !due {
        return;
    }
    if inner.refresh_inflight.swap(true, Ordering::AcqRel) {
        return;
    }
    let inner = Arc::clone(inner);
    tokio::spawn(async move {
        refresh_endpoint_task(inner).await;
    });
}

async fn refresh_endpoint_task(inner: Arc<ClientInner>) {
    let resolved = tokio::select! {
        () = inner.shutdown.cancelled() => {
            inner.refresh_inflight.store(false, Ordering::Release);
            return;
        }
        result = tokio::time::timeout(
            PEER_RESOLVE_TIMEOUT,
            resolve_peer_endpoint(&inner.server, inner.port, inner.resolve_peer.as_ref()),
        ) => result,
    };
    match resolved {
        Ok(Ok(endpoint)) => {
            if apply_endpoint(&inner, endpoint).await.is_err() {
                schedule_refresh_backoff(&inner);
            }
        }
        Ok(Err(_)) | Err(_) => schedule_refresh_backoff(&inner),
    }
    inner.refresh_inflight.store(false, Ordering::Release);
}

fn schedule_refresh_backoff(inner: &ClientInner) {
    let interval = inner.refresh_server_ip_interval;
    let cap = interval.max(MIN_REFRESH_BACKOFF);
    let stored = inner.refresh_backoff_ms.load(Ordering::Relaxed);
    let wait = if stored == 0 {
        MIN_REFRESH_BACKOFF.min(cap)
    } else {
        Duration::from_millis(stored).min(cap)
    };
    let doubled = wait.saturating_mul(2).min(cap);
    inner
        .refresh_backoff_ms
        .store(millis_u64(doubled), Ordering::Relaxed);
    *inner
        .next_refresh_at
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now() + wait;
}

fn millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

struct ConnectingTcp {
    handle: Option<SocketHandle>,
    stack: Arc<Mutex<IpStack>>,
    notify: Arc<Notify>,
}

impl ConnectingTcp {
    fn into_stream(mut self) -> WgTcpStream {
        let handle = self.handle.take().expect("connecting handle");
        WgTcpStream::new(handle, Arc::clone(&self.stack), Arc::clone(&self.notify))
    }
}

impl Drop for ConnectingTcp {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            lock_stack(&self.stack).abort(handle);
            self.notify.notify_one();
        }
    }
}

async fn resolve_peer_endpoint(
    server: &str,
    port: u16,
    hook: Option<&PeerResolveHook>,
) -> Result<SocketAddr, WireGuardProtocolError> {
    if let Some(hook) = hook {
        return (hook.0)(server.to_owned(), port)
            .await
            .ok_or_else(|| WireGuardProtocolError::protocol("WireGuard server did not resolve"));
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((server, port))
        .await?
        .next()
        .ok_or_else(|| WireGuardProtocolError::protocol("WireGuard server did not resolve"))
}
