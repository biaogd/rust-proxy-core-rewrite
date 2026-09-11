//! Long-lived `WireGuard` client: UDP bind, handshake, smoltcp TCP dials.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::RngExt as _;
use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::stack::{IpStack, WgTcpStream, lock_stack};
use crate::tunnel::{NoiseTunnel, TunnelAction};
use crate::{DEFAULT_MTU, HANDSHAKE_TIMEOUT, WireGuardProtocolError};

/// Construction options for a single-peer IPv4 `WireGuard` outbound.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub local_addr: Ipv4Addr,
    pub local_prefix_len: u8,
    pub mtu: u16,
    pub persistent_keepalive: Option<u16>,
    pub reserved: [u8; 3],
    pub bind_interface: String,
    pub routing_mark: i64,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 51820,
            private_key: [0; 32],
            peer_public_key: [0; 32],
            preshared_key: None,
            local_addr: Ipv4Addr::new(10, 0, 0, 2),
            local_prefix_len: 32,
            mtu: DEFAULT_MTU,
            persistent_keepalive: None,
            reserved: [0; 3],
            bind_interface: String::new(),
            routing_mark: 0,
        }
    }
}

struct ClientInner {
    tunnel: NoiseTunnel,
    stack: Arc<Mutex<IpStack>>,
    udp: UdpSocket,
    endpoint: Mutex<SocketAddr>,
    notify: Arc<Notify>,
    shutdown: CancellationToken,
    established: AtomicBool,
}

/// Userspace `WireGuard` client matching Go `adapter/outbound.WireGuard` for 6I-A TCP.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WireGuardClient")
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // Client clones plus the reactor each hold `ClientInner`. Cancel only
        // when this is the last Client (count is 2: this value + reactor).
        if Arc::strong_count(&self.inner) <= 2 {
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
        let endpoint = resolve_ipv4_endpoint(&options.server, options.port).await?;
        let mtu = if options.mtu == 0 {
            DEFAULT_MTU
        } else {
            options.mtu
        };
        let local = match endpoint.ip() {
            IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            IpAddr::V6(_) => {
                return Err(WireGuardProtocolError::Ipv4Only);
            }
        };
        let std_socket = rewrite_platform::bind_outbound_udp(
            local,
            endpoint,
            &options.bind_interface,
            options.routing_mark,
        )?;
        std_socket.set_nonblocking(true)?;
        let udp = UdpSocket::from_std(std_socket)?;
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
            options.local_addr,
            options.local_prefix_len,
            usize::from(mtu),
        )));
        let notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let inner = Arc::new(ClientInner {
            tunnel,
            stack,
            udp,
            endpoint: Mutex::new(endpoint),
            notify,
            shutdown,
            established: AtomicBool::new(false),
        });
        let reactor = Arc::clone(&inner);
        tokio::spawn(async move {
            run_reactor(reactor).await;
        });
        Ok(Self { inner })
    }

    /// Opens a TCP stream to `destination` through the tunnel.
    ///
    /// # Errors
    ///
    /// Returns handshake, IPv4, or stack connect failures.
    pub async fn open_tcp(
        &self,
        destination: &Destination,
    ) -> Result<BoxedStream, WireGuardProtocolError> {
        let dest = destination_v4(destination)?;
        self.ensure_handshake().await?;
        let handle = {
            let mut stack = lock_stack(&self.inner.stack);
            stack.connect(dest)?
        };
        self.inner.notify.notify_one();
        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        loop {
            {
                let stack = lock_stack(&self.inner.stack);
                match stack.state(handle) {
                    Some(smoltcp::socket::tcp::State::Established) => {
                        drop(stack);
                        return Ok(Box::new(WgTcpStream::new(
                            handle,
                            Arc::clone(&self.inner.stack),
                            Arc::clone(&self.inner.notify),
                        )));
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
                lock_stack(&self.inner.stack).abort(handle);
                self.inner.notify.notify_one();
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

    /// Stops the packet reactor. Outstanding streams fail subsequent I/O.
    #[allow(clippy::unused_async)] // matches TUIC/Hysteria2 retire/close shape
    pub async fn close(&self) {
        self.inner.shutdown.cancel();
        self.inner.notify.notify_waiters();
    }

    async fn ensure_handshake(&self) -> Result<(), WireGuardProtocolError> {
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
}

async fn run_reactor(inner: Arc<ClientInner>) {
    let mut buf = vec![0_u8; 65_535];
    let mut timers = tokio::time::interval(Duration::from_millis(100));
    timers.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let delay = lock_stack(&inner.stack)
            .poll_delay()
            .unwrap_or(Duration::from_millis(100));
        tokio::select! {
            () = inner.shutdown.cancelled() => break,
            result = inner.udp.recv_from(&mut buf) => {
                let Ok((n, from)) = result else { break };
                handle_incoming(&inner, Some(from), &buf[..n]).await;
            }
            () = inner.notify.notified() => {
                pump_stack(&inner).await;
            }
            () = tokio::time::sleep(delay) => {
                pump_stack(&inner).await;
            }
            _ = timers.tick() => {
                let action = inner.tunnel.update_timers();
                let _ = dispatch_action(&inner, action).await;
                pump_stack(&inner).await;
            }
        }
    }
}

async fn handle_incoming(inner: &ClientInner, from: Option<SocketAddr>, datagram: &[u8]) {
    let mut packet: &[u8] = datagram;
    loop {
        match inner.tunnel.decapsulate(from, packet) {
            TunnelAction::Done => break,
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
        TunnelAction::SendUdp(datagram) => {
            if is_transport(&datagram) {
                inner.established.store(true, Ordering::Release);
                inner.notify.notify_waiters();
            }
            send_udp(inner, &datagram).await
        }
    }
}

async fn send_udp(inner: &ClientInner, datagram: &[u8]) -> Result<(), WireGuardProtocolError> {
    let endpoint = *inner
        .endpoint
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    inner.udp.send_to(datagram, endpoint).await?;
    Ok(())
}

async fn resolve_ipv4_endpoint(
    server: &str,
    port: u16,
) -> Result<SocketAddr, WireGuardProtocolError> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Ok(SocketAddr::from((v4, port))),
            IpAddr::V6(_) => Err(WireGuardProtocolError::Ipv4Only),
        };
    }
    let mut addresses = tokio::net::lookup_host((server, port)).await?;
    addresses
        .find(SocketAddr::is_ipv4)
        .ok_or(WireGuardProtocolError::Ipv4Only)
}

fn destination_v4(destination: &Destination) -> Result<SocketAddrV4, WireGuardProtocolError> {
    match destination.host {
        Host::Ip(IpAddr::V4(addr)) => Ok(SocketAddrV4::new(addr, destination.port)),
        Host::Ip(IpAddr::V6(_)) => Err(WireGuardProtocolError::Ipv4Only),
        Host::Domain(_) => Err(WireGuardProtocolError::protocol(
            "WireGuard destination must be resolved to IPv4 before dial",
        )),
    }
}
