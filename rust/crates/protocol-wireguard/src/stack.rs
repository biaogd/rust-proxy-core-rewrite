//! smoltcp IPv4/IPv6 TCP+UDP client stack bound to virtual IPs (no OS TUN).

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::poll_fn;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

const TCP_BUFFER: usize = 64 * 1024;
const UDP_PACKET_SLOTS: usize = 32;
const UDP_PAYLOAD: usize = 64 * 1024;
const EPHEMERAL_START: u16 = 49_152;
/// Bound for sockets the application already dropped. Held half-closes are
/// not on this list and are not aborted.
const RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Clone, Copy)]
enum SocketKind {
    Tcp,
    Udp,
}

struct PacketDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl PacketDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }
}

struct DeviceRxToken {
    buffer: Vec<u8>,
}

impl RxToken for DeviceRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct DeviceTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for DeviceTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0_u8; len];
        let result = f(&mut buffer);
        self.tx.push_back(buffer);
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = DeviceRxToken;
    type TxToken<'a> = DeviceTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = self.rx.pop_front()?;
        Some((DeviceRxToken { buffer }, DeviceTxToken { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(DeviceTxToken { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

struct SocketWakers {
    read: Option<Waker>,
    write: Option<Waker>,
}

struct ReleasedSocket {
    handle: SocketHandle,
    abort_at: Option<std::time::Instant>,
}

pub(crate) struct IpStack {
    iface: Interface,
    device: PacketDevice,
    sockets: SocketSet<'static>,
    wakers: HashMap<SocketHandle, SocketWakers>,
    live: HashMap<SocketHandle, (SocketKind, u16)>,
    releasing: Vec<ReleasedSocket>,
    allocated_ports: HashSet<u16>,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
    next_port: u16,
    terminated: bool,
}

impl IpStack {
    pub(crate) fn new(
        local_v4: Option<(Ipv4Addr, u8)>,
        local_v6: Option<(Ipv6Addr, u8)>,
        mtu: usize,
    ) -> Self {
        let mut device = PacketDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, now());
        iface.update_ip_addrs(|addrs| {
            if let Some((addr, prefix)) = local_v4 {
                addrs
                    .push(IpCidr::new(
                        IpAddress::Ipv4(Ipv4Address::from(addr.octets())),
                        prefix,
                    ))
                    .expect("IPv4 CIDR");
            }
            if let Some((addr, prefix)) = local_v6 {
                addrs
                    .push(IpCidr::new(
                        IpAddress::Ipv6(Ipv6Address::from(addr.octets())),
                        prefix,
                    ))
                    .expect("IPv6 CIDR");
            }
        });
        if let Some((addr, _)) = local_v4 {
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::from(addr.octets()))
                .expect("default IPv4 route");
        }
        if let Some((addr, _)) = local_v6 {
            iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::from(addr.octets()))
                .expect("default IPv6 route");
        }
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            wakers: HashMap::new(),
            live: HashMap::new(),
            releasing: Vec::new(),
            allocated_ports: HashSet::new(),
            local_v4: local_v4.map(|(addr, _)| addr),
            local_v6: local_v6.map(|(addr, _)| addr),
            next_port: EPHEMERAL_START,
            terminated: false,
        }
    }

    pub(crate) fn ingest_ip(&mut self, packet: Vec<u8>) {
        self.device.rx.push_back(packet);
    }

    pub(crate) fn take_ip(&mut self) -> Vec<Vec<u8>> {
        self.device.tx.drain(..).collect()
    }

    pub(crate) fn poll(&mut self) {
        let timestamp = now();
        let _ = self
            .iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
        self.wake_ready();
        self.reap();
    }

    pub(crate) fn poll_delay(&mut self) -> Option<std::time::Duration> {
        self.iface.poll_delay(now(), &self.sockets).map(smol_to_std)
    }

    fn wake_ready(&mut self) {
        let handles: Vec<SocketHandle> = self.wakers.keys().copied().collect();
        for handle in handles {
            let Some(kind) = self.kind(handle) else {
                continue;
            };
            let (wake_read, wake_write) = match kind {
                SocketKind::Tcp => {
                    let socket = self.sockets.get::<TcpSocket>(handle);
                    let terminated = matches!(
                        socket.state(),
                        State::Closed | State::TimeWait | State::Listen
                    );
                    (
                        socket.can_recv() || !socket.may_recv() || terminated,
                        socket.can_send() || socket.send_queue() == 0 || terminated,
                    )
                }
                SocketKind::Udp => {
                    let socket = self.sockets.get::<UdpSocket>(handle);
                    (
                        socket.can_recv() || !socket.is_open(),
                        socket.can_send() || !socket.is_open(),
                    )
                }
            };
            let Some(wakers) = self.wakers.get_mut(&handle) else {
                continue;
            };
            if wake_read && let Some(waker) = wakers.read.take() {
                waker.wake();
            }
            if wake_write && let Some(waker) = wakers.write.take() {
                waker.wake();
            }
        }
    }

    fn reap(&mut self) {
        let now = std::time::Instant::now();
        let mut still = Vec::new();
        for item in self.releasing.drain(..) {
            let Some((kind, port)) = self.live.get(&item.handle).copied() else {
                continue;
            };
            let mut finished = match kind {
                SocketKind::Tcp => {
                    let state = self.sockets.get::<TcpSocket>(item.handle).state();
                    matches!(state, State::Closed | State::TimeWait | State::Listen)
                }
                SocketKind::Udp => !self.sockets.get::<UdpSocket>(item.handle).is_open(),
            };
            if !finished
                && matches!(kind, SocketKind::Tcp)
                && item.abort_at.is_some_and(|deadline| now >= deadline)
            {
                self.sockets.get_mut::<TcpSocket>(item.handle).abort();
                finished = true;
            }
            if finished {
                self.sockets.remove(item.handle);
                self.wakers.remove(&item.handle);
                self.live.remove(&item.handle);
                self.allocated_ports.remove(&port);
            } else {
                still.push(item);
            }
        }
        self.releasing = still;
    }

    pub(crate) fn connect(&mut self, dest: SocketAddr) -> Result<SocketHandle, io::Error> {
        self.ensure_active()?;
        let local_ip = self.local_for(dest.ip()).ok_or_else(|| {
            io::Error::new(
                ErrorKind::AddrNotAvailable,
                "WireGuard stack has no address for this family",
            )
        })?;
        let local_port = self.alloc_port()?;
        let rx = SocketBuffer::new(vec![0_u8; TCP_BUFFER]);
        let tx = SocketBuffer::new(vec![0_u8; TCP_BUFFER]);
        let mut socket = TcpSocket::new(rx, tx);
        socket.set_nagle_enabled(false);
        let remote = IpEndpoint::new(to_smol_ip(dest.ip()), dest.port());
        let local = IpEndpoint::new(to_smol_ip(local_ip), local_port);
        if let Err(error) = socket.connect(self.iface.context(), remote, local) {
            self.allocated_ports.remove(&local_port);
            return Err(io::Error::other(format!("smoltcp connect: {error}")));
        }
        let handle = self.sockets.add(socket);
        self.live.insert(handle, (SocketKind::Tcp, local_port));
        Ok(handle)
    }

    pub(crate) fn bind_udp(&mut self) -> Result<SocketHandle, io::Error> {
        self.ensure_active()?;
        let local_port = self.alloc_port()?;
        let rx = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_PACKET_SLOTS],
            vec![0_u8; UDP_PAYLOAD],
        );
        let tx = UdpPacketBuffer::new(
            vec![UdpPacketMetadata::EMPTY; UDP_PACKET_SLOTS],
            vec![0_u8; UDP_PAYLOAD],
        );
        let mut socket = UdpSocket::new(rx, tx);
        if let Err(error) = socket.bind(IpListenEndpoint {
            addr: None,
            port: local_port,
        }) {
            self.allocated_ports.remove(&local_port);
            return Err(io::Error::other(format!("smoltcp udp bind: {error}")));
        }
        let handle = self.sockets.add(socket);
        self.live.insert(handle, (SocketKind::Udp, local_port));
        Ok(handle)
    }

    fn alloc_port(&mut self) -> Result<u16, io::Error> {
        let start = self.next_port;
        loop {
            let port = self.next_port;
            self.next_port = if self.next_port == u16::MAX {
                EPHEMERAL_START
            } else {
                self.next_port.saturating_add(1)
            };
            if self.allocated_ports.insert(port) {
                return Ok(port);
            }
            if self.next_port == start {
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    "WireGuard ephemeral ports exhausted",
                ));
            }
        }
    }

    fn local_for(&self, dest: IpAddr) -> Option<IpAddr> {
        match dest {
            IpAddr::V4(_) => self.local_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.local_v6.map(IpAddr::V6),
        }
    }

    fn kind(&self, handle: SocketHandle) -> Option<SocketKind> {
        self.live.get(&handle).map(|(kind, _)| *kind)
    }

    pub(crate) fn ensure_active(&self) -> io::Result<()> {
        if self.terminated {
            Err(retired())
        } else {
            Ok(())
        }
    }

    pub(crate) fn live_socket_count(&self) -> usize {
        self.live.len()
    }

    pub(crate) fn shutdown_all(&mut self) {
        self.terminated = true;
        let handles: Vec<SocketHandle> = self.live.keys().copied().collect();
        for handle in handles {
            self.abort(handle);
        }
        for wakers in self.wakers.values_mut() {
            if let Some(waker) = wakers.read.take() {
                waker.wake();
            }
            if let Some(waker) = wakers.write.take() {
                waker.wake();
            }
        }
    }

    pub(crate) fn abort(&mut self, handle: SocketHandle) {
        let Some(kind) = self.kind(handle) else {
            return;
        };
        match kind {
            SocketKind::Tcp => self.sockets.get_mut::<TcpSocket>(handle).abort(),
            SocketKind::Udp => self.sockets.get_mut::<UdpSocket>(handle).close(),
        }
        if let Some(wakers) = self.wakers.get_mut(&handle) {
            if let Some(waker) = wakers.read.take() {
                waker.wake();
            }
            if let Some(waker) = wakers.write.take() {
                waker.wake();
            }
        }
        self.enqueue_release(handle, None);
    }

    pub(crate) fn close_write(&mut self, handle: SocketHandle) {
        if !matches!(self.kind(handle), Some(SocketKind::Tcp)) {
            return;
        }
        self.sockets.get_mut::<TcpSocket>(handle).close();
    }

    /// Enqueues a socket for reap without sending RST. Used after a graceful
    /// TCP close so FIN / `TimeWait` can finish on the reactor.
    pub(crate) fn release(&mut self, handle: SocketHandle) {
        if self.kind(handle).is_none() {
            return;
        }
        if let Some(wakers) = self.wakers.get_mut(&handle) {
            if let Some(waker) = wakers.read.take() {
                waker.wake();
            }
            if let Some(waker) = wakers.write.take() {
                waker.wake();
            }
        }
        self.enqueue_release(handle, Some(std::time::Instant::now() + RELEASE_TIMEOUT));
    }

    fn enqueue_release(&mut self, handle: SocketHandle, abort_at: Option<std::time::Instant>) {
        if self.releasing.iter().any(|item| item.handle == handle) {
            return;
        }
        self.releasing.push(ReleasedSocket { handle, abort_at });
    }

    pub(crate) fn tcp_send_queue(&self, handle: SocketHandle) -> usize {
        matches!(self.kind(handle), Some(SocketKind::Tcp))
            .then(|| self.sockets.get::<TcpSocket>(handle).send_queue())
            .unwrap_or(0)
    }

    /// `Ok(true)` when the write side is drained. `Ok(false)` when more ACKs
    /// are needed. `Err` when the socket is reset with unacked data still queued.
    pub(crate) fn tcp_write_progress(&self, handle: SocketHandle) -> io::Result<bool> {
        self.ensure_active()?;
        if !matches!(self.kind(handle), Some(SocketKind::Tcp)) {
            return Err(io::Error::new(ErrorKind::NotConnected, "tcp socket gone"));
        }
        let socket = self.sockets.get::<TcpSocket>(handle);
        let queue = self.tcp_send_queue(handle);
        match socket.state() {
            State::Closed | State::Listen => {
                if queue == 0 {
                    Ok(true)
                } else {
                    Err(io::Error::new(
                        ErrorKind::ConnectionReset,
                        "tcp reset with unacked data",
                    ))
                }
            }
            State::TimeWait => Ok(true),
            _ => Ok(queue == 0),
        }
    }

    pub(crate) fn state(&self, handle: SocketHandle) -> Option<State> {
        matches!(self.kind(handle), Some(SocketKind::Tcp))
            .then(|| self.sockets.get::<TcpSocket>(handle).state())
    }

    pub(crate) fn recv(
        &mut self,
        handle: SocketHandle,
        buf: &mut [u8],
    ) -> Result<usize, io::Error> {
        self.ensure_active()?;
        if !matches!(self.kind(handle), Some(SocketKind::Tcp)) {
            return Ok(0);
        }
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        if !socket.may_recv() && socket.recv_queue() == 0 {
            return Ok(0);
        }
        match socket.recv_slice(buf) {
            Ok(n) => Ok(n),
            Err(smoltcp::socket::tcp::RecvError::Finished) => Ok(0),
            Err(smoltcp::socket::tcp::RecvError::InvalidState) => Err(io::Error::new(
                ErrorKind::NotConnected,
                "tcp recv invalid state",
            )),
        }
    }

    pub(crate) fn send(&mut self, handle: SocketHandle, buf: &[u8]) -> Result<usize, io::Error> {
        self.ensure_active()?;
        if !matches!(self.kind(handle), Some(SocketKind::Tcp)) {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "tcp send closed"));
        }
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        if !socket.may_send() {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "tcp send closed"));
        }
        if !socket.can_send() {
            return Err(io::Error::new(ErrorKind::WouldBlock, "tcp send window"));
        }
        socket
            .send_slice(buf)
            .map_err(|error| io::Error::other(format!("tcp send: {error}")))
    }

    pub(crate) fn send_udp(
        &mut self,
        handle: SocketHandle,
        dest: SocketAddr,
        payload: &[u8],
    ) -> Result<(), io::Error> {
        self.ensure_active()?;
        if !matches!(self.kind(handle), Some(SocketKind::Udp)) {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "udp send closed"));
        }
        if self.local_for(dest.ip()).is_none() {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "WireGuard stack has no address for this family",
            ));
        }
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        if !socket.is_open() {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "udp send closed"));
        }
        if !socket.can_send() {
            return Err(io::Error::new(ErrorKind::WouldBlock, "udp send buffer"));
        }
        let endpoint = IpEndpoint::new(to_smol_ip(dest.ip()), dest.port());
        socket
            .send_slice(payload, endpoint)
            .map_err(|error| io::Error::other(format!("udp send: {error}")))
    }

    pub(crate) fn recv_udp(
        &mut self,
        handle: SocketHandle,
    ) -> Result<(SocketAddr, Vec<u8>), io::Error> {
        self.ensure_active()?;
        if !matches!(self.kind(handle), Some(SocketKind::Udp)) {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "udp recv closed"));
        }
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        if !socket.is_open() {
            return Err(io::Error::new(ErrorKind::BrokenPipe, "udp recv closed"));
        }
        if !socket.can_recv() {
            return Err(io::Error::new(ErrorKind::WouldBlock, "udp recv empty"));
        }
        let mut buf = vec![0_u8; UDP_PAYLOAD];
        match socket.recv_slice(&mut buf) {
            Ok((n, meta)) => {
                buf.truncate(n);
                Ok((from_smol_endpoint(meta.endpoint), buf))
            }
            Err(smoltcp::socket::udp::RecvError::Exhausted) => {
                Err(io::Error::new(ErrorKind::WouldBlock, "udp recv empty"))
            }
            Err(smoltcp::socket::udp::RecvError::Truncated) => {
                Err(io::Error::other("udp truncated"))
            }
        }
    }

    pub(crate) fn register_read(&mut self, handle: SocketHandle, waker: Waker) {
        self.wakers
            .entry(handle)
            .or_insert(SocketWakers {
                read: None,
                write: None,
            })
            .read = Some(waker);
    }

    pub(crate) fn register_write(&mut self, handle: SocketHandle, waker: Waker) {
        self.wakers
            .entry(handle)
            .or_insert(SocketWakers {
                read: None,
                write: None,
            })
            .write = Some(waker);
    }
}

fn to_smol_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(addr) => IpAddress::Ipv4(Ipv4Address::from(addr.octets())),
        IpAddr::V6(addr) => IpAddress::Ipv6(Ipv6Address::from(addr.octets())),
    }
}

fn from_smol_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let port = endpoint.port;
    match endpoint.addr {
        IpAddress::Ipv4(addr) => SocketAddr::from((Ipv4Addr::from(addr.octets()), port)),
        IpAddress::Ipv6(addr) => SocketAddr::from((Ipv6Addr::from(addr.octets()), port)),
    }
}

fn now() -> Instant {
    Instant::from_micros(
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros(),
        )
        .unwrap_or(0),
    )
}

fn smol_to_std(duration: SmolDuration) -> std::time::Duration {
    std::time::Duration::from_micros(duration.micros())
}

/// TCP stream through the `WireGuard` userspace stack.
pub struct WgTcpStream {
    handle: SocketHandle,
    stack: Arc<Mutex<IpStack>>,
    notify: Arc<Notify>,
    /// Set by `poll_shutdown`: Drop must not RST, so queued data and FIN can finish.
    closing: bool,
}

impl WgTcpStream {
    pub(crate) fn new(
        handle: SocketHandle,
        stack: Arc<Mutex<IpStack>>,
        notify: Arc<Notify>,
    ) -> Self {
        Self {
            handle,
            stack,
            notify,
            closing: false,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, IpStack> {
        self.stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        let mut stack = self.lock();
        if self.closing {
            stack.close_write(self.handle);
            stack.release(self.handle);
        } else {
            stack.abort(self.handle);
        }
        drop(stack);
        self.notify.notify_one();
    }
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut stack = self.lock();
        let unfilled = buf.initialize_unfilled();
        match stack.recv(self.handle, unfilled) {
            Ok(0) => {
                if stack.state(self.handle).is_some_and(|state| {
                    matches!(state, State::CloseWait | State::Closed | State::TimeWait)
                }) {
                    Poll::Ready(Ok(()))
                } else {
                    stack.register_read(self.handle, cx.waker().clone());
                    drop(stack);
                    self.notify.notify_one();
                    Poll::Pending
                }
            }
            Ok(n) => {
                buf.advance(n);
                drop(stack);
                self.notify.notify_one();
                Poll::Ready(Ok(()))
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                stack.register_read(self.handle, cx.waker().clone());
                drop(stack);
                self.notify.notify_one();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut stack = self.lock();
        match stack.send(self.handle, buf) {
            Ok(n) => {
                drop(stack);
                self.notify.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                stack.register_write(self.handle, cx.waker().clone());
                drop(stack);
                self.notify.notify_one();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        let mut stack = this.lock();
        match stack.tcp_write_progress(this.handle) {
            Ok(true) => {
                drop(stack);
                this.notify.notify_one();
                Poll::Ready(Ok(()))
            }
            Ok(false) => {
                stack.register_write(this.handle, cx.waker().clone());
                drop(stack);
                this.notify.notify_one();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        this.closing = true;
        let mut stack = this.lock();
        stack.close_write(this.handle);
        match stack.tcp_write_progress(this.handle) {
            Ok(true) => {
                drop(stack);
                this.notify.notify_one();
                Poll::Ready(Ok(()))
            }
            Ok(false) => {
                stack.register_write(this.handle, cx.waker().clone());
                drop(stack);
                this.notify.notify_one();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

/// Connectionless UDP socket through the `WireGuard` userspace stack.
pub struct WgUdpSocket {
    handle: SocketHandle,
    stack: Arc<Mutex<IpStack>>,
    notify: Arc<Notify>,
}

impl WgUdpSocket {
    pub(crate) fn new(
        handle: SocketHandle,
        stack: Arc<Mutex<IpStack>>,
        notify: Arc<Notify>,
    ) -> Self {
        Self {
            handle,
            stack,
            notify,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, IpStack> {
        self.stack
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Sends one datagram to `dest`.
    ///
    /// # Errors
    ///
    /// Returns when the socket is closed or the address family has no inner IP.
    pub async fn send(&self, dest: SocketAddr, payload: &[u8]) -> io::Result<()> {
        poll_fn(|cx| {
            let mut stack = self.lock();
            match stack.send_udp(self.handle, dest, payload) {
                Ok(()) => {
                    drop(stack);
                    self.notify.notify_one();
                    Poll::Ready(Ok(()))
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    stack.register_write(self.handle, cx.waker().clone());
                    drop(stack);
                    self.notify.notify_one();
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await
    }

    /// Receives one datagram and its source.
    ///
    /// # Errors
    ///
    /// Returns when the socket is closed.
    pub async fn recv(&self) -> io::Result<(SocketAddr, Vec<u8>)> {
        poll_fn(|cx| {
            let mut stack = self.lock();
            match stack.recv_udp(self.handle) {
                Ok((from, payload)) => {
                    drop(stack);
                    self.notify.notify_one();
                    Poll::Ready(Ok((from, payload)))
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    stack.register_read(self.handle, cx.waker().clone());
                    drop(stack);
                    self.notify.notify_one();
                    Poll::Pending
                }
                Err(error) => Poll::Ready(Err(error)),
            }
        })
        .await
    }
}

impl Drop for WgUdpSocket {
    fn drop(&mut self) {
        self.lock().abort(self.handle);
        self.notify.notify_one();
    }
}

pub(crate) fn lock_stack(stack: &Arc<Mutex<IpStack>>) -> std::sync::MutexGuard<'_, IpStack> {
    stack
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn retired() -> io::Error {
    io::Error::new(ErrorKind::BrokenPipe, "WireGuard client retired")
}

#[cfg(test)]
mod port_tests {
    use super::*;
    use smoltcp::wire::{
        IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };

    fn stack() -> IpStack {
        IpStack::new(Some((Ipv4Addr::new(10, 0, 0, 2), 32)), None, 1408)
    }

    #[test]
    fn alloc_port_skips_occupied_and_wraps() {
        let mut first = stack();
        first.allocated_ports.insert(EPHEMERAL_START);
        let port = first.alloc_port().expect("next port");
        assert_eq!(port, EPHEMERAL_START + 1);
        let mut wrapping = stack();
        wrapping.next_port = u16::MAX;
        wrapping.allocated_ports.insert(u16::MAX);
        let wrapped = wrapping.alloc_port().expect("wrap");
        assert_eq!(wrapped, EPHEMERAL_START);
    }

    #[test]
    fn alloc_port_errors_when_ephemeral_range_is_full() {
        let mut stack = stack();
        for port in EPHEMERAL_START..=u16::MAX {
            stack.allocated_ports.insert(port);
        }
        let error = stack.alloc_port().expect_err("exhausted");
        assert_eq!(error.kind(), ErrorKind::AddrInUse);
    }

    #[test]
    fn shutdown_all_marks_stack_retired() {
        let mut stack = stack();
        let handle = stack.bind_udp().expect("udp");
        assert_eq!(stack.live_socket_count(), 1);
        stack.shutdown_all();
        assert!(stack.recv_udp(handle).is_err());
        stack.poll();
        assert_eq!(stack.live_socket_count(), 0);
    }

    fn parse_ipv4_tcp(packet: &[u8]) -> (Ipv4Repr, TcpRepr<'_>) {
        let caps = smoltcp::phy::ChecksumCapabilities::ignored();
        let ipv4 = Ipv4Packet::new_checked(packet).expect("ipv4");
        let ipv4_repr = Ipv4Repr::parse(&ipv4, &caps).expect("ipv4 repr");
        let tcp = TcpPacket::new_checked(ipv4.payload()).expect("tcp");
        let tcp_repr = TcpRepr::parse(
            &tcp,
            &IpAddress::Ipv4(ipv4_repr.src_addr),
            &IpAddress::Ipv4(ipv4_repr.dst_addr),
            &caps,
        )
        .expect("tcp repr");
        (ipv4_repr, tcp_repr)
    }

    fn emit_ipv4_tcp(src: Ipv4Address, dst: Ipv4Address, tcp: TcpRepr<'_>) -> Vec<u8> {
        let caps = smoltcp::phy::ChecksumCapabilities::default();
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.header_len() + tcp.payload.len(),
            hop_limit: 64,
        };
        let mut out = vec![0_u8; ip.buffer_len() + ip.payload_len];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut out);
        ip.emit(&mut ip_pkt, &caps);
        tcp.emit(
            &mut TcpPacket::new_unchecked(ip_pkt.payload_mut()),
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            &caps,
        );
        out
    }

    fn empty_tcp(
        src_port: u16,
        dst_port: u16,
        control: TcpControl,
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
    ) -> TcpRepr<'static> {
        TcpRepr {
            src_port,
            dst_port,
            control,
            seq_number: seq,
            ack_number: ack,
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        }
    }

    #[test]
    fn flush_errors_when_rst_leaves_unacked_data() {
        let mut stack = stack();
        let dest = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 80));
        let handle = stack.connect(dest).expect("connect");
        stack.poll();
        let syn = stack.take_ip().pop().expect("syn");
        let (ip, tcp) = parse_ipv4_tcp(&syn);
        assert_eq!(tcp.control, TcpControl::Syn);
        let syn_ack = emit_ipv4_tcp(
            ip.dst_addr,
            ip.src_addr,
            empty_tcp(
                tcp.dst_port,
                tcp.src_port,
                TcpControl::Syn,
                TcpSeqNumber(1),
                Some(tcp.seq_number + 1),
            ),
        );
        stack.ingest_ip(syn_ack);
        stack.poll();
        assert_eq!(stack.state(handle), Some(State::Established));
        let wrote = stack.send(handle, &[0x5a; 64]).expect("send");
        assert_eq!(wrote, 64);
        assert!(stack.tcp_send_queue(handle) > 0);
        let rst = emit_ipv4_tcp(
            ip.dst_addr,
            ip.src_addr,
            empty_tcp(
                tcp.dst_port,
                tcp.src_port,
                TcpControl::Rst,
                TcpSeqNumber(2),
                Some(tcp.seq_number + 1),
            ),
        );
        stack.ingest_ip(rst);
        stack.poll();
        assert_eq!(stack.state(handle), Some(State::Closed));
        assert!(stack.tcp_send_queue(handle) > 0);
        let error = stack.tcp_write_progress(handle).expect_err("rst");
        assert_eq!(error.kind(), ErrorKind::ConnectionReset);
    }

    #[test]
    fn released_socket_is_reaped_after_timeout() {
        let mut stack = stack();
        let dest = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 80));
        let handle = stack.connect(dest).expect("connect");
        stack.release(handle);
        assert_eq!(stack.live_socket_count(), 1);
        std::thread::sleep(RELEASE_TIMEOUT + std::time::Duration::from_millis(20));
        stack.poll();
        assert_eq!(stack.live_socket_count(), 0);
    }

    #[test]
    fn held_socket_is_not_reaped_after_release_timeout() {
        let mut stack = stack();
        let dest = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 80));
        let _handle = stack.connect(dest).expect("connect");
        std::thread::sleep(RELEASE_TIMEOUT + std::time::Duration::from_millis(20));
        stack.poll();
        assert_eq!(stack.live_socket_count(), 1);
    }
}
