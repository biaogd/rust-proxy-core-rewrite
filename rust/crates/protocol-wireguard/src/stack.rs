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

pub(crate) struct IpStack {
    iface: Interface,
    device: PacketDevice,
    sockets: SocketSet<'static>,
    wakers: HashMap<SocketHandle, SocketWakers>,
    live: HashMap<SocketHandle, (SocketKind, u16)>,
    releasing: Vec<SocketHandle>,
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
                    (
                        socket.can_recv() || !socket.may_recv(),
                        socket.can_send() || !socket.may_send(),
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
        let mut still = Vec::new();
        for handle in self.releasing.drain(..) {
            let Some((kind, port)) = self.live.get(&handle).copied() else {
                continue;
            };
            let finished = match kind {
                SocketKind::Tcp => {
                    let state = self.sockets.get::<TcpSocket>(handle).state();
                    matches!(state, State::Closed | State::TimeWait | State::Listen)
                }
                SocketKind::Udp => !self.sockets.get::<UdpSocket>(handle).is_open(),
            };
            if finished {
                self.sockets.remove(handle);
                self.wakers.remove(&handle);
                self.live.remove(&handle);
                self.allocated_ports.remove(&port);
            } else {
                still.push(handle);
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

    fn ensure_active(&self) -> io::Result<()> {
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
        if !self.releasing.contains(&handle) {
            self.releasing.push(handle);
        }
    }

    pub(crate) fn close_write(&mut self, handle: SocketHandle) {
        if !matches!(self.kind(handle), Some(SocketKind::Tcp)) {
            return;
        }
        self.sockets.get_mut::<TcpSocket>(handle).close();
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
        self.lock().abort(self.handle);
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.lock().close_write(self.handle);
        self.notify.notify_one();
        Poll::Ready(Ok(()))
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
}
