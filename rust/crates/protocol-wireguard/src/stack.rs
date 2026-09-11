//! smoltcp IPv4 TCP client stack bound to a virtual IP (no OS TUN).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State};
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

const TCP_BUFFER: usize = 64 * 1024;
const EPHEMERAL_START: u16 = 49_152;

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
    live: HashSet<SocketHandle>,
    releasing: Vec<SocketHandle>,
    local: Ipv4Addr,
    next_port: u16,
}

impl IpStack {
    pub(crate) fn new(local: Ipv4Addr, prefix_len: u8, mtu: usize) -> Self {
        let mut device = PacketDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device, now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv4(Ipv4Address::from(local.octets())),
                    prefix_len,
                ))
                .expect("one IPv4 CIDR");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from(local.octets()))
            .expect("default route");
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            wakers: HashMap::new(),
            live: HashSet::new(),
            releasing: Vec::new(),
            local,
            next_port: EPHEMERAL_START,
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
            if !self.live.contains(&handle) {
                continue;
            }
            let socket = self.sockets.get::<TcpSocket>(handle);
            let wake_read = socket.can_recv() || !socket.may_recv();
            let wake_write = socket.can_send() || !socket.may_send();
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
            if !self.live.contains(&handle) {
                continue;
            }
            let state = self.sockets.get::<TcpSocket>(handle).state();
            if matches!(state, State::Closed | State::TimeWait | State::Listen) {
                self.sockets.remove(handle);
                self.wakers.remove(&handle);
                self.live.remove(&handle);
            } else {
                still.push(handle);
            }
        }
        self.releasing = still;
    }

    pub(crate) fn connect(&mut self, dest: SocketAddrV4) -> Result<SocketHandle, io::Error> {
        let local_port = self.alloc_port();
        let rx = SocketBuffer::new(vec![0_u8; TCP_BUFFER]);
        let tx = SocketBuffer::new(vec![0_u8; TCP_BUFFER]);
        let mut socket = TcpSocket::new(rx, tx);
        socket.set_nagle_enabled(false);
        let remote = IpEndpoint::new(
            IpAddress::Ipv4(Ipv4Address::from(dest.ip().octets())),
            dest.port(),
        );
        let local = IpEndpoint::new(
            IpAddress::Ipv4(Ipv4Address::from(self.local.octets())),
            local_port,
        );
        socket
            .connect(self.iface.context(), remote, local)
            .map_err(|error| io::Error::other(format!("smoltcp connect: {error}")))?;
        let handle = self.sockets.add(socket);
        self.live.insert(handle);
        Ok(handle)
    }

    fn alloc_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if self.next_port == u16::MAX {
            EPHEMERAL_START
        } else {
            self.next_port.saturating_add(1)
        };
        port
    }

    pub(crate) fn abort(&mut self, handle: SocketHandle) {
        if !self.live.contains(&handle) {
            return;
        }
        self.sockets.get_mut::<TcpSocket>(handle).abort();
        if !self.releasing.contains(&handle) {
            self.releasing.push(handle);
        }
    }

    pub(crate) fn close_write(&mut self, handle: SocketHandle) {
        if !self.live.contains(&handle) {
            return;
        }
        self.sockets.get_mut::<TcpSocket>(handle).close();
    }

    pub(crate) fn state(&self, handle: SocketHandle) -> Option<State> {
        self.live
            .contains(&handle)
            .then(|| self.sockets.get::<TcpSocket>(handle).state())
    }

    pub(crate) fn recv(
        &mut self,
        handle: SocketHandle,
        buf: &mut [u8],
    ) -> Result<usize, io::Error> {
        if !self.live.contains(&handle) {
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
        if !self.live.contains(&handle) {
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

pub(crate) fn lock_stack(stack: &Arc<Mutex<IpStack>>) -> std::sync::MutexGuard<'_, IpStack> {
    stack
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
