//! UDP relay over QUIC unreliable datagrams (Go: core/client/udp.go +
//! `UDPMessage` / `FragUDPMessage` / `Defragger` in the protocol package).
//!
//! A single background task reads datagrams off the QUIC connection, parses
//! them into [`UdpMessage`]s and dispatches them to the owning session by
//! Session ID. Each [`UdpSession`] reassembles fragments locally and sends with
//! automatic fragmentation when a payload exceeds the current datagram limit.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use rand::Rng;
use tokio::sync::mpsc;

use crate::varint::read_from;
use crate::Hysteria2ProtocolError;

/// Largest reassembled UDP payload buffer (Go `MaxUDPSize`).
pub(crate) const MAX_UDP_SIZE: usize = 4096;
/// Largest QUIC datagram frame Hysteria2 advertises (Go `MaxDatagramFrameSize`).
pub(crate) const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
/// DoS guard on address string length (Go `MaxMessageLength`).
pub(crate) const MAX_MESSAGE_LENGTH: u64 = 2048;
/// Per-session inbound queue depth (Go `udpMessageChanSize`).
const SESSION_CHAN_SIZE: usize = 1024;
/// Soft cap on concurrent UDP sessions per QUIC connection.
const MAX_SESSIONS: usize = 256;
/// Drop incomplete reassembly state after this age.
const DEFRAG_TTL: Duration = Duration::from_secs(10);
/// Bound buffered fragment bytes held by a single [`Defragger`].
const MAX_DEFRAG_BYTES: usize = 4 * 1024 * 1024;

/// A UDP datagram encapsulated for relay over QUIC's unreliable datagram channel.
///
/// Wire format (big-endian, Go `UDPMessage`):
/// `SessionID(u32) | PacketID(u16) | FragID(u8) | FragCount(u8) |
///  varint(addr_len) | addr | data`
#[derive(Clone, Debug)]
pub(crate) struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    /// Size of everything before the payload.
    pub fn header_size(&self) -> usize {
        4 + 2 + 1 + 1 + varint_len(self.addr.len() as u64) + self.addr.len()
    }

    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// Serialize into `buf`, returning the number of bytes written, or `None`
    /// if `buf` is too small (Go returns -1).
    pub fn serialize(&self, buf: &mut [u8]) -> Option<usize> {
        let total = self.size();
        if buf.len() < total {
            return None;
        }
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.packet_id.to_be_bytes());
        buf[6] = self.frag_id;
        buf[7] = self.frag_count;
        let mut i = 8;
        i += put_varint(&mut buf[i..], self.addr.len() as u64);
        buf[i..i + self.addr.len()].copy_from_slice(self.addr.as_bytes());
        i += self.addr.len();
        buf[i..i + self.data.len()].copy_from_slice(&self.data);
        i += self.data.len();
        Some(i)
    }

    /// Parse a UDPMessage from a complete datagram (Go `ParseUDPMessage`).
    pub fn parse(msg: &[u8]) -> Option<Self> {
        if msg.len() < 8 {
            return None;
        }
        let session_id = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let packet_id = u16::from_be_bytes([msg[4], msg[5]]);
        let frag_id = msg[6];
        let frag_count = msg[7];
        let (addr_len, n) = read_from(&msg[8..])?;
        // Go: `lAddr == 0 || lAddr > MaxMessageLength` is invalid.
        if addr_len == 0 || addr_len > MAX_MESSAGE_LENGTH {
            return None;
        }
        let addr_start = 8 + n;
        let addr_end = addr_start + addr_len as usize;
        // Go expects at least one byte of data after the address (uses `<=`).
        if msg.len() <= addr_end {
            return None;
        }
        let addr = String::from_utf8(msg[addr_start..addr_end].to_vec()).ok()?;
        let data = msg[addr_end..].to_vec();
        Some(Self {
            session_id,
            packet_id,
            frag_id,
            frag_count,
            addr,
            data,
        })
    }
}

/// Byte length of a QUIC varint encoding `v`.
fn varint_len(v: u64) -> usize {
    if v <= 63 {
        1
    } else if v <= 16_383 {
        2
    } else if v <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// Write a varint into the front of `buf`; returns bytes written.
fn put_varint(buf: &mut [u8], v: u64) -> usize {
    if v <= 63 {
        buf[0] = v as u8;
        1
    } else if v <= 16_383 {
        buf[0] = (v >> 8) as u8 | 0x40;
        buf[1] = v as u8;
        2
    } else if v <= 1_073_741_823 {
        buf[0] = (v >> 24) as u8 | 0x80;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else {
        buf[0] = (v >> 56) as u8 | 0xc0;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    }
}

/// Split a UDP message into fragments no larger than `max_size` bytes on the
/// wire (Go `FragUDPMessage`). Returns the fragments in order, or an empty
/// vec if even a single header doesn't fit.
pub(crate) fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }
    let max_payload = max_size.saturating_sub(m.header_size());
    if max_payload == 0 {
        return Vec::new();
    }
    let frag_count = m.data.len().div_ceil(max_payload);
    let mut frags = Vec::with_capacity(frag_count);
    let mut off = 0;
    let mut frag_id = 0u8;
    while off < m.data.len() {
        let end = (off + max_payload).min(m.data.len());
        frags.push(UdpMessage {
            session_id: m.session_id,
            packet_id: m.packet_id,
            frag_id,
            frag_count: frag_count as u8,
            addr: m.addr.clone(),
            data: m.data[off..end].to_vec(),
        });
        off = end;
        frag_id = frag_id.wrapping_add(1);
    }
    frags
}

/// Reassembles fragmented UDP messages. Tracks one packet ID at a time; a new
/// packet ID (or TTL expiry) discards prior state. Buffered fragment bytes are
/// capped by [`MAX_DEFRAG_BYTES`].
#[derive(Default)]
pub(crate) struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: u8,
    size: usize,
    started: Option<Instant>,
}

impl Defragger {
    fn clear(&mut self) {
        self.pkt_id = 0;
        self.frags.clear();
        self.count = 0;
        self.size = 0;
        self.started = None;
    }

    fn drop_if_expired(&mut self, now: Instant) {
        if let Some(started) = self.started {
            if now.saturating_duration_since(started) >= DEFRAG_TTL {
                self.clear();
            }
        }
    }

    /// Feed a (possibly fragmented) message. Returns the fully reassembled
    /// message once all fragments have arrived, otherwise `None`.
    pub fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        let now = Instant::now();
        self.drop_if_expired(now);

        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            return None;
        }

        if m.packet_id != self.pkt_id || m.frag_count as usize != self.frags.len() {
            // New message — reset state.
            if m.data.len() > MAX_DEFRAG_BYTES {
                self.clear();
                return None;
            }
            self.pkt_id = m.packet_id;
            self.frags = vec![None; m.frag_count as usize];
            self.size = m.data.len();
            self.count = 1;
            self.started = Some(now);
            let frag_id = m.frag_id as usize;
            self.frags[frag_id] = Some(m);
            None
        } else if self.frags[m.frag_id as usize].is_none() {
            if self.size.saturating_add(m.data.len()) > MAX_DEFRAG_BYTES {
                self.clear();
                return None;
            }
            self.size += m.data.len();
            self.count += 1;
            let frag_id = m.frag_id as usize;
            self.frags[frag_id] = Some(m);
            if self.count as usize == self.frags.len() {
                // All fragments present — assemble in order.
                let mut data = Vec::with_capacity(self.size);
                let mut first: Option<UdpMessage> = None;
                for slot in self.frags.iter_mut() {
                    if let Some(frag) = slot.take() {
                        data.extend_from_slice(&frag.data);
                        if first.is_none() {
                            first = Some(frag);
                        }
                    }
                }
                self.clear();
                let mut out = first?;
                out.data = data;
                out.frag_id = 0;
                out.frag_count = 1;
                Some(out)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Routes inbound UDP datagrams to per-session channels.
pub struct UdpSessionManager {
    conn: quinn::Connection,
    sessions: Mutex<HashMap<u32, mpsc::Sender<UdpMessage>>>,
    next_id: AtomicU32,
}

impl UdpSessionManager {
    /// Spawn the receive loop and return the manager.
    pub(crate) fn new(conn: quinn::Connection) -> Arc<Self> {
        let mgr = Arc::new(Self {
            conn: conn.clone(),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        });
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(receive_loop(conn, weak));
        mgr
    }

    /// Open a new UDP session with a fresh Session ID.
    ///
    /// # Errors
    ///
    /// Returns when the concurrent session count would exceed [`MAX_SESSIONS`].
    pub fn new_session(self: &Arc<Self>) -> Result<UdpSession, Hysteria2ProtocolError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(SESSION_CHAN_SIZE);
        {
            let mut sessions = self.sessions.lock().unwrap();
            if sessions.len() >= MAX_SESSIONS {
                return Err(Hysteria2ProtocolError::Protocol(
                    "udp session limit exceeded".to_owned(),
                ));
            }
            sessions.insert(id, tx);
        }
        Ok(UdpSession {
            id,
            conn: self.conn.clone(),
            rx,
            defrag: Defragger::default(),
            mgr: Arc::downgrade(self),
        })
    }

    fn dispatch(&self, msg: UdpMessage) {
        let sessions = self.sessions.lock().unwrap();
        if let Some(tx) = sessions.get(&msg.session_id) {
            // Non-blocking: drop the datagram if the session queue is full or
            // its receiver is gone (Go's `default:` case in udp.go).
            let _ = tx.try_send(msg);
        }
        // Unknown session — ignore (Go does the same).
    }

    fn remove(&self, id: u32) {
        self.sessions.lock().unwrap().remove(&id);
    }
}

async fn receive_loop(conn: quinn::Connection, mgr: Weak<UdpSessionManager>) {
    loop {
        match conn.read_datagram().await {
            Ok(data) => {
                if let Some(msg) = UdpMessage::parse(&data) {
                    match mgr.upgrade() {
                        Some(m) => m.dispatch(msg),
                        None => return, // manager dropped
                    }
                }
                // Invalid datagram — skip, like Go.
            }
            Err(_) => return, // connection closed; senders drop, sessions see EOF
        }
    }
}

/// A UDP relay session. Send and receive datagrams to/from arbitrary
/// destination addresses through the proxy.
pub struct UdpSession {
    id: u32,
    conn: quinn::Connection,
    rx: mpsc::Receiver<UdpMessage>,
    defrag: Defragger,
    mgr: Weak<UdpSessionManager>,
}

impl UdpSession {
    /// The Session ID assigned by the client.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Send `data` to `addr` (`host:port`) through the proxy, fragmenting if the
    /// payload exceeds the current QUIC datagram limit.
    ///
    /// # Errors
    ///
    /// Returns when the QUIC datagram send fails (other than `TooLarge`, which
    /// triggers fragmentation).
    pub fn send(&self, data: &[u8], addr: &str) -> Result<(), Hysteria2ProtocolError> {
        let msg = UdpMessage {
            session_id: self.id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_owned(),
            data: data.to_vec(),
        };

        // Fast path: try to send unfragmented.
        let mut buf = vec![0u8; msg.size().max(MAX_UDP_SIZE)];
        if let Some(n) = msg.serialize(&mut buf) {
            match self.conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                Ok(()) => return Ok(()),
                Err(quinn::SendDatagramError::TooLarge) => { /* fall through to fragment */ }
                Err(e) => {
                    return Err(Hysteria2ProtocolError::Protocol(format!(
                        "send datagram: {e}"
                    )));
                }
            }
        }

        // Fragment to the current datagram limit and send each piece.
        let max = self
            .conn
            .max_datagram_size()
            .unwrap_or(MAX_DATAGRAM_FRAME_SIZE);
        let mut frag = msg;
        frag.packet_id = rand::rng().random_range(1..=u16::MAX);
        for f in frag_udp_message(&frag, max) {
            let mut fbuf = vec![0u8; f.size()];
            if let Some(n) = f.serialize(&mut fbuf) {
                self.conn
                    .send_datagram(Bytes::copy_from_slice(&fbuf[..n]))
                    .map_err(|e| {
                        Hysteria2ProtocolError::Protocol(format!("send fragment: {e}"))
                    })?;
            }
        }
        Ok(())
    }

    /// Receive the next datagram, returning `(payload, source_addr)`.
    ///
    /// # Errors
    ///
    /// Returns once the session or connection is closed.
    pub async fn recv(&mut self) -> Result<(Vec<u8>, String), Hysteria2ProtocolError> {
        loop {
            let msg = self.rx.recv().await.ok_or_else(|| {
                Hysteria2ProtocolError::Protocol("udp session closed".to_owned())
            })?;
            if let Some(full) = self.defrag.feed(msg) {
                return Ok((full.data, full.addr));
            }
            // Incomplete fragmented packet — wait for more.
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        if let Some(mgr) = self.mgr.upgrade() {
            mgr.remove(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(data: &[u8], frag_id: u8, frag_count: u8, packet_id: u16) -> UdpMessage {
        UdpMessage {
            session_id: 0xDEAD_BEEF,
            packet_id,
            frag_id,
            frag_count,
            addr: "example.com:53".into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn udp_message_roundtrip() {
        let m = msg(b"hello world", 0, 1, 0);
        let mut buf = vec![0u8; m.size()];
        let n = m.serialize(&mut buf).unwrap();
        assert_eq!(n, m.size());
        let parsed = UdpMessage::parse(&buf[..n]).unwrap();
        assert_eq!(parsed.session_id, m.session_id);
        assert_eq!(parsed.addr, m.addr);
        assert_eq!(parsed.data, m.data);
    }

    #[test]
    fn udp_message_rejects_truncated_and_empty_data() {
        // No payload after the address is invalid (Go uses `<=`).
        let m = msg(b"", 0, 1, 0);
        let mut buf = vec![0u8; m.size() + 1];
        let n = m.serialize(&mut buf).unwrap();
        assert!(UdpMessage::parse(&buf[..n]).is_none());
        // Truncated header.
        assert!(UdpMessage::parse(&[0u8; 4]).is_none());
    }

    #[test]
    fn frag_then_defrag_reassembles() {
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let m = msg(&payload, 0, 1, 7);
        let frags = frag_udp_message(&m, m.header_size() + 100);
        assert!(frags.len() > 1);
        assert!(frags.iter().all(|f| f.frag_count as usize == frags.len()));

        let mut d = Defragger::default();
        let mut out = None;
        for f in frags {
            if let Some(full) = d.feed(f) {
                out = Some(full);
            }
        }
        let full = out.expect("reassembled");
        assert_eq!(full.data, payload);
        assert_eq!(full.frag_count, 1);
    }

    #[test]
    fn defrag_passes_through_unfragmented() {
        let m = msg(b"single", 0, 1, 0);
        let mut d = Defragger::default();
        let out = d.feed(m).unwrap();
        assert_eq!(out.data, b"single");
    }

    #[test]
    fn defrag_new_packet_id_resets_state() {
        let p1: Vec<u8> = vec![1; 300];
        let m1 = msg(&p1, 0, 2, 1); // only first frag of packet 1
        let p2: Vec<u8> = vec![2; 200];
        let f2 = frag_udp_message(&msg(&p2, 0, 1, 2), msg(&p2, 0, 1, 2).header_size() + 50);

        let mut d = Defragger::default();
        assert!(d.feed(m1).is_none());
        // A different packet arrives; previous partial state is dropped.
        let mut out = None;
        for f in f2 {
            if let Some(full) = d.feed(f) {
                out = Some(full);
            }
        }
        assert_eq!(out.unwrap().data, p2);
    }
}
