//! UDP relay over QUIC unreliable datagrams (Go: core/client/udp.go +
//! `UDPMessage` / `FragUDPMessage` / `Defragger` in the protocol package).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use rand::RngExt;
use tokio::sync::mpsc;

use crate::Hysteria2ProtocolError;
use crate::varint::read_from;

/// Largest reassembled UDP payload buffer (Go `MaxUDPSize`).
pub(crate) const MAX_UDP_SIZE: usize = 4096;
/// Largest QUIC datagram frame Hysteria2 advertises (Go `MaxDatagramFrameSize`).
pub(crate) const MAX_DATAGRAM_FRAME_SIZE: usize = 1200;
/// Denial-of-service guard on address string length (Go `MaxMessageLength`).
pub(crate) const MAX_MESSAGE_LENGTH: u64 = 2048;
/// Per-session inbound queue depth (Go `udpMessageChanSize`).
const SESSION_CHAN_SIZE: usize = 1024;
/// Soft cap on concurrent UDP sessions per QUIC connection.
const MAX_SESSIONS: usize = 256;
/// Drop incomplete reassembly state after this age (Go LRU `WithAge(10)`).
const DEFRAG_TTL: Duration = Duration::from_secs(10);
/// Bound buffered fragment bytes held across all in-flight packet IDs.
const MAX_DEFRAG_BYTES: usize = 4 * 1024 * 1024;
/// Bound concurrent packet IDs awaiting reassembly (Go caches per packet ID).
const MAX_DEFRAG_PACKETS: usize = 64;

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

    /// Parse a `UDPMessage` from a complete datagram (Go `ParseUDPMessage`).
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

/// Partial reassembly state for one packet ID.
struct PacketAssembly {
    frags: Vec<Option<UdpMessage>>,
    count: u8,
    size: usize,
    started: Instant,
}

impl PacketAssembly {
    fn new(frag_count: u8, now: Instant) -> Self {
        Self {
            frags: vec![None; frag_count as usize],
            count: 0,
            size: 0,
            started: now,
        }
    }

    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started) >= DEFRAG_TTL
    }
}

/// Reassembles fragmented UDP messages with a bounded multi-packet table
/// (Go `udpDefragger` LRU keyed by packet ID). Interleaved fragments from
/// different packet IDs no longer wipe each other. Age, packet-count, and
/// buffered-byte caps prevent unbounded growth.
#[derive(Default)]
pub(crate) struct Defragger {
    packets: HashMap<u16, PacketAssembly>,
    /// Insertion / touch order for eviction (oldest first).
    order: VecDeque<u16>,
    /// Total buffered fragment payload bytes across all assemblies.
    size: usize,
}

impl Defragger {
    fn touch(&mut self, packet_id: u16) {
        self.order.retain(|id| *id != packet_id);
        self.order.push_back(packet_id);
    }

    fn remove_packet(&mut self, packet_id: u16) {
        if let Some(item) = self.packets.remove(&packet_id) {
            self.size = self.size.saturating_sub(item.size);
        }
        self.order.retain(|id| *id != packet_id);
    }

    fn drop_expired(&mut self, now: Instant) {
        let expired: Vec<u16> = self
            .packets
            .iter()
            .filter_map(|(id, item)| item.expired(now).then_some(*id))
            .collect();
        for id in expired {
            self.remove_packet(id);
        }
    }

    /// Evict a single oldest incomplete assembly. Always removes one entry when
    /// the order queue is non-empty (callers that need room must not spin on a
    /// no-op when `size` is under the byte cap but `size + incoming` would
    /// exceed it).
    fn evict_one_oldest(&mut self) -> bool {
        let Some(oldest) = self.order.pop_front() else {
            return false;
        };
        if let Some(item) = self.packets.remove(&oldest) {
            self.size = self.size.saturating_sub(item.size);
        }
        true
    }

    /// Feed a (possibly fragmented) message. Returns the fully reassembled
    /// message once all fragments have arrived, otherwise `None`.
    pub fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        let now = Instant::now();
        self.drop_expired(now);

        if m.frag_count <= 1 {
            return Some(m);
        }
        if m.frag_id >= m.frag_count {
            return None;
        }
        if m.data.len() > MAX_DEFRAG_BYTES {
            return None;
        }

        let packet_id = m.packet_id;
        let needs_reset = self
            .packets
            .get(&packet_id)
            .is_some_and(|item| item.frags.len() != m.frag_count as usize);
        if needs_reset {
            self.remove_packet(packet_id);
        }

        if self.packets.contains_key(&packet_id) {
            self.touch(packet_id);
        } else {
            // Reserve room before inserting a new assembly. Each iteration must
            // make progress (evict one) or reject — otherwise
            // `size + incoming > MAX` with `size <= MAX` spins forever.
            while self.packets.len() >= MAX_DEFRAG_PACKETS
                || self.size.saturating_add(m.data.len()) > MAX_DEFRAG_BYTES
            {
                if !self.evict_one_oldest() {
                    return None;
                }
            }
            self.packets
                .insert(packet_id, PacketAssembly::new(m.frag_count, now));
            self.touch(packet_id);
        }

        // Check room / duplicate without holding a long-lived map borrow.
        let data_len = m.data.len();
        let frag_id = m.frag_id as usize;
        let (duplicate, over_budget) = {
            let item = self.packets.get(&packet_id)?;
            (
                item.frags.get(frag_id).is_some_and(Option::is_some),
                self.size.saturating_add(data_len) > MAX_DEFRAG_BYTES,
            )
        };
        if duplicate {
            return None;
        }
        if over_budget {
            self.remove_packet(packet_id);
            return None;
        }

        let complete = {
            let item = self.packets.get_mut(&packet_id)?;
            self.size += data_len;
            item.size += data_len;
            item.count = item.count.saturating_add(1);
            item.frags[frag_id] = Some(m);
            item.count as usize == item.frags.len()
        };
        if !complete {
            return None;
        }

        // All fragments present — assemble in order and drop the table entry.
        let item = self.packets.remove(&packet_id)?;
        self.order.retain(|id| *id != packet_id);
        self.size = self.size.saturating_sub(item.size);

        let mut data = Vec::with_capacity(item.size);
        let mut first: Option<UdpMessage> = None;
        for frag in item.frags.into_iter().flatten() {
            data.extend_from_slice(&frag.data);
            if first.is_none() {
                first = Some(frag);
            }
        }
        let mut out = first?;
        out.data = data;
        out.frag_id = 0;
        out.frag_count = 1;
        Some(out)
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
    pub fn new_session(
        self: &Arc<Self>,
        udp_mtu: usize,
    ) -> Result<UdpSession, Hysteria2ProtocolError> {
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
            // Strong ref: keeps the manager (and its channel senders / receive
            // loop) alive after `Client::open_udp` drops a non-reused Session.
            mgr: Arc::clone(self),
            udp_mtu: udp_mtu.clamp(64, MAX_UDP_SIZE),
            session_owner: None,
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

    /// Drop every session sender so blocked `recv` callers wake with EOF
    /// (QUIC closed / receive loop exit).
    fn close_all(&self) {
        self.sessions.lock().unwrap().clear();
    }
}

async fn receive_loop(conn: quinn::Connection, mgr: Weak<UdpSessionManager>) {
    loop {
        if let Ok(data) = conn.read_datagram().await {
            if let Some(msg) = UdpMessage::parse(&data) {
                match mgr.upgrade() {
                    Some(m) => m.dispatch(msg),
                    None => return, // manager dropped
                }
            }
            // Invalid datagram — skip, like Go.
        } else {
            // Connection closed: actively close session channels so
            // receivers wake (senders do not drop merely because this
            // task exits — they live in the manager map).
            if let Some(m) = mgr.upgrade() {
                m.close_all();
            }
            return;
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
    /// Strong manager ownership so channel senders stay alive after a
    /// non-reused [`crate::Session`] handle is dropped.
    mgr: Arc<UdpSessionManager>,
    udp_mtu: usize,
    /// Optional owner (typically the [`crate::Session`]) retained by
    /// [`crate::Client::open_udp`] for `disable-reuse` dials.
    session_owner: Option<Box<dyn Send + Sync>>,
}

impl UdpSession {
    /// Retain an owner object for the lifetime of this UDP session.
    pub(crate) fn retain_owner(&mut self, owner: impl Send + Sync + 'static) {
        self.session_owner = Some(Box::new(owner));
    }

    /// The Session ID assigned by the client.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Send `data` to `addr` (`host:port`) through the proxy, fragmenting when
    /// the payload exceeds the configured `udp-mtu` (or the live QUIC datagram
    /// limit, whichever is tighter). Go fragments by configured MTU first.
    ///
    /// # Errors
    ///
    /// Returns when the QUIC datagram send fails.
    pub fn send(&self, data: &[u8], addr: &str) -> Result<(), Hysteria2ProtocolError> {
        let msg = UdpMessage {
            session_id: self.id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_owned(),
            data: data.to_vec(),
        };

        let max = self
            .conn
            .max_datagram_size()
            .unwrap_or(MAX_DATAGRAM_FRAME_SIZE)
            .min(self.udp_mtu)
            .max(64);

        // Honor configured MTU before send (do not rely on Quinn TooLarge alone).
        if msg.size() <= max {
            let mut buf = vec![0u8; msg.size()];
            if let Some(n) = msg.serialize(&mut buf) {
                self.conn
                    .send_datagram(Bytes::copy_from_slice(&buf[..n]))
                    .map_err(|e| Hysteria2ProtocolError::Protocol(format!("send datagram: {e}")))?;
            }
            return Ok(());
        }

        let mut frag = msg;
        frag.packet_id = rand::rng().random_range(1..=u16::MAX);
        for f in frag_udp_message(&frag, max) {
            let mut fbuf = vec![0u8; f.size()];
            if let Some(n) = f.serialize(&mut fbuf) {
                self.conn
                    .send_datagram(Bytes::copy_from_slice(&fbuf[..n]))
                    .map_err(|e| Hysteria2ProtocolError::Protocol(format!("send fragment: {e}")))?;
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
            let msg =
                self.rx.recv().await.ok_or_else(|| {
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
        self.mgr.remove(self.id);
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
    fn defrag_interleaved_packet_ids_reassemble_both() {
        // A0 → B0 → A1 → B1 must not clear either assembly (Go multi-ID cache).
        let a: Vec<u8> = vec![0xA; 300];
        let b: Vec<u8> = vec![0xB; 300];
        let a_frags = frag_udp_message(&msg(&a, 0, 1, 1), msg(&a, 0, 1, 1).header_size() + 150);
        let b_frags = frag_udp_message(&msg(&b, 0, 1, 2), msg(&b, 0, 1, 2).header_size() + 150);
        assert_eq!(a_frags.len(), 2);
        assert_eq!(b_frags.len(), 2);

        let mut d = Defragger::default();
        assert!(d.feed(a_frags[0].clone()).is_none());
        assert!(d.feed(b_frags[0].clone()).is_none());
        let full_a = d.feed(a_frags[1].clone()).expect("packet A");
        let full_b = d.feed(b_frags[1].clone()).expect("packet B");
        assert_eq!(full_a.data, a);
        assert_eq!(full_b.data, b);
        assert_eq!(d.size, 0);
        assert!(d.packets.is_empty());
    }

    #[test]
    fn defrag_reordered_fragments_within_packet() {
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let frags = frag_udp_message(
            &msg(&payload, 0, 1, 9),
            msg(&payload, 0, 1, 9).header_size() + 100,
        );
        assert!(frags.len() > 2);

        let mut d = Defragger::default();
        let mut out = None;
        // Feed in reverse order.
        for f in frags.into_iter().rev() {
            if let Some(full) = d.feed(f) {
                out = Some(full);
            }
        }
        assert_eq!(out.expect("reassembled").data, payload);
    }

    #[test]
    fn defrag_packet_count_cap_evicts_oldest() {
        let mut d = Defragger::default();
        for packet_id in 0..MAX_DEFRAG_PACKETS as u16 {
            let m = msg(&[1, 2, 3, 4], 0, 2, packet_id.wrapping_add(1));
            assert!(d.feed(m).is_none());
        }
        assert_eq!(d.packets.len(), MAX_DEFRAG_PACKETS);
        // One more distinct packet ID evicts the oldest incomplete assembly.
        let m = msg(&[9, 9, 9, 9], 0, 2, 0xBEEF);
        assert!(d.feed(m).is_none());
        assert!(d.packets.len() <= MAX_DEFRAG_PACKETS);
        assert!(!d.packets.contains_key(&1));
        assert!(d.packets.contains_key(&0xBEEF));
    }

    #[test]
    fn defrag_near_byte_cap_new_packet_returns_without_hanging() {
        // Regression: size under MAX but size+incoming over MAX used to spin
        // forever because eviction only ran when size was already over MAX.
        let mut d = Defragger::default();
        const PACKETS: usize = 17;
        let chunk = 4_194_000 / PACKETS;
        assert!(chunk * PACKETS <= MAX_DEFRAG_BYTES);
        assert!(chunk * PACKETS + 1000 > MAX_DEFRAG_BYTES);
        for packet_id in 1..=PACKETS as u16 {
            let m = msg(&vec![0xA; chunk], 0, 2, packet_id);
            assert!(d.feed(m).is_none());
        }
        assert_eq!(d.packets.len(), PACKETS);
        assert_eq!(d.size, chunk * PACKETS);

        // Must return (reject or evict+accept). A hang here is the bug.
        let started = Instant::now();
        let out = d.feed(msg(&vec![0xB; 1000], 0, 2, 0xBEEF));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "defrag feed hung under near-cap eviction"
        );
        assert!(out.is_none());
        assert!(d.size <= MAX_DEFRAG_BYTES);
        assert!(d.packets.len() <= MAX_DEFRAG_PACKETS);
    }

    #[test]
    fn malformed_udp_corpus_is_bounded_and_never_panics() {
        let mut corpus: Vec<Vec<u8>> = vec![
            vec![],
            vec![0; 4],
            vec![0; 7],
            vec![0xff; 8],
            // addr_len = 0 after header
            {
                let mut buf = vec![0u8; 9];
                buf[8] = 0;
                buf
            },
            // absurd addr_len varint
            {
                let mut buf = vec![0u8; 16];
                buf[8] = 0xff;
                buf[9] = 0xff;
                buf[10] = 0xff;
                buf[11] = 0xff;
                buf
            },
        ];
        for length in 0..=96_usize {
            corpus.push(
                (0..length)
                    .map(|index| u8::try_from((index * 41 + length * 7) & 0xff).unwrap())
                    .collect(),
            );
        }
        let mut defrag = Defragger::default();
        for bytes in corpus {
            let _ = UdpMessage::parse(&bytes);
            // Feed any parseable message; oversized / bad frag ids must not grow forever.
            if let Some(parsed) = UdpMessage::parse(&bytes) {
                let _ = defrag.feed(parsed);
            }
            assert!(
                defrag.size <= MAX_DEFRAG_BYTES,
                "defrag size exceeded bound: {}",
                defrag.size
            );
            assert!(defrag.packets.len() <= MAX_DEFRAG_PACKETS);
        }
        // Explicit oversize first fragment is rejected.
        let huge = msg(&vec![0u8; MAX_DEFRAG_BYTES + 1], 0, 2, 99);
        assert!(defrag.feed(huge).is_none());
    }
}
