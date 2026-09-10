//! TUIC v5 UDP relay: native QUIC DATAGRAM and uni-stream modes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use rewrite_model::Destination;
use tokio::sync::mpsc;

use crate::TuicProtocolError;
use crate::lease::StreamLease;
use crate::protocol::{
    DecodeProgress, Packet, encode_dissociate, encode_packet, try_decode_command,
};

const DEFRAG_TTL: Duration = Duration::from_secs(10);
const DISSOCIATE_QUEUE: usize = 32;
const DISSOCIATE_TIMEOUT: Duration = Duration::from_secs(1);

/// Clash `udp-relay-mode`. Empty / `native` uses QUIC DATAGRAM frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpRelayMode {
    Native,
    Quic,
}

struct PacketBag {
    total: u8,
    parts: Vec<Option<Packet>>,
    count: u8,
    created: Instant,
}

#[derive(Default)]
struct DeFragger {
    bags: HashMap<u16, PacketBag>,
}

impl DeFragger {
    fn feed(&mut self, packet: Packet) -> Option<Packet> {
        self.evict_expired();
        if packet.frag_total <= 1 {
            return Some(packet);
        }
        if packet.frag_id >= packet.frag_total {
            return None;
        }
        let pkt_id = packet.pkt_id;
        let bag = self.bags.entry(pkt_id).or_insert_with(|| PacketBag {
            total: packet.frag_total,
            parts: vec![None; usize::from(packet.frag_total)],
            count: 0,
            created: Instant::now(),
        });
        if bag.total != packet.frag_total || bag.parts.len() != usize::from(packet.frag_total) {
            bag.total = packet.frag_total;
            bag.parts = vec![None; usize::from(packet.frag_total)];
            bag.count = 0;
            bag.created = Instant::now();
        }
        let index = usize::from(packet.frag_id);
        if bag.parts.get(index).is_some_and(Option::is_some) {
            return None;
        }
        if let Some(slot) = bag.parts.get_mut(index) {
            *slot = Some(packet);
            bag.count = bag.count.saturating_add(1);
        }
        if usize::from(bag.count) != bag.parts.len() {
            return None;
        }
        let mut assembled = bag.parts[0].clone()?;
        let mut data = Vec::new();
        for part in &bag.parts {
            data.extend_from_slice(&part.as_ref()?.data);
        }
        assembled.data = data;
        assembled.frag_id = 0;
        assembled.frag_total = 1;
        self.bags.remove(&pkt_id);
        Some(assembled)
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.bags
            .retain(|_, bag| now.saturating_duration_since(bag.created) < DEFRAG_TTL);
    }
}

pub(crate) struct UdpHub {
    connection: quinn::Connection,
    mode: UdpRelayMode,
    max_packet: usize,
    associations: Mutex<HashMap<u16, mpsc::Sender<Packet>>>,
    dissociate: mpsc::Sender<u16>,
    ids: AssociationIds,
}

#[derive(Default)]
struct AssociationIds(AtomicU32);

impl AssociationIds {
    fn available(&self) -> bool {
        u16::try_from(self.0.load(Ordering::Acquire)).is_ok()
    }

    fn allocate(&self) -> Option<u16> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                u16::try_from(next).is_ok().then_some(next + 1)
            })
            .ok()
            .and_then(|id| u16::try_from(id).ok())
    }
}

impl UdpHub {
    pub(crate) fn new(
        connection: quinn::Connection,
        mode: UdpRelayMode,
        max_packet: usize,
    ) -> Arc<Self> {
        let (dissociate, pending) = mpsc::channel(DISSOCIATE_QUEUE);
        spawn_dissociate_worker(connection.clone(), pending);
        let hub = Arc::new(Self {
            connection,
            mode,
            max_packet: max_packet.max(1),
            associations: Mutex::new(HashMap::new()),
            dissociate,
            ids: AssociationIds::default(),
        });
        spawn_close_watcher(Arc::clone(&hub));
        spawn_datagram_loop(Arc::clone(&hub));
        if mode == UdpRelayMode::Quic {
            spawn_uni_loop(Arc::clone(&hub));
        }
        hub
    }

    pub(crate) fn open_session(self: &Arc<Self>) -> Result<UdpSession, TuicProtocolError> {
        let (tx, rx) = mpsc::channel(64);
        let mut map = self.associations.lock().map_err(|_| {
            TuicProtocolError::Protocol("TUIC UDP association map is poisoned".to_owned())
        })?;
        if let Some(assoc_id) = self.ids.allocate() {
            map.insert(assoc_id, tx);
            return Ok(UdpSession {
                hub: Arc::clone(self),
                assoc_id,
                rx,
                defrag: DeFragger::default(),
                stream_lease: None,
            });
        }
        Err(TuicProtocolError::Protocol(
            "failed to allocate a TUIC UDP association id".to_owned(),
        ))
    }

    pub(crate) fn has_available_ids(&self) -> bool {
        self.ids.available()
    }

    fn dispatch(&self, packet: Packet) {
        let Ok(map) = self.associations.lock() else {
            return;
        };
        if let Some(sender) = map.get(&packet.assoc_id) {
            let _ = sender.try_send(packet);
        }
    }

    fn close_all(&self) {
        if let Ok(mut map) = self.associations.lock() {
            map.clear();
        }
    }

    fn unregister(&self, assoc_id: u16) {
        if let Ok(mut map) = self.associations.lock() {
            map.remove(&assoc_id);
        }
    }

    async fn send_packet(&self, packet: &Packet) -> Result<(), TuicProtocolError> {
        match self.mode {
            UdpRelayMode::Quic => self.send_quic(packet).await,
            UdpRelayMode::Native => self.send_native(packet),
        }
    }

    async fn send_quic(&self, packet: &Packet) -> Result<(), TuicProtocolError> {
        let bytes = encode_packet(packet)?;
        let mut stream = tokio::select! {
            stream = self.connection.open_uni() => stream?,
            error = self.connection.closed() => return Err(error.into()),
        };
        tokio::select! {
            result = stream.write_all(&bytes) => {
                result.map_err(|error| {
                    TuicProtocolError::Io(std::io::Error::other(error.to_string()))
                })?;
            }
            error = self.connection.closed() => return Err(error.into()),
        }
        stream
            .finish()
            .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?;
        Ok(())
    }

    fn send_native(&self, packet: &Packet) -> Result<(), TuicProtocolError> {
        let initial = if packet.data.len() > self.max_packet {
            self.frag_write_native(packet, self.max_packet)
        } else {
            self.connection
                .send_datagram(Bytes::from(encode_packet(packet)?))
                .map_err(Into::into)
        };
        match initial {
            Ok(()) => Ok(()),
            Err(TuicProtocolError::Datagram(quinn::SendDatagramError::TooLarge)) => {
                let overhead = encode_packet(packet)?.len() - packet.data.len();
                let frag = self
                    .connection
                    .max_datagram_size()
                    .and_then(|size| size.checked_sub(overhead))
                    .filter(|size| *size > 0)
                    .ok_or(TuicProtocolError::Datagram(
                        quinn::SendDatagramError::TooLarge,
                    ))?;
                self.frag_write_native(packet, frag)
            }
            Err(error) => Err(error),
        }
    }

    fn frag_write_native(
        &self,
        packet: &Packet,
        frag_size: usize,
    ) -> Result<(), TuicProtocolError> {
        let payload = &packet.data;
        if payload.is_empty() {
            let encoded = encode_packet(packet)?;
            return self
                .connection
                .send_datagram(Bytes::from(encoded))
                .map_err(Into::into);
        }
        let frag_count = u8::try_from(payload.len().div_ceil(frag_size).max(1)).map_err(|_| {
            TuicProtocolError::Protocol("TUIC UDP fragment count exceeds 255".to_owned())
        })?;
        let mut offset = 0_usize;
        let mut frag_id = 0_u8;
        let mut addr = packet.addr.clone();
        while offset < payload.len() {
            let end = (offset + frag_size).min(payload.len());
            let fragment = Packet {
                assoc_id: packet.assoc_id,
                pkt_id: packet.pkt_id,
                frag_total: frag_count,
                frag_id,
                addr: addr.take(),
                data: payload[offset..end].to_vec(),
            };
            let encoded = encode_packet(&fragment)?;
            self.connection
                .send_datagram(Bytes::from(encoded))
                .map_err(TuicProtocolError::from)?;
            offset = end;
            frag_id = frag_id.saturating_add(1);
        }
        Ok(())
    }
}

async fn send_dissociate(
    connection: &quinn::Connection,
    assoc_id: u16,
) -> Result<(), TuicProtocolError> {
    let mut stream = connection.open_uni().await?;
    stream
        .write_all(&encode_dissociate(assoc_id))
        .await
        .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?;
    stream
        .finish()
        .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?;
    Ok(())
}

fn spawn_dissociate_worker(connection: quinn::Connection, mut pending: mpsc::Receiver<u16>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = connection.closed() => break,
                assoc_id = pending.recv() => {
                    let Some(assoc_id) = assoc_id else { break };
                    tokio::select! {
                        _ = connection.closed() => break,
                        _ = tokio::time::timeout(DISSOCIATE_TIMEOUT, send_dissociate(&connection, assoc_id)) => {}
                    }
                }
            }
        }
    });
}

/// One TUIC UDP association (`ASSOC_ID`) with fragment reassembly.
pub struct UdpSession {
    hub: Arc<UdpHub>,
    assoc_id: u16,
    rx: mpsc::Receiver<Packet>,
    defrag: DeFragger,
    stream_lease: Option<StreamLease>,
}

impl UdpSession {
    pub(crate) fn attach_lease(&mut self, lease: StreamLease) {
        self.stream_lease = Some(lease);
    }

    /// Sends `payload` to `destination` on this association.
    ///
    /// # Errors
    ///
    /// Returns when the payload is larger than 65535 bytes or QUIC send fails.
    pub async fn send(
        &self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), TuicProtocolError> {
        if payload.len() > usize::from(u16::MAX) {
            return Err(TuicProtocolError::Protocol(
                "TUIC UDP payload exceeds 65535 bytes".to_owned(),
            ));
        }
        let packet = Packet {
            assoc_id: self.assoc_id,
            pkt_id: rand::random(),
            frag_total: 1,
            frag_id: 0,
            addr: Some(destination.clone()),
            data: payload.to_vec(),
        };
        self.hub.send_packet(&packet).await
    }

    /// Receives the next reassembled datagram.
    ///
    /// # Errors
    ///
    /// Returns when the association or QUIC connection is closed, or when a
    /// completed packet has no destination address.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), TuicProtocolError> {
        loop {
            tokio::select! {
                packet = self.rx.recv() => {
                    let Some(packet) = packet else {
                        return Err(TuicProtocolError::Protocol(
                            "TUIC UDP association closed".to_owned(),
                        ));
                    };
                    let Some(packet) = self.defrag.feed(packet) else {
                        continue;
                    };
                    let destination = packet.addr.ok_or_else(|| {
                        TuicProtocolError::Protocol("TUIC UDP packet missing address".to_owned())
                    })?;
                    return Ok((destination, packet.data));
                }
                error = self.hub.connection.closed() => {
                    return Err(error.into());
                }
            }
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.hub.unregister(self.assoc_id);
        // Best effort: never block teardown or allocate an unbounded number of tasks.
        let _ = self.hub.dissociate.try_send(self.assoc_id);
    }
}

fn spawn_close_watcher(hub: Arc<UdpHub>) {
    tokio::spawn(async move {
        let _ = hub.connection.closed().await;
        hub.close_all();
    });
}

fn spawn_datagram_loop(hub: Arc<UdpHub>) {
    tokio::spawn(async move {
        while let Ok(bytes) = hub.connection.read_datagram().await {
            if let Ok(DecodeProgress::Packet(packet)) = try_decode_command(&bytes)
                && hub.mode == UdpRelayMode::Native
            {
                hub.dispatch(packet);
            }
        }
        hub.close_all();
    });
}

fn spawn_uni_loop(hub: Arc<UdpHub>) {
    tokio::spawn(async move {
        while let Ok(recv) = hub.connection.accept_uni().await {
            let hub = Arc::clone(&hub);
            tokio::spawn(async move {
                if let Ok(packet) = read_packet_from_uni(recv).await {
                    hub.dispatch(packet);
                }
            });
        }
        hub.close_all();
    });
}

async fn read_packet_from_uni(mut recv: quinn::RecvStream) -> Result<Packet, TuicProtocolError> {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 2048];
    loop {
        match recv.read(&mut tmp).await {
            Ok(None) => break,
            Ok(Some(n)) => buf.extend_from_slice(&tmp[..n]),
            Err(error) => {
                return Err(TuicProtocolError::Io(std::io::Error::other(
                    error.to_string(),
                )));
            }
        }
        match try_decode_command(&buf)? {
            DecodeProgress::Incomplete => {}
            DecodeProgress::Packet(packet) => return Ok(packet),
            DecodeProgress::Heartbeat | DecodeProgress::Other(_) => {
                return Err(TuicProtocolError::Protocol(
                    "unexpected TUIC command on UDP uni-stream".to_owned(),
                ));
            }
        }
    }
    decode_finished(&buf)
}

fn decode_finished(buf: &[u8]) -> Result<Packet, TuicProtocolError> {
    match try_decode_command(buf)? {
        DecodeProgress::Packet(packet) => Ok(packet),
        DecodeProgress::Incomplete => Err(TuicProtocolError::Protocol(
            "truncated TUIC packet on uni-stream".to_owned(),
        )),
        DecodeProgress::Heartbeat | DecodeProgress::Other(_) => Err(TuicProtocolError::Protocol(
            "unexpected TUIC command on UDP uni-stream".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rewrite_model::Host;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn association_ids_never_reuse_even_after_retirement() {
        let ids = AssociationIds::default();
        for expected in 0..=u16::MAX {
            assert!(ids.available());
            assert_eq!(ids.allocate(), Some(expected));
            // A delayed cleanup for any previous ID cannot name a newer session.
        }
        assert!(!ids.available());
        assert_eq!(ids.allocate(), None);
        assert_eq!(ids.allocate(), None);
    }

    fn dest() -> Destination {
        Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 9,
        }
    }

    #[test]
    fn defragger_reorders_and_ignores_duplicates() {
        let mut defrag = DeFragger::default();
        let first = Packet {
            assoc_id: 1,
            pkt_id: 42,
            frag_total: 3,
            frag_id: 0,
            addr: Some(dest()),
            data: b"aa".to_vec(),
        };
        let second = Packet {
            assoc_id: 1,
            pkt_id: 42,
            frag_total: 3,
            frag_id: 1,
            addr: None,
            data: b"bb".to_vec(),
        };
        let third = Packet {
            assoc_id: 1,
            pkt_id: 42,
            frag_total: 3,
            frag_id: 2,
            addr: None,
            data: b"cc".to_vec(),
        };
        assert!(defrag.feed(second.clone()).is_none());
        assert!(defrag.feed(second).is_none());
        assert!(defrag.feed(third).is_none());
        let assembled = defrag.feed(first).expect("assembled");
        assert_eq!(assembled.data, b"aabbcc");
        assert_eq!(assembled.addr, Some(dest()));
        assert_eq!(assembled.frag_total, 1);
    }

    #[test]
    fn defragger_drops_invalid_frag_id_and_incomplete() {
        let mut defrag = DeFragger::default();
        let bad = Packet {
            assoc_id: 1,
            pkt_id: 1,
            frag_total: 2,
            frag_id: 2,
            addr: Some(dest()),
            data: b"x".to_vec(),
        };
        assert!(defrag.feed(bad).is_none());
        let only = Packet {
            assoc_id: 1,
            pkt_id: 2,
            frag_total: 2,
            frag_id: 0,
            addr: Some(dest()),
            data: b"x".to_vec(),
        };
        assert!(defrag.feed(only).is_none());
    }
}
