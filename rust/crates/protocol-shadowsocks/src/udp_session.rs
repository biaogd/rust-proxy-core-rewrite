//! SIP022 UDP session identifiers, packet counters and replay windows.
//!
//! The maintained `shadowsocks` crate encrypts whatever
//! [`UdpSocketControlData`](shadowsocks::relay::udprelay::options::UdpSocketControlData)
//! the caller supplies. This module owns the client/server counters so AEAD-2022
//! datagrams never reuse the all-zero default control block.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use shadowsocks::relay::udprelay::options::UdpSocketControlData;

/// Matches `sing-shadowsocks2` `SlidingWindow` (`swRingBlocks=128`, 64-bit blocks).
const BLOCK_BITS: u64 = 64;
const RING_BLOCKS: usize = 128;
const WINDOW_SIZE: u64 = (RING_BLOCKS as u64 - 1) * BLOCK_BITS;
const SERVER_SESSION_TTL: Duration = Duration::from_mins(1);
const SERVER_SESSION_CAP: usize = 1024;
const CLIENT_SERVER_SESSION_CAP: usize = 8;
/// Peer address→session routes are independent of replay windows: a single live
/// session can be observed from many source ports, so the route table needs its
/// own cap and TTL or memory grows without bound while the session stays hot.
const PEER_INDEX_TTL: Duration = Duration::from_secs(30);
const PEER_INDEX_CAP: usize = 4096;

/// Sliding window that accepts legitimate reordering and rejects duplicates
/// or counters that have already slid out of the window.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    last: u64,
    ring: [u64; RING_BLOCKS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            last: 0,
            ring: [0; RING_BLOCKS],
        }
    }
}

impl ReplayWindow {
    /// Returns whether `packet_id` may be accepted, and records it when it can.
    #[must_use]
    pub fn accept(&mut self, packet_id: u64) -> bool {
        if !self.check(packet_id) {
            return false;
        }
        self.add(packet_id);
        true
    }

    fn check(&self, packet_id: u64) -> bool {
        if packet_id > self.last {
            return true;
        }
        if self.last - packet_id > WINDOW_SIZE {
            return false;
        }
        let block_index = ring_index(packet_id);
        let bit_index = packet_id & (BLOCK_BITS - 1);
        self.ring[block_index] >> bit_index & 1 == 0
    }

    fn add(&mut self, packet_id: u64) {
        if packet_id > self.last {
            let mut last_block = ring_index(self.last);
            let diff = ring_block_distance(self.last, packet_id);
            for _ in 0..diff {
                last_block = (last_block + 1) % RING_BLOCKS;
                self.ring[last_block] = 0;
            }
            self.last = packet_id;
        }
        let bit_index = packet_id & (BLOCK_BITS - 1);
        self.ring[ring_index(packet_id)] |= 1 << bit_index;
    }
}

fn ring_index(packet_id: u64) -> usize {
    usize::try_from(packet_id >> 6).unwrap_or(usize::MAX) & (RING_BLOCKS - 1)
}

fn ring_block_distance(from: u64, to: u64) -> usize {
    let distance = (to >> 6).saturating_sub(from >> 6);
    usize::try_from(distance.min(RING_BLOCKS as u64)).unwrap_or(RING_BLOCKS)
}

#[derive(Debug)]
struct ServerReplay {
    window: ReplayWindow,
    last_seen: Instant,
}

#[derive(Debug)]
pub(crate) struct ClientUdpState {
    pub(crate) aead_2022: bool,
    client_session_id: u64,
    next_packet_id: u64,
    last_server_session_id: Option<u64>,
    server_replays: HashMap<u64, ServerReplay>,
}

impl ClientUdpState {
    pub(crate) fn new(aead_2022: bool) -> Self {
        Self {
            aead_2022,
            client_session_id: random_session_id(),
            next_packet_id: 0,
            last_server_session_id: None,
            server_replays: HashMap::new(),
        }
    }

    pub(crate) fn next_send_control(&mut self) -> UdpSocketControlData {
        if !self.aead_2022 {
            return UdpSocketControlData::default();
        }
        self.next_packet_id = next_packet_id(self.next_packet_id);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        control.server_session_id = self.last_server_session_id.unwrap_or(0);
        control.packet_id = self.next_packet_id;
        control
    }

    pub(crate) fn accept_recv(
        &mut self,
        control: Option<&UdpSocketControlData>,
    ) -> Result<(), ClientUdpReject> {
        self.accept_recv_at(control, Instant::now())
    }

    fn accept_recv_at(
        &mut self,
        control: Option<&UdpSocketControlData>,
        now: Instant,
    ) -> Result<(), ClientUdpReject> {
        if !self.aead_2022 {
            return Ok(());
        }
        let Some(control) = control else {
            return Err(ClientUdpReject::MissingControl);
        };
        if control.client_session_id != self.client_session_id {
            return Err(ClientUdpReject::ClientSession);
        }
        if control.server_session_id == 0 {
            return Err(ClientUdpReject::ServerSession);
        }
        self.reap_server_replays(now);
        let session_id = control.server_session_id;
        if !self.server_replays.contains_key(&session_id)
            && self.server_replays.len() >= CLIENT_SERVER_SESSION_CAP
        {
            return Err(ClientUdpReject::ServerSessionLimit);
        }
        let replay = self
            .server_replays
            .entry(session_id)
            .or_insert_with(|| ServerReplay {
                window: ReplayWindow::default(),
                last_seen: now,
            });
        if !replay.window.accept(control.packet_id) {
            return Err(ClientUdpReject::Replay);
        }
        replay.last_seen = now;
        self.last_server_session_id = Some(session_id);
        Ok(())
    }

    fn reap_server_replays(&mut self, now: Instant) {
        self.server_replays.retain(|_, replay| {
            now.saturating_duration_since(replay.last_seen) < SERVER_SESSION_TTL
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientUdpReject {
    MissingControl,
    ClientSession,
    ServerSession,
    ServerSessionLimit,
    Replay,
}

/// Why an inbound SIP022 datagram was dropped by the server session table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerUdpReject {
    /// AEAD-2022 datagram lacked a control block.
    MissingControl,
    /// Client session identifier was zero.
    ClientSession,
    /// Packet identifier was zero.
    PacketId,
    /// Duplicate or too-old client packet identifier.
    Replay,
}

/// Per-peer SIP022 server counters used by the test authority and product inbound.
#[derive(Debug, Default)]
pub struct Aead2022ServerSessions {
    /// Replay windows keyed by authenticated identity + client session id.
    /// Peer addresses are only routing hints via [`Self::peer_index`].
    sessions: HashMap<SessionKey, ServerUdpSession>,
    /// Last session observed from each peer, used to build replies.
    /// Bounded independently of [`Self::sessions`] so rotating source ports
    /// cannot retain unbounded address→session mappings.
    peer_index: HashMap<SocketAddr, PeerRoute>,
}

#[derive(Clone, Debug)]
struct PeerRoute {
    key: SessionKey,
    last_seen: Instant,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum AuthKey {
    Default,
    User(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SessionKey {
    auth: AuthKey,
    client_session_id: u64,
}

#[derive(Debug)]
struct ServerUdpSession {
    client_session_id: u64,
    server_session_id: u64,
    next_packet_id: u64,
    incoming_window: ReplayWindow,
    last_user: Option<std::sync::Arc<shadowsocks::config::ServerUser>>,
    last_seen: Instant,
}

impl Aead2022ServerSessions {
    /// Accepts one inbound SIP022 datagram for `peer`.
    ///
    /// Keys the replay window by authenticated identity + client session id so
    /// source-port changes cannot bypass replay, and alternating sessions from
    /// one peer cannot wipe each other's windows. Rejects missing control, zero
    /// ids, and replayed client packet ids.
    ///
    /// # Errors
    ///
    /// Returns [`ServerUdpReject`] when the datagram must be dropped.
    pub fn accept_incoming(
        &mut self,
        peer: SocketAddr,
        incoming: Option<&UdpSocketControlData>,
    ) -> Result<(), ServerUdpReject> {
        self.accept_incoming_at(peer, incoming, Instant::now())
    }

    fn accept_incoming_at(
        &mut self,
        peer: SocketAddr,
        incoming: Option<&UdpSocketControlData>,
        now: Instant,
    ) -> Result<(), ServerUdpReject> {
        self.reap(now);
        let Some(incoming) = incoming else {
            return Err(ServerUdpReject::MissingControl);
        };
        if incoming.client_session_id == 0 {
            return Err(ServerUdpReject::ClientSession);
        }
        if incoming.packet_id == 0 {
            return Err(ServerUdpReject::PacketId);
        }
        let key = SessionKey {
            auth: auth_key(&incoming.user),
            client_session_id: incoming.client_session_id,
        };
        if self.sessions.len() >= SERVER_SESSION_CAP && !self.sessions.contains_key(&key) {
            self.evict_oldest();
        }
        let session = self
            .sessions
            .entry(key.clone())
            .or_insert_with(|| ServerUdpSession::new(incoming.client_session_id));
        if !session.incoming_window.accept(incoming.packet_id) {
            return Err(ServerUdpReject::Replay);
        }
        session.last_user.clone_from(&incoming.user);
        session.last_seen = now;
        self.remember_peer(peer, key, now);
        Ok(())
    }

    /// Builds the next reply control for a peer that previously passed
    /// [`Self::accept_incoming`]. Returns the all-zero default when the peer has
    /// no live AEAD-2022 session (pre-2022 callers).
    pub fn next_reply(&mut self, peer: SocketAddr) -> UdpSocketControlData {
        self.next_reply_at(peer, Instant::now())
    }

    fn next_reply_at(&mut self, peer: SocketAddr, now: Instant) -> UdpSocketControlData {
        self.reap(now);
        let Some(route) = self.peer_index.get_mut(&peer) else {
            return UdpSocketControlData::default();
        };
        route.last_seen = now;
        let key = route.key.clone();
        let Some(session) = self.sessions.get_mut(&key) else {
            self.peer_index.remove(&peer);
            return UdpSocketControlData::default();
        };
        session.last_seen = now;
        session.next_packet_id = next_packet_id(session.next_packet_id);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = session.client_session_id;
        control.server_session_id = session.server_session_id;
        control.packet_id = session.next_packet_id;
        control.user.clone_from(&session.last_user);
        control
    }

    /// Accepts `incoming` then builds one reply control. Echo authorities and
    /// unit tests use this one-shot helper. Missing control is treated as a
    /// pre-2022 datagram and yields the all-zero default reply block.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::accept_incoming`] failures for AEAD-2022 datagrams.
    pub fn prepare_reply(
        &mut self,
        peer: SocketAddr,
        incoming: Option<&UdpSocketControlData>,
    ) -> Result<UdpSocketControlData, ServerUdpReject> {
        if incoming.is_none() {
            return Ok(UdpSocketControlData::default());
        }
        self.accept_incoming(peer, incoming)?;
        Ok(self.next_reply(peer))
    }

    /// Drops idle sessions and stale peer routes so both tables stay bounded.
    pub fn reap(&mut self, now: Instant) {
        self.sessions.retain(|_, session| {
            now.saturating_duration_since(session.last_seen) < SERVER_SESSION_TTL
        });
        self.peer_index.retain(|_, route| {
            now.saturating_duration_since(route.last_seen) < PEER_INDEX_TTL
                && self.sessions.contains_key(&route.key)
        });
    }

    /// Number of live identity/session replay windows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns whether the table currently holds no sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[cfg(test)]
    fn peer_route_count(&self) -> usize {
        self.peer_index.len()
    }

    #[cfg(test)]
    fn has_peer_route(&self, peer: SocketAddr) -> bool {
        self.peer_index.contains_key(&peer)
    }

    fn remember_peer(&mut self, peer: SocketAddr, key: SessionKey, now: Instant) {
        if let Some(route) = self.peer_index.get_mut(&peer) {
            route.key = key;
            route.last_seen = now;
            return;
        }
        if self.peer_index.len() >= PEER_INDEX_CAP {
            self.evict_oldest_peer();
        }
        self.peer_index.insert(
            peer,
            PeerRoute {
                key,
                last_seen: now,
            },
        );
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.last_seen)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.sessions.remove(&key);
            self.peer_index.retain(|_, route| route.key != key);
        }
    }

    fn evict_oldest_peer(&mut self) {
        let oldest = self
            .peer_index
            .iter()
            .min_by_key(|(_, route)| route.last_seen)
            .map(|(peer, _)| *peer);
        if let Some(peer) = oldest {
            self.peer_index.remove(&peer);
        }
    }
}

fn auth_key(user: &Option<std::sync::Arc<shadowsocks::config::ServerUser>>) -> AuthKey {
    match user {
        Some(user) => AuthKey::User(user.name().to_owned()),
        None => AuthKey::Default,
    }
}

impl ServerUdpSession {
    fn new(client_session_id: u64) -> Self {
        Self {
            client_session_id,
            server_session_id: random_session_id(),
            next_packet_id: 0,
            incoming_window: ReplayWindow::default(),
            last_user: None,
            last_seen: Instant::now(),
        }
    }
}

pub(crate) fn lock_client_state(
    state: &Mutex<ClientUdpState>,
) -> std::sync::MutexGuard<'_, ClientUdpState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn next_packet_id(current: u64) -> u64 {
    let next = current.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

fn random_session_id() -> u64 {
    loop {
        let id = rand::random::<u64>();
        if id != 0 {
            return id;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(client_session_id: u64, packet_id: u64) -> UdpSocketControlData {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = client_session_id;
        control.packet_id = packet_id;
        control
    }

    fn client_reply(
        client_session_id: u64,
        server_session_id: u64,
        packet_id: u64,
    ) -> UdpSocketControlData {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = client_session_id;
        control.server_session_id = server_session_id;
        control.packet_id = packet_id;
        control
    }

    #[test]
    fn replay_window_allows_reorder_and_rejects_duplicates_and_old_ids() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(1));
        assert!(window.accept(3));
        assert!(window.accept(2));
        assert!(!window.accept(2));
        assert!(!window.accept(1));
        assert!(window.accept(WINDOW_SIZE + 10));
        assert!(!window.accept(8));
    }

    #[test]
    fn client_state_rejects_wrong_session_and_replay() {
        let mut state = ClientUdpState::new(true);
        let send = state.next_send_control();
        assert_ne!(send.client_session_id, 0);
        assert_eq!(send.packet_id, 1);
        let reply = client_reply(send.client_session_id, 7, 1);
        assert_eq!(state.accept_recv(Some(&reply)), Ok(()));
        assert_eq!(
            state.accept_recv(Some(&reply)),
            Err(ClientUdpReject::Replay)
        );
        let wrong_client = client_reply(send.client_session_id.wrapping_add(1), 7, 2);
        assert_eq!(
            state.accept_recv(Some(&wrong_client)),
            Err(ClientUdpReject::ClientSession)
        );
        let zero_server = client_reply(send.client_session_id, 0, 2);
        assert_eq!(
            state.accept_recv(Some(&zero_server)),
            Err(ClientUdpReject::ServerSession)
        );
        let next = client_reply(send.client_session_id, 7, 2);
        assert_eq!(state.accept_recv(Some(&next)), Ok(()));
    }

    #[test]
    fn client_state_keeps_per_server_session_replay_across_aba() {
        let mut state = ClientUdpState::new(true);
        let client_session_id = state.next_send_control().client_session_id;
        let session_a = client_reply(client_session_id, 7, 1);
        let session_b = client_reply(client_session_id, 9, 1);
        assert_eq!(state.accept_recv(Some(&session_a)), Ok(()));
        assert_eq!(state.accept_recv(Some(&session_b)), Ok(()));
        assert_eq!(
            state.accept_recv(Some(&session_a)),
            Err(ClientUdpReject::Replay)
        );
        assert_eq!(
            state.accept_recv(Some(&session_b)),
            Err(ClientUdpReject::Replay)
        );
        let session_a_next = client_reply(client_session_id, 7, 2);
        assert_eq!(state.accept_recv(Some(&session_a_next)), Ok(()));
    }

    #[test]
    fn client_state_rejects_new_server_session_when_full_without_forgetting() {
        let mut state = ClientUdpState::new(true);
        let client_session_id = state.next_send_control().client_session_id;
        let t0 = Instant::now();
        for index in 1..=CLIENT_SERVER_SESSION_CAP {
            let reply = client_reply(client_session_id, index as u64, 1);
            let at = t0 + Duration::from_millis(index as u64);
            assert_eq!(state.accept_recv_at(Some(&reply), at), Ok(()));
        }
        let first = client_reply(client_session_id, 1, 1);
        let full_at = t0 + Duration::from_millis(CLIENT_SERVER_SESSION_CAP as u64);
        assert_eq!(
            state.accept_recv_at(Some(&first), full_at),
            Err(ClientUdpReject::Replay)
        );
        let extra = client_reply(client_session_id, CLIENT_SERVER_SESSION_CAP as u64 + 1, 1);
        assert_eq!(
            state.accept_recv_at(Some(&extra), full_at),
            Err(ClientUdpReject::ServerSessionLimit)
        );
        assert_eq!(
            state.accept_recv_at(Some(&first), full_at),
            Err(ClientUdpReject::Replay)
        );
    }

    #[test]
    fn client_state_expires_idle_server_replay_window() {
        let mut state = ClientUdpState::new(true);
        let client_session_id = state.next_send_control().client_session_id;
        let t0 = Instant::now();
        let reply = client_reply(client_session_id, 11, 1);
        assert_eq!(state.accept_recv_at(Some(&reply), t0), Ok(()));
        assert_eq!(
            state.accept_recv_at(Some(&reply), t0 + Duration::from_secs(1)),
            Err(ClientUdpReject::Replay)
        );
        assert_eq!(
            state.accept_recv_at(
                Some(&reply),
                t0 + SERVER_SESSION_TTL + Duration::from_secs(1)
            ),
            Ok(())
        );
    }

    #[test]
    fn client_state_reuses_expired_slot_without_dropping_live_windows() {
        let mut state = ClientUdpState::new(true);
        let client_session_id = state.next_send_control().client_session_id;
        let t0 = Instant::now();
        let first = client_reply(client_session_id, 1, 1);
        assert_eq!(state.accept_recv_at(Some(&first), t0), Ok(()));
        for index in 2..=CLIENT_SERVER_SESSION_CAP {
            let reply = client_reply(client_session_id, index as u64, 1);
            assert_eq!(
                state.accept_recv_at(Some(&reply), t0 + SERVER_SESSION_TTL / 2),
                Ok(())
            );
        }
        let after_first_ttl = t0 + SERVER_SESSION_TTL + Duration::from_millis(1);
        let extra = client_reply(client_session_id, CLIENT_SERVER_SESSION_CAP as u64 + 1, 1);
        assert_eq!(state.accept_recv_at(Some(&extra), after_first_ttl), Ok(()));
        let live = client_reply(client_session_id, 2, 1);
        assert_eq!(
            state.accept_recv_at(Some(&live), after_first_ttl),
            Err(ClientUdpReject::Replay)
        );
    }

    #[test]
    fn server_sessions_isolate_peers_and_rotate_on_client_rebuild() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer_a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let incoming_a = control(11, 1);
        let first_a = sessions
            .prepare_reply(peer_a, Some(&incoming_a))
            .expect("first a");
        let second_a = sessions
            .prepare_reply(peer_a, Some(&control(11, 2)))
            .expect("second a");
        assert_eq!(first_a.client_session_id, 11);
        assert_ne!(first_a.server_session_id, 0);
        assert_eq!(first_a.packet_id, 1);
        assert_eq!(second_a.server_session_id, first_a.server_session_id);
        assert_eq!(second_a.packet_id, 2);
        assert_eq!(
            sessions.prepare_reply(peer_a, Some(&incoming_a)).err(),
            Some(ServerUdpReject::Replay)
        );
        let incoming_b = control(22, 1);
        let first_b = sessions
            .prepare_reply(peer_b, Some(&incoming_b))
            .expect("first b");
        assert_ne!(first_b.server_session_id, first_a.server_session_id);
        let rebuilt = control(33, 1);
        let rotated = sessions
            .prepare_reply(peer_a, Some(&rebuilt))
            .expect("rotated");
        assert_eq!(rotated.client_session_id, 33);
        assert_ne!(rotated.server_session_id, first_a.server_session_id);
        assert_eq!(rotated.packet_id, 1);
        // Rebuilding must not wipe the prior session window.
        assert_eq!(
            sessions.prepare_reply(peer_a, Some(&incoming_a)).err(),
            Some(ServerUdpReject::Replay)
        );
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn server_sessions_reject_cross_port_replay_of_same_session() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer_a: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        let packet = control(77, 1);
        sessions
            .prepare_reply(peer_a, Some(&packet))
            .expect("first delivery");
        assert_eq!(
            sessions.prepare_reply(peer_b, Some(&packet)).err(),
            Some(ServerUdpReject::Replay),
            "same ciphertext from another source port must stay rejected"
        );
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn server_sessions_keep_windows_when_sessions_alternate_on_one_peer() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        let session_a = control(11, 1);
        let session_b = control(22, 1);
        sessions
            .prepare_reply(peer, Some(&session_a))
            .expect("session a first");
        sessions
            .prepare_reply(peer, Some(&session_b))
            .expect("session b first");
        assert_eq!(
            sessions.prepare_reply(peer, Some(&session_a)).err(),
            Some(ServerUdpReject::Replay),
            "alternating sessions must not clear the earlier window"
        );
        assert_eq!(
            sessions.prepare_reply(peer, Some(&session_b)).err(),
            Some(ServerUdpReject::Replay)
        );
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn server_sessions_reject_missing_control_and_zero_ids() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        assert_eq!(
            sessions.accept_incoming(peer, None),
            Err(ServerUdpReject::MissingControl)
        );
        assert_eq!(
            sessions.accept_incoming(peer, Some(&control(0, 1))),
            Err(ServerUdpReject::ClientSession)
        );
        assert_eq!(
            sessions.accept_incoming(peer, Some(&control(9, 0))),
            Err(ServerUdpReject::PacketId)
        );
    }

    #[test]
    fn server_sessions_reap_idle_peers() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let incoming = control(1, 1);
        sessions
            .prepare_reply(peer, Some(&incoming))
            .expect("prepare");
        assert_eq!(sessions.len(), 1);
        sessions.reap(Instant::now() + SERVER_SESSION_TTL + Duration::from_secs(1));
        assert_eq!(sessions.len(), 0);
    }

    #[test]
    fn server_sessions_evict_oldest_when_full() {
        let mut sessions = Aead2022ServerSessions::default();
        for index in 0..SERVER_SESSION_CAP {
            let port = u16::try_from(index + 1).expect("port");
            let peer = SocketAddr::from(([127, 0, 0, 1], port));
            sessions
                .prepare_reply(peer, Some(&control(u64::from(port), 1)))
                .expect("prepare");
        }
        assert_eq!(sessions.len(), SERVER_SESSION_CAP);
        let extra = SocketAddr::from(([127, 0, 0, 1], 60_000));
        sessions
            .prepare_reply(extra, Some(&control(60_000, 1)))
            .expect("evict prepare");
        assert_eq!(sessions.len(), SERVER_SESSION_CAP);
    }

    #[test]
    fn server_sessions_next_reply_after_accept() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        sessions
            .accept_incoming(peer, Some(&control(44, 1)))
            .expect("accept");
        let first = sessions.next_reply(peer);
        let second = sessions.next_reply(peer);
        assert_eq!(first.client_session_id, 44);
        assert_eq!(first.packet_id, 1);
        assert_eq!(second.server_session_id, first.server_session_id);
        assert_eq!(second.packet_id, 2);
    }

    #[test]
    fn server_peer_routes_cap_independently_of_replay_windows() {
        let mut sessions = Aead2022ServerSessions::default();
        let now = Instant::now();
        for index in 0..(PEER_INDEX_CAP + 32) {
            let port = u16::try_from(10_000 + (index % 50_000)).expect("port");
            let peer = SocketAddr::from(([127, 0, 0, 1], port));
            // One live session, many source addresses with increasing packet ids.
            sessions
                .accept_incoming_at(
                    peer,
                    Some(&control(7, u64::try_from(index + 1).unwrap())),
                    now,
                )
                .expect("accept rotating peer");
        }
        assert_eq!(
            sessions.len(),
            1,
            "session cap must not be the peer-route bound"
        );
        assert!(
            sessions.peer_route_count() <= PEER_INDEX_CAP,
            "peer routes must stay capped"
        );
        // Early packet id remains rejected even after address-table pressure.
        let late_peer = SocketAddr::from(([127, 0, 0, 1], 9));
        assert_eq!(
            sessions.accept_incoming_at(late_peer, Some(&control(7, 1)), now),
            Err(ServerUdpReject::Replay)
        );
    }

    #[test]
    fn server_peer_routes_expire_while_session_window_stays() {
        let mut sessions = Aead2022ServerSessions::default();
        let t0 = Instant::now();
        let peer_a: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:7002".parse().unwrap();
        sessions
            .accept_incoming_at(peer_a, Some(&control(9, 1)), t0)
            .expect("peer a");
        sessions
            .accept_incoming_at(peer_b, Some(&control(9, 2)), t0)
            .expect("peer b");
        // Keep the session (and peer_a) fresh past the peer-route TTL.
        let mid = t0 + PEER_INDEX_TTL / 2;
        sessions
            .accept_incoming_at(peer_a, Some(&control(9, 3)), mid)
            .expect("refresh peer a");
        sessions.reap(t0 + PEER_INDEX_TTL + Duration::from_millis(1));
        assert_eq!(sessions.len(), 1);
        assert!(sessions.has_peer_route(peer_a));
        assert!(
            !sessions.has_peer_route(peer_b),
            "idle peer routes must expire independently of the live session"
        );
        assert_eq!(
            sessions.accept_incoming_at(
                SocketAddr::from(([127, 0, 0, 1], 7003)),
                Some(&control(9, 1)),
                mid + Duration::from_secs(1)
            ),
            Err(ServerUdpReject::Replay),
            "replay window must survive peer-route expiry"
        );
    }
}
