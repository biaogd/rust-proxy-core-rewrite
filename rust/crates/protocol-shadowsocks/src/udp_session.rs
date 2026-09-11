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
            self.evict_oldest_server_replay();
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

    fn evict_oldest_server_replay(&mut self) {
        let oldest = self
            .server_replays
            .iter()
            .min_by_key(|(_, replay)| replay.last_seen)
            .map(|(session_id, _)| *session_id);
        if let Some(session_id) = oldest {
            self.server_replays.remove(&session_id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientUdpReject {
    MissingControl,
    ClientSession,
    ServerSession,
    Replay,
}

/// Per-peer SIP022 server counters used by the test authority and later inbound.
#[derive(Debug, Default)]
pub struct Aead2022ServerSessions {
    entries: HashMap<SocketAddr, ServerUdpSession>,
}

#[derive(Debug)]
struct ServerUdpSession {
    client_session_id: u64,
    server_session_id: u64,
    next_packet_id: u64,
    last_seen: Instant,
}

impl Aead2022ServerSessions {
    /// Builds reply control data for `peer`, creating or rotating the server
    /// session when the client session identifier changes.
    pub fn prepare_reply(
        &mut self,
        peer: SocketAddr,
        incoming: Option<&UdpSocketControlData>,
    ) -> UdpSocketControlData {
        self.reap(Instant::now());
        let Some(incoming) = incoming else {
            return UdpSocketControlData::default();
        };
        if self.entries.len() >= SERVER_SESSION_CAP && !self.entries.contains_key(&peer) {
            self.evict_oldest();
        }
        let session = self
            .entries
            .entry(peer)
            .and_modify(|session| {
                if session.client_session_id != incoming.client_session_id {
                    *session = ServerUdpSession::new(incoming.client_session_id);
                }
            })
            .or_insert_with(|| ServerUdpSession::new(incoming.client_session_id));
        session.last_seen = Instant::now();
        session.next_packet_id = next_packet_id(session.next_packet_id);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = session.client_session_id;
        control.server_session_id = session.server_session_id;
        control.packet_id = session.next_packet_id;
        control.user.clone_from(&incoming.user);
        control
    }

    /// Drops idle peer sessions so the table stays bounded.
    pub fn reap(&mut self, now: Instant) {
        self.entries.retain(|_, session| {
            now.saturating_duration_since(session.last_seen) < SERVER_SESSION_TTL
        });
    }

    /// Number of live peer sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the table currently holds no peer sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, session)| session.last_seen)
            .map(|(peer, _)| *peer);
        if let Some(peer) = oldest {
            self.entries.remove(&peer);
        }
    }
}

impl ServerUdpSession {
    fn new(client_session_id: u64) -> Self {
        Self {
            client_session_id,
            server_session_id: random_session_id(),
            next_packet_id: 0,
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
    fn client_state_expires_and_bounds_server_replay_windows() {
        let mut state = ClientUdpState::new(true);
        let client_session_id = state.next_send_control().client_session_id;
        let t0 = Instant::now();
        for index in 1..=CLIENT_SERVER_SESSION_CAP {
            let reply = client_reply(client_session_id, index as u64, 1);
            let at = t0 + Duration::from_millis(index as u64);
            assert_eq!(state.accept_recv_at(Some(&reply), at), Ok(()));
        }
        let first = client_reply(client_session_id, 1, 1);
        assert_eq!(
            state.accept_recv_at(
                Some(&first),
                t0 + Duration::from_millis(CLIENT_SERVER_SESSION_CAP as u64)
            ),
            Err(ClientUdpReject::Replay)
        );
        let extra = client_reply(client_session_id, CLIENT_SERVER_SESSION_CAP as u64 + 1, 1);
        assert_eq!(
            state.accept_recv_at(
                Some(&extra),
                t0 + Duration::from_millis(CLIENT_SERVER_SESSION_CAP as u64 + 1)
            ),
            Ok(())
        );
        assert_eq!(
            state.accept_recv_at(
                Some(&first),
                t0 + Duration::from_millis(CLIENT_SERVER_SESSION_CAP as u64 + 1)
            ),
            Ok(())
        );

        let mut expired = ClientUdpState::new(true);
        let client_session_id = expired.next_send_control().client_session_id;
        let reply = client_reply(client_session_id, 11, 1);
        assert_eq!(expired.accept_recv_at(Some(&reply), t0), Ok(()));
        assert_eq!(
            expired.accept_recv_at(Some(&reply), t0 + Duration::from_secs(1)),
            Err(ClientUdpReject::Replay)
        );
        assert_eq!(
            expired.accept_recv_at(
                Some(&reply),
                t0 + SERVER_SESSION_TTL + Duration::from_secs(1)
            ),
            Ok(())
        );
    }

    #[test]
    fn server_sessions_isolate_peers_and_rotate_on_client_rebuild() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer_a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let incoming_a = control(11, 1);
        let first_a = sessions.prepare_reply(peer_a, Some(&incoming_a));
        let second_a = sessions.prepare_reply(peer_a, Some(&incoming_a));
        assert_eq!(first_a.client_session_id, 11);
        assert_ne!(first_a.server_session_id, 0);
        assert_eq!(first_a.packet_id, 1);
        assert_eq!(second_a.server_session_id, first_a.server_session_id);
        assert_eq!(second_a.packet_id, 2);
        let incoming_b = control(22, 1);
        let first_b = sessions.prepare_reply(peer_b, Some(&incoming_b));
        assert_ne!(first_b.server_session_id, first_a.server_session_id);
        let rebuilt = control(33, 1);
        let rotated = sessions.prepare_reply(peer_a, Some(&rebuilt));
        assert_eq!(rotated.client_session_id, 33);
        assert_ne!(rotated.server_session_id, first_a.server_session_id);
        assert_eq!(rotated.packet_id, 1);
    }

    #[test]
    fn server_sessions_reap_idle_peers() {
        let mut sessions = Aead2022ServerSessions::default();
        let peer: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let incoming = control(1, 1);
        sessions.prepare_reply(peer, Some(&incoming));
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
            sessions.prepare_reply(peer, Some(&control(u64::from(port), 1)));
        }
        assert_eq!(sessions.len(), SERVER_SESSION_CAP);
        let extra = SocketAddr::from(([127, 0, 0, 1], 60_000));
        sessions.prepare_reply(extra, Some(&control(60_000, 1)));
        assert_eq!(sessions.len(), SERVER_SESSION_CAP);
    }
}
