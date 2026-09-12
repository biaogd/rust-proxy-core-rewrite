//! boringtun `Tunn` wrapper: encapsulate/decapsulate plus reserved-byte overlay.

use std::net::SocketAddr;
use std::sync::Mutex;

use defguard_boringtun::noise::errors::WireGuardError;
use defguard_boringtun::noise::{Tunn, TunnResult};
use defguard_boringtun::x25519::{PublicKey, StaticSecret};

use crate::WireGuardProtocolError;

/// Outcome of one encapsulate/decapsulate/timer step.
#[derive(Debug)]
pub enum TunnelAction {
    /// Nothing to send.
    Done,
    /// Encrypted (or handshake) UDP datagram to the peer.
    SendUdp(Vec<u8>),
    /// Decrypted inner IP packet for the userspace stack.
    RecvIp(Vec<u8>),
    /// Session keys expired; the reactor must clear `established` and handshake.
    Expired,
}

/// Single-peer `WireGuard` session (initiator or responder).
pub struct NoiseTunnel {
    tunn: Mutex<Tunn>,
    reserved: [u8; 3],
}

impl NoiseTunnel {
    /// Constructs a boringtun session for one peer.
    ///
    /// # Errors
    ///
    /// Returns when boringtun rejects the key material.
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        reserved: [u8; 3],
        index: u32,
    ) -> Result<Self, WireGuardProtocolError> {
        let tunn = Tunn::new(
            StaticSecret::from(private_key),
            PublicKey::from(peer_public_key),
            preshared_key,
            persistent_keepalive,
            index,
            None,
        );
        Ok(Self {
            tunn: Mutex::new(tunn),
            reserved,
        })
    }

    /// Replaces the boringtun session after `ConnectionExpired`.
    pub fn reset(
        &self,
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
    ) {
        let tunn = Tunn::new(
            StaticSecret::from(private_key),
            PublicKey::from(peer_public_key),
            preshared_key,
            persistent_keepalive,
            index,
            None,
        );
        *self.lock() = tunn;
    }

    /// Handshake initiation (force retries an in-progress attempt).
    pub fn format_handshake(&self, force: bool) -> TunnelAction {
        let mut output = vec![0_u8; 2048];
        let mut tunn = self.lock();
        match tunn.format_handshake_initiation(&mut output, force) {
            TunnResult::WriteToNetwork(packet) => owned_udp(packet, self.reserved),
            other => map_result(other, self.reserved),
        }
    }

    /// `true` when boringtun already has a completed session that is not expired.
    #[must_use]
    pub fn has_session(&self) -> bool {
        let tunn = self.lock();
        !tunn.is_expired() && tunn.stats().0.is_some()
    }

    /// Starts a handshake only when no session exists. `None` means a session
    /// is already live — callers must not `format_handshake(true)`, which would
    /// clobber keys the reactor just installed.
    pub fn format_handshake_unless_session(&self) -> Option<TunnelAction> {
        let mut output = vec![0_u8; 2048];
        let mut tunn = self.lock();
        if !tunn.is_expired() && tunn.stats().0.is_some() {
            return None;
        }
        Some(match tunn.format_handshake_initiation(&mut output, true) {
            TunnResult::WriteToNetwork(packet) => owned_udp(packet, self.reserved),
            other => map_result(other, self.reserved),
        })
    }

    /// Encrypts an inner IP packet (empty `src` sends a keepalive when a session exists).
    pub fn encapsulate(&self, src: &[u8]) -> TunnelAction {
        let mut output = vec![0_u8; src.len().saturating_add(64).max(2048)];
        let mut tunn = self.lock();
        match tunn.encapsulate(src, &mut output) {
            TunnResult::WriteToNetwork(packet) => owned_udp(packet, self.reserved),
            other => map_result(other, self.reserved),
        }
    }

    /// Decrypts one UDP datagram. Call again with an empty datagram to drain
    /// follow-up handshake packets (boringtun's documented loop).
    pub fn decapsulate(&self, src: Option<SocketAddr>, datagram: &[u8]) -> TunnelAction {
        let mut output = vec![0_u8; datagram.len().saturating_add(64).max(2048)];
        let mut packet = datagram.to_vec();
        zero_reserved(&mut packet);
        let mut tunn = self.lock();
        match tunn.decapsulate(src.map(|addr| addr.ip()), &packet, &mut output) {
            TunnResult::WriteToNetwork(packet) => owned_udp(packet, self.reserved),
            other => map_result(other, self.reserved),
        }
    }

    /// Periodic rekey / keepalive / handshake retry.
    pub fn update_timers(&self) -> TunnelAction {
        let mut output = vec![0_u8; 2048];
        let mut tunn = self.lock();
        match tunn.update_timers(&mut output) {
            TunnResult::WriteToNetwork(packet) => owned_udp(packet, self.reserved),
            other => map_result(other, self.reserved),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tunn> {
        self.tunn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn owned_udp(packet: &[u8], reserved: [u8; 3]) -> TunnelAction {
    let mut datagram = packet.to_vec();
    apply_reserved(&mut datagram, reserved);
    TunnelAction::SendUdp(datagram)
}

fn map_result(result: TunnResult<'_>, reserved: [u8; 3]) -> TunnelAction {
    match result {
        TunnResult::Err(WireGuardError::ConnectionExpired) => TunnelAction::Expired,
        TunnResult::Done | TunnResult::Err(_) => TunnelAction::Done,
        TunnResult::WriteToNetwork(packet) => {
            let mut datagram = packet.to_vec();
            apply_reserved(&mut datagram, reserved);
            TunnelAction::SendUdp(datagram)
        }
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            TunnelAction::RecvIp(packet.to_vec())
        }
    }
}

fn apply_reserved(packet: &mut [u8], reserved: [u8; 3]) {
    if packet.len() >= 4 && reserved != [0, 0, 0] {
        packet[1] = reserved[0];
        packet[2] = reserved[1];
        packet[3] = reserved[2];
    }
}

fn zero_reserved(packet: &mut [u8]) {
    if packet.len() >= 4 {
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::decode_key;
    use defguard_boringtun::x25519::{PublicKey as DalekPublic, StaticSecret};

    fn pair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::from([7_u8; 32]);
        let public = DalekPublic::from(&secret);
        (*secret.as_bytes(), *public.as_bytes())
    }

    #[test]
    fn handshake_then_ip_roundtrip() {
        let (alice_priv, alice_pub) = pair();
        let bob_secret = StaticSecret::from([9_u8; 32]);
        let bob_pub = DalekPublic::from(&bob_secret).to_bytes();
        let bob_priv = bob_secret.to_bytes();

        let alice = NoiseTunnel::new(alice_priv, bob_pub, None, None, [0; 3], 1).expect("alice");
        let bob = NoiseTunnel::new(bob_priv, alice_pub, None, None, [0; 3], 2).expect("bob");

        let TunnelAction::SendUdp(init) = alice.format_handshake(true) else {
            panic!("expected handshake initiation");
        };
        let TunnelAction::SendUdp(resp) = bob.decapsulate(None, &init) else {
            panic!("expected handshake response");
        };
        // Drain initiator completion / cookie.
        let _ = alice.decapsulate(None, &resp);
        while let TunnelAction::SendUdp(extra) = alice.decapsulate(None, &[]) {
            let _ = bob.decapsulate(None, &extra);
        }
        while let TunnelAction::SendUdp(extra) = bob.decapsulate(None, &[]) {
            let _ = alice.decapsulate(None, &extra);
        }

        // Minimal IPv4 header (20 bytes) + 4 bytes payload; checksums ignored by boringtun.
        let mut ip = vec![
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 0, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1,
        ];
        ip.extend_from_slice(&[1, 2, 3, 4]);
        let TunnelAction::SendUdp(wrapped) = alice.encapsulate(&ip) else {
            panic!("expected transport datagram after handshake");
        };
        assert_eq!(wrapped.first().copied(), Some(4));
        match bob.decapsulate(None, &wrapped) {
            TunnelAction::RecvIp(plain) => assert_eq!(plain, ip),
            other => panic!("expected inner IP, got {other:?}"),
        }
        assert!(alice.has_session());
        assert!(
            alice.format_handshake_unless_session().is_none(),
            "forcing a handshake after the session exists would clobber it"
        );
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_key("not-a-key").is_err());
    }
}
