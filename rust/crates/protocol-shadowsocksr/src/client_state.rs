//! Per-adapter authentication identity, matching Go SSR protocol/base.go authData.

use std::sync::Mutex;

use crate::crypto_util::random_u32_bounded;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthState {
    pub(crate) client_id: [u8; 4],
    pub(crate) connection_id: u32,
}

impl AuthState {
    pub(crate) fn next_connection() -> Self {
        SsrClientState::default().next()
    }
}

/// Authentication state shared by connections to one configured SSR adapter.
/// Do not create a new instance per dial: servers limit active client IDs.
#[derive(Debug)]
pub struct SsrClientState {
    auth: Mutex<AuthState>,
}

impl Default for SsrClientState {
    fn default() -> Self {
        Self {
            auth: Mutex::new(AuthState {
                client_id: [0; 4],
                connection_id: 0,
            }),
        }
    }
}

impl SsrClientState {
    pub(crate) fn next(&self) -> AuthState {
        let mut auth = self
            .auth
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if auth.connection_id == 0 || auth.connection_id > 0xff00_0000 {
            rand::fill(&mut auth.client_id);
            auth.connection_id = random_u32_bounded(0x0100_0000);
        }
        auth.connection_id += 1;
        *auth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_connections_share_identity_without_replaying_ids() {
        let state = SsrClientState::default();
        let ids = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..128).map(|_| scope.spawn(|| state.next())).collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(ids.iter().all(|id| id.client_id == ids[0].client_id));
        let mut sequences: Vec<_> = ids.iter().map(|id| id.connection_id).collect();
        sequences.sort_unstable();
        assert!(sequences.windows(2).all(|pair| pair[1] == pair[0] + 1));
    }

    #[test]
    fn rotates_at_go_connection_id_boundary() {
        let state = SsrClientState::default();
        state.auth.lock().unwrap().connection_id = 0xff00_0000;
        assert_eq!(state.next().connection_id, 0xff00_0001);
        assert!(state.next().connection_id <= 0x0100_0000);
    }
}
