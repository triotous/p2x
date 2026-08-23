use libp2p::PeerId;
use p2x_net::{ConnectionBook, ConnectionId, PathPolicy};
use p2x_protocol::PublicErrorCode;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedPath {
    Direct(ConnectionId),
    Relay(ConnectionId),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupLimits {
    pub max_peer_states: usize,
    pub max_pending_setups: usize,
    pub max_pending_per_server: usize,
}
#[derive(Debug)]
struct PeerState {
    pending: usize,
    active: usize,
    last_used: u64,
    draining: bool,
}
#[derive(Debug)]
pub struct ConnectionManager {
    exchange_peer_id: PeerId,
    policy: PathPolicy,
    limits: SetupLimits,
    peers: HashMap<PeerId, PeerState>,
    sequence: u64,
    pending: usize,
}
impl ConnectionManager {
    pub fn new(exchange_peer_id: PeerId, policy: PathPolicy, limits: SetupLimits) -> Self {
        Self {
            exchange_peer_id,
            policy,
            limits,
            peers: HashMap::new(),
            sequence: 0,
            pending: 0,
        }
    }
    pub fn admit(&mut self, server: PeerId) -> Result<(), PublicErrorCode> {
        if let Some(state) = self.peers.get_mut(&server) {
            if state.draining || state.pending >= self.limits.max_pending_per_server {
                return Err(PublicErrorCode::LimitPeerConnections);
            }
            state.pending += 1;
            self.pending += 1;
            return Ok(());
        }
        if self.pending >= self.limits.max_pending_setups {
            return Err(PublicErrorCode::LimitPeerConnections);
        }
        if self.peers.len() >= self.limits.max_peer_states {
            self.evict()?;
        }
        self.peers.insert(
            server,
            PeerState {
                pending: 1,
                active: 0,
                last_used: self.sequence,
                draining: false,
            },
        );
        self.pending += 1;
        Ok(())
    }
    pub fn release(&mut self, server: PeerId) {
        if let Some(state) = self.peers.get_mut(&server) {
            state.pending = state.pending.saturating_sub(1);
            self.pending = self.pending.saturating_sub(1);
        }
    }
    pub fn mark_active(&mut self, server: PeerId) {
        if let Some(state) = self.peers.get_mut(&server) {
            state.active += 1;
            state.last_used = self.sequence;
        }
    }
    pub fn close_active(&mut self, server: PeerId) {
        if let Some(state) = self.peers.get_mut(&server) {
            state.active = state.active.saturating_sub(1);
        }
    }
    pub fn set_draining(&mut self, server: PeerId, value: bool) {
        if let Some(state) = self.peers.get_mut(&server) {
            state.draining = value;
        }
    }
    pub fn path_policy(&self) -> PathPolicy {
        self.policy
    }
    pub fn exchange_peer_id(&self) -> PeerId {
        self.exchange_peer_id
    }
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    pub fn pending_count(&self) -> usize {
        self.pending
    }
    fn evict(&mut self) -> Result<(), PublicErrorCode> {
        let victim = self
            .peers
            .iter()
            .filter(|(_, state)| state.pending == 0 && state.active == 0 && !state.draining)
            .min_by_key(|(_, state)| state.last_used)
            .map(|(peer, _)| *peer)
            .ok_or(PublicErrorCode::LimitPeerConnections)?;
        self.peers.remove(&victim);
        Ok(())
    }
}
pub struct PeerConnections {
    pub book: ConnectionBook,
    pub relay: Option<ConnectionId>,
    pub direct: Option<ConnectionId>,
    pub last_setup: Option<Instant>,
    pub setup_timeout: Duration,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busy_peers_are_not_evicted_and_limits_release_once() {
        let exchange = PeerId::random();
        let mut manager = ConnectionManager::new(
            exchange,
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 2,
                max_pending_per_server: 1,
            },
        );
        let first = PeerId::random();
        let second = PeerId::random();
        manager.admit(first).unwrap();
        assert_eq!(
            manager.admit(second),
            Err(PublicErrorCode::LimitPeerConnections)
        );
        manager.release(first);
        manager.admit(second).unwrap();
        manager.release(second);
        assert_eq!(manager.pending_count(), 0);
    }
}
