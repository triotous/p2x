use libp2p::{PeerId, core::ConnectedPoint};
use p2x_net::{ConnectionBook, ConnectionId, PathAttempt, PathDecision, PathEvent, PathPolicy};
use p2x_protocol::Capabilities;
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
struct PeerState {
    book: ConnectionBook,
    pending: usize,
    active: usize,
    last_used: u64,
    draining: bool,
}
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
        if self.pending >= self.limits.max_pending_setups {
            return Err(PublicErrorCode::LimitPeerConnections);
        }
        if let Some(state) = self.peers.get_mut(&server) {
            if state.draining || state.pending >= self.limits.max_pending_per_server {
                return Err(PublicErrorCode::LimitPeerConnections);
            }
            state.pending += 1;
            self.pending += 1;
            return Ok(());
        }
        if self.peers.len() >= self.limits.max_peer_states {
            self.evict()?;
        }
        self.peers.insert(
            server,
            PeerState {
                book: ConnectionBook::new(self.exchange_peer_id),
                pending: 1,
                active: 0,
                last_used: self.sequence,
                draining: false,
            },
        );
        self.pending += 1;
        Ok(())
    }
    pub fn release(&mut self, server: PeerId) -> bool {
        let Some(state) = self.peers.get_mut(&server) else {
            return false;
        };
        if state.pending == 0 {
            return false;
        }
        state.pending -= 1;
        self.pending -= 1;
        true
    }
    pub fn mark_active(&mut self, server: PeerId) {
        if let Some(state) = self.peers.get_mut(&server) {
            state.active += 1;
            self.sequence = self.sequence.saturating_add(1);
            state.last_used = self.sequence;
        }
    }

    pub fn on_connection_established(
        &mut self,
        server: PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
        now: Instant,
    ) -> Result<(), p2x_net::connection_book::ConnectionBookError> {
        self.peers
            .get_mut(&server)
            .ok_or(p2x_net::connection_book::ConnectionBookError::Capacity)?
            .book
            .on_connection_established(server, connection_id, endpoint, now)
    }

    pub fn on_connection_closed(
        &mut self,
        server: PeerId,
        connection_id: ConnectionId,
    ) -> Result<(), p2x_net::connection_book::ConnectionBookError> {
        let Some(state) = self.peers.get_mut(&server) else {
            return Ok(());
        };
        state.book.on_connection_closed(server, connection_id)
    }

    pub fn on_dcutr_succeeded(
        &mut self,
        server: PeerId,
        connection_id: ConnectionId,
        now: Instant,
    ) -> Result<(), p2x_net::connection_book::ConnectionBookError> {
        self.peers
            .get_mut(&server)
            .ok_or(p2x_net::connection_book::ConnectionBookError::Capacity)?
            .book
            .on_dcutr_succeeded(server, connection_id, now)
    }

    pub fn close_active(&mut self, server: PeerId) {
        if let Some(state) = self.peers.get_mut(&server) {
            state.active = state.active.saturating_sub(1);
        }
    }

    pub fn direct(&self, server: PeerId) -> Option<ConnectionId> {
        self.peers
            .get(&server)
            .and_then(|state| state.book.direct(server))
            .map(|record| record.connection_id)
    }

    pub fn relay(&self, server: PeerId) -> Option<ConnectionId> {
        self.peers
            .get(&server)
            .and_then(|state| state.book.relay(server))
            .map(|record| record.connection_id)
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

    pub fn begin_path(
        &mut self,
        server: PeerId,
        now: Instant,
    ) -> Result<(PathAttempt, Vec<p2x_net::PathAction>), PublicErrorCode> {
        self.begin_path_with_policy(server, now, self.policy, true)
    }

    pub fn begin_path_at_deadline_with_capabilities(
        &mut self,
        server: PeerId,
        started: Instant,
        setup_deadline: Instant,
        capabilities: Capabilities,
    ) -> Result<(PathAttempt, Vec<p2x_net::PathAction>), PublicErrorCode> {
        let mut policy = self.policy;
        let allow_direct =
            capabilities.contains(Capabilities::DCUTR) && capabilities.direct_transport();
        if !allow_direct {
            policy.direct_preference = Duration::ZERO;
        }
        self.begin_path_at_deadline_with_policy(
            server,
            started,
            setup_deadline,
            policy,
            allow_direct,
        )
    }

    fn begin_path_with_policy(
        &mut self,
        server: PeerId,
        now: Instant,
        policy: PathPolicy,
        allow_direct: bool,
    ) -> Result<(PathAttempt, Vec<p2x_net::PathAction>), PublicErrorCode> {
        self.admit(server)?;
        self.sequence = self.sequence.saturating_add(1);
        let (direct, relay) = self
            .peers
            .get(&server)
            .map(|state| {
                (
                    allow_direct
                        .then(|| state.book.direct(server))
                        .flatten()
                        .map(|record| record.connection_id),
                    state.book.relay(server).map(|record| record.connection_id),
                )
            })
            .unwrap_or((None, None));
        let mut attempt = PathAttempt::with_policy(p2x_net::AttemptId(self.sequence), now, policy);
        let actions = attempt.apply(PathEvent {
            attempt_id: attempt.id,
            now,
            kind: p2x_net::PathEventKind::Begin { relay, direct },
        });
        Ok((attempt, actions))
    }

    pub fn finish_path(&mut self, server: PeerId, selected: Option<PathDecision>) {
        self.release(server);
        if selected.is_some() {
            self.mark_active(server);
        }
    }

    pub fn setup_deadline(&self, started: Instant) -> Instant {
        started + self.policy.setup_budget
    }

    pub fn has_direct(&self, server: PeerId, connection: ConnectionId) -> bool {
        self.direct(server) == Some(connection)
    }

    pub fn begin_path_at_deadline(
        &mut self,
        server: PeerId,
        started: Instant,
        setup_deadline: Instant,
    ) -> Result<(PathAttempt, Vec<p2x_net::PathAction>), PublicErrorCode> {
        self.begin_path_at_deadline_with_policy(server, started, setup_deadline, self.policy, true)
    }

    fn begin_path_at_deadline_with_policy(
        &mut self,
        server: PeerId,
        started: Instant,
        setup_deadline: Instant,
        policy: PathPolicy,
        allow_direct: bool,
    ) -> Result<(PathAttempt, Vec<p2x_net::PathAction>), PublicErrorCode> {
        self.admit(server)?;
        self.sequence = self.sequence.saturating_add(1);
        let (direct, relay) = self
            .peers
            .get(&server)
            .map(|state| {
                (
                    allow_direct
                        .then(|| state.book.direct(server))
                        .flatten()
                        .map(|record| record.connection_id),
                    state.book.relay(server).map(|record| record.connection_id),
                )
            })
            .unwrap_or((None, None));
        let mut attempt = PathAttempt::with_deadline(
            p2x_net::AttemptId(self.sequence),
            started,
            policy,
            setup_deadline,
        );
        let actions = attempt.apply(PathEvent {
            attempt_id: attempt.id,
            now: started,
            kind: p2x_net::PathEventKind::Begin { relay, direct },
        });
        Ok((attempt, actions))
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
        assert!(manager.release(first));
        manager.admit(second).unwrap();
        assert!(manager.release(second));
        assert!(!manager.release(second));
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn global_pending_limit_applies_to_existing_peer() {
        let mut manager = ConnectionManager::new(
            PeerId::random(),
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 1,
                max_pending_per_server: 2,
            },
        );
        let server = PeerId::random();
        manager.admit(server).unwrap();
        assert_eq!(
            manager.admit(server),
            Err(PublicErrorCode::LimitPeerConnections)
        );
        assert!(manager.release(server));
    }

    #[test]
    fn manager_path_uses_confirmed_direct_before_relay() {
        let exchange = PeerId::random();
        let server = PeerId::random();
        let mut manager = ConnectionManager::new(
            exchange,
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 2,
                max_pending_setups: 2,
                max_pending_per_server: 2,
            },
        );
        manager.admit(server).unwrap();
        let now = Instant::now();
        let relay = ConnectionId::new_unchecked(1);
        let direct = ConnectionId::new_unchecked(2);
        let relay_address = format!("/ip4/127.0.0.1/tcp/1/p2p/{exchange}/p2p-circuit/p2p/{server}")
            .parse()
            .unwrap();
        let direct_address = format!("/ip4/127.0.0.1/tcp/2/p2p/{server}")
            .parse()
            .unwrap();
        let endpoint = |address| libp2p::core::ConnectedPoint::Dialer {
            address,
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        };
        manager
            .on_connection_established(server, relay, &endpoint(relay_address), now)
            .unwrap();
        manager
            .on_connection_established(server, direct, &endpoint(direct_address), now)
            .unwrap();
        manager.on_dcutr_succeeded(server, direct, now).unwrap();
        let (attempt, actions) = manager.begin_path(server, now).unwrap();
        assert_eq!(
            attempt.state,
            p2x_net::PathState::Committed {
                decision: PathDecision::Direct(direct),
                relay_id: Some(relay),
                relay_fallback_used: false
            }
        );
        assert_eq!(
            actions,
            vec![p2x_net::PathAction::OpenExact { connection: direct }]
        );
        manager.finish_path(server, Some(PathDecision::Direct(direct)));
        manager.finish_path(server, None);
        assert_eq!(manager.pending_count(), 0);
    }

    #[test]
    fn missing_direct_capability_commits_relay_immediately() {
        let exchange = PeerId::random();
        let server = PeerId::random();
        let mut manager = ConnectionManager::new(
            exchange,
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 1,
                max_pending_per_server: 1,
            },
        );
        let now = Instant::now();
        let relay = ConnectionId::new_unchecked(1);
        let address = format!("/ip4/127.0.0.1/tcp/1/p2p/{exchange}/p2p-circuit/p2p/{server}")
            .parse()
            .unwrap();
        let endpoint = libp2p::core::ConnectedPoint::Dialer {
            address,
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        };
        manager.admit(server).unwrap();
        assert!(manager.release(server));
        manager
            .on_connection_established(server, relay, &endpoint, now)
            .unwrap();
        let (attempt, actions) = manager
            .begin_path_at_deadline_with_capabilities(
                server,
                now,
                now + Duration::from_secs(20),
                Capabilities::RELAY_V2,
            )
            .unwrap();
        assert_eq!(
            attempt.state,
            p2x_net::PathState::Committed {
                decision: PathDecision::Relay(relay),
                relay_id: Some(relay),
                relay_fallback_used: false,
            }
        );
        assert_eq!(
            actions,
            vec![p2x_net::PathAction::OpenExact { connection: relay }]
        );
    }

    #[test]
    fn caller_deadline_is_preserved() {
        let now = Instant::now();
        let manager = ConnectionManager::new(
            PeerId::random(),
            PathPolicy::new(Duration::from_millis(10), Duration::from_secs(20)).unwrap(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 1,
                max_pending_per_server: 1,
            },
        );
        let deadline = now + Duration::from_millis(250);
        assert_eq!(manager.setup_deadline(now), now + Duration::from_secs(20));
        assert!(deadline < manager.setup_deadline(now));
    }
}
