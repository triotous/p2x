use libp2p::{PeerId, core::ConnectedPoint};
use p2x_net::{ConnectionBook, ConnectionId, PathAttempt, PathDecision, PathEvent, PathPolicy};
use p2x_protocol::{Capabilities, PublicErrorCode, RegistrationRevision};
use std::{
    collections::{HashMap, HashSet},
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
    pub max_streams_per_server: usize,
}
struct PeerState {
    book: ConnectionBook,
    pending: usize,
    active: usize,
    last_used: u64,
    draining: bool,
    relay_dial_generation: u64,
    relay_dial_active: bool,
    dcutr_generation: u64,
    waiters: HashSet<u64>,
    metadata: Option<ResolvedPeerMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPeerMetadata {
    pub relay_addresses: Vec<Vec<u8>>,
    pub capabilities: Capabilities,
    pub registration_revision: RegistrationRevision,
    pub registration_expires_at: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionSetupAction {
    DialRelay { generation: u64 },
    JoinRelayDial { generation: u64 },
    ReuseRelay { connection: ConnectionId },
    StartDcutr { generation: u64 },
    Close { connection: ConnectionId },
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
            if state.draining
                || state.pending >= self.limits.max_pending_per_server
                || state.pending.saturating_add(state.active)
                    >= self
                        .limits
                        .max_streams_per_server
                        .max(self.limits.max_pending_per_server)
            {
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
                relay_dial_generation: 0,
                relay_dial_active: false,
                dcutr_generation: 0,
                waiters: HashSet::new(),
                metadata: None,
            },
        );
        self.pending += 1;
        Ok(())
    }
    pub fn begin_relay_setup(
        &mut self,
        server: PeerId,
        waiter_id: u64,
    ) -> Result<ConnectionSetupAction, PublicErrorCode> {
        self.admit(server)?;
        let state = self.peers.get_mut(&server).expect("admitted peer exists");
        state.waiters.insert(waiter_id);
        if let Some(connection) = state.book.relay(server).map(|record| record.connection_id) {
            return Ok(ConnectionSetupAction::ReuseRelay { connection });
        }
        if state.relay_dial_active {
            return Ok(ConnectionSetupAction::JoinRelayDial {
                generation: state.relay_dial_generation,
            });
        }
        state.relay_dial_generation = state.relay_dial_generation.saturating_add(1);
        state.relay_dial_active = true;
        Ok(ConnectionSetupAction::DialRelay {
            generation: state.relay_dial_generation,
        })
    }

    pub fn relay_dial_finished(&mut self, server: PeerId, generation: u64) -> bool {
        let Some(state) = self.peers.get_mut(&server) else {
            return false;
        };
        if state.relay_dial_generation != generation {
            return false;
        }
        state.relay_dial_active = false;
        true
    }

    pub fn relay_connection_ready(&mut self, server: PeerId) -> bool {
        let Some(state) = self.peers.get_mut(&server) else {
            return false;
        };
        let was_active = state.relay_dial_active;
        state.relay_dial_active = false;
        was_active
    }

    pub fn update_metadata(
        &mut self,
        server: PeerId,
        metadata: ResolvedPeerMetadata,
    ) -> Result<(), PublicErrorCode> {
        let state = self
            .peers
            .get_mut(&server)
            .ok_or(PublicErrorCode::LimitPeerConnections)?;
        if state
            .metadata
            .as_ref()
            .is_some_and(|current| current.registration_revision != metadata.registration_revision)
        {
            state.relay_dial_generation = state.relay_dial_generation.saturating_add(1);
            state.relay_dial_active = false;
            state.dcutr_generation = state.dcutr_generation.saturating_add(1);
        }
        state.metadata = Some(metadata);
        Ok(())
    }

    pub fn metadata(&self, server: PeerId, now: i64) -> Option<&ResolvedPeerMetadata> {
        self.peers
            .get(&server)
            .and_then(|state| state.metadata.as_ref())
            .filter(|metadata| metadata.registration_expires_at > now)
    }

    pub fn begin_dcutr(&mut self, server: PeerId) -> Option<ConnectionSetupAction> {
        let state = self.peers.get_mut(&server)?;
        if !state.metadata.as_ref().is_some_and(|metadata| {
            metadata.capabilities.contains(Capabilities::DCUTR)
                && metadata.capabilities.direct_transport()
        }) {
            return None;
        }
        if state.book.direct(server).is_some() {
            return None;
        }
        state.dcutr_generation = state.dcutr_generation.saturating_add(1);
        Some(ConnectionSetupAction::StartDcutr {
            generation: state.dcutr_generation,
        })
    }

    pub fn generation_current(&self, server: PeerId, generation: u64) -> bool {
        self.peers
            .get(&server)
            .is_some_and(|state| state.relay_dial_generation == generation)
    }

    pub fn release_waiter(&mut self, server: PeerId, waiter_id: u64) -> bool {
        self.peers
            .get_mut(&server)
            .is_some_and(|state| state.waiters.remove(&waiter_id))
    }

    pub fn track_waiter(&mut self, server: PeerId, waiter_id: u64) -> bool {
        self.peers
            .get_mut(&server)
            .is_some_and(|state| state.waiters.insert(waiter_id))
    }

    pub fn pool_close_actions(&mut self, server: PeerId) -> Vec<ConnectionSetupAction> {
        let Some(state) = self.peers.get_mut(&server) else {
            return Vec::new();
        };
        let mut keep = HashSet::new();
        if let Some(record) = state.book.relay(server) {
            keep.insert(record.connection_id);
        }
        for transport in [
            p2x_net::connection_book::TransportKind::Quic,
            p2x_net::connection_book::TransportKind::Tcp,
        ] {
            if let Some(record) = state.book.iter().find(|record| {
                record.dcutr_confirmed
                    && record.path == p2x_net::connection_book::PathKind::Direct(transport)
            }) {
                keep.insert(record.connection_id);
            }
        }
        let surplus = state
            .book
            .iter()
            .filter(|record| !keep.contains(&record.connection_id) && !record.closing)
            .map(|record| record.connection_id)
            .collect::<Vec<_>>();
        surplus
            .into_iter()
            .filter(|connection| state.book.mark_closing(server, *connection))
            .map(|connection| ConnectionSetupAction::Close { connection })
            .collect()
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

    pub fn waiter_count(&self, server: PeerId) -> usize {
        self.peers
            .get(&server)
            .map_or(0, |state| state.waiters.len())
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
    pub fn has_peer(&self, server: PeerId) -> bool {
        self.peers.contains_key(&server)
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
        let actions = self.coordinate_relay_dial(server, actions);
        Ok((attempt, actions))
    }

    pub fn finish_path(&mut self, server: PeerId, selected: Option<PathDecision>) {
        self.release(server);
        if selected.is_some() {
            self.mark_active(server);
        }
    }

    pub fn admit_stream(&mut self, server: PeerId) -> Result<(), PublicErrorCode> {
        let state = self
            .peers
            .get_mut(&server)
            .ok_or(PublicErrorCode::LimitPeerConnections)?;
        if state.active >= self.limits.max_streams_per_server {
            return Err(PublicErrorCode::LimitProxyStreams);
        }
        state.active += 1;
        Ok(())
    }

    pub fn release_stream(&mut self, server: PeerId) -> bool {
        let Some(state) = self.peers.get_mut(&server) else {
            return false;
        };
        if state.active == 0 {
            return false;
        }
        state.active -= 1;
        true
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
        let actions = self.coordinate_relay_dial(server, actions);
        Ok((attempt, actions))
    }

    fn coordinate_relay_dial(
        &mut self,
        server: PeerId,
        mut actions: Vec<p2x_net::PathAction>,
    ) -> Vec<p2x_net::PathAction> {
        if !actions
            .iter()
            .any(|action| matches!(action, p2x_net::PathAction::DialRelay))
        {
            return actions;
        }
        let state = self.peers.get_mut(&server).expect("admitted peer exists");
        if state.relay_dial_active {
            actions.retain(|action| !matches!(action, p2x_net::PathAction::DialRelay));
        } else {
            state.relay_dial_generation = state.relay_dial_generation.saturating_add(1);
            state.relay_dial_active = true;
        }
        actions
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
                max_streams_per_server: 1,
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
                max_streams_per_server: 2,
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
    fn relay_setup_singleflight_reuses_one_generation() {
        let server = PeerId::random();
        let mut manager = ConnectionManager::new(
            PeerId::random(),
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 4,
                max_pending_per_server: 4,
                max_streams_per_server: 4,
            },
        );
        assert_eq!(
            manager.begin_relay_setup(server, 1).unwrap(),
            ConnectionSetupAction::DialRelay { generation: 1 }
        );
        assert_eq!(
            manager.begin_relay_setup(server, 2).unwrap(),
            ConnectionSetupAction::JoinRelayDial { generation: 1 }
        );
        assert!(!manager.relay_dial_finished(server, 2));
        assert!(manager.relay_dial_finished(server, 1));
        assert_eq!(manager.waiter_count(server), 2);
        assert!(manager.release_waiter(server, 1));
        assert!(!manager.release_waiter(server, 1));
    }

    #[test]
    fn path_setup_emits_one_relay_dial_for_joined_waiters() {
        let server = PeerId::random();
        let mut manager = ConnectionManager::new(
            PeerId::random(),
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 4,
                max_pending_per_server: 4,
                max_streams_per_server: 4,
            },
        );
        let (_, first) = manager.begin_path(server, Instant::now()).unwrap();
        let (_, joined) = manager.begin_path(server, Instant::now()).unwrap();
        assert!(
            first
                .iter()
                .any(|action| matches!(action, p2x_net::PathAction::DialRelay))
        );
        assert!(
            !joined
                .iter()
                .any(|action| matches!(action, p2x_net::PathAction::DialRelay))
        );
        assert!(manager.relay_connection_ready(server));
        assert!(!manager.relay_connection_ready(server));
    }

    #[test]
    fn registration_revision_replacement_invalidates_setup_generations() {
        let server = PeerId::random();
        let mut manager = ConnectionManager::new(
            PeerId::random(),
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 4,
                max_pending_per_server: 4,
                max_streams_per_server: 4,
            },
        );
        manager.admit(server).unwrap();
        let first = ResolvedPeerMetadata {
            relay_addresses: vec![vec![1]],
            capabilities: Capabilities::RELAY_V2,
            registration_revision: RegistrationRevision::new(1).unwrap(),
            registration_expires_at: 10,
        };
        manager.update_metadata(server, first.clone()).unwrap();
        assert_eq!(manager.metadata(server, 9), Some(&first));
        assert!(manager.metadata(server, 10).is_none());
        let replacement = ResolvedPeerMetadata {
            registration_revision: RegistrationRevision::new(2).unwrap(),
            registration_expires_at: 20,
            ..first
        };
        manager
            .update_metadata(server, replacement.clone())
            .unwrap();
        assert_eq!(manager.metadata(server, 19), Some(&replacement));
    }

    #[test]
    fn stale_dial_generation_is_ignored() {
        let server = PeerId::random();
        let mut manager = ConnectionManager::new(
            PeerId::random(),
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 2,
                max_pending_per_server: 2,
                max_streams_per_server: 2,
            },
        );
        assert!(manager.begin_relay_setup(server, 1).is_ok());
        assert!(!manager.generation_current(server, 2));
        assert!(!manager.relay_dial_finished(server, 2));
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
                max_streams_per_server: 2,
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
    fn pool_close_marks_surplus_connections_before_dispatch() {
        let exchange = PeerId::random();
        let server = PeerId::random();
        let mut manager = ConnectionManager::new(
            exchange,
            PathPolicy::default(),
            SetupLimits {
                max_peer_states: 1,
                max_pending_setups: 2,
                max_pending_per_server: 2,
                max_streams_per_server: 2,
            },
        );
        manager.admit(server).unwrap();
        let now = Instant::now();
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let relay = format!("/ip4/127.0.0.1/tcp/1/p2p/{exchange}/p2p-circuit/p2p/{server}")
            .parse::<libp2p::Multiaddr>()
            .unwrap();
        let endpoint = |address| libp2p::core::ConnectedPoint::Dialer {
            address,
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        };
        manager
            .on_connection_established(server, first, &endpoint(relay.clone()), now)
            .unwrap();
        manager
            .on_connection_established(server, second, &endpoint(relay), now)
            .unwrap();
        let closes = manager.pool_close_actions(server);
        assert_eq!(closes.len(), 1);
        assert!(manager.relay(server) == Some(first) || manager.relay(server) == Some(second));
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
                max_streams_per_server: 1,
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
                max_streams_per_server: 1,
            },
        );
        let deadline = now + Duration::from_millis(250);
        assert_eq!(manager.setup_deadline(now), now + Duration::from_secs(20));
        assert!(deadline < manager.setup_deadline(now));
    }
}
