use libp2p::swarm::ConnectionId as Libp2pConnectionId;
use libp2p::{Multiaddr, PeerId, core::ConnectedPoint, multiaddr::Protocol};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub type ConnectionId = Libp2pConnectionId;
pub const MAX_PENDING_DCUTR: usize = 128;
pub const MAX_CONNECTION_LIFECYCLES: usize = 512;
pub const TOMBSTONE_TTL: Duration = Duration::from_secs(20);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    Tcp,
    Quic,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathKind {
    Direct(TransportKind),
    Relay { exchange_peer_id: PeerId },
    UnknownDirect,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRole {
    Dialer,
    Listener,
}
#[derive(Clone, Debug)]
pub struct ConnectionRecord {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub endpoint_role: EndpointRole,
    pub endpoint_address: Multiaddr,
    pub path: PathKind,
    pub sequence: u64,
    pub established_at: Instant,
    pub closing: bool,
    pub dcutr_confirmed: bool,
    pub last_ping: Option<Instant>,
}
pub struct ConnectionBook {
    expected_exchange: Option<PeerId>,
    next_sequence: u64,
    records: HashMap<(PeerId, ConnectionId), ConnectionRecord>,
    pending_dcutr: HashMap<(PeerId, ConnectionId), Instant>,
    tombstones: HashMap<(PeerId, ConnectionId), Instant>,
}
impl Default for ConnectionBook {
    fn default() -> Self {
        Self::new(None)
    }
}
impl ConnectionBook {
    pub fn new(expected_exchange: Option<PeerId>) -> Self {
        Self {
            expected_exchange,
            next_sequence: 0,
            records: HashMap::new(),
            pending_dcutr: HashMap::new(),
            tombstones: HashMap::new(),
        }
    }
    pub fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
        now: Instant,
    ) {
        self.sweep(now);
        let key = (peer_id, connection_id);
        if self.tombstones.contains_key(&key) {
            return;
        }
        if matches!(classify_connected_point(endpoint), PathKind::Relay { .. })
            && !self.valid_relay(endpoint.get_remote_address())
        {
            return;
        }
        if let Some(record) = self.records.get_mut(&key) {
            record.closing = false;
            return;
        }
        if self.records.len() >= MAX_CONNECTION_LIFECYCLES {
            return;
        }
        self.next_sequence += 1;
        let confirmed = self.pending_dcutr.remove(&key).is_some();
        self.records.insert(
            key,
            ConnectionRecord {
                peer_id,
                connection_id,
                endpoint_role: if endpoint.is_dialer() {
                    EndpointRole::Dialer
                } else {
                    EndpointRole::Listener
                },
                endpoint_address: endpoint.get_remote_address().clone(),
                path: classify_connected_point(endpoint),
                sequence: self.next_sequence,
                established_at: now,
                closing: false,
                dcutr_confirmed: confirmed,
                last_ping: None,
            },
        );
    }
    pub fn on_dcutr_succeeded(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        now: Instant,
    ) {
        self.sweep(now);
        let key = (peer_id, connection_id);
        if self.tombstones.contains_key(&key) {
            return;
        }
        if let Some(record) = self.records.get_mut(&key) {
            if matches!(record.path, PathKind::Direct(_)) {
                record.dcutr_confirmed = true;
            }
            return;
        }
        Self::insert_bounded(&mut self.pending_dcutr, key, now + TOMBSTONE_TTL);
    }
    pub fn on_connection_closed(&mut self, peer_id: PeerId, connection_id: ConnectionId) {
        self.on_connection_closed_at(peer_id, connection_id, Instant::now());
    }
    pub fn on_connection_closed_at(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        now: Instant,
    ) {
        let key = (peer_id, connection_id);
        self.records.remove(&key);
        self.pending_dcutr.remove(&key);
        self.sweep(now);
        if self.tombstones.len() >= MAX_CONNECTION_LIFECYCLES
            && let Some(oldest) = self
                .tombstones
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(key, _)| *key)
        {
            self.tombstones.remove(&oldest);
        }
        self.tombstones.insert(key, now + TOMBSTONE_TTL);
    }
    pub fn mark_ping(&mut self, peer_id: PeerId, connection_id: ConnectionId, now: Instant) {
        if let Some(r) = self.records.get_mut(&(peer_id, connection_id)) {
            r.last_ping = Some(now);
        }
    }
    pub fn direct(&self, peer_id: PeerId) -> Option<&ConnectionRecord> {
        self.records
            .values()
            .filter(|r| {
                r.peer_id == peer_id
                    && !r.closing
                    && r.dcutr_confirmed
                    && matches!(r.path, PathKind::Direct(_))
            })
            .min_by_key(|r| (transport_rank(&r.path), r.sequence))
    }
    pub fn get(&self, peer_id: PeerId, connection_id: ConnectionId) -> Option<&ConnectionRecord> {
        self.records.get(&(peer_id, connection_id))
    }
    pub fn is_direct(&self, peer_id: PeerId, connection_id: ConnectionId) -> bool {
        self.get(peer_id, connection_id).is_some_and(|r| {
            matches!(r.path, PathKind::Direct(_)) && !r.closing && r.dcutr_confirmed
        })
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &ConnectionRecord> {
        self.records.values()
    }
    pub fn sweep(&mut self, now: Instant) {
        self.pending_dcutr.retain(|_, d| *d > now);
        self.tombstones.retain(|_, d| *d > now);
    }
    pub fn pending_count(&self) -> usize {
        self.pending_dcutr.len()
    }
    pub fn tombstone_count(&self) -> usize {
        self.tombstones.len()
    }
    fn valid_relay(&self, address: &Multiaddr) -> bool {
        self.expected_exchange.is_some_and(|expected| {
            address
                .iter()
                .any(|p| matches!(p, Protocol::P2p(peer) if peer == expected))
        })
    }
    fn insert_bounded(
        map: &mut HashMap<(PeerId, ConnectionId), Instant>,
        key: (PeerId, ConnectionId),
        expiry: Instant,
    ) {
        if map.len() >= MAX_PENDING_DCUTR
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(key, _)| *key)
        {
            map.remove(&oldest);
        }
        map.insert(key, expiry);
    }
}
fn transport_rank(path: &PathKind) -> u8 {
    match path {
        PathKind::Direct(TransportKind::Quic) => 0,
        PathKind::Direct(TransportKind::Tcp) => 1,
        _ => 2,
    }
}
pub fn classify_connected_point(endpoint: &ConnectedPoint) -> PathKind {
    let address = endpoint.get_remote_address();
    if endpoint.is_relayed() {
        if let Some(exchange) = address.iter().find_map(|p| {
            if let Protocol::P2p(peer) = p {
                Some(peer)
            } else {
                None
            }
        }) {
            return PathKind::Relay {
                exchange_peer_id: exchange,
            };
        }
        return PathKind::UnknownDirect;
    }
    PathKind::Direct(classify_address(address))
}
pub fn classify_path(address: &Multiaddr) -> PathKind {
    if address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        if let Some(exchange) = address.iter().find_map(|p| {
            if let Protocol::P2p(peer) = p {
                Some(peer)
            } else {
                None
            }
        }) {
            return PathKind::Relay {
                exchange_peer_id: exchange,
            };
        }
        return PathKind::UnknownDirect;
    }
    PathKind::Direct(classify_address(address))
}
pub fn classify_address(address: &Multiaddr) -> TransportKind {
    if address.iter().any(|p| matches!(p, Protocol::QuicV1)) {
        TransportKind::Quic
    } else if address.iter().any(|p| matches!(p, Protocol::Tcp(_))) {
        TransportKind::Tcp
    } else {
        TransportKind::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> PeerId {
        PeerId::random()
    }
    fn id(n: u8) -> ConnectionId {
        ConnectionId::new_unchecked(n as usize)
    }
    fn endpoint(s: &str) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: s.parse().unwrap(),
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        }
    }
    #[test]
    fn reordered_dcutr_is_consumed_and_unconfirmed_is_excluded() {
        let p = peer();
        let mut b = ConnectionBook::default();
        let n = Instant::now();
        b.on_dcutr_succeeded(p, id(1), n);
        b.on_connection_established(p, id(1), &endpoint("/ip4/127.0.0.1/tcp/1"), n);
        assert!(b.is_direct(p, id(1)));
        b.on_connection_established(p, id(2), &endpoint("/ip4/127.0.0.1/tcp/2"), n);
        assert!(!b.is_direct(p, id(2)));
    }
    #[test]
    fn close_tombstones_late_success() {
        let p = peer();
        let mut b = ConnectionBook::default();
        let n = Instant::now();
        b.on_connection_established(p, id(1), &endpoint("/ip4/127.0.0.1/udp/1/quic-v1"), n);
        b.on_connection_closed_at(p, id(1), n);
        b.on_dcutr_succeeded(p, id(1), n);
        assert!(b.get(p, id(1)).is_none());
    }
    #[test]
    fn direct_prefers_quic_then_oldest() {
        let p = peer();
        let mut b = ConnectionBook::default();
        let n = Instant::now();
        b.on_connection_established(p, id(1), &endpoint("/ip4/127.0.0.1/tcp/1"), n);
        b.on_dcutr_succeeded(p, id(1), n);
        b.on_connection_established(p, id(2), &endpoint("/ip4/127.0.0.1/udp/1/quic-v1"), n);
        b.on_dcutr_succeeded(p, id(2), n);
        assert_eq!(b.direct(p).unwrap().connection_id, id(2));
    }
    #[test]
    fn caps_are_evicted_and_sweep_expires() {
        let p = peer();
        let mut b = ConnectionBook::default();
        let n = Instant::now();
        for i in 0..=MAX_PENDING_DCUTR {
            b.on_dcutr_succeeded(p, id((i % 255) as u8), n);
        }
        assert_eq!(b.pending_count(), MAX_PENDING_DCUTR);
        b.sweep(n + TOMBSTONE_TTL);
        assert_eq!(b.pending_count(), 0);
    }
}
