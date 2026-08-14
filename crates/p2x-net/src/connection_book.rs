use libp2p::{Multiaddr, PeerId, multiaddr::Protocol, swarm::ConnectionId as Libp2pConnectionId};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

pub type ConnectionId = Libp2pConnectionId;
pub const MAX_PENDING_DCUTR: usize = 128;

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

#[derive(Clone, Debug)]
pub struct ConnectionRecord {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub path: PathKind,
    pub sequence: u64,
    pub established_at: Instant,
    pub closing: bool,
    pub dcutr_confirmed: bool,
    pub last_ping: Option<Instant>,
}

#[derive(Default)]
pub struct ConnectionBook {
    next_sequence: u64,
    records: HashMap<(PeerId, ConnectionId), ConnectionRecord>,
    pending_dcutr: HashMap<(PeerId, ConnectionId), Instant>,
    tombstones: HashSet<(PeerId, ConnectionId)>,
}
impl ConnectionBook {
    pub fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        address: &Multiaddr,
        now: Instant,
    ) {
        self.expire_pending(now);
        let key = (peer_id, connection_id);
        if self.tombstones.contains(&key) {
            return;
        }
        if let Some(record) = self.records.get_mut(&key) {
            record.closing = false;
            return;
        }
        self.next_sequence += 1;
        let confirmed = self.pending_dcutr.remove(&key).is_some();
        self.records.insert(
            key,
            ConnectionRecord {
                peer_id,
                connection_id,
                path: classify_path(address),
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
        self.expire_pending(now);
        let key = (peer_id, connection_id);
        if self.tombstones.contains(&key) {
            return;
        }
        if let Some(record) = self.records.get_mut(&key) {
            if matches!(record.path, PathKind::Direct(_)) {
                record.dcutr_confirmed = true;
            }
            return;
        }
        if self.pending_dcutr.len() < MAX_PENDING_DCUTR {
            self.pending_dcutr
                .insert(key, now + Duration::from_secs(20));
        }
    }
    pub fn on_connection_closed(&mut self, peer_id: PeerId, connection_id: ConnectionId) {
        let key = (peer_id, connection_id);
        self.records.remove(&key);
        self.pending_dcutr.remove(&key);
        self.tombstones.insert(key);
    }
    pub fn mark_ping(&mut self, peer_id: PeerId, connection_id: ConnectionId, now: Instant) {
        if let Some(record) = self.records.get_mut(&(peer_id, connection_id)) {
            record.last_ping = Some(now);
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
    fn expire_pending(&mut self, now: Instant) {
        self.pending_dcutr.retain(|_, deadline| *deadline > now);
    }
}
fn transport_rank(path: &PathKind) -> u8 {
    match path {
        PathKind::Direct(TransportKind::Quic) => 0,
        PathKind::Direct(TransportKind::Tcp) => 1,
        _ => 2,
    }
}

pub fn classify_path(address: &Multiaddr) -> PathKind {
    let transport = classify_address(address);
    if let Some(exchange) = address.iter().find_map(|p| match p {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    }) && address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
    {
        return PathKind::Relay {
            exchange_peer_id: exchange,
        };
    }
    PathKind::Direct(transport)
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
    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }
    #[test]
    fn reordered_dcutr_is_consumed_and_unconfirmed_is_excluded() {
        let p = peer();
        let mut b = ConnectionBook::default();
        let now = Instant::now();
        b.on_dcutr_succeeded(p, id(1), now);
        b.on_connection_established(p, id(1), &addr("/ip4/127.0.0.1/tcp/1"), now);
        assert!(b.is_direct(p, id(1)));
        assert!(b.direct(p).is_some());
        b.on_connection_established(p, id(2), &addr("/ip4/127.0.0.1/tcp/2"), now);
        assert!(!b.is_direct(p, id(2)));
    }
    #[test]
    fn close_tombstones_late_success_and_duplicate_establish_is_idempotent() {
        let p = peer();
        let mut b = ConnectionBook::default();
        let now = Instant::now();
        b.on_connection_established(p, id(1), &addr("/ip4/127.0.0.1/udp/1/quic-v1"), now);
        let seq = b.get(p, id(1)).unwrap().sequence;
        b.on_connection_established(p, id(1), &addr("/ip4/127.0.0.1/udp/1/quic-v1"), now);
        assert_eq!(b.get(p, id(1)).unwrap().sequence, seq);
        b.on_connection_closed(p, id(1));
        b.on_dcutr_succeeded(p, id(1), now);
        assert!(b.get(p, id(1)).is_none());
    }
    #[test]
    fn direct_prefers_quic_then_oldest() {
        let p = peer();
        let mut b = ConnectionBook::default();
        let now = Instant::now();
        b.on_connection_established(p, id(1), &addr("/ip4/127.0.0.1/tcp/1"), now);
        b.on_dcutr_succeeded(p, id(1), now);
        b.on_connection_established(p, id(2), &addr("/ip4/127.0.0.1/udp/1/quic-v1"), now);
        b.on_dcutr_succeeded(p, id(2), now);
        assert_eq!(b.direct(p).unwrap().connection_id, id(2));
    }
}
