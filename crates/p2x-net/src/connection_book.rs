use libp2p::{Multiaddr, PeerId, swarm::ConnectionId as Libp2pConnectionId};
use std::collections::HashMap;

pub type ConnectionId = Libp2pConnectionId;

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
    pub closing: bool,
    pub dcutr_confirmed: bool,
}

#[derive(Default)]
pub struct ConnectionBook {
    next_sequence: u64,
    records: HashMap<(PeerId, ConnectionId), ConnectionRecord>,
}
impl ConnectionBook {
    pub fn insert(&mut self, peer_id: PeerId, connection_id: ConnectionId, path: PathKind) {
        self.next_sequence += 1;
        self.records.insert(
            (peer_id, connection_id),
            ConnectionRecord {
                peer_id,
                connection_id,
                path,
                sequence: self.next_sequence,
                closing: false,
                dcutr_confirmed: false,
            },
        );
    }
    pub fn mark_dcutr(&mut self, connection_id: ConnectionId) {
        if let Some(r) = self
            .records
            .values_mut()
            .find(|r| r.connection_id == connection_id)
        {
            r.dcutr_confirmed = true;
        }
    }

    pub fn is_direct(&self, peer_id: PeerId, connection_id: ConnectionId) -> bool {
        self.get(peer_id, connection_id)
            .is_some_and(|r| matches!(r.path, PathKind::Direct(_)) && !r.closing)
    }
    pub fn close(&mut self, peer_id: PeerId, connection_id: ConnectionId) {
        self.records.remove(&(peer_id, connection_id));
    }
    pub fn get(&self, peer_id: PeerId, connection_id: ConnectionId) -> Option<&ConnectionRecord> {
        self.records.get(&(peer_id, connection_id))
    }
    pub fn direct(&self, peer_id: PeerId) -> Option<&ConnectionRecord> {
        self.records
            .values()
            .filter(|r| r.peer_id == peer_id && matches!(r.path, PathKind::Direct(_)) && !r.closing)
            .min_by_key(|r| (transport_rank(&r.path), r.sequence))
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
}
fn transport_rank(path: &PathKind) -> u8 {
    match path {
        PathKind::Direct(TransportKind::Quic) => 0,
        PathKind::Direct(TransportKind::Tcp) => 1,
        _ => 2,
    }
}

pub fn classify_address(address: &Multiaddr) -> TransportKind {
    if address
        .iter()
        .any(|p| matches!(p, libp2p::multiaddr::Protocol::QuicV1))
    {
        TransportKind::Quic
    } else if address
        .iter()
        .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
    {
        TransportKind::Tcp
    } else {
        TransportKind::Unknown
    }
}
