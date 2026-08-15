use libp2p::swarm::ConnectionId as Libp2pConnectionId;
use libp2p::{Multiaddr, PeerId, core::ConnectedPoint, multiaddr::Protocol};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

pub type ConnectionId = Libp2pConnectionId;
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
#[derive(Clone, Debug)]
enum Lifecycle {
    PendingDcutr { expires_at: Instant },
    Active(Box<ConnectionRecord>),
    Retired { expires_at: Instant },
}
pub struct ConnectionBook {
    expected_exchange: PeerId,
    next_sequence: u64,
    ledger: HashMap<(PeerId, ConnectionId), Lifecycle>,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConnectionBookError {
    #[error("connection lifecycle ledger is full")]
    Capacity,
    #[error("relayed endpoint does not identify the expected exchange")]
    WrongExchange,
    #[error("connection sequence exhausted")]
    SequenceExhausted,
}
impl ConnectionBook {
    pub fn new(expected_exchange: PeerId) -> Self {
        Self {
            expected_exchange,
            next_sequence: 0,
            ledger: HashMap::new(),
        }
    }
    pub fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
        now: Instant,
    ) -> Result<(), ConnectionBookError> {
        self.sweep(now);
        let key = (peer_id, connection_id);
        if matches!(self.ledger.get(&key), Some(Lifecycle::Retired { .. })) {
            return Ok(());
        }
        let authoritative_address = authoritative_path_address(endpoint);
        let path = classify_path(authoritative_address);
        if endpoint.is_relayed() && !self.valid_relay(authoritative_address) {
            return Err(ConnectionBookError::WrongExchange);
        }
        if let Some(Lifecycle::Active(record)) = self.ledger.get_mut(&key) {
            record.closing = false;
            return Ok(());
        }
        let replaces_pending =
            matches!(self.ledger.get(&key), Some(Lifecycle::PendingDcutr { .. }));
        if !replaces_pending && self.ledger.len() >= MAX_CONNECTION_LIFECYCLES {
            return Err(ConnectionBookError::Capacity);
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ConnectionBookError::SequenceExhausted)?;
        let confirmed = matches!(
            self.ledger.remove(&key),
            Some(Lifecycle::PendingDcutr { .. })
        );
        self.ledger.insert(
            key,
            Lifecycle::Active(Box::new(ConnectionRecord {
                peer_id,
                connection_id,
                endpoint_role: if endpoint.is_dialer() {
                    EndpointRole::Dialer
                } else {
                    EndpointRole::Listener
                },
                endpoint_address: authoritative_address.clone(),
                path,
                sequence: self.next_sequence,
                established_at: now,
                closing: false,
                dcutr_confirmed: confirmed,
                last_ping: None,
            })),
        );
        Ok(())
    }
    pub fn on_dcutr_succeeded(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        now: Instant,
    ) -> Result<(), ConnectionBookError> {
        self.sweep(now);
        let key = (peer_id, connection_id);
        if let Some(lifecycle) = self.ledger.get_mut(&key) {
            match lifecycle {
                Lifecycle::Active(record) => {
                    if matches!(record.path, PathKind::Direct(_)) {
                        record.dcutr_confirmed = true;
                    }
                }
                Lifecycle::Retired { .. } | Lifecycle::PendingDcutr { .. } => {}
            }
            return Ok(());
        }
        if self.ledger.len() >= MAX_CONNECTION_LIFECYCLES {
            return Err(ConnectionBookError::Capacity);
        }
        self.ledger.insert(
            key,
            Lifecycle::PendingDcutr {
                expires_at: now + TOMBSTONE_TTL,
            },
        );
        Ok(())
    }
    pub fn on_connection_closed(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) -> Result<(), ConnectionBookError> {
        self.on_connection_closed_at(peer_id, connection_id, Instant::now())
    }
    pub fn on_connection_closed_at(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        now: Instant,
    ) -> Result<(), ConnectionBookError> {
        let key = (peer_id, connection_id);
        if self.ledger.len() >= MAX_CONNECTION_LIFECYCLES && !self.ledger.contains_key(&key) {
            return Err(ConnectionBookError::Capacity);
        }
        self.ledger.insert(
            key,
            Lifecycle::Retired {
                expires_at: now + TOMBSTONE_TTL,
            },
        );
        Ok(())
    }
    pub fn mark_ping(&mut self, peer_id: PeerId, connection_id: ConnectionId, now: Instant) {
        if let Some(Lifecycle::Active(r)) = self.ledger.get_mut(&(peer_id, connection_id)) {
            r.last_ping = Some(now);
        }
    }
    pub fn direct(&self, peer_id: PeerId) -> Option<&ConnectionRecord> {
        self.ledger
            .values()
            .filter_map(|l| match l {
                Lifecycle::Active(r)
                    if r.peer_id == peer_id
                        && !r.closing
                        && r.dcutr_confirmed
                        && matches!(r.path, PathKind::Direct(_)) =>
                {
                    Some(r.as_ref())
                }
                _ => None,
            })
            .min_by_key(|r| (transport_rank(&r.path), r.sequence))
    }
    pub fn get(&self, peer_id: PeerId, connection_id: ConnectionId) -> Option<&ConnectionRecord> {
        match self.ledger.get(&(peer_id, connection_id)) {
            Some(Lifecycle::Active(r)) => Some(r.as_ref()),
            _ => None,
        }
    }
    pub fn is_direct(&self, peer_id: PeerId, connection_id: ConnectionId) -> bool {
        self.get(peer_id, connection_id).is_some_and(|r| {
            matches!(r.path, PathKind::Direct(_)) && !r.closing && r.dcutr_confirmed
        })
    }
    pub fn len(&self) -> usize {
        self.ledger
            .values()
            .filter(|l| matches!(l, Lifecycle::Active(_)))
            .count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn iter(&self) -> impl Iterator<Item = &ConnectionRecord> {
        self.ledger.values().filter_map(|l| match l {
            Lifecycle::Active(r) => Some(r.as_ref()),
            _ => None,
        })
    }
    pub fn sweep(&mut self, now: Instant) {
        self.ledger.retain(|_, l| !matches!(l, Lifecycle::PendingDcutr { expires_at } | Lifecycle::Retired { expires_at } if *expires_at <= now));
    }
    pub fn pending_count(&self) -> usize {
        self.ledger
            .values()
            .filter(|l| matches!(l, Lifecycle::PendingDcutr { .. }))
            .count()
    }
    pub fn tombstone_count(&self) -> usize {
        self.ledger
            .values()
            .filter(|l| matches!(l, Lifecycle::Retired { .. }))
            .count()
    }
    pub fn lifecycle_count(&self) -> usize {
        self.ledger.len()
    }
    fn valid_relay(&self, address: &Multiaddr) -> bool {
        relay_peer_before_circuit(address) == Some(self.expected_exchange)
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
    classify_path(authoritative_path_address(endpoint))
}

fn authoritative_path_address(endpoint: &ConnectedPoint) -> &Multiaddr {
    match endpoint {
        ConnectedPoint::Dialer { address, .. } => address,
        ConnectedPoint::Listener {
            local_addr,
            send_back_addr: _,
        } if local_addr
            .iter()
            .any(|protocol| matches!(protocol, Protocol::P2pCircuit)) =>
        {
            local_addr
        }
        ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
    }
}
pub fn classify_path(address: &Multiaddr) -> PathKind {
    if address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        relay_peer_before_circuit(address)
            .map(|exchange_peer_id| PathKind::Relay { exchange_peer_id })
            .unwrap_or(PathKind::UnknownDirect)
    } else {
        PathKind::Direct(classify_address(address))
    }
}

fn relay_peer_before_circuit(address: &Multiaddr) -> Option<PeerId> {
    let mut relay = None;
    for protocol in address.iter() {
        match protocol {
            Protocol::P2p(peer) => relay = Some(peer),
            Protocol::P2pCircuit => return relay,
            _ => {}
        }
    }
    None
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
    fn endpoint(address: &str) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: address.parse().unwrap(),
            role_override: libp2p::core::Endpoint::Dialer,
            port_use: libp2p::core::transport::PortUse::New,
        }
    }
    fn listener_endpoint(local_addr: &str, remote_addr: &str) -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: local_addr.parse().unwrap(),
            send_back_addr: remote_addr.parse().unwrap(),
        }
    }
    fn id(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }
    #[test]
    fn dcutr_reordering_and_selection() {
        let exchange = PeerId::random();
        let peer = PeerId::random();
        let now = Instant::now();
        let mut book = ConnectionBook::new(exchange);
        book.on_dcutr_succeeded(peer, id(1), now).unwrap();
        book.on_connection_established(peer, id(1), &endpoint("/ip4/127.0.0.1/tcp/1"), now)
            .unwrap();
        assert!(book.is_direct(peer, id(1)));
        book.on_connection_established(peer, id(2), &endpoint("/ip4/127.0.0.1/udp/1/quic-v1"), now)
            .unwrap();
        book.on_dcutr_succeeded(peer, id(2), now).unwrap();
        assert_eq!(book.direct(peer).unwrap().connection_id, id(2));
    }
    #[test]
    fn close_tombstone_blocks_late_success() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut book = ConnectionBook::new(PeerId::random());
        book.on_connection_closed_at(peer, id(1), now).unwrap();
        book.on_dcutr_succeeded(peer, id(1), now).unwrap();
        assert_eq!(book.pending_count(), 0);
        book.sweep(now + TOMBSTONE_TTL);
        assert_eq!(book.tombstone_count(), 0);
    }
    #[test]
    fn wrong_relay_is_rejected() {
        let mut book = ConnectionBook::new(PeerId::random());
        let address = format!("/ip4/127.0.0.1/tcp/1/p2p/{}/p2p-circuit", PeerId::random());
        assert_eq!(
            book.on_connection_established(
                PeerId::random(),
                id(1),
                &endpoint(&address),
                Instant::now()
            ),
            Err(ConnectionBookError::WrongExchange)
        );
    }

    #[test]
    fn relayed_endpoint_without_identity_is_rejected() {
        let mut book = ConnectionBook::new(PeerId::random());
        assert_eq!(
            book.on_connection_established(
                PeerId::random(),
                id(1),
                &endpoint("/ip4/127.0.0.1/tcp/1/p2p-circuit"),
                Instant::now(),
            ),
            Err(ConnectionBookError::WrongExchange)
        );
    }

    #[test]
    fn relayed_listener_validates_its_authoritative_local_circuit() {
        let exchange = PeerId::random();
        let peer = PeerId::random();
        let address = format!("/ip4/127.0.0.1/tcp/1/p2p/{exchange}/p2p-circuit");
        let remote = format!("/p2p/{peer}");
        let mut book = ConnectionBook::new(exchange);
        book.on_connection_established(
            peer,
            id(1),
            &listener_endpoint(&address, &remote),
            Instant::now(),
        )
        .unwrap();
        assert!(matches!(
            book.get(peer, id(1)).unwrap().path,
            PathKind::Relay { .. }
        ));
    }

    #[test]
    fn pending_slot_can_become_active_at_capacity() {
        let exchange = PeerId::random();
        let peer = PeerId::random();
        let now = Instant::now();
        let mut book = ConnectionBook::new(exchange);
        for index in 0..MAX_CONNECTION_LIFECYCLES {
            book.on_dcutr_succeeded(peer, id(index), now).unwrap();
        }
        assert_eq!(book.lifecycle_count(), MAX_CONNECTION_LIFECYCLES);
        book.on_connection_established(peer, id(0), &endpoint("/ip4/127.0.0.1/tcp/1"), now)
            .unwrap();
        assert!(book.is_direct(peer, id(0)));
        assert_eq!(book.lifecycle_count(), MAX_CONNECTION_LIFECYCLES);
    }

    #[test]
    fn full_ledger_rejects_untracked_lifecycle_without_eviction() {
        let peer = PeerId::random();
        let now = Instant::now();
        let mut book = ConnectionBook::new(PeerId::random());
        for index in 0..MAX_CONNECTION_LIFECYCLES {
            book.on_connection_closed_at(peer, id(index), now).unwrap();
        }
        assert_eq!(
            book.on_dcutr_succeeded(peer, id(MAX_CONNECTION_LIFECYCLES), now),
            Err(ConnectionBookError::Capacity)
        );
        assert_eq!(book.tombstone_count(), MAX_CONNECTION_LIFECYCLES);
    }
}
