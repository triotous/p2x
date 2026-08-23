use libp2p::PeerId;
use p2x_protocol::{
    Capabilities, RawTicket, RegistrationRevision, ResolveRequestV1, ResolveResponseV1,
    UnscopedSelector,
};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

pub const MAX_WAITERS_PER_SELECTOR: usize = 64;

fn valid_relay_address(address: &[u8], exchange: Option<PeerId>, server: PeerId) -> bool {
    let Ok(address) = libp2p::Multiaddr::try_from(address.to_vec()) else {
        return false;
    };
    let parts = address.iter().collect::<Vec<_>>();
    let circuit = parts
        .iter()
        .position(|part| matches!(part, libp2p::multiaddr::Protocol::P2pCircuit));
    let peers = parts
        .iter()
        .filter_map(|part| match part {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(*peer),
            _ => None,
        })
        .collect::<Vec<_>>();
    circuit.is_some()
        && exchange.is_none_or(|exchange| peers.first() == Some(&exchange))
        && peers.last() == Some(&server)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedServiceMetadata {
    pub server_peer_id: PeerId,
    pub upstream_id: p2x_protocol::UpstreamId,
    pub selector_fingerprint: [u8; 32],
    pub registration_revision: RegistrationRevision,
    pub relay_addresses: Vec<Vec<u8>>,
    pub compatible_capabilities: Capabilities,
    pub registration_expires_at: i64,
}
#[derive(Debug)]
pub struct AuthorizationGrant {
    pub metadata: ResolvedServiceMetadata,
    pub ticket: RawTicket,
    pub ticket_expires_at: i64,
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CacheKey {
    session_id: [u8; 16],
    selector: UnscopedSelector,
}
#[derive(Clone, Debug)]
struct Positive {
    metadata: ResolvedServiceMetadata,
    expires_at: i64,
}
#[derive(Clone, Copy, Debug)]
struct Negative {
    code: p2x_protocol::PublicErrorCode,
    expires_at: Instant,
}
#[derive(Default)]
pub struct ResolverState {
    exchange_peer_id: Option<PeerId>,
    positive: HashMap<CacheKey, Positive>,
    negative: HashMap<CacheKey, Negative>,
    waiters: HashMap<CacheKey, VecDeque<u64>>,
    pending: HashMap<[u8; 16], CacheKey>,
}
impl ResolverState {
    pub fn set_exchange_peer(&mut self, exchange_peer_id: PeerId) {
        self.exchange_peer_id = Some(exchange_peer_id);
    }
    pub fn begin(
        &mut self,
        request_id: [u8; 16],
        session_id: [u8; 16],
        selector: UnscopedSelector,
        now: i64,
    ) -> Result<ResolveRequestV1, p2x_protocol::PublicErrorCode> {
        self.sweep(now);
        let key = CacheKey {
            session_id,
            selector: selector.clone(),
        };
        let queue = self.waiters.entry(key.clone()).or_default();
        if queue.len() >= MAX_WAITERS_PER_SELECTOR {
            return Err(p2x_protocol::PublicErrorCode::LimitResolveRequests);
        }
        queue.push_back(u64::from_be_bytes(
            request_id[..8].try_into().unwrap_or_default(),
        ));
        self.pending.insert(request_id, key.clone());
        Ok(ResolveRequestV1::Resolve {
            request_id,
            session_id,
            selector,
            client_capabilities: Capabilities::from_bits(15).expect("known capabilities"),
        })
    }
    pub fn metadata(
        &self,
        session_id: [u8; 16],
        selector: &UnscopedSelector,
        now: i64,
    ) -> Option<ResolvedServiceMetadata> {
        self.positive
            .get(&CacheKey {
                session_id,
                selector: selector.clone(),
            })
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.metadata.clone())
    }
    pub fn complete(
        &mut self,
        response: ResolveResponseV1,
        session_id: [u8; 16],
        selector: &UnscopedSelector,
        now: i64,
    ) -> Result<AuthorizationGrant, p2x_protocol::PublicErrorCode> {
        let request_id = match &response {
            ResolveResponseV1::Resolved { request_id, .. }
            | ResolveResponseV1::Rejected {
                request_id: Some(request_id),
                ..
            } => *request_id,
            ResolveResponseV1::Rejected {
                request_id: None, ..
            } => return Err(p2x_protocol::PublicErrorCode::ProtocolMalformed),
        };
        let key = self
            .pending
            .remove(&request_id)
            .ok_or(p2x_protocol::PublicErrorCode::ProtocolMalformed)?;
        if key.session_id != session_id || key.selector != *selector {
            return Err(p2x_protocol::PublicErrorCode::ProtocolMalformed);
        }
        if let Some(queue) = self.waiters.get_mut(&key) {
            queue.pop_front();
            if queue.is_empty() {
                self.waiters.remove(&key);
            }
        }
        match response {
            ResolveResponseV1::Resolved {
                server_peer_id,
                upstream_id,
                selector_fingerprint,
                registration_revision,
                relay_addresses,
                compatible_capabilities,
                registration_expires_at,
                ticket_expires_at,
                ticket,
                ..
            } => {
                let server_peer_id = PeerId::from_bytes(&server_peer_id)
                    .map_err(|_| p2x_protocol::PublicErrorCode::ProtocolMalformed)?;
                if !relay_addresses.iter().all(|address| {
                    valid_relay_address(address, self.exchange_peer_id, server_peer_id)
                }) {
                    return Err(p2x_protocol::PublicErrorCode::ProtocolMalformed);
                }
                if ticket_expires_at <= now || ticket_expires_at > registration_expires_at {
                    return Err(p2x_protocol::PublicErrorCode::RegistryStaleRevision);
                }
                let metadata = ResolvedServiceMetadata {
                    server_peer_id,
                    upstream_id,
                    selector_fingerprint,
                    registration_revision,
                    relay_addresses,
                    compatible_capabilities,
                    registration_expires_at,
                };
                self.positive.insert(
                    key,
                    Positive {
                        metadata: metadata.clone(),
                        expires_at: registration_expires_at,
                    },
                );
                Ok(AuthorizationGrant {
                    metadata,
                    ticket,
                    ticket_expires_at,
                })
            }
            ResolveResponseV1::Rejected { error, .. } => {
                if matches!(
                    error.code,
                    p2x_protocol::PublicErrorCode::RegistryNotFound
                        | p2x_protocol::PublicErrorCode::RegistryOffline
                ) {
                    self.negative.insert(
                        key,
                        Negative {
                            code: error.code,
                            expires_at: Instant::now() + Duration::from_secs(1),
                        },
                    );
                }
                Err(error.code)
            }
        }
    }
    pub fn invalidate(&mut self, session_id: [u8; 16], selector: &UnscopedSelector) {
        let key = CacheKey {
            session_id,
            selector: selector.clone(),
        };
        self.positive.remove(&key);
        self.negative.remove(&key);
    }
    pub fn clear(&mut self) {
        self.exchange_peer_id = None;
        self.positive.clear();
        self.negative.clear();
        self.waiters.clear();
        self.pending.clear();
    }
    pub fn sweep(&mut self, now: i64) {
        self.positive.retain(|_, value| value.expires_at > now);
        self.negative
            .retain(|_, value| value.expires_at > Instant::now());
    }
    pub fn pending(&self) -> usize {
        self.pending.len()
    }
    pub fn cached_tickets(&self) -> usize {
        0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    fn selector() -> UnscopedSelector {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            p2x_protocol::MetadataKey::new("service").unwrap(),
            p2x_protocol::MetadataValue::new("orders").unwrap(),
        );
        UnscopedSelector::new(p2x_protocol::ProtocolClass::Http, metadata).unwrap()
    }
    #[test]
    fn binary_multiaddr_bytes_are_revalidated() {
        let exchange = PeerId::random();
        let server = PeerId::random();
        let address = format!("/ip4/127.0.0.1/tcp/1/p2p/{exchange}/p2p-circuit/p2p/{server}")
            .parse::<libp2p::Multiaddr>()
            .unwrap()
            .to_vec();
        assert!(valid_relay_address(&address, Some(exchange), server));
    }

    #[test]
    fn metadata_is_cacheable_but_ticket_is_not() {
        let mut state = ResolverState::default();
        let selector = selector();
        let id = [1; 16];
        state.begin(id, [2; 16], selector.clone(), 1).unwrap();
        let peer = PeerId::random().to_bytes();
        let exchange = PeerId::random();
        state.set_exchange_peer(exchange);
        let relay = format!(
            "/ip4/127.0.0.1/tcp/1/p2p/{}/p2p-circuit/p2p/{}",
            exchange,
            PeerId::from_bytes(&peer).unwrap()
        )
        .parse::<libp2p::Multiaddr>()
        .unwrap()
        .to_vec();
        let response = ResolveResponseV1::Resolved {
            request_id: id,
            server_peer_id: peer,
            upstream_id: p2x_protocol::UpstreamId::new("orders").unwrap(),
            selector_fingerprint: [3; 32],
            registration_revision: RegistrationRevision::new(1).unwrap(),
            relay_addresses: vec![relay],
            compatible_capabilities: Capabilities::RELAY_V2,
            registration_expires_at: 20,
            ticket_expires_at: 19,
            ticket: RawTicket::new(vec![7; 16]).unwrap(),
        };
        let grant = state.complete(response, [2; 16], &selector, 1).unwrap();
        assert!(state.metadata([2; 16], &selector, 1).is_some());
        assert_eq!(state.cached_tickets(), 0);
        assert!(!grant.ticket.as_bytes().is_empty());
    }
}
