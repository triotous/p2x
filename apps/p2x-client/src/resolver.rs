use libp2p::PeerId;
use p2x_net::auth_state::PrincipalBinding;
use p2x_protocol::{
    Capabilities, RawTicket, RegistrationRevision, ResolveRequestV1, ResolveResponseV1,
    UnscopedSelector,
};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

pub const MAX_WAITERS_PER_SELECTOR: usize = 64;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_CACHE_ENTRIES: usize = 2_048;

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
    let Some(circuit) = circuit else {
        return false;
    };
    peers.len() == 2
        && peers.first().copied() == exchange
        && peers.first().and_then(|_| parts.get(circuit.wrapping_sub(1)))
            .is_some_and(|part| matches!(part, libp2p::multiaddr::Protocol::P2p(peer) if Some(*peer) == exchange))
        && peers.last() == Some(&server)
        && matches!(parts.last(), Some(libp2p::multiaddr::Protocol::P2p(peer)) if *peer == server)
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
    binding: PrincipalBinding,
    selector: UnscopedSelector,
}
#[derive(Clone, Debug)]
struct PendingRequest {
    key: CacheKey,
    session_id: [u8; 16],
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
    waiters: HashMap<CacheKey, VecDeque<[u8; 16]>>,
    pending: HashMap<[u8; 16], PendingRequest>,
    queued_requests: HashMap<[u8; 16], ResolveRequestV1>,
    principal_binding: Option<PrincipalBinding>,
}
impl ResolverState {
    pub fn set_exchange_peer(&mut self, exchange_peer_id: PeerId) {
        self.exchange_peer_id = Some(exchange_peer_id);
    }

    /// Replacing the principal binding invalidates all metadata, negatives, and ticket waiters.
    pub fn set_principal_binding(&mut self, binding: PrincipalBinding) {
        if self.principal_binding.as_ref() == Some(&binding) {
            return;
        }
        self.positive.clear();
        self.negative.clear();
        self.waiters.clear();
        self.pending.clear();
        self.queued_requests.clear();
        self.principal_binding = Some(binding);
    }
    pub fn begin(
        &mut self,
        request_id: [u8; 16],
        binding: PrincipalBinding,
        session_id: [u8; 16],
        selector: UnscopedSelector,
        now: i64,
    ) -> Result<Option<ResolveRequestV1>, p2x_protocol::PublicErrorCode> {
        self.sweep(now);
        self.set_principal_binding(binding.clone());
        if self.pending.len() + self.queued_requests.len() >= MAX_PENDING_REQUESTS
            || self.pending.contains_key(&request_id)
            || self.queued_requests.contains_key(&request_id)
        {
            return Err(p2x_protocol::PublicErrorCode::LimitResolveRequests);
        }
        let key = CacheKey {
            binding,
            selector: selector.clone(),
        };
        let queue = self.waiters.entry(key.clone()).or_default();
        if queue.len() >= MAX_WAITERS_PER_SELECTOR {
            return Err(p2x_protocol::PublicErrorCode::LimitResolveRequests);
        }
        queue.push_back(request_id);
        let request = ResolveRequestV1::Resolve {
            request_id,
            session_id,
            selector,
            client_capabilities: Capabilities::from_bits(15).expect("known capabilities"),
        };
        self.queued_requests.insert(request_id, request.clone());
        if queue.len() == 1 {
            self.pending
                .insert(request_id, PendingRequest { key, session_id });
            Ok(Some(request))
        } else {
            Ok(None)
        }
    }

    /// Promotes the next FIFO waiter for a selector to the wire request owner.
    pub fn next_request(&mut self) -> Option<ResolveRequestV1> {
        let (key, request_id) = self.waiters.iter().find_map(|(key, queue)| {
            queue
                .front()
                .copied()
                .filter(|id| !self.pending.contains_key(id))
                .map(|id| (key.clone(), id))
        })?;
        let request = self.queued_requests.remove(&request_id)?;
        let session_id = match &request {
            ResolveRequestV1::Resolve { session_id, .. } => *session_id,
        };
        self.pending
            .insert(request_id, PendingRequest { key, session_id });
        Some(request)
    }

    pub fn metadata(
        &self,
        binding: &PrincipalBinding,
        selector: &UnscopedSelector,
        now: i64,
    ) -> Option<ResolvedServiceMetadata> {
        self.positive
            .get(&CacheKey {
                binding: binding.clone(),
                selector: selector.clone(),
            })
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.metadata.clone())
    }

    /// Returns only the short-lived not-found/offline result, never a ticket.
    pub fn negative(
        &self,
        binding: &PrincipalBinding,
        selector: &UnscopedSelector,
    ) -> Option<p2x_protocol::PublicErrorCode> {
        self.negative
            .get(&CacheKey {
                binding: binding.clone(),
                selector: selector.clone(),
            })
            .filter(|entry| entry.expires_at > Instant::now())
            .map(|entry| entry.code)
    }
    pub fn complete(
        &mut self,
        response: ResolveResponseV1,
        binding: &PrincipalBinding,
        _session_id: [u8; 16],
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
        let pending = self
            .pending
            .get(&request_id)
            .ok_or(p2x_protocol::PublicErrorCode::ProtocolMalformed)?;
        if pending.session_id != _session_id
            || pending.key.binding != *binding
            || pending.key.selector != *selector
        {
            return Err(p2x_protocol::PublicErrorCode::ProtocolMalformed);
        }
        let key = pending.key.clone();
        if self
            .waiters
            .get(&key)
            .is_some_and(|queue| queue.front() != Some(&request_id))
        {
            return Err(p2x_protocol::PublicErrorCode::ProtocolMalformed);
        }
        self.pending.remove(&request_id);
        if let Some(queue) = self.waiters.get_mut(&key) {
            queue.pop_front();
            if queue.is_empty() {
                self.waiters.remove(&key);
            }
        }
        self.queued_requests.remove(&request_id);
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
                self.cache_metadata(
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
                    self.cache_negative(
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
    pub fn cancel(&mut self, request_id: [u8; 16]) -> bool {
        let Some(pending) = self.pending.remove(&request_id) else {
            return self.queued_requests.remove(&request_id).is_some();
        };
        self.queued_requests.remove(&request_id);
        if let Some(queue) = self.waiters.get_mut(&pending.key) {
            queue.retain(|id| *id != request_id);
            if queue.is_empty() {
                self.waiters.remove(&pending.key);
            }
        }
        true
    }

    pub fn invalidate(&mut self, binding: &PrincipalBinding, selector: &UnscopedSelector) {
        let key = CacheKey {
            binding: binding.clone(),
            selector: selector.clone(),
        };
        self.positive.remove(&key);
        self.negative.remove(&key);
    }

    fn cache_metadata(&mut self, key: CacheKey, value: Positive) {
        self.trim_cache();
        self.positive.insert(key, value);
    }

    fn cache_negative(&mut self, key: CacheKey, value: Negative) {
        self.trim_cache();
        self.negative.insert(key, value);
    }

    fn trim_cache(&mut self) {
        while self.positive.len() + self.negative.len() >= MAX_CACHE_ENTRIES {
            if let Some(key) = self
                .positive
                .iter()
                .min_by_key(|(_, value)| value.expires_at)
                .map(|(key, _)| key.clone())
            {
                self.positive.remove(&key);
            } else if let Some(key) = self
                .negative
                .iter()
                .min_by_key(|(_, value)| value.expires_at)
                .map(|(key, _)| key.clone())
            {
                self.negative.remove(&key);
            } else {
                break;
            }
        }
    }

    pub fn clear(&mut self) {
        self.exchange_peer_id = None;
        self.positive.clear();
        self.negative.clear();
        self.waiters.clear();
        self.pending.clear();
        self.queued_requests.clear();
        self.principal_binding = None;
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
        let wrong = format!("/ip4/127.0.0.1/tcp/1/p2p/{server}/p2p-circuit/p2p/{server}")
            .parse::<libp2p::Multiaddr>()
            .unwrap()
            .to_vec();
        assert!(!valid_relay_address(&wrong, Some(exchange), server));
    }

    #[test]
    fn queued_waiters_promote_in_fifo_and_cancel_releases_one() {
        let mut state = ResolverState::default();
        let selector = selector();
        let binding = PrincipalBinding {
            tenant: p2x_protocol::Tenant::new("tenant").unwrap(),
            role: p2x_protocol::Role::Client,
            scopes: p2x_protocol::Scope::OpenProxyStream.bit(),
            quota_profile: p2x_protocol::QuotaProfile::new("standard").unwrap(),
            authorization_revision: 1,
        };
        assert!(
            state
                .begin([1; 16], binding.clone(), [2; 16], selector.clone(), 1)
                .unwrap()
                .is_some()
        );
        assert!(
            state
                .begin([2; 16], binding.clone(), [2; 16], selector.clone(), 1)
                .unwrap()
                .is_none()
        );
        assert_eq!(state.pending(), 1);
        assert!(state.cancel([1; 16]));
        assert_eq!(state.pending(), 0);
        let next = state.next_request().unwrap();
        assert!(matches!(
            next,
            ResolveRequestV1::Resolve { request_id, .. } if request_id == [2; 16]
        ));
        assert!(state.cancel([2; 16]));
    }

    #[test]
    fn principal_binding_change_clears_pending_and_metadata() {
        let mut state = ResolverState::default();
        let selector = selector();
        let binding = PrincipalBinding {
            tenant: p2x_protocol::Tenant::new("tenant").unwrap(),
            role: p2x_protocol::Role::Client,
            scopes: p2x_protocol::Scope::OpenProxyStream.bit(),
            quota_profile: p2x_protocol::QuotaProfile::new("standard").unwrap(),
            authorization_revision: 1,
        };
        state
            .begin([1; 16], binding.clone(), [2; 16], selector.clone(), 1)
            .unwrap();
        let changed = PrincipalBinding {
            authorization_revision: 2,
            ..binding
        };
        state.set_principal_binding(changed);
        assert_eq!(state.pending(), 0);
        assert!(state.next_request().is_none());
    }

    #[test]
    fn metadata_is_cacheable_but_ticket_is_not() {
        let mut state = ResolverState::default();
        let selector = selector();
        let id = [1; 16];
        let binding = PrincipalBinding {
            tenant: p2x_protocol::Tenant::new("tenant").unwrap(),
            role: p2x_protocol::Role::Client,
            scopes: p2x_protocol::Scope::OpenProxyStream.bit(),
            quota_profile: p2x_protocol::QuotaProfile::new("standard").unwrap(),
            authorization_revision: 1,
        };
        state
            .begin(id, binding.clone(), [2; 16], selector.clone(), 1)
            .unwrap();
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
        let grant = state
            .complete(response, &binding, [2; 16], &selector, 1)
            .unwrap();
        assert!(state.metadata(&binding, &selector, 1).is_some());
        assert_eq!(state.cached_tickets(), 0);
        assert!(!grant.ticket.as_bytes().is_empty());
    }
}
