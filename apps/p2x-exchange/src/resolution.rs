use crate::{
    auth_sessions::AuthSession,
    registry::Registry,
    resolution_admission::{ResolveAdmission, ResolveAdmissionLedger, ResolveOwner},
};
use libp2p::{PeerId, swarm::ConnectionId};
use p2x_config::ticket_key::TicketKey;
use p2x_protocol::{
    Capabilities, PublicError, PublicErrorCode, ResolveRequestV1, ResolveResponseV1, Role, Scope,
    ScopedSelector, ticket::ConnectionTicketClaimsV1,
};
use std::collections::HashMap;

const MIN_TICKET_LIFETIME: i64 = 5;
const DEFAULT_TICKET_LIFETIME: i64 = 30;
const MAX_IDEMPOTENCY_PER_CLIENT: usize = 8;
const MAX_IDEMPOTENCY_GLOBAL: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedResponse {
    digest: [u8; 32],
    response: ResolveResponseV1,
    expires_at: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionLimits {
    pub global_inflight: usize,
    pub per_client_inflight: usize,
    pub per_minute: usize,
    pub buckets: usize,
}
impl Default for ResolutionLimits {
    fn default() -> Self {
        Self {
            global_inflight: 128,
            per_client_inflight: 16,
            per_minute: 120,
            buckets: 256,
        }
    }
}
pub struct Resolver<'a> {
    exchange_peer_id: PeerId,
    signer: &'a TicketKey,
    ticket_lifetime: i64,
    pub admission: ResolveAdmissionLedger,
    idempotency: HashMap<(PeerId, [u8; 16]), CachedResponse>,
    draining: bool,
    issued: u64,
}
impl<'a> Resolver<'a> {
    pub fn new(exchange_peer_id: PeerId, signer: &'a TicketKey) -> Self {
        Self::with_lifetime(exchange_peer_id, signer, DEFAULT_TICKET_LIFETIME)
            .expect("default ticket lifetime is valid")
    }
    pub fn with_lifetime(
        exchange_peer_id: PeerId,
        signer: &'a TicketKey,
        ticket_lifetime: i64,
    ) -> Result<Self, PublicErrorCode> {
        if !(5..=60).contains(&ticket_lifetime) {
            return Err(PublicErrorCode::ProtocolMalformed);
        }
        Ok(Self {
            exchange_peer_id,
            signer,
            ticket_lifetime,
            admission: ResolveAdmissionLedger::default(),
            idempotency: HashMap::new(),
            draining: false,
            issued: 0,
        })
    }
    pub fn issued(&self) -> u64 {
        self.issued
    }
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_and_authorize(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        request: &ResolveRequestV1,
        admission_request_id: impl ToString,
        client_session: Option<&AuthSession>,
        server_session: impl FnOnce(&PeerId) -> Option<AuthSession>,
        reserved: impl FnOnce(&PeerId) -> bool,
        registry: &Registry,
        now: i64,
    ) -> ResolveResponseV1 {
        let (request_id, session_id, selector, capabilities) = match request {
            ResolveRequestV1::Resolve {
                request_id,
                session_id,
                selector,
                client_capabilities,
            } => (*request_id, *session_id, selector, *client_capabilities),
        };
        if self.draining {
            return rejected(Some(request_id), PublicErrorCode::ExchangeDraining, true);
        }
        let owner = ResolveOwner {
            peer_id,
            connection_id,
            request_id: admission_request_id.to_string(),
        };
        if self.admission.begin(owner.clone(), now) != ResolveAdmission::Accepted {
            return rejected(
                Some(request_id),
                PublicErrorCode::LimitResolveRequests,
                true,
            );
        }
        self.resolve_inner(
            peer_id,
            request_id,
            session_id,
            selector,
            capabilities,
            client_session,
            server_session,
            reserved,
            registry,
            now,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn resolve_inner(
        &mut self,
        peer_id: PeerId,
        request_id: [u8; 16],
        session_id: [u8; 16],
        selector: &p2x_protocol::UnscopedSelector,
        client_capabilities: Capabilities,
        client_session: Option<&AuthSession>,
        server_session: impl FnOnce(&PeerId) -> Option<AuthSession>,
        reserved: impl FnOnce(&PeerId) -> bool,
        registry: &Registry,
        now: i64,
    ) -> ResolveResponseV1 {
        if !client_capabilities.contains(Capabilities::RELAY_V2) {
            return rejected(
                Some(request_id),
                PublicErrorCode::ProtocolCapabilityMismatch,
                false,
            );
        }
        let Some(session) = client_session
            .filter(|session| session.session_id == session_id && session.expires_at > now)
        else {
            return rejected(
                Some(request_id),
                PublicErrorCode::AuthSessionRequired,
                false,
            );
        };
        if session.principal.role != Role::Client
            || session.principal.scopes & Scope::OpenProxyStream.bit() == 0
            || session.principal.quota_profile.as_str() != "standard"
        {
            return rejected(Some(request_id), PublicErrorCode::AuthRoleForbidden, false);
        }
        let digest = request_digest(request_id, session_id, selector, client_capabilities);
        if let Some(cached) = self.idempotency.get(&(peer_id, request_id)) {
            return if cached.digest == digest {
                cached.response.clone()
            } else {
                rejected(Some(request_id), PublicErrorCode::ProtocolMalformed, false)
            };
        }
        let tenant = session.principal.tenant.clone();
        let scoped = ScopedSelector::new(tenant.clone(), selector.clone());
        let resolved = match registry.resolve_exact(&scoped, now) {
            Ok(value) => value,
            Err(error) => return rejected(Some(request_id), error.code(), error.retryable()),
        };
        let Some(server) = server_session(&resolved.server_peer_id).filter(|session| {
            session.principal.role == Role::Server
                && session.expires_at > now
                && session.principal.tenant == resolved.tenant
                && session.principal.authorization_revision
                    == resolved.server_authorization_revision
        }) else {
            return rejected(Some(request_id), PublicErrorCode::RegistryOffline, true);
        };
        let _ = server;
        if !reserved(&resolved.server_peer_id) {
            return rejected(Some(request_id), PublicErrorCode::RegistryOffline, true);
        }
        let compatible = Capabilities::from_bits(
            client_capabilities.bits() & resolved.server_capabilities.bits(),
        )
        .unwrap_or_else(Capabilities::empty);
        if !client_capabilities.contains(Capabilities::RELAY_V2)
            || !resolved
                .server_capabilities
                .contains(Capabilities::RELAY_V2)
            || !compatible.contains(Capabilities::RELAY_V2)
        {
            return rejected(
                Some(request_id),
                PublicErrorCode::ProtocolCapabilityMismatch,
                false,
            );
        }
        self.sweep(now);
        if !self.cache_available(peer_id) {
            return rejected(
                Some(request_id),
                PublicErrorCode::LimitResolveRequests,
                true,
            );
        }
        let mut ticket_id = [0; 16];
        if getrandom::fill(&mut ticket_id).is_err() {
            return rejected(Some(request_id), PublicErrorCode::ExchangeOverloaded, true);
        }
        let ticket_expires_at = now
            .saturating_add(self.ticket_lifetime)
            .min(resolved.registration_expires_at);
        if ticket_expires_at.saturating_sub(now) < MIN_TICKET_LIFETIME {
            return rejected(Some(request_id), PublicErrorCode::RegistryOffline, true);
        }
        let claims = match ConnectionTicketClaimsV1::new(
            self.exchange_peer_id.to_bytes(),
            session.principal.tenant.as_str().to_owned(),
            peer_id.to_bytes(),
            resolved.server_peer_id.to_bytes(),
            resolved.upstream_id.as_str().to_owned(),
            resolved.selector_fingerprint,
            resolved.registration_revision.get(),
            resolved.server_authorization_revision,
            Scope::OpenProxyStream.bit(),
            now,
            ticket_expires_at,
            ticket_id,
            1,
        ) {
            Ok(claims) => claims,
            Err(_) => return rejected(Some(request_id), PublicErrorCode::ExchangeOverloaded, true),
        };
        let ticket = match p2x_protocol::ticket::sign_ticket(self.signer, &claims) {
            Ok(ticket) => ticket,
            Err(_) => return rejected(Some(request_id), PublicErrorCode::ExchangeOverloaded, true),
        };
        let response = ResolveResponseV1::Resolved {
            request_id,
            server_peer_id: resolved.server_peer_id.to_bytes(),
            upstream_id: resolved.upstream_id,
            selector_fingerprint: resolved.selector_fingerprint,
            registration_revision: resolved.registration_revision,
            relay_addresses: resolved.relay_addresses,
            compatible_capabilities: compatible,
            registration_expires_at: resolved.registration_expires_at,
            ticket_expires_at,
            ticket,
        };
        self.issued = self.issued.saturating_add(1);
        self.cache(
            peer_id,
            request_id,
            digest,
            response.clone(),
            ticket_expires_at,
        );
        response
    }
    fn cache_available(&self, peer: PeerId) -> bool {
        self.idempotency.len() < MAX_IDEMPOTENCY_GLOBAL
            && self
                .idempotency
                .keys()
                .filter(|(owner, _)| *owner == peer)
                .count()
                < MAX_IDEMPOTENCY_PER_CLIENT
    }

    fn cache(
        &mut self,
        peer: PeerId,
        request_id: [u8; 16],
        digest: [u8; 32],
        response: ResolveResponseV1,
        expires_at: i64,
    ) {
        self.sweep(expires_at);
        let peer_count = self
            .idempotency
            .keys()
            .filter(|(owner, _)| *owner == peer)
            .count();
        if peer_count >= MAX_IDEMPOTENCY_PER_CLIENT
            && let Some(key) = self
                .idempotency
                .keys()
                .filter(|(owner, _)| *owner == peer)
                .min()
                .copied()
        {
            self.idempotency.remove(&key);
        }
        if self.idempotency.len() >= MAX_IDEMPOTENCY_GLOBAL
            && let Some(key) = self.idempotency.keys().min().copied()
        {
            self.idempotency.remove(&key);
        }
        self.idempotency.insert(
            (peer, request_id),
            CachedResponse {
                digest,
                response,
                expires_at,
            },
        );
    }
    pub fn set_draining(&mut self, draining: bool) {
        self.draining = draining;
    }

    pub fn cache_len(&self) -> usize {
        self.idempotency.len()
    }

    pub fn sweep(&mut self, now: i64) {
        self.idempotency
            .retain(|_, cached| cached.expires_at.saturating_add(5) > now);
        self.admission.sweep(now);
    }
    pub fn clear(&mut self) {
        self.idempotency.clear();
        self.admission.shutdown();
    }
}

fn request_digest(
    request_id: [u8; 16],
    session_id: [u8; 16],
    selector: &p2x_protocol::UnscopedSelector,
    capabilities: Capabilities,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&request_id);
    bytes.extend_from_slice(&session_id);
    bytes.extend_from_slice(&selector.canonical_bytes(None));
    bytes.extend_from_slice(&capabilities.bits().to_be_bytes());
    Sha256::digest(bytes).into()
}
fn rejected(
    request_id: Option<[u8; 16]>,
    code: PublicErrorCode,
    retryable: bool,
) -> ResolveResponseV1 {
    ResolveResponseV1::Rejected {
        request_id,
        error: PublicError::new(code, retryable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authn::{AuthPrincipal, CredentialBinding, FixedTokenProvider},
        registry::Registry,
    };
    use p2x_protocol::{CredentialId, QuotaProfile, Tenant, TokenDigest};
    fn session(peer: PeerId, role: Role, scopes: u32) -> AuthSession {
        AuthSession {
            session_id: [2; 16],
            principal: AuthPrincipal {
                peer_id: peer.to_string(),
                credential_id: CredentialId::new("id").unwrap(),
                tenant: Tenant::new("tenant").unwrap(),
                role,
                scopes,
                quota_profile: QuotaProfile::new("standard").unwrap(),
                authorization_revision: 1,
                credential_not_before: 0,
                credential_expires_at: 100,
                credential_digest: TokenDigest::from_bytes([0; 32]),
            },
            established_at: 0,
            expires_at: 100,
        }
    }
    #[test]
    fn same_request_replays_without_new_issuance() {
        let key = TicketKey::from_seed([9; 32]);
        let exchange = PeerId::random();
        let client = PeerId::random();
        let server = PeerId::random();
        let mut resolver = Resolver::new(exchange, &key);
        let mut registry = Registry::default();
        let tenant = Tenant::new("tenant").unwrap();
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert(
            p2x_protocol::MetadataKey::new("service").unwrap(),
            p2x_protocol::MetadataValue::new("orders").unwrap(),
        );
        let selector =
            p2x_protocol::UnscopedSelector::new(p2x_protocol::ProtocolClass::Http, metadata)
                .unwrap();
        let services =
            p2x_protocol::ServiceSet::new(vec![p2x_protocol::ServiceAdvertisementV1::new(
                p2x_protocol::UpstreamId::new("orders").unwrap(),
                selector.clone(),
                p2x_protocol::Health::Ready,
            )])
            .unwrap();
        registry.set_advertise_addresses(vec![format!("/ip4/127.0.0.1/tcp/1/p2p/{exchange}")]);
        let registration = p2x_protocol::RegistryRequestV1::Register {
            request_id: [8; 16],
            session_id: [2; 16],
            instance_id: p2x_protocol::InstanceId::new([3; 16]),
            requested_lease_seconds: 30,
            capabilities: Capabilities::from_bits(15).unwrap(),
            services,
        };
        registry
            .register(
                server,
                &tenant,
                Role::Server,
                Scope::RegisterServices.bit(),
                &QuotaProfile::new("standard").unwrap(),
                1,
                true,
                registration,
                1,
            )
            .unwrap();
        let request = ResolveRequestV1::Resolve {
            request_id: [1; 16],
            session_id: [2; 16],
            selector,
            client_capabilities: Capabilities::RELAY_V2,
        };
        let client_session = session(client, Role::Client, Scope::OpenProxyStream.bit());
        let first = resolver.resolve_and_authorize(
            client,
            ConnectionId::new_unchecked(1),
            &request,
            "wire-1",
            Some(&client_session),
            |_| Some(session(server, Role::Server, Scope::RegisterServices.bit())),
            |_| true,
            &registry,
            1,
        );
        let second = resolver.resolve_and_authorize(
            client,
            ConnectionId::new_unchecked(1),
            &request,
            "wire-2",
            Some(&client_session),
            |_| Some(session(server, Role::Server, Scope::RegisterServices.bit())),
            |_| true,
            &registry,
            1,
        );
        assert_eq!(first, second);
        assert_eq!(resolver.issued(), 1);
        assert_eq!(resolver.cache_len(), 1);
    }

    #[test]
    fn resolution_requires_relay_capability_on_both_sides() {
        let key = TicketKey::from_seed([9; 32]);
        let mut resolver = Resolver::new(PeerId::random(), &key);
        let client = PeerId::random();
        let request = ResolveRequestV1::Resolve {
            request_id: [1; 16],
            session_id: [2; 16],
            selector: p2x_protocol::UnscopedSelector::new(
                p2x_protocol::ProtocolClass::Http,
                [(
                    p2x_protocol::MetadataKey::new("service").unwrap(),
                    p2x_protocol::MetadataValue::new("orders").unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .unwrap(),
            client_capabilities: Capabilities::DIRECT_TCP,
        };
        let response = resolver.resolve_and_authorize(
            client,
            ConnectionId::new_unchecked(1),
            &request,
            "1",
            Some(&session(client, Role::Client, Scope::OpenProxyStream.bit())),
            |_| None,
            |_| false,
            &Registry::default(),
            1,
        );
        assert!(matches!(
            response,
            ResolveResponseV1::Rejected {
                error: PublicError {
                    code: PublicErrorCode::ProtocolCapabilityMismatch,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn authorization_rejects_missing_client_scope_before_lookup() {
        let key = TicketKey::from_seed([9; 32]);
        let mut resolver = Resolver::new(PeerId::random(), &key);
        let peer = PeerId::random();
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert(
            p2x_protocol::MetadataKey::new("service").unwrap(),
            p2x_protocol::MetadataValue::new("orders").unwrap(),
        );
        let request = ResolveRequestV1::Resolve {
            request_id: [1; 16],
            session_id: [2; 16],
            selector: p2x_protocol::UnscopedSelector::new(
                p2x_protocol::ProtocolClass::Http,
                metadata,
            )
            .unwrap(),
            client_capabilities: Capabilities::RELAY_V2,
        };
        let response = resolver.resolve_and_authorize(
            peer,
            ConnectionId::new_unchecked(1),
            &request,
            "1",
            Some(&session(peer, Role::Client, 0)),
            |_| None,
            |_| false,
            &Registry::default(),
            1,
        );
        assert!(matches!(
            response,
            ResolveResponseV1::Rejected {
                error: PublicError {
                    code: PublicErrorCode::AuthRoleForbidden,
                    ..
                },
                ..
            }
        ));
        let _ = FixedTokenProvider::new(
            1,
            [CredentialBinding {
                credential_id: CredentialId::new("id").unwrap(),
                digest: TokenDigest::from_bytes([0; 32]),
                peer_id: peer.to_string(),
                tenant: Tenant::new("tenant").unwrap(),
                role: Role::Client,
                scopes: 0,
                quota_profile: QuotaProfile::new("standard").unwrap(),
                not_before: 0,
                expires_at: 100,
                revoked: false,
            }],
        );
    }
}
