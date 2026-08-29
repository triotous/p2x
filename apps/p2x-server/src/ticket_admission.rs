use libp2p::PeerId;
use p2x_config::ticket_key::VerificationKeyRing;
use p2x_protocol::{
    OpenProxyStreamV1, PublicErrorCode, RegistrationRevision, ServiceAdvertisementV1, Tenant,
    TicketValidation,
};
use std::collections::HashMap;

pub const MAX_REPLAY_ENTRIES: usize = 8_192;
pub const MAX_REPLAY_ENTRIES_HARD: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationCandidate {
    pub ticket_id: [u8; 16],
    pub claims: p2x_protocol::ticket::ConnectionTicketClaimsV1,
    pub owner_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TicketAdmission {
    Authorized([u8; 16]),
    Rejected(PublicErrorCode),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplayEntry {
    expires_at: i64,
    owner_fingerprint: [u8; 32],
}
pub struct TicketAdmissionLedger {
    capacity: usize,
    clock_skew: i64,
    replay: HashMap<[u8; 16], ReplayEntry>,
    stream_id_source: Box<dyn FnMut() -> Result<[u8; 16], PublicErrorCode>>,
}
impl Default for TicketAdmissionLedger {
    fn default() -> Self {
        Self::new(MAX_REPLAY_ENTRIES, 5).expect("default ticket admission is valid")
    }
}
impl TicketAdmissionLedger {
    pub fn new(capacity: usize, clock_skew: i64) -> Result<Self, PublicErrorCode> {
        if capacity == 0 || capacity > MAX_REPLAY_ENTRIES_HARD || !(0..=30).contains(&clock_skew) {
            return Err(PublicErrorCode::ProtocolMalformed);
        }
        Ok(Self {
            capacity,
            clock_skew,
            replay: HashMap::new(),
            stream_id_source: Box::new(random_stream_id),
        })
    }

    #[cfg(test)]
    fn with_stream_id_source(
        mut self,
        source: impl FnMut() -> Result<[u8; 16], PublicErrorCode> + 'static,
    ) -> Self {
        self.stream_id_source = Box::new(source);
        self
    }
    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn authorize_open(
        &mut self,
        ring: &VerificationKeyRing,
        issuer: PeerId,
        client: PeerId,
        server: PeerId,
        tenant: &Tenant,
        service: &ServiceAdvertisementV1,
        registration_revision: Option<RegistrationRevision>,
        registration_expires_at: i64,
        authorization_revision: u64,
        open: &OpenProxyStreamV1,
        now: i64,
        owner_fingerprint: [u8; 32],
    ) -> TicketAdmission {
        let Some(registration_revision) = registration_revision else {
            return TicketAdmission::Rejected(PublicErrorCode::RegistryStaleRevision);
        };
        if registration_expires_at <= now || service.health() != p2x_protocol::Health::Ready {
            return TicketAdmission::Rejected(PublicErrorCode::RegistryStaleRevision);
        }
        let (_, claims, _) = match p2x_protocol::ticket::decode_envelope(open.ticket.as_bytes()) {
            Ok(value) => value,
            Err(_) => return TicketAdmission::Rejected(PublicErrorCode::AuthTicketInvalid),
        };
        let fingerprint = service.selector().fingerprint(tenant);
        if open.upstream_id != *service.upstream_id()
            || open.registration_revision != registration_revision
            || claims.upstream_id() != service.upstream_id().as_str()
            || claims.registration_revision() != registration_revision.get()
        {
            return TicketAdmission::Rejected(PublicErrorCode::AuthTicketInvalid);
        }
        let issuer_bytes = issuer.to_bytes();
        let client_bytes = client.to_bytes();
        let server_bytes = server.to_bytes();
        let expected = TicketValidation {
            issuer_exchange_peer_id: &issuer_bytes,
            client_peer_id: &client_bytes,
            server_peer_id: &server_bytes,
            tenant: tenant.as_str(),
            upstream_id: service.upstream_id().as_str(),
            selector_fingerprint: fingerprint,
            registration_revision: registration_revision.get(),
            authorization_revision,
            permissions: p2x_protocol::Scope::OpenProxyStream.bit(),
            max_streams: 1,
            now,
            clock_skew: self.clock_skew,
        };
        self.validate_and_consume(ring, open.ticket.as_bytes(), &expected, owner_fingerprint)
    }

    #[allow(dead_code)]
    pub fn verify_candidate(
        &self,
        ring: &VerificationKeyRing,
        envelope: &[u8],
        now: i64,
    ) -> Result<ValidationCandidate, PublicErrorCode> {
        let ticket = p2x_protocol::ticket::verify_signature_with_key_resolver(
            envelope,
            ring,
            now,
            self.clock_skew,
        )
        .map_err(|error| match error {
            p2x_protocol::ticket::TicketError::Expired => PublicErrorCode::AuthTicketExpired,
            _ => PublicErrorCode::AuthTicketInvalid,
        })?;
        Ok(ValidationCandidate {
            ticket_id: ticket.ticket_id(),
            claims: ticket.claims().clone(),
            owner_fingerprint: [0; 32],
        })
    }

    pub fn candidate_time_valid(&self, candidate: &ValidationCandidate, now: i64) -> bool {
        candidate.claims.expires_at() > now.saturating_sub(self.clock_skew)
            && candidate.claims.not_before() <= now.saturating_add(self.clock_skew)
    }

    pub fn preflight_candidate(
        &mut self,
        candidate: &ValidationCandidate,
        now: i64,
    ) -> Result<(), PublicErrorCode> {
        self.sweep(now);
        if !self.candidate_time_valid(candidate, now) {
            return Err(PublicErrorCode::AuthTicketExpired);
        }
        if self.replay.contains_key(&candidate.ticket_id) {
            return Err(PublicErrorCode::AuthTicketReplayed);
        }
        if self.replay.len() >= self.capacity {
            return Err(PublicErrorCode::LimitProxyStreams);
        }
        Ok(())
    }

    pub fn allocate_stream_id(
        &mut self,
        candidate: &ValidationCandidate,
        now: i64,
    ) -> Result<[u8; 16], PublicErrorCode> {
        self.preflight_candidate(candidate, now)?;
        let stream_id = (self.stream_id_source)()?;
        if stream_id == [0; 16] {
            return Err(PublicErrorCode::ExchangeOverloaded);
        }
        Ok(stream_id)
    }

    pub fn consume_candidate_with_stream_id(
        &mut self,
        candidate: ValidationCandidate,
        stream_id: [u8; 16],
        now: i64,
    ) -> TicketAdmission {
        if let Err(code) = self.preflight_candidate(&candidate, now) {
            return TicketAdmission::Rejected(code);
        }
        if stream_id == [0; 16] {
            return TicketAdmission::Rejected(PublicErrorCode::ExchangeOverloaded);
        }
        self.replay.insert(
            candidate.ticket_id,
            ReplayEntry {
                expires_at: candidate.claims.expires_at(),
                owner_fingerprint: candidate.owner_fingerprint,
            },
        );
        TicketAdmission::Authorized(stream_id)
    }

    pub fn consume_candidate(
        &mut self,
        candidate: ValidationCandidate,
        now: i64,
    ) -> TicketAdmission {
        let stream_id = match self.allocate_stream_id(&candidate, now) {
            Ok(stream_id) => stream_id,
            Err(code) => return TicketAdmission::Rejected(code),
        };
        self.consume_candidate_with_stream_id(candidate, stream_id, now)
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn validate_candidate(
        &self,
        candidate: &ValidationCandidate,
        issuer: PeerId,
        client: PeerId,
        server: PeerId,
        tenant: &Tenant,
        service: &ServiceAdvertisementV1,
        registration_revision: Option<RegistrationRevision>,
        registration_expires_at: i64,
        authorization_revision: u64,
        open: &OpenProxyStreamV1,
        now: i64,
    ) -> Result<(), PublicErrorCode> {
        let Some(registration_revision) = registration_revision else {
            return Err(PublicErrorCode::RegistryStaleRevision);
        };
        if registration_expires_at <= now || service.health() != p2x_protocol::Health::Ready {
            return Err(PublicErrorCode::RegistryStaleRevision);
        }
        if open.registration_revision != registration_revision
            || candidate.claims.registration_revision() != registration_revision.get()
        {
            return Err(PublicErrorCode::RegistryStaleRevision);
        }
        let selector_fingerprint = service.selector().fingerprint(tenant);
        let issuer_bytes = issuer.to_bytes();
        let client_bytes = client.to_bytes();
        let server_bytes = server.to_bytes();
        let claims = &candidate.claims;
        if open.upstream_id != *service.upstream_id()
            || open.registration_revision != registration_revision
            || claims.issuer_exchange_peer_id() != issuer_bytes
            || claims.client_peer_id() != client_bytes
            || claims.server_peer_id() != server_bytes
            || claims.tenant() != tenant.as_str()
            || claims.upstream_id() != service.upstream_id().as_str()
            || claims.selector_fingerprint() != selector_fingerprint
            || claims.authorization_revision() != authorization_revision
            || claims.permissions() != p2x_protocol::Scope::OpenProxyStream.bit()
            || claims.max_streams() != 1
        {
            return Err(PublicErrorCode::AuthTicketInvalid);
        }
        Ok(())
    }

    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn authorize_candidate(
        &mut self,
        candidate: ValidationCandidate,
        issuer: PeerId,
        client: PeerId,
        server: PeerId,
        tenant: &Tenant,
        service: &ServiceAdvertisementV1,
        registration_revision: Option<RegistrationRevision>,
        registration_expires_at: i64,
        authorization_revision: u64,
        open: &OpenProxyStreamV1,
        now: i64,
    ) -> TicketAdmission {
        if let Err(code) = self.validate_candidate(
            &candidate,
            issuer,
            client,
            server,
            tenant,
            service,
            registration_revision,
            registration_expires_at,
            authorization_revision,
            open,
            now,
        ) {
            return TicketAdmission::Rejected(code);
        }
        self.consume_candidate(candidate, now)
    }

    #[allow(dead_code)]
    pub fn validate_and_consume(
        &mut self,
        ring: &VerificationKeyRing,
        envelope: &[u8],
        expected: &TicketValidation<'_>,
        owner_fingerprint: [u8; 32],
    ) -> TicketAdmission {
        let ticket = match ring.verify(envelope, expected) {
            Ok(ticket) => ticket,
            Err(p2x_protocol::ticket::TicketError::Expired) => {
                return TicketAdmission::Rejected(PublicErrorCode::AuthTicketExpired);
            }
            Err(_) => return TicketAdmission::Rejected(PublicErrorCode::AuthTicketInvalid),
        };
        self.consume_candidate(
            ValidationCandidate {
                ticket_id: ticket.ticket_id(),
                claims: ticket.claims().clone(),
                owner_fingerprint,
            },
            expected.now,
        )
    }
    pub fn sweep(&mut self, now: i64) {
        let skew = self.clock_skew;
        self.replay
            .retain(|_, entry| entry.expires_at.saturating_add(skew) > now);
    }
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.replay.len()
    }

    pub fn is_empty(&self) -> bool {
        self.replay.is_empty()
    }

    #[allow(dead_code)]
    pub fn clock_skew(&self) -> i64 {
        self.clock_skew
    }
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.replay.clear();
    }

    #[allow(dead_code)]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

fn random_stream_id() -> Result<[u8; 16], PublicErrorCode> {
    let mut stream_id = [0u8; 16];
    getrandom::fill(&mut stream_id).map_err(|_| PublicErrorCode::LimitProxyStreams)?;
    Ok(stream_id)
}
#[cfg(test)]
mod tests {
    use super::*;
    use p2x_protocol::{TicketSigner, ticket::ConnectionTicketClaimsV1};
    #[test]
    fn invalid_binding_does_not_consume_replay_entry() {
        let signer = TicketSigner::from_seed([9; 32]);
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let id = libp2p::PeerId::from_public_key(&peer.public()).to_bytes();
        let claims = ConnectionTicketClaimsV1::new(
            id.to_vec(),
            "tenant".into(),
            id.to_vec(),
            id.to_vec(),
            "orders".into(),
            [3; 32],
            1,
            2,
            4,
            10,
            20,
            [5; 16],
            1,
        )
        .unwrap();
        let envelope = signer.sign(&claims).unwrap();
        let ring = verification_ring(&signer);
        let mut expected = TicketValidation {
            issuer_exchange_peer_id: &id,
            client_peer_id: &id,
            server_peer_id: &id,
            tenant: "tenant",
            upstream_id: "wrong",
            selector_fingerprint: [3; 32],
            registration_revision: 1,
            authorization_revision: 2,
            permissions: 4,
            max_streams: 1,
            now: 15,
            clock_skew: 0,
        };
        let mut admission = TicketAdmissionLedger::new(1, 0)
            .unwrap()
            .with_stream_id_source(|| Ok([9; 16]));
        assert_eq!(
            admission.validate_and_consume(&ring, envelope.as_bytes(), &expected, [7; 32]),
            TicketAdmission::Rejected(PublicErrorCode::AuthTicketInvalid)
        );
        expected.upstream_id = "orders";
        assert_eq!(
            admission.validate_and_consume(&ring, envelope.as_bytes(), &expected, [7; 32]),
            TicketAdmission::Authorized([9; 16])
        );
        assert_eq!(admission.len(), 1);
    }

    #[test]
    fn explicit_stream_id_is_consumed_only_after_admission() {
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from_public_key(&peer.public()).to_bytes();
        let candidate = ValidationCandidate {
            ticket_id: [8; 16],
            claims: p2x_protocol::ticket::ConnectionTicketClaimsV1::new(
                peer_id.clone(),
                "tenant".into(),
                peer_id.clone(),
                peer_id,
                "orders".into(),
                [4; 32],
                1,
                2,
                4,
                10,
                20,
                [8; 16],
                1,
            )
            .unwrap(),
            owner_fingerprint: [6; 32],
        };
        let mut admission = TicketAdmissionLedger::new(1, 0)
            .unwrap()
            .with_stream_id_source(|| Ok([9; 16]));
        assert_eq!(
            admission.allocate_stream_id(&candidate, 11).unwrap(),
            [9; 16]
        );
        assert_eq!(admission.len(), 0);
        assert_eq!(
            admission.consume_candidate_with_stream_id(candidate, [9; 16], 11),
            TicketAdmission::Authorized([9; 16])
        );
        assert_eq!(admission.len(), 1);
    }

    #[test]
    fn stream_id_failure_does_not_consume_replay_capacity() {
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from_public_key(&peer.public()).to_bytes();
        let claims = ConnectionTicketClaimsV1::new(
            peer_id.clone(),
            "tenant".into(),
            peer_id.clone(),
            peer_id,
            "orders".into(),
            [4; 32],
            1,
            1,
            p2x_protocol::Scope::OpenProxyStream.bit(),
            10,
            20,
            [5; 16],
            1,
        )
        .unwrap();
        let candidate = ValidationCandidate {
            ticket_id: [5; 16],
            claims,
            owner_fingerprint: [6; 32],
        };
        let mut admission = TicketAdmissionLedger::new(1, 0)
            .unwrap()
            .with_stream_id_source(|| Err(PublicErrorCode::LimitProxyStreams));
        assert_eq!(
            admission.consume_candidate(candidate, 11),
            TicketAdmission::Rejected(PublicErrorCode::LimitProxyStreams)
        );
        assert_eq!(admission.len(), 0);
    }

    #[test]
    fn stale_current_registration_rejects_before_replay_consume() {
        use std::collections::BTreeMap;
        let signer = TicketSigner::from_seed([9; 32]);
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let id = libp2p::PeerId::from_public_key(&peer.public());
        let tenant = Tenant::new("tenant").unwrap();
        let selector = p2x_protocol::UnscopedSelector::new(
            p2x_protocol::ProtocolClass::Http,
            BTreeMap::from([(
                p2x_protocol::MetadataKey::new("service").unwrap(),
                p2x_protocol::MetadataValue::new("orders").unwrap(),
            )]),
        )
        .unwrap();
        let service = ServiceAdvertisementV1::new(
            p2x_protocol::UpstreamId::new("orders").unwrap(),
            selector,
            p2x_protocol::Health::Ready,
        );
        let claims = ConnectionTicketClaimsV1::new(
            id.to_bytes().to_vec(),
            tenant.as_str().into(),
            id.to_bytes().to_vec(),
            id.to_bytes().to_vec(),
            "orders".into(),
            [3; 32],
            1,
            2,
            4,
            10,
            20,
            [5; 16],
            1,
        )
        .unwrap();
        let envelope = signer.sign(&claims).unwrap();
        let open = OpenProxyStreamV1 {
            request_id: [1; 16],
            ticket: p2x_protocol::RawTicket::new(envelope.as_bytes().to_vec()).unwrap(),
            upstream_id: p2x_protocol::UpstreamId::new("orders").unwrap(),
            registration_revision: RegistrationRevision::new(1).unwrap(),
            ingress_kind: p2x_protocol::IngressKind::FixedTcp,
        };
        let mut admission = TicketAdmissionLedger::new(1, 0).unwrap();
        assert_eq!(
            admission.authorize_candidate(
                ValidationCandidate {
                    ticket_id: [5; 16],
                    claims,
                    owner_fingerprint: [7; 32],
                },
                id,
                id,
                id,
                &tenant,
                &service,
                RegistrationRevision::new(2),
                30,
                2,
                &open,
                15,
            ),
            TicketAdmission::Rejected(PublicErrorCode::RegistryStaleRevision)
        );
        assert_eq!(admission.len(), 0);
    }

    #[test]
    fn ticket_binding_matrix_rejects_without_consuming_replay() {
        let signer = TicketSigner::from_seed([9; 32]);
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let id = libp2p::PeerId::from_public_key(&peer.public()).to_bytes();
        let claims = ConnectionTicketClaimsV1::new(
            id.to_vec(),
            "tenant".into(),
            id.to_vec(),
            id.to_vec(),
            "orders".into(),
            [3; 32],
            1,
            2,
            4,
            10,
            20,
            [5; 16],
            1,
        )
        .unwrap();
        let envelope = signer.sign(&claims).unwrap();
        let ring = verification_ring(&signer);
        let base = || TicketValidation {
            issuer_exchange_peer_id: &id,
            client_peer_id: &id,
            server_peer_id: &id,
            tenant: "tenant",
            upstream_id: "orders",
            selector_fingerprint: [3; 32],
            registration_revision: 1,
            authorization_revision: 2,
            permissions: 4,
            max_streams: 1,
            now: 15,
            clock_skew: 0,
        };
        let mut cases = Vec::new();
        let mut issuer = [0; 38];
        issuer[0] = 1;
        cases.push(("issuer", issuer.to_vec()));
        let mut client = [0; 38];
        client[0] = 1;
        cases.push(("client", client.to_vec()));
        let mut server = [0; 38];
        server[0] = 1;
        cases.push(("server", server.to_vec()));
        for (name, value) in cases {
            let mut expected = base();
            match name {
                "issuer" => expected.issuer_exchange_peer_id = &value,
                "client" => expected.client_peer_id = &value,
                "server" => expected.server_peer_id = &value,
                _ => unreachable!(),
            }
            let mut admission = TicketAdmissionLedger::new(32, 0).unwrap();
            assert_eq!(
                admission.validate_and_consume(&ring, envelope.as_bytes(), &expected, [7; 32]),
                TicketAdmission::Rejected(PublicErrorCode::AuthTicketInvalid)
            );
            assert_eq!(admission.len(), 0);
        }
        for (_name, expected) in [
            (
                "tenant",
                TicketValidation {
                    tenant: "other",
                    ..base()
                },
            ),
            (
                "upstream",
                TicketValidation {
                    upstream_id: "other",
                    ..base()
                },
            ),
            (
                "selector",
                TicketValidation {
                    selector_fingerprint: [4; 32],
                    ..base()
                },
            ),
            (
                "registration",
                TicketValidation {
                    registration_revision: 2,
                    ..base()
                },
            ),
            (
                "authorization",
                TicketValidation {
                    authorization_revision: 3,
                    ..base()
                },
            ),
            (
                "permissions",
                TicketValidation {
                    permissions: 0,
                    ..base()
                },
            ),
            (
                "max_streams",
                TicketValidation {
                    max_streams: 2,
                    ..base()
                },
            ),
            ("not_before", TicketValidation { now: 1, ..base() }),
        ] {
            let mut admission = TicketAdmissionLedger::new(32, 0).unwrap();
            let expected_code = PublicErrorCode::AuthTicketInvalid;
            assert_eq!(
                admission.validate_and_consume(&ring, envelope.as_bytes(), &expected, [7; 32]),
                TicketAdmission::Rejected(expected_code)
            );
            assert_eq!(admission.len(), 0);
        }
        let wrong_ring = verification_ring(&TicketSigner::from_seed([8; 32]));
        let mut admission = TicketAdmissionLedger::new(32, 0).unwrap();
        assert_eq!(
            admission.validate_and_consume(&wrong_ring, envelope.as_bytes(), &base(), [7; 32]),
            TicketAdmission::Rejected(PublicErrorCode::AuthTicketInvalid)
        );
        assert_eq!(admission.len(), 0);
    }

    #[test]
    fn owner_time_recheck_rejects_expired_candidate() {
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from_public_key(&peer.public()).to_bytes();
        let candidate = ValidationCandidate {
            ticket_id: [8; 16],
            claims: p2x_protocol::ticket::ConnectionTicketClaimsV1::new(
                peer_id.clone(),
                "tenant".into(),
                peer_id.clone(),
                peer_id,
                "orders".into(),
                [4; 32],
                1,
                2,
                4,
                10,
                20,
                [8; 16],
                1,
            )
            .unwrap(),
            owner_fingerprint: [0; 32],
        };
        let admission = TicketAdmissionLedger::new(1, 0).unwrap();
        assert!(admission.candidate_time_valid(&candidate, 19));
        assert!(!admission.candidate_time_valid(&candidate, 20));
    }

    #[test]
    fn replay_retention_includes_expiry_plus_clock_skew() {
        let signer = TicketSigner::from_seed([9; 32]);
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let id = libp2p::PeerId::from_public_key(&peer.public()).to_bytes();
        let claims = ConnectionTicketClaimsV1::new(
            id.to_vec(),
            "tenant".into(),
            id.to_vec(),
            id.to_vec(),
            "orders".into(),
            [3; 32],
            1,
            2,
            4,
            10,
            20,
            [5; 16],
            1,
        )
        .unwrap();
        let envelope = signer.sign(&claims).unwrap();
        let ring = verification_ring(&signer);
        let expected = |now| TicketValidation {
            issuer_exchange_peer_id: &id,
            client_peer_id: &id,
            server_peer_id: &id,
            tenant: "tenant",
            upstream_id: "orders",
            selector_fingerprint: [3; 32],
            registration_revision: 1,
            authorization_revision: 2,
            permissions: 4,
            max_streams: 1,
            now,
            clock_skew: 5,
        };
        let mut admission = TicketAdmissionLedger::new(1, 5).unwrap();
        assert!(matches!(
            admission.validate_and_consume(&ring, envelope.as_bytes(), &expected(15), [7; 32]),
            TicketAdmission::Authorized(_)
        ));
        admission.sweep(24);
        assert_eq!(admission.len(), 1);
        admission.sweep(25);
        assert_eq!(admission.len(), 0);
    }

    #[test]
    fn valid_ticket_is_consumed_once_and_capacity_does_not_evict_live_entries() {
        let signer = TicketSigner::from_seed([9; 32]);
        let peer = libp2p::identity::Keypair::generate_ed25519();
        let id = libp2p::PeerId::from_public_key(&peer.public()).to_bytes();
        let claims = ConnectionTicketClaimsV1::new(
            id.to_vec(),
            "tenant".into(),
            id.to_vec(),
            id.to_vec(),
            "orders".into(),
            [3; 32],
            1,
            2,
            4,
            10,
            20,
            [5; 16],
            1,
        )
        .unwrap();
        let envelope = signer.sign(&claims).unwrap();
        let ring = verification_ring(&signer);
        let expected = TicketValidation {
            issuer_exchange_peer_id: &id,
            client_peer_id: &id,
            server_peer_id: &id,
            tenant: "tenant",
            upstream_id: "orders",
            selector_fingerprint: [3; 32],
            registration_revision: 1,
            authorization_revision: 2,
            permissions: 4,
            max_streams: 1,
            now: 15,
            clock_skew: 0,
        };
        let mut admission = TicketAdmissionLedger::new(1, 0).unwrap();
        assert!(matches!(
            admission.validate_and_consume(&ring, envelope.as_bytes(), &expected, [7; 32]),
            TicketAdmission::Authorized(_)
        ));
        assert_eq!(
            admission.validate_and_consume(&ring, envelope.as_bytes(), &expected, [7; 32]),
            TicketAdmission::Rejected(PublicErrorCode::AuthTicketReplayed)
        );
    }
    fn verification_ring(signer: &TicketSigner) -> VerificationKeyRing {
        let mut ring = VerificationKeyRing::default();
        ring.add(p2x_config::ticket_key::VerificationKey {
            key_id: signer.key_id(),
            public: signer.public_key(),
            activates_at: 0,
            retires_at: None,
        })
        .unwrap();
        ring
    }
}
