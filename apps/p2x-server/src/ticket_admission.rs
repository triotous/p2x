use libp2p::PeerId;
use p2x_config::ticket_key::VerificationKeyRing;
use p2x_protocol::{
    OpenProxyStreamV1, PublicErrorCode, RegistrationRevision, ServiceAdvertisementV1, Tenant,
    TicketValidation,
};
use std::collections::HashMap;

pub const MAX_REPLAY_ENTRIES: usize = 8_192;
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
#[derive(Debug)]
pub struct TicketAdmissionLedger {
    capacity: usize,
    clock_skew: i64,
    replay: HashMap<[u8; 16], ReplayEntry>,
}
impl Default for TicketAdmissionLedger {
    fn default() -> Self {
        Self::new(MAX_REPLAY_ENTRIES, 5).expect("default ticket admission is valid")
    }
}
impl TicketAdmissionLedger {
    pub fn new(capacity: usize, clock_skew: i64) -> Result<Self, PublicErrorCode> {
        if capacity == 0 || capacity > 65_536 || !(0..=30).contains(&clock_skew) {
            return Err(PublicErrorCode::ProtocolMalformed);
        }
        Ok(Self {
            capacity,
            clock_skew,
            replay: HashMap::new(),
        })
    }
    #[allow(clippy::too_many_arguments)]
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

    pub fn validate_and_consume(
        &mut self,
        ring: &VerificationKeyRing,
        envelope: &[u8],
        expected: &TicketValidation<'_>,
        owner_fingerprint: [u8; 32],
    ) -> TicketAdmission {
        self.sweep(expected.now);
        let ticket = match ring.verify(envelope, expected) {
            Ok(ticket) => ticket,
            Err(p2x_protocol::ticket::TicketError::Expired) => {
                return TicketAdmission::Rejected(PublicErrorCode::AuthTicketExpired);
            }
            Err(_) => return TicketAdmission::Rejected(PublicErrorCode::AuthTicketInvalid),
        };
        let ticket_id = ticket.ticket_id();
        if self.replay.contains_key(&ticket_id) {
            return TicketAdmission::Rejected(PublicErrorCode::AuthTicketReplayed);
        }
        if self.replay.len() >= self.capacity {
            return TicketAdmission::Rejected(PublicErrorCode::LimitProxyStreams);
        }
        self.replay.insert(
            ticket_id,
            ReplayEntry {
                expires_at: ticket.claims().expires_at(),
                owner_fingerprint,
            },
        );
        TicketAdmission::Authorized(ticket_id)
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

    #[allow(dead_code)]
    pub fn clock_skew(&self) -> i64 {
        self.clock_skew
    }
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.replay.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use p2x_protocol::{TicketSigner, ticket::ConnectionTicketClaimsV1};
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
