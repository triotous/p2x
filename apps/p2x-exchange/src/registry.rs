use libp2p::PeerId;
use p2x_protocol::{
    Capabilities, Health, InstanceId, PublicErrorCode, QuotaProfile, RegistrationRevision,
    RegistryRequestV1, RegistryResponseV1, Role, Scope, ServiceSet, Tenant,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const MAX_SERVERS: usize = 64;
const MAX_SERVICES: usize = 32;
const MAX_IDEMPOTENCY_PER_PEER: usize = 8;
const MAX_IDEMPOTENCY_GLOBAL: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationRecord {
    pub peer_id: PeerId,
    pub instance_id: InstanceId,
    pub tenant: Tenant,
    pub authorization_revision: u64,
    pub quota_profile: QuotaProfile,
    pub registration_revision: RegistrationRevision,
    pub capabilities: Capabilities,
    pub service_set_hash: [u8; 32],
    pub services: ServiceSet,
    pub expires_at: i64,
    pub relay_addresses: Vec<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    InvalidAdvertisement,
    Conflict,
    ReservationRequired,
    StaleRevision,
    NotFound,
    Offline,
    LimitServices,
    Overloaded,
    Draining,
    Unauthorized,
}
impl RegistryError {
    pub const fn code(self) -> PublicErrorCode {
        match self {
            Self::InvalidAdvertisement => PublicErrorCode::RegistryInvalidAdvertisement,
            Self::Conflict => PublicErrorCode::RegistryConflict,
            Self::ReservationRequired => PublicErrorCode::RegistryReservationRequired,
            Self::StaleRevision => PublicErrorCode::RegistryStaleRevision,
            Self::NotFound => PublicErrorCode::RegistryNotFound,
            Self::Offline => PublicErrorCode::RegistryOffline,
            Self::LimitServices => PublicErrorCode::LimitServices,
            Self::Overloaded => PublicErrorCode::ExchangeOverloaded,
            Self::Draining => PublicErrorCode::ExchangeDraining,
            Self::Unauthorized => PublicErrorCode::AuthRoleForbidden,
        }
    }
}
#[derive(Clone, Debug)]
struct CachedResponse {
    digest: [u8; 32],
    response: RegistryResponseV1,
}
#[derive(Default)]
pub struct Registry {
    registrations: HashMap<PeerId, RegistrationRecord>,
    selector_owners: HashMap<(Tenant, [u8; 32]), PeerId>,
    idempotency: HashMap<(PeerId, [u8; 16]), CachedResponse>,
    revision_allocator: RevisionAllocator,
    draining: bool,
}
#[derive(Default)]
struct RevisionAllocator;
impl RevisionAllocator {
    fn next(&mut self) -> Option<RegistrationRevision> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).ok()?;
        RegistrationRevision::new(u64::from_be_bytes(bytes))
    }
}

impl Registry {
    pub fn set_draining(&mut self, value: bool) {
        self.draining = value;
    }
    pub fn register(
        &mut self,
        peer_id: PeerId,
        principal: &p2x_protocol::Tenant,
        role: Role,
        scopes: u32,
        quota: &QuotaProfile,
        authorization_revision: u64,
        reserved: bool,
        request: RegistryRequestV1,
        now: i64,
    ) -> Result<RegistryResponseV1, RegistryError> {
        let (request_id, session_id, instance_id, lease, capabilities, services) = match &request {
            RegistryRequestV1::Register {
                request_id,
                session_id,
                instance_id,
                requested_lease_seconds,
                capabilities,
                services,
            } => (
                *request_id,
                *session_id,
                *instance_id,
                *requested_lease_seconds,
                *capabilities,
                services,
            ),
            _ => return Err(RegistryError::InvalidAdvertisement),
        };
        let digest = request_digest(&request);
        if let Some(cached) = self.idempotency.get(&(peer_id, request_id)) {
            if cached.digest == digest {
                return Ok(cached.response.clone());
            }
            return Err(RegistryError::InvalidAdvertisement);
        }
        if self.draining {
            return Err(RegistryError::Draining);
        }
        if role != Role::Server
            || scopes & Scope::RegisterServices.bit() == 0
            || quota.as_str() != "standard"
        {
            return Err(RegistryError::Unauthorized);
        }
        if !reserved {
            return Err(RegistryError::ReservationRequired);
        }
        if services.as_slice().is_empty()
            || services.as_slice().len() > MAX_SERVICES
            || lease == 0
            || lease > 60
            || !capabilities.contains(Capabilities::RELAY_V2)
            || !capabilities.direct_transport()
        {
            return Err(RegistryError::InvalidAdvertisement);
        }
        if self.registrations.len() >= MAX_SERVERS && !self.registrations.contains_key(&peer_id) {
            return Err(RegistryError::Overloaded);
        }
        let mut prepared_owners = Vec::with_capacity(services.as_slice().len());
        for service in services.as_slice() {
            let fingerprint = service.selector().fingerprint(principal);
            let key = (principal.clone(), fingerprint);
            if let Some(owner) = self.selector_owners.get(&key) {
                if *owner != peer_id {
                    return Err(RegistryError::Conflict);
                }
            }
            prepared_owners.push(key);
        }
        let revision = self
            .revision_allocator
            .next()
            .ok_or(RegistryError::Overloaded)?;
        let hash = service_set_hash(services);
        let expires_at = now.saturating_add(lease as i64);
        let response = RegistryResponseV1::Registered {
            request_id,
            instance_id,
            registration_revision: revision,
            service_set_hash: hash,
            expires_at,
            effective_lease_seconds: lease,
        };
        let record = RegistrationRecord {
            peer_id,
            instance_id,
            tenant: principal.clone(),
            authorization_revision,
            quota_profile: quota.clone(),
            registration_revision: revision,
            capabilities,
            service_set_hash: hash,
            services: services.clone(),
            expires_at,
            relay_addresses: Vec::new(),
        };
        if let Some(old) = self.registrations.remove(&peer_id) {
            for service in old.services.as_slice() {
                self.selector_owners.remove(&(
                    old.tenant.clone(),
                    service.selector().fingerprint(&old.tenant),
                ));
            }
        }
        for key in prepared_owners {
            self.selector_owners.insert(key, peer_id);
        }
        self.registrations.insert(peer_id, record);
        self.cache(peer_id, request_id, digest, response.clone());
        let _ = session_id;
        Ok(response)
    }
    pub fn refresh(
        &mut self,
        peer_id: PeerId,
        instance_id: InstanceId,
        revision: RegistrationRevision,
        reserved: bool,
        requested_lease: u16,
        now: i64,
    ) -> Result<RegistryResponseV1, RegistryError> {
        if self.draining {
            return Err(RegistryError::Draining);
        }
        if !reserved {
            return Err(RegistryError::ReservationRequired);
        }
        let record = self
            .registrations
            .get_mut(&peer_id)
            .ok_or(RegistryError::NotFound)?;
        if record.instance_id != instance_id || record.registration_revision != revision {
            return Err(RegistryError::StaleRevision);
        }
        let lease = requested_lease.clamp(1, 60);
        record.expires_at = now.saturating_add(lease as i64);
        Ok(RegistryResponseV1::Refreshed {
            request_id: [0; 16],
            instance_id,
            registration_revision: revision,
            expires_at: record.expires_at,
        })
    }
    pub fn withdraw(
        &mut self,
        peer_id: PeerId,
        instance_id: InstanceId,
        revision: RegistrationRevision,
    ) -> Result<RegistryResponseV1, RegistryError> {
        let record = self
            .registrations
            .get(&peer_id)
            .ok_or(RegistryError::NotFound)?;
        if record.instance_id != instance_id || record.registration_revision != revision {
            return Err(RegistryError::StaleRevision);
        }
        let record = self
            .registrations
            .remove(&peer_id)
            .expect("record was checked");
        self.remove_indexes(&record);
        Ok(RegistryResponseV1::Withdrawn {
            request_id: [0; 16],
            instance_id,
            registration_revision: revision,
        })
    }
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        let Some(record) = self.registrations.remove(peer_id) else {
            return false;
        };
        self.remove_indexes(&record);
        true
    }
    pub fn sweep(&mut self, now: i64) {
        let peers = self
            .registrations
            .iter()
            .filter(|(_, record)| record.expires_at <= now)
            .map(|(peer, _)| *peer)
            .collect::<Vec<_>>();
        for peer in peers {
            self.remove_peer(&peer);
        }
    }
    pub fn get(&self, peer_id: &PeerId) -> Option<&RegistrationRecord> {
        self.registrations.get(peer_id)
    }
    pub fn len(&self) -> usize {
        self.registrations.len()
    }
    pub fn owner_count(&self) -> usize {
        self.selector_owners.len()
    }
    fn remove_indexes(&mut self, record: &RegistrationRecord) {
        for service in record.services.as_slice() {
            self.selector_owners.remove(&(
                record.tenant.clone(),
                service.selector().fingerprint(&record.tenant),
            ));
        }
    }
    fn cache(
        &mut self,
        peer: PeerId,
        request_id: [u8; 16],
        digest: [u8; 32],
        response: RegistryResponseV1,
    ) {
        if self.idempotency.len() >= MAX_IDEMPOTENCY_GLOBAL {
            self.idempotency.clear();
        }
        let peer_entries = self
            .idempotency
            .keys()
            .filter(|(owner, _)| *owner == peer)
            .copied()
            .collect::<Vec<_>>();
        if peer_entries.len() >= MAX_IDEMPOTENCY_PER_PEER {
            if let Some(oldest) = peer_entries.first() {
                self.idempotency.remove(oldest);
            }
        }
        self.idempotency
            .insert((peer, request_id), CachedResponse { digest, response });
    }
}
fn request_digest(request: &RegistryRequestV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{request:?}").as_bytes());
    hasher.finalize().into()
}
fn service_set_hash(services: &ServiceSet) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for service in services.as_slice() {
        hasher.update(service.upstream_id().as_str().as_bytes());
        hasher.update(service.selector().canonical_bytes(None));
        hasher.update([match service.health() {
            Health::Ready => 0,
            Health::Unavailable => 1,
        }]);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2x_protocol::selector::{MetadataKey, MetadataValue, ProtocolClass, UnscopedSelector};
    use std::collections::BTreeMap;
    fn data() -> (Tenant, QuotaProfile, ServiceSet) {
        let tenant = Tenant::new("tenant").unwrap();
        let quota = QuotaProfile::new("standard").unwrap();
        let mut metadata = BTreeMap::new();
        metadata.insert(
            MetadataKey::new("service").unwrap(),
            MetadataValue::new("orders").unwrap(),
        );
        let selector = UnscopedSelector::new(ProtocolClass::Http, metadata).unwrap();
        let service = p2x_protocol::ServiceAdvertisementV1::new(
            p2x_protocol::UpstreamId::new("orders").unwrap(),
            selector,
            Health::Ready,
        );
        (tenant, quota, ServiceSet::new(vec![service]).unwrap())
    }
    fn request(services: ServiceSet, id: [u8; 16]) -> RegistryRequestV1 {
        RegistryRequestV1::Register {
            request_id: id,
            session_id: [2; 16],
            instance_id: InstanceId::new([3; 16]),
            requested_lease_seconds: 30,
            capabilities: Capabilities::from_bits(7).unwrap(),
            services,
        }
    }
    #[test]
    fn replacement_conflict_expiry_and_idempotency_are_atomic() {
        let (tenant, quota, services) = data();
        let peer = PeerId::random();
        let mut registry = Registry::default();
        let first = registry
            .register(
                peer,
                &tenant,
                Role::Server,
                3,
                &quota,
                1,
                true,
                request(services.clone(), [1; 16]),
                10,
            )
            .unwrap();
        let second = registry
            .register(
                peer,
                &tenant,
                Role::Server,
                3,
                &quota,
                1,
                true,
                request(services.clone(), [1; 16]),
                10,
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.owner_count(), 1);
        assert!(matches!(
            registry.register(
                PeerId::random(),
                &tenant,
                Role::Server,
                3,
                &quota,
                1,
                true,
                request(services, [4; 16]),
                10
            ),
            Err(RegistryError::Conflict)
        ));
        registry.sweep(40);
        assert_eq!(registry.len(), 0);
        assert_eq!(registry.owner_count(), 0);
    }
    #[test]
    fn removal_is_idempotent_and_requires_reservation() {
        let (tenant, quota, services) = data();
        let peer = PeerId::random();
        let mut registry = Registry::default();
        assert_eq!(
            registry.register(
                peer,
                &tenant,
                Role::Server,
                3,
                &quota,
                1,
                false,
                request(services, [1; 16]),
                10
            ),
            Err(RegistryError::ReservationRequired)
        );
        assert!(!registry.remove_peer(&peer));
    }
}
