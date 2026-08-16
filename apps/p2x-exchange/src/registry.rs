use libp2p::PeerId;
use p2x_protocol::{
    Capabilities, Health, InstanceId, PublicErrorCode, QuotaProfile, RegistrationRevision,
    RegistryRequestV1, RegistryResponseV1, Role, Scope, ScopedSelector, ServiceSet, Tenant,
};
use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroU64,
};

const MAX_SERVERS: usize = 64;
const MAX_SERVICES: usize = 32;
const MAX_IDEMPOTENCY_PER_PEER: usize = 8;
const MAX_IDEMPOTENCY_GLOBAL: usize = 2048;
const REVISION_ATTEMPTS: usize = 8;

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
    Malformed,
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
            Self::Malformed => PublicErrorCode::ProtocolMalformed,
        }
    }
}
#[derive(Clone, Debug)]
struct CachedResponse {
    digest: [u8; 32],
    response: RegistryResponseV1,
    created_at: i64,
}
#[derive(Default)]
pub struct Registry {
    registrations: HashMap<PeerId, RegistrationRecord>,
    selector_owners: HashMap<(Tenant, [u8; 32]), PeerId>,
    idempotency: HashMap<(PeerId, [u8; 16]), CachedResponse>,
    revision_allocator: RevisionAllocator,
    draining: bool,
    advertise_addresses: Vec<String>,
}
#[derive(Default)]
struct RevisionAllocator {
    candidates: Option<VecDeque<u64>>,
}
impl RevisionAllocator {
    fn next_unique<'a>(
        &mut self,
        records: impl Iterator<Item = &'a RegistrationRecord>,
    ) -> Option<RegistrationRevision> {
        let used = records
            .map(|record| record.registration_revision.get())
            .collect::<std::collections::HashSet<_>>();
        for _ in 0..REVISION_ATTEMPTS {
            let value = match self.candidates.as_mut() {
                Some(values) => values.pop_front().unwrap_or(0),
                None => {
                    let mut bytes = [0; 8];
                    getrandom::fill(&mut bytes).ok()?;
                    u64::from_be_bytes(bytes)
                }
            };
            if value != 0 && !used.contains(&value) {
                return RegistrationRevision::new(value);
            }
        }
        None
    }
}

impl Registry {
    pub fn set_draining(&mut self, value: bool) {
        self.draining = value;
    }
    pub fn set_advertise_addresses(&mut self, addresses: Vec<String>) {
        self.advertise_addresses = addresses;
    }

    #[cfg(test)]
    fn set_revision_candidates(&mut self, candidates: Vec<u64>) {
        self.revision_allocator = RevisionAllocator {
            candidates: Some(candidates.into()),
        };
    }
    #[allow(clippy::too_many_arguments)]
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
        let digest = request.hash();
        if let Some(cached) = self.idempotency.get(&(peer_id, request_id)) {
            if cached.digest == digest {
                return Ok(cached.response.clone());
            }
            return Err(RegistryError::Malformed);
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
            || !(10..=60).contains(&lease)
            || !capabilities.contains(Capabilities::RELAY_V2)
            || !capabilities.direct_transport()
            || capabilities.contains(Capabilities::DCUTR)
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
            if self
                .selector_owners
                .get(&key)
                .is_some_and(|owner| *owner != peer_id)
            {
                return Err(RegistryError::Conflict);
            }
            prepared_owners.push(key);
        }
        let revision = self
            .revision_allocator
            .next_unique(self.registrations.values())
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
            relay_addresses: self
                .advertise_addresses
                .iter()
                .map(|address| format!("{address}/p2p-circuit/p2p/{peer_id}"))
                .collect(),
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
        self.cache(peer_id, request_id, digest, response.clone(), now);
        let _ = session_id;
        Ok(response)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn refresh(
        &mut self,
        peer_id: PeerId,
        request_id: [u8; 16],
        instance_id: InstanceId,
        revision: RegistrationRevision,
        reserved: bool,
        tenant: &Tenant,
        role: Role,
        scopes: u32,
        quota: &QuotaProfile,
        authorization_revision: u64,
        requested_lease: u16,
        session_id: [u8; 16],
        now: i64,
    ) -> Result<RegistryResponseV1, RegistryError> {
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
        if !(10..=60).contains(&requested_lease) {
            return Err(RegistryError::InvalidAdvertisement);
        }
        let request = RegistryRequestV1::Refresh {
            request_id,
            session_id,
            instance_id,
            expected_registration_revision: NonZeroU64::new(revision.get())
                .expect("nonzero revision"),
            requested_lease_seconds: requested_lease,
        };
        let digest = request.hash();
        if let Some(cached) = self.idempotency.get(&(peer_id, request_id)) {
            if cached.digest == digest {
                return Ok(cached.response.clone());
            }
            return Err(RegistryError::Malformed);
        }
        if self
            .registrations
            .get(&peer_id)
            .is_some_and(|record| record.expires_at <= now)
        {
            self.remove_peer(&peer_id);
            return Err(RegistryError::NotFound);
        }
        let record = self
            .registrations
            .get_mut(&peer_id)
            .ok_or(RegistryError::NotFound)?;
        if record.instance_id != instance_id || record.registration_revision != revision {
            return Err(RegistryError::StaleRevision);
        }
        if record.authorization_revision != authorization_revision
            || record.tenant != *tenant
            || record.quota_profile != *quota
        {
            return Err(RegistryError::Unauthorized);
        }
        let lease = requested_lease;
        record.expires_at = now.saturating_add(lease as i64);
        let response = RegistryResponseV1::Refreshed {
            request_id,
            instance_id,
            registration_revision: revision,
            expires_at: record.expires_at,
        };
        self.cache(peer_id, request_id, digest, response.clone(), now);
        Ok(response)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &mut self,
        peer_id: PeerId,
        request_id: [u8; 16],
        instance_id: InstanceId,
        revision: RegistrationRevision,
        session_id: [u8; 16],
        tenant: &Tenant,
        role: Role,
        scopes: u32,
        quota: &QuotaProfile,
        authorization_revision: u64,
        now: i64,
    ) -> Result<RegistryResponseV1, RegistryError> {
        let request = RegistryRequestV1::Withdraw {
            request_id,
            session_id,
            instance_id,
            expected_registration_revision: NonZeroU64::new(revision.get())
                .expect("nonzero revision"),
        };
        let digest = request.hash();
        if role != Role::Server
            || scopes & Scope::RegisterServices.bit() == 0
            || quota.as_str() != "standard"
        {
            return Err(RegistryError::Unauthorized);
        }
        if let Some(cached) = self.idempotency.get(&(peer_id, request_id)) {
            if cached.digest == digest {
                return Ok(cached.response.clone());
            }
            return Err(RegistryError::Malformed);
        }
        if self
            .registrations
            .get(&peer_id)
            .is_some_and(|record| record.expires_at <= now)
        {
            self.remove_peer(&peer_id);
            return Err(RegistryError::NotFound);
        }
        let record = self
            .registrations
            .get(&peer_id)
            .ok_or(RegistryError::NotFound)?;
        if record.instance_id != instance_id || record.registration_revision != revision {
            return Err(RegistryError::StaleRevision);
        }
        if record.authorization_revision != authorization_revision
            || record.quota_profile != *quota
            || record.tenant != *tenant
        {
            return Err(RegistryError::Unauthorized);
        }
        let record = self
            .registrations
            .remove(&peer_id)
            .expect("record was checked");
        self.remove_indexes(&record);
        let response = RegistryResponseV1::Withdrawn {
            request_id,
            instance_id,
            registration_revision: revision,
        };
        self.cache(peer_id, request_id, digest, response.clone(), now);
        Ok(response)
    }
    pub fn clear(&mut self) {
        self.registrations.clear();
        self.selector_owners.clear();
        self.idempotency.clear();
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        let Some(record) = self.registrations.remove(peer_id) else {
            return false;
        };
        self.remove_indexes(&record);
        true
    }
    pub fn sweep(&mut self, now: i64) {
        self.idempotency.retain(|_, cached| {
            cached.created_at == i64::MAX || now.saturating_sub(cached.created_at) <= 60
        });
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
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
    pub fn owner_count(&self) -> usize {
        self.selector_owners.len()
    }

    pub fn resolve_exact(
        &self,
        selector: &ScopedSelector,
        now: i64,
    ) -> Result<&RegistrationRecord, RegistryError> {
        let key = (
            selector.tenant().clone(),
            selector.selector().fingerprint(selector.tenant()),
        );
        let peer = self
            .selector_owners
            .get(&key)
            .ok_or(RegistryError::NotFound)?;
        let record = self
            .registrations
            .get(peer)
            .ok_or(RegistryError::NotFound)?;
        if record.expires_at <= now {
            return Err(RegistryError::NotFound);
        }
        if record.services.as_slice().iter().any(|service| {
            service.selector() == selector.selector() && service.health() == Health::Ready
        }) {
            Ok(record)
        } else {
            Err(RegistryError::Offline)
        }
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
        created_at: i64,
    ) {
        let peer_entries = self
            .idempotency
            .iter()
            .filter(|((owner, _), _)| *owner == peer)
            .min_by_key(|(key, cached)| (cached.created_at, key.1))
            .map(|(key, _)| *key);
        if self.idempotency.len() >= MAX_IDEMPOTENCY_GLOBAL
            && let Some(oldest) = self
                .idempotency
                .iter()
                .min_by_key(|(key, cached)| (cached.created_at, key.1))
                .map(|(key, _)| *key)
        {
            self.idempotency.remove(&oldest);
        }
        if self
            .idempotency
            .keys()
            .filter(|(owner, _)| *owner == peer)
            .count()
            >= MAX_IDEMPOTENCY_PER_PEER
            && let Some(oldest) = peer_entries
        {
            self.idempotency.remove(&oldest);
        }
        self.idempotency.insert(
            (peer, request_id),
            CachedResponse {
                digest,
                response,
                created_at,
            },
        );
    }
}
fn service_set_hash(services: &ServiceSet) -> [u8; 32] {
    services.hash()
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
    fn refresh_and_withdraw_are_session_scoped_and_idempotent() {
        let (tenant, quota, services) = data();
        let peer = PeerId::random();
        let mut registry = Registry::default();
        let registered = registry
            .register(
                peer,
                &tenant,
                Role::Server,
                3,
                &quota,
                7,
                true,
                request(services, [1; 16]),
                10,
            )
            .unwrap();
        let (instance, revision) = match registered {
            RegistryResponseV1::Registered {
                instance_id,
                registration_revision,
                ..
            } => (instance_id, registration_revision),
            _ => unreachable!(),
        };
        let refreshed = registry
            .refresh(
                peer,
                [2; 16],
                instance,
                revision,
                true,
                &tenant,
                Role::Server,
                3,
                &quota,
                7,
                30,
                [2; 16],
                20,
            )
            .unwrap();
        assert_eq!(
            refreshed,
            registry
                .refresh(
                    peer,
                    [2; 16],
                    instance,
                    revision,
                    true,
                    &tenant,
                    Role::Server,
                    3,
                    &quota,
                    7,
                    30,
                    [2; 16],
                    99
                )
                .unwrap()
        );
        assert_eq!(
            registry
                .withdraw(
                    peer,
                    [3; 16],
                    instance,
                    revision,
                    [3; 16],
                    &tenant,
                    Role::Server,
                    3,
                    &quota,
                    7,
                    21
                )
                .unwrap(),
            RegistryResponseV1::Withdrawn {
                request_id: [3; 16],
                instance_id: instance,
                registration_revision: revision
            }
        );
        assert!(registry.is_empty());
    }
    #[test]
    fn expired_refresh_removes_record_and_rejects_resurrection() {
        let (tenant, quota, services) = data();
        let peer = PeerId::random();
        let mut registry = Registry::default();
        let response = registry
            .register(
                peer,
                &tenant,
                Role::Server,
                3,
                &quota,
                1,
                true,
                request(services, [1; 16]),
                10,
            )
            .unwrap();
        let (instance, revision) = match response {
            RegistryResponseV1::Registered {
                instance_id,
                registration_revision,
                ..
            } => (instance_id, registration_revision),
            _ => unreachable!(),
        };
        assert_eq!(
            registry.refresh(
                peer,
                [2; 16],
                instance,
                revision,
                true,
                &tenant,
                Role::Server,
                3,
                &quota,
                1,
                30,
                [2; 16],
                40
            ),
            Err(RegistryError::NotFound)
        );
        assert!(registry.is_empty());
        assert_eq!(registry.owner_count(), 0);
    }

    #[test]
    fn revision_allocator_exhaustion_is_atomic() {
        let (tenant, quota, services) = data();
        let peer = PeerId::random();
        let mut registry = Registry::default();
        registry.set_revision_candidates(vec![0; REVISION_ATTEMPTS]);
        assert_eq!(
            registry.register(
                peer,
                &tenant,
                Role::Server,
                3,
                &quota,
                1,
                true,
                request(services, [1; 16]),
                10
            ),
            Err(RegistryError::Overloaded)
        );
        assert!(registry.is_empty());
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
