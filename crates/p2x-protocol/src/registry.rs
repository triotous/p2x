use crate::{
    error::PublicError,
    ids::{InstanceId, RegistrationRevision, UpstreamId},
    selector::{ScopedSelector, SelectorError, UnscopedSelector},
};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, num::NonZeroU64};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Capabilities(u32);
impl Capabilities {
    pub const RELAY_V2: Self = Self(1);
    pub const DIRECT_TCP: Self = Self(2);
    pub const DIRECT_QUIC: Self = Self(4);
    pub const DCUTR: Self = Self(8);
    pub const fn empty() -> Self {
        Self(0)
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !(Self::RELAY_V2.0 | Self::DIRECT_TCP.0 | Self::DIRECT_QUIC.0 | Self::DCUTR.0)
            == 0
        {
            Some(Self(bits))
        } else {
            None
        }
    }
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn direct_transport(self) -> bool {
        self.contains(Self::DIRECT_TCP) || self.contains(Self::DIRECT_QUIC)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Health {
    Ready,
    Unavailable,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServiceAdvertisementV1 {
    upstream_id: UpstreamId,
    selector: UnscopedSelector,
    health: Health,
}
impl ServiceAdvertisementV1 {
    pub fn new(upstream_id: UpstreamId, selector: UnscopedSelector, health: Health) -> Self {
        Self {
            upstream_id,
            selector,
            health,
        }
    }
    pub fn upstream_id(&self) -> &UpstreamId {
        &self.upstream_id
    }
    pub fn selector(&self) -> &UnscopedSelector {
        &self.selector
    }
    pub const fn health(&self) -> Health {
        self.health
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceSet(Vec<ServiceAdvertisementV1>);
impl ServiceSet {
    pub fn new(mut services: Vec<ServiceAdvertisementV1>) -> Result<Self, SelectorError> {
        if services.is_empty() || services.len() > 128 {
            return Err(SelectorError::ServiceCount);
        }
        let mut upstream_ids = HashSet::with_capacity(services.len());
        let mut selectors = HashSet::with_capacity(services.len());
        for service in &services {
            if !upstream_ids.insert(service.upstream_id.clone())
                || !selectors.insert(service.selector.clone())
            {
                return Err(SelectorError::DuplicateService);
            }
        }
        services.sort_by(|a, b| a.upstream_id.as_str().cmp(b.upstream_id.as_str()));
        Ok(Self(services))
    }
    pub fn as_slice(&self) -> &[ServiceAdvertisementV1] {
        &self.0
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"p2x-service-set-v1\0");
        out.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        for service in &self.0 {
            put_bytes(&mut out, service.upstream_id.as_str().as_bytes());
            put_bytes(&mut out, &service.selector.canonical_bytes(None));
            out.push(match service.health {
                Health::Ready => 0,
                Health::Unavailable => 1,
            });
        }
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryRequestV1 {
    Register {
        request_id: [u8; 16],
        session_id: [u8; 16],
        instance_id: InstanceId,
        requested_lease_seconds: u16,
        capabilities: Capabilities,
        services: ServiceSet,
    },
    Refresh {
        request_id: [u8; 16],
        session_id: [u8; 16],
        instance_id: InstanceId,
        expected_registration_revision: NonZeroU64,
        requested_lease_seconds: u16,
    },
    Withdraw {
        request_id: [u8; 16],
        session_id: [u8; 16],
        instance_id: InstanceId,
        expected_registration_revision: NonZeroU64,
    },
}

impl RegistryRequestV1 {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"p2x-registry-request-v1\0");
        match self {
            Self::Register {
                request_id,
                session_id,
                instance_id,
                requested_lease_seconds,
                capabilities,
                services,
            } => {
                out.push(0);
                out.extend_from_slice(request_id);
                out.extend_from_slice(session_id);
                out.extend_from_slice(instance_id.as_bytes());
                out.extend_from_slice(&requested_lease_seconds.to_be_bytes());
                out.extend_from_slice(&capabilities.bits().to_be_bytes());
                put_bytes(&mut out, &services.canonical_bytes());
            }
            Self::Refresh {
                request_id,
                session_id,
                instance_id,
                expected_registration_revision,
                requested_lease_seconds,
            } => {
                out.push(1);
                out.extend_from_slice(request_id);
                out.extend_from_slice(session_id);
                out.extend_from_slice(instance_id.as_bytes());
                out.extend_from_slice(&expected_registration_revision.get().to_be_bytes());
                out.extend_from_slice(&requested_lease_seconds.to_be_bytes());
            }
            Self::Withdraw {
                request_id,
                session_id,
                instance_id,
                expected_registration_revision,
            } => {
                out.push(2);
                out.extend_from_slice(request_id);
                out.extend_from_slice(session_id);
                out.extend_from_slice(instance_id.as_bytes());
                out.extend_from_slice(&expected_registration_revision.get().to_be_bytes());
            }
        }
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryResponseV1 {
    Registered {
        request_id: [u8; 16],
        instance_id: InstanceId,
        registration_revision: RegistrationRevision,
        service_set_hash: [u8; 32],
        expires_at: i64,
        effective_lease_seconds: u16,
    },
    Refreshed {
        request_id: [u8; 16],
        instance_id: InstanceId,
        registration_revision: RegistrationRevision,
        expires_at: i64,
    },
    Withdrawn {
        request_id: [u8; 16],
        instance_id: InstanceId,
        registration_revision: RegistrationRevision,
    },
    Rejected {
        request_id: Option<[u8; 16]>,
        error: PublicError,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TenantSelector {
    pub selector: ScopedSelector,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Tenant,
        selector::{MetadataKey, MetadataValue, ProtocolClass},
    };
    use std::collections::BTreeMap;
    fn service(id: &str, value: &str) -> ServiceAdvertisementV1 {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            MetadataKey::new("service").unwrap(),
            MetadataValue::new(value).unwrap(),
        );
        ServiceAdvertisementV1::new(
            UpstreamId::new(id).unwrap(),
            UnscopedSelector::new(ProtocolClass::Http, metadata).unwrap(),
            Health::Ready,
        )
    }
    #[test]
    fn service_sets_are_sorted_and_unique() {
        let set = ServiceSet::new(vec![service("z", "z"), service("a", "a")]).unwrap();
        assert_eq!(set.as_slice()[0].upstream_id().as_str(), "a");
        assert!(matches!(
            ServiceSet::new(vec![service("a", "a"), service("a", "b")]),
            Err(SelectorError::DuplicateService)
        ));
        assert!(matches!(
            ServiceSet::new(vec![
                service("a", "same"),
                service("b", "other"),
                service("c", "same")
            ]),
            Err(SelectorError::DuplicateService)
        ));
        let _ = Tenant::new("t");
    }
    #[test]
    fn capabilities_are_closed() {
        assert!(Capabilities::from_bits(16).is_none());
        assert!(Capabilities::from_bits(7).unwrap().direct_transport());
    }
}
