use crate::ids::Tenant;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

pub const MAX_SELECTOR_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolClass {
    Http,
    TlsPassthrough,
    Tcp,
}
impl ProtocolClass {
    pub const fn wire(self) -> u8 {
        match self {
            Self::Http => 0,
            Self::TlsPassthrough => 1,
            Self::Tcp => 2,
        }
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MetadataKey(String);
impl MetadataKey {
    pub fn new(value: &str) -> Result<Self, SelectorError> {
        if value.is_empty()
            || value.len() > 64
            || value.bytes().enumerate().any(|(i, b)| {
                !(b.is_ascii_lowercase()
                    || (i > 0 && (b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'))))
            })
            || value.starts_with("p2x.")
        {
            return Err(SelectorError::InvalidMetadataKey);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for MetadataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MetadataKey").field(&self.0).finish()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct MetadataValue(String);
impl MetadataValue {
    pub fn new(value: &str) -> Result<Self, SelectorError> {
        let value = value.trim();
        if value.is_empty() || value.len() > 256 {
            return Err(SelectorError::InvalidMetadataValue);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for MetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MetadataValue").field(&self.0).finish()
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SelectorError {
    #[error("invalid metadata key")]
    InvalidMetadataKey,
    #[error("invalid metadata value")]
    InvalidMetadataValue,
    #[error("metadata count is out of bounds")]
    MetadataCount,
    #[error("selector is too large")]
    TooLarge,
    #[error("invalid identifier")]
    InvalidIdentifier,
    #[error("service set is empty or too large")]
    ServiceCount,
    #[error("duplicate service identifier or selector")]
    DuplicateService,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UnscopedSelector {
    protocol: ProtocolClass,
    metadata: BTreeMap<MetadataKey, MetadataValue>,
}
impl UnscopedSelector {
    pub fn new(
        protocol: ProtocolClass,
        metadata: BTreeMap<MetadataKey, MetadataValue>,
    ) -> Result<Self, SelectorError> {
        if metadata.is_empty() || metadata.len() > 32 {
            return Err(SelectorError::MetadataCount);
        }
        let selector = Self { protocol, metadata };
        if selector.canonical_bytes(None).len() > MAX_SELECTOR_BYTES {
            return Err(SelectorError::TooLarge);
        }
        Ok(selector)
    }
    pub const fn protocol(&self) -> ProtocolClass {
        self.protocol
    }
    pub fn metadata(&self) -> &BTreeMap<MetadataKey, MetadataValue> {
        &self.metadata
    }
    pub fn canonical_bytes(&self, tenant: Option<&Tenant>) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(tenant) = tenant {
            out.extend((tenant.as_str().len() as u16).to_be_bytes());
            out.extend(tenant.as_str().as_bytes());
        }
        out.push(self.protocol.wire());
        out.push(self.metadata.len() as u8);
        for (key, value) in &self.metadata {
            out.extend((key.0.len() as u16).to_be_bytes());
            out.extend(key.0.as_bytes());
            out.extend((value.0.len() as u16).to_be_bytes());
            out.extend(value.0.as_bytes());
        }
        out
    }
    pub fn fingerprint(&self, tenant: &Tenant) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"p2x-selector-v1\0");
        hasher.update(self.canonical_bytes(Some(tenant)));
        hasher.finalize().into()
    }
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ScopedSelector {
    tenant: Tenant,
    selector: UnscopedSelector,
}
impl ScopedSelector {
    pub fn new(tenant: Tenant, selector: UnscopedSelector) -> Self {
        Self { tenant, selector }
    }
    pub fn tenant(&self) -> &Tenant {
        &self.tenant
    }
    pub fn selector(&self) -> &UnscopedSelector {
        &self.selector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selector() -> UnscopedSelector {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            MetadataKey::new("environment").unwrap(),
            MetadataValue::new(" production ").unwrap(),
        );
        metadata.insert(
            MetadataKey::new("service").unwrap(),
            MetadataValue::new("orders").unwrap(),
        );
        UnscopedSelector::new(ProtocolClass::Http, metadata).unwrap()
    }
    #[test]
    fn canonicalizes_and_fingerprints() {
        let tenant = Tenant::new("tenant-a").unwrap();
        let selector = selector();
        assert_eq!(
            selector.metadata()[&MetadataKey::new("environment").unwrap()].as_str(),
            "production"
        );
        assert_eq!(
            selector.fingerprint(&tenant),
            [
                0x89, 0xff, 0xc2, 0xc6, 0x29, 0x67, 0xad, 0x3c, 0xa6, 0x45, 0x0e, 0x3d, 0xe4, 0x5a,
                0xc5, 0xc8, 0x6f, 0xfd, 0x7a, 0x7d, 0xfc, 0x6f, 0x4d, 0xb2, 0x40, 0xef, 0x35, 0xaa,
                0x5b, 0x73, 0x00, 0xdb,
            ]
        );
    }
    #[test]
    fn rejects_reserved_keys_and_invalid_counts() {
        assert_eq!(
            MetadataKey::new("p2x.secret"),
            Err(SelectorError::InvalidMetadataKey)
        );
        assert_eq!(
            MetadataValue::new("  "),
            Err(SelectorError::InvalidMetadataValue)
        );
        assert_eq!(
            UnscopedSelector::new(ProtocolClass::Tcp, BTreeMap::new()),
            Err(SelectorError::MetadataCount)
        );
    }
}
