use p2x_protocol::selector::{MetadataKey, MetadataValue, ProtocolClass, UnscopedSelector};
use p2x_protocol::{Health, ServiceAdvertisementV1, ServiceSet, UpstreamId};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceConfigError {
    #[error("service configuration could not be loaded: {0}")]
    Load(String),
    #[error("service configuration is invalid: {0}")]
    Invalid(String),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema_version: u8,
    registration: Registration,
    services: Vec<Entry>,
    proxy: Option<Proxy>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proxy {
    max_workers: Option<usize>,
    max_workers_per_client: Option<usize>,
    max_replay_entries: Option<usize>,
    ticket_clock_skew: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    requested_lease_seconds: Option<u16>,
    refresh_seconds: Option<u16>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    upstream_id: String,
    selector: Selector,
    enabled: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    protocol: String,
    metadata: BTreeMap<String, String>,
}
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ProxyLimits {
    pub max_workers: usize,
    pub max_workers_per_client: usize,
    pub max_replay_entries: usize,
    pub ticket_clock_skew: u64,
}
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub requested_lease_seconds: u16,
    pub refresh_seconds: u16,
    pub services: ServiceSet,
    pub service_set_hash: [u8; 32],
    #[allow(dead_code)]
    pub proxy: ProxyLimits,
}
impl ServiceConfig {
    #[allow(dead_code)]
    pub fn service(&self, upstream_id: &UpstreamId) -> Option<&ServiceAdvertisementV1> {
        self.services
            .as_slice()
            .iter()
            .find(|service| service.upstream_id() == upstream_id)
    }

    pub fn load(path: &Path) -> Result<Self, ServiceConfigError> {
        let file: File =
            p2x_config::yaml::load(path).map_err(|e| ServiceConfigError::Load(e.to_string()))?;
        if file.schema_version != 1 {
            return Err(ServiceConfigError::Invalid(
                "schema_version must be 1".into(),
            ));
        }
        let lease = file.registration.requested_lease_seconds.unwrap_or(30);
        let refresh = file.registration.refresh_seconds.unwrap_or(10);
        if !(10..=60).contains(&lease) || refresh == 0 || refresh > lease / 2 {
            return Err(ServiceConfigError::Invalid(
                "invalid registration lease or refresh".into(),
            ));
        }
        if file.services.is_empty() || file.services.len() > 128 {
            return Err(ServiceConfigError::Invalid(
                "service entry count is out of bounds".into(),
            ));
        }
        let mut all_ids = std::collections::HashSet::new();
        let mut all_selectors = std::collections::HashSet::new();
        let mut services = Vec::new();
        for entry in file.services {
            let id = UpstreamId::new(&entry.upstream_id)
                .map_err(|_| ServiceConfigError::Invalid("invalid upstream_id".into()))?;
            let protocol = match entry.selector.protocol.as_str() {
                "http" => ProtocolClass::Http,
                "tls_passthrough" => ProtocolClass::TlsPassthrough,
                "tcp" => ProtocolClass::Tcp,
                _ => return Err(ServiceConfigError::Invalid("invalid protocol".into())),
            };
            let mut metadata = BTreeMap::new();
            for (key, value) in entry.selector.metadata {
                metadata.insert(
                    MetadataKey::new(&key)
                        .map_err(|_| ServiceConfigError::Invalid("invalid metadata key".into()))?,
                    MetadataValue::new(&value).map_err(|_| {
                        ServiceConfigError::Invalid("invalid metadata value".into())
                    })?,
                );
            }
            let selector = UnscopedSelector::new(protocol, metadata)
                .map_err(|e| ServiceConfigError::Invalid(e.to_string()))?;
            if !all_ids.insert(id.clone()) || !all_selectors.insert(selector.clone()) {
                return Err(ServiceConfigError::Invalid(
                    "duplicate service identifier or selector".into(),
                ));
            }
            services.push(ServiceAdvertisementV1::new(
                id,
                selector,
                if entry.enabled {
                    Health::Ready
                } else {
                    Health::Unavailable
                },
            ));
        }
        let services =
            ServiceSet::new(services).map_err(|e| ServiceConfigError::Invalid(e.to_string()))?;
        let proxy = file.proxy.unwrap_or(Proxy {
            max_workers: None,
            max_workers_per_client: None,
            max_replay_entries: None,
            ticket_clock_skew: None,
        });
        let proxy = ProxyLimits {
            max_workers: proxy.max_workers.unwrap_or(256),
            max_workers_per_client: proxy.max_workers_per_client.unwrap_or(32),
            max_replay_entries: proxy.max_replay_entries.unwrap_or(8_192),
            ticket_clock_skew: proxy.ticket_clock_skew.unwrap_or(5),
        };
        if proxy.max_workers == 0
            || proxy.max_workers > 2_048
            || proxy.max_workers_per_client == 0
            || proxy.max_workers_per_client > 256
            || proxy.max_replay_entries == 0
            || proxy.max_replay_entries > 65_536
            || proxy.ticket_clock_skew > 30
        {
            return Err(ServiceConfigError::Invalid("invalid proxy limits".into()));
        }
        let service_set_hash = services.hash();
        Ok(Self {
            requested_lease_seconds: lease,
            refresh_seconds: refresh,
            services,
            service_set_hash,
            proxy,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_service_config_rejects_unknown_and_non_strict_fields() {
        let path = std::env::temp_dir().join(format!("p2x-services-strict-{}", std::process::id()));
        std::fs::write(
            &path,
            "schema_version: 1\nregistration: {}\nunknown: true\nservices: []\n",
        )
        .unwrap();
        assert!(ServiceConfig::load(&path).is_err());
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: http\n    metadata: {service: orders}\n  enabled: yes\n").unwrap();
        assert!(ServiceConfig::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn disabled_services_are_retained_as_unavailable() {
        let path =
            std::env::temp_dir().join(format!("p2x-services-offline-{}", std::process::id()));
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: http\n    metadata: {service: orders}\n  enabled: false\n").unwrap();
        let config = ServiceConfig::load(&path).unwrap();
        assert_eq!(config.services.as_slice()[0].health(), Health::Unavailable);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn strict_service_config_requires_enabled_service() {
        let path = std::env::temp_dir().join(format!("p2x-services-{}", std::process::id()));
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: http\n    metadata: {service: orders}\n  enabled: true\n").unwrap();
        let config = ServiceConfig::load(&path).unwrap();
        assert_eq!(config.services.as_slice().len(), 1);
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices: []\n").unwrap();
        assert!(ServiceConfig::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
