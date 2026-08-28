use p2x_protocol::selector::{MetadataKey, MetadataValue, ProtocolClass, UnscopedSelector};
use p2x_protocol::{Health, ServiceAdvertisementV1, ServiceSet, UpstreamId};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::Duration,
};
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
    max_upstream_dials: Option<usize>,
    copy_buffer_bytes: Option<usize>,
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
    connect: String,
    connect_timeout_ms: Option<u64>,
    idle_timeout_ms: Option<u64>,
    concurrency_limit: Option<usize>,
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
    pub max_upstream_dials: usize,
    pub copy_buffer_bytes: usize,
    pub max_replay_entries: usize,
    pub ticket_clock_skew: u64,
}
#[derive(Clone, Eq, PartialEq)]
pub struct LocalUpstream {
    pub advertisement: ServiceAdvertisementV1,
    pub connect: SocketAddr,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub concurrency_limit: usize,
}
impl fmt::Debug for LocalUpstream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalUpstream")
            .field("advertisement", &self.advertisement)
            .field("connect", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("concurrency_limit", &self.concurrency_limit)
            .finish()
    }
}
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub requested_lease_seconds: u16,
    pub refresh_seconds: u16,
    pub services: ServiceSet,
    pub service_set_hash: [u8; 32],
    #[allow(dead_code)]
    pub upstreams: HashMap<UpstreamId, Arc<LocalUpstream>>,
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
        let mut upstreams = HashMap::new();
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
            let connect = entry.connect.parse::<SocketAddr>().map_err(|_| {
                ServiceConfigError::Invalid("connect must be an IP-literal socket address".into())
            })?;
            if connect.port() == 0 {
                return Err(ServiceConfigError::Invalid(
                    "connect port must be nonzero".into(),
                ));
            }
            let connect_timeout_ms = entry.connect_timeout_ms.unwrap_or(3_000);
            let idle_timeout_ms = entry.idle_timeout_ms.unwrap_or(300_000);
            let concurrency_limit = entry.concurrency_limit.unwrap_or(64);
            if !(100..=20_000).contains(&connect_timeout_ms)
                || !(1_000..=3_600_000).contains(&idle_timeout_ms)
                || !(1..=1_024).contains(&concurrency_limit)
            {
                return Err(ServiceConfigError::Invalid(
                    "invalid upstream bounds".into(),
                ));
            }
            let advertisement = ServiceAdvertisementV1::new(
                id.clone(),
                selector,
                if entry.enabled {
                    Health::Ready
                } else {
                    Health::Unavailable
                },
            );
            services.push(advertisement.clone());
            upstreams.insert(
                id,
                Arc::new(LocalUpstream {
                    advertisement,
                    connect,
                    connect_timeout: Duration::from_millis(connect_timeout_ms),
                    idle_timeout: Duration::from_millis(idle_timeout_ms),
                    concurrency_limit,
                }),
            );
        }
        let services =
            ServiceSet::new(services).map_err(|e| ServiceConfigError::Invalid(e.to_string()))?;
        let proxy = file.proxy.unwrap_or(Proxy {
            max_workers: None,
            max_workers_per_client: None,
            max_upstream_dials: None,
            copy_buffer_bytes: None,
            max_replay_entries: None,
            ticket_clock_skew: None,
        });
        let proxy = ProxyLimits {
            max_workers: proxy.max_workers.unwrap_or(256),
            max_workers_per_client: proxy.max_workers_per_client.unwrap_or(32),
            max_upstream_dials: proxy.max_upstream_dials.unwrap_or(64),
            copy_buffer_bytes: proxy.copy_buffer_bytes.unwrap_or(32 * 1024),
            max_replay_entries: proxy.max_replay_entries.unwrap_or(8_192),
            ticket_clock_skew: proxy.ticket_clock_skew.unwrap_or(5),
        };
        if proxy.max_workers == 0
            || proxy.max_workers > 2_048
            || proxy.max_workers_per_client == 0
            || proxy.max_workers_per_client > 256
            || proxy.max_upstream_dials == 0
            || proxy.max_upstream_dials > 512
            || proxy.max_upstream_dials > proxy.max_workers
            || !(p2x_proxy::MIN_COPY_BUFFER..=p2x_proxy::MAX_COPY_BUFFER)
                .contains(&proxy.copy_buffer_bytes)
            || proxy
                .copy_buffer_bytes
                .checked_mul(proxy.max_workers)
                .and_then(|value| value.checked_mul(2))
                .is_none()
            || upstreams
                .values()
                .any(|upstream| upstream.concurrency_limit > proxy.max_workers)
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
            upstreams,
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
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: http\n    metadata: {service: orders}\n  enabled: yes\n  connect: 127.0.0.1:5432\n").unwrap();
        assert!(ServiceConfig::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn disabled_services_are_retained_as_unavailable() {
        let path =
            std::env::temp_dir().join(format!("p2x-services-offline-{}", std::process::id()));
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: http\n    metadata: {service: orders}\n  enabled: false\n  connect: 127.0.0.1:5432\n").unwrap();
        let config = ServiceConfig::load(&path).unwrap();
        assert_eq!(config.services.as_slice()[0].health(), Health::Unavailable);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn immutable_upstream_is_private_and_redacted() {
        let path =
            std::env::temp_dir().join(format!("p2x-services-upstream-{}", std::process::id()));
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: tcp\n    metadata: {service: orders}\n  enabled: false\n  connect: 127.0.0.1:5432\n").unwrap();
        let config = ServiceConfig::load(&path).unwrap();
        let upstream = config
            .upstreams
            .get(&UpstreamId::new("orders").unwrap())
            .unwrap();
        assert_eq!(upstream.connect, "127.0.0.1:5432".parse().unwrap());
        assert!(!format!("{upstream:?}").contains("5432"));
        assert_eq!(config.service_set_hash, config.services.hash());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn strict_service_config_requires_enabled_service() {
        let path = std::env::temp_dir().join(format!("p2x-services-{}", std::process::id()));
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: http\n    metadata: {service: orders}\n  enabled: true\n  connect: 127.0.0.1:5432\n").unwrap();
        let config = ServiceConfig::load(&path).unwrap();
        assert_eq!(config.services.as_slice().len(), 1);
        std::fs::write(&path, "schema_version: 1\nregistration: {}\nservices: []\n").unwrap();
        assert!(ServiceConfig::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
