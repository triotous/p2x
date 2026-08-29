use p2x_protocol::{MetadataKey, MetadataValue, ProtocolClass, UnscopedSelector};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    path::Path,
};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RouteConfigError {
    #[error("route configuration could not be loaded: {0}")]
    Load(String),
    #[error("route configuration is invalid: {0}")]
    Invalid(String),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema_version: u8,
    network: Network,
    targets: Vec<Target>,
    raw_tcp: Option<Vec<RawTcp>>,
    limits: Limits,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    direct_preference_ms: Option<u64>,
    connection_setup_timeout_ms: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    route_id: String,
    selector: Selector,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTcp {
    name: String,
    bind: String,
    route_id: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    protocol: String,
    metadata: BTreeMap<String, String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_peer_states: Option<usize>,
    max_pending_setups: Option<usize>,
    max_pending_per_server: Option<usize>,
    max_route_opens: Option<usize>,
    max_ingress_connections: Option<usize>,
    max_streams_per_server: Option<usize>,
    copy_buffer_bytes: Option<usize>,
}
#[derive(Clone, Debug)]
pub struct Route {
    pub route_id: String,
    pub selector: UnscopedSelector,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawTcpListener {
    pub name: String,
    pub bind: SocketAddr,
    pub route_id: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientLimits {
    pub max_peer_states: usize,
    pub max_pending_setups: usize,
    pub max_pending_per_server: usize,
    pub max_route_opens: usize,
    pub max_ingress_connections: usize,
    pub max_streams_per_server: usize,
    pub copy_buffer_bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientNetwork {
    pub direct_preference_ms: u64,
    pub connection_setup_timeout_ms: u64,
}
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub network: ClientNetwork,
    pub routes: Vec<Route>,
    pub raw_tcp: Vec<RawTcpListener>,
    pub limits: ClientLimits,
}

pub const MIN_COPY_BUFFER_BYTES: usize = 4 * 1024;
pub const MAX_COPY_BUFFER_BYTES: usize = 256 * 1024;
pub const MAX_INGRESS_CONNECTIONS: usize = 2_048;
pub const MAX_STREAMS_PER_SERVER: usize = 512;
impl ClientConfig {
    pub fn load(path: &Path) -> Result<Self, RouteConfigError> {
        let file: File =
            p2x_config::yaml::load(path).map_err(|e| RouteConfigError::Load(e.to_string()))?;
        if file.schema_version != 1 {
            return Err(RouteConfigError::Invalid("schema_version must be 1".into()));
        }
        let network = ClientNetwork {
            direct_preference_ms: file.network.direct_preference_ms.unwrap_or(1500),
            connection_setup_timeout_ms: file.network.connection_setup_timeout_ms.unwrap_or(20_000),
        };
        if network.direct_preference_ms > 5_000
            || !(1_000..=20_000).contains(&network.connection_setup_timeout_ms)
            || (network.direct_preference_ms != 0
                && network.direct_preference_ms >= network.connection_setup_timeout_ms)
        {
            return Err(RouteConfigError::Invalid(
                "invalid network timeout bounds".into(),
            ));
        }
        if !(1..=256).contains(&file.targets.len()) {
            return Err(RouteConfigError::Invalid(
                "target count is out of bounds".into(),
            ));
        }
        let limits = ClientLimits {
            max_peer_states: file.limits.max_peer_states.unwrap_or(64),
            max_pending_setups: file.limits.max_pending_setups.unwrap_or(256),
            max_pending_per_server: file.limits.max_pending_per_server.unwrap_or(64),
            max_route_opens: file.limits.max_route_opens.unwrap_or(128),
            max_ingress_connections: file.limits.max_ingress_connections.unwrap_or(512),
            max_streams_per_server: file.limits.max_streams_per_server.unwrap_or(128),
            copy_buffer_bytes: file.limits.copy_buffer_bytes.unwrap_or(32 * 1024),
        };
        if limits.max_peer_states == 0
            || limits.max_peer_states > 256
            || limits.max_pending_setups == 0
            || limits.max_pending_setups > 256
            || limits.max_pending_per_server == 0
            || limits.max_pending_per_server > 128
            || limits.max_route_opens == 0
            || limits.max_route_opens > 128
            || !(1..=MAX_INGRESS_CONNECTIONS).contains(&limits.max_ingress_connections)
            || !(1..=MAX_STREAMS_PER_SERVER).contains(&limits.max_streams_per_server)
            || !(MIN_COPY_BUFFER_BYTES..=MAX_COPY_BUFFER_BYTES).contains(&limits.copy_buffer_bytes)
            || limits
                .copy_buffer_bytes
                .checked_mul(limits.max_ingress_connections)
                .and_then(|value| value.checked_mul(3))
                .is_none()
        {
            return Err(RouteConfigError::Invalid("invalid client limits".into()));
        }
        let mut route_ids = HashSet::new();
        let routes = file
            .targets
            .into_iter()
            .map(|target| {
                if target.route_id.is_empty()
                    || target.route_id.len() > 64
                    || !target
                        .route_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    || !route_ids.insert(target.route_id.clone())
                {
                    return Err(RouteConfigError::Invalid(
                        "invalid or duplicate route_id".into(),
                    ));
                }
                let protocol = match target.selector.protocol.as_str() {
                    "http" => ProtocolClass::Http,
                    "tls_passthrough" => ProtocolClass::TlsPassthrough,
                    "tcp" => ProtocolClass::Tcp,
                    _ => return Err(RouteConfigError::Invalid("invalid protocol".into())),
                };
                let metadata = target
                    .selector
                    .metadata
                    .into_iter()
                    .map(|(key, value)| {
                        Ok((
                            MetadataKey::new(&key).map_err(|_| {
                                RouteConfigError::Invalid("invalid metadata key".into())
                            })?,
                            MetadataValue::new(&value).map_err(|_| {
                                RouteConfigError::Invalid("invalid metadata value".into())
                            })?,
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, RouteConfigError>>()?;
                Ok(Route {
                    route_id: target.route_id,
                    selector: UnscopedSelector::new(protocol, metadata)
                        .map_err(|e| RouteConfigError::Invalid(e.to_string()))?,
                })
            })
            .collect::<Result<Vec<_>, RouteConfigError>>()?;
        let route_by_id = routes
            .iter()
            .map(|route| (route.route_id.as_str(), route))
            .collect::<HashMap<_, _>>();
        let mut listener_names = HashSet::new();
        let mut listener_binds = HashSet::new();
        let raw_tcp = file
            .raw_tcp
            .unwrap_or_default()
            .into_iter()
            .map(|listener| {
                if listener.name.is_empty()
                    || listener.name.len() > 64
                    || !listener
                        .name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
                    || !listener_names.insert(listener.name.clone())
                {
                    return Err(RouteConfigError::Invalid(
                        "invalid or duplicate raw_tcp listener name".into(),
                    ));
                }
                let bind = listener.bind.parse::<SocketAddr>().map_err(|_| {
                    RouteConfigError::Invalid("invalid raw_tcp bind address".into())
                })?;
                if bind.port() == 0 || !bind.ip().is_loopback() || !listener_binds.insert(bind) {
                    return Err(RouteConfigError::Invalid(
                        "raw_tcp binds must be unique loopback addresses with nonzero ports".into(),
                    ));
                }
                let route = route_by_id.get(listener.route_id.as_str()).ok_or_else(|| {
                    RouteConfigError::Invalid("raw_tcp route_id must resolve exactly once".into())
                })?;
                if route.selector.protocol() != ProtocolClass::Tcp {
                    return Err(RouteConfigError::Invalid(
                        "raw_tcp route must use protocol tcp".into(),
                    ));
                }
                Ok(RawTcpListener {
                    name: listener.name,
                    bind,
                    route_id: listener.route_id,
                })
            })
            .collect::<Result<Vec<_>, RouteConfigError>>()?;
        Ok(Self {
            network,
            routes,
            raw_tcp,
            limits,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn file(body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "p2x-routes-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, body).unwrap();
        path
    }
    const VALID: &str = "schema_version: 1\nnetwork: {}\ntargets:\n  - route_id: orders\n    selector:\n      protocol: http\n      metadata: {service: orders}\nlimits: {}\n";
    const TCP_VALID: &str = "schema_version: 1\nnetwork: {}\ntargets:\n  - route_id: orders\n    selector:\n      protocol: tcp\n      metadata: {service: orders}\nraw_tcp:\n  - name: orders-local\n    bind: 127.0.0.1:15432\n    route_id: orders\nlimits: {}\n";
    #[test]
    fn strict_routes_validate_defaults_and_unknown_fields() {
        let path = file(VALID);
        let config = ClientConfig::load(&path).unwrap();
        assert_eq!(config.network.direct_preference_ms, 1500);
        assert_eq!(config.limits.max_peer_states, 64);
        assert!(config.raw_tcp.is_empty());
        std::fs::write(&path, format!("{VALID}extra: true\n")).unwrap();
        assert!(ClientConfig::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn fixed_tcp_listeners_require_unique_loopback_tcp_targets() {
        let path = file(TCP_VALID);
        let config = ClientConfig::load(&path).unwrap();
        assert_eq!(config.raw_tcp[0].bind, "127.0.0.1:15432".parse().unwrap());
        for invalid in [
            TCP_VALID.replace("127.0.0.1:15432", "0.0.0.0:15432"),
            TCP_VALID.replace("route_id: orders\nlimits", "route_id: missing\nlimits"),
            TCP_VALID.replace("protocol: tcp", "protocol: http"),
            TCP_VALID.replace(
                "name: orders-local",
                "name: orders-local\n  - name: orders-local",
            ),
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(ClientConfig::load(&path).is_err());
        }
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn timeout_and_duplicate_route_bounds_are_rejected() {
        let path = file(VALID);
        std::fs::write(&path, VALID.replace("route_id: orders", "route_id: orders\n  - route_id: orders\n    selector:\n      protocol: tcp\n      metadata: {{service: other}}" )).unwrap();
        assert!(ClientConfig::load(&path).is_err());
        std::fs::write(
            &path,
            VALID.replace(
                "network: {}",
                "network:\n  direct_preference_ms: 20000\n  connection_setup_timeout_ms: 1000",
            ),
        )
        .unwrap();
        assert!(ClientConfig::load(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
