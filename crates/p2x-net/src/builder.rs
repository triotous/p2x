use crate::{
    auth_codec::{AUTH_PROTOCOL, AuthCodec},
    probe_stream::ProbeStreamBehaviour,
    registry_codec::{REGISTRY_PROTOCOL, RegistryCodec},
    relay_admission::{CircuitAuthorization, RelayAdmissionHandle, ReservationAuthorization},
};
use libp2p::core::transport::ListenerId;
use libp2p::swarm::{NetworkBehaviour, Swarm};
use libp2p::{Multiaddr, PeerId, dcutr, identify, noise, ping, relay, tcp, yamux};
use std::{net::IpAddr, num::NonZeroU32, time::Duration};
use thiserror::Error;

pub const IDENTIFY_PROTOCOL: &str = "/p2x/connectivity/0.1.0";
pub const AUTH_REQUEST_TIMEOUT_SECONDS: u64 = 5;
pub const REGISTRY_REQUEST_TIMEOUT_SECONDS: u64 = 5;
pub const PROBE_PROTOCOL: libp2p::StreamProtocol = libp2p::StreamProtocol::new("/p2x/spike/1");
pub const MAX_STREAMS: usize = 256;
pub const MAX_NEGOTIATIONS: usize = 64;
pub const PROBE_TIMEOUT_SECONDS: u64 = 5;
pub const IDLE_TIMEOUT_SECONDS: u64 = 120;
pub const PING_INTERVAL_SECONDS: u64 = 15;
pub const PING_TIMEOUT_SECONDS: u64 = 5;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RuntimeMode {
    #[default]
    Product,
    ConnectivityLab,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RelayProfile {
    #[default]
    Product,
    DefaultLab,
    LimitTest,
}
impl RelayProfile {
    pub fn config(self) -> relay::Config {
        let product = matches!(self, Self::Product);
        let limit = matches!(self, Self::LimitTest);
        relay::Config {
            max_reservations: if limit { 2 } else { 64 },
            max_reservations_per_peer: if product || limit { 0 } else { 1 },
            reservation_duration: Duration::from_secs(60),
            max_circuits: if limit { 2 } else { 128 },
            max_circuits_per_peer: if product {
                31
            } else if limit {
                0
            } else {
                3
            },
            max_circuit_duration: if limit {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(3600)
            },
            max_circuit_bytes: if limit {
                16 * 1024 * 1024
            } else {
                1024 * 1024 * 1024
            },
            reservation_rate_limiters: vec![],
            circuit_src_rate_limiters: vec![],
        }
        .reservation_rate_per_peer(
            NonZeroU32::new(if limit { 8 } else { 256 }).expect("positive relay rate"),
            Duration::from_secs(60),
        )
        .reservation_rate_per_ip(
            NonZeroU32::new(if limit { 16 } else { 512 }).expect("positive relay rate"),
            Duration::from_secs(60),
        )
        .circuit_src_per_peer(
            NonZeroU32::new(if limit { 8 } else { 1024 }).expect("positive relay rate"),
            Duration::from_secs(60),
        )
        .circuit_src_per_ip(
            NonZeroU32::new(if limit { 16 } else { 2048 }).expect("positive relay rate"),
            Duration::from_secs(60),
        )
    }
}

pub fn lab_identity(seed: Option<u64>) -> Result<libp2p::identity::Keypair, BuildError> {
    match seed {
        None => Ok(libp2p::identity::Keypair::generate_ed25519()),
        Some(seed) => {
            let mut bytes = [0u8; 32];
            let mut value = seed;
            for byte in &mut bytes {
                value ^= value << 13;
                value ^= value >> 7;
                value ^= value << 17;
                *byte = value as u8;
            }
            libp2p::identity::Keypair::ed25519_from_bytes(bytes)
                .map_err(|e| BuildError::Builder(e.to_string()))
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExchangeSwarmConfig {
    pub tcp_listen: Multiaddr,
    pub quic_listen: Multiaddr,
    pub allow_public: bool,
    pub relay_profile: RelayProfile,
    pub relay_admission: Option<RelayAdmissionHandle>,
    pub mode: RuntimeMode,
}

impl Default for ExchangeSwarmConfig {
    fn default() -> Self {
        Self {
            tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().expect("valid TCP default"),
            quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid QUIC default"),
            allow_public: false,
            relay_profile: RelayProfile::Product,
            relay_admission: None,
            mode: RuntimeMode::Product,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerSwarmConfig {
    pub tcp_listen: Multiaddr,
    pub quic_listen: Multiaddr,
    pub mode: RuntimeMode,
    pub relay_client_enabled: bool,
    pub registry_enabled: bool,
    pub auth_fault: Option<crate::auth_codec::AuthFault>,
}

impl Default for PeerSwarmConfig {
    fn default() -> Self {
        Self {
            tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().expect("valid TCP default"),
            quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1"
                .parse()
                .expect("valid QUIC default"),
            mode: RuntimeMode::Product,
            relay_client_enabled: false,
            registry_enabled: false,
            auth_fault: None,
        }
    }
}

impl PeerSwarmConfig {
    pub fn is_connectivity_lab(&self) -> bool {
        self.mode == RuntimeMode::ConnectivityLab
    }
}

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("non-loopback listener requires the lab public acknowledgement")]
    PublicListener,
    #[error("invalid {transport} listener address: {address}")]
    InvalidListener {
        transport: &'static str,
        address: Multiaddr,
    },
    #[error("failed to start {transport} listener: {message}")]
    Listener {
        transport: &'static str,
        message: String,
    },
    #[error("swarm builder failed: {0}")]
    Builder(String),
}
impl ExchangeSwarmConfig {
    pub fn validate(&self) -> Result<(), BuildError> {
        validate_listener(&self.tcp_listen, "tcp")?;
        validate_listener(&self.quic_listen, "quic")?;
        for address in [&self.tcp_listen, &self.quic_listen] {
            let ip = listener_ip(address).ok_or_else(|| BuildError::InvalidListener {
                transport: "exchange",
                address: address.clone(),
            })?;
            if !ip.is_loopback() && !self.allow_public {
                return Err(BuildError::PublicListener);
            }
        }
        Ok(())
    }
}

impl PeerSwarmConfig {
    pub fn validate(&self) -> Result<(), BuildError> {
        validate_listener(&self.tcp_listen, "tcp")?;
        validate_listener(&self.quic_listen, "quic")
    }
}

fn validate_listener(address: &Multiaddr, transport: &'static str) -> Result<(), BuildError> {
    use libp2p::multiaddr::Protocol;
    let valid = match transport {
        "tcp" => {
            address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
                && !address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
        }
        "quic" => {
            address.iter().any(|p| matches!(p, Protocol::Udp(_)))
                && address.iter().any(|p| matches!(p, Protocol::QuicV1))
                && !address.iter().any(|p| matches!(p, Protocol::P2pCircuit))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(BuildError::InvalidListener {
            transport,
            address: address.clone(),
        })
    }
}

fn listener_ip(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ExchangeEvent", prelude = "libp2p::swarm::derive_prelude")]
pub struct ExchangeBehaviour {
    pub relay: libp2p::swarm::behaviour::toggle::Toggle<relay::Behaviour>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub auth: libp2p::request_response::Behaviour<AuthCodec>,
    pub registry: libp2p::request_response::Behaviour<RegistryCodec>,
}
#[derive(Debug)]
pub enum ExchangeEvent {
    Relay(relay::Event),
    Identify(Box<identify::Event>),
    Ping(ping::Event),
    Auth(libp2p::request_response::Event<p2x_protocol::AuthRequest, p2x_protocol::AuthResponse>),
    Registry(
        libp2p::request_response::Event<
            p2x_protocol::RegistryRequestV1,
            p2x_protocol::RegistryResponseV1,
        >,
    ),
}
impl From<relay::Event> for ExchangeEvent {
    fn from(v: relay::Event) -> Self {
        Self::Relay(v)
    }
}
impl From<identify::Event> for ExchangeEvent {
    fn from(v: identify::Event) -> Self {
        Self::Identify(Box::new(v))
    }
}
impl
    From<
        libp2p::request_response::Event<
            p2x_protocol::RegistryRequestV1,
            p2x_protocol::RegistryResponseV1,
        >,
    > for ExchangeEvent
{
    fn from(
        v: libp2p::request_response::Event<
            p2x_protocol::RegistryRequestV1,
            p2x_protocol::RegistryResponseV1,
        >,
    ) -> Self {
        Self::Registry(v)
    }
}
impl From<libp2p::request_response::Event<p2x_protocol::AuthRequest, p2x_protocol::AuthResponse>>
    for ExchangeEvent
{
    fn from(
        v: libp2p::request_response::Event<p2x_protocol::AuthRequest, p2x_protocol::AuthResponse>,
    ) -> Self {
        Self::Auth(v)
    }
}
impl From<ping::Event> for ExchangeEvent {
    fn from(v: ping::Event) -> Self {
        Self::Ping(v)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "PeerEvent", prelude = "libp2p::swarm::derive_prelude")]
pub struct PeerBehaviour {
    pub relay_client: libp2p::swarm::behaviour::toggle::Toggle<relay::client::Behaviour>,
    pub dcutr: libp2p::swarm::behaviour::toggle::Toggle<dcutr::Behaviour>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub probe_stream: libp2p::swarm::behaviour::toggle::Toggle<ProbeStreamBehaviour>,
    pub auth: libp2p::request_response::Behaviour<AuthCodec>,
    pub registry: libp2p::request_response::Behaviour<RegistryCodec>,
}
#[derive(Debug)]
pub enum PeerEvent {
    Relay(relay::client::Event),
    Dcutr(dcutr::Event),
    Identify(Box<identify::Event>),
    Ping(ping::Event),
    Probe(crate::probe_stream::behaviour::ProbeOutput),
    Auth(libp2p::request_response::Event<p2x_protocol::AuthRequest, p2x_protocol::AuthResponse>),
    Registry(
        libp2p::request_response::Event<
            p2x_protocol::RegistryRequestV1,
            p2x_protocol::RegistryResponseV1,
        >,
    ),
}
impl From<relay::client::Event> for PeerEvent {
    fn from(v: relay::client::Event) -> Self {
        Self::Relay(v)
    }
}
impl From<dcutr::Event> for PeerEvent {
    fn from(v: dcutr::Event) -> Self {
        Self::Dcutr(v)
    }
}
impl From<identify::Event> for PeerEvent {
    fn from(v: identify::Event) -> Self {
        Self::Identify(Box::new(v))
    }
}
impl From<ping::Event> for PeerEvent {
    fn from(v: ping::Event) -> Self {
        Self::Ping(v)
    }
}
impl
    From<
        libp2p::request_response::Event<
            p2x_protocol::RegistryRequestV1,
            p2x_protocol::RegistryResponseV1,
        >,
    > for PeerEvent
{
    fn from(
        v: libp2p::request_response::Event<
            p2x_protocol::RegistryRequestV1,
            p2x_protocol::RegistryResponseV1,
        >,
    ) -> Self {
        Self::Registry(v)
    }
}
impl From<libp2p::request_response::Event<p2x_protocol::AuthRequest, p2x_protocol::AuthResponse>>
    for PeerEvent
{
    fn from(
        v: libp2p::request_response::Event<p2x_protocol::AuthRequest, p2x_protocol::AuthResponse>,
    ) -> Self {
        Self::Auth(v)
    }
}
impl From<crate::probe_stream::behaviour::ProbeOutput> for PeerEvent {
    fn from(v: crate::probe_stream::behaviour::ProbeOutput) -> Self {
        Self::Probe(v)
    }
}

pub fn build_exchange_swarm(
    keypair: libp2p::identity::Keypair,
    config: &ExchangeSwarmConfig,
) -> Result<Swarm<ExchangeBehaviour>, BuildError> {
    config.validate()?;
    let peer_id = PeerId::from_public_key(&keypair.public());
    let public_key = keypair.public();
    libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                let mut config = yamux::Config::default();
                config.set_max_num_streams(MAX_STREAMS);
                config
            },
        )
        .map_err(|e| BuildError::Builder(e.to_string()))?
        .with_quic_config(|mut quic| {
            quic.max_concurrent_stream_limit = MAX_STREAMS as u32;
            quic
        })
        .with_dns()
        .map_err(|e| BuildError::Builder(e.to_string()))?
        .with_behaviour(|_| ExchangeBehaviour {
            relay: libp2p::swarm::behaviour::toggle::Toggle::from(
                (config.mode == RuntimeMode::ConnectivityLab || config.relay_admission.is_some())
                    .then(|| {
                        let mut relay_config = config.relay_profile.config();
                        if let Some(admission) = config.relay_admission.clone() {
                            relay_config.reservation_rate_limiters.insert(
                                0,
                                Box::new(ReservationAuthorization::new(admission.clone())),
                            );
                            relay_config
                                .circuit_src_rate_limiters
                                .insert(0, Box::new(CircuitAuthorization::new(admission)));
                        }
                        relay::Behaviour::new(peer_id, relay_config)
                    }),
            ),
            identify: identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), public_key)
                    .with_push_listen_addr_updates(true),
            ),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(PING_INTERVAL_SECONDS))
                    .with_timeout(Duration::from_secs(PING_TIMEOUT_SECONDS)),
            ),
            auth: libp2p::request_response::Behaviour::with_codec(
                AuthCodec::default(),
                [(
                    libp2p::StreamProtocol::new(AUTH_PROTOCOL),
                    libp2p::request_response::ProtocolSupport::Inbound,
                )],
                libp2p::request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(AUTH_REQUEST_TIMEOUT_SECONDS)),
            ),
            registry: libp2p::request_response::Behaviour::with_codec(
                RegistryCodec,
                [(
                    libp2p::StreamProtocol::new(REGISTRY_PROTOCOL),
                    libp2p::request_response::ProtocolSupport::Inbound,
                )],
                libp2p::request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(REGISTRY_REQUEST_TIMEOUT_SECONDS)),
            ),
        })
        .map_err(|e| BuildError::Builder(e.to_string()))
        .map(|b| {
            b.with_swarm_config(|config| {
                config
                    .with_max_negotiating_inbound_streams(MAX_NEGOTIATIONS)
                    .with_idle_connection_timeout(Duration::from_secs(IDLE_TIMEOUT_SECONDS))
            })
            .build()
        })
}
pub fn build_peer_swarm(
    keypair: libp2p::identity::Keypair,
    config: &PeerSwarmConfig,
) -> Result<Swarm<PeerBehaviour>, BuildError> {
    config.validate()?;
    let peer_id = PeerId::from_public_key(&keypair.public());
    let public_key = keypair.public();
    libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                let mut config = yamux::Config::default();
                config.set_max_num_streams(MAX_STREAMS);
                config
            },
        )
        .map_err(|e| BuildError::Builder(e.to_string()))?
        .with_quic_config(|mut quic| {
            quic.max_concurrent_stream_limit = MAX_STREAMS as u32;
            quic
        })
        .with_dns()
        .map_err(|e| BuildError::Builder(e.to_string()))?
        .with_relay_client(noise::Config::new, || {
            let mut config = yamux::Config::default();
            config.set_max_num_streams(MAX_STREAMS);
            config
        })
        .map_err(|e| BuildError::Builder(e.to_string()))?
        .with_behaviour(|_, relay_client| PeerBehaviour {
            relay_client: libp2p::swarm::behaviour::toggle::Toggle::from(
                (config.mode == RuntimeMode::ConnectivityLab || config.relay_client_enabled)
                    .then_some(relay_client),
            ),
            dcutr: libp2p::swarm::behaviour::toggle::Toggle::from(
                (config.mode == RuntimeMode::ConnectivityLab)
                    .then(|| dcutr::Behaviour::new(peer_id)),
            ),
            identify: identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), public_key)
                    .with_push_listen_addr_updates(true),
            ),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(PING_INTERVAL_SECONDS))
                    .with_timeout(Duration::from_secs(PING_TIMEOUT_SECONDS)),
            ),
            probe_stream: libp2p::swarm::behaviour::toggle::Toggle::from(
                (config.mode == RuntimeMode::ConnectivityLab).then(ProbeStreamBehaviour::default),
            ),
            auth: libp2p::request_response::Behaviour::with_codec(
                AuthCodec::with_fault(config.auth_fault),
                [(
                    libp2p::StreamProtocol::new(AUTH_PROTOCOL),
                    libp2p::request_response::ProtocolSupport::Outbound,
                )],
                libp2p::request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(AUTH_REQUEST_TIMEOUT_SECONDS)),
            ),
            registry: libp2p::request_response::Behaviour::with_codec(
                RegistryCodec,
                (config.mode == RuntimeMode::Product && config.registry_enabled).then_some((
                    libp2p::StreamProtocol::new(REGISTRY_PROTOCOL),
                    libp2p::request_response::ProtocolSupport::Outbound,
                )),
                libp2p::request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(REGISTRY_REQUEST_TIMEOUT_SECONDS)),
            ),
        })
        .map_err(|e| BuildError::Builder(e.to_string()))
        .map(|b| {
            b.with_swarm_config(|config| {
                config
                    .with_max_negotiating_inbound_streams(MAX_NEGOTIATIONS)
                    .with_idle_connection_timeout(Duration::from_secs(IDLE_TIMEOUT_SECONDS))
            })
            .build()
        })
}

pub fn start_exchange_listeners(
    swarm: &mut Swarm<ExchangeBehaviour>,
    config: &ExchangeSwarmConfig,
) -> Result<[ListenerId; 2], BuildError> {
    config.validate()?;
    start_listeners(swarm, &config.tcp_listen, &config.quic_listen)
}

pub fn start_peer_listeners(
    swarm: &mut Swarm<PeerBehaviour>,
    config: &PeerSwarmConfig,
) -> Result<[ListenerId; 2], BuildError> {
    config.validate()?;
    start_listeners(swarm, &config.tcp_listen, &config.quic_listen)
}

fn start_listeners<B: NetworkBehaviour>(
    swarm: &mut Swarm<B>,
    tcp: &Multiaddr,
    quic: &Multiaddr,
) -> Result<[ListenerId; 2], BuildError> {
    let tcp_listener = swarm
        .listen_on(tcp.clone())
        .map_err(|error| BuildError::Listener {
            transport: "tcp",
            message: error.to_string(),
        })?;
    let quic_listener = swarm
        .listen_on(quic.clone())
        .map_err(|error| BuildError::Listener {
            transport: "quic",
            message: error.to_string(),
        })?;
    Ok([tcp_listener, quic_listener])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn product_and_lab_surfaces_are_distinct() {
        let product = build_exchange_swarm(
            libp2p::identity::Keypair::generate_ed25519(),
            &ExchangeSwarmConfig::default(),
        )
        .unwrap();
        assert!(!product.behaviour().relay.is_enabled());
        let lab = build_exchange_swarm(
            libp2p::identity::Keypair::generate_ed25519(),
            &ExchangeSwarmConfig {
                mode: RuntimeMode::ConnectivityLab,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(lab.behaviour().relay.is_enabled());

        let product = build_peer_swarm(
            libp2p::identity::Keypair::generate_ed25519(),
            &PeerSwarmConfig::default(),
        )
        .unwrap();
        assert!(!product.behaviour().probe_stream.is_enabled());
        assert!(!product.behaviour().relay_client.is_enabled());
        assert!(!product.behaviour().dcutr.is_enabled());
        let lab = build_peer_swarm(
            libp2p::identity::Keypair::generate_ed25519(),
            &PeerSwarmConfig {
                mode: RuntimeMode::ConnectivityLab,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(lab.behaviour().probe_stream.is_enabled());
        assert!(lab.behaviour().relay_client.is_enabled());
        assert!(lab.behaviour().dcutr.is_enabled());
    }

    #[test]
    fn protocol_surface_is_exact() {
        assert_eq!(MAX_STREAMS, 256);
        assert_eq!(MAX_NEGOTIATIONS, 64);
    }
    #[test]
    fn concrete_swarms_build_with_loopback_config() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        build_exchange_swarm(key, &ExchangeSwarmConfig::default()).unwrap();
        let key = libp2p::identity::Keypair::generate_ed25519();
        build_peer_swarm(key, &PeerSwarmConfig::default()).unwrap();
    }

    #[test]
    fn validates_listener_transport_and_exchange_safety() {
        let public = ExchangeSwarmConfig {
            tcp_listen: "/ip4/0.0.0.0/tcp/1".parse().unwrap(),
            quic_listen: "/ip4/0.0.0.0/udp/1/quic-v1".parse().unwrap(),
            ..Default::default()
        };
        assert!(matches!(public.validate(), Err(BuildError::PublicListener)));
        let invalid = PeerSwarmConfig {
            tcp_listen: "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap(),
            ..Default::default()
        };
        assert!(matches!(
            invalid.validate(),
            Err(BuildError::InvalidListener {
                transport: "tcp",
                ..
            })
        ));
    }

    #[test]
    fn relay_profiles_apply_all_effective_limits() {
        let default = RelayProfile::Product.config();
        assert_eq!(default.max_reservations, 64);
        assert_eq!(default.max_circuits, 128);
        assert_eq!(default.max_reservations_per_peer, 0);
        assert_eq!(default.max_circuits_per_peer, 31);
        let lab = RelayProfile::DefaultLab.config();
        assert_eq!(lab.max_reservations_per_peer, 1);
        assert_eq!(lab.max_circuits_per_peer, 3);
        assert_eq!(default.max_circuit_bytes, 1024 * 1024 * 1024);
        assert_eq!(default.reservation_rate_limiters.len(), 2);
        assert_eq!(default.circuit_src_rate_limiters.len(), 2);

        let limited = RelayProfile::LimitTest.config();
        assert_eq!(limited.max_reservations, 2);
        assert_eq!(limited.max_reservations_per_peer, 1);
        assert_eq!(limited.max_circuits, 2);
        assert_eq!(limited.max_circuits_per_peer, 0);
        assert_eq!(limited.max_circuit_bytes, 16 * 1024 * 1024);
    }
}
