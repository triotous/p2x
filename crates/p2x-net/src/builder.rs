use crate::probe_stream::ProbeStreamBehaviour;
use libp2p::swarm::{NetworkBehaviour, Swarm};
use libp2p::{PeerId, dcutr, identify, noise, ping, relay, tcp, yamux};
use std::{net::IpAddr, time::Duration};
use thiserror::Error;

pub const IDENTIFY_PROTOCOL: &str = "/p2x/connectivity/0.1.0";
pub const PROBE_PROTOCOL: libp2p::StreamProtocol = libp2p::StreamProtocol::new("/p2x/spike/1");
pub const MAX_STREAMS: usize = 256;
pub const MAX_NEGOTIATIONS: usize = 64;
pub const PROBE_TIMEOUT_SECONDS: u64 = 5;
pub const IDLE_TIMEOUT_SECONDS: u64 = 120;
pub const PING_INTERVAL_SECONDS: u64 = 15;
pub const PING_TIMEOUT_SECONDS: u64 = 5;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RelayProfile {
    #[default]
    DefaultLab,
    LimitTest,
}
impl RelayProfile {
    pub fn config(self) -> relay::Config {
        let limit = matches!(self, Self::LimitTest);
        relay::Config {
            max_reservations: if limit { 2 } else { 64 },
            max_reservations_per_peer: if limit { 1 } else { 2 },
            reservation_duration: Duration::from_secs(60),
            max_circuits: if limit { 2 } else { 128 },
            max_circuits_per_peer: if limit { 1 } else { 4 },
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
            ..relay::Config::default()
        }
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

#[derive(Clone, Debug, Default)]
pub struct SwarmConfig {
    pub tcp_listen: Option<libp2p::Multiaddr>,
    pub quic_listen: Option<libp2p::Multiaddr>,
    pub allow_public: bool,
    pub relay_profile: RelayProfile,
}
#[derive(Debug, Error)]
pub enum BuildError {
    #[error("non-loopback listener requires the lab public acknowledgement")]
    PublicListener,
    #[error("swarm builder failed: {0}")]
    Builder(String),
}
fn validate(config: &SwarmConfig) -> Result<(), BuildError> {
    for address in [config.tcp_listen.as_ref(), config.quic_listen.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(ip) = address.iter().find_map(|p| match p {
            libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        }) && !ip.is_loopback()
            && !config.allow_public
        {
            return Err(BuildError::PublicListener);
        }
    }
    Ok(())
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ExchangeEvent", prelude = "libp2p::swarm::derive_prelude")]
pub struct ExchangeBehaviour {
    pub relay: relay::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}
#[derive(Debug)]
pub enum ExchangeEvent {
    Relay(relay::Event),
    Identify(Box<identify::Event>),
    Ping(ping::Event),
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
impl From<ping::Event> for ExchangeEvent {
    fn from(v: ping::Event) -> Self {
        Self::Ping(v)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "PeerEvent", prelude = "libp2p::swarm::derive_prelude")]
pub struct PeerBehaviour {
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub probe_stream: ProbeStreamBehaviour,
}
#[derive(Debug)]
pub enum PeerEvent {
    Relay(relay::client::Event),
    Dcutr(dcutr::Event),
    Identify(Box<identify::Event>),
    Ping(ping::Event),
    Probe(crate::probe_stream::behaviour::ProbeOutput),
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
impl From<crate::probe_stream::behaviour::ProbeOutput> for PeerEvent {
    fn from(v: crate::probe_stream::behaviour::ProbeOutput) -> Self {
        Self::Probe(v)
    }
}

pub fn build_exchange_swarm(
    keypair: libp2p::identity::Keypair,
    config: SwarmConfig,
) -> Result<Swarm<ExchangeBehaviour>, BuildError> {
    validate(&config)?;
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
        .with_quic()
        .with_behaviour(|_| ExchangeBehaviour {
            relay: relay::Behaviour::new(peer_id, config.relay_profile.config()),
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_owned(),
                public_key,
            )),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(PING_INTERVAL_SECONDS))
                    .with_timeout(Duration::from_secs(PING_TIMEOUT_SECONDS)),
            ),
        })
        .map_err(|e| BuildError::Builder(e.to_string()))
        .map(|b| {
            b.with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(IDLE_TIMEOUT_SECONDS))
            })
            .build()
        })
}
pub fn build_peer_swarm(
    keypair: libp2p::identity::Keypair,
    config: SwarmConfig,
) -> Result<Swarm<PeerBehaviour>, BuildError> {
    validate(&config)?;
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
        .with_quic()
        .with_relay_client(noise::Config::new, || {
            let mut config = yamux::Config::default();
            config.set_max_num_streams(MAX_STREAMS);
            config
        })
        .map_err(|e| BuildError::Builder(e.to_string()))?
        .with_behaviour(|_, relay_client| PeerBehaviour {
            relay_client,
            dcutr: dcutr::Behaviour::new(peer_id),
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_owned(),
                public_key,
            )),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_interval(Duration::from_secs(PING_INTERVAL_SECONDS))
                    .with_timeout(Duration::from_secs(PING_TIMEOUT_SECONDS)),
            ),
            probe_stream: ProbeStreamBehaviour::default(),
        })
        .map_err(|e| BuildError::Builder(e.to_string()))
        .map(|b| {
            b.with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(IDLE_TIMEOUT_SECONDS))
            })
            .build()
        })
}
pub fn supported_protocols() -> [libp2p::StreamProtocol; 1] {
    [PROBE_PROTOCOL]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_surface_is_exact() {
        assert_eq!(supported_protocols(), [PROBE_PROTOCOL]);
        assert_eq!(MAX_STREAMS, 256);
        assert_eq!(MAX_NEGOTIATIONS, 64);
    }
    #[test]
    fn concrete_swarms_build_with_loopback_config() {
        let key = libp2p::identity::Keypair::generate_ed25519();
        build_exchange_swarm(
            key,
            SwarmConfig {
                relay_profile: RelayProfile::DefaultLab,
                ..Default::default()
            },
        )
        .unwrap();
        let key = libp2p::identity::Keypair::generate_ed25519();
        build_peer_swarm(key, SwarmConfig::default()).unwrap();
    }
}
