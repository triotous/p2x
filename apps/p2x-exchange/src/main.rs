#[cfg(test)]
mod auth_sessions;
#[cfg(test)]
mod authn;
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use p2x_net::{
    builder::{
        ExchangeSwarmConfig, RelayProfile, build_exchange_swarm, lab_identity,
        start_exchange_listeners,
    },
    lifecycle::{ConnectionState, Emitter, LifecycleRecord, TerminalResult, stable_hash},
};
use std::{io, path::PathBuf};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    identity_seed: Option<u64>,
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    tcp_listen: Multiaddr,
    #[arg(long, default_value = "/ip4/127.0.0.1/udp/0/quic-v1")]
    quic_listen: Multiaddr,
    #[arg(long, value_enum, default_value_t = RelayProfileArg::DefaultLab)]
    relay_profile: RelayProfileArg,
    #[arg(long)]
    unsafe_lab_public_relay: bool,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long, default_value = "lifecycle")]
    case_id: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RelayProfileArg {
    DefaultLab,
    LimitTest,
}

impl From<RelayProfileArg> for RelayProfile {
    fn from(value: RelayProfileArg) -> Self {
        match value {
            RelayProfileArg::DefaultLab => Self::DefaultLab,
            RelayProfileArg::LimitTest => Self::LimitTest,
        }
    }
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = match &args.artifact {
        Some(path) => Emitter::with_artifact("exchange", &run_id, path)?,
        None => Emitter::new("exchange", &run_id),
    };
    let key = lab_identity(args.identity_seed).map_err(io::Error::other)?;
    let config = ExchangeSwarmConfig {
        tcp_listen: args.tcp_listen,
        quic_listen: args.quic_listen,
        allow_public: args.unsafe_lab_public_relay,
        relay_profile: args.relay_profile.into(),
    };
    let mut swarm = build_exchange_swarm(key, &config).map_err(io::Error::other)?;
    start_exchange_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    let local_peer = swarm.local_peer_id().to_string();
    emitter.emit(&LifecycleRecord::Started {
        peer_id: &local_peer,
    })?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { listener_id, address } => {
                    swarm.add_external_address(address.clone());
                    let advertised = address.with(libp2p::multiaddr::Protocol::P2p(*swarm.local_peer_id()));
                    let listener_id = format!("{listener_id:?}");
                    let advertised = advertised.to_string();
                    emitter.emit(&LifecycleRecord::ListenerReady { listener_id: &listener_id, address: &advertised })?;
                }
                SwarmEvent::Behaviour(event) => { let message = format!("{event:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "relay.event", message: &message })?; }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => { let peer = peer_id.to_string(); emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Established, path: Some(if endpoint.is_relayed() { p2x_net::probe::ProbePath::Relay } else { p2x_net::probe::ProbePath::Direct }), reason: None })?; }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => { let peer = peer_id.to_string(); let reason = format!("{cause:?}"); emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Closed, path: None, reason: Some(&reason) })?; }
                SwarmEvent::IncomingConnectionError { error, .. } => { let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "connection.incoming", message: &message })?; }
                SwarmEvent::OutgoingConnectionError { error, .. } => { let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "connection.outgoing", message: &message })?; }
                _ => {}
            }
        }
    }
    emitter.terminal(&TerminalResult::simple(
        &args.case_id,
        "stopped",
        "shutdown",
    ))?;
    Ok(())
}
