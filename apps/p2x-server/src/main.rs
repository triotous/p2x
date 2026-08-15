use clap::Parser;
use futures::StreamExt;
use libp2p::{Multiaddr, multiaddr::Protocol, swarm::SwarmEvent};
use p2x_net::{
    builder::{PeerEvent, SwarmConfig, build_peer_swarm, lab_identity},
    lifecycle::Emitter,
    probe_stream::behaviour::ProbeOutput,
    probe_worker::execute_probe_futures,
};
use std::io;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    identity_seed: Option<u64>,
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    tcp_listen: Multiaddr,
    /// Exchange relay address, including its /p2p/<peer-id> component.
    #[arg(long)]
    exchange: Option<Multiaddr>,
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = Emitter::new("server", &run_id);
    let key = lab_identity(args.identity_seed).map_err(io::Error::other)?;
    let mut swarm = build_peer_swarm(key, SwarmConfig::default()).map_err(io::Error::other)?;
    swarm.listen_on(args.tcp_listen).map_err(io::Error::other)?;
    let mut relay_peer_id = None;
    let mut pending_circuit = None;
    if let Some(exchange) = args.exchange {
        let relay_peer = exchange
            .iter()
            .find_map(|part| match part {
                Protocol::P2p(peer) => Some(peer),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exchange address needs /p2p/<peer>",
                )
            })?;
        swarm.dial(exchange.clone()).map_err(io::Error::other)?;
        let circuit = exchange.with(Protocol::P2pCircuit);
        relay_peer_id = Some(relay_peer);
        pending_circuit = Some(circuit.clone());
        let advertised = circuit.clone().with(Protocol::P2p(*swarm.local_peer_id()));
        emitter.event(
            "relay_dial",
            Some(&format!("relay={relay_peer} circuit={advertised}")),
        )?;
        swarm.listen_on(circuit).map_err(io::Error::other)?;
    }
    emitter.event("started", Some(&swarm.local_peer_id().to_string()))?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        emitter.event("listen_addr", Some(&address.to_string()))?;
                    }
                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        if address.to_string().contains("p2p-circuit") {
                            emitter.event("circuit_ready", Some(&address.to_string()))?;
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                        emitter.event("connection_established", Some(&format!("peer_id={peer_id} connection_id={connection_id:?}")))?;
                        if relay_peer_id == Some(peer_id)
                            && let Some(address) = pending_circuit.take()
                        {
                            swarm.listen_on(address).map_err(io::Error::other)?;
                            emitter.event("reservation_requested", Some(&peer_id.to_string()))?;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        emitter.event("connection_error", Some(&format!("peer_id={peer_id:?} error={error}")))?;
                    }
                    SwarmEvent::ListenerError { error, .. } => {
                        emitter.event("listener_error", Some(&error.to_string()))?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Relay(relay_event)) => {
                        let accepted = matches!(relay_event, libp2p::relay::client::Event::ReservationReqAccepted { .. });
                        emitter.event("relay_event", Some(&format!("{relay_event:?}")))?;
                        if accepted && let Some(address) = pending_circuit.as_ref() {
                            let advertised = address.clone().with(Protocol::P2p(*swarm.local_peer_id()));
                            emitter.event("reservation_accepted", Some(&advertised.to_string()))?;
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Probe(ProbeOutput::InboundOpened { mut stream, peer_id, connection_id })) => {
                        let ack = execute_probe_futures(&mut stream, p2x_net::probe::ProbePath::Relay, format!("{connection_id:?}").bytes().fold(0u64, |hash, byte| hash.wrapping_mul(31).wrapping_add(byte as u64))).await.map_err(io::Error::other)?;
                        emitter.event("probe_observed", Some(&format!("peer_id={peer_id} connection_id={connection_id:?} path={:?} bytes={}", ack.path, ack.bytes_written)))?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Probe(ProbeOutput::InboundRejected { code, .. })) => {
                        emitter.event("probe_rejected", Some(code))?;
                    }
                    _ => {}
                }
            }
        }
    }
    emitter.terminal("stopped", "shutdown")?;
    Ok(())
}
