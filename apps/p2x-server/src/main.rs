use clap::Parser;
use futures::StreamExt;
use libp2p::{Multiaddr, multiaddr::Protocol, swarm::SwarmEvent};
use p2x_net::{
    builder::{SwarmConfig, build_peer_swarm, lab_identity},
    lifecycle::Emitter,
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
        let circuit = exchange
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(*swarm.local_peer_id()));
        emitter.event(
            "relay_dial",
            Some(&format!("relay={relay_peer} circuit={circuit}")),
        )?;
        swarm.listen_on(circuit).map_err(io::Error::other)?;
    }
    emitter.event("started", Some(&swarm.local_peer_id().to_string()))?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    let name = if address.to_string().contains("p2p-circuit") { "circuit_ready" } else { "listen_addr" };
                    emitter.event(name, Some(&address.to_string()))?;
                }
            }
        }
    }
    emitter.terminal("stopped", "shutdown")?;
    Ok(())
}
