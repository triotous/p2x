use clap::{Parser, ValueEnum};
use futures::StreamExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use p2x_net::builder::{SwarmConfig, build_peer_swarm, lab_identity};
use std::io;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Path {
    Direct,
    Relay,
}
#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    identity_seed: Option<u64>,
    #[arg(long)]
    exchange: Option<Multiaddr>,
    #[arg(long, value_enum, default_value_t = Path::Relay)]
    path: Path,
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let key = lab_identity(args.identity_seed).map_err(io::Error::other)?;
    let mut swarm = build_peer_swarm(key, SwarmConfig::default()).map_err(io::Error::other)?;
    println!(
        "{{\"component\":\"client\",\"peer_id\":\"{}\",\"started\":true,\"requested_path\":\"{:?}\"}}",
        swarm.local_peer_id(),
        args.path
    );
    if let Some(address) = args.exchange {
        swarm.dial(address).map_err(io::Error::other)?;
    }
    loop {
        tokio::select! { _ = tokio::signal::ctrl_c() => break, event = swarm.select_next_some() => { if let SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } = event { println!("{{\"component\":\"client\",\"peer_id\":\"{}\",\"connection_id\":\"{:?}\",\"connected\":true}}", peer_id, connection_id); } } }
    }
    Ok(())
}
