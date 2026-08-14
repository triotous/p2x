use clap::Parser;
use futures::StreamExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use p2x_net::builder::{SwarmConfig, build_exchange_swarm, lab_identity};
use std::io;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    identity_seed: Option<u64>,
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    tcp_listen: Multiaddr,
    #[arg(long)]
    unsafe_lab_public_relay: bool,
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let key = lab_identity(args.identity_seed).map_err(io::Error::other)?;
    let mut swarm = build_exchange_swarm(
        key,
        SwarmConfig {
            tcp_listen: Some(args.tcp_listen.clone()),
            allow_public: args.unsafe_lab_public_relay,
            ..Default::default()
        },
    )
    .map_err(io::Error::other)?;
    swarm.listen_on(args.tcp_listen).map_err(io::Error::other)?;
    println!(
        "{{\"component\":\"exchange\",\"peer_id\":\"{}\",\"started\":true}}",
        swarm.local_peer_id()
    );
    loop {
        tokio::select! { _ = tokio::signal::ctrl_c() => break, event = swarm.select_next_some() => { if let SwarmEvent::NewListenAddr { address, .. } = event { println!("{{\"component\":\"exchange\",\"listen_addr\":\"{}\"}}", address); } } }
    }
    Ok(())
}
