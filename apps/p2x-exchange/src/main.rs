use clap::Parser;
use futures::StreamExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use p2x_net::{
    builder::{SwarmConfig, build_exchange_swarm, lab_identity},
    lifecycle::Emitter,
};
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
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = Emitter::new("exchange", &run_id);
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
    emitter.event("started", Some(&swarm.local_peer_id().to_string()))?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let advertised = address.with(libp2p::multiaddr::Protocol::P2p(*swarm.local_peer_id()));
                    emitter.event("listen_addr", Some(&advertised.to_string()))?;
                }
                SwarmEvent::Behaviour(event) => emitter.event("relay_event", Some(&format!("{event:?}")))?,
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => emitter.event("connection_established", Some(&format!("peer_id={peer_id} connection_id={connection_id:?}")))?,
                SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => emitter.event("connection_closed", Some(&format!("peer_id={peer_id} connection_id={connection_id:?} cause={cause:?}")))?,
                SwarmEvent::IncomingConnectionError { error, .. } => emitter.event("incoming_error", Some(&error.to_string()))?,
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => emitter.event("outgoing_error", Some(&format!("peer_id={peer_id:?} error={error}")))?,
                _ => {}
            }
        }
    }
    emitter.terminal("stopped", "shutdown")?;
    Ok(())
}
