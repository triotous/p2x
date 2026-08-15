use clap::{Parser, ValueEnum};
use futures::StreamExt;
use futures::io::AsyncWriteExt;
use libp2p::{Multiaddr, swarm::SwarmEvent};
use p2x_net::{
    builder::{SwarmConfig, build_peer_swarm, lab_identity},
    lifecycle::Emitter,
    probe::{ProbeAck, ProbeHeader, ProbeMode, SCHEMA_VERSION},
    probe_stream::behaviour::ProbeOutput,
    probe_worker::{read_frame_futures, write_frame_futures},
};
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
    #[arg(long)]
    server: Option<Multiaddr>,
    #[arg(long, value_enum, default_value_t = Path::Relay)]
    path: Path,
    #[arg(long, default_value_t = 1)]
    count: u64,
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = Emitter::new("client", &run_id);
    let key = lab_identity(args.identity_seed).map_err(io::Error::other)?;
    let mut swarm = build_peer_swarm(key, SwarmConfig::default()).map_err(io::Error::other)?;
    let target_peer = args.server.as_ref().and_then(|address| {
        address.iter().fold(None, |last, part| match part {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => last,
        })
    });
    emitter.event(
        "started",
        Some(&format!(
            "peer_id={} path={:?}",
            swarm.local_peer_id(),
            args.path
        )),
    )?;
    if let Some(address) = args.exchange {
        swarm.dial(address).map_err(io::Error::other)?;
    }
    if let Some(address) = args.server {
        swarm.dial(address).map_err(io::Error::other)?;
    }
    let mut remaining = args.count;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                        emitter.event("connection_established", Some(&format!("peer_id={peer_id} connection_id={connection_id:?}")))?;
                        if remaining != 0 && target_peer == Some(peer_id) {
                            swarm.behaviour_mut().probe_stream.open_on(peer_id, connection_id).map_err(io::Error::other)?;
                            remaining -= 1;
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Probe(output)) => match output {
                        ProbeOutput::OutboundOpened { stream, request_id, peer_id, connection_id } => {
                            let mut stream = stream;
                            let header = ProbeHeader { schema_version: SCHEMA_VERSION, request_id: request_id.0, mode: ProbeMode::NonceEcho, nonce: request_id.0, length: 0, slow_delay_ms: 0, slow_chunk_size: 0 };
                            let body = serde_json::to_vec(&header).map_err(io::Error::other)?;
                            write_frame_futures(&mut stream, &body).await.map_err(io::Error::other)?;
                            stream.close().await.map_err(io::Error::other)?;
                            let ack_body = read_frame_futures(&mut stream).await.map_err(io::Error::other)?;
                            let ack: ProbeAck = serde_json::from_slice(&ack_body).map_err(io::Error::other)?;
                            if ack.nonce != header.nonce || ack.request_id != header.request_id {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, "probe acknowledgement mismatch"));
                            }
                            emitter.event("probe_succeeded", Some(&format!("peer_id={peer_id} connection_id={connection_id:?} path={:?}", ack.path)))?;
                            emitter.terminal("passed", "probe.ok")?;
                            return Ok(());
                        }
                        ProbeOutput::OutboundFailed { code, .. } => {
                            emitter.terminal("failed", code)?;
                            return Err(io::Error::other(code));
                        }
                        ProbeOutput::InboundOpened { .. } | ProbeOutput::InboundRejected { .. } => {}
                    },
                    _ => {}
                }
            }
        }
    }
    emitter.terminal("stopped", "shutdown")?;
    Ok(())
}
