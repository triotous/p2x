use clap::Parser;
use futures::StreamExt;
use libp2p::{Multiaddr, multiaddr::Protocol, swarm::SwarmEvent};
use p2x_net::{
    builder::{PeerEvent, PeerSwarmConfig, build_peer_swarm, lab_identity, start_peer_listeners},
    lifecycle::{
        ConnectionState, Emitter, LifecycleRecord, ReservationState as LifecycleReservationState,
        TerminalResult, stable_hash,
    },
    probe::{ProbeAck, ProbePath},
    probe_stream::behaviour::ProbeOutput,
    probe_worker::{WorkerAdmission, execute_probe_futures_with_timeout},
};
use std::{collections::HashMap, io, path::PathBuf};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    identity_seed: Option<u64>,
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    tcp_listen: Multiaddr,
    #[arg(long, default_value = "/ip4/127.0.0.1/udp/0/quic-v1")]
    quic_listen: Multiaddr,
    /// Exchange relay address, including its /p2p/<peer-id> component.
    #[arg(long)]
    exchange: Option<Multiaddr>,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long, default_value = "lifecycle")]
    case_id: String,
    #[arg(long, default_value_t = 300)]
    worker_timeout_secs: u64,
}

struct WorkerResult {
    peer_id: libp2p::PeerId,
    result: Result<ProbeAck, p2x_net::probe::ProbeError>,
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = match &args.artifact {
        Some(path) => Emitter::with_artifact("server", &run_id, path)?,
        None => Emitter::new("server", &run_id),
    };
    let key = lab_identity(args.identity_seed).map_err(io::Error::other)?;
    let config = PeerSwarmConfig {
        tcp_listen: args.tcp_listen,
        quic_listen: args.quic_listen,
    };
    let mut swarm = build_peer_swarm(key, &config).map_err(io::Error::other)?;
    start_peer_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    let mut relay_peer_id = None;
    let mut pending_circuit = None;
    let mut reservation_requested = false;
    let mut connection_paths = HashMap::new();
    let mut worker_admission = WorkerAdmission::default();
    let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerResult>(128);
    let mut resource_tick = tokio::time::interval(std::time::Duration::from_secs(1));
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
        relay_peer_id = Some(relay_peer);
        let circuit = exchange
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(*swarm.local_peer_id()));
        pending_circuit = Some(circuit.clone());
        let advertised = circuit.clone();
        let relay = relay_peer.to_string();
        let circuit = advertised.to_string();
        emitter.emit(&LifecycleRecord::ReservationTransition {
            state: LifecycleReservationState::Requested,
            exchange_peer_id: &relay,
            listener_id: None,
            address: Some(&circuit),
            generation: 1,
        })?;
    }
    let local_peer = swarm.local_peer_id().to_string();
    emitter.emit(&LifecycleRecord::Started {
        peer_id: &local_peer,
    })?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = resource_tick.tick() => {
                emitter.emit(&LifecycleRecord::Resources { connections: connection_paths.len(), pending_opens: swarm.behaviour().probe_stream.pending_count(), workers: worker_admission.admitted(), tasks: worker_admission.admitted() })?;
            }
            Some(worker) = worker_rx.recv() => {
                let released = worker_admission.release(worker.peer_id);
                swarm.behaviour_mut().probe_stream.inbound_release(worker.peer_id);
                if !released {
                    return Err(io::Error::other("worker permit released more than once"));
                }
                let peer = worker.peer_id.to_string();
                match worker.result {
                    Ok(ack) => emitter.emit(&LifecycleRecord::ProbeCompleted { peer_id: &peer, ack: &ack })?,
                    Err(error) => { let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "probe.worker", message: &message })?; }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { listener_id, address } => {
                        let listener = format!("{listener_id:?}");
                        let address = address.to_string();
                        emitter.emit(&LifecycleRecord::ListenerReady { listener_id: &listener, address: &address })?;
                    }
                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        if address.to_string().contains("p2p-circuit") {
                            let relay = relay_peer_id.map(|peer| peer.to_string()).unwrap_or_default();
                            let address = address.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Ready, exchange_peer_id: &relay, listener_id: None, address: Some(&address), generation: 1 })?;
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        let path = if endpoint.is_relayed() {
                            p2x_net::probe::ProbePath::Relay
                        } else {
                            p2x_net::probe::ProbePath::Direct
                        };
                        connection_paths.insert(connection_id, path);
                        let peer = peer_id.to_string();
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Established, path: Some(path), reason: None })?;
                        if relay_peer_id == Some(peer_id)
                            && !reservation_requested
                            && let Some(address) = pending_circuit.clone()
                        {
                            swarm.listen_on(address).map_err(io::Error::other)?;
                            reservation_requested = true;
                            let relay = peer_id.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Requested, exchange_peer_id: &relay, listener_id: None, address: None, generation: 1 })?;
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => {
                        connection_paths.remove(&connection_id);
                        let peer = peer_id.to_string();
                        let reason = format!("{cause:?}");
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Closed, path: None, reason: Some(&reason) })?;
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        let message = format!("peer_id={peer_id:?} error={error}");
                        emitter.emit(&LifecycleRecord::OperationalError { code: "connection.outgoing", message: &message })?;
                    }
                    SwarmEvent::ListenerError { error, .. } => {
                        let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "listener.error", message: &message })?;
                    }
                    SwarmEvent::ListenerClosed { reason, .. } => {
                        let message = format!("{reason:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "listener.closed", message: &message })?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Relay(relay_event)) => {
                        let accepted = matches!(relay_event, libp2p::relay::client::Event::ReservationReqAccepted { .. });
                        if accepted {
                            let relay = relay_peer_id.map(|peer| peer.to_string()).unwrap_or_default();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Accepted, exchange_peer_id: &relay, listener_id: None, address: None, generation: 1 })?;
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Probe(ProbeOutput::InboundOpened { mut stream, peer_id, connection_id })) => {
                        let path = connection_paths.get(&connection_id).copied().unwrap_or(ProbePath::Relay);
                        if let Err(error) = worker_admission.admit(peer_id) {
                            swarm.behaviour_mut().probe_stream.inbound_release(peer_id);
                            let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "probe.admission_rejected", message: &message })?;
                            continue;
                        }
                        let tx = worker_tx.clone();
                        let connection_id_hash = stable_hash(connection_id);
                        let worker_timeout = std::time::Duration::from_secs(args.worker_timeout_secs);
                        tokio::spawn(async move {
                            let result = execute_probe_futures_with_timeout(&mut stream, path, connection_id_hash, worker_timeout).await;
                            let _ = tx.send(WorkerResult { peer_id, result }).await;
                        });
                    }
                    SwarmEvent::Behaviour(PeerEvent::Probe(ProbeOutput::InboundRejected { code, .. })) => {
                        emitter.emit(&LifecycleRecord::OperationalError { code: "probe.inbound_rejected", message: code })?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Dcutr(event)) => {
                        let message = format!("{event:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "dcutr.event", message: &message })?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Identify(event)) => {
                        let message = format!("{event:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "identify.event", message: &message })?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Ping(event)) => {
                        let message = format!("{event:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "ping.event", message: &message })?;
                    }
                    SwarmEvent::Behaviour(event) => {
                        let message = format!("{event:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "behaviour.event", message: &message })?;
                    }
                    _ => {}
                }
            }
        }
    }
    worker_admission.close_and_discard();
    emitter.terminal(&TerminalResult::simple(
        &args.case_id,
        "stopped",
        "shutdown",
    ))?;
    Ok(())
}
