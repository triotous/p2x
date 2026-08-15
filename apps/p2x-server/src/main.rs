use clap::Parser;
use futures::StreamExt;
use libp2p::{
    Multiaddr,
    multiaddr::Protocol,
    request_response::{Event as RequestResponseEvent, Message as RequestResponseMessage},
    swarm::SwarmEvent,
};
use p2x_net::{
    ReservationContext, ReservationEvent,
    auth_state::{AuthAction, AuthState},
    builder::{
        PeerEvent, PeerSwarmConfig, RuntimeMode, build_peer_swarm, lab_identity,
        start_peer_listeners,
    },
    connection_book::ConnectionBook,
    lifecycle::{
        ConnectionState, Emitter, LifecycleRecord, ReservationState as LifecycleReservationState,
        TerminalResult, stable_hash,
    },
    probe::{ProbeAck, ProbePath},
    probe_stream::behaviour::ProbeOutput,
    probe_worker::{WorkerAdmission, execute_probe_futures_with_timeout},
};
use p2x_protocol::{AuthRequest, AuthResponse, PublicErrorCode, Role};
use std::{collections::HashMap, io, path::PathBuf};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    identity_seed: Option<u64>,
    #[arg(long)]
    unsafe_connectivity_lab: bool,
    #[arg(long)]
    identity_file: Option<PathBuf>,
    #[arg(long)]
    generate_identity: bool,
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    tcp_listen: Multiaddr,
    #[arg(long, default_value = "/ip4/127.0.0.1/udp/0/quic-v1")]
    quic_listen: Multiaddr,
    /// Exchange relay address, including its /p2p/<peer-id> component.
    #[arg(long)]
    exchange: Option<Multiaddr>,
    #[arg(long)]
    exchange_peer_id: Option<String>,
    #[arg(long)]
    credential_env: Option<String>,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long, default_value = "lifecycle")]
    case_id: String,
    #[arg(long, default_value_t = 300)]
    worker_timeout_secs: u64,
    #[arg(long, default_value_t = false)]
    drop_first_probe: bool,
}

fn random_request_id() -> [u8; 16] {
    let mut id = [0; 16];
    getrandom::fill(&mut id).expect("OS randomness unavailable");
    id
}
fn probe_mut(
    swarm: &mut libp2p::Swarm<p2x_net::builder::PeerBehaviour>,
) -> io::Result<&mut p2x_net::probe_stream::behaviour::ProbeStreamBehaviour> {
    swarm
        .behaviour_mut()
        .probe_stream
        .as_mut()
        .ok_or_else(|| io::Error::other("probe is unavailable in product mode"))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
    let key = if let Some(path) = args.identity_file.as_ref() {
        p2x_config::identity::load_or_create_identity(&p2x_config::identity::IdentityConfig {
            path: path.clone(),
            generate_if_missing: args.generate_identity,
        })
        .map_err(io::Error::other)?
        .keypair
    } else if args.credential_env.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated server requires --identity-file",
        ));
    } else if args.unsafe_connectivity_lab {
        lab_identity(args.identity_seed).map_err(io::Error::other)?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --identity-file",
        ));
    };
    if args.credential_env.is_none() && !args.unsafe_connectivity_lab {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --credential-env",
        ));
    }
    let credential = args
        .credential_env
        .as_deref()
        .map(|env_name| {
            p2x_config::credential::CredentialRef {
                env_name: env_name.to_owned(),
            }
            .read()
            .map_err(io::Error::other)
        })
        .transpose()?;
    if credential.is_some() {
        let exchange = args.exchange.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "credential mode requires --exchange",
            )
        })?;
        let configured = args.exchange_peer_id.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "credential mode requires --exchange-peer-id",
            )
        })?;
        let address_peer = exchange
            .iter()
            .find_map(|part| match part {
                Protocol::P2p(peer) => Some(peer.to_string()),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "exchange address needs /p2p/<peer>",
                )
            })?;
        if address_peer != configured {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "exchange pin does not match address",
            ));
        }
    }
    let config = PeerSwarmConfig {
        tcp_listen: args.tcp_listen,
        quic_listen: args.quic_listen,
        mode: if args.unsafe_connectivity_lab {
            RuntimeMode::ConnectivityLab
        } else {
            RuntimeMode::Product
        },
    };
    let mut swarm = build_peer_swarm(key, &config).map_err(io::Error::other)?;
    start_peer_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    let mut relay_peer_id = args
        .exchange_peer_id
        .as_deref()
        .and_then(|v| v.parse().ok());
    let mut relay_connection_id = None;
    let mut circuit_listener_id = None;
    let mut reservation = ReservationContext::new(0);
    let mut pending_circuit = None;
    let mut reservation_requested = false;
    let mut connection_paths = HashMap::new();
    let mut worker_admission = WorkerAdmission::default();
    let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerResult>(128);
    let mut resource_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut first_probe_dropped = false;
    let mut auth_request_id = random_request_id();
    let mut ping_request_id = random_request_id();
    let mut auth_state = AuthState::new();
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
            renewal: false,
        })?;
    }
    let mut connection_book = relay_peer_id.map(ConnectionBook::new);
    let local_peer = swarm.local_peer_id().to_string();
    emitter.emit(&LifecycleRecord::Started {
        peer_id: &local_peer,
    })?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = resource_tick.tick() => {
                if let Some(book) = connection_book.as_mut() { book.sweep(std::time::Instant::now()); }
                if let Some((id, token)) = credential.as_ref()
                    && let AuthAction::Authenticate { request_id } = auth_state.tick(random_request_id(), unix_now())
                {
                    auth_request_id = request_id;
                    if let Some(peer_id) = relay_peer_id { swarm.behaviour_mut().auth.send_request(&peer_id, AuthRequest::Authenticate { request_id, credential_id: id.clone(), token_secret: *token.as_bytes(), requested_role: Role::Server, supported_features: 0 }); }
                }
                let connections = connection_book.as_ref().map(ConnectionBook::len).unwrap_or(connection_paths.len());
                emitter.emit(&LifecycleRecord::Resources { connections, pending_opens: swarm.behaviour().probe_stream.as_ref().map_or(0, |probe| probe.pending_count()), workers: worker_admission.admitted(), tasks: worker_admission.admitted() })?;
            }
            Some(worker) = worker_rx.recv() => {
                let released = worker_admission.release(worker.peer_id);
                probe_mut(&mut swarm)?.inbound_release(worker.peer_id);
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
                        if address.contains("p2p-circuit") && let (Some(peer_id), Some(connection_id)) = (relay_peer_id, relay_connection_id) {
                            reservation.apply(ReservationEvent::RelayAddressConfirmed { generation: 1, peer_id, connection_id, listener_id, address: address.parse().map_err(io::Error::other)? }).map_err(io::Error::other)?;
                        }
                    }
                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        if address.to_string().contains("p2p-circuit") {
                            let relay = relay_peer_id.map(|peer| peer.to_string()).unwrap_or_default();
                            let address = address.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Ready, exchange_peer_id: &relay, listener_id: None, address: Some(&address), generation: 1, renewal: false })?;
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        let path = if endpoint.is_relayed() {
                            p2x_net::probe::ProbePath::Relay
                        } else {
                            p2x_net::probe::ProbePath::Direct
                        };
                        if let Some(book) = connection_book.as_mut() && let Err(error) = book.on_connection_established(peer_id, connection_id, &endpoint, std::time::Instant::now()) {
                            swarm.close_connection(connection_id);
                            let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "connection.rejected", message: &message })?;
                            continue;
                        }
                        connection_paths.insert(connection_id, path);
                        let peer = peer_id.to_string();
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Established, path: Some(path), reason: None })?;
                        if relay_peer_id == Some(peer_id) && let Some((id, token)) = credential.as_ref()
                            && let AuthAction::Authenticate { request_id } = auth_state.connected(auth_request_id, unix_now())
                        {
                            auth_request_id = request_id;
                            swarm.behaviour_mut().auth.send_request(&peer_id, AuthRequest::Authenticate { request_id, credential_id: id.clone(), token_secret: *token.as_bytes(), requested_role: Role::Server, supported_features: 0 });
                        }
                        if relay_peer_id == Some(peer_id)
                            && !reservation_requested
                            && let Some(address) = pending_circuit.clone()
                        {
                            relay_connection_id = Some(connection_id);
                            reservation.apply(ReservationEvent::GenerationStarted { generation: 1, peer_id, connection_id }).map_err(io::Error::other)?;
                            let listener_id = swarm.listen_on(address).map_err(io::Error::other)?;
                            circuit_listener_id = Some(listener_id);
                            reservation.apply(ReservationEvent::ReservationRequested { generation: 1, peer_id, connection_id }).map_err(io::Error::other)?;
                            reservation_requested = true;
                            let relay = peer_id.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Requested, exchange_peer_id: &relay, listener_id: None, address: None, generation: 1, renewal: false })?;
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => {
                        if relay_peer_id == Some(peer_id) && relay_connection_id == Some(connection_id) {
                            reservation.apply(ReservationEvent::ExchangeLost { generation: 1, peer_id, connection_id }).map_err(io::Error::other)?;
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Degraded, exchange_peer_id: &peer_id.to_string(), listener_id: circuit_listener_id.as_ref().map(|_| "circuit"), address: None, generation: 1, renewal: false })?;
                        }
                        if let Some(book) = connection_book.as_mut() { book.on_connection_closed(peer_id, connection_id).map_err(io::Error::other)?; }
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
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Response { response: AuthResponse::Authenticated { session_id, request_id, .. }, .. }, .. })) => {
                        if let AuthAction::Ping { request_id: ping_id, session_id, nonce } = auth_state.authenticated(request_id, session_id, { ping_request_id = random_request_id(); ping_request_id }, 1, unix_now()) {
                            ping_request_id = ping_id;
                            swarm.behaviour_mut().auth.send_request(&peer, AuthRequest::Ping { request_id: ping_id, session_id, nonce });
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { message: RequestResponseMessage::Response { response: AuthResponse::Pong { request_id, nonce, .. }, .. }, .. })) if credential.is_some() && request_id == ping_request_id && auth_state.pong(request_id, nonce) == AuthAction::Ready => { emitter.terminal(&TerminalResult::simple(&args.case_id, "passed", "auth.pong"))?; return Ok(()); }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { message: RequestResponseMessage::Response { response: AuthResponse::Rejected { request_id, error }, .. }, .. })) if credential.is_some() && auth_state.rejected(request_id, error.code, unix_now()) != AuthAction::Ignore => {
                        if matches!(auth_state.phase(), p2x_net::auth_state::AuthPhase::Terminal(_)) {
                            emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", error.code.as_str()))?;
                            return Ok(());
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::OutboundFailure { error: libp2p::request_response::OutboundFailure::Timeout, .. })) if credential.is_some() => {
                        let _ = auth_state.timeout(unix_now());
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::OutboundFailure { error: libp2p::request_response::OutboundFailure::UnsupportedProtocols, .. })) if credential.is_some() => {
                        let code = PublicErrorCode::ProtocolCapabilityMismatch;
                        emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                        return Ok(());
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::OutboundFailure { error: libp2p::request_response::OutboundFailure::ConnectionClosed, .. })) if credential.is_some() => {
                        auth_state.disconnected();
                    }
                    SwarmEvent::Behaviour(PeerEvent::Relay(libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id: peer_id, renewal, .. })) => {
                        if let (Some(connection_id), Some(listener_id)) = (relay_connection_id, circuit_listener_id) {
                            reservation.apply(ReservationEvent::ReservationAccepted { generation: 1, peer_id, connection_id, listener_id, renewal }).map_err(io::Error::other)?;
                            let relay = peer_id.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Accepted, exchange_peer_id: &relay, listener_id: Some("circuit"), address: None, generation: 1, renewal })?;
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Relay(_)) => {}
                    SwarmEvent::Behaviour(PeerEvent::Probe(ProbeOutput::InboundOpened { mut stream, peer_id, connection_id })) => {
                        if args.drop_first_probe && !first_probe_dropped {
                            first_probe_dropped = true;
                            probe_mut(&mut swarm)?.inbound_release(peer_id);
                            swarm.close_connection(connection_id);
                            emitter.emit(&LifecycleRecord::OperationalError { code: "probe.fault_drop_first", message: "selected connection closed during payload" })?;
                            drop(stream);
                            continue;
                        }
                        let path = connection_paths.get(&connection_id).copied().unwrap_or(ProbePath::Relay);
                        if let Err(error) = worker_admission.admit(peer_id) {
                            probe_mut(&mut swarm)?.inbound_release(peer_id);
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
                        if let Ok(connection_id) = event.result && let Some(book) = connection_book.as_mut() {
                            book.on_dcutr_succeeded(event.remote_peer_id, connection_id, std::time::Instant::now()).map_err(io::Error::other)?;
                        }
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
