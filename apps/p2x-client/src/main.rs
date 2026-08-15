use clap::{Parser, ValueEnum};
use futures::StreamExt;
use libp2p::{
    Multiaddr,
    request_response::{Event as RequestResponseEvent, Message as RequestResponseMessage},
    swarm::SwarmEvent,
};
use p2x_net::{
    AttemptId, PathAction, PathAttempt, PathDecision, PathEvent, PathEventKind,
    builder::{PeerSwarmConfig, build_peer_swarm, lab_identity, start_peer_listeners},
    connection_book::{ConnectionBook, PathKind},
    lifecycle::{ConnectionState, Emitter, LifecycleRecord, TerminalResult, stable_hash},
    probe::{ProbeAck, ProbeHeader, ProbeMode, ProbePath, ProbeTerminal, SCHEMA_VERSION},
    probe_stream::behaviour::ProbeOutput,
    probe_worker::execute_probe_client_futures_with_timeout,
};
use p2x_protocol::{AuthRequest, AuthResponse, Role};
use std::{
    collections::{HashSet, VecDeque},
    io,
    path::PathBuf,
};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Path {
    Auto,
    Both,
    Direct,
    Relay,
}

fn forced_path_matches(path: Path, observed_path: ProbePath) -> bool {
    matches!(
        (path, observed_path),
        (Path::Direct, ProbePath::Direct)
            | (Path::Relay, ProbePath::Relay)
            | (Path::Both, ProbePath::Direct | ProbePath::Relay)
    )
}

fn release_failed_launch(
    launched: &mut u64,
    opened_connections: &mut HashSet<libp2p::swarm::ConnectionId>,
    connection_id: libp2p::swarm::ConnectionId,
) {
    *launched = launched.saturating_sub(1);
    opened_connections.remove(&connection_id);
}
#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    identity_seed: Option<u64>,
    #[arg(long)]
    exchange: Option<Multiaddr>,
    #[arg(long)]
    credential_env: Option<String>,
    #[arg(long)]
    server: Option<Multiaddr>,
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    tcp_listen: Multiaddr,
    #[arg(long, default_value = "/ip4/127.0.0.1/udp/0/quic-v1")]
    quic_listen: Multiaddr,
    #[arg(long, value_enum, default_value_t = Path::Auto)]
    path: Path,
    #[arg(long, default_value_t = 1)]
    count: u64,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=128))]
    concurrency: u64,
    #[arg(long, default_value = "nonce_echo")]
    mode: String,
    #[arg(long, default_value_t = 0)]
    length: u64,
    #[arg(long, default_value_t = false)]
    churn: bool,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long, default_value = "probe")]
    case_id: String,
    #[arg(long, default_value_t = 1)]
    slow_delay_ms: u32,
    #[arg(long, default_value_t = 32 * 1024)]
    slow_chunk_size: u32,
    #[arg(long, default_value_t = 300)]
    worker_timeout_secs: u64,
    #[arg(long, default_value_t = false)]
    suppress_dcutr_result: bool,
    #[arg(long, default_value_t = false)]
    recover_after_failure: bool,
}

struct WorkerResult {
    peer_id: libp2p::PeerId,
    connection_id: libp2p::swarm::ConnectionId,
    selected_path: ProbePath,
    result: Result<ProbeAck, p2x_net::probe::ProbeError>,
}

fn drive_path_actions(
    behaviour: &mut p2x_net::probe_stream::behaviour::ProbeStreamBehaviour,
    attempt: &mut PathAttempt,
    peer_id: libp2p::PeerId,
    emitter: &Emitter,
    actions: Vec<PathAction>,
    launched: &mut u64,
) -> io::Result<()> {
    let mut actions = VecDeque::from(actions);
    while let Some(action) = actions.pop_front() {
        match action {
            PathAction::OpenExact { connection } => {
                let now = std::time::Instant::now();
                match behaviour.open_on(peer_id, connection) {
                    Ok(request_id) => {
                        *launched += 1;
                        emitter.emit(&LifecycleRecord::PathSelected {
                            request_id: request_id.0,
                            connection_id_hash: stable_hash(connection),
                            selected_path: match attempt.state {
                                p2x_net::PathState::Committed {
                                    decision: PathDecision::Direct(_),
                                    ..
                                } => ProbePath::Direct,
                                _ => ProbePath::Relay,
                            },
                        })?;
                        actions.extend(attempt.apply(PathEvent {
                            attempt_id: attempt.id,
                            now,
                            kind: PathEventKind::ExactOpenQueued {
                                request_id,
                                connection,
                            },
                        }));
                    }
                    Err(_) => actions.extend(attempt.apply(PathEvent {
                        attempt_id: attempt.id,
                        now,
                        kind: PathEventKind::ExactOpenRejected { connection },
                    })),
                }
            }
            PathAction::CancelOpen { request_id } => {
                behaviour.cancel(request_id);
            }
            PathAction::DialRelay | PathAction::CloseStream | PathAction::Finish(_) => {}
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let started_at = std::time::Instant::now();
    let args = Args::parse();
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = match &args.artifact {
        Some(path) => Emitter::with_artifact("client", &run_id, path)?,
        None => Emitter::new("client", &run_id),
    };
    let key = lab_identity(args.identity_seed).map_err(io::Error::other)?;
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
    let config = PeerSwarmConfig {
        tcp_listen: args.tcp_listen,
        quic_listen: args.quic_listen,
    };
    let mut swarm = build_peer_swarm(key, &config).map_err(io::Error::other)?;
    start_peer_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    let server_address = args.server.clone();
    let target_peer = args.server.as_ref().and_then(|address| {
        address.iter().fold(None, |last, part| match part {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => last,
        })
    });
    let local_peer = swarm.local_peer_id().to_string();
    emitter.emit(&LifecycleRecord::Started {
        peer_id: &local_peer,
    })?;
    let expected_exchange = args
        .exchange
        .as_ref()
        .and_then(|address| {
            address.iter().find_map(|part| match part {
                libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
                _ => None,
            })
        })
        .or_else(|| {
            args.server.as_ref().and_then(|address| {
                let mut peer = None;
                for part in address.iter() {
                    match part {
                        libp2p::multiaddr::Protocol::P2p(value) => peer = Some(value),
                        libp2p::multiaddr::Protocol::P2pCircuit => return peer,
                        _ => {}
                    }
                }
                None
            })
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "client requires an exchange identity",
            )
        })?;
    let mut connections = ConnectionBook::new(expected_exchange);
    if let Some(address) = args.exchange.clone() {
        swarm.dial(address).map_err(io::Error::other)?;
    }
    if let Some(address) = args.server.clone() {
        swarm.dial(address).map_err(io::Error::other)?;
    }
    let mut started = false;
    let mut completed = 0u64;
    let mut launched = 0u64;
    let mut saw_direct = false;
    let mut saw_relay = false;
    let mut recovery_attempted = false;
    let mut churn_redial_pending = false;
    let mut forced_opened_connections = HashSet::new();
    let mut attempt: Option<PathAttempt> = None;
    let auth_request_id = [1u8; 16];
    let mut maintenance = tokio::time::interval(std::time::Duration::from_millis(100));
    let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerResult>(128);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = maintenance.tick() => {
                let now = std::time::Instant::now();
                connections.sweep(now);
                if let (Some(peer_id), Some(attempt)) = (target_peer, attempt.as_mut()) {
                    let actions = attempt.apply(PathEvent { attempt_id: attempt.id, now, kind: PathEventKind::DirectDeadlineElapsed });
                    drive_path_actions(&mut swarm.behaviour_mut().probe_stream, attempt, peer_id, &emitter, actions, &mut launched)?;
                }
                emitter.emit(&LifecycleRecord::Resources { connections: connections.len(), pending_opens: swarm.behaviour().probe_stream.pending_count(), workers: 0, tasks: 0 })?;
            }
            Some(worker) = worker_rx.recv() => {
                let peer = worker.peer_id.to_string();
                match worker.result {
                    Ok(ack) => {
                        saw_direct |= ack.path == ProbePath::Direct;
                        saw_relay |= ack.path == ProbePath::Relay;
                        emitter.emit(&LifecycleRecord::ProbeCompleted { peer_id: &peer, ack: &ack })?;
                        completed += 1;
                        if completed == args.count && (!matches!(args.path, Path::Both) || (saw_direct && saw_relay)) {
                            let mut terminal = TerminalResult::simple(&args.case_id, "passed", "probe.ok");
                            terminal.selected_path = Some(worker.selected_path);
                            terminal.observed_path = Some(ack.path);
                            terminal.connection_id_hash = Some(ack.connection_id_hash);
                            terminal.bytes_read = ack.bytes_read;
                            terminal.bytes_written = ack.bytes_written;
                            terminal.read_hash = ack.read_hash;
                            terminal.write_hash = ack.write_hash;
                            terminal.half_close = ack.half_close;
                            terminal.terminal = ack.terminal;
                            terminal.setup_duration_ms = started_at.elapsed().as_millis();
                            emitter.terminal(&terminal)?;
                            return Ok(());
                        }
                        if args.churn {
                            let open_connections = connections
                                .iter()
                                .filter(|record| record.peer_id == worker.peer_id)
                                .map(|record| record.connection_id)
                                .collect::<Vec<_>>();
                            for connection_id in open_connections {
                                swarm.close_connection(connection_id);
                            }
                            started = false;
                            churn_redial_pending = true;
                        } else if launched < args.count && !matches!(args.path, Path::Both) {
                            let request_id = swarm.behaviour_mut().probe_stream.open_on(worker.peer_id, worker.connection_id).map_err(io::Error::other)?;
                            launched += 1;
                            emitter.emit(&LifecycleRecord::PathSelected { request_id: request_id.0, connection_id_hash: stable_hash(worker.connection_id), selected_path: worker.selected_path })?;
                        }
                    }
                    Err(error) => {
                        if args.recover_after_failure && !recovery_attempted {
                            recovery_attempted = true;
                            started = false;
                            release_failed_launch(&mut launched, &mut forced_opened_connections, worker.connection_id);
                            swarm.close_connection(worker.connection_id);
                            if let Some(address) = server_address.clone() { swarm.dial(address).map_err(io::Error::other)?; }
                            let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "probe.recovering", message: &message })?;
                            continue;
                        }
                        let mut terminal = TerminalResult::simple(&args.case_id, "failed", "probe.failed");
                        terminal.selected_path = Some(worker.selected_path);
                        terminal.connection_id_hash = Some(stable_hash(worker.connection_id));
                        terminal.terminal = error.terminal();
                        terminal.setup_duration_ms = started_at.elapsed().as_millis();
                        emitter.terminal(&terminal)?;
                        return Err(io::Error::other(error));
                    }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        let observed_path = if endpoint.is_relayed() { ProbePath::Relay } else { ProbePath::Direct };
                        let peer = peer_id.to_string();
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Established, path: Some(observed_path), reason: None })?;
                        if expected_exchange == peer_id && let Some((id, token)) = credential.as_ref() { swarm.behaviour_mut().auth.send_request(&peer_id, AuthRequest::Authenticate { request_id: auth_request_id, credential_id: id.clone(), token_secret: *token.as_bytes(), requested_role: Role::Client, supported_features: 0 }); }
                        if target_peer == Some(peer_id) {
                            if let Err(error) = connections.on_connection_established(peer_id, connection_id, &endpoint, std::time::Instant::now()) {
                                swarm.close_connection(connection_id);
                                let message = error.to_string();
                                emitter.emit(&LifecycleRecord::OperationalError { code: "connection.rejected", message: &message })?;
                                continue;
                            }
                            if forced_path_matches(args.path, observed_path)
                                && (!started || matches!(args.path, Path::Both))
                                && launched < args.count
                                && forced_opened_connections.insert(connection_id)
                            {
                                let request_id = swarm.behaviour_mut().probe_stream.open_on(peer_id, connection_id).map_err(io::Error::other)?;
                                launched += 1;
                                emitter.emit(&LifecycleRecord::PathSelected { request_id: request_id.0, connection_id_hash: stable_hash(connection_id), selected_path: observed_path })?;
                                started = true;
                            } else if !started && matches!(args.path, Path::Auto) && observed_path == ProbePath::Relay {
                                let current = attempt.get_or_insert_with(|| PathAttempt::with_id(AttemptId(1), std::time::Instant::now()));
                                let direct = connections.direct(peer_id).map(|record| record.connection_id);
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::Begin { relay: Some(connection_id), direct } });
                                drive_path_actions(&mut swarm.behaviour_mut().probe_stream, current, peer_id, &emitter, actions, &mut launched)?;
                                started = true;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Response { response: AuthResponse::Authenticated { session_id, .. }, .. }, .. })) => { swarm.behaviour_mut().auth.send_request(&peer, AuthRequest::Ping { request_id: [2; 16], session_id, nonce: 1 }); }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => {
                        connections.on_connection_closed(peer_id, connection_id).map_err(io::Error::other)?;
                        if let Some(current) = attempt.as_mut() {
                            let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ConnectionClosed(connection_id) });
                            drive_path_actions(&mut swarm.behaviour_mut().probe_stream, current, peer_id, &emitter, actions, &mut launched)?;
                        }
                        let peer = peer_id.to_string();
                        let reason = format!("{cause:?}");
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Closed, path: None, reason: Some(&reason) })?;
                        if args.churn && churn_redial_pending && target_peer == Some(peer_id) && completed < args.count && let Some(address) = server_address.clone() {
                            churn_redial_pending = false;
                            swarm.dial(address).map_err(io::Error::other)?;
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Probe(output)) => match output {
                        ProbeOutput::OutboundOpened { stream, request_id, peer_id, connection_id } => {
                            let mut stream = stream;
                            if let Some(current) = attempt.as_mut() {
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ExactOpenSucceeded { request_id, connection: connection_id } });
                                drive_path_actions(&mut swarm.behaviour_mut().probe_stream, current, peer_id, &emitter, actions, &mut launched)?;
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::PayloadAccepted });
                                drive_path_actions(&mut swarm.behaviour_mut().probe_stream, current, peer_id, &emitter, actions, &mut launched)?;
                            }
                            let mode = match args.mode.as_str() {
                                "nonce_echo" => ProbeMode::NonceEcho,
                                "half_close" => ProbeMode::HalfClose,
                                "slow_reader" => ProbeMode::SlowReader,
                                other => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown probe mode: {other}"))),
                            };
                            let header = ProbeHeader { schema_version: SCHEMA_VERSION, request_id: request_id.0, mode, nonce: request_id.0, length: args.length, slow_delay_ms: if mode == ProbeMode::SlowReader { args.slow_delay_ms } else { 0 }, slow_chunk_size: if mode == ProbeMode::SlowReader { args.slow_chunk_size } else { 0 } };
                            let selected_path = connections.get(peer_id, connection_id).map(|record| match record.path { PathKind::Relay { .. } => ProbePath::Relay, _ => ProbePath::Direct }).unwrap_or(ProbePath::Relay);
                            while !matches!(args.path, Path::Both) && launched < args.count && launched < args.concurrency {
                                let next = swarm.behaviour_mut().probe_stream.open_on(peer_id, connection_id).map_err(io::Error::other)?;
                                launched += 1;
                                emitter.emit(&LifecycleRecord::PathSelected { request_id: next.0, connection_id_hash: stable_hash(connection_id), selected_path })?;
                            }
                            let tx = worker_tx.clone();
                            let worker_timeout = std::time::Duration::from_secs(args.worker_timeout_secs);
                            tokio::spawn(async move {
                                let result = execute_probe_client_futures_with_timeout(&mut stream, &header, worker_timeout).await;
                                let _ = tx.send(WorkerResult { peer_id, connection_id, selected_path, result }).await;
                            });
                        }
                        ProbeOutput::OutboundFailed { request_id, peer_id, connection_id, code } => {
                            if let Some(current) = attempt.as_mut() {
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ExactOpenFailed { request_id, connection: connection_id } });
                                drive_path_actions(&mut swarm.behaviour_mut().probe_stream, current, peer_id, &emitter, actions, &mut launched)?;
                            }
                            if args.recover_after_failure && !recovery_attempted {
                                recovery_attempted = true;
                                started = false;
                                release_failed_launch(&mut launched, &mut forced_opened_connections, connection_id);
                                if let Some(address) = server_address.clone() { swarm.dial(address).map_err(io::Error::other)?; }
                                emitter.emit(&LifecycleRecord::OperationalError { code: "probe.recovering", message: code })?;
                                continue;
                            }
                            let mut terminal = TerminalResult::simple(&args.case_id, "failed", code);
                            terminal.terminal = ProbeTerminal::Io;
                            terminal.setup_duration_ms = started_at.elapsed().as_millis();
                            emitter.terminal(&terminal)?;
                            return Err(io::Error::other(code));
                        }
                        ProbeOutput::InboundOpened { .. } | ProbeOutput::InboundRejected { .. } => {}
                    },
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Dcutr(event)) => {
                        if args.suppress_dcutr_result {
                            continue;
                        }
                        match event.result {
                            Ok(connection_id) => {
                                connections.on_dcutr_succeeded(event.remote_peer_id, connection_id, std::time::Instant::now()).map_err(io::Error::other)?;
                                if target_peer == Some(event.remote_peer_id)
                                    && forced_path_matches(args.path, ProbePath::Direct)
                                    && (!started || matches!(args.path, Path::Both))
                                    && launched < args.count
                                    && forced_opened_connections.insert(connection_id)
                                {
                                    let request_id = swarm.behaviour_mut().probe_stream.open_on(event.remote_peer_id, connection_id).map_err(io::Error::other)?;
                                    launched += 1;
                                    emitter.emit(&LifecycleRecord::PathSelected { request_id: request_id.0, connection_id_hash: stable_hash(connection_id), selected_path: ProbePath::Direct })?;
                                    started = true;
                                } else if let Some(current) = attempt.as_mut() {
                                    let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::DirectReady(connection_id) });
                                    drive_path_actions(&mut swarm.behaviour_mut().probe_stream, current, event.remote_peer_id, &emitter, actions, &mut launched)?;
                                }
                            }
                            Err(error) => {
                                if let Some(current) = attempt.as_mut() {
                                    let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::DcutrFailed });
                                    drive_path_actions(&mut swarm.behaviour_mut().probe_stream, current, event.remote_peer_id, &emitter, actions, &mut launched)?;
                                }
                                let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "dcutr.failed", message: &message })?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let mut terminal = TerminalResult::simple(&args.case_id, "stopped", "shutdown");
    terminal.setup_duration_ms = started_at.elapsed().as_millis();
    emitter.terminal(&terminal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_paths_match_established_connection_kind() {
        assert!(forced_path_matches(Path::Direct, ProbePath::Direct));
        assert!(!forced_path_matches(Path::Direct, ProbePath::Relay));
        assert!(forced_path_matches(Path::Relay, ProbePath::Relay));
        assert!(!forced_path_matches(Path::Relay, ProbePath::Direct));
        assert!(forced_path_matches(Path::Both, ProbePath::Direct));
        assert!(forced_path_matches(Path::Both, ProbePath::Relay));
        assert!(!forced_path_matches(Path::Auto, ProbePath::Direct));
    }

    #[test]
    fn recovery_releases_failed_launch_budget_and_connection() {
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(7);
        let mut launched = 1;
        let mut opened = HashSet::from([connection_id]);

        release_failed_launch(&mut launched, &mut opened, connection_id);

        assert_eq!(launched, 0);
        assert!(opened.is_empty());
    }
}
