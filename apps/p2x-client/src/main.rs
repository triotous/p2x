#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod connection_manager;
mod ingress;
mod ingress_owner;
#[allow(dead_code)]
mod proxy_open;
#[allow(dead_code)]
mod resolver;
#[allow(dead_code)]
mod route_open;

use clap::{Parser, ValueEnum};
use connection_manager::{ConnectionManager, ResolvedPeerMetadata, SetupLimits};
use futures::StreamExt;
use ingress::{IngressCommand, IngressEvent, IngressId};
use ingress_owner::{IngressOwnerBook, IngressSetupOwner};
use libp2p::{
    Multiaddr,
    request_response::{Event as RequestResponseEvent, Message as RequestResponseMessage},
    swarm::{
        SwarmEvent,
        dial_opts::{DialOpts, PeerCondition},
    },
};
use p2x_net::{
    AttemptId, PathAction, PathAttempt, PathDecision, PathEvent, PathEventKind, PathRequestId,
    auth_state::{
        AddressCursor, AuthAction, AuthState, ConnectionLoss, ExchangeConnections, PendingRequest,
        RedialBackoff,
    },
    builder::{PeerSurface, PeerSwarmConfig, build_peer_swarm, lab_identity, start_peer_listeners},
    connection_book::{ConnectionBook, PathKind},
    lifecycle::{ConnectionState, Emitter, LifecycleRecord, TerminalResult, stable_hash},
    path_selector::PathPolicy,
    probe::{ProbeAck, ProbeHeader, ProbeMode, ProbePath, ProbeTerminal, SCHEMA_VERSION},
    probe_stream::behaviour::ProbeOutput,
    probe_worker::execute_probe_client_futures_with_timeout,
    proxy_stream::behaviour::{ProxyOutput, ProxyRequestId},
};
use p2x_protocol::{
    AuthRequest, AuthResponse, OpenProxyStreamV1, PublicErrorCode, ResolveRequestV1, Role,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    path::PathBuf,
};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuthFaultArg {
    UnsupportedVersion,
    OversizedFrame,
    MalformedFrame,
}
impl From<AuthFaultArg> for p2x_net::auth_codec::AuthFault {
    fn from(value: AuthFaultArg) -> Self {
        match value {
            AuthFaultArg::UnsupportedVersion => Self::UnsupportedVersion,
            AuthFaultArg::OversizedFrame => Self::OversizedFrame,
            AuthFaultArg::MalformedFrame => Self::Malformed,
        }
    }
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Path {
    Auto,
    Both,
    Direct,
    Relay,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OpenMutation {
    None,
    TicketByte,
    UpstreamId,
    Revision,
}

fn forced_path_matches(path: Path, observed_path: ProbePath) -> bool {
    matches!(
        (path, observed_path),
        (Path::Direct, ProbePath::Direct)
            | (Path::Relay, ProbePath::Relay)
            | (Path::Both, ProbePath::Direct | ProbePath::Relay)
    )
}

fn tunnel_terminal_class(terminal: p2x_proxy::Terminal) -> p2x_net::lifecycle::TunnelTerminalClass {
    match terminal {
        p2x_proxy::Terminal::Complete => p2x_net::lifecycle::TunnelTerminalClass::Complete,
        p2x_proxy::Terminal::IdleTimeout => p2x_net::lifecycle::TunnelTerminalClass::IdleTimeout,
        p2x_proxy::Terminal::Cancelled => p2x_net::lifecycle::TunnelTerminalClass::Cancelled,
        p2x_proxy::Terminal::LocalIo => p2x_net::lifecycle::TunnelTerminalClass::LocalIo,
        p2x_proxy::Terminal::RemoteIo => p2x_net::lifecycle::TunnelTerminalClass::RemoteIo,
    }
}

fn emit_client_tunnel_terminal(
    emitter: &Emitter,
    owner: &ingress_owner::ActiveTunnelOwner,
    result: Option<&p2x_proxy::PumpResult>,
    terminal_class: p2x_net::lifecycle::TunnelTerminalClass,
    code: Option<&str>,
) -> io::Result<()> {
    let peer = owner.server.to_string();
    emitter.emit(&LifecycleRecord::TunnelTerminal {
        component_side: p2x_net::lifecycle::ComponentSide::Client,
        peer_id: &peer,
        connection_id_hash: stable_hash(owner.connection),
        request_id_hash: owner.request_id_hash,
        stream_id_hash: Some(owner.stream_id_hash),
        selected_path: Some(owner.selected_path),
        accepted: true,
        code,
        terminal_class,
        setup_duration_ms: owner.setup_duration.as_millis(),
        local_to_remote_bytes: result.map_or(0, |result| result.local_to_remote_bytes),
        remote_to_local_bytes: result.map_or(0, |result| result.remote_to_local_bytes),
        local_eof: result.is_some_and(|result| result.local_eof),
        remote_eof: result.is_some_and(|result| result.remote_eof),
        duration_ms: result.map_or(0, |result| result.duration.as_millis()),
    })
}

async fn reject_ingress(
    owners: &mut IngressOwnerBook,
    id: IngressId,
    code: PublicErrorCode,
    emitter: &Emitter,
) -> io::Result<bool> {
    let Some(owner) = owners.take_setup(id) else {
        return Ok(false);
    };
    owner.cancel.cancel();
    let _ = owner.command.send(IngressCommand::Reject).await;
    emitter.emit(&LifecycleRecord::IngressRejected {
        route_id_hash: stable_hash(&owner.route_id),
        ingress_id: id.0,
        code: code.as_str(),
    })?;
    Ok(true)
}

fn protocol_failure_code(error: &std::io::Error, fault: Option<AuthFaultArg>) -> PublicErrorCode {
    if let Some(fault) = fault {
        return match fault {
            AuthFaultArg::UnsupportedVersion => PublicErrorCode::ProtocolUnsupportedVersion,
            AuthFaultArg::OversizedFrame => PublicErrorCode::ProtocolFrameTooLarge,
            AuthFaultArg::MalformedFrame => PublicErrorCode::ProtocolMalformed,
        };
    }
    let message = error.to_string();
    if message.contains("too large") {
        PublicErrorCode::ProtocolFrameTooLarge
    } else if message.contains("unsupported") {
        PublicErrorCode::ProtocolUnsupportedVersion
    } else if message.contains("capabilities") {
        PublicErrorCode::ProtocolCapabilityMismatch
    } else {
        PublicErrorCode::ProtocolMalformed
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn random_jitter_per_mille() -> io::Result<i16> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("runtime randomness unavailable"))?;
    Ok((u16::from_be_bytes(bytes) % 201) as i16 - 100)
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
    unsafe_connectivity_lab: bool,
    #[arg(long)]
    identity_file: Option<PathBuf>,
    #[arg(long)]
    generate_identity: bool,
    #[arg(long, action = clap::ArgAction::Append)]
    exchange: Vec<Multiaddr>,
    #[arg(long)]
    routes_file: Option<PathBuf>,
    #[arg(long)]
    exchange_peer_id: Option<String>,
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
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(1..=128))]
    test_proxy_open_count: Option<u64>,
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(1..=128))]
    test_proxy_concurrency: Option<u64>,
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(0..=10_000))]
    test_delay_after_resolve_ms: Option<u64>,
    #[arg(long, hide = true)]
    test_replay_first_ticket: bool,
    #[arg(long, hide = true)]
    test_fail_first_resolve: bool,
    #[arg(long, hide = true, value_enum, default_value_t = OpenMutation::None)]
    test_open_mutation: OpenMutation,
    #[arg(long, hide = true)]
    test_fail_first_direct_open_before_handshake: bool,
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(0..=10_000))]
    test_hold_proxy_handshake_ms: Option<u64>,
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(1..=30_000))]
    test_close_proxy_after_accept_ms: Option<u64>,
    #[arg(long, default_value_t = false)]
    recover_after_failure: bool,
    #[arg(long)]
    finite_auth_check: bool,
    #[arg(long)]
    finite_relay_ping: bool,
    #[arg(long)]
    finite_proxy_check: bool,
    #[arg(long, hide = true, default_value_t = 0)]
    test_hold_relay_seconds: u64,
    #[arg(long, hide = true, default_value_t = 1)]
    test_relay_circuit_count: u32,
    #[arg(long, hide = true, action = clap::ArgAction::Append)]
    test_relay_target: Vec<Multiaddr>,
    #[arg(long, value_enum)]
    auth_fault: Option<AuthFaultArg>,
}

struct WorkerResult {
    peer_id: libp2p::PeerId,
    connection_id: libp2p::swarm::ConnectionId,
    selected_path: ProbePath,
    result: Result<ProbeAck, p2x_net::probe::ProbeError>,
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
                                request_id: PathRequestId(request_id.0),
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
                behaviour.cancel(p2x_net::probe_stream::handler::RequestId(request_id.0));
            }
            PathAction::DialRelay | PathAction::CloseStream | PathAction::Finish(_) => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drive_proxy_path_actions(
    behaviour: &mut p2x_net::proxy_stream::behaviour::ProxyStreamBehaviour,
    attempt: &mut PathAttempt,
    peer_id: libp2p::PeerId,
    open: &OpenProxyStreamV1,
    deadline: std::time::Instant,
    emitter: &Emitter,
    actions: Vec<PathAction>,
    pending: &mut Option<ProxyRequestId>,
    selected: &mut Option<libp2p::swarm::ConnectionId>,
    terminal: &mut Option<p2x_net::PathFailure>,
) -> io::Result<()> {
    let mut actions = VecDeque::from(actions);
    while let Some(action) = actions.pop_front() {
        match action {
            PathAction::OpenExact { connection } => {
                let now = std::time::Instant::now();
                match behaviour.open_on_at_deadline(
                    peer_id,
                    connection,
                    open.clone(),
                    now,
                    deadline,
                ) {
                    Ok(request_id) => {
                        *pending = Some(request_id);
                        *selected = Some(connection);
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
                                request_id: PathRequestId(request_id.0),
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
                behaviour.cancel(ProxyRequestId(request_id.0));
            }
            PathAction::DialRelay | PathAction::CloseStream => {}
            PathAction::Finish(reason) => *terminal = Some(reason),
        }
    }
    Ok(())
}

type MultiResolveWire = HashMap<
    libp2p::request_response::OutboundRequestId,
    (route_open::OpenId, u64, std::time::Instant),
>;
type RouteCompletion = (
    route_open::OpenId,
    Option<libp2p::PeerId>,
    [u8; 16],
    Result<(), PublicErrorCode>,
);

#[allow(clippy::too_many_arguments)]
async fn complete_route_actions(
    product_ingress: bool,
    completions: Vec<RouteCompletion>,
    resolver: &mut resolver::ResolverState,
    route_resolve_wires: &mut MultiResolveWire,
    route_proxy_requests: &mut HashMap<ProxyRequestId, route_open::OpenId>,
    ingress_owners: &mut IngressOwnerBook,
    route_owner: &mut route_open::RouteOpenSupervisor,
    exchange_peer: libp2p::PeerId,
    connections: &ConnectionBook,
    next_wire_id: &mut u64,
    manager: &mut Option<ConnectionManager>,
    swarm: &mut libp2p::Swarm<p2x_net::builder::PeerBehaviour>,
    emitter: &Emitter,
    case_id: &str,
) -> io::Result<bool> {
    let mut completions = VecDeque::from(completions);
    while let Some((open_id, server, request_id, result)) = completions.pop_front() {
        route_resolve_wires.retain(|_, (candidate, _, _)| *candidate != open_id);
        route_proxy_requests.retain(|_, candidate| *candidate != open_id);
        resolver.cancel(request_id);
        if let (Some(manager), Some(server)) = (manager.as_mut(), server) {
            release_route_setup(manager, swarm, server, open_id);
        }
        if let Err(code) = result {
            if product_ingress {
                if let Some(ingress_id) = ingress_owners.ingress_for_open(open_id)
                    && let Some(owner) = ingress_owners.take_setup_for_open(open_id)
                {
                    owner.cancel.cancel();
                    let _ = owner.command.send(IngressCommand::Reject).await;
                    emitter.emit(&LifecycleRecord::IngressRejected {
                        route_id_hash: stable_hash(&owner.route_id),
                        ingress_id: ingress_id.0,
                        code: code.as_str(),
                    })?;
                }
            } else {
                emitter.terminal(&TerminalResult::simple(case_id, "failed", code.as_str()))?;
                return Ok(true);
            }
        }
        let promoted = route_owner.promote_waiters(resolver);
        if !promoted.is_empty() {
            let promoted_completions = drive_route_actions(
                swarm,
                route_owner,
                exchange_peer,
                emitter,
                connections,
                route_resolve_wires,
                route_proxy_requests,
                next_wire_id,
                promoted,
            )?;
            completions.extend(promoted_completions);
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn drive_route_actions(
    swarm: &mut libp2p::Swarm<p2x_net::builder::PeerBehaviour>,
    owner: &mut route_open::RouteOpenSupervisor,
    exchange_peer: libp2p::PeerId,
    emitter: &Emitter,
    connections: &ConnectionBook,
    resolve_wires: &mut MultiResolveWire,
    proxy_requests: &mut HashMap<ProxyRequestId, route_open::OpenId>,
    next_wire_id: &mut u64,
    actions: Vec<route_open::RouteAction>,
) -> io::Result<Vec<RouteCompletion>> {
    let mut actions = VecDeque::from(actions);
    let mut completed = Vec::new();
    while let Some(action) = actions.pop_front() {
        match action {
            route_open::RouteAction::SendResolve { open_id, request } => {
                *next_wire_id = next_wire_id
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("resolve wire ID exhausted"))?;
                let outbound = swarm
                    .behaviour_mut()
                    .resolve
                    .send_request(&exchange_peer, request);
                if !owner.resolve_sent(open_id, *next_wire_id) {
                    return Err(io::Error::other("route owner rejected resolve dispatch"));
                }
                resolve_wires.insert(
                    outbound,
                    (open_id, *next_wire_id, std::time::Instant::now()),
                );
            }
            route_open::RouteAction::DialRelay {
                open_id: _,
                peer: _,
                address,
            } => {
                let address = Multiaddr::try_from(address).map_err(io::Error::other)?;
                swarm.dial(address).map_err(io::Error::other)?;
            }
            route_open::RouteAction::OpenExact {
                open_id,
                connection,
                open,
            } => {
                let deadline = owner
                    .path_input(open_id)
                    .map(|input| input.5)
                    .ok_or_else(|| io::Error::other("route path input missing"))?;
                let peer = owner
                    .path_input(open_id)
                    .map(|input| input.0)
                    .ok_or_else(|| io::Error::other("route peer missing"))?;
                let request = swarm
                    .behaviour_mut()
                    .proxy_stream
                    .as_mut()
                    .ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?
                    .open_on_at_deadline(
                        peer,
                        connection,
                        open,
                        std::time::Instant::now(),
                        deadline,
                    );
                match request {
                    Ok(request_id) => {
                        let queued = owner
                            .proxy_queued(
                                open_id,
                                request_id.0,
                                connection,
                                std::time::Instant::now(),
                            )
                            .ok_or_else(|| {
                                io::Error::other("route owner rejected proxy dispatch")
                            })?;
                        proxy_requests.insert(request_id, open_id);
                        actions.extend(queued);
                        emitter.emit(&LifecycleRecord::PathSelected {
                            request_id: request_id.0,
                            connection_id_hash: stable_hash(connection),
                            selected_path: if connections.is_direct(peer, connection) {
                                ProbePath::Direct
                            } else {
                                ProbePath::Relay
                            },
                        })?;
                    }
                    Err(_) => {
                        let attempt_id = owner
                            .path_attempt_id(open_id)
                            .ok_or_else(|| io::Error::other("route path attempt missing"))?;
                        if let Some(next) = owner.path_event(
                            open_id,
                            PathEvent {
                                attempt_id,
                                now: std::time::Instant::now(),
                                kind: PathEventKind::ExactOpenRejected { connection },
                            },
                        ) {
                            actions.extend(next);
                        }
                    }
                }
            }
            route_open::RouteAction::CloseConnection { connection, .. } => {
                swarm.close_connection(connection);
            }
            route_open::RouteAction::Complete {
                open_id,
                server,
                request_id,
                proxy_request_id,
                result,
            } => {
                if let Some(request_id) = proxy_request_id {
                    let request_id = ProxyRequestId(request_id);
                    proxy_requests.remove(&request_id);
                    if let Some(proxy) = swarm.behaviour_mut().proxy_stream.as_mut() {
                        proxy.cancel(request_id);
                    }
                }
                completed.push((open_id, server, request_id, result));
            }
            route_open::RouteAction::StartHandshakeWorker { .. } => {
                return Err(io::Error::other(
                    "handshake worker action must be dispatched from an opened stream",
                ));
            }
        }
    }
    Ok(completed)
}

#[allow(clippy::too_many_arguments)]
fn admit_route_window(
    owner: &mut route_open::RouteOpenSupervisor,
    resolver: &mut resolver::ResolverState,
    binding: p2x_net::auth_state::PrincipalBinding,
    session_id: [u8; 16],
    selector: &p2x_protocol::UnscopedSelector,
    now: i64,
    setup_budget: std::time::Duration,
    target: u64,
    concurrency: u64,
    admitted: &mut u64,
) -> Result<Vec<route_open::RouteAction>, PublicErrorCode> {
    let mut actions = Vec::new();
    while *admitted < target && owner.len() < concurrency as usize {
        let (_, admitted_actions) = owner.admit(
            resolver,
            binding.clone(),
            session_id,
            selector.clone(),
            now,
            std::time::Instant::now() + setup_budget,
        )?;
        *admitted = admitted.saturating_add(1);
        actions.extend(admitted_actions);
    }
    Ok(actions)
}

fn release_route_setup(
    manager: &mut ConnectionManager,
    swarm: &mut libp2p::Swarm<p2x_net::builder::PeerBehaviour>,
    server: libp2p::PeerId,
    waiter_id: route_open::OpenId,
) {
    if !manager.release_waiter(server, waiter_id.0) {
        return;
    }
    let _ = manager.release(server);
    for action in manager.pool_close_actions(server) {
        if let connection_manager::ConnectionSetupAction::Close { connection } = action {
            swarm.close_connection(connection);
        }
    }
}

fn route_proxy_rejection_needs_fresh_ticket(code: PublicErrorCode) -> bool {
    matches!(
        code,
        PublicErrorCode::RegistryStaleRevision
            | PublicErrorCode::AuthSessionRequired
            | PublicErrorCode::PeerConnectionFailed
            | PublicErrorCode::PeerSetupTimeout
            | PublicErrorCode::ExchangeTimeout
    )
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let started_at = std::time::Instant::now();
    let args = Args::parse();
    if !args.unsafe_connectivity_lab
        && args.routes_file.is_none()
        && !args.finite_auth_check
        && !args.finite_relay_ping
        && args.test_proxy_open_count.is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --routes-file",
        ));
    }
    let routes = args
        .routes_file
        .as_deref()
        .map(config::ClientConfig::load)
        .transpose()
        .map_err(io::Error::other)?;
    let product_ingress = routes
        .as_ref()
        .is_some_and(|config| !config.raw_tcp.is_empty());
    let route_test_hook_used = args.test_proxy_open_count.is_some()
        || args.test_proxy_concurrency.is_some()
        || args.test_delay_after_resolve_ms.is_some()
        || args.test_replay_first_ticket
        || args.test_fail_first_resolve
        || !matches!(args.test_open_mutation, OpenMutation::None)
        || args.test_fail_first_direct_open_before_handshake
        || args.test_hold_proxy_handshake_ms.is_some()
        || args.test_close_proxy_after_accept_ms.is_some();
    if route_test_hook_used && std::env::var("P2X_ENABLE_TEST_HOOKS").ok().as_deref() != Some("1") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "route test hooks require P2X_ENABLE_TEST_HOOKS=1",
        ));
    }
    if args.test_proxy_concurrency.unwrap_or(1) > args.test_proxy_open_count.unwrap_or(1) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy concurrency cannot exceed proxy open count",
        ));
    }
    if (args.test_hold_relay_seconds > 0
        || args.test_relay_circuit_count != 1
        || !args.test_relay_target.is_empty())
        && std::env::var_os("P2X_ENABLE_TEST_HOOKS").is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay test hooks require P2X_ENABLE_TEST_HOOKS=1",
        ));
    }
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = match &args.artifact {
        Some(path) => Emitter::with_artifact("client", &run_id, path)?,
        None => Emitter::new("client", &run_id),
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
            "authenticated client requires --identity-file",
        ));
    } else if args.unsafe_connectivity_lab {
        lab_identity(args.identity_seed).map_err(io::Error::other)?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --identity-file",
        ));
    };
    let exchange_trust = if args.unsafe_connectivity_lab {
        None
    } else {
        let _exchange = args.exchange.first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "product mode requires --exchange",
            )
        })?;
        let configured = args.exchange_peer_id.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "product mode requires --exchange-peer-id",
            )
        })?;
        Some(
            p2x_config::trust::validate_exchange_trust(configured, &args.exchange).map_err(
                |_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "auth.exchange_identity_mismatch",
                    )
                },
            )?,
        )
    };
    if args.credential_env.is_none() && !args.unsafe_connectivity_lab {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --credential-env",
        ));
    }
    let credential_ref =
        args.credential_env
            .as_deref()
            .map(|env_name| p2x_config::credential::CredentialRef {
                env_name: env_name.to_owned(),
            });
    let config = PeerSwarmConfig {
        tcp_listen: args.tcp_listen,
        quic_listen: args.quic_listen,
        surface: if args.unsafe_connectivity_lab {
            PeerSurface::ConnectivityLab
        } else {
            PeerSurface::ProductClient
        },
        auth_fault: args.auth_fault.map(Into::into),
    };
    let mut swarm = build_peer_swarm(key, &config).map_err(io::Error::other)?;
    start_peer_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let (ingress_tx, mut ingress_rx) = mpsc::channel::<IngressEvent>(128);
    let mut ingress_tasks = if product_ingress {
        let route_config = routes.as_ref().expect("raw ingress has route config");
        let listeners = ingress::bind_all(&route_config.raw_tcp).await?;
        ingress::spawn_all(
            listeners,
            route_config.limits.max_ingress_connections,
            route_config.limits.copy_buffer_bytes,
            std::time::Duration::from_millis(route_config.network.connection_setup_timeout_ms),
            ingress_tx.clone(),
            shutdown.clone(),
        )
    } else {
        Vec::new()
    };
    let server_address = args.server.clone();
    let mut target_peer = args.server.as_ref().and_then(|address| {
        address.iter().fold(None, |last, part| match part {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => last,
        })
    });
    let local_peer = swarm.local_peer_id().to_string();
    emitter.emit(&LifecycleRecord::Started {
        peer_id: &local_peer,
    })?;
    if let Some(fault) = args.auth_fault {
        let fault = match fault {
            AuthFaultArg::UnsupportedVersion => "unsupported_version",
            AuthFaultArg::OversizedFrame => "oversized_frame",
            AuthFaultArg::MalformedFrame => "malformed_frame",
        };
        emitter.emit(&LifecycleRecord::OperationalError {
            code: "auth.fault_applied",
            message: fault,
        })?;
    }
    let expected_exchange = exchange_trust
        .as_ref()
        .map(|trust| trust.peer_id)
        .or_else(|| {
            args.exchange.first().and_then(|address| {
                address.iter().find_map(|part| match part {
                    libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
                    _ => None,
                })
            })
        })
        .or_else(|| {
            if args.unsafe_connectivity_lab {
                args.server.as_ref().and_then(|address| {
                    address.iter().find_map(|part| match part {
                        libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
                        _ => None,
                    })
                })
            } else {
                None
            }
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "client requires an exchange identity",
            )
        })?;
    let mut credential: Option<(p2x_protocol::CredentialId, p2x_protocol::TokenSecret)> = None;
    let mut resolver_state = resolver::ResolverState::default();
    resolver_state.set_exchange_peer(expected_exchange);
    let mut connections = ConnectionBook::new(expected_exchange);
    let mut connection_manager = routes.as_ref().map(|config| {
        let policy = PathPolicy::new(
            std::time::Duration::from_millis(config.network.direct_preference_ms),
            std::time::Duration::from_millis(config.network.connection_setup_timeout_ms),
        )
        .expect("validated route timing");
        ConnectionManager::new(
            expected_exchange,
            policy,
            SetupLimits {
                max_peer_states: config.limits.max_peer_states,
                max_pending_setups: config.limits.max_pending_setups,
                max_pending_per_server: config.limits.max_pending_per_server,
                max_streams_per_server: config.limits.max_streams_per_server,
            },
        )
    });
    let mut exchange_addresses = AddressCursor::new();
    if let Some(index) = exchange_addresses.next(args.exchange.len()) {
        swarm
            .dial(args.exchange[index].clone())
            .map_err(io::Error::other)?;
    }
    if args.unsafe_connectivity_lab
        && let Some(address) = args.server.clone()
    {
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
    let mut request_ids = p2x_protocol::CorrelationIdGenerator::new(1);
    let mut auth_request_id = request_ids.allocate().map_err(io::Error::other)?;
    let mut ping_request_id = request_ids.allocate().map_err(io::Error::other)?;
    let mut auth_state = AuthState::new();
    let mut exchange_connections = ExchangeConnections::new();
    let mut pending_auth = PendingRequest::new();
    let mut exchange_redial = RedialBackoff::new();
    let mut test_relay_targets: VecDeque<Multiaddr> = VecDeque::new();
    let mut test_dialed_targets = HashSet::new();
    let mut readiness_generation = 0u64;
    let mut pending_resolve: PendingRequest<libp2p::request_response::OutboundRequestId> =
        PendingRequest::new();
    let mut resolve_request: Option<ResolveRequestV1> = None;
    let mut resolve_retried = false;
    let mut recovery_resolve_retried = false;
    let mut exchange_restarted = false;
    let mut recovery_retry_deadline: Option<std::time::Instant> = None;
    let mut deferred_resolve_retry_at: Option<std::time::Instant> = None;
    let mut resolve_sent_at: Option<std::time::Instant> = None;
    let mut resolve_setup_deadline: Option<std::time::Instant> = None;
    let mut proxy_open: Option<OpenProxyStreamV1> = None;
    let mut last_proxy_open: Option<OpenProxyStreamV1> = None;
    let mut delayed_proxy_open: Option<(
        OpenProxyStreamV1,
        std::time::Instant,
        libp2p::PeerId,
        Multiaddr,
        p2x_protocol::Capabilities,
    )> = None;
    let mut replay_attempted = false;
    let mut proxy_completed = 0u64;
    let proxy_target = args.test_proxy_open_count.unwrap_or(1);
    let proxy_concurrency = args.test_proxy_concurrency.unwrap_or(1);
    let supervised_proxy_mode = (args.finite_proxy_check || args.test_proxy_open_count.is_some())
        && !args.test_replay_first_ticket
        && matches!(args.test_open_mutation, OpenMutation::None)
        && args.test_delay_after_resolve_ms.is_none()
        && !args.test_fail_first_direct_open_before_handshake
        && !args.recover_after_failure;
    let mut route_owner = (supervised_proxy_mode || product_ingress).then(|| {
        route_open::RouteOpenSupervisor::new(
            routes
                .as_ref()
                .map_or(route_open::MAX_ROUTE_OPENS, |config| {
                    config.limits.max_route_opens
                }),
        )
    });
    let mut route_admitted = 0u64;
    let mut ingress_owners = IngressOwnerBook::default();
    let mut route_resolve_wires = MultiResolveWire::new();
    let mut route_proxy_requests = HashMap::<ProxyRequestId, route_open::OpenId>::new();
    let mut route_wire_sequence = 0u64;
    let mut proxy_request_id: Option<[u8; 16]> = None;
    let mut selected_proxy_connection: Option<libp2p::swarm::ConnectionId> = None;
    let mut test_direct_failure_applied = false;
    let mut test_first_resolve_failure_applied = false;
    let mut proxy_setup_deadline: Option<std::time::Instant> = None;
    let mut proxy_capabilities: Option<p2x_protocol::Capabilities> = None;
    let mut proxy_attempt: Option<PathAttempt> = None;
    let mut proxy_server: Option<libp2p::PeerId> = None;
    let mut pending_proxy: Option<ProxyRequestId> = None;
    let mut close_proxy_due: Option<(p2x_net::ConnectionId, std::time::Instant)> = None;
    let mut close_proxy_applied = false;
    let mut maintenance = tokio::time::interval(std::time::Duration::from_millis(100));
    struct ProxyResult {
        open_id: Option<route_open::OpenId>,
        request_id: [u8; 16],
        result: Result<([u8; 16], [u8; 16], libp2p::swarm::Stream), PublicErrorCode>,
    }
    let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerResult>(128);
    let (proxy_result_tx, mut proxy_result_rx) = mpsc::channel::<ProxyResult>(16);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = maintenance.tick() => {
                if let Some(address) = test_relay_targets.pop_front() {
                    let peer = address.iter().filter_map(|part| match part { libp2p::multiaddr::Protocol::P2p(peer) => Some(peer), _ => None }).last().ok_or_else(|| io::Error::other("relay target peer is missing"))?;
                    if test_dialed_targets.insert(peer) {
                        let _ = swarm.dial(address);
                    } else {
                        swarm.dial(DialOpts::peer_id(peer).condition(PeerCondition::Always).addresses(vec![address]).build()).map_err(io::Error::other)?;
                    }
                }
                if exchange_redial.take_due(unix_millis())
                    && let Some(index) = exchange_addresses.next(args.exchange.len())
                    && let Err(error) = swarm.dial(args.exchange[index].clone())
                {
                    exchange_redial.schedule(unix_millis(), random_jitter_per_mille()?);
                    let message = error.to_string();
                    emitter.emit(&LifecycleRecord::OperationalError { code: "connection.outgoing", message: &message })?;
                }
                let now = std::time::Instant::now();
                if let Some((connection, due)) = close_proxy_due.take() {
                    if now >= due {
                        swarm.close_connection(connection);
                    } else {
                        close_proxy_due = Some((connection, due));
                    }
                }
                if supervised_proxy_mode || product_ingress {
                    let timed_out = route_resolve_wires
                        .iter()
                        .filter(|(_, (_, _, sent_at))| now.duration_since(*sent_at) >= std::time::Duration::from_secs(5))
                        .map(|(outbound, _)| *outbound)
                        .collect::<Vec<_>>();
                    for outbound in timed_out {
                        let Some((open_id, wire_id, _)) = route_resolve_wires.remove(&outbound) else { continue; };
                        let Some(request_id) = route_owner.as_ref().and_then(|owner| owner.resolve_request_id(open_id)) else { continue; };
                        let Some(action) = route_owner.as_mut().and_then(|owner| owner.resolve_timed_out(open_id, wire_id, now)) else { continue; };
                        if matches!(action, route_open::RouteAction::Complete { .. }) { resolver_state.cancel(request_id); }
                        let completed_actions = drive_route_actions(
                            &mut swarm,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &emitter,
                            &connections,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut route_wire_sequence,
                            vec![action],
                        )?;
                        if complete_route_actions(
                            product_ingress,
                            completed_actions,
                            &mut resolver_state,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut ingress_owners,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &connections,
                            &mut route_wire_sequence,
                            &mut connection_manager,
                            &mut swarm,
                            &emitter,
                            &args.case_id,
                        ).await? {
                            return Ok(());
                        }
                    }
                    let path_actions = route_owner.as_mut().expect("multi-open owner exists").tick_paths(now);
                    let completed_actions = drive_route_actions(
                        &mut swarm,
                        route_owner.as_mut().expect("multi-open owner exists"),
                        expected_exchange,
                        &emitter,
                        &connections,
                        &mut route_resolve_wires,
                        &mut route_proxy_requests,
                        &mut route_wire_sequence,
                        path_actions,
                    )?;
                    if complete_route_actions(
                        product_ingress,
                        completed_actions,
                        &mut resolver_state,
                        &mut route_resolve_wires,
                        &mut route_proxy_requests,
                        &mut ingress_owners,
                        route_owner.as_mut().expect("multi-open owner exists"),
                        expected_exchange,
                        &connections,
                        &mut route_wire_sequence,
                        &mut connection_manager,
                        &mut swarm,
                        &emitter,
                        &args.case_id,
                    ).await? {
                        return Ok(());
                    }
                }
                if deferred_resolve_retry_at.is_some_and(|due| due <= now)
                    && resolve_request.is_none()
                    && (exchange_restarted || recovery_resolve_retried)
                    && resolve_setup_deadline.is_some_and(|deadline| now < deadline)
                    && let (Some(route), Some(session_id), Some(binding)) = (
                        routes.as_ref().and_then(|config| config.routes.first()),
                        auth_state.current_session_id(unix_now()),
                        auth_state.current_session(unix_now()).map(|session| session.principal_binding()),
                    ) {
                        resolver_state.invalidate(&binding, &route.selector);
                        let request_id = request_ids.allocate().map_err(io::Error::other)?;
                        let request = resolver_state.begin(request_id, binding, session_id, route.selector.clone(), unix_now()).map_err(|code| io::Error::other(code.as_str()))?.ok_or_else(|| io::Error::other("resolve request was paced"))?;
                        let outbound = swarm.behaviour_mut().resolve.send_request(&expected_exchange, request.clone());
                        if !pending_resolve.begin(outbound) { return Err(io::Error::other("resolve outbound request limit exceeded")); }
                        resolve_request = Some(request);
                        resolve_retried = false;
                        resolve_sent_at = Some(now);
                        deferred_resolve_retry_at = None;
                        emitter.emit(&LifecycleRecord::OperationalError { code: "proxy.recovering", message: "retrying while replacement registration converges" })?;
                }
                if !resolve_retried
                    && resolve_sent_at.is_some_and(|sent| now.duration_since(sent) >= std::time::Duration::from_secs(5))
                    && resolve_setup_deadline.is_some_and(|deadline| now < deadline)
                    && let Some(request) = resolve_request.as_ref().cloned()
                {
                    pending_resolve.clear();
                    let retry = swarm
                        .behaviour_mut()
                        .resolve
                        .send_request(&expected_exchange, request);
                    if pending_resolve.begin(retry) {
                        resolve_retried = true;
                        resolve_sent_at = Some(now);
                    }
                }
                connections.sweep(now);
                if let Some(proxy) = swarm.behaviour_mut().proxy_stream.as_mut() {
                    proxy.expire(now);
                }
                if let (Some(peer_id), Some(attempt)) = (target_peer, attempt.as_mut()) {
                    let actions = attempt.apply(PathEvent { attempt_id: attempt.id, now, kind: PathEventKind::DirectDeadlineElapsed });
                    drive_path_actions(probe_mut(&mut swarm)?, attempt, peer_id, &emitter, actions, &mut launched)?;
                }
                if let Some((open, due, peer, address, capabilities)) = delayed_proxy_open.take() {
                    if now >= due {
                        proxy_open = Some(open);
                        proxy_server = Some(peer);
                        proxy_capabilities = Some(capabilities);
                        target_peer = Some(peer);
                        if let Some(manager) = connection_manager.as_mut() {
                            let deadline = resolve_setup_deadline
                                .ok_or_else(|| io::Error::other("proxy setup deadline missing"))?;
                            let (path, actions) = manager
                                .begin_path_at_deadline_with_capabilities(
                                    peer,
                                    now,
                                    deadline,
                                    capabilities,
                                )
                                .map_err(|code| io::Error::other(code.as_str()))?;
                            proxy_setup_deadline = Some(path.setup_deadline);
                            proxy_attempt = Some(path);
                            let should_dial = actions
                                .iter()
                                .any(|action| matches!(action, PathAction::DialRelay));
                            let mut terminal = None;
                            if let Some(open) = proxy_open.as_ref() {
                                let current = proxy_attempt
                                    .as_mut()
                                    .expect("proxy attempt was stored");
                                let proxy = swarm
                                    .behaviour_mut()
                                    .proxy_stream
                                    .as_mut()
                                    .ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?;
                                drive_proxy_path_actions(
                                    proxy,
                                    current,
                                    peer,
                                    open,
                                    deadline,
                                    &emitter,
                                    actions,
                                    &mut pending_proxy,
                                    &mut selected_proxy_connection,
                                    &mut terminal,
                                )?;
                            }
                            if terminal.is_some() {
                                let _ = manager.release(peer);
                                emitter.terminal(&TerminalResult::simple(
                                    &args.case_id,
                                    "failed",
                                    PublicErrorCode::PeerConnectionFailed.as_str(),
                                ))?;
                                return Ok(());
                            }
                            if should_dial {
                                swarm.dial(address).map_err(io::Error::other)?;
                            }
                        } else {
                            swarm.dial(address).map_err(io::Error::other)?;
                        }
                    } else {
                        delayed_proxy_open = Some((open, due, peer, address, capabilities));
                    }
                }
                if let (Some(peer_id), Some(current), Some(open), Some(deadline)) = (proxy_server, proxy_attempt.as_mut(), proxy_open.as_ref().cloned(), proxy_setup_deadline) {
                    let actions = current.apply(PathEvent {
                        attempt_id: current.id,
                        now,
                        kind: PathEventKind::DirectDeadlineElapsed,
                    });
                    if !actions.is_empty() {
                        let proxy = swarm
                            .behaviour_mut()
                            .proxy_stream
                            .as_mut()
                            .ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?;
                        let mut terminal = None;
                        drive_proxy_path_actions(
                            proxy,
                            current,
                            peer_id,
                            &open,
                            deadline,
                            &emitter,
                            actions,
                            &mut pending_proxy,
                            &mut selected_proxy_connection,
                            &mut terminal,
                        )?;
                        if terminal.is_some() {
                            if let Some(manager) = connection_manager.as_mut() {
                                let _ = manager.release(peer_id);
                            }
                            return Err(io::Error::other("proxy path setup failed"));
                        }
                        if pending_proxy.is_some() {
                            proxy_request_id = Some(open.request_id);
                        }
                    }
                    if current.expired(now) {
                        if let Some(manager) = connection_manager.as_mut() {
                            let _ = manager.release(peer_id);
                        }
                        return Err(io::Error::other("proxy setup timeout"));
                    }
                }
                if let Some((id, token)) = credential.as_ref() {
                    match auth_state.tick(request_ids.allocate().map_err(io::Error::other)?, unix_now()) {
                        AuthAction::Authenticate { request_id } => {
                            auth_request_id = request_id;
                            let outbound = swarm.behaviour_mut().auth.send_request(&expected_exchange, AuthRequest::Authenticate { request_id, credential_id: id.clone(), token_secret: p2x_protocol::TokenSecret::from_bytes(*token.as_bytes()), requested_role: Role::Client, supported_features: 0 });
                            if !pending_auth.begin(outbound) { return Err(io::Error::other("auth outbound request limit exceeded")); }
                        }
                        AuthAction::Retry => pending_auth.clear(),
                        _ => {}
                    }
                }
                let proxy_pending = swarm.behaviour().proxy_stream.as_ref().map_or(0, |proxy| proxy.pending_count());
                let route_pending = route_owner.as_ref().map_or(0, route_open::RouteOpenSupervisor::len);
                let active_streams = ingress_owners.active_len();
                if let Some(owner) = route_owner.as_ref() {
                    emitter.emit(&LifecycleRecord::RouteOwnerHighWater {
                        opens: owner.high_water(),
                    })?;
                }
                emitter.emit(&LifecycleRecord::Resources { connections: connections.len(), pending_opens: proxy_pending.max(route_pending), workers: route_owner.as_ref().map_or(0, route_open::RouteOpenSupervisor::handshake_count).saturating_add(active_streams), tasks: active_streams })?;
            }
            Some(event) = ingress_rx.recv(), if product_ingress => {
                match event {
                    IngressEvent::Accepted { id, route_id, started_at, deadline, command, cancel } => {
                        ingress_owners
                            .insert_setup(IngressSetupOwner {
                                ingress_id: id,
                                route_id: route_id.clone(),
                                accepted_at: started_at,
                                deadline,
                                command: command.clone(),
                                cancel: cancel.clone(),
                                open_id: None,
                            })
                            .map_err(io::Error::other)?;
                        emitter.emit(&LifecycleRecord::IngressAccepted {
                            route_id_hash: stable_hash(&route_id),
                            ingress_id: id.0,
                        })?;
                        let Some(route) = routes.as_ref().and_then(|config| config.routes.iter().find(|route| route.route_id == route_id)) else {
                            reject_ingress(&mut ingress_owners, id, PublicErrorCode::ProtocolMalformed, &emitter).await?;
                            continue;
                        };
                        let (Some(session_id), Some(binding)) = (
                            auth_state.current_session_id(unix_now()),
                            auth_state.current_session(unix_now()).map(|session| session.principal_binding()),
                        ) else {
                            reject_ingress(&mut ingress_owners, id, PublicErrorCode::AuthSessionRequired, &emitter).await?;
                            continue;
                        };
                        if args.test_fail_first_resolve && !test_first_resolve_failure_applied {
                            test_first_resolve_failure_applied = true;
                            emitter.emit(&LifecycleRecord::TestFaultApplied { fault: "fail_first_resolve" })?;
                            reject_ingress(&mut ingress_owners, id, PublicErrorCode::RegistryOffline, &emitter).await?;
                            continue;
                        }
                        let Some(owner) = route_owner.as_mut() else {
                            reject_ingress(&mut ingress_owners, id, PublicErrorCode::LimitProxyStreams, &emitter).await?;
                            continue;
                        };
                        match owner.admit(&mut resolver_state, binding, session_id, route.selector.clone(), unix_now(), deadline) {
                            Ok((open_id, actions)) => {
                                ingress_owners
                                    .attach_open(id, open_id)
                                    .map_err(io::Error::other)?;
                                let completed_actions = drive_route_actions(
                                    &mut swarm,
                                    owner,
                                    expected_exchange,
                                    &emitter,
                                    &connections,
                                    &mut route_resolve_wires,
                                    &mut route_proxy_requests,
                                    &mut route_wire_sequence,
                                    actions,
                                )?;
                                if complete_route_actions(
                                    product_ingress,
                                    completed_actions,
                                    &mut resolver_state,
                                    &mut route_resolve_wires,
                                    &mut route_proxy_requests,
                                    &mut ingress_owners,
                                    route_owner.as_mut().expect("multi-open owner exists"),
                                    expected_exchange,
                                    &connections,
                                    &mut route_wire_sequence,
                                    &mut connection_manager,
                                    &mut swarm,
                                    &emitter,
                                    &args.case_id,
                                ).await? {
                                    return Ok(());
                                }
                            }
                            Err(code) => {
                                reject_ingress(&mut ingress_owners, id, code, &emitter).await?;
                            }
                        }
                    }
                    IngressEvent::Rejected { id, route_id, code } => {
                        emitter.emit(&LifecycleRecord::IngressRejected {
                            route_id_hash: stable_hash(&route_id),
                            ingress_id: id.0,
                            code,
                        })?;
                    }
                    IngressEvent::PreAcceptClosed { id, cause } => {
                        let code = match cause {
                            ingress::PreAcceptCause::Eof | ingress::PreAcceptCause::LocalIo => {
                                PublicErrorCode::PeerConnectionFailed
                            }
                            ingress::PreAcceptCause::Deadline => PublicErrorCode::PeerSetupTimeout,
                            ingress::PreAcceptCause::Shutdown => PublicErrorCode::ExchangeDraining,
                        };
                        let route_id = ingress_owners
                            .setup(id)
                            .map(|owner| owner.route_id.clone())
                            .unwrap_or_default();
                        if let Some(open_id) = ingress_owners.setup_open_id(id) {
                            route_resolve_wires.retain(|_, (candidate, _, _)| *candidate != open_id);
                            route_proxy_requests.retain(|_, candidate| *candidate != open_id);
                            if let Some(route_owner) = route_owner.as_mut() {
                                let (completed, promoted) = route_owner
                                    .cancel_with_code_and_promotion(&mut resolver_state, open_id, code);
                                let mut actions = promoted;
                                if let Some(completed) = completed {
                                    actions.push(completed);
                                }
                                let completed_actions = drive_route_actions(
                                    &mut swarm,
                                    route_owner,
                                    expected_exchange,
                                    &emitter,
                                    &connections,
                                    &mut route_resolve_wires,
                                    &mut route_proxy_requests,
                                    &mut route_wire_sequence,
                                    actions,
                                )?;
                                if complete_route_actions(
                                    product_ingress,
                                    completed_actions,
                                    &mut resolver_state,
                                    &mut route_resolve_wires,
                                    &mut route_proxy_requests,
                                    &mut ingress_owners,
                                    route_owner,
                                    expected_exchange,
                                    &connections,
                                    &mut route_wire_sequence,
                                    &mut connection_manager,
                                    &mut swarm,
                                    &emitter,
                                    &args.case_id,
                                ).await? {
                                    return Ok(());
                                }
                            }
                        } else {
                            reject_ingress(&mut ingress_owners, id, code, &emitter).await?;
                        }
                        if !route_id.is_empty() && ingress_owners.setup(id).is_some() {
                            reject_ingress(&mut ingress_owners, id, code, &emitter).await?;
                        }
                    }
                    IngressEvent::TunnelFinished { id, result } => {
                        let Some(active) = ingress_owners.take_active(id) else {
                            continue;
                        };
                        match result {
                            Ok(result) => {
                                emit_client_tunnel_terminal(
                                    &emitter,
                                    &active,
                                    Some(&result),
                                    tunnel_terminal_class(result.terminal),
                                    None,
                                )?;
                            }
                            Err(error) => {
                                emit_client_tunnel_terminal(
                                    &emitter,
                                    &active,
                                    None,
                                    p2x_net::lifecycle::TunnelTerminalClass::Cancelled,
                                    Some("internal.pump_setup"),
                                )?;
                                let _ = error;
                            }
                        }
                        if let Some(manager) = connection_manager.as_mut() {
                            if !manager.close_active(active.server) {
                                return Err(io::Error::other("connection manager active release missing"));
                            }
                            if !manager.release_waiter(active.server, active.open_id.0) {
                                return Err(io::Error::other("connection manager waiter release missing"));
                            }
                        }
                        active.cancel.cancel();
                    }
                }
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
                            let request_id = probe_mut(&mut swarm)?.open_on(worker.peer_id, worker.connection_id).map_err(io::Error::other)?;
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
            Some(proxy_result) = proxy_result_rx.recv() => {
                if let Some(open_id) = proxy_result.open_id {
                    let Some((server, _, _, _, _, _)) = route_owner.as_ref().and_then(|owner| owner.path_input(open_id)) else { continue; };
                    let Some(connection) = route_owner.as_ref().and_then(|owner| owner.selected_connection(open_id)) else { continue; };
                    match proxy_result.result {
                        Ok((request_id, stream_id, stream)) => {
                            if product_ingress {
                                let proxy_id = route_owner.as_ref().and_then(|owner| owner.proxy_request_id(open_id)).ok_or_else(|| io::Error::other("route proxy request missing"))?;
                                let attempt_id = route_owner.as_ref().and_then(|owner| owner.path_attempt_id(open_id)).ok_or_else(|| io::Error::other("route path attempt missing"))?;
                                let _ = route_owner.as_mut().expect("route owner exists").path_event(open_id, PathEvent { attempt_id, now: std::time::Instant::now(), kind: PathEventKind::PayloadAccepted });
                                let handoff = route_owner.as_mut().expect("route owner exists").accepted(open_id, proxy_id, request_id, stream_id).ok_or_else(|| io::Error::other("route accepted handoff missing"))?;
                                let selected_path = if connections.is_direct(handoff.server, handoff.connection) {
                                    ProbePath::Direct
                                } else {
                                    ProbePath::Relay
                                };
                                if let Some(manager) = connection_manager.as_mut()
                                    && !manager.finish_path(handoff.server, Some(match selected_path {
                                        ProbePath::Direct => PathDecision::Direct(handoff.connection),
                                        ProbePath::Relay => PathDecision::Relay(handoff.connection),
                                    }))
                                {
                                    return Err(io::Error::other("connection manager active promotion missing"));
                                }
                                let active = ingress_owners
                                    .promote_active(&handoff, selected_path)
                                    .map_err(io::Error::other)?;
                                let peer = active.server.to_string();
                                emitter.emit(&LifecycleRecord::TunnelAccepted {
                                    component_side: p2x_net::lifecycle::ComponentSide::Client,
                                    peer_id: &peer,
                                    connection_id_hash: stable_hash(active.connection),
                                    request_id_hash: active.request_id_hash,
                                    stream_id_hash: active.stream_id_hash,
                                    selected_path: Some(active.selected_path),
                                    setup_duration_ms: active.setup_duration.as_millis(),
                                })?;
                                if let Some(delay) = args.test_close_proxy_after_accept_ms
                                    && !close_proxy_applied
                                {
                                    close_proxy_applied = true;
                                    close_proxy_due = Some((
                                        handoff.connection,
                                        std::time::Instant::now()
                                            + std::time::Duration::from_millis(delay),
                                    ));
                                }
                                let active_id = active.ingress_id;
                                if ingress_owners
                                    .start_tunnel(active_id, Box::new(stream))
                                    .await
                                    .is_err()
                                    && let Some(active) = ingress_owners.take_active(active_id)
                                {
                                    emit_client_tunnel_terminal(
                                        &emitter,
                                        &active,
                                        None,
                                        p2x_net::lifecycle::TunnelTerminalClass::Cancelled,
                                        Some(PublicErrorCode::PeerConnectionFailed.as_str()),
                                    )?;
                                    active.cancel.cancel();
                                    if let Some(manager) = connection_manager.as_mut()
                                        && !manager.close_active(active.server)
                                    {
                                        return Err(io::Error::other("connection manager active release missing"));
                                    }
                                    if let Some(manager) = connection_manager.as_mut()
                                        && !manager.release_waiter(active.server, active.open_id.0)
                                    {
                                        return Err(io::Error::other("connection manager waiter release missing"));
                                    }
                                }
                                continue;
                            }
                            emitter.emit(&LifecycleRecord::ProxyAuthorization {
                                peer_id: &server.to_string(),
                                connection_id_hash: stable_hash(connection),
                                request_id_hash: stable_hash(request_id),
                                stream_id_hash: Some(stable_hash(stream_id)),
                                authorized: true,
                                code: None,
                            })?;
                            let action = route_owner.as_mut().expect("multi-open owner exists").complete(open_id, Ok(())).ok_or_else(|| io::Error::other("route completion owner missing"))?;
                            let completed_actions = drive_route_actions(
                                &mut swarm,
                                route_owner.as_mut().expect("multi-open owner exists"),
                                expected_exchange,
                                &emitter,
                                &connections,
                                &mut route_resolve_wires,
                                &mut route_proxy_requests,
                                &mut route_wire_sequence,
                                vec![action],
                            )?;
                            for (_, completed_server, _, result) in completed_actions {
                                result.map_err(|code| io::Error::other(code.as_str()))?;
                                if let (Some(manager), Some(completed_server)) = (connection_manager.as_mut(), completed_server) {
                                    release_route_setup(manager, &mut swarm, completed_server, open_id);
                                }
                            }
                            proxy_completed = proxy_completed.saturating_add(1);
                            if proxy_completed >= proxy_target {
                                emitter.terminal(&TerminalResult::simple(&args.case_id, "passed", "proxy.authorized"))?;
                                return Ok(());
                            }
                            let route = routes.as_ref().and_then(|config| config.routes.first()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy check requires a route"))?;
                            let session_id = auth_state.current_session_id(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?;
                            let binding = auth_state.current_session(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?.principal_binding();
                            let setup_budget = std::time::Duration::from_millis(routes.as_ref().expect("routes are loaded").network.connection_setup_timeout_ms);
                            let mut actions = admit_route_window(
                                route_owner.as_mut().expect("multi-open owner exists"),
                                &mut resolver_state,
                                binding,
                                session_id,
                                &route.selector,
                                unix_now(),
                                setup_budget,
                                proxy_target,
                                proxy_concurrency,
                                &mut route_admitted,
                            ).map_err(|code| io::Error::other(code.as_str()))?;
                            actions.extend(route_owner.as_mut().expect("multi-open owner exists").promote_waiters(&mut resolver_state));
                            let completed_actions = drive_route_actions(
                                &mut swarm,
                                route_owner.as_mut().expect("multi-open owner exists"),
                                expected_exchange,
                                &emitter,
                                &connections,
                                &mut route_resolve_wires,
                                &mut route_proxy_requests,
                                &mut route_wire_sequence,
                                actions,
                            )?;
                            if !completed_actions.is_empty() { return Err(io::Error::other("route replacement completed unexpectedly")); }
                        }
                        Err(code) => {
                            if product_ingress {
                                let action = route_owner
                                    .as_mut()
                                    .and_then(|owner| owner.complete(open_id, Err(code)));
                                if let Some(action) = action {
                                    let completed_actions = drive_route_actions(
                                        &mut swarm,
                                        route_owner.as_mut().expect("route owner exists"),
                                        expected_exchange,
                                        &emitter,
                                        &connections,
                                        &mut route_resolve_wires,
                                        &mut route_proxy_requests,
                                        &mut route_wire_sequence,
                                        vec![action],
                                    )?;
                                    if complete_route_actions(
                                        product_ingress,
                                        completed_actions,
                                        &mut resolver_state,
                                        &mut route_resolve_wires,
                                        &mut route_proxy_requests,
                                        &mut ingress_owners,
                                        route_owner.as_mut().expect("route owner exists"),
                                        expected_exchange,
                                        &connections,
                                        &mut route_wire_sequence,
                                        &mut connection_manager,
                                        &mut swarm,
                                        &emitter,
                                        &args.case_id,
                                    )
                                    .await?
                                    {
                                        return Ok(());
                                    }
                                }
                                continue;
                            }
                            emitter.emit(&LifecycleRecord::ProxyAuthorization {
                                peer_id: &server.to_string(),
                                connection_id_hash: stable_hash(connection),
                                request_id_hash: stable_hash(proxy_result.request_id),
                                stream_id_hash: None,
                                authorized: false,
                                code: Some(code.as_str()),
                            })?;
                            let action = if route_proxy_rejection_needs_fresh_ticket(code) {
                                release_route_setup(
                                    connection_manager.as_mut().expect("route connection manager exists"),
                                    &mut swarm,
                                    server,
                                    open_id,
                                );
                                let proxy_wire_id = route_owner.as_ref().and_then(|owner| owner.proxy_request_id(open_id)).ok_or_else(|| io::Error::other("route proxy request missing"))?;
                                route_owner.as_mut().expect("multi-open owner exists").proxy_failed_at(
                                    &mut resolver_state,
                                    open_id,
                                    proxy_wire_id,
                                    route_open::RetryClass::Ambiguous,
                                    unix_now(),
                                    std::time::Instant::now(),
                                )
                            } else {
                                route_owner.as_mut().expect("multi-open owner exists").complete(open_id, Err(code))
                            };
                            let completed_actions = drive_route_actions(
                                &mut swarm,
                                route_owner.as_mut().expect("multi-open owner exists"),
                                expected_exchange,
                                &emitter,
                                &connections,
                                &mut route_resolve_wires,
                                &mut route_proxy_requests,
                                &mut route_wire_sequence,
                                action.into_iter().collect(),
                            )?;
                            if completed_actions.is_empty() && route_owner.as_ref().is_some_and(|owner| owner.len() > 0) {
                                continue;
                            }
                            if let Some((_, completed_server, _, _)) = completed_actions.into_iter().next()
                                && let Some(manager) = connection_manager.as_mut()
                            { let _ = completed_server.map(|peer| manager.release(peer)); }
                            emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                            return Ok(());
                        }
                    }
                    continue;
                }
                if proxy_request_id == Some(proxy_result.request_id) {
                    match proxy_result.result {
                        Ok((request_id, stream_id, mut _stream)) => {
                            if let (Some(manager), Some(server), Some(connection)) = (connection_manager.as_mut(), proxy_server, selected_proxy_connection) {
                                let selected = if connections.is_direct(server, connection) {
                                    PathDecision::Direct(connection)
                                } else {
                                    PathDecision::Relay(connection)
                                };
                                if !manager.finish_path(server, Some(selected)) {
                                    return Err(io::Error::other("connection manager active promotion missing"));
                                }
                                if !manager.close_active(server) {
                                    return Err(io::Error::other("connection manager active release missing"));
                                }
                            }
                            let peer = proxy_server.ok_or_else(|| io::Error::other("proxy authorization peer missing"))?;
                            proxy_completed = proxy_completed.saturating_add(1);
                            emitter.emit(&LifecycleRecord::ProxyAuthorization {
                                peer_id: &peer.to_string(),
                                connection_id_hash: selected_proxy_connection.map(stable_hash).unwrap_or_default(),
                                request_id_hash: stable_hash(request_id),
                                stream_id_hash: Some(stable_hash(stream_id)),
                                authorized: true,
                                code: None,
                            })?;
                            if args.test_replay_first_ticket && !replay_attempted {
                                replay_attempted = true;
                                let replay = last_proxy_open.clone().ok_or_else(|| io::Error::other("replay grant missing"))?;
                                let server = proxy_server.ok_or_else(|| io::Error::other("replay peer missing"))?;
                                let connection = selected_proxy_connection.ok_or_else(|| io::Error::other("replay connection missing"))?;
                                let deadline = proxy_setup_deadline.unwrap_or_else(|| std::time::Instant::now() + std::time::Duration::from_secs(5));
                                let request = swarm.behaviour_mut().proxy_stream.as_mut().ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?.open_on_at_deadline(server, connection, replay.clone(), std::time::Instant::now(), deadline).map_err(io::Error::other)?;
                                pending_proxy = Some(request);
                                proxy_request_id = Some(replay.request_id);
                                proxy_open = Some(replay);
                                continue;
                            }
                            if proxy_completed >= proxy_target {
                                emitter.terminal(&TerminalResult::simple(&args.case_id, "passed", "proxy.authorized"))?;
                                return Ok(())
                            }
                            proxy_open = None;
                            proxy_attempt = None;
                            proxy_server = None;
                            pending_proxy = None;
                            selected_proxy_connection = None;
                            proxy_request_id = None;
                            let route = routes.as_ref().and_then(|config| config.routes.first()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy check requires a route"))?;
                            let session_id = auth_state.current_session_id(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?;
                            let binding = auth_state.current_session(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?.principal_binding();
                            let request_id = request_ids.allocate().map_err(io::Error::other)?;
                            recovery_resolve_retried = false;
                            let request = resolver_state.begin(request_id, binding, session_id, route.selector.clone(), unix_now()).map_err(|code| io::Error::other(code.as_str()))?.ok_or_else(|| io::Error::other("resolve request was paced"))?;
                            let outbound = swarm.behaviour_mut().resolve.send_request(&expected_exchange, request.clone());
                            if !pending_resolve.begin(outbound) { return Err(io::Error::other("resolve outbound request limit exceeded")); }
                            resolve_request = Some(request);
                            resolve_setup_deadline = connection_manager.as_ref().map(|manager| manager.setup_deadline(std::time::Instant::now()));
                            resolve_retried = false;
                            resolve_sent_at = Some(std::time::Instant::now());
                            continue
                        }
                        Err(code) => {
                            if replay_attempted && code == PublicErrorCode::AuthTicketReplayed {
                                emitter.emit(&LifecycleRecord::ProxyAuthorization {
                                    peer_id: &proxy_server.ok_or_else(|| io::Error::other("replay peer missing"))?.to_string(),
                                    connection_id_hash: selected_proxy_connection.map(stable_hash).unwrap_or_default(),
                                    request_id_hash: stable_hash(proxy_result.request_id),
                                    stream_id_hash: None,
                                    authorized: false,
                                    code: Some(code.as_str()),
                                })?;
                                emitter.terminal(&TerminalResult::simple(&args.case_id, "passed", code.as_str()))?;
                                return Ok(())
                            }
                            if args.recover_after_failure
                                && !recovery_attempted
                                && matches!(
                                    code,
                                    PublicErrorCode::RegistryStaleRevision
                                        | PublicErrorCode::AuthSessionRequired
                                        | PublicErrorCode::PeerConnectionFailed
                                        | PublicErrorCode::PeerSetupTimeout
                                        | PublicErrorCode::ExchangeTimeout
                                )
                            {
                                recovery_attempted = true;
                                if let (Some(manager), Some(server)) = (connection_manager.as_mut(), proxy_server) {
                                    let _ = manager.release(server);
                                }
                                proxy_open = None;
                                proxy_attempt = None;
                                proxy_server = None;
                                pending_proxy = None;
                                selected_proxy_connection = None;
                                proxy_request_id = None;
                                let route = routes.as_ref().and_then(|config| config.routes.first()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy check requires a route"))?;
                                let session_id = auth_state.current_session_id(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?;
                                let binding = auth_state.current_session(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?.principal_binding();
                                let deadline = resolve_setup_deadline.ok_or_else(|| io::Error::other("proxy setup deadline missing"))?;
                                if std::time::Instant::now() >= deadline {
                                    emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", PublicErrorCode::PeerSetupTimeout.as_str()))?;
                                    return Ok(());
                                }
                                resolver_state.invalidate(&binding, &route.selector);
                                let request_id = request_ids.allocate().map_err(io::Error::other)?;
                                let request = resolver_state.begin(request_id, binding, session_id, route.selector.clone(), unix_now()).map_err(|error| io::Error::other(error.as_str()))?.ok_or_else(|| io::Error::other("resolve request was paced"))?;
                                let outbound = swarm.behaviour_mut().resolve.send_request(&expected_exchange, request.clone());
                                if !pending_resolve.begin(outbound) { return Err(io::Error::other("resolve outbound request limit exceeded")); }
                                resolve_request = Some(request);
                                resolve_retried = false;
                                recovery_resolve_retried = true;
                                resolve_sent_at = Some(std::time::Instant::now());
                                emitter.emit(&LifecycleRecord::OperationalError { code: "proxy.recovering", message: "fresh ticket resolution" })?;
                                continue;
                            }
                            if let (Some(manager), Some(server)) = (connection_manager.as_mut(), proxy_server) {
                                let _ = manager.release(server);
                            }
                            emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                            return Ok(())
                        }
                    }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        let observed_path = if endpoint.is_relayed() { ProbePath::Relay } else { ProbePath::Direct };
                        let peer = peer_id.to_string();
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Established, path: Some(observed_path), reason: None })?;
                        if expected_exchange == peer_id {
                            exchange_connections.established(connection_id);
                            exchange_redial.reset();
                            if credential.is_none() {
                                credential = credential_ref.as_ref().map(|reference| reference.read().map_err(io::Error::other)).transpose()?;
                            }
                            if let Some((id, token)) = credential.as_ref()
                                && let AuthAction::Authenticate { request_id } = auth_state.connected(auth_request_id, unix_now())
                            {
                            auth_request_id = request_id;
                                let outbound = swarm.behaviour_mut().auth.send_request(&peer_id, AuthRequest::Authenticate { request_id, credential_id: id.clone(), token_secret: p2x_protocol::TokenSecret::from_bytes(*token.as_bytes()), requested_role: Role::Client, supported_features: 0 });
                                if !pending_auth.begin(outbound) { return Err(io::Error::other("auth outbound request limit exceeded")); }
                            }
                        }
                        if let Some(manager) = connection_manager.as_mut()
                            && (target_peer == Some(peer_id) || manager.has_peer(peer_id))
                            && let Err(error) = manager.on_connection_established(
                                peer_id,
                                connection_id,
                                &endpoint,
                                std::time::Instant::now(),
                            )
                        {
                            swarm.close_connection(connection_id);
                            let message = error.to_string();
                            emitter.emit(&LifecycleRecord::OperationalError {
                                code: "connection.rejected",
                                message: &message,
                            })?;
                            continue;
                        }
                        let route_peer = route_owner
                            .as_ref()
                            .is_some_and(|owner| !owner.open_ids_for_server(peer_id).is_empty());
                        if target_peer == Some(peer_id) || route_peer {
                            if let Err(error) = connections.on_connection_established(peer_id, connection_id, &endpoint, std::time::Instant::now()) {
                                swarm.close_connection(connection_id);
                                let message = error.to_string();
                                emitter.emit(&LifecycleRecord::OperationalError { code: "connection.rejected", message: &message })?;
                                continue;
                            }
                            if route_peer {
                                if observed_path == ProbePath::Relay
                                    && let Some(manager) = connection_manager.as_mut()
                                {
                                    manager.relay_connection_ready(peer_id);
                                    let _ = manager.begin_dcutr(peer_id);
                                }
                                let open_ids = route_owner
                                    .as_ref()
                                    .expect("multi-open owner exists")
                                    .open_ids_for_server(peer_id);
                                let mut actions = Vec::new();
                                for open_id in open_ids {
                                    let attempt_id = route_owner
                                        .as_ref()
                                        .and_then(|owner| owner.path_attempt_id(open_id))
                                        .ok_or_else(|| io::Error::other("route path attempt missing"))?;
                                    let kind = if observed_path == ProbePath::Relay {
                                        PathEventKind::RelayReady(connection_id)
                                    } else {
                                        continue;
                                    };
                                    actions.extend(
                                        route_owner
                                            .as_mut()
                                            .expect("multi-open owner exists")
                                            .path_event(
                                                open_id,
                                                PathEvent {
                                                    attempt_id,
                                                    now: std::time::Instant::now(),
                                                    kind,
                                                },
                                            )
                                            .unwrap_or_default(),
                                    );
                                }
                                let completed_actions = drive_route_actions(
                                    &mut swarm,
                                    route_owner.as_mut().expect("multi-open owner exists"),
                                    expected_exchange,
                                    &emitter,
                                    &connections,
                                    &mut route_resolve_wires,
                                    &mut route_proxy_requests,
                                    &mut route_wire_sequence,
                                    actions,
                                )?;
                                if complete_route_actions(
                                    product_ingress,
                                    completed_actions,
                                    &mut resolver_state,
                                    &mut route_resolve_wires,
                                    &mut route_proxy_requests,
                                    &mut ingress_owners,
                                    route_owner.as_mut().expect("multi-open owner exists"),
                                    expected_exchange,
                                    &connections,
                                    &mut route_wire_sequence,
                                    &mut connection_manager,
                                    &mut swarm,
                                    &emitter,
                                    &args.case_id,
                                ).await? {
                                    return Ok(());
                                }
                            }
                            if supervised_proxy_mode || product_ingress {
                                // RouteOpenSupervisor already dispatched every matching path event.
                            } else if (args.finite_proxy_check || args.test_proxy_open_count.is_some())
                                && !supervised_proxy_mode
                                && proxy_server == Some(peer_id)
                                && let (Some(open), Some(deadline), Some(current)) = (proxy_open.as_ref().cloned(), proxy_setup_deadline, proxy_attempt.as_mut())
                            {
                                let kind = if observed_path == ProbePath::Relay {
                                    Some(PathEventKind::RelayReady(connection_id))
                                } else if connection_manager
                                    .as_ref()
                                    .is_some_and(|manager| manager.direct(peer_id) == Some(connection_id))
                                {
                                    Some(PathEventKind::DirectReady(connection_id))
                                } else {
                                    None
                                };
                                let actions = kind.map_or_else(Vec::new, |kind| current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind }));
                                let proxy = swarm.behaviour_mut().proxy_stream.as_mut().ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?;
                                let mut terminal = None;
                                if args.test_fail_first_direct_open_before_handshake
                                    && !test_direct_failure_applied
                                    && observed_path == ProbePath::Direct
                                    && actions.iter().any(|action| matches!(action, PathAction::OpenExact { .. }))
                                {
                                    test_direct_failure_applied = true;
                                    proxy.fail_next_open_before_handshake();
                                    emitter.emit(&LifecycleRecord::TestFaultApplied { fault: "fail_first_direct_open_before_handshake" })?;
                                }
                                drive_proxy_path_actions(proxy, current, peer_id, &open, deadline, &emitter, actions, &mut pending_proxy, &mut selected_proxy_connection, &mut terminal)?;
                                if terminal.is_some() {
                                    return Err(io::Error::other("proxy path setup failed"));
                                }
                                if pending_proxy.is_some() { proxy_request_id = Some(open.request_id); }
                            } else if args.finite_relay_ping {
                                if observed_path == ProbePath::Relay {
                                    started = true;
                                }
                            } else if forced_path_matches(args.path, observed_path)
                                && (!started || matches!(args.path, Path::Both))
                                && launched < args.count
                                && forced_opened_connections.insert(connection_id)
                            {
                                let request_id = probe_mut(&mut swarm)?.open_on(peer_id, connection_id).map_err(io::Error::other)?;
                                launched += 1;
                                emitter.emit(&LifecycleRecord::PathSelected { request_id: request_id.0, connection_id_hash: stable_hash(connection_id), selected_path: observed_path })?;
                                started = true;
                            } else if !started && matches!(args.path, Path::Auto) && observed_path == ProbePath::Relay {
                                let current = attempt.get_or_insert_with(|| PathAttempt::with_id(AttemptId(1), std::time::Instant::now()));
                                let direct = connections.direct(peer_id).map(|record| record.connection_id);
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::Begin { relay: Some(connection_id), direct } });
                                drive_path_actions(probe_mut(&mut swarm)?, current, peer_id, &emitter, actions, &mut launched)?;
                                started = true;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Authenticated { session_id, request_id, tenant, role, scopes, quota_profile, authorization_revision, expires_at, .. } }, .. })) if pending_auth.complete(&outbound_id) => {
                        if let AuthAction::Ping { request_id: ping_id, session_id, nonce } = auth_state.authenticated_with_context(request_id, session_id, expires_at, tenant, role, scopes, quota_profile, authorization_revision, { ping_request_id = request_ids.allocate().map_err(io::Error::other)?; ping_request_id }, 1, unix_now()) {
                            ping_request_id = ping_id;
                            let outbound = swarm.behaviour_mut().auth.send_request(&peer, AuthRequest::Ping { request_id: ping_id, session_id, nonce });
                            if !pending_auth.begin(outbound) { return Err(io::Error::other("auth outbound request limit exceeded")); }
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::Message { message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Pong { request_id, nonce, .. } }, .. })) if credential.is_some() && pending_auth.complete(&outbound_id) && request_id == ping_request_id && auth_state.pong(request_id, nonce) == AuthAction::Ready => {
                        readiness_generation = readiness_generation.saturating_add(1);
                        if args.finite_auth_check {
                            emitter.terminal(&TerminalResult::simple(&args.case_id, "passed", "auth.pong"))?;
                            return Ok(());
                        }
                        emitter.emit(&LifecycleRecord::AuthReadiness { ready: true, generation: readiness_generation })?;
                        if let Some(binding) = auth_state.current_session(unix_now()).map(|session| session.principal_binding()) {
                            resolver_state.set_principal_binding(binding);
                        }
                        if supervised_proxy_mode {
                            let route = routes.as_ref().and_then(|config| config.routes.first()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy check requires a route"))?;
                            let session_id = auth_state.current_session_id(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?;
                            let binding = auth_state.current_session(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?.principal_binding();
                            let setup_budget = std::time::Duration::from_millis(routes.as_ref().expect("routes are loaded").network.connection_setup_timeout_ms);
                            let actions = admit_route_window(
                                route_owner.as_mut().expect("multi-open owner exists"),
                                &mut resolver_state,
                                binding,
                                session_id,
                                &route.selector,
                                unix_now(),
                                setup_budget,
                                proxy_target,
                                proxy_concurrency,
                                &mut route_admitted,
                            ).map_err(|code| io::Error::other(code.as_str()))?;
                            let completed_actions = drive_route_actions(
                                &mut swarm,
                                route_owner.as_mut().expect("multi-open owner exists"),
                                expected_exchange,
                                &emitter,
                                &connections,
                                &mut route_resolve_wires,
                                &mut route_proxy_requests,
                                &mut route_wire_sequence,
                                actions,
                            )?;
                            if !completed_actions.is_empty() {
                                return Err(io::Error::other("route admission completed unexpectedly"));
                            }
                        } else if args.finite_proxy_check || args.test_proxy_open_count.is_some() {
                            let route = routes.as_ref().and_then(|config| config.routes.first()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy check requires a route"))?;
                            let session_id = auth_state.current_session_id(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?;
                            let request_id = request_ids.allocate().map_err(io::Error::other)?;
                            let binding = auth_state.current_session(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?.principal_binding();
                            let request = resolver_state.begin(request_id, binding, session_id, route.selector.clone(), unix_now()).map_err(|code| io::Error::other(code.as_str()))?.ok_or_else(|| io::Error::other("resolve request was paced"))?;
                            let outbound = swarm.behaviour_mut().resolve.send_request(&expected_exchange, request.clone());
                            if !pending_resolve.begin(outbound) { return Err(io::Error::other("resolve outbound request limit exceeded")); }
                            resolve_setup_deadline = connection_manager.as_ref().map(|manager| manager.setup_deadline(std::time::Instant::now()));
                            resolve_retried = false;
                            resolve_sent_at = Some(std::time::Instant::now());
                            resolve_request = Some(request);
                        }
                        if args.finite_relay_ping && let Some(address) = server_address.clone() {
                            let explicit_targets = !args.test_relay_target.is_empty();
                            let targets = if explicit_targets { args.test_relay_target.clone() } else { vec![address; args.test_relay_circuit_count as usize] };
                            if explicit_targets {
                                test_relay_targets.extend(targets);
                                continue;
                            }
                            for address in targets {
                                let peer = address.iter().filter_map(|part| match part { libp2p::multiaddr::Protocol::P2p(peer) => Some(peer), _ => None }).last().ok_or_else(|| io::Error::other("relay target peer is missing"))?;
                                swarm.dial(DialOpts::peer_id(peer).condition(PeerCondition::Always).addresses(vec![address]).build()).map_err(io::Error::other)?;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::Message { message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Rejected { request_id, error } }, .. })) if credential.is_some() && pending_auth.complete(&outbound_id) && auth_state.rejected(request_id, error.code, unix_now()) != AuthAction::Ignore => {
                        if args.finite_auth_check || matches!(auth_state.phase(), p2x_net::auth_state::AuthPhase::Terminal(_)) {
                            emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", error.code.as_str()))?;
                            return Ok(());
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::OutboundFailure { request_id, error: libp2p::request_response::OutboundFailure::Timeout, .. })) if credential.is_some() && pending_auth.complete(&request_id) => {
                        let _ = auth_state.timeout(unix_now());
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::OutboundFailure { request_id, error: libp2p::request_response::OutboundFailure::UnsupportedProtocols, .. })) if credential.is_some() && pending_auth.complete(&request_id) => {
                        let code = PublicErrorCode::ProtocolCapabilityMismatch;
                        emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                        return Ok(());
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::OutboundFailure { request_id, error: libp2p::request_response::OutboundFailure::Io(error), .. })) if credential.is_some() && pending_auth.complete(&request_id) => {
                        let code = protocol_failure_code(&error, args.auth_fault);
                        emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                        return Ok(());
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Auth(RequestResponseEvent::OutboundFailure { request_id, error: libp2p::request_response::OutboundFailure::ConnectionClosed, .. })) if credential.is_some() => { pending_auth.complete(&request_id); }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Resolve(RequestResponseEvent::OutboundFailure { request_id: outbound_id, error: libp2p::request_response::OutboundFailure::Timeout, .. })) if route_resolve_wires.contains_key(&outbound_id) => {
                        let (open_id, wire_id, _) = route_resolve_wires.remove(&outbound_id).expect("checked route wire exists");
                        let Some(request_id) = route_owner.as_ref().and_then(|owner| owner.resolve_request_id(open_id)) else { continue; };
                        let owner = route_owner.as_mut().expect("multi-open owner exists");
                        let Some(action) = owner.resolve_timed_out(open_id, wire_id, std::time::Instant::now()) else { continue; };
                        if matches!(action, route_open::RouteAction::Complete { .. }) {
                            resolver_state.cancel(request_id);
                        }
                        let completed_actions = drive_route_actions(
                            &mut swarm,
                            owner,
                            expected_exchange,
                            &emitter,
                            &connections,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut route_wire_sequence,
                            vec![action],
                        )?;
                        if complete_route_actions(
                            product_ingress,
                            completed_actions,
                            &mut resolver_state,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut ingress_owners,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &connections,
                            &mut route_wire_sequence,
                            &mut connection_manager,
                            &mut swarm,
                            &emitter,
                            &args.case_id,
                        ).await? {
                            return Ok(());
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Resolve(RequestResponseEvent::Message { peer: _, message: RequestResponseMessage::Response { request_id: outbound_id, response }, .. })) if route_resolve_wires.contains_key(&outbound_id) => {
                        let (open_id, wire_id, _) = route_resolve_wires.remove(&outbound_id).expect("checked route wire exists");
                        let Some(request_id) = route_owner.as_ref().and_then(|owner| owner.resolve_request_id(open_id)) else { continue; };
                        let response_fingerprint = response.canonical_bytes().map(stable_hash).unwrap_or_default();
                        let resolve_result = route_owner.as_mut().expect("multi-open owner exists").resolve_completed_at(
                            &mut resolver_state,
                            open_id,
                            wire_id,
                            response,
                            unix_now(),
                            std::time::Instant::now(),
                        );
                        let mut actions = Vec::new();
                        match resolve_result {
                            Ok(_) => {
                                emitter.emit(&LifecycleRecord::ResolutionOutcome {
                                    peer_id: &expected_exchange.to_string(),
                                    request_id_hash: stable_hash(request_id),
                                    request_fingerprint: stable_hash(request_id),
                                    response_fingerprint,
                                    issuance_count: route_admitted,
                                    resolved: true,
                                    ticket_issued: true,
                                    code: None,
                                })?;
                                let (server, capabilities, relay_address, revision, registration_expires_at, deadline) = route_owner.as_ref().expect("multi-open owner exists").path_input(open_id).ok_or_else(|| io::Error::other("resolved route path input missing"))?;
                                let mut path_failure = None;
                                let mut path = None;
                                if let Some(manager) = connection_manager.as_mut() {
                                    let started = std::time::Instant::now();
                                    match manager.begin_path_at_deadline_with_capabilities(server, started, deadline, capabilities) {
                                        Ok((attempt, path_actions)) if manager.track_waiter(server, open_id.0) => {
                                            match manager.update_metadata(server, ResolvedPeerMetadata {
                                                relay_addresses: vec![relay_address],
                                                capabilities,
                                                registration_revision: revision,
                                                registration_expires_at,
                                            }) {
                                                Ok(()) => path = Some((attempt, path_actions)),
                                                Err(code) => {
                                                    let _ = manager.release_waiter(server, open_id.0);
                                                    let _ = manager.release(server);
                                                    path_failure = Some(code);
                                                }
                                            }
                                        }
                                        Ok(_) => path_failure = Some(PublicErrorCode::LimitPeerConnections),
                                        Err(code) => path_failure = Some(code),
                                    }
                                } else {
                                    path_failure = Some(PublicErrorCode::PeerConnectionFailed);
                                }
                                if let Some((attempt, path_actions)) = path {
                                    if let Some(path_actions) = route_owner.as_mut().expect("multi-open owner exists").begin_path(open_id, attempt, path_actions) {
                                        actions.extend(path_actions);
                                    } else {
                                        if let Some(manager) = connection_manager.as_mut() {
                                            let _ = manager.release_waiter(server, open_id.0);
                                            let _ = manager.release(server);
                                        }
                                        return Err(io::Error::other(format!("route path admission missing for open {open_id:?}")));
                                    }
                                }
                                if let Some(code) = path_failure
                                    && let Some(action) = route_owner.as_mut().expect("multi-open owner exists").complete(open_id, Err(code))
                                {
                                    actions.push(action);
                                }
                            }
                            Err(code) => {
                                emitter.emit(&LifecycleRecord::ResolutionOutcome {
                                    peer_id: &expected_exchange.to_string(),
                                    request_id_hash: stable_hash(request_id),
                                    request_fingerprint: stable_hash(request_id),
                                    response_fingerprint,
                                    issuance_count: route_admitted,
                                    resolved: false,
                                    ticket_issued: false,
                                    code: Some(code.as_str()),
                                })?;
                                if let Some(action) = route_owner.as_mut().expect("multi-open owner exists").complete(open_id, Err(code)) { actions.push(action); }
                            }
                        }
                        actions.extend(route_owner.as_mut().expect("multi-open owner exists").promote_waiters(&mut resolver_state));
                        let completed_actions = drive_route_actions(
                            &mut swarm,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &emitter,
                            &connections,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut route_wire_sequence,
                            actions,
                        )?;
                        if complete_route_actions(
                            product_ingress,
                            completed_actions,
                            &mut resolver_state,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut ingress_owners,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &connections,
                            &mut route_wire_sequence,
                            &mut connection_manager,
                            &mut swarm,
                            &emitter,
                            &args.case_id,
                        ).await? {
                            return Ok(());
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Resolve(RequestResponseEvent::OutboundFailure { request_id: outbound_id, error: libp2p::request_response::OutboundFailure::Timeout, .. })) if pending_resolve.complete(&outbound_id) => {
                        let now = std::time::Instant::now();
                        resolve_sent_at = None;
                        if !resolve_retried
                            && resolve_setup_deadline.is_some_and(|deadline| now < deadline)
                            && let Some(request) = resolve_request.as_ref().cloned()
                        {
                            let retry = swarm.behaviour_mut().resolve.send_request(&expected_exchange, request);
                            if pending_resolve.begin(retry) {
                                resolve_retried = true;
                                continue;
                            }
                        }
                        if let Some(request) = resolve_request.take() {
                            let request_id = match request {
                                ResolveRequestV1::Resolve { request_id, .. } => request_id,
                            };
                            resolver_state.cancel(request_id);
                        }
                        let code = if resolve_setup_deadline.is_some_and(|deadline| now >= deadline) {
                            PublicErrorCode::PeerSetupTimeout
                        } else {
                            PublicErrorCode::ExchangeTimeout
                        };
                        emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                        return Ok(());
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Resolve(RequestResponseEvent::Message { peer: _, message: RequestResponseMessage::Response { request_id: outbound_id, response }, .. })) if pending_resolve.complete(&outbound_id) => {
                        let request = resolve_request.take().ok_or_else(|| io::Error::other("resolve response without request"))?;
                        let (request_id, session_id, selector) = match request { ResolveRequestV1::Resolve { request_id, session_id, selector, .. } => (request_id, session_id, selector) };
                        let binding = auth_state.current_session(unix_now()).ok_or_else(|| io::Error::other("authenticated session expired"))?.principal_binding();
                        let resolution_request_id_hash = stable_hash(request_id);
                        resolve_sent_at = None;
                        let response_fingerprint = response
                            .canonical_bytes()
                            .map(stable_hash)
                            .unwrap_or_default();
                        match resolver_state.complete(response, &binding, session_id, &selector, unix_now()) {
                            Ok(grant) if args.finite_proxy_check || args.test_proxy_open_count.is_some() => {
                                emitter.emit(&LifecycleRecord::ResolutionOutcome {
                                    peer_id: &expected_exchange.to_string(),
                                    request_id_hash: resolution_request_id_hash,
                                    request_fingerprint: resolution_request_id_hash,
                                    response_fingerprint,
                                    issuance_count: 1,
                                    resolved: true,
                                    ticket_issued: true,
                                    code: None,
                                })?;
                                let peer = grant.metadata.server_peer_id;
                                if !grant.metadata.compatible_capabilities.contains(p2x_protocol::Capabilities::RELAY_V2) { return Err(io::Error::other("resolve omitted relay capability")); }
                                let address = grant.metadata.relay_addresses.first().ok_or_else(|| io::Error::other("resolve returned no relay address"))?;
                                let address = Multiaddr::try_from(address.clone()).map_err(io::Error::other)?;
                                target_peer = Some(peer);
                                proxy_server = Some(peer);
                                proxy_capabilities = Some(grant.metadata.compatible_capabilities);
                                proxy_request_id = Some(request_id);
                                let mut open = OpenProxyStreamV1 { request_id, ticket: grant.ticket, upstream_id: grant.metadata.upstream_id, registration_revision: grant.metadata.registration_revision, ingress_kind: p2x_protocol::IngressKind::FixedTcp };
                                match args.test_open_mutation {
                                    OpenMutation::None => {}
                                    OpenMutation::TicketByte => {
                                        let mut bytes = open.ticket.as_bytes().to_vec();
                                        if let Some(byte) = bytes.last_mut() { *byte ^= 1; }
                                        open.ticket = p2x_protocol::RawTicket::new(bytes).map_err(io::Error::other)?;
                                    }
                                    OpenMutation::UpstreamId => { open.upstream_id = p2x_protocol::UpstreamId::new("mutated").map_err(io::Error::other)?; }
                                    OpenMutation::Revision => { open.registration_revision = p2x_protocol::RegistrationRevision::new(open.registration_revision.get().saturating_add(1)).ok_or_else(|| io::Error::other("mutation revision exhausted"))?; }
                                }
                                if let Some(delay) = args.test_delay_after_resolve_ms {
                                    delayed_proxy_open = Some((
                                        open.clone(),
                                        std::time::Instant::now()
                                            + std::time::Duration::from_millis(delay),
                                        peer,
                                        address.clone(),
                                        grant.metadata.compatible_capabilities,
                                    ));
                                }
                                if args.test_replay_first_ticket {
                                    last_proxy_open = Some(open.clone());
                                }
                                if !args.test_replay_first_ticket {
                                    last_proxy_open = Some(open.clone());
                                }
                                if args.test_delay_after_resolve_ms.is_none() {
                                    proxy_open = Some(open);
                                }
                                if args.test_delay_after_resolve_ms.is_none()
                                    && let Some(manager) = connection_manager.as_mut()
                                {
                                    let started = std::time::Instant::now();
                                    let setup_deadline = resolve_setup_deadline.unwrap_or_else(|| manager.setup_deadline(started));
                                    let (path, actions) = manager
                                        .begin_path_at_deadline_with_capabilities(
                                            peer,
                                            started,
                                            setup_deadline,
                                            grant.metadata.compatible_capabilities,
                                        )
                                        .map_err(|code| io::Error::other(code.as_str()))?;
                                    proxy_setup_deadline = Some(path.setup_deadline);
                                    proxy_attempt = Some(path);
                                    let mut terminal = None;
                                    let proxy = swarm.behaviour_mut().proxy_stream.as_mut().ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?;
                                    let current = proxy_attempt.as_mut().expect("proxy attempt was stored");
                                    if args.test_fail_first_direct_open_before_handshake
                                        && !test_direct_failure_applied
                                    {
                                        test_direct_failure_applied = true;
                                        proxy.fail_next_open_before_handshake();
                                        emitter.emit(&LifecycleRecord::TestFaultApplied { fault: "fail_first_direct_open_before_handshake" })?;
                                    }
                                    let should_dial = actions.iter().any(|action| matches!(action, PathAction::DialRelay));
                                    if let Some(open) = proxy_open.as_ref() {
                                        drive_proxy_path_actions(proxy, current, peer, open, proxy_setup_deadline.expect("proxy deadline was stored"), &emitter, actions, &mut pending_proxy, &mut selected_proxy_connection, &mut terminal)?;
                                    }
                                    if terminal.is_some() {
                                        return Err(io::Error::other("proxy path setup failed"));
                                    }
                                    if should_dial && let Err(error) = swarm.dial(address) {
                                            let _ = manager.release(peer);
                                            let message = error.to_string();
                                            emitter.emit(&LifecycleRecord::OperationalError {
                                                code: "peer.connection_failed",
                                                message: &message,
                                            })?;
                                            emitter.terminal(&TerminalResult::simple(
                                                &args.case_id,
                                                "failed",
                                                PublicErrorCode::PeerConnectionFailed.as_str(),
                                            ))?;
                                        return Ok(());
                                    }
                                } else if args.test_delay_after_resolve_ms.is_none() {
                                    swarm.dial(address.clone()).map_err(io::Error::other)?;
                                }
                            }
                            Ok(_) => {}
                            Err(code) => {
                                if args.recover_after_failure
                                    && (recovery_resolve_retried || exchange_restarted)
                                    && matches!(code, PublicErrorCode::RegistryNotFound | PublicErrorCode::RegistryOffline)
                                    && resolve_setup_deadline.is_some_and(|deadline| std::time::Instant::now() < deadline)
                                    && recovery_retry_deadline.is_none_or(|deadline| std::time::Instant::now() < deadline)
                                {
                                    recovery_resolve_retried = false;
                                    exchange_restarted = false;
                                    recovery_retry_deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(15));
                                    resolver_state.invalidate(&binding, &selector);
                                    deferred_resolve_retry_at = Some(std::time::Instant::now() + std::time::Duration::from_millis(250));
                                    emitter.emit(&LifecycleRecord::OperationalError { code: "proxy.recovering", message: "retrying while replacement registration converges" })?;
                                    continue;
                                }
                                emitter.emit(&LifecycleRecord::ResolutionOutcome {
                                    peer_id: &expected_exchange.to_string(),
                                    request_id_hash: resolution_request_id_hash,
                                    request_fingerprint: resolution_request_id_hash,
                                    response_fingerprint,
                                    issuance_count: 0,
                                    resolved: false,
                                    ticket_issued: false,
                                    code: Some(code.as_str()),
                                })?;
                                emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                                return Ok(());
                            }
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Proxy(ProxyOutput::OutboundOpened { request_id, peer_id: _, connection_id, stream })) if route_proxy_requests.contains_key(&request_id) => {
                        let open_id = route_proxy_requests.remove(&request_id).expect("checked route proxy request exists");
                        let Some(attempt_id) = route_owner.as_ref().and_then(|owner| owner.path_attempt_id(open_id)) else { continue; };
                        let next_actions = route_owner.as_mut().expect("multi-open owner exists").path_event(
                            open_id,
                            PathEvent {
                                attempt_id,
                                now: std::time::Instant::now(),
                                kind: PathEventKind::ExactOpenSucceeded { request_id: PathRequestId(request_id.0), connection: connection_id },
                            },
                        ).unwrap_or_default();
                        let completed_actions = drive_route_actions(
                            &mut swarm,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &emitter,
                            &connections,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut route_wire_sequence,
                            next_actions,
                        )?;
                        if !completed_actions.is_empty() { return Err(io::Error::other("route completed before handshake")); }
                        let action = route_owner.as_mut().expect("multi-open owner exists").handshake_started(open_id, request_id.0).ok_or_else(|| io::Error::other("route handshake owner missing"))?;
                        let route_open::RouteAction::StartHandshakeWorker { open, .. } = action else { return Err(io::Error::other("route handshake action mismatch")); };
                        let deadline = route_owner.as_ref().and_then(|owner| owner.path_input(open_id)).map(|input| input.5).ok_or_else(|| io::Error::other("route deadline missing"))?;
                        let hold = args.test_hold_proxy_handshake_ms.unwrap_or(0);
                        if hold > 0 {
                            emitter.emit(&LifecycleRecord::TestFaultApplied { fault: "hold_client_proxy_handshake" })?;
                        }
                        let tx = proxy_result_tx.clone();
                        tokio::spawn(async move {
                            if hold > 0 { tokio::time::sleep(std::time::Duration::from_millis(hold)).await; }
                            let timeout = deadline.saturating_duration_since(std::time::Instant::now()).min(std::time::Duration::from_secs(5));
                            let result = proxy_open::open_accepted_stream(stream, &open, timeout).await;
                            let _ = tx.send(ProxyResult { open_id: Some(open_id), request_id: open.request_id, result }).await;
                        });
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Proxy(ProxyOutput::OutboundFailed { request_id, peer_id: _, connection_id: _, code: _ })) if route_proxy_requests.contains_key(&request_id) => {
                        let open_id = route_proxy_requests.remove(&request_id).expect("checked route proxy request exists");
                        let action = route_owner.as_mut().expect("multi-open owner exists").proxy_failed_at(
                            &mut resolver_state,
                            open_id,
                            request_id.0,
                            route_open::RetryClass::PreHandshake,
                            unix_now(),
                            std::time::Instant::now(),
                        );
                        let completed_actions = drive_route_actions(
                            &mut swarm,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &emitter,
                            &connections,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut route_wire_sequence,
                            action.into_iter().collect(),
                        )?;
                        if complete_route_actions(
                            product_ingress,
                            completed_actions,
                            &mut resolver_state,
                            &mut route_resolve_wires,
                            &mut route_proxy_requests,
                            &mut ingress_owners,
                            route_owner.as_mut().expect("multi-open owner exists"),
                            expected_exchange,
                            &connections,
                            &mut route_wire_sequence,
                            &mut connection_manager,
                            &mut swarm,
                            &emitter,
                            &args.case_id,
                        ).await? {
                            return Ok(());
                        }
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Proxy(ProxyOutput::OutboundOpened { request_id, peer_id, connection_id, stream })) if pending_proxy == Some(request_id) => {
                        let open = proxy_open.take().ok_or_else(|| io::Error::other("proxy stream opened without grant"))?;
                        if let Some(current) = proxy_attempt.as_mut() {
                            let _ = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ExactOpenSucceeded { request_id: PathRequestId(request_id.0), connection: connection_id } });
                        }
                        let timeout = proxy_setup_deadline
                            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()).min(std::time::Duration::from_secs(5)))
                            .unwrap_or_else(|| std::time::Duration::from_secs(5));
                        let tx = proxy_result_tx.clone();
                        tokio::spawn(async move {
                            let result = proxy_open::open_accepted_stream(stream, &open, timeout).await;
                            let _ = tx
                                .send(ProxyResult {
                                    open_id: None,
                                    request_id: open.request_id,
                                    result,
                                })
                                .await;
                        });
                        let _ = (peer_id, connection_id, selected_proxy_connection, proxy_request_id);
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Proxy(ProxyOutput::OutboundFailed { request_id, peer_id, connection_id, code })) if pending_proxy == Some(request_id) => {
                        if let (Some(current), Some(open), Some(deadline)) = (proxy_attempt.as_mut(), proxy_open.as_ref().cloned(), proxy_setup_deadline) {
                            let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ExactOpenFailed { request_id: PathRequestId(request_id.0), connection: connection_id } });
                            let mut terminal = None;
                            let proxy = swarm.behaviour_mut().proxy_stream.as_mut().ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?;
                            drive_proxy_path_actions(proxy, current, peer_id, &open, deadline, &emitter, actions, &mut pending_proxy, &mut selected_proxy_connection, &mut terminal)?;
                            if terminal.is_none() && pending_proxy.is_some() {
                                continue;
                            }
                        }
                        if let (Some(manager), Some(server)) = (connection_manager.as_mut(), proxy_server) {
                            let _ = manager.release(server);
                        }
                        emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code))?;
                        return Ok(());
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Ping(event)) if args.finite_relay_ping && target_peer == Some(event.peer) && event.result.is_ok() && started && connections.get(event.peer, event.connection).is_some_and(|record| matches!(record.path, PathKind::Relay { .. })) => {
                        if args.test_relay_circuit_count > 1 || !args.test_relay_target.is_empty() {
                            continue;
                        }
                        if args.test_hold_relay_seconds > 0 {
                            tokio::time::sleep(std::time::Duration::from_secs(args.test_hold_relay_seconds)).await;
                        }
                        emitter.terminal(&TerminalResult::simple(&args.case_id, "passed", "relay.ping"))?;
                        return Ok(());
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => {
                        if let Some(manager) = connection_manager.as_mut()
                            && manager.has_peer(peer_id)
                        {
                            manager.on_connection_closed(peer_id, connection_id).map_err(io::Error::other)?;
                        }
                        connections.on_connection_closed(peer_id, connection_id).map_err(io::Error::other)?;
                        let open_ids = route_owner.as_ref().map_or_else(Vec::new, |owner| owner.open_ids_for_server(peer_id));
                        if !open_ids.is_empty() {
                            let mut actions = Vec::new();
                            for open_id in open_ids {
                                let attempt_id = route_owner.as_ref().and_then(|owner| owner.path_attempt_id(open_id)).ok_or_else(|| io::Error::other("route path attempt missing"))?;
                                actions.extend(route_owner.as_mut().expect("multi-open owner exists").path_event(
                                    open_id,
                                    PathEvent { attempt_id, now: std::time::Instant::now(), kind: PathEventKind::ConnectionClosed(connection_id) },
                                ).unwrap_or_default());
                            }
                            let completed_actions = drive_route_actions(
                                &mut swarm,
                                route_owner.as_mut().expect("multi-open owner exists"),
                                expected_exchange,
                                &emitter,
                                &connections,
                                &mut route_resolve_wires,
                                &mut route_proxy_requests,
                                &mut route_wire_sequence,
                                actions,
                            )?;
                            if complete_route_actions(
                                product_ingress,
                                completed_actions,
                                &mut resolver_state,
                                &mut route_resolve_wires,
                                &mut route_proxy_requests,
                                &mut ingress_owners,
                                route_owner.as_mut().expect("multi-open owner exists"),
                                expected_exchange,
                                &connections,
                                &mut route_wire_sequence,
                                &mut connection_manager,
                                &mut swarm,
                                &emitter,
                                &args.case_id,
                            ).await? {
                                return Ok(());
                            }
                        }
                        if product_ingress {
                            for active in ingress_owners.active_for_connection(connection_id) {
                                active.cancel.cancel();
                            }
                        }
                        if !product_ingress
                            && let Some(current) = proxy_attempt.as_mut()
                            && proxy_server == Some(peer_id)
                        {
                            let actions = current.apply(PathEvent {
                                attempt_id: current.id,
                                now: std::time::Instant::now(),
                                kind: PathEventKind::ConnectionClosed(connection_id),
                            });
                            if !actions.is_empty() {
                                if let Some(manager) = connection_manager.as_mut() {
                                    let _ = manager.release(peer_id);
                                }
                                proxy_open = None;
                                pending_proxy = None;
                                emitter.emit(&LifecycleRecord::OperationalError {
                                    code: "peer.connection_failed",
                                    message: "proxy path connection closed",
                                })?;
                            }
                        }
                        if let Some(current) = attempt.as_mut() {
                            let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ConnectionClosed(connection_id) });
                            drive_path_actions(probe_mut(&mut swarm)?, current, peer_id, &emitter, actions, &mut launched)?;
                        }
                        let peer = peer_id.to_string();
                        let reason = format!("{cause:?}");
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Closed, path: None, reason: Some(&reason) })?;
                        if expected_exchange == peer_id && credential.is_some() && exchange_connections.closed(&connection_id) == ConnectionLoss::Final {
                            let was_ready = auth_state.ready();
                            auth_state.disconnected();
                            if args.recover_after_failure && was_ready {
                                exchange_restarted = true;
                                recovery_retry_deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(15));
                            }
                            pending_auth.clear();
                            if args.finite_auth_check && !was_ready {
                                emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", PublicErrorCode::LimitAuthConnections.as_str()))?;
                                return Ok(());
                            }
                            exchange_redial.schedule(unix_millis(), random_jitter_per_mille()?);
                            if was_ready { emitter.emit(&LifecycleRecord::AuthReadiness { ready: false, generation: readiness_generation })?; }
                        }
                        if args.churn && churn_redial_pending && target_peer == Some(peer_id) && completed < args.count && let Some(address) = server_address.clone() {
                            churn_redial_pending = false;
                            swarm.dial(address).map_err(io::Error::other)?;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        if peer_id.is_none() || peer_id == Some(expected_exchange) {
                            exchange_redial.schedule(unix_millis(), random_jitter_per_mille()?);
                        }
                        let message = format!("peer_id={peer_id:?} error={error}");
                        emitter.emit(&LifecycleRecord::OperationalError { code: "connection.outgoing", message: &message })?;
                    }
                    SwarmEvent::Behaviour(p2x_net::builder::PeerEvent::Probe(output)) => match output {
                        ProbeOutput::OutboundOpened { stream, request_id, peer_id, connection_id } => {
                            let mut stream = stream;
                            if let Some(current) = attempt.as_mut() {
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ExactOpenSucceeded { request_id: PathRequestId(request_id.0), connection: connection_id } });
                                drive_path_actions(probe_mut(&mut swarm)?, current, peer_id, &emitter, actions, &mut launched)?;
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::PayloadAccepted });
                                drive_path_actions(probe_mut(&mut swarm)?, current, peer_id, &emitter, actions, &mut launched)?;
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
                                let next = probe_mut(&mut swarm)?.open_on(peer_id, connection_id).map_err(io::Error::other)?;
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
                                let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::ExactOpenFailed { request_id: PathRequestId(request_id.0), connection: connection_id } });
                                drive_path_actions(probe_mut(&mut swarm)?, current, peer_id, &emitter, actions, &mut launched)?;
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
                                if let Some(manager) = connection_manager.as_mut()
                                    && manager.has_peer(event.remote_peer_id)
                                {
                                    manager
                                        .on_dcutr_succeeded(
                                            event.remote_peer_id,
                                            connection_id,
                                            std::time::Instant::now(),
                                        )
                                        .map_err(io::Error::other)?;
                                    connections.on_dcutr_succeeded(event.remote_peer_id, connection_id, std::time::Instant::now()).map_err(io::Error::other)?;
                                    let open_ids = route_owner.as_ref().map_or_else(Vec::new, |owner| owner.open_ids_for_server(event.remote_peer_id));
                                    if !open_ids.is_empty() {
                                        let mut actions = Vec::new();
                                        for open_id in open_ids {
                                            let attempt_id = route_owner.as_ref().and_then(|owner| owner.path_attempt_id(open_id)).ok_or_else(|| io::Error::other("route path attempt missing"))?;
                                            actions.extend(route_owner.as_mut().expect("multi-open owner exists").path_event(
                                                open_id,
                                                PathEvent { attempt_id, now: std::time::Instant::now(), kind: PathEventKind::DirectReady(connection_id) },
                                            ).unwrap_or_default());
                                        }
                                        let completed_actions = drive_route_actions(
                                            &mut swarm,
                                            route_owner.as_mut().expect("multi-open owner exists"),
                                            expected_exchange,
                                            &emitter,
                                            &connections,
                                            &mut route_resolve_wires,
                                            &mut route_proxy_requests,
                                            &mut route_wire_sequence,
                                            actions,
                                        )?;
                                        if complete_route_actions(
                                            product_ingress,
                                            completed_actions,
                                            &mut resolver_state,
                                            &mut route_resolve_wires,
                                            &mut route_proxy_requests,
                                            &mut ingress_owners,
                                            route_owner.as_mut().expect("multi-open owner exists"),
                                            expected_exchange,
                                            &connections,
                                            &mut route_wire_sequence,
                                            &mut connection_manager,
                                            &mut swarm,
                                            &emitter,
                                            &args.case_id,
                                        ).await? {
                                            return Ok(());
                                        }
                                    }
                                    if proxy_capabilities
                                    .is_some_and(|capabilities| capabilities.contains(p2x_protocol::Capabilities::DCUTR))
                                    && proxy_server == Some(event.remote_peer_id)
                                    && let (Some(current), Some(open), Some(deadline)) = (proxy_attempt.as_mut(), proxy_open.as_ref().cloned(), proxy_setup_deadline) {
                                        let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::DirectReady(connection_id) });
                                        let proxy = swarm.behaviour_mut().proxy_stream.as_mut().ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?;
                                        let mut terminal = None;
                                        drive_proxy_path_actions(proxy, current, event.remote_peer_id, &open, deadline, &emitter, actions, &mut pending_proxy, &mut selected_proxy_connection, &mut terminal)?;
                                        if terminal.is_some() {
                                            return Err(io::Error::other("proxy path setup failed"));
                                        }
                                    }
                                }
                                if connection_manager.as_ref().is_none_or(|manager| !manager.has_peer(event.remote_peer_id)) {
                                    connections.on_dcutr_succeeded(event.remote_peer_id, connection_id, std::time::Instant::now()).map_err(io::Error::other)?;
                                }
                                if target_peer == Some(event.remote_peer_id)
                                    && forced_path_matches(args.path, ProbePath::Direct)
                                    && (!started || matches!(args.path, Path::Both))
                                    && launched < args.count
                                    && forced_opened_connections.insert(connection_id)
                                {
                                    let request_id = probe_mut(&mut swarm)?.open_on(event.remote_peer_id, connection_id).map_err(io::Error::other)?;
                                    launched += 1;
                                    emitter.emit(&LifecycleRecord::PathSelected { request_id: request_id.0, connection_id_hash: stable_hash(connection_id), selected_path: ProbePath::Direct })?;
                                    started = true;
                                } else if let Some(current) = attempt.as_mut() {
                                    let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::DirectReady(connection_id) });
                                    drive_path_actions(probe_mut(&mut swarm)?, current, event.remote_peer_id, &emitter, actions, &mut launched)?;
                                }
                            }
                            Err(error) => {
                                let open_ids = route_owner.as_ref().map_or_else(Vec::new, |owner| owner.open_ids_for_server(event.remote_peer_id));
                                if !open_ids.is_empty() {
                                    let mut actions = Vec::new();
                                    for open_id in open_ids {
                                        let attempt_id = route_owner.as_ref().and_then(|owner| owner.path_attempt_id(open_id)).ok_or_else(|| io::Error::other("route path attempt missing"))?;
                                        actions.extend(route_owner.as_mut().expect("multi-open owner exists").path_event(
                                            open_id,
                                            PathEvent { attempt_id, now: std::time::Instant::now(), kind: PathEventKind::DcutrFailed },
                                        ).unwrap_or_default());
                                    }
                                    let completed_actions = drive_route_actions(
                                        &mut swarm,
                                        route_owner.as_mut().expect("multi-open owner exists"),
                                        expected_exchange,
                                        &emitter,
                                        &connections,
                                        &mut route_resolve_wires,
                                        &mut route_proxy_requests,
                                        &mut route_wire_sequence,
                                        actions,
                                    )?;
                                    if complete_route_actions(
                                        product_ingress,
                                        completed_actions,
                                        &mut resolver_state,
                                        &mut route_resolve_wires,
                                        &mut route_proxy_requests,
                                        &mut ingress_owners,
                                        route_owner.as_mut().expect("multi-open owner exists"),
                                        expected_exchange,
                                        &connections,
                                        &mut route_wire_sequence,
                                        &mut connection_manager,
                                        &mut swarm,
                                        &emitter,
                                        &args.case_id,
                                    ).await? {
                                        return Ok(());
                                    }
                                }
                                if let Some(current) = attempt.as_mut() {
                                    let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::DcutrFailed });
                                    drive_path_actions(probe_mut(&mut swarm)?, current, event.remote_peer_id, &emitter, actions, &mut launched)?;
                                }
                                if let (Some(current), Some(open), Some(deadline)) = (proxy_attempt.as_mut(), proxy_open.as_ref().cloned(), proxy_setup_deadline)
                                    && proxy_server == Some(event.remote_peer_id)
                                {
                                    let actions = current.apply(PathEvent { attempt_id: current.id, now: std::time::Instant::now(), kind: PathEventKind::DcutrFailed });
                                    let proxy = swarm.behaviour_mut().proxy_stream.as_mut().ok_or_else(|| io::Error::other("proxy is unavailable in product mode"))?;
                                    let mut terminal = None;
                                    drive_proxy_path_actions(proxy, current, event.remote_peer_id, &open, deadline, &emitter, actions, &mut pending_proxy, &mut selected_proxy_connection, &mut terminal)?;
                                    if pending_proxy.is_some() {
                                        proxy_request_id = Some(open.request_id);
                                    }
                                    if terminal.is_some() {
                                        return Err(io::Error::other("proxy path setup failed"));
                                    }
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
    shutdown.cancel();
    for mut task in ingress_tasks.drain(..) {
        if tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
    for id in ingress_owners.setup_ids().collect::<Vec<_>>() {
        if let Some(owner) = ingress_owners.take_setup(id) {
            owner.cancel.cancel();
        }
    }
    while let Ok(event) = ingress_rx.try_recv() {
        if let IngressEvent::TunnelFinished { id, result } = event
            && let Some(active) = ingress_owners.take_active(id)
        {
            let result = result.map_err(io::Error::other)?;
            emit_client_tunnel_terminal(
                &emitter,
                &active,
                Some(&result),
                tunnel_terminal_class(result.terminal),
                None,
            )?;
            if let Some(manager) = connection_manager.as_mut() {
                let _ = manager.close_active(active.server);
                let _ = manager.release_waiter(active.server, active.open_id.0);
            }
            active.cancel.cancel();
        }
    }
    for id in ingress_owners.active_ids().collect::<Vec<_>>() {
        if let Some(active) = ingress_owners.take_active(id) {
            emit_client_tunnel_terminal(
                &emitter,
                &active,
                None,
                p2x_net::lifecycle::TunnelTerminalClass::Cancelled,
                Some(PublicErrorCode::ExchangeDraining.as_str()),
            )?;
            active.cancel.cancel();
            if let Some(manager) = connection_manager.as_mut() {
                let _ = manager.close_active(active.server);
                let _ = manager.release_waiter(active.server, active.open_id.0);
            }
        }
    }
    route_resolve_wires.clear();
    route_proxy_requests.clear();
    if product_ingress {
        emitter.emit(&LifecycleRecord::Resources {
            connections: 0,
            pending_opens: 0,
            workers: 0,
            tasks: 0,
        })?;
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

    #[test]
    fn capacity_rejections_are_terminal_for_a_route_open() {
        assert!(!route_proxy_rejection_needs_fresh_ticket(
            PublicErrorCode::LimitProxyStreams
        ));
        assert!(route_proxy_rejection_needs_fresh_ticket(
            PublicErrorCode::RegistryStaleRevision
        ));
    }
}
