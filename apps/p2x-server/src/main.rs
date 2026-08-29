#[allow(dead_code)]
mod availability;
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
    auth_state::{
        AddressCursor, AuthAction, AuthState, ConnectionLoss, ExchangeConnections, PendingRequest,
        RedialBackoff,
    },
    builder::{
        PeerEvent, PeerSurface, PeerSwarmConfig, build_peer_swarm, lab_identity,
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
use p2x_protocol::{
    AuthRequest, AuthResponse, Capabilities, InstanceId, PublicErrorCode, RegistryRequestV1,
    RegistryResponseV1, Role,
};
use p2x_server::{
    config, proxy_open, proxy_owner::ProxyWorkerTable, stream_admission, ticket_admission,
};
use std::{collections::HashMap, io, path::PathBuf};
use tokio::{sync::mpsc, task::JoinSet};

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
    #[arg(long, action = clap::ArgAction::Append)]
    exchange: Vec<Multiaddr>,
    #[arg(long)]
    exchange_peer_id: Option<String>,
    #[arg(long)]
    credential_env: Option<String>,
    #[arg(long)]
    ticket_verification_keys_file: Option<PathBuf>,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(0..=30))]
    ticket_clock_skew: u64,
    #[arg(long)]
    services_file: Option<PathBuf>,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long, default_value = "lifecycle")]
    case_id: String,
    #[arg(long, default_value_t = 300)]
    worker_timeout_secs: u64,
    #[arg(long, default_value_t = false)]
    drop_first_probe: bool,
    #[arg(long)]
    finite_auth_check: bool,
    #[arg(long, hide = true)]
    test_register_without_reservation: bool,
    #[arg(long, hide = true)]
    test_suppress_registry_refresh: bool,
    #[arg(long, hide = true)]
    test_replay_register_response: bool,
    #[arg(long, hide = true)]
    test_drop_reservation_after_register: bool,
    #[arg(long, hide = true)]
    test_concurrent_registry_requests: bool,
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(0..=10_000))]
    test_hold_proxy_handshake_ms: Option<u64>,
    #[arg(long, hide = true, value_parser = clap::value_parser!(u64).range(0..=30_000))]
    test_hold_upstream_dial_ms: Option<u64>,
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

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn request_id_start() -> io::Result<u128> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok((u128::from_be_bytes(bytes) % (u128::MAX - 1)).saturating_add(1))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryOperationKind {
    Register,
    Refresh(p2x_protocol::RegistrationRevision),
    Withdraw(p2x_protocol::RegistrationRevision),
}

#[derive(Clone, Debug)]
struct RegistryOperation {
    request: RegistryRequestV1,
    kind: RegistryOperationKind,
    reservation_generation: u64,
    expected_service_set_hash: [u8; 32],
    attempts: u32,
}

impl RegistryOperation {
    fn request_id(&self) -> [u8; 16] {
        match &self.request {
            RegistryRequestV1::Register { request_id, .. }
            | RegistryRequestV1::Refresh { request_id, .. }
            | RegistryRequestV1::Withdraw { request_id, .. } => *request_id,
        }
    }

    fn session_id(&self) -> [u8; 16] {
        match &self.request {
            RegistryRequestV1::Register { session_id, .. }
            | RegistryRequestV1::Refresh { session_id, .. }
            | RegistryRequestV1::Withdraw { session_id, .. } => *session_id,
        }
    }

    fn accepts_registered(
        &self,
        request_id: [u8; 16],
        instance_matches: bool,
        service_set_hash: [u8; 32],
        current_reservation_generation: u64,
        reservation_ready: bool,
    ) -> bool {
        self.kind == RegistryOperationKind::Register
            && self.request_id() == request_id
            && instance_matches
            && service_set_hash == self.expected_service_set_hash
            && self.reservation_generation == current_reservation_generation
            && reservation_ready
    }

    fn accepts_refreshed(
        &self,
        request_id: [u8; 16],
        instance_matches: bool,
        revision: p2x_protocol::RegistrationRevision,
        current_reservation_generation: u64,
        reservation_ready: bool,
        prior_lease_current: bool,
    ) -> bool {
        matches!(self.kind, RegistryOperationKind::Refresh(expected) if expected == revision)
            && self.request_id() == request_id
            && instance_matches
            && self.reservation_generation == current_reservation_generation
            && reservation_ready
            && prior_lease_current
    }
}

fn random_jitter_per_mille() -> io::Result<i16> {
    let mut bytes = [0u8; 2];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("runtime randomness unavailable"))?;
    Ok((u16::from_be_bytes(bytes) % 201) as i16 - 100)
}

struct WorkerResult {
    peer_id: libp2p::PeerId,
    result: Result<ProbeAck, p2x_net::probe::ProbeError>,
}

fn new_register(
    request_ids: &mut p2x_protocol::CorrelationIdGenerator,
    session_id: [u8; 16],
    instance_id: InstanceId,
    services: &config::ServiceConfig,
    reservation_generation: u64,
) -> io::Result<RegistryOperation> {
    let request_id = request_ids.allocate().map_err(io::Error::other)?;
    let request = RegistryRequestV1::Register {
        request_id,
        session_id,
        instance_id,
        requested_lease_seconds: services.requested_lease_seconds,
        capabilities: Capabilities::from_bits(31).expect("known capabilities"),
        services: services.services.clone(),
    };
    Ok(RegistryOperation {
        request,
        kind: RegistryOperationKind::Register,
        reservation_generation,
        expected_service_set_hash: services.service_set_hash,
        attempts: 0,
    })
}

fn new_withdraw(
    request_ids: &mut p2x_protocol::CorrelationIdGenerator,
    session_id: [u8; 16],
    instance_id: InstanceId,
    revision: p2x_protocol::RegistrationRevision,
    reservation_generation: u64,
) -> io::Result<RegistryOperation> {
    let request_id = request_ids.allocate().map_err(io::Error::other)?;
    let request = RegistryRequestV1::Withdraw {
        request_id,
        session_id,
        instance_id,
        expected_registration_revision: std::num::NonZeroU64::new(revision.get()).expect("nonzero"),
    };
    Ok(RegistryOperation {
        request,
        kind: RegistryOperationKind::Withdraw(revision),
        reservation_generation,
        expected_service_set_hash: [0; 32],
        attempts: 0,
    })
}

fn new_refresh(
    request_ids: &mut p2x_protocol::CorrelationIdGenerator,
    session_id: [u8; 16],
    instance_id: InstanceId,
    revision: p2x_protocol::RegistrationRevision,
    lease_seconds: u16,
    reservation_generation: u64,
    service_set_hash: [u8; 32],
) -> io::Result<RegistryOperation> {
    let request_id = request_ids.allocate().map_err(io::Error::other)?;
    let request = RegistryRequestV1::Refresh {
        request_id,
        session_id,
        instance_id,
        expected_registration_revision: std::num::NonZeroU64::new(revision.get()).expect("nonzero"),
        requested_lease_seconds: lease_seconds,
    };
    Ok(RegistryOperation {
        request,
        kind: RegistryOperationKind::Refresh(revision),
        reservation_generation,
        expected_service_set_hash: service_set_hash,
        attempts: 0,
    })
}

fn send_registry(
    swarm: &mut libp2p::Swarm<p2x_net::builder::PeerBehaviour>,
    peer_id: libp2p::PeerId,
    operation: &RegistryOperation,
) -> libp2p::request_response::OutboundRequestId {
    swarm
        .behaviour_mut()
        .registry
        .send_request(&peer_id, operation.request.clone())
}

fn registry_retry_at(operation: &mut RegistryOperation, now_millis: i64, jitter: i16) -> i64 {
    operation.attempts = operation.attempts.saturating_add(1);
    let shift = operation.attempts.saturating_sub(1).min(5);
    let delay = (250i64 << shift).min(10_000);
    now_millis.saturating_add(delay + delay * i64::from(jitter.clamp(-100, 100)) / 1000)
}

fn proxy_terminal_class(terminal: p2x_proxy::Terminal) -> p2x_net::lifecycle::TunnelTerminalClass {
    match terminal {
        p2x_proxy::Terminal::Complete => p2x_net::lifecycle::TunnelTerminalClass::Complete,
        p2x_proxy::Terminal::IdleTimeout => p2x_net::lifecycle::TunnelTerminalClass::IdleTimeout,
        p2x_proxy::Terminal::Cancelled => p2x_net::lifecycle::TunnelTerminalClass::Cancelled,
        p2x_proxy::Terminal::LocalIo => p2x_net::lifecycle::TunnelTerminalClass::LocalIo,
        p2x_proxy::Terminal::RemoteIo => p2x_net::lifecycle::TunnelTerminalClass::RemoteIo,
    }
}

fn finish_proxy_worker(
    release: proxy_open::Release,
    workers: &mut ProxyWorkerTable,
    admission: &mut stream_admission::StreamAdmission,
    swarm: &mut libp2p::Swarm<p2x_net::builder::PeerBehaviour>,
    connection_paths: &HashMap<libp2p::swarm::ConnectionId, ProbePath>,
    emitter: &Emitter,
) -> io::Result<()> {
    let record = workers
        .remove(release.worker_id)
        .ok_or_else(|| io::Error::other("proxy worker completion missing owner"))?;
    finish_proxy_worker_record(release, record, admission, swarm, connection_paths, emitter)
}

fn finish_proxy_worker_record(
    release: proxy_open::Release,
    record: p2x_server::proxy_owner::WorkerRecord,
    admission: &mut stream_admission::StreamAdmission,
    swarm: &mut libp2p::Swarm<p2x_net::builder::PeerBehaviour>,
    connection_paths: &HashMap<libp2p::swarm::ConnectionId, ProbePath>,
    emitter: &Emitter,
) -> io::Result<()> {
    if let Some(proxy) = swarm.behaviour_mut().proxy_stream.as_mut() {
        proxy.inbound_release_on(release.peer_id, release.connection_id);
    }
    let owned_admission = record
        .admission
        .or_else(|| (!release.admission.is_empty()).then_some(release.admission));
    if let Some(admission_token) = owned_admission
        && !admission.release(admission_token)
    {
        return Err(io::Error::other(
            "proxy stream admission released more than once",
        ));
    }
    let accepted = release.accepted || record.accepted;
    if accepted && !record.accepted {
        emitter.emit(&LifecycleRecord::TunnelAccepted {
            component_side: p2x_net::lifecycle::ComponentSide::Server,
            peer_id: &release.peer_id.to_string(),
            connection_id_hash: stable_hash(release.connection_id),
            request_id_hash: release.request_id_hash,
            stream_id_hash: release
                .stream_id_hash
                .ok_or_else(|| io::Error::other("accepted worker missing stream ID"))?,
            selected_path: Some(release.selected_path),
            setup_duration_ms: release.setup_duration.as_millis(),
        })?;
    }
    let selected_path = if record.accepted {
        record.selected_path
    } else {
        release.selected_path
    };
    let setup_duration = if record.accepted {
        record.setup_duration
    } else {
        release.setup_duration
    };
    let request_id_hash = if record.accepted {
        record.request_id_hash
    } else {
        release.request_id_hash
    };
    let stream_id_hash = if record.accepted {
        record.stream_id_hash
    } else {
        release.stream_id_hash
    };
    let peer = release.peer_id.to_string();
    if accepted {
        let pump = release.pump;
        emitter.emit(&LifecycleRecord::TunnelTerminal {
            component_side: p2x_net::lifecycle::ComponentSide::Server,
            peer_id: &peer,
            connection_id_hash: stable_hash(release.connection_id),
            request_id_hash,
            stream_id_hash,
            selected_path: Some(selected_path),
            accepted: true,
            code: release.code.map(PublicErrorCode::as_str),
            terminal_class: pump.as_ref().map_or(
                p2x_net::lifecycle::TunnelTerminalClass::Cancelled,
                |result| proxy_terminal_class(result.terminal),
            ),
            setup_duration_ms: setup_duration.as_millis(),
            local_to_remote_bytes: pump
                .as_ref()
                .map_or(0, |result| result.local_to_remote_bytes),
            remote_to_local_bytes: pump
                .as_ref()
                .map_or(0, |result| result.remote_to_local_bytes),
            local_eof: pump.as_ref().is_some_and(|result| result.local_eof),
            remote_eof: pump.as_ref().is_some_and(|result| result.remote_eof),
            duration_ms: pump
                .as_ref()
                .map_or(0, |result| result.duration.as_millis()),
        })?;
    } else if let Some(code) = release.code {
        emitter.emit(&LifecycleRecord::ProxyAuthorization {
            peer_id: &peer,
            connection_id_hash: stable_hash(release.connection_id),
            request_id_hash,
            stream_id_hash,
            authorized: false,
            code: Some(code.as_str()),
        })?;
    }
    let _ = connection_paths;
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    if (args.test_register_without_reservation
        || args.test_suppress_registry_refresh
        || args.test_replay_register_response
        || args.test_drop_reservation_after_register
        || args.test_concurrent_registry_requests
        || args.test_hold_proxy_handshake_ms.is_some()
        || args.test_hold_upstream_dial_ms.is_some())
        && std::env::var("P2X_ENABLE_TEST_HOOKS").ok().as_deref() != Some("1")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "registry test hooks require P2X_ENABLE_TEST_HOOKS=1",
        ));
    }
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
    let verification_ring = if args.unsafe_connectivity_lab {
        None
    } else {
        Some(
            p2x_config::ticket_key::VerificationKeyRing::load(
                args.ticket_verification_keys_file
                    .as_deref()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "product mode requires --ticket-verification-keys-file",
                        )
                    })?,
            )
            .map_err(io::Error::other)?,
        )
    };
    let service_config = if args.unsafe_connectivity_lab {
        None
    } else {
        Some(
            config::ServiceConfig::load(args.services_file.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "product mode requires --services-file",
                )
            })?)
            .map_err(io::Error::other)?,
        )
    };
    let shutdown = tokio_util::sync::CancellationToken::new();
    let mut ticket_admission = ticket_admission::TicketAdmissionLedger::new(
        service_config
            .as_ref()
            .map_or(ticket_admission::MAX_REPLAY_ENTRIES, |config| {
                config.proxy.max_replay_entries
            }),
        args.ticket_clock_skew as i64,
    )
    .map_err(|code| io::Error::new(io::ErrorKind::InvalidInput, code.as_str()))?;
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
            PeerSurface::ProductServer
        },
        auth_fault: None,
    };
    let mut swarm = build_peer_swarm(key, &config).map_err(io::Error::other)?;
    start_peer_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    if let Some(proxy) = swarm.behaviour_mut().proxy_stream.as_mut()
        && let Some(service_config) = service_config.as_ref()
    {
        proxy.set_inbound_limits(
            service_config.proxy.max_workers,
            service_config.proxy.max_workers_per_client,
        );
    }
    let mut credential: Option<(p2x_protocol::CredentialId, p2x_protocol::TokenSecret)> = None;
    let mut relay_peer_id = exchange_trust.as_ref().map(|trust| trust.peer_id);
    let mut relay_connection_id = None;
    let mut circuit_listener_id = None;
    let mut reservation_generation = 0u64;
    let mut reservation = ReservationContext::new(0);
    let mut pending_circuit = None;
    let mut reservation_requested = false;
    let mut connection_paths = HashMap::new();
    let mut worker_admission = WorkerAdmission::default();
    let (worker_tx, mut worker_rx) = mpsc::channel::<WorkerResult>(128);
    let proxy_limit = service_config
        .as_ref()
        .map_or(256, |config| config.proxy.max_workers);
    let (proxy_tx, mut proxy_rx) = mpsc::channel::<proxy_open::Candidate>(proxy_limit);
    let (proxy_promotion_tx, mut proxy_promotion_rx) =
        mpsc::channel::<proxy_open::Promotion>(proxy_limit);
    let (proxy_accept_tx, mut proxy_accept_rx) = mpsc::channel::<proxy_open::Accepted>(proxy_limit);
    let mut proxy_admission = service_config.as_ref().map_or_else(
        || stream_admission::StreamAdmission::new(256, 32, 64),
        |services| {
            stream_admission::StreamAdmission::new(
                services.proxy.max_workers,
                services.proxy.max_workers_per_client,
                services.proxy.max_upstream_dials,
            )
        },
    );
    let mut proxy_workers = JoinSet::new();
    let mut proxy_worker_tasks = HashMap::<tokio::task::Id, proxy_open::ProxyWorkerId>::new();
    let mut proxy_worker_table = ProxyWorkerTable::default();
    let mut resource_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut first_probe_dropped = false;
    let mut request_ids = p2x_protocol::CorrelationIdGenerator::new(request_id_start()?);
    let mut auth_request_id = request_ids.allocate().map_err(io::Error::other)?;
    let mut ping_request_id = request_ids.allocate().map_err(io::Error::other)?;
    let mut auth_state = AuthState::new();
    let mut exchange_connections = ExchangeConnections::new();
    let mut pending_auth = PendingRequest::new();
    let mut exchange_redial = RedialBackoff::new();
    let mut exchange_addresses = AddressCursor::new();
    let mut readiness_generation = 0u64;
    let mut instance_bytes = [0; 16];
    getrandom::fill(&mut instance_bytes).map_err(io::Error::other)?;
    let instance_id = InstanceId::new(instance_bytes);
    let mut availability = availability::Availability::with_refresh_seconds(
        instance_bytes,
        service_config
            .as_ref()
            .map_or(10, |config| config.refresh_seconds),
    );
    let mut registration_requested = false;
    let mut pending_registry: PendingRequest<libp2p::request_response::OutboundRequestId> =
        PendingRequest::new();
    let mut registry_operation: Option<RegistryOperation> = None;
    let mut registry_retry_due_at = None;
    let mut registration_revision = None;
    let mut registration_expires_at = 0i64;
    let mut register_response_replayed = false;
    let mut changed_register_replayed = false;
    let mut late_refresh_sent = false;
    if !config.is_connectivity_lab()
        && let Some(index) = exchange_addresses.next(args.exchange.len())
    {
        swarm
            .dial(args.exchange[index].clone())
            .map_err(io::Error::other)?;
    }
    if !config.is_connectivity_lab()
        && let Some(index) = exchange_addresses.next(args.exchange.len())
    {
        let exchange = args.exchange[index].clone();
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
        relay_peer_id = Some(relay_peer);
        pending_circuit = Some(
            exchange
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(*swarm.local_peer_id())),
        );
    }
    if config.is_connectivity_lab()
        && let Some(index) = exchange_addresses.next(args.exchange.len())
    {
        let exchange = args.exchange[index].clone();
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
            _ = tokio::signal::ctrl_c() => { shutdown.cancel(); break },
            _ = resource_tick.tick() => {
                if !config.is_connectivity_lab() {
                    match availability.tick(unix_now()) {
                        availability::AvailabilityAction::Refresh if !args.test_suppress_registry_refresh && !registration_requested && registry_operation.is_none() => {
                            if let (Some(peer_id), Some(session_id), Some(revision), Some(services)) = (relay_peer_id, auth_state.current_session_id(unix_now()), registration_revision, service_config.as_ref()) {
                                let operation = new_refresh(&mut request_ids, session_id, instance_id, revision, services.requested_lease_seconds, reservation.generation, services.service_set_hash)?;
                                let outbound = send_registry(&mut swarm, peer_id, &operation);
                                if pending_registry.begin(outbound) { registry_operation = Some(operation); registration_requested = true; }
                            }
                        }
                        availability::AvailabilityAction::Publish(false) if registration_expires_at != 0 => {
                            registration_expires_at = 0;
                            let snapshot = availability.readiness(unix_now());
                            emitter.emit(&LifecycleRecord::ServerReadiness { ready: false, generation: snapshot.generation, auth: snapshot.auth, reservation: snapshot.reservation, registration: snapshot.registration })?;
                            if args.test_suppress_registry_refresh
                                && !late_refresh_sent
                                && let (Some(peer_id), Some(session_id), Some(revision), Some(services)) = (relay_peer_id, auth_state.current_session_id(unix_now()), registration_revision, service_config.as_ref())
                            {
                                late_refresh_sent = true;
                                let operation = new_refresh(&mut request_ids, session_id, instance_id, revision, services.requested_lease_seconds, reservation.generation, services.service_set_hash)?;
                                let outbound = send_registry(&mut swarm, peer_id, &operation);
                                if pending_registry.begin(outbound) {
                                    registry_operation = Some(operation);
                                    registration_requested = true;
                                }
                            }
                        }
                        _ => {}
                    }
                    if registry_retry_due_at.is_some_and(|due| unix_millis() >= due)
                        && !registration_requested
                        && reservation.is_ready()
                        && let (Some(peer_id), Some(operation)) = (relay_peer_id, registry_operation.as_ref())
                    {
                        let outbound = send_registry(&mut swarm, peer_id, operation);
                        if pending_registry.begin(outbound) {
                            registration_requested = true;
                            registry_retry_due_at = None;
                        }
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
                if let Some(book) = connection_book.as_mut() { book.sweep(std::time::Instant::now()); }
                if let Some((id, token)) = credential.as_ref() {
                    match auth_state.tick(request_ids.allocate().map_err(io::Error::other)?, unix_now()) {
                        AuthAction::Authenticate { request_id } => {
                            auth_request_id = request_id;
                            if let Some(peer_id) = relay_peer_id {
                                let outbound = swarm.behaviour_mut().auth.send_request(&peer_id, AuthRequest::Authenticate { request_id, credential_id: id.clone(), token_secret: p2x_protocol::TokenSecret::from_bytes(*token.as_bytes()), requested_role: Role::Server, supported_features: 0 });
                                if !pending_auth.begin(outbound) { return Err(io::Error::other("auth outbound request limit exceeded")); }
                            }
                        }
                        AuthAction::Retry => pending_auth.clear(),
                        _ => {}
                    }
                }
                let connections = connection_book.as_ref().map(ConnectionBook::len).unwrap_or(connection_paths.len());
                let pending_opens = swarm.behaviour().probe_stream.as_ref().map_or(0, |probe| probe.pending_count())
                    + swarm.behaviour().proxy_stream.as_ref().map_or(0, |proxy| proxy.pending_count());
                let configured_proxy_workers = proxy_worker_table.len();
                emitter.emit(&LifecycleRecord::Resources { connections, pending_opens, workers: worker_admission.admitted() + configured_proxy_workers, tasks: worker_admission.admitted() + configured_proxy_workers })?;
                if !proxy_admission.is_empty() {
                    emitter.emit(&LifecycleRecord::Resources {
                        connections,
                        pending_opens,
                        workers: proxy_worker_table.len(),
                        tasks: proxy_admission.dialing(),
                    })?;
                }
            }
            Some(result) = proxy_workers.join_next_with_id() => {
                match result {
                    Ok((task_id, release)) => {
                        proxy_worker_tasks.remove(&task_id);
                        finish_proxy_worker(release, &mut proxy_worker_table, &mut proxy_admission, &mut swarm, &connection_paths, &emitter)?;
                    }
                    Err(error) => {
                        let task_id = error.id();
                        let worker_id = proxy_worker_tasks
                            .remove(&task_id)
                            .ok_or_else(|| io::Error::other("proxy worker join owner missing"))?;
                        let record = proxy_worker_table
                            .remove(worker_id)
                            .ok_or_else(|| io::Error::other("proxy worker panic owner missing"))?;
                        let release = proxy_open::Release {
                            worker_id,
                            peer_id: record.peer_id,
                            connection_id: record.connection_id,
                            selected_path: record.selected_path,
                            setup_duration: record.setup_duration,
                            admission: record.admission.unwrap_or_else(stream_admission::AdmissionToken::empty),
                            request_id_hash: record.request_id_hash,
                            stream_id_hash: record.stream_id_hash,
                            accepted: record.accepted,
                            code: Some(PublicErrorCode::PeerConnectionFailed),
                            pump: None,
                        };
                        finish_proxy_worker_record(release, record, &mut proxy_admission, &mut swarm, &connection_paths, &emitter)?;
                    }
                }
            }
            Some(promotion) = proxy_promotion_rx.recv() => {
                let acknowledged = proxy_worker_table
                    .get(promotion.worker_id)
                    .is_some_and(|record| record.admission == Some(promotion.admission))
                    && proxy_admission.promote(promotion.admission);
                let _ = promotion.acknowledged.send(acknowledged);
                if !acknowledged {
                    return Err(io::Error::other("proxy stream promotion failed"));
                }
            }
            Some(accepted) = proxy_accept_rx.recv() => {
                if proxy_worker_table.get(accepted.worker_id).is_none() {
                    continue;
                }
                proxy_worker_table
                    .mark_accepted(
                        accepted.worker_id,
                        accepted.setup_duration,
                        accepted.request_id_hash,
                        accepted.stream_id_hash,
                    )
                    .map_err(io::Error::other)?;
                let peer = accepted.peer_id.to_string();
                emitter.emit(&LifecycleRecord::TunnelAccepted {
                    component_side: p2x_net::lifecycle::ComponentSide::Server,
                    peer_id: &peer,
                    connection_id_hash: stable_hash(accepted.connection_id),
                    request_id_hash: accepted.request_id_hash,
                    stream_id_hash: accepted.stream_id_hash,
                    selected_path: Some(accepted.selected_path),
                    setup_duration_ms: accepted.setup_duration.as_millis(),
                })?;
            }
            Some(candidate) = proxy_rx.recv() => {
                let peer_name = candidate.peer_id.to_string();
                let request_id = candidate.open.as_ref().ok().map(|open| open.request_id);
                let decision = match candidate.open {
                    Ok(open) => {
                        let now = unix_now();
                        if std::time::Instant::now() >= candidate.deadline {
                            proxy_open::ServerDecision::Reject(
                                p2x_protocol::ProxyOpenResponseV1::Rejected {
                                    request_id: Some(open.request_id),
                                    error: p2x_protocol::PublicError::new(
                                        PublicErrorCode::PeerSetupTimeout,
                                        true,
                                    ),
                                },
                            )
                        } else {
                        match (verification_ring.as_ref(), auth_state.current_session(now), service_config.as_ref(), availability.registration_context(now)) {
                            (Some(_ring), Some(session), Some(services), Some((_, expires_at))) => {
                                let Some(service) = services.service(&open.upstream_id) else {
                                    return Err(io::Error::other("advertised service disappeared"));
                                };
                                let Some(upstream) = services.upstreams.get(&open.upstream_id).cloned() else {
                                    return Err(io::Error::other("immutable upstream disappeared"));
                                };
                                let reject = |code: PublicErrorCode| proxy_open::ServerDecision::Reject(
                                    p2x_protocol::ProxyOpenResponseV1::Rejected {
                                        request_id: Some(open.request_id),
                                        error: p2x_protocol::PublicError::new(
                                            code,
                                            matches!(code, PublicErrorCode::RegistryStaleRevision | PublicErrorCode::LimitProxyStreams | PublicErrorCode::RegistryOffline),
                                        ),
                                    },
                                );
                                match candidate.validation {
                                    Ok(validation_candidate) => {
                                        let preflight = ticket_admission.preflight_candidate(&validation_candidate, now);
                                        if let Err(code) = preflight {
                                            reject(code)
                                        } else if let Err(code) = ticket_admission.validate_candidate(
                                            &validation_candidate,
                                            relay_peer_id.unwrap_or(*swarm.local_peer_id()),
                                            candidate.peer_id,
                                            *swarm.local_peer_id(),
                                            session.tenant(),
                                            service,
                                            registration_revision,
                                            expires_at,
                                            session.authorization_revision(),
                                            &open,
                                            now,
                                        ) {
                                            reject(code)
                                        } else if service.selector().protocol() != p2x_protocol::ProtocolClass::Tcp {
                                            reject(PublicErrorCode::ProtocolCapabilityMismatch)
                                        } else if upstream.advertisement.health() != p2x_protocol::Health::Ready {
                                            reject(PublicErrorCode::RegistryOffline)
                                        } else if let Err(code) = proxy_admission.preflight(candidate.peer_id, &open.upstream_id, upstream.concurrency_limit) {
                                            reject(code)
                                        } else {
                                            match ticket_admission.allocate_stream_id(&validation_candidate, now) {
                                                Ok(stream_id) => {
                                                    let admission = stream_admission::AdmissionToken::new(stream_id);
                                                    match proxy_admission.reserve(admission, candidate.peer_id, open.upstream_id.clone(), upstream.concurrency_limit) {
                                                        Ok(()) => match ticket_admission.consume_candidate_with_stream_id(validation_candidate, stream_id, now) {
                                                            ticket_admission::TicketAdmission::Authorized(stream_id) => proxy_open::ServerDecision::Admit {
                                                                stream_id,
                                                                admission,
                                                                upstream,
                                                                copy_buffer_bytes: services.proxy.copy_buffer_bytes,
                                                            },
                                                            ticket_admission::TicketAdmission::Rejected(code) => {
                                                                let _ = proxy_admission.release(admission);
                                                                reject(code)
                                                            }
                                                        },
                                                        Err(code) => reject(code),
                                                    }
                                                }
                                                Err(code) => reject(code),
                                            }
                                        }
                                    }
                                    Err(code) => reject(code),
                                }
                            }
                            _ => proxy_open::ServerDecision::Reject(
                                p2x_protocol::ProxyOpenResponseV1::Rejected {
                                    request_id,
                                    error: p2x_protocol::PublicError::new(PublicErrorCode::AuthSessionRequired, false),
                                },
                            ),
                        }
                        }
                    }
                    Err(code) => proxy_open::ServerDecision::Reject(
                        p2x_protocol::ProxyOpenResponseV1::Rejected {
                            request_id,
                            error: p2x_protocol::PublicError::new(code, false),
                        },
                    ),
                };
                let (request_id_hash, stream_id_hash, authorized, code) = match &decision {
                    proxy_open::ServerDecision::Admit { stream_id, .. } => (
                        request_id.map(stable_hash).unwrap_or_default(),
                        Some(stable_hash(stream_id)),
                        true,
                        None,
                    ),
                    proxy_open::ServerDecision::Reject(p2x_protocol::ProxyOpenResponseV1::Rejected { request_id, error }) => (
                        request_id.map(stable_hash).unwrap_or_default(),
                        None,
                        false,
                        Some(error.code.as_str()),
                    ),
                    proxy_open::ServerDecision::Reject(_) => (0, None, false, Some(PublicErrorCode::ProtocolMalformed.as_str())),
                };
                emitter.emit(&LifecycleRecord::ProxyAuthorization {
                    peer_id: &peer_name,
                    connection_id_hash: stable_hash(candidate.connection_id),
                    request_id_hash,
                    stream_id_hash,
                    authorized,
                    code,
                })?;
                if let proxy_open::ServerDecision::Admit { admission, .. } = &decision {
                    proxy_worker_table
                        .attach_admission(candidate.worker_id, *admission)
                        .map_err(io::Error::other)?;
                }
                let _ = candidate.decision.send(decision);
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
                            reservation.apply(ReservationEvent::RelayAddressConfirmed { generation: reservation_generation, peer_id, connection_id, listener_id, address: address.parse().map_err(io::Error::other)? }).map_err(io::Error::other)?;
                            if !config.is_connectivity_lab() && reservation.is_ready() && !registration_requested && registry_operation.is_none()
                                && let Some(session_id) = auth_state.current_session_id(unix_now())
                            {
                                let operation = new_register(&mut request_ids, session_id, instance_id, service_config.as_ref().expect("product services"), reservation.generation)?;
                                let outbound = send_registry(&mut swarm, peer_id, &operation);
                                if !pending_registry.begin(outbound) { return Err(io::Error::other("registry outbound request limit exceeded")); }
                                registry_operation = Some(operation);
                                registration_requested = true;
                                if args.test_concurrent_registry_requests {
                                    let duplicate = new_register(&mut request_ids, session_id, instance_id, service_config.as_ref().expect("product services"), reservation.generation)?;
                                    let _ = send_registry(&mut swarm, peer_id, &duplicate);
                                }
                            }
                        }
                    }
                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        if address.to_string().contains("p2p-circuit") {
                            let relay = relay_peer_id.map(|peer| peer.to_string()).unwrap_or_default();
                            let address = address.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Ready, exchange_peer_id: &relay, listener_id: None, address: Some(&address), generation: reservation.generation, renewal: false })?;
                        }
                    }
                    SwarmEvent::ExternalAddrExpired { address } if address.to_string().contains("p2p-circuit") => {
                        if reservation.canonical_address.as_ref() == Some(&address)
                            && let (Some(peer_id), Some(connection_id), Some(listener_id)) = (reservation.exchange_peer_id, reservation.exchange_connection_id, reservation.listener_id)
                        {
                            let _ = reservation.apply(ReservationEvent::RelayAddressLost { generation: reservation.generation, peer_id, connection_id, listener_id, address });
                            let _ = availability.reservation_lost_for(reservation.generation);
                            registration_revision = None;
                            registration_expires_at = 0;
                            registration_requested = false;
                            registry_operation = None;
                            registry_retry_due_at = None;
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Degraded, exchange_peer_id: &peer_id.to_string(), listener_id: Some("circuit"), address: None, generation: reservation.generation, renewal: false })?;
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
                        if relay_peer_id == Some(peer_id) {
                            exchange_connections.established(connection_id);
                            if !config.is_connectivity_lab() {
                                relay_connection_id = Some(connection_id);
                            }
                            exchange_redial.reset();
                            if credential.is_none() {
                                credential = credential_ref.as_ref().map(|reference| reference.read().map_err(io::Error::other)).transpose()?;
                            }
                            if let Some((id, token)) = credential.as_ref()
                                && let AuthAction::Authenticate { request_id } = auth_state.connected(auth_request_id, unix_now())
                            {
                            auth_request_id = request_id;
                                let outbound = swarm.behaviour_mut().auth.send_request(&peer_id, AuthRequest::Authenticate { request_id, credential_id: id.clone(), token_secret: p2x_protocol::TokenSecret::from_bytes(*token.as_bytes()), requested_role: Role::Server, supported_features: 0 });
                                if !pending_auth.begin(outbound) { return Err(io::Error::other("auth outbound request limit exceeded")); }
                            }
                        }
                        if relay_peer_id == Some(peer_id)
                            && config.is_connectivity_lab()
                            && !reservation_requested
                            && let Some(address) = pending_circuit.clone()
                        {
                            relay_connection_id = Some(connection_id);
                            reservation_generation = reservation_generation.saturating_add(1);
                            reservation.apply(ReservationEvent::GenerationStarted { generation: reservation_generation, peer_id, connection_id }).map_err(io::Error::other)?;
                            let listener_id = swarm.listen_on(address).map_err(io::Error::other)?;
                            circuit_listener_id = Some(listener_id);
                            reservation.apply(ReservationEvent::ReservationRequested { generation: reservation_generation, peer_id, connection_id }).map_err(io::Error::other)?;
                            reservation_requested = true;
                            let relay = peer_id.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Requested, exchange_peer_id: &relay, listener_id: None, address: None, generation: 1, renewal: false })?;
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => {
                        if !config.is_connectivity_lab()
                            && relay_peer_id == Some(peer_id)
                            && relay_connection_id == Some(connection_id) {
                            if let Some(listener_id) = circuit_listener_id.take() {
                                swarm.remove_listener(listener_id);
                            }
                            let _ = reservation.apply(ReservationEvent::ExchangeLost { generation: reservation.generation, peer_id, connection_id });
                            reservation_requested = false;
                            relay_connection_id = None;
                            let _ = availability.reservation_lost_for(reservation.generation);
                            let snapshot = availability.readiness(unix_now());
                            emitter.emit(&LifecycleRecord::ServerReadiness { ready: false, generation: snapshot.generation, auth: snapshot.auth, reservation: snapshot.reservation, registration: snapshot.registration })?;
                            registration_revision = None;
                            registration_expires_at = 0;
                            registration_requested = false;
                            registry_operation = None;
                            registry_retry_due_at = None;
                        }
                        if config.is_connectivity_lab()
                            && relay_peer_id == Some(peer_id)
                            && relay_connection_id == Some(connection_id) {
                            reservation.apply(ReservationEvent::ExchangeLost { generation: reservation_generation, peer_id, connection_id }).map_err(io::Error::other)?;
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Degraded, exchange_peer_id: &peer_id.to_string(), listener_id: circuit_listener_id.as_ref().map(|_| "circuit"), address: None, generation: 1, renewal: false })?;
                        }
                        if let Some(book) = connection_book.as_mut() { book.on_connection_closed(peer_id, connection_id).map_err(io::Error::other)?; }
                        if relay_peer_id == Some(peer_id) && credential.is_some() && exchange_connections.closed(&connection_id) == ConnectionLoss::Final {
                            let was_ready = auth_state.ready();
                            auth_state.disconnected();
                            pending_auth.clear();
                            pending_registry.clear();
                            registration_requested = false;
                            registry_operation = None;
                            registry_retry_due_at = None;
                            registration_revision = None;
                            registration_expires_at = 0;
                            let _ = availability.session_lost();
                            exchange_redial.schedule(unix_millis(), random_jitter_per_mille()?);
                            if was_ready { emitter.emit(&LifecycleRecord::AuthReadiness { ready: false, generation: readiness_generation })?; }
                        }
                        connection_paths.remove(&connection_id);
                        let peer = peer_id.to_string();
                        let reason = format!("{cause:?}");
                        emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Closed, path: None, reason: Some(&reason) })?;
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        if peer_id.is_none() || peer_id == relay_peer_id {
                            exchange_redial.schedule(unix_millis(), random_jitter_per_mille()?);
                        }
                        let message = format!("peer_id={peer_id:?} error={error}");
                        emitter.emit(&LifecycleRecord::OperationalError { code: "connection.outgoing", message: &message })?;
                    }
                    SwarmEvent::ListenerError { error, .. } => {
                        let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "listener.error", message: &message })?;
                    }
                    SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                        if circuit_listener_id == Some(listener_id)
                            && let (Some(peer_id), Some(connection_id)) = (reservation.exchange_peer_id, reservation.exchange_connection_id)
                        {
                            let _ = reservation.apply(ReservationEvent::ListenerClosed { generation: reservation.generation, peer_id, connection_id, listener_id });
                            let _ = availability.reservation_lost_for(reservation.generation);
                            circuit_listener_id = None;
                            registration_revision = None;
                            registration_expires_at = 0;
                            registration_requested = false;
                            registry_operation = None;
                            registry_retry_due_at = None;
                        }
                        let message = format!("{reason:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "listener.closed", message: &message })?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Proxy(p2x_net::proxy_stream::behaviour::ProxyOutput::InboundOpened { peer_id, connection_id, stream })) => {
                        let selected_path = connection_paths.get(&connection_id).copied().unwrap_or(ProbePath::Relay);
                        let worker_id = proxy_worker_table.insert(peer_id, connection_id, selected_path);
                        let tx = proxy_tx.clone();
                        let task = proxy_workers.spawn(proxy_open::run_worker(
                            worker_id,
                            peer_id,
                            connection_id,
                            selected_path,
                            stream,
                            verification_ring.clone(),
                            unix_now(),
                            args.ticket_clock_skew as i64,
                            args.test_hold_proxy_handshake_ms,
                            args.test_hold_upstream_dial_ms,
                            tx,
                            proxy_accept_tx.clone(),
                            proxy_promotion_tx.clone(),
                            shutdown.child_token(),
                        ));
                        proxy_worker_tasks.insert(task.id(), worker_id);
                    }
                    SwarmEvent::Behaviour(PeerEvent::Proxy(p2x_net::proxy_stream::behaviour::ProxyOutput::InboundRejected { peer_id, connection_id, stream, code })) => {
                        if let Some(stream) = stream {
                            let public_code = PublicErrorCode::parse(code);
                            tokio::spawn(proxy_open::reject_stream(stream, public_code));
                        }
                        emitter.emit(&LifecycleRecord::ProxyAuthorization {
                            peer_id: &peer_id.to_string(),
                            connection_id_hash: stable_hash(connection_id),
                            request_id_hash: 0,
                            stream_id_hash: None,
                            authorized: false,
                            code: Some(code),
                        })?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Authenticated { session_id, request_id, tenant, role, scopes, quota_profile, authorization_revision, expires_at, .. } }, .. })) if pending_auth.complete(&outbound_id) => {
                        let next_ping_id = request_ids.allocate().map_err(io::Error::other)?;
                        if let AuthAction::Ping { request_id: ping_id, session_id, nonce } = auth_state.authenticated_with_context(request_id, session_id, expires_at, tenant, role, scopes, quota_profile, authorization_revision, next_ping_id, 1, unix_now()) {
                            ping_request_id = ping_id;
                            let outbound = swarm.behaviour_mut().auth.send_request(&peer, AuthRequest::Ping { request_id: ping_id, session_id, nonce });
                            if !pending_auth.begin(outbound) { return Err(io::Error::other("auth outbound request limit exceeded")); }
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Pong { request_id, nonce, .. } }, .. })) if credential.is_some() && pending_auth.complete(&outbound_id) && request_id == ping_request_id && auth_state.pong(request_id, nonce) == AuthAction::Ready => {
                        readiness_generation = readiness_generation.saturating_add(1);
                        if !config.is_connectivity_lab() { let _ = availability.auth_ready(); }
                        if !config.is_connectivity_lab()
                            && args.test_register_without_reservation
                            && registry_operation.is_none()
                            && let (Some(session_id), Some(services)) = (auth_state.current_session_id(unix_now()), service_config.as_ref())
                        {
                            let operation = new_register(&mut request_ids, session_id, instance_id, services, reservation.generation)?;
                            let outbound = send_registry(&mut swarm, peer, &operation);
                            if pending_registry.begin(outbound) {
                                registry_operation = Some(operation);
                                registration_requested = true;
                            }
                        }
                        if !config.is_connectivity_lab() && !args.test_register_without_reservation && !reservation_requested && let (Some(address), Some(connection_id)) = (pending_circuit.clone(), relay_connection_id) {
                            reservation_generation = reservation_generation.saturating_add(1);
                            reservation.apply(ReservationEvent::GenerationStarted { generation: reservation_generation, peer_id: peer, connection_id }).map_err(io::Error::other)?;
                            let listener_id = swarm.listen_on(address).map_err(io::Error::other)?;
                            circuit_listener_id = Some(listener_id);
                            reservation.apply(ReservationEvent::ReservationRequested { generation: reservation_generation, peer_id: peer, connection_id }).map_err(io::Error::other)?;
                            reservation_requested = true;
                        }
                        if !config.is_connectivity_lab()
                            && reservation.is_ready()
                            && registration_revision.is_none()
                            && !registration_requested
                            && registry_operation.is_none()
                            && let (Some(session_id), Some(services)) = (auth_state.current_session_id(unix_now()), service_config.as_ref())
                        {
                            let operation = new_register(&mut request_ids, session_id, instance_id, services, reservation.generation)?;
                            let outbound = send_registry(&mut swarm, peer, &operation);
                            if pending_registry.begin(outbound) {
                                registry_operation = Some(operation);
                                registry_retry_due_at = None;
                                registration_requested = true;
                            }
                        }
                        if args.finite_auth_check { emitter.terminal(&TerminalResult::simple(&args.case_id, "passed", "auth.pong"))?; return Ok(()); }
                        emitter.emit(&LifecycleRecord::AuthReadiness { ready: true, generation: readiness_generation })?;
                        let snapshot = availability.readiness(unix_now());
                        emitter.emit(&LifecycleRecord::ServerReadiness { ready: snapshot.auth && snapshot.reservation && snapshot.registration, generation: snapshot.generation, auth: snapshot.auth, reservation: snapshot.reservation, registration: snapshot.registration })?;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Rejected { request_id, error } }, .. })) if credential.is_some() && pending_auth.complete(&outbound_id) && auth_state.rejected(request_id, error.code, unix_now()) != AuthAction::Ignore => {
                        if matches!(auth_state.phase(), p2x_net::auth_state::AuthPhase::Terminal(_)) {
                            emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", error.code.as_str()))?;
                            return Ok(());
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::OutboundFailure { request_id, error: libp2p::request_response::OutboundFailure::Timeout, .. })) if credential.is_some() && pending_auth.complete(&request_id) => {
                        let _ = auth_state.timeout(unix_now());
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::OutboundFailure { request_id, error: libp2p::request_response::OutboundFailure::UnsupportedProtocols, .. })) if credential.is_some() && pending_auth.complete(&request_id) => {
                        let code = PublicErrorCode::ProtocolCapabilityMismatch;
                        emitter.terminal(&TerminalResult::simple(&args.case_id, "failed", code.as_str()))?;
                        return Ok(());
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::OutboundFailure { request_id, error: libp2p::request_response::OutboundFailure::ConnectionClosed, .. })) if credential.is_some() => { pending_auth.complete(&request_id); }
                    SwarmEvent::Behaviour(PeerEvent::Relay(libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id: peer_id, renewal, .. })) => {
                        if let (Some(connection_id), Some(listener_id)) = (relay_connection_id, circuit_listener_id) {
                            reservation.apply(ReservationEvent::ReservationAccepted { generation: reservation.generation, peer_id, connection_id, listener_id, renewal }).map_err(io::Error::other)?;
                            if !config.is_connectivity_lab() {
                                let _ = availability.reservation_ready(reservation.generation);
                            }
                            if !config.is_connectivity_lab() && reservation.is_ready() && !registration_requested && registry_operation.is_none() && let Some(session_id) = auth_state.current_session_id(unix_now()) {
                                let operation = new_register(&mut request_ids, session_id, instance_id, service_config.as_ref().expect("product services"), reservation.generation)?;
                                let outbound = send_registry(&mut swarm, peer_id, &operation);
                                if !pending_registry.begin(outbound) { return Err(io::Error::other("registry outbound request limit exceeded")); }
                                registry_operation = Some(operation);
                                registration_requested = true;
                            }
                            let relay = peer_id.to_string();
                            emitter.emit(&LifecycleRecord::ReservationTransition { state: LifecycleReservationState::Accepted, exchange_peer_id: &relay, listener_id: Some("circuit"), address: None, generation: reservation.generation, renewal })?;
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Registry(RequestResponseEvent::Message { message: RequestResponseMessage::Response { request_id: outbound_id, response }, .. })) if pending_registry.complete(&outbound_id) => {
                        registration_requested = false;
                        registry_retry_due_at = None;
                        let Some(mut operation) = registry_operation.take() else { continue };
                        let now = unix_now();
                        match response {
                            RegistryResponseV1::Registered { request_id: response_id, instance_id: response_instance, registration_revision: revision, service_set_hash, expires_at, .. }
                                if operation.accepts_registered(response_id, response_instance == instance_id, service_set_hash, reservation.generation, reservation.is_ready()) => {
                                if args.test_replay_register_response && !register_response_replayed {
                                    register_response_replayed = true;
                                    let Some(peer_id) = relay_peer_id else { continue };
                                    let outbound = send_registry(&mut swarm, peer_id, &operation);
                                    if !pending_registry.begin(outbound) { return Err(io::Error::other("registry replay outbound request limit exceeded")); }
                                    registry_operation = Some(operation);
                                    registration_requested = true;
                                    continue;
                                }
                                registration_revision = Some(revision);
                                registration_expires_at = expires_at;
                                let _ = availability.registered_with_jitter(reservation.generation, expires_at, now, random_jitter_per_mille()?);
                                let snapshot = availability.readiness(now);
                                emitter.emit(&LifecycleRecord::ServerReadiness { ready: snapshot.auth && snapshot.reservation && snapshot.registration, generation: snapshot.generation, auth: snapshot.auth, reservation: snapshot.reservation, registration: snapshot.registration })?;
                                if args.test_replay_register_response
                                    && register_response_replayed
                                    && !changed_register_replayed
                                {
                                    changed_register_replayed = true;
                                    let mut changed = operation.clone();
                                    if let RegistryRequestV1::Register { requested_lease_seconds, .. } = &mut changed.request {
                                        *requested_lease_seconds = requested_lease_seconds.saturating_add(1);
                                    }
                                    let Some(peer_id) = relay_peer_id else { continue };
                                    let outbound = send_registry(&mut swarm, peer_id, &changed);
                                    if !pending_registry.begin(outbound) { return Err(io::Error::other("changed registry replay outbound request limit exceeded")); }
                                    registry_operation = Some(changed);
                                    registration_requested = true;
                                }
                                if args.test_drop_reservation_after_register
                                    && let Some(listener_id) = circuit_listener_id.take()
                                {
                                    swarm.remove_listener(listener_id);
                                    if let Some(connection_id) = relay_connection_id {
                                        swarm.close_connection(connection_id);
                                    }
                                }
                            }
                            RegistryResponseV1::Refreshed { request_id: response_id, instance_id: response_instance, registration_revision: response_revision, expires_at }
                                if operation.accepts_refreshed(response_id, response_instance == instance_id, response_revision, reservation.generation, reservation.is_ready(), registration_expires_at > now) => {
                                registration_expires_at = expires_at;
                                let _ = availability.registered_with_jitter(reservation.generation, expires_at, now, random_jitter_per_mille()?);
                                let snapshot = availability.readiness(now);
                                emitter.emit(&LifecycleRecord::ServerReadiness { ready: snapshot.auth && snapshot.reservation && snapshot.registration, generation: snapshot.generation, auth: snapshot.auth, reservation: snapshot.reservation, registration: snapshot.registration })?;
                            }
                            RegistryResponseV1::Rejected { request_id: Some(response_id), error }
                                if response_id == operation.request_id() => {
                                match error.code {
                                    PublicErrorCode::RegistryStaleRevision | PublicErrorCode::RegistryNotFound => {
                                        let _ = availability.registration_lost();
                                        registration_expires_at = 0;
                                        registration_revision = None;
                                        if let (Some(session_id), Some(services)) = (auth_state.current_session_id(now), service_config.as_ref()) {
                                            operation = new_register(&mut request_ids, session_id, instance_id, services, reservation.generation)?;
                                            registry_retry_due_at = Some(registry_retry_at(&mut operation, unix_millis(), random_jitter_per_mille()?));
                                            registry_operation = Some(operation);
                                        }
                                    }
                                    PublicErrorCode::AuthSessionRequired | PublicErrorCode::AuthSessionExpired => {
                                        registration_revision = None;
                                        if let (Some(session_id), Some(services)) = (auth_state.current_session_id(now), service_config.as_ref())
                                            && session_id != operation.session_id()
                                        {
                                            operation = new_register(&mut request_ids, session_id, instance_id, services, reservation.generation)?;
                                            registry_retry_due_at = Some(registry_retry_at(&mut operation, unix_millis(), random_jitter_per_mille()?));
                                            registry_operation = Some(operation);
                                        }
                                    }
                                    PublicErrorCode::ExchangeOverloaded
                                    | PublicErrorCode::ExchangeTimeout
                                    | PublicErrorCode::LimitRegistryRequests
                                    | PublicErrorCode::ExchangeDraining => {
                                        registry_retry_due_at = Some(registry_retry_at(&mut operation, unix_millis(), random_jitter_per_mille()?));
                                        registry_operation = Some(operation);
                                    }
                                    PublicErrorCode::RegistryReservationRequired => {
                                        let _ = availability.registration_lost();
                                        registration_expires_at = 0;
                                        registration_revision = None;
                                    }
                                    _ => {
                                        let _ = availability.registration_lost();
                                        registration_expires_at = 0;
                                        registration_revision = None;
                                        let message = error.code.as_str();
                                        emitter.emit(&LifecycleRecord::OperationalError { code: "registry.terminal", message })?;
                                    }
                                }
                            }
                            _ => {
                                registration_revision = None;
                                registration_expires_at = 0;
                                let _ = availability.registration_lost();
                                emitter.emit(&LifecycleRecord::OperationalError { code: "registry.correlation", message: "registry response did not match the pending operation" })?;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Registry(RequestResponseEvent::OutboundFailure { request_id, .. })) if pending_registry.complete(&request_id) => {
                        registration_requested = false;
                        if let Some(operation) = registry_operation.as_mut() {
                            if operation.kind == RegistryOperationKind::Register {
                                let _ = availability.registration_lost();
                            }
                            registry_retry_due_at = Some(registry_retry_at(operation, unix_millis(), random_jitter_per_mille()?));
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
    shutdown.cancel();
    if !config.is_connectivity_lab()
        && let Some(proxy) = swarm.behaviour_mut().proxy_stream.as_mut()
    {
        proxy.set_draining(true);
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while (worker_admission.admitted() > 0 || !proxy_worker_table.is_empty())
        && tokio::time::Instant::now() < deadline
    {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            Some(worker) = worker_rx.recv() => {
                let _ = worker_admission.release(worker.peer_id);
                if let Some(probe) = swarm.behaviour_mut().probe_stream.as_mut() {
                    probe.inbound_release(worker.peer_id);
                }
            }
            Some(candidate) = proxy_rx.recv() => {
                let request_id = candidate.open.as_ref().ok().map(|open| open.request_id);
                emitter.emit(&LifecycleRecord::ProxyAuthorization {
                    peer_id: &candidate.peer_id.to_string(),
                    connection_id_hash: stable_hash(candidate.connection_id),
                    request_id_hash: request_id.map(stable_hash).unwrap_or_default(),
                    stream_id_hash: None,
                    authorized: false,
                    code: Some(PublicErrorCode::PeerDraining.as_str()),
                })?;
                let _ = candidate.decision.send(proxy_open::ServerDecision::Reject(
                    p2x_protocol::ProxyOpenResponseV1::Rejected {
                        request_id,
                        error: p2x_protocol::PublicError::new(
                            PublicErrorCode::PeerDraining,
                            true,
                        ),
                    },
                ));
            }
            Some(accepted) = proxy_accept_rx.recv() => {
                if proxy_worker_table.get(accepted.worker_id).is_none() {
                    continue;
                }
                proxy_worker_table
                    .mark_accepted(
                        accepted.worker_id,
                        accepted.setup_duration,
                        accepted.request_id_hash,
                        accepted.stream_id_hash,
                    )
                    .map_err(io::Error::other)?;
                let peer = accepted.peer_id.to_string();
                emitter.emit(&LifecycleRecord::TunnelAccepted {
                    component_side: p2x_net::lifecycle::ComponentSide::Server,
                    peer_id: &peer,
                    connection_id_hash: stable_hash(accepted.connection_id),
                    request_id_hash: accepted.request_id_hash,
                    stream_id_hash: accepted.stream_id_hash,
                    selected_path: Some(accepted.selected_path),
                    setup_duration_ms: accepted.setup_duration.as_millis(),
                })?;
            }
            Some(result) = proxy_workers.join_next() => {
                let release = result.map_err(|_| io::Error::other("proxy worker panicked during shutdown"))?;
                finish_proxy_worker(release, &mut proxy_worker_table, &mut proxy_admission, &mut swarm, &connection_paths, &emitter)?;
            }
            Some(promotion) = proxy_promotion_rx.recv() => {
                let _ = promotion.acknowledged.send(false);
            }
        }
    }
    if !config.is_connectivity_lab() {
        let _ = availability.begin_shutdown();
        let snapshot = availability.readiness(unix_now());
        emitter.emit(&LifecycleRecord::ServerReadiness {
            ready: false,
            generation: snapshot.generation,
            auth: snapshot.auth,
            reservation: snapshot.reservation,
            registration: snapshot.registration,
        })?;
    }
    if !config.is_connectivity_lab()
        && let (Some(peer_id), Some(session_id), Some(revision)) = (
            relay_peer_id,
            auth_state.current_session_id(unix_now()),
            registration_revision,
        )
        && let Ok(operation) = new_withdraw(
            &mut request_ids,
            session_id,
            instance_id,
            revision,
            reservation.generation,
        )
    {
        let request_id = operation.request_id();
        let outbound = send_registry(&mut swarm, peer_id, &operation);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::Behaviour(PeerEvent::Registry(RequestResponseEvent::Message {
                    message:
                        RequestResponseMessage::Response {
                            request_id: response_id,
                            response:
                                RegistryResponseV1::Withdrawn {
                                    request_id: wire_id,
                                    instance_id: response_instance,
                                    ..
                                },
                        },
                    ..
                })) = swarm.select_next_some().await
                    && response_id == outbound
                    && wire_id == request_id
                    && response_instance == instance_id
                {
                    break;
                }
            }
        })
        .await;
        availability.withdrawn();
    }
    if let Some(listener_id) = circuit_listener_id {
        swarm.remove_listener(listener_id);
    }
    if let Some(connection_id) = relay_connection_id {
        swarm.close_connection(connection_id);
    }
    availability.stopped();
    ticket_admission.clear();
    connection_paths.clear();
    if !proxy_worker_table.is_empty() {
        return Err(io::Error::other(
            "proxy worker table leaked during shutdown",
        ));
    }
    emitter.emit(&LifecycleRecord::Resources {
        connections: 0,
        pending_opens: 0,
        workers: 0,
        tasks: 0,
    })?;
    if !proxy_admission.is_empty() {
        return Err(io::Error::other(
            "proxy stream admission leaked during shutdown",
        ));
    }
    worker_admission.close_and_discard();
    emitter.terminal(&TerminalResult::simple(
        &args.case_id,
        "stopped",
        "shutdown",
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(kind: RegistryOperationKind) -> RegistryOperation {
        RegistryOperation {
            request: RegistryRequestV1::Withdraw {
                request_id: [1; 16],
                session_id: [2; 16],
                instance_id: InstanceId::new([3; 16]),
                expected_registration_revision: std::num::NonZeroU64::new(7).unwrap(),
            },
            kind,
            reservation_generation: 4,
            expected_service_set_hash: [5; 32],
            attempts: 0,
        }
    }

    #[test]
    fn register_correlation_rejects_stale_hash_and_generation() {
        let operation = operation(RegistryOperationKind::Register);
        assert!(operation.accepts_registered([1; 16], true, [5; 32], 4, true));
        assert!(!operation.accepts_registered([1; 16], true, [6; 32], 4, true));
        assert!(!operation.accepts_registered([1; 16], true, [5; 32], 5, true));
    }

    #[test]
    fn late_refresh_cannot_resurrect_an_expired_lease() {
        let revision = p2x_protocol::RegistrationRevision::new(7).unwrap();
        let operation = operation(RegistryOperationKind::Refresh(revision));
        assert!(operation.accepts_refreshed([1; 16], true, revision, 4, true, true));
        assert!(!operation.accepts_refreshed([1; 16], true, revision, 4, true, false));
    }

    #[test]
    fn registry_retry_preserves_request_bytes_and_is_bounded() {
        let mut operation = operation(RegistryOperationKind::Register);
        let hash = operation.request.hash();
        assert_eq!(registry_retry_at(&mut operation, 1_000, -100), 1_225);
        for _ in 0..20 {
            let due = registry_retry_at(&mut operation, 0, 100);
            assert!(due <= 11_000);
        }
        assert_eq!(operation.request.hash(), hash);
        assert_eq!(operation.request_id(), [1; 16]);
    }
}
