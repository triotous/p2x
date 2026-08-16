#[allow(dead_code)]
mod availability;
mod config;

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
use p2x_protocol::{
    AuthRequest, AuthResponse, Capabilities, InstanceId, PublicErrorCode, RegistryRequestV1,
    RegistryResponseV1, Role,
};
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
    #[arg(long, action = clap::ArgAction::Append)]
    exchange: Vec<Multiaddr>,
    #[arg(long)]
    exchange_peer_id: Option<String>,
    #[arg(long)]
    credential_env: Option<String>,
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
        capabilities: Capabilities::from_bits(7).expect("known capabilities"),
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
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    if (args.test_register_without_reservation
        || args.test_suppress_registry_refresh
        || args.test_replay_register_response
        || args.test_drop_reservation_after_register
        || args.test_concurrent_registry_requests)
        && std::env::var_os("P2X_ENABLE_TEST_HOOKS").is_none()
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
        mode: if args.unsafe_connectivity_lab {
            RuntimeMode::ConnectivityLab
        } else {
            RuntimeMode::Product
        },
        relay_client_enabled: !args.unsafe_connectivity_lab,
        registry_enabled: !args.unsafe_connectivity_lab,
        auth_fault: None,
    };
    let mut swarm = build_peer_swarm(key, &config).map_err(io::Error::other)?;
    start_peer_listeners(&mut swarm, &config).map_err(io::Error::other)?;
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
    let mut resource_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut first_probe_dropped = false;
    let mut request_ids = p2x_protocol::CorrelationIdGenerator::new(1);
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
    if config.mode == RuntimeMode::Product
        && let Some(index) = exchange_addresses.next(args.exchange.len())
    {
        swarm
            .dial(args.exchange[index].clone())
            .map_err(io::Error::other)?;
    }
    if config.mode == RuntimeMode::Product
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
    if config.mode == RuntimeMode::ConnectivityLab
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
            _ = tokio::signal::ctrl_c() => break,
            _ = resource_tick.tick() => {
                if config.mode == RuntimeMode::Product {
                    match availability.tick(unix_now()) {
                        availability::AvailabilityAction::Refresh if !args.test_suppress_registry_refresh && !registration_requested && registry_operation.is_none() => {
                            if let (Some(peer_id), Some(session_id), Some(revision), Some(services)) = (relay_peer_id, auth_state.current_session(unix_now()), registration_revision, service_config.as_ref()) {
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
                                && let (Some(peer_id), Some(session_id), Some(revision), Some(services)) = (relay_peer_id, auth_state.current_session(unix_now()), registration_revision, service_config.as_ref())
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
                            reservation.apply(ReservationEvent::RelayAddressConfirmed { generation: reservation_generation, peer_id, connection_id, listener_id, address: address.parse().map_err(io::Error::other)? }).map_err(io::Error::other)?;
                            if config.mode == RuntimeMode::Product && reservation.is_ready() && !registration_requested && registry_operation.is_none()
                                && let Some(session_id) = auth_state.current_session(unix_now())
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
                            if config.mode == RuntimeMode::Product {
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
                            && config.mode == RuntimeMode::ConnectivityLab
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
                        if config.mode == RuntimeMode::Product
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
                        if config.mode == RuntimeMode::ConnectivityLab
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
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Authenticated { session_id, request_id, expires_at, .. } }, .. })) if pending_auth.complete(&outbound_id) => {
                        let next_ping_id = request_ids.allocate().map_err(io::Error::other)?;
                        if let AuthAction::Ping { request_id: ping_id, session_id, nonce } = auth_state.authenticated(request_id, session_id, expires_at, next_ping_id, 1, unix_now()) {
                            ping_request_id = ping_id;
                            let outbound = swarm.behaviour_mut().auth.send_request(&peer, AuthRequest::Ping { request_id: ping_id, session_id, nonce });
                            if !pending_auth.begin(outbound) { return Err(io::Error::other("auth outbound request limit exceeded")); }
                        }
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Response { request_id: outbound_id, response: AuthResponse::Pong { request_id, nonce, .. } }, .. })) if credential.is_some() && pending_auth.complete(&outbound_id) && request_id == ping_request_id && auth_state.pong(request_id, nonce) == AuthAction::Ready => {
                        readiness_generation = readiness_generation.saturating_add(1);
                        if config.mode == RuntimeMode::Product { let _ = availability.auth_ready(); }
                        if config.mode == RuntimeMode::Product
                            && args.test_register_without_reservation
                            && registry_operation.is_none()
                            && let (Some(session_id), Some(services)) = (auth_state.current_session(unix_now()), service_config.as_ref())
                        {
                            let operation = new_register(&mut request_ids, session_id, instance_id, services, reservation.generation)?;
                            let outbound = send_registry(&mut swarm, peer, &operation);
                            if pending_registry.begin(outbound) {
                                registry_operation = Some(operation);
                                registration_requested = true;
                            }
                        }
                        if config.mode == RuntimeMode::Product && !args.test_register_without_reservation && !reservation_requested && let (Some(address), Some(connection_id)) = (pending_circuit.clone(), relay_connection_id) {
                            reservation_generation = reservation_generation.saturating_add(1);
                            reservation.apply(ReservationEvent::GenerationStarted { generation: reservation_generation, peer_id: peer, connection_id }).map_err(io::Error::other)?;
                            let listener_id = swarm.listen_on(address).map_err(io::Error::other)?;
                            circuit_listener_id = Some(listener_id);
                            reservation.apply(ReservationEvent::ReservationRequested { generation: reservation_generation, peer_id: peer, connection_id }).map_err(io::Error::other)?;
                            reservation_requested = true;
                        }
                        if config.mode == RuntimeMode::Product
                            && reservation.is_ready()
                            && registration_revision.is_none()
                            && !registration_requested
                            && registry_operation.is_none()
                            && let (Some(session_id), Some(services)) = (auth_state.current_session(unix_now()), service_config.as_ref())
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
                    SwarmEvent::Behaviour(PeerEvent::Relay(libp2p::relay::client::Event::ReservationReqAccepted { relay_peer_id: peer_id, renewal, .. })) if config.mode == RuntimeMode::ConnectivityLab || config.mode == RuntimeMode::Product => {
                        if let (Some(connection_id), Some(listener_id)) = (relay_connection_id, circuit_listener_id) {
                            reservation.apply(ReservationEvent::ReservationAccepted { generation: reservation.generation, peer_id, connection_id, listener_id, renewal }).map_err(io::Error::other)?;
                            if config.mode == RuntimeMode::Product {
                                let _ = availability.reservation_ready(reservation.generation);
                            }
                            if config.mode == RuntimeMode::Product && reservation.is_ready() && !registration_requested && registry_operation.is_none() && let Some(session_id) = auth_state.current_session(unix_now()) {
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
                                        if let (Some(session_id), Some(services)) = (auth_state.current_session(now), service_config.as_ref()) {
                                            operation = new_register(&mut request_ids, session_id, instance_id, services, reservation.generation)?;
                                            registry_retry_due_at = Some(registry_retry_at(&mut operation, unix_millis(), random_jitter_per_mille()?));
                                            registry_operation = Some(operation);
                                        }
                                    }
                                    PublicErrorCode::AuthSessionRequired | PublicErrorCode::AuthSessionExpired => {
                                        registration_revision = None;
                                        if let (Some(session_id), Some(services)) = (auth_state.current_session(now), service_config.as_ref())
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
    if config.mode == RuntimeMode::Product {
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
    if config.mode == RuntimeMode::Product
        && let (Some(peer_id), Some(session_id), Some(revision)) = (
            relay_peer_id,
            auth_state.current_session(unix_now()),
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
