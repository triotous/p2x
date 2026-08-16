use clap::{Parser, ValueEnum};
use futures::StreamExt;
use libp2p::{
    Multiaddr,
    request_response::{Event as RequestResponseEvent, Message as RequestResponseMessage},
    swarm::SwarmEvent,
};
use p2x_exchange::{
    admission::{Admission, AdmissionLedger},
    auth_handler::handle_request,
    auth_sessions::AuthSessionLedger,
    authn::FixedTokenProvider,
    registry_admission::{RegistryAdmission, RegistryAdmissionLedger},
};
use p2x_net::{
    builder::{
        ExchangeSwarmConfig, RelayProfile, RuntimeMode, build_exchange_swarm, lab_identity,
        start_exchange_listeners,
    },
    lifecycle::{ConnectionState, Emitter, LifecycleRecord, TerminalResult, stable_hash},
};
use p2x_protocol::{AuthResponse, PublicError, PublicErrorCode};
use std::{
    collections::HashSet,
    io,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
fn validate_advertise(
    addresses: &[Multiaddr],
    peer_id: libp2p::PeerId,
    product: bool,
) -> io::Result<()> {
    if product && addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --advertise",
        ));
    }
    if addresses.len() > 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at most four advertise addresses are allowed",
        ));
    }
    for address in addresses {
        let mut peers = address.iter().filter_map(|part| match part {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        });
        if peers.next() != Some(peer_id)
            || peers.next().is_some()
            || !matches!(address.iter().last(), Some(libp2p::multiaddr::Protocol::P2p(peer)) if peer == peer_id)
            || address
                .iter()
                .any(|part| matches!(part, libp2p::multiaddr::Protocol::P2pCircuit))
            || !address.iter().any(|part| {
                matches!(
                    part,
                    libp2p::multiaddr::Protocol::Tcp(_) | libp2p::multiaddr::Protocol::QuicV1
                )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid --advertise address",
            ));
        }
    }
    Ok(())
}
fn chrono_like_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/0")]
    tcp_listen: Multiaddr,
    #[arg(long, default_value = "/ip4/127.0.0.1/udp/0/quic-v1")]
    quic_listen: Multiaddr,
    #[arg(long, action = clap::ArgAction::Append)]
    advertise: Vec<Multiaddr>,
    #[arg(long, value_enum, default_value_t = RelayProfileArg::Product)]
    relay_profile: RelayProfileArg,
    #[arg(long)]
    unsafe_lab_public_relay: bool,
    #[arg(long)]
    credential_file: Option<PathBuf>,
    #[arg(long)]
    ticket_key_file: Option<PathBuf>,
    #[arg(long)]
    artifact: Option<PathBuf>,
    #[arg(long, default_value = "lifecycle")]
    case_id: String,
    #[arg(long)]
    auth_limit_connections: Option<usize>,
    #[arg(long)]
    auth_limit_requests: Option<usize>,
    #[arg(long)]
    auth_limit_sessions: Option<usize>,
    #[arg(long, hide = true)]
    auth_limit_connections_per_ip: Option<usize>,
    #[arg(long, hide = true)]
    registry_limit_global: Option<usize>,
    #[arg(long, hide = true)]
    registry_limit_per_peer: Option<usize>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RelayProfileArg {
    Product,
    DefaultLab,
    LimitTest,
}

impl From<RelayProfileArg> for RelayProfile {
    fn from(value: RelayProfileArg) -> Self {
        match value {
            RelayProfileArg::Product => Self::Product,
            RelayProfileArg::DefaultLab => Self::DefaultLab,
            RelayProfileArg::LimitTest => Self::LimitTest,
        }
    }
}
#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let run_id = std::env::var("P2X_RUN_ID").unwrap_or_else(|_| "manual".into());
    let emitter = match &args.artifact {
        Some(path) => Emitter::with_artifact("exchange", &run_id, path)?,
        None => Emitter::new("exchange", &run_id),
    };
    let ticket_key = args
        .ticket_key_file
        .as_deref()
        .map(p2x_config::ticket_key::TicketKey::load)
        .transpose()
        .map_err(io::Error::other)?;
    if args.credential_file.is_none() && !args.unsafe_connectivity_lab {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --credential-file",
        ));
    }
    let provider = args
        .credential_file
        .as_deref()
        .map(|path| p2x_config::credential::FixedTokenFile::load(path).map_err(io::Error::other))
        .transpose()?
        .map(|file| FixedTokenProvider::from_config(&file))
        .transpose()
        .map_err(io::Error::other)?;
    if provider.is_some() && ticket_key.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated exchange requires --ticket-key-file",
        ));
    }
    let key = if let Some(path) = args.identity_file.as_ref() {
        p2x_config::identity::load_or_create_identity(&p2x_config::identity::IdentityConfig {
            path: path.clone(),
            generate_if_missing: args.generate_identity,
        })
        .map_err(io::Error::other)?
        .keypair
    } else if provider.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authenticated exchange requires --identity-file",
        ));
    } else if args.unsafe_connectivity_lab {
        lab_identity(args.identity_seed).map_err(io::Error::other)?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product mode requires --identity-file",
        ));
    };
    if let Some(ticket_key) = ticket_key.as_ref() {
        let transport_public = key
            .public()
            .try_into_ed25519()
            .map_err(|_| io::Error::other("transport identity is not Ed25519"))?
            .to_bytes();
        ticket_key
            .ensure_separate_from(&transport_public)
            .map_err(io::Error::other)?;
    }
    let local_peer_id = libp2p::PeerId::from_public_key(&key.public());
    validate_advertise(
        &args.advertise,
        local_peer_id,
        !args.unsafe_connectivity_lab,
    )?;
    let mut sessions = args.auth_limit_sessions.map_or_else(
        AuthSessionLedger::default,
        AuthSessionLedger::with_max_sessions,
    );
    let mut admission = match (
        args.auth_limit_connections,
        args.auth_limit_requests,
        args.auth_limit_connections_per_ip,
    ) {
        (Some(connections), Some(requests), Some(per_ip)) => {
            AdmissionLedger::with_connection_limits(connections, requests, per_ip)
        }
        (Some(connections), Some(requests), None) => {
            AdmissionLedger::with_limits(connections, requests)
        }
        _ => AdmissionLedger::default(),
    };
    let relay_admission = p2x_net::RelayAdmissionHandle::default();
    let mut registry = p2x_exchange::registry::Registry::default();
    let mut registry_admission = match (args.registry_limit_global, args.registry_limit_per_peer) {
        (Some(global), Some(per_peer)) => RegistryAdmissionLedger::with_limits(
            global,
            per_peer,
            p2x_exchange::registry_admission::MAX_PER_MINUTE,
            p2x_exchange::registry_admission::MAX_BUCKETS,
        ),
        _ => RegistryAdmissionLedger::default(),
    };
    let mut reserved_servers = HashSet::new();
    let mut active_circuits = 0usize;
    registry.set_advertise_addresses(args.advertise.iter().map(ToString::to_string).collect());
    let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
    let config = ExchangeSwarmConfig {
        tcp_listen: args.tcp_listen,
        quic_listen: args.quic_listen,
        allow_public: args.unsafe_lab_public_relay,
        relay_profile: args.relay_profile.into(),
        relay_admission: (!args.unsafe_connectivity_lab).then(|| relay_admission.clone()),
        registry_enabled: !args.unsafe_connectivity_lab,
        mode: if args.unsafe_connectivity_lab {
            RuntimeMode::ConnectivityLab
        } else {
            RuntimeMode::Product
        },
    };
    let mut swarm = build_exchange_swarm(key, &config).map_err(io::Error::other)?;
    for address in &args.advertise {
        swarm.add_external_address(address.clone());
    }
    start_exchange_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    let local_peer = swarm.local_peer_id().to_string();
    emitter.emit(&LifecycleRecord::Started {
        peer_id: &local_peer,
    })?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = maintenance.tick() => {
                let now = chrono_like_now();
                let actions = sessions.sweep(now);
                for action in actions {
                    match action {
                        p2x_exchange::auth_sessions::SessionAction::Removed(peer)
                        | p2x_exchange::auth_sessions::SessionAction::PrincipalRevoked(peer) => {
                            if let Ok(peer_id) = peer.parse() {
                                relay_admission.remove(&peer_id);
                                reserved_servers.remove(&peer_id);
                                registry.remove_peer(&peer_id);
                            }
                        }
                        p2x_exchange::auth_sessions::SessionAction::ClosePeerConnections { connection_ids, .. } => {
                            for connection_id in connection_ids { swarm.close_connection(connection_id); }
                        }
                        _ => {}
                    }
                }
                registry.sweep(now);
                registry_admission.sweep(now);
                relay_admission.sweep(std::time::Instant::now());
                if relay_admission.is_poisoned() {
                    emitter.emit(&LifecycleRecord::OperationalError { code: "relay.admission_poisoned", message: "relay admission snapshot is unavailable" })?;
                    break;
                }
                admission.sweep(chrono_like_now());
                emitter.emit(&LifecycleRecord::ExchangeResources {
                    sessions: sessions.len(),
                    relay_admissions: relay_admission.len(),
                    reservations: reserved_servers.len(),
                    circuits: active_circuits,
                    registrations: registry.len(),
                    selector_owners: registry.owner_count(),
                    auth_requests: admission.inflight(),
                    registry_requests: registry_admission.inflight(),
                })?;
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { listener_id, address } => {
                    if args.unsafe_connectivity_lab {
                        swarm.add_external_address(address.clone());
                    }
                    let advertised = address.with(libp2p::multiaddr::Protocol::P2p(*swarm.local_peer_id()));
                    let listener_id = format!("{listener_id:?}");
                    let advertised = advertised.to_string();
                    emitter.emit(&LifecycleRecord::ListenerReady { listener_id: &listener_id, address: &advertised })?;
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Auth(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Request { request_id, request, channel }, connection_id, .. })) => {
                    let peer_name = peer.to_string();
                    emitter.emit(&LifecycleRecord::AuthRequestObserved { peer_id: &peer_name, request_id: request_id.to_string() })?;
                    let wire_request_id = match &request {
                        p2x_protocol::AuthRequest::Authenticate { request_id, .. } | p2x_protocol::AuthRequest::Ping { request_id, .. } => Some(*request_id),
                    };
                    let admission_request_id = request_id;
                    if admission.begin_auth(admission_request_id, connection_id, chrono_like_now()) != Admission::Accepted {
                        let response = AuthResponse::Rejected { request_id: wire_request_id, error: PublicError::new(PublicErrorCode::LimitAuthRequests, true) };
                        swarm.behaviour_mut().auth.send_response(channel, response).map_err(|_| io::Error::other("auth response channel closed"))?;
                        continue;
                    }
                    let failed = matches!(&request, p2x_protocol::AuthRequest::Authenticate { .. });
                    let response = if let Some(provider) = provider.as_ref() { handle_request(provider, &mut sessions, &peer.to_string(), request, chrono_like_now(), Some(&relay_admission)) } else { AuthResponse::Rejected { request_id: wire_request_id, error: PublicError::new(PublicErrorCode::AuthSessionRequired, false) } };
                    if let AuthResponse::Authenticated { .. } = response {
                        // Relay admission is installed transactionally by handle_request.
                    }
                    let rejected = matches!(response, AuthResponse::Rejected { .. });
                    admission.mark_response(admission_request_id, rejected && failed);
                    swarm.behaviour_mut().auth.send_response(channel, response).map_err(|_| io::Error::other("auth response channel closed"))?;
                },
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Auth(RequestResponseEvent::ResponseSent { request_id, .. })) => {
                    admission.response_delivered(request_id, chrono_like_now());
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Auth(RequestResponseEvent::InboundFailure { request_id, .. })) => {
                    admission.response_delivered(request_id, chrono_like_now());
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Registry(RequestResponseEvent::Message { peer, message: RequestResponseMessage::Request { request, channel, request_id }, connection_id, .. })) => {
                    if let RegistryAdmission::Rejected(code) = registry_admission.begin(peer, request_id, connection_id, chrono_like_now()) {
                        let response = p2x_protocol::RegistryResponseV1::Rejected { request_id: match &request { p2x_protocol::RegistryRequestV1::Register { request_id, .. } | p2x_protocol::RegistryRequestV1::Refresh { request_id, .. } | p2x_protocol::RegistryRequestV1::Withdraw { request_id, .. } => Some(*request_id) }, error: p2x_protocol::PublicError::new(code, true) };
                        let peer_name = peer.to_string();
                        emitter.emit(&LifecycleRecord::RegistryTransition {
                            peer_id: &peer_name,
                            operation: "rejected",
                            code: code.as_str(),
                            revision: None,
                            registrations: registry.len(),
                            selector_owners: registry.owner_count(),
                            mutations: registry.mutation_count(),
                        })?;
                        if swarm.behaviour_mut().registry.send_response(channel, response).is_err() { /* no owner was acquired */ }
                        continue;
                    }
                    let registry_request_id = match &request {
                        p2x_protocol::RegistryRequestV1::Register { request_id, .. }
                        | p2x_protocol::RegistryRequestV1::Refresh { request_id, .. }
                        | p2x_protocol::RegistryRequestV1::Withdraw { request_id, .. } => Some(*request_id),
                    };
                    let session = sessions.current(&peer.to_string(), chrono_like_now());
                    let response = match (session, request.clone()) {
                        (Some(session), p2x_protocol::RegistryRequestV1::Register { session_id, .. }) if session.principal.role == p2x_protocol::Role::Server && session_id == session.session_id => registry.register(peer, &session.principal.tenant, session.principal.role, session.principal.scopes, &session.principal.quota_profile, session.principal.authorization_revision, reserved_servers.contains(&peer), request, chrono_like_now()).unwrap_or_else(|error| p2x_protocol::RegistryResponseV1::Rejected { request_id: registry_request_id, error: p2x_protocol::PublicError::new(error.code(), error.retryable()) }),
                        (Some(session), p2x_protocol::RegistryRequestV1::Refresh { request_id, session_id, instance_id, expected_registration_revision, requested_lease_seconds }) if session.principal.role == p2x_protocol::Role::Server && session_id == session.session_id => registry.refresh(peer, request_id, instance_id, p2x_protocol::RegistrationRevision::new(expected_registration_revision.get()).expect("nonzero revision"), reserved_servers.contains(&peer), &session.principal.tenant, session.principal.role, session.principal.scopes, &session.principal.quota_profile, session.principal.authorization_revision, requested_lease_seconds, session_id, chrono_like_now()).unwrap_or_else(|error| p2x_protocol::RegistryResponseV1::Rejected { request_id: Some(request_id), error: p2x_protocol::PublicError::new(error.code(), error.retryable()) }),
                        (Some(session), p2x_protocol::RegistryRequestV1::Withdraw { request_id, session_id, instance_id, expected_registration_revision }) if session.principal.role == p2x_protocol::Role::Server && session_id == session.session_id => registry.withdraw(peer, request_id, instance_id, p2x_protocol::RegistrationRevision::new(expected_registration_revision.get()).expect("nonzero revision"), session_id, &session.principal.tenant, session.principal.role, session.principal.scopes, &session.principal.quota_profile, session.principal.authorization_revision, chrono_like_now()).unwrap_or_else(|error| p2x_protocol::RegistryResponseV1::Rejected { request_id: Some(request_id), error: p2x_protocol::PublicError::new(error.code(), error.retryable()) }),
                        _ => p2x_protocol::RegistryResponseV1::Rejected { request_id: registry_request_id, error: p2x_protocol::PublicError::new(p2x_protocol::PublicErrorCode::AuthSessionRequired, false) },
                    };
                    let (operation, code, revision) = match &response {
                        p2x_protocol::RegistryResponseV1::Registered { registration_revision, .. } => ("register", "registry.registered", Some(registration_revision.get())),
                        p2x_protocol::RegistryResponseV1::Refreshed { registration_revision, .. } => ("refresh", "registry.refreshed", Some(registration_revision.get())),
                        p2x_protocol::RegistryResponseV1::Withdrawn { registration_revision, .. } => ("withdraw", "registry.withdrawn", Some(registration_revision.get())),
                        p2x_protocol::RegistryResponseV1::Rejected { error, .. } => ("rejected", error.code.as_str(), None),
                    };
                    let peer_name = peer.to_string();
                    emitter.emit(&LifecycleRecord::RegistryTransition {
                        peer_id: &peer_name,
                        operation,
                        code,
                        revision,
                        registrations: registry.len(),
                        selector_owners: registry.owner_count(),
                        mutations: registry.mutation_count(),
                    })?;
                    if swarm.behaviour_mut().registry.send_response(channel, response).is_err() {
                        registry_admission.release(peer, request_id, connection_id);
                    }
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Registry(RequestResponseEvent::ResponseSent { peer, connection_id, request_id, .. })) => {
                    registry_admission.release(peer, request_id, connection_id);
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Registry(RequestResponseEvent::InboundFailure { peer, connection_id, request_id, .. })) => {
                    registry_admission.release(peer, request_id, connection_id);
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Relay(libp2p::relay::Event::ReservationReqAccepted { src_peer_id, .. })) => {
                    reserved_servers.insert(src_peer_id);
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Relay(libp2p::relay::Event::ReservationClosed { src_peer_id }))
                | SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Relay(libp2p::relay::Event::ReservationTimedOut { src_peer_id })) => {
                    reserved_servers.remove(&src_peer_id);
                    registry.remove_peer(&src_peer_id);
                    emitter.emit(&LifecycleRecord::ExchangeResources {
                        sessions: sessions.len(),
                        relay_admissions: relay_admission.len(),
                        reservations: reserved_servers.len(),
                        circuits: active_circuits,
                        registrations: registry.len(),
                        selector_owners: registry.owner_count(),
                        auth_requests: admission.inflight(),
                        registry_requests: registry_admission.inflight(),
                    })?;
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Relay(libp2p::relay::Event::CircuitReqAccepted { .. })) => {
                    active_circuits = active_circuits.saturating_add(1);
                }
                SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Relay(libp2p::relay::Event::CircuitClosed { .. })) => {
                    active_circuits = active_circuits.saturating_sub(1);
                }
                SwarmEvent::Behaviour(event) => { let message = format!("{event:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "relay.event", message: &message })?; }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => { let peer = peer_id.to_string(); let ip = endpoint.get_remote_address().iter().find_map(|p| match p { libp2p::multiaddr::Protocol::Ip4(v) => Some(v.to_string()), libp2p::multiaddr::Protocol::Ip6(v) => Some(v.to_string()), _ => None }).unwrap_or_else(|| "<unknown>".into()); if admission.admit_connection(connection_id, &peer, &ip) != Admission::Accepted { swarm.close_connection(connection_id); continue; } sessions.connection_established(&peer, connection_id); emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Established, path: Some(if endpoint.is_relayed() { p2x_net::probe::ProbePath::Relay } else { p2x_net::probe::ProbePath::Direct }), reason: None })?; }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => {
                    let peer = peer_id.to_string();
                    if let Some(action) = sessions.connection_closed(&peer, connection_id)
                        && matches!(action, p2x_exchange::auth_sessions::SessionAction::Removed(_))
                    {
                        relay_admission.remove(&peer_id);
                        reserved_servers.remove(&peer_id);
                        registry.remove_peer(&peer_id);
                    }
                    registry_admission.close_connection(connection_id);
                    admission.close_connection(connection_id);
                    let reason = format!("{cause:?}");
                    emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Closed, path: None, reason: Some(&reason) })?;
                }
                SwarmEvent::IncomingConnectionError { error, .. } => { let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "connection.incoming", message: &message })?; }
                SwarmEvent::OutgoingConnectionError { error, .. } => { let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "connection.outgoing", message: &message })?; }
                _ => {}
            }
        }
    }
    relay_admission.set_draining(true);
    registry.set_draining(true);
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while (registry_admission.inflight() > 0 || admission.inflight() > 0)
        && tokio::time::Instant::now() < drain_deadline
    {
        let Ok(event) = tokio::time::timeout_at(drain_deadline, swarm.select_next_some()).await
        else {
            break;
        };
        match event {
            SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Auth(
                RequestResponseEvent::ResponseSent { request_id, .. },
            ))
            | SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Auth(
                RequestResponseEvent::InboundFailure { request_id, .. },
            )) => {
                admission.response_delivered(request_id, chrono_like_now());
            }
            SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Registry(
                RequestResponseEvent::ResponseSent {
                    peer,
                    connection_id,
                    request_id,
                    ..
                },
            ))
            | SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Registry(
                RequestResponseEvent::InboundFailure {
                    peer,
                    connection_id,
                    request_id,
                    ..
                },
            )) => {
                registry_admission.release(peer, request_id, connection_id);
            }
            SwarmEvent::ConnectionClosed { connection_id, .. } => {
                registry_admission.close_connection(connection_id);
                admission.close_connection(connection_id);
            }
            SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Registry(
                RequestResponseEvent::Message {
                    message:
                        RequestResponseMessage::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                let request_id = match request {
                    p2x_protocol::RegistryRequestV1::Register { request_id, .. }
                    | p2x_protocol::RegistryRequestV1::Refresh { request_id, .. }
                    | p2x_protocol::RegistryRequestV1::Withdraw { request_id, .. } => request_id,
                };
                let response = p2x_protocol::RegistryResponseV1::Rejected {
                    request_id: Some(request_id),
                    error: PublicError::new(PublicErrorCode::ExchangeDraining, true),
                };
                let _ = swarm
                    .behaviour_mut()
                    .registry
                    .send_response(channel, response);
            }
            SwarmEvent::Behaviour(p2x_net::builder::ExchangeEvent::Auth(
                RequestResponseEvent::Message {
                    message:
                        RequestResponseMessage::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                let request_id = match request {
                    p2x_protocol::AuthRequest::Authenticate { request_id, .. }
                    | p2x_protocol::AuthRequest::Ping { request_id, .. } => request_id,
                };
                let response = AuthResponse::Rejected {
                    request_id: Some(request_id),
                    error: PublicError::new(PublicErrorCode::ExchangeDraining, true),
                };
                let _ = swarm.behaviour_mut().auth.send_response(channel, response);
            }
            _ => {}
        }
    }
    registry.clear();
    relay_admission.clear();
    sessions.clear();
    reserved_servers.clear();
    registry_admission.shutdown();
    admission.shutdown(chrono_like_now());
    active_circuits = 0;
    emitter.emit(&LifecycleRecord::ExchangeResources {
        sessions: sessions.len(),
        relay_admissions: relay_admission.len(),
        reservations: reserved_servers.len(),
        circuits: active_circuits,
        registrations: registry.len(),
        selector_owners: registry.owner_count(),
        auth_requests: admission.inflight(),
        registry_requests: registry_admission.inflight(),
    })?;
    emitter.terminal(&TerminalResult::simple(
        &args.case_id,
        "stopped",
        "shutdown",
    ))?;
    Ok(())
}
