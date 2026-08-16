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
    io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
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
    #[arg(long, value_enum, default_value_t = RelayProfileArg::DefaultLab)]
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
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RelayProfileArg {
    DefaultLab,
    LimitTest,
}

impl From<RelayProfileArg> for RelayProfile {
    fn from(value: RelayProfileArg) -> Self {
        match value {
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
    let mut sessions = AuthSessionLedger::default();
    let mut admission = match (args.auth_limit_connections, args.auth_limit_requests) {
        (Some(connections), Some(requests)) => AdmissionLedger::with_limits(connections, requests),
        _ => AdmissionLedger::default(),
    };
    let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(1));
    let config = ExchangeSwarmConfig {
        tcp_listen: args.tcp_listen,
        quic_listen: args.quic_listen,
        allow_public: args.unsafe_lab_public_relay,
        relay_profile: args.relay_profile.into(),
        mode: if args.unsafe_connectivity_lab {
            RuntimeMode::ConnectivityLab
        } else {
            RuntimeMode::Product
        },
    };
    let mut swarm = build_exchange_swarm(key, &config).map_err(io::Error::other)?;
    start_exchange_listeners(&mut swarm, &config).map_err(io::Error::other)?;
    let local_peer = swarm.local_peer_id().to_string();
    emitter.emit(&LifecycleRecord::Started {
        peer_id: &local_peer,
    })?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = maintenance.tick() => {
                sessions.sweep(chrono_like_now());
                admission.sweep(chrono_like_now());
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { listener_id, address } => {
                    swarm.add_external_address(address.clone());
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
                    let response = if let Some(provider) = provider.as_ref() { handle_request(provider, &mut sessions, &peer.to_string(), request, chrono_like_now()) } else { AuthResponse::Rejected { request_id: wire_request_id, error: PublicError::new(PublicErrorCode::AuthSessionRequired, false) } };
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
                SwarmEvent::Behaviour(event) => { let message = format!("{event:?}"); emitter.emit(&LifecycleRecord::OperationalError { code: "relay.event", message: &message })?; }
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => { let peer = peer_id.to_string(); let ip = endpoint.get_remote_address().iter().find_map(|p| match p { libp2p::multiaddr::Protocol::Ip4(v) => Some(v.to_string()), libp2p::multiaddr::Protocol::Ip6(v) => Some(v.to_string()), _ => None }).unwrap_or_else(|| "<unknown>".into()); if admission.admit_connection(connection_id, &peer, &ip) != Admission::Accepted { swarm.close_connection(connection_id); continue; } sessions.connection_established(&peer, connection_id); emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Established, path: Some(if endpoint.is_relayed() { p2x_net::probe::ProbePath::Relay } else { p2x_net::probe::ProbePath::Direct }), reason: None })?; }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, cause, .. } => { let peer = peer_id.to_string(); sessions.connection_closed(&peer, connection_id); admission.close_connection(connection_id); let reason = format!("{cause:?}"); emitter.emit(&LifecycleRecord::ConnectionObserved { peer_id: &peer, connection_id_hash: stable_hash(connection_id), state: ConnectionState::Closed, path: None, reason: Some(&reason) })?; }
                SwarmEvent::IncomingConnectionError { error, .. } => { let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "connection.incoming", message: &message })?; }
                SwarmEvent::OutgoingConnectionError { error, .. } => { let message = error.to_string(); emitter.emit(&LifecycleRecord::OperationalError { code: "connection.outgoing", message: &message })?; }
                _ => {}
            }
        }
    }
    admission.shutdown(chrono_like_now());
    emitter.terminal(&TerminalResult::simple(
        &args.case_id,
        "stopped",
        "shutdown",
    ))?;
    Ok(())
}
