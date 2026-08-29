use libp2p::{PeerId, swarm::ConnectionId};
use p2x_config::ticket_key::{TicketKey, VerificationKey, VerificationKeyRing};
use p2x_exchange::{
    auth_sessions::AuthSession, authn::AuthPrincipal, registry::Registry, resolution::Resolver,
};
use p2x_protocol::{
    Capabilities, CredentialId, Health, IngressKind, InstanceId, OpenProxyStreamV1, QuotaProfile,
    RegistryRequestV1, RegistryResponseV1, ResolveRequestV1, ResolveResponseV1, Role, Scope,
    ServiceAdvertisementV1, ServiceSet, Tenant, TokenDigest, UpstreamId,
};
use p2x_server::{
    proxy_open::{Candidate, ProxyWorkerId, ServerDecision},
    proxy_owner::{ProxyDecisionContext, ServerProxyOwner},
    ticket_admission::TicketAdmissionLedger,
    upstream,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::{compat::TokioAsyncReadCompatExt, sync::CancellationToken};

fn session(peer: PeerId, role: Role, scopes: u32, tenant: &Tenant) -> AuthSession {
    AuthSession {
        session_id: [2; 16],
        principal: AuthPrincipal {
            peer_id: peer.to_string(),
            credential_id: CredentialId::new("owner-pipeline").unwrap(),
            tenant: tenant.clone(),
            role,
            scopes,
            quota_profile: QuotaProfile::new("standard").unwrap(),
            authorization_revision: 1,
            credential_not_before: 0,
            credential_expires_at: 100,
            credential_digest: TokenDigest::from_bytes([0; 32]),
        },
        established_at: 0,
        expires_at: 100,
    }
}

#[tokio::test]
async fn actual_resolution_ticket_flows_through_server_owner_once() {
    let exchange = PeerId::random();
    let client = PeerId::random();
    let server = PeerId::random();
    let tenant = Tenant::new("tenant").unwrap();
    let selector = p2x_protocol::UnscopedSelector::new(
        p2x_protocol::ProtocolClass::Tcp,
        BTreeMap::from([(
            p2x_protocol::MetadataKey::new("service").unwrap(),
            p2x_protocol::MetadataValue::new("orders").unwrap(),
        )]),
    )
    .unwrap();
    let service = ServiceAdvertisementV1::new(
        UpstreamId::new("orders").unwrap(),
        selector.clone(),
        Health::Ready,
    );
    let capabilities = Capabilities::from_bits(31).unwrap();

    let mut registry = Registry::default();
    registry.set_advertise_addresses(vec![format!("/ip4/127.0.0.1/tcp/1/p2p/{exchange}")]);
    let registered = registry
        .register(
            server,
            &tenant,
            Role::Server,
            Scope::RegisterServices.bit(),
            &QuotaProfile::new("standard").unwrap(),
            1,
            true,
            RegistryRequestV1::Register {
                request_id: [3; 16],
                session_id: [2; 16],
                instance_id: InstanceId::new([4; 16]),
                requested_lease_seconds: 30,
                capabilities,
                services: ServiceSet::new(vec![service.clone()]).unwrap(),
            },
            1,
        )
        .unwrap();
    let (registration_revision, registration_expires_at) = match registered {
        RegistryResponseV1::Registered {
            registration_revision,
            expires_at,
            ..
        } => (registration_revision, expires_at),
        _ => panic!("registration owner did not register"),
    };

    let signing_key = TicketKey::from_seed([9; 32]);
    let mut resolver = Resolver::new(exchange, &signing_key);
    let resolve_request = ResolveRequestV1::Resolve {
        request_id: [5; 16],
        session_id: [2; 16],
        selector,
        client_capabilities: capabilities,
    };
    let response = resolver.resolve_and_authorize(
        client,
        ConnectionId::new_unchecked(1),
        &resolve_request,
        "owner-wire",
        Some(&session(
            client,
            Role::Client,
            Scope::OpenProxyStream.bit(),
            &tenant,
        )),
        |_| {
            Some(session(
                server,
                Role::Server,
                Scope::RegisterServices.bit(),
                &tenant,
            ))
        },
        |_| true,
        &registry,
        1,
    );
    let (ticket, upstream_id, resolved_revision) = match response {
        ResolveResponseV1::Resolved {
            ticket,
            upstream_id,
            registration_revision,
            ..
        } => (ticket, upstream_id, registration_revision),
        rejected => panic!("resolution owner rejected: {rejected:?}"),
    };
    assert_eq!(resolver.issued(), 1);
    assert_eq!(resolved_revision, registration_revision);

    let open = OpenProxyStreamV1 {
        request_id: [5; 16],
        ticket,
        upstream_id,
        registration_revision,
        ingress_kind: IngressKind::FixedTcp,
    };
    let mut ring = VerificationKeyRing::default();
    ring.add(VerificationKey {
        key_id: signing_key.key_id(),
        public: signing_key.public(),
        activates_at: 0,
        retires_at: None,
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let upstream_connections = Arc::new(AtomicUsize::new(0));
    let observed_connections = upstream_connections.clone();
    let echo = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        observed_connections.fetch_add(1, Ordering::Relaxed);
        let mut buffer = [0; 4096];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            socket.write_all(&buffer[..count]).await.unwrap();
        }
    });
    let verification_admission = TicketAdmissionLedger::new(8, 0).unwrap();
    let candidate = verification_admission
        .verify_candidate(&ring, open.ticket.as_bytes(), 1)
        .unwrap();
    let config_path =
        std::env::temp_dir().join(format!("p2x-owner-service-{}", std::process::id()));
    std::fs::write(
        &config_path,
        format!(
            "schema_version: 1\nregistration: {{}}\nservices:\n- upstream_id: orders\n  selector:\n    protocol: tcp\n    metadata: {{service: orders}}\n  enabled: true\n  connect: {}\n  connect_timeout_ms: 1000\n  idle_timeout_ms: 1000\n  concurrency_limit: 1\nproxy:\n  max_workers: 1\n  max_workers_per_client: 1\n  max_upstream_dials: 1\n  copy_buffer_bytes: 32768\n  max_replay_entries: 8\n  ticket_clock_skew: 0\n",
            upstream_address
        ),
    )
    .unwrap();
    let service_config = p2x_server::config::ServiceConfig::load(&config_path).unwrap();
    let mut owner = ServerProxyOwner::new(
        TicketAdmissionLedger::new(8, 0).unwrap(),
        Some(service_config),
    );
    let (decision_tx, _decision_rx) = tokio::sync::oneshot::channel();
    let candidate_for_owner = Candidate {
        worker_id: ProxyWorkerId(1),
        peer_id: client,
        connection_id: ConnectionId::new_unchecked(1),
        selected_path: p2x_net::probe::ProbePath::Direct,
        deadline: std::time::Instant::now() + Duration::from_secs(5),
        open: Ok(open.clone()),
        validation: Ok(candidate.clone()),
        decision: decision_tx,
    };
    let decision = owner.decide(
        &candidate_for_owner,
        ProxyDecisionContext {
            issuer: exchange,
            server,
            tenant: &tenant,
            registration_revision: Some(registration_revision),
            registration_expires_at,
            authorization_revision: 1,
            now: 1,
        },
    );
    let (stream_id, token, upstream, copy_buffer_bytes) = match decision {
        ServerDecision::Admit {
            stream_id,
            admission,
            upstream,
            copy_buffer_bytes,
        } => {
            assert_eq!(stream_id, admission.stream_id);
            (stream_id, admission, upstream, copy_buffer_bytes)
        }
        ServerDecision::Reject(response) => {
            panic!("production owner rejected valid open: {response:?}")
        }
    };
    let socket = upstream::connect(&upstream, Duration::from_secs(1), CancellationToken::new())
        .await
        .unwrap();
    owner.promote(ProxyWorkerId(1), token).unwrap();
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let accepted = p2x_protocol::ProxyOpenResponseV1::Accepted {
        request_id: open.request_id,
        stream_id,
        selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp,
    };
    let accepted_for_worker = accepted.clone();
    let pump_task = tokio::spawn(async move {
        let mut server_stream = server_stream.compat();
        p2x_net::proxy_codec::write_response(&mut server_stream, &accepted_for_worker)
            .await
            .unwrap();
        p2x_proxy::pump(
            server_stream,
            socket.compat(),
            copy_buffer_bytes,
            Duration::from_secs(1),
            futures::future::pending(),
        )
        .await
        .unwrap()
    });
    let accepted = p2x_protocol::ProxyOpenResponseV1::Accepted {
        request_id: open.request_id,
        stream_id,
        selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp,
    };
    let mut client_stream = client_stream.compat();
    assert_eq!(
        p2x_net::proxy_codec::read_response(&mut client_stream)
            .await
            .unwrap(),
        accepted
    );
    futures::io::AsyncWriteExt::write_all(&mut client_stream, b"opaque-owner-bytes")
        .await
        .unwrap();
    let mut response = [0; 18];
    futures::io::AsyncReadExt::read_exact(&mut client_stream, &mut response)
        .await
        .unwrap();
    assert_eq!(&response, b"opaque-owner-bytes");
    futures::io::AsyncWriteExt::close(&mut client_stream)
        .await
        .unwrap();
    let pump = pump_task.await.unwrap();
    assert_eq!(pump.local_to_remote_bytes, 18);
    assert_eq!(pump.remote_to_local_bytes, 18);
    assert_eq!(pump.terminal, p2x_proxy::Terminal::Complete);
    assert_eq!(upstream_connections.load(Ordering::Relaxed), 1);
    assert!(owner.release(token));
    assert!(owner.stream_admission().is_empty());
    let (replay_tx, _replay_rx) = tokio::sync::oneshot::channel();
    let replay = Candidate {
        worker_id: ProxyWorkerId(2),
        peer_id: client,
        connection_id: ConnectionId::new_unchecked(1),
        selected_path: p2x_net::probe::ProbePath::Direct,
        deadline: std::time::Instant::now() + Duration::from_secs(5),
        open: Ok(open),
        validation: Ok(candidate),
        decision: replay_tx,
    };
    assert!(matches!(
        owner.decide(
            &replay,
            ProxyDecisionContext {
                issuer: exchange,
                server,
                tenant: &tenant,
                registration_revision: Some(registration_revision),
                registration_expires_at,
                authorization_revision: 1,
                now: 1,
            },
        ),
        ServerDecision::Reject(p2x_protocol::ProxyOpenResponseV1::Rejected { error, .. })
            if error.code == p2x_protocol::PublicErrorCode::AuthTicketReplayed
    ));
    assert_eq!(upstream_connections.load(Ordering::Relaxed), 1);
    let _ = std::fs::remove_file(config_path);
    echo.abort();
}
