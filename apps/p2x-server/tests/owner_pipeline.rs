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
use p2x_server::ticket_admission::{TicketAdmission, TicketAdmissionLedger};
use std::collections::BTreeMap;

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

#[test]
fn actual_resolution_ticket_flows_through_server_owner_once() {
    let exchange = PeerId::random();
    let client = PeerId::random();
    let server = PeerId::random();
    let tenant = Tenant::new("tenant").unwrap();
    let selector = p2x_protocol::UnscopedSelector::new(
        p2x_protocol::ProtocolClass::Http,
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
    let capabilities = Capabilities::from_bits(15).unwrap();

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
    let mut admission = TicketAdmissionLedger::new(8, 0).unwrap();
    let candidate = admission
        .verify_candidate(&ring, open.ticket.as_bytes(), 1)
        .unwrap();
    let first = admission.authorize_candidate(
        candidate.clone(),
        exchange,
        client,
        server,
        &tenant,
        &service,
        Some(registration_revision),
        registration_expires_at,
        1,
        &open,
        1,
    );
    let stream_id = match first {
        TicketAdmission::Authorized(stream_id) => stream_id,
        rejected => panic!("server admission owner rejected: {rejected:?}"),
    };
    assert_ne!(stream_id, [0; 16]);
    assert_eq!(
        admission.authorize_candidate(
            candidate,
            exchange,
            client,
            server,
            &tenant,
            &service,
            Some(registration_revision),
            registration_expires_at,
            1,
            &open,
            1,
        ),
        TicketAdmission::Rejected(p2x_protocol::PublicErrorCode::AuthTicketReplayed)
    );
}
