use futures::StreamExt;
use libp2p::{
    request_response::{Event, Message},
    swarm::SwarmEvent,
};
use p2x_net::builder::{
    ExchangeEvent, ExchangeSwarmConfig, PeerEvent, PeerSurface, PeerSwarmConfig,
    build_exchange_swarm, build_peer_swarm, start_exchange_listeners, start_peer_listeners,
};
use p2x_protocol::{
    Capabilities, RawTicket, RegistrationRevision, ResolveRequestV1, ResolveResponseV1, UpstreamId,
};
use std::{collections::BTreeMap, time::Duration};

fn super_request() -> ResolveRequestV1 {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        p2x_protocol::MetadataKey::new("service").unwrap(),
        p2x_protocol::MetadataValue::new("orders").unwrap(),
    );
    ResolveRequestV1::Resolve {
        request_id: [1; 16],
        session_id: [2; 16],
        selector: p2x_protocol::UnscopedSelector::new(p2x_protocol::ProtocolClass::Http, metadata)
            .unwrap(),
        client_capabilities: Capabilities::RELAY_V2,
    }
}

async fn run_resolve_over(quic: bool) {
    let exchange_config = ExchangeSwarmConfig {
        tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        ..Default::default()
    };
    let client_config = PeerSwarmConfig {
        tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        surface: PeerSurface::ProductClient,
        auth_fault: None,
    };
    let exchange_key = libp2p::identity::Keypair::generate_ed25519();
    let server_peer = libp2p::PeerId::random();
    let exchange_peer = libp2p::PeerId::from_public_key(&exchange_key.public());
    let mut exchange = build_exchange_swarm(exchange_key, &exchange_config).unwrap();
    let mut client = build_peer_swarm(
        libp2p::identity::Keypair::generate_ed25519(),
        &client_config,
    )
    .unwrap();
    start_exchange_listeners(&mut exchange, &exchange_config).unwrap();
    start_peer_listeners(&mut client, &client_config).unwrap();

    let exchange_address = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = exchange.select_next_some().await
                && ((quic && address.to_string().contains("/quic-v1"))
                    || (!quic && address.to_string().contains("/tcp/")))
            {
                break address.with(libp2p::multiaddr::Protocol::P2p(exchange_peer));
            }
        }
    })
    .await
    .expect("exchange listener timeout");
    client.dial(exchange_address).unwrap();
    let mut sent = false;

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = exchange.select_next_some() => if let SwarmEvent::Behaviour(ExchangeEvent::Resolve(Event::Message { message: Message::Request { request, channel, .. }, .. })) = event {
                    assert_eq!(request, super_request());
                    let relay = format!(
                        "/ip4/127.0.0.1/tcp/1/p2p/{exchange_peer}/p2p-circuit/p2p/{server_peer}"
                    ).parse::<libp2p::Multiaddr>().unwrap().to_vec();
                    exchange.behaviour_mut().resolve.send_response(channel, ResolveResponseV1::Resolved {
                        request_id: [1; 16],
                        server_peer_id: server_peer.to_bytes(),
                        upstream_id: UpstreamId::new("orders").unwrap(),
                        selector_fingerprint: [3; 32],
                        registration_revision: RegistrationRevision::new(7).unwrap(),
                        relay_addresses: vec![relay],
                        compatible_capabilities: Capabilities::RELAY_V2,
                        registration_expires_at: 1000,
                        ticket_expires_at: 30,
                        ticket: RawTicket::new(vec![7; 16]).unwrap(),
                    }).unwrap();
                },
                event = client.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == exchange_peer && !sent => {
                        client.behaviour_mut().resolve.send_request(&exchange_peer, super_request());
                        sent = true;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Resolve(Event::Message { message: Message::Response { response, .. }, .. })) => {
                        match response {
                            ResolveResponseV1::Resolved { server_peer_id, upstream_id, registration_revision, relay_addresses, ticket, .. } => {
                                assert_eq!(server_peer_id, server_peer.to_bytes());
                                assert_eq!(upstream_id.as_str(), "orders");
                                assert_eq!(registration_revision.get(), 7);
                                assert_eq!(relay_addresses.len(), 1);
                                assert_eq!(ticket.as_bytes(), &[7; 16]);
                                return;
                            }
                            ResolveResponseV1::Rejected { .. } => panic!("resolve unexpectedly rejected"),
                        }
                    }
                    _ => {}
                },
            }
        }
    }).await.expect("resolve round trip timeout");
}

#[tokio::test]
async fn product_resolve_round_trip_over_tcp() {
    run_resolve_over(false).await;
}

#[tokio::test]
async fn product_resolve_round_trip_over_quic() {
    run_resolve_over(true).await;
}
