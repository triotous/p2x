use futures::StreamExt;
use libp2p::{
    request_response::{Event, Message},
    swarm::SwarmEvent,
};
use p2x_net::builder::{
    ExchangeEvent, ExchangeSwarmConfig, PeerEvent, PeerSwarmConfig, RuntimeMode,
    build_exchange_swarm, build_peer_swarm, start_exchange_listeners, start_peer_listeners,
};
use p2x_protocol::selector::{MetadataKey, MetadataValue, ProtocolClass, UnscopedSelector};
use p2x_protocol::{
    Capabilities, Health, InstanceId, RegistryRequestV1, ServiceAdvertisementV1, ServiceSet,
    UpstreamId,
};
use std::{collections::BTreeMap, time::Duration};

fn request() -> RegistryRequestV1 {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        MetadataKey::new("service").unwrap(),
        MetadataValue::new("orders").unwrap(),
    );
    let service = ServiceAdvertisementV1::new(
        UpstreamId::new("orders").unwrap(),
        UnscopedSelector::new(ProtocolClass::Http, metadata).unwrap(),
        Health::Ready,
    );
    RegistryRequestV1::Register {
        request_id: [7; 16],
        session_id: [8; 16],
        instance_id: InstanceId::new([9; 16]),
        requested_lease_seconds: 30,
        capabilities: Capabilities::from_bits(7).unwrap(),
        services: ServiceSet::new(vec![service]).unwrap(),
    }
}

async fn run_registry_round_trip(quic: bool) {
    let exchange_config = ExchangeSwarmConfig {
        tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        ..Default::default()
    };
    let peer_config = PeerSwarmConfig {
        tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        mode: RuntimeMode::Product,
        relay_client_enabled: false,
        registry_enabled: true,
        auth_fault: None,
    };
    let mut exchange = build_exchange_swarm(
        libp2p::identity::Keypair::generate_ed25519(),
        &exchange_config,
    )
    .unwrap();
    let mut peer =
        build_peer_swarm(libp2p::identity::Keypair::generate_ed25519(), &peer_config).unwrap();
    start_exchange_listeners(&mut exchange, &exchange_config).unwrap();
    start_peer_listeners(&mut peer, &peer_config).unwrap();

    let exchange_address = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = exchange.select_next_some().await
                && ((quic && address.to_string().contains("/quic-v1"))
                    || (!quic && address.to_string().contains("/tcp/")))
            {
                break address.with(libp2p::multiaddr::Protocol::P2p(*exchange.local_peer_id()));
            }
        }
    })
    .await
    .expect("exchange listener timeout");
    let exchange_peer = *exchange.local_peer_id();
    peer.dial(exchange_address).unwrap();
    let mut sent = false;

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = exchange.select_next_some() => if let SwarmEvent::Behaviour(ExchangeEvent::Registry(Event::Message { peer: remote, message: Message::Request { request, channel, .. }, .. })) = event {
                    assert_eq!(remote, *peer.local_peer_id());
                    exchange.behaviour_mut().registry.send_response(channel, p2x_protocol::RegistryResponseV1::Rejected { request_id: Some([7; 16]), error: p2x_protocol::PublicError::new(p2x_protocol::PublicErrorCode::RegistryReservationRequired, true) }).unwrap();
                    let _ = request;
                },
                event = peer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == exchange_peer && !sent => {
                        peer.behaviour_mut().registry.send_request(&exchange_peer, request());
                        sent = true;
                    }
                    SwarmEvent::Behaviour(PeerEvent::Registry(Event::Message { message: Message::Response { response: p2x_protocol::RegistryResponseV1::Rejected { request_id, error }, .. }, .. })) => {
                        assert_eq!(request_id, Some([7; 16]));
                        assert_eq!(error.code, p2x_protocol::PublicErrorCode::RegistryReservationRequired);
                        break;
                    }
                    _ => {}
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("registry event timeout"),
            }
        }
    }).await.expect("registry round trip timeout");
}

#[tokio::test]
async fn registry_round_trip_over_tcp() {
    run_registry_round_trip(false).await;
}

#[tokio::test]
async fn registry_round_trip_over_quic() {
    run_registry_round_trip(true).await;
}
