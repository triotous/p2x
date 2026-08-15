use futures::StreamExt;
use libp2p::{
    request_response::{Event, Message},
    swarm::SwarmEvent,
};
use p2x_net::builder::{
    ExchangeEvent, ExchangeSwarmConfig, PeerEvent, PeerSwarmConfig, build_exchange_swarm,
    build_peer_swarm, start_exchange_listeners, start_peer_listeners,
};
use p2x_protocol::{AuthRequest, AuthResponse, QuotaProfile, Role, Tenant};
use std::time::Duration;

async fn run_auth_round_trip(quic: bool) {
    let exchange_config = ExchangeSwarmConfig {
        tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        ..Default::default()
    };
    let peer_config = PeerSwarmConfig {
        tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        mode: p2x_net::builder::RuntimeMode::Product,
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
    peer.dial(exchange_address).unwrap();

    let authenticate_id = [11; 16];
    let ping_id = [12; 16];
    let mut authenticated = false;
    let mut ping_sent = false;
    let exchange_peer = *exchange.local_peer_id();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = exchange.select_next_some() => if let SwarmEvent::Behaviour(ExchangeEvent::Auth(Event::Message { peer: remote, message: Message::Request { request, channel, .. }, .. })) = event {
                    let response = match request {
                        AuthRequest::Authenticate { request_id, .. } => AuthResponse::Authenticated {
                            request_id,
                            session_id: [21; 16],
                            tenant: Tenant::new("test").unwrap(),
                            role: Role::Client,
                            scopes: 1,
                            quota_profile: QuotaProfile::new("standard").unwrap(),
                            authorization_revision: 1,
                            expires_at: 2_000_000_000,
                            exchange_features: 0,
                        },
                        AuthRequest::Ping { request_id, nonce, .. } => AuthResponse::Pong {
                            request_id,
                            nonce,
                            exchange_time: 1_000,
                        },
                    };
                    exchange.behaviour_mut().auth.send_response(channel, response).unwrap();
                    let _ = remote;
                },
                event = peer.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == exchange_peer => {
                        peer.behaviour_mut().auth.send_request(&exchange_peer, AuthRequest::Authenticate {
                            request_id: authenticate_id,
                            credential_id: p2x_protocol::CredentialId::new("test").unwrap(),
                            token_secret: [7; 32],
                            requested_role: Role::Client,
                            supported_features: 0,
                        });
                    }
                    SwarmEvent::Behaviour(PeerEvent::Auth(Event::Message { peer: remote, message: Message::Response { response, .. }, .. })) => {
                    match response {
                        AuthResponse::Authenticated { request_id, session_id, .. } => {
                            assert_eq!(request_id, authenticate_id);
                            assert_eq!(session_id, [21; 16]);
                            authenticated = true;
                            peer.behaviour_mut().auth.send_request(&remote, AuthRequest::Ping { request_id: ping_id, session_id, nonce: 99 });
                            ping_sent = true;
                        }
                        AuthResponse::Pong { request_id, nonce, .. } => {
                            assert!(authenticated && ping_sent);
                            assert_eq!(request_id, ping_id);
                            assert_eq!(nonce, 99);
                            break;
                        }
                        AuthResponse::Rejected { .. } => panic!("auth round trip rejected"),
                    }
                    }
                    _ => {}
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("auth event timeout"),
            }
        }
    })
    .await
    .expect("auth round trip timeout");
}

#[tokio::test]
async fn auth_round_trip_over_tcp() {
    run_auth_round_trip(false).await;
}

#[tokio::test]
async fn auth_round_trip_over_quic() {
    run_auth_round_trip(true).await;
}
