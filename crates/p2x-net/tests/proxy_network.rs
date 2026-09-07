use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::swarm::SwarmEvent;
use p2x_net::{
    builder::{PeerEvent, PeerSurface, PeerSwarmConfig, build_peer_swarm, start_peer_listeners},
    proxy_codec,
    proxy_stream::behaviour::{ProxyOutput, ProxyRequestId},
};
use p2x_protocol::{
    IngressKind, OpenProxyStreamV1, ProxyOpenResponseV1, RawTicket, RegistrationRevision,
    UpstreamId,
};
use std::time::Duration;

fn open() -> OpenProxyStreamV1 {
    OpenProxyStreamV1 {
        request_id: [1; 16],
        ticket: RawTicket::new(vec![7; 16]).unwrap(),
        upstream_id: UpstreamId::new("orders").unwrap(),
        registration_revision: RegistrationRevision::new(1).unwrap(),
        ingress_kind: IngressKind::FixedTcp,
    }
}

async fn run_proxy_over(quic: bool) {
    let config = |surface| PeerSwarmConfig {
        tcp_listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        quic_listen: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        surface,
        auth_fault: None,
    };
    let client_key = libp2p::identity::Keypair::generate_ed25519();
    let server_key = libp2p::identity::Keypair::generate_ed25519();
    let server_peer = libp2p::PeerId::from_public_key(&server_key.public());
    let mut client = build_peer_swarm(client_key, &config(PeerSurface::ProductClient)).unwrap();
    let mut server = build_peer_swarm(server_key, &config(PeerSurface::ProductServer)).unwrap();
    start_peer_listeners(&mut client, &config(PeerSurface::ProductClient)).unwrap();
    start_peer_listeners(&mut server, &config(PeerSurface::ProductServer)).unwrap();

    let server_address = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await
                && ((quic && address.to_string().contains("/quic-v1"))
                    || (!quic && address.to_string().contains("/tcp/")))
            {
                break address.with(libp2p::multiaddr::Protocol::P2p(server_peer));
            }
        }
    })
    .await
    .expect("server listener timeout");
    client.dial(server_address).unwrap();
    let mut opened: Option<ProxyRequestId> = None;
    let mut inbound = false;
    let mut client_io = false;
    let mut completed_io = 0;
    let mut io_tasks = tokio::task::JoinSet::new();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                event = client.select_next_some() => match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } if peer_id == server_peer && opened.is_none() => {
                        let request = client.behaviour_mut().proxy_stream.as_mut().unwrap().open_on(peer_id, connection_id, open()).unwrap();
                        opened = Some(request);
                    }
                    SwarmEvent::Behaviour(PeerEvent::Proxy(ProxyOutput::OutboundOpened { request_id, mut stream, .. })) if Some(request_id) == opened => {
                        client_io = true;
                        io_tasks.spawn(async move {
                            proxy_codec::write_open(&mut stream, &open()).await.unwrap();
                            let response = proxy_codec::read_response(&mut stream).await.unwrap();
                            assert_eq!(response, ProxyOpenResponseV1::Accepted { request_id: [1; 16], stream_id: [2; 16], selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp });
                            stream.write_all(b"client").await.unwrap();
                            let mut echoed = [0; 6];
                            stream.read_exact(&mut echoed).await.unwrap();
                            assert_eq!(&echoed, b"server");
                        });
                    }
                    SwarmEvent::Behaviour(PeerEvent::Proxy(ProxyOutput::OutboundFailed { code, .. })) => panic!("proxy open failed: {code}"),
                    _ => {}
                },
                event = server.select_next_some() => match event {
                    SwarmEvent::Behaviour(PeerEvent::Proxy(ProxyOutput::InboundOpened { peer_id, connection_id, mut stream })) => {
                        inbound = true;
                        server.behaviour_mut().proxy_stream.as_mut().unwrap().inbound_release_on(peer_id, connection_id);
                        io_tasks.spawn(async move {
                            let received = proxy_codec::read_open(&mut stream).await.unwrap();
                            assert_eq!(received, open());
                            proxy_codec::write_response(&mut stream, &ProxyOpenResponseV1::Accepted { request_id: [1; 16], stream_id: [2; 16], selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp }).await.unwrap();
                            let mut received_data = [0; 6];
                            stream.read_exact(&mut received_data).await.unwrap();
                            assert_eq!(&received_data, b"client");
                            stream.write_all(b"server").await.unwrap();
                        });
                    }
                    SwarmEvent::ConnectionEstablished { .. } => {}
                    _ => {}
                },
                result = io_tasks.join_next(), if !io_tasks.is_empty() => {
                    result.expect("proxy I/O task missing").expect("proxy I/O task failed");
                    completed_io += 1;
                    if client_io && inbound && completed_io == 2 {
                        return;
                    }
                }
            }
        }
    }).await.expect("proxy round trip timeout");
}

#[tokio::test]
async fn product_proxy_round_trip_over_tcp() {
    run_proxy_over(false).await;
}

#[tokio::test]
async fn product_proxy_round_trip_over_quic() {
    run_proxy_over(true).await;
}
