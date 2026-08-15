use p2x_net::{ConnectionBook, ConnectionId};
use std::time::Instant;

#[test]
fn test_exact_connection_direct_and_relay_coexistence() {
    let p = libp2p::PeerId::random();
    let exchange = libp2p::PeerId::random();
    let mut book = ConnectionBook::new(exchange);

    let now = Instant::now();
    let cid_relay = ConnectionId::new_unchecked(1);
    let cid_direct = ConnectionId::new_unchecked(2);

    // Simulate relay connection establishment
    let endpoint_relay = libp2p::core::ConnectedPoint::Dialer {
        address: format!("/ip4/127.0.0.1/tcp/5001/p2p/{exchange}/p2p-circuit/p2p/{p}")
            .parse()
            .unwrap(),
        role_override: libp2p::core::Endpoint::Dialer,
        port_use: libp2p::core::transport::PortUse::New,
    };
    book.on_connection_established(p, cid_relay, &endpoint_relay, now)
        .unwrap();

    // Simulate direct connection establishment (DCUtR not confirmed yet)
    let endpoint_direct = libp2p::core::ConnectedPoint::Dialer {
        address: format!("/ip4/127.0.0.1/tcp/5002/p2p/{p}").parse().unwrap(),
        role_override: libp2p::core::Endpoint::Dialer,
        port_use: libp2p::core::transport::PortUse::New,
    };
    book.on_connection_established(p, cid_direct, &endpoint_direct, now)
        .unwrap();

    // Check that direct is not yet active for selection
    assert!(book.direct(p).is_none());

    // Confirm DCUtR for direct connection
    book.on_dcutr_succeeded(p, cid_direct, now).unwrap();

    // Now direct connection should be selected
    let selected_direct = book.direct(p).unwrap();
    assert_eq!(selected_direct.connection_id, cid_direct);

    // Both direct and relay connection reside concurrently in the connection book
    assert!(book.get(p, cid_relay).is_some());
    assert!(book.get(p, cid_direct).is_some());
}
