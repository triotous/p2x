use p2x_protocol::ticket::{ConnectionTicketClaimsV1, TicketSigner};
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let c = ConnectionTicketClaimsV1 {
        issuer_exchange_peer_id: vec![
            0, 36, 8, 1, 18, 32, 107, 117, 237, 81, 229, 13, 170, 0, 121, 162, 207, 180, 128, 192,
            5, 180, 135, 200, 156, 15, 161, 190, 109, 221, 66, 55, 60, 198, 198, 8, 78, 161,
        ],
        tenant: "t".into(),
        client_peer_id: vec![
            0, 36, 8, 1, 18, 32, 107, 117, 237, 81, 229, 13, 170, 0, 121, 162, 207, 180, 128, 192,
            5, 180, 135, 200, 156, 15, 161, 190, 109, 221, 66, 55, 60, 198, 198, 8, 78, 161,
        ],
        server_peer_id: vec![
            0, 36, 8, 1, 18, 32, 107, 117, 237, 81, 229, 13, 170, 0, 121, 162, 207, 180, 128, 192,
            5, 180, 135, 200, 156, 15, 161, 190, 109, 221, 66, 55, 60, 198, 198, 8, 78, 161,
        ],
        upstream_id: "u".into(),
        selector_fingerprint: [4; 32],
        registration_revision: 1,
        authorization_revision: 2,
        permissions: 4,
        not_before: 10,
        expires_at: 20,
        ticket_id: [5; 16],
        max_streams: 1,
    };
    let s = TicketSigner::from_seed([9; 32]);
    let claims = c.encode().unwrap();
    let ticket = s.sign(&c).unwrap();
    println!(
        "claims {}\nticket {}\nkey_id {}",
        hex(&claims),
        hex(&ticket),
        hex(&s.key_id())
    );
}
