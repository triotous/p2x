use p2x_protocol::ticket::{ConnectionTicketClaimsV1, TicketSigner};

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let peer = vec![
        0, 36, 8, 1, 18, 32, 107, 117, 237, 81, 229, 13, 170, 0, 121, 162, 207, 180, 128, 192, 5,
        180, 135, 200, 156, 15, 161, 190, 109, 221, 66, 55, 60, 198, 198, 8, 78, 161,
    ];
    let c = ConnectionTicketClaimsV1::new(
        peer.clone(),
        "t".into(),
        peer.clone(),
        peer,
        "u".into(),
        [4; 32],
        1,
        2,
        4,
        10,
        20,
        [5; 16],
        1,
    )
    .unwrap();
    let s = TicketSigner::from_seed([9; 32]);
    let claims = c.encode().unwrap();
    let ticket = s.sign(&c).unwrap();
    println!(
        "claims {}\nticket {}\nkey_id {}",
        hex(&claims),
        hex(ticket.as_bytes()),
        hex(&s.key_id())
    );
}
