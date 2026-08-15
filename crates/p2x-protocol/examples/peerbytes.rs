fn main() {
    let k = libp2p_identity::Keypair::generate_ed25519();
    println!(
        "{:?}",
        libp2p_identity::PeerId::from_public_key(&k.public()).to_bytes()
    );
}
