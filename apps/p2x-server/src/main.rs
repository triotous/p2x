use clap::Parser;
use libp2p::identity;
use std::io;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, hide = true)]
    identity_seed: Option<u64>,
    #[arg(
        long,
        help = "Lab-only: bind a non-loopback relay; firewall it to test peers"
    )]
    unsafe_lab_public_relay: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let key = identity::Keypair::generate_ed25519();
    println!(
        "{{\"component\":\"server\",\"peer_id\":\"{}\",\"started\":true}}",
        key.public().to_peer_id()
    );
    tokio::signal::ctrl_c().await?;
    eprintln!("server cancellation received");
    let _ = (args.identity_seed, args.unsafe_lab_public_relay);
    Ok(())
}
