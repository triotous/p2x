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
        "{{\"component\":\"exchange\",\"peer_id\":\"{}\",\"started\":true,\"lab_public_relay\":{}}}",
        key.public().to_peer_id(),
        args.unsafe_lab_public_relay
    );
    tokio::signal::ctrl_c().await?;
    eprintln!("exchange cancellation received");
    let _ = args.identity_seed;
    Ok(())
}
