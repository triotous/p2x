use p2x_config::{IdentityConfig, load_or_create_identity};
use std::{env, path::PathBuf};
fn main() {
    let mut args = env::args().skip(1);
    let path = PathBuf::from(args.next().expect("identity path"));
    let generate = args.next().as_deref() == Some("--generate");
    let identity = load_or_create_identity(&IdentityConfig {
        path,
        generate_if_missing: generate,
    })
    .expect("identity");
    println!("{}", identity.peer_id);
}
