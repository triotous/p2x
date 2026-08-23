use base64::Engine;
use p2x_config::ticket_key::TicketKey;
use std::{env, fs, path::PathBuf};

fn main() {
    let mut args = env::args().skip(1);
    let key = PathBuf::from(args.next().expect("ticket key path"));
    let output = PathBuf::from(args.next().expect("verification output path"));
    let key = TicketKey::load(&key).expect("ticket key");
    let id = key
        .key_id()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let public = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public().as_bytes());
    fs::write(
        output,
        format!(
            "schema_version: 1\nkeys:\n  - key_id: {id}\n    public_key: {public}\n    activates_at: 0\n"
        ),
    )
    .expect("verification output");
}
