#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = p2x_protocol::ticket::ConnectionTicketClaimsV1::decode(data); });
