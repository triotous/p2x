#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| if data.len() <= 4096 { let _ = p2x_net::auth_codec::decode_auth_frame(data);
    let _ = p2x_net::auth_codec::decode_auth_request(data); let _ = p2x_net::auth_codec::decode_auth_response(data); });
