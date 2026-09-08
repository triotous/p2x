#![no_main]
use libfuzzer_sys::fuzz_target;
use p2x_proxy::http::HttpRequestGate;

fuzz_target!(|input: &[u8]| {
    if input.len() <= 64 * 1024 {
        if let Ok(mut gate) = HttpRequestGate::new(16 * 1024) {
            let _ = gate.feed(input);
        }
    }
});
