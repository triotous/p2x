#![no_main]
use libfuzzer_sys::fuzz_target;
use p2x_proxy::tls::ClientHelloInspector;

fuzz_target!(|input: &[u8]| {
    if input.len() <= 256 * 1024 {
        if let Ok(mut inspector) = ClientHelloInspector::new(64 * 1024) {
            let _ = inspector.feed(input);
        }
    }
});
