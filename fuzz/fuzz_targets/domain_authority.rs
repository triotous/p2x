#![no_main]
use libfuzzer_sys::fuzz_target;
use p2x_proxy::domain::CanonicalDomain;

fuzz_target!(|input: &[u8]| {
    if input.len() <= 1024 {
        if let Ok(value) = std::str::from_utf8(input) {
            let _ = CanonicalDomain::from_config(value);
            let _ = CanonicalDomain::from_http_authority(value);
            let _ = CanonicalDomain::from_sni(value);
        }
    }
});
