#![no_main]
use libfuzzer_sys::fuzz_target;
use p2x_proxy::http::{HttpRequestGate, HttpResponseGate};

fuzz_target!(|input: &[u8]| {
    if input.len() <= 128 * 1024 && input.len() >= 3 {
        let request_len = u16::from_be_bytes([input[0], input[1]]) as usize;
        let request_len = request_len.min(input.len() - 2);
        let (request_bytes, response_bytes) = input[2..].split_at(request_len);
        let stride = usize::from(input[2]).saturating_add(1);
        if let (Ok(mut requests), Ok(mut responses)) = (
            HttpRequestGate::new(16 * 1024),
            HttpResponseGate::with_limit(16 * 1024),
        ) {
            for chunk in request_bytes.chunks(stride) {
                if requests.feed(chunk).is_err() {
                    return;
                }
                for metadata in requests.take_metadata() {
                    if responses.queue_request(metadata).is_err() {
                        return;
                    }
                }
            }
            for chunk in response_bytes.chunks(stride) {
                if responses.feed(chunk).is_err() {
                    return;
                }
            }
            let _ = responses.finish_eof();
        }
    }
});
