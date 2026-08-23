#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= p2x_protocol::MAX_PROXY_HANDSHAKE_FRAME + 4 {
        let _ = p2x_protocol::OpenProxyStreamV1::decode(data);
        let _ = p2x_protocol::ProxyOpenResponseV1::decode(data);
        let mut open = futures::io::Cursor::new(data);
        let _ = futures::executor::block_on(p2x_net::proxy_codec::read_open(&mut open));
        let mut response = futures::io::Cursor::new(data);
        let _ = futures::executor::block_on(p2x_net::proxy_codec::read_response(&mut response));
    }
});
