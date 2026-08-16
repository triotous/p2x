#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= p2x_net::MAX_REGISTRY_FRAME + 4 {
        let protocol = libp2p::StreamProtocol::new(p2x_net::REGISTRY_PROTOCOL);
        let mut request_codec = p2x_net::RegistryCodec;
        let mut request_cursor = futures::io::Cursor::new(data);
        let _ = futures::executor::block_on(libp2p::request_response::Codec::read_request(
            &mut request_codec,
            &protocol,
            &mut request_cursor,
        ));
        let mut response_codec = p2x_net::RegistryCodec;
        let mut response_cursor = futures::io::Cursor::new(data);
        let _ = futures::executor::block_on(libp2p::request_response::Codec::read_response(
            &mut response_codec,
            &protocol,
            &mut response_cursor,
        ));
    }
});
