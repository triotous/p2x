#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= p2x_net::MAX_REGISTRY_FRAME + 4 {
        let mut cursor = futures::io::Cursor::new(data);
        let mut codec = p2x_net::RegistryCodec;
        let protocol = libp2p::StreamProtocol::new(p2x_net::REGISTRY_PROTOCOL);
        let _ = futures::executor::block_on(libp2p::request_response::Codec::read_request(
            &mut codec, &protocol, &mut cursor,
        ));
    }
});
