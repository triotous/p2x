#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= p2x_protocol::MAX_RESOLVE_FRAME + 4 {
        let _ = p2x_protocol::ResolveRequestV1::decode(data);
        let _ = p2x_protocol::ResolveResponseV1::decode(data);
        let protocol = libp2p::StreamProtocol::new(p2x_net::RESOLVE_PROTOCOL);
        let mut request = p2x_net::ResolveCodec;
        let mut request_cursor = futures::io::Cursor::new(data);
        let _ = futures::executor::block_on(libp2p::request_response::Codec::read_request(
            &mut request,
            &protocol,
            &mut request_cursor,
        ));
        let mut response = p2x_net::ResolveCodec;
        let mut response_cursor = futures::io::Cursor::new(data);
        let _ = futures::executor::block_on(libp2p::request_response::Codec::read_response(
            &mut response,
            &protocol,
            &mut response_cursor,
        ));
    }
});
