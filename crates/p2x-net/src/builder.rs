use libp2p::StreamProtocol;

pub const IDENTIFY_PROTOCOL: &str = "/p2x/connectivity/0.1.0";
pub const PROBE_PROTOCOL: StreamProtocol = StreamProtocol::new("/p2x/spike/1");
pub const MAX_STREAMS: usize = 256;
pub const MAX_NEGOTIATIONS: usize = 64;
pub const PROBE_TIMEOUT_SECONDS: u64 = 5;
pub const IDLE_TIMEOUT_SECONDS: u64 = 120;

pub fn supported_protocols() -> [StreamProtocol; 1] {
    [PROBE_PROTOCOL]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spike_protocol_surface_is_explicit() {
        assert_eq!(supported_protocols()[0].as_ref(), "/p2x/spike/1");
        assert_eq!(MAX_STREAMS, 256);
        assert_eq!(MAX_NEGOTIATIONS, 64);
    }
}
