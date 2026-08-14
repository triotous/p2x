use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_HEADER: usize = 4096;
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeHeader {
    pub mode: String,
    pub nonce: u64,
    pub length: u64,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    #[error("header exceeds {MAX_HEADER} bytes")]
    TooLarge,
    #[error("invalid header: {0}")]
    Invalid(String),
}
pub fn decode_header(bytes: &[u8]) -> Result<ProbeHeader, ProbeError> {
    if bytes.len() > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|e| ProbeError::Invalid(e.to_string()))
}
pub fn pattern_byte(offset: u64) -> u8 {
    (offset % 251) as u8
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_large_header() {
        assert_eq!(
            decode_header(&vec![b'x'; MAX_HEADER + 1]),
            Err(ProbeError::TooLarge)
        );
    }
    #[test]
    fn pattern_is_deterministic() {
        assert_eq!(pattern_byte(0), 0);
        assert_eq!(pattern_byte(251), 0);
    }
}
