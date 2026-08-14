use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

pub const MAX_HEADER: usize = 4096;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMode {
    NonceEcho,
    HalfClose,
    SlowReader,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeHeader {
    pub mode: ProbeMode,
    pub nonce: u64,
    pub length: u64,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    #[error("header exceeds {MAX_HEADER} bytes")]
    TooLarge,
    #[error("truncated frame")]
    Truncated,
    #[error("invalid header: {0}")]
    Invalid(String),
}

pub fn decode_header(bytes: &[u8]) -> Result<ProbeHeader, ProbeError> {
    if bytes.len() > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|e| ProbeError::Invalid(e.to_string()))
}
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, ProbeError> {
    let mut prefix = [0; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| ProbeError::Truncated)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| ProbeError::Truncated)?;
    Ok(body)
}
pub fn write_frame<W: Write>(writer: &mut W, body: &[u8]) -> Result<(), ProbeError> {
    if body.len() > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    writer
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|_| ProbeError::Truncated)?;
    writer.write_all(body).map_err(|_| ProbeError::Truncated)
}
pub fn pattern_byte(offset: u64) -> u8 {
    (offset % 251) as u8
}
pub fn pattern_hash(length: u64) -> u64 {
    (0..length)
        .map(pattern_byte)
        .fold(1469598103934665603, |hash, byte| {
            (hash ^ byte as u64).wrapping_mul(1099511628211)
        })
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
    fn rejects_oversized_declared_length_before_body() {
        assert_eq!(
            read_frame(&mut (MAX_HEADER as u32 + 1).to_be_bytes().as_slice()),
            Err(ProbeError::TooLarge)
        );
    }
    #[test]
    fn rejects_truncated_frame() {
        assert_eq!(
            read_frame(&mut &[0, 0, 0, 2, b'{'][..]),
            Err(ProbeError::Truncated)
        );
    }
    #[test]
    fn mode_is_closed_and_pattern_is_streamable() {
        assert!(
            serde_json::from_str::<ProbeHeader>(r#"{"mode":"unknown","nonce":1,"length":0}"#)
                .is_err()
        );
        assert_eq!(pattern_byte(251), 0);
        assert_ne!(pattern_hash(1), pattern_hash(2));
    }
}
