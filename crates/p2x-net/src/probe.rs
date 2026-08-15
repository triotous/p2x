use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

pub const MAX_HEADER: usize = 4096;
pub const MAX_TRANSFER: u64 = 256 * 1024 * 1024;
pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_SLOW_DELAY_MS: u32 = 1_000;
pub const MAX_SLOW_CHUNK_SIZE: u32 = 32 * 1024;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeTerminal {
    Ok,
    Oversize,
    Malformed,
    Truncated,
    Timeout,
    Io,
    HashMismatch,
    EofMismatch,
    AdmissionRejected,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeAck {
    pub schema_version: u16,
    pub nonce: u64,
    pub request_id: u64,
    pub path: ProbePath,
    pub connection_id_hash: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_hash: u64,
    pub write_hash: u64,
    pub half_close: bool,
    pub terminal: ProbeTerminal,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbePath {
    Direct,
    Relay,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMode {
    NonceEcho,
    HalfClose,
    SlowReader,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeHeader {
    pub schema_version: u16,
    pub request_id: u64,
    pub mode: ProbeMode,
    pub nonce: u64,
    pub length: u64,
    #[serde(default)]
    pub slow_delay_ms: u32,
    #[serde(default)]
    pub slow_chunk_size: u32,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    #[error("header exceeds {MAX_HEADER} bytes")]
    TooLarge,
    #[error("truncated frame")]
    Truncated,
    #[error("operation timed out")]
    Timeout,
    #[error("invalid header: {0}")]
    Invalid(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("payload hash mismatch")]
    HashMismatch,
    #[error("expected stream EOF")]
    EofMismatch,
    #[error("probe worker admission rejected")]
    AdmissionRejected,
}

impl ProbeError {
    pub const fn terminal(&self) -> ProbeTerminal {
        match self {
            Self::TooLarge => ProbeTerminal::Oversize,
            Self::Truncated => ProbeTerminal::Truncated,
            Self::Timeout => ProbeTerminal::Timeout,
            Self::Invalid(_) => ProbeTerminal::Malformed,
            Self::Io(_) => ProbeTerminal::Io,
            Self::HashMismatch => ProbeTerminal::HashMismatch,
            Self::EofMismatch => ProbeTerminal::EofMismatch,
            Self::AdmissionRejected => ProbeTerminal::AdmissionRejected,
        }
    }
}

pub fn decode_header(bytes: &[u8]) -> Result<ProbeHeader, ProbeError> {
    if bytes.len() > MAX_HEADER {
        return Err(ProbeError::TooLarge);
    }
    let header: ProbeHeader =
        serde_json::from_slice(bytes).map_err(|e| ProbeError::Invalid(e.to_string()))?;
    if header.schema_version != SCHEMA_VERSION {
        return Err(ProbeError::Invalid("unsupported schema version".into()));
    }
    if header.length > MAX_TRANSFER {
        return Err(ProbeError::Invalid(
            "length exceeds configured transfer limit".into(),
        ));
    }
    if header.mode != ProbeMode::SlowReader
        && (header.slow_delay_ms != 0 || header.slow_chunk_size != 0)
    {
        return Err(ProbeError::Invalid(
            "slow-reader options require slow_reader mode".into(),
        ));
    }
    if header.mode == ProbeMode::SlowReader
        && (header.slow_chunk_size == 0 || header.slow_chunk_size > MAX_SLOW_CHUNK_SIZE)
    {
        return Err(ProbeError::Invalid("invalid slow-reader chunk size".into()));
    }
    if header.slow_delay_ms > MAX_SLOW_DELAY_MS {
        return Err(ProbeError::Invalid(
            "slow-reader delay exceeds profile cap".into(),
        ));
    }
    if header.mode == ProbeMode::NonceEcho && header.length != 0 {
        return Err(ProbeError::Invalid("nonce-echo length must be zero".into()));
    }
    Ok(header)
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
    fn rejects_transfer_above_configured_limit() {
        let body = serde_json::to_vec(&ProbeHeader {
            schema_version: SCHEMA_VERSION,
            request_id: 1,
            mode: ProbeMode::NonceEcho,
            nonce: 1,
            length: MAX_TRANSFER + 1,
            slow_delay_ms: 0,
            slow_chunk_size: 0,
        })
        .unwrap();
        assert!(matches!(decode_header(&body), Err(ProbeError::Invalid(_))));
    }
    #[test]
    fn ack_round_trips_with_stable_terminal_code() {
        let ack = ProbeAck {
            schema_version: SCHEMA_VERSION,
            nonce: 1,
            request_id: 2,
            path: ProbePath::Direct,
            connection_id_hash: 3,
            bytes_read: 4,
            bytes_written: 5,
            read_hash: 6,
            write_hash: 7,
            half_close: true,
            terminal: ProbeTerminal::Ok,
        };
        assert_eq!(
            serde_json::from_slice::<ProbeAck>(&serde_json::to_vec(&ack).unwrap()).unwrap(),
            ack
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

    #[test]
    fn every_error_has_a_stable_terminal_code() {
        assert_eq!(ProbeError::TooLarge.terminal(), ProbeTerminal::Oversize);
        assert_eq!(
            ProbeError::HashMismatch.terminal(),
            ProbeTerminal::HashMismatch
        );
        assert_eq!(
            ProbeError::EofMismatch.terminal(),
            ProbeTerminal::EofMismatch
        );
        assert_eq!(
            ProbeError::AdmissionRejected.terminal(),
            ProbeTerminal::AdmissionRejected
        );
    }
}
