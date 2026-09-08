use crate::domain::{CanonicalDomain, DomainError};
use std::fmt;

pub const MIN_CLIENT_HELLO_BYTES: usize = 4 * 1024;
pub const MAX_CLIENT_HELLO_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientHelloResult {
    NeedMore,
    Selected {
        domain: CanonicalDomain,
        prefix_len: usize,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsError {
    Limit,
    Malformed,
    Unsupported,
    MissingSni,
    InvalidSni,
}
impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit => "TLS ClientHello limit exceeded",
            Self::Malformed => "malformed TLS ClientHello",
            Self::Unsupported => "unsupported TLS record",
            Self::MissingSni => "TLS SNI is required",
            Self::InvalidSni => "invalid TLS SNI",
        })
    }
}
impl std::error::Error for TlsError {}

pub struct ClientHelloInspector {
    max_bytes: usize,
    bytes: Vec<u8>,
}
impl ClientHelloInspector {
    pub fn new(max_bytes: usize) -> Result<Self, TlsError> {
        if !(MIN_CLIENT_HELLO_BYTES..=MAX_CLIENT_HELLO_BYTES).contains(&max_bytes) {
            return Err(TlsError::Limit);
        }
        Ok(Self {
            max_bytes,
            bytes: Vec::with_capacity(max_bytes.min(16 * 1024)),
        })
    }
    pub fn into_prefix(self) -> Vec<u8> {
        self.bytes
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<ClientHelloResult, TlsError> {
        if self
            .bytes
            .len()
            .checked_add(input.len())
            .filter(|size| *size <= self.max_bytes)
            .is_none()
        {
            return Err(TlsError::Limit);
        }
        self.bytes.extend_from_slice(input);
        self.inspect()
    }

    fn inspect(&self) -> Result<ClientHelloResult, TlsError> {
        let mut offset = 0;
        let mut handshake = Vec::new();
        let handshake_limit = self.max_bytes;
        while offset < self.bytes.len() {
            if self.bytes.len() - offset < 5 {
                return Ok(ClientHelloResult::NeedMore);
            }
            let content_type = self.bytes[offset];
            let version = u16::from_be_bytes([self.bytes[offset + 1], self.bytes[offset + 2]]);
            let length =
                u16::from_be_bytes([self.bytes[offset + 3], self.bytes[offset + 4]]) as usize;
            if !(0x0301..=0x0303).contains(&version) {
                return Err(TlsError::Unsupported);
            }
            if content_type != 22 || length == 0 || length > 16_384 {
                return Err(TlsError::Malformed);
            }
            let end = offset
                .checked_add(5)
                .and_then(|value| value.checked_add(length))
                .ok_or(TlsError::Limit)?;
            if end > self.bytes.len() {
                return Ok(ClientHelloResult::NeedMore);
            }
            if handshake
                .len()
                .checked_add(length)
                .filter(|size| *size <= handshake_limit)
                .is_none()
            {
                return Err(TlsError::Limit);
            }
            handshake.extend_from_slice(&self.bytes[offset + 5..end]);
            offset = end;
            if handshake.len() >= 4 {
                let message_type = handshake[0];
                let declared = u24(&handshake[1..4])?;
                if message_type != 1 {
                    return Err(TlsError::Malformed);
                }
                let message_end = 4usize.checked_add(declared).ok_or(TlsError::Limit)?;
                if message_end > handshake_limit {
                    return Err(TlsError::Limit);
                }
                if handshake.len() >= message_end {
                    let domain = parse_client_hello(&handshake[4..message_end])?;
                    return Ok(ClientHelloResult::Selected {
                        domain,
                        prefix_len: offset,
                    });
                }
            }
        }
        Ok(ClientHelloResult::NeedMore)
    }
}

fn u24(value: &[u8]) -> Result<usize, TlsError> {
    if value.len() != 3 {
        return Err(TlsError::Malformed);
    }
    Ok(((value[0] as usize) << 16) | ((value[1] as usize) << 8) | value[2] as usize)
}
fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], TlsError> {
    let end = offset.checked_add(length).ok_or(TlsError::Malformed)?;
    let value = bytes.get(*offset..end).ok_or(TlsError::Malformed)?;
    *offset = end;
    Ok(value)
}
fn vector<'a>(bytes: &'a [u8], offset: &mut usize, width: usize) -> Result<&'a [u8], TlsError> {
    let length = match width {
        1 => *take(bytes, offset, 1)?.first().ok_or(TlsError::Malformed)? as usize,
        2 => u16::from_be_bytes(
            take(bytes, offset, 2)?
                .try_into()
                .map_err(|_| TlsError::Malformed)?,
        ) as usize,
        _ => return Err(TlsError::Malformed),
    };
    take(bytes, offset, length)
}
fn parse_client_hello(bytes: &[u8]) -> Result<CanonicalDomain, TlsError> {
    let mut offset = 0;
    let version = u16::from_be_bytes(
        take(bytes, &mut offset, 2)?
            .try_into()
            .map_err(|_| TlsError::Malformed)?,
    );
    if !(0x0301..=0x0303).contains(&version) {
        return Err(TlsError::Unsupported);
    }
    take(bytes, &mut offset, 32)?;
    let session = vector(bytes, &mut offset, 1)?;
    if session.len() > 32 {
        return Err(TlsError::Malformed);
    }
    let suites = vector(bytes, &mut offset, 2)?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(TlsError::Malformed);
    }
    let compression = vector(bytes, &mut offset, 1)?;
    if compression.is_empty() {
        return Err(TlsError::Malformed);
    }
    let extensions = vector(bytes, &mut offset, 2)?;
    if offset != bytes.len() {
        return Err(TlsError::Malformed);
    }
    let mut extension_offset = 0;
    let mut seen = Vec::new();
    let mut sni = None;
    while extension_offset < extensions.len() {
        let kind = u16::from_be_bytes(
            take(extensions, &mut extension_offset, 2)?
                .try_into()
                .map_err(|_| TlsError::Malformed)?,
        );
        let value = vector(extensions, &mut extension_offset, 2)?;
        if seen.contains(&kind) {
            return Err(TlsError::Malformed);
        }
        seen.push(kind);
        if kind == 0 {
            if sni.is_some() {
                return Err(TlsError::Malformed);
            }
            let names = vector(value, &mut 0, 2)?;
            let mut name_offset = 0;
            let mut found = None;
            while name_offset < names.len() {
                let name_type = *take(names, &mut name_offset, 1)?
                    .first()
                    .ok_or(TlsError::Malformed)?;
                let name = vector(names, &mut name_offset, 2)?;
                if name_type == 0 {
                    if found.is_some() || name.is_empty() {
                        return Err(TlsError::Malformed);
                    }
                    found = Some(name);
                }
            }
            sni = found;
        }
    }
    let name = sni.ok_or(TlsError::MissingSni)?;
    if !name.is_ascii() {
        return Err(TlsError::InvalidSni);
    }
    CanonicalDomain::from_sni(std::str::from_utf8(name).map_err(|_| TlsError::InvalidSni)?)
        .map_err(map_domain)
}
fn map_domain(error: DomainError) -> TlsError {
    match error {
        DomainError::TooLong => TlsError::Limit,
        _ => TlsError::InvalidSni,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hello(name: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend([0, 2, 0, 47]);
        body.extend([1, 0]);
        let mut extensions = vec![0, 0];
        let mut sni = vec![0, (name.len() + 3) as u8, 0, 0, name.len() as u8];
        sni.extend_from_slice(name);
        extensions.extend((sni.len() as u16).to_be_bytes());
        extensions.extend(sni);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut handshake = vec![1];
        handshake.extend([
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        handshake.extend(body);
        let mut record = vec![22, 3, 3];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }
    #[test]
    fn selects_only_after_complete_structural_hello() {
        let input = hello(b"Example.com");
        let mut inspector = ClientHelloInspector::new(4096).unwrap();
        for byte in input.iter().take(input.len() - 1) {
            assert_eq!(
                inspector.feed(&[*byte]).unwrap(),
                ClientHelloResult::NeedMore
            );
        }
        assert_eq!(
            inspector.feed(&input[input.len() - 1..]).unwrap(),
            ClientHelloResult::Selected {
                domain: CanonicalDomain::from_sni("example.com").unwrap(),
                prefix_len: input.len()
            }
        );
    }
    #[test]
    fn rejects_missing_or_duplicate_sni_and_preserves_limit() {
        let mut input = hello(b"example.com");
        let at = input.len();
        input.extend_from_slice(&[22, 3, 3, 0, 4, 1, 0, 0, 0]);
        let mut inspector = ClientHelloInspector::new(4096).unwrap();
        assert!(
            matches!(inspector.feed(&input), Ok(ClientHelloResult::Selected { prefix_len, .. }) if prefix_len == at)
        );
        let mut inspector = ClientHelloInspector::new(4096).unwrap();
        assert_eq!(
            inspector.feed(&hello(b"bad name")),
            Err(TlsError::InvalidSni)
        );
    }
}
