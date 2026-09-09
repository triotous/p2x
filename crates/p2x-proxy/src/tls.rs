use crate::domain::{CanonicalDomain, DomainError};
use std::{collections::BTreeSet, fmt, ops::Range};

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
    record_offset: usize,
    spans: Vec<RecordSpan>,
    handshake_len: usize,
    selected: Option<CanonicalDomain>,
}
impl ClientHelloInspector {
    pub fn new(max_bytes: usize) -> Result<Self, TlsError> {
        if !(MIN_CLIENT_HELLO_BYTES..=MAX_CLIENT_HELLO_BYTES).contains(&max_bytes) {
            return Err(TlsError::Limit);
        }
        Ok(Self {
            max_bytes,
            bytes: Vec::with_capacity(max_bytes.min(16 * 1024)),
            record_offset: 0,
            spans: Vec::new(),
            handshake_len: 0,
            selected: None,
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

    fn inspect(&mut self) -> Result<ClientHelloResult, TlsError> {
        if let Some(domain) = &self.selected {
            return Ok(ClientHelloResult::Selected {
                domain: domain.clone(),
                prefix_len: self.record_offset,
            });
        }
        while self.record_offset < self.bytes.len() {
            if self.bytes.len() - self.record_offset < 5 {
                return Ok(ClientHelloResult::NeedMore);
            }
            let content_type = self.bytes[self.record_offset];
            let version = u16::from_be_bytes([
                self.bytes[self.record_offset + 1],
                self.bytes[self.record_offset + 2],
            ]);
            let length = u16::from_be_bytes([
                self.bytes[self.record_offset + 3],
                self.bytes[self.record_offset + 4],
            ]) as usize;
            if !(0x0301..=0x0303).contains(&version) {
                return Err(TlsError::Unsupported);
            }
            if content_type != 22 || length == 0 || length > 16_384 {
                return Err(TlsError::Malformed);
            }
            let end = self
                .record_offset
                .checked_add(5)
                .and_then(|value| value.checked_add(length))
                .ok_or(TlsError::Limit)?;
            if end > self.bytes.len() {
                return Ok(ClientHelloResult::NeedMore);
            }
            if self
                .handshake_len
                .checked_add(length)
                .filter(|size| *size <= self.max_bytes)
                .is_none()
            {
                return Err(TlsError::Limit);
            }
            self.spans.push(RecordSpan {
                logical_start: self.handshake_len,
                wire: self.record_offset + 5..end,
            });
            self.handshake_len += length;
            self.record_offset = end;
            if self.handshake_len >= 4 {
                let view = PayloadView {
                    wire: &self.bytes,
                    spans: &self.spans,
                };
                let mut header = Cursor::new(view, 0, self.handshake_len)?;
                let message_type = header.u8()?;
                let declared = header.u24()?;
                if message_type != 1 {
                    return Err(TlsError::Malformed);
                }
                let message_end = 4usize.checked_add(declared).ok_or(TlsError::Limit)?;
                if message_end > self.max_bytes {
                    return Err(TlsError::Limit);
                }
                if self.handshake_len >= message_end {
                    let domain = parse_client_hello(Cursor::new(view, 4, message_end)?)?;
                    self.selected = Some(domain.clone());
                    return Ok(ClientHelloResult::Selected {
                        domain,
                        prefix_len: self.record_offset,
                    });
                }
            }
        }
        Ok(ClientHelloResult::NeedMore)
    }
}

#[derive(Clone, Debug)]
struct RecordSpan {
    logical_start: usize,
    wire: Range<usize>,
}

#[derive(Clone, Copy)]
struct PayloadView<'a> {
    wire: &'a [u8],
    spans: &'a [RecordSpan],
}
impl PayloadView<'_> {
    fn byte(self, logical: usize) -> Result<u8, TlsError> {
        let index = self
            .spans
            .partition_point(|span| span.logical_start <= logical);
        let span = index
            .checked_sub(1)
            .and_then(|index| self.spans.get(index))
            .ok_or(TlsError::Malformed)?;
        let offset = logical
            .checked_sub(span.logical_start)
            .and_then(|offset| span.wire.start.checked_add(offset))
            .filter(|offset| *offset < span.wire.end)
            .ok_or(TlsError::Malformed)?;
        self.wire.get(offset).copied().ok_or(TlsError::Malformed)
    }
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    view: PayloadView<'a>,
    position: usize,
    end: usize,
}
impl<'a> Cursor<'a> {
    fn new(view: PayloadView<'a>, position: usize, end: usize) -> Result<Self, TlsError> {
        if position > end {
            return Err(TlsError::Malformed);
        }
        Ok(Self {
            view,
            position,
            end,
        })
    }
    fn remaining(self) -> usize {
        self.end - self.position
    }
    fn take(&mut self, length: usize) -> Result<Self, TlsError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(TlsError::Malformed)?;
        if end > self.end {
            return Err(TlsError::Malformed);
        }
        let value = Self::new(self.view, self.position, end)?;
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, TlsError> {
        if self.position >= self.end {
            return Err(TlsError::Malformed);
        }
        let value = self.view.byte(self.position)?;
        self.position += 1;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, TlsError> {
        Ok(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
    fn u24(&mut self) -> Result<usize, TlsError> {
        Ok(((self.u8()? as usize) << 16) | ((self.u8()? as usize) << 8) | self.u8()? as usize)
    }
    fn vector(&mut self, width: usize) -> Result<Self, TlsError> {
        let length = match width {
            1 => self.u8()? as usize,
            2 => self.u16()? as usize,
            _ => return Err(TlsError::Malformed),
        };
        self.take(length)
    }
    fn bytes(mut self) -> Result<Vec<u8>, TlsError> {
        let mut value = Vec::with_capacity(self.remaining());
        while self.remaining() != 0 {
            value.push(self.u8()?);
        }
        Ok(value)
    }
}

fn parse_client_hello(mut bytes: Cursor<'_>) -> Result<CanonicalDomain, TlsError> {
    let version = bytes.u16()?;
    if !(0x0301..=0x0303).contains(&version) {
        return Err(TlsError::Unsupported);
    }
    bytes.take(32)?;
    let session = bytes.vector(1)?;
    if session.remaining() > 32 {
        return Err(TlsError::Malformed);
    }
    let suites = bytes.vector(2)?;
    if suites.remaining() == 0 || suites.remaining() % 2 != 0 {
        return Err(TlsError::Malformed);
    }
    let compression = bytes.vector(1)?;
    if compression.remaining() == 0 {
        return Err(TlsError::Malformed);
    }
    let mut extensions = bytes.vector(2)?;
    if bytes.remaining() != 0 {
        return Err(TlsError::Malformed);
    }
    let mut seen = BTreeSet::new();
    let mut sni = None;
    while extensions.remaining() != 0 {
        let kind = extensions.u16()?;
        let mut value = extensions.vector(2)?;
        if !seen.insert(kind) {
            return Err(TlsError::Malformed);
        }
        if kind == 0 {
            if sni.is_some() {
                return Err(TlsError::Malformed);
            }
            let mut names = value.vector(2)?;
            if value.remaining() != 0 {
                return Err(TlsError::Malformed);
            }
            let mut found = None;
            while names.remaining() != 0 {
                let name_type = names.u8()?;
                let name = names.vector(2)?;
                if name_type == 0 {
                    if found.is_some() || name.remaining() == 0 || name.remaining() > 253 {
                        return Err(TlsError::Malformed);
                    }
                    found = Some(name.bytes()?);
                }
            }
            sni = found;
        }
    }
    let name = sni.ok_or(TlsError::MissingSni)?;
    if !name.is_ascii() {
        return Err(TlsError::InvalidSni);
    }
    CanonicalDomain::from_sni(std::str::from_utf8(&name).map_err(|_| TlsError::InvalidSni)?)
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
    fn fragment_records(input: &[u8], chunk: usize) -> Vec<u8> {
        let payload = &input[5..];
        let mut records = Vec::new();
        for part in payload.chunks(chunk) {
            records.extend([22, 3, 3]);
            records.extend((part.len() as u16).to_be_bytes());
            records.extend(part);
        }
        records
    }
    fn insert_extension(input: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        let extension_length_at = 50;
        let extension_at = extension_length_at + 2;
        let mut extension = Vec::new();
        extension.extend(extension_type.to_be_bytes());
        extension.extend((value.len() as u16).to_be_bytes());
        extension.extend(value);
        input.splice(extension_at..extension_at, extension.iter().copied());
        let extensions_length =
            u16::from_be_bytes([input[extension_length_at], input[extension_length_at + 1]])
                + extension.len() as u16;
        input[extension_length_at..extension_length_at + 2]
            .copy_from_slice(&extensions_length.to_be_bytes());
        let record_length = u16::from_be_bytes([input[3], input[4]]) + extension.len() as u16;
        input[3..5].copy_from_slice(&record_length.to_be_bytes());
        let body_length =
            ((input[6] as usize) << 16) | ((input[7] as usize) << 8) | input[8] as usize;
        let new_body_length = body_length + extension.len();
        input[6] = (new_body_length >> 16) as u8;
        input[7] = (new_body_length >> 8) as u8;
        input[8] = new_body_length as u8;
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

    #[test]
    fn fragmented_records_are_processed_once_and_preserved() {
        let input = fragment_records(&hello(b"example.com"), 3);
        let mut inspector = ClientHelloInspector::new(4096).unwrap();
        for split in input.chunks(2) {
            let result = inspector.feed(split).unwrap();
            if matches!(result, ClientHelloResult::Selected { .. }) {
                break;
            }
        }
        assert_eq!(inspector.into_prefix(), input);
    }

    #[test]
    fn grease_and_ech_extensions_preserve_visible_outer_sni() {
        let mut input = hello(b"outer.example.com");
        insert_extension(&mut input, 0x0a0a, &[0]);
        insert_extension(&mut input, 0xfe0d, &[1, 2, 3, 4]);
        let mut inspector = ClientHelloInspector::new(4096).unwrap();
        assert!(matches!(
            inspector.feed(&input),
            Ok(ClientHelloResult::Selected { domain, prefix_len })
                if domain == CanonicalDomain::from_sni("outer.example.com").unwrap()
                    && prefix_len == input.len()
        ));
        assert_eq!(inspector.into_prefix(), input);
    }

    #[test]
    fn sni_extension_rejects_trailing_nested_bytes() {
        let mut input = hello(b"example.com");
        let record_length = u16::from_be_bytes([input[3], input[4]]) as usize;
        input.extend_from_slice(&[]);
        let sni_extension_length_at = 54;
        input[sni_extension_length_at + 1] += 1;
        let sni_list_length_at = sni_extension_length_at + 2;
        input[sni_list_length_at + 1] += 1;
        input.push(0);
        let new_record_length = record_length + 1;
        input[3..5].copy_from_slice(&(new_record_length as u16).to_be_bytes());
        let body_length =
            ((input[6] as usize) << 16) | ((input[7] as usize) << 8) | input[8] as usize;
        let new_body_length = body_length + 1;
        input[6] = (new_body_length >> 16) as u8;
        input[7] = (new_body_length >> 8) as u8;
        input[8] = new_body_length as u8;
        let extensions_length_at = 50;
        let extensions_length =
            u16::from_be_bytes([input[extensions_length_at], input[extensions_length_at + 1]]) + 1;
        input[extensions_length_at..extensions_length_at + 2]
            .copy_from_slice(&extensions_length.to_be_bytes());
        let mut inspector = ClientHelloInspector::new(4096).unwrap();
        assert_eq!(inspector.feed(&input), Err(TlsError::Malformed));
    }
}
