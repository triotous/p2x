use crate::domain::{CanonicalDomain, DomainError};
use httparse::Request;
use std::fmt;

pub const MAX_HTTP_FIELDS: usize = 128;
pub const MAX_HTTP_METADATA: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpError {
    Limit,
    Malformed,
    MissingHost,
    AuthorityMismatch,
    Unsupported,
    InvalidFraming,
}
impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit => "HTTP ingress limit exceeded",
            Self::Malformed => "malformed HTTP request",
            Self::MissingHost => "HTTP Host is required",
            Self::AuthorityMismatch => "HTTP authority changed",
            Self::Unsupported => "unsupported HTTP protocol",
            Self::InvalidFraming => "invalid HTTP message framing",
        })
    }
}
impl std::error::Error for HttpError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestAuthority {
    pub domain: CanonicalDomain,
    pub port: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Body {
    None,
    Fixed(u64),
    Chunked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestState {
    Head,
    Fixed(u64),
    ChunkLine,
    ChunkData(u64),
    ChunkCrlf,
    Trailers,
}

pub struct HttpRequestGate {
    max_head: usize,
    buffer: Vec<u8>,
    state: RequestState,
    locked: Option<RequestAuthority>,
    requests: usize,
}
impl HttpRequestGate {
    pub fn new(max_head: usize) -> Result<Self, HttpError> {
        if !(1..=64 * 1024).contains(&max_head) {
            return Err(HttpError::Limit);
        }
        Ok(Self {
            max_head,
            buffer: Vec::with_capacity(max_head),
            state: RequestState::Head,
            locked: None,
            requests: 0,
        })
    }

    pub fn locked_authority(&self) -> Option<&RequestAuthority> {
        self.locked.as_ref()
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>, HttpError> {
        let mut output = Vec::new();
        self.buffer.extend_from_slice(input);
        loop {
            let progressed = match self.state {
                RequestState::Head => self.parse_head(&mut output)?,
                RequestState::Fixed(remaining) => {
                    let count = (remaining as usize).min(self.buffer.len());
                    output.extend(self.buffer.drain(..count));
                    self.state = if remaining == count as u64 {
                        RequestState::Head
                    } else {
                        RequestState::Fixed(remaining - count as u64)
                    };
                    count != 0
                }
                RequestState::ChunkLine => self.parse_chunk_line(&mut output)?,
                RequestState::ChunkData(remaining) => {
                    let count = (remaining as usize).min(self.buffer.len());
                    output.extend(self.buffer.drain(..count));
                    self.state = if remaining == count as u64 {
                        RequestState::ChunkCrlf
                    } else {
                        RequestState::ChunkData(remaining - count as u64)
                    };
                    count != 0
                }
                RequestState::ChunkCrlf => {
                    if self.buffer.len() < 2 {
                        false
                    } else if self.buffer[..2] != *b"\r\n" {
                        return Err(HttpError::Malformed);
                    } else {
                        output.extend(self.buffer.drain(..2));
                        self.state = RequestState::ChunkLine;
                        true
                    }
                }
                RequestState::Trailers => self.parse_trailers(&mut output)?,
            };
            if !progressed {
                break;
            }
        }
        Ok(output)
    }

    fn parse_head(&mut self, output: &mut Vec<u8>) -> Result<bool, HttpError> {
        if self.buffer.len() > self.max_head {
            return Err(HttpError::Limit);
        }
        let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_FIELDS];
        let mut request = Request::new(&mut headers);
        let status = request
            .parse(&self.buffer)
            .map_err(|_| HttpError::Malformed)?;
        let httparse::Status::Complete(head_len) = status else {
            return Ok(false);
        };
        let method = request.method.ok_or(HttpError::Malformed)?;
        let path = request.path.ok_or(HttpError::Malformed)?;
        if request.version != Some(1) || !valid_method(method) || !valid_target(path) {
            return Err(HttpError::Unsupported);
        }
        if path == "*" && method != "OPTIONS" {
            return Err(HttpError::Unsupported);
        }
        if path != "*" && (!path.starts_with('/') || path.starts_with("//")) {
            return Err(HttpError::Unsupported);
        }
        let mut host = None;
        let mut content_length = None;
        let mut transfer_chunked = false;
        let mut upgrade_websocket = false;
        for header in request.headers.iter() {
            let name = header.name.as_bytes();
            if !valid_field_name(name) || header.value.iter().any(|b| b.is_ascii_control()) {
                return Err(HttpError::Malformed);
            }
            if header
                .value
                .first()
                .is_some_and(|b| b.is_ascii_whitespace())
            {
                return Err(HttpError::Malformed);
            }
            match header.name.to_ascii_lowercase().as_str() {
                "host" => {
                    if host.is_some() {
                        return Err(HttpError::Malformed);
                    }
                    host =
                        Some(std::str::from_utf8(header.value).map_err(|_| HttpError::Malformed)?);
                }
                "content-length" => {
                    if content_length.is_some()
                        || header.value.is_empty()
                        || !header.value.iter().all(|b| b.is_ascii_digit())
                    {
                        return Err(HttpError::InvalidFraming);
                    }
                    content_length = Some(parse_decimal(header.value)?);
                }
                "transfer-encoding" => {
                    if transfer_chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                        return Err(HttpError::InvalidFraming);
                    }
                    transfer_chunked = true;
                }
                "upgrade" => {
                    upgrade_websocket = header.value.eq_ignore_ascii_case(b"websocket");
                }
                _ => {}
            }
        }
        if transfer_chunked && content_length.is_some() {
            return Err(HttpError::InvalidFraming);
        }
        let host = host.ok_or(HttpError::MissingHost)?;
        let (domain, port) = CanonicalDomain::from_http_authority(host).map_err(map_domain)?;
        let authority = RequestAuthority { domain, port };
        if let Some(locked) = &self.locked {
            if locked != &authority {
                return Err(HttpError::AuthorityMismatch);
            }
        } else {
            self.locked = Some(authority);
        }
        if upgrade_websocket
            && (method != "GET" || !header_token_present(request.headers, "connection", "upgrade"))
        {
            return Err(HttpError::Unsupported);
        }
        let body = if transfer_chunked {
            Body::Chunked
        } else if let Some(length) = content_length {
            Body::Fixed(length)
        } else {
            Body::None
        };
        let head = self.buffer.drain(..head_len).collect::<Vec<_>>();
        output.extend_from_slice(&head);
        self.requests = self.requests.checked_add(1).ok_or(HttpError::Limit)?;
        self.state = match body {
            Body::None => RequestState::Head,
            Body::Fixed(length) => RequestState::Fixed(length),
            Body::Chunked => RequestState::ChunkLine,
        };
        Ok(true)
    }

    fn parse_chunk_line(&mut self, output: &mut Vec<u8>) -> Result<bool, HttpError> {
        let Some(end) = find_crlf(&self.buffer) else {
            if self.buffer.len() > 1_024 {
                return Err(HttpError::Limit);
            }
            return Ok(false);
        };
        let line = self.buffer.drain(..end + 2).collect::<Vec<_>>();
        let value = &line[..end];
        let size = value
            .split(|b| *b == b';')
            .next()
            .ok_or(HttpError::Malformed)?;
        if size.is_empty() || size.len() > 16 || !size.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(HttpError::Malformed);
        }
        let size = u64::from_str_radix(std::str::from_utf8(size).unwrap_or(""), 16)
            .map_err(|_| HttpError::Malformed)?;
        output.extend_from_slice(&line);
        self.state = if size == 0 {
            RequestState::Trailers
        } else {
            RequestState::ChunkData(size)
        };
        Ok(true)
    }

    fn parse_trailers(&mut self, output: &mut Vec<u8>) -> Result<bool, HttpError> {
        let Some(end) = find_double_crlf(&self.buffer) else {
            if self.buffer.len() > self.max_head {
                return Err(HttpError::Limit);
            }
            return Ok(false);
        };
        let block = &self.buffer[..end + 4];
        validate_trailers(&block[..end + 2])?;
        output.extend(self.buffer.drain(..end + 4));
        self.state = RequestState::Head;
        Ok(true)
    }
}

fn map_domain(error: DomainError) -> HttpError {
    match error {
        DomainError::TooLong => HttpError::Limit,
        _ => HttpError::Malformed,
    }
}
fn parse_decimal(value: &[u8]) -> Result<u64, HttpError> {
    value.iter().try_fold(0u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add((byte - b'0') as u64))
            .ok_or(HttpError::InvalidFraming)
    })
}
fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b' ' && b != b'\t')
        && method != "CONNECT"
}
fn valid_target(target: &str) -> bool {
    !target
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || b == b'\t')
        && !target.contains("://")
}
fn valid_field_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}
fn tokens(value: &[u8]) -> Vec<&str> {
    std::str::from_utf8(value)
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect()
}
fn header_token_present(headers: &[httparse::Header<'_>], name: &str, token: &str) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case(name)
            && tokens(header.value)
                .iter()
                .any(|value| value.eq_ignore_ascii_case(token))
    })
}
fn find_crlf(value: &[u8]) -> Option<usize> {
    value.windows(2).position(|pair| pair == b"\r\n")
}
fn find_double_crlf(value: &[u8]) -> Option<usize> {
    value.windows(4).position(|pair| pair == b"\r\n\r\n")
}
fn validate_trailers(value: &[u8]) -> Result<(), HttpError> {
    for line in value.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let line = line.strip_suffix(b"\r").ok_or(HttpError::Malformed)?;
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            return Err(HttpError::Malformed);
        };
        let name = &line[..colon];
        if !valid_field_name(name)
            || matches!(
                std::str::from_utf8(name)
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            )
        {
            return Err(HttpError::Malformed);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseMetadata {
    pub status: u16,
    pub informational: bool,
    pub no_body: bool,
    pub close_delimited: bool,
}
#[derive(Default)]
pub struct HttpResponseGate {
    outstanding: usize,
    max_outstanding: usize,
    close: bool,
}
impl HttpResponseGate {
    pub fn new() -> Self {
        Self {
            max_outstanding: 32,
            ..Self::default()
        }
    }
    pub fn queue_request(&mut self) -> Result<(), HttpError> {
        if self.outstanding >= self.max_outstanding {
            Err(HttpError::Limit)
        } else {
            self.outstanding += 1;
            Ok(())
        }
    }
    pub fn response(
        &mut self,
        status: u16,
        request_head: bool,
    ) -> Result<ResponseMetadata, HttpError> {
        if status < 200 {
            return Ok(ResponseMetadata {
                status,
                informational: true,
                no_body: true,
                close_delimited: false,
            });
        }
        if self.outstanding == 0 {
            return Err(HttpError::Malformed);
        }
        self.outstanding -= 1;
        let no_body = request_head || status == 204 || status == 304;
        Ok(ResponseMetadata {
            status,
            informational: false,
            no_body,
            close_delimited: !no_body,
        })
    }
    pub fn should_close(&self) -> bool {
        self.close
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn holds_cross_authority_request_and_releases_valid_bytes_only() {
        let mut gate = HttpRequestGate::new(1024).unwrap();
        let a = b"GET / HTTP/1.1\r\nHost: Example.com\r\n\r\n";
        assert_eq!(gate.feed(a).unwrap(), a);
        let b = b"GET /secret HTTP/1.1\r\nHost: other.example\r\n\r\n";
        assert_eq!(gate.feed(b), Err(HttpError::AuthorityMismatch));
    }
    #[test]
    fn streams_chunked_payload_and_validates_trailers() {
        let mut gate = HttpRequestGate::new(1024).unwrap();
        let input = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nHost\r\n0\r\nX-Test: ok\r\n\r\n";
        assert_eq!(gate.feed(input).unwrap(), input);
    }
    #[test]
    fn rejects_ambiguous_lengths_and_oversized_heads() {
        let mut gate = HttpRequestGate::new(32).unwrap();
        assert_eq!(
            gate.feed(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Err(HttpError::Limit)
        );
        let mut gate = HttpRequestGate::new(1024).unwrap();
        assert_eq!(gate.feed(b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"), Err(HttpError::InvalidFraming));
    }
}
