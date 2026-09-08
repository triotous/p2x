use crate::domain::{CanonicalDomain, DomainError};
use base64::Engine;
use httparse::{Request, Response};
use std::{collections::VecDeque, fmt};

pub const MAX_HTTP_FIELDS: usize = 128;
pub const MAX_HTTP_METADATA: usize = 256;
pub const MAX_PENDING_REQUESTS: usize = 32;
pub const MAX_INFORMATIONAL_RESPONSES: u8 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpError {
    Limit,
    Malformed,
    MissingHost,
    AuthorityMismatch,
    Unsupported,
    InvalidFraming,
    Timeout,
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
            Self::Timeout => "HTTP ingress parse timed out",
        })
    }
}
impl std::error::Error for HttpError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestAuthority {
    pub domain: CanonicalDomain,
    pub port: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestMetadata {
    pub head_response: bool,
    pub upgrade: bool,
    pub connection_close: bool,
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
    AwaitUpgrade,
}

pub struct HttpRequestGate {
    max_head: usize,
    buffer: Vec<u8>,
    state: RequestState,
    locked: Option<RequestAuthority>,
    requests: usize,
    metadata: VecDeque<RequestMetadata>,
    close: bool,
    opaque: bool,
    stopped: bool,
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
            metadata: VecDeque::new(),
            close: false,
            opaque: false,
            stopped: false,
        })
    }

    pub fn locked_authority(&self) -> Option<&RequestAuthority> {
        self.locked.as_ref()
    }

    pub fn max_head(&self) -> usize {
        self.max_head
    }

    pub fn take_metadata(&mut self) -> impl Iterator<Item = RequestMetadata> + '_ {
        self.metadata.drain(..)
    }

    pub fn close(&mut self) {
        self.close = true;
    }

    pub fn upgrade_declined(&mut self) -> Result<Vec<u8>, HttpError> {
        if !matches!(self.state, RequestState::AwaitUpgrade) {
            return Ok(Vec::new());
        }
        self.state = RequestState::Head;
        let buffered = std::mem::take(&mut self.buffer);
        self.feed(&buffered)
    }

    pub fn release_opaque(&mut self) -> Vec<u8> {
        self.opaque = true;
        self.buffer.drain(..).collect()
    }

    pub fn at_message_boundary(&self) -> bool {
        self.buffer.is_empty()
            && matches!(self.state, RequestState::Head | RequestState::AwaitUpgrade)
    }

    pub fn is_opaque(&self) -> bool {
        self.opaque
    }

    pub fn is_waiting_for_upgrade(&self) -> bool {
        !self.opaque && matches!(self.state, RequestState::AwaitUpgrade)
    }

    pub fn has_buffered_input(&self) -> bool {
        !self.buffer.is_empty()
    }

    pub fn upload_in_progress(&self) -> bool {
        matches!(
            self.state,
            RequestState::Fixed(_)
                | RequestState::ChunkLine
                | RequestState::ChunkData(_)
                | RequestState::ChunkCrlf
                | RequestState::Trailers
        )
    }

    pub fn stop_upload(&mut self) {
        self.stopped = true;
        self.buffer.clear();
    }

    pub fn stopped(&self) -> bool {
        self.stopped
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<Vec<u8>, HttpError> {
        self.feed_limited(input, MAX_PENDING_REQUESTS)
    }

    pub(crate) fn feed_limited(
        &mut self,
        input: &[u8],
        available_metadata: usize,
    ) -> Result<Vec<u8>, HttpError> {
        if self.opaque {
            return Ok(input.to_vec());
        }
        let mut output = Vec::new();
        // A single bounded transport read can contain a small head followed by a
        // large body segment (or the end of one message and the next head). Keep
        // the staging allocation bounded by the transport contract while the
        // state-specific parsers enforce their tighter syntax limits below.
        let limit = self.max_head.max(crate::MAX_COPY_BUFFER);
        if self
            .buffer
            .len()
            .checked_add(input.len())
            .is_none_or(|size| size > limit)
        {
            return Err(HttpError::Limit);
        }
        self.buffer.extend_from_slice(input);
        loop {
            let progressed = match self.state {
                RequestState::Head if self.metadata.len() >= available_metadata => false,
                RequestState::Head => self.parse_head(&mut output)?,
                RequestState::Fixed(remaining) => {
                    let count = (remaining as usize).min(self.buffer.len());
                    output.extend(self.buffer.drain(..count));
                    self.state = if remaining == count as u64 {
                        RequestState::Head
                    } else {
                        RequestState::Fixed(remaining - count as u64)
                    };
                    if count != 0 && matches!(self.state, RequestState::Head) {
                        break;
                    }
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
                RequestState::Trailers => {
                    let progressed = self.parse_trailers(&mut output)?;
                    if progressed {
                        break;
                    }
                    progressed
                }
                RequestState::AwaitUpgrade => false,
            };
            if !progressed {
                break;
            }
        }
        Ok(output)
    }

    fn parse_head(&mut self, output: &mut Vec<u8>) -> Result<bool, HttpError> {
        if self.metadata.len() >= MAX_PENDING_REQUESTS {
            return Ok(false);
        }
        if self.close && !self.buffer.is_empty() {
            return Err(HttpError::Unsupported);
        }
        let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_FIELDS];
        let mut request = Request::new(&mut headers);
        let status = request
            .parse(&self.buffer)
            .map_err(|_| HttpError::Malformed)?;
        let httparse::Status::Complete(head_len) = status else {
            if self.buffer.len() > self.max_head {
                return Err(HttpError::Limit);
            }
            return Ok(false);
        };
        if head_len > self.max_head {
            return Err(HttpError::Limit);
        }
        let method = request.method.ok_or(HttpError::Malformed)?;
        if method.len() > MAX_HTTP_METADATA {
            return Err(HttpError::Limit);
        }
        let path = request.path.ok_or(HttpError::Malformed)?;
        let request_line_end = find_crlf(&self.buffer).ok_or(HttpError::Malformed)?;
        let expected_line = format!("{method} {path} HTTP/1.1");
        if self.buffer[..request_line_end] != *expected_line.as_bytes() {
            return Err(HttpError::Malformed);
        }
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
        let mut websocket_version = None;
        let mut websocket_key = None;
        let mut connection_close = false;
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
                "connection" => {
                    connection_close |=
                        header_token_present(request.headers, "connection", "close");
                }
                "upgrade" => {
                    if upgrade_websocket || !header.value.eq_ignore_ascii_case(b"websocket") {
                        return Err(HttpError::Unsupported);
                    }
                    upgrade_websocket = true;
                }
                "sec-websocket-version" => {
                    if websocket_version.is_some() {
                        return Err(HttpError::Unsupported);
                    }
                    websocket_version = Some(header.value);
                }
                "sec-websocket-key" => {
                    if websocket_key.is_some() {
                        return Err(HttpError::Unsupported);
                    }
                    websocket_key = Some(header.value);
                }
                _ => {}
            }
        }
        if transfer_chunked && content_length.is_some() {
            return Err(HttpError::InvalidFraming);
        }
        if upgrade_websocket {
            if method != "GET"
                || content_length.is_some()
                || transfer_chunked
                || !header_token_present(request.headers, "connection", "upgrade")
                || websocket_version != Some(&b"13"[..])
            {
                return Err(HttpError::Unsupported);
            }
            let key = websocket_key.ok_or(HttpError::Unsupported)?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(key)
                .map_err(|_| HttpError::Unsupported)?;
            if decoded.len() != 16 {
                return Err(HttpError::Unsupported);
            }
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
        } else if let Some(length) = content_length.filter(|length| *length != 0) {
            Body::Fixed(length)
        } else {
            Body::None
        };
        let head_response = method.eq_ignore_ascii_case("HEAD");
        let head = self.buffer.drain(..head_len).collect::<Vec<_>>();
        output.extend_from_slice(&head);
        self.requests = self.requests.checked_add(1).ok_or(HttpError::Limit)?;
        self.metadata.push_back(RequestMetadata {
            head_response,
            upgrade: upgrade_websocket,
            connection_close,
        });
        self.close |= connection_close;
        self.state = match body {
            Body::None if upgrade_websocket => RequestState::AwaitUpgrade,
            Body::None => RequestState::Head,
            Body::Fixed(length) => RequestState::Fixed(length),
            Body::Chunked => RequestState::ChunkLine,
        };
        Ok(!matches!(
            self.state,
            RequestState::Head | RequestState::AwaitUpgrade
        ))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeDecision {
    None,
    Declined,
    Accepted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseMetadata {
    pub status: u16,
    pub informational: bool,
    pub no_body: bool,
    pub close_delimited: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBody {
    Head,
    Fixed(u64),
    ChunkLine,
    ChunkData(u64),
    ChunkCrlf,
    Trailers,
    Close,
    Opaque,
}

pub struct HttpResponseGate {
    max_head: usize,
    requests: VecDeque<RequestMetadata>,
    buffer: Vec<u8>,
    body: ResponseBody,
    close: bool,
    upgraded: bool,
    pending_upgrade: bool,
    response_active: bool,
    informational: u8,
    final_started: bool,
}
impl Default for HttpResponseGate {
    fn default() -> Self {
        Self::new()
    }
}
impl HttpResponseGate {
    pub fn new() -> Self {
        Self::with_limit(64 * 1024).expect("valid HTTP response head limit")
    }

    pub fn with_limit(max_head: usize) -> Result<Self, HttpError> {
        if !(1..=64 * 1024).contains(&max_head) {
            return Err(HttpError::Limit);
        }
        Ok(Self {
            max_head,
            requests: VecDeque::new(),
            buffer: Vec::new(),
            body: ResponseBody::Head,
            close: false,
            upgraded: false,
            pending_upgrade: false,
            response_active: false,
            informational: 0,
            final_started: false,
        })
    }

    pub fn queue_request(&mut self, metadata: RequestMetadata) -> Result<(), HttpError> {
        if self.requests.len() >= MAX_PENDING_REQUESTS {
            return Err(HttpError::Limit);
        }
        self.requests.push_back(metadata);
        Ok(())
    }

    pub fn feed(&mut self, input: &[u8]) -> Result<(Vec<u8>, UpgradeDecision), HttpError> {
        if matches!(self.body, ResponseBody::Opaque) {
            return Ok((input.to_vec(), UpgradeDecision::None));
        }
        let limit = self.max_head.max(crate::MAX_COPY_BUFFER);
        if self
            .buffer
            .len()
            .checked_add(input.len())
            .is_none_or(|size| size > limit)
        {
            return Err(HttpError::Limit);
        }
        self.final_started = false;
        self.buffer.extend_from_slice(input);
        let mut output = Vec::new();
        let mut decision = UpgradeDecision::None;
        loop {
            match self.body {
                ResponseBody::Head => {
                    if self.close && !self.buffer.is_empty() {
                        return Err(HttpError::InvalidFraming);
                    }
                    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_FIELDS];
                    let mut response = Response::new(&mut headers);
                    let status = match response
                        .parse(&self.buffer)
                        .map_err(|_| HttpError::Malformed)?
                    {
                        httparse::Status::Complete(size) => size,
                        httparse::Status::Partial => {
                            if self.buffer.len() > self.max_head {
                                return Err(HttpError::Limit);
                            }
                            break;
                        }
                    };
                    if status > self.max_head {
                        return Err(HttpError::Limit);
                    }
                    if response.version != Some(1) {
                        return Err(HttpError::Unsupported);
                    }
                    let code = response.code.ok_or(HttpError::Malformed)?;
                    let informational = code < 200;
                    if code == 101 && !self.requests.front().is_some_and(|request| request.upgrade)
                    {
                        return Err(HttpError::Unsupported);
                    }
                    let metadata = if informational && code != 101 {
                        self.informational =
                            self.informational.checked_add(1).ok_or(HttpError::Limit)?;
                        if self.informational > MAX_INFORMATIONAL_RESPONSES {
                            return Err(HttpError::Limit);
                        }
                        None
                    } else {
                        if self.response_active {
                            return Err(HttpError::Malformed);
                        }
                        Some(self.requests.front().ok_or(HttpError::Malformed)?.clone())
                    };
                    let mut content_length = None;
                    let mut chunked = false;
                    let mut response_close = false;
                    let mut websocket = false;
                    for header in response.headers.iter() {
                        if !valid_field_name(header.name.as_bytes())
                            || header.value.iter().any(|b| b.is_ascii_control())
                        {
                            return Err(HttpError::Malformed);
                        }
                        match header.name.to_ascii_lowercase().as_str() {
                            "content-length" => {
                                if content_length.is_some()
                                    || header.value.is_empty()
                                    || !header.value.iter().all(u8::is_ascii_digit)
                                {
                                    return Err(HttpError::InvalidFraming);
                                }
                                content_length = Some(parse_decimal(header.value)?);
                            }
                            "transfer-encoding" => {
                                if chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                                    return Err(HttpError::InvalidFraming);
                                }
                                chunked = true;
                            }
                            "connection" => {
                                response_close |=
                                    header_token_present(response.headers, "connection", "close")
                            }
                            "upgrade" => {
                                websocket |= header.value.eq_ignore_ascii_case(b"websocket")
                            }
                            _ => {}
                        }
                    }
                    if chunked && content_length.is_some() {
                        return Err(HttpError::InvalidFraming);
                    }
                    let request = metadata.as_ref();
                    let no_body = informational
                        || request.is_some_and(|request| request.head_response)
                        || code == 204
                        || code == 304;
                    if response_close {
                        self.close = true;
                    }
                    let upgrade = request.is_some_and(|request| request.upgrade);
                    if code == 101 && upgrade {
                        if !websocket
                            || !header_token_present(response.headers, "connection", "upgrade")
                        {
                            return Err(HttpError::Malformed);
                        }
                        self.requests.pop_front();
                        self.response_active = false;
                        self.upgraded = true;
                        decision = UpgradeDecision::Accepted;
                        self.body = ResponseBody::Opaque;
                        self.informational = 0;
                    } else if informational {
                        self.body = ResponseBody::Head;
                    } else {
                        self.final_started = true;
                        if upgrade {
                            self.pending_upgrade = true;
                        }
                        self.body = if no_body {
                            ResponseBody::Head
                        } else if chunked {
                            ResponseBody::ChunkLine
                        } else if let Some(length) = content_length {
                            ResponseBody::Fixed(length)
                        } else {
                            self.close = true;
                            ResponseBody::Close
                        };
                    }
                    if !informational && !matches!(self.body, ResponseBody::Opaque) {
                        self.response_active = true;
                        self.informational = 0;
                    }
                    output.extend(self.buffer.drain(..status));
                    if matches!(self.body, ResponseBody::Opaque) {
                        output.append(&mut self.buffer);
                        break;
                    }
                    if matches!(self.body, ResponseBody::Head) {
                        if self.response_active {
                            self.requests.pop_front();
                            self.response_active = false;
                        }
                        if self.pending_upgrade {
                            self.pending_upgrade = false;
                            decision = UpgradeDecision::Declined;
                        }
                        continue;
                    }
                }
                ResponseBody::Fixed(remaining) => {
                    let count = remaining.min(self.buffer.len() as u64) as usize;
                    output.extend(self.buffer.drain(..count));
                    self.body = if count as u64 == remaining {
                        self.requests.pop_front();
                        self.response_active = false;
                        if self.pending_upgrade {
                            self.pending_upgrade = false;
                            decision = UpgradeDecision::Declined;
                        }
                        ResponseBody::Head
                    } else {
                        ResponseBody::Fixed(remaining - count as u64)
                    };
                    if count == 0 {
                        break;
                    }
                }
                ResponseBody::ChunkLine => {
                    let Some(end) = find_crlf(&self.buffer) else {
                        if self.buffer.len() > 1_024 {
                            return Err(HttpError::Limit);
                        }
                        break;
                    };
                    let line = self.buffer[..end].to_vec();
                    let size = line
                        .split(|b| *b == b';')
                        .next()
                        .ok_or(HttpError::Malformed)?;
                    if size.is_empty() || size.len() > 16 || !size.iter().all(u8::is_ascii_hexdigit)
                    {
                        return Err(HttpError::Malformed);
                    }
                    let size = u64::from_str_radix(
                        std::str::from_utf8(size).map_err(|_| HttpError::Malformed)?,
                        16,
                    )
                    .map_err(|_| HttpError::Malformed)?;
                    output.extend(self.buffer.drain(..end + 2));
                    self.body = if size == 0 {
                        ResponseBody::Trailers
                    } else {
                        ResponseBody::ChunkData(size)
                    };
                }
                ResponseBody::ChunkData(remaining) => {
                    let count = remaining.min(self.buffer.len() as u64) as usize;
                    output.extend(self.buffer.drain(..count));
                    self.body = if count as u64 == remaining {
                        ResponseBody::ChunkCrlf
                    } else {
                        ResponseBody::ChunkData(remaining - count as u64)
                    };
                    if count == 0 {
                        break;
                    }
                }
                ResponseBody::ChunkCrlf => {
                    if self.buffer.len() < 2 {
                        break;
                    }
                    if self.buffer[..2] != *b"\r\n" {
                        return Err(HttpError::Malformed);
                    }
                    output.extend(self.buffer.drain(..2));
                    self.body = ResponseBody::ChunkLine;
                }
                ResponseBody::Trailers => {
                    let Some(end) = find_double_crlf(&self.buffer) else {
                        if self.buffer.len() > self.max_head {
                            return Err(HttpError::Limit);
                        }
                        break;
                    };
                    validate_trailers(&self.buffer[..end + 2])?;
                    output.extend(self.buffer.drain(..end + 4));
                    self.body = ResponseBody::Head;
                    self.requests.pop_front();
                    self.response_active = false;
                    if self.pending_upgrade {
                        self.pending_upgrade = false;
                        decision = UpgradeDecision::Declined;
                    }
                }
                ResponseBody::Close | ResponseBody::Opaque => {
                    output.append(&mut self.buffer);
                    break;
                }
            }
        }
        Ok((output, decision))
    }

    pub fn pending_requests(&self) -> usize {
        self.requests.len()
    }

    pub fn take_final_started(&mut self) -> bool {
        std::mem::take(&mut self.final_started)
    }

    pub fn pending_upgrade(&self) -> bool {
        self.pending_upgrade || self.requests.front().is_some_and(|request| request.upgrade)
    }

    pub fn finish_eof(&mut self) -> Result<(), HttpError> {
        if matches!(self.body, ResponseBody::Opaque) {
            return Ok(());
        }
        if matches!(self.body, ResponseBody::Close) {
            self.requests.pop_front().ok_or(HttpError::Malformed)?;
            self.body = ResponseBody::Head;
            self.response_active = false;
            return Ok(());
        }
        if self.requests.is_empty() && matches!(self.body, ResponseBody::Head) {
            Ok(())
        } else {
            Err(HttpError::InvalidFraming)
        }
    }

    pub fn should_close(&self) -> bool {
        self.close
    }
    pub fn upgraded(&self) -> bool {
        self.upgraded
    }

    pub fn response(
        &mut self,
        status: u16,
        request_head: bool,
    ) -> Result<ResponseMetadata, HttpError> {
        let no_body = request_head || status == 204 || status == 304;
        Ok(ResponseMetadata {
            status,
            informational: status < 200,
            no_body,
            close_delimited: !no_body,
        })
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
    fn same_read_pipeline_holds_the_second_head_until_validation() {
        let mut gate = HttpRequestGate::new(1024).unwrap();
        let first = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let second = b"GET /secret HTTP/1.1\r\nHost: other.example\r\n\r\n";
        let input = [first.as_slice(), second.as_slice()].concat();
        assert_eq!(gate.feed(&input).unwrap(), first);
        assert_eq!(gate.feed(&[]), Err(HttpError::AuthorityMismatch));
    }

    #[test]
    fn strict_request_line_and_informational_limit_are_enforced() {
        let mut gate = HttpRequestGate::new(1024).unwrap();
        assert_eq!(
            gate.feed(b"GET  / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Err(HttpError::Malformed)
        );

        let mut request = HttpRequestGate::new(1024).unwrap();
        request
            .feed(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let mut response = HttpResponseGate::new();
        response
            .queue_request(request.take_metadata().next().unwrap())
            .unwrap();
        for _ in 0..MAX_INFORMATIONAL_RESPONSES {
            response.feed(b"HTTP/1.1 103 Early Hints\r\n\r\n").unwrap();
        }
        assert_eq!(
            response.feed(b"HTTP/1.1 103 Early Hints\r\n\r\n"),
            Err(HttpError::Limit)
        );
    }
    #[test]
    fn streams_chunked_payload_and_validates_trailers() {
        let mut gate = HttpRequestGate::new(1024).unwrap();
        let input = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nHost\r\n0\r\nX-Test: ok\r\n\r\n";
        assert_eq!(gate.feed(input).unwrap(), input);
    }
    #[test]
    fn websocket_upgrade_requires_a_valid_associated_response() {
        let mut request = HttpRequestGate::new(1024).unwrap();
        let input = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert_eq!(request.feed(input).unwrap(), input);
        let metadata = request.take_metadata().next().unwrap();
        assert!(metadata.upgrade);
        let mut response = HttpResponseGate::new();
        response.queue_request(metadata).unwrap();
        let (bytes, decision) = response
            .feed(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .unwrap();
        assert_eq!(decision, UpgradeDecision::Accepted);
        assert_eq!(bytes, b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        assert!(response.upgraded());
    }

    #[test]
    fn declined_websocket_upgrade_returns_to_http_mode() {
        let mut request = HttpRequestGate::new(1024).unwrap();
        let input = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        request.feed(input).unwrap();
        let metadata = request.take_metadata().next().unwrap();
        let mut response = HttpResponseGate::new();
        response.queue_request(metadata).unwrap();
        let (_, decision) = response
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        assert_eq!(decision, UpgradeDecision::Declined);
        assert_eq!(response.pending_requests(), 0);
    }

    #[test]
    fn response_gate_rejects_bytes_after_connection_close() {
        let mut request = HttpRequestGate::new(1024).unwrap();
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        request.feed(bytes).unwrap();
        let mut metadata = request.take_metadata();
        let mut response = HttpResponseGate::new();
        response.queue_request(metadata.next().unwrap()).unwrap();
        let (output, _) = response
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
        assert!(!output.is_empty());
        assert!(response.should_close());
        assert!(matches!(
            response.feed(b"HTTP/1.1 204 No Content\r\n\r\n"),
            Err(HttpError::InvalidFraming)
        ));
    }

    #[test]
    fn response_gate_keeps_partial_heads_and_informational_responses_associated() {
        let mut request = HttpRequestGate::new(1024).unwrap();
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        request.feed(bytes).unwrap();
        let metadata = request.take_metadata().next().unwrap();
        let mut response = HttpResponseGate::new();
        response.queue_request(metadata).unwrap();
        assert_eq!(
            response
                .feed(b"HTTP/1.1 103 Early Hints\r\n\r\n")
                .unwrap()
                .1,
            UpgradeDecision::None
        );
        let (first, _) = response
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe")
            .unwrap();
        assert_eq!(first, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe");
        let (second, _) = response.feed(b"llo").unwrap();
        assert_eq!(second, b"llo");
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
