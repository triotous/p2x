use crate::{PublicError, RegistrationRevision, UpstreamId, ticket::RawTicket};
use thiserror::Error;

pub const MAX_PROXY_HANDSHAKE_FRAME: usize = 4_096;
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressKind {
    FixedTcp,
    HttpHost,
    TlsSni,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenProxyStreamV1 {
    pub request_id: [u8; 16],
    pub ticket: RawTicket,
    pub upstream_id: UpstreamId,
    pub registration_revision: RegistrationRevision,
    pub ingress_kind: IngressKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamMode {
    Tcp,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyOpenResponseV1 {
    Authorized {
        request_id: [u8; 16],
        stream_id: [u8; 16],
    },
    Accepted {
        request_id: [u8; 16],
        stream_id: [u8; 16],
        selected_upstream_mode: UpstreamMode,
    },
    Rejected {
        request_id: Option<[u8; 16]>,
        error: PublicError,
    },
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProxyProtocolError {
    #[error("proxy handshake frame is too large")]
    FrameTooLarge,
    #[error("proxy handshake is malformed")]
    Malformed,
    #[error("proxy handshake version is unsupported")]
    UnsupportedVersion,
}
impl ProxyProtocolError {
    pub const fn public_code(self) -> crate::PublicErrorCode {
        match self {
            Self::FrameTooLarge => crate::PublicErrorCode::ProtocolFrameTooLarge,
            Self::Malformed => crate::PublicErrorCode::ProtocolMalformed,
            Self::UnsupportedVersion => crate::PublicErrorCode::ProtocolUnsupportedVersion,
        }
    }
}
fn malformed() -> ProxyProtocolError {
    ProxyProtocolError::Malformed
}
fn take<'a>(
    bytes: &'a [u8],
    position: &mut usize,
    length: usize,
) -> Result<&'a [u8], ProxyProtocolError> {
    let end = position.checked_add(length).ok_or_else(malformed)?;
    let value = bytes.get(*position..end).ok_or_else(malformed)?;
    *position = end;
    Ok(value)
}
fn u16v(bytes: &[u8], position: &mut usize) -> Result<u16, ProxyProtocolError> {
    Ok(u16::from_be_bytes(
        take(bytes, position, 2)?
            .try_into()
            .map_err(|_| malformed())?,
    ))
}
fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), ProxyProtocolError> {
    if value.len() > u16::MAX as usize {
        return Err(malformed());
    }
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}
fn text(bytes: &[u8], position: &mut usize) -> Result<String, ProxyProtocolError> {
    let length = u16v(bytes, position)? as usize;
    String::from_utf8(take(bytes, position, length)?.to_vec()).map_err(|_| malformed())
}
fn id(bytes: &[u8], position: &mut usize) -> Result<[u8; 16], ProxyProtocolError> {
    take(bytes, position, 16)?
        .try_into()
        .map_err(|_| malformed())
}
fn ingress(value: IngressKind) -> u8 {
    match value {
        IngressKind::FixedTcp => 0,
        IngressKind::HttpHost => 1,
        IngressKind::TlsSni => 2,
    }
}
fn decode_ingress(value: u8) -> Result<IngressKind, ProxyProtocolError> {
    match value {
        0 => Ok(IngressKind::FixedTcp),
        1 => Ok(IngressKind::HttpHost),
        2 => Ok(IngressKind::TlsSni),
        _ => Err(malformed()),
    }
}
fn error(output: &mut Vec<u8>, value: PublicError) -> Result<(), ProxyProtocolError> {
    put_text(output, value.code.as_str())?;
    output.push(u8::from(value.retryable));
    Ok(())
}
fn decode_error(bytes: &[u8], position: &mut usize) -> Result<PublicError, ProxyProtocolError> {
    let code =
        crate::PublicErrorCode::try_from_wire(&text(bytes, position)?).map_err(|_| malformed())?;
    let retryable = take(bytes, position, 1)?[0];
    if retryable > 1 {
        return Err(malformed());
    }
    Ok(PublicError::new(code, retryable == 1))
}
fn finish(output: Vec<u8>) -> Result<Vec<u8>, ProxyProtocolError> {
    if output.len() > MAX_PROXY_HANDSHAKE_FRAME {
        Err(ProxyProtocolError::FrameTooLarge)
    } else {
        Ok(output)
    }
}
impl OpenProxyStreamV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        let mut output = vec![VERSION, 0];
        output.extend_from_slice(&self.request_id);
        if self.ticket.as_bytes().len() > u16::MAX as usize {
            return Err(ProxyProtocolError::FrameTooLarge);
        }
        output.extend_from_slice(&(self.ticket.as_bytes().len() as u16).to_be_bytes());
        output.extend_from_slice(self.ticket.as_bytes());
        put_text(&mut output, self.upstream_id.as_str())?;
        output.extend_from_slice(&self.registration_revision.get().to_be_bytes());
        output.push(ingress(self.ingress_kind));
        finish(output)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProxyProtocolError> {
        let mut position = 0;
        if take(bytes, &mut position, 1)?[0] != VERSION {
            return Err(ProxyProtocolError::UnsupportedVersion);
        }
        if take(bytes, &mut position, 1)?[0] != 0 {
            return Err(malformed());
        }
        let request_id = id(bytes, &mut position)?;
        let ticket_length = u16v(bytes, &mut position)? as usize;
        if ticket_length == 0 {
            return Err(malformed());
        }
        let ticket = RawTicket::new(take(bytes, &mut position, ticket_length)?.to_vec())
            .map_err(|_| malformed())?;
        let upstream_id = UpstreamId::new(&text(bytes, &mut position)?).map_err(|_| malformed())?;
        let registration_revision = crate::RegistrationRevision::new(u64::from_be_bytes(
            take(bytes, &mut position, 8)?
                .try_into()
                .map_err(|_| malformed())?,
        ))
        .ok_or_else(malformed)?;
        let ingress_kind = decode_ingress(take(bytes, &mut position, 1)?[0])?;
        if position != bytes.len() {
            return Err(malformed());
        }
        Ok(Self {
            request_id,
            ticket,
            upstream_id,
            registration_revision,
            ingress_kind,
        })
    }
}
impl ProxyOpenResponseV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProxyProtocolError> {
        let mut output = vec![VERSION];
        match self {
            Self::Authorized {
                request_id,
                stream_id,
            } => {
                output.push(0);
                output.extend_from_slice(request_id);
                output.extend_from_slice(stream_id);
            }
            Self::Accepted {
                request_id,
                stream_id,
                selected_upstream_mode,
            } => {
                output.push(1);
                output.extend_from_slice(request_id);
                output.extend_from_slice(stream_id);
                match selected_upstream_mode {
                    UpstreamMode::Tcp => output.push(0),
                }
            }
            Self::Rejected {
                request_id,
                error: value,
            } => {
                output.push(2);
                match request_id {
                    Some(id) => {
                        output.push(1);
                        output.extend_from_slice(id);
                    }
                    None => output.push(0),
                }
                error(&mut output, *value)?;
            }
        }
        finish(output)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProxyProtocolError> {
        let mut position = 0;
        if take(bytes, &mut position, 1)?[0] != VERSION {
            return Err(ProxyProtocolError::UnsupportedVersion);
        }
        let response = match take(bytes, &mut position, 1)?[0] {
            0 => Self::Authorized {
                request_id: id(bytes, &mut position)?,
                stream_id: id(bytes, &mut position)?,
            },
            1 => {
                let request_id = id(bytes, &mut position)?;
                let stream_id = id(bytes, &mut position)?;
                if take(bytes, &mut position, 1)?[0] != 0 {
                    return Err(malformed());
                }
                Self::Accepted {
                    request_id,
                    stream_id,
                    selected_upstream_mode: UpstreamMode::Tcp,
                }
            }
            2 => {
                let request_id = match take(bytes, &mut position, 1)?[0] {
                    0 => None,
                    1 => Some(id(bytes, &mut position)?),
                    _ => return Err(malformed()),
                };
                Self::Rejected {
                    request_id,
                    error: decode_error(bytes, &mut position)?,
                }
            }
            _ => return Err(malformed()),
        };
        if position != bytes.len() {
            return Err(malformed());
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn open_and_all_responses_round_trip() {
        let open = OpenProxyStreamV1 {
            request_id: [1; 16],
            ticket: RawTicket::new(vec![7; 16]).unwrap(),
            upstream_id: UpstreamId::new("orders").unwrap(),
            registration_revision: RegistrationRevision::new(1).unwrap(),
            ingress_kind: IngressKind::FixedTcp,
        };
        assert_eq!(
            OpenProxyStreamV1::decode(&open.canonical_bytes().unwrap()).unwrap(),
            open
        );
        for response in [
            ProxyOpenResponseV1::Authorized {
                request_id: [1; 16],
                stream_id: [2; 16],
            },
            ProxyOpenResponseV1::Accepted {
                request_id: [1; 16],
                stream_id: [2; 16],
                selected_upstream_mode: UpstreamMode::Tcp,
            },
            ProxyOpenResponseV1::Rejected {
                request_id: None,
                error: PublicError::new(crate::PublicErrorCode::AuthTicketReplayed, false),
            },
        ] {
            assert_eq!(
                ProxyOpenResponseV1::decode(&response.canonical_bytes().unwrap()).unwrap(),
                response
            );
        }
    }
    #[test]
    fn trailing_and_unknown_values_are_rejected() {
        let response = ProxyOpenResponseV1::Authorized {
            request_id: [1; 16],
            stream_id: [2; 16],
        };
        let mut bytes = response.canonical_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            ProxyOpenResponseV1::decode(&bytes),
            Err(ProxyProtocolError::Malformed)
        );
        let mut open = OpenProxyStreamV1 {
            request_id: [1; 16],
            ticket: RawTicket::new(vec![7; 16]).unwrap(),
            upstream_id: UpstreamId::new("orders").unwrap(),
            registration_revision: RegistrationRevision::new(1).unwrap(),
            ingress_kind: IngressKind::FixedTcp,
        }
        .canonical_bytes()
        .unwrap();
        *open.last_mut().unwrap() = 9;
        assert_eq!(
            OpenProxyStreamV1::decode(&open),
            Err(ProxyProtocolError::Malformed)
        );
    }
}
