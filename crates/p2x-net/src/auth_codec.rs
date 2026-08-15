use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use p2x_protocol::frame::MAX_AUTH_FRAME;
use p2x_protocol::{
    AuthRequest, AuthResponse, CredentialId, KNOWN_AUTH_FEATURES_V1, PublicError, PublicErrorCode,
    QuotaProfile, Role, Tenant, TokenSecret,
};
use std::io;
use thiserror::Error;
use zeroize::Zeroizing;

pub const AUTH_PROTOCOL: &str = "/p2x/auth/1";
const VERSION: u8 = 1;
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthProtocolError {
    #[error("auth frame is too large")]
    FrameTooLarge,
    #[error("auth message is malformed")]
    Malformed,
    #[error("auth version is unsupported")]
    UnsupportedVersion,
    #[error("auth capabilities are unsupported")]
    CapabilityMismatch,
}
#[derive(Clone, Default)]
pub struct AuthCodec;
pub fn decode_auth_request(bytes: &[u8]) -> Result<AuthRequest, AuthProtocolError> {
    decode_request(bytes)
}
pub fn decode_auth_response(bytes: &[u8]) -> Result<AuthResponse, AuthProtocolError> {
    decode_response(bytes)
}
pub fn decode_auth_frame(frame: &[u8]) -> Result<AuthRequest, AuthProtocolError> {
    if frame.len() < 4 {
        return Err(AuthProtocolError::Malformed);
    }
    let n = u32::from_be_bytes(
        frame[..4]
            .try_into()
            .map_err(|_| AuthProtocolError::Malformed)?,
    ) as usize;
    if n == 0 || n > MAX_AUTH_FRAME {
        return Err(AuthProtocolError::FrameTooLarge);
    }
    if frame.len() != n + 4 {
        return Err(AuthProtocolError::Malformed);
    }
    decode_request(&frame[4..])
}

fn invalid() -> AuthProtocolError {
    AuthProtocolError::Malformed
}
fn version(value: u8) -> Result<(), AuthProtocolError> {
    (value == VERSION)
        .then_some(())
        .ok_or(AuthProtocolError::UnsupportedVersion)
}
fn protocol_io(error: AuthProtocolError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], AuthProtocolError> {
    let end = pos.checked_add(n).ok_or_else(invalid)?;
    let value = b.get(*pos..end).ok_or_else(invalid)?;
    *pos = end;
    Ok(value)
}
fn u16v(b: &[u8], pos: &mut usize) -> Result<u16, AuthProtocolError> {
    Ok(u16::from_be_bytes(
        take(b, pos, 2)?.try_into().map_err(|_| invalid())?,
    ))
}
fn u64v(b: &[u8], pos: &mut usize) -> Result<u64, AuthProtocolError> {
    Ok(u64::from_be_bytes(
        take(b, pos, 8)?.try_into().map_err(|_| invalid())?,
    ))
}
fn i64v(b: &[u8], pos: &mut usize) -> Result<i64, AuthProtocolError> {
    Ok(i64::from_be_bytes(
        take(b, pos, 8)?.try_into().map_err(|_| invalid())?,
    ))
}
fn text(b: &[u8], pos: &mut usize) -> Result<String, AuthProtocolError> {
    let n = u16v(b, pos)? as usize;
    String::from_utf8(take(b, pos, n)?.to_vec()).map_err(|_| invalid())
}
fn role(v: u8) -> Result<Role, AuthProtocolError> {
    match v {
        0 => Ok(Role::Client),
        1 => Ok(Role::Server),
        _ => Err(invalid()),
    }
}
fn put_text(out: &mut Vec<u8>, value: &str) -> Result<(), AuthProtocolError> {
    if value.len() > u16::MAX as usize {
        return Err(invalid());
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn encode_request(req: AuthRequest) -> Result<Zeroizing<Vec<u8>>, AuthProtocolError> {
    let mut o = Zeroizing::new(vec![VERSION]);
    match req {
        AuthRequest::Authenticate {
            request_id,
            credential_id,
            token_secret,
            requested_role,
            supported_features,
        } => {
            o.push(0);
            o.extend_from_slice(&request_id);
            put_text(&mut o, credential_id.as_str())?;
            o.extend_from_slice(token_secret.as_bytes());
            o.push(if requested_role == Role::Client { 0 } else { 1 });
            o.extend_from_slice(&supported_features.to_be_bytes());
        }
        AuthRequest::Ping {
            request_id,
            session_id,
            nonce,
        } => {
            o.push(1);
            o.extend_from_slice(&request_id);
            o.extend_from_slice(&session_id);
            o.extend_from_slice(&nonce.to_be_bytes());
        }
    }
    Ok(o)
}
fn decode_request(b: &[u8]) -> Result<AuthRequest, AuthProtocolError> {
    let mut p = 0;
    version(*take(b, &mut p, 1)?.first().ok_or_else(invalid)?)?;
    match take(b, &mut p, 1)?[0] {
        0 => {
            let request_id = take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?;
            let id = CredentialId::new(&text(b, &mut p)?).map_err(|_| invalid())?;
            let token_secret =
                TokenSecret::from_bytes(take(b, &mut p, 32)?.try_into().map_err(|_| invalid())?);
            let requested_role = role(take(b, &mut p, 1)?[0])?;
            let supported_features = u64v(b, &mut p)?;
            if supported_features & !KNOWN_AUTH_FEATURES_V1 != 0 {
                return Err(AuthProtocolError::CapabilityMismatch);
            }
            if p != b.len() {
                return Err(invalid());
            }
            Ok(AuthRequest::Authenticate {
                request_id,
                credential_id: id,
                token_secret,
                requested_role,
                supported_features,
            })
        }
        1 => {
            let request_id = take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?;
            let session_id = take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?;
            let nonce = u64v(b, &mut p)?;
            if p != b.len() {
                return Err(invalid());
            }
            Ok(AuthRequest::Ping {
                request_id,
                session_id,
                nonce,
            })
        }
        _ => Err(invalid()),
    }
}
fn encode_response(res: AuthResponse) -> Result<Vec<u8>, AuthProtocolError> {
    let mut o = vec![VERSION];
    match res {
        AuthResponse::Authenticated {
            request_id,
            session_id,
            tenant,
            role,
            scopes,
            quota_profile,
            authorization_revision,
            expires_at,
            exchange_features,
        } => {
            o.push(0);
            o.extend_from_slice(&request_id);
            o.extend_from_slice(&session_id);
            put_text(&mut o, tenant.as_str())?;
            o.push(if role == Role::Client { 0 } else { 1 });
            o.extend_from_slice(&scopes.to_be_bytes());
            put_text(&mut o, quota_profile.as_str())?;
            o.extend_from_slice(&authorization_revision.to_be_bytes());
            o.extend_from_slice(&expires_at.to_be_bytes());
            o.extend_from_slice(&exchange_features.to_be_bytes());
        }
        AuthResponse::Pong {
            request_id,
            nonce,
            exchange_time,
        } => {
            o.push(1);
            o.extend_from_slice(&request_id);
            o.extend_from_slice(&nonce.to_be_bytes());
            o.extend_from_slice(&exchange_time.to_be_bytes());
        }
        AuthResponse::Rejected { request_id, error } => {
            o.push(2);
            match request_id {
                Some(id) => {
                    o.push(1);
                    o.extend_from_slice(&id)
                }
                None => o.push(0),
            }
            put_text(&mut o, error.code.as_str())?;
            o.push(u8::from(error.retryable));
        }
    }
    Ok(o)
}
fn decode_response(b: &[u8]) -> Result<AuthResponse, AuthProtocolError> {
    let mut p = 0;
    version(take(b, &mut p, 1)?[0])?;
    let kind = take(b, &mut p, 1)?[0];
    let r = match kind {
        0 => {
            let request_id = take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?;
            let session_id = take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?;
            let tenant = Tenant::new(&text(b, &mut p)?).map_err(|_| invalid())?;
            let role = role(take(b, &mut p, 1)?[0])?;
            let scopes = u32::from_be_bytes(take(b, &mut p, 4)?.try_into().map_err(|_| invalid())?);
            let quota_profile = QuotaProfile::new(&text(b, &mut p)?).map_err(|_| invalid())?;
            let authorization_revision = u64v(b, &mut p)?;
            let expires_at = i64v(b, &mut p)?;
            let exchange_features = u64v(b, &mut p)?;
            if exchange_features & !KNOWN_AUTH_FEATURES_V1 != 0 {
                return Err(AuthProtocolError::CapabilityMismatch);
            }
            AuthResponse::Authenticated {
                request_id,
                session_id,
                tenant,
                role,
                scopes,
                quota_profile,
                authorization_revision,
                expires_at,
                exchange_features,
            }
        }
        1 => {
            let request_id = take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?;
            let nonce = u64v(b, &mut p)?;
            let exchange_time = i64v(b, &mut p)?;
            AuthResponse::Pong {
                request_id,
                nonce,
                exchange_time,
            }
        }
        2 => {
            let request_id = if take(b, &mut p, 1)?[0] == 1 {
                Some(take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?)
            } else {
                None
            };
            let code = PublicErrorCode::parse(&text(b, &mut p)?);
            let retryable = take(b, &mut p, 1)?[0];
            if retryable > 1 {
                return Err(invalid());
            };
            AuthResponse::Rejected {
                request_id,
                error: PublicError::new(code, retryable == 1),
            }
        }
        _ => return Err(invalid()),
    };
    if p != b.len() {
        return Err(invalid());
    }
    Ok(r)
}
async fn read_frame<T: AsyncRead + Unpin + Send>(io: &mut T) -> Result<Vec<u8>, AuthProtocolError> {
    let mut h = [0; 4];
    io.read_exact(&mut h)
        .await
        .map_err(|_| AuthProtocolError::Malformed)?;
    let n = u32::from_be_bytes(h) as usize;
    if n == 0 || n > MAX_AUTH_FRAME {
        return Err(AuthProtocolError::FrameTooLarge);
    }
    let mut b = vec![0; n];
    io.read_exact(&mut b)
        .await
        .map_err(|_| AuthProtocolError::Malformed)?;
    Ok(b)
}
async fn write_frame<T: AsyncWrite + Unpin + Send>(
    io: &mut T,
    b: &[u8],
) -> Result<(), AuthProtocolError> {
    if b.is_empty() || b.len() > MAX_AUTH_FRAME {
        return Err(AuthProtocolError::FrameTooLarge);
    }
    io.write_all(&(b.len() as u32).to_be_bytes())
        .await
        .map_err(|_| AuthProtocolError::Malformed)?;
    io.write_all(b)
        .await
        .map_err(|_| AuthProtocolError::Malformed)?;
    io.flush().await.map_err(|_| AuthProtocolError::Malformed)?;
    io.close().await.map_err(|_| AuthProtocolError::Malformed)
}
#[async_trait::async_trait]
impl Codec for AuthCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = AuthRequest;
    type Response = AuthResponse;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request> {
        read_frame(io)
            .await
            .and_then(|frame| decode_request(&frame))
            .map_err(protocol_io)
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        read_frame(io)
            .await
            .and_then(|frame| decode_response(&frame))
            .map_err(protocol_io)
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        r: Self::Request,
    ) -> io::Result<()> {
        write_frame(io, &encode_request(r).map_err(protocol_io)?)
            .await
            .map_err(protocol_io)
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        r: Self::Response,
    ) -> io::Result<()> {
        write_frame(io, &encode_response(r).map_err(protocol_io)?)
            .await
            .map_err(protocol_io)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use futures::io::Cursor;
    #[test]
    fn binary_round_trip() {
        let r = AuthRequest::Ping {
            request_id: [1; 16],
            session_id: [2; 16],
            nonce: 9,
        };
        let mut w = Vec::new();
        block_on(AuthCodec::write_request(
            &mut AuthCodec,
            &libp2p::StreamProtocol::new(AUTH_PROTOCOL),
            &mut w,
            r,
        ))
        .unwrap();
        let d = block_on(AuthCodec::read_request(
            &mut AuthCodec,
            &libp2p::StreamProtocol::new(AUTH_PROTOCOL),
            &mut Cursor::new(w),
        ))
        .unwrap();
        assert!(matches!(d, AuthRequest::Ping { nonce: 9, .. }));
    }
    #[test]
    fn rejects_version_capability_and_trailing() {
        for b in [vec![2, 1], vec![1, 1]] {
            let mut w = (b.len() as u32).to_be_bytes().to_vec();
            w.extend(b);
            assert!(
                block_on(AuthCodec::read_request(
                    &mut AuthCodec,
                    &libp2p::StreamProtocol::new(AUTH_PROTOCOL),
                    &mut Cursor::new(w)
                ))
                .is_err()
            )
        }
        let mut capability = encode_request(AuthRequest::Authenticate {
            request_id: [0; 16],
            credential_id: CredentialId::new("id").unwrap(),
            token_secret: TokenSecret::from_bytes([7; 32]),
            requested_role: Role::Client,
            supported_features: 0,
        })
        .unwrap()
        .to_vec();
        *capability.last_mut().unwrap() = 1;
        assert_eq!(
            decode_auth_request(&capability).err(),
            Some(AuthProtocolError::CapabilityMismatch),
            "capability decode: {:?}",
            decode_auth_request(&capability)
        );
    }
    #[test]
    fn rejects_zero_oversize_and_truncated_frames_before_decode() {
        for frame in [
            0u32.to_be_bytes().to_vec(),
            ((MAX_AUTH_FRAME as u32) + 1).to_be_bytes().to_vec(),
            vec![0, 0, 0],
        ] {
            assert!(
                block_on(AuthCodec::read_request(
                    &mut AuthCodec,
                    &libp2p::StreamProtocol::new(AUTH_PROTOCOL),
                    &mut Cursor::new(frame),
                ))
                .is_err()
            );
        }
        let mut truncated = (3u32).to_be_bytes().to_vec();
        truncated.extend_from_slice(&[VERSION, 0]);
        assert!(
            block_on(AuthCodec::read_request(
                &mut AuthCodec,
                &libp2p::StreamProtocol::new(AUTH_PROTOCOL),
                &mut Cursor::new(truncated),
            ))
            .is_err()
        );
    }
}
