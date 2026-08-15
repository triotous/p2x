use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use p2x_protocol::frame::MAX_AUTH_FRAME;
use p2x_protocol::{
    AuthRequest, AuthResponse, CredentialId, PublicError, PublicErrorCode, QuotaProfile, Role,
    Tenant,
};
use std::io;

pub const AUTH_PROTOCOL: &str = "/p2x/auth/1";
const VERSION: u8 = 1;
#[derive(Clone, Default)]
pub struct AuthCodec;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed auth message")
}
fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    let end = pos.checked_add(n).ok_or_else(invalid)?;
    let value = b.get(*pos..end).ok_or_else(invalid)?;
    *pos = end;
    Ok(value)
}
fn u16v(b: &[u8], pos: &mut usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(
        take(b, pos, 2)?.try_into().map_err(|_| invalid())?,
    ))
}
fn u64v(b: &[u8], pos: &mut usize) -> io::Result<u64> {
    Ok(u64::from_be_bytes(
        take(b, pos, 8)?.try_into().map_err(|_| invalid())?,
    ))
}
fn i64v(b: &[u8], pos: &mut usize) -> io::Result<i64> {
    Ok(i64::from_be_bytes(
        take(b, pos, 8)?.try_into().map_err(|_| invalid())?,
    ))
}
fn text(b: &[u8], pos: &mut usize) -> io::Result<String> {
    let n = u16v(b, pos)? as usize;
    String::from_utf8(take(b, pos, n)?.to_vec()).map_err(|_| invalid())
}
fn role(v: u8) -> io::Result<Role> {
    match v {
        0 => Ok(Role::Client),
        1 => Ok(Role::Server),
        _ => Err(invalid()),
    }
}
fn put_text(out: &mut Vec<u8>, value: &str) -> io::Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(invalid());
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn encode_request(req: AuthRequest) -> io::Result<Vec<u8>> {
    let mut o = vec![VERSION];
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
            o.extend_from_slice(&token_secret);
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
fn decode_request(b: &[u8]) -> io::Result<AuthRequest> {
    let mut p = 0;
    if *take(b, &mut p, 1)?.first().ok_or_else(invalid)? != VERSION {
        return Err(invalid());
    }
    match take(b, &mut p, 1)?[0] {
        0 => {
            let request_id = take(b, &mut p, 16)?.try_into().map_err(|_| invalid())?;
            let id = CredentialId::new(&text(b, &mut p)?).map_err(|_| invalid())?;
            let token_secret = take(b, &mut p, 32)?.try_into().map_err(|_| invalid())?;
            let requested_role = role(take(b, &mut p, 1)?[0])?;
            let supported_features = u64v(b, &mut p)?;
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
fn encode_response(res: AuthResponse) -> io::Result<Vec<u8>> {
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
fn decode_response(b: &[u8]) -> io::Result<AuthResponse> {
    let mut p = 0;
    if take(b, &mut p, 1)?[0] != VERSION {
        return Err(invalid());
    };
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
async fn read_frame<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    io.read_exact(&mut h).await?;
    let n = u32::from_be_bytes(h) as usize;
    if n == 0 || n > MAX_AUTH_FRAME {
        return Err(invalid());
    }
    let mut b = vec![0; n];
    io.read_exact(&mut b).await?;
    Ok(b)
}
async fn write_frame<T: AsyncWrite + Unpin + Send>(io: &mut T, b: &[u8]) -> io::Result<()> {
    if b.is_empty() || b.len() > MAX_AUTH_FRAME {
        return Err(invalid());
    }
    io.write_all(&(b.len() as u32).to_be_bytes()).await?;
    io.write_all(b).await?;
    io.flush().await
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
        decode_request(&read_frame(io).await?)
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        decode_response(&read_frame(io).await?)
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        r: Self::Request,
    ) -> io::Result<()> {
        write_frame(io, &encode_request(r)?).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        r: Self::Response,
    ) -> io::Result<()> {
        write_frame(io, &encode_response(r)?).await
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
    fn rejects_version_and_trailing() {
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
    }
}
