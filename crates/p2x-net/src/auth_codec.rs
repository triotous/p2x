use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use p2x_protocol::frame::MAX_AUTH_FRAME;
use p2x_protocol::{AuthRequest, AuthResponse};
use std::io;

pub const AUTH_PROTOCOL: &str = "/p2x/auth/1";
#[derive(Clone, Default)]
pub struct AuthCodec;
async fn read<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    io.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_AUTH_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid auth frame",
        ));
    }
    let mut body = vec![0; len];
    io.read_exact(&mut body).await?;
    Ok(body)
}
async fn write<T: AsyncWrite + Unpin + Send>(io: &mut T, body: &[u8]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_AUTH_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid auth frame",
        ));
    }
    io.write_all(&(body.len() as u32).to_be_bytes()).await?;
    io.write_all(body).await?;
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
        serde_json::from_slice(&read(io).await?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed auth request"))
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response> {
        serde_json::from_slice(&read(io).await?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed auth response"))
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()> {
        let body = serde_json::to_vec(&req)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encode auth request"))?;
        write(io, &body).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()> {
        let body = serde_json::to_vec(&res)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encode auth response"))?;
        write(io, &body).await
    }
}
