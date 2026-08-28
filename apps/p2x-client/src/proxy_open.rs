use futures::io::{AsyncRead, AsyncWrite};
use p2x_net::proxy_codec;
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicErrorCode};
use std::time::Duration;

pub async fn open_accepted_stream<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    open: &OpenProxyStreamV1,
    timeout: Duration,
) -> Result<([u8; 16], [u8; 16], T), PublicErrorCode> {
    tokio::time::timeout(timeout, async {
        proxy_codec::write_open(&mut stream, open)
            .await
            .map_err(|_| PublicErrorCode::ProtocolMalformed)?;
        match proxy_codec::read_response(&mut stream)
            .await
            .map_err(|_| PublicErrorCode::ProtocolMalformed)?
        {
            ProxyOpenResponseV1::Accepted {
                request_id,
                stream_id,
                selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp,
            } if request_id == open.request_id => Ok((request_id, stream_id, stream)),
            ProxyOpenResponseV1::Rejected { request_id, error }
                if request_id == Some(open.request_id) || request_id.is_none() =>
            {
                Err(error.code)
            }
            ProxyOpenResponseV1::Rejected { .. } => Err(PublicErrorCode::ProtocolMalformed),
            ProxyOpenResponseV1::Authorized { .. } => {
                Err(PublicErrorCode::ProtocolCapabilityMismatch)
            }
            _ => Err(PublicErrorCode::ProtocolMalformed),
        }
    })
    .await
    .map_err(|_| PublicErrorCode::PeerSetupTimeout)?
}
