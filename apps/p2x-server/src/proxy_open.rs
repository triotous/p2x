use libp2p::{PeerId, swarm::ConnectionId};
use p2x_net::proxy_codec;
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicError, PublicErrorCode};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub struct Candidate {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub open: Result<OpenProxyStreamV1, PublicErrorCode>,
    pub decision: oneshot::Sender<ProxyOpenResponseV1>,
}

pub async fn run_worker(
    peer_id: PeerId,
    connection_id: ConnectionId,
    mut stream: libp2p::swarm::Stream,
    candidates: mpsc::Sender<Candidate>,
) {
    let (decision, response) = oneshot::channel();
    let open = tokio::time::timeout(Duration::from_secs(5), proxy_codec::read_open(&mut stream))
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(PublicErrorCode::ProtocolMalformed);
    let request_id = open.as_ref().ok().map(|open| open.request_id);
    if candidates
        .send(Candidate {
            peer_id,
            connection_id,
            open,
            decision,
        })
        .await
        .is_err()
    {
        return;
    }
    let response = response
        .await
        .unwrap_or_else(|_| ProxyOpenResponseV1::Rejected {
            request_id,
            error: PublicError::new(PublicErrorCode::ExchangeOverloaded, true),
        });
    let _ = proxy_codec::write_response(&mut stream, &response).await;
}

pub fn random_stream_id() -> Result<[u8; 16], PublicErrorCode> {
    let mut stream_id = [0; 16];
    getrandom::fill(&mut stream_id).map_err(|_| PublicErrorCode::ExchangeOverloaded)?;
    Ok(stream_id)
}
