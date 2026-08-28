use crate::{config::LocalUpstream, stream_admission::AdmissionToken};
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::{PeerId, swarm::ConnectionId};
use p2x_config::ticket_key::VerificationKeyRing;
use p2x_net::proxy_codec;
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicError, PublicErrorCode};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug)]
pub struct Release {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub admission: AdmissionToken,
}

pub enum ServerDecision {
    Admit {
        stream_id: [u8; 16],
        admission: AdmissionToken,
        upstream: Arc<LocalUpstream>,
        copy_buffer_bytes: usize,
    },
    Reject(ProxyOpenResponseV1),
}

pub struct Candidate {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub open: Result<OpenProxyStreamV1, PublicErrorCode>,
    pub validation: Result<super::ticket_admission::ValidationCandidate, PublicErrorCode>,
    pub decision: oneshot::Sender<ServerDecision>,
}

async fn read_open<T: AsyncRead + Unpin>(
    stream: &mut T,
) -> Result<OpenProxyStreamV1, PublicErrorCode> {
    proxy_codec::read_open(stream)
        .await
        .map_err(|_| PublicErrorCode::ProtocolMalformed)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_worker(
    peer_id: PeerId,
    connection_id: ConnectionId,
    mut stream: libp2p::swarm::Stream,
    verification_ring: Option<VerificationKeyRing>,
    now: i64,
    clock_skew: i64,
    hold_handshake_ms: Option<u64>,
    hold_dial_ms: Option<u64>,
    candidates: mpsc::Sender<Candidate>,
    releases: mpsc::Sender<Release>,
    promotions: mpsc::Sender<AdmissionToken>,
) {
    let (decision, response) = oneshot::channel();
    let open = tokio::time::timeout(Duration::from_secs(5), read_open(&mut stream))
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or(PublicErrorCode::ProtocolMalformed);
    let request_id = open.as_ref().ok().map(|open| open.request_id);
    if let Some(delay) = hold_handshake_ms {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let validation = match (&verification_ring, open.as_ref()) {
        (Some(ring), Ok(open)) => super::ticket_admission::TicketAdmissionLedger::new(
            super::ticket_admission::MAX_REPLAY_ENTRIES,
            clock_skew,
        )
        .expect("worker verification limits are valid")
        .verify_candidate(ring, open.ticket.as_bytes(), now),
        (None, Ok(_)) => Err(PublicErrorCode::AuthSessionRequired),
        (_, Err(_)) => Err(PublicErrorCode::ProtocolMalformed),
    };
    if candidates
        .send(Candidate {
            peer_id,
            connection_id,
            open: open.clone(),
            validation,
            decision,
        })
        .await
        .is_err()
    {
        release(&releases, peer_id, connection_id, AdmissionToken::empty()).await;
        return;
    }
    let decision = response.await.unwrap_or_else(|_| {
        ServerDecision::Reject(ProxyOpenResponseV1::Rejected {
            request_id,
            error: PublicError::new(PublicErrorCode::ExchangeOverloaded, true),
        })
    });
    let admission = match decision {
        ServerDecision::Reject(response) => {
            let _ = proxy_codec::write_response(&mut stream, &response).await;
            AdmissionToken::empty()
        }
        ServerDecision::Admit {
            stream_id,
            admission,
            upstream,
            copy_buffer_bytes,
        } => {
            let Ok(open) = open.as_ref() else {
                release(&releases, peer_id, connection_id, admission).await;
                return;
            };
            if let Some(delay) = hold_dial_ms {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            match super::upstream::connect(&upstream).await {
                Ok(socket) => {
                    let _ = promotions.send(admission).await;
                    let response = ProxyOpenResponseV1::Accepted {
                        request_id: open.request_id,
                        stream_id,
                        selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp,
                    };
                    if proxy_codec::write_response(&mut stream, &response)
                        .await
                        .is_ok()
                    {
                        let _ = p2x_proxy::pump(
                            stream,
                            tokio_util::compat::TokioAsyncReadCompatExt::compat(socket),
                            copy_buffer_bytes,
                            upstream.idle_timeout,
                            futures::future::pending(),
                        )
                        .await;
                    }
                }
                Err(error) => {
                    let response = ProxyOpenResponseV1::Rejected {
                        request_id: Some(open.request_id),
                        error: PublicError::new(error.code(), true),
                    };
                    let _ = proxy_codec::write_response(&mut stream, &response).await;
                }
            }
            admission
        }
    };
    release(&releases, peer_id, connection_id, admission).await;
}

async fn release(
    releases: &mpsc::Sender<Release>,
    peer_id: PeerId,
    connection_id: ConnectionId,
    admission: AdmissionToken,
) {
    let _ = releases
        .send(Release {
            peer_id,
            connection_id,
            admission,
        })
        .await;
}

pub async fn reject_stream<T: AsyncRead + AsyncWrite + Unpin>(
    mut stream: T,
    code: PublicErrorCode,
) {
    let request_id = proxy_codec::read_open(&mut stream)
        .await
        .ok()
        .map(|open| open.request_id);
    let response = ProxyOpenResponseV1::Rejected {
        request_id,
        error: PublicError::new(code, true),
    };
    let _ = proxy_codec::write_response(&mut stream, &response).await;
}

pub fn random_stream_id() -> Result<[u8; 16], PublicErrorCode> {
    let mut stream_id = [0; 16];
    getrandom::fill(&mut stream_id).map_err(|_| PublicErrorCode::ExchangeOverloaded)?;
    Ok(stream_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{executor::block_on, io::Cursor};
    use p2x_protocol::{IngressKind, RawTicket, RegistrationRevision, UpstreamId};

    fn open() -> OpenProxyStreamV1 {
        OpenProxyStreamV1 {
            request_id: [1; 16],
            ticket: RawTicket::new(vec![7; 16]).unwrap(),
            upstream_id: UpstreamId::new("orders").unwrap(),
            registration_revision: RegistrationRevision::new(1).unwrap(),
            ingress_kind: IngressKind::FixedTcp,
        }
    }

    fn framed_open() -> Vec<u8> {
        let body = open().canonical_bytes().unwrap();
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn open_reads_one_frame_without_waiting_for_write_half_close() {
        let mut valid = Cursor::new(framed_open());
        assert_eq!(block_on(read_open(&mut valid)).unwrap(), open());

        let mut early_data = framed_open();
        early_data.push(0x42);
        assert_eq!(
            block_on(read_open(&mut Cursor::new(early_data))).unwrap(),
            open()
        );
    }
}
