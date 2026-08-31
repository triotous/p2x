use crate::{config::LocalUpstream, stream_admission::AdmissionToken};
use futures::io::{AsyncRead, AsyncWrite};
use libp2p::{PeerId, swarm::ConnectionId};
use p2x_config::ticket_key::VerificationKeyRing;
use p2x_net::{probe::ProbePath, proxy_codec};
use p2x_protocol::{OpenProxyStreamV1, ProxyOpenResponseV1, PublicError, PublicErrorCode};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

pub use crate::proxy_owner::ProxyWorkerId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestDeadlineStage {
    Verification,
    OwnerDecision,
    Promotion,
    UpstreamDial,
    AcceptedWrite,
}

impl std::str::FromStr for TestDeadlineStage {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "verification" => Ok(Self::Verification),
            "owner-decision" => Ok(Self::OwnerDecision),
            "promotion" => Ok(Self::Promotion),
            "upstream-dial" => Ok(Self::UpstreamDial),
            "accepted-write" => Ok(Self::AcceptedWrite),
            _ => Err("invalid server deadline test stage"),
        }
    }
}

impl TestDeadlineStage {
    pub const fn fault(self) -> &'static str {
        match self {
            Self::Verification => "hold_server_verification",
            Self::OwnerDecision => "hold_server_owner_decision",
            Self::Promotion => "hold_server_promotion",
            Self::UpstreamDial => "hold_server_upstream_dial",
            Self::AcceptedWrite => "hold_server_accepted_write",
        }
    }
}

pub struct Promotion {
    pub worker_id: ProxyWorkerId,
    pub admission: AdmissionToken,
    pub acknowledged: oneshot::Sender<bool>,
}

#[derive(Clone)]
pub struct Accepted {
    pub worker_id: ProxyWorkerId,
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub selected_path: ProbePath,
    pub setup_duration: Duration,
    pub request_id_hash: u64,
    pub stream_id_hash: u64,
}

pub struct Release {
    pub worker_id: ProxyWorkerId,
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub selected_path: ProbePath,
    pub setup_duration: Duration,
    pub admission: AdmissionToken,
    pub request_id_hash: u64,
    pub stream_id_hash: Option<u64>,
    pub accepted: bool,
    pub code: Option<PublicErrorCode>,
    pub pump: Option<p2x_proxy::PumpResult>,
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
    pub worker_id: ProxyWorkerId,
    pub test_deadline_stage: Option<TestDeadlineStage>,
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub selected_path: ProbePath,
    pub deadline: std::time::Instant,
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

async fn bounded_promotion(
    promotions: &mpsc::Sender<Promotion>,
    promotion: Promotion,
    deadline: std::time::Instant,
    cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        sent = tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            promotions.send(promotion),
        ) => sent.is_ok_and(|result| result.is_ok()),
    }
}

async fn bounded_ack(
    ack: oneshot::Receiver<bool>,
    deadline: std::time::Instant,
    cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        result = tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            ack,
        ) => result.is_ok_and(|result| result.unwrap_or(false)),
    }
}

async fn reserve_accepted(
    accepts: &mpsc::Sender<Accepted>,
    deadline: std::time::Instant,
    cancel: &tokio_util::sync::CancellationToken,
) -> Option<mpsc::OwnedPermit<Accepted>> {
    tokio::select! {
        _ = cancel.cancelled() => None,
        permit = tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            accepts.clone().reserve_owned(),
        ) => permit.ok().and_then(Result::ok),
    }
}

pub async fn hold_test_deadline_stage(
    delay: Duration,
    deadline: std::time::Instant,
    cancel: tokio_util::sync::CancellationToken,
) -> bool {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    tokio::select! {
        _ = cancel.cancelled() => false,
        _ = tokio::time::sleep(delay.min(remaining)) => delay <= remaining,
    }
}

async fn write_response_bounded<T: AsyncWrite + Unpin>(
    stream: &mut T,
    response: &ProxyOpenResponseV1,
    deadline: std::time::Instant,
    cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        result = tokio::time::timeout(
            deadline.saturating_duration_since(std::time::Instant::now()),
            proxy_codec::write_response(stream, response),
        ) => result.is_ok_and(|result| result.is_ok()),
    }
}

fn transition_failure_code(shutdown: &tokio_util::sync::CancellationToken) -> PublicErrorCode {
    if shutdown.is_cancelled() {
        PublicErrorCode::PeerDraining
    } else {
        PublicErrorCode::PeerSetupTimeout
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_worker(
    worker_id: ProxyWorkerId,
    peer_id: PeerId,
    connection_id: ConnectionId,
    selected_path: ProbePath,
    mut stream: libp2p::swarm::Stream,
    verification_ring: Option<VerificationKeyRing>,
    now: i64,
    clock_skew: i64,
    hold_handshake_ms: Option<u64>,
    test_deadline_stage: Option<TestDeadlineStage>,
    test_deadline_hold_ms: Option<u64>,
    test_deadline_claimed: Arc<std::sync::atomic::AtomicBool>,
    test_faults: mpsc::Sender<TestDeadlineStage>,
    hold_dial_ms: Option<u64>,
    candidates: mpsc::Sender<Candidate>,
    accepts: mpsc::Sender<Accepted>,
    promotions: mpsc::Sender<Promotion>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Release {
    let (decision, response) = oneshot::channel();
    let started = std::time::Instant::now();
    let worker_deadline = started + Duration::from_secs(5);
    let started_unix = now;
    let cancel = shutdown.child_token();
    let test_deadline_stage = test_deadline_stage.filter(|_| {
        test_deadline_claimed
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    });
    let open = tokio::select! {
        _ = cancel.cancelled() => Err(PublicErrorCode::ExchangeDraining),
        result = tokio::time::timeout(
            worker_deadline.saturating_duration_since(std::time::Instant::now()),
            read_open(&mut stream),
        ) => result
            .ok()
            .and_then(Result::ok)
            .ok_or(PublicErrorCode::ProtocolMalformed),
    };
    let request_id = open.as_ref().ok().map(|open| open.request_id);
    let verification_hold = if test_deadline_stage == Some(TestDeadlineStage::Verification) {
        if let Some(stage) = test_deadline_stage {
            let _ = test_faults.try_send(stage);
        }
        test_deadline_hold_ms
    } else {
        hold_handshake_ms
    };
    if let Some(delay) = verification_hold
        && !hold_test_deadline_stage(
            Duration::from_millis(delay),
            worker_deadline,
            cancel.clone(),
        )
        .await
    {
        let code = transition_failure_code(&shutdown);
        if let Ok(open) = open.as_ref() {
            let response = ProxyOpenResponseV1::Rejected {
                request_id: Some(open.request_id),
                error: PublicError::new(code, true),
            };
            let _ = write_response_bounded(&mut stream, &response, worker_deadline, &cancel).await;
        }
        return release(
            worker_id,
            peer_id,
            connection_id,
            selected_path,
            started.elapsed(),
            AdmissionToken::empty(),
            request_id
                .map(p2x_net::lifecycle::stable_hash)
                .unwrap_or_default(),
            None,
            false,
            Some(code),
            None,
        );
    }
    let validation = match (&verification_ring, open.as_ref()) {
        (Some(ring), Ok(open)) => super::ticket_admission::TicketAdmissionLedger::new(
            super::ticket_admission::MAX_REPLAY_ENTRIES,
            clock_skew,
        )
        .expect("worker verification limits are valid")
        .verify_candidate(
            ring,
            open.ticket.as_bytes(),
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64)
                .max(started_unix),
        ),
        (None, Ok(_)) => Err(PublicErrorCode::AuthSessionRequired),
        (_, Err(_)) => Err(PublicErrorCode::ProtocolMalformed),
    };
    let candidate = Candidate {
        worker_id,
        test_deadline_stage,
        peer_id,
        connection_id,
        selected_path,
        deadline: worker_deadline,
        open: open.clone(),
        validation,
        decision,
    };
    let candidate_sent = tokio::select! {
        _ = cancel.cancelled() => false,
        result = tokio::time::timeout(
            worker_deadline.saturating_duration_since(std::time::Instant::now()),
            candidates.send(candidate),
        ) => result.is_ok_and(|result| result.is_ok()),
    };
    if !candidate_sent {
        return release(
            worker_id,
            peer_id,
            connection_id,
            selected_path,
            started.elapsed(),
            AdmissionToken::empty(),
            request_id
                .map(p2x_net::lifecycle::stable_hash)
                .unwrap_or_default(),
            None,
            false,
            Some(transition_failure_code(&shutdown)),
            None,
        );
    }
    let decision = tokio::select! {
        _ = cancel.cancelled() => ServerDecision::Reject(ProxyOpenResponseV1::Rejected {
            request_id,
            error: PublicError::new(PublicErrorCode::ExchangeDraining, true),
        }),
        decision = tokio::time::timeout(
            worker_deadline.saturating_duration_since(std::time::Instant::now()),
            response,
        ) => decision.ok().and_then(Result::ok).unwrap_or_else(|| ServerDecision::Reject(
            ProxyOpenResponseV1::Rejected {
                request_id,
                error: PublicError::new(PublicErrorCode::PeerSetupTimeout, true),
            },
        )),
    };
    let request_id_hash = request_id
        .map(p2x_net::lifecycle::stable_hash)
        .unwrap_or_default();
    let mut stream_id_hash = None;
    let mut accepted = false;
    let mut code = None;
    let mut pump = None;
    let mut accepted_setup_duration = None;
    let admission = match decision {
        ServerDecision::Reject(response) => {
            if let ProxyOpenResponseV1::Rejected { error, .. } = &response {
                code = Some(error.code);
            }
            let _ = write_response_bounded(&mut stream, &response, worker_deadline, &cancel).await;
            AdmissionToken::empty()
        }
        ServerDecision::Admit {
            stream_id,
            admission,
            upstream,
            copy_buffer_bytes,
        } => {
            stream_id_hash = Some(p2x_net::lifecycle::stable_hash(stream_id));
            let Ok(open) = open.as_ref() else {
                return release(
                    worker_id,
                    peer_id,
                    connection_id,
                    selected_path,
                    started.elapsed(),
                    admission,
                    request_id_hash,
                    stream_id_hash,
                    false,
                    Some(PublicErrorCode::ProtocolMalformed),
                    None,
                );
            };
            let remaining = worker_deadline.saturating_duration_since(std::time::Instant::now());
            let stage_dial_hold = (test_deadline_stage == Some(TestDeadlineStage::UpstreamDial))
                .then_some(test_deadline_hold_ms)
                .flatten();
            let dial = if let Some(delay) = stage_dial_hold {
                let _ = test_faults.try_send(TestDeadlineStage::UpstreamDial);
                if hold_test_deadline_stage(
                    Duration::from_millis(delay),
                    worker_deadline,
                    cancel.clone(),
                )
                .await
                {
                    super::upstream::connect(
                        &upstream,
                        worker_deadline.saturating_duration_since(std::time::Instant::now()),
                        cancel.clone(),
                    )
                    .await
                } else {
                    Err(super::upstream::ConnectError::Timeout)
                }
            } else {
                match hold_dial_ms {
                    Some(delay) => match super::upstream::hold(
                        Duration::from_millis(delay),
                        remaining,
                        cancel.clone(),
                    )
                    .await
                    {
                        Ok(()) if Duration::from_millis(delay) >= upstream.connect_timeout => {
                            Err(super::upstream::ConnectError::Timeout)
                        }
                        Ok(()) => {
                            super::upstream::connect(
                                &upstream,
                                worker_deadline
                                    .saturating_duration_since(std::time::Instant::now()),
                                cancel.clone(),
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    },
                    None => super::upstream::connect(&upstream, remaining, cancel.clone()).await,
                }
            };
            match dial {
                Ok(socket) => {
                    if test_deadline_stage == Some(TestDeadlineStage::Promotion)
                        && let Some(delay) = test_deadline_hold_ms
                    {
                        let _ = test_faults.try_send(TestDeadlineStage::Promotion);
                        if !hold_test_deadline_stage(
                            Duration::from_millis(delay),
                            worker_deadline,
                            cancel.clone(),
                        )
                        .await
                        {
                            drop(socket);
                            return release(
                                worker_id,
                                peer_id,
                                connection_id,
                                selected_path,
                                started.elapsed(),
                                admission,
                                request_id_hash,
                                stream_id_hash,
                                false,
                                Some(transition_failure_code(&shutdown)),
                                None,
                            );
                        }
                    }
                    let (acknowledged, ack) = oneshot::channel();
                    if !bounded_promotion(
                        &promotions,
                        Promotion {
                            worker_id,
                            admission,
                            acknowledged,
                        },
                        worker_deadline,
                        &cancel,
                    )
                    .await
                        || !bounded_ack(ack, worker_deadline, &cancel).await
                    {
                        drop(socket);
                        return release(
                            worker_id,
                            peer_id,
                            connection_id,
                            selected_path,
                            started.elapsed(),
                            admission,
                            request_id_hash,
                            stream_id_hash,
                            false,
                            Some(transition_failure_code(&shutdown)),
                            None,
                        );
                    }
                    let Some(accepted_permit) =
                        reserve_accepted(&accepts, worker_deadline, &cancel).await
                    else {
                        let failure = transition_failure_code(&shutdown);
                        let response = ProxyOpenResponseV1::Rejected {
                            request_id: Some(open.request_id),
                            error: PublicError::new(failure, true),
                        };
                        let _ = write_response_bounded(
                            &mut stream,
                            &response,
                            worker_deadline,
                            &cancel,
                        )
                        .await;
                        drop(socket);
                        return release(
                            worker_id,
                            peer_id,
                            connection_id,
                            selected_path,
                            started.elapsed(),
                            admission,
                            request_id_hash,
                            stream_id_hash,
                            false,
                            Some(failure),
                            None,
                        );
                    };
                    let response = ProxyOpenResponseV1::Accepted {
                        request_id: open.request_id,
                        stream_id,
                        selected_upstream_mode: p2x_protocol::UpstreamMode::Tcp,
                    };
                    let accepted_write_ready = if test_deadline_stage
                        == Some(TestDeadlineStage::AcceptedWrite)
                        && let Some(delay) = test_deadline_hold_ms
                    {
                        let _ = test_faults.try_send(TestDeadlineStage::AcceptedWrite);
                        hold_test_deadline_stage(
                            Duration::from_millis(delay),
                            worker_deadline,
                            cancel.clone(),
                        )
                        .await
                    } else {
                        true
                    };
                    if accepted_write_ready
                        && write_response_bounded(&mut stream, &response, worker_deadline, &cancel)
                            .await
                    {
                        accepted = true;
                        let setup_duration = started.elapsed();
                        accepted_setup_duration = Some(setup_duration);
                        accepted_permit.send(Accepted {
                            worker_id,
                            peer_id,
                            connection_id,
                            selected_path,
                            setup_duration,
                            request_id_hash,
                            stream_id_hash: p2x_net::lifecycle::stable_hash(stream_id),
                        });
                        pump = p2x_proxy::pump(
                            stream,
                            tokio_util::compat::TokioAsyncReadCompatExt::compat(socket),
                            copy_buffer_bytes,
                            upstream.idle_timeout,
                            shutdown.cancelled(),
                        )
                        .await
                        .ok();
                        if pump.as_ref().is_some_and(|result| {
                            result.terminal == p2x_proxy::Terminal::IdleTimeout
                        }) {
                            code = Some(PublicErrorCode::UpstreamIdleTimeout);
                        }
                    } else {
                        code = Some(if accepted_write_ready {
                            PublicErrorCode::ProtocolMalformed
                        } else {
                            transition_failure_code(&shutdown)
                        });
                        drop(socket);
                    }
                }
                Err(error) => {
                    code = Some(if cancel.is_cancelled() && shutdown.is_cancelled() {
                        PublicErrorCode::PeerDraining
                    } else {
                        error.code()
                    });
                    let response = ProxyOpenResponseV1::Rejected {
                        request_id: Some(open.request_id),
                        error: PublicError::new(code.expect("dial code is set"), true),
                    };
                    let _ =
                        write_response_bounded(&mut stream, &response, worker_deadline, &cancel)
                            .await;
                }
            }
            admission
        }
    };
    release(
        worker_id,
        peer_id,
        connection_id,
        selected_path,
        accepted_setup_duration.unwrap_or_else(|| started.elapsed()),
        admission,
        request_id_hash,
        stream_id_hash,
        accepted,
        code,
        pump,
    )
}

#[allow(clippy::too_many_arguments)]
fn release(
    worker_id: ProxyWorkerId,
    peer_id: PeerId,
    connection_id: ConnectionId,
    selected_path: ProbePath,
    setup_duration: Duration,
    admission: AdmissionToken,
    request_id_hash: u64,
    stream_id_hash: Option<u64>,
    accepted: bool,
    code: Option<PublicErrorCode>,
    pump: Option<p2x_proxy::PumpResult>,
) -> Release {
    Release {
        worker_id,
        peer_id,
        connection_id,
        selected_path,
        setup_duration,
        admission,
        request_id_hash,
        stream_id_hash,
        accepted,
        code,
        pump,
    }
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
    fn deadline_stage_names_are_closed_and_stable() {
        for (name, stage, fault) in [
            (
                "verification",
                TestDeadlineStage::Verification,
                "hold_server_verification",
            ),
            (
                "owner-decision",
                TestDeadlineStage::OwnerDecision,
                "hold_server_owner_decision",
            ),
            (
                "promotion",
                TestDeadlineStage::Promotion,
                "hold_server_promotion",
            ),
            (
                "upstream-dial",
                TestDeadlineStage::UpstreamDial,
                "hold_server_upstream_dial",
            ),
            (
                "accepted-write",
                TestDeadlineStage::AcceptedWrite,
                "hold_server_accepted_write",
            ),
        ] {
            assert_eq!(name.parse::<TestDeadlineStage>(), Ok(stage));
            assert_eq!(stage.fault(), fault);
        }
        assert!("synthetic".parse::<TestDeadlineStage>().is_err());
    }

    #[tokio::test]
    async fn promotion_and_ack_are_bounded_by_deadline_and_cancellation() {
        let (promotions, mut received) = mpsc::channel(1);
        let (acknowledged, ack) = oneshot::channel();
        assert!(
            bounded_promotion(
                &promotions,
                Promotion {
                    worker_id: ProxyWorkerId(1),
                    admission: AdmissionToken::empty(),
                    acknowledged,
                },
                std::time::Instant::now() + Duration::from_secs(1),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
        );
        let promotion = received.recv().await.unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        drop(promotion);
        assert!(
            !bounded_ack(
                ack,
                std::time::Instant::now() + Duration::from_secs(1),
                &cancel,
            )
            .await
        );
    }

    #[tokio::test]
    async fn accepted_channel_reservation_is_bounded() {
        let (accepts, mut received) = mpsc::channel(1);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let permit = reserve_accepted(
            &accepts,
            deadline,
            &tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        permit.send(Accepted {
            worker_id: ProxyWorkerId(1),
            peer_id: PeerId::random(),
            connection_id: ConnectionId::new_unchecked(1),
            selected_path: ProbePath::Direct,
            setup_duration: Duration::ZERO,
            request_id_hash: 1,
            stream_id_hash: 2,
        });
        assert!(received.recv().await.is_some());
        accepts
            .send(Accepted {
                worker_id: ProxyWorkerId(2),
                peer_id: PeerId::random(),
                connection_id: ConnectionId::new_unchecked(2),
                selected_path: ProbePath::Direct,
                setup_duration: Duration::ZERO,
                request_id_hash: 3,
                stream_id_hash: 4,
            })
            .await
            .unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        assert!(
            reserve_accepted(&accepts, deadline, &cancel)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn expired_transition_returns_without_waiting() {
        let (promotions, mut received) = mpsc::channel(1);
        let (filler_ack, _filler_rx) = oneshot::channel();
        let (acknowledged, _ack) = oneshot::channel();
        promotions
            .send(Promotion {
                worker_id: ProxyWorkerId(1),
                admission: AdmissionToken::empty(),
                acknowledged: filler_ack,
            })
            .await
            .unwrap();
        let deadline = std::time::Instant::now() - Duration::from_millis(1);
        let cancel = tokio_util::sync::CancellationToken::new();
        assert!(
            !bounded_promotion(
                &promotions,
                Promotion {
                    worker_id: ProxyWorkerId(2),
                    admission: AdmissionToken::empty(),
                    acknowledged,
                },
                deadline,
                &cancel,
            )
            .await
        );
        let _ = received.recv().await;
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
