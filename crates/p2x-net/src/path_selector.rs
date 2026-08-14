use crate::connection_book::ConnectionId;
use std::time::{Duration, Instant};

pub const SETUP_BUDGET: Duration = Duration::from_secs(20);
pub const DIRECT_PREFERENCE: Duration = Duration::from_millis(1500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptId(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathDecision {
    Direct(ConnectionId),
    Relay(ConnectionId),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathFailure {
    SetupExpired,
    Cancelled,
    ConnectionClosed,
    RelayLost,
    DirectOpenFailed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathState {
    Absent,
    RelayDialing,
    DirectWaiting {
        relay: ConnectionId,
        direct_deadline: Instant,
    },
    Committed {
        decision: PathDecision,
    },
    StreamOpening {
        decision: PathDecision,
        request_id: u64,
        relay_id: Option<ConnectionId>,
        relay_fallback_used: bool,
    },
    Streaming {
        decision: PathDecision,
    },
    Failed {
        reason: PathFailure,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathEventKind {
    RelayReady(ConnectionId),
    DirectReady(ConnectionId),
    DirectDeadlineElapsed,
    ExactOpenSucceeded,
    ExactOpenFailed,
    PayloadAccepted,
    SelectedConnectionClosed,
    RelayLost,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEvent {
    pub attempt_id: AttemptId,
    pub now: Instant,
    pub kind: PathEventKind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathAction {
    DialRelay,
    OpenExact { connection: ConnectionId },
    CancelOpen { request_id: u64 },
    CloseStream,
    Finish(PathFailure),
}

#[derive(Debug)]
pub struct PathAttempt {
    pub id: AttemptId,
    pub started_at: Instant,
    pub setup_deadline: Instant,
    pub state: PathState,
    next_request_id: u64,
    relay_connection: Option<ConnectionId>,
}
impl PathAttempt {
    pub fn new(now: Instant) -> Self {
        Self::with_id(AttemptId(0), now)
    }
    pub fn with_id(id: AttemptId, now: Instant) -> Self {
        Self {
            id,
            started_at: now,
            setup_deadline: now + SETUP_BUDGET,
            state: PathState::Absent,
            next_request_id: 0,
            relay_connection: None,
        }
    }
    pub fn apply(&mut self, event: PathEvent) -> Vec<PathAction> {
        if event.attempt_id != self.id {
            return vec![];
        }
        let expired = event.now >= self.setup_deadline
            && !matches!(
                self.state,
                PathState::Streaming { .. } | PathState::Failed { .. }
            );
        if expired {
            return self.fail(PathFailure::SetupExpired);
        }
        match event.kind {
            PathEventKind::RelayReady(relay)
                if matches!(self.state, PathState::Absent | PathState::RelayDialing) =>
            {
                self.relay_connection = Some(relay);
                self.state = PathState::DirectWaiting {
                    relay,
                    direct_deadline: (event.now + DIRECT_PREFERENCE).min(self.setup_deadline),
                };
                vec![]
            }
            PathEventKind::DirectReady(direct) => match self.state {
                PathState::Absent | PathState::RelayDialing => {
                    self.commit(PathDecision::Direct(direct));
                    vec![]
                }
                PathState::DirectWaiting {
                    direct_deadline, ..
                } if event.now < direct_deadline => {
                    self.commit(PathDecision::Direct(direct));
                    vec![]
                }
                _ => vec![],
            },
            PathEventKind::DirectDeadlineElapsed => match self.state {
                PathState::DirectWaiting {
                    relay,
                    direct_deadline,
                } if event.now >= direct_deadline => {
                    self.commit(PathDecision::Relay(relay));
                    vec![]
                }
                _ => vec![],
            },
            PathEventKind::ExactOpenSucceeded => match self.state {
                PathState::StreamOpening { decision, .. } => {
                    self.state = PathState::Streaming { decision };
                    vec![]
                }
                _ => vec![],
            },
            PathEventKind::ExactOpenFailed => match self.state {
                PathState::StreamOpening {
                    decision: PathDecision::Direct(_),
                    request_id,
                    relay_id: Some(_),
                    relay_fallback_used: false,
                } => {
                    let relay = match self.state {
                        PathState::StreamOpening { relay_id, .. } => relay_id,
                        _ => None,
                    };
                    if let Some(relay) = relay {
                        self.state = PathState::StreamOpening {
                            decision: PathDecision::Relay(relay),
                            request_id,
                            relay_id: Some(relay),
                            relay_fallback_used: true,
                        };
                        vec![PathAction::OpenExact { connection: relay }]
                    } else {
                        self.fail(PathFailure::DirectOpenFailed)
                    }
                }
                PathState::StreamOpening { .. } => self.fail(PathFailure::DirectOpenFailed),
                _ => vec![],
            },
            PathEventKind::PayloadAccepted => match self.state {
                PathState::StreamOpening { decision, .. } => {
                    self.state = PathState::Streaming { decision };
                    vec![]
                }
                _ => vec![],
            },
            PathEventKind::SelectedConnectionClosed => match self.state {
                PathState::Streaming { .. } | PathState::StreamOpening { .. } => {
                    self.fail(PathFailure::ConnectionClosed)
                }
                _ => vec![],
            },
            PathEventKind::RelayLost => match self.state {
                PathState::Streaming { .. } => self.fail(PathFailure::RelayLost),
                _ => vec![],
            },
            PathEventKind::Cancelled => self.fail(PathFailure::Cancelled),
            _ => vec![],
        }
    }
    pub fn open_committed(&mut self) -> Option<PathAction> {
        let decision = match self.state {
            PathState::Committed { decision } => decision,
            _ => return None,
        };
        self.next_request_id = self.next_request_id.checked_add(1)?;
        self.state = PathState::StreamOpening {
            decision,
            request_id: self.next_request_id,
            relay_id: self.relay_connection,
            relay_fallback_used: false,
        };
        Some(PathAction::OpenExact {
            connection: match decision {
                PathDecision::Direct(id) | PathDecision::Relay(id) => id,
            },
        })
    }
    fn commit(&mut self, decision: PathDecision) {
        self.state = PathState::Committed { decision };
    }
    fn fail(&mut self, reason: PathFailure) -> Vec<PathAction> {
        self.state = PathState::Failed { reason };
        vec![PathAction::Finish(reason)]
    }
    pub fn expired(&self, now: Instant) -> bool {
        now >= self.setup_deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u8) -> ConnectionId {
        ConnectionId::new_unchecked(n as usize)
    }
    fn event(id_: AttemptId, now: Instant, kind: PathEventKind) -> PathEvent {
        PathEvent {
            attempt_id: id_,
            now,
            kind,
        }
    }
    #[test]
    fn deadline_is_authoritative_and_stale_events_are_ignored() {
        let now = Instant::now();
        let aid = AttemptId(4);
        let mut a = PathAttempt::with_id(aid, now);
        assert!(
            a.apply(event(AttemptId(3), now, PathEventKind::RelayReady(id(1))))
                .is_empty()
        );
        a.apply(event(aid, now, PathEventKind::RelayReady(id(1))));
        a.apply(event(
            aid,
            now + DIRECT_PREFERENCE,
            PathEventKind::DirectDeadlineElapsed,
        ));
        assert!(matches!(
            a.state,
            PathState::Committed {
                decision: PathDecision::Relay(_)
            }
        ));
    }
    #[test]
    fn direct_open_has_one_relay_fallback_before_payload() {
        let now = Instant::now();
        let mut a = PathAttempt::new(now);
        a.apply(event(a.id, now, PathEventKind::RelayReady(id(1))));
        a.apply(event(
            a.id,
            now + Duration::from_millis(1),
            PathEventKind::DirectReady(id(2)),
        ));
        assert!(
            matches!(a.open_committed(), Some(PathAction::OpenExact { connection }) if connection == id(2))
        );
        assert!(
            matches!(a.apply(event(a.id, now + Duration::from_millis(2), PathEventKind::ExactOpenFailed))[..], [PathAction::OpenExact { connection }] if connection == id(1))
        );
        a.apply(event(
            a.id,
            now + Duration::from_millis(3),
            PathEventKind::PayloadAccepted,
        ));
        assert!(
            a.apply(event(
                a.id,
                now + Duration::from_millis(4),
                PathEventKind::ExactOpenFailed
            ))
            .is_empty()
        );
    }
}
