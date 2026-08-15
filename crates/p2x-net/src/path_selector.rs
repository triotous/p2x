use crate::{connection_book::ConnectionId, probe_stream::handler::RequestId};
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

impl PathDecision {
    pub fn connection(self) -> ConnectionId {
        match self {
            Self::Direct(connection) | Self::Relay(connection) => connection,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathFailure {
    SetupExpired,
    Cancelled,
    ConnectionClosed,
    RelayLost,
    ExactOpenFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathState {
    Absent,
    RelayDialing,
    DirectWaiting {
        relay_id: ConnectionId,
        direct_deadline: Instant,
    },
    Committed {
        decision: PathDecision,
        relay_id: Option<ConnectionId>,
        relay_fallback_used: bool,
    },
    StreamOpening {
        decision: PathDecision,
        request_id: RequestId,
        relay_id: Option<ConnectionId>,
        relay_fallback_used: bool,
    },
    StreamReady {
        decision: PathDecision,
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
    Begin {
        relay: Option<ConnectionId>,
        direct: Option<ConnectionId>,
    },
    RelayReady(ConnectionId),
    DirectReady(ConnectionId),
    DcutrFailed,
    DirectDeadlineElapsed,
    ExactOpenQueued {
        request_id: RequestId,
        connection: ConnectionId,
    },
    ExactOpenRejected {
        connection: ConnectionId,
    },
    ExactOpenSucceeded {
        request_id: RequestId,
        connection: ConnectionId,
    },
    ExactOpenFailed {
        request_id: RequestId,
        connection: ConnectionId,
    },
    PayloadAccepted,
    ConnectionClosed(ConnectionId),
    RelayLost(ConnectionId),
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
    CancelOpen { request_id: RequestId },
    CloseStream,
    Finish(PathFailure),
}

#[derive(Debug)]
pub struct PathAttempt {
    pub id: AttemptId,
    pub started_at: Instant,
    pub setup_deadline: Instant,
    pub state: PathState,
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
            relay_connection: None,
        }
    }

    pub fn apply(&mut self, event: PathEvent) -> Vec<PathAction> {
        if event.attempt_id != self.id || matches!(self.state, PathState::Failed { .. }) {
            return vec![];
        }
        if event.now >= self.setup_deadline && !matches!(self.state, PathState::Streaming { .. }) {
            return self.fail(PathFailure::SetupExpired);
        }

        match event.kind {
            PathEventKind::Begin { relay, direct } if matches!(self.state, PathState::Absent) => {
                self.relay_connection = relay;
                if let Some(direct) = direct {
                    self.commit_and_open(PathDecision::Direct(direct), false)
                } else if let Some(relay) = relay {
                    self.wait_for_direct(relay, event.now);
                    vec![]
                } else {
                    self.state = PathState::RelayDialing;
                    vec![PathAction::DialRelay]
                }
            }
            PathEventKind::RelayReady(relay)
                if matches!(self.state, PathState::RelayDialing | PathState::Absent) =>
            {
                self.relay_connection = Some(relay);
                self.wait_for_direct(relay, event.now);
                vec![]
            }
            PathEventKind::DirectReady(direct) => match self.state {
                PathState::RelayDialing => {
                    self.commit_and_open(PathDecision::Direct(direct), false)
                }
                PathState::DirectWaiting {
                    direct_deadline, ..
                } if event.now < direct_deadline => {
                    self.commit_and_open(PathDecision::Direct(direct), false)
                }
                _ => vec![],
            },
            PathEventKind::DcutrFailed => self.commit_waiting_relay(),
            PathEventKind::DirectDeadlineElapsed => match self.state {
                PathState::DirectWaiting {
                    direct_deadline, ..
                } if event.now >= direct_deadline => self.commit_waiting_relay(),
                _ => vec![],
            },
            PathEventKind::ExactOpenQueued {
                request_id,
                connection,
            } => match self.state {
                PathState::Committed {
                    decision,
                    relay_id,
                    relay_fallback_used,
                } if decision.connection() == connection => {
                    self.state = PathState::StreamOpening {
                        decision,
                        request_id,
                        relay_id,
                        relay_fallback_used,
                    };
                    vec![]
                }
                _ => vec![],
            },
            PathEventKind::ExactOpenRejected { connection } => {
                self.reject_committed_open(connection)
            }
            PathEventKind::ExactOpenSucceeded {
                request_id,
                connection,
            } => match self.state {
                PathState::StreamOpening {
                    decision,
                    request_id: expected,
                    ..
                } if expected == request_id && decision.connection() == connection => {
                    self.state = PathState::StreamReady { decision };
                    vec![]
                }
                _ => vec![],
            },
            PathEventKind::ExactOpenFailed {
                request_id,
                connection,
            } => match self.state {
                PathState::StreamOpening {
                    decision,
                    request_id: expected,
                    relay_id,
                    relay_fallback_used,
                } if expected == request_id && decision.connection() == connection => {
                    self.handle_open_failure(decision, relay_id, relay_fallback_used)
                }
                _ => vec![],
            },
            PathEventKind::PayloadAccepted => match self.state {
                PathState::StreamReady { decision } => {
                    self.state = PathState::Streaming { decision };
                    vec![]
                }
                _ => vec![],
            },
            PathEventKind::ConnectionClosed(connection) => {
                if self.selected_connection() == Some(connection) {
                    self.fail(PathFailure::ConnectionClosed)
                } else if matches!(
                    self.state,
                    PathState::DirectWaiting { relay_id, .. } if relay_id == connection
                ) {
                    self.fail(PathFailure::RelayLost)
                } else {
                    vec![]
                }
            }
            PathEventKind::RelayLost(connection) => {
                if self.relay_is_required(connection) {
                    self.fail(PathFailure::RelayLost)
                } else {
                    vec![]
                }
            }
            PathEventKind::Cancelled => self.fail(PathFailure::Cancelled),
            _ => vec![],
        }
    }

    pub fn expired(&self, now: Instant) -> bool {
        now >= self.setup_deadline
    }

    fn wait_for_direct(&mut self, relay_id: ConnectionId, now: Instant) {
        self.state = PathState::DirectWaiting {
            relay_id,
            direct_deadline: (now + DIRECT_PREFERENCE).min(self.setup_deadline),
        };
    }

    fn commit_waiting_relay(&mut self) -> Vec<PathAction> {
        match self.state {
            PathState::DirectWaiting { relay_id, .. } => {
                self.commit_and_open(PathDecision::Relay(relay_id), false)
            }
            _ => vec![],
        }
    }

    fn commit_and_open(
        &mut self,
        decision: PathDecision,
        relay_fallback_used: bool,
    ) -> Vec<PathAction> {
        self.state = PathState::Committed {
            decision,
            relay_id: self.relay_connection,
            relay_fallback_used,
        };
        vec![PathAction::OpenExact {
            connection: decision.connection(),
        }]
    }

    fn reject_committed_open(&mut self, connection: ConnectionId) -> Vec<PathAction> {
        match self.state {
            PathState::Committed {
                decision,
                relay_id,
                relay_fallback_used,
            } if decision.connection() == connection => {
                self.handle_open_failure(decision, relay_id, relay_fallback_used)
            }
            _ => vec![],
        }
    }

    fn handle_open_failure(
        &mut self,
        decision: PathDecision,
        relay_id: Option<ConnectionId>,
        relay_fallback_used: bool,
    ) -> Vec<PathAction> {
        if matches!(decision, PathDecision::Direct(_))
            && !relay_fallback_used
            && let Some(relay) = relay_id
        {
            return self.commit_and_open(PathDecision::Relay(relay), true);
        }
        self.fail(PathFailure::ExactOpenFailed)
    }

    fn selected_connection(&self) -> Option<ConnectionId> {
        match self.state {
            PathState::Committed { decision, .. }
            | PathState::StreamOpening { decision, .. }
            | PathState::StreamReady { decision }
            | PathState::Streaming { decision } => Some(decision.connection()),
            _ => None,
        }
    }

    fn relay_is_required(&self, connection: ConnectionId) -> bool {
        match self.state {
            PathState::DirectWaiting { relay_id, .. } => relay_id == connection,
            PathState::Committed {
                decision: PathDecision::Relay(relay),
                ..
            }
            | PathState::StreamOpening {
                decision: PathDecision::Relay(relay),
                ..
            }
            | PathState::StreamReady {
                decision: PathDecision::Relay(relay),
            }
            | PathState::Streaming {
                decision: PathDecision::Relay(relay),
            } => relay == connection,
            _ => false,
        }
    }

    fn fail(&mut self, reason: PathFailure) -> Vec<PathAction> {
        if matches!(self.state, PathState::Failed { .. }) {
            return vec![];
        }
        let mut actions = match self.state {
            PathState::StreamOpening { request_id, .. } => {
                vec![PathAction::CancelOpen { request_id }]
            }
            PathState::StreamReady { .. } | PathState::Streaming { .. } => {
                vec![PathAction::CloseStream]
            }
            _ => vec![],
        };
        self.state = PathState::Failed { reason };
        actions.push(PathAction::Finish(reason));
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: usize) -> ConnectionId {
        ConnectionId::new_unchecked(value)
    }

    fn event(attempt: &PathAttempt, now: Instant, kind: PathEventKind) -> PathEvent {
        PathEvent {
            attempt_id: attempt.id,
            now,
            kind,
        }
    }

    #[test]
    fn begin_uses_pooled_direct_without_dialing_relay() {
        let now = Instant::now();
        let mut attempt = PathAttempt::with_id(AttemptId(1), now);
        assert_eq!(
            attempt.apply(event(
                &attempt,
                now,
                PathEventKind::Begin {
                    relay: Some(id(1)),
                    direct: Some(id(2)),
                },
            )),
            vec![PathAction::OpenExact { connection: id(2) }]
        );
    }

    #[test]
    fn relay_readiness_starts_deadline_and_early_timer_is_ignored() {
        let now = Instant::now();
        let mut attempt = PathAttempt::new(now);
        let attempt_id = attempt.id;
        assert_eq!(
            attempt.apply(PathEvent {
                attempt_id,
                now,
                kind: PathEventKind::Begin {
                    relay: None,
                    direct: None,
                },
            }),
            vec![PathAction::DialRelay]
        );
        assert!(
            attempt
                .apply(event(&attempt, now, PathEventKind::RelayReady(id(1))))
                .is_empty()
        );
        assert!(
            attempt
                .apply(event(
                    &attempt,
                    now + DIRECT_PREFERENCE - Duration::from_millis(1),
                    PathEventKind::DirectDeadlineElapsed,
                ))
                .is_empty()
        );
        assert_eq!(
            attempt.apply(event(
                &attempt,
                now + DIRECT_PREFERENCE,
                PathEventKind::DirectDeadlineElapsed,
            )),
            vec![PathAction::OpenExact { connection: id(1) }]
        );
    }

    #[test]
    fn direct_failure_uses_one_fresh_relay_open() {
        let now = Instant::now();
        let mut attempt = PathAttempt::new(now);
        let attempt_id = attempt.id;
        attempt.apply(PathEvent {
            attempt_id,
            now,
            kind: PathEventKind::Begin {
                relay: Some(id(1)),
                direct: Some(id(2)),
            },
        });
        attempt.apply(event(
            &attempt,
            now,
            PathEventKind::ExactOpenQueued {
                request_id: RequestId(7),
                connection: id(2),
            },
        ));
        assert_eq!(
            attempt.apply(event(
                &attempt,
                now,
                PathEventKind::ExactOpenFailed {
                    request_id: RequestId(7),
                    connection: id(2),
                },
            )),
            vec![PathAction::OpenExact { connection: id(1) }]
        );
        assert!(
            attempt
                .apply(event(
                    &attempt,
                    now,
                    PathEventKind::ExactOpenSucceeded {
                        request_id: RequestId(7),
                        connection: id(2),
                    },
                ))
                .is_empty()
        );
        attempt.apply(event(
            &attempt,
            now,
            PathEventKind::ExactOpenQueued {
                request_id: RequestId(8),
                connection: id(1),
            },
        ));
        assert_eq!(
            attempt.apply(event(
                &attempt,
                now,
                PathEventKind::ExactOpenFailed {
                    request_id: RequestId(8),
                    connection: id(1),
                },
            )),
            vec![
                PathAction::CancelOpen {
                    request_id: RequestId(8)
                },
                PathAction::Finish(PathFailure::ExactOpenFailed),
            ]
        );
    }

    #[test]
    fn cancellation_returns_cleanup_once() {
        let now = Instant::now();
        let mut attempt = PathAttempt::new(now);
        let attempt_id = attempt.id;
        attempt.apply(PathEvent {
            attempt_id,
            now,
            kind: PathEventKind::Begin {
                relay: None,
                direct: Some(id(2)),
            },
        });
        attempt.apply(event(
            &attempt,
            now,
            PathEventKind::ExactOpenQueued {
                request_id: RequestId(1),
                connection: id(2),
            },
        ));
        assert_eq!(
            attempt.apply(event(&attempt, now, PathEventKind::Cancelled)),
            vec![
                PathAction::CancelOpen {
                    request_id: RequestId(1)
                },
                PathAction::Finish(PathFailure::Cancelled),
            ]
        );
        assert!(
            attempt
                .apply(event(&attempt, now, PathEventKind::Cancelled))
                .is_empty()
        );
    }

    #[test]
    fn relay_loss_does_not_fail_direct_stream() {
        let now = Instant::now();
        let mut attempt = PathAttempt::new(now);
        let attempt_id = attempt.id;
        attempt.apply(PathEvent {
            attempt_id,
            now,
            kind: PathEventKind::Begin {
                relay: Some(id(1)),
                direct: Some(id(2)),
            },
        });
        attempt.apply(event(
            &attempt,
            now,
            PathEventKind::ExactOpenQueued {
                request_id: RequestId(1),
                connection: id(2),
            },
        ));
        attempt.apply(event(
            &attempt,
            now,
            PathEventKind::ExactOpenSucceeded {
                request_id: RequestId(1),
                connection: id(2),
            },
        ));
        attempt.apply(event(&attempt, now, PathEventKind::PayloadAccepted));
        assert!(
            attempt
                .apply(event(&attempt, now, PathEventKind::RelayLost(id(1))))
                .is_empty()
        );
        assert!(matches!(attempt.state, PathState::Streaming { .. }));
    }

    #[test]
    fn stale_attempt_is_ignored() {
        let now = Instant::now();
        let mut attempt = PathAttempt::with_id(AttemptId(9), now);
        assert!(
            attempt
                .apply(PathEvent {
                    attempt_id: AttemptId(8),
                    now,
                    kind: PathEventKind::Cancelled,
                })
                .is_empty()
        );
        assert!(matches!(attempt.state, PathState::Absent));
    }
}
