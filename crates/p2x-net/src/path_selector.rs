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
pub enum FallbackReason {
    DcutrFailed,
    DirectDeadline,
    DirectOpenFailed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathFailure {
    SetupExpired,
    Cancelled,
    ConnectionClosed,
    RelayLost,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathState {
    Absent,
    RelayDialing,
    DirectWaiting,
    Committed,
    StreamOpening,
    Streaming,
    Failed,
}

#[derive(Debug)]
pub struct PathAttempt {
    pub id: AttemptId,
    pub state: PathState,
    pub started_at: Instant,
    pub setup_deadline: Instant,
    pub direct_deadline: Option<Instant>,
    pub relay: Option<ConnectionId>,
    pub direct: Option<ConnectionId>,
    pub decision: Option<PathDecision>,
    pub fallback: Option<FallbackReason>,
}
impl PathAttempt {
    pub fn new(now: Instant) -> Self {
        Self::with_id(AttemptId(0), now)
    }
    pub fn with_id(id: AttemptId, now: Instant) -> Self {
        Self {
            id,
            state: PathState::Absent,
            started_at: now,
            setup_deadline: now + SETUP_BUDGET,
            direct_deadline: None,
            relay: None,
            direct: None,
            decision: None,
            fallback: None,
        }
    }
    pub fn relay_ready(&mut self, now: Instant, relay: ConnectionId) {
        if !matches!(self.state, PathState::Absent | PathState::RelayDialing)
            || now >= self.setup_deadline
        {
            return;
        }
        self.relay = Some(relay);
        self.direct_deadline = Some((now + DIRECT_PREFERENCE).min(self.setup_deadline));
        self.state = PathState::DirectWaiting;
    }
    pub fn direct_ready_at(&mut self, now: Instant, direct: ConnectionId) -> Option<PathDecision> {
        if self.state != PathState::DirectWaiting
            || now >= self.setup_deadline
            || self.direct_deadline.is_some_and(|d| now >= d)
        {
            return None;
        }
        self.direct = Some(direct);
        self.commit(PathDecision::Direct(direct))
    }
    pub fn direct_ready(&mut self, direct: ConnectionId) -> Option<PathDecision> {
        self.direct_ready_at(Instant::now(), direct)
    }
    pub fn fallback_at(&mut self, now: Instant, reason: FallbackReason) -> Option<PathDecision> {
        if self.state != PathState::DirectWaiting
            || self.fallback.is_some()
            || now >= self.setup_deadline
        {
            return None;
        }
        self.fallback = Some(reason);
        self.relay
            .and_then(|id| self.commit(PathDecision::Relay(id)))
    }
    pub fn fallback(&mut self, reason: FallbackReason) -> Option<PathDecision> {
        self.fallback_at(Instant::now(), reason)
    }
    pub fn cancel(&mut self) {
        if !matches!(
            self.state,
            PathState::Committed | PathState::Streaming | PathState::Failed
        ) {
            self.state = PathState::Failed;
        }
    }
    pub fn fail_if_expired(&mut self, now: Instant) -> bool {
        if now >= self.setup_deadline
            && !matches!(
                self.state,
                PathState::Committed | PathState::Streaming | PathState::Failed
            )
        {
            self.state = PathState::Failed;
            true
        } else {
            false
        }
    }
    pub fn expired(&self, now: Instant) -> bool {
        now >= self.setup_deadline
    }
    fn commit(&mut self, decision: PathDecision) -> Option<PathDecision> {
        self.decision = Some(decision);
        self.state = PathState::Committed;
        Some(decision)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u8) -> ConnectionId {
        ConnectionId::new_unchecked(n as usize)
    }
    #[test]
    fn commitment_is_terminal_and_deadline_is_absolute() {
        let now = Instant::now();
        let mut a = PathAttempt::new(now);
        a.relay_ready(now, id(1));
        assert_eq!(
            a.fallback_at(now, FallbackReason::DirectDeadline),
            Some(PathDecision::Relay(id(1)))
        );
        assert_eq!(a.direct_ready_at(now, id(2)), None);
        assert_eq!(a.fallback(FallbackReason::DcutrFailed), None);
    }
    #[test]
    fn boundaries_and_cancellation_are_terminal() {
        let now = Instant::now();
        let mut a = PathAttempt::with_id(AttemptId(4), now);
        a.relay_ready(now, id(1));
        assert_eq!(a.direct_ready_at(now + DIRECT_PREFERENCE, id(2)), None);
        assert!(a.fail_if_expired(now + SETUP_BUDGET));
        assert_eq!(a.state, PathState::Failed);
        a.cancel();
        assert_eq!(a.state, PathState::Failed);
    }
}
