use crate::connection_book::ConnectionId;
use std::time::{Duration, Instant};

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
pub enum PathState {
    Absent,
    RelayDialing,
    DirectWaiting,
    Committed,
    Streaming,
    Failed,
}

#[derive(Debug)]
pub struct PathAttempt {
    pub state: PathState,
    pub setup_deadline: Instant,
    pub direct_deadline: Option<Instant>,
    pub relay: Option<ConnectionId>,
    pub direct: Option<ConnectionId>,
    pub fallback: Option<FallbackReason>,
}
impl PathAttempt {
    pub fn new(now: Instant) -> Self {
        Self {
            state: PathState::Absent,
            setup_deadline: now + Duration::from_secs(20),
            direct_deadline: None,
            relay: None,
            direct: None,
            fallback: None,
        }
    }
    pub fn relay_ready(&mut self, now: Instant, relay: ConnectionId) {
        if self.state != PathState::Absent && self.state != PathState::RelayDialing {
            return;
        }
        self.relay = Some(relay);
        self.direct_deadline = Some((now + Duration::from_millis(1500)).min(self.setup_deadline));
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
        self.state = PathState::Committed;
        Some(PathDecision::Direct(direct))
    }
    pub fn direct_ready(&mut self, direct: ConnectionId) -> Option<PathDecision> {
        self.direct_ready_at(Instant::now(), direct)
    }
    pub fn fallback(&mut self, reason: FallbackReason) -> Option<PathDecision> {
        if self.state != PathState::DirectWaiting || self.fallback.is_some() {
            return None;
        }
        self.fallback = Some(reason);
        self.relay.map(|id| {
            self.state = PathState::Committed;
            PathDecision::Relay(id)
        })
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
    #[test]
    fn commitment_is_terminal_and_deadline_is_absolute() {
        let now = Instant::now();
        let mut a = PathAttempt::new(now);
        a.relay_ready(now, id(1));
        assert_eq!(
            a.fallback(FallbackReason::DirectDeadline),
            Some(PathDecision::Relay(id(1)))
        );
        assert_eq!(a.direct_ready_at(now, id(2)), None);
        assert_eq!(a.fallback(FallbackReason::DcutrFailed), None);
    }
    #[test]
    fn direct_must_arrive_before_preference_deadline() {
        let now = Instant::now();
        let mut a = PathAttempt::new(now);
        a.relay_ready(now, id(1));
        assert_eq!(
            a.direct_ready_at(now + Duration::from_millis(1499), id(2)),
            Some(PathDecision::Direct(id(2)))
        );
    }
}
