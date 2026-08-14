use crate::connection_book::ConnectionId;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathState {
    Absent,
    RelayDialing,
    RelayReady,
    DirectWaiting,
    Committed,
    Streaming,
    Failed,
}
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
        self.relay = Some(relay);
        self.direct_deadline = Some((now + Duration::from_millis(1500)).min(self.setup_deadline));
        self.state = PathState::DirectWaiting;
    }
    pub fn direct_ready(&mut self, direct: ConnectionId) -> Option<PathDecision> {
        self.direct = Some(direct);
        self.state = PathState::Committed;
        Some(PathDecision::Direct(direct))
    }
    pub fn fallback(&mut self, reason: FallbackReason) -> Option<PathDecision> {
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
    #[test]
    fn silent_dcutr_falls_back_at_preference_deadline() {
        let now = Instant::now();
        let mut a = PathAttempt::new(now);
        let id = ConnectionId::new_unchecked(1);
        a.relay_ready(now, id);
        assert_eq!(a.direct_deadline, Some(now + Duration::from_millis(1500)));
        assert_eq!(
            a.fallback(FallbackReason::DirectDeadline),
            Some(PathDecision::Relay(id))
        );
    }
}
