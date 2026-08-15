use p2x_protocol::PublicErrorCode;
use std::collections::HashMap;

pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_INFLIGHT: usize = 128;
pub const MAX_FAILURE_BUCKETS: usize = 1024;
pub const FAILURE_LIMIT: u32 = 10;
pub const FAILURE_WINDOW: i64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Accepted,
    Rejected(PublicErrorCode),
}
#[derive(Default)]
struct FailureBucket {
    window: i64,
    failures: u32,
}
#[derive(Default)]
pub struct AdmissionLedger {
    connections: usize,
    inflight: usize,
    peer_inflight: HashMap<String, usize>,
    failures: HashMap<String, FailureBucket>,
}
impl AdmissionLedger {
    pub fn admit_connection(&mut self) -> Admission {
        if self.connections >= MAX_CONNECTIONS {
            return Admission::Rejected(PublicErrorCode::LimitAuthConnections);
        }
        self.connections += 1;
        Admission::Accepted
    }
    pub fn close_connection(&mut self) {
        self.connections = self.connections.saturating_sub(1);
    }
    pub fn begin_auth(&mut self, peer: &str, now: i64) -> Admission {
        self.sweep(now);
        if self.inflight >= MAX_INFLIGHT {
            return Admission::Rejected(PublicErrorCode::LimitAuthRequests);
        }
        if self.peer_inflight.get(peer).copied().unwrap_or(0) >= 1 {
            return Admission::Rejected(PublicErrorCode::LimitAuthRequests);
        }
        if self
            .failures
            .get(peer)
            .is_some_and(|b| b.failures >= FAILURE_LIMIT)
        {
            return Admission::Rejected(PublicErrorCode::LimitAuthRequests);
        }
        self.inflight += 1;
        *self.peer_inflight.entry(peer.to_owned()).or_default() += 1;
        Admission::Accepted
    }
    pub fn finish_auth(&mut self, peer: &str, failed: bool, now: i64) {
        self.inflight = self.inflight.saturating_sub(1);
        if let Some(n) = self.peer_inflight.get_mut(peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.peer_inflight.remove(peer);
            }
        }
        if failed {
            let bucket = self.failures.entry(peer.to_owned()).or_default();
            if bucket.window != now / FAILURE_WINDOW {
                bucket.window = now / FAILURE_WINDOW;
                bucket.failures = 0;
            }
            bucket.failures = bucket.failures.saturating_add(1);
        }
    }
    pub fn sweep(&mut self, now: i64) {
        let window = now / FAILURE_WINDOW;
        self.failures.retain(|_, b| b.window >= window);
    }
    pub fn connections(&self) -> usize {
        self.connections
    }
    pub fn inflight(&self) -> usize {
        self.inflight
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_failure_windows_are_deterministic() {
        let mut a = AdmissionLedger::default();
        for _ in 0..MAX_CONNECTIONS {
            assert_eq!(a.admit_connection(), Admission::Accepted);
        }
        assert_eq!(
            a.admit_connection(),
            Admission::Rejected(PublicErrorCode::LimitAuthConnections)
        );
        a.close_connection();
        assert_eq!(a.begin_auth("p", 0), Admission::Accepted);
        assert_eq!(
            a.begin_auth("p", 0),
            Admission::Rejected(PublicErrorCode::LimitAuthRequests)
        );
        a.finish_auth("p", true, 0);
        for _ in 1..FAILURE_LIMIT {
            assert_eq!(a.begin_auth("p", 0), Admission::Accepted);
            a.finish_auth("p", true, 0);
        }
        assert_eq!(
            a.begin_auth("p", 0),
            Admission::Rejected(PublicErrorCode::LimitAuthRequests)
        );
        assert_eq!(a.begin_auth("p", FAILURE_WINDOW), Admission::Accepted);
    }
}
