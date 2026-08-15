use p2x_protocol::PublicErrorCode;
use std::collections::HashMap;

pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_INFLIGHT: usize = 128;
pub const MAX_FAILURE_BUCKETS: usize = 1024;
pub const MAX_CONNECTIONS_PER_IP: usize = 8;
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
    peer_connections: HashMap<String, usize>,
    ip_connections: HashMap<String, usize>,
    inflight: usize,
    peer_inflight: HashMap<String, usize>,
    failures: HashMap<String, FailureBucket>,
}
impl AdmissionLedger {
    pub fn admit_connection(&mut self) -> Admission {
        self.admit_connection_from("<unknown>")
    }
    pub fn admit_connection_from(&mut self, ip: &str) -> Admission {
        if self.connections >= MAX_CONNECTIONS
            || self.ip_connections.get(ip).copied().unwrap_or(0) >= MAX_CONNECTIONS_PER_IP
        {
            return Admission::Rejected(PublicErrorCode::LimitAuthConnections);
        }
        self.connections += 1;
        *self.ip_connections.entry(ip.to_owned()).or_default() += 1;
        Admission::Accepted
    }
    pub fn admit_peer_connection(&mut self, peer: &str) -> Admission {
        if self.peer_connections.get(peer).copied().unwrap_or(0) >= 2 {
            self.connections = self.connections.saturating_sub(1);
            return Admission::Rejected(PublicErrorCode::LimitAuthConnections);
        }
        *self.peer_connections.entry(peer.to_owned()).or_default() += 1;
        Admission::Accepted
    }
    pub fn close_connection(&mut self, peer: &str) {
        self.close_connection_from(peer, "<unknown>");
    }
    pub fn close_connection_from(&mut self, peer: &str, ip: &str) {
        self.connections = self.connections.saturating_sub(1);
        if let Some(n) = self.ip_connections.get_mut(ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.ip_connections.remove(ip);
            }
        }
        if let Some(n) = self.peer_connections.get_mut(peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.peer_connections.remove(peer);
            }
        }
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
            if !self.failures.contains_key(peer) && self.failures.len() >= MAX_FAILURE_BUCKETS {
                return;
            }
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
    pub fn ip_connections(&self, ip: &str) -> usize {
        self.ip_connections.get(ip).copied().unwrap_or(0)
    }
    pub fn peer_connections(&self, peer: &str) -> usize {
        self.peer_connections.get(peer).copied().unwrap_or(0)
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
        for n in 0..MAX_CONNECTIONS {
            let ip = format!("ip{n}");
            assert_eq!(a.admit_connection_from(&ip), Admission::Accepted);
        }
        assert_eq!(
            a.admit_connection(),
            Admission::Rejected(PublicErrorCode::LimitAuthConnections)
        );
        a.close_connection("p");
        assert_eq!(a.connections(), MAX_CONNECTIONS - 1);
        let mut peers = AdmissionLedger::default();
        for n in 0..2 {
            assert_eq!(
                peers.admit_connection_from(if n == 0 { "ip" } else { "ip2" }),
                Admission::Accepted
            );
            assert_eq!(peers.admit_peer_connection("p"), Admission::Accepted);
        }
        assert_eq!(peers.admit_connection_from("ip3"), Admission::Accepted);
        assert_eq!(
            peers.admit_peer_connection("p"),
            Admission::Rejected(PublicErrorCode::LimitAuthConnections)
        );
        assert_eq!(peers.connections(), 2);
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
