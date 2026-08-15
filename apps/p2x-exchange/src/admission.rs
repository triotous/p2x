use libp2p::swarm::ConnectionId;
use p2x_protocol::PublicErrorCode;
use std::collections::HashMap;

pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_INFLIGHT: usize = 128;
pub const MAX_FAILURE_BUCKETS: usize = 1024;
pub const MAX_CONNECTIONS_PER_IP: usize = 8;
pub const FAILURE_LIMIT: u32 = 10;
pub const FAILURE_WINDOW: i64 = 60;
pub const MAX_CONNECTIONS_PER_PEER: usize = 2;
pub const MAX_INFLIGHT_PER_PEER: usize = 1;

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
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectionRecord {
    peer: String,
    ip: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestRecord {
    connection_id: ConnectionId,
    peer: String,
    ip: String,
    failed: bool,
}
#[derive(Default)]
pub struct AdmissionLedger {
    connections: HashMap<ConnectionId, ConnectionRecord>,
    peer_connections: HashMap<String, usize>,
    ip_connections: HashMap<String, usize>,
    inflight: usize,
    peer_inflight: HashMap<String, usize>,
    failures: HashMap<String, FailureBucket>,
    requests: HashMap<String, RequestRecord>,
}
impl AdmissionLedger {
    pub fn admit_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: &str,
        ip: &str,
    ) -> Admission {
        if self.connections.contains_key(&connection_id) {
            return Admission::Accepted;
        }
        if self.connections.len() >= MAX_CONNECTIONS
            || self.ip_connections.get(ip).copied().unwrap_or(0) >= MAX_CONNECTIONS_PER_IP
            || self.peer_connections.get(peer).copied().unwrap_or(0) >= MAX_CONNECTIONS_PER_PEER
        {
            return Admission::Rejected(PublicErrorCode::LimitAuthConnections);
        }
        self.connections.insert(
            connection_id,
            ConnectionRecord {
                peer: peer.to_owned(),
                ip: ip.to_owned(),
            },
        );
        *self.ip_connections.entry(ip.to_owned()).or_default() += 1;
        *self.peer_connections.entry(peer.to_owned()).or_default() += 1;
        Admission::Accepted
    }
    pub fn begin_auth(
        &mut self,
        request_id: impl ToString,
        connection_id: ConnectionId,
        now: i64,
    ) -> Admission {
        self.sweep(now);
        let request_id = request_id.to_string();
        if self.requests.contains_key(&request_id) {
            return Admission::Rejected(PublicErrorCode::LimitAuthRequests);
        }
        let Some(record) = self.connections.get(&connection_id).cloned() else {
            return Admission::Rejected(PublicErrorCode::LimitAuthConnections);
        };
        if self.inflight >= MAX_INFLIGHT
            || self.peer_inflight.get(&record.peer).copied().unwrap_or(0) >= MAX_INFLIGHT_PER_PEER
        {
            return Admission::Rejected(PublicErrorCode::LimitAuthRequests);
        }
        for key in [
            Self::peer_failure_key(&record.peer),
            Self::ip_failure_key(&record.ip),
        ] {
            if self
                .failures
                .get(&key)
                .is_some_and(|b| b.failures >= FAILURE_LIMIT)
            {
                return Admission::Rejected(PublicErrorCode::LimitAuthRequests);
            }
            if !self.failures.contains_key(&key) && self.failures.len() >= MAX_FAILURE_BUCKETS {
                return Admission::Rejected(PublicErrorCode::ExchangeOverloaded);
            }
        }
        self.inflight += 1;
        *self.peer_inflight.entry(record.peer.clone()).or_default() += 1;
        self.requests.insert(
            request_id,
            RequestRecord {
                connection_id,
                peer: record.peer,
                ip: record.ip,
                failed: false,
            },
        );
        Admission::Accepted
    }
    pub fn mark_response(&mut self, request_id: impl ToString, failed: bool) {
        let request_id = request_id.to_string();
        if let Some(record) = self.requests.get_mut(&request_id) {
            record.failed = failed;
        }
    }
    pub fn response_delivered(&mut self, request_id: impl ToString, now: i64) {
        let request_id = request_id.to_string();
        let Some(record) = self.requests.remove(&request_id) else {
            return;
        };
        self.release_request(&record, now);
    }
    pub fn close_connection(&mut self, connection_id: ConnectionId) {
        let request_ids = self
            .requests
            .iter()
            .filter(|(_, record)| record.connection_id == connection_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for request_id in request_ids {
            self.response_delivered(request_id, 0);
        }
        let Some(record) = self.connections.remove(&connection_id) else {
            return;
        };
        decrement(&mut self.ip_connections, &record.ip);
        decrement(&mut self.peer_connections, &record.peer);
    }
    pub fn shutdown(&mut self, now: i64) {
        let requests = self.requests.keys().cloned().collect::<Vec<_>>();
        for request_id in requests {
            self.response_delivered(request_id, now);
        }
        self.connections.clear();
        self.peer_connections.clear();
        self.ip_connections.clear();
    }
    fn release_request(&mut self, record: &RequestRecord, now: i64) {
        self.inflight = self.inflight.saturating_sub(1);
        decrement(&mut self.peer_inflight, &record.peer);
        if record.failed {
            for key in [
                Self::peer_failure_key(&record.peer),
                Self::ip_failure_key(&record.ip),
            ] {
                if !self.failures.contains_key(&key) && self.failures.len() >= MAX_FAILURE_BUCKETS {
                    continue;
                }
                let bucket = self.failures.entry(key).or_default();
                if bucket.window != now / FAILURE_WINDOW {
                    bucket.window = now / FAILURE_WINDOW;
                    bucket.failures = 0;
                }
                bucket.failures = bucket.failures.saturating_add(1);
            }
        }
    }
    fn peer_failure_key(peer: &str) -> String {
        format!("peer:{peer}")
    }
    fn ip_failure_key(ip: &str) -> String {
        format!("ip:{ip}")
    }
    pub fn sweep(&mut self, now: i64) {
        self.failures
            .retain(|_, b| b.window >= now / FAILURE_WINDOW);
    }
    pub fn connections(&self) -> usize {
        self.connections.len()
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
fn decrement(map: &mut HashMap<String, usize>, key: &str) {
    if let Some(value) = map.get_mut(key) {
        *value = value.saturating_sub(1);
        if *value == 0 {
            map.remove(key);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_close_cannot_undercount_admitted_connections() {
        let mut ledger = AdmissionLedger::default();
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let rejected = ConnectionId::new_unchecked(3);
        assert_eq!(
            ledger.admit_connection(first, "peer-a", "ip"),
            Admission::Accepted
        );
        assert_eq!(
            ledger.admit_connection(second, "peer-a", "ip2"),
            Admission::Accepted
        );
        assert_eq!(
            ledger.admit_connection(rejected, "peer-a", "ip"),
            Admission::Rejected(PublicErrorCode::LimitAuthConnections)
        );
        ledger.close_connection(rejected);
        assert_eq!(ledger.connections(), 2);
        assert_eq!(ledger.peer_connections("peer-a"), 2);
        assert_eq!(ledger.ip_connections("ip"), 1);
        ledger.close_connection(rejected);
        assert_eq!(ledger.connections(), 2);
    }
    #[test]
    fn auth_is_owned_by_connection_id() {
        let mut ledger = AdmissionLedger::default();
        let id = ConnectionId::new_unchecked(7);
        assert_eq!(
            ledger.begin_auth("1", id, 0),
            Admission::Rejected(PublicErrorCode::LimitAuthConnections)
        );
        ledger.admit_connection(id, "peer", "ip");
        assert_eq!(ledger.begin_auth("2", id, 0), Admission::Accepted);
        ledger.mark_response("2", true);
        ledger.response_delivered("2", 0);
        assert_eq!(ledger.inflight(), 0);
    }
    #[test]
    fn response_delivery_and_close_release_each_request_once() {
        let mut ledger = AdmissionLedger::default();
        let connection = ConnectionId::new_unchecked(8);
        ledger.admit_connection(connection, "peer", "ip");
        let request = 3;
        assert_eq!(
            ledger.begin_auth(request, connection, 0),
            Admission::Accepted
        );
        ledger.mark_response(request, true);
        ledger.close_connection(connection);
        ledger.response_delivered(request, 0);
        assert_eq!(ledger.inflight(), 0);
        assert_eq!(ledger.connections(), 0);
    }
}
