use libp2p::{PeerId, swarm::ConnectionId};
use p2x_protocol::PublicErrorCode;
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

pub const MAX_GLOBAL: usize = 128;
pub const MAX_PER_PEER: usize = 1;
pub const MAX_PER_MINUTE: usize = 30;
pub const MAX_BUCKETS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryAdmission {
    Accepted,
    Rejected(PublicErrorCode),
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Key {
    request_id: String,
    connection_id: ConnectionId,
    peer: PeerId,
}
#[derive(Default)]
pub struct RegistryAdmissionLedger {
    owners: HashMap<Key, ()>,
    peer_counts: HashMap<PeerId, usize>,
    buckets: HashMap<PeerId, VecDeque<i64>>,
}
impl RegistryAdmissionLedger {
    pub fn begin(
        &mut self,
        peer: PeerId,
        request_id: impl ToString,
        connection_id: ConnectionId,
        now: i64,
    ) -> RegistryAdmission {
        self.sweep(now);
        if self.owners.len() >= MAX_GLOBAL
            || self.peer_counts.get(&peer).copied().unwrap_or(0) >= MAX_PER_PEER
        {
            return RegistryAdmission::Rejected(PublicErrorCode::LimitRegistryRequests);
        }
        if !self.buckets.contains_key(&peer) && self.buckets.len() >= MAX_BUCKETS {
            return RegistryAdmission::Rejected(PublicErrorCode::ExchangeOverloaded);
        }
        let bucket = self.buckets.entry(peer).or_default();
        if bucket.len() >= MAX_PER_MINUTE {
            return RegistryAdmission::Rejected(PublicErrorCode::LimitRegistryRequests);
        }
        let key = Key {
            request_id: request_id.to_string(),
            connection_id,
            peer,
        };
        if self.owners.contains_key(&key) {
            return RegistryAdmission::Rejected(PublicErrorCode::LimitRegistryRequests);
        }
        bucket.push_back(now);
        self.owners.insert(key, ());
        *self.peer_counts.entry(peer).or_default() += 1;
        RegistryAdmission::Accepted
    }
    pub fn release(
        &mut self,
        peer: PeerId,
        request_id: impl ToString,
        connection_id: ConnectionId,
    ) {
        let key = Key {
            request_id: request_id.to_string(),
            connection_id,
            peer,
        };
        if self.owners.remove(&key).is_some() {
            decrement(&mut self.peer_counts, &peer);
        }
    }
    pub fn close_connection(&mut self, connection_id: ConnectionId) {
        let keys = self
            .owners
            .keys()
            .filter(|key| key.connection_id == connection_id)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if self.owners.remove(&key).is_some() {
                decrement(&mut self.peer_counts, &key.peer);
            }
        }
    }
    pub fn shutdown(&mut self) {
        self.owners.clear();
        self.peer_counts.clear();
        self.buckets.clear();
    }
    pub fn sweep(&mut self, now: i64) {
        let window = Duration::from_secs(60).as_secs() as i64;
        self.buckets.retain(|_, bucket| {
            while bucket
                .front()
                .is_some_and(|at| now.saturating_sub(*at) >= window)
            {
                bucket.pop_front();
            }
            !bucket.is_empty()
        });
    }
    pub fn inflight(&self) -> usize {
        self.owners.len()
    }
}
fn decrement(map: &mut HashMap<PeerId, usize>, peer: &PeerId) {
    if let Some(value) = map.get_mut(peer) {
        *value = value.saturating_sub(1);
        if *value == 0 {
            map.remove(peer);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn global_peer_and_rate_limits_and_idempotent_release() {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(1);
        let mut ledger = RegistryAdmissionLedger::default();
        assert_eq!(
            ledger.begin(peer, 1u64, connection, 0),
            RegistryAdmission::Accepted
        );
        assert_eq!(
            ledger.begin(peer, 2u64, connection, 0),
            RegistryAdmission::Rejected(PublicErrorCode::LimitRegistryRequests)
        );
        ledger.release(peer, 1u64, connection);
        ledger.release(peer, 1u64, connection);
        assert_eq!(ledger.inflight(), 0);
    }
    #[test]
    fn rolling_rate_limit_allows_after_window() {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(1);
        let mut ledger = RegistryAdmissionLedger::default();
        for id in 0..MAX_PER_MINUTE {
            assert_eq!(
                ledger.begin(peer, id as u64, connection, 0),
                RegistryAdmission::Accepted
            );
            ledger.release(peer, id as u64, connection);
        }
        assert_eq!(
            ledger.begin(peer, 99u64, connection, 0),
            RegistryAdmission::Rejected(PublicErrorCode::LimitRegistryRequests)
        );
        assert_eq!(
            ledger.begin(peer, 100u64, connection, 60),
            RegistryAdmission::Accepted
        );
    }
}
