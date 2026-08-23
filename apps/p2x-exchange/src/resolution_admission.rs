use libp2p::{PeerId, swarm::ConnectionId};
use p2x_protocol::PublicErrorCode;
use std::collections::{HashMap, VecDeque};

pub const MAX_GLOBAL_INFLIGHT: usize = 128;
pub const MAX_PER_CLIENT_INFLIGHT: usize = 16;
pub const MAX_PER_MINUTE: usize = 120;
pub const MAX_BUCKETS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveAdmission {
    Accepted,
    Rejected(PublicErrorCode),
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ResolveOwner {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub request_id: String,
}
#[derive(Default)]
struct Bucket {
    accepted_at: VecDeque<i64>,
}
pub struct ResolveAdmissionLedger {
    max_global: usize,
    max_per_client: usize,
    max_per_minute: usize,
    max_buckets: usize,
    owners: HashMap<ResolveOwner, ()>,
    clients: HashMap<PeerId, usize>,
    buckets: HashMap<PeerId, Bucket>,
}
impl Default for ResolveAdmissionLedger {
    fn default() -> Self {
        Self::with_limits(
            MAX_GLOBAL_INFLIGHT,
            MAX_PER_CLIENT_INFLIGHT,
            MAX_PER_MINUTE,
            MAX_BUCKETS,
        )
    }
}
impl ResolveAdmissionLedger {
    pub fn with_limits(
        max_global: usize,
        max_per_client: usize,
        max_per_minute: usize,
        max_buckets: usize,
    ) -> Self {
        Self {
            max_global,
            max_per_client,
            max_per_minute,
            max_buckets,
            owners: HashMap::new(),
            clients: HashMap::new(),
            buckets: HashMap::new(),
        }
    }
    pub fn begin(&mut self, owner: ResolveOwner, now: i64) -> ResolveAdmission {
        self.sweep(now);
        if self.owners.contains_key(&owner)
            || self.owners.len() >= self.max_global
            || self.clients.get(&owner.peer_id).copied().unwrap_or(0) >= self.max_per_client
        {
            return ResolveAdmission::Rejected(PublicErrorCode::LimitResolveRequests);
        }
        if !self.buckets.contains_key(&owner.peer_id) && self.buckets.len() >= self.max_buckets {
            return ResolveAdmission::Rejected(PublicErrorCode::ExchangeOverloaded);
        }
        let bucket = self.buckets.entry(owner.peer_id).or_default();
        if bucket.accepted_at.len() >= self.max_per_minute {
            return ResolveAdmission::Rejected(PublicErrorCode::LimitResolveRequests);
        }
        bucket.accepted_at.push_back(now);
        *self.clients.entry(owner.peer_id).or_default() += 1;
        self.owners.insert(owner, ());
        ResolveAdmission::Accepted
    }
    pub fn release(&mut self, owner: &ResolveOwner) {
        if self.owners.remove(owner).is_some()
            && let Some(count) = self.clients.get_mut(&owner.peer_id)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.clients.remove(&owner.peer_id);
            }
        }
    }
    pub fn release_request(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        request_id: impl ToString,
    ) {
        self.release(&ResolveOwner {
            peer_id,
            connection_id,
            request_id: request_id.to_string(),
        });
    }

    pub fn close_connection(&mut self, connection_id: ConnectionId) {
        let owners = self
            .owners
            .keys()
            .filter(|owner| owner.connection_id == connection_id)
            .cloned()
            .collect::<Vec<_>>();
        for owner in owners {
            self.release(&owner);
        }
    }
    pub fn sweep(&mut self, now: i64) {
        self.buckets.retain(|_, bucket| {
            while bucket
                .accepted_at
                .front()
                .is_some_and(|at| now.saturating_sub(*at) >= 60)
            {
                bucket.accepted_at.pop_front();
            }
            !bucket.accepted_at.is_empty()
        });
    }
    pub fn inflight(&self) -> usize {
        self.owners.len()
    }

    pub fn is_admitted(&self, owner: &ResolveOwner) -> bool {
        self.owners.contains_key(owner)
    }
    pub fn shutdown(&mut self) {
        self.owners.clear();
        self.clients.clear();
        self.buckets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner(peer: PeerId, id: u64) -> ResolveOwner {
        ResolveOwner {
            peer_id: peer,
            connection_id: ConnectionId::new_unchecked(1),
            request_id: id.to_string(),
        }
    }
    #[test]
    fn limits_and_every_release_path_are_bounded() {
        let peer = PeerId::random();
        let mut ledger = ResolveAdmissionLedger::with_limits(2, 1, 2, 1);
        assert_eq!(ledger.begin(owner(peer, 1), 0), ResolveAdmission::Accepted);
        assert_eq!(
            ledger.begin(owner(peer, 2), 0),
            ResolveAdmission::Rejected(PublicErrorCode::LimitResolveRequests)
        );
        ledger.release(&owner(peer, 1));
        assert_eq!(ledger.inflight(), 0);
        assert_eq!(ledger.begin(owner(peer, 2), 60), ResolveAdmission::Accepted);
        ledger.close_connection(ConnectionId::new_unchecked(1));
        assert_eq!(ledger.inflight(), 0);
        ledger.shutdown();
    }
}
