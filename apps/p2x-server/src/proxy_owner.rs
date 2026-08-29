use crate::stream_admission::AdmissionToken;
use libp2p::{PeerId, swarm::ConnectionId};
use std::collections::HashMap;

pub use crate::proxy_open::ProxyWorkerId;

#[derive(Clone, Copy, Debug)]
pub struct WorkerRecord {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub selected_path: p2x_net::probe::ProbePath,
    pub admission: Option<AdmissionToken>,
    pub accepted: bool,
    pub setup_duration: std::time::Duration,
    pub request_id_hash: u64,
    pub stream_id_hash: Option<u64>,
}

#[derive(Default, Debug)]
pub struct ProxyWorkerTable {
    next_id: u64,
    workers: HashMap<ProxyWorkerId, WorkerRecord>,
}

impl ProxyWorkerTable {
    pub fn insert(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        selected_path: p2x_net::probe::ProbePath,
    ) -> ProxyWorkerId {
        self.next_id = self.next_id.saturating_add(1);
        let id = ProxyWorkerId(self.next_id);
        self.workers.insert(
            id,
            WorkerRecord {
                peer_id,
                connection_id,
                selected_path,
                admission: None,
                accepted: false,
                setup_duration: std::time::Duration::ZERO,
                request_id_hash: 0,
                stream_id_hash: None,
            },
        );
        id
    }

    pub fn attach_admission(
        &mut self,
        id: ProxyWorkerId,
        admission: AdmissionToken,
    ) -> Result<(), &'static str> {
        let record = self.workers.get_mut(&id).ok_or("proxy worker missing")?;
        if record.admission.is_some() || admission.is_empty() {
            return Err("proxy worker admission already attached");
        }
        record.admission = Some(admission);
        Ok(())
    }

    pub fn mark_accepted(
        &mut self,
        id: ProxyWorkerId,
        setup_duration: std::time::Duration,
        request_id_hash: u64,
        stream_id_hash: u64,
    ) -> Result<(), &'static str> {
        let record = self.workers.get_mut(&id).ok_or("proxy worker missing")?;
        if record.accepted || record.admission.is_none() {
            return Err("proxy worker cannot be accepted");
        }
        record.accepted = true;
        record.setup_duration = setup_duration;
        record.request_id_hash = request_id_hash;
        record.stream_id_hash = Some(stream_id_hash);
        Ok(())
    }

    pub fn get(&self, id: ProxyWorkerId) -> Option<WorkerRecord> {
        self.workers.get(&id).copied()
    }

    pub fn detach_admission(&mut self, id: ProxyWorkerId) -> Option<AdmissionToken> {
        self.workers.get_mut(&id)?.admission.take()
    }

    pub fn remove(&mut self, id: ProxyWorkerId) -> Option<WorkerRecord> {
        self.workers.remove(&id)
    }
    pub fn len(&self) -> usize {
        self.workers.len()
    }
    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }
    pub fn ids(&self) -> impl Iterator<Item = ProxyWorkerId> + '_ {
        self.workers.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_record_requires_one_admission_and_one_acceptance() {
        let peer = PeerId::random();
        let connection = ConnectionId::new_unchecked(1);
        let mut table = ProxyWorkerTable::default();
        let id = table.insert(peer, connection, p2x_net::probe::ProbePath::Direct);
        assert!(
            table
                .mark_accepted(id, std::time::Duration::ZERO, 1, 2)
                .is_err()
        );
        let admission = AdmissionToken::new([7; 16]);
        table.attach_admission(id, admission).unwrap();
        assert!(table.attach_admission(id, admission).is_err());
        table
            .mark_accepted(id, std::time::Duration::ZERO, 1, 2)
            .unwrap();
        assert!(
            table
                .mark_accepted(id, std::time::Duration::ZERO, 1, 2)
                .is_err()
        );
        assert_eq!(table.remove(id).unwrap().admission, Some(admission));
        assert!(table.remove(id).is_none());
    }
}
