use crate::{
    config::ServiceConfig,
    proxy_open::{Candidate, ServerDecision},
    stream_admission::{AdmissionToken, StreamAdmission},
    ticket_admission::{TicketAdmission, TicketAdmissionLedger},
};
use libp2p::PeerId;
use p2x_protocol::{
    ProxyOpenResponseV1, PublicError, PublicErrorCode, RegistrationRevision, Tenant,
};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProxyWorkerId(pub u64);

#[derive(Clone, Copy, Debug)]
pub struct WorkerRecord {
    pub peer_id: PeerId,
    pub connection_id: libp2p::swarm::ConnectionId,
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
        connection_id: libp2p::swarm::ConnectionId,
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

pub struct ProxyDecisionContext<'a> {
    pub issuer: PeerId,
    pub server: PeerId,
    pub tenant: &'a Tenant,
    pub registration_revision: Option<RegistrationRevision>,
    pub registration_expires_at: i64,
    pub authorization_revision: u64,
    pub now: i64,
}

pub struct ServerProxyOwner {
    ticket_admission: TicketAdmissionLedger,
    stream_admission: StreamAdmission,
    worker_admissions: HashMap<ProxyWorkerId, AdmissionToken>,
    service_config: Option<ServiceConfig>,
}

impl ServerProxyOwner {
    pub fn new(
        ticket_admission: TicketAdmissionLedger,
        service_config: Option<ServiceConfig>,
    ) -> Self {
        let (max_workers, max_workers_per_client, max_upstream_dials) =
            service_config.as_ref().map_or((256, 32, 64), |config| {
                (
                    config.proxy.max_workers,
                    config.proxy.max_workers_per_client,
                    config.proxy.max_upstream_dials,
                )
            });
        Self {
            ticket_admission,
            stream_admission: StreamAdmission::new(
                max_workers,
                max_workers_per_client,
                max_upstream_dials,
            ),
            worker_admissions: HashMap::new(),
            service_config,
        }
    }

    pub fn decide(
        &mut self,
        candidate: &Candidate,
        context: ProxyDecisionContext<'_>,
    ) -> ServerDecision {
        let reject = |request_id: Option<[u8; 16]>, code: PublicErrorCode| {
            ServerDecision::Reject(ProxyOpenResponseV1::Rejected {
                request_id,
                error: PublicError::new(
                    code,
                    matches!(
                        code,
                        PublicErrorCode::RegistryStaleRevision
                            | PublicErrorCode::LimitProxyStreams
                            | PublicErrorCode::RegistryOffline
                    ),
                ),
            })
        };
        let Ok(open) = candidate.open.as_ref() else {
            return reject(None, candidate.open.as_ref().unwrap_err().to_owned());
        };
        if std::time::Instant::now() >= candidate.deadline {
            return reject(Some(open.request_id), PublicErrorCode::PeerSetupTimeout);
        }
        let Some(services) = self.service_config.as_ref() else {
            return reject(Some(open.request_id), PublicErrorCode::AuthSessionRequired);
        };
        let Some(service) = services.service(&open.upstream_id) else {
            return reject(Some(open.request_id), PublicErrorCode::RegistryNotFound);
        };
        let Some(upstream) = services.upstreams.get(&open.upstream_id).cloned() else {
            return reject(Some(open.request_id), PublicErrorCode::RegistryNotFound);
        };
        let Ok(validation) = candidate.validation.as_ref() else {
            return reject(
                Some(open.request_id),
                candidate.validation.as_ref().unwrap_err().to_owned(),
            );
        };
        if let Err(code) = self
            .ticket_admission
            .preflight_candidate(validation, context.now)
        {
            return reject(Some(open.request_id), code);
        }
        if let Err(code) = self.ticket_admission.validate_candidate(
            validation,
            context.issuer,
            candidate.peer_id,
            context.server,
            context.tenant,
            service,
            context.registration_revision,
            context.registration_expires_at,
            context.authorization_revision,
            open,
            context.now,
        ) {
            return reject(Some(open.request_id), code);
        }
        if service.selector().protocol() != p2x_protocol::ProtocolClass::Tcp {
            return reject(
                Some(open.request_id),
                PublicErrorCode::ProtocolCapabilityMismatch,
            );
        }
        if upstream.advertisement.health() != p2x_protocol::Health::Ready {
            return reject(Some(open.request_id), PublicErrorCode::RegistryOffline);
        }
        if let Err(code) = self.stream_admission.preflight(
            candidate.peer_id,
            &open.upstream_id,
            upstream.concurrency_limit,
        ) {
            return reject(Some(open.request_id), code);
        }
        let stream_id = match self
            .ticket_admission
            .allocate_stream_id(validation, context.now)
        {
            Ok(stream_id) => stream_id,
            Err(code) => return reject(Some(open.request_id), code),
        };
        let admission = AdmissionToken::new(stream_id);
        if let TicketAdmission::Rejected(code) = self
            .ticket_admission
            .consume_candidate_with_stream_id(validation.clone(), stream_id, context.now)
        {
            return reject(Some(open.request_id), code);
        }
        if let Err(code) = self.stream_admission.reserve(
            admission,
            candidate.peer_id,
            open.upstream_id.clone(),
            upstream.concurrency_limit,
        ) {
            return reject(Some(open.request_id), code);
        }
        if self
            .worker_admissions
            .insert(candidate.worker_id, admission)
            .is_some()
        {
            let _ = self.stream_admission.release(admission);
            return reject(Some(open.request_id), PublicErrorCode::ProtocolMalformed);
        }
        ServerDecision::Admit {
            stream_id,
            admission,
            upstream,
            copy_buffer_bytes: services.proxy.copy_buffer_bytes,
        }
    }

    pub fn promote(
        &mut self,
        worker_id: ProxyWorkerId,
        admission: AdmissionToken,
    ) -> Result<(), &'static str> {
        if self.worker_admissions.get(&worker_id) != Some(&admission) {
            return Err("proxy worker admission correlation mismatch");
        }
        self.stream_admission
            .promote(admission)
            .then_some(())
            .ok_or("proxy stream promotion is not valid")
    }

    pub fn complete(
        &mut self,
        worker_id: ProxyWorkerId,
        admission: Option<AdmissionToken>,
    ) -> Result<(), &'static str> {
        let owned = self.worker_admissions.remove(&worker_id);
        let admission = match (owned, admission) {
            (Some(expected), Some(actual)) if expected != actual => {
                return Err("proxy worker admission release correlation mismatch");
            }
            (Some(expected), _) => expected,
            (None, Some(actual)) => actual,
            (None, None) => return Ok(()),
        };
        if self.stream_admission.release(admission) {
            Ok(())
        } else {
            Err("proxy stream admission released more than once")
        }
    }

    pub fn release(&mut self, admission: AdmissionToken) -> bool {
        self.stream_admission.release(admission)
    }

    pub fn worker_count(&self) -> usize {
        self.worker_admissions.len()
    }

    pub fn stream_admission(&self) -> &StreamAdmission {
        &self.stream_admission
    }

    pub fn stream_admission_mut(&mut self) -> &mut StreamAdmission {
        &mut self.stream_admission
    }

    pub fn ticket_admission_mut(&mut self) -> &mut TicketAdmissionLedger {
        &mut self.ticket_admission
    }

    pub fn clear_tickets(&mut self) {
        self.ticket_admission.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_record_requires_one_admission_and_one_acceptance() {
        let peer = PeerId::random();
        let connection = libp2p::swarm::ConnectionId::new_unchecked(1);
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

    #[test]
    fn owner_exposes_exact_release_transition() {
        let tickets = TicketAdmissionLedger::new(1, 0).unwrap();
        let mut owner = ServerProxyOwner::new(tickets, None);
        let admission = AdmissionToken::new([8; 16]);
        assert!(owner.promote(ProxyWorkerId(1), admission).is_err());
        assert!(owner.complete(ProxyWorkerId(1), None).is_ok());
        assert!(owner.stream_admission().is_empty());
    }
}
