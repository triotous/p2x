use libp2p::PeerId;
use p2x_protocol::{PublicErrorCode, UpstreamId};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Dialing,
    Active,
}
#[derive(Clone, Debug)]
struct Entry {
    peer: PeerId,
    service: UpstreamId,
    phase: Phase,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionToken {
    pub stream_id: [u8; 16],
}
impl AdmissionToken {
    pub const fn new(stream_id: [u8; 16]) -> Self {
        Self { stream_id }
    }
    pub const fn empty() -> Self {
        Self::new([0; 16])
    }
    pub fn is_empty(self) -> bool {
        self.stream_id == [0; 16]
    }
}
#[derive(Debug)]
pub struct StreamAdmission {
    max_workers: usize,
    max_per_client: usize,
    max_dials: usize,
    entries: HashMap<[u8; 16], Entry>,
}
impl StreamAdmission {
    pub fn new(max_workers: usize, max_per_client: usize, max_dials: usize) -> Self {
        Self {
            max_workers,
            max_per_client,
            max_dials,
            entries: HashMap::new(),
        }
    }

    pub fn preflight(
        &self,
        peer: PeerId,
        service: &UpstreamId,
        service_limit: usize,
    ) -> Result<(), PublicErrorCode> {
        if self.entries.len() >= self.max_workers {
            return Err(PublicErrorCode::LimitProxyStreams);
        }
        let dials = self
            .entries
            .values()
            .filter(|entry| entry.phase == Phase::Dialing)
            .count();
        if dials >= self.max_dials {
            return Err(PublicErrorCode::LimitProxyStreams);
        }
        let service_count = self
            .entries
            .values()
            .filter(|entry| entry.service == *service)
            .count();
        if service_count >= service_limit || self.peer_count(peer) >= self.max_per_client {
            return Err(PublicErrorCode::LimitProxyStreams);
        }
        Ok(())
    }

    pub fn reserve(
        &mut self,
        token: AdmissionToken,
        peer: PeerId,
        service: UpstreamId,
        service_limit: usize,
    ) -> Result<(), PublicErrorCode> {
        self.preflight(peer, &service, service_limit)?;
        if self
            .entries
            .insert(
                token.stream_id,
                Entry {
                    peer,
                    service,
                    phase: Phase::Dialing,
                },
            )
            .is_some()
        {
            return Err(PublicErrorCode::ProtocolMalformed);
        }
        Ok(())
    }

    pub fn promote(&mut self, token: AdmissionToken) -> bool {
        self.entries.get_mut(&token.stream_id).is_some_and(|entry| {
            if entry.phase != Phase::Dialing {
                return false;
            }
            entry.phase = Phase::Active;
            true
        })
    }

    pub fn release(&mut self, token: AdmissionToken) -> bool {
        self.entries.remove(&token.stream_id).is_some()
    }

    pub fn contains(&self, token: AdmissionToken) -> bool {
        self.entries.contains_key(&token.stream_id)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn dialing(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.phase == Phase::Dialing)
            .count()
    }
    pub fn active(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.phase == Phase::Active)
            .count()
    }
    pub fn peer_count(&self, peer: PeerId) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.peer == peer)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn service() -> UpstreamId {
        UpstreamId::new("orders").unwrap()
    }
    #[test]
    fn preflight_reserve_promote_release_is_exactly_once() {
        let peer = PeerId::random();
        let mut admission = StreamAdmission::new(2, 2, 1);
        let first = AdmissionToken::new([1; 16]);
        admission.reserve(first, peer, service(), 1).unwrap();
        assert_eq!(admission.dialing(), 1);
        assert_eq!(
            admission.preflight(peer, &service(), 1),
            Err(PublicErrorCode::LimitProxyStreams)
        );
        assert!(admission.promote(first));
        assert!(!admission.promote(first));
        assert!(admission.release(first));
        assert!(!admission.release(first));
        assert_eq!(admission.len(), 0);
    }

    #[test]
    fn global_and_dial_bounds_reject_before_reservation() {
        let peer = PeerId::random();
        let mut admission = StreamAdmission::new(1, 1, 1);
        admission
            .reserve(AdmissionToken::new([1; 16]), peer, service(), 2)
            .unwrap();
        assert_eq!(
            admission.preflight(peer, &UpstreamId::new("other").unwrap(), 2),
            Err(PublicErrorCode::LimitProxyStreams)
        );
        assert_eq!(admission.len(), 1);
    }
}
