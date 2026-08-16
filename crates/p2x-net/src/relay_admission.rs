use libp2p::{Multiaddr, PeerId, relay::RateLimiter};
use p2x_protocol::{Role, Scope};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

const MAX_ENTRIES: usize = 256;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayInstall {
    Installed,
    Capacity,
    Draining,
    Poisoned,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelaySession {
    pub role: Role,
    pub scopes: u32,
    pub quota_profile: String,
    pub authorization_revision: u64,
    pub expires_at: Instant,
}
#[derive(Clone, Debug, Default)]
struct Snapshot {
    entries: HashMap<PeerId, RelaySession>,
    draining: bool,
}
#[derive(Clone, Debug, Default)]
pub struct RelayAdmissionHandle(Arc<RwLock<Snapshot>>);
impl RelayAdmissionHandle {
    pub fn install_checked(&self, peer: PeerId, session: RelaySession) -> RelayInstall {
        let Ok(mut snapshot) = self.0.write() else {
            return RelayInstall::Poisoned;
        };
        if snapshot.draining {
            return RelayInstall::Draining;
        }
        if snapshot.entries.len() >= MAX_ENTRIES && !snapshot.entries.contains_key(&peer) {
            return RelayInstall::Capacity;
        }
        snapshot.entries.insert(peer, session);
        RelayInstall::Installed
    }
    pub fn install(&self, peer: PeerId, session: RelaySession) -> bool {
        self.install_checked(peer, session) == RelayInstall::Installed
    }
    pub fn remove(&self, peer: &PeerId) {
        if let Ok(mut snapshot) = self.0.write() {
            snapshot.entries.remove(peer);
        }
    }
    pub fn set_draining(&self, draining: bool) {
        if let Ok(mut snapshot) = self.0.write() {
            snapshot.draining = draining;
        }
    }
    pub fn clear(&self) {
        if let Ok(mut snapshot) = self.0.write() {
            snapshot.entries.clear();
        }
    }
    pub fn is_poisoned(&self) -> bool {
        self.0.read().is_err()
    }
    pub fn sweep(&self, now: Instant) {
        if let Ok(mut snapshot) = self.0.write() {
            snapshot
                .entries
                .retain(|_, session| session.expires_at > now);
        }
    }
    pub fn is_reservation_authorized(&self, peer: &PeerId, now: Instant) -> bool {
        self.authorized(peer, now, Role::Server, Scope::ReserveRelay)
    }
    pub fn is_circuit_source_authorized(&self, peer: &PeerId, now: Instant) -> bool {
        self.authorized(peer, now, Role::Client, Scope::OpenProxyStream)
    }
    pub fn len(&self) -> usize {
        self.0.read().map(|s| s.entries.len()).unwrap_or(0)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn authorized(&self, peer: &PeerId, now: Instant, role: Role, scope: Scope) -> bool {
        let Ok(snapshot) = self.0.read() else {
            return false;
        };
        if snapshot.draining {
            return false;
        }
        snapshot.entries.get(peer).is_some_and(|session| {
            session.role == role
                && session.scopes & scope.bit() != 0
                && session.quota_profile == "standard"
                && session.expires_at > now
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    pub max_reservations: u32,
    pub max_circuits: u32,
    pub max_circuits_per_peer: u32,
}
impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_reservations: 64,
            max_circuits: 128,
            max_circuits_per_peer: 32,
        }
    }
}
impl RelayLimits {
    pub fn to_libp2p_config(self) -> libp2p::relay::Config {
        libp2p::relay::Config {
            max_reservations: self.max_reservations as usize,
            max_reservations_per_peer: 1,
            reservation_duration: Duration::from_secs(60),
            max_circuits: self.max_circuits as usize,
            max_circuits_per_peer: self.max_circuits_per_peer.saturating_sub(1) as usize,
            max_circuit_duration: Duration::from_secs(3600),
            max_circuit_bytes: 1024 * 1024 * 1024,
            reservation_rate_limiters: vec![],
            circuit_src_rate_limiters: vec![],
        }
    }
}

pub struct ReservationAuthorization {
    admission: RelayAdmissionHandle,
}
impl ReservationAuthorization {
    pub fn new(admission: RelayAdmissionHandle) -> Self {
        Self { admission }
    }
}
impl RateLimiter for ReservationAuthorization {
    fn try_next(&mut self, peer: PeerId, _: &Multiaddr, _now: web_time::Instant) -> bool {
        self.admission
            .is_reservation_authorized(&peer, Instant::now())
    }
}
pub struct CircuitAuthorization {
    admission: RelayAdmissionHandle,
}
impl CircuitAuthorization {
    pub fn new(admission: RelayAdmissionHandle) -> Self {
        Self { admission }
    }
}
impl RateLimiter for CircuitAuthorization {
    fn try_next(&mut self, peer: PeerId, _: &Multiaddr, _now: web_time::Instant) -> bool {
        self.admission
            .is_circuit_source_authorized(&peer, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> PeerId {
        PeerId::random()
    }
    fn session(role: Role, scopes: u32) -> RelaySession {
        RelaySession {
            role,
            scopes,
            quota_profile: "standard".into(),
            authorization_revision: 1,
            expires_at: Instant::now() + Duration::from_secs(30),
        }
    }
    #[test]
    fn gates_role_scope_expiry_and_drain_fail_closed() {
        let admission = RelayAdmissionHandle::default();
        let server = peer();
        let client = peer();
        assert_eq!(
            admission.install_checked(server, session(Role::Server, Scope::ReserveRelay.bit())),
            RelayInstall::Installed
        );
        assert!(admission.is_reservation_authorized(&server, Instant::now()));
        assert!(!admission.is_circuit_source_authorized(&server, Instant::now()));
        assert_eq!(
            admission.install_checked(client, session(Role::Client, Scope::OpenProxyStream.bit())),
            RelayInstall::Installed
        );
        assert!(admission.is_circuit_source_authorized(&client, Instant::now()));
        admission.set_draining(true);
        assert!(!admission.is_circuit_source_authorized(&client, Instant::now()));
        admission.set_draining(false);
        admission.sweep(Instant::now() + Duration::from_secs(31));
        assert_eq!(admission.len(), 0);
    }
    #[test]
    fn install_rejects_drain_before_mutation() {
        let admission = RelayAdmissionHandle::default();
        admission.set_draining(true);
        assert_eq!(
            admission.install_checked(peer(), session(Role::Server, Scope::ReserveRelay.bit())),
            RelayInstall::Draining
        );
        assert!(admission.is_empty());
    }
    #[test]
    fn poisoned_snapshot_fails_closed_and_is_reported() {
        let admission = RelayAdmissionHandle::default();
        let poisoned = admission.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoned.0.write().unwrap();
            panic!("poison relay admission snapshot");
        });
        assert!(admission.is_poisoned());
        assert_eq!(
            admission.install_checked(peer(), session(Role::Server, Scope::ReserveRelay.bit())),
            RelayInstall::Poisoned
        );
        assert!(!admission.is_reservation_authorized(&peer(), Instant::now()));
    }
    #[test]
    fn per_peer_limit_translation_is_n_minus_one() {
        assert_eq!(
            RelayLimits {
                max_circuits_per_peer: 32,
                ..Default::default()
            }
            .to_libp2p_config()
            .max_circuits_per_peer,
            31
        );
    }
}
