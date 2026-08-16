#![allow(dead_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityState {
    Starting,
    Authenticating,
    AuthReady,
    Reserving,
    RelayReady,
    Registering,
    Ready,
    Degraded,
    Draining,
    Withdrawn,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailabilitySnapshot {
    pub auth: bool,
    pub reservation: bool,
    pub registration: bool,
    pub draining: bool,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityAction {
    Authenticate,
    Reserve(u64),
    Register(u64),
    Refresh,
    Withdraw,
    Publish(bool),
}
#[derive(Debug)]
pub struct Availability {
    state: AvailabilityState,
    generation: u64,
    registration_expires_at: i64,
    instance_id: [u8; 16],
}
impl Availability {
    pub fn new(instance_id: [u8; 16]) -> Self {
        Self {
            state: AvailabilityState::Starting,
            generation: 0,
            registration_expires_at: 0,
            instance_id,
        }
    }
    pub const fn state(&self) -> AvailabilityState {
        self.state
    }
    pub const fn instance_id(&self) -> [u8; 16] {
        self.instance_id
    }
    pub fn auth_ready(&mut self) -> AvailabilityAction {
        self.state = AvailabilityState::AuthReady;
        AvailabilityAction::Reserve(self.generation)
    }
    pub fn reservation_ready(&mut self, generation: u64) -> AvailabilityAction {
        if generation != self.generation {
            return AvailabilityAction::Publish(false);
        }
        self.state = AvailabilityState::RelayReady;
        AvailabilityAction::Register(generation)
    }
    pub fn registered(&mut self, generation: u64, expires_at: i64, now: i64) -> AvailabilityAction {
        if generation != self.generation || expires_at <= now {
            self.state = AvailabilityState::Degraded;
            return AvailabilityAction::Publish(false);
        }
        self.registration_expires_at = expires_at;
        self.state = AvailabilityState::Ready;
        AvailabilityAction::Publish(true)
    }
    pub fn reservation_lost(&mut self) -> AvailabilityAction {
        if self.state == AvailabilityState::Ready {
            self.state = AvailabilityState::Degraded;
        }
        self.generation = self.generation.saturating_add(1);
        AvailabilityAction::Publish(false)
    }
    pub fn session_lost(&mut self) -> AvailabilityAction {
        self.state = AvailabilityState::Degraded;
        AvailabilityAction::Authenticate
    }
    pub fn begin_shutdown(&mut self) -> AvailabilityAction {
        self.state = AvailabilityState::Draining;
        AvailabilityAction::Withdraw
    }
    pub fn withdrawn(&mut self) {
        self.state = AvailabilityState::Withdrawn;
    }
    pub fn stopped(&mut self) {
        self.state = AvailabilityState::Stopped;
    }
    pub fn readiness(&self, now: i64) -> AvailabilitySnapshot {
        AvailabilitySnapshot {
            auth: matches!(
                self.state,
                AvailabilityState::AuthReady
                    | AvailabilityState::Reserving
                    | AvailabilityState::RelayReady
                    | AvailabilityState::Registering
                    | AvailabilityState::Ready
            ),
            reservation: matches!(
                self.state,
                AvailabilityState::RelayReady
                    | AvailabilityState::Registering
                    | AvailabilityState::Ready
            ),
            registration: self.state == AvailabilityState::Ready
                && self.registration_expires_at > now,
            draining: matches!(
                self.state,
                AvailabilityState::Draining
                    | AvailabilityState::Withdrawn
                    | AvailabilityState::Stopped
            ),
            generation: self.generation,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_requires_all_gates_and_generation() {
        let mut state = Availability::new([1; 16]);
        assert!(!state.readiness(0).auth);
        assert!(matches!(state.auth_ready(), AvailabilityAction::Reserve(0)));
        assert!(matches!(
            state.reservation_ready(0),
            AvailabilityAction::Register(0)
        ));
        assert_eq!(
            state.registered(0, 30, 1),
            AvailabilityAction::Publish(true)
        );
        assert!(state.readiness(1).registration);
        state.reservation_lost();
        assert!(!state.readiness(1).registration);
        assert!(matches!(
            state.reservation_ready(0),
            AvailabilityAction::Publish(false)
        ));
    }
}
