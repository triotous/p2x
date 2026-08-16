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
    auth: bool,
    reservation: bool,
    registration_expires_at: i64,
    refresh_at: i64,
    instance_id: [u8; 16],
}

impl Availability {
    pub fn new(instance_id: [u8; 16]) -> Self {
        Self {
            state: AvailabilityState::Starting,
            generation: 0,
            auth: false,
            reservation: false,
            registration_expires_at: 0,
            refresh_at: i64::MAX,
            instance_id,
        }
    }

    pub const fn state(&self) -> AvailabilityState {
        self.state
    }
    pub const fn instance_id(&self) -> [u8; 16] {
        self.instance_id
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn auth_ready(&mut self) -> AvailabilityAction {
        self.auth = true;
        self.state = if self.reservation && self.registration_expires_at > 0 {
            AvailabilityState::Ready
        } else if self.reservation {
            AvailabilityState::RelayReady
        } else {
            AvailabilityState::Reserving
        };
        AvailabilityAction::Reserve(self.generation)
    }

    pub fn reservation_ready(&mut self, generation: u64) -> AvailabilityAction {
        if generation < self.generation || !self.auth || self.draining() {
            return AvailabilityAction::Publish(false);
        }
        self.generation = generation;
        self.reservation = true;
        self.state = AvailabilityState::RelayReady;
        AvailabilityAction::Register(generation)
    }

    pub fn registered(&mut self, generation: u64, expires_at: i64, now: i64) -> AvailabilityAction {
        if generation != self.generation || !self.auth || !self.reservation || expires_at <= now {
            self.registration_expires_at = 0;
            self.state = AvailabilityState::Degraded;
            return AvailabilityAction::Publish(false);
        }
        self.registration_expires_at = expires_at;
        self.refresh_at = now + ((expires_at - now) / 3).max(1);
        self.state = AvailabilityState::Ready;
        AvailabilityAction::Publish(true)
    }

    pub fn tick(&mut self, now: i64) -> AvailabilityAction {
        if self.state == AvailabilityState::Ready && now >= self.registration_expires_at {
            self.registration_expires_at = 0;
            self.state = AvailabilityState::Degraded;
            return AvailabilityAction::Publish(false);
        }
        if self.state == AvailabilityState::Ready && now >= self.refresh_at {
            return AvailabilityAction::Refresh;
        }
        AvailabilityAction::Publish(
            self.readiness(now).auth
                && self.readiness(now).reservation
                && self.readiness(now).registration,
        )
    }

    pub fn reservation_lost(&mut self) -> AvailabilityAction {
        self.reservation = false;
        self.registration_expires_at = 0;
        if !self.draining() {
            self.state = AvailabilityState::Degraded;
        }
        self.generation = self.generation.saturating_add(1);
        AvailabilityAction::Publish(false)
    }

    pub fn session_lost(&mut self) -> AvailabilityAction {
        self.auth = false;
        self.reservation = false;
        self.registration_expires_at = 0;
        self.state = AvailabilityState::Degraded;
        AvailabilityAction::Authenticate
    }

    pub fn registration_lost(&mut self) -> AvailabilityAction {
        self.registration_expires_at = 0;
        if !self.draining() {
            self.state = AvailabilityState::Degraded;
        }
        AvailabilityAction::Publish(false)
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
            auth: self.auth && !self.draining(),
            reservation: self.reservation && !self.draining(),
            registration: self.registration_expires_at > now && !self.draining(),
            draining: self.draining(),
            generation: self.generation,
        }
    }

    fn draining(&self) -> bool {
        matches!(
            self.state,
            AvailabilityState::Draining | AvailabilityState::Withdrawn | AvailabilityState::Stopped
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_current_auth_reservation_and_lease() {
        let mut state = Availability::new([1; 16]);
        assert!(!state.readiness(0).auth);
        assert_eq!(state.auth_ready(), AvailabilityAction::Reserve(0));
        assert_eq!(state.reservation_ready(0), AvailabilityAction::Register(0));
        assert_eq!(
            state.registered(0, 30, 1),
            AvailabilityAction::Publish(true)
        );
        assert!(state.readiness(1).registration);
        assert_eq!(state.tick(30), AvailabilityAction::Publish(false));
        assert!(!state.readiness(30).registration);
    }

    #[test]
    fn stale_generation_cannot_restore_readiness() {
        let mut state = Availability::new([1; 16]);
        state.auth_ready();
        state.reservation_ready(0);
        state.reservation_lost();
        assert_eq!(state.generation(), 1);
        assert_eq!(
            state.reservation_ready(0),
            AvailabilityAction::Publish(false)
        );
        assert!(!state.readiness(0).reservation);
    }

    #[test]
    fn refresh_is_due_before_expiry() {
        let mut state = Availability::new([1; 16]);
        state.auth_ready();
        state.reservation_ready(0);
        state.registered(0, 30, 0);
        assert_eq!(state.tick(10), AvailabilityAction::Refresh);
    }
}
