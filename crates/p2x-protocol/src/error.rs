use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[non_exhaustive]
pub enum PublicErrorCode {
    AuthInvalidCredential,
    AuthExchangeIdentityMismatch,
    AuthSessionRequired,
    AuthSessionExpired,
    AuthRoleForbidden,
    AuthTicketInvalid,
    AuthTicketExpired,
    ExchangeOverloaded,
    ExchangeTimeout,
    LimitAuthConnections,
    LimitAuthRequests,
    LimitAuthSessions,
    ProtocolFrameTooLarge,
    ProtocolMalformed,
    ProtocolUnsupportedVersion,
    ProtocolCapabilityMismatch,
    RegistryInvalidAdvertisement,
    RegistryConflict,
    RegistryReservationRequired,
    RegistryStaleRevision,
    RegistryNotFound,
    RegistryOffline,
    RelayUnauthorized,
    RelayQuota,
    LimitServices,
    LimitRegistryRequests,
    ExchangeDraining,
}
impl PublicErrorCode {
    const ALL: &'static [Self] = &[
        Self::AuthInvalidCredential,
        Self::AuthExchangeIdentityMismatch,
        Self::AuthSessionRequired,
        Self::AuthSessionExpired,
        Self::AuthRoleForbidden,
        Self::AuthTicketInvalid,
        Self::AuthTicketExpired,
        Self::ExchangeOverloaded,
        Self::ExchangeTimeout,
        Self::LimitAuthConnections,
        Self::LimitAuthRequests,
        Self::LimitAuthSessions,
        Self::ProtocolFrameTooLarge,
        Self::ProtocolMalformed,
        Self::ProtocolUnsupportedVersion,
        Self::ProtocolCapabilityMismatch,
        Self::RegistryInvalidAdvertisement,
        Self::RegistryConflict,
        Self::RegistryReservationRequired,
        Self::RegistryStaleRevision,
        Self::RegistryNotFound,
        Self::RegistryOffline,
        Self::RelayUnauthorized,
        Self::RelayQuota,
        Self::LimitServices,
        Self::LimitRegistryRequests,
        Self::ExchangeDraining,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthInvalidCredential => "auth.invalid_credential",
            Self::AuthExchangeIdentityMismatch => "auth.exchange_identity_mismatch",
            Self::AuthSessionRequired => "auth.session_required",
            Self::AuthSessionExpired => "auth.session_expired",
            Self::AuthRoleForbidden => "auth.role_forbidden",
            Self::AuthTicketInvalid => "auth.ticket_invalid",
            Self::AuthTicketExpired => "auth.ticket_expired",
            Self::ExchangeOverloaded => "exchange.overloaded",
            Self::ExchangeTimeout => "exchange.timeout",
            Self::LimitAuthConnections => "limit.auth_connections",
            Self::LimitAuthRequests => "limit.auth_requests",
            Self::LimitAuthSessions => "limit.auth_sessions",
            Self::ProtocolFrameTooLarge => "protocol.frame_too_large",
            Self::ProtocolMalformed => "protocol.malformed",
            Self::ProtocolUnsupportedVersion => "protocol.unsupported_version",
            Self::ProtocolCapabilityMismatch => "protocol.capability_mismatch",
            Self::RegistryInvalidAdvertisement => "registry.invalid_advertisement",
            Self::RegistryConflict => "registry.conflict",
            Self::RegistryReservationRequired => "registry.reservation_required",
            Self::RegistryStaleRevision => "registry.stale_revision",
            Self::RegistryNotFound => "registry.not_found",
            Self::RegistryOffline => "registry.offline",
            Self::RelayUnauthorized => "relay.unauthorized",
            Self::RelayQuota => "relay.quota",
            Self::LimitServices => "limit.services",
            Self::LimitRegistryRequests => "limit.registry_requests",
            Self::ExchangeDraining => "exchange.draining",
        }
    }
    pub fn try_from_wire(value: &str) -> Result<Self, ()> {
        Self::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == value)
            .ok_or(())
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "auth.invalid_credential" => Self::AuthInvalidCredential,
            "auth.exchange_identity_mismatch" => Self::AuthExchangeIdentityMismatch,
            "auth.session_required" => Self::AuthSessionRequired,
            "auth.session_expired" => Self::AuthSessionExpired,
            "auth.role_forbidden" => Self::AuthRoleForbidden,
            "auth.ticket_invalid" => Self::AuthTicketInvalid,
            "auth.ticket_expired" => Self::AuthTicketExpired,
            "exchange.overloaded" => Self::ExchangeOverloaded,
            "exchange.timeout" => Self::ExchangeTimeout,
            "limit.auth_connections" => Self::LimitAuthConnections,
            "limit.auth_requests" => Self::LimitAuthRequests,
            "limit.auth_sessions" => Self::LimitAuthSessions,
            "protocol.frame_too_large" => Self::ProtocolFrameTooLarge,
            "protocol.unsupported_version" => Self::ProtocolUnsupportedVersion,
            "protocol.capability_mismatch" => Self::ProtocolCapabilityMismatch,
            "registry.invalid_advertisement" => Self::RegistryInvalidAdvertisement,
            "registry.conflict" => Self::RegistryConflict,
            "registry.reservation_required" => Self::RegistryReservationRequired,
            "registry.stale_revision" => Self::RegistryStaleRevision,
            "registry.not_found" => Self::RegistryNotFound,
            "registry.offline" => Self::RegistryOffline,
            "relay.unauthorized" => Self::RelayUnauthorized,
            "relay.quota" => Self::RelayQuota,
            "limit.services" => Self::LimitServices,
            "limit.registry_requests" => Self::LimitRegistryRequests,
            "exchange.draining" => Self::ExchangeDraining,
            _ => Self::ProtocolMalformed,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicError {
    pub code: PublicErrorCode,
    pub retryable: bool,
}
impl PublicError {
    pub const fn new(code: PublicErrorCode, retryable: bool) -> Self {
        Self { code, retryable }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_round_trip() {
        for code in [
            PublicErrorCode::AuthInvalidCredential,
            PublicErrorCode::ProtocolMalformed,
            PublicErrorCode::LimitAuthSessions,
        ] {
            assert_eq!(PublicErrorCode::parse(code.as_str()), code);
        }
        assert_eq!(
            PublicErrorCode::parse("secret"),
            PublicErrorCode::ProtocolMalformed
        );
        assert!(PublicErrorCode::try_from_wire("secret").is_err());
    }
}
