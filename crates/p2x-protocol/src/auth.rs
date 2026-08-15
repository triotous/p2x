use crate::credential::TokenSecret;
use crate::{
    error::PublicError,
    ids::{CredentialId, QuotaProfile, Tenant},
};
use serde::{Deserialize, Serialize};

pub const KNOWN_AUTH_FEATURES_V1: u64 = 0;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Role {
    Client,
    Server,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Scope {
    RegisterServices,
    ReserveRelay,
    OpenProxyStream,
}
impl Scope {
    pub const fn bit(self) -> u32 {
        match self {
            Self::RegisterServices => 1,
            Self::ReserveRelay => 2,
            Self::OpenProxyStream => 4,
        }
    }
}
pub enum AuthRequest {
    Authenticate {
        request_id: [u8; 16],
        credential_id: CredentialId,
        token_secret: TokenSecret,
        requested_role: Role,
        supported_features: u64,
    },
    Ping {
        request_id: [u8; 16],
        session_id: [u8; 16],
        nonce: u64,
    },
}
impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticate {
                request_id,
                credential_id,
                requested_role,
                supported_features,
                ..
            } => f
                .debug_struct("Authenticate")
                .field("request_id", request_id)
                .field("credential_id", credential_id)
                .field("token_secret", &"REDACTED")
                .field("requested_role", requested_role)
                .field("supported_features", supported_features)
                .finish(),
            Self::Ping {
                request_id,
                session_id,
                nonce,
            } => f
                .debug_struct("Ping")
                .field("request_id", request_id)
                .field("session_id", session_id)
                .field("nonce", nonce)
                .finish(),
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
pub enum AuthResponse {
    Authenticated {
        request_id: [u8; 16],
        session_id: [u8; 16],
        tenant: Tenant,
        role: Role,
        scopes: u32,
        quota_profile: QuotaProfile,
        authorization_revision: u64,
        expires_at: i64,
        exchange_features: u64,
    },
    Pong {
        request_id: [u8; 16],
        nonce: u64,
        exchange_time: i64,
    },
    Rejected {
        request_id: Option<[u8; 16]>,
        error: PublicError,
    },
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_bits_are_stable() {
        assert_eq!(Scope::OpenProxyStream.bit(), 4);
    }
}
