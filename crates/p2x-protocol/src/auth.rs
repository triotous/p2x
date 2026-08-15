use crate::{
    error::PublicError,
    ids::{CredentialId, QuotaProfile, Tenant},
};
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Deserialize, Serialize)]
pub enum AuthRequest {
    Authenticate {
        request_id: [u8; 16],
        credential_id: CredentialId,
        #[serde(skip)]
        token_secret: [u8; 32],
        requested_role: Role,
        supported_features: u64,
    },
    Ping {
        request_id: [u8; 16],
        session_id: [u8; 16],
        nonce: u64,
    },
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
