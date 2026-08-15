use base64::Engine;
use p2x_protocol::{CredentialId, QuotaProfile, Role, Tenant, TokenDigest, TokenSecret};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthPrincipal {
    pub peer_id: String,
    pub credential_id: CredentialId,
    pub tenant: Tenant,
    pub role: Role,
    pub scopes: u32,
    pub quota_profile: QuotaProfile,
    pub authorization_revision: u64,
    pub credential_expires_at: i64,
}
pub struct CredentialBinding {
    pub credential_id: CredentialId,
    pub digest: TokenDigest,
    pub peer_id: String,
    pub tenant: Tenant,
    pub role: Role,
    pub scopes: u32,
    pub quota_profile: QuotaProfile,
    pub not_before: i64,
    pub expires_at: i64,
    pub revoked: bool,
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum AuthFailure {
    #[error("invalid credential")]
    InvalidCredential,
    #[error("forbidden role")]
    ForbiddenRole,
}
pub struct FixedTokenProvider {
    revision: u64,
    credentials: HashMap<CredentialId, CredentialBinding>,
}
impl FixedTokenProvider {
    pub fn from_config(file: &p2x_config::credential::FixedTokenFile) -> Result<Self, AuthFailure> {
        file.validate()
            .map_err(|_| AuthFailure::InvalidCredential)?;
        let mut bindings = Vec::with_capacity(file.credentials.len());
        for record in &file.credentials {
            let digest: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&record.token_sha256)
                .map_err(|_| AuthFailure::InvalidCredential)?
                .try_into()
                .map_err(|_| AuthFailure::InvalidCredential)?;
            let role = match record.role {
                p2x_config::credential::CredentialRole::Client => Role::Client,
                p2x_config::credential::CredentialRole::Server => Role::Server,
            };
            let scopes =
                record
                    .scopes
                    .iter()
                    .try_fold(0u32, |bits, scope| match scope.as_str() {
                        "register_services" => Ok(bits | 1),
                        "reserve_relay" => Ok(bits | 2),
                        "open_proxy_stream" => Ok(bits | 4),
                        _ => Err(AuthFailure::InvalidCredential),
                    })?;
            bindings.push(CredentialBinding {
                credential_id: CredentialId::new(&record.credential_id)
                    .map_err(|_| AuthFailure::InvalidCredential)?,
                digest: TokenDigest::from_bytes(digest),
                peer_id: record.peer_id.clone(),
                tenant: Tenant::new(&record.tenant).map_err(|_| AuthFailure::InvalidCredential)?,
                role,
                scopes,
                quota_profile: QuotaProfile::new(&record.quota_profile)
                    .map_err(|_| AuthFailure::InvalidCredential)?,
                not_before: record.not_before,
                expires_at: record.expires_at,
                revoked: record.revoked,
            });
        }
        Ok(Self::new(file.authorization_revision, bindings))
    }
    pub fn new(revision: u64, bindings: impl IntoIterator<Item = CredentialBinding>) -> Self {
        Self {
            revision,
            credentials: bindings
                .into_iter()
                .map(|binding| (binding.credential_id.clone(), binding))
                .collect(),
        }
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn binding_matches(&self, peer_id: &str, principal: &AuthPrincipal) -> bool {
        self.credentials
            .get(&principal.credential_id)
            .is_some_and(|binding| {
                binding.peer_id == peer_id
                    && binding.tenant == principal.tenant
                    && binding.role == principal.role
                    && binding.scopes == principal.scopes
                    && binding.quota_profile == principal.quota_profile
                    && !binding.revoked
                    && binding.expires_at == principal.credential_expires_at
                    && self.revision == principal.authorization_revision
            })
    }
    pub fn authenticate(
        &self,
        peer_id: &str,
        id: &CredentialId,
        secret: &TokenSecret,
        requested_role: Role,
        now: i64,
    ) -> Result<AuthPrincipal, AuthFailure> {
        let dummy = TokenDigest::from_bytes([0; 32]);
        let binding = self.credentials.get(id);
        let matches = binding
            .map(|value| value.digest.matches(secret))
            .unwrap_or_else(|| dummy.matches(secret));
        let Some(binding) = binding else {
            return Err(AuthFailure::InvalidCredential);
        };
        if !matches
            || binding.revoked
            || binding.peer_id != peer_id
            || now < binding.not_before
            || now >= binding.expires_at
        {
            return Err(AuthFailure::InvalidCredential);
        }
        if binding.role != requested_role {
            return Err(AuthFailure::ForbiddenRole);
        }
        Ok(AuthPrincipal {
            peer_id: peer_id.to_owned(),
            credential_id: binding.credential_id.clone(),
            tenant: binding.tenant.clone(),
            role: binding.role,
            scopes: binding.scopes,
            quota_profile: binding.quota_profile.clone(),
            authorization_revision: self.revision,
            credential_expires_at: binding.expires_at,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn provider() -> (FixedTokenProvider, TokenSecret, CredentialId) {
        let (_, token) =
            TokenSecret::parse("p2x1.id.AwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc").unwrap();
        let id = CredentialId::new("id").unwrap();
        let binding = CredentialBinding {
            credential_id: id.clone(),
            digest: token.digest(),
            peer_id: "peer".into(),
            tenant: Tenant::new("tenant").unwrap(),
            role: Role::Client,
            scopes: 1,
            quota_profile: QuotaProfile::new("standard").unwrap(),
            not_before: 0,
            expires_at: 100,
            revoked: false,
        };
        (FixedTokenProvider::new(2, [binding]), token, id)
    }
    #[test]
    fn validates_binding_and_rejects_wrong_peer() {
        let (provider, token, id) = provider();
        assert_eq!(provider.revision(), 2);
        assert!(
            provider
                .authenticate("peer", &id, &token, Role::Client, 1)
                .is_ok()
        );
        assert_eq!(
            provider.authenticate("other", &id, &token, Role::Client, 1),
            Err(AuthFailure::InvalidCredential)
        );
        assert_eq!(
            provider.authenticate("peer", &id, &token, Role::Server, 1),
            Err(AuthFailure::ForbiddenRole)
        );
    }
}
