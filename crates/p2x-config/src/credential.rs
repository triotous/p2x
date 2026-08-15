use base64::Engine;
use p2x_protocol::{CredentialId, QuotaProfile, Tenant, TokenDigest, TokenSecret};
use serde::Deserialize;
use std::{env, fs, path::Path};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "lowercase")]
pub enum CredentialRole {
    Client,
    Server,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRecord {
    pub credential_id: String,
    pub token_sha256: String,
    pub peer_id: String,
    pub tenant: String,
    pub role: CredentialRole,
    pub scopes: Vec<String>,
    pub quota_profile: String,
    pub not_before: i64,
    pub expires_at: i64,
    pub revoked: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedTokenFile {
    pub schema_version: u16,
    pub authorization_revision: u64,
    pub credentials: Vec<CredentialRecord>,
}
#[derive(Debug, Error)]
pub enum CredentialConfigError {
    #[error("credential configuration is invalid: {0}")]
    Invalid(&'static str),
    #[error("credential file could not be read")]
    Io(#[from] std::io::Error),
    #[error("credential YAML is invalid")]
    Yaml(#[from] serde_yaml::Error),
    #[error("credential environment variable is missing")]
    MissingEnvironment,
}
impl FixedTokenFile {
    pub fn load(path: &Path) -> Result<Self, CredentialConfigError> {
        if fs::metadata(path)?.len() > 512 * 1024 {
            return Err(CredentialConfigError::Invalid("file too large"));
        }
        let file: Self = serde_yaml::from_slice(&fs::read(path)?)?;
        file.validate()?;
        Ok(file)
    }
    pub fn validate(&self) -> Result<(), CredentialConfigError> {
        if self.schema_version != 1 || self.credentials.len() > 256 {
            return Err(CredentialConfigError::Invalid("schema or count"));
        }
        for (i, record) in self.credentials.iter().enumerate() {
            let id = CredentialId::new(&record.credential_id)
                .map_err(|_| CredentialConfigError::Invalid("credential id"))?;
            if self
                .credentials
                .iter()
                .skip(i + 1)
                .any(|other| other.credential_id == id.as_str())
            {
                return Err(CredentialConfigError::Invalid("duplicate credential id"));
            }
            if record.expires_at <= record.not_before
                || record.expires_at - record.not_before > 400 * 86400
                || record.peer_id.is_empty()
                || record.tenant.is_empty()
                || record.quota_profile.is_empty()
                || record.quota_profile.len() > 64
            {
                return Err(CredentialConfigError::Invalid("credential binding"));
            }
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&record.token_sha256)
                .map_err(|_| CredentialConfigError::Invalid("token digest"))?;
            if digest.len() != 32 {
                return Err(CredentialConfigError::Invalid("token digest"));
            }
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct CredentialRef {
    pub env_name: String,
}
impl CredentialRef {
    pub fn read(&self) -> Result<(CredentialId, TokenSecret), CredentialConfigError> {
        let value =
            env::var(&self.env_name).map_err(|_| CredentialConfigError::MissingEnvironment)?;
        TokenSecret::parse(&value).map_err(|_| CredentialConfigError::Invalid("token"))
    }
}
#[derive(Debug)]
pub struct ValidatedCredential {
    pub id: CredentialId,
    pub digest: TokenDigest,
    pub peer_id: String,
    pub tenant: Tenant,
    pub role: CredentialRole,
    pub quota_profile: QuotaProfile,
    pub not_before: i64,
    pub expires_at: i64,
    pub revoked: bool,
}
