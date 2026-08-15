use base64::Engine;
use libp2p_identity::PeerId;
use p2x_protocol::{CredentialId, QuotaProfile, Tenant, TokenDigest, TokenSecret};
use serde::{Deserialize, Deserializer, de::Visitor};
use std::fmt;
use std::str::FromStr;
use std::{env, fs, path::Path};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "lowercase")]
pub enum CredentialRole {
    Client,
    Server,
}
#[derive(Clone, Deserialize)]
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
    #[serde(deserialize_with = "strict_bool")]
    pub revoked: bool,
}
fn strict_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    struct StrictBool;
    impl<'de> Visitor<'de> for StrictBool {
        type Value = bool;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a YAML boolean")
        }
        fn visit_bool<E>(self, value: bool) -> Result<bool, E> {
            Ok(value)
        }
    }
    deserializer.deserialize_bool(StrictBool)
}
#[derive(Deserialize)]
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
        let file: Self = crate::yaml::load(path).map_err(|error| match error {
            crate::yaml::YamlError::Io(error) => CredentialConfigError::Io(error),
            crate::yaml::YamlError::Parse(error) => CredentialConfigError::Yaml(error),
            crate::yaml::YamlError::TooLarge => CredentialConfigError::Invalid("file too large"),
        })?;
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
            if PeerId::from_str(&record.peer_id).is_err()
                || record.expires_at <= record.not_before
                || record.expires_at.saturating_sub(record.not_before) > 400 * 86400
                || record.peer_id.is_empty()
                || record.tenant.is_empty()
                || record.quota_profile.is_empty()
                || record.quota_profile.len() > 64
            {
                return Err(CredentialConfigError::Invalid("credential binding"));
            }
            let mut seen_scopes = 0u32;
            for scope in &record.scopes {
                let bit = match scope.as_str() {
                    "register_services" => 1,
                    "reserve_relay" => 2,
                    "open_proxy_stream" => 4,
                    _ => return Err(CredentialConfigError::Invalid("scope")),
                };
                if seen_scopes & bit != 0 {
                    return Err(CredentialConfigError::Invalid("duplicate scope"));
                }
                seen_scopes |= bit;
            }
            let allowed = match record.role {
                CredentialRole::Client => 4,
                CredentialRole::Server => 3,
            };
            if seen_scopes & !allowed != 0 {
                return Err(CredentialConfigError::Invalid("role scope"));
            }
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&record.token_sha256)
                .map_err(|_| CredentialConfigError::Invalid("token digest"))?;
            if digest.len() != 32
                || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest)
                    != record.token_sha256
            {
                return Err(CredentialConfigError::Invalid("token digest"));
            }
        }
        Ok(())
    }
}
impl fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("credential_id", &self.credential_id)
            .field("token_sha256", &"REDACTED")
            .field("peer_id", &self.peer_id)
            .field("tenant", &self.tenant)
            .field("role", &self.role)
            .field("scopes", &self.scopes)
            .field("quota_profile", &self.quota_profile)
            .field("not_before", &self.not_before)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}
impl fmt::Debug for FixedTokenFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedTokenFile")
            .field("schema_version", &self.schema_version)
            .field("authorization_revision", &self.authorization_revision)
            .field("credentials", &self.credentials)
            .finish()
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
