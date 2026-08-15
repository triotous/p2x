use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialError {
    #[error("invalid credential")]
    Invalid,
}

pub struct TokenSecret(Zeroizing<[u8; 32]>);
impl TokenSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn parse(value: &str) -> Result<(crate::CredentialId, Self), CredentialError> {
        let mut parts = value.split('.');
        let prefix = parts.next();
        let id = parts.next();
        let encoded = parts.next();
        if prefix != Some("p2x1") || parts.next().is_some() {
            return Err(CredentialError::Invalid);
        }
        let id = crate::CredentialId::new(id.ok_or(CredentialError::Invalid)?)
            .map_err(|_| CredentialError::Invalid)?;
        let encoded = encoded.ok_or(CredentialError::Invalid)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CredentialError::Invalid)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| CredentialError::Invalid)?;
        Ok((id, Self(Zeroizing::new(bytes))))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn digest(&self) -> TokenDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"p2x-fixed-token-v1\0");
        hasher.update(self.as_bytes());
        TokenDigest(hasher.finalize().into())
    }
}
impl fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenSecret(REDACTED)")
    }
}

pub struct TokenDigest([u8; 32]);
impl PartialEq for TokenDigest {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for TokenDigest {}
impl Clone for TokenDigest {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
impl TokenDigest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn matches(&self, secret: &TokenSecret) -> bool {
        bool::from(self.0.ct_eq(secret.digest().as_bytes()))
    }
}
impl Drop for TokenDigest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenDigest(REDACTED)")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_canonical_token_and_redacts() {
        let value = format!("p2x1.server-1.{}", URL_SAFE_NO_PAD.encode([7u8; 32]));
        let (_, token) = TokenSecret::parse(&value).unwrap();
        assert!(format!("{token:?}").contains("REDACTED"));
        assert!(token.digest().matches(&token));
        assert!(TokenSecret::parse(&format!("{value}=")).is_err());
    }
}
