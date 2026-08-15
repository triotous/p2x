use std::fmt;
use thiserror::Error;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdError {
    #[error("invalid identifier")]
    Invalid,
}
fn validate(value: &str, max: usize) -> Result<String, IdError> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(IdError::Invalid);
    }
    Ok(value.to_owned())
}
macro_rules! id {
    ($name:ident, $max:expr) => {
        #[derive(Clone, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: &str) -> Result<Self, IdError> {
                Ok(Self(validate(value, $max)?))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
id!(CredentialId, 64);
id!(Tenant, 64);
id!(QuotaProfile, 64);
