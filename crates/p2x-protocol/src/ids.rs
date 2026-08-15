use std::fmt;
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
#[error("request correlation ID exhausted")]
pub struct CorrelationIdExhausted;

#[derive(Clone, Debug)]
pub struct CorrelationIdGenerator {
    next: u128,
    exhausted: bool,
}
impl CorrelationIdGenerator {
    pub const fn new(start: u128) -> Self {
        Self {
            next: start,
            exhausted: false,
        }
    }

    pub fn allocate(&mut self) -> Result<[u8; 16], CorrelationIdExhausted> {
        if self.exhausted {
            return Err(CorrelationIdExhausted);
        }
        let value = self.next;
        if value == u128::MAX {
            self.exhausted = true;
        } else {
            self.next += 1;
        }
        Ok(value.to_be_bytes())
    }
}
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_ids_are_checked_big_endian_and_fail_closed() {
        let mut generator = CorrelationIdGenerator::new(u128::MAX - 1);
        assert_eq!(generator.allocate().unwrap(), (u128::MAX - 1).to_be_bytes());
        assert_eq!(generator.allocate().unwrap(), u128::MAX.to_be_bytes());
        assert_eq!(generator.allocate(), Err(CorrelationIdExhausted));
    }
}
