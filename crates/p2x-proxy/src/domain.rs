use std::{fmt, net::IpAddr, str::FromStr};

pub const MAX_DOMAIN_INPUT_BYTES: usize = 1_024;
pub const MAX_DOMAIN_BYTES: usize = 253;
pub const MAX_LABEL_BYTES: usize = 63;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalDomain(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    TooLong,
    Empty,
    Invalid,
    IpLiteral,
}
impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "domain is too long",
            Self::Empty => "domain is empty",
            Self::Invalid => "domain is invalid",
            Self::IpLiteral => "domain must not be an IP literal",
        })
    }
}
impl std::error::Error for DomainError {}

impl CanonicalDomain {
    pub fn from_config(input: &str) -> Result<Self, DomainError> {
        Self::parse(input, true, true)
    }

    pub fn from_http_authority(input: &str) -> Result<(Self, u16), DomainError> {
        let input = input.trim_matches(|byte| byte == ' ' || byte == '\t');
        if input.is_empty() || input.contains('@') || input.contains('/') || input.contains(',') {
            return Err(DomainError::Invalid);
        }
        if input.starts_with('[') || input.matches(':').count() > 1 {
            return Err(DomainError::Invalid);
        }
        let (host, port) = match input.rsplit_once(':') {
            Some((host, port)) => {
                if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(DomainError::Invalid);
                }
                let port = port.parse::<u16>().map_err(|_| DomainError::Invalid)?;
                if port == 0 {
                    return Err(DomainError::Invalid);
                }
                (host, port)
            }
            None => (input, 80),
        };
        Ok((Self::parse(host, true, true)?, port))
    }

    pub fn from_sni(input: &str) -> Result<Self, DomainError> {
        if input.ends_with('.') {
            return Err(DomainError::Invalid);
        }
        Self::parse(input, false, false)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(input: &str, unicode: bool, trailing_dot: bool) -> Result<Self, DomainError> {
        if input.is_empty() || input.len() > MAX_DOMAIN_INPUT_BYTES {
            return Err(if input.is_empty() {
                DomainError::Empty
            } else {
                DomainError::TooLong
            });
        }
        let input = if trailing_dot && input.ends_with('.') {
            if input.ends_with("..") {
                return Err(DomainError::Invalid);
            }
            &input[..input.len() - 1]
        } else {
            input
        };
        if !unicode && !input.is_ascii() {
            return Err(DomainError::Invalid);
        }
        let ascii = idna::domain_to_ascii_strict(input).map_err(|_| DomainError::Invalid)?;
        let ascii = ascii.to_ascii_lowercase();
        if IpAddr::from_str(&ascii).is_ok() {
            return Err(DomainError::IpLiteral);
        }
        if ascii.is_empty() || ascii.len() > MAX_DOMAIN_BYTES {
            return Err(if ascii.is_empty() {
                DomainError::Empty
            } else {
                DomainError::TooLong
            });
        }
        if ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > MAX_LABEL_BYTES
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return Err(DomainError::Invalid);
        }
        Ok(Self(ascii))
    }
}
impl fmt::Display for CanonicalDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpAuthority {
    pub domain: CanonicalDomain,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_forms_and_http_ports_agree() {
        assert_eq!(
            CanonicalDomain::from_config("Orders.Example.")
                .unwrap()
                .as_str(),
            "orders.example"
        );
        let (domain, port) =
            CanonicalDomain::from_http_authority(" \tORDERS.EXAMPLE:80\t").unwrap();
        assert_eq!(domain.as_str(), "orders.example");
        assert_eq!(port, 80);
        assert_eq!(CanonicalDomain::from_sni("ORDERS.EXAMPLE").unwrap(), domain);
    }

    #[test]
    fn invalid_domain_and_authority_forms_are_rejected() {
        for value in [
            "",
            "*.example.com",
            "a..example.com",
            "-a.example.com",
            "127.0.0.1",
            "a b.example.com",
        ] {
            assert!(CanonicalDomain::from_config(value).is_err(), "{value}");
        }
        for value in ["example.com:0", "example.com:", "user@example.com", "[::1]"] {
            assert!(
                CanonicalDomain::from_http_authority(value).is_err(),
                "{value}"
            );
        }
        assert!(CanonicalDomain::from_config("127.0.0.1.").is_err());
        assert!(CanonicalDomain::from_sni("xn--").is_err());
        assert!(CanonicalDomain::from_sni("example.com.").is_err());
    }
}
