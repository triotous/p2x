use serde::de::DeserializeOwned;
use std::{fs, path::Path};
use thiserror::Error;
pub const MAX_YAML_FILE: u64 = 512 * 1024;
#[derive(Debug, Error)]
pub enum YamlError {
    #[error("configuration file is too large")]
    TooLarge,
    #[error("configuration file could not be read")]
    Io(#[from] std::io::Error),
    #[error("configuration YAML is invalid")]
    Parse(#[from] serde_yaml::Error),
}
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<T, YamlError> {
    if fs::metadata(path)?.len() > MAX_YAML_FILE {
        return Err(YamlError::TooLarge);
    }
    Ok(serde_yaml::from_slice(&fs::read(path)?)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_file_is_fatal() {
        assert!(matches!(
            load::<serde_yaml::Value>(Path::new("/missing/config")),
            Err(YamlError::Io(_))
        ));
    }
}
