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
    let bytes = fs::read(path)?;
    validate_document(&bytes)?;
    Ok(serde_yaml::from_slice(&bytes)?)
}
fn validate_document(bytes: &[u8]) -> Result<(), YamlError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        YamlError::Parse(serde_yaml::from_str::<serde_yaml::Value>("!invalid").unwrap_err())
    })?;
    let documents = text.lines().filter(|line| line.trim() == "---").count();
    if documents > 1
        || text.lines().any(|line| {
            let t = line.trim_start();
            t.starts_with("<<:") || t.contains(" *") || t.contains(" &")
        })
    {
        return Err(YamlError::Parse(
            serde_yaml::from_str::<serde_yaml::Value>("[invalid").unwrap_err(),
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_merge_and_multiple_documents() {
        let path = std::env::temp_dir().join(format!("p2x-yaml-{}", std::process::id()));
        std::fs::write(&path, "a: 1\n---\nb: 2\n").unwrap();
        assert!(load::<serde_yaml::Value>(&path).is_err());
        std::fs::write(&path, "a: &x 1\nb: *x\n").unwrap();
        assert!(load::<serde_yaml::Value>(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
    #[test]
    fn missing_file_is_fatal() {
        assert!(matches!(
            load::<serde_yaml::Value>(Path::new("/missing/config")),
            Err(YamlError::Io(_))
        ));
    }
}
