use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{fmt, fs, path::Path};
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
struct DuplicateKeyCheck;
struct DuplicateKeySeed;
impl<'de> DeserializeSeed<'de> for DuplicateKeySeed {
    type Value = ();
    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyCheck)
    }
}
impl<'de> Visitor<'de> for DuplicateKeyCheck {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML value without duplicate mapping keys")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_char<E>(self, _: char) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_borrowed_str<E>(self, _: &'de str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_bytes<E>(self, _: &[u8]) -> Result<(), E> {
        Ok(())
    }
    fn visit_borrowed_bytes<E>(self, _: &'de [u8]) -> Result<(), E> {
        Ok(())
    }
    fn visit_byte_buf<E>(self, _: Vec<u8>) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyCheck)
    }
    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyCheck)
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(DuplicateKeySeed)?.is_some() {}
        Ok(())
    }
    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = Vec::<serde_yaml::Value>::new();
        while let Some(key) = map.next_key::<serde_yaml::Value>()? {
            if keys.iter().any(|old| old == &key) {
                return Err(serde::de::Error::custom("duplicate YAML mapping key"));
            }
            keys.push(key);
            map.next_value_seed(DuplicateKeySeed)?;
        }
        Ok(())
    }
}
fn invalid_yaml() -> serde_yaml::Error {
    serde_yaml::from_str::<serde_yaml::Value>("[invalid").unwrap_err()
}
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<T, YamlError> {
    if fs::metadata(path)?.len() > MAX_YAML_FILE {
        return Err(YamlError::TooLarge);
    }
    let bytes = fs::read(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| YamlError::Parse(invalid_yaml()))?;
    if text.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("<<:")
            || t.split_whitespace()
                .any(|word| word.starts_with('&') || word.starts_with('*'))
    }) {
        return Err(YamlError::Parse(invalid_yaml()));
    }
    let mut checked = serde_yaml::Deserializer::from_slice(&bytes);
    let first_checked = checked
        .next()
        .ok_or_else(|| YamlError::Parse(invalid_yaml()))?;
    serde::Deserializer::deserialize_any(first_checked, DuplicateKeyCheck)
        .map_err(YamlError::Parse)?;
    if checked.next().is_some() {
        return Err(YamlError::Parse(invalid_yaml()));
    }
    let mut documents = serde_yaml::Deserializer::from_slice(&bytes);
    let first = documents
        .next()
        .ok_or_else(|| YamlError::Parse(invalid_yaml()))?;
    let value = T::deserialize(first)?;
    if documents.next().is_some() {
        return Err(YamlError::Parse(invalid_yaml()));
    }
    Ok(value)
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
        std::fs::write(&path, "a: 1\na: 2\n").unwrap();
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
