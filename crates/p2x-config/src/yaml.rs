use serde::{
    Deserialize,
    de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use std::{fmt, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};
use thiserror::Error;
use yaml_rust2::{Event, parser::Parser};
pub const MAX_YAML_FILE: u64 = 512 * 1024;
const MAX_YAML_NODES: usize = 4096;
const MAX_YAML_DEPTH: usize = 32;
const MAX_YAML_SCALAR: usize = 4096;
#[derive(Debug, Error)]
pub enum YamlError {
    #[error("configuration file is too large")]
    TooLarge,
    #[error("configuration file could not be read")]
    Io(#[from] std::io::Error),
    #[error("configuration YAML is invalid")]
    Parse(#[from] serde_yaml::Error),
    #[error("configuration YAML exceeds structural bounds")]
    Bounds,
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
fn validate_events(text: &str) -> Result<(), YamlError> {
    let mut parser = Parser::new_from_str(text);
    let mut depth = 0usize;
    let mut nodes = 0usize;
    loop {
        let (event, _) = parser
            .next_token()
            .map_err(|_| YamlError::Parse(invalid_yaml()))?;
        match event {
            Event::Nothing | Event::StreamStart | Event::DocumentStart | Event::DocumentEnd => {}
            Event::StreamEnd => break,
            Event::Alias(_) => return Err(YamlError::Bounds),
            Event::Scalar(value, _, anchor, tag) => {
                if anchor != 0 || tag.is_some() || value.len() > MAX_YAML_SCALAR {
                    return Err(YamlError::Bounds);
                }
                nodes += 1;
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(YamlError::Bounds);
                }
                depth += 1;
                nodes += 1;
            }
            Event::SequenceEnd | Event::MappingEnd => {
                depth = depth.checked_sub(1).ok_or(YamlError::Bounds)?
            }
        }
        if depth > MAX_YAML_DEPTH || nodes > MAX_YAML_NODES {
            return Err(YamlError::Bounds);
        }
    }
    Ok(())
}
fn validate_structure(
    value: &serde_yaml::Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), YamlError> {
    *nodes = nodes.checked_add(1).ok_or(YamlError::Bounds)?;
    if *nodes > MAX_YAML_NODES || depth > MAX_YAML_DEPTH {
        return Err(YamlError::Bounds);
    }
    match value {
        serde_yaml::Value::String(value) if value.len() > MAX_YAML_SCALAR => Err(YamlError::Bounds),
        serde_yaml::Value::Tagged(_) => Err(YamlError::Bounds),
        serde_yaml::Value::Sequence(values) => values
            .iter()
            .try_for_each(|value| validate_structure(value, depth + 1, nodes)),
        serde_yaml::Value::Mapping(values) => values.iter().try_for_each(|(key, value)| {
            validate_structure(key, depth + 1, nodes)?;
            validate_structure(value, depth + 1, nodes)
        }),
        _ => Ok(()),
    }
}
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<T, YamlError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_YAML_FILE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_YAML_FILE {
        return Err(YamlError::TooLarge);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| YamlError::Parse(invalid_yaml()))?;
    validate_events(text)?;
    let mut checked = serde_yaml::Deserializer::from_slice(&bytes);
    let first_checked = checked
        .next()
        .ok_or_else(|| YamlError::Parse(invalid_yaml()))?;
    serde::Deserializer::deserialize_any(first_checked, DuplicateKeyCheck)
        .map_err(YamlError::Parse)?;
    if checked.next().is_some() {
        return Err(YamlError::Parse(invalid_yaml()));
    }
    let mut structure_documents = serde_yaml::Deserializer::from_slice(&bytes);
    let structure = structure_documents
        .next()
        .ok_or_else(|| YamlError::Parse(invalid_yaml()))?;
    let structure = serde_yaml::Value::deserialize(structure).map_err(YamlError::Parse)?;
    let mut nodes = 0;
    validate_structure(&structure, 0, &mut nodes)?;
    if structure_documents.next().is_some() {
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
        let path = std::env::temp_dir().join(format!(
            "p2x-yaml-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
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
    #[test]
    fn rejects_structural_bounds_and_tags() {
        let path = std::env::temp_dir().join(format!(
            "p2x-yaml-bounds-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "a: !secret value\n").unwrap();
        assert!(load::<serde_yaml::Value>(&path).is_err());
        std::fs::write(&path, format!("a: {}\n", "x".repeat(4097))).unwrap();
        assert!(matches!(
            load::<serde_yaml::Value>(&path),
            Err(YamlError::Bounds)
        ));
        let _ = std::fs::remove_file(path);
    }
}
