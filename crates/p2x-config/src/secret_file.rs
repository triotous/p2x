use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    path::PathBuf,
};
use thiserror::Error;
pub const MAX_SECRET_FILE: usize = 4096;
#[derive(Debug, Error)]
pub enum SecretFileError {
    #[error("secret file I/O failed")]
    Io(#[from] io::Error),
    #[error("secret file is too large or empty")]
    InvalidSize,
    #[error("secret file permissions are unsafe")]
    UnsafePermissions,
}
pub fn read_secret_file(path: &Path) -> Result<Vec<u8>, SecretFileError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() as usize > MAX_SECRET_FILE
    {
        return Err(SecretFileError::InvalidSize);
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(SecretFileError::UnsafePermissions);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_SECRET_FILE + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SECRET_FILE {
        return Err(SecretFileError::InvalidSize);
    }
    Ok(bytes)
}
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), SecretFileError> {
    if bytes.is_empty() || bytes.len() > MAX_SECRET_FILE {
        return Err(SecretFileError::InvalidSize);
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = PathBuf::from(parent);
    tmp.push(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("secret")
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    let directory = OpenOptions::new().read(true).open(parent)?;
    directory.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds() {
        assert!(matches!(
            read_secret_file(Path::new("/definitely/missing")),
            Err(SecretFileError::Io(_))
        ));
    }
}
