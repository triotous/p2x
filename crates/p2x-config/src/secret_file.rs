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
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|_| SecretFileError::Io(io::Error::other("OS randomness unavailable")))?;
    let mut tmp = PathBuf::from(parent);
    tmp.push(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("secret"),
        u64::from_ne_bytes(nonce)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    match fs::hard_link(&tmp, path) {
        Ok(()) => {
            fs::remove_file(&tmp)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            return Err(SecretFileError::Io(error));
        }
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            return Err(SecretFileError::Io(error));
        }
    }
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
    #[test]
    fn concurrent_creators_do_not_share_temp_names() {
        let dir = std::env::temp_dir().join(format!("p2x-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        let mut threads = Vec::new();
        for byte in 0..8u8 {
            let path = path.clone();
            threads.push(std::thread::spawn(move || {
                write_secret_file(&path, &[byte; 32])
            }));
        }
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(read_secret_file(&path).is_ok());
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
    }
}
