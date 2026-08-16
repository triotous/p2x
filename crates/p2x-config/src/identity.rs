use crate::secret_file::{SecretFileError, read_secret_file, write_secret_file};
use libp2p_identity::{Keypair, PeerId};
use sha2::{Digest, Sha256};
use std::{fmt, path::PathBuf};
use thiserror::Error;
use zeroize::Zeroize;
#[derive(Clone, Debug)]
pub struct IdentityConfig {
    pub path: PathBuf,
    pub generate_if_missing: bool,
}
pub struct LoadedIdentity {
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub fingerprint: String,
}
impl fmt::Debug for LoadedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedIdentity")
            .field("peer_id", &self.peer_id)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity file failed: {0}")]
    File(#[from] SecretFileError),
    #[error("identity encoding is invalid")]
    InvalidEncoding,
    #[error("identity already exists")]
    AlreadyExists,
    #[error("identity generation is not enabled")]
    MissingWithoutGeneration,
}
pub fn load_or_create_identity(config: &IdentityConfig) -> Result<LoadedIdentity, IdentityError> {
    let bytes = match read_secret_file(&config.path) {
        Ok(value) => value,
        Err(SecretFileError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound && config.generate_if_missing =>
        {
            let key = Keypair::generate_ed25519();
            let bytes = key
                .to_protobuf_encoding()
                .map_err(|_| IdentityError::InvalidEncoding)?;
            match write_secret_file(&config.path, &bytes) {
                Ok(()) => bytes,
                Err(SecretFileError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    return load_or_create_identity(&IdentityConfig {
                        path: config.path.clone(),
                        generate_if_missing: false,
                    });
                }
                Err(error) => return Err(IdentityError::File(error)),
            }
        }
        Err(SecretFileError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(IdentityError::MissingWithoutGeneration);
        }
        Err(error) => return Err(IdentityError::File(error)),
    };
    let keypair =
        Keypair::from_protobuf_encoding(&bytes).map_err(|_| IdentityError::InvalidEncoding)?;
    let mut bytes = bytes;
    bytes.zeroize();
    if keypair.key_type() != libp2p_identity::KeyType::Ed25519 {
        return Err(IdentityError::InvalidEncoding);
    }
    let peer_id = PeerId::from_public_key(&keypair.public());
    let fingerprint = hex(&Sha256::digest(keypair.public().encode_protobuf()));
    Ok(LoadedIdentity {
        keypair,
        peer_id,
        fingerprint,
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_is_fatal_without_opt_in() {
        let result = load_or_create_identity(&IdentityConfig {
            path: PathBuf::from("/definitely/missing/p2x"),
            generate_if_missing: false,
        });
        assert!(matches!(
            result,
            Err(IdentityError::MissingWithoutGeneration)
        ));
    }
}
