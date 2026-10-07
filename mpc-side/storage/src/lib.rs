//! Authenticated, atomic storage for exactly one node's share.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"WMPCSHARE2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShareIdentity {
    pub keyset_id: Uuid,
    pub party_id: String,
    pub algorithm: String,
}

fn aad(identity: &ShareIdentity) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(2u8, identity))?)
}

pub trait Wrapper {
    fn wrap(&self, identity: &ShareIdentity, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, identity: &ShareIdentity, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

/// Software wrapper for development or hosts whose root-only key file is
/// protected by encrypted storage. TPM/HSM wrappers implement the same trait.
pub struct LocalAesWrapper(Zeroizing<[u8; 32]>);

impl LocalAesWrapper {
    pub fn from_key_file(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).context("wrapping key metadata")?;
        ensure!(metadata.is_file(), "wrapping key is not a file");
        ensure!(
            metadata.mode() & 0o077 == 0,
            "wrapping key must not be group/world accessible"
        );
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut key = Zeroizing::new([0u8; 32]);
        file.read_exact(&mut key[..])
            .context("wrapping key must contain exactly 32 bytes")?;
        let mut extra = [0u8; 1];
        ensure!(
            file.read(&mut extra)? == 0,
            "wrapping key must contain exactly 32 bytes"
        );
        Ok(Self(key))
    }

    #[cfg(test)]
    fn test_key(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }
}

impl Wrapper for LocalAesWrapper {
    fn wrap(&self, identity: &ShareIdentity, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.0[..])?;
        let mut output = MAGIC.to_vec();
        output.extend(nonce);
        output.extend(
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad(identity)?,
                    },
                )
                .map_err(|_| anyhow::anyhow!("share encryption failed"))?,
        );
        Ok(output)
    }

    fn unwrap(&self, identity: &ShareIdentity, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            data.starts_with(MAGIC) && data.len() > MAGIC.len() + 12,
            "invalid encrypted share"
        );
        let position = MAGIC.len();
        let cipher = Aes256Gcm::new_from_slice(&self.0[..])?;
        Ok(Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&data[position..position + 12]),
                    Payload {
                        msg: &data[position + 12..],
                        aad: &aad(identity)?,
                    },
                )
                .map_err(|_| anyhow::anyhow!("share identity/authentication failed"))?,
        ))
    }
}

pub fn atomic_store(path: &Path, encrypted: &[u8]) -> Result<()> {
    let parent = path.parent().context("share path has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(encrypted)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        OpenOptions::new().read(true).open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn identity(party: &str) -> ShareIdentity {
        ShareIdentity {
            keyset_id: Uuid::nil(),
            party_id: party.into(),
            algorithm: "FROST_ED25519".into(),
        }
    }

    #[test]
    fn identity_aad_and_wrong_key_reject_transplants() {
        let wrapper = LocalAesWrapper::test_key([7; 32]);
        let ciphertext = wrapper.wrap(&identity("a"), b"party share").unwrap();
        assert_eq!(
            &*wrapper.unwrap(&identity("a"), &ciphertext).unwrap(),
            b"party share"
        );
        assert!(wrapper.unwrap(&identity("b"), &ciphertext).is_err());
        assert!(LocalAesWrapper::test_key([8; 32])
            .unwrap(&identity("a"), &ciphertext)
            .is_err());
    }

    #[test]
    fn corruption_and_truncation_are_rejected() {
        let wrapper = LocalAesWrapper::test_key([7; 32]);
        let mut ciphertext = wrapper.wrap(&identity("a"), b"secret").unwrap();
        ciphertext.pop();
        assert!(wrapper.unwrap(&identity("a"), &ciphertext).is_err());
        assert!(wrapper.unwrap(&identity("a"), b"short").is_err());
    }

    #[test]
    fn atomic_file_has_restrictive_permissions_and_no_plaintext() {
        let directory = std::env::temp_dir().join(format!(
            "wallet-mpc-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("share.enc");
        let encrypted = LocalAesWrapper::test_key([7; 32])
            .wrap(&identity("a"), b"secret")
            .unwrap();
        atomic_store(&path, &encrypted).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(!String::from_utf8_lossy(&fs::read(&path).unwrap()).contains("secret"));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn wrapping_key_file_rejects_bad_permissions_size_and_symlink() {
        use std::os::unix::fs::symlink;
        let directory = std::env::temp_dir().join(format!(
            "wallet-mpc-key-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let key = directory.join("wrapping.key");
        fs::write(&key, [9u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(LocalAesWrapper::from_key_file(&key).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(LocalAesWrapper::from_key_file(&key).is_ok());
        fs::write(&key, [9u8; 31]).unwrap();
        assert!(LocalAesWrapper::from_key_file(&key).is_err());
        fs::write(&key, [9u8; 33]).unwrap();
        assert!(LocalAesWrapper::from_key_file(&key).is_err());
        let link = directory.join("link.key");
        symlink(&key, &link).unwrap();
        assert!(LocalAesWrapper::from_key_file(&link).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
