//! Atomic encrypted storage for exactly one node's share. A future Wrapper trait
//! implementation can delegate wrapping to a TPM or HSM without changing protocols.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{ensure, Context, Result};
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"WMPCSHARE1";
pub trait Wrapper {
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}
pub struct LocalAesWrapper(pub Zeroizing<[u8; 32]>);
impl Wrapper for LocalAesWrapper {
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut n = [0u8; 12];
        OsRng.fill_bytes(&mut n);
        let c = Aes256Gcm::new_from_slice(&self.0[..])?;
        let mut out = MAGIC.to_vec();
        out.extend(n);
        out.extend(
            c.encrypt(Nonce::from_slice(&n), plaintext)
                .map_err(|_| anyhow::anyhow!("share encryption failed"))?,
        );
        Ok(out)
    }
    fn unwrap(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            data.starts_with(MAGIC) && data.len() > MAGIC.len() + 12,
            "invalid encrypted share"
        );
        let p = MAGIC.len();
        let c = Aes256Gcm::new_from_slice(&self.0[..])?;
        Ok(Zeroizing::new(
            c.decrypt(Nonce::from_slice(&data[p..p + 12]), &data[p + 12..])
                .map_err(|_| anyhow::anyhow!("share authentication failed"))?,
        ))
    }
}
pub fn atomic_store(path: &Path, encrypted: &[u8]) -> Result<()> {
    let parent = path.parent().context("share path has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(encrypted)?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_round_trip_and_corruption_rejected() {
        let w = LocalAesWrapper(Zeroizing::new([7; 32]));
        let mut c = w.wrap(b"party share").unwrap();
        assert!(!String::from_utf8_lossy(&c).contains("party share"));
        assert_eq!(&*w.unwrap(&c).unwrap(), b"party share");
        let n = c.len();
        c[n - 1] ^= 1;
        assert!(w.unwrap(&c).is_err());
    }
}
