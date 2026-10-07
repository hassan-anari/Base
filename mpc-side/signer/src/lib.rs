//! Signer-local identity, encrypted share persistence, and authenticated
//! protocol-envelope validation. Secret shares are never response types.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Mutex};
use uuid::Uuid;
use wallet_mpc_storage::{atomic_store, LocalAesWrapper, ShareIdentity, Wrapper};
use zeroize::{Zeroize, Zeroizing};

pub const PROTOCOL_VERSION: &str = "phase6-v1";
pub const SHARE_FORMAT_VERSION: u16 = 1;

#[derive(Clone, Debug)]
pub struct SignerConfig {
    pub party_id: String,
    pub certificate_identity: String,
    pub storage_directory: PathBuf,
    pub wrapping_key_path: PathBuf,
    pub supported_algorithms: Vec<String>,
}

impl SignerConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.party_id.as_str(), "signer-a" | "signer-b" | "signer-c"),
            "unknown signer party"
        );
        ensure!(
            !self.certificate_identity.is_empty(),
            "certificate identity is required"
        );
        ensure!(
            !self.supported_algorithms.is_empty(),
            "supported algorithms are required"
        );
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredShare {
    pub format_version: u16,
    pub protocol_version: String,
    pub algorithm: String,
    pub keyset_id: Uuid,
    pub party_id: String,
    /// Opaque serialization produced by the reviewed protocol library.
    pub protocol_share: Vec<u8>,
}

impl Drop for StoredShare {
    fn drop(&mut self) {
        self.protocol_share.zeroize();
    }
}

pub struct SignerStore {
    config: SignerConfig,
    wrapper: LocalAesWrapper,
}

impl SignerStore {
    pub fn open(config: SignerConfig) -> Result<Self> {
        config.validate()?;
        let wrapper = LocalAesWrapper::from_key_file(&config.wrapping_key_path)?;
        Ok(Self { config, wrapper })
    }

    fn identity(&self, keyset_id: Uuid, algorithm: &str) -> ShareIdentity {
        ShareIdentity {
            keyset_id,
            party_id: self.config.party_id.clone(),
            algorithm: algorithm.to_owned(),
        }
    }

    fn path(&self, keyset_id: Uuid) -> PathBuf {
        self.config
            .storage_directory
            .join(format!("{keyset_id}.share.enc"))
    }

    pub fn persist(&self, share: &StoredShare) -> Result<()> {
        ensure!(
            share.format_version == SHARE_FORMAT_VERSION,
            "unsupported share format"
        );
        ensure!(
            share.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version"
        );
        ensure!(
            share.party_id == self.config.party_id,
            "share belongs to another party"
        );
        ensure!(
            self.config.supported_algorithms.contains(&share.algorithm),
            "unsupported share algorithm"
        );
        let plaintext = Zeroizing::new(serde_json::to_vec(share)?);
        let encrypted = self.wrapper.wrap(
            &self.identity(share.keyset_id, &share.algorithm),
            plaintext.as_slice(),
        )?;
        atomic_store(&self.path(share.keyset_id), &encrypted)
    }

    pub fn load(&self, keyset_id: Uuid, algorithm: &str) -> Result<StoredShare> {
        ensure!(
            self.config
                .supported_algorithms
                .contains(&algorithm.to_owned()),
            "unsupported share algorithm"
        );
        let encrypted = fs::read(self.path(keyset_id)).context("keyset share is not present")?;
        let plaintext = self
            .wrapper
            .unwrap(&self.identity(keyset_id, algorithm), &encrypted)?;
        let share: StoredShare = serde_json::from_slice(&plaintext)?;
        ensure!(
            share.format_version == SHARE_FORMAT_VERSION,
            "unsupported share format"
        );
        ensure!(
            share.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version"
        );
        ensure!(share.keyset_id == keyset_id, "share keyset mismatch");
        ensure!(
            share.party_id == self.config.party_id,
            "share party mismatch"
        );
        ensure!(share.algorithm == algorithm, "share algorithm mismatch");
        Ok(share)
    }

    pub fn share_present(&self, keyset_id: Uuid) -> bool {
        self.path(keyset_id).is_file()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolEnvelope {
    pub logical_session_id: Uuid,
    pub crypto_execution_id: Uuid,
    pub keyset_id: Uuid,
    pub protocol: String,
    pub sender: String,
    pub recipient: String,
    pub round: u16,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub payload_digest: String,
}

impl ProtocolEnvelope {
    pub fn transcript_digest(&self) -> String {
        let mut transcript = Sha256::new();
        transcript.update(b"wallet-mpc/protocol-envelope/v1\0");
        for field in [
            PROTOCOL_VERSION.as_bytes(),
            self.logical_session_id.as_bytes(),
            self.crypto_execution_id.as_bytes(),
            self.keyset_id.as_bytes(),
            self.protocol.as_bytes(),
            self.sender.as_bytes(),
            self.recipient.as_bytes(),
            &self.round.to_be_bytes(),
            &self.sequence.to_be_bytes(),
            &self.payload,
        ] {
            transcript.update((field.len() as u64).to_be_bytes());
            transcript.update(field);
        }
        format!("{:x}", transcript.finalize())
    }
}

#[derive(Default)]
pub struct EnvelopeGuard(Mutex<BTreeMap<(Uuid, Uuid, String, u64), String>>);

impl EnvelopeGuard {
    /// `peer_certificate_identity` is extracted from the verified TLS client
    /// certificate by the transport layer, never from request JSON.
    pub fn accept(
        &self,
        envelope: &ProtocolEnvelope,
        own_party: &str,
        peer_certificate_identity: &str,
        certificate_parties: &BTreeMap<String, String>,
    ) -> Result<()> {
        ensure!(envelope.recipient == own_party, "wrong protocol recipient");
        let authenticated_party = certificate_parties
            .get(peer_certificate_identity)
            .context("unknown peer certificate identity")?;
        ensure!(
            authenticated_party == &envelope.sender,
            "certificate/party mismatch"
        );
        ensure!(
            envelope.transcript_digest() == envelope.payload_digest,
            "protocol transcript digest mismatch"
        );
        let key = (
            envelope.logical_session_id,
            envelope.crypto_execution_id,
            envelope.sender.clone(),
            envelope.sequence,
        );
        let mut seen = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("envelope guard poisoned"))?;
        if let Some(previous) = seen.get(&key) {
            ensure!(
                previous == &envelope.payload_digest,
                "conflicting duplicate message"
            );
            anyhow::bail!("replayed protocol message");
        }
        seen.insert(key, envelope.payload_digest.clone());
        Ok(())
    }
}

/// Non-secret execution tombstones prevent a restarted signer from accepting
/// messages for an execution whose ephemeral nonce state was lost.
pub struct ExecutionTombstones {
    directory: PathBuf,
}

impl ExecutionTombstones {
    pub fn open(directory: PathBuf) -> Result<Self> {
        let tombstones = Self { directory };
        fs::create_dir_all(&tombstones.directory)?;
        for entry in fs::read_dir(&tombstones.directory)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) == Some("state")
                && fs::read(&path)? == b"ACTIVE"
            {
                atomic_store(&path, b"ABORTED_AFTER_RESTART")?;
            }
        }
        Ok(tombstones)
    }

    fn path(&self, execution_id: Uuid) -> PathBuf {
        self.directory.join(format!("{execution_id}.state"))
    }

    pub fn begin(&self, execution_id: Uuid) -> Result<()> {
        ensure!(
            !self.path(execution_id).exists(),
            "crypto execution ID was already used"
        );
        atomic_store(&self.path(execution_id), b"ACTIVE")
    }

    pub fn require_active(&self, execution_id: Uuid) -> Result<()> {
        ensure!(
            fs::read(self.path(execution_id))? == b"ACTIVE",
            "crypto execution is stale"
        );
        Ok(())
    }

    pub fn abort(&self, execution_id: Uuid) -> Result<()> {
        self.require_active(execution_id)?;
        atomic_store(&self.path(execution_id), b"ABORTED")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temporary_config(party: &str) -> (SignerConfig, PathBuf) {
        let root = std::env::temp_dir().join(format!("signer-service-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let key = root.join("wrapping.key");
        fs::write(&key, [7u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        (
            SignerConfig {
                party_id: party.into(),
                certificate_identity: format!("spiffe://wallet-mpc/{party}"),
                storage_directory: root.join("shares"),
                wrapping_key_path: key,
                supported_algorithms: vec!["FROST_ED25519".into(), "CGGMP24_ECDSA".into()],
            },
            root,
        )
    }

    #[test]
    fn encrypted_share_survives_restart_and_cannot_move_to_another_party() {
        let keyset = Uuid::new_v4();
        let (config, root) = temporary_config("signer-a");
        let store = SignerStore::open(config.clone()).unwrap();
        store
            .persist(&StoredShare {
                format_version: SHARE_FORMAT_VERSION,
                protocol_version: PROTOCOL_VERSION.into(),
                algorithm: "FROST_ED25519".into(),
                keyset_id: keyset,
                party_id: "signer-a".into(),
                protocol_share: vec![1, 2, 3],
            })
            .unwrap();
        drop(store);
        assert_eq!(
            SignerStore::open(config)
                .unwrap()
                .load(keyset, "FROST_ED25519")
                .unwrap()
                .protocol_share,
            vec![1, 2, 3]
        );
        let (other_config, other_root) = temporary_config("signer-b");
        let other = SignerStore::open(other_config).unwrap();
        fs::create_dir_all(&other.config.storage_directory).unwrap();
        fs::copy(
            root.join("shares").join(format!("{keyset}.share.enc")),
            other.path(keyset),
        )
        .unwrap();
        assert!(other.load(keyset, "FROST_ED25519").is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(other_root).unwrap();
    }

    #[test]
    fn envelope_rejects_spoofing_replay_wrong_recipient_and_conflict() {
        let guard = EnvelopeGuard::default();
        let mut parties = BTreeMap::new();
        parties.insert("spiffe://wallet-mpc/signer-a".into(), "signer-a".into());
        let payload = b"round-message".to_vec();
        let mut envelope = ProtocolEnvelope {
            logical_session_id: Uuid::new_v4(),
            crypto_execution_id: Uuid::new_v4(),
            keyset_id: Uuid::new_v4(),
            protocol: "FROST_ED25519".into(),
            sender: "signer-a".into(),
            recipient: "signer-b".into(),
            round: 1,
            sequence: 1,
            payload_digest: String::new(),
            payload,
        };
        envelope.payload_digest = envelope.transcript_digest();
        guard
            .accept(
                &envelope,
                "signer-b",
                "spiffe://wallet-mpc/signer-a",
                &parties,
            )
            .unwrap();
        assert!(guard
            .accept(
                &envelope,
                "signer-b",
                "spiffe://wallet-mpc/signer-a",
                &parties
            )
            .is_err());
        let mut wrong = envelope.clone();
        wrong.sequence = 2;
        wrong.recipient = "signer-c".into();
        assert!(guard
            .accept(&wrong, "signer-b", "spiffe://wallet-mpc/signer-a", &parties)
            .is_err());
        wrong.recipient = "signer-b".into();
        wrong.sender = "signer-b".into();
        assert!(guard
            .accept(&wrong, "signer-b", "spiffe://wallet-mpc/signer-a", &parties)
            .is_err());
    }

    #[test]
    fn transcript_digest_rejects_every_metadata_tamper() {
        let mut envelope = ProtocolEnvelope {
            logical_session_id: Uuid::new_v4(),
            crypto_execution_id: Uuid::new_v4(),
            keyset_id: Uuid::new_v4(),
            protocol: "CGGMP24_ECDSA".into(),
            sender: "signer-a".into(),
            recipient: "signer-b".into(),
            round: 2,
            sequence: 9,
            payload: vec![4, 5, 6],
            payload_digest: String::new(),
        };
        envelope.payload_digest = envelope.transcript_digest();
        let digest = envelope.payload_digest.clone();
        let mut variants = Vec::new();
        let mut changed = envelope.clone();
        changed.logical_session_id = Uuid::new_v4();
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.crypto_execution_id = Uuid::new_v4();
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.keyset_id = Uuid::new_v4();
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.protocol = "FROST_ED25519".into();
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.sender = "signer-c".into();
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.recipient = "signer-c".into();
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.round += 1;
        variants.push(changed);
        let mut changed = envelope.clone();
        changed.sequence += 1;
        variants.push(changed);
        let mut changed = envelope;
        changed.payload.push(7);
        variants.push(changed);
        assert!(variants
            .iter()
            .all(|changed| changed.transcript_digest() != digest));
    }

    #[test]
    fn restart_aborts_active_execution_and_prevents_id_reuse() {
        let root = std::env::temp_dir().join(format!("execution-state-{}", Uuid::new_v4()));
        let execution = Uuid::new_v4();
        let guard = ExecutionTombstones::open(root.clone()).unwrap();
        guard.begin(execution).unwrap();
        guard.require_active(execution).unwrap();
        drop(guard);
        let restarted = ExecutionTombstones::open(root.clone()).unwrap();
        assert!(restarted.require_active(execution).is_err());
        assert!(restarted.begin(execution).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
