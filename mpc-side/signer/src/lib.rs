//! Signer-local identity, encrypted share persistence, and authenticated
//! protocol-envelope validation. Secret shares are never response types.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::Mutex,
};
use uuid::Uuid;
use wallet_mpc_storage::{
    atomic_create_secret, atomic_replace_state, confirm_parent_durability, AtomicWritePhase,
    LocalAesWrapper, ShareIdentity, Wrapper,
};
use zeroize::{Zeroize, Zeroizing};

pub mod cggmp;
pub mod cggmp_aux;
mod cggmp_delivery;
pub mod cggmp_sign;
mod cggmp_wire;
pub mod dkg;
pub mod hd;
pub mod sign;

pub const PROTOCOL_VERSION: &str = "phase6-v1";
pub const SHARE_FORMAT_VERSION: u16 = 1;

/// Phase 6A intentionally has no authenticated network protocol. Never bind
/// an insecure signer outside explicit loopback-only development mode.
pub fn phase6a_insecure_local_listener(enabled: bool) -> Result<std::net::SocketAddr> {
    ensure!(
        enabled,
        "Phase 6A foundation only: unauthenticated signer service startup is disabled"
    );
    Ok("127.0.0.1:8080".parse()?)
}

#[derive(Clone, Debug)]
pub struct SignerConfig {
    pub party_id: String,
    pub certificate_identity: String,
    pub storage_directory: PathBuf,
    pub wrapping_key_path: PathBuf,
    pub supported_algorithms: Vec<String>,
    pub trusted_peers: BTreeMap<String, String>,
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
        let allowed = ["CGGMP24_ECDSA", "FROST_ED25519"];
        ensure!(
            self.supported_algorithms
                .iter()
                .all(|algorithm| !algorithm.is_empty() && allowed.contains(&algorithm.as_str())),
            "unknown or empty signer algorithm"
        );
        ensure!(
            self.supported_algorithms
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == self.supported_algorithms.len(),
            "duplicate signer algorithm"
        );
        ensure!(!self.trusted_peers.is_empty(), "trusted peers are required");
        for (certificate, party) in &self.trusted_peers {
            ensure!(
                certificate.starts_with("spiffe://wallet-mpc/") && certificate.len() > 20,
                "malformed trusted peer identity"
            );
            ensure!(
                matches!(
                    party.as_str(),
                    "signer-a" | "signer-b" | "signer-c" | "coordinator"
                ),
                "invalid trusted peer party"
            );
            ensure!(
                certificate != &self.certificate_identity || party == &self.party_id,
                "own certificate identity maps to another party"
            );
        }
        Ok(())
    }

    pub fn parse_trusted_peers(value: &str) -> Result<BTreeMap<String, String>> {
        let mut peers = BTreeMap::new();
        for entry in value.split(',') {
            let (certificate, party) = entry
                .split_once('=')
                .context("trusted peer must be certificate=party")?;
            ensure!(
                !certificate.is_empty() && !party.is_empty(),
                "empty trusted peer token"
            );
            ensure!(
                peers
                    .insert(certificate.to_owned(), party.to_owned())
                    .is_none(),
                "duplicate trusted peer identity"
            );
        }
        ensure!(!peers.is_empty(), "trusted peers are required");
        Ok(peers)
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
        if self.path(share.keyset_id).exists() {
            let existing = self.load(share.keyset_id, &share.algorithm)?;
            ensure!(existing == *share, "keyset share conflict");
            return confirm_parent_durability(&self.path(share.keyset_id)).map_err(Into::into);
        }
        let plaintext = Zeroizing::new(serde_json::to_vec(share)?);
        let encrypted = self.wrapper.wrap(
            &self.identity(share.keyset_id, &share.algorithm),
            plaintext.as_slice(),
        )?;
        match atomic_create_secret(&self.path(share.keyset_id), &encrypted) {
            Ok(()) => Ok(()),
            Err(error) if error.phase == AtomicWritePhase::PostRenameDurabilityUncertain => {
                // The immutable target may already be authoritative. Decrypt and
                // compare it, then explicitly confirm directory durability.
                let existing = self.load(share.keyset_id, &share.algorithm)?;
                ensure!(
                    existing == *share,
                    "uncertain keyset share conflicts with requested share"
                );
                confirm_parent_durability(&self.path(share.keyset_id)).map_err(Into::into)
            }
            Err(_error) if self.path(share.keyset_id).exists() => {
                // Concurrent exact replay may lose the create-once race.
                let existing = self.load(share.keyset_id, &share.algorithm)?;
                ensure!(existing == *share, "keyset share conflict");
                confirm_parent_durability(&self.path(share.keyset_id)).map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone)]
pub struct ExecutionTombstones {
    directory: PathBuf,
}

impl ExecutionTombstones {
    pub fn open(directory: PathBuf) -> Result<Self> {
        let tombstones = Self { directory };
        fs::create_dir_all(&tombstones.directory)?;
        confirm_parent_durability(&tombstones.directory)?;
        for entry in fs::read_dir(&tombstones.directory)? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) == Some("state")
                && fs::read(&path)? == b"ACTIVE"
            {
                atomic_replace_state(&path, b"ABORTED_AFTER_RESTART")?;
            }
        }
        Ok(tombstones)
    }

    fn path(&self, execution_id: Uuid) -> PathBuf {
        self.directory.join(format!("{execution_id}.state"))
    }

    pub fn begin(&self, execution_id: Uuid) -> Result<()> {
        let path = self.path(execution_id);
        match atomic_create_secret(&path, b"ACTIVE") {
            Ok(()) => Ok(()),
            Err(error) if error.phase == AtomicWritePhase::PostRenameDurabilityUncertain => {
                confirm_parent_durability(&path).map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn require_active(&self, execution_id: Uuid) -> Result<()> {
        ensure!(
            fs::read(self.path(execution_id))? == b"ACTIVE",
            "crypto execution is stale"
        );
        Ok(())
    }

    pub fn complete(&self, execution_id: Uuid) -> Result<()> {
        self.require_active(execution_id)?;
        atomic_replace_state(&self.path(execution_id), b"COMPLETED").map_err(Into::into)
    }

    pub fn abort(&self, execution_id: Uuid) -> Result<()> {
        self.require_active(execution_id)?;
        atomic_replace_state(&self.path(execution_id), b"ABORTED").map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn phase6a_service_is_disabled_except_explicit_loopback_development() {
        assert!(phase6a_insecure_local_listener(false).is_err());
        assert_eq!(
            phase6a_insecure_local_listener(true).unwrap().ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }

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
                trusted_peers: BTreeMap::from([
                    ("spiffe://wallet-mpc/signer-b".into(), "signer-b".into()),
                    (
                        "spiffe://wallet-mpc/coordinator".into(),
                        "coordinator".into(),
                    ),
                ]),
            },
            root,
        )
    }

    #[test]
    fn signer_configuration_rejects_ambiguous_algorithms_and_peers() {
        let (mut config, root) = temporary_config("signer-a");
        config.supported_algorithms.push("".into());
        assert!(config.validate().is_err());
        config.supported_algorithms = vec!["CGGMP24_ECDSA".into(), "CGGMP24_ECDSA".into()];
        assert!(config.validate().is_err());
        config.supported_algorithms = vec!["UNKNOWN".into()];
        assert!(config.validate().is_err());
        config.supported_algorithms = vec!["CGGMP24_ECDSA".into()];
        config.trusted_peers.clear();
        assert!(config.validate().is_err());
        config
            .trusted_peers
            .insert("not-a-spiffe-id".into(), "signer-b".into());
        assert!(config.validate().is_err());
        assert!(SignerConfig::parse_trusted_peers(
            "spiffe://wallet-mpc/signer-b=signer-b,spiffe://wallet-mpc/signer-b=signer-c"
        )
        .is_err());
        fs::remove_dir_all(root).unwrap();
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
    fn keyset_share_is_create_once_and_exact_replay_is_idempotent() {
        let keyset = Uuid::new_v4();
        let (config, root) = temporary_config("signer-a");
        let store = SignerStore::open(config).unwrap();
        let share = StoredShare {
            format_version: SHARE_FORMAT_VERSION,
            protocol_version: PROTOCOL_VERSION.into(),
            algorithm: "CGGMP24_ECDSA".into(),
            keyset_id: keyset,
            party_id: "signer-a".into(),
            protocol_share: vec![1, 2, 3],
        };
        store.persist(&share).unwrap();
        let original = fs::read(store.path(keyset)).unwrap();
        store.persist(&share).unwrap();
        assert_eq!(fs::read(store.path(keyset)).unwrap(), original);
        let conflicting = StoredShare {
            format_version: SHARE_FORMAT_VERSION,
            protocol_version: PROTOCOL_VERSION.into(),
            algorithm: "CGGMP24_ECDSA".into(),
            keyset_id: keyset,
            party_id: "signer-a".into(),
            protocol_share: vec![9, 9, 9],
        };
        assert!(store.persist(&conflicting).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn keyset_share_rejects_wrong_party_and_algorithm() {
        let keyset = Uuid::new_v4();
        let (config, root) = temporary_config("signer-a");
        let store = SignerStore::open(config).unwrap();
        let wrong_party = StoredShare {
            format_version: SHARE_FORMAT_VERSION,
            protocol_version: PROTOCOL_VERSION.into(),
            algorithm: "FROST_ED25519".into(),
            keyset_id: keyset,
            party_id: "signer-b".into(),
            protocol_share: vec![1],
        };
        assert!(store.persist(&wrong_party).is_err());
        let unsupported = StoredShare {
            format_version: SHARE_FORMAT_VERSION,
            protocol_version: PROTOCOL_VERSION.into(),
            algorithm: "UNKNOWN".into(),
            keyset_id: keyset,
            party_id: "signer-a".into(),
            protocol_share: vec![1],
        };
        assert!(store.persist(&unsupported).is_err());
        fs::remove_dir_all(root).unwrap();
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

    #[test]
    fn execution_begin_is_atomic_under_twenty_callers() {
        use std::sync::{Arc, Barrier};

        let root = std::env::temp_dir().join(format!("execution-race-{}", Uuid::new_v4()));
        let guard = Arc::new(ExecutionTombstones::open(root.clone()).unwrap());
        let barrier = Arc::new(Barrier::new(20));
        let execution = Uuid::new_v4();
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let guard = Arc::clone(&guard);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    guard.begin(execution).is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|succeeded| *succeeded)
                .count(),
            1
        );
        guard.abort(execution).unwrap();
        assert!(guard.begin(execution).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
