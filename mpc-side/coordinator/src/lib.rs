//! Durable, non-secret coordinator metadata and idempotent HTTP API.
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionStatus {
    Created,
    Starting,
    InProgress,
    Completed,
    DefinitiveNoSignatureFailure,
    ReconciliationRequired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignRequest {
    pub session_id: Uuid,
    pub attempt_id: u64,
    pub keyset_id: Uuid,
    pub algorithm: String,
    pub payload_type: String,
    pub payload_hex: String,
    pub message_fingerprint: String,
    pub operation_type: String,
    pub chain: String,
    pub asset: String,
    pub expected_source: String,
    pub derivation_reference: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignSession {
    #[serde(flatten)]
    pub request: SignRequest,
    pub status: SessionStatus,
    pub selected_signers: Vec<String>,
    pub crypto_execution_id: Uuid,
    pub signature: Option<serde_json::Value>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DkgRequest {
    pub session_id: Uuid,
    pub execution_id: Uuid,
    pub keyset_id: Uuid,
    pub algorithm: String,
    pub curve: String,
    pub scope: String,
    pub derivation_version: String,
    pub threshold: u16,
    pub party_count: u16,
    pub participants: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DkgSession {
    #[serde(flatten)]
    pub request: DkgRequest,
    pub status: SessionStatus,
    pub group_public_key: Option<String>,
    pub result_fingerprint: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Database {
    signing: BTreeMap<Uuid, SignSession>,
    dkg: BTreeMap<Uuid, DkgSession>,
}

pub struct DurableStore {
    path: PathBuf,
    data: Mutex<Database>,
    durability_uncertain: Mutex<BTreeSet<OperationKey>>,
    #[cfg(test)]
    fault: std::sync::atomic::AtomicU8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OperationKey {
    Sign(Uuid),
    Dkg(Uuid),
}

#[derive(Debug)]
enum PersistError {
    PreCommit,
    PostRenameDurabilityUncertain,
}
impl DurableStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let parent = path
            .parent()
            .context("coordinator state path has no parent")?;
        if !parent.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir(),
            "coordinator state parent is not a directory"
        );
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "coordinator state directory owner mismatch"
        );
        ensure!(
            metadata.mode() & 0o077 == 0,
            "coordinator state directory must be private"
        );
        let data = if path.exists() {
            let state_metadata = fs::symlink_metadata(&path)?;
            ensure!(
                state_metadata.is_file(),
                "coordinator state is not a regular file"
            );
            ensure!(
                state_metadata.uid() == unsafe { libc::geteuid() },
                "coordinator state owner mismatch"
            );
            ensure!(
                state_metadata.mode() & 0o077 == 0,
                "coordinator state file must be private"
            );
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            Database::default()
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
            durability_uncertain: Mutex::new(BTreeSet::new()),
            #[cfg(test)]
            fault: std::sync::atomic::AtomicU8::new(0),
        })
    }
    async fn persist(&self, data: &Database) -> Result<(), PersistError> {
        let parent = self.path.parent().ok_or(PersistError::PreCommit)?;
        let temporary = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut renamed = false;
        let result = (|| -> Result<()> {
            #[cfg(test)]
            if self.fault.load(std::sync::atomic::Ordering::SeqCst) == 1 {
                anyhow::bail!("injected failure before write");
            }
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&serde_json::to_vec(data)?)?;
            file.sync_all()?;
            #[cfg(test)]
            if self.fault.load(std::sync::atomic::Ordering::SeqCst) == 2 {
                anyhow::bail!("injected failure before rename");
            }
            fs::rename(&temporary, &self.path)?;
            renamed = true;
            #[cfg(test)]
            if self.fault.load(std::sync::atomic::Ordering::SeqCst) == 3 {
                anyhow::bail!("injected failure after rename");
            }
            OpenOptions::new().read(true).open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|_| {
            if renamed {
                PersistError::PostRenameDurabilityUncertain
            } else {
                PersistError::PreCommit
            }
        })
    }
    pub async fn create_sign(&self, request: SignRequest) -> Result<SignSession, StoreError> {
        validate_sign_request(&request)?;
        let mut data = self.data.lock().await;
        if let Some(existing) = data.signing.get(&request.session_id) {
            if self
                .durability_uncertain
                .lock()
                .await
                .contains(&OperationKey::Sign(request.session_id))
            {
                return Err(StoreError::DurabilityUncertain);
            }
            return if existing.request == request {
                Ok(existing.clone())
            } else {
                Err(StoreError::Conflict)
            };
        }
        let session = SignSession {
            request: request.clone(),
            status: SessionStatus::Created,
            selected_signers: vec![],
            crypto_execution_id: Uuid::new_v4(),
            signature: None,
            error_code: None,
        };
        data.signing.insert(request.session_id, session.clone());
        match self.persist(&data).await {
            Ok(()) => {}
            Err(PersistError::PreCommit) => {
                data.signing.remove(&request.session_id);
                return Err(StoreError::Storage);
            }
            Err(PersistError::PostRenameDurabilityUncertain) => {
                self.durability_uncertain
                    .lock()
                    .await
                    .insert(OperationKey::Sign(request.session_id));
                return Err(StoreError::DurabilityUncertain);
            }
        }
        Ok(session)
    }
    async fn confirm_durability(&self, key: OperationKey) -> Result<(), StoreError> {
        if !self.durability_uncertain.lock().await.contains(&key) {
            return Ok(());
        }
        #[cfg(test)]
        if self.fault.load(std::sync::atomic::Ordering::SeqCst) == 4 {
            return Err(StoreError::DurabilityUncertain);
        }
        let parent = self.path.parent().ok_or(StoreError::DurabilityUncertain)?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StoreError::DurabilityUncertain)?;
        self.durability_uncertain.lock().await.remove(&key);
        Ok(())
    }
    pub async fn get_sign(&self, id: Uuid) -> Result<Option<SignSession>, StoreError> {
        self.confirm_durability(OperationKey::Sign(id)).await?;
        Ok(self.data.lock().await.signing.get(&id).cloned())
    }
    pub async fn create_dkg(&self, request: DkgRequest) -> Result<DkgSession, StoreError> {
        let participants: BTreeSet<_> = request.participants.iter().map(String::as_str).collect();
        let topology_valid = request.threshold == 2
            && request.party_count == 3
            && participants == BTreeSet::from(["signer-a", "signer-b", "signer-c"]);
        let algorithm_valid = match request.scope.as_str() {
            "EVM" | "TRON" => {
                request.algorithm == "CGGMP24_ECDSA"
                    && request.curve == "secp256k1"
                    && request.derivation_version == "cggmp_hd_v1"
            }
            "SOLANA" => {
                request.algorithm == "FROST_ED25519"
                    && request.curve == "ed25519"
                    && request.derivation_version == "frost_keyset_v1"
            }
            _ => false,
        };
        if !topology_valid || !algorithm_valid {
            return Err(StoreError::Invalid);
        }
        let mut data = self.data.lock().await;
        if let Some(existing) = data.dkg.get(&request.session_id) {
            if self
                .durability_uncertain
                .lock()
                .await
                .contains(&OperationKey::Dkg(request.session_id))
            {
                return Err(StoreError::DurabilityUncertain);
            }
            return if existing.request == request {
                Ok(existing.clone())
            } else {
                Err(StoreError::Conflict)
            };
        }
        let session = DkgSession {
            request: request.clone(),
            status: SessionStatus::Created,
            group_public_key: None,
            result_fingerprint: None,
        };
        data.dkg.insert(request.session_id, session.clone());
        match self.persist(&data).await {
            Ok(()) => {}
            Err(PersistError::PreCommit) => {
                data.dkg.remove(&request.session_id);
                return Err(StoreError::Storage);
            }
            Err(PersistError::PostRenameDurabilityUncertain) => {
                self.durability_uncertain
                    .lock()
                    .await
                    .insert(OperationKey::Dkg(request.session_id));
                return Err(StoreError::DurabilityUncertain);
            }
        }
        Ok(session)
    }
    pub async fn get_dkg(&self, id: Uuid) -> Result<Option<DkgSession>, StoreError> {
        self.confirm_durability(OperationKey::Dkg(id)).await?;
        Ok(self.data.lock().await.dkg.get(&id).cloned())
    }
    pub async fn get_keyset(&self, keyset_id: Uuid) -> Result<Option<DkgSession>, StoreError> {
        let candidate = self
            .data
            .lock()
            .await
            .dkg
            .values()
            .find(|session| session.request.keyset_id == keyset_id)
            .cloned();
        if let Some(session) = &candidate {
            self.confirm_durability(OperationKey::Dkg(session.request.session_id))
                .await?;
        }
        Ok(candidate)
    }

    #[cfg(test)]
    fn inject_persist_fault(&self, point: u8) {
        self.fault.store(point, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Debug)]
pub enum StoreError {
    Invalid,
    Conflict,
    Storage,
    DurabilityUncertain,
}
fn validate_sign_request(request: &SignRequest) -> Result<(), StoreError> {
    if !matches!(
        request.payload_type.as_str(),
        "EVM_LEGACY_DIGEST" | "EVM_EIP1559_DIGEST" | "TRON_TXID" | "SOLANA_MESSAGE"
    ) || request.operation_type.is_empty()
        || request.chain.is_empty()
        || request.asset.is_empty()
        || request.expected_source.is_empty()
    {
        return Err(StoreError::Invalid);
    }
    let bytes = decode_hex(&request.payload_hex).ok_or(StoreError::Invalid)?;
    if format!("{:x}", Sha256::digest(bytes)) != request.message_fingerprint {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}
fn response(error: StoreError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match error {
        StoreError::Invalid => StatusCode::BAD_REQUEST,
        StoreError::Conflict => StatusCode::CONFLICT,
        StoreError::Storage => StatusCode::INTERNAL_SERVER_ERROR,
        StoreError::DurabilityUncertain => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(serde_json::json!({"error":format!("{error:?}")})),
    )
}

async fn create_sign(
    State(store): State<Arc<DurableStore>>,
    Json(request): Json<SignRequest>,
) -> Result<Json<SignSession>, (StatusCode, Json<serde_json::Value>)> {
    store.create_sign(request).await.map(Json).map_err(response)
}
async fn get_sign(
    State(store): State<Arc<DurableStore>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SignSession>, (StatusCode, Json<serde_json::Value>)> {
    store
        .get_sign(id)
        .await
        .map_err(response)?
        .map(Json)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"not found"})),
        ))
}
async fn create_dkg(
    State(store): State<Arc<DurableStore>>,
    Json(request): Json<DkgRequest>,
) -> Result<Json<DkgSession>, (StatusCode, Json<serde_json::Value>)> {
    store.create_dkg(request).await.map(Json).map_err(response)
}
async fn get_dkg(
    State(store): State<Arc<DurableStore>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DkgSession>, (StatusCode, Json<serde_json::Value>)> {
    store.get_dkg(id).await.map_err(response)?.map(Json).ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    ))
}
async fn get_keyset(
    State(store): State<Arc<DurableStore>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DkgSession>, (StatusCode, Json<serde_json::Value>)> {
    store
        .get_keyset(id)
        .await
        .map_err(response)?
        .map(Json)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"not found"})),
        ))
}
async fn get_public_key(
    State(store): State<Arc<DurableStore>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session = store.get_keyset(id).await.map_err(response)?.ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"not found"})),
    ))?;
    let public_key = session.group_public_key.ok_or((
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error":"DKG incomplete"})),
    ))?;
    Ok(Json(
        serde_json::json!({"keyset_id":id,"public_key":public_key}),
    ))
}
async fn quorum() -> Json<serde_json::Value> {
    // Reachability is deliberately UNKNOWN until authenticated signer clients
    // are configured; process health is never reported as signer quorum.
    Json(
        serde_json::json!({"healthy":0,"required":2,"party_count":3,"signable":false,"signers":[]}),
    )
}
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"service":"coordinator","protocol":"phase6-v1"}))
}

pub fn app(store: Arc<DurableStore>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/sign-sessions", post(create_sign))
        .route("/v1/sign-sessions/{id}", get(get_sign))
        .route("/v1/dkg-sessions", post(create_dkg))
        .route("/v1/dkg-sessions/{id}", get(get_dkg))
        .route("/v1/keysets/{id}", get(get_keyset))
        .route("/v1/keysets/{id}/public-key", get(get_public_key))
        .route("/v1/health/quorum", get(quorum))
        .with_state(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    fn state_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("wallet-mpc-test-{}", Uuid::new_v4()))
            .join("coordinator")
            .join("state.json")
    }
    fn request(id: Uuid) -> SignRequest {
        let payload = b"digest";
        SignRequest {
            session_id: id,
            attempt_id: 7,
            keyset_id: Uuid::new_v4(),
            algorithm: "CGGMP24_ECDSA".into(),
            payload_type: "EVM_LEGACY_DIGEST".into(),
            payload_hex: payload.iter().map(|b| format!("{b:02x}")).collect(),
            message_fingerprint: format!("{:x}", Sha256::digest(payload)),
            operation_type: "WITHDRAWAL".into(),
            chain: "ETH".into(),
            asset: "ETH".into(),
            expected_source: "0x123".into(),
            derivation_reference: Some("cggmp_hd_v1/1/2/0".into()),
        }
    }
    fn dkg_request(id: Uuid) -> DkgRequest {
        DkgRequest {
            session_id: id,
            execution_id: Uuid::new_v4(),
            keyset_id: Uuid::new_v4(),
            algorithm: "CGGMP24_ECDSA".into(),
            curve: "secp256k1".into(),
            scope: "EVM".into(),
            derivation_version: "cggmp_hd_v1".into(),
            threshold: 2,
            party_count: 3,
            participants: vec!["signer-a".into(), "signer-b".into(), "signer-c".into()],
        }
    }
    #[tokio::test]
    async fn duplicate_concurrent_create_is_one_logical_session_and_survives_restart() {
        let path = state_path();
        let store = Arc::new(DurableStore::open(&path).unwrap());
        let id = Uuid::new_v4();
        let request = request(id);
        let (a, b) = tokio::join!(
            store.create_sign(request.clone()),
            store.create_sign(request)
        );
        assert_eq!(
            a.unwrap().crypto_execution_id,
            b.unwrap().crypto_execution_id
        );
        drop(store);
        assert_eq!(
            DurableStore::open(&path)
                .unwrap()
                .get_sign(id)
                .await
                .unwrap()
                .unwrap()
                .request
                .attempt_id,
            7
        );
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }
    #[tokio::test]
    async fn conflicting_duplicate_and_bad_fingerprint_fail_closed() {
        let path = state_path();
        let store = DurableStore::open(&path).unwrap();
        let id = Uuid::new_v4();
        store.create_sign(request(id)).await.unwrap();
        let mut conflict = request(id);
        conflict.attempt_id = 8;
        assert!(matches!(
            store.create_sign(conflict).await,
            Err(StoreError::Conflict)
        ));
        let mut bad = request(Uuid::new_v4());
        bad.message_fingerprint = "00".repeat(32);
        assert!(matches!(
            store.create_sign(bad).await,
            Err(StoreError::Invalid)
        ));
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn durable_state_is_private_atomic_and_not_acknowledged_on_failure() {
        let directory = std::env::temp_dir()
            .join(format!("coordinator-dir-{}", Uuid::new_v4()))
            .join("coordinator");
        let path = directory.join("state.json");
        let store = DurableStore::open(&path).unwrap();
        let id = Uuid::new_v4();
        store.create_sign(request(id)).await.unwrap();
        assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        fs::remove_dir_all(directory.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn persistence_faults_preserve_one_logical_execution() {
        for point in [1, 2] {
            let path = state_path();
            let store = DurableStore::open(&path).unwrap();
            store.inject_persist_fault(point);
            let id = Uuid::new_v4();
            assert!(matches!(
                store.create_sign(request(id)).await,
                Err(StoreError::Storage)
            ));
            assert!(store.get_sign(id).await.unwrap().is_none());
            assert!(!path.exists());
            drop(store);
            assert!(DurableStore::open(&path)
                .unwrap()
                .get_sign(id)
                .await
                .unwrap()
                .is_none());
            fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
        }

        let path = state_path();
        let store = DurableStore::open(&path).unwrap();
        store.inject_persist_fault(3);
        let id = Uuid::new_v4();
        let original = request(id);
        assert!(matches!(
            store.create_sign(original.clone()).await,
            Err(StoreError::DurabilityUncertain)
        ));
        let execution = store
            .data
            .lock()
            .await
            .signing
            .get(&id)
            .unwrap()
            .crypto_execution_id;
        store.inject_persist_fault(4);
        assert!(matches!(
            store.get_sign(id).await,
            Err(StoreError::DurabilityUncertain)
        ));
        assert!(matches!(
            store.create_sign(original).await,
            Err(StoreError::DurabilityUncertain)
        ));
        store.inject_persist_fault(0);
        assert_eq!(
            store
                .get_sign(id)
                .await
                .unwrap()
                .unwrap()
                .crypto_execution_id,
            execution
        );
        drop(store);
        let reopened = DurableStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .get_sign(id)
                .await
                .unwrap()
                .unwrap()
                .crypto_execution_id,
            execution
        );
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn dkg_has_identical_namespaced_durability_semantics() {
        for point in [1, 2] {
            let path = state_path();
            let store = DurableStore::open(&path).unwrap();
            store.inject_persist_fault(point);
            let id = Uuid::new_v4();
            assert!(matches!(
                store.create_dkg(dkg_request(id)).await,
                Err(StoreError::Storage)
            ));
            assert!(store.get_dkg(id).await.unwrap().is_none());
            fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
        }
        let path = state_path();
        let store = DurableStore::open(&path).unwrap();
        let id = Uuid::new_v4();
        store.create_sign(request(id)).await.unwrap();
        store.inject_persist_fault(3);
        let dkg = dkg_request(id);
        let execution = dkg.execution_id;
        assert!(matches!(
            store.create_dkg(dkg).await,
            Err(StoreError::DurabilityUncertain)
        ));
        // DKG uncertainty with the same raw UUID cannot contaminate SIGN.
        assert!(store.get_sign(id).await.unwrap().is_some());
        store.inject_persist_fault(4);
        assert!(matches!(
            store.get_dkg(id).await,
            Err(StoreError::DurabilityUncertain)
        ));
        store.inject_persist_fault(0);
        assert_eq!(
            store
                .get_dkg(id)
                .await
                .unwrap()
                .unwrap()
                .request
                .execution_id,
            execution
        );
        drop(store);
        assert_eq!(
            DurableStore::open(&path)
                .unwrap()
                .get_dkg(id)
                .await
                .unwrap()
                .unwrap()
                .request
                .execution_id,
            execution
        );
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn dkg_contract_rejects_invalid_topology_and_algorithm_shape() {
        let path = state_path();
        let store = DurableStore::open(&path).unwrap();
        let mut duplicate = dkg_request(Uuid::new_v4());
        duplicate.participants[2] = "signer-b".into();
        assert!(matches!(
            store.create_dkg(duplicate).await,
            Err(StoreError::Invalid)
        ));
        let mut wrong_shape = dkg_request(Uuid::new_v4());
        wrong_shape.algorithm = "FROST_ED25519".into();
        assert!(matches!(
            store.create_dkg(wrong_shape).await,
            Err(StoreError::Invalid)
        ));
        let mut wrong_threshold = dkg_request(Uuid::new_v4());
        wrong_threshold.threshold = 3;
        assert!(matches!(
            store.create_dkg(wrong_threshold).await,
            Err(StoreError::Invalid)
        ));
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }
}
