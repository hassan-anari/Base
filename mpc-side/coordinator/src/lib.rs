//! Durable, non-secret coordinator metadata and idempotent HTTP API.
use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
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
    pub keyset_id: Uuid,
    pub algorithm: String,
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
}
impl DurableStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let data = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            Database::default()
        };
        Ok(Self {
            path,
            data: Mutex::new(data),
        })
    }
    async fn persist(&self, data: &Database) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("coordinator state path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        fs::write(&temporary, serde_json::to_vec(data)?)?;
        fs::rename(temporary, &self.path)?;
        Ok(())
    }
    pub async fn create_sign(&self, request: SignRequest) -> Result<SignSession, StoreError> {
        validate_sign_request(&request)?;
        let mut data = self.data.lock().await;
        if let Some(existing) = data.signing.get(&request.session_id) {
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
        self.persist(&data).await.map_err(|_| StoreError::Storage)?;
        Ok(session)
    }
    pub async fn get_sign(&self, id: Uuid) -> Option<SignSession> {
        self.data.lock().await.signing.get(&id).cloned()
    }
    pub async fn create_dkg(&self, request: DkgRequest) -> Result<DkgSession, StoreError> {
        if request.threshold < 2
            || request.party_count < request.threshold
            || request.participants.len() != usize::from(request.party_count)
        {
            return Err(StoreError::Invalid);
        }
        let mut data = self.data.lock().await;
        if let Some(existing) = data.dkg.get(&request.session_id) {
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
        self.persist(&data).await.map_err(|_| StoreError::Storage)?;
        Ok(session)
    }
    pub async fn get_dkg(&self, id: Uuid) -> Option<DkgSession> {
        self.data.lock().await.dkg.get(&id).cloned()
    }
    pub async fn get_keyset(&self, keyset_id: Uuid) -> Option<DkgSession> {
        self.data
            .lock()
            .await
            .dkg
            .values()
            .find(|session| session.request.keyset_id == keyset_id)
            .cloned()
    }
}

#[derive(Debug)]
pub enum StoreError {
    Invalid,
    Conflict,
    Storage,
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
) -> Result<Json<SignSession>, StatusCode> {
    store
        .get_sign(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
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
) -> Result<Json<DkgSession>, StatusCode> {
    store
        .get_dkg(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
async fn get_keyset(
    State(store): State<Arc<DurableStore>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DkgSession>, StatusCode> {
    store
        .get_keyset(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
async fn get_public_key(
    State(store): State<Arc<DurableStore>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session = store.get_keyset(id).await.ok_or(StatusCode::NOT_FOUND)?;
    let public_key = session.group_public_key.ok_or(StatusCode::CONFLICT)?;
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
    #[tokio::test]
    async fn duplicate_concurrent_create_is_one_logical_session_and_survives_restart() {
        let path = std::env::temp_dir().join(format!("coordinator-{}.json", Uuid::new_v4()));
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
                .request
                .attempt_id,
            7
        );
        fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn conflicting_duplicate_and_bad_fingerprint_fail_closed() {
        let path = std::env::temp_dir().join(format!("coordinator-{}.json", Uuid::new_v4()));
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
        fs::remove_file(path).unwrap();
    }
}
