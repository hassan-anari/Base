//! Signer-local create-once approval. HD material is read from the original
//! validated encrypted share; public statements never manufacture historical evidence.
use anyhow::{ensure, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use tokio::sync::Mutex;
use wallet_mpc_protocol::{
    dkg::hex,
    hd::{fingerprint, ChildIdentity, ChildReport, ChildRequest, HdRequest, HdRoot, HdRootReport},
};
use wallet_mpc_storage::{atomic_create_secret, confirm_parent_durability};
use wallet_mpc_transport::{CustodyRequestVerifier, PeerIdentity};

pub struct HdService {
    directory: PathBuf,
    party: String,
    auxiliary: Arc<crate::cggmp_aux::AuxService>,
    lock: Mutex<()>,
    dedicated: RwLock<BTreeSet<uuid::Uuid>>,
    custody_verifier: CustodyRequestVerifier,
}
impl HdService {
    pub fn verify_original_request(
        &self,
        request: &wallet_mpc_protocol::sign::SignRequest,
    ) -> Result<()> {
        use wallet_mpc_protocol::sign::decode_hex;
        let auth = request
            .custody_authorization
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("original custody child authorization required"))?;
        let chain = auth
            .certificate_chain_der_hex
            .iter()
            .map(|c| {
                decode_hex(c).ok_or_else(|| anyhow::anyhow!("invalid custody certificate encoding"))
            })
            .collect::<Result<Vec<_>>>()?;
        let signature = decode_hex(&auth.signature_der_hex)
            .ok_or_else(|| anyhow::anyhow!("invalid custody signature encoding"))?;
        self.custody_verifier.verify(
            &request.custody_authorization_message()?,
            &chain,
            &signature,
        )
    }
    pub fn require_historical_root_signing(&self, keyset: uuid::Uuid) -> Result<()> {
        // A dedicated DEPOSIT namespace has no issued root account. Dropping
        // child authorization must not turn its approval into root signing.
        ensure!(
            !self
                .dedicated
                .read()
                .map_err(|_| anyhow::anyhow!("HD binding lock poisoned"))?
                .contains(&keyset)
                && !self.directory.join(format!("{keyset}.root")).exists(),
            "dedicated HD root requires approved child authorization"
        );
        Ok(())
    }
    pub fn open(
        directory: PathBuf,
        party: String,
        auxiliary: Arc<crate::cggmp_aux::AuxService>,
        custody_verifier: CustodyRequestVerifier,
    ) -> Result<Arc<Self>> {
        let directory = directory.join("cggmp-hd");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let mut dedicated = BTreeSet::new();
        for entry in fs::read_dir(&directory)? {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            let root = name.strip_suffix(".root").or_else(|| {
                (name.ends_with(".index") && name.get(36..37) == Some("-"))
                    .then(|| name.get(..36))
                    .flatten()
            });
            if let Some(root) = root {
                dedicated.insert(root.parse()?);
            }
        }
        Ok(Arc::new(Self {
            directory,
            party,
            auxiliary,
            lock: Mutex::new(()),
            dedicated: RwLock::new(dedicated),
            custody_verifier,
        }))
    }
    fn pin<T: serde::Serialize>(&self, name: &str, value: &T, create: bool) -> Result<()> {
        let path = self.directory.join(name);
        let bytes = serde_json::to_vec(value)?;
        if create && !path.exists() {
            atomic_create_secret(&path, &bytes)?;
        }
        ensure!(
            fs::read(&path)? == bytes,
            "immutable original HD approval mismatch"
        );
        confirm_parent_durability(&path)?;
        Ok(())
    }
    async fn original(&self, request: &HdRequest) -> Result<HdRoot> {
        request.validate()?;
        let key = self.auxiliary.own_key(&request.auxiliary).await?;
        let epub = key
            .extended_public_key()
            .ok_or_else(|| anyhow::anyhow!("original DKG has no HD chain code"))?;
        ensure!(
            hex(epub.public_key.to_bytes(true).as_ref()) == request.auxiliary.group_public_key,
            "own original HD/key binding mismatch"
        );
        HdRoot::new(request.clone(), hex(&epub.chain_code))
    }
    pub async fn attest(&self, request: HdRequest) -> Result<HdRootReport> {
        let _guard = self.lock.lock().await;
        let root = self.original(&request).await?;
        self.dedicated
            .write()
            .map_err(|_| anyhow::anyhow!("HD binding lock poisoned"))?
            .insert(request.auxiliary.dkg.keyset_id);
        let report = HdRootReport {
            root,
            party_id: self.party.clone(),
            durable: true,
        };
        self.pin(
            &format!("{}.root", request.auxiliary.dkg.keyset_id),
            &report,
            true,
        )?;
        Ok(report)
    }
    async fn own_child(&self, child: &ChildIdentity, create: bool) -> Result<ChildReport> {
        child.validate()?;
        let original = self.original(&child.request.root.request).await?;
        ensure!(
            original == child.request.root,
            "original chain code/root cannot be substituted"
        );
        let root_report = HdRootReport {
            root: original,
            party_id: self.party.clone(),
            durable: true,
        };
        self.pin(
            &format!(
                "{}.root",
                child.request.root.request.auxiliary.dkg.keyset_id
            ),
            &root_report,
            false,
        )?;
        // Independent upstream derivation from this signer's own validated key,
        // checked against the coordinator's independent extended-public derivation.
        let key = self
            .auxiliary
            .own_key(&child.request.root.request.auxiliary)
            .await?;
        let public =
            key.derive_child_public_key::<cggmp24::hd_wallet::Slip10, _>(child.request.path()?)?;
        ensure!(
            hex(public.public_key.to_bytes(true).as_ref()) == child.public_key,
            "own upstream child differs"
        );
        let report = ChildReport {
            child: child.clone(),
            party_id: self.party.clone(),
            durable: true,
        };
        let root_id = child.request.root.request.auxiliary.dkg.keyset_id;
        // Bind both the index and canonical customer before publishing the approval.
        // Partial writes can only recover the same request; indices never recycle.
        self.pin(
            &format!("{root_id}-{}.index", child.request.child_index),
            &report,
            create,
        )?;
        self.pin(
            &format!(
                "{}.owner",
                fingerprint(
                    "CGGMP24_ACCOUNT_OWNER_V1",
                    &(root_id, &child.request.customer_ref)
                )?
            ),
            &report,
            create,
        )?;
        self.pin(
            &format!("{}.child", child.request.reservation_id),
            &report,
            create,
        )?;
        Ok(report)
    }
    pub async fn approve(&self, request: ChildRequest) -> Result<ChildReport> {
        let _guard = self.lock.lock().await;
        self.own_child(&request.derive()?, true).await
    }
    pub async fn validate_child(&self, child: &ChildIdentity) -> Result<()> {
        let _guard = self.lock.lock().await;
        self.own_child(child, false).await?;
        Ok(())
    }
}
async fn attest(
    State(service): State<Arc<HdService>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<HdRootReport>, StatusCode> {
    if peer.role() != "coordinator" {
        return Err(StatusCode::FORBIDDEN);
    }
    let request = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .attest(request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
async fn approve(
    State(service): State<Arc<HdService>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<ChildReport>, StatusCode> {
    if peer.role() != "coordinator" {
        return Err(StatusCode::FORBIDDEN);
    }
    let request = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .approve(request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
pub fn router(service: Arc<HdService>) -> Router {
    Router::new()
        .route("/internal/v1/cggmp/hd/attest", post(attest))
        .route("/internal/v1/cggmp/hd/child", post(approve))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(service)
}
