//! Immutable signer-origin receipts and custody-authorized root lifecycle.
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::hex,
    hd::{
        fingerprint, receipt_message, ChildApprovalRequest, ChildIdentity, ChildReport,
        HdDedicationRequest, HdDedicationStatement, HdRequest, HdRoot, HdRootReport,
    },
    sign::decode_hex,
};
use wallet_mpc_storage::{atomic_create_secret, confirm_parent_durability};
use wallet_mpc_transport::{CustodyRequestVerifier, PeerIdentity, ReceiptIdentity};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RootRole {
    keyset_id: Uuid,
    // None is irreversible historical root use. Some is one exact authorized dedication.
    dedication: Option<HdDedicationStatement>,
    custody_authorization: Option<wallet_mpc_protocol::sign::CustodyAuthorization>,
}
pub struct HdService {
    directory: PathBuf,
    party: String,
    auxiliary: Arc<crate::cggmp_aux::AuxService>,
    lock: Mutex<()>,
    custody_verifier: CustodyRequestVerifier,
    receipt_identity: Option<ReceiptIdentity>,
}
impl HdService {
    pub fn verify_original_request(
        &self,
        request: &wallet_mpc_protocol::sign::SignRequest,
    ) -> Result<()> {
        let auth = request
            .custody_authorization
            .as_ref()
            .context("original custody child authorization required")?;
        self.verify_custody_message(&request.custody_authorization_message()?, auth)
    }
    fn verify_custody_message(
        &self,
        message: &[u8],
        auth: &wallet_mpc_protocol::sign::CustodyAuthorization,
    ) -> Result<()> {
        let chain = auth
            .certificate_chain_der_hex
            .iter()
            .map(|c| decode_hex(c).context("invalid custody certificate encoding"))
            .collect::<Result<Vec<_>>>()?;
        let signature =
            decode_hex(&auth.signature_der_hex).context("invalid custody signature encoding")?;
        self.custody_verifier.verify(message, &chain, &signature)
    }
    fn role_path(&self, keyset: Uuid) -> PathBuf {
        self.directory.join(format!("{keyset}.role"))
    }
    fn role(&self, keyset: Uuid) -> Result<Option<RootRole>> {
        let path = self.role_path(keyset);
        if !path.exists() {
            return Ok(None);
        }
        let role: RootRole = serde_json::from_slice(&fs::read(&path)?)?;
        ensure!(role.keyset_id == keyset, "root role keyset mismatch");
        ensure!(
            role.dedication.is_some() == role.custody_authorization.is_some(),
            "incomplete original dedication authorization"
        );
        if let Some(statement) = &role.dedication {
            statement.validate()?;
            ensure!(
                statement.dedication_id == keyset,
                "dedication keyset mismatch"
            );
        }
        confirm_parent_durability(&path)?;
        Ok(Some(role))
    }
    pub async fn require_historical_root_signing(&self, keyset: Uuid, reserve: bool) -> Result<()> {
        let _guard = self.lock.lock().await;
        ensure!(
            !self.directory.join(format!("{keyset}.root")).exists()
                && self.role(keyset)?.is_none_or(|r| r.dedication.is_none()),
            "dedicated HD root requires approved child authorization"
        );
        if reserve {
            self.pin(
                &format!("{keyset}.role"),
                &RootRole {
                    keyset_id: keyset,
                    dedication: None,
                    custody_authorization: None,
                },
                true,
            )?;
        }
        Ok(())
    }
    pub fn open(
        directory: PathBuf,
        party: String,
        auxiliary: Arc<crate::cggmp_aux::AuxService>,
        custody_verifier: CustodyRequestVerifier,
        receipt_identity: Option<ReceiptIdentity>,
    ) -> Result<Arc<Self>> {
        let signing_directory = directory.join("cggmp-signing");
        let directory = directory.join("cggmp-hd");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let service = Arc::new(Self {
            directory,
            party,
            auxiliary,
            lock: Mutex::new(()),
            custody_verifier,
            receipt_identity,
        });
        // Existing original execution records are historical-use evidence. Never infer
        // UNUSED for a previously prepared, consumed, aborted or completed root session.
        let mut historical = BTreeSet::new();
        if signing_directory.exists() {
            for entry in fs::read_dir(&signing_directory)? {
                let path = entry?.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ["json", "completed", "consumed"].contains(&ext) {
                    let value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
                    let execution = if ext == "consumed" {
                        &value
                    } else {
                        &value["execution"]
                    };
                    let request: wallet_mpc_protocol::sign::SignRequest =
                        serde_json::from_value(execution["request"].clone())?;
                    if request.child_authorization.is_none() {
                        historical.insert(request.keyset_id);
                    }
                }
            }
        }
        // Pre-fix unsigned receipts cannot authorize anything after upgrade. Preserve
        // files and fail startup for an offline audit; never fabricate retrospective grants.
        for entry in fs::read_dir(&service.directory)? {
            let path = entry?.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "role" {
                let role: RootRole = serde_json::from_slice(&fs::read(&path)?)?;
                service.role(role.keyset_id)?;
            } else if ext == "root" {
                let report: HdRootReport = serde_json::from_slice(&fs::read(&path)?).context(
                    "unsigned pre-fix HD evidence requires quarantine and independent audit",
                )?;
                let keyset = report.root.request.auxiliary.dkg.keyset_id;
                let role = service
                    .role(keyset)?
                    .context("root receipt lacks original authorized dedication")?;
                ensure!(
                    role.dedication
                        .as_ref()
                        .is_some_and(|d| d.request == report.root.request)
                        && !historical.contains(&keyset)
                        && report.durable,
                    "incompatible original root lifecycle history"
                );
                service.verify_receipt(
                    "root",
                    &report.root,
                    &report.party_id,
                    &report.signer_signature,
                )?;
                ensure!(
                    path == service.directory.join(format!("{keyset}.root")),
                    "root filename mismatch"
                );
            } else if ["index", "owner", "child"].contains(&ext) {
                let report: ChildReport = serde_json::from_slice(&fs::read(&path)?)
                    .context("unsigned child receipt requires quarantine")?;
                let keyset = report.child.request.root.request.auxiliary.dkg.keyset_id;
                ensure!(
                    service.role(keyset)?.is_some_and(|r| r
                        .dedication
                        .is_some_and(|d| d.request == report.child.request.root.request))
                        && service.directory.join(format!("{keyset}.root")).exists()
                        && report.durable,
                    "child approval lacks original dedicated root"
                );
                service.verify_receipt(
                    "child",
                    &report.child,
                    &report.party_id,
                    &report.signer_signature,
                )?;
            }
        }
        for keyset in historical {
            ensure!(
                service.role(keyset)?.is_none_or(|r| r.dedication.is_none()),
                "historical root cannot become dedicated"
            );
            service.pin(
                &format!("{keyset}.role"),
                &RootRole {
                    keyset_id: keyset,
                    dedication: None,
                    custody_authorization: None,
                },
                true,
            )?;
        }
        Ok(service)
    }
    fn pin<T: Serialize>(&self, name: &str, value: &T, create: bool) -> Result<()> {
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
    fn verify_receipt<T: Serialize>(
        &self,
        kind: &str,
        identity: &T,
        party: &str,
        signature: &str,
    ) -> Result<()> {
        ensure!(party == self.party, "own signer receipt identity mismatch");
        self.receipt_identity
            .as_ref()
            .context("HD receipt identity unavailable")?
            .verify(
                &receipt_message(kind, identity, party)?,
                &decode_hex(signature).context("invalid signer receipt signature")?,
            )
    }
    fn signature<T: Serialize>(&self, kind: &str, identity: &T) -> Result<String> {
        Ok(hex(&self
            .receipt_identity
            .as_ref()
            .context("HD receipt identity unavailable")?
            .sign(&receipt_message(kind, identity, &self.party)?)?))
    }
    async fn original(&self, request: &HdRequest) -> Result<HdRoot> {
        request.validate()?;
        let key = self.auxiliary.own_key(&request.auxiliary).await?;
        // Recompute the original DKG public transcript from our validated share's
        // complete public verification shares, rather than trusting its label.
        let reports: Vec<_> = wallet_mpc_protocol::dkg::PARTIES
            .iter()
            .enumerate()
            .map(|(i, party)| wallet_mpc_protocol::dkg::DkgReport {
                request: request.auxiliary.dkg.clone(),
                party_id: (*party).into(),
                status: wallet_mpc_protocol::cggmp::CORE_READY.into(),
                share_format_version: crate::SHARE_FORMAT_VERSION,
                group_public_key: Some(request.auxiliary.group_public_key.clone()),
                public_key_package: Some(request.auxiliary.public_key_package.clone()),
                verification_share: Some(
                    key.core.public_shares[i].to_bytes(true).as_ref().to_vec(),
                ),
                durable: true,
            })
            .collect();
        use sha2::{Digest, Sha256};
        ensure!(
            request.scope.root_identity["dkg_fingerprint"]
                == hex(&Sha256::digest(serde_json::to_vec(&(
                    &request.auxiliary.dkg,
                    reports
                ))?)),
            "original DKG transcript fingerprint mismatch"
        );
        let epub = key
            .extended_public_key()
            .context("original DKG has no HD chain code")?;
        ensure!(
            hex(epub.public_key.to_bytes(true).as_ref()) == request.auxiliary.group_public_key,
            "own original HD/key binding mismatch"
        );
        HdRoot::new(request.clone(), hex(&epub.chain_code))
    }
    pub async fn attest(&self, dedication: HdDedicationRequest) -> Result<HdRootReport> {
        // Authentication, complete transition validation and lifecycle checks precede
        // any file creation or memory mutation, including the first role reservation.
        self.verify_custody_message(
            &dedication.authorization_message()?,
            &dedication.custody_authorization,
        )?;
        let _guard = self.lock.lock().await;
        let request = &dedication.statement.request;
        let keyset = request.auxiliary.dkg.keyset_id;
        let expected_role = if let Some(role) = self.role(keyset)? {
            ensure!(
                role.dedication.as_ref() == Some(&dedication.statement)
                    && role.custody_authorization.is_some(),
                "historical or conflicting root role"
            );
            role
        } else {
            RootRole {
                keyset_id: keyset,
                dedication: Some(dedication.statement.clone()),
                custody_authorization: Some(dedication.custody_authorization.clone()),
            }
        };
        let root = self.original(request).await?;
        let name = format!("{keyset}.root");
        if self.directory.join(&name).exists() {
            let report: HdRootReport =
                serde_json::from_slice(&fs::read(self.directory.join(&name))?)?;
            ensure!(
                report.root == root && report.durable,
                "conflicting original root receipt"
            );
            self.verify_receipt("root", &root, &report.party_id, &report.signer_signature)?;
            self.pin(&format!("{keyset}.role"), &expected_role, false)?;
            return Ok(report);
        }
        let report = HdRootReport {
            signer_signature: self.signature("root", &root)?,
            root,
            party_id: self.party.clone(),
            durable: true,
        };
        self.pin(&format!("{keyset}.role"), &expected_role, true)?;
        self.pin(&name, &report, true)?;
        Ok(report)
    }
    async fn own_child(&self, child: &ChildIdentity, create: bool) -> Result<ChildReport> {
        child.validate()?;
        let original = self.original(&child.request.root.request).await?;
        ensure!(
            original == child.request.root,
            "original chain code/root cannot be substituted"
        );
        let root_id = original.request.auxiliary.dkg.keyset_id;
        let role = self.role(root_id)?.context("missing original dedication")?;
        ensure!(
            role.dedication
                .is_some_and(|d| d.request == original.request),
            "dedication namespace mismatch"
        );
        let root_path = self.directory.join(format!("{root_id}.root"));
        let root_report: HdRootReport = serde_json::from_slice(&fs::read(&root_path)?)?;
        ensure!(
            root_report.root == original && root_report.durable,
            "original root receipt mismatch"
        );
        self.verify_receipt(
            "root",
            &original,
            &root_report.party_id,
            &root_report.signer_signature,
        )?;
        confirm_parent_durability(&root_path)?;
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
        let names = [
            format!("{root_id}-{}.index", child.request.child_index),
            format!(
                "{}.owner",
                fingerprint(
                    "CGGMP24_ACCOUNT_OWNER_V1",
                    &(root_id, &child.request.customer_ref)
                )?
            ),
            format!("{}.child", child.request.reservation_id),
        ];
        // Any partial create contains the exact original randomized receipt. Recover
        // it without re-signing, reassigning or consuming an MPC execution.
        let mut previous = None;
        for name in &names {
            let path = self.directory.join(name);
            if path.exists() {
                let report: ChildReport = serde_json::from_slice(&fs::read(path)?)?;
                ensure!(
                    report.child == *child && report.durable,
                    "conflicting original child receipt"
                );
                self.verify_receipt("child", child, &report.party_id, &report.signer_signature)?;
                if let Some(prior) = &previous {
                    ensure!(*prior == report, "partial receipt conflict");
                }
                previous = Some(report);
            }
        }
        let report = match previous {
            Some(report) => report,
            None => {
                ensure!(create, "missing original child approval");
                ChildReport {
                    child: child.clone(),
                    party_id: self.party.clone(),
                    durable: true,
                    signer_signature: self.signature("child", child)?,
                }
            }
        };
        for name in names {
            self.pin(&name, &report, create)?;
        }
        Ok(report)
    }
    pub async fn approve(&self, approval: ChildApprovalRequest) -> Result<ChildReport> {
        self.verify_custody_message(
            &approval.authorization_message()?,
            &approval.custody_authorization,
        )?;
        let _guard = self.lock.lock().await;
        self.own_child(&approval.request.derive()?, true).await
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
