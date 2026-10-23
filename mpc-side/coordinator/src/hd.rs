//! All three authenticated original stores must agree before public issuance.
use super::*;
use wallet_mpc_protocol::{
    cggmp::AUX_READY,
    hd::{ChildApprovalRequest, ChildEvidence, HdDedicationRequest, HdEvidence},
};
use wallet_mpc_transport::SignerClient;

impl DurableStore {
    pub(super) fn hd_path(&self, name: &str) -> PathBuf {
        self.path.with_extension("hd").join(name)
    }
    pub(super) fn hd_read<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<T>> {
        let path = self.hd_path(name);
        if !path.exists() {
            return Ok(None);
        }
        let value = serde_json::from_slice(&fs::read(&path)?)?;
        wallet_mpc_storage::confirm_parent_durability(&path)?;
        Ok(Some(value))
    }
    fn hd_pin<T: Serialize>(&self, name: &str, value: &T) -> anyhow::Result<()> {
        let path = self.hd_path(name);
        let parent = path.parent().context("HD parent missing")?;
        fs::create_dir_all(parent)?;
        wallet_mpc_storage::confirm_parent_durability(parent)?;
        let bytes = serde_json::to_vec(value)?;
        if !path.exists() {
            wallet_mpc_storage::atomic_create_secret(&path, &bytes)?;
        }
        ensure!(fs::read(&path)? == bytes, "immutable HD evidence conflict");
        wallet_mpc_storage::confirm_parent_durability(&path)?;
        Ok(())
    }
    pub(super) fn approved_child(
        &self,
        child: &wallet_mpc_protocol::hd::ChildIdentity,
    ) -> anyhow::Result<()> {
        let root: HdEvidence = self
            .hd_read(&format!(
                "{}.root",
                child.request.root.request.auxiliary.dkg.keyset_id
            ))?
            .context("missing original HD agreement")?;
        root.validate()?;
        ensure!(root.root == child.request.root, "wrong original HD root");
        let evidence: ChildEvidence = self
            .hd_read(&format!("{}.child", child.request.reservation_id))?
            .context("missing approved child")?;
        evidence.validate()?;
        ensure!(evidence.child == *child, "child approval mismatch");
        Ok(())
    }
}
struct Service {
    store: Arc<DurableStore>,
    peers: SignerClient,
    lock: Mutex<()>,
}
async fn attest_inner(
    service: &Service,
    keyset: Uuid,
    dedication: HdDedicationRequest,
) -> anyhow::Result<HdEvidence> {
    let dkg = service
        .store
        .get_keyset(keyset)
        .await
        .map_err(|_| anyhow::anyhow!("keyset unavailable"))?
        .context("missing DKG")?;
    let aux = dkg
        .auxiliary
        .as_ref()
        .context("missing auxiliary evidence")?;
    aux.validate(&dkg)?;
    ensure!(
        aux.status == AUX_READY && aux.internally_signable,
        "root is not spendable"
    );
    dedication.statement.validate()?;
    let request = &dedication.statement.request;
    ensure!(
        request.auxiliary == aux.request && request.auxiliary.dkg.keyset_id == keyset,
        "dedication must preserve original keyset and auxiliary execution"
    );
    ensure!(
        request.scope.root_identity["dkg_fingerprint"]
            == dkg
                .result_fingerprint
                .as_deref()
                .context("DKG fingerprint missing")?,
        "wrong original DKG fingerprint"
    );
    let name = format!("{keyset}.root");
    if let Some(previous) = service.store.hd_read::<HdEvidence>(&name)? {
        previous.validate()?;
        ensure!(
            previous.root.request == *request,
            "original namespace cannot change"
        );
    }
    let mut reports = vec![];
    for party in PARTIES {
        let bytes = service
            .peers
            .request(
                party,
                "POST",
                "/internal/v1/cggmp/hd/attest",
                serde_json::to_vec(&dedication)?,
            )
            .await?;
        let report: wallet_mpc_protocol::hd::HdRootReport = serde_json::from_slice(&bytes)?;
        ensure!(
            report.party_id == party && report.root.request == *request && report.durable,
            "wrong authenticated HD receipt"
        );
        reports.push(report);
    }
    let evidence = HdEvidence {
        root: reports[0].root.clone(),
        participant_agreement: reports,
    };
    evidence.validate()?;
    service.store.hd_pin(&name, &evidence)?;
    Ok(evidence)
}
async fn child_inner(
    service: &Service,
    keyset: Uuid,
    approval: ChildApprovalRequest,
) -> anyhow::Result<ChildEvidence> {
    let request = &approval.request;
    let root: HdEvidence = service
        .store
        .hd_read(&format!("{keyset}.root"))?
        .context("original HD evidence unavailable")?;
    root.validate()?;
    ensure!(
        root.root == request.root && request.root.request.auxiliary.dkg.keyset_id == keyset,
        "wrong original root/network"
    );
    let expected = request.derive()?;
    let name = format!("{}.child", request.reservation_id);
    if let Some(previous) = service.store.hd_read::<ChildEvidence>(&name)? {
        previous.validate()?;
        ensure!(
            previous.child == expected,
            "approved child cannot be reassigned"
        );
        // Durable retries are public; they do not need a newly available quorum.
        return Ok(previous);
    }
    let mut reports = vec![];
    for party in PARTIES {
        let bytes = service
            .peers
            .request(
                party,
                "POST",
                "/internal/v1/cggmp/hd/child",
                serde_json::to_vec(&approval)?,
            )
            .await?;
        let report: wallet_mpc_protocol::hd::ChildReport = serde_json::from_slice(&bytes)?;
        ensure!(
            report.party_id == party && report.child == expected && report.durable,
            "wrong authenticated child receipt"
        );
        reports.push(report);
    }
    let evidence = ChildEvidence {
        child: expected,
        participant_agreement: reports,
    };
    evidence.validate()?;
    service.store.hd_pin(&name, &evidence)?;
    Ok(evidence)
}
async fn attest(
    State(service): State<Arc<Service>>,
    Path(keyset): Path<Uuid>,
    Json(dedication): Json<HdDedicationRequest>,
) -> Result<Json<HdEvidence>, StatusCode> {
    let _guard = service.lock.lock().await;
    attest_inner(&service, keyset, dedication)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
async fn child(
    State(service): State<Arc<Service>>,
    Path(keyset): Path<Uuid>,
    Json(request): Json<ChildApprovalRequest>,
) -> Result<Json<ChildEvidence>, StatusCode> {
    let _guard = service.lock.lock().await;
    child_inner(&service, keyset, request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
pub(super) fn router(store: Arc<DurableStore>, peers: SignerClient) -> Router {
    Router::new()
        .route("/v1/keysets/{id}/hd-attestation", post(attest))
        .route("/v1/keysets/{id}/children", post(child))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(Arc::new(Service {
            store,
            peers,
            lock: Mutex::new(()),
        }))
}
