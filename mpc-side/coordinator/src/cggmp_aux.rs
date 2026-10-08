//! Durable auxiliary readiness is separate from immutable core DKG completion.
use super::*;
use std::time::Duration;
use wallet_mpc_protocol::cggmp::{verify_aux_receipts, verify_keygen_receipts, AuxReport, AuxRequest, AUX_READY};
use wallet_mpc_transport::SignerClient;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuxiliaryState {
    pub request: AuxRequest,
    pub status: String,
    pub internally_signable: bool,
    pub participant_agreement: Vec<AuxReport>,
}
impl AuxiliaryState {
    pub(super) fn validate(&self, session: &DkgSession) -> anyhow::Result<()> {
        verify_keygen_receipts(&session.request, &session.participant_agreement)?;
        self.request.validate()?;
        ensure!(session.status == SessionStatus::KeygenCompleted && self.request.dkg == session.request
            && Some(&self.request.group_public_key) == session.group_public_key.as_ref()
            && Some(&self.request.public_key_package) == session.participant_agreement[0].public_key_package.as_ref(),
            "wrong auxiliary/core coordinator binding");
        if self.status == AUX_READY {
            verify_aux_receipts(&self.request, &self.participant_agreement)?;
            ensure!(self.internally_signable, "invalid completed auxiliary readiness");
        } else {
            ensure!(["IN_PROGRESS", "RECONCILIATION_REQUIRED"].contains(&self.status.as_str())
                && !self.internally_signable && self.participant_agreement.is_empty(), "false auxiliary readiness");
        }
        Ok(())
    }
}
impl DurableStore {
    async fn claim_aux(&self, id: Uuid) -> Result<(DkgSession, bool), StoreError> {
        self.confirm_durability(OperationKey::Dkg(id)).await?;
        let mut data = self.data.lock().await;
        let previous = data.dkg.get(&id).cloned().ok_or(StoreError::Invalid)?;
        if previous.status != SessionStatus::KeygenCompleted
            || verify_keygen_receipts(&previous.request, &previous.participant_agreement).is_err() { return Err(StoreError::Invalid); }
        if previous.auxiliary.is_some() { return Ok((previous, false)); }
        let request = AuxRequest { dkg: previous.request.clone(), execution_id: Uuid::new_v4(),
            group_public_key: previous.group_public_key.clone().ok_or(StoreError::Invalid)?,
            public_key_package: previous.participant_agreement[0].public_key_package.clone().ok_or(StoreError::Invalid)? };
        let mut session = previous.clone();
        session.auxiliary = Some(AuxiliaryState { request, status: "IN_PROGRESS".into(), internally_signable: false, participant_agreement: vec![] });
        data.dkg.insert(id, session.clone());
        match self.persist(&data).await {
            Ok(()) => Ok((session, true)),
            Err(PersistError::PreCommit) => { data.dkg.insert(id, previous); Err(StoreError::Storage) }
            Err(PersistError::PostRenameDurabilityUncertain) => {
                self.durability_uncertain.lock().await.insert(OperationKey::Dkg(id)); Err(StoreError::DurabilityUncertain)
            }
        }
    }
    async fn finish_aux(&self, id: Uuid, request: &AuxRequest, reports: Option<Vec<AuxReport>>) -> Result<DkgSession, StoreError> {
        self.confirm_durability(OperationKey::Dkg(id)).await?;
        let mut data = self.data.lock().await;
        let previous = data.dkg.get(&id).cloned().ok_or(StoreError::Invalid)?;
        let old = previous.auxiliary.as_ref().ok_or(StoreError::Invalid)?;
        if old.request != *request { return Err(StoreError::Conflict); }
        if old.status == AUX_READY { old.validate(&previous).map_err(|_| StoreError::Invalid)?; return Ok(previous); }
        let mut session = previous.clone();
        let auxiliary = session.auxiliary.as_mut().ok_or(StoreError::Invalid)?;
        if let Some(reports) = reports {
            verify_aux_receipts(request, &reports).map_err(|_| StoreError::Invalid)?;
            auxiliary.status = AUX_READY.into(); auxiliary.internally_signable = true; auxiliary.participant_agreement = reports;
        } else {
            auxiliary.status = "RECONCILIATION_REQUIRED".into(); auxiliary.internally_signable = false;
        }
        auxiliary.validate(&previous).map_err(|_| StoreError::Invalid)?;
        data.dkg.insert(id, session.clone());
        match self.persist(&data).await {
            Ok(()) => Ok(session),
            Err(PersistError::PreCommit) => { data.dkg.insert(id, previous); Err(StoreError::Storage) }
            Err(PersistError::PostRenameDurabilityUncertain) => {
                self.durability_uncertain.lock().await.insert(OperationKey::Dkg(id)); Err(StoreError::DurabilityUncertain)
            }
        }
    }
}
struct Driver { store: Arc<DurableStore>, peers: SignerClient }
impl Driver {
    async fn all(&self, request: &AuxRequest, action: &str) -> anyhow::Result<Vec<AuxReport>> {
        let mut reports = vec![];
        for party in PARTIES {
            let bytes = self.peers.request(party, "POST", &format!("/internal/v1/cggmp/aux/{action}"), serde_json::to_vec(request)?).await?;
            let report: AuxReport = serde_json::from_slice(&bytes)?;
            ensure!(report.request == *request && report.party_id == party, "invalid authenticated auxiliary receipt");
            reports.push(report);
        }
        Ok(reports)
    }
    async fn execute(self: &Arc<Self>, id: Uuid, reconcile: bool) -> Result<DkgSession, StoreError> {
        let (session, claimed) = if reconcile {
            (self.store.get_dkg(id).await?.ok_or(StoreError::Invalid)?, false)
        } else { self.store.claim_aux(id).await? };
        let auxiliary = session.auxiliary.as_ref().ok_or(StoreError::Invalid)?;
        auxiliary.validate(&session).map_err(|_| StoreError::Invalid)?;
        if auxiliary.status == AUX_READY { return Ok(session); }
        if reconcile {
            if auxiliary.status != "RECONCILIATION_REQUIRED" { return Err(StoreError::Conflict); }
            let reports = self.all(&auxiliary.request, "report").await.map_err(|_| StoreError::Conflict)?;
            return self.store.finish_aux(id, &auxiliary.request, Some(reports)).await;
        }
        if !claimed {
            if auxiliary.status == "IN_PROGRESS" { return Ok(session); }
            return Err(StoreError::Conflict);
        }
        let driver = self.clone(); let request = auxiliary.request.clone();
        tokio::spawn(async move {
            let result = tokio::time::timeout(Duration::from_secs(1810), async {
                driver.all(&request, "prepare").await?; driver.all(&request, "start").await?;
                loop {
                    let reports = driver.all(&request, "report").await?;
                    if reports.iter().all(|r| r.status == AUX_READY) {
                        verify_aux_receipts(&request, &reports)?; return Ok::<_, anyhow::Error>(reports);
                    }
                    ensure!(reports.iter().all(|r| r.status == "IN_PROGRESS" || r.status == AUX_READY), "auxiliary interrupted");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }).await;
            if let Ok(Ok(reports)) = result {
                if driver.store.finish_aux(id, &request, Some(reports)).await.is_ok() { return; }
            }
            // Every party receives best-effort abort even when another one is offline.
            for party in PARTIES {
                if let Ok(body) = serde_json::to_vec(&request) {
                    let _ = driver.peers.request(party, "POST", "/internal/v1/cggmp/aux/abort", body).await;
                }
            }
            let _ = driver.store.finish_aux(id, &request, None).await;
        });
        Ok(session)
    }
}
async fn execute(State(driver): State<Arc<Driver>>, Path(id): Path<Uuid>) -> Result<Json<DkgSession>, (StatusCode, Json<serde_json::Value>)> {
    driver.execute(id, false).await.map(Json).map_err(response)
}
async fn reconcile(State(driver): State<Arc<Driver>>, Path(id): Path<Uuid>) -> Result<Json<DkgSession>, (StatusCode, Json<serde_json::Value>)> {
    driver.execute(id, true).await.map(Json).map_err(response)
}
pub(super) fn router(store: Arc<DurableStore>, peers: SignerClient) -> Router {
    Router::new().route("/v1/dkg-sessions/{id}/auxiliary/execute", post(execute))
        .route("/v1/dkg-sessions/{id}/auxiliary/reconcile", post(reconcile))
        .with_state(Arc::new(Driver { store, peers }))
}
