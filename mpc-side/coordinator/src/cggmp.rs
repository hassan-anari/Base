//! Asynchronous coordinator dispatch; only authenticated public receipts cross this boundary.
use super::*;
use std::time::Duration;
use wallet_mpc_protocol::cggmp::{verify_keygen_receipts, CORE_READY};
use wallet_mpc_transport::SignerClient;

pub(super) async fn execute(store: Arc<DurableStore>, peers: SignerClient, session: DkgSession, reconcile: bool) -> Result<DkgSession, StoreError> {
    let request = &session.request;
    if session.status == SessionStatus::KeygenCompleted {
        verify_keygen_receipts(request, &session.participant_agreement).map_err(|_| StoreError::Invalid)?;
        return Ok(session);
    }
    if reconcile {
        if session.status != SessionStatus::ReconciliationRequired { return Err(StoreError::Conflict); }
        let reports = all(&peers, request, "report").await.map_err(|_| StoreError::Conflict)?;
        return store.update_dkg(request.session_id, SessionStatus::KeygenCompleted, reports).await;
    }
    if matches!(session.status, SessionStatus::Starting | SessionStatus::InProgress) { return Ok(session); }
    if session.status != SessionStatus::Created { return Err(StoreError::Conflict); }
    let claimed = match store.update_dkg(request.session_id, SessionStatus::InProgress, vec![]).await {
        Ok(session) => session,
        Err(StoreError::Conflict) => return store.get_dkg(request.session_id).await?.ok_or(StoreError::Invalid),
        Err(error) => return Err(error),
    };
    let request = request.clone();
    tokio::spawn(async move {
        let result = tokio::time::timeout(Duration::from_secs(125), async {
            all(&peers, &request, "prepare").await?;
            all(&peers, &request, "start").await?;
            loop {
                let reports = all(&peers, &request, "report").await?;
                if reports.iter().all(|r| r.status == CORE_READY) {
                    verify_keygen_receipts(&request, &reports)?;
                    return Ok::<_, anyhow::Error>(reports);
                }
                ensure!(reports.iter().all(|r| r.status == "IN_PROGRESS" || r.status == CORE_READY), "keygen interrupted");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await;
        if let Ok(Ok(reports)) = result {
            if store.update_dkg(request.session_id, SessionStatus::KeygenCompleted, reports).await.is_ok() { return; }
        }
        let _ = all(&peers, &request, "abort").await;
        let _ = store.update_dkg(request.session_id, SessionStatus::ReconciliationRequired, vec![]).await;
    });
    Ok(claimed)
}
async fn all(peers: &SignerClient, request: &DkgRequest, action: &str) -> anyhow::Result<Vec<DkgReport>> {
    let mut reports = vec![];
    for party in PARTIES {
        let bytes = peers.request(party, "POST", &format!("/internal/v1/cggmp/keygen/{action}"), serde_json::to_vec(request)?).await?;
        let report: DkgReport = serde_json::from_slice(&bytes)?;
        ensure!(report.request == *request && report.party_id == party, "invalid CGGMP receipt identity");
        reports.push(report);
    }
    Ok(reports)
}
