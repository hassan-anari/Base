//! Authenticated public-only signing dispatch. Never substitutes a new crypto execution.
use super::*;
use std::time::Duration;
use wallet_mpc_protocol::cggmp::{verified_signature, SignReport, SigningExecution, AUX_READY};
use wallet_mpc_transport::SignerClient;
fn execution(
    session: &SignSession,
    dkg: &DkgSession,
    selected: Vec<String>,
) -> anyhow::Result<SigningExecution> {
    let auxiliary = dkg
        .auxiliary
        .as_ref()
        .context("auxiliary material missing")?;
    auxiliary.validate(dkg)?;
    ensure!(
        auxiliary.status == AUX_READY && auxiliary.internally_signable,
        "auxiliary generation incomplete"
    );
    let binding = SigningExecution {
        request: session.request.clone(),
        crypto_execution_id: session.crypto_execution_id,
        selected_signers: selected,
        auxiliary: auxiliary.request.clone(),
    };
    binding.validate()?;
    Ok(binding)
}
pub(super) fn validate_completed(session: &SignSession, dkg: &DkgSession) -> anyhow::Result<()> {
    let binding = execution(session, dkg, session.selected_signers.clone())?;
    let result = session
        .signature
        .as_ref()
        .context("missing completed signature")?;
    let bytes = decode_hex(
        result
            .get("signature_hex")
            .and_then(serde_json::Value::as_str)
            .context("missing signature encoding")?,
    )
    .context("invalid signature")?;
    ensure!(
        verified_signature(&binding, &bytes)? == *result,
        "invalid completed signature metadata"
    );
    Ok(())
}
async fn control(
    peers: &SignerClient,
    binding: &SigningExecution,
    party: &str,
    action: &str,
) -> anyhow::Result<SignReport> {
    let bytes = peers
        .request(
            party,
            "POST",
            &format!("/internal/v1/cggmp/sign/{action}"),
            serde_json::to_vec(binding)?,
        )
        .await?;
    let report: SignReport = serde_json::from_slice(&bytes)?;
    ensure!(
        report.execution == *binding && report.party_id == party,
        "invalid authenticated signing receipt"
    );
    Ok(report)
}
async fn completed(
    peers: &SignerClient,
    binding: &SigningExecution,
) -> anyhow::Result<Option<serde_json::Value>> {
    let mut signature = None;
    for party in &binding.selected_signers {
        let report = control(peers, binding, party, "report").await?;
        if report.status != "COMPLETED" {
            ensure!(report.status == "IN_PROGRESS", "signing interrupted");
            return Ok(None);
        }
        let value = report.signature.context("missing signer completion")?;
        let bytes = decode_hex(
            value
                .get("signature_hex")
                .and_then(serde_json::Value::as_str)
                .context("missing signature")?,
        )
        .context("invalid signature")?;
        ensure!(
            verified_signature(binding, &bytes)? == value,
            "invalid signer signature"
        );
        if let Some(previous) = &signature {
            ensure!(*previous == value, "signer completion disagreement");
        }
        signature = Some(value);
    }
    Ok(signature)
}
pub(super) async fn execute(
    store: Arc<DurableStore>,
    peers: SignerClient,
    session: SignSession,
    reconcile: bool,
) -> Result<SignSession, StoreError> {
    if session.status == SessionStatus::Completed {
        return Ok(session);
    }
    let id = session.request.session_id;
    let dkg = store
        .get_keyset(session.request.keyset_id)
        .await?
        .ok_or(StoreError::Invalid)?;
    // Validation before any probe or state advancement; core-only keys cannot sign.
    execution(&session, &dkg, vec!["signer-a".into(), "signer-b".into()])
        .map_err(|_| StoreError::Invalid)?;
    if reconcile {
        if session.status != SessionStatus::ReconciliationRequired {
            return Err(StoreError::Conflict);
        }
        let binding = execution(&session, &dkg, session.selected_signers.clone())
            .map_err(|_| StoreError::Conflict)?;
        let signature = completed(&peers, &binding)
            .await
            .map_err(|_| StoreError::Conflict)?
            .ok_or(StoreError::Conflict)?;
        return store
            .advance_sign(
                id,
                SessionStatus::ReconciliationRequired,
                SessionStatus::Completed,
                None,
                Some(signature),
            )
            .await;
    }
    if matches!(
        session.status,
        SessionStatus::Starting | SessionStatus::InProgress
    ) {
        return Ok(session);
    }
    if session.status != SessionStatus::Created {
        return Err(StoreError::Conflict);
    }
    let claimed = match store
        .advance_sign(
            id,
            SessionStatus::Created,
            SessionStatus::Starting,
            None,
            None,
        )
        .await
    {
        Ok(claimed) => claimed,
        Err(StoreError::Conflict) => return store.get_sign(id).await?.ok_or(StoreError::Invalid),
        Err(error) => return Err(error),
    };
    tokio::spawn(async move {
        let result = tokio::time::timeout(Duration::from_secs(200), async {
            let mut eligible = vec![];
            for party in PARTIES {
                let other = PARTIES
                    .into_iter()
                    .find(|p| *p != party)
                    .context("missing other party")?;
                let mut pair = vec![party.to_owned(), other.to_owned()];
                pair.sort();
                let probe = execution(&session, &dkg, pair)?;
                if control(&peers, &probe, party, "probe")
                    .await
                    .is_ok_and(|r| r.status == "ELIGIBLE" && r.signature.is_none())
                {
                    eligible.push(party.to_owned());
                }
            }
            ensure!(eligible.len() >= 2, "insufficient auxiliary-ready quorum");
            eligible.truncate(2);
            let binding = execution(&session, &dkg, eligible.clone())?;
            store
                .advance_sign(
                    id,
                    SessionStatus::Starting,
                    SessionStatus::Starting,
                    Some(eligible),
                    None,
                )
                .await
                .map_err(|_| anyhow::anyhow!("selection persistence uncertain"))?;
            store
                .advance_sign(
                    id,
                    SessionStatus::Starting,
                    SessionStatus::InProgress,
                    None,
                    None,
                )
                .await
                .map_err(|_| anyhow::anyhow!("execution persistence uncertain"))?;
            for action in ["prepare", "start"] {
                for party in &binding.selected_signers {
                    let report = control(&peers, &binding, party, action).await?;
                    ensure!(
                        report.status
                            == if action == "prepare" {
                                "PREPARED"
                            } else {
                                "IN_PROGRESS"
                            },
                        "unexpected signing state"
                    );
                }
            }
            loop {
                if let Some(signature) = completed(&peers, &binding).await? {
                    store
                        .advance_sign(
                            id,
                            SessionStatus::InProgress,
                            SessionStatus::Completed,
                            None,
                            Some(signature),
                        )
                        .await
                        .map_err(|_| anyhow::anyhow!("completion persistence uncertain"))?;
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        if matches!(result, Ok(Ok(()))) {
            return;
        }
        if let Ok(Some(current)) = store.get_sign(id).await {
            if current.status == SessionStatus::Completed {
                return;
            }
            if matches!(
                current.status,
                SessionStatus::Starting | SessionStatus::InProgress
            ) {
                let _ = store
                    .advance_sign(
                        id,
                        current.status.clone(),
                        SessionStatus::ReconciliationRequired,
                        None,
                        None,
                    )
                    .await;
            }
            if let Ok(binding) = execution(&current, &dkg, current.selected_signers.clone()) {
                for party in &binding.selected_signers {
                    let _ = control(&peers, &binding, party, "abort").await;
                }
            }
        }
    });
    Ok(claimed)
}
