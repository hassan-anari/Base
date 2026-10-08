//! Coordinator only drives public controls and records unanimous durable receipts.
use super::*;
use wallet_mpc_transport::SignerClient;

impl DurableStore {
    pub(super) async fn update_dkg(
        &self,
        id: Uuid,
        status: SessionStatus,
        agreement: Vec<DkgReport>,
    ) -> Result<DkgSession, StoreError> {
        self.confirm_durability(OperationKey::Dkg(id)).await?;
        let mut data = self.data.lock().await;
        let previous = data.dkg.get(&id).cloned().ok_or(StoreError::Invalid)?;
        if status == SessionStatus::Completed && !unanimous(&previous.request, &agreement) {
            return Err(StoreError::Invalid);
        }
        if status == SessionStatus::InProgress && previous.status != SessionStatus::Created {
            return Err(StoreError::Conflict);
        }
        if status == SessionStatus::KeygenCompleted
            && wallet_mpc_protocol::cggmp::verify_keygen_receipts(&previous.request, &agreement).is_err() {
            return Err(StoreError::Invalid);
        }
        if previous.status == SessionStatus::KeygenCompleted {
            return Err(StoreError::Conflict);
        }
        let mut session = previous.clone();
        session.status = status;
        session.participant_agreement = agreement;
        if matches!(session.status, SessionStatus::Completed | SessionStatus::KeygenCompleted) {
            session.group_public_key = session.participant_agreement[0].group_public_key.clone();
            session.result_fingerprint = Some(format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(&(&session.request, &session.participant_agreement))
                        .map_err(|_| StoreError::Storage)?
                )
            ));
        }
        data.dkg.insert(id, session.clone());
        match self.persist(&data).await {
            Ok(()) => Ok(session),
            Err(PersistError::PreCommit) => {
                data.dkg.insert(id, previous);
                Err(StoreError::Storage)
            }
            Err(PersistError::PostRenameDurabilityUncertain) => {
                self.durability_uncertain
                    .lock()
                    .await
                    .insert(OperationKey::Dkg(id));
                Err(StoreError::DurabilityUncertain)
            }
        }
    }
}

pub(super) fn verified_public(
    request: &DkgRequest,
    reports: &[DkgReport],
) -> anyhow::Result<frost_ed25519::keys::PublicKeyPackage> {
    use frost_ed25519 as frost;
    ensure!(
        request.is_frost() && reports.len() == 3,
        "incomplete DKG receipts"
    );
    let group = reports[0]
        .group_public_key
        .as_deref()
        .context("missing group key")?;
    let mut shares = BTreeMap::new();
    for (report, party) in reports.iter().zip(PARTIES) {
        ensure!(
            report.request == *request
                && report.party_id == party
                && report.status == "COMPLETED"
                && report.durable
                && report.share_format_version == 1
                && report.group_public_key.as_deref() == Some(group)
                && report.public_key_package == reports[0].public_key_package,
            "invalid DKG agreement"
        );
        shares.insert(
            wallet_mpc_protocol::dkg::identifier(party).unwrap(),
            frost::keys::VerifyingShare::deserialize(
                report
                    .verification_share
                    .as_deref()
                    .context("missing verification share")?,
            )?,
        );
    }
    // Legacy Phase 6C.1 packages can recover PUBLIC material from each authenticated
    // signer's own verification share. No private share is sent or combined.
    let public = frost::keys::PublicKeyPackage::new(
        shares,
        frost::VerifyingKey::deserialize(&decode_hex(group).context("invalid public key")?)?,
        Some(2),
    );
    let bytes = public.serialize()?;
    wallet_mpc_protocol::sign::public_package(&bytes, group)?;
    if let Some(recorded) = &reports[0].public_key_package {
        ensure!(*recorded == bytes, "public DKG metadata mismatch");
    }
    Ok(public)
}
pub(super) fn unanimous(request: &DkgRequest, reports: &[DkgReport]) -> bool {
    verified_public(request, reports).is_ok()
}

struct Driver {
    store: Arc<DurableStore>,
    peers: SignerClient,
    serial: Mutex<()>,
}
impl Driver {
    async fn all(&self, request: &DkgRequest, action: &str) -> anyhow::Result<Vec<DkgReport>> {
        let mut receipts = vec![];
        for party in PARTIES {
            let bytes = self
                .peers
                .request(
                    party,
                    "POST",
                    &format!("/internal/v1/dkg/{action}"),
                    serde_json::to_vec(request)?,
                )
                .await?;
            let receipt: DkgReport = serde_json::from_slice(&bytes)?;
            ensure!(
                receipt.request == *request && receipt.party_id == party,
                "invalid public receipt"
            );
            receipts.push(receipt);
        }
        Ok(receipts)
    }
    async fn execute(&self, id: Uuid, reconcile: bool) -> Result<DkgSession, StoreError> {
        let session = self.store.get_dkg(id).await?.ok_or(StoreError::Invalid)?;
        if session.request.is_cggmp() {
            return super::cggmp::execute(self.store.clone(), self.peers.clone(), session, reconcile).await;
        }
        let _serial = self.serial.lock().await;
        let session = self.store.get_dkg(id).await?.ok_or(StoreError::Invalid)?;
        if !session.request.is_frost() {
            return Err(StoreError::Invalid);
        }
        if session.status == SessionStatus::Completed || reconcile {
            let receipts = self
                .all(&session.request, "report")
                .await
                .map_err(|_| StoreError::Conflict)?;
            if !unanimous(&session.request, &receipts) {
                return Err(StoreError::Conflict);
            }
            if session.status == SessionStatus::Completed {
                if receipts != session.participant_agreement {
                    if session
                        .participant_agreement
                        .iter()
                        .all(|r| r.verification_share.is_none())
                        && receipts
                            .iter()
                            .all(|r| r.group_public_key == session.group_public_key)
                    {
                        return self
                            .store
                            .update_dkg(id, SessionStatus::Completed, receipts)
                            .await;
                    }
                    return Err(StoreError::Conflict);
                }
                return Ok(session);
            }
            return self
                .store
                .update_dkg(id, SessionStatus::Completed, receipts)
                .await;
        }
        if session.status != SessionStatus::Created {
            return Err(StoreError::Conflict);
        }
        self.store
            .update_dkg(id, SessionStatus::InProgress, vec![])
            .await?;
        let outcome = async {
            for action in ["start", "round1", "round2"] {
                self.all(&session.request, action).await?;
            }
            let receipts = self.all(&session.request, "finalize").await?;
            ensure!(
                unanimous(&session.request, &receipts),
                "DKG result disagreement"
            );
            Ok::<_, anyhow::Error>(receipts)
        }
        .await;
        match outcome {
            Ok(receipts) => {
                self.store
                    .update_dkg(id, SessionStatus::Completed, receipts)
                    .await
            }
            Err(_) => {
                for party in PARTIES {
                    let _ = self
                        .peers
                        .request(
                            party,
                            "POST",
                            "/internal/v1/dkg/abort",
                            serde_json::to_vec(&session.request)
                                .map_err(|_| StoreError::Storage)?,
                        )
                        .await;
                }
                self.store
                    .update_dkg(id, SessionStatus::ReconciliationRequired, vec![])
                    .await?;
                Err(StoreError::Conflict)
            }
        }
    }
}

async fn execute(
    State(driver): State<Arc<Driver>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DkgSession>, (StatusCode, Json<serde_json::Value>)> {
    driver.execute(id, false).await.map(Json).map_err(response)
}
async fn reconcile(
    State(driver): State<Arc<Driver>>,
    Path(id): Path<Uuid>,
) -> Result<Json<DkgSession>, (StatusCode, Json<serde_json::Value>)> {
    driver.execute(id, true).await.map(Json).map_err(response)
}

pub(super) fn router(store: Arc<DurableStore>, peers: SignerClient) -> Router {
    Router::new()
        .route("/v1/dkg-sessions/{id}/execute", post(execute))
        .route("/v1/dkg-sessions/{id}/reconcile", post(reconcile))
        .with_state(Arc::new(Driver {
            store,
            peers,
            serial: Mutex::new(()),
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> DkgRequest {
        DkgRequest {
            session_id: Uuid::new_v4(),
            execution_id: Uuid::new_v4(),
            keyset_id: Uuid::new_v4(),
            algorithm: "FROST_ED25519".into(),
            curve: "ed25519".into(),
            scope: "SOLANA".into(),
            derivation_version: "frost_keyset_v1".into(),
            threshold: 2,
            party_count: 3,
            participants: PARTIES.into_iter().map(str::to_owned).collect(),
        }
    }

    #[tokio::test]
    async fn incomplete_or_disagreeing_receipts_cannot_commit_completion() {
        let root = std::env::temp_dir().join(format!("dkg-agreement-{}", Uuid::new_v4()));
        let path = root.join("coordinator").join("state.json");
        let store = DurableStore::open(&path).unwrap();
        let request = binding();
        store.create_dkg(request.clone()).await.unwrap();
        store
            .update_dkg(request.session_id, SessionStatus::InProgress, vec![])
            .await
            .unwrap();
        let reports: Vec<_> = PARTIES
            .into_iter()
            .map(|party| DkgReport {
                request: request.clone(),
                party_id: party.into(),
                status: "COMPLETED".into(),
                share_format_version: 1,
                group_public_key: Some("ab".repeat(32)),
                public_key_package: None,
                verification_share: None,
                durable: true,
            })
            .collect();
        let mut invalid = vec![reports[..2].to_vec()];
        for field in 0..6 {
            let mut changed = reports.clone();
            match field {
                0 => changed[2].durable = false,
                1 => changed[2].status = "IN_PROGRESS".into(),
                2 => changed[2].group_public_key = Some("cd".repeat(32)),
                3 => changed[2].request.execution_id = Uuid::new_v4(),
                4 => changed[2].party_id = "signer-a".into(),
                5 => changed[2].share_format_version = 2,
                _ => unreachable!(),
            }
            invalid.push(changed);
        }
        for rejected in invalid {
            assert!(matches!(
                store
                    .update_dkg(request.session_id, SessionStatus::Completed, rejected)
                    .await,
                Err(StoreError::Invalid)
            ));
            assert_eq!(
                store
                    .get_dkg(request.session_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                SessionStatus::InProgress
            );
        }
        drop(store);
        let reopened = DurableStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .get_dkg(request.session_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SessionStatus::ReconciliationRequired
        );
        assert!(reopened
            .get_dkg(request.session_id)
            .await
            .unwrap()
            .unwrap()
            .group_public_key
            .is_none());
        fs::remove_dir_all(root).unwrap();
    }
}
