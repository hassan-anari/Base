//! Public aggregation only. Durable advancement claims executions before network I/O.
use super::*;
use frost_ed25519 as frost;
use wallet_mpc_protocol::{
    dkg::identifier,
    sign::{public_package, SignControl, SignReport, SigningExecution},
};
use wallet_mpc_transport::SignerClient;

impl DurableStore {
    pub(super) async fn signing_evidence(
        &self,
        request: &SignRequest,
    ) -> Result<DkgSession, StoreError> {
        let dkg = self
            .get_keyset(request.keyset_id)
            .await?
            .ok_or(StoreError::Invalid)?;
        let group = dkg.group_public_key.as_deref().ok_or(StoreError::Invalid)?;
        if dkg.status != SessionStatus::Completed
            || !dkg::unanimous(&dkg.request, &dkg.participant_agreement)
            || dkg.participant_agreement[0].group_public_key.as_deref() != Some(group)
            || (dkg.request.scope == "TON") != (request.payload_type == "TON_V5R1_CELL_HASH")
            || request.frost_message(group).is_err()
        {
            return Err(StoreError::Invalid);
        }
        Ok(dkg)
    }
    pub(super) async fn advance_sign(
        &self,
        id: Uuid,
        expected: SessionStatus,
        status: SessionStatus,
        selected: Option<Vec<String>>,
        signature: Option<serde_json::Value>,
    ) -> Result<SignSession, StoreError> {
        self.confirm_durability(OperationKey::Sign(id)).await?;
        let mut data = self.data.lock().await;
        let previous = data.signing.get(&id).cloned().ok_or(StoreError::Invalid)?;
        if previous.status != expected || previous.status == SessionStatus::Completed {
            return Err(StoreError::Conflict);
        }
        let valid = matches!(
            (&expected, &status),
            (SessionStatus::Created, SessionStatus::Starting)
                | (SessionStatus::Starting, SessionStatus::Starting)
                | (SessionStatus::Starting, SessionStatus::InProgress)
                | (
                    SessionStatus::Starting | SessionStatus::InProgress,
                    SessionStatus::ReconciliationRequired
                )
                | (
                    SessionStatus::InProgress | SessionStatus::ReconciliationRequired,
                    SessionStatus::Completed
                )
        );
        if !valid {
            return Err(StoreError::Invalid);
        }
        let mut session = previous.clone();
        session.status = status;
        if let Some(selected) = selected {
            if !previous.selected_signers.is_empty() && previous.selected_signers != selected {
                return Err(StoreError::Conflict);
            }
            session.selected_signers = selected;
        }
        session.signature = signature;
        session.error_code = (session.status == SessionStatus::ReconciliationRequired)
            .then(|| "SIGNING_UNCERTAIN".into());
        if session.status == SessionStatus::Completed && session.signature.is_none() {
            return Err(StoreError::Invalid);
        }
        if session.status == SessionStatus::Completed {
            let dkg = data
                .dkg
                .values()
                .find(|d| d.request.keyset_id == session.request.keyset_id)
                .ok_or(StoreError::Invalid)?;
            validate_completed(&session, dkg).map_err(|_| StoreError::Invalid)?;
        }
        data.signing.insert(id, session.clone());
        match self.persist(&data).await {
            Ok(()) => Ok(session),
            Err(PersistError::PreCommit) => {
                data.signing.insert(id, previous);
                Err(StoreError::Storage)
            }
            Err(PersistError::PostRenameDurabilityUncertain) => {
                self.durability_uncertain
                    .lock()
                    .await
                    .insert(OperationKey::Sign(id));
                Err(StoreError::DurabilityUncertain)
            }
        }
    }
}

fn execution(
    session: &SignSession,
    dkg: &DkgSession,
    selected: Vec<String>,
) -> Result<SigningExecution, StoreError> {
    let binding = SigningExecution {
        request: session.request.clone(),
        crypto_execution_id: session.crypto_execution_id,
        selected_signers: selected,
        dkg: dkg.request.clone(),
        group_public_key: dkg.group_public_key.clone().ok_or(StoreError::Invalid)?,
        public_key_package: dkg::verified_public(&dkg.request, &dkg.participant_agreement)
            .map_err(|_| StoreError::Invalid)?
            .serialize()
            .map_err(|_| StoreError::Invalid)?,
    };
    binding.validate().map_err(|_| StoreError::Invalid)?;
    Ok(binding)
}

pub(super) fn validate_completed(session: &SignSession, dkg: &DkgSession) -> anyhow::Result<()> {
    if session.request.algorithm == wallet_mpc_protocol::cggmp::ALGORITHM {
        return super::cggmp_sign::validate_completed(session, dkg);
    }
    ensure!(dkg.status == SessionStatus::Completed, "incomplete keyset");
    let binding = execution(session, dkg, session.selected_signers.clone())
        .map_err(|_| anyhow::anyhow!("invalid completion binding"))?;
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
    .context("invalid signature encoding")?;
    ensure!(
        verified_result(&binding, &bytes)? == *result,
        "completed metadata mismatch"
    );
    Ok(())
}

fn verified_result(binding: &SigningExecution, bytes: &[u8]) -> anyhow::Result<serde_json::Value> {
    ensure!(bytes.len() == 64, "invalid Ed25519 signature length");
    let public = public_package(&binding.public_key_package, &binding.group_public_key)?;
    let signature = frost::Signature::deserialize(bytes)?;
    public
        .verifying_key()
        .verify(&binding.validate()?, &signature)?;
    ensure!(
        signature.serialize()? == bytes,
        "non-canonical Ed25519 encoding"
    );
    Ok(
        serde_json::json!({"logical_session_id":binding.request.session_id,"crypto_execution_id":binding.crypto_execution_id,
        "keyset_id":binding.request.keyset_id,"selected_signers":binding.selected_signers,"algorithm":binding.request.algorithm,
        "payload_fingerprint":binding.request.message_fingerprint,"signature_hex":wallet_mpc_protocol::dkg::hex(bytes),"verified":true}),
    )
}
struct Driver {
    store: Arc<DurableStore>,
    peers: SignerClient,
}
impl Driver {
    async fn control(
        &self,
        execution: &SigningExecution,
        party: &str,
        action: &str,
        round: u16,
        signing_package: Option<Vec<u8>>,
    ) -> anyhow::Result<SignReport> {
        let control = SignControl {
            execution: execution.clone(),
            sender: "coordinator".into(),
            recipient: party.into(),
            round,
            signing_package,
        };
        let bytes = self
            .peers
            .request(
                party,
                "POST",
                &format!("/internal/v1/sign/{action}"),
                serde_json::to_vec(&control)?,
            )
            .await?;
        let report: SignReport = serde_json::from_slice(&bytes)?;
        ensure!(
            report.execution == *execution
                && report.sender == party
                && report.recipient == "coordinator",
            "invalid signing response identity"
        );
        if action != "report" && action != "abort" {
            ensure!(report.round == round, "invalid response round");
        }
        Ok(report)
    }
    async fn execute(&self, id: Uuid, reconcile: bool) -> Result<SignSession, StoreError> {
        let session = self.store.get_sign(id).await?.ok_or(StoreError::Invalid)?;
        if session.request.algorithm == wallet_mpc_protocol::cggmp::ALGORITHM {
            return super::cggmp_sign::execute(
                self.store.clone(),
                self.peers.clone(),
                session,
                reconcile,
            )
            .await;
        }
        if session.status == SessionStatus::Completed {
            return Ok(session);
        }
        let dkg = self.store.signing_evidence(&session.request).await?;
        if reconcile {
            if session.status != SessionStatus::ReconciliationRequired {
                return Err(StoreError::Conflict);
            }
            let binding = execution(&session, &dkg, session.selected_signers.clone())?;
            let signature = self
                .recover(&binding)
                .await
                .map_err(|_| StoreError::Conflict)?;
            return self
                .store
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
        // Compare-and-set under the store mutex. Concurrent callers cannot start another execution.
        match self
            .store
            .advance_sign(
                id,
                SessionStatus::Created,
                SessionStatus::Starting,
                None,
                None,
            )
            .await
        {
            Ok(_) => {}
            Err(StoreError::Conflict) => {
                return self.store.get_sign(id).await?.ok_or(StoreError::Invalid)
            }
            Err(e) => return Err(e),
        }
        let outcome = async {
            let mut eligible = vec![];
            for party in PARTIES {
                let other = PARTIES.into_iter().find(|p| *p != party).unwrap();
                let mut pair = vec![party.to_owned(), other.to_owned()];
                pair.sort();
                let probe = execution(&session, &dkg, pair)?;
                if self
                    .control(&probe, party, "probe", 0, None)
                    .await
                    .is_ok_and(|r| {
                        r.status == "ELIGIBLE"
                            && r.commitments.is_none()
                            && r.signature_share.is_none()
                    })
                {
                    eligible.push(party.to_owned());
                }
            }
            if eligible.len() < 2 {
                return Err(StoreError::Conflict);
            }
            eligible.truncate(2);
            let binding = execution(&session, &dkg, eligible.clone())?;
            self.store
                .advance_sign(
                    id,
                    SessionStatus::Starting,
                    SessionStatus::Starting,
                    Some(eligible),
                    None,
                )
                .await?;
            self.store
                .advance_sign(
                    id,
                    SessionStatus::Starting,
                    SessionStatus::InProgress,
                    None,
                    None,
                )
                .await?;
            let signature = self
                .sign(&binding)
                .await
                .map_err(|_| StoreError::Conflict)?;
            self.store
                .advance_sign(
                    id,
                    SessionStatus::InProgress,
                    SessionStatus::Completed,
                    None,
                    Some(signature),
                )
                .await
        }
        .await;
        match outcome {
            Ok(completed) => Ok(completed),
            Err(error) => {
                let current = self.store.get_sign(id).await?.ok_or(StoreError::Invalid)?;
                if current.status == SessionStatus::Completed {
                    return Ok(current);
                }
                if matches!(
                    current.status,
                    SessionStatus::Starting | SessionStatus::InProgress
                ) {
                    self.store
                        .advance_sign(
                            id,
                            current.status.clone(),
                            SessionStatus::ReconciliationRequired,
                            None,
                            None,
                        )
                        .await?;
                }
                // Public reconciliation can still recover persisted shares. No new rounds are issued.
                if let Ok(binding) = execution(&current, &dkg, current.selected_signers.clone()) {
                    for party in &binding.selected_signers {
                        let _ = self.control(&binding, party, "abort", 0, None).await;
                    }
                }
                Err(error)
            }
        }
    }
    async fn sign(&self, binding: &SigningExecution) -> anyhow::Result<serde_json::Value> {
        let mut commitments = BTreeMap::new();
        for party in &binding.selected_signers {
            let report = self.control(binding, party, "round1", 1, None).await?;
            ensure!(
                report.status == "NONCES_CREATED" && report.signature_share.is_none(),
                "invalid round1 response"
            );
            commitments.insert(
                identifier(party).unwrap(),
                frost::round1::SigningCommitments::deserialize(
                    report
                        .commitments
                        .as_deref()
                        .context("missing commitments")?,
                )?,
            );
        }
        let package = frost::SigningPackage::new(commitments, &binding.validate()?);
        let bytes = package.serialize()?;
        let mut reports = vec![];
        for party in &binding.selected_signers {
            reports.push(
                self.control(binding, party, "round2", 2, Some(bytes.clone()))
                    .await?,
            );
        }
        aggregate(binding, &reports)
    }
    async fn recover(&self, binding: &SigningExecution) -> anyhow::Result<serde_json::Value> {
        let mut reports = vec![];
        for party in &binding.selected_signers {
            reports.push(self.control(binding, party, "report", 0, None).await?);
        }
        aggregate(binding, &reports)
    }
}

fn aggregate(
    binding: &SigningExecution,
    reports: &[SignReport],
) -> anyhow::Result<serde_json::Value> {
    let message = binding.validate()?;
    ensure!(reports.len() == 2, "two shares required");
    let bytes = reports[0]
        .signing_package
        .as_deref()
        .context("missing signing package")?;
    let package = frost::SigningPackage::deserialize(bytes)?;
    ensure!(
        package.serialize()? == bytes
            && package.message() == &message
            && package.signing_commitments().len() == 2,
        "package/message mismatch"
    );
    let mut shares = BTreeMap::new();
    for (report, party) in reports.iter().zip(&binding.selected_signers) {
        let id = identifier(party).unwrap();
        ensure!(
            report.execution == *binding
                && report.sender == *party
                && report.recipient == "coordinator"
                && report.round == 2
                && report.status == "SHARE_PRODUCED"
                && report.signing_package.as_deref() == Some(bytes)
                && package
                    .signing_commitment(&id)
                    .context("missing signer commitment")?
                    .serialize()?
                    == *report.commitments.as_ref().context("missing commitments")?,
            "invalid signature receipt"
        );
        shares.insert(
            id,
            frost::round2::SignatureShare::deserialize(
                report.signature_share.as_deref().context("missing share")?,
            )?,
        );
    }
    let public = public_package(&binding.public_key_package, &binding.group_public_key)?;
    let signature = frost::aggregate(&package, &shares, &public)?;
    public.verifying_key().verify(&message, &signature)?;
    let signature = signature.serialize()?;
    verified_result(binding, &signature)
}
async fn execute(
    State(driver): State<Arc<Driver>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SignSession>, (StatusCode, Json<serde_json::Value>)> {
    driver.execute(id, false).await.map(Json).map_err(response)
}
async fn reconcile(
    State(driver): State<Arc<Driver>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SignSession>, (StatusCode, Json<serde_json::Value>)> {
    driver.execute(id, true).await.map(Json).map_err(response)
}
pub(super) fn router(store: Arc<DurableStore>, peers: SignerClient) -> Router {
    Router::new()
        .route("/v1/sign-sessions/{id}/execute", post(execute))
        .route("/v1/sign-sessions/{id}/reconcile", post(reconcile))
        .with_state(Arc::new(Driver { store, peers }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn signing_claim_storage_faults_never_allow_an_ambiguous_replacement() {
        for point in [1, 2, 3] {
            let root = std::env::temp_dir().join(format!("signing-claim-{}", Uuid::new_v4()));
            let path = root.join("coordinator/state.json");
            let store = DurableStore::open(&path).unwrap();
            let request: SignRequest = serde_json::from_value(serde_json::json!({
                "session_id":Uuid::new_v4(),"attempt_id":1,"keyset_id":Uuid::new_v4(),
                "algorithm":"CGGMP24_ECDSA","payload_type":"EVM_LEGACY_DIGEST",
                "payload_hex":"ab","message_fingerprint":format!("{:x}", Sha256::digest([0xab])),
                "operation_type":"WITHDRAWAL","chain":"ETH","asset":"ETH","expected_source":"test", "derivation_reference":null
            })).unwrap();
            let created = store.create_sign(request.clone()).await.unwrap();
            store.inject_persist_fault(point);
            assert!(store
                .advance_sign(
                    request.session_id,
                    SessionStatus::Created,
                    SessionStatus::Starting,
                    None,
                    None
                )
                .await
                .is_err());
            store.inject_persist_fault(0);
            let observed = store.get_sign(request.session_id).await.unwrap().unwrap();
            assert_eq!(observed.crypto_execution_id, created.crypto_execution_id);
            assert_eq!(
                observed.status,
                if point == 3 {
                    SessionStatus::Starting
                } else {
                    SessionStatus::Created
                }
            );
            drop(store);
            let recovered = DurableStore::open(&path).unwrap();
            let observed = recovered
                .get_sign(request.session_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(observed.crypto_execution_id, created.crypto_execution_id);
            if point == 3 {
                assert_eq!(observed.status, SessionStatus::ReconciliationRequired);
                assert!(recovered
                    .advance_sign(
                        request.session_id,
                        SessionStatus::Created,
                        SessionStatus::Starting,
                        None,
                        None
                    )
                    .await
                    .is_err());
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}
