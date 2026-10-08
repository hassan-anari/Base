//! Interactive CGGMP signing with durable execution consumption before nonce randomness.
use crate::{
    cggmp_aux::AuxService,
    cggmp_delivery::{protocol_delivery, DeliveryContext},
    ExecutionTombstones, ProtocolEnvelope,
};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use cggmp24::{
    generic_ec::Scalar,
    round_based::{MpcParty, ProtocolMessage},
    signing::PrehashedDataToSign,
    supported_curves::Secp256k1,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};
use uuid::Uuid;
use wallet_mpc_protocol::{
    cggmp::{verified_signature, SignReport, SigningExecution},
    dkg::{hex, PARTIES},
    sign::decode_hex,
};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::{PeerIdentity, SignerClient};

type Msg = cggmp24::signing::msg::Msg<Secp256k1, sha2::Sha256>;
struct Active {
    sender: mpsc::Sender<ProtocolEnvelope>,
    receiver: Option<mpsc::Receiver<ProtocolEnvelope>>,
    seen: BTreeSet<(String, u64)>,
    seen_payload: BTreeSet<(String, u16, String)>,
    task: Option<JoinHandle<()>>,
}
struct Local {
    directory: PathBuf,
    party: String,
    executions: ExecutionTombstones,
    reports: BTreeMap<Uuid, SignReport>,
    active: BTreeMap<Uuid, Active>,
}
pub struct SigningService {
    local: Mutex<Local>,
    auxiliary: Arc<AuxService>,
    peers: SignerClient,
}
impl Local {
    fn path(&self, session: Uuid) -> PathBuf {
        self.directory.join(format!("{session}.json"))
    }
    fn completion_path(&self, session: Uuid) -> PathBuf {
        self.directory.join(format!("{session}.completed"))
    }
    fn consumption_path(&self, execution: Uuid) -> PathBuf {
        self.directory.join(format!("{execution}.consumed"))
    }
    fn save(&self, report: &SignReport) -> Result<()> {
        atomic_replace_state(
            &self.path(report.execution.request.session_id),
            &serde_json::to_vec(report)?,
        )?;
        Ok(())
    }
    fn validate_completion(&self, report: &SignReport) -> Result<()> {
        ensure!(
            report.status == "COMPLETED" && report.party_id == self.party,
            "wrong completion identity"
        );
        let value = report.signature.as_ref().context("missing signature")?;
        let encoded = value
            .get("signature_hex")
            .and_then(serde_json::Value::as_str)
            .context("missing signature encoding")?;
        let bytes = decode_hex(encoded).context("invalid signature encoding")?;
        ensure!(
            verified_signature(&report.execution, &bytes)? == *value,
            "invalid completed result"
        );
        ensure!(
            fs::read(self.consumption_path(report.execution.crypto_execution_id))?
                == serde_json::to_vec(&report.execution)?,
            "missing durable nonce consumption"
        );
        Ok(())
    }
    fn report(&self, execution: &SigningExecution) -> Result<SignReport> {
        let report = self
            .reports
            .get(&execution.request.session_id)
            .context("unknown signing execution")?;
        ensure!(
            report.execution == *execution,
            "conflicting signing execution"
        );
        if report.status == "COMPLETED" {
            self.validate_completion(report)?;
            let immutable: SignReport = serde_json::from_slice(&fs::read(
                self.completion_path(execution.request.session_id),
            )?)?;
            ensure!(immutable == *report, "conflicting immutable completion");
            confirm_parent_durability(&self.completion_path(execution.request.session_id))?;
        }
        Ok(report.clone())
    }
}
impl SigningService {
    pub fn open(
        directory: PathBuf,
        party: String,
        executions: ExecutionTombstones,
        auxiliary: Arc<AuxService>,
        peers: SignerClient,
    ) -> Result<Arc<Self>> {
        let directory = directory.join("cggmp-signing");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let mut local = Local {
            directory,
            party,
            executions,
            reports: BTreeMap::new(),
            active: BTreeMap::new(),
        };
        for entry in fs::read_dir(&local.directory)? {
            let path = entry?.path();
            if path.extension().and_then(|p| p.to_str()) != Some("json") {
                continue;
            }
            let mut report: SignReport = serde_json::from_slice(&fs::read(&path)?)?;
            report.execution.validate()?;
            ensure!(
                path == local.path(report.execution.request.session_id)
                    && report.party_id == local.party
                    && report.execution.selected_signers.contains(&local.party),
                "invalid persisted signing record"
            );
            let completed = local.completion_path(report.execution.request.session_id);
            if completed.exists() {
                let immutable: SignReport = serde_json::from_slice(&fs::read(&completed)?)?;
                ensure!(
                    immutable.execution == report.execution
                        && immutable.party_id == report.party_id,
                    "conflicting signing completion"
                );
                if report.status == "COMPLETED" {
                    ensure!(immutable == report, "conflicting completed record");
                }
                local.validate_completion(&immutable)?;
                report = immutable;
                local.save(&report)?;
            } else {
                ensure!(report.status != "COMPLETED", "lost completed signature");
                report.status = "RECONCILIATION_REQUIRED".into();
                report.signature = None;
                local.save(&report)?;
            }
            ensure!(
                local.reports.values().all(
                    |r| r.execution.crypto_execution_id != report.execution.crypto_execution_id
                ),
                "reused persisted signing execution"
            );
            local
                .reports
                .insert(report.execution.request.session_id, report);
        }
        Ok(Arc::new(Self {
            local: Mutex::new(local),
            auxiliary,
            peers,
        }))
    }
    async fn control(
        self: &Arc<Self>,
        action: &str,
        execution: SigningExecution,
    ) -> Result<SignReport> {
        execution.validate()?;
        let party = { self.local.lock().await.party.clone() };
        ensure!(
            execution.selected_signers.contains(&party),
            "signer not selected"
        );
        if action == "probe" {
            self.auxiliary.own_key(&execution.auxiliary).await?;
            return Ok(SignReport {
                execution,
                party_id: party,
                status: "ELIGIBLE".into(),
                signature: None,
            });
        }
        // Completed retries are entirely public. Other controls reload exact encrypted own material.
        if action != "report" && action != "abort" {
            self.auxiliary.own_key(&execution.auxiliary).await?;
        }
        let mut local = self.local.lock().await;
        let id = execution.request.session_id;
        if action == "prepare" {
            ensure!(
                local.active.len() < 4
                    && !local.reports.contains_key(&id)
                    && local
                        .reports
                        .values()
                        .all(|r| r.execution.crypto_execution_id != execution.crypto_execution_id),
                "signing already reserved or capacity exhausted"
            );
            // The exact pair, digest, logical session and auxiliary binding are reserved
            // durably before cryptographic nonce randomness is allowed.
            local.executions.begin(execution.crypto_execution_id)?;
            let report = SignReport {
                execution,
                party_id: party,
                status: "PREPARED".into(),
                signature: None,
            };
            atomic_create_secret(&local.path(id), &serde_json::to_vec(&report)?)?;
            let (sender, receiver) = mpsc::channel(16);
            local.active.insert(
                id,
                Active {
                    sender,
                    receiver: Some(receiver),
                    seen: BTreeSet::new(),
                    seen_payload: BTreeSet::new(),
                    task: None,
                },
            );
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        let mut report = local.report(&execution)?;
        if action == "report" {
            return Ok(report);
        }
        if action == "abort" {
            if report.status == "COMPLETED" {
                return Ok(report);
            }
            if let Some(active) = local.active.remove(&id) {
                if let Some(task) = active.task {
                    task.abort();
                }
            }
            if local
                .executions
                .require_active(execution.crypto_execution_id)
                .is_ok()
            {
                local.executions.abort(execution.crypto_execution_id)?;
            }
            report.status = "RECONCILIATION_REQUIRED".into();
            local.save(&report)?;
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        ensure!(
            action == "start" && report.status == "PREPARED",
            "signing cannot replay or regenerate nonces"
        );
        local
            .executions
            .require_active(execution.crypto_execution_id)?;
        // Irreversible for this execution even if the following write or RPC is lost.
        // No nonce/presignature is persisted or later replayed.
        atomic_create_secret(
            &local.consumption_path(execution.crypto_execution_id),
            &serde_json::to_vec(&execution)?,
        )?;
        report.status = "IN_PROGRESS".into();
        local.save(&report)?;
        local.reports.insert(id, report.clone());
        let inbox = local
            .active
            .get_mut(&id)
            .context("lost signing inbox")?
            .receiver
            .take()
            .context("already started")?;
        let service = self.clone();
        let task = tokio::spawn(async move {
            service.run(execution, party, inbox).await;
        });
        local
            .active
            .get_mut(&id)
            .context("lost signing state")?
            .task = Some(task);
        Ok(report)
    }
    async fn run(
        self: Arc<Self>,
        execution: SigningExecution,
        party: String,
        inbox: mpsc::Receiver<ProtocolEnvelope>,
    ) {
        let outcome = tokio::time::timeout(Duration::from_secs(180), async {
            let digest = execution.validate()?;
            let key = self.auxiliary.own_key(&execution.auxiliary).await?;
            let index = execution
                .selected_signers
                .iter()
                .position(|p| p == &party)
                .context("unknown selected party")? as u16;
            let original: Vec<u16> = execution
                .selected_signers
                .iter()
                .map(|p| {
                    PARTIES
                        .iter()
                        .position(|s| *s == p.as_str())
                        .map(|i| i as u16)
                        .context("unknown DKG party")
                })
                .collect::<Result<_>>()?;
            let transcript = execution.transcript()?;
            let context = DeliveryContext {
                logical_session_id: execution.request.session_id,
                execution_id: execution.crypto_execution_id,
                keyset_id: execution.request.keyset_id,
                participants: execution.selected_signers.clone(),
                transcript: transcript.clone(),
                message_path: "/internal/v1/cggmp/sign/message".into(),
                message_budget: 256,
            };
            // The pinned upstream full interactive protocol accepts AnyDataToSign.
            // Converting the custody prehash to a scalar does NOT hash it again.
            let message = PrehashedDataToSign::<Secp256k1>::from_scalar(
                Scalar::from_be_bytes_mod_order(digest),
            );
            let signature = cggmp24::signing(
                cggmp24::ExecutionId::new(transcript.as_bytes()),
                index,
                &original,
                &key,
            )
            .sign(
                &mut rand_core::OsRng,
                MpcParty::connected(protocol_delivery::<Msg>(
                    context,
                    party.clone(),
                    self.peers.clone(),
                    inbox,
                )),
                &message,
            )
            .await?
            .normalize_s();
            let mut bytes = [0u8; 64];
            signature.write_to_slice(&mut bytes);
            verified_signature(&execution, &bytes)
        })
        .await;
        let mut local = self.local.lock().await;
        if !local.active.contains_key(&execution.request.session_id) {
            return;
        }
        let persisted = (|| -> Result<()> {
            let signature = outcome.context("signing timeout")??;
            local
                .executions
                .require_active(execution.crypto_execution_id)?;
            let report = SignReport {
                execution: execution.clone(),
                party_id: party,
                status: "COMPLETED".into(),
                signature: Some(signature),
            };
            local.validate_completion(&report)?;
            // Publish a create-once verified public result before marking completion.
            atomic_create_secret(
                &local.completion_path(execution.request.session_id),
                &serde_json::to_vec(&report)?,
            )?;
            local.executions.complete(execution.crypto_execution_id)?;
            local.save(&report)?;
            local.reports.insert(execution.request.session_id, report);
            Ok(())
        })();
        if persisted.is_err() {
            if let Some(mut report) = local.reports.get(&execution.request.session_id).cloned() {
                report.status = "RECONCILIATION_REQUIRED".into();
                report.signature = None;
                let _ = local.save(&report);
                local.reports.insert(execution.request.session_id, report);
            }
            if local
                .executions
                .require_active(execution.crypto_execution_id)
                .is_ok()
            {
                let _ = local.executions.abort(execution.crypto_execution_id);
            }
        }
        local.active.remove(&execution.request.session_id);
    }
    async fn receive(&self, peer: &str, wire: ProtocolEnvelope) -> Result<()> {
        ensure!(
            PARTIES.contains(&peer)
                && wire.sender == peer
                && wire.sequence < 256
                && wire.payload.len() <= 192 * 1024
                && wire.transcript_digest() == wire.payload_digest,
            "invalid signing message"
        );
        let msg: Msg = serde_json::from_slice(&wire.payload)?;
        ensure!(msg.round() == wire.round, "invalid signing round");
        let mut local = self.local.lock().await;
        let report = local
            .reports
            .get(&wire.logical_session_id)
            .context("unknown signing session")?;
        let execution = &report.execution;
        let transcript = execution.transcript()?;
        ensure!(
            wire.recipient == local.party
                && wire.sender != wire.recipient
                && execution.selected_signers.contains(&wire.sender)
                && wire.crypto_execution_id == execution.crypto_execution_id
                && wire.keyset_id == execution.request.keyset_id
                && [
                    format!("{transcript}/broadcast"),
                    format!("{transcript}/p2p")
                ]
                .contains(&wire.protocol)
                && ["PREPARED", "IN_PROGRESS"].contains(&report.status.as_str()),
            "wrong signing message binding"
        );
        local.executions.require_active(wire.crypto_execution_id)?;
        let active = local
            .active
            .get_mut(&wire.logical_session_id)
            .context("lost signing state")?;
        let payload_identity = (peer.into(), wire.round, hex(&Sha256::digest(&wire.payload)));
        ensure!(
            !active.seen.contains(&(peer.into(), wire.sequence))
                && !active.seen_payload.contains(&payload_identity),
            "duplicate signing message"
        );
        active
            .sender
            .try_send(wire.clone())
            .context("full signing inbox")?;
        active.seen.insert((peer.into(), wire.sequence));
        active.seen_payload.insert(payload_identity);
        Ok(())
    }
}
async fn control(
    State(service): State<Arc<SigningService>>,
    Extension(peer): Extension<PeerIdentity>,
    Path(action): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<SignReport>, StatusCode> {
    if peer.role() != "coordinator" {
        return Err(StatusCode::FORBIDDEN);
    }
    let execution = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .control(&action, execution)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
async fn receive(
    State(service): State<Arc<SigningService>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !PARTIES.contains(&peer.role()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let wire = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .receive(peer.role(), wire)
        .await
        .map(|()| Json(serde_json::json!({"accepted":true})))
        .map_err(|_| StatusCode::CONFLICT)
}
pub fn router(service: Arc<SigningService>) -> Router {
    Router::new()
        .route("/internal/v1/cggmp/sign/message", post(receive))
        .route("/internal/v1/cggmp/sign/{action}", post(control))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(service)
}
