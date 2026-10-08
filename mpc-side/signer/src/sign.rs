//! Nonces and private packages stay in this signer. Only public reports are durable.
use crate::{dkg::DkgService, ExecutionTombstones};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::post,
    Extension, Json, Router,
};
use frost_ed25519 as frost;
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;
use wallet_mpc_protocol::{
    dkg::identifier,
    sign::{SignControl, SignReport},
};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::PeerIdentity;

struct Active {
    key: frost::keys::KeyPackage,
    nonces: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
}
struct Local {
    reports: BTreeMap<Uuid, SignReport>,
    active: BTreeMap<Uuid, Active>,
}
pub struct SigningService {
    dkg: Arc<DkgService>,
    executions: ExecutionTombstones,
    directory: PathBuf,
    party: String,
    local: Mutex<Local>,
}
impl SigningService {
    pub fn open(
        dkg: Arc<DkgService>,
        executions: ExecutionTombstones,
        storage: PathBuf,
        party: String,
    ) -> Result<Arc<Self>> {
        let directory = storage.join("signing");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let service = Self {
            dkg,
            executions,
            directory,
            party,
            local: Mutex::new(Local {
                reports: BTreeMap::new(),
                active: BTreeMap::new(),
            }),
        };
        let mut local = Local {
            reports: BTreeMap::new(),
            active: BTreeMap::new(),
        };
        for entry in fs::read_dir(&service.directory)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let mut report: SignReport = serde_json::from_slice(&fs::read(&path)?)?;
            report.execution.validate()?;
            ensure!(
                report.sender == service.party
                    && report.recipient == "coordinator"
                    && report.execution.selected_signers.contains(&service.party)
                    && path == service.path(report.execution.crypto_execution_id),
                "invalid signing record"
            );
            if report.status != "SHARE_PRODUCED" {
                report.status = "RECONCILIATION_REQUIRED".into();
                service.save(&report)?;
            }
            local
                .reports
                .insert(report.execution.crypto_execution_id, report);
        }
        Ok(Arc::new(Self {
            local: Mutex::new(local),
            ..service
        }))
    }
    fn path(&self, id: Uuid) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }
    fn save(&self, report: &SignReport) -> Result<()> {
        atomic_replace_state(
            &self.path(report.execution.crypto_execution_id),
            &serde_json::to_vec(report)?,
        )?;
        Ok(())
    }
    async fn control(&self, action: &str, control: SignControl) -> Result<SignReport> {
        let message = control.execution.validate()?;
        ensure!(
            control.sender == "coordinator"
                && control.recipient == self.party
                && control.execution.selected_signers.contains(&self.party),
            "wrong signing identity"
        );
        let expected_round = match action {
            "probe" | "report" | "abort" => 0,
            "round1" => 1,
            "round2" => 2,
            _ => anyhow::bail!("unknown action"),
        };
        ensure!(
            control.round == expected_round
                && (action == "round2" || control.signing_package.is_none()),
            "wrong signing round"
        );
        let key = self.dkg.signing_key(&control.execution).await?;
        let id = control.execution.crypto_execution_id;
        let mut local = self.local.lock().await;
        let fresh_report = || SignReport {
            execution: control.execution.clone(),
            sender: self.party.clone(),
            recipient: "coordinator".into(),
            round: expected_round,
            status: "ELIGIBLE".into(),
            commitments: None,
            signature_share: None,
            signing_package: None,
        };
        if action == "probe" {
            return Ok(fresh_report());
        }
        if action == "round1" {
            ensure!(
                !local.reports.contains_key(&id)
                    && !local
                        .reports
                        .values()
                        .any(|r| r.execution.request.session_id
                            == control.execution.request.session_id),
                "execution/session already reserved"
            );
            ensure!(
                local.active.len() < 32,
                "too many active signing executions"
            );
            self.executions.begin(id)?;
            let mut report = fresh_report();
            report.status = "RESERVED".into();
            atomic_create_secret(&self.path(id), &serde_json::to_vec(&report)?)?;
            local.reports.insert(id, report.clone());
            let (nonces, commitments) =
                frost::round1::commit(key.signing_share(), &mut rand_core::OsRng);
            report.status = "NONCES_CREATED".into();
            report.commitments = Some(commitments.serialize()?);
            local.active.insert(
                id,
                Active {
                    key,
                    nonces,
                    commitments,
                },
            );
            self.save(&report)?;
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        let mut report = local.reports.get(&id).context("unknown execution")?.clone();
        ensure!(
            report.execution == control.execution,
            "execution binding mismatch"
        );
        if action == "report" {
            confirm_parent_durability(&self.path(id))?;
            return Ok(report);
        }
        if action == "abort" {
            if report.status != "SHARE_PRODUCED" {
                local.active.remove(&id);
                if self.executions.require_active(id).is_ok() {
                    self.executions.abort(id)?;
                }
                report.status = "RECONCILIATION_REQUIRED".into();
                self.save(&report)?;
                local.reports.insert(id, report.clone());
            }
            return Ok(report);
        }
        ensure!(
            report.status == "NONCES_CREATED",
            "round already consumed or lost state"
        );
        self.executions.require_active(id)?;
        let bytes = control
            .signing_package
            .context("signing package required")?;
        let package = frost::SigningPackage::deserialize(&bytes)?;
        let active = local.active.get(&id).context("lost nonce state")?;
        ensure!(
            package.serialize()? == bytes
                && package.message() == &message
                && package.signing_commitments().len() == 2
                && control.execution.selected_signers.iter().all(|p| package
                    .signing_commitments()
                    .contains_key(&identifier(p).unwrap()))
                && package.signing_commitment(active.key.identifier()) == Some(active.commitments),
            "signing package mismatch"
        );
        // Consume both durable and ephemeral state BEFORE calling upstream sign.
        // Any interruption from here is ambiguous; round2 can never be replayed.
        let active = local.active.remove(&id).context("nonce consumed")?;
        self.executions.complete(id)?;
        report.status = "RECONCILIATION_REQUIRED".into();
        report.round = 2;
        report.signing_package = Some(bytes);
        self.save(&report)?;
        local.reports.insert(id, report.clone());
        let share = frost::round2::sign(&package, &active.nonces, &active.key)?;
        report.signature_share = Some(share.serialize());
        report.status = "SHARE_PRODUCED".into();
        self.save(&report)?;
        local.reports.insert(id, report.clone());
        Ok(report)
    }
}

async fn coordinator_only(
    Extension(peer): Extension<PeerIdentity>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if peer.role() != "coordinator" {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}
async fn control(
    State(service): State<Arc<SigningService>>,
    Path(action): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<SignReport>, (StatusCode, Json<serde_json::Value>)> {
    let rejected = |_| {
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error":"signing rejected"})),
        )
    };
    let control =
        serde_json::from_slice(&body).map_err(|_| rejected(anyhow::anyhow!("invalid control")))?;
    service
        .control(&action, control)
        .await
        .map(Json)
        .map_err(rejected)
}
pub fn router(service: Arc<SigningService>) -> Router {
    Router::new()
        .route("/internal/v1/sign/{action}", post(control))
        .route_layer(middleware::from_fn(coordinator_only))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(service)
}
