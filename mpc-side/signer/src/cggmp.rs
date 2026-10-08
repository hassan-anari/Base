//! A real CGGMP keygen participant. No auxiliary protocol or signing is claimed here.
use crate::{ExecutionTombstones, ProtocolEnvelope, SignerConfig, SignerStore, StoredShare, PROTOCOL_VERSION, SHARE_FORMAT_VERSION};
use anyhow::{ensure, Context, Result};
use axum::{extract::{DefaultBodyLimit, Path, State}, http::StatusCode, routing::post, Extension, Json, Router};
use cggmp24::{key_share::AnyKeyShare, supported_curves::Secp256k1, IncompleteKeyShare};
use cggmp24::round_based::{MpcParty, ProtocolMessage};
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, BTreeSet}, fs, sync::Arc, time::Duration};
use tokio::{sync::{mpsc, Mutex}, task::JoinHandle};
use uuid::Uuid;
use wallet_mpc_protocol::{cggmp::{ALGORITHM, CORE_READY}, dkg::{hex, DkgReport, DkgRequest, PARTIES}};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::{PeerIdentity, SignerClient};
use zeroize::{Zeroize, Zeroizing};

type Msg = cggmp24::keygen::msg::threshold::Msg<Secp256k1, cggmp24::security_level::SecurityLevel128, sha2::Sha256>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreBlob {
    format_version: u16,
    kind: String,
    request: DkgRequest,
    core: Vec<u8>,
}
impl Drop for CoreBlob { fn drop(&mut self) { self.core.zeroize(); } }

struct Active {
    sender: mpsc::Sender<ProtocolEnvelope>,
    receiver: Option<mpsc::Receiver<ProtocolEnvelope>>,
    seen: BTreeSet<(String, u64)>,
    rounds: BTreeSet<(String, u16)>,
    task: Option<JoinHandle<()>>,
}
struct Local {
    store: SignerStore,
    executions: ExecutionTombstones,
    reports: BTreeMap<Uuid, DkgReport>,
    active: BTreeMap<Uuid, Active>,
}
pub struct CggmpService { local: Mutex<Local>, peers: SignerClient }

fn public_report(request: &DkgRequest, party: &str, core: &IncompleteKeyShare<Secp256k1>) -> Result<DkgReport> {
    let index = PARTIES.iter().position(|p| *p == party).context("unknown party")?;
    ensure!(usize::from(core.i) == index && core.min_signers() == 2 && core.n() == 3, "invalid core identity");
    let public: Vec<String> = core.public_shares.iter().map(|p| hex(p.to_bytes(true).as_ref())).collect();
    Ok(DkgReport { request: request.clone(), party_id: party.into(), status: CORE_READY.into(),
        share_format_version: SHARE_FORMAT_VERSION, group_public_key: Some(hex(core.shared_public_key().to_bytes(true).as_ref())),
        public_key_package: Some(serde_json::to_vec(&public)?), verification_share: Some(core.public_shares[index].to_bytes(true).as_ref().to_vec()), durable: true })
}
impl Local {
    fn path(&self, keyset: Uuid) -> std::path::PathBuf { self.store.config.storage_directory.join("cggmp-keygen").join(format!("{keyset}.json")) }
    fn save(&self, report: &DkgReport) -> Result<()> { atomic_replace_state(&self.path(report.request.keyset_id), &serde_json::to_vec(report)?)?; Ok(()) }
    fn core_report(&self, request: &DkgRequest) -> Result<DkgReport> {
        let stored = self.store.load(request.keyset_id, ALGORITHM)?;
        let blob: CoreBlob = serde_json::from_slice(&stored.protocol_share)?;
        ensure!(blob.format_version == 1 && blob.kind == "CGGMP24_CORE_V1" && blob.request == *request, "wrong keygen material binding");
        let core: IncompleteKeyShare<Secp256k1> = serde_json::from_slice(&blob.core)?;
        public_report(request, &self.store.config.party_id, &core)
    }
    fn report(&self, request: &DkgRequest) -> Result<DkgReport> {
        let report = self.reports.get(&request.keyset_id).context("unknown keygen")?;
        ensure!(report.request == *request, "conflicting keygen identity");
        if report.status == CORE_READY {
            ensure!(*report == self.core_report(request)?, "encrypted core/report mismatch");
            confirm_parent_durability(&self.store.path(request.keyset_id))?;
            confirm_parent_durability(&self.path(request.keyset_id))?;
        }
        Ok(report.clone())
    }
}
impl CggmpService {
    pub fn open(config: SignerConfig, executions: ExecutionTombstones, peers: SignerClient) -> Result<Arc<Self>> {
        for party in PARTIES.into_iter().chain(["coordinator"]) {
            ensure!(config.trusted_peers.get(&format!("spiffe://wallet-mpc/{party}")) == Some(&party.to_owned()), "exact CGGMP peer mapping required");
        }
        let store = SignerStore::open(config)?;
        let directory = store.config.storage_directory.join("cggmp-keygen");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let mut local = Local { store, executions, reports: BTreeMap::new(), active: BTreeMap::new() };
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().and_then(|p| p.to_str()) != Some("json") { continue; }
            let mut report: DkgReport = serde_json::from_slice(&fs::read(&path)?)?;
            ensure!(report.request.is_cggmp() && report.party_id == local.store.config.party_id && path == local.path(report.request.keyset_id), "invalid keygen record");
            if report.status != CORE_READY {
                report.status = "RECONCILIATION_REQUIRED".into();
                report.durable = false;
                local.save(&report)?;
            } else {
                ensure!(report == local.core_report(&report.request)?, "corrupt persisted CGGMP core");
            }
            ensure!(local.reports.values().all(|r| r.request.session_id != report.request.session_id && r.request.execution_id != report.request.execution_id), "duplicate stored keygen identity");
            local.reports.insert(report.request.keyset_id, report);
        }
        Ok(Arc::new(Self { local: Mutex::new(local), peers }))
    }
    async fn control(self: &Arc<Self>, action: &str, request: DkgRequest) -> Result<DkgReport> {
        ensure!(request.is_cggmp(), "invalid CGGMP context");
        let mut local = self.local.lock().await;
        ensure!(local.store.config.supported_algorithms.iter().any(|a| a == ALGORITHM), "algorithm unavailable");
        let id = request.keyset_id;
        if action == "prepare" {
            ensure!(!local.reports.contains_key(&id) && !local.store.share_present(id)
                && local.reports.values().all(|r| r.request.session_id != request.session_id && r.request.execution_id != request.execution_id), "keygen already reserved");
            ensure!(local.active.len() < 8, "keygen capacity exhausted");
            // Tombstone precedes all cryptographic randomness; uncertain writes fail closed.
            local.executions.begin(request.execution_id)?;
            let report = DkgReport { request, party_id: local.store.config.party_id.clone(), status: "PREPARED".into(),
                share_format_version: SHARE_FORMAT_VERSION, group_public_key: None, public_key_package: None, verification_share: None, durable: false };
            atomic_create_secret(&local.path(id), &serde_json::to_vec(&report)?)?;
            let (sender, receiver) = mpsc::channel(32);
            local.active.insert(id, Active { sender, receiver: Some(receiver), seen: BTreeSet::new(), rounds: BTreeSet::new(), task: None });
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        let mut report = local.report(&request)?;
        if action == "report" { return Ok(report); }
        if action == "abort" {
            if report.status == CORE_READY { return Ok(report); }
            if let Some(active) = local.active.remove(&id) { if let Some(task) = active.task { task.abort(); } }
            if local.executions.require_active(request.execution_id).is_ok() { local.executions.abort(request.execution_id)?; }
            report.status = "RECONCILIATION_REQUIRED".into();
            local.save(&report)?;
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        ensure!(action == "start" && report.status == "PREPARED", "keygen cannot restart or replay");
        local.executions.require_active(request.execution_id)?;
        let inbox = local.active.get_mut(&id).context("lost keygen state")?.receiver.take().context("keygen already started")?;
        report.status = "IN_PROGRESS".into();
        local.save(&report)?;
        local.reports.insert(id, report.clone());
        let service = self.clone();
        let party = local.store.config.party_id.clone();
        let task = tokio::spawn(async move { service.run(request, party, inbox).await; });
        local.active.get_mut(&id).context("lost state")?.task = Some(task);
        Ok(report)
    }
    async fn run(self: Arc<Self>, request: DkgRequest, party: String, inbox: mpsc::Receiver<ProtocolEnvelope>) {
        let outcome = async {
            let index = PARTIES.iter().position(|p| *p == party).context("unknown party")? as u16;
            let transcript = request.cggmp_transcript()?;
            let eid = cggmp24::ExecutionId::new(transcript.as_bytes());
            let delivery = super::cggmp_delivery::delivery::<Msg>(request.clone(), party.clone(), self.peers.clone(), inbox);
            let core = cggmp24::keygen::<Secp256k1>(eid, index, 3).set_threshold(2)
                .start(&mut rand_core::OsRng, MpcParty::connected(delivery)).await?;
            let report = public_report(&request, &party, &core)?;
            let core_bytes = Zeroizing::new(serde_json::to_vec(&core)?);
            let blob = CoreBlob { format_version: 1, kind: "CGGMP24_CORE_V1".into(), request: request.clone(), core: core_bytes.to_vec() };
            let serialized = Zeroizing::new(serde_json::to_vec(&blob)?);
            Ok::<_, anyhow::Error>((report, StoredShare { format_version: 1, protocol_version: PROTOCOL_VERSION.into(), algorithm: ALGORITHM.into(), keyset_id: request.keyset_id, party_id: party, protocol_share: serialized.to_vec() }))
        };
        let outcome = tokio::time::timeout(Duration::from_secs(120), outcome).await;
        let mut local = self.local.lock().await;
        if !local.active.contains_key(&request.keyset_id) { return; }
        let persisted = (|| -> Result<()> {
            let (report, stored) = outcome.context("keygen timeout")??;
            local.executions.require_active(request.execution_id)?;
            local.store.persist(&stored)?;
            ensure!(local.core_report(&request)? == report, "invalid persisted core");
            local.executions.complete(request.execution_id)?;
            local.save(&report)?;
            local.reports.insert(request.keyset_id, report);
            Ok(())
        })();
        if persisted.is_err() {
            // No details or protocol data are logged, including upstream error Debug values.
            if let Some(mut report) = local.reports.get(&request.keyset_id).cloned() {
                report.status = "RECONCILIATION_REQUIRED".into();
                report.durable = false;
                let _ = local.save(&report);
                local.reports.insert(request.keyset_id, report);
            }
            if local.executions.require_active(request.execution_id).is_ok() { let _ = local.executions.abort(request.execution_id); }
        }
        local.active.remove(&request.keyset_id);
    }
    async fn receive(&self, peer: &str, mut wire: ProtocolEnvelope) -> Result<()> {
        let result = self.receive_inner(peer, &wire).await;
        wire.payload.zeroize();
        result
    }
    async fn receive_inner(&self, peer: &str, wire: &ProtocolEnvelope) -> Result<()> {
        ensure!(PARTIES.contains(&peer) && wire.sender == peer && wire.sequence < 64 && wire.payload.len() <= 48 * 1024, "invalid message source/budget");
        let msg: Msg = serde_json::from_slice(&wire.payload)?;
        ensure!(msg.round() == wire.round && wire.transcript_digest() == wire.payload_digest, "invalid protocol transcript");
        let mut local = self.local.lock().await;
        let report = local.reports.get(&wire.keyset_id).context("unknown keygen")?;
        let request = &report.request;
        let transcript = request.cggmp_transcript()?;
        ensure!(wire.recipient == local.store.config.party_id && wire.sender != wire.recipient
            && wire.logical_session_id == request.session_id && wire.crypto_execution_id == request.execution_id
            && [format!("{transcript}/broadcast"), format!("{transcript}/p2p")].contains(&wire.protocol)
            && ["PREPARED", "IN_PROGRESS"].contains(&report.status.as_str()), "wrong keygen message binding");
        local.executions.require_active(wire.crypto_execution_id)?;
        let active = local.active.get_mut(&wire.keyset_id).context("lost keygen state")?;
        ensure!(!active.seen.contains(&(peer.into(), wire.sequence)) && !active.rounds.contains(&(peer.into(), wire.round)), "replayed/conflicting protocol message");
        active.sender.try_send(wire.clone()).context("full or closed keygen inbox")?;
        active.seen.insert((peer.into(), wire.sequence));
        active.rounds.insert((peer.into(), wire.round));
        Ok(())
    }
}
async fn control(State(service): State<Arc<CggmpService>>, Extension(peer): Extension<PeerIdentity>, Path(action): Path<String>, body: axum::body::Bytes) -> Result<Json<DkgReport>, StatusCode> {
    if peer.role() != "coordinator" { return Err(StatusCode::FORBIDDEN); }
    let request = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service.control(&action, request).await.map(Json).map_err(|_| StatusCode::CONFLICT)
}
async fn receive(State(service): State<Arc<CggmpService>>, Extension(peer): Extension<PeerIdentity>, body: axum::body::Bytes) -> Result<Json<serde_json::Value>, StatusCode> {
    if !PARTIES.contains(&peer.role()) { return Err(StatusCode::FORBIDDEN); }
    let wire = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service.receive(peer.role(), wire).await.map(|()| Json(serde_json::json!({"accepted":true}))).map_err(|_| StatusCode::CONFLICT)
}
pub fn router(service: Arc<CggmpService>) -> Router {
    Router::new().route("/internal/v1/cggmp/keygen/message", post(receive))
        .route("/internal/v1/cggmp/keygen/{action}", post(control))
        .layer(DefaultBodyLimit::max(64 * 1024)).with_state(service)
}
