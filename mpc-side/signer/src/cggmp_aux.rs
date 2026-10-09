//! Local auxiliary generation and create-once encryption. Only public receipts leave a signer.
use crate::{
    cggmp::{public_report, CoreBlob},
    cggmp_delivery::{protocol_delivery, DeliveryContext},
    ExecutionTombstones, ProtocolEnvelope, SignerConfig, SignerStore, StoredShare,
    PROTOCOL_VERSION,
};
use anyhow::{ensure, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::post,
    Extension, Json, Router,
};
use cggmp24::{
    key_share::{AnyKeyShare, AuxInfo},
    round_based::{MpcParty, ProtocolMessage},
    supported_curves::Secp256k1,
    IncompleteKeyShare, KeyShare, PregeneratedPrimes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
use uuid::Uuid;
use wallet_mpc_protocol::{
    cggmp::{AuxReport, AuxRequest, ALGORITHM, AUX_READY},
    dkg::{hex, PARTIES},
};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::{PeerIdentity, SignerClient};
use zeroize::{Zeroize, Zeroizing};

type Msg = cggmp24::key_refresh::msg::Msg<sha2::Sha256, cggmp24::security_level::SecurityLevel128>;
const TIMEOUT: Duration = Duration::from_secs(1800);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuxBlob {
    format_version: u16,
    protocol_version: String,
    kind: String,
    party_id: String,
    request: AuxRequest,
    prime_generation_ms: u64,
    aux: Vec<u8>,
}
impl Drop for AuxBlob {
    fn drop(&mut self) {
        self.aux.zeroize();
    }
}
struct Active {
    sender: mpsc::Sender<ProtocolEnvelope>,
    receiver: Option<mpsc::Receiver<ProtocolEnvelope>>,
    seen: BTreeSet<(String, u64)>,
    seen_payload: BTreeSet<(String, u16, String)>,
    task: Option<JoinHandle<()>>,
    prime_permit: Option<OwnedSemaphorePermit>,
}
struct Local {
    core_store: SignerStore,
    aux_store: SignerStore,
    executions: ExecutionTombstones,
    reports: BTreeMap<Uuid, AuxReport>,
    active: BTreeMap<Uuid, Active>,
}
pub struct AuxService {
    local: Mutex<Local>,
    peers: SignerClient,
    prime_slots: Arc<Semaphore>,
}

/// Reload exactly this signer's encrypted core. Never collect another party's core.
fn own_core(store: &SignerStore, request: &AuxRequest) -> Result<IncompleteKeyShare<Secp256k1>> {
    request.validate()?;
    let stored = store.load(request.dkg.keyset_id, ALGORITHM)?;
    let blob: CoreBlob = serde_json::from_slice(&stored.protocol_share)?;
    ensure!(
        blob.format_version == 1 && blob.kind == "CGGMP24_CORE_V1" && blob.request == request.dkg,
        "wrong core generation"
    );
    let core: IncompleteKeyShare<Secp256k1> = serde_json::from_slice(&blob.core)?;
    let report = public_report(&request.dkg, &store.config.party_id, &core)?;
    ensure!(
        report.group_public_key.as_deref() == Some(&request.group_public_key)
            && report.public_key_package.as_deref() == Some(request.public_key_package.as_slice()),
        "wrong auxiliary/core public binding"
    );
    Ok(core)
}
fn fingerprint(aux: &AuxInfo) -> Result<String> {
    // CRT precomputation, primes and secret values are deliberately excluded.
    let public: Vec<_> = aux
        .pedersen_params
        .iter()
        .map(|p| (&p.hat_N, &p.s, &p.t))
        .collect();
    Ok(hex(&Sha256::digest(serde_json::to_vec(&(&aux.N, public))?)))
}
impl Local {
    fn path(&self, keyset: Uuid) -> std::path::PathBuf {
        self.core_store
            .config
            .storage_directory
            .join("cggmp-aux-records")
            .join(format!("{keyset}.json"))
    }
    fn save(&self, report: &AuxReport) -> Result<()> {
        atomic_replace_state(
            &self.path(report.request.dkg.keyset_id),
            &serde_json::to_vec(report)?,
        )?;
        Ok(())
    }
    fn key(&self, request: &AuxRequest) -> Result<(KeyShare<Secp256k1>, u64)> {
        let core = own_core(&self.core_store, request)?;
        let stored = self.aux_store.load(request.dkg.keyset_id, ALGORITHM)?;
        let blob: AuxBlob = serde_json::from_slice(&stored.protocol_share)?;
        ensure!(
            blob.format_version == 1
                && blob.protocol_version == PROTOCOL_VERSION
                && blob.kind == "CGGMP24_AUX_V1"
                && blob.request == *request
                && blob.party_id == self.core_store.config.party_id,
            "wrong auxiliary artifact binding"
        );
        let aux: AuxInfo = serde_json::from_slice(&blob.aux)?;
        // Upstream consistency validation binds p*q to this core's ORIGINAL index.
        ensure!(
            aux.N.len() == 3 && aux.pedersen_params.len() == 3,
            "invalid auxiliary topology"
        );
        let key = KeyShare::from_parts((core, aux))
            .map_err(|_| anyhow::anyhow!("invalid own combined key"))?;
        ensure!(
            key.min_signers() == 2
                && key.n() == 3
                && hex(key.shared_public_key().to_bytes(true).as_ref()) == request.group_public_key,
            "wrong combined public key"
        );
        Ok((key, blob.prime_generation_ms))
    }
    fn ready_report(&self, request: &AuxRequest) -> Result<AuxReport> {
        let (key, prime_generation_ms) = self.key(request)?;
        // Validated key shares expose auxiliary information through AsRef.
        let aux = &key.aux;
        let public: Vec<_> = aux
            .pedersen_params
            .iter()
            .map(|p| (&p.hat_N, &p.s, &p.t))
            .collect();
        let public_parameters_fingerprint =
            hex(&Sha256::digest(serde_json::to_vec(&(&aux.N, public))?));
        Ok(AuxReport {
            request: request.clone(),
            party_id: self.core_store.config.party_id.clone(),
            status: AUX_READY.into(),
            artifact_format_version: 1,
            durable: true,
            public_parameters_fingerprint: Some(public_parameters_fingerprint),
            prime_generation_ms: Some(prime_generation_ms),
        })
    }
    fn report(&self, request: &AuxRequest) -> Result<AuxReport> {
        let report = self
            .reports
            .get(&request.dkg.keyset_id)
            .context("unknown auxiliary execution")?;
        ensure!(
            report.request == *request,
            "conflicting auxiliary execution"
        );
        if report.status == AUX_READY {
            ensure!(
                *report == self.ready_report(request)?,
                "auxiliary artifact/receipt mismatch"
            );
            confirm_parent_durability(&self.aux_store.path(request.dkg.keyset_id))?;
            confirm_parent_durability(&self.path(request.dkg.keyset_id))?;
        }
        Ok(report.clone())
    }
}
impl AuxService {
    pub fn open(
        config: SignerConfig,
        executions: ExecutionTombstones,
        peers: SignerClient,
    ) -> Result<Arc<Self>> {
        let core_store = SignerStore::open(config.clone())?;
        let mut aux_config = config;
        aux_config.storage_directory = aux_config.storage_directory.join("cggmp-aux");
        fs::create_dir_all(&aux_config.storage_directory)?;
        confirm_parent_durability(&aux_config.storage_directory)?;
        let aux_store = SignerStore::open(aux_config)?;
        let directory = core_store
            .config
            .storage_directory
            .join("cggmp-aux-records");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let mut local = Local {
            core_store,
            aux_store,
            executions,
            reports: BTreeMap::new(),
            active: BTreeMap::new(),
        };
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().and_then(|p| p.to_str()) != Some("json") {
                continue;
            }
            let mut report: AuxReport = serde_json::from_slice(&fs::read(&path)?)?;
            report.request.validate()?;
            ensure!(
                path == local.path(report.request.dkg.keyset_id)
                    && report.party_id == local.core_store.config.party_id,
                "invalid auxiliary record"
            );
            own_core(&local.core_store, &report.request)?;
            if report.status == AUX_READY {
                ensure!(
                    report == local.ready_report(&report.request)?,
                    "corrupt persisted auxiliary artifact"
                );
            } else {
                report.status = "RECONCILIATION_REQUIRED".into();
                report.durable = false;
                local.save(&report)?;
            }
            ensure!(
                local
                    .reports
                    .values()
                    .all(|r| r.request.execution_id != report.request.execution_id),
                "duplicate auxiliary execution"
            );
            local.reports.insert(report.request.dkg.keyset_id, report);
        }
        Ok(Arc::new(Self {
            local: Mutex::new(local),
            peers,
            prime_slots: Arc::new(Semaphore::new(1)),
        }))
    }
    /// Signing can only load the exact, durably validated own-key combination.
    pub async fn own_key(&self, request: &AuxRequest) -> Result<KeyShare<Secp256k1>> {
        let local = self.local.lock().await;
        ensure!(
            local.report(request)?.status == AUX_READY,
            "auxiliary material unavailable"
        );
        Ok(local.key(request)?.0)
    }
    async fn control(self: &Arc<Self>, action: &str, request: AuxRequest) -> Result<AuxReport> {
        request.validate()?;
        let mut local = self.local.lock().await;
        let id = request.dkg.keyset_id;
        own_core(&local.core_store, &request)?;
        if action == "prepare" {
            ensure!(
                !local.reports.contains_key(&id)
                    && !local.aux_store.share_present(id)
                    && local
                        .reports
                        .values()
                        .all(|r| r.request.execution_id != request.execution_id),
                "auxiliary material already reserved"
            );
            // One expensive safe-prime job per process; no unbounded blocking pool.
            ensure!(local.active.is_empty(), "auxiliary capacity exhausted");
            let prime_permit = self
                .prime_slots
                .clone()
                .try_acquire_owned()
                .context("safe-prime worker busy")?;
            local.executions.begin(request.execution_id)?;
            let report = AuxReport {
                request,
                party_id: local.core_store.config.party_id.clone(),
                status: "PREPARED".into(),
                artifact_format_version: 1,
                durable: false,
                public_parameters_fingerprint: None,
                prime_generation_ms: None,
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
                    prime_permit: Some(prime_permit),
                },
            );
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        let mut report = local.report(&request)?;
        if action == "report" {
            return Ok(report);
        }
        if action == "reconcile" {
            if report.status == AUX_READY {
                return Ok(report);
            }
            ensure!(
                report.status == "RECONCILIATION_REQUIRED" && !local.active.contains_key(&id),
                "auxiliary work is not quiescent"
            );
            report = local.ready_report(&request)?;
            confirm_parent_durability(&local.aux_store.path(id))?;
            local.save(&report)?;
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        if action == "abort" {
            if report.status == AUX_READY {
                return Ok(report);
            }
            if let Some(active) = local.active.remove(&id) {
                if let Some(task) = active.task {
                    task.abort();
                }
            }
            if local
                .executions
                .require_active(request.execution_id)
                .is_ok()
            {
                local.executions.abort(request.execution_id)?;
            }
            report.status = "RECONCILIATION_REQUIRED".into();
            report.durable = false;
            local.save(&report)?;
            local.reports.insert(id, report.clone());
            return Ok(report);
        }
        ensure!(
            action == "start" && report.status == "PREPARED",
            "auxiliary execution cannot restart"
        );
        local.executions.require_active(request.execution_id)?;
        let inbox = local
            .active
            .get_mut(&id)
            .context("lost auxiliary state")?
            .receiver
            .take()
            .context("auxiliary already started")?;
        let prime_permit = local
            .active
            .get_mut(&id)
            .context("lost auxiliary state")?
            .prime_permit
            .take()
            .context("lost prime capacity")?;
        report.status = "IN_PROGRESS".into();
        local.save(&report)?;
        local.reports.insert(id, report.clone());
        let service = self.clone();
        let party = local.core_store.config.party_id.clone();
        let task = tokio::spawn(async move {
            service.run(request, party, inbox, prime_permit).await;
        });
        local
            .active
            .get_mut(&id)
            .context("lost auxiliary state")?
            .task = Some(task);
        Ok(report)
    }
    async fn run(
        self: Arc<Self>,
        request: AuxRequest,
        party: String,
        inbox: mpsc::Receiver<ProtocolEnvelope>,
        prime_permit: OwnedSemaphorePermit,
    ) {
        let result = tokio::time::timeout(TIMEOUT, async {
            // No fixtures, cached primes or other signers' primes enter the service.
            let started = Instant::now();
            let (primes, prime_permit) = tokio::task::spawn_blocking(move || {
                // Aborting the async task cannot kill a blocking prime calculation.
                // Its capacity permit stays here until the calculation actually ends.
                let primes =
                    PregeneratedPrimes::<cggmp24::security_level::SecurityLevel128>::generate(
                        &mut rand_core::OsRng,
                    );
                (primes, prime_permit)
            })
            .await?;
            let prime_generation_ms = u64::try_from(started.elapsed().as_millis())?;
            {
                let mut local = self.local.lock().await;
                let mut report = local
                    .reports
                    .get(&request.dkg.keyset_id)
                    .context("lost auxiliary report")?
                    .clone();
                report.prime_generation_ms = Some(prime_generation_ms);
                local.save(&report)?;
                local.reports.insert(request.dkg.keyset_id, report);
            }
            eprintln!("CGGMP auxiliary fresh primes generated: milliseconds={prime_generation_ms}");
            let index = PARTIES
                .iter()
                .position(|p| *p == party)
                .context("unknown party")? as u16;
            let transcript = request.transcript()?;
            let context = DeliveryContext {
                logical_session_id: request.dkg.session_id,
                execution_id: request.execution_id,
                keyset_id: request.dkg.keyset_id,
                participants: request.dkg.participants.clone(),
                transcript: transcript.clone(),
                message_path: "/internal/v1/cggmp/aux/message".into(),
                message_budget: 256,
            };
            let peers = self.peers.clone();
            let worker_party = party.clone();
            let aux = tokio::task::spawn_blocking(move || {
                let _permit = prime_permit;
                tokio::runtime::Handle::current().block_on(async move {
                    tokio::time::timeout(TIMEOUT, async move {
                        cggmp24::aux_info_gen(
                            cggmp24::ExecutionId::new(transcript.as_bytes()),
                            index,
                            3,
                            primes,
                        )
                        .start(
                            &mut rand_core::OsRng,
                            MpcParty::connected(protocol_delivery::<Msg>(
                                context,
                                worker_party,
                                peers,
                                inbox,
                            )),
                        )
                        .await
                    })
                    .await
                    .context("auxiliary proof timeout")?
                    .map_err(anyhow::Error::from)
                })
            })
            .await??;
            let _public_fingerprint = fingerprint(&aux)?;
            let blob = AuxBlob {
                format_version: 1,
                protocol_version: PROTOCOL_VERSION.into(),
                kind: "CGGMP24_AUX_V1".into(),
                party_id: party.clone(),
                request: request.clone(),
                prime_generation_ms,
                aux: serde_json::to_vec(&aux)?,
            };
            let serialized = Zeroizing::new(serde_json::to_vec(&blob)?);
            Ok::<_, anyhow::Error>(StoredShare {
                format_version: 1,
                protocol_version: PROTOCOL_VERSION.into(),
                algorithm: ALGORITHM.into(),
                keyset_id: request.dkg.keyset_id,
                party_id: party,
                protocol_share: serialized.to_vec(),
            })
        })
        .await;
        let mut local = self.local.lock().await;
        if !local.active.contains_key(&request.dkg.keyset_id) {
            return;
        }
        let persisted = (|| -> Result<()> {
            let stored = result.context("auxiliary timeout")??;
            local.executions.require_active(request.execution_id)?;
            local.aux_store.persist(&stored)?;
            let report = local.ready_report(&request)?;
            local.executions.complete(request.execution_id)?;
            local.save(&report)?;
            local.reports.insert(request.dkg.keyset_id, report);
            Ok(())
        })();
        if persisted.is_err() {
            if let Some(mut report) = local.reports.get(&request.dkg.keyset_id).cloned() {
                report.status = "RECONCILIATION_REQUIRED".into();
                report.durable = false;
                let _ = local.save(&report);
                local.reports.insert(request.dkg.keyset_id, report);
            }
            if local
                .executions
                .require_active(request.execution_id)
                .is_ok()
            {
                let _ = local.executions.abort(request.execution_id);
            }
        }
        local.active.remove(&request.dkg.keyset_id);
    }
    async fn receive(&self, peer: &str, wire: ProtocolEnvelope) -> Result<()> {
        ensure!(
            PARTIES.contains(&peer)
                && wire.sender == peer
                && wire.sequence < 256
                && wire.payload.len() <= super::cggmp_wire::PAYLOAD_LIMIT
                && wire.transcript_digest() == wire.payload_digest,
            "invalid auxiliary message"
        );
        let msg: Msg = serde_json::from_slice(&wire.payload)?;
        ensure!(msg.round() == wire.round, "invalid auxiliary round");
        let mut local = self.local.lock().await;
        let report = local
            .reports
            .get(&wire.keyset_id)
            .context("unknown auxiliary keyset")?;
        let request = &report.request;
        let transcript = request.transcript()?;
        ensure!(
            wire.recipient == local.core_store.config.party_id
                && wire.sender != wire.recipient
                && wire.logical_session_id == request.dkg.session_id
                && wire.crypto_execution_id == request.execution_id
                && [
                    format!("{transcript}/broadcast"),
                    format!("{transcript}/p2p")
                ]
                .contains(&wire.protocol)
                && ["PREPARED", "IN_PROGRESS"].contains(&report.status.as_str()),
            "wrong auxiliary message binding"
        );
        local.executions.require_active(wire.crypto_execution_id)?;
        let active = local
            .active
            .get_mut(&wire.keyset_id)
            .context("lost auxiliary inbox")?;
        // Upstream may send distinct messages in the SAME round. Sequence, not round,
        // is the unique delivery identity; both exact and conflicting duplicates fail.
        let payload_identity = (peer.into(), wire.round, hex(&Sha256::digest(&wire.payload)));
        ensure!(
            !active.seen.contains(&(peer.into(), wire.sequence))
                && !active.seen_payload.contains(&payload_identity),
            "duplicate auxiliary message"
        );
        active
            .sender
            .try_send(wire.clone())
            .context("full auxiliary inbox")?;
        active.seen.insert((peer.into(), wire.sequence));
        active.seen_payload.insert(payload_identity);
        Ok(())
    }
}
async fn control(
    State(service): State<Arc<AuxService>>,
    Extension(peer): Extension<PeerIdentity>,
    Path(action): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<AuxReport>, StatusCode> {
    if peer.role() != "coordinator" {
        return Err(StatusCode::FORBIDDEN);
    }
    let request = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    service
        .control(&action, request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}
async fn receive(
    State(service): State<Arc<AuxService>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !PARTIES.contains(&peer.role()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let wire = super::cggmp_wire::decode(&body).map_err(|_| {
        eprintln!(
            "CGGMP proof rejected: phase=cggmp_aux category=wire_encoding http_bytes={}",
            body.len()
        );
        StatusCode::BAD_REQUEST
    })?;
    service
        .receive(peer.role(), wire)
        .await
        .map(|()| Json(serde_json::json!({"accepted":true})))
        .map_err(|_| {
            eprintln!("CGGMP proof rejected: phase=cggmp_aux category=peer_queue_or_validation");
            StatusCode::CONFLICT
        })
}
pub fn router(service: Arc<AuxService>) -> Router {
    Router::new()
        .route("/internal/v1/cggmp/aux/message", post(receive))
        .route("/internal/v1/cggmp/aux/{action}", post(control))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(service)
}
