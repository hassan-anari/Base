//! Each instance owns one party's ephemeral FROST state and encrypted key package.
//! Controls return only public receipts. Round packages travel directly between peers.
use crate::{
    EnvelopeGuard, ExecutionTombstones, ProtocolEnvelope, SignerStore, StoredShare,
    PROTOCOL_VERSION, SHARE_FORMAT_VERSION,
};
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, sync::Arc};
use tokio::sync::Mutex;
use wallet_mpc_protocol::dkg::{hex, identifier, DkgReport, DkgRequest, ALGORITHM, PARTIES};
use wallet_mpc_storage::{atomic_create_secret, atomic_replace_state, confirm_parent_durability};
use wallet_mpc_transport::{PeerIdentity, SignerClient};
use zeroize::{Zeroize, Zeroizing};

struct Active {
    round1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    round1_public: frost::keys::dkg::round1::Package,
    round1_received: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    round2_secret: Option<frost::keys::dkg::round2::SecretPackage>,
    round2_received: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    round1_sent: bool,
    round2_sent: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round2Wire {
    round1_view: String,
    package: Vec<u8>,
}
impl Drop for Round2Wire {
    fn drop(&mut self) {
        self.package.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBlob {
    format_version: u16,
    request: DkgRequest,
    key_package: Vec<u8>,
    #[serde(default)]
    public_key_package: Option<Vec<u8>>,
}
impl Drop for KeyBlob {
    fn drop(&mut self) {
        self.key_package.zeroize();
    }
}

struct Local {
    store: SignerStore,
    executions: ExecutionTombstones,
    reports: BTreeMap<uuid::Uuid, DkgReport>,
    active: BTreeMap<uuid::Uuid, Active>,
}

pub struct DkgService {
    local: Mutex<Local>,
    peers: SignerClient,
    guard: EnvelopeGuard,
}

impl Local {
    fn record_path(&self, keyset: uuid::Uuid) -> std::path::PathBuf {
        self.store
            .config
            .storage_directory
            .join("dkg")
            .join(format!("{keyset}.json"))
    }
    fn save(&self, report: &DkgReport) -> Result<()> {
        atomic_replace_state(
            &self.record_path(report.request.keyset_id),
            &serde_json::to_vec(report)?,
        )?;
        Ok(())
    }
    fn loaded_key(
        &self,
        request: &DkgRequest,
    ) -> Result<(frost::keys::KeyPackage, Option<Vec<u8>>)> {
        let share = self.store.load(request.keyset_id, ALGORITHM)?;
        let blob: KeyBlob = serde_json::from_slice(&share.protocol_share)?;
        ensure!(
            blob.format_version == SHARE_FORMAT_VERSION && blob.request == *request,
            "key package execution binding mismatch"
        );
        let key = frost::keys::KeyPackage::deserialize(&blob.key_package)
            .map_err(|_| anyhow::anyhow!("invalid FROST key package"))?;
        ensure!(
            *key.identifier()
                == identifier(&self.store.config.party_id).context("unknown party")?
                && *key.min_signers() == 2,
            "FROST key package identity mismatch"
        );
        ensure!(
            frost::keys::VerifyingShare::from(*key.signing_share()) == *key.verifying_share(),
            "private signing share mismatch"
        );
        if let Some(bytes) = &blob.public_key_package {
            let public = wallet_mpc_protocol::sign::public_package(
                bytes,
                &hex(&key.verifying_key().serialize()?),
            )?;
            ensure!(
                public.verifying_shares().get(key.identifier()) == Some(key.verifying_share()),
                "private/public verification share mismatch"
            );
        }
        Ok((key, blob.public_key_package.clone()))
    }
    fn loaded_public(&self, request: &DkgRequest) -> Result<String> {
        let (key, _) = self.loaded_key(request)?;
        Ok(hex(&key.verifying_key().serialize()?))
    }
    fn report(&self, request: &DkgRequest) -> Result<DkgReport> {
        let report = self
            .reports
            .get(&request.keyset_id)
            .context("DKG not started")?;
        ensure!(report.request == *request, "DKG binding conflict");
        if report.status == "COMPLETED" {
            ensure!(
                report.durable
                    && report.share_format_version == SHARE_FORMAT_VERSION
                    && report.group_public_key.as_ref() == Some(&self.loaded_public(request)?),
                "persisted DKG result mismatch"
            );
            ensure!(
                report.public_key_package == self.loaded_key(request)?.1,
                "durable public package mismatch"
            );
            ensure!(
                report.verification_share.as_ref()
                    == Some(&self.loaded_key(request)?.0.verifying_share().serialize()?),
                "verification share mismatch"
            );
            confirm_parent_durability(&self.store.path(request.keyset_id))?;
            confirm_parent_durability(&self.record_path(request.keyset_id))?;
        }
        Ok(report.clone())
    }
    fn abort(&mut self, request: &DkgRequest) -> Result<DkgReport> {
        let mut report = self.report(request)?;
        ensure!(
            report.status != "COMPLETED",
            "completed keyset cannot be aborted"
        );
        self.active.remove(&request.keyset_id);
        if self.executions.require_active(request.execution_id).is_ok() {
            self.executions.abort(request.execution_id)?;
        }
        report.status = if self.store.share_present(request.keyset_id) {
            "RECONCILIATION_REQUIRED"
        } else {
            "ABORTED"
        }
        .into();
        self.save(&report)?;
        self.reports.insert(request.keyset_id, report.clone());
        Ok(report)
    }
}

impl DkgService {
    pub async fn signing_key(
        &self,
        execution: &wallet_mpc_protocol::sign::SigningExecution,
    ) -> Result<frost::keys::KeyPackage> {
        execution.validate()?;
        let local = self.local.lock().await;
        ensure!(
            local
                .store
                .config
                .supported_algorithms
                .iter()
                .any(|a| a == ALGORITHM),
            "algorithm unavailable"
        );
        let report = local.report(&execution.dkg)?;
        ensure!(
            report.status == "COMPLETED"
                && report.durable
                && (report.public_key_package.is_none()
                    || report.public_key_package.as_ref() == Some(&execution.public_key_package))
                && report.group_public_key.as_ref() == Some(&execution.group_public_key),
            "signing evidence does not match completed DKG"
        );
        let key = local.loaded_key(&execution.dkg)?.0;
        let public = wallet_mpc_protocol::sign::public_package(
            &execution.public_key_package,
            &execution.group_public_key,
        )?;
        ensure!(
            public.verifying_shares().get(key.identifier()) == Some(key.verifying_share()),
            "public verification share mismatch"
        );
        Ok(key)
    }
    pub fn open(
        store: SignerStore,
        executions: ExecutionTombstones,
        peers: SignerClient,
    ) -> Result<Arc<Self>> {
        for party in PARTIES.into_iter().chain(["coordinator"]) {
            ensure!(
                store
                    .config
                    .trusted_peers
                    .get(&format!("spiffe://wallet-mpc/{party}"))
                    == Some(&party.to_owned()),
                "exact DKG peer mapping required"
            );
        }
        let directory = store.config.storage_directory.join("dkg");
        fs::create_dir_all(&directory)?;
        confirm_parent_durability(&directory)?;
        let mut local = Local {
            store,
            executions,
            reports: BTreeMap::new(),
            active: BTreeMap::new(),
        };
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let mut report: DkgReport = serde_json::from_slice(&fs::read(&path)?)?;
            ensure!(
                report.request.is_frost()
                    && report.party_id == local.store.config.party_id
                    && path == local.record_path(report.request.keyset_id),
                "invalid local DKG record"
            );
            if report.status == "IN_PROGRESS" {
                report.status = if local.store.share_present(report.request.keyset_id) {
                    "RECONCILIATION_REQUIRED"
                } else {
                    "ABORTED_AFTER_RESTART"
                }
                .into();
                local.save(&report)?;
            }
            let request = report.request.clone();
            if report.status == "COMPLETED" && report.verification_share.is_none() {
                report.verification_share = Some(
                    local
                        .loaded_key(&request)?
                        .0
                        .verifying_share()
                        .serialize()?,
                );
                local.save(&report)?;
            }
            local.reports.insert(request.keyset_id, report);
            local.report(&request)?;
        }
        Ok(Arc::new(Self {
            local: Mutex::new(local),
            peers,
            guard: EnvelopeGuard::default(),
        }))
    }

    async fn control(&self, action: &str, request: DkgRequest) -> Result<DkgReport> {
        ensure!(request.is_frost(), "only fixed FROST 2-of-3 DKG supported");
        let mut local = self.local.lock().await;
        ensure!(
            local
                .store
                .config
                .supported_algorithms
                .iter()
                .any(|a| a == ALGORITHM),
            "FROST is not enabled for this signer"
        );
        if action == "report" {
            return local.report(&request);
        }
        if action == "abort" {
            return local.abort(&request);
        }
        if action == "start" {
            if local.reports.contains_key(&request.keyset_id) {
                let report = local.report(&request)?;
                ensure!(
                    report.status == "COMPLETED" || local.active.contains_key(&request.keyset_id),
                    "lost ephemeral DKG state cannot resume"
                );
                return Ok(report);
            }
            ensure!(
                !local.store.share_present(request.keyset_id),
                "existing keyset cannot run DKG"
            );
            ensure!(local.active.len() < 32, "too many active DKG executions");
            let report = DkgReport {
                request: request.clone(),
                party_id: local.store.config.party_id.clone(),
                status: "IN_PROGRESS".into(),
                share_format_version: SHARE_FORMAT_VERSION,
                group_public_key: None,
                public_key_package: None,
                verification_share: None,
                durable: false,
            };
            // Reserve execution before generating any ephemeral randomness. The
            // keyset claim is immutable even if the process subsequently crashes.
            local.executions.begin(request.execution_id)?;
            atomic_create_secret(
                &local.record_path(request.keyset_id),
                &serde_json::to_vec(&report)?,
            )?;
            local.reports.insert(request.keyset_id, report.clone());
            let (secret, public) = frost::keys::dkg::part1(
                identifier(&report.party_id).unwrap(),
                3,
                2,
                rand_core::OsRng,
            )?;
            local.active.insert(
                request.keyset_id,
                Active {
                    round1_secret: Some(secret),
                    round1_public: public,
                    round1_received: BTreeMap::new(),
                    round2_secret: None,
                    round2_received: BTreeMap::new(),
                    round1_sent: false,
                    round2_sent: false,
                },
            );
            return Ok(report);
        }
        let report = local.report(&request)?;
        ensure!(report.status == "IN_PROGRESS", "DKG execution is terminal");
        local.executions.require_active(request.execution_id)?;
        let own = report.party_id.clone();
        let active = local
            .active
            .get_mut(&request.keyset_id)
            .context("lost ephemeral DKG state")?;
        if action == "finalize" {
            ensure!(
                active.round2_sent && active.round2_received.len() == 2,
                "all three DKG parties required"
            );
            let (key, public) = frost::keys::dkg::part3(
                active.round2_secret.as_ref().context("round2 required")?,
                &active.round1_received,
                &active.round2_received,
            )?;
            ensure!(
                key.verifying_key() == public.verifying_key(),
                "public key mismatch"
            );
            let blob = KeyBlob {
                format_version: SHARE_FORMAT_VERSION,
                request: request.clone(),
                key_package: key.serialize()?,
                public_key_package: Some(public.serialize()?),
            };
            let share = StoredShare {
                format_version: SHARE_FORMAT_VERSION,
                protocol_version: PROTOCOL_VERSION.into(),
                algorithm: ALGORITHM.into(),
                keyset_id: request.keyset_id,
                party_id: own,
                protocol_share: serde_json::to_vec(&blob)?,
            };
            local.store.persist(&share)?;
            ensure!(
                local.loaded_public(&request)? == hex(&public.verifying_key().serialize()?),
                "durable key mismatch"
            );
            let mut completed = report;
            completed.status = "COMPLETED".into();
            completed.group_public_key = Some(hex(&public.verifying_key().serialize()?));
            completed.public_key_package = Some(public.serialize()?);
            completed.verification_share = Some(key.verifying_share().serialize()?);
            completed.durable = true;
            // If either state write fails, completion is not acknowledged. A
            // restart reconciles the encrypted package rather than rerunning DKG.
            local.executions.complete(request.execution_id)?;
            local.save(&completed)?;
            local.reports.insert(request.keyset_id, completed.clone());
            local.active.remove(&request.keyset_id);
            return Ok(completed);
        }
        let (round, outgoing): (u16, BTreeMap<String, Vec<u8>>) = match action {
            "round1" => {
                ensure!(!active.round1_sent, "round1 already dispatched");
                active.round1_sent = true;
                (
                    1,
                    PARTIES
                        .into_iter()
                        .filter(|p| *p != own)
                        .map(|p| Ok((p.to_owned(), active.round1_public.serialize()?)))
                        .collect::<Result<_>>()?,
                )
            }
            "round2" => {
                ensure!(
                    active.round1_sent && active.round1_received.len() == 2 && !active.round2_sent,
                    "round1 incomplete or round2 already dispatched"
                );
                let view = round1_view(active, &own)?;
                let (secret, outgoing) = frost::keys::dkg::part2(
                    active
                        .round1_secret
                        .take()
                        .context("round1 state consumed")?,
                    &active.round1_received,
                )?;
                active.round2_secret = Some(secret);
                active.round2_sent = true;
                (
                    2,
                    outgoing
                        .into_iter()
                        .map(|(id, package)| {
                            let party = PARTIES
                                .into_iter()
                                .find(|p| identifier(p) == Some(id))
                                .context("invalid upstream recipient")?;
                            Ok((
                                party.to_owned(),
                                serde_json::to_vec(&Round2Wire {
                                    round1_view: view.clone(),
                                    package: package.serialize()?,
                                })?,
                            ))
                        })
                        .collect::<Result<_>>()?,
                )
            }
            _ => anyhow::bail!("unknown DKG control"),
        };
        drop(local);
        for (recipient, payload) in outgoing {
            let mut envelope = ProtocolEnvelope {
                logical_session_id: request.session_id,
                crypto_execution_id: request.execution_id,
                keyset_id: request.keyset_id,
                protocol: ALGORITHM.into(),
                sender: own.clone(),
                recipient: recipient.clone(),
                round,
                sequence: u64::from(round),
                payload,
                payload_digest: String::new(),
            };
            envelope.payload_digest = envelope.transcript_digest();
            self.peers
                .request(
                    &recipient,
                    "POST",
                    "/internal/v1/dkg/message",
                    serde_json::to_vec(&envelope)?,
                )
                .await?;
        }
        Ok(report)
    }

    async fn receive(&self, peer: &PeerIdentity, envelope: ProtocolEnvelope) -> Result<()> {
        let mut local = self.local.lock().await;
        let report = local
            .reports
            .get(&envelope.keyset_id)
            .context("unknown keyset")?;
        ensure!(
            report.status == "IN_PROGRESS"
                && envelope.logical_session_id == report.request.session_id
                && envelope.crypto_execution_id == report.request.execution_id
                && envelope.protocol == ALGORITHM
                && envelope.sequence == u64::from(envelope.round)
                && [1, 2].contains(&envelope.round)
                && envelope.sender != local.store.config.party_id,
            "wrong DKG execution/round binding"
        );
        local
            .executions
            .require_active(envelope.crypto_execution_id)?;
        ensure!(
            PARTIES.contains(&peer.role()),
            "only signer peers can send DKG packages"
        );
        self.guard.accept(
            &envelope,
            &local.store.config.party_id,
            &format!("spiffe://wallet-mpc/{}", peer.role()),
            &local.store.config.trusted_peers,
        )?;
        let own = local.store.config.party_id.clone();
        let active = local
            .active
            .get_mut(&envelope.keyset_id)
            .context("lost ephemeral state")?;
        let id = identifier(&envelope.sender).context("unknown sender")?;
        match envelope.round {
            1 => {
                ensure!(
                    active.round2_secret.is_none() && !active.round1_received.contains_key(&id),
                    "round1 is closed"
                );
                let package = frost::keys::dkg::round1::Package::deserialize(&envelope.payload)?;
                active.round1_received.insert(id, package);
            }
            2 => {
                ensure!(
                    active.round1_received.len() == 2 && !active.round2_received.contains_key(&id),
                    "round2 not ready"
                );
                let wire: Round2Wire = serde_json::from_slice(&envelope.payload)?;
                ensure!(
                    wire.round1_view == round1_view(active, &own)?,
                    "inconsistent public round1 view"
                );
                let package = frost::keys::dkg::round2::Package::deserialize(&wire.package)?;
                active.round2_received.insert(id, package);
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

fn round1_view(active: &Active, own: &str) -> Result<String> {
    let mut view = BTreeMap::new();
    view.insert(own.to_owned(), active.round1_public.serialize()?);
    for (id, package) in &active.round1_received {
        let party = PARTIES
            .into_iter()
            .find(|p| identifier(p) == Some(*id))
            .context("unknown round1 party")?;
        view.insert(party.to_owned(), package.serialize()?);
    }
    ensure!(view.len() == 3, "incomplete public round1 view");
    Ok(hex(&Sha256::digest(serde_json::to_vec(&view)?)))
}

impl Drop for ProtocolEnvelope {
    fn drop(&mut self) {
        self.payload.zeroize();
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
async fn signer_only(
    Extension(peer): Extension<PeerIdentity>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !PARTIES.contains(&peer.role()) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}
fn rejected(_: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    // Upstream errors and request bodies never enter responses or logs.
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error":"DKG rejected"})),
    )
}
async fn control(
    State(service): State<Arc<DkgService>>,
    Path(action): Path<String>,
    Json(request): Json<DkgRequest>,
) -> Result<Json<DkgReport>, (StatusCode, Json<serde_json::Value>)> {
    service
        .control(&action, request)
        .await
        .map(Json)
        .map_err(rejected)
}
async fn receive(
    State(service): State<Arc<DkgService>>,
    Extension(peer): Extension<PeerIdentity>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Deserialize privately: Axum's detailed JSON errors could echo field values.
    let buffer = Zeroizing::new(body.to_vec());
    let envelope = serde_json::from_slice(&buffer)
        .map_err(|_| rejected(anyhow::anyhow!("invalid envelope")))?;
    service.receive(&peer, envelope).await.map_err(rejected)?;
    Ok(Json(serde_json::json!({"accepted":true})))
}

pub fn router(service: Arc<DkgService>) -> Router {
    Router::new()
        .route(
            "/internal/v1/dkg/{action}",
            post(control).route_layer(middleware::from_fn(coordinator_only)),
        )
        .route(
            "/internal/v1/dkg/message",
            post(receive).route_layer(middleware::from_fn(signer_only)),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(service)
}
