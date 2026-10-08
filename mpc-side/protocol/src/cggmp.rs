//! Public CGGMP key-generation evidence. Core shares alone are not signing keys.
use crate::{
    dkg::{hex, DkgReport, DkgRequest, PARTIES},
    sign::decode_hex,
};
use anyhow::{ensure, Context, Result};
use cggmp24::{generic_ec::Point, supported_curves::Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const ALGORITHM: &str = "CGGMP24_ECDSA";
pub const CORE_READY: &str = "KEYGEN_COMPLETED";
pub const AUX_READY: &str = "AUXILIARY_COMPLETED";

/// Public binding for auxiliary generation; contains no prime or key-share material.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuxRequest {
    pub dkg: DkgRequest,
    pub execution_id: Uuid,
    pub group_public_key: String,
    pub public_key_package: Vec<u8>,
}
impl AuxRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.dkg.is_cggmp()
                && !self.execution_id.is_nil()
                && self.execution_id != self.dkg.execution_id,
            "invalid auxiliary execution"
        );
        canonical_point(&self.group_public_key)?;
        let public: Vec<String> = serde_json::from_slice(&self.public_key_package)?;
        ensure!(
            public.len() == 3 && serde_json::to_vec(&public)? == self.public_key_package,
            "invalid auxiliary public package"
        );
        for point in public {
            canonical_point(&point)?;
        }
        Ok(())
    }
    pub fn transcript(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "CGGMP24_AUX:{}",
            hex(&Sha256::digest(serde_json::to_vec(self)?))
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuxReport {
    pub request: AuxRequest,
    pub party_id: String,
    pub status: String,
    pub artifact_format_version: u16,
    pub durable: bool,
    pub public_parameters_fingerprint: Option<String>,
    pub prime_generation_ms: Option<u64>,
}
pub fn verify_aux_receipts(request: &AuxRequest, reports: &[AuxReport]) -> Result<()> {
    request.validate()?;
    ensure!(reports.len() == 3, "incomplete auxiliary receipts");
    let fingerprint = reports[0]
        .public_parameters_fingerprint
        .as_deref()
        .context("missing auxiliary parameters")?;
    ensure!(
        decode_hex(fingerprint).is_some_and(|b| b.len() == 32 && hex(&b) == fingerprint),
        "invalid auxiliary fingerprint"
    );
    for (report, party) in reports.iter().zip(PARTIES) {
        ensure!(
            report.request == *request
                && report.party_id == party
                && report.status == AUX_READY
                && report.artifact_format_version == 1
                && report.durable
                && report.public_parameters_fingerprint.as_deref() == Some(fingerprint)
                && report.prime_generation_ms.is_some(),
            "invalid auxiliary receipt agreement"
        );
    }
    Ok(())
}

impl DkgRequest {
    pub fn is_cggmp(&self) -> bool {
        self.algorithm == ALGORITHM
            && self.curve == "secp256k1"
            && ["EVM", "TRON"].contains(&self.scope.as_str())
            && self.derivation_version == "cggmp_hd_v1"
            && self.threshold == 2
            && self.party_count == 3
            && self.participants == PARTIES
            && !self.session_id.is_nil()
            && !self.execution_id.is_nil()
            && !self.keyset_id.is_nil()
    }
    pub fn cggmp_transcript(&self) -> Result<String> {
        ensure!(self.is_cggmp(), "invalid CGGMP keygen binding");
        Ok(format!(
            "CGGMP24_KEYGEN:{}",
            hex(&Sha256::digest(serde_json::to_vec(self)?))
        ))
    }
}

pub fn canonical_point(encoded: &str) -> Result<()> {
    let bytes = decode_hex(encoded).context("invalid secp256k1 encoding")?;
    let point = Point::<Secp256k1>::from_bytes(&bytes)?;
    ensure!(
        !point.is_zero() && hex(point.to_bytes(true).as_ref()) == encoded,
        "noncanonical secp256k1 point"
    );
    Ok(())
}

pub fn verify_keygen_receipts(request: &DkgRequest, reports: &[DkgReport]) -> Result<()> {
    ensure!(
        request.is_cggmp() && reports.len() == 3,
        "incomplete CGGMP keygen evidence"
    );
    let group = reports[0]
        .group_public_key
        .as_deref()
        .context("missing group key")?;
    canonical_point(group)?;
    let bytes = reports[0]
        .public_key_package
        .as_deref()
        .context("missing public shares")?;
    let public: Vec<String> = serde_json::from_slice(bytes)?;
    ensure!(
        public.len() == 3 && serde_json::to_vec(&public)? == bytes,
        "invalid public package"
    );
    for (index, (report, party)) in reports.iter().zip(PARTIES).enumerate() {
        canonical_point(&public[index])?;
        ensure!(
            report.request == *request
                && report.party_id == party
                && report.status == CORE_READY
                && report.durable
                && report.share_format_version == 1
                && report.group_public_key.as_deref() == Some(group)
                && report.public_key_package.as_deref() == Some(bytes)
                && report.verification_share.as_deref()
                    == Some(
                        decode_hex(&public[index])
                            .context("invalid share")?
                            .as_slice()
                    ),
            "invalid CGGMP receipt agreement"
        );
    }
    Ok(())
}

/// Full interactive signing only: no offline presignature is issued for unknown preimages.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningExecution {
    pub request: crate::sign::SignRequest,
    pub crypto_execution_id: Uuid,
    pub selected_signers: Vec<String>,
    pub auxiliary: AuxRequest,
}
impl SigningExecution {
    pub fn validate(&self) -> Result<[u8; 32]> {
        self.auxiliary.validate()?;
        ensure!(self.request.keyset_id == self.auxiliary.dkg.keyset_id
            && self.request.algorithm == ALGORITHM && self.request.attempt_id > 0
            && !self.request.session_id.is_nil() && !self.crypto_execution_id.is_nil()
            && ![self.auxiliary.dkg.execution_id, self.auxiliary.execution_id].contains(&self.crypto_execution_id)
            && self.selected_signers.len() == 2 && self.selected_signers[0] < self.selected_signers[1]
            && self.selected_signers.iter().all(|s| PARTIES.contains(&s.as_str()))
            && ["WITHDRAWAL", "SWEEP", "GAS_TOPUP"].contains(&self.request.operation_type.as_str())
            && !self.request.asset.trim().is_empty() && self.request.derivation_reference.is_none(),
            "invalid CGGMP custody signing context");
        let scope = self.auxiliary.dkg.scope.as_str();
        ensure!((scope == "EVM" && ["EVM_LEGACY_DIGEST", "EVM_EIP1559_DIGEST"].contains(&self.request.payload_type.as_str())
                && ["ETH", "BSC", "MATIC", "ARB", "BASE"].contains(&self.request.chain.as_str()))
            || (scope == "TRON" && self.request.payload_type == "TRON_TXID" && self.request.chain == "TRON"),
            "invalid digest scope");
        let bytes = decode_hex(&self.request.payload_hex).context("invalid digest encoding")?;
        ensure!(bytes.len() == 32 && hex(&bytes) == self.request.payload_hex
            && hex(&Sha256::digest(&bytes)) == self.request.message_fingerprint, "digest/fingerprint mismatch");
        ensure!(self.request.expected_source == source_address(&self.auxiliary.group_public_key, scope)?,
            "custody group/source mismatch");
        Ok(bytes.try_into().map_err(|_| anyhow::anyhow!("wrong digest length"))?)
    }
    pub fn transcript(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("CGGMP24_SIGN:{}", hex(&Sha256::digest(serde_json::to_vec(self)?))))
    }
}

pub fn source_address(group: &str, scope: &str) -> Result<String> {
    canonical_point(group)?;
    let point = Point::<Secp256k1>::from_bytes(&decode_hex(group).context("invalid group")?)?;
    let uncompressed = point.to_bytes(false);
    let hash = sha3::Keccak256::digest(&uncompressed.as_ref()[1..]);
    if scope == "EVM" { return Ok(format!("0x{}", hex(&hash[12..]))); }
    ensure!(scope == "TRON", "unsupported address scope");
    let mut payload = vec![0x41]; payload.extend_from_slice(&hash[12..]);
    let check = Sha256::digest(Sha256::digest(&payload)); payload.extend_from_slice(&check[..4]);
    Ok(bs58::encode(payload).into_string())
}

/// Normalize public metadata only after verifying recovery against the ORIGINAL DKG key.
/// k256 consumes the exact prehash. Independent process acceptance also uses libsecp256k1.
pub fn verified_signature(execution: &SigningExecution, bytes: &[u8]) -> Result<serde_json::Value> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    let digest = execution.validate()?;
    let signature = Signature::from_slice(bytes)?;
    ensure!(signature.normalize_s().is_none(), "high-s signature rejected");
    let group = decode_hex(&execution.auxiliary.group_public_key).context("invalid group")?;
    let mut recovery_id = None;
    for id in 0..4 {
        if let Some(rid) = RecoveryId::from_byte(id) {
            if let Ok(key) = VerifyingKey::recover_from_prehash(&digest, &signature, rid) {
                if key.to_encoded_point(true).as_bytes() == group { recovery_id = Some(id); break; }
            }
        }
    }
    let recovery_id = recovery_id.context("signature does not recover original DKG key")?;
    // Ethereum/TRON support the ordinary y parity encoding. Extremely rare x-overflow
    // recovery is an uncertain failure; never retry this execution with fresh nonces.
    ensure!(recovery_id < 2, "unsupported recovery overflow");
    Ok(serde_json::json!({"logical_session_id":execution.request.session_id,
        "crypto_execution_id":execution.crypto_execution_id,"keyset_id":execution.request.keyset_id,
        "selected_signers":execution.selected_signers,"algorithm":ALGORITHM,
        "payload_fingerprint":execution.request.message_fingerprint,"signature_hex":hex(bytes),
        "r":hex(&bytes[..32]),"s":hex(&bytes[32..]),"recovery_id":recovery_id,"y_parity":recovery_id,"verified":true}))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignReport {
    pub execution: SigningExecution,
    pub party_id: String,
    pub status: String,
    pub signature: Option<serde_json::Value>,
}
