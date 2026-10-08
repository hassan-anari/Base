//! Public CGGMP key-generation evidence. Core shares alone are not signing keys.
use crate::{
    dkg::{hex, DkgReport, DkgRequest, PARTIES},
    sign::decode_hex,
};
use anyhow::{ensure, Context, Result};
use cggmp24::{generic_ec::Point, supported_curves::Secp256k1};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
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
        ensure!(self.dkg.is_cggmp() && !self.execution_id.is_nil()
            && self.execution_id != self.dkg.execution_id, "invalid auxiliary execution");
        canonical_point(&self.group_public_key)?;
        let public: Vec<String> = serde_json::from_slice(&self.public_key_package)?;
        ensure!(public.len() == 3 && serde_json::to_vec(&public)? == self.public_key_package,
            "invalid auxiliary public package");
        for point in public { canonical_point(&point)?; }
        Ok(())
    }
    pub fn transcript(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("CGGMP24_AUX:{}", hex(&Sha256::digest(serde_json::to_vec(self)?))))
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
    let fingerprint = reports[0].public_parameters_fingerprint.as_deref()
        .context("missing auxiliary parameters")?;
    ensure!(decode_hex(fingerprint).is_some_and(|b| b.len() == 32 && hex(&b) == fingerprint),
        "invalid auxiliary fingerprint");
    for (report, party) in reports.iter().zip(PARTIES) {
        ensure!(report.request == *request && report.party_id == party && report.status == AUX_READY
            && report.artifact_format_version == 1 && report.durable
            && report.public_parameters_fingerprint.as_deref() == Some(fingerprint)
            && report.prime_generation_ms.is_some(), "invalid auxiliary receipt agreement");
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
