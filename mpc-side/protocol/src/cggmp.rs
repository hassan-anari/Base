//! Public CGGMP key-generation evidence. Core shares alone are not signing keys.
use crate::{dkg::{hex, DkgReport, DkgRequest, PARTIES}, sign::decode_hex};
use anyhow::{ensure, Context, Result};
use cggmp24::{generic_ec::Point, supported_curves::Secp256k1};
use sha2::{Digest, Sha256};

pub const ALGORITHM: &str = "CGGMP24_ECDSA";
pub const CORE_READY: &str = "KEYGEN_COMPLETED";

impl DkgRequest {
    pub fn is_cggmp(&self) -> bool {
        self.algorithm == ALGORITHM && self.curve == "secp256k1"
            && ["EVM", "TRON"].contains(&self.scope.as_str())
            && self.derivation_version == "cggmp_hd_v1"
            && self.threshold == 2 && self.party_count == 3 && self.participants == PARTIES
            && !self.session_id.is_nil() && !self.execution_id.is_nil() && !self.keyset_id.is_nil()
    }
    pub fn cggmp_transcript(&self) -> Result<String> {
        ensure!(self.is_cggmp(), "invalid CGGMP keygen binding");
        Ok(format!("CGGMP24_KEYGEN:{}", hex(&Sha256::digest(serde_json::to_vec(self)?))))
    }
}

pub fn canonical_point(encoded: &str) -> Result<()> {
    let bytes = decode_hex(encoded).context("invalid secp256k1 encoding")?;
    let point = Point::<Secp256k1>::from_bytes(&bytes)?;
    ensure!(!point.is_zero() && hex(point.to_bytes(true).as_ref()) == encoded,
        "noncanonical secp256k1 point");
    Ok(())
}

pub fn verify_keygen_receipts(request: &DkgRequest, reports: &[DkgReport]) -> Result<()> {
    ensure!(request.is_cggmp() && reports.len() == 3, "incomplete CGGMP keygen evidence");
    let group = reports[0].group_public_key.as_deref().context("missing group key")?;
    canonical_point(group)?;
    let bytes = reports[0].public_key_package.as_deref().context("missing public shares")?;
    let public: Vec<String> = serde_json::from_slice(bytes)?;
    ensure!(public.len() == 3 && serde_json::to_vec(&public)? == bytes, "invalid public package");
    for (index, (report, party)) in reports.iter().zip(PARTIES).enumerate() {
        canonical_point(&public[index])?;
        ensure!(report.request == *request && report.party_id == party && report.status == CORE_READY
            && report.durable && report.share_format_version == 1
            && report.group_public_key.as_deref() == Some(group)
            && report.public_key_package.as_deref() == Some(bytes)
            && report.verification_share.as_deref() == Some(decode_hex(&public[index]).context("invalid share")?.as_slice()),
            "invalid CGGMP receipt agreement");
    }
    Ok(())
}
