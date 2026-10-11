//! Public signing contracts shared by the authenticated services.
use crate::dkg::{hex, identifier, DkgRequest, ALGORITHM, PARTIES};
use anyhow::{ensure, Context, Result};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyAuthorization {
    pub certificate_chain_der_hex: Vec<String>,
    pub signature_der_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub session_id: Uuid,
    pub attempt_id: u64,
    pub keyset_id: Uuid,
    pub algorithm: String,
    pub payload_type: String,
    pub payload_hex: String,
    pub message_fingerprint: String,
    pub operation_type: String,
    pub chain: String,
    pub asset: String,
    pub expected_source: String,
    pub derivation_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_authorization: Option<crate::hd::ChildIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_authorization: Option<CustodyAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ton_authorization: Option<crate::ton::TonAuthorization>,
}

pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.is_ascii() {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect()
}

impl SignRequest {
    pub fn custody_authorization_message(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .context("invalid custody request")?
            .remove("custody_authorization");
        let mut message = b"Wallet-MPC/CUSTODY_CHILD_SIGNING_AUTH_V1\0".to_vec();
        message.extend(serde_json::to_vec(&value)?);
        Ok(message)
    }
    pub fn frost_message(&self, group: &str) -> Result<Vec<u8>> {
        ensure!(
            self.algorithm == ALGORITHM
                && ((self.payload_type == "SOLANA_MESSAGE"
                    && self.chain == "SOL"
                    && self.ton_authorization.is_none())
                    || (self.payload_type == "TON_V5R1_CELL_HASH"
                        && self.chain == "TON"
                        && self.ton_authorization.is_some()))
                && !self.asset.trim().is_empty()
                && ["WITHDRAWAL", "SWEEP", "GAS_TOPUP"].contains(&self.operation_type.as_str())
                && self.attempt_id > 0
                && !self.session_id.is_nil()
                && !self.keyset_id.is_nil()
                && self.derivation_reference.is_none()
                && self.child_authorization.is_none(),
            "invalid custody signing context"
        );
        let message = decode_hex(&self.payload_hex).context("invalid message encoding")?;
        ensure!(
            !message.is_empty()
                && message.len() <= 1232
                && hex(&message) == self.payload_hex
                && hex(&Sha256::digest(&message)) == self.message_fingerprint,
            "message/fingerprint mismatch"
        );
        if let Some(authorization) = &self.ton_authorization {
            ensure!(
                message == authorization.signing_hash(group, &self.expected_source, &self.asset)?,
                "TON cell signing input mismatch"
            );
            return Ok(message);
        }
        let public = decode_hex(group).context("invalid group key")?;
        ensure!(
            public.len() == 32 && bs58::encode(public).into_string() == self.expected_source,
            "custody public-key identity mismatch"
        );
        Ok(message)
    }
}

pub fn public_package(bytes: &[u8], group: &str) -> Result<frost::keys::PublicKeyPackage> {
    let public = frost::keys::PublicKeyPackage::deserialize(bytes)?;
    ensure!(
        public.serialize()? == bytes
            && hex(&public.verifying_key().serialize()?) == group
            && public.verifying_shares().len() == 3
            && PARTIES.iter().all(|party| public
                .verifying_shares()
                .contains_key(&identifier(party).unwrap()))
            && public.min_signers() == Some(2),
        "public DKG package mismatch"
    );
    Ok(public)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SigningExecution {
    pub request: SignRequest,
    pub crypto_execution_id: Uuid,
    pub selected_signers: Vec<String>,
    pub dkg: DkgRequest,
    pub group_public_key: String,
    pub public_key_package: Vec<u8>,
}
impl SigningExecution {
    pub fn validate(&self) -> Result<Vec<u8>> {
        ensure!(
            self.dkg.is_frost()
                && ((self.dkg.scope == "SOLANA" && self.request.payload_type == "SOLANA_MESSAGE")
                    || (self.dkg.scope == "TON"
                        && self.request.payload_type == "TON_V5R1_CELL_HASH"))
                && self.dkg.keyset_id == self.request.keyset_id
                && !self.crypto_execution_id.is_nil()
                && self.crypto_execution_id != self.dkg.execution_id
                && self.selected_signers.len() == 2
                && self.selected_signers[0] < self.selected_signers[1]
                && self
                    .selected_signers
                    .iter()
                    .all(|p| PARTIES.contains(&p.as_str())),
            "invalid signing execution"
        );
        public_package(&self.public_key_package, &self.group_public_key)?;
        self.request.frost_message(&self.group_public_key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignControl {
    pub execution: SigningExecution,
    pub sender: String,
    pub recipient: String,
    pub round: u16,
    pub signing_package: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignReport {
    pub execution: SigningExecution,
    pub sender: String,
    pub recipient: String,
    pub round: u16,
    pub status: String,
    pub commitments: Option<Vec<u8>>,
    pub signature_share: Option<Vec<u8>>,
    pub signing_package: Option<Vec<u8>>,
}
