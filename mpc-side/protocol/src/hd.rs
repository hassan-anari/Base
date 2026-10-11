//! Immutable original DKG HD evidence and approved, non-hardened deposit children.
//! No secrets, seed derivation, reconstructed key or caller-selected path.
use crate::{
    cggmp::{canonical_point, source_address, AuxRequest},
    dkg::{hex, PARTIES},
    sign::decode_hex,
};
use anyhow::{ensure, Context, Result};
use cggmp24::{
    generic_ec::Point,
    hd_wallet::{ExtendedPublicKey, HdWallet, Slip10},
    supported_curves::Secp256k1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const VERSION: &str = "cggmp_slip10_nonhardened_v1";

pub fn fingerprint<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    // Serialize through Value to sort every object key. Cross-language canonical JSON,
    // with domain separation, integer-only network metadata and UTF-8 strings.
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(&serde_json::to_value(value)?)?);
    Ok(hex(&hash.finalize()))
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.chars().count() <= max
}
fn digest(value: &str, prefix: bool) -> bool {
    let value = if prefix {
        match value.strip_prefix("0x") {
            Some(v) => v,
            None => return false,
        }
    } else {
        value
    };
    decode_hex(value)
        .is_some_and(|b| b.len() == 32 && hex(&b) == value && b.iter().any(|v| *v != 0))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HdScope {
    pub ownership_scope: String,
    pub chain_id: String,
    pub purpose: String,
    pub wallet_class: String,
    pub derivation_version: String,
    pub root_identity: serde_json::Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HdRequest {
    pub auxiliary: AuxRequest,
    pub scope: HdScope,
}
impl HdRequest {
    pub fn validate(&self) -> Result<()> {
        self.auxiliary.validate()?;
        let scope = &self.scope;
        let dkg = &self.auxiliary.dkg;
        let identity = &scope.root_identity;
        ensure!(
            text(&scope.ownership_scope, 64)
                && scope.purpose == "DEPOSIT"
                && scope.wallet_class == "HOT"
                && scope.derivation_version == VERSION
                && identity.as_object().is_some_and(|o| o.len() == 8)
                && identity["keyset_id"] == dkg.keyset_id.to_string()
                && identity["chain_id"] == scope.chain_id
                && identity["scope"] == dkg.scope
                && identity["algorithm"] == dkg.algorithm
                && identity["public_key"] == self.auxiliary.group_public_key
                && identity["dkg_execution_id"] == dkg.execution_id.to_string()
                && identity["dkg_fingerprint"]
                    .as_str()
                    .is_some_and(|v| digest(v, false)),
            "invalid HD namespace/root binding"
        );
        let network = &identity["network"];
        if dkg.scope == "EVM" {
            ensure!(
                ["ETH", "BSC", "MATIC", "ARB", "BASE"].contains(&scope.chain_id.as_str())
                    && network.as_object().is_some_and(|o| o.len() == 2)
                    && network["evm_chain_id"].as_u64().is_some_and(|v| v > 0)
                    && network["genesis_hash"]
                        .as_str()
                        .is_some_and(|v| digest(v, true)),
                "missing original EVM genesis"
            );
        } else {
            ensure!(
                scope.chain_id == "TRX"
                    && network.as_object().is_some_and(|o| o.len() == 4)
                    && network["network"] == "isolated-v1"
                    && network["genesis_block_id"]
                        .as_str()
                        .is_some_and(|v| digest(v, false))
                    && network["checkpoint_block_id"]
                        .as_str()
                        .is_some_and(|v| digest(v, false))
                    && network["checkpoint_height"].as_u64().is_some_and(|v| v > 0),
                "missing original TRON genesis/checkpoint"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HdRoot {
    pub request: HdRequest,
    pub chain_code: String,
    pub extended_identity: String,
}
impl HdRoot {
    pub fn new(request: HdRequest, chain_code: String) -> Result<Self> {
        request.validate()?;
        ensure!(
            decode_hex(&chain_code).is_some_and(|b| b.len() == 32 && hex(&b) == chain_code),
            "missing canonical original chain code"
        );
        let extended_identity = fingerprint("CGGMP24_HD_ROOT_V1", &(&request, &chain_code))?;
        Ok(Self {
            request,
            chain_code,
            extended_identity,
        })
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            Self::new(self.request.clone(), self.chain_code.clone())? == *self,
            "extended root identity mismatch"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HdRootReport {
    pub root: HdRoot,
    pub party_id: String,
    pub durable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HdEvidence {
    pub root: HdRoot,
    pub participant_agreement: Vec<HdRootReport>,
}
impl HdEvidence {
    pub fn validate(&self) -> Result<()> {
        self.root.validate()?;
        ensure!(
            self.participant_agreement.len() == 3,
            "incomplete original HD agreement"
        );
        for (receipt, party) in self.participant_agreement.iter().zip(PARTIES) {
            ensure!(
                receipt.root == self.root && receipt.party_id == party && receipt.durable,
                "original HD evidence disagreement"
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChildRequest {
    pub root: HdRoot,
    pub reservation_id: Uuid,
    pub customer_ref: String,
    pub idempotency_key: String,
    pub child_index: u32,
    pub derivation_path: String,
}
impl ChildRequest {
    pub fn path(&self) -> Result<[u32; 2]> {
        self.root.validate()?;
        ensure!(
            !self.reservation_id.is_nil()
                && text(&self.customer_ref, 64)
                && text(&self.idempotency_key, 128)
                && self.child_index < (1 << 31)
                && self.derivation_path == format!("m/0/{}", self.child_index),
            "invalid approved non-hardened reservation"
        );
        Ok([0, self.child_index])
    }
    pub fn derive(&self) -> Result<ChildIdentity> {
        let path = self.path()?;
        let group = &self.root.request.auxiliary.group_public_key;
        canonical_point(group)?;
        let epub = ExtendedPublicKey::<Secp256k1> {
            public_key: Point::from_bytes(&decode_hex(group).context("invalid root key")?)?,
            chain_code: decode_hex(&self.root.chain_code)
                .context("invalid chain code")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid chain code length"))?,
        };
        let child = Slip10::derive_child_public_key_with_path(
            &epub,
            path.map(|i| i.try_into().expect("validated non-hardened index")),
        );
        let public_key = hex(child.public_key.to_bytes(true).as_ref());
        ensure!(public_key != *group, "child equals original root");
        let address = source_address(&public_key, &self.root.request.auxiliary.dkg.scope)?;
        Ok(ChildIdentity {
            request: self.clone(),
            public_key,
            address,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChildIdentity {
    pub request: ChildRequest,
    pub public_key: String,
    pub address: String,
}
impl ChildIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.request.derive()? == *self,
            "child key/address mismatch"
        );
        Ok(())
    }
    pub fn reference(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "child:{}:{}",
            self.request.reservation_id,
            fingerprint("CGGMP24_CHILD_V1", self)?
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChildReport {
    pub child: ChildIdentity,
    pub party_id: String,
    pub durable: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChildEvidence {
    pub child: ChildIdentity,
    pub participant_agreement: Vec<ChildReport>,
}
impl ChildEvidence {
    pub fn validate(&self) -> Result<()> {
        self.child.validate()?;
        ensure!(
            self.participant_agreement.len() == 3,
            "incomplete spendable-child agreement"
        );
        for (report, party) in self.participant_agreement.iter().zip(PARTIES) {
            ensure!(
                report.child == self.child && report.party_id == party && report.durable,
                "child evidence disagreement"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ChildRequest {
        let public = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let dkg = crate::dkg::DkgRequest {
            session_id: Uuid::new_v4(),
            execution_id: Uuid::new_v4(),
            keyset_id: Uuid::new_v4(),
            algorithm: "CGGMP24_ECDSA".into(),
            curve: "secp256k1".into(),
            scope: "EVM".into(),
            derivation_version: "cggmp_hd_v1".into(),
            threshold: 2,
            party_count: 3,
            participants: PARTIES.map(String::from).to_vec(),
        };
        let identity = serde_json::json!({"keyset_id":dkg.keyset_id,"chain_id":"ETH","scope":"EVM",
            "algorithm":"CGGMP24_ECDSA","public_key":public,"dkg_execution_id":dkg.execution_id,
            "dkg_fingerprint":"ab".repeat(32),"network":{"evm_chain_id":31337,"genesis_hash":format!("0x{}", "11".repeat(32))}});
        let hd = HdRequest {
            auxiliary: AuxRequest {
                dkg,
                execution_id: Uuid::new_v4(),
                group_public_key: public.into(),
                public_key_package: serde_json::to_vec(&[public; 3]).unwrap(),
            },
            scope: HdScope {
                ownership_scope: "deployment".into(),
                chain_id: "ETH".into(),
                purpose: "DEPOSIT".into(),
                wallet_class: "HOT".into(),
                derivation_version: VERSION.into(),
                root_identity: identity,
            },
        };
        ChildRequest {
            root: HdRoot::new(hd, "13".repeat(32)).unwrap(),
            reservation_id: Uuid::new_v4(),
            customer_ref: "customer".into(),
            idempotency_key: "retry".into(),
            child_index: 0,
            derivation_path: "m/0/0".into(),
        }
    }
    #[test]
    fn only_reserved_nonhardened_deposit_shape() {
        let original = request();
        for path in ["m/0/00", "m/0/0'", "m/1/0", "m/0", "m/0/2147483648"] {
            let mut changed = original.clone();
            changed.derivation_path = path.into();
            assert!(changed.derive().is_err());
        }
        let mut changed = original;
        changed.child_index = 1 << 31;
        assert!(changed.derive().is_err());
    }
    #[test]
    fn original_root_network_and_owner_are_committed() {
        let original = request();
        let child = original.derive().unwrap();
        assert_ne!(
            child.public_key,
            original.root.request.auxiliary.group_public_key
        );
        for field in ["chain_code", "genesis", "owner"] {
            let mut changed = original.clone();
            match field {
                "chain_code" => changed.root.chain_code = "14".repeat(32),
                "genesis" => {
                    changed.root.request.scope.root_identity["network"]["genesis_hash"] =
                        serde_json::json!(format!("0x{}", "12".repeat(32)))
                }
                _ => changed.root.request.scope.ownership_scope = "other".into(),
            }
            assert!(changed.derive().is_err());
        }
        let mut wrong = child.clone();
        wrong.address = "0x0000000000000000000000000000000000000000".into();
        assert!(wrong.validate().is_err());
        let mut another = original;
        another.customer_ref = "other".into();
        assert_ne!(
            child.reference().unwrap(),
            another.derive().unwrap().reference().unwrap()
        );
    }
}
