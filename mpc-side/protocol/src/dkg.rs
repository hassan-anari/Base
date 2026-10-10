//! Public DKG control/receipt contract; no secret protocol state is a response.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PARTIES: [&str; 3] = ["signer-a", "signer-b", "signer-c"];
pub const ALGORITHM: &str = "FROST_ED25519";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DkgRequest {
    pub session_id: Uuid,
    pub execution_id: Uuid,
    pub keyset_id: Uuid,
    pub algorithm: String,
    pub curve: String,
    pub scope: String,
    pub derivation_version: String,
    pub threshold: u16,
    pub party_count: u16,
    pub participants: Vec<String>,
}

impl DkgRequest {
    pub fn is_frost(&self) -> bool {
        self.algorithm == ALGORITHM
            && self.curve == "ed25519"
            && ["SOLANA", "TON"].contains(&self.scope.as_str())
            && self.derivation_version == "frost_keyset_v1"
            && self.threshold == 2
            && self.party_count == 3
            && self.participants == PARTIES
            && !self.session_id.is_nil()
            && !self.execution_id.is_nil()
            && !self.keyset_id.is_nil()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DkgReport {
    pub request: DkgRequest,
    pub party_id: String,
    pub status: String,
    pub share_format_version: u16,
    pub group_public_key: Option<String>,
    #[serde(default)]
    pub public_key_package: Option<Vec<u8>>,
    #[serde(default)]
    pub verification_share: Option<Vec<u8>>,
    pub durable: bool,
}

pub fn identifier(party: &str) -> Option<frost_ed25519::Identifier> {
    PARTIES.iter().position(|p| *p == party).map(|index| {
        ((index + 1) as u16)
            .try_into()
            .expect("fixed valid identifier")
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
