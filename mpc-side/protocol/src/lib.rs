//! Protocol boundary for CGGMP24 secp256k1 and RFC 9591 FROST Ed25519.
//! Production code exposes DKG/signing only: there is deliberately no key reconstruction API.
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ExecutionId(Uuid);
impl ExecutionId {
    /// UUID bytes are sourced directly from the operating-system CSPRNG.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(Uuid::from_bytes(bytes))
    }
}

/// Domain-separates every party message by execution, sender, recipient and round.
pub fn transcript_binding(
    id: &ExecutionId,
    sender: &str,
    recipient: &str,
    round: u32,
    body: &[u8],
) -> [u8; 32] {
    let encoded =
        serde_json::to_vec(&(id, sender, recipient, round, body)).expect("serializable transcript");
    Sha256::digest(encoded).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn execution_ids_and_transcripts_are_unique() {
        let a = ExecutionId::random();
        let b = ExecutionId::random();
        assert_ne!(a, b);
        assert_ne!(
            transcript_binding(&a, "a", "b", 1, b"x"),
            transcript_binding(&b, "a", "b", 1, b"x")
        );
        assert_ne!(
            transcript_binding(&a, "a", "b", 1, b"x"),
            transcript_binding(&a, "a", "b", 2, b"x")
        );
    }
}
