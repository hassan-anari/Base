//! Versioned compact proof transport; the authenticated transcript still covers
//! the exact original upstream JSON bytes, before base64 encoding.
use crate::ProtocolEnvelope;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

pub(super) const PAYLOAD_LIMIT: usize = 512 * 1024;
pub(super) const BODY_LIMIT: usize = 1024 * 1024;
const ENCODED_LIMIT: usize = PAYLOAD_LIMIT.div_ceil(3) * 4;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofEnvelope {
    wire_version: u16,
    logical_session_id: Uuid,
    crypto_execution_id: Uuid,
    keyset_id: Uuid,
    protocol: String,
    sender: String,
    recipient: String,
    round: u16,
    sequence: u64,
    payload_base64: String,
    payload_digest: String,
}
impl Drop for ProofEnvelope {
    fn drop(&mut self) { self.payload_base64.zeroize(); }
}

pub(super) fn encode(wire: &ProtocolEnvelope) -> Result<Vec<u8>> {
    ensure!(wire.payload.len() <= PAYLOAD_LIMIT, "proof payload budget exceeded");
    let compact = ProofEnvelope {
        wire_version: 1, logical_session_id: wire.logical_session_id,
        crypto_execution_id: wire.crypto_execution_id, keyset_id: wire.keyset_id,
        protocol: wire.protocol.clone(), sender: wire.sender.clone(), recipient: wire.recipient.clone(),
        round: wire.round, sequence: wire.sequence,
        payload_base64: base64::encode(&wire.payload), payload_digest: wire.payload_digest.clone(),
    };
    let body = serde_json::to_vec(&compact)?;
    ensure!(body.len() <= BODY_LIMIT, "proof body budget exceeded");
    Ok(body)
}

pub(super) fn decode(body: &[u8]) -> Result<ProtocolEnvelope> {
    ensure!(body.len() <= BODY_LIMIT, "proof body budget exceeded");
    let compact: ProofEnvelope = serde_json::from_slice(body)?;
    ensure!(compact.wire_version == 1, "unsupported proof wire version");
    // Bound the decoded allocation before asking the codec to allocate it.
    ensure!(compact.payload_base64.len() <= ENCODED_LIMIT, "encoded proof budget exceeded");
    let payload = base64::decode(&compact.payload_base64)?;
    ensure!(payload.len() <= PAYLOAD_LIMIT && base64::encode(&payload) == compact.payload_base64,
        "noncanonical or oversized proof payload");
    Ok(ProtocolEnvelope {
        logical_session_id: compact.logical_session_id, crypto_execution_id: compact.crypto_execution_id,
        keyset_id: compact.keyset_id, protocol: compact.protocol.clone(), sender: compact.sender.clone(),
        recipient: compact.recipient.clone(), round: compact.round, sequence: compact.sequence,
        payload, payload_digest: compact.payload_digest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wire(payload: Vec<u8>) -> ProtocolEnvelope {
        let mut wire = ProtocolEnvelope { logical_session_id: Uuid::new_v4(), crypto_execution_id: Uuid::new_v4(),
            keyset_id: Uuid::new_v4(), protocol: "CGGMP24_AUX:test/broadcast".into(), sender: "signer-b".into(),
            recipient: "signer-a".into(), round: 1, sequence: 0, payload, payload_digest: String::new() };
        wire.payload_digest = wire.transcript_digest(); wire
    }
    #[test]
    fn large_proofs_round_trip_preserving_the_original_authenticated_bytes() {
        let original = wire(vec![255; PAYLOAD_LIMIT]);
        let compact = encode(&original).unwrap();
        assert!(compact.len() < BODY_LIMIT);
        let decoded = decode(&compact).unwrap();
        assert_eq!(decoded.payload, original.payload);
        assert_eq!(decoded.transcript_digest(), original.transcript_digest());
        assert_eq!(decoded.payload_digest, original.payload_digest);
        // JSON byte-array expansion would exceed the existing one-MiB HTTP cap.
        assert!(serde_json::to_vec(&original).unwrap().len() > BODY_LIMIT);
    }
    #[test]
    fn oversized_unknown_or_noncanonical_proof_encoding_fails_closed() {
        assert!(encode(&wire(vec![0; PAYLOAD_LIMIT + 1])).is_err());
        assert!(decode(&vec![b' '; BODY_LIMIT + 1]).is_err());
        let original = wire(vec![0]);
        let mut value: serde_json::Value = serde_json::from_slice(&encode(&original).unwrap()).unwrap();
        for encoded in ["AA", "AB==", "AA==\n", "!invalid!"] {
            value["payload_base64"] = encoded.into();
            assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        value["payload_base64"] = "AA==".into(); value["wire_version"] = 2.into();
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(decode(&serde_json::to_vec(&original).unwrap()).is_err());
    }
}
