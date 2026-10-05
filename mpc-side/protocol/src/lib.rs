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
    use frost_ed25519 as frost;
    use std::collections::BTreeMap;
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

    #[test]
    fn frost_real_two_of_three_dkg_and_signing() {
        let mut rng = OsRng;
        let identifiers: Vec<frost::Identifier> =
            (1u16..=3).map(|value| value.try_into().unwrap()).collect();
        let mut round1_secret = BTreeMap::new();
        let mut round1_public = BTreeMap::new();
        for identifier in &identifiers {
            let (secret, public) = frost::keys::dkg::part1(*identifier, 3, 2, rng).unwrap();
            round1_secret.insert(*identifier, secret);
            round1_public.insert(*identifier, public);
        }
        let mut round2_secret = BTreeMap::new();
        let mut directed_round2: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
        for identifier in &identifiers {
            let received = round1_public
                .iter()
                .filter(|(sender, _)| *sender != identifier)
                .map(|(sender, package)| (*sender, package.clone()))
                .collect();
            let (secret, outgoing) =
                frost::keys::dkg::part2(round1_secret.remove(identifier).unwrap(), &received)
                    .unwrap();
            round2_secret.insert(*identifier, secret);
            for (recipient, package) in outgoing {
                directed_round2
                    .entry(recipient)
                    .or_default()
                    .insert(*identifier, package);
            }
        }
        let mut keys = BTreeMap::new();
        let mut public_package: Option<frost::keys::PublicKeyPackage> = None;
        for identifier in &identifiers {
            let received_round1 = round1_public
                .iter()
                .filter(|(sender, _)| *sender != identifier)
                .map(|(sender, package)| (*sender, package.clone()))
                .collect();
            let (key, public) = frost::keys::dkg::part3(
                &round2_secret[identifier],
                &received_round1,
                &directed_round2[identifier],
            )
            .unwrap();
            if let Some(previous) = &public_package {
                assert_eq!(previous.verifying_key(), public.verifying_key());
            }
            public_package = Some(public);
            keys.insert(*identifier, key);
        }
        let selected = &identifiers[..2];
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for identifier in selected {
            let (nonce, commitment) =
                frost::round1::commit(keys[identifier].signing_share(), &mut rng);
            nonces.insert(*identifier, nonce);
            commitments.insert(*identifier, commitment);
        }
        let message = b"wallet-mpc FROST compatibility";
        let signing_package = frost::SigningPackage::new(commitments, message);
        let shares = selected
            .iter()
            .map(|identifier| {
                (
                    *identifier,
                    frost::round2::sign(&signing_package, &nonces[identifier], &keys[identifier])
                        .unwrap(),
                )
            })
            .collect();
        let public_package = public_package.unwrap();
        let signature = frost::aggregate(&signing_package, &shares, &public_package).unwrap();
        public_package
            .verifying_key()
            .verify(message, &signature)
            .unwrap();
    }
}
