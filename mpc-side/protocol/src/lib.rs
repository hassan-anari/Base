//! Protocol boundary for CGGMP24 secp256k1 and RFC 9591 FROST Ed25519.
//! Production code exposes DKG/signing only: there is deliberately no key reconstruction API.
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub mod cggmp;
pub mod dkg;
pub mod sign;

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
        let message = b"wallet-mpc FROST compatibility";
        let public_package = public_package.unwrap();
        for selected_indexes in [[0usize, 1usize], [0, 2], [1, 2]] {
            let selected = selected_indexes.map(|index| identifiers[index]);
            let mut nonces = BTreeMap::new();
            let mut commitments = BTreeMap::new();
            for identifier in selected {
                let (nonce, commitment) =
                    frost::round1::commit(keys[&identifier].signing_share(), &mut rng);
                nonces.insert(identifier, nonce);
                commitments.insert(identifier, commitment);
            }
            let signing_package = frost::SigningPackage::new(commitments, message);
            let shares = selected
                .iter()
                .map(|identifier| {
                    (
                        *identifier,
                        frost::round2::sign(
                            &signing_package,
                            &nonces[identifier],
                            &keys[identifier],
                        )
                        .unwrap(),
                    )
                })
                .collect();
            let signature = frost::aggregate(&signing_package, &shares, &public_package).unwrap();
            public_package
                .verifying_key()
                .verify(message, &signature)
                .unwrap();
        }
        for identifier in &identifiers {
            let (nonce, commitment) =
                frost::round1::commit(keys[identifier].signing_share(), &mut rng);
            let signing_package =
                frost::SigningPackage::new(BTreeMap::from([(*identifier, commitment)]), message);
            assert!(frost::round2::sign(&signing_package, &nonce, &keys[identifier]).is_err());
        }
    }

    #[test]
    fn cggmp_real_two_of_three_distributed_key_generation() {
        use cggmp24::{supported_curves::Secp256k1, ExecutionId as CggmpExecutionId};

        let mut execution_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut execution_bytes);
        let execution_id = CggmpExecutionId::new(&execution_bytes);
        let shares = round_based::sim::run(3, |party_index, party| async move {
            let mut rng = OsRng;
            cggmp24::keygen::<Secp256k1>(execution_id, party_index, 3)
                .set_threshold(2)
                .start(&mut rng, party)
                .await
        })
        .unwrap()
        .expect_ok()
        .into_vec();

        assert_eq!(shares.len(), 3);
        let expected = shares[0].shared_public_key();
        assert!(shares
            .iter()
            .all(|share| share.shared_public_key() == expected));
        assert!(shares.iter().all(|share| share.min_signers() == 2));
    }

    #[test]
    fn cggmp_real_two_of_three_all_signer_pairs() {
        use cggmp24::{
            key_share::{AnyKeyShare, KeyShare},
            signing::DataToSign,
            supported_curves::Secp256k1,
            ExecutionId as CggmpExecutionId, PregeneratedPrimes,
        };
        use sha2::Sha256;

        let new_execution_id = || {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            bytes
        };
        let keygen_bytes = new_execution_id();
        let keygen_id = CggmpExecutionId::new(&keygen_bytes);
        let incomplete = round_based::sim::run(3, |party_index, party| async move {
            cggmp24::keygen::<Secp256k1>(keygen_id, party_index, 3)
                .set_threshold(2)
                .start(&mut OsRng, party)
                .await
        })
        .unwrap()
        .expect_ok()
        .into_vec();

        let aux_bytes = new_execution_id();
        let aux_id = CggmpExecutionId::new(&aux_bytes);
        // Test-only cached safe primes keep CI bounded. Production signers call
        // PregeneratedPrimes::generate with OsRng and never share prime data.
        let primes: Vec<PregeneratedPrimes<cggmp24::security_level::SecurityLevel128>> =
            serde_json::from_str(include_str!("../test-data/cggmp-primes-128-test-only.json"))
                .unwrap();
        let shares = round_based::sim::run_with_setup(
            incomplete.into_iter().zip(primes),
            |party_index, party, (incomplete_share, primes)| async move {
                let aux = cggmp24::aux_info_gen(aux_id, party_index, 3, primes)
                    .start(&mut OsRng, party)
                    .await
                    .unwrap();
                KeyShare::from_parts((incomplete_share, aux)).unwrap()
            },
        )
        .unwrap()
        .into_vec();

        let message = DataToSign::digest::<Sha256>(b"wallet-mpc CGGMP compatibility");
        for participants in [[0u16, 1u16], [0, 2], [1, 2]] {
            let execution_bytes = new_execution_id();
            let execution_id = CggmpExecutionId::new(&execution_bytes);
            let selected = participants.map(|index| &shares[usize::from(index)]);
            let signatures = round_based::sim::run_with_setup(
                selected,
                |signing_index, party, share| async move {
                    cggmp24::signing(execution_id, signing_index, &participants, share)
                        .sign(&mut OsRng, party, &message)
                        .await
                },
            )
            .unwrap()
            .expect_ok()
            .expect_eq();
            signatures
                .verify(&shares[0].shared_public_key(), &message)
                .unwrap();
        }
        for participant in [0u16, 1, 2] {
            let execution_bytes = new_execution_id();
            let execution_id = CggmpExecutionId::new(&execution_bytes);
            let outcomes = round_based::sim::run_with_setup(
                [&shares[usize::from(participant)]],
                |signing_index, party, share| async move {
                    cggmp24::signing(execution_id, signing_index, &[participant], share)
                        .sign(&mut OsRng, party, &message)
                        .await
                },
            )
            .unwrap()
            .into_vec();
            assert!(outcomes[0].is_err(), "one CGGMP party must not sign");
        }
    }
}
