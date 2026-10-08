//! Acceptance helper: encode only public commitments and a public message.
use frost_ed25519 as frost;
use serde::Deserialize;
use std::{collections::BTreeMap, io::Read};
#[derive(Deserialize)]
struct Input {
    commitments: BTreeMap<String, Vec<u8>>,
    message: Vec<u8>,
}
fn main() {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    let commitments = input
        .commitments
        .into_iter()
        .map(|(party, bytes)| {
            (
                wallet_mpc_protocol::dkg::identifier(&party).unwrap(),
                frost::round1::SigningCommitments::deserialize(&bytes).unwrap(),
            )
        })
        .collect();
    let package = frost::SigningPackage::new(commitments, &input.message);
    println!(
        "{}",
        serde_json::to_string(&package.serialize().unwrap()).unwrap()
    );
}
