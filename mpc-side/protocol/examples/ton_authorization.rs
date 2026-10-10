//! Public-only diagnostic/vector cross-check; never signs or accepts private material.
use anyhow::Result;
use serde::Deserialize;
use std::io::{self, Read};
use wallet_mpc_protocol::ton::TonAuthorization;
#[derive(Deserialize)]
struct Input {
    authorization: TonAuthorization,
    public_key: String,
    source: String,
    asset: String,
}
fn main() -> Result<()> {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    let input: Input = serde_json::from_str(&text)?;
    let hash = input
        .authorization
        .signing_hash(&input.public_key, &input.source, &input.asset)?;
    println!("{}", wallet_mpc_protocol::dkg::hex(&hash));
    Ok(())
}
