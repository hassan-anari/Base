//! One process identity, one encrypted party share. Protocol endpoints are
//! intentionally private and must be protected by certificate-to-party mTLS.
use axum::{routing::get, Json, Router};
use serde::Serialize;
use wallet_mpc_signer::PROTOCOL_VERSION;
#[derive(Serialize)]
struct Health {
    service: &'static str,
    party_id: String,
    protocol_version: &'static str,
    algorithms: [&'static str; 2],
}
async fn health() -> Json<Health> {
    Json(Health {
        service: "signer",
        party_id: std::env::var("MPC_PARTY_ID").unwrap_or_else(|_| "UNCONFIGURED".into()),
        protocol_version: PROTOCOL_VERSION,
        algorithms: ["CGGMP24_ECDSA_SECP256K1", "FROST_ED25519"],
    })
}
#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
