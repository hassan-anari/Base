//! One process identity, one encrypted party share. Startup is fail-closed:
//! an unconfigured process never binds a network socket.
use axum::{routing::get, Json, Router};
use serde::Serialize;
use std::path::PathBuf;
use wallet_mpc_signer::{ExecutionTombstones, SignerConfig, SignerStore, PROTOCOL_VERSION};

#[derive(Serialize)]
struct Health {
    service: &'static str,
    party_id: String,
    protocol_version: &'static str,
    algorithms: [&'static str; 2],
}

async fn health(party_id: String) -> Json<Health> {
    Json(Health {
        service: "signer",
        party_id,
        protocol_version: PROTOCOL_VERSION,
        algorithms: ["CGGMP24_ECDSA_SECP256K1", "FROST_ED25519"],
    })
}

#[tokio::main]
async fn main() {
    let required = |name: &str| {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("required signer configuration {name} missing"))
    };
    let party_id = required("MPC_PARTY_ID");
    let storage_directory = PathBuf::from(required("MPC_SHARE_STORAGE_DIR"));
    let config = SignerConfig {
        party_id: party_id.clone(),
        certificate_identity: required("MPC_CERTIFICATE_IDENTITY"),
        storage_directory: storage_directory.clone(),
        wrapping_key_path: PathBuf::from(required("MPC_WRAPPING_KEY_FILE")),
        supported_algorithms: required("MPC_SUPPORTED_ALGORITHMS")
            .split(',')
            .map(str::to_owned)
            .collect(),
    };
    let _trusted_peers = required("MPC_TRUSTED_PEERS");
    let _store = SignerStore::open(config).expect("signer share store configuration is invalid");
    let _executions = ExecutionTombstones::open(storage_directory.join("executions"))
        .expect("signer execution tombstones unavailable");
    let app = Router::new().route("/health", get(move || health(party_id.clone())));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
