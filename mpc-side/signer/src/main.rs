//! One process identity, one encrypted party share. Startup is fail-closed:
//! an unconfigured process never binds a network socket.
use axum::{routing::get, Json, Router};
use std::path::PathBuf;
use wallet_mpc_signer::{
    phase6a_insecure_local_listener, ExecutionTombstones, SignerConfig, SignerStore,
    PROTOCOL_VERSION,
};
use wallet_mpc_transport::{serve, Capabilities, TlsConfig};

#[tokio::main]
async fn main() {
    let local_development = std::env::var("MPC_INSECURE_LOCAL_DEV").as_deref() == Ok("true");
    let required = |name: &str| {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("required signer configuration {name} missing"))
    };
    let party_id = required("MPC_PARTY_ID");
    let storage_directory = PathBuf::from(required("MPC_SHARE_STORAGE_DIR"));
    let trusted_peers = SignerConfig::parse_trusted_peers(&required("MPC_TRUSTED_PEERS"))
        .expect("trusted peer configuration is invalid");
    let config = SignerConfig {
        party_id: party_id.clone(),
        certificate_identity: required("MPC_CERTIFICATE_IDENTITY"),
        storage_directory: storage_directory.clone(),
        wrapping_key_path: PathBuf::from(required("MPC_WRAPPING_KEY_FILE")),
        supported_algorithms: required("MPC_SUPPORTED_ALGORITHMS")
            .split(',')
            .map(str::to_owned)
            .collect(),
        trusted_peers,
    };
    assert_eq!(
        config.certificate_identity,
        format!("spiffe://wallet-mpc/{party_id}"),
        "configured signer identity mismatch"
    );
    let algorithms = config.supported_algorithms.clone();
    let _store = SignerStore::open(config).expect("signer share store configuration is invalid");
    let _executions = ExecutionTombstones::open(storage_directory.join("executions"))
        .expect("signer execution tombstones unavailable");
    let metadata = Capabilities {
        signer_identity: party_id.clone(),
        protocol_version: PROTOCOL_VERSION.into(),
        supported_algorithms: algorithms,
        service_ready: true,
    };
    let app = Router::new().route(
        "/internal/v1/capabilities",
        get(move || {
            let metadata = metadata.clone();
            async move { Json(metadata) }
        }),
    );
    if local_development {
        let bind = phase6a_insecure_local_listener(true).unwrap();
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    } else {
        let tls = TlsConfig::from_env().expect("mTLS configuration required");
        let server = tls
            .server(&party_id)
            .expect("signer TLS identity/configuration invalid");
        let bind = required("MPC_BIND_ADDR")
            .parse()
            .expect("invalid bind address");
        serve(bind, server, app, "coordinator").await.unwrap();
    }
}
