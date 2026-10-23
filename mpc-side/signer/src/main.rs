//! One process identity, one encrypted party share. Startup is fail-closed:
//! an unconfigured process never binds a network socket.
use axum::{middleware, routing::get, Json, Router};
use std::path::PathBuf;
use wallet_mpc_signer::{
    phase6a_insecure_local_listener, ExecutionTombstones, SignerConfig, SignerStore,
    PROTOCOL_VERSION,
};
use wallet_mpc_transport::{serve_roles, Capabilities, PeerIdentity, SignerClient, TlsConfig};

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
    let store =
        SignerStore::open(config.clone()).expect("signer share store configuration is invalid");
    let executions = ExecutionTombstones::open(storage_directory.join("executions"))
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
        let app = app.route_layer(middleware::from_fn(
            |axum::Extension(peer): axum::Extension<PeerIdentity>,
             request: axum::extract::Request,
             next: middleware::Next| async move {
                if peer.role() != "coordinator" {
                    return Err(axum::http::StatusCode::FORBIDDEN);
                }
                Ok(next.run(request).await)
            },
        ));
        let peers =
            SignerClient::from_env_for(&tls, &party_id).expect("DKG peer destinations required");
        let dkg =
            wallet_mpc_signer::dkg::DkgService::open(store, executions.clone(), peers.clone())
                .expect("DKG recovery failed");
        let cggmp = wallet_mpc_signer::cggmp::CggmpService::open(
            config.clone(),
            executions.clone(),
            peers.clone(),
        )
        .expect("CGGMP keygen recovery failed");
        let auxiliary = wallet_mpc_signer::cggmp_aux::AuxService::open(
            config,
            executions.clone(),
            peers.clone(),
        )
        .expect("CGGMP auxiliary recovery failed");
        // Existing root-only TLS identities remain supported. HD dedication has
        // no unsigned fallback: it requires a usable pinned receipt identity.
        let receipt_identity = match wallet_mpc_transport::ReceiptIdentity::new(&tls, &party_id) {
            Ok(identity) => Some(identity),
            Err(_) => {
                eprintln!("HD receipt identity unavailable; new HD dedication is disabled");
                None
            }
        };
        let hd = wallet_mpc_signer::hd::HdService::open(
            storage_directory.clone(),
            party_id.clone(),
            auxiliary.clone(),
            wallet_mpc_transport::CustodyRequestVerifier::new(&tls)
                .expect("custody request trust unavailable"),
            receipt_identity,
        )
        .expect("CGGMP HD evidence recovery failed");
        let cggmp_signing = wallet_mpc_signer::cggmp_sign::SigningService::open(
            storage_directory.clone(),
            party_id.clone(),
            executions.clone(),
            auxiliary.clone(),
            hd.clone(),
            peers,
        )
        .expect("CGGMP signing recovery failed");
        let signing = wallet_mpc_signer::sign::SigningService::open(
            dkg.clone(),
            executions,
            storage_directory,
            party_id.clone(),
        )
        .expect("signing recovery failed");
        let app = app
            .merge(wallet_mpc_signer::dkg::router(dkg))
            .merge(wallet_mpc_signer::sign::router(signing))
            .merge(wallet_mpc_signer::cggmp::router(cggmp))
            .merge(wallet_mpc_signer::cggmp_aux::router(auxiliary))
            .merge(wallet_mpc_signer::cggmp_sign::router(cggmp_signing))
            .merge(wallet_mpc_signer::hd::router(hd));
        let server = tls
            .server(&party_id)
            .expect("signer TLS identity/configuration invalid");
        let bind = required("MPC_BIND_ADDR")
            .parse()
            .expect("invalid bind address");
        serve_roles(
            bind,
            server,
            app,
            &["coordinator", "signer-a", "signer-b", "signer-c"],
        )
        .await
        .unwrap();
    }
}
