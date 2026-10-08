use std::{path::PathBuf, sync::Arc};
use wallet_mpc_coordinator::{app, network_app, phase6a_insecure_local_listener, DurableStore};
use wallet_mpc_transport::{required, serve, SignerClient, TlsConfig};
#[tokio::main]
async fn main() {
    let local_development = std::env::var("MPC_INSECURE_LOCAL_DEV").as_deref() == Ok("true");
    let path = std::env::var_os("MPC_COORDINATOR_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/wallet-mpc/coordinator.json"));
    let store = Arc::new(DurableStore::open(path).expect("open durable coordinator state"));
    if local_development {
        let bind = phase6a_insecure_local_listener(true).unwrap();
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        axum::serve(listener, app(store)).await.unwrap();
    } else {
        let tls = TlsConfig::from_env().expect("mTLS configuration required");
        let server = tls
            .server("coordinator")
            .expect("coordinator TLS configuration invalid");
        let signers =
            SignerClient::from_env(&tls).expect("authenticated signer destinations required");
        let bind = required("MPC_BIND_ADDR")
            .unwrap()
            .parse()
            .expect("invalid bind address");
        serve(bind, server, network_app(store, signers), "custody")
            .await
            .unwrap();
    }
}
