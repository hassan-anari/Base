use std::{path::PathBuf, sync::Arc};
use wallet_mpc_coordinator::{app, phase6a_insecure_local_listener, DurableStore};
#[tokio::main]
async fn main() {
    let local_development = std::env::var("MPC_INSECURE_LOCAL_DEV").as_deref() == Ok("true");
    let bind = phase6a_insecure_local_listener(local_development)
        .expect("production coordinator startup requires authenticated transport (Phase 6B)");
    let path = std::env::var_os("MPC_COORDINATOR_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/wallet-mpc/coordinator.json"));
    let store = Arc::new(DurableStore::open(path).expect("open durable coordinator state"));
    let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
    axum::serve(listener, app(store)).await.unwrap();
}
