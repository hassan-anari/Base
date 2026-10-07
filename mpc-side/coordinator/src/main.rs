use std::{path::PathBuf, sync::Arc};
use wallet_mpc_coordinator::{app, DurableStore};
#[tokio::main]
async fn main() {
    let path = std::env::var_os("MPC_COORDINATOR_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/wallet-mpc/coordinator.json"));
    let store = Arc::new(DurableStore::open(path).expect("open durable coordinator state"));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app(store)).await.unwrap();
}
