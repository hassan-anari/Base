//! The coordinator owns only public metadata and routing state. TLS termination
//! MUST require a client certificate (deployment/TLS proxy or service mesh).
use axum::{routing::get, Json, Router};
use serde::Serialize;
#[derive(Serialize)]
struct Health {
    service: &'static str,
    protocol: &'static str,
}
async fn health() -> Json<Health> {
    Json(Health {
        service: "coordinator",
        protocol: "phase6-v1",
    })
}
#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
