//! TLS 1.3 only, private-CA mTLS. Roles are extracted only after rustls has
//! verified the peer chain, validity, EKU and proof of key possession.
use anyhow::{ensure, Context, Result};
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    Router,
};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::{extensions::GeneralName, prelude::*};

pub const PROTOCOL_VERSION: &str = "phase6-v1";
pub const ROLES: [&str; 5] = ["custody", "coordinator", "signer-a", "signer-b", "signer-c"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity(String);

impl PeerIdentity {
    pub fn role(&self) -> &str {
        &self.0
    }
}

/// CN, headers and request JSON are never identity sources. Require exactly
/// one URI SAN and an exact, fixed mapping; ambiguous identities fail closed.
pub fn certificate_identity(cert: &CertificateDer<'_>) -> Result<PeerIdentity> {
    let (remaining, cert) = X509Certificate::from_der(cert.as_ref())?;
    ensure!(remaining.is_empty(), "trailing certificate data");
    let san = cert
        .subject_alternative_name()?
        .context("URI SAN required")?;
    let uris: Vec<_> = san
        .value
        .general_names
        .iter()
        .filter_map(|name| {
            if let GeneralName::URI(uri) = name {
                Some(*uri)
            } else {
                None
            }
        })
        .collect();
    ensure!(uris.len() == 1, "exactly one identity URI required");
    let role = uris[0]
        .strip_prefix("spiffe://wallet-mpc/")
        .context("unknown identity domain")?;
    ensure!(ROLES.contains(&role), "unknown certificate role");
    Ok(PeerIdentity(role.to_owned()))
}

fn certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!certs.is_empty(), "certificate file is empty");
    Ok(certs)
}

#[derive(Clone)]
pub struct TlsConfig {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

pub fn required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("required configuration {name} missing"))
}

impl TlsConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            ca: required("MPC_TLS_CA")?,
            cert: required("MPC_TLS_CERT")?,
            key: required("MPC_TLS_KEY")?,
        })
    }

    fn material(
        &self,
        role: &str,
    ) -> Result<(
        RootCertStore,
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
    )> {
        let mut roots = RootCertStore::empty();
        for cert in certificates(&self.ca)? {
            roots.add(cert)?;
        }
        let certs = certificates(&self.cert)?;
        ensure!(
            certificate_identity(&certs[0])?.role() == role,
            "local certificate role mismatch"
        );
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&self.key)?))?
            .context("private key missing")?;
        Ok((roots, certs, key))
    }

    pub fn server(&self, role: &str) -> Result<Arc<ServerConfig>> {
        let (roots, certs, key) = self.material(role)?;
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Do not resume sessions with stale client authentication.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Arc::new(config))
    }

    pub fn client(&self, role: &str) -> Result<Arc<ClientConfig>> {
        let (roots, certs, key) = self.material(role)?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Arc::new(config))
    }
}

async fn authorize(
    request: Request,
    next: Next,
    allowed: &'static str,
) -> Result<Response, StatusCode> {
    if request
        .extensions()
        .get::<PeerIdentity>()
        .map(PeerIdentity::role)
        != Some(allowed)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

/// Every route (including health and unknown routes) is role protected.
pub async fn serve(
    bind: SocketAddr,
    config: Arc<ServerConfig>,
    app: Router,
    allowed: &'static str,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    let acceptor = TlsAcceptor::from(config);
    let slots = Arc::new(Semaphore::new(256));
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(stream)) = timeout(Duration::from_secs(5), acceptor.accept(socket)).await
            else {
                return;
            };
            let Some(cert) = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
            else {
                return;
            };
            let Ok(peer) = certificate_identity(cert) else {
                return;
            };
            let app = app
                .layer(middleware::from_fn(move |request, next| {
                    authorize(request, next, allowed)
                }))
                .layer(axum::Extension(peer));
            let mut http = hyper::server::conn::http1::Builder::new();
            http.timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5));
            // Bound idle/body connections as well as handshake resource use.
            let _ = timeout(
                Duration::from_secs(15),
                http.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app)),
            )
            .await;
        });
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub signer_identity: String,
    pub protocol_version: String,
    pub supported_algorithms: Vec<String>,
    pub service_ready: bool,
}

#[derive(Clone)]
pub struct SignerClient {
    tls: Arc<ClientConfig>,
    // Transport destinations are operator configuration, never request input.
    targets: Vec<(String, SocketAddr, String)>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl SignerClient {
    pub fn from_env(tls: &TlsConfig) -> Result<Self> {
        let mut targets = Vec::new();
        for (role, suffix) in [("signer-a", "A"), ("signer-b", "B"), ("signer-c", "C")] {
            targets.push((
                role.to_owned(),
                required(&format!("MPC_SIGNER_{suffix}_ADDR"))?.parse()?,
                required(&format!("MPC_SIGNER_{suffix}_SERVER_NAME"))?,
            ));
        }
        Ok(Self {
            tls: tls.client("coordinator")?,
            targets,
        })
    }

    pub async fn capabilities(&self) -> Result<Vec<Capabilities>> {
        let mut output = Vec::new();
        for (role, addr, name) in &self.targets {
            output.push(timeout(Duration::from_secs(5), self.fetch(role, *addr, name)).await??);
        }
        Ok(output)
    }

    async fn fetch(&self, role: &str, addr: SocketAddr, name: &str) -> Result<Capabilities> {
        let socket = tokio::net::TcpStream::connect(addr).await?;
        let stream = TlsConnector::from(self.tls.clone())
            .connect(ServerName::try_from(name.to_owned())?, socket)
            .await?;
        let cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .context("server certificate missing")?;
        ensure!(
            certificate_identity(cert)?.role() == role,
            "destination signer identity mismatch"
        );
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let _task = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        // Abort the HTTP driver even when a response or bounded body read fails.
        let result = async {
            let request = hyper::Request::builder()
                .uri("/internal/v1/capabilities")
                .header("Host", name)
                .body(Empty::<Bytes>::new())?;
            let response = sender.send_request(request).await?;
            ensure!(
                response.status() == StatusCode::OK,
                "signer capability request rejected"
            );
            let body = Limited::new(response.into_body(), 16 * 1024)
                .collect()
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .to_bytes();
            let metadata: Capabilities = serde_json::from_slice(&body)?;
            ensure!(
                metadata.signer_identity == role
                    && metadata.protocol_version == PROTOCOL_VERSION
                    && metadata.service_ready,
                "signer capability contract mismatch"
            );
            ensure!(
                !metadata.supported_algorithms.is_empty()
                    && metadata
                        .supported_algorithms
                        .iter()
                        .all(|a| matches!(a.as_str(), "CGGMP24_ECDSA" | "FROST_ED25519")),
                "invalid capability algorithms"
            );
            Ok(metadata)
        }
        .await;
        result
    }
}
