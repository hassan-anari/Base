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
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
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
    let certs = CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "certificate file is empty");
    Ok(certs)
}

#[derive(Clone)]
pub struct TlsConfig {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

/// Verify the original custody machine request across the coordinator hop.
/// Uses the same private CA and client-auth identity as the mTLS boundary.
pub struct CustodyRequestVerifier {
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
}

impl CustodyRequestVerifier {
    pub fn new(config: &TlsConfig) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in certificates(&config.ca)? {
            roots.add(cert)?;
        }
        Ok(Self {
            verifier: WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::new(rustls::crypto::ring::default_provider()),
            )
            .build()?,
        })
    }

    pub fn verify(&self, message: &[u8], chain: &[Vec<u8>], signature: &[u8]) -> Result<()> {
        ensure!(
            !chain.is_empty()
                && chain.len() <= 5
                && chain.iter().all(|c| !c.is_empty() && c.len() <= 8192)
                && (8..=80).contains(&signature.len()),
            "invalid custody request credential bounds"
        );
        let leaf = CertificateDer::from(chain[0].as_slice());
        let intermediates: Vec<_> = chain[1..]
            .iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect();
        self.verifier.verify_client_cert(
            &leaf,
            &intermediates,
            rustls::pki_types::UnixTime::now(),
        )?;
        ensure!(
            certificate_identity(&leaf)?.role() == "custody",
            "custody identity required"
        );
        let (_, cert) = X509Certificate::from_der(leaf.as_ref())?;
        let public = cert.public_key();
        ensure!(
            public.algorithm.algorithm.to_id_string() == "1.2.840.10045.2.1"
                && public
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok())
                    .is_some_and(|oid| oid.to_id_string() == "1.2.840.10045.3.1.7"),
            "custody child authorization requires P-256 identity"
        );
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            public.subject_public_key.data.as_ref(),
        )
        .verify(message, signature)
        .map_err(|_| anyhow::anyhow!("original custody request signature mismatch"))
    }
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
        let key = PrivateKeyDer::from_pem_file(&self.key)?;
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

/// Non-secret peer rejection diagnostics; never includes response/proof bodies.
#[derive(Debug)]
pub struct PeerHttpStatus(pub StatusCode);
impl std::fmt::Display for PeerHttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signer request rejected: HTTP {}", self.0.as_u16())
    }
}
impl std::error::Error for PeerHttpStatus {}

async fn authorize(
    request: Request,
    next: Next,
    allowed: &'static [&'static str],
) -> Result<Response, StatusCode> {
    if !request
        .extensions()
        .get::<PeerIdentity>()
        .map(PeerIdentity::role)
        .is_some_and(|role| allowed.contains(&role))
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
    let roles: &'static [&'static str] = match allowed {
        "custody" => &["custody"],
        "coordinator" => &["coordinator"],
        _ => anyhow::bail!("unknown listener authorization"),
    };
    serve_roles(bind, config, app, roles).await
}

pub async fn serve_roles(
    bind: SocketAddr,
    config: Arc<ServerConfig>,
    app: Router,
    allowed: &'static [&'static str],
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
                Duration::from_secs(45),
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
        Self::from_env_for(tls, "coordinator")
    }

    pub fn from_env_for(tls: &TlsConfig, local_role: &str) -> Result<Self> {
        ensure!(ROLES.contains(&local_role), "unknown local role");
        let mut targets = Vec::new();
        for (role, suffix) in [("signer-a", "A"), ("signer-b", "B"), ("signer-c", "C")] {
            targets.push((
                role.to_owned(),
                required(&format!("MPC_SIGNER_{suffix}_ADDR"))?.parse()?,
                required(&format!("MPC_SIGNER_{suffix}_SERVER_NAME"))?,
            ));
        }
        Ok(Self {
            tls: tls.client(local_role)?,
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

    pub async fn request(
        &self,
        role: &str,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let (_, addr, name) = self
            .targets
            .iter()
            .find(|(r, _, _)| r == role)
            .context("unconfigured signer destination")?;
        timeout(
            Duration::from_secs(
                if path.starts_with("/internal/v1/cggmp/aux/")
                    || path.starts_with("/internal/v1/cggmp/sign/")
                {
                    30
                } else {
                    5
                },
            ),
            self.exchange(role, *addr, name, method, path, body),
        )
        .await?
    }

    async fn fetch(&self, role: &str, _addr: SocketAddr, _name: &str) -> Result<Capabilities> {
        let body = self
            .request(role, "GET", "/internal/v1/capabilities", vec![])
            .await?;
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

    async fn exchange(
        &self,
        role: &str,
        addr: SocketAddr,
        name: &str,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // Auxiliary/signing proofs need more space than keygen controls. These RPCs
        // enqueue bounded messages; expensive crypto runs in asynchronous workers.
        let limit = if path.starts_with("/internal/v1/cggmp/aux/")
            || path.starts_with("/internal/v1/cggmp/sign/")
        {
            1024 * 1024
        } else {
            64 * 1024
        };
        ensure!(body.len() <= limit, "protocol request too large");
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
        let request = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", name)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))?;
        let response = sender.send_request(request).await?;
        if response.status() != StatusCode::OK {
            return Err(PeerHttpStatus(response.status()).into());
        }
        let body = Limited::new(response.into_body(), limit)
            .collect()
            .await
            .map_err(|_| anyhow::anyhow!("invalid signer response"))?
            .to_bytes();
        Ok(body.to_vec())
    }
}

/// Detached receipts use the signer's existing P-256 identity key, with its
/// public identity pinned separately at custody. No coordinator certificate or
/// coordinator-provided trust material participates in receipt verification.
pub struct ReceiptIdentity {
    key: ring::signature::EcdsaKeyPair,
}
impl ReceiptIdentity {
    pub fn new(config: &TlsConfig, party: &str) -> Result<Self> {
        use ring::signature::KeyPair;
        ensure!(
            party.starts_with("signer-") && ROLES.contains(&party),
            "signer identity required"
        );
        let (_, certs, secret) = config.material(party)?;
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            secret.secret_der(),
            &ring::rand::SystemRandom::new(),
        )
        .map_err(|_| anyhow::anyhow!("P-256 signer identity key required"))?;
        let (_, cert) = X509Certificate::from_der(certs[0].as_ref())?;
        ensure!(
            key.public_key().as_ref() == cert.public_key().subject_public_key.data.as_ref(),
            "receipt key must match local signer certificate"
        );
        Ok(Self { key })
    }
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .key
            .sign(&ring::rand::SystemRandom::new(), message)
            .map_err(|_| anyhow::anyhow!("signer receipt signing failed"))?
            .as_ref()
            .to_vec())
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use ring::signature::KeyPair;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            self.key.public_key().as_ref(),
        )
        .verify(message, signature)
        .map_err(|_| anyhow::anyhow!("invalid own signer receipt"))
    }
}
