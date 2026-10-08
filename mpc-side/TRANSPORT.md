# Phase 6B secure transport

Transport only. Operational MPC signing remains disabled (`custody.E011` and the
runtime guard remain intact). CREATED is durable metadata, not a signature or a
distributed protocol execution. `signable` stays false, including when all three
signers are reachable. No DKG, share exchange, wallet provisioning, blockchain
assembly, CGGMP or FROST network execution is added here.

## Authentication boundary

The shared `wallet-mpc-transport` crate uses pinned rustls 0.23.45,
tokio-rustls 0.26.6, rustls-webpki chain verification and the ring provider.
See [rustls](https://github.com/rustls/rustls) and its
[security policy](https://github.com/rustls/rustls/blob/main/SECURITY.md) for
upstream security information. This change uses the standard verifier, with no
custom cryptographic verifier or certificate-validation bypass.

Servers and the Rust client permit only TLS 1.3. A configured private CA is the
only trust store; client certificates are mandatory. rustls verifies the peer
chain, validity, appropriate EKU and proof of possession. The Rust client also
verifies the configured DNS name. Only after TLS verification does application
authorization inspect the leaf certificate. Exactly one URI SAN is required:

| Certificate URI SAN | Authorized role |
| --- | --- |
| `spiffe://wallet-mpc/custody` | Coordinator custody API, including health |
| `spiffe://wallet-mpc/coordinator` | Signer internal capabilities |
| `spiffe://wallet-mpc/signer-a` | Signer A identity; no custody/internal API access |
| `spiffe://wallet-mpc/signer-b` | Signer B identity; no custody/internal API access |
| `spiffe://wallet-mpc/signer-c` | Signer C identity; no custody/internal API access |

Unknown or ambiguous URI identities fail closed. CN, JSON and HTTP headers do
not authorize a caller. Every server route and fallback is role protected.
Startup compares the local certificate identity to the configured service role;
Signer A cannot be configured as B using A's certificate. The coordinator checks
each destination's URI identity against its configured signer, independently of
DNS verification, before sending the capability request. Django verifies both
the coordinator hostname and its URI SAN before sending an HTTP request.

Django uses Python's standard verified HTTPSConnection with TLS 1.3 bounds,
the private CA and custody client certificate. It rejects redirects and caps
response size. Existing isolated `SelfHostedMpcAdapter` methods use this client;
the guarded production adapter factory still rejects `self_hosted_mpc`.

TLS session resumption is disabled, so each connection authenticates its peer
afresh. Rust connections have handshake/header/body lifetime and concurrency
bounds, and signer responses have a 16 KiB limit. Configuration is loaded at
startup; restart services after replacing CA/certificate files. Issuance and
rotation are operator responsibilities; automated PKI/CRL distribution is outside
this transport milestone. No service receives the CA private key.

## Network contracts

`GET /internal/v1/capabilities` exists only on a signer, requires a coordinator
certificate and returns exactly these non-secret fields:

```json
{"signer_identity":"signer-a","protocol_version":"phase6-v1","supported_algorithms":["CGGMP24_ECDSA","FROST_ED25519"],"service_ready":true}
```

Readiness means the configured signer storage and transport initialized. It does
not claim share presence, keyset activation or ability to sign. Algorithms name
the foundation's compatibility implementations.

Custody-only `GET /v1/health/quorum` actively connects to all three signer
destinations over mTLS and returns their verified capabilities. Any failed TLS,
identity or metadata check returns 503; success returns `healthy: 3` and
`signable: false`. It never starts signing. Existing session response fields and
UUID idempotency are unchanged.

## Configuration

Both Rust services require `MPC_BIND_ADDR`, `MPC_TLS_CA`, `MPC_TLS_CERT`,
`MPC_TLS_KEY`. The coordinator also requires `MPC_SIGNER_{A,B,C}_ADDR` (numeric
IP:port) and `MPC_SIGNER_{A,B,C}_SERVER_NAME` (certificate DNS name), plus private
`MPC_COORDINATOR_STATE`. Signers retain Phase 6A's party, trusted-peer, storage,
algorithm and wrapping-key settings. The fixed transport URI mapping does not
use the foundation's trusted-peer configuration to grant alternate API roles.

The explicit `MPC_INSECURE_LOCAL_DEV=true` option still binds only 127.0.0.1:8080.
TLS configuration failure never enters that branch. The integration environment
sets this option false for every process.

## Reproduce the real-process suite

From the repository root, in a Python virtual environment:

```sh
pip install -r backend-side/requirements.txt
export MPC_SIGNER_BACKEND=local_key CUSTODY_DEMO_MODE=true CUSTODY_TX_MODE=stub
export CUSTODY_INDEXER_MODE=stub LOCAL_KEY_ENCRYPTION_PASSPHRASE=transport-test-only
cargo build --locked --manifest-path mpc-side/Cargo.toml --bin wallet-mpc-coordinator --bin wallet-mpc-signer
pytest -v mpc-side/integration/test_network.py
```

The suite generates a fresh private test CA and distinct P-256 certificates,
then spawns one coordinator and three signer binaries with separate environment
configuration, ports, private wrapping keys and storage directories. Django is
initialized by pytest-django; actual adapter requests cross HTTPS sockets.
No in-process application or transport mock is used. Tests cover CREATED's
exact response, UUID retries/conflicts, all-process restart durability, all five
roles, absent/foreign/expired/unknown/ambiguous certificates, wrong trust store,
TLS 1.2, caller header spoofing, destination DNS and signer substitution.
The `mpc-network` GitHub Actions job runs this same suite. All original CI jobs
remain present.

## Reproduce separately mounted services

This development topology gives each service only its own identity and storage
mount. Signer storage/wrapping keys are never shared with another signer or the
coordinator. These four containers on one host are a development environment;
production failure-domain separation remains later deployment work.

```sh
export MPC_TRANSPORT_DIR="$PWD/work/phase6b-compose"
export MPC_DEV_UID="$(id -u)" MPC_DEV_GID="$(id -g)"
python mpc-side/integration/environment.py "$MPC_TRANSPORT_DIR" --compose
docker compose -f mpc-side/compose.transport.yaml up --build -d
python mpc-side/integration/probe.py "$MPC_TRANSPORT_DIR"
docker compose -f mpc-side/compose.transport.yaml restart
python mpc-side/integration/probe.py "$MPC_TRANSPORT_DIR"
docker compose -f mpc-side/compose.transport.yaml down
```

Use a new output directory for each PKI generation. Keys and state are ignored
under `work/`; no test keys are committed. Use the same Python environment and
demo settings as the suite above. For a managed environment with a session
proxy, supply its CA bundle as a BuildKit secret to networked Docker build steps
according to that environment's runtime instructions.

```text
Django custody cert -> localhost:8443 [coordinator 172.28.6.11]
                    -> signer-a 172.28.6.12:8443 -> /internal/v1/capabilities
                    -> signer-b 172.28.6.13:8443 -> /internal/v1/capabilities
                    -> signer-c 172.28.6.14:8443 -> /internal/v1/capabilities
```

Every arrow uses TLS 1.3 mTLS; only the coordinator port is published to host
loopback. The Docker transport network is internal. Each signer returns only
non-secret metadata.
