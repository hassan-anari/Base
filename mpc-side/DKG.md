# Phase 6C.1: distributed FROST Ed25519 DKG

Three independent `wallet-mpc-signer` processes (`signer-a`, `signer-b`,
`signer-c`) run upstream `frost-ed25519 =3.0.0` `part1`, `part2`, and `part3`.
The fixed FROST identifiers are 1, 2, and 3; the threshold is 2. There is no
dealer, key reconstruction, network signing or custom threshold cryptography.
The existing cryptographic compatibility tests remain intact. Phase 6C.2 adds
public aggregation material persistence and authenticated service signing on
top of this DKG; see [SIGNING.md](SIGNING.md), including legacy public-material recovery.

## Run the acceptance gate

From the repository root, using the pinned Rust toolchain and Python environment:

```sh
pip install -r backend-side/requirements.txt
export DJANGO_SECRET_KEY=dkg-test-only
export MPC_SIGNER_BACKEND=local_key CUSTODY_DEMO_MODE=true CUSTODY_TX_MODE=stub
export CUSTODY_INDEXER_MODE=stub LOCAL_KEY_ENCRYPTION_PASSPHRASE=dkg-test-only
cargo build --locked --manifest-path mpc-side/Cargo.toml --bin wallet-mpc-coordinator --bin wallet-mpc-signer --example frost_round1_fixture
pytest -v mpc-side/integration/test_dkg.py mpc-side/integration/test_network.py
cargo fmt --manifest-path mpc-side/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path mpc-side/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --locked --manifest-path mpc-side/Cargo.toml --workspace
```

The DKG suite uses fresh private CA material, distinct client/server credentials,
separate wrapping keys, ports and storage directories. Completion always uses
three actual signer binaries; no simulated party or mocked signer is involved.
The `frost_round1_fixture` example emits only an upstream **public** round1 package
for hostile envelope injection; it never participates in successful DKG.
Tests independently inspect each test store without reconstructing a private key.
The `mpc-network` CI job runs both DKG and existing transport suites.

## Configuration and authorization

Use the configuration generator and isolated mounts in [TRANSPORT.md](TRANSPORT.md).
Each signer now also needs `MPC_SIGNER_{A,B,C}_ADDR` and
`MPC_SIGNER_{A,B,C}_SERVER_NAME` for direct connections. Destinations are operator
configuration, never supplied by a DKG request. Every connection checks both DNS
and the expected leaf URI identity. Every signer needs these exact peer mappings:

```text
MPC_TRUSTED_PEERS=spiffe://wallet-mpc/coordinator=coordinator,spiffe://wallet-mpc/signer-a=signer-a,spiffe://wallet-mpc/signer-b=signer-b,spiffe://wallet-mpc/signer-c=signer-c
```

| Route | Required verified certificate role | Contents |
| --- | --- | --- |
| Coordinator `/v1/dkg-sessions` and subroutes | custody | Public control/metadata |
| Signer `/internal/v1/dkg/{action}` | coordinator | Public control/receipt |
| Signer `/internal/v1/dkg/message` | signer peer | Directed protocol package |
| Signer `/internal/v1/capabilities` | coordinator | Public readiness |

Custody and coordinator certificates cannot access the directed message route.
Signer certificates cannot access controls or custody APIs. Claimed sender and
recipient are constraints checked against authenticated identity and local state,
never identity sources. TLS and exact-envelope rejection precede accepting a
package. Session, keyset, execution, algorithm, sender, recipient, round and fixed
sequence are bound by the existing transcript digest. Exact and conflicting
replays are rejected. Each peer compares a digest of all three public round1
packages before accepting round2, so divergent round1 views cannot complete.
Private round2 packages travel directly over TLS 1.3 mTLS to their named recipients.
The coordinator neither receives nor relays plaintext round packages.

## Public lifecycle

1. Custody creates public metadata with `POST /v1/dkg-sessions`:

   ```json
   {"session_id":"<fresh UUID>","execution_id":"<fresh UUID>","keyset_id":"<fresh UUID>","algorithm":"FROST_ED25519","curve":"ed25519","scope":"SOLANA","derivation_version":"frost_keyset_v1","threshold":2,"party_count":3,"participants":["signer-a","signer-b","signer-c"]}
   ```

   The UUIDs must be non-nil. The participant order and algorithm parameters are
   fixed. Exact metadata retries are idempotent; conflicting session, keyset or
   execution reuse returns 409. CGGMP metadata compatibility remains, but the
   network driver executes only this FROST contract.
2. `POST /v1/dkg-sessions/{session_id}/execute` durably enters `IN_PROGRESS`,
   starts each signer, directs each to send public round1 and private directed
   round2 packages, then asks every signer to finalize. Round state lives only
   in its owning signer process. Round controls are single-use; dispatch failure
   is not automatically retried with new randomness or a replacement share.
3. Each signer verifies upstream `part3`, persists its key package, reloads it,
   confirms its identifier, threshold and public key, and returns a public receipt
   with the exact request, party, format version, public group key and durability.
4. The coordinator enters `COMPLETED` only with all three correctly bound,
   durable receipts reporting the same public key. It stores those receipts,
   group key and public result fingerprint. `GET /v1/dkg-sessions/{session_id}`,
   `GET /v1/keysets/{keyset_id}` and `/public-key` expose only public metadata.

This is key generation only. `scope: SOLANA` is the existing public keyset
namespace; no Solana address provisioning, transaction assembly or signing occurs.
Coordinator executions are serialized and signer active states are bounded.
Transport requests and responses are bounded to 64 KiB with existing connection
limits. Single-use rounds intentionally favor abort/reconciliation over delivery
retry after an uncertain network response.

## Encrypted local persistence and restart

`SignerStore` stores one immutable `{keyset_id}.share.enc` at each signer. The
existing AES-256-GCM wrapper authenticates keyset, party, algorithm and storage
version; the encrypted payload additionally binds the exact DKG request and
explicit share format version 1 around upstream serialized `KeyPackage` bytes.
There is no plaintext share file. Creation uses the existing create-once atomic
link, file fsync, directory fsync and durability confirmation. Exact persistence
retries compare existing plaintext internally and never replace ciphertext;
conflicting key packages fail. Each signer receives only its own wrapping key.
Upstream secret packages and owning stored-share buffers are zeroized when dropped.
No secret fields are part of control responses, coordinator state or logs.

On startup a completed record must successfully decrypt and validate its own
package, exact binding, party identifier, threshold, version and recorded public
key. Corruption, a wrong wrapping key or a transplanted package fails startup.
The restart acceptance test stops all three signers and the coordinator, starts
them again, verifies the same group key at each signer, then repeats execute.
Completed execute only reads three persisted receipts; it dispatches no new rounds
and leaves the encrypted files and execution tombstones byte-for-byte unchanged.

An ACTIVE execution tombstone becomes `ABORTED_AFTER_RESTART`. A signer with lost
ephemeral state refuses start/round/finalize for that keyset and execution. Its
public DKG record becomes `ABORTED_AFTER_RESTART`, or `RECONCILIATION_REQUIRED` if
an encrypted package exists but local completion was not acknowledged. It never
regenerates a share for that reserved keyset. Coordinator `IN_PROGRESS` records
become `RECONCILIATION_REQUIRED` at restart. Network failures trigger best-effort
explicit signer abort and retain reconciliation status, never `COMPLETED`.

`POST /v1/dkg-sessions/{session_id}/reconcile` performs only public receipt reads.
It completes the coordinator record only if all three signers already report the
same durable completed result. Partial persistence or lost ephemeral state cannot
pass this gate. A signer whose encrypted package exists without a completed local
record stays unavailable for that result pending operator investigation; this
milestone does not automatically repair that ambiguity. Preserve the old records
and use a fresh session, execution **and keyset** for a new DKG after abort. Never
remove tombstones or overwrite an existing share to retry.

## Acceptance coverage and boundaries

The suite covers successful three-process DKG, identical public keys, distinct
local encrypted packages, absent coordinator secrets, complete restart and no
new DKG for a completed keyset; valid upstream round1 replay/conflicting duplicate
injection; wrong party/session/execution/keyset/recipient/protocol/round/sequence/
digest rejection; role authorization; destination DNS/role mismatch; missing
signer; conflicting keyset/execution reuse; lost ephemeral state; partial
persistence; invalid encrypted packages; and private parse errors without echo.
Existing TLS negative tests and Django's `custody.E011` remain unchanged.

Independent production hosts, operator PKI lifecycle, automated local recovery of
uncertain completion, signing, provisioning and production cutover remain separate
work. The existing indirect `atomic-polyfill` maintenance warning remains documented
in [SELF_HOSTED_MPC.md](../SELF_HOSTED_MPC.md); dependency versions are unchanged.
