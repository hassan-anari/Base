# Phase 6D: distributed CGGMP work in progress

**Phase 6D is INCOMPLETE.** This branch implements distributed CGGMP key
**generation**, not a completed auxiliary protocol or service ECDSA signing.
Production signing, Django `custody.E011`, and runtime signing guards remain
unchanged. No Phase 6E work, transaction assembly, or broadcasting is included.

Three independent signer binaries run the pinned `cggmp24 =0.7.0-alpha.3`
threshold keygen protocol with `OsRng`, threshold 2, and party count 3. The
existing pinned `round-based =0.4.1` interface connects to direct TLS 1.3 mTLS
peer delivery. No simulated parties, dealer, or private-key reconstruction are
used by this service implementation. Existing FROST services remain available.

## API and identity

Custody creates a session through `POST /v1/dkg-sessions` using the existing
DkgRequest contract: CGGMP24_ECDSA, secp256k1, scope EVM or TRON,
derivation_version cggmp_hd_v1, fixed ordered signer-a/b/c participants, and
non-nil session, execution, and keyset UUIDs. The derivation version is metadata;
this change does not add child-key derivation.

`POST /v1/dkg-sessions/{id}/execute` durably claims one execution and returns
IN_PROGRESS immediately. The coordinator prepares all inboxes before starting
protocol workers, then polls authenticated public reports. It does not hold its
global store mutex or the FROST driver mutex during CGGMP execution. Distinct
keysets can execute concurrently; duplicate calls cannot launch another worker.
GET returns the authoritative state. All matching, durable public receipts
advance to **KEYGEN_COMPLETED**, explicitly separate from COMPLETED.

Signer `/internal/v1/cggmp/keygen/{prepare,start,report,abort}` accepts only the
verified coordinator certificate. `/internal/v1/cggmp/keygen/message` accepts
only signer certificates, and the sender must match the exact authenticated
party. The envelope binds the complete immutable request hash, protocol phase,
logical session, crypto execution, keyset, sender, recipient, upstream round,
sequence, broadcast/p2p mode, and payload. Repeated sequences, repeated sender
rounds, conflicting messages, stale executions and alternate bindings fail
closed. Directed protocol messages never pass through the coordinator.

The upstream public Round1 fixture example only emits a public commitment for
hostile-envelope tests. It terminates on its first outgoing broadcast, owns no
completed key share and does not run a protocol simulation.

## Storage and recovery

Each signer stores only its own upstream IncompleteKeyShare in an immutable
AES-256-GCM encrypted `.share.enc` file, using its independent wrapping key.
Its encrypted CoreBlob discriminator is CGGMP24_CORE_V1; the complete original
DkgRequest is inside the authenticated blob. On load, the existing storage
layer validates algorithm, protocol and format versions, keyset and party. The
upstream validated core then verifies cryptographic shape; local checks enforce
party index, 2-of-3 threshold, public shares and group key against the public
record. Serialization buffers and protocol envelope payloads are zeroized.

Only the compressed group key, public verification shares and durable receipts
enter coordinator storage. No private share, prime, auxiliary secret or private
key is returned or logged. Upstream keygen produces a core share without CGGMP
auxiliary information, and that core **cannot sign** through the current driver.

Execution tombstones and reservations precede keygen randomness. Lost ephemeral
state never recreates a protocol execution. Signer restart changes unfinished
records to RECONCILIATION_REQUIRED. Coordinator restart also marks dispatched
unfinished work ambiguous. `/reconcile` only queries existing public reports;
it can recover three already persisted matching core receipts without starting
new protocol rounds. Failed or conflicting recovery remains unresolved.
Completed core metadata is revalidated when coordinator storage opens. A
completed execute retry returns the same public result even with signers down.
Corrupt ciphertext, a wrong wrapping key or altered completion metadata fails
restart validation.

Messages have the existing 64 KiB HTTP bound, a 48 KiB decoded-payload bound,
32-entry per-execution inbox, and 64-message sender budget. There are at most
eight active signer keygens. Peer HTTP operations retain the five-second
transport timeout; signer keygen has a 120-second deadline and coordinator
orchestration 125 seconds. These limits are for keygen and must not be reused
unchanged for the substantially heavier auxiliary protocol.

## Reproduction

Use the private development PKI/topology in [TRANSPORT.md](TRANSPORT.md):

```sh
cargo build --locked --manifest-path mpc-side/Cargo.toml --bin wallet-mpc-coordinator --bin wallet-mpc-signer --example frost_round1_fixture --example frost_signing_package --example cggmp_round1_fixture
pytest -v mpc-side/integration/test_cggmp.py
pytest -v mpc-side/integration/test_network.py mpc-side/integration/test_dkg.py mpc-side/integration/test_signing.py
cargo fmt --manifest-path mpc-side/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path mpc-side/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --locked --manifest-path mpc-side/Cargo.toml --workspace
```

All acceptance cases use real service binaries, independent certificates and
wrapping keys, and actual TLS network requests. Test collection alone is not
successful execution. Current verified run results belong in the draft PR;
passing these keygen tests does not establish Phase 6D PASS.

## Remaining requirements in the same task and PR

- Actual distributed auxiliary generation with secure OS randomness and fresh
  cryptographic primes; immutable encrypted auxiliary storage and validated reload.
- Full interactive 32-byte prehashed threshold ECDSA signing using completed
  CGGMP key shares, for A+B, A+C and B+C, with unavailable-A B+C execution.
- Canonical low-s secp256k1 signatures, recovery metadata, independent signature
  verification, and exact EVM/TRON public-source identity checks.
- Signing orchestration, single-use execution/nonce handling, public-result
  reconciliation, crash recovery, duplicates and concurrency acceptance tests.
- The entire requested positive/negative signing and auxiliary service matrix,
  plus final full six-job CI verification for the completed implementation.

Continue in `phase6d/cggmp-complete` and draft PR #29. Do not create another PR
for the next iteration, merge this draft, or enable production signing.
