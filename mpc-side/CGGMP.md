# Phase 6D: distributed CGGMP work in progress

**Phase 6D remains INCOMPLETE until the complete acceptance matrix and final
six-job CI run pass.** Distributed core keygen, fresh-prime auxiliary generation,
and full interactive prehashed ECDSA services are implemented on this branch.
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
auxiliary information, and that core **cannot sign** until all three auxiliary
artifacts have been validated and durably attested.

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

## Auxiliary generation and internal readiness

Custody dispatches `POST /v1/dkg-sessions/{id}/auxiliary/execute` after core
KEYGEN_COMPLETED. An immutable auxiliary execution ID is saved before network
I/O. The response returns immediately; GET on the DKG session includes an
`auxiliary` state. The original core status, receipts, and result fingerprint
remain unchanged. Duplicate calls share the same execution and never generate
replacement primes. `/auxiliary/reconcile` queries existing public receipts only.

Each signer independently runs upstream `PregeneratedPrimes::generate(OsRng)`
and the pinned three-party `aux_info_gen` protocol. No test prime fixture is
linked into either service binary. Prime generation and proof computation use
bounded blocking workers. One capacity permit per process remains held even if
an aborted blocking operation has not yet returned. There is a 1,800-second
signer deadline and 1,810-second coordinator deadline. Measured prime-generation
milliseconds are public receipt metadata, including unfinished protocol records.

Encrypted auxiliary artifacts use `cggmp-aux/{keyset}.share.enc`, separately
from the immutable root core file. The encrypted discriminator CGGMP24_AUX_V1
binds format, protocol version, signer identity, complete core DKG request,
compressed group key, public-share package, and auxiliary execution ID. The
existing authenticated create-once storage primitive rejects conflicting
replacement. Load combines exactly one own core and one own auxiliary artifact
with upstream `KeyShare::from_parts`, enforcing the original index, 2-of-3
shape, group key, and Paillier-factor consistency. No private material enters
coordinator state. Public parameter fingerprints exclude primes and sensitive
CRT/precomputation material.

Only three matching authenticated AUXILIARY_COMPLETED receipts set durable
`internally_signable=true`. This is an internal service capability, not production
activation. Unfinished restart state becomes RECONCILIATION_REQUIRED. Corrupt
material or inconsistent ready receipts fail startup validation. Partial
persistence cannot produce unanimous readiness.

## Exact-digest threshold signing

The existing custody-only `/v1/sign-sessions` and `/execute` dispatch CGGMP
sessions only after auxiliary readiness. The coordinator probes authenticated
signers and durably fixes two eligible identities before protocol dispatch.
B+C can execute with A offline; selection is immutable for that execution.
Each signer loads only its own validated combined key. Upstream selected indices
are pair-relative, while the original DKG indices are passed to `signing`.

Inputs are canonical exactly 32-byte EVM legacy/EIP-1559 digests or TRON txIDs,
bound to the persisted SHA-256 fingerprint and custody operation metadata.
The full interactive upstream `.sign` accepts `PrehashedDataToSign` derived
from the supplied scalar, with no second hash, offline presignature API, unsafe
preimage override, transaction assembly, or broadcast. Expected source addresses
are checked against the original DKG public key.

Low-s results include r, s, recovery ID/y parity, signature bytes, keyset,
logical session, crypto execution, selected identities, algorithm, and payload
fingerprint. k256 recovers from the exact prehash and must match the original
compressed group key. Both authenticated signers must return the same verified
public result before coordinator completion. Acceptance independently verifies
and recovers with libsecp256k1 through coincurve, including double-hash rejection.

Before any signing nonce randomness, the signer persists the exact execution
reservation and a create-once `.consumed` record. Lost ephemeral state cannot
resume, regenerate nonces, replay consumed messages, or substitute a new
execution. Uncertainty stays RECONCILIATION_REQUIRED. A create-once verified
public `.completed` result survives restart and supports reconciliation without
cryptographic work. Coordinator completed results are revalidated on restart
and are returned unchanged on retry, even if signers are offline.

Auxiliary/signing delivery allows distinct messages in the same upstream round.
Repeated sender sequences, conflicting sequences, and repeated sender/round
payloads are rejected. Transport binds phase, full request transcript, session,
execution, keyset, sender, destination, mode, round, sequence, and payload.
Proof RPCs use a version-1 canonical base64 envelope with the original raw-byte
transcript digest unchanged. They have a 1 MiB body cap, 512 KiB decoded-payload cap, 16-entry inbox,
256-message sender budget, and bounded 30-second RPC deadline. TLS handshakes
and header reads retain five-second bounds; server connections are bounded at
45 seconds. Signing workers have 180 seconds and orchestration 200 seconds.
At most four signing executions are active per signer.

## Acceptance status

Run the additional real-process gate after the baseline 162 network cases:

```sh
pytest -x -v -s mpc-side/integration/test_cggmp_aux.py
```

Build `--example cggmp_aux_message_fixture` alongside the baseline examples.
This fixture emits only synthetic public messages for hostile-input tests;
it contains no primes, private shares, or signing nonces.

The exact verified counts, fresh-prime timing, all-pair results, and final CI
HEAD are recorded in draft PR #29. Test collection or a passing keygen gate
alone does not establish Phase 6D PASS. Continue in `phase6d/cggmp-complete`
and PR #29. Do not create another PR, merge this draft, begin Phase 6E, or
enable production signing.
