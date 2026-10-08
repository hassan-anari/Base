# Phase 6C.2: service FROST signing

Two independent signer processes use pinned `frost-ed25519 =3.0.0` round-one
and round-two APIs over the existing TLS 1.3 mTLS transport. The coordinator
uses `frost::aggregate` with verified public material, verifies the final
Ed25519 signature over the original bytes, and returns 64 signature bytes
encoded as lowercase hex. No transaction is assembled or broadcast.

Production signing stays disabled: Django's `custody.E011` and runtime guard
are unchanged, and generic quorum health continues to return `signable: false`.
This service milestone adds no CGGMP, provisioning, withdrawal execution or
production cutover. Use the isolated development topology from [TRANSPORT.md](TRANSPORT.md).

## Public DKG material

New DKG key blobs persist the upstream serialized PublicKeyPackage alongside
the encrypted private KeyPackage. Each signer validates the group key, fixed
participant identifiers, 2-of-3 threshold, own public verification share and
its correspondence with the own private signing share. Public DKG receipts
now contain the serialized public package and the party's verification share.
The coordinator accepts completion only when all three authenticated receipts
agree on the entire package and its shares. Receipt storage binds the package
to the exact DKG session, execution and keyset and survives restart.

Existing Phase 6C.1 blobs omitted the PublicKeyPackage. On signer restart,
completed records acquire only their own public verification share, loaded from
their existing encrypted KeyPackage. Run the existing DKG `/execute` or
`/reconcile` route to recover public metadata from all three authenticated
signers. The coordinator constructs a PublicKeyPackage with the upstream API
from these verification shares and the original group key, retaining all
authenticated receipts durably. The original DKG identity and group key cannot
change. No private shares leave their signers and no private key is reconstructed.
Signing is rejected until this public recovery is complete. Missing/corrupted
shares cannot be repaired by this operation.

## Custody request and advancement

Only the verified custody certificate can use coordinator routes. Create a
logical session with `POST /v1/sign-sessions` using the existing immutable request
contract. Executable requests require a completed fixed SOLANA FROST DKG,
`algorithm: FROST_ED25519`, `payload_type: SOLANA_MESSAGE`, `chain: SOL`, a nonempty
asset, operation WITHDRAWAL/SWEEP/GAS_TOPUP, a positive attempt ID, non-nil session
and keyset UUIDs, and `derivation_reference: null` (no HD derivation).
`expected_source` must be the base58 encoding of the recorded 32-byte group key.
`payload_hex` must contain the exact nonempty message bytes in lowercase hex,
at most 1232 bytes. `message_fingerprint` is the lowercase SHA-256 of those
bytes. The authenticated custody service remains responsible for its original
business authorization; this milestone does not parse or assemble Solana messages.

`POST /v1/sign-sessions/{session_id}/execute` explicitly advances:

```
CREATED -> STARTING -> IN_PROGRESS -> COMPLETED
```

A store compare-and-set claims STARTING before network I/O. Each signer is
probed over authenticated transport and must decrypt/validate the exact keyset.
The first two eligible identities in A/B/C order are selected. Their identities
and the crypto execution UUID are persisted before issuing either signing round.
An unavailable/corrupted A allows B+C. A sole eligible signer causes no nonce
generation and no signature. Network operations have bounded transport timeouts
and never hold the coordinator's global store mutex.

The result's `signature` object contains `logical_session_id`,
`crypto_execution_id`, `keyset_id`, `selected_signers`, `algorithm`,
`payload_fingerprint`, `signature_hex` and `verified: true`. Repeated GET or
execute returns the exact stored completed result, including after coordinator
restart or when signers are unavailable. Concurrent create/execute requests
cannot launch a second cryptographic execution. Concurrent callers may observe
STARTING or IN_PROGRESS and then read the authoritative completed result.

## Nonces and recovery

Signer `/internal/v1/sign/{probe,round1,round2,report,abort}` requires the verified
coordinator certificate. SignControl carries the full immutable request, DKG
binding, public package, selected pair, execution UUID, sender, recipient and
round. Round two additionally carries the exact serialized upstream SigningPackage.
The signer checks its own round-one commitment, both selected identifiers,
message bytes and fingerprint before producing a share.

An execution tombstone and public reservation are durably created before OS
randomness generates nonces. Nonce secrets and private packages stay only in
the owning signer memory. Valid round two removes ephemeral nonce state and
durably consumes the execution before invoking upstream signing. Exact or
conflicting round replays, execution reuse, and a new execution for an already
reserved logical session are rejected. Public reports persist commitments,
the exact package and produced signature shares, never nonce/signing secrets.
Signature shares are public cryptographic outputs, not private signing shares.

A crash with unfinished signer state or coordinator STARTING/IN_PROGRESS becomes
RECONCILIATION_REQUIRED. No new execution is automatically substituted, and
failures are never mislabeled definitive no-signature failures. A public
`POST /v1/sign-sessions/{session_id}/reconcile` reads existing persisted reports
only; it can complete only if both already produced valid shares for the same
exact package. It never calls nonce generation or round two. Lost nonce state,
missing shares or conflicting/invalid outputs remain unresolved. Preserve
tombstones and original custody context; operator/business recovery of these
uncertain outcomes is outside this milestone.

## Acceptance gate

```
cargo build --locked --manifest-path mpc-side/Cargo.toml --bin wallet-mpc-coordinator --bin wallet-mpc-signer --example frost_round1_fixture --example frost_signing_package
pytest -v mpc-side/integration/test_network.py mpc-side/integration/test_dkg.py mpc-side/integration/test_signing.py
cargo fmt --manifest-path mpc-side/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path mpc-side/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --locked --manifest-path mpc-side/Cargo.toml --workspace
```

Use the pinned toolchain and backend test environment as in [DKG.md](DKG.md).
All acceptance signing uses actual coordinator/signer binaries, separate
encrypted storage and certificates, and TLS connections. Python cryptography
independently verifies standard Ed25519 encoding and the exact original message.
The helper example only encodes public commitments for hostile package injection;
it owns no private share, generates no nonce and never simulates a signer.
Negative recovery tests corrupt public persisted reports or test encrypted
artifacts to exercise real service restart and verification boundaries.

Independent production hosts, operator PKI lifecycle, business reconciliation of
ambiguous executions, key provisioning, Solana message assembly and broadcasting
remain outside scope. Historical Phase 6A/6B CREATED metadata contracts remain
compatible; CGGMP metadata sessions cannot execute through this signing driver.
