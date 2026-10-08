# Self-hosted MPC — Phase 6A Foundation Baseline Only

Phase 6C.1 adds real FROST Ed25519 2-of-3 DKG over Phase 6B's TLS 1.3 mTLS
transport. Each independently running signer exchanges private directed packages
with its peers and retains only its own encrypted key package. The coordinator
stores public metadata and three matching durable receipts. See [DKG.md](mpc-side/DKG.md)
and [TRANSPORT.md](mpc-side/TRANSPORT.md) for current APIs, recovery and tests.

**Production MPC signing remains disabled.** `custody.E011` and the runtime guard
remain unchanged. This milestone adds no signing, wallet provisioning, chain
transaction assembly or production cutover. The Phase 6A sections below describe
the historical foundation and future design, not a production deployment.

Implemented in Phase 6A:

- pinned, executable CGGMP24 and FROST cryptographic compatibility tests;
- public keyset and durable signing-session metadata;
- exact signing-payload and local EVM assembly primitives;
- durable coordinator metadata/idempotency primitives;
- encrypted, identity-bound, create-once share storage and execution tombstones;
- isolated Django/Rust unit tests and CI gates.

Not implemented in Phase 6A:

- real networked DKG or signing between signer services;
- mTLS termination or authenticated coordinator-to-signer dispatch;
- production MPC wallet provisioning or keyset activation;
- service-generated EVM signatures or full EVM/TRON/Solana custody E2E;
- production quorum, backup/restore, or disaster-recovery workflows.

All architecture below is the **target design for later Phase 6 milestones**, unless a paragraph
explicitly identifies a Phase 6A primitive. It must not be read as an operational claim.

Signing recovery now distinguishes unsubmitted `STARTING` sessions from coordinator-owned work:
a coordinator 404 causes the same UUID and persisted payload to be reposted. Completed signatures
remain durable until consumed, and verified EVM legacy/type-2 components are assembled locally;
only definitive proof that no signature exists permits the next session number.

## Target threat model and boundary (not operational in Phase 6A)

Django prepares and persists transactions; the coordinator schedules authenticated protocol
participants; signer nodes alone hold shares. Neither Django nor the coordinator stores or can
export a share. A single compromised signer has no signing authority. The coordinator is not a
generic public signing oracle: ingress is private, mTLS-authenticated, custody-only, and requests
carry the attempt, operation, chain, asset, source/destination fingerprint and immutable message
fingerprint. Phase 4/5 remains authoritative for nonce/TAPOS/blockhash, assembly, own-RPC
broadcast, reconciliation and exactly-once settlement.

## Target topology and protocols

The initial topology is 2-of-3. Signer A, B and C **must be on independent hosts and failure
domains**, with separate operators/access controls where possible. Three containers on one host
are NOT production-safe; `mpc-side/compose.yaml` is test/development only. The coordinator is
separately deployable and has no share.

ECDSA uses LFDT/Lockness `cggmp24` 0.7.0-alpha.3 and `cggmp24-keygen`
0.7.0-alpha.3 over secp256k1, with SLIP-10 HD support. Ed25519 uses Zcash Foundation
`frost-ed25519` 3.0.0 (RFC 9591); final signatures are RFC 8032-verifiable. Versions and features
are pinned in `Cargo.lock`. See the upstream repository security/audit material before every
upgrade; run `cargo audit` and deny unreviewed lockfile changes.

`atomic-polyfill 1.0.3` is retained technical debt on non-host targets through
`frost-ed25519 3.0.0 → frost-core → postcard 1.1.3 → heapless 0.7.17`. It is not a direct
dependency and is not selected for the Linux service target, but remains in the all-target lock
graph. Replacing it requires upgrading the reviewed FROST release rather than patching cryptographic
dependency internals locally. The direct `anyhow` advisory is resolved by pinning 1.0.103.

## Target DKG, derivation, and rotation

An operator creates a random execution UUID and public keyset record. All three certificate-bound
parties run audited DKG; each atomically persists only its output share. The coordinator activates
the result only when every participant reports the same group public key. There is no dealer or
reconstruction endpoint. ECDSA uses reviewed non-hardened public child derivation under
`cggmp_hd_v1/<asset-salt>/<user-index>/<address-index>`; hardened derivation is forbidden. FROST
does not use invented public HD derivation: each Solana address is an explicit DKG keyset.

Threshold changes are not configuration changes. In-place refresh/resharing is intentionally not
implemented until the chosen upstream provides and reviews the exact operation. Rotation creates
a new DKG keyset. New wallets bind to the active keyset; existing `legacy_local_v1` addresses stay
unbound and historical until explicitly drained. Hot-wallet binding derives and compares the exact
address and fails closed on mismatch. Addresses are never silently regenerated.

## Storage baseline and target transport

Each signer uses authenticated AES-256-GCM storage with a fresh OS-CSPRNG nonce, mode 0600,
0700 parent directory, fsync and atomic rename. Its 256-bit node-specific wrapping key is supplied
through a host secret facility (not environment, image, Git, coordinator or Django). The `Wrapper`
interface permits TPM/HSM sealing. Decrypted data is zeroized and never logged.

Later milestones require all links (Django/coordinator, coordinator/signer, and direct party
traffic) to use TLS 1.3 mutual
authentication against private CAs. Certificate identity maps exactly to the configured service or
party number. Wrong, expired or revoked identity fails closed. Protocol envelopes bind random
execution UUID, keyset, sender, recipient, round and transcript hash; duplicates, conflicts,
wrong-session/recipient messages and replayed request nonces are rejected. CGGMP execution IDs
provide domain separation. Ephemeral signing nonce state is single-use; after crash/abort it is
destroyed and the execution cannot resume.

## Durable signing primitives and target recovery

Inside one PostgreSQL transaction Django locks the PREPARED attempt, fingerprints exact signing
content, creates the unique `MpcSigningSession`, and changes the attempt to SIGNING. Only after
commit does it call `POST /v1/sign-sessions`. Retrying the UUID returns the same logical operation.
`GET /v1/sign-sessions/{uuid}` distinguishes not-started, in-progress, completed, definitive
no-signature failure and inconsistent/unknown. A timeout never creates a second session. Completed
signatures are verified locally against the bound key/address before local assembly. If an
individual protocol loses ephemeral state it aborts; a new cryptographic execution is allowed only
after authoritative proof the old one could not sign, while the network attempt and EVM nonce stay.

## Target backups, disaster recovery, and incidents

Back up one encrypted share per independent location: A→A, B→B, C→C, never co-locate two
backups. Independent access controls and wrapping keys are mandatory. Quarterly drill: stop and
destroy A, restore A's encrypted file/wrapping identity, verify its party/keyset and group public
key, rejoin, sign with A+B, then prove A alone cannot sign. Confirm the group public key did not
change and retain only non-secret evidence.

On invalid proof/message, wrong identity, nonce-reuse alarm, share corruption or public-key
disagreement: isolate the named party, revoke its certificate, stop the affected session, mark it
for reconciliation, preserve non-secret transcript hashes/metrics, and rotate through a new DKG if
integrity is uncertain. Never print shares, scalars, decrypted files, nonces or secret protocol state.
Health exposes identity, protocol/version, supported algorithms, share presence and 3/3, 2/3 or
1/3 quorum only. Metrics include session counts/duration/outcome, timeouts, invalid messages and
DKG outcomes.

## Future cutover gate

There is no Phase 6A production cutover. A future milestone may deploy the coordinator and three
independent signers, issue private mTLS identities, perform DKG,
import only public metadata into Django, validate addresses, then activate the keyset. Set
`MPC_SIGNER_BACKEND=self_hosted_mpc` only after the intentional production guard is removed by a
reviewed milestone with network, mTLS, persistence, and E2E gates.
Drain/migrate legacy addresses as a separate reviewed operation; no automatic asset migration is
provided. TON and Jettons remain disabled.
