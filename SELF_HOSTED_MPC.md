# Self-hosted MPC (Phase 6)

> **Implementation status:** the durable Django boundary, versioned key metadata, encrypted
> identity-bound share envelope, dependency pins, CI gates, and an executable FROST 2-of-3 DKG/
> signing compatibility test are implemented. The network CGGMP engine, signer APIs, durable
> coordinator, and mTLS termination are not implemented yet. Therefore this branch is not a
> production MPC deployment. Requirements below describe the mandatory target architecture and
> must not be read as claims that the unfinished network services enforce them today.

## Threat model and boundary

Django prepares and persists transactions; the coordinator schedules authenticated protocol
participants; signer nodes alone hold shares. Neither Django nor the coordinator stores or can
export a share. A single compromised signer has no signing authority. The coordinator is not a
generic public signing oracle: ingress is private, mTLS-authenticated, custody-only, and requests
carry the attempt, operation, chain, asset, source/destination fingerprint and immutable message
fingerprint. Phase 4/5 remains authoritative for nonce/TAPOS/blockhash, assembly, own-RPC
broadcast, reconciliation and exactly-once settlement.

## Topology and protocols

The initial topology is 2-of-3. Signer A, B and C **must be on independent hosts and failure
domains**, with separate operators/access controls where possible. Three containers on one host
are NOT production-safe; `mpc-side/compose.yaml` is test/development only. The coordinator is
separately deployable and has no share.

ECDSA uses LFDT/Lockness `cggmp24` 0.7.0-alpha.3 and `cggmp24-keygen`
0.7.0-alpha.3 over secp256k1, with SLIP-10 HD support. Ed25519 uses Zcash Foundation
`frost-ed25519` 3.0.0 (RFC 9591); final signatures are RFC 8032-verifiable. Versions and features
are pinned in `Cargo.lock`. See the upstream repository security/audit material before every
upgrade; run `cargo audit` and deny unreviewed lockfile changes.

## DKG, derivation, and rotation

An operator creates a random execution UUID and public keyset record. All three certificate-bound
parties run audited DKG; each atomically persists only its output share. The coordinator activates
the result only when every participant reports the same group public key. There is no dealer or
reconstruction endpoint. ECDSA uses reviewed non-hardened public child derivation under
`mpc_hd_v1/<asset-salt>/<user-index>/<address-index>`; hardened derivation is forbidden. FROST
does not use invented public HD derivation: each Solana address is an explicit DKG keyset.

Threshold changes are not configuration changes. In-place refresh/resharing is intentionally not
implemented until the chosen upstream provides and reviews the exact operation. Rotation creates
a new DKG keyset. New wallets bind to the active keyset; existing `legacy_local_v1` addresses stay
unbound and historical until explicitly drained. Hot-wallet binding derives and compares the exact
address and fails closed on mismatch. Addresses are never silently regenerated.

## Storage and transport

Each signer uses authenticated AES-256-GCM storage with a fresh OS-CSPRNG nonce, mode 0600,
0700 parent directory, fsync and atomic rename. Its 256-bit node-specific wrapping key is supplied
through a host secret facility (not environment, image, Git, coordinator or Django). The `Wrapper`
interface permits TPM/HSM sealing. Decrypted data is zeroized and never logged.

All links (Django/coordinator, coordinator/signer, and direct party traffic) require TLS 1.3 mutual
authentication against private CAs. Certificate identity maps exactly to the configured service or
party number. Wrong, expired or revoked identity fails closed. Protocol envelopes bind random
execution UUID, keyset, sender, recipient, round and transcript hash; duplicates, conflicts,
wrong-session/recipient messages and replayed request nonces are rejected. CGGMP execution IDs
provide domain separation. Ephemeral signing nonce state is single-use; after crash/abort it is
destroyed and the execution cannot resume.

## Durable signing and recovery

Inside one PostgreSQL transaction Django locks the PREPARED attempt, fingerprints exact signing
content, creates the unique `MpcSigningSession`, and changes the attempt to SIGNING. Only after
commit does it call `POST /v1/sign-sessions`. Retrying the UUID returns the same logical operation.
`GET /v1/sign-sessions/{uuid}` distinguishes not-started, in-progress, completed, definitive
no-signature failure and inconsistent/unknown. A timeout never creates a second session. Completed
signatures are verified locally against the bound key/address before local assembly. If an
individual protocol loses ephemeral state it aborts; a new cryptographic execution is allowed only
after authoritative proof the old one could not sign, while the network attempt and EVM nonce stay.

## Backups, disaster recovery, and incidents

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

## Cutover

Deploy the coordinator and three independent signers, issue private mTLS identities, perform DKG,
import only public metadata into Django, validate addresses, then activate the keyset. Set
`MPC_SIGNER_BACKEND=self_hosted_mpc` with CA/client certificate paths and demo mode false.
Drain/migrate legacy addresses as a separate reviewed operation; no automatic asset migration is
provided. TON and Jettons remain disabled.
