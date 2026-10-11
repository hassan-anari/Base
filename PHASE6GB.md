# Phase 6G-B — genuine EVM/TRON child custody, draft development implementation

Base: `24eed19e6e280083793c69c3901f5f746dd0a2fe` (merged PR #36).
Branch: `phase6g-b-child-wallets`. One draft PR; independent review required.
This record describes implemented controls and acceptance scenarios. Final-head
results and measured artifacts must be read with the draft PR's exact-SHA report.
An implemented acceptance scenario is not itself a passing result.

## Original HD identity and authenticated agreement

The pinned `cggmp24` 0.7.0-alpha.3, `key-share` 0.6.1 and `hd-wallet` 0.6.1
provide extended public roots, SLIP-10 public derivation and signing
`set_derivation_path`. Rust dependency versions and Cargo.lock are unchanged.
Each signer reloads its original encrypted validated DKG/auxiliary share,
checks `extended_public_key()` against the original group key, and reads its
actual original 32-byte chain code. It never manufactures missing metadata.
Three matching mTLS-authenticated reports bind algorithm, keyset, original DKG
execution/fingerprint, root public key/chain code, original network/genesis,
deployment namespace, HOT/DEPOSIT purpose and derivation version. Extended root
identity is a domain-separated SHA-256 commitment to canonical public metadata.
Each original signer and the coordinator create and fsync immutable evidence.
Changing network or scope cannot register another interpretation of that root.
Roots lacking verifiable original HD material remain root-only and unissuable;
an explicitly authorized new DKG is required, not historical evidence fabrication.

The coordinator stores public evidence only. Reports are authenticated over mTLS
and persisted; they are not portable detached signer signatures. Secure original
stores, DB roles and authenticated custody/coordinator identities are trust
prerequisites. Compromise of all those authorities is not solved by JSON hashes.
Independent policy authority outside Django belongs to the existing Phase 7 plan.

## Canonical public derivation and threshold spendability

Only the Phase 6G-A original `m/0/<allocated-index>` reservation is accepted.
The index must be integer 0 through 2^31-1; hardened/arbitrary paths fail closed.
Upstream SLIP-10 derives the child independently at coordinator and each signer.
Django uses pinned coincurve 21.0.0/libsecp256k1 for a separate public-point/HMAC
verification, including SLIP-10 same-index invalid-child retry semantics. No local
custody private key, private-child derivation or reconstructed secret is used.
Canonical compressed secp256k1 public keys yield lowercase EVM addresses or
TRON Base58Check addresses. A child key equal to its root is rejected.

Before issuance, all three original ready stores independently derive the child
and durably approve reservation UUID, index, customer, original retry key and
root identity. Signers pin index, customer and reservation separately; partial
writes can recover only the same statement, never recycle an index. New issuance
requires all three stores; spending an issued account requires genuine 2-of-3.

Signing requests commit the complete child identity plus
`child:<reservation-uuid>:<canonical-fingerprint>`. The coordinator checks its
original durable approval and each signer checks its own original approval and
share binding before nonce work, then invokes upstream `set_derivation_path` on
the original shares. Verification and ECDSA recovery use the CHILD public key.
Wrong owner/root/chain code/path/source/replay is rejected. Original signing
execution IDs, consumed tombstones and reconciliation behavior remain intact.
Restart validates persisted child authorization before resuming coordinator work.
Absence of child authorization preserves the historical root-only contract.

## Additive ownership schema and durable lifecycle

Migration 0029 adds immutable original `MpcHdRootEvidence`, canonical
`MpcCustodyAccount` and nullable `UserWallet.custody_account`. Migration 0030 adds
PostgreSQL trigger guards. Existing rows remain nullable; no historical wallet,
asset, financial owner, balance or journal is rewritten or backfilled.

A transaction allocates the original reservation and commits a PROVISIONING
account claim before external requests. Issuance rejects an enclosing caller
transaction to prevent an approval outliving a rolled-back original DB claim.
Three independently validated approvals permit a second transaction to publish
ISSUED public key/address/evidence. RPC loss, partial signer writes or crash
between those commits leaves the original durable claim for idempotent recovery.
Issued identities and ownership are immutable, undeletable and never reassigned.
The reservation remains immutable RESERVED; its one-to-one account owns the
issuance lifecycle, avoiding two competing mutable status fields.

One canonical account exists per approved registry network/global customer.
`ownership_scope` is the existing trusted deployment namespace, not a new tenant
API. Multiple verified token/native UserWallet asset views share that same owner,
address and signing account; each view retains distinct immutable asset identity.
Legacy address ownership conflicts fail closed, including EVM case aliases.
Existing historical root wallets remain supported. DB downgrade refuses populated
HD/account evidence; rollback is not a license to delete financial ownership.

Indexing validates child ownership before ledger credit. EVM/TRON transaction
snapshots commit original root plus child identity. Existing builders, nonce/TAPOS,
finality, token-code verification, gas/resource funding, fee journals, persisted
signed bytes, exactly-once deposits and uncertain withdrawals remain authoritative.
No second ledger or balance reconstruction is introduced.

## Operator use and release controls

`mpc_child_wallet attest --keyset-id ... --ownership-scope ...` obtains original
HD evidence. `issue` additionally specifies customer/ref, original idempotency
key and optional verified asset views; inspect `--help` for exact CLI flags.
Existing operator wallet APIs require explicit `MPC_PROVISIONING_ROOTS` per chain.
No automatic DKG root activation or caller-selected HD path is added. New child
views use address_index=0; the original HD allocation index stays in reservation.
All existing genuine MPC/live-development network guards remain. No public
mainnet, customer funds, Phase 7 approvals/RBAC/AML, Phase 8 treasury/batch,
Solana/FROST derivation, TON expansion, Bitcoin, matching engine or merchant API
is enabled here.

## Required genuine development evidence

The new EVM scenario uses two independent fresh CGGMP roots, all three authenticated
stores, several distinct children, a genuine finalized native deposit, exactly-once
ledger credit and actual B+C child-source sweep. It exercises ERC-20 discovery,
same-account asset association, MPC hot-root gas funding, child token sweep,
coordinator/DB restart, retained signed bytes and lost accepted RPC response.
Faucet/demo keys perform inbound funding and fixture deployment only.

The TRON scenario uses its independently authenticated root and pinned real
GreatVoyage-v4.8.2.3 validator. Native TRX and verified TRC-20 deposits and sweeps
use child sources; hot funding uses actual MPC. TAPOS, resource/energy, genesis/
checkpoint and finality controls are inherited without relaxation. Acceptance
asserts intended child source and root/child public-key inequality.

Public/synthetic PostgreSQL fixtures test guards/concurrency only, never count as
MPC or chain evidence. Rust protocol tests additionally exercise all three 2-of-3
pairs with upstream child signing and reject verification under the root key.
New hostile-service cases exercise certificate roles, chain/owner/chain-code/path/
public-key replay, partial approval recovery and insufficient signer quorum with
original execution identity. Existing four-chain regressions remain in the full
final-head gate, without test skips or gate suppression.

## Complete issuance benchmark methodology

The EVM acceptance benchmark defaults to 1,000 distinct customers and eight
concurrent workers against PostgreSQL. Each customer receives its committed
reservation, original-share approval at all three real stores, independent public
verification, persistent issued account/address and native asset view. It measures
elapsed actual wallet issuance rate, reservation/public verification/account-save/
asset-view timings, authenticated coordinator request time, SQL and FOR UPDATE
latencies, table/index size and reconnected idempotent retry. FOR UPDATE latency
includes lock waiting and query work; it is not isolated lock-wait attribution.
Report hardware, sample/concurrency and root metadata with the JSON artifact.

Fresh DKG/auxiliary setup is excluded from per-child issuance and reported separately
by real fixture timing. Genuine MPC signing latency is measured separately on chain
sweeps; public issuance itself generates no threshold signature. A small development
benchmark proves neither unlimited population nor production throughput. Full signer
restore/lifecycle recovery costs remain Phase 6G-C, not hidden in a reconnect figure.
Artifacts: `child-issuance-benchmark.json`, `evm-child-evidence.json`,
`tron-child-evidence.json`, per-suite manifests and final-head CI run links.

## Scoped dependency/security assessment

P1 **RUSTSEC-2026-0205 remains OPEN**. `cargo tree --locked -i scc` confirms
`scc 2.4.0 -> everscale-types 0.1.2 -> wallet-mpc-protocol -> coordinator/signer`.
Recursive source search of pinned everscale-types finds exactly one scc use:
`cell/usage_tree.rs:316`, `scc::HashSet<HashBytes, ahash::RandomState>` under sync.
The advisory describes TreeIndex Array insertion when a user comparator panics.
No TreeIndex reference or instantiation is present in the inspected application or
that transitive consumer. The application's existing TON module uses Boc,
Cell/CellBuilder; EVM/TRON HD code adds no everscale or scc call. The reported
TreeIndex entry path was not found reachable in this scoped static assessment.

That evidence does not prove absence of every unsafe-library defect, compare-panic
path in other code, or production exploit. Independent dependency review remains
required. No unreviewed scc 2->3 upgrade or cryptographic major upgrade was performed.
Cargo audit output, including existing atomic-polyfill maintenance and scc unsoundness
warnings, must remain visible; an exit-zero informational warning is not a clean
security result. Pinned coincurve is an additive public verification dependency,
not a new secret holder or replacement threshold protocol.

Existing P1 TON audit/public-network trust and independent signer policy authority
remain. P2: bounded per-root DB allocation/asset locks and globally serialized HD
coordinator requests; historical/global customer-to-tenant mapping, trusted DB/file
administrators and backup economics need separate infrastructure/lifecycle review.
No independent audit or production security clearance is claimed.

## Final Phase 6G-C scope

Solana scalable chain-native provisioning with reviewed Ed25519/FROST semantics;
key generations, activation/drain/retirement; signer/node and share lifecycle;
versioned rotation, recovery/resharing/backup drills; Hot/Warm/Cold foundations and
class boundaries. Preserve issued account ownership and original ledger. Do not
invent unreviewed FROST HD, public TON expansion or Phase 7/8 product work. This is
the final Phase 6G implementation PR, not an additional attestation/signing slice.
