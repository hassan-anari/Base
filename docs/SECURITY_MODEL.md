# Security, financial trust and production acceptance

## Distinct decision layers

1. **Business policy / Human Approval** — whether operation is allowed; tenant, risk, destination, amount/USD value, wallet class and named human approvers. Example future configurable policy: withdrawal > USD 500 requires three *different authorized humans*; this is neither fixed nor implemented today.
2. **Signer-side independent authorization** — verify an unforgeable short-lived policy/approval-bound signing grant tied to canonical signed operation, keyset, network/genesis, account and policy version. Compromise of a Django process alone must not permit arbitrary signatures.
3. **Cryptographic MPC quorum** — genuine 2-of-3 signer share threshold; no complete private key reconstruction. Two cryptographic signer approvals are NOT two human approvals.

A policy amendment itself may require multi-person quorum, MFA and a delayed activation window. No requester self-approval, voting twice, mutable recipient, replayed grant or expired stale FX price bypass.

## Threats and required controls

- **Backend/API compromise:** least privilege, operator/security separation, signer-side grants outside unilateral backend control, tenant-scoped auth, immutable audit, deny arbitrary unsigned/freeform transactions.
- **Single signer compromise:** encrypted local shares, independent security domains, quorum requirements, nonce use-once, replay prevention; compromise assessment should consider coordinated signer collusion.
- **Ledger fraud and race:** exact Decimal/base-unit, row locking, deterministic account lock order, idempotent journal, immutable populated asset identity, tenant isolation; mutation through privileged SQL is a distinct threat requiring DB permissions and/or triggers.
- **Malicious/stale RPC or reorg:** independent network identity, finality policy, verified receipts/history as applicable, multi-RPC disagreement/recovery, no false-empty logs; fail closed on unprovable history.
- **Ambiguous blockchain delivery:** retain original signed bytes, on-chain identity and reservation. Never infer non-execution from timeout or explorer absence.
- **Insider / treasury abuse:** human quorum, destination allowlist changes with delay, cold exit isolation, operational velocity controls, alerts, emergency freeze.
- **Backup/recovery:** encrypted independently retained signing state and PostgreSQL financial state, documented RPO/RTO, restore drills, stale-share invalidation, key-transition audit.
- **Token/network identity:** immutable network genesis and canonical contract/master/mint/fingerprint; do not treat same ticker as interchangeable asset.
- **Supply-chain / CI artifact leaks:** pin cryptographic dependencies, signed or integrity-checked validator binaries, public evidence allowlists, no shares/nonces/PKI secrets in logs.

## Configuration and finality governance

Allow operator control of non-critical business policy, but enforce reviewed minimum safety floors. EVM deposit confirmation is not an equivalent of Solana finalized commitment or TON proof chain. Snapshot the policy version applied to each credit and withdrawal; require high privilege for changing finality floor, RPC provenance or signing scope.

## Production gates, independently applied per chain

A chain may activate only with reviewed code/protocol and threat model, mainnet/testnet-specific chain identity and token deployments, appropriate independent trust anchors, fail-closed indexes/reorg recovery, distributed signer and PKI/IdP/RBAC separation, fully tested financial accounting, mature runbooks/monitoring/backup/restore, compliance policy, volume/chaos tests and independent security assessments with findings resolved or explicitly governed.

**Not acceptable:** green isolated tests alone, owner willingness to assume risk alone, change of localhost RPC to public endpoint, disabling audit blockers, treating local Node endpoint as honest consensus proof.

**Current**: EVM/TRON/Solana integrations not mainnet-authorized. TON isolated only; exact Wallet V5R1 external audit correspondence P1 OPEN. Dynamic public sharding and actual USDT compatibility not implemented. This owner-approved deferral must not block other independently gated chains, but also cannot authorize TON mainnet.

## Acceptance artifacts

Phase 6G's initial unmerged reservation foundation is described in
[PHASE6G.md](../PHASE6G.md). Its deployment ownership scope, network and purpose
are immutable allocation evidence, not tenant authorization, child spendability
or independent Cold authority. Reservations cannot enter signing/indexing and
Warm/Cold/ISSUED labels are rejected. Existing funded-root retirement behavior
still requires a separate lifecycle review; retaining path evidence does not
make the historical root retirement command safe for funded wallets.

Per PR provide threat-model deltas, proof/identity and exact original signing-intent linkage, ledger invariants, concurrency/restart/replay/unknown-outcome test cases, CI final SHA and job links, migration/backfill plans, monitoring/runbooks and unresolved risk register. Reviews are independent, not self-approved.

## Phase 6G-B child custody boundary (unmerged development)

Original HD evidence is read from each signer's encrypted, original, validated
DKG/auxiliary share and pinned create-once to root, algorithm, DKG, network/genesis,
deployment namespace and DEPOSIT/HOT purpose. Three mTLS-authenticated matching
reports are required for attestation and new child issuance; two original shares
are sufficient for signing an already approved child. Historical missing HD material
is never invented; such roots remain root-only. Canonical non-hardened paths come
from immutable reservations, never the external caller. Signers independently reload
original HD/share metadata and their own approved reservation before nonce work.
Child request/path/owner/public key/source are bound into the original execution;
root/child signatures and authorizations cannot be substituted.

PostgreSQL triggers freeze HD evidence, claims, issued identities and asset views.
The application separately verifies public derivation before issuance, deposit
credit and signing. Database superusers, disabled triggers, compromised trusted
custody credentials and altered signer files are not neutralized by JSON receipts;
secure DB roles, separate stores and independent infrastructure review remain
mandatory. This does not implement Phase 7 independently issued policy tickets.
Uncertain signing or broadcast retains the original execution, signed bytes and
financial reservation. Issuance rejects caller-owned transactions so a published
signer approval cannot outlive a rolled-back original database claim.

P1 RUSTSEC-2026-0205 remains open. The scoped source/reverse-dependency assessment
in [PHASE6GB.md](../PHASE6GB.md) identifies HashSet rather than the advisory's
TreeIndex insertion path; it is not an independent exploitability clearance.
No cryptographic major dependency upgrade, audit suppression, TON scope expansion
or production flag relaxation is part of this branch.

Cross-asset address publication is serialized across canonical accounts and legacy
wallet inserts by a shared PostgreSQL advisory transaction lock. Publication uses
READ COMMITTED; other isolation levels fail closed to prevent stale-snapshot write
skew. Immutable issued account reads avoid an inverse scanner/account lock order.
This fixes the race found during this branch's security assessment; independent
review must confirm DB role/isolation/locking assumptions before acceptance.

Security assessment found a P1 EVM liability-inflation path: native scanning could
credit operator MPC gas funding as a customer deposit when native/token views
shared an address. This branch excludes only an exact known GAS_TOPUP transaction
with recovered persisted signed bytes, original source/destination/native amount/
chain, and consumed completed signing intent. Missing or altered provenance aborts
history; another payment from the same sender is still a deposit. Genuine live
acceptance caught the issue; dedicated negative contracts and final validator
checks cover the repair. Existing append-only historical journals are not rewritten;
any preexisting affected deployment needs a separate evidence-led investigation.
Independent review is required before considering this P1 repair accepted.

The coordinator substitution review also identified an authorization gap: approving
a child in each store did not authenticate which approved child the custody
service originally requested. This branch commits the full child signing request
with a once-persisted ECDSA/SHA-256 signature under the existing custody P-256 TLS
identity. Signers independently validate private-CA client authentication, current
certificate validity, exact custody URI and signature before nonce work and in the
worker. Substitution of another valid approved child, digest or session fails
closed. Dedicated DEPOSIT roots also reject dropping child authorization.
Migration 0031 freezes the original grant and prevents retrospective minting for
already-started executions. Original completed public signature recovery remains
possible; uncertain funds are never released on credential expiry or RPC timeout.
This does not make a compromised custody authority trustworthy; independent policy
authority remains Phase 7. Independent review must verify canonical serialization,
identity-key isolation, credential validity and immutable session/replay controls.
Transport adds the existing pinned ring 0.17.14 dependency edge; no Rust package or
cryptographic version is upgraded and the scc P1 remains open.

The first full-population restart benchmark issued all 1,000 real accounts, then
failed on a PostgreSQL deadlock during concurrent idempotent replay. Django's
joined FOR UPDATE implicitly locked account/reservation/root/keyset rows in query
plan order, conflicting with issuance's keyset-first order. Asset attachment now
explicitly locks keyset -> provisioning root -> account -> asset; the joined
account query locks only `self`. Deterministic first-view and existing-view tests
wait for a demonstrably blocked PostgreSQL backend and assert the account lock
remains available until its keyset lock is acquired. No deadlock is hidden by
retrying or claiming a passing benchmark. Initial-stage public benchmark evidence
is persisted before recovery so failed stages remain attributable. The full
recovery/validator run must pass on the final head.

Child issuance additionally verifies the current spending credential at all three
signers. The coordinator forwards an envelope containing the original ChildRequest
and a custody P-256 signature under `Wallet-MPC/CUSTODY_CHILD_APPROVAL_V1`. Each
signer validates private-CA client authentication, validity, exact custody URI and
public-request signature before reading/pinning child approval. Unsupported keys
or a custody CA trusted only by the coordinator cannot publish a new spendable
account. This public proof is domain-separated from signing grants, consumes no
CGGMP nonce and is not part of immutable child identity; public retries retain
original receipt identity. Private signing still requires its once-persisted
original operation grant. No human/policy approval authority is added.


## 2026-10-23 independent review remediation (PR #37)

The prior mTLS report design was insufficient against a compromised coordinator.
R1 now requires detached, domain-separated ECDSA/SHA-256 receipts from all three
signers, verified by Django against separately installed signer public identities
(`MPC_HD_SIGNER_CERTIFICATES`), never coordinator-provided trust anchors. Receipt
bytes and original ownership remain immutable across retries. Migration 0032 checks
signature presence/shape; application writes and every use verify cryptography.
SQL is not an ECDSA verifier; database writers and independent trust enrollment
remain protected authorities. Old unsigned records remain immutable and quarantined;
use the read-only `audit_mpc_hd_evidence` procedure in PHASE6GB before upgrade.

R2 requires a domain-separated original custody dedication proof checked by every
signer before role/namespace mutation, plus durable historical root-use reservation
before nonce work. Signers seed use from original retained execution records and
reject used/conflicting roots. Authorized dedication of a fresh eligible root is
irreversible; no root-only fallback. Dedicated role and original proof persist
across restart. Unverified old signer HD stores fail startup for offline audit.
These are machine-authentication corrections, not Phase 7 policy/RBAC or lifecycle
completion. R1/R2 require independent re-review and fresh final-head gates; prior
normal-path CI is insufficient. scc/RUSTSEC-2026-0205 remains P1 OPEN.
