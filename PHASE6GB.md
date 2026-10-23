# Phase 6G-B — genuine EVM/TRON child custody, draft development implementation

Base: `24eed19e6e280083793c69c3901f5f746dd0a2fe` (merged PR #36).
Branch: `phase6g-b-child-wallets`. [Draft PR #37](https://github.com/hassan-anari/Base/pull/37); independent review required.
This record describes implemented controls and acceptance scenarios. Final-head
results and measured artifacts must be read with the draft PR's exact-SHA report.
An implemented acceptance scenario is not itself a passing result.

## Independent P1 review corrections — 2026-10-23

Independent review of `ebe9dd7fa3619ab03b46ce565f322552acfbdaa2`
([review 5628227149](https://github.com/hassan-anari/Base/pull/37#pullrequestreview-5628227149))
reproduced **R1: fabricated coordinator HD/child reports** and **R2: unauthorized
permanent root dedication**. Both block development merge. The earlier fourteen-job
passes below are historical normal-path evidence; they did not cover these attacks.
Corrections in this same draft require new exact-head acceptance and independent
re-review. No issue is independently closed merely by changing implementation.

R1 correction: each original signer signs its root/child report using its own
P-256 identity key, with separate `Wallet-MPC/SIGNER_HD_ROOT_RECEIPT_V1` and
`Wallet-MPC/SIGNER_CHILD_RECEIPT_V1` domains, NUL, and sorted UTF-8 JSON of the
original statement (`root` or `child`, `party_id`, `durable=true`). ASN.1 DER ECDSA/
SHA-256 is encoded in `signer_signature`. The root commits original DKG execution,
keyset, algorithm, public root, actual original chain code, network/genesis,
namespace and version. The child additionally commits original reservation UUID,
customer/retry identity, index/path, public child and address. Every signer reloads
its own validated share; it recomputes the original DKG public-transcript fingerprint.

Django verifies all three signatures against **independently installed**, distinct
signer P-256 public identities in `MPC_HD_SIGNER_CERTIFICATES` (exact signer-to-local-
certificate-path JSON mapping). No certificate/key from coordinator JSON is trusted.
Pins must be enrolled out of band, protected from coordinator writes and retained
for archival verification. Receipt verification does not expire with transport
certificates; replacing an identity pin is a separate reviewed lifecycle operation,
not automatic certificate renewal. Missing pins, missing/forged signatures, wrong
signer and replay fail before publication. Model writes and every account exposure,
asset attachment, deposit credit and signing reverify evidence. Migration 0032
extends immutable SQL guards to require signed report shape on publication. SQL
checks shape/ownership, **not ECDSA**; trusted database writers and protected local
trust configuration remain explicit prerequisites. The coordinator has neither.

Original randomized signer signatures are persisted once. Child partial commits
recover the same receipt bytes from any original index/owner/reservation pin;
retries never re-sign an existing receipt or consume CGGMP nonces. All three genuine
root/child signatures remain mandatory for issuance; two shares still sign spends.
The malicious-coordinator regression substitutes chain code, recomputes every
fingerprint/public child/address/report, and verifies rejection with no issued
account, asset wallet or customer deposit address. Genuine EVM/TRON acceptance
runs this attack against real root metadata before authentic issuance and spending.

R2 correction: root attestation accepts a `HdDedicationRequest`, containing an
immutable statement and original custody proof under
`Wallet-MPC/CUSTODY_HD_DEDICATION_V1` + NUL + sorted UTF-8 JSON. The statement binds
full original HdRequest, dedication UUID equal to original keyset UUID,
`original_role=UNUSED` and `target_role=DEDICATED_DEPOSIT`. Every signer checks its
own private-CA custody authority, validity, exact URI, P-256 key/signature, original
DKG/share and lifecycle compatibility **before mutation**. A coordinator certificate
alone is insufficient. Original dedication proof is retained with the durable role.

A signer-local immutable `.role` reserves historical root use before valid signing
preparation and nonce reservation. Original pre-upgrade prepared/consumed/completed
execution records establish historical use on startup; no new UNUSED history is
fabricated. Dedication and root-use reservations share a mutex, preventing a race.
Used roots cannot become dedicated, including with a custody-signed incompatible
request. A fresh eligible root may be irreversibly dedicated to exactly one original
namespace; conflicting/replayed transitions cannot change it. Dedicated roots still
reject root-only fallback. Existing session, nonce and reconciliation rules remain.

### Pre-fix evidence audit and quarantine

Do not upgrade retained unverified development stores as if their receipts were
authenticated. Preserve encrypted shares, original receipts, DB backup, ownership,
signed bytes and journals. Freeze publication, deposit-address delivery, gas funding
and new outbound work for unverifiable accounts; uncertain reservations remain held.
`python manage.py audit_mpc_hd_evidence` is a read-only audit with nonzero exit for
unverifiable evidence; it reports record IDs/reasons without deposit addresses.
Every ordinary use independently fails verification too. Migration 0032 retains
old rows byte-for-byte; no signatures, owners, addresses or financial history are
backfilled. Immutable false ISSUED records cannot be healed by retry or replacement.

Signers refuse startup with pre-fix unsigned HD receipts or incompatible role/history;
all three were checked against the retained original R2 attack stores, without
changing their HD files. Plan an offline deployment audit before upgrade: isolate
those stores, preserve evidence, independently compare all original shares/DKG/HD
material and any funded addresses, and obtain a reviewed reconciliation disposition.
Do not delete receipt/use records, manufacture retrospective grants, recycle indices,
reset a financial DB or rewrite an owner/journal to resume. This PR supplies no online
conversion of unverified evidence. Fresh development acceptance uses explicitly
authorized fresh DKG roots and new disposable stores. Production remains disabled.

### Verification checkpoint

Unchanged-baseline R1 reproductions passed (public verifier plus actual PostgreSQL
false issuance; two cases, 7.04s). Unchanged genuine-service R2 reproduction passed
in 571.67s: root COMPLETED, coordinator-only dedication `[200,200,200]`, post-restart
RECONCILIATION_REQUIRED, direct probe 409. Corrected backend issuance/migration/
concurrency checks passed 38 cases in 183.23s. Corrected genuine signer regression passed two cases in 947.96s; the full backend
passed 607 cases in 647.24s. The updated audit/quarantine check separately passed
in 29.49s. Rust fmt/clippy, frontend contracts/two builds and system/migration checks
passed. Supporting EVM reached authenticated issuance but timed out at the fixture's
five-second client boundary during partial-quorum recovery (846.24s total); no
successful benchmark or chain-spend result is claimed for that run. Child acceptance
now uses a bounded 30-second client timeout to observe the coordinator's bounded
sequential peer responses. Peer timeouts/quorum rules and signing checks are unchanged.
New exact final SHA/CI evidence is recorded in this existing PR at completion.
Existing `scc` / RUSTSEC-2026-0205 remains explicitly **P1 OPEN**; no dependency
upgrade or audit suppression is included. No merge, mainnet or Phase 6G-C work.

## Verified implementation acceptance — 2026-10-12

Implementation validation SHA: `3670893bdfa6b21e2a99887e1238de5a979658cb`.
[Fast 38262366737](https://github.com/hassan-anari/Base/actions/runs/38262366737)
and [full gate 38262414457](https://github.com/hassan-anari/Base/actions/runs/38262414457)
passed; **all fourteen full-gate jobs succeeded**. Preflight ran eight checks.
PostgreSQL backend: 600 passed, no system-check issues or migration drift.
Rust: 32 distinct cases across Fast/full execution, including genuine all-pair
child signatures. Integration: **218 executed, zero required skips** — EVM 44,
TRON 5, Solana 2, TON 3, network 162, auxiliary persistence 1, integrated 1.
The originally failing EVM legacy pair and the new trusted/untrusted custody
regression pass, including directly after child issuance. Genuine EVM/TRON
native/token deposits and child-source spending, gas/resource fees, financial
replay and uncertain-outcome recovery passed. Existing TON scope stays isolated.

Complete real issuance on that CI runner: 1,000 customers, eight workers,
653.488s, **1.5302 issued accounts/s**. All four services restarted in 0.662s;
reconnecting PostgreSQL and recovering all 1,000 original UUIDs took 56.182s
(17.799/s), with zero new signer derivation approvals. Four logical x86_64 CPUs,
16,373,452 KiB RAM, PostgreSQL 16.15, Python 3.11.17. Public derivation verification
averaged 2.174ms (2,000 samples); 78,000 SQL queries averaged 0.370ms and 12,000
FOR UPDATE queries averaged 0.378ms, including query work/lock waits.
Fresh independent deposit/hot root setup took 230.249s / 143.660s separately;
original fixture auxiliary setup took 240.109s. These are outside per-account
issuance. Threshold signing is measured separately in the public evidence.
This bounded population/host does not establish production capacity.

Corrected local EVM: all 44 passed in 1391.85s, all 1,000 identities recovered,
1.5736 accounts/s issuance, recovery 56.666s; previous 1.67/s remains historical
supporting evidence. See the [full implementation/security report](docs/PHASE6GB_SECURITY_REVIEW.md)
and its public JSON records for transaction IDs, source keys, timings, migrations,
dependency assessment and open findings. P1 scc / RUSTSEC-2026-0205 remains OPEN.

Publishing this report adds only documentation/public evidence. The final draft
head and its **fresh** Fast/fourteen-job verification are sealed in [PR #37](https://github.com/hassan-anari/Base/pull/37),
with each job and crypto manifest binding REVIEWED_HEAD_SHA. Handoff requires
that exact final-head gate; implementation acceptance is not an independent
security approval, merge permission or production/mainnet authorization.

## Final-head regression investigation — 2026-10-12

Full run [38181533803](https://github.com/hassan-anari/Base/actions/runs/38181533803)
on `2c22c8b66954444f47f3868ca5df2538c4183764` passed twelve primary jobs;
EVM and therefore the final gate failed. Its EVM child scenario itself passed,
including 1,000 actual issuances at 1.6008 accounts/s and full original-identity
restart recovery; this remains supporting evidence, not full-head acceptance.
The later legacy all-pairs case returned **400, `{"error":"Invalid"}`**.
An actual-service replay using the retained original development stores confirmed
that response. Coordinator `create_sign` rejects root-only CGGMP requests when
the keyset has an immutable original `.root` HD receipt. This branch runs before
child credential verification: no missing custody grant caused the rejection.

The child acceptance scenario had permanently attested the module-scoped fixture
root as a dedicated DEPOSIT root. Subsequent legacy-root tests reused it; a Django
test database flush cannot undo signer/coordinator receipts. Child acceptance now
generates its own fresh genuine DKG/auxiliary deposit root, distinct from both the
unchanged historical fixture root and its separately generated hot funding root.
No original receipt is removed, no root is reassigned, and no production signing
contract, credential validation or signature verification is relaxed.

The targeted root-credential regression rejects coordinator/signer roles at POST,
rejects wrong-CA/expired/ambiguous/unknown client credentials while trusting the
genuine server CA, proves no session was created by those attempts, then obtains
and independently verifies a genuine root signature with trusted custody mTLS.
It also runs immediately after child issuance to prove fixture-order independence.
Legacy roots use their original custody-mTLS contract; approved children still
require their separately persisted original P-256 signing grant. Existing hostile
child tests continue to reject invalid/untrusted public approval and private
signing proofs before nonce work. The legacy all-pairs assertion now includes the
actual rejection body in failure diagnostics instead of discarding it.

Continuation checks: the fresh genuine three-signer fixture passed both the new
credential regression and the originally failing legacy pair in **212.00s**;
600 PostgreSQL backend tests passed in **153.01s**. System check reports zero
issues and migration dry-run reports no changes. Integration Ruff checks pass.
The extra fresh dedicated and hot root setup times are emitted separately as
public `GENUINE_INDEPENDENT_ROOT_SETUP` diagnostics; generation is excluded from
complete per-child issuance throughput. Public acceptance records distinguish
legacy, dedicated deposit and hot root public keys and assert all three differ.
Supporting results below and the failed run above must not be promoted to
acceptance of a subsequent commit. The new exact-head Fast/full gate and its
public artifacts are recorded in the existing draft PR before independent review.

## Original HD identity and authenticated agreement

The pinned `cggmp24` 0.7.0-alpha.3, `key-share` 0.6.1 and `hd-wallet` 0.6.1
provide extended public roots, SLIP-10 public derivation and signing
`set_derivation_path`. Cryptographic dependency versions are unchanged. Transport
adds a direct dependency on the already pinned ring 0.17.14 for original custody
request verification; Cargo.lock adds that edge, with no package/version upgrade.
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

Historical pre-fix design: the coordinator stored public evidence authenticated
over mTLS but without portable detached signer signatures. R1 supersedes that
design: transport alone did not authenticate signer origin at Django. Secure original
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
Historical roots without an HD provisioning namespace retain root-only signing.
An attested dedicated DEPOSIT root requires child authorization; dropping the
path cannot turn an issued-child approval into root signing.
Attestation refuses a historical root with existing root-only customer/hot
bindings before contacting signers. Registered namespaces prohibit new root-only
bindings under PostgreSQL keyset locks; existing historical bindings remain
usable without attestation. Caller transactions cannot roll back the original
namespace after external approval; use a committed, fresh dedicated DKG root.

The original custody service signs the complete canonical child SignRequest under
`Wallet-MPC/CUSTODY_CHILD_SIGNING_AUTH_V1`, using its existing P-256 TLS identity
key. Django persists this randomized ECDSA grant exactly once with the original
session, before RPC. Every signer validates the private-CA client-auth chain,
current validity, exact custody URI SAN, P-256 key and request signature before
probe/prepare/start and again before private work. A coordinator substituting
another already-approved child, source, digest or session cannot retain a valid
grant. This authenticates the existing machine authority; it does not implement
Phase 7 human approval, RBAC or an independent policy authority. Expired grants
fail closed for new private work; immutable completed public reports remain
recoverable without retrospectively authorizing another operation.

## Additive ownership schema and durable lifecycle

Migration 0029 adds immutable original `MpcHdRootEvidence`, canonical
`MpcCustodyAccount` and nullable `UserWallet.custody_account`. Migration 0030 adds
PostgreSQL trigger guards. Cross-table address publication and legacy inserts
serialize under a shared advisory transaction lock. READ COMMITTED is enforced
for address publication; stale snapshot isolation cannot bypass ownership checks. Existing rows remain nullable; no historical wallet,
asset, financial owner, balance or journal is rewritten or backfilled.
Migration 0031 adds persisted original custody authorization to signing sessions,
freezes populated grants, forbids their deletion and prevents retrospective
authorization of an already-started execution. Historical root-only sessions
remain empty and compatible; downgrade with retained grant evidence is refused.

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
Issuance uses a bounded 120-second HTTP timeout because approvals serialize at
the coordinator; the initial five-second benchmark timeout is retained as a
failed development attempt. Full-population recovery restarts all four services,
reconnects PostgreSQL and verifies every original account UUID without additional
signer approval operations. Query timings include work and lock waits; they do
not independently attribute PostgreSQL waiting time.

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

## Supporting local results (not final-head acceptance)

- PostgreSQL 16: 581 backend tests passed in 466.63s; focused ten issuance cases
  passed in 28.14s. Migration dry-run reports no changes; system check passes.
- Rust workspace: 32 unit tests passed, including genuine upstream all-pair child
  signatures (protocol cases 282.27s under concurrent local load). Latest
  coordinator/signer security-check tests pass; fmt/clippy pass.
- Frontend: two contract tests and both normal/simulator builds pass.
- Genuine fresh-root TRON child validator case: passed in 1167.54s, five actual
  confirmed MPC transactions including native/token CHILD sweeps, with B+C.
  Native/token deposits each have exactly one original ledger credit.
- cargo-audit 0.22.0 loaded 1,296 advisories and scanned 255 crates; exited zero
  with both existing informational warnings explicitly shown, not suppressed.
- Supporting head `9835a6afdb878b09a90890d8ab5d484528c4c148`
  [Fast CI 38175512208](https://github.com/hassan-anari/Base/actions/runs/38175512208)
  passed. That head still had an EVM harness environment issue; it is not the
  final cryptographic acceptance claim. A later exact-head full gate is required.

Earlier local failures are preserved in the handoff: overlapping pytest databases,
missing Ganache and explicit EVM live-indexer mode. The latter caused a missing
scan_complete attribute on the demo result; no synthetic result was accepted as
chain evidence. Corrected runs use separate databases and real live validators.
Original attested root/network bindings are never deleted or changed to make a
rerun pass; fresh fixtures are required when an ephemeral genesis is lost.

Address-claim concurrency review found and repaired a race on this unmerged branch:
a legacy asset view could otherwise insert between canonical publication checks.
A shared canonical-address PostgreSQL advisory lock now serializes both tables;
non-READ-COMMITTED publication fails closed. Issued child views read the immutable
account without reversing the wallet/account lock order during scans. Dedicated
concurrent legacy-owner and stale-snapshot tests cover the fix. Independent review
must include these migration guards; no original ledger mutation is involved.

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

Additional supporting checks after original-request authentication: 591 backend
contracts passed in 303.50s, the final eighteen issuance/authentication cases
passed in 27.12s, coordinator/signer units passed (21 cases), and fmt/clippy
passed. Cargo audit again scanned 255 packages with the same two explicit
informationals. These are supporting checks; the final exact-head full gate,
including the latest migration and original machine grant, remains authoritative.
The supporting full run 38175926795 passed Fast and all suites except EVM; EVM
failed on the gas-credit finding above, so its gate correctly failed.

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

Supporting complete issuance measurement at `3e5ddc7a036b70cc73074ab1aa997e28d7155817`
(before the additional public credential-readiness proof): genuine local EVM
acceptance passed in 1176.65s. One thousand customers, eight workers, PostgreSQL 16,
three logical CPUs / AMD EPYC 9V74, 10,207,516 KiB RAM: complete issuance took
609.505s (1.64067 accounts/s). The reservation stage averaged 6.473ms; two public
checks per customer averaged 2.989ms, two claim/publication saves averaged 2.313ms,
and asset attachment averaged 17.324ms. Twelve thousand FOR UPDATE queries averaged
0.474ms with a 49.948ms maximum (includes work/wait). All four services restarted
in 0.462s; all 1,000 original account IDs recovered in 55.982s (17.863/s), with no
new approval requests. Native signing including preparation/dispatch took 6.150s;
token signing after dispatch took 6.034s. This is a bounded development measurement,
not final-head throughput or arbitrary scale. Final credential-proof measurements
and all exact-head suite results belong in the PR's final security handoff.


Historical root-only TLS key profiles remain supported. If the TLS identity cannot
create supported P-256/PKCS8 detached receipts, HD dedication is disabled without
an unsigned fallback; existing root signing retains its original authenticated
contract. Existing signed HD stores require their original receipt identity and
fail closed if unavailable. The genuine signer regression includes a legitimate
legacy key-encoding compatibility check. Identity rotation remains separately gated.


## 2026-10-23 TLS dependency gate correction

Fresh unsuppressed Cargo Audit on pushed f973cc8 failed with five newly published
advisories, while preserving the two existing informational warnings. This is a
real failed gate, not a platform approval rejection or a reason to skip crypto.
Fast run 39965525267 / audit job 120454268053 records the failure. These advisories
postdate the 2026-10-12 acceptance and were not introduced by the R1/R2 code.

Scoped review retrieved the canonical RustSec entries and compared locked upstream
source. Correction is limited to **rustls 0.23.45 → 0.23.46** and
**rustls-webpki 0.103.15 → 0.103.16**, the minimum patched releases. The lock diff
changes only those two versions/checksums; tokio-rustls, ring, CGGMP24, key-share,
hd-wallet and FROST stay pinned. No major cryptographic upgrade, trust/verification
bypass, audit ignore or older advisory snapshot is used. The normal full gate must
verify the new exact head before review.

| Advisory | Prerequisite and scoped application evidence |
|---|---|
| [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346) | Debug of client-session secret values in a custom session store. No custom ClientSessionStore implementation or Debug logging of those values was found; client resumption is explicitly disabled. Upstream patch replaces secret-bearing derived Debug with redacted formatting. |
| [RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347) | ECH enabled plus buffered application writes before handshake completion and ECH rejection. Application config does not enable ECH; transport awaits TLS connect before HTTP writes. Patch prevents sending buffered application data on ECH rejection. |
| [RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348) | Non-default brotli certificate decompression. Locked feature tree contains only rustls ring/std; brotli is absent. Patch limits decompressor window allocation. |
| [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349) | Cached key-exchange prediction before authentication; PQ downgrade impact. Client resumption/session storage is disabled and this ring provider has no configured hybrid group. Patch delays remembered key-exchange hints until authenticated handshake completion. |
| [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382) | A configured trust anchor permits a path through specifically distrusted emSign intermediate keys. Rust certificate verification is directly used by mTLS and custody grants. Fixtures install an independent private CA, not public web roots. Production CA contents have not been inspected; no universal non-reachability claim. Patch rejects those SPKIs anywhere in the path, including anchors. |

These are scoped configuration/source observations, not offensive demonstrations or
independent production clearance. The patch also contains upstream connection/
cache/record-handling fixes and tests; application TLS APIs and feature selection
remain compatible, with TLS 1.3, exact roles, private CA, no resumption and bounded
transport unchanged. Rust checks, genuine socket/credential regressions and all
chain suites remain mandatory. **scc / RUSTSEC-2026-0205 remains P1 OPEN** with the
prior scoped HashSet assessment and no independent blanket exception. The
atomic-polyfill maintenance warning remains visible too.


2026-10-23 validation update: published R1/R2 corrections and TLS patch head
`ac476accfae4ed91bfe31fc0bfce1499831b9a42` passed Fast CI. Full run 39966475502
had twelve successful jobs; EVM child spending and the 1,000-account issuance/restart
benchmark passed, followed by a legacy TLS fixture failure (44 passed / 1 failed).
The aggregate correctly failed. The lifecycle test now uses an independent genuine
root-only fixture, preserving rejection of HD stores without their receipt identity.
[Detailed evidence and measurements](docs/acceptance/phase6gb/r1-r2-validation.md)
record the original failure, public signer proofs and 1.57922 complete accounts/s.
A fresh exact-final-head Fast/full run and independent R1/R2 re-review are required;
PR #37 remains Draft and unmerged, with scc P1 open.


The unsuppressed audit in final-candidate Fast/full runs 40000063620 /
40000095316 additionally reported **tokio 1.47.1 / RUSTSEC-2026-0386 OPEN**
(informational `unsound`, published 2026-10-13), alongside scc and atomic-polyfill.
The canonical advisory identifies `tokio::io::unix::AsyncFd::{new,with_interest,
try_new,try_with_interest}` accepting non-owning/invalid descriptors, with potential
I/O-safety violation and use-after-free. Scoped searches found no application
AsyncFd/raw-descriptor manipulation and no AsyncFd caller in the downloaded
application dependency sources outside Tokio's own implementation/tests/BSD AIO.
This is source/configuration evidence, not complete dynamic reachability or
independent exploitability clearance. The runtime is directly depended on by
coordinator, signer and transport; no broad exemption is asserted. Advisory fixes
start in 1.51.6 / 1.53.3; Tokio stays pinned pending a separately reviewed compatible
runtime assessment. Audit output is not suppressed. Record this additional open
finding in independent dependency review; scc P1 remains unchanged and open.
See https://rustsec.org/advisories/RUSTSEC-2026-0386 . No attack reproduction was
performed. A new exact-head gate remains necessary after this documentation update.
