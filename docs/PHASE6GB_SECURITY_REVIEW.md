# Phase 6G-B implementation and security report

Repository: `hassan-anari/Base`. One Draft PR: [#37](https://github.com/hassan-anari/Base/pull/37). No merge or public-mainnet activation.

- Base: `24eed19e6e280083793c69c3901f5f746dd0a2fe` (PR #36 exact merge).
- Implementation validation head: `3670893bdfa6b21e2a99887e1238de5a979658cb`.
- Implementation change extent: 52 files, 4,744 additions / 104 deletions at the implementation validation hash; publication additionally supplies documentation/public evidence.
- Fast: [38262366737](https://github.com/hassan-anari/Base/actions/runs/38262366737).
- Full cryptographic gate: [38262414457](https://github.com/hassan-anari/Base/actions/runs/38262414457).

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

## Implementation

The three independent signer services read their original encrypted validated CGGMP DKG and auxiliary stores. Original `extended_public_key()` chain code, public root, algorithm, DKG/keyset, network/genesis and immutable provisioning namespace must agree at all three services. Durable create-once signer and coordinator receipts prohibit replacement and cross-network interpretation. Missing historical material stays unissuable; no historical chain code is invented.

Canonical original reservations alone select `m/0/<index>` (non-hardened, index below 2^31). The pinned upstream SLIP-10 implementation derives and checks the child at the coordinator and each signer. Django independently verifies HMAC/public-point derivation with pinned coincurve 21.0.0. Canonical EVM and TRON addresses are checked against the child key and original network. Each signer durably pins original reservation, index, customer and retry identity before issuance.

The original two independently held CGGMP shares sign with upstream `set_derivation_path`. Signatures and recovered source are checked against the CHILD public key. Original execution IDs, tombstones, signed bytes and reconciliation remain authoritative. No private key reconstruction, private-child derivation, synthetic keys, mocked chain signatures or fallback are used for acceptance.

The custody service signs the complete original child SignRequest using its existing P-256 TLS identity key. The once-persisted grant binds child/root/path/customer/network/source, payload digest, session and operation context. Signers independently verify private-CA client authentication, validity, exact custody URI and P-256 signature before private operations and again in the worker. Changing to another valid already-approved child fails, as does dropping child authorization on an attested dedicated deposit root. This is original machine authentication, not Phase 7 human approval or an independently issued policy ticket.

Issuance commits an original PROVISIONING claim before external approval, then publishes an ISSUED canonical account only after authenticated three-store agreement and independent public verification. Retries recover that claim and UUID. Asset-specific UserWallet views share the canonical owner/address. No second ledger, balance reconstruction, index recycling or historical financial backfill is added. Existing root-only wallets remain usable; attestation rejects historical root bindings before contacting signers and requires a fresh dedicated root when necessary.

## Migrations and recovery

| Migration | Change and compatibility |
|---|---|
| 0029 | Adds original HD evidence, canonical custody accounts and nullable UserWallet account link. Historical links remain NULL. |
| 0030 | Freezes original HD/claim/issued/account-asset identity, prevents competing normalized address owners across tables under a shared advisory lock, enforces READ COMMITTED publication. |
| 0031 | Persists original custody grants, freezes populated grants, refuses deletion/retrospective authorization, prevents new root-only bindings to dedicated deposit namespaces while preserving historical bindings. |

Downgrade refuses retained HD/account/grant evidence. Caller-owned transactions cannot roll back an original namespace or issuance claim after external approval. RPC losses and partial signer commits retain the same claim. Missing approval, malformed paths, wrong chain, ownership or public key fail closed. Expired machine credentials cannot start private work; completed immutable public recovery does not retrospectively authorize an operation. An uncertain signature or broadcast remains reserved; timeout never releases funds. Ledger journals remain append-only and balanced.

## Security findings and dependency reachability

| Finding | Evidence and disposition |
|---|---|
| Existing P1 scc / RUSTSEC-2026-0205 | **OPEN.** `scc 2.4.0 -> everscale-types 0.1.2 -> protocol -> coordinator/signer`. Recursive pinned source review found one HashSet consumer (`cell/usage_tree.rs:316`), no TreeIndex reference or instantiation. The advisory's TreeIndex comparator-panic entry path was not found reachable in this scoped review. This is not independent clearance of unsafe library code. |
| Newly found EVM gas-credit liability inflation | Live native/token acceptance exposed operator MPC gas funding credited as a customer deposit at a shared address. Fixed with exact known GAS_TOPUP txid, recovered persisted signed bytes/source, original native destination/amount/network and consumed completed signing intent. Altered provenance aborts history; another payment from the same sender remains a deposit. Five focused negatives plus genuine acceptance cover it. **Independent P1 repair review pending.** No historical journal rewrite; preexisting deployments require separate evidence-led investigation. |
| Coordinator approved-child substitution | Per-store child approval alone did not authenticate which approved child custody originally requested. Fixed by the original custody machine grant verified independently before nonce work. Actual signer negative cases include another approved child, changed digest, absent/invalid signatures, wrong role/CA and expiry. **Independent repair review pending.** |
| Cross-table ownership publication race | A legacy asset insert could race account publication. Fixed by canonical-address advisory serialization, READ COMMITTED checks, immutable owner constraints and concurrent negative cases. **Independent migration/locking review pending.** |
| Existing production trust/lifecycle blockers | Independent signer policy authority, TON audit/public-network trust, funded-root retirement/lifecycle and tenant-aware infrastructure remain open. This PR grants no customer-fund or production permission. |
| Scalability limits | Per-root allocation and asset locks plus a globally serialized HD coordinator queue are measurable limits. One development host and 1,000 customers do not establish arbitrary population or production throughput. |

Cargo audit 0.22.0 loaded 1,296 advisories and scanned 255 packages. Both informational warnings remain visible: atomic-polyfill 1.0.3 / RUSTSEC-2023-0089 and scc 2.4.0 / RUSTSEC-2026-0205. No suppression or cryptographic major upgrade. Rust versions stay pinned; Cargo.lock adds only the transport dependency edge to the existing ring 0.17.14. Coincurve is additive public verification and never holds a custody private key.

Trust limits: original share stores, DB roles/triggers, private CA and custody TLS-key isolation remain prerequisites. Same-host development fixtures demonstrate independent encrypted stores, real services and protocol authentication; they are not production host/administrator isolation or an external cryptographic audit. This historical pre-review boundary is superseded by R1 above: portable signer receipts are now required; coordinator transport alone never proves independent signer origin.

Asset attachment explicitly follows keyset → provisioning root → account → asset lock order. Joined account locks target only the account row. A deterministic PostgreSQL blocking test covers both first attachment and idempotent attachment; recovery deadlocks are not hidden by retries.


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

## Final-head validation

All fourteen full-gate jobs passed on the implementation validation hash; Fast CI also passed. Complete integration inventory: **218 executed**, zero required skips.

| Check | Result |
|---|---|
| Django/PostgreSQL | 600 passed; system check zero issues; no migration drift; concurrency, ownership and recovery guards included |
| Cryptographic preflight | 8 passed; full 218-scenario inventory verified before expensive fixtures |
| Rust workspace | 31 Fast executions; protocol full suite 6 executions; 32 distinct cases after overlap, including genuine all-pair child signatures |
| EVM | 44 passed, including legacy/EIP-1559 all-pairs, new credential negatives, native/ERC-20 child spending and complete issuance/recovery |
| TRON | 5 passed, including native/TRC-20 child sources and historical root regressions |
| Solana | 2 passed, existing genuine FROST/native/SPL/nonce recovery scope |
| TON | 3 passed, existing isolated scope only |
| Network | 162 passed, actual TLS/role/DKG/signing negatives and recovery |
| Auxiliary persistence | 1 passed |
| Integrated four-chain | 1 passed, financial isolation and durability |
| Fast checks | Rust fmt/clippy, frontend contracts/normal/simulator builds, backend Ruff and unsuppressed dependency audit |

The 600 backend unit/contract cases include public synthetic metadata solely for database invariants; those are not counted as genuine MPC/chain evidence. Genuine three-service fixtures and actual validators provide that evidence in the integration gate. Local continuation checks additionally passed 600 backend cases in 153.01s and two fresh genuine credential/legacy-pair cases in 212.00s. Earlier local benchmark and child acceptance are supporting evidence only after the code change.

Negative coverage retains duplicate and conflicting idempotency/customer/namespace ownership; immutable DB tampering/index exhaustion/hardened paths; partial signer approval and lost issuance RPC; wrong original chain/genesis/public key/address/chain code; missing/stale root evidence; coordinator child/digest substitution; missing one/two signers; reservation/signing/signed-byte/broadcast restart; exactly-once deposit replay; existing reorg-sensitive four-chain history; and uncertain withdrawals remaining reserved. Journals are append-only and balanced.


## Genuine chain evidence

Fresh independent EVM deposit/hot roots and the preserved legacy root have distinct public keys. All three authenticated original stores attest HD material and approve several children; each child public key differs from its deposit root. Native and ERC-20 deposits credit exactly once. Actual finalized EVM receipts recover the child source for both native and token sweeps; genuine B+C signing works with A stopped. The hot MPC root funds token gas, without customer gas-credit inflation. Lost accepted RPC response retains original bytes/uncertain state until authoritative final confirmation. No faucet key signs custody movements.

TRON uses an independently authenticated CGGMP deposit root and real pinned GreatVoyage v4.8.2.3 validator. Three distinct child addresses, native TRX and TRC-20 deposits, genuine B+C child-source sweeps, solidification, TAPOS, resource/energy costs and exactly-once attribution pass. Actual validator OwnerAddress is checked against the intended child for both sweeps. Gas grants create zero customer credits. Original genesis/checkpoint controls and historical root functionality remain intact.

| Operation | Actual child source | Finalized transaction ID |
|---|---|---|
| EVM native sweep | `0xddb10fa5dca1eb1be3a05024fd74e153b04424fb` | `0x61883e61a0f44e411c446f4a5871c2301274388641267622658dd10c4aa86f39` |
| EVM ERC-20 sweep | `0xddb10fa5dca1eb1be3a05024fd74e153b04424fb` | `0x7d5bb90c8fa710d52ff23d6009b3a63ddc31b6eae251ba67771b0e751f0b8103` |
| TRON native sweep | `TJ73YbBGGmeAEDUCPQM58qdAaoAgb2qk15` | `9226ad5d7268436b7b42eeac967e4f7d538a84e7c1006e08dcedc9035304523a` |
| TRON TRC-20 sweep | `TJ73YbBGGmeAEDUCPQM58qdAaoAgb2qk15` | `1142aa391c805710242b226380995a03d5c4d94df9dc5c244d148948db3df6a5` |

EVM deposit root `02937dcc29b11966bffc71217241789d1c79982f7938e6e4d6b541a5e8b1274179`; child `0237289c81def2ab6717af2682d9e83f37f78e143420b2d24d95c64e4379208166`. TRON deposit root `020c2fc20cd98206c6168280be1e536c9971b8267c62af709824172e5987be2850`; child `02b1a885f4bacf7e534ddea4bef1fc057f5dfe11e6c32e48ee1836692dfc742553`. The accompanying public JSON records all issued examples, original session/execution IDs, signers, sources and final receipts. These isolated validators are not production trust or public-mainnet activation.


Public records: [EVM](acceptance/phase6gb/evm-child-implementation-ci.json),
[TRON](acceptance/phase6gb/tron-child-implementation-ci.json), and
[CI verification/artifact digests](acceptance/phase6gb/implementation-validation.json).
These contain public material only; no private shares, nonces or TLS keys.

## Complete issuance performance

Complete actual issuance: **1.5302 accounts/s**, 1,000 customers, 8 workers, 653.488 seconds. Each account includes reservation, genuine authenticated derivation/credential approval at all three original stores, independent Django public verification, persisted issuance and native asset view. This is not the earlier reservation-only rate.

Runner hardware: 4 logical CPUs, reported CPU `x86_64`, 16,373,452 KiB RAM, `Linux-6.17.0-1022-azure-x86_64-with-glibc2.39`; Python 3.11.17; PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2). A generic x86_64 CPU report does not identify the physical model. One development host holds four real services with independent encrypted stores; it does not prove production host/admin isolation.

| Stage | Samples | Mean ms | Maximum ms |
|---|---:|---:|---:|
| asset view | 1,000 | 15.810 | 210.783 |
| independent public verification | 2,000 | 2.174 | 3.991 |
| persistent issue save | 2,000 | 2.068 | 5.197 |
| postgres queries | 78,000 | 0.370 | 50.753 |
| postgres select for update | 12,000 | 0.378 | 50.753 |
| reservation | 1,000 | 5.451 | 89.492 |

Reservation throughput within the full workload is 1.5302/s. Mean client-observed coordinator approval time: 5.134s over 1,000 requests, including queued signer/coordinator work. The bounded HTTP timeout is 120s. SQL FOR UPDATE latency includes query work and lock waits; no separately isolated wait-time claim is made. Account table/index size: 9,060,352 bytes.

Four-service restart: 0.662s. Single DB reconnect/idempotent recovery: 0.065s. Full 1,000-UUID recovery with eight workers: 56.182s, 17.799/s, zero new signer derivation approvals. Issuance performs zero CGGMP signatures/nonces; actual spendability and signing are measured separately.

Individual genuine signing observations: EVM native including prepare/dispatch 5.328s, EVM token after dispatch 5.009s. TRON child sessions to consumed signature: 4.572s, 4.640s. These are observed individual development operations, not signing-only percentiles. Fresh root DKG/auxiliary setup is excluded from per-child issuance and separately logged as public root-setup diagnostics.

Prior supporting 2c22 local data: 1,000 customers/eight workers, 599.690s, 1.6675 accounts/s, full recovery 54.700s at 18.281/s on three logical AMD EPYC 9V74 CPUs/10,207,516 KiB RAM/PostgreSQL 16.15. Prior supporting 2c22 CI measured 1.6008/s with successful 1,000-account recovery before the later legacy test correctly failed. Neither is reused as final-head proof.

One 1,000-customer run cannot establish million-customer behavior, unlimited throughput, multi-host latency or production capacity. Per-root PostgreSQL locks and global coordinator HD serialization remain measurable limits. Full signer/share restoration and lifecycle RPO/RTO belong to final Phase 6G-C.


## Historical CI correction and preserved failures

PR #36 final head `4e0ef58d08196a42a3e308b65b6e67a2459626d7` passed all fourteen jobs on [38142219480, attempt 2](https://github.com/hassan-anari/Base/actions/runs/38142219480/attempts/2), then merged exactly as the base above. The earlier Fast failure 38142190057 and runner-blocked attempts are preserved. The successful rerun corrects the formerly unresolved status without erasing it.

Earlier Phase 6G-B development attempts also remain failures: overlapping pytest databases, missing Ganache, live-indexer environment not set, EVM gas-credit finding, five-second benchmark HTTP timeout, and the 1,000-account restart replay lock-order deadlock. Supporting full run 38175926795 passed all required suites except EVM, and correctly failed its gate. Fresh immutable roots/genesis and separate PostgreSQL test databases are used on corrected runs; original evidence is not deleted or rewritten to make a rerun pass.

## Exactly what remains for the final Phase 6G-C PR

Solana scalable chain-native provisioning with reviewed Ed25519/FROST semantics; key generation activation/drain/retirement; signer/node/share lifecycle; versioned rotation, recovery/resharing/backup drills; Hot/Warm/Cold foundations and class boundaries. Preserve issued ownership, original financial journals and transaction recovery already delivered here. No unreviewed FROST HD, TON public expansion, Phase 7 approval/RBAC/AML, Phase 8 treasury/batch, matching engine, merchant APIs, Bitcoin, bridges or swaps are included.

The three-PR Phase 6G direction remains A (#36 merged), B (#37 this draft), C (one final PR). Independent review must cover the original HD semantics, machine grant serialization/replay, dedicated-root separation, nonce recovery, database guards and all open findings before any merge. No self-approval or merge was performed.

## Final draft-head evidence seal

This report records the tested implementation commit above. Its publication adds
only documentation/public evidence. The **exact final draft head**, its Fast run,
its fresh fourteen-job cryptographic gate and final runner artifacts are recorded
in the [PR #37 acceptance report](https://github.com/hassan-anari/Base/pull/37).
Each job independently checks REVIEWED_HEAD_SHA; the cryptographic manifests bind
scenario execution to that hash. Revalidation of the documentation seal is required
before handoff. No independent review, merge or production authorization is implied.

## Final-head EVM regression cause and repair

The failed 2c22 full run 38181533803 is preserved. Retained original stores reproduced HTTP 400 `{"error":"Invalid"}` from the coordinator's immutable dedicated-root guard before child credential verification. Child acceptance had attested the shared module root for DEPOSIT, then legacy all-pair tests attempted root-only signing. A DB test flush cannot reset signer/coordinator receipts. This was an outdated fixture identity, not a missing child credential or an unintended production contract incompatibility.

Acceptance now creates a fresh genuine deposit root, separate from the historical fixture and separate hot root. Hostile child requests explicitly carry the dedicated root's keyset ID so negatives exercise their stated condition rather than a stale-keyset mismatch. The new regression rejects wrong-role POST requests and wrong-CA/expired/ambiguous/unknown client credentials while trusting the genuine server CA, verifies no session exists, then obtains and independently verifies a genuine root signature with custody mTLS. It repeats immediately after child issuance. Dedicated-root fallback remains rejected; child private grants and public credential-readiness proofs remain mandatory. No production cryptographic/authorization code, original receipt, migration or safety flag was relaxed by this continuation.

The intermediate 1a00466 run 38261875338 also remains a failed EVM attempt:
the direct hostile child request still carried the legacy fixture keyset ID.
This was corrected explicitly before the successful 3670893 acceptance.
Corrected local EVM executed all 44 cases with zero skips in 1391.85s;
1,000-account issuance measured 1.5736/s and full identity recovery 56.666s.
The successful CI independent deposit/hot setup observations were 230.249s and
143.660s; original fixture auxiliary setup was 240.109s. They are excluded from
the complete per-account issuance benchmark and do not establish root-generation
percentiles. The final draft-head gate is separately recorded in PR #37.


Historical root-only TLS key profiles remain supported. If the TLS identity cannot
create supported P-256/PKCS8 detached receipts, HD dedication is disabled without
an unsigned fallback; existing root signing retains its original authenticated
contract. Existing signed HD stores require their original receipt identity and
fail closed if unavailable. The genuine signer regression includes a legitimate
legacy key-encoding compatibility check. Identity rotation remains separately gated.
