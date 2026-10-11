# Verified development history and evidence

**Source policy:** timeline below is extracted from merged pull requests / main history, not an assertion that every historical attempted PR merged. The repository had 34 PRs as of 2026-10-11; several earlier attempts were closed **without merge** (e.g. PRs #4–7, #9–13, #15–24). Do not include unmerged proposals in delivered capability counts.

## Mainline implementation chronology (UTC)

| Date | PR | Delivered development milestone |
| --- | --- | --- |
| 2026-10-03 | [#1](https://github.com/hassan-anari/Wallet-MPC/pull/1) | Stabilization, fail-closed signer/demo boundaries, sweep/gas/idempotency regressions |
| 2026-10-03 | [#2](https://github.com/hassan-anari/Wallet-MPC/pull/2) | Phase 2 authoritative double-entry custody ledger |
| 2026-10-03 | [#3](https://github.com/hassan-anari/Wallet-MPC/pull/3) | Phase 3 DB-backed chain registry and adapter/indexer resolution |
| 2026-10-04 | [#8](https://github.com/hassan-anari/Wallet-MPC/pull/8) | Phase 4 durable native transaction execution/reconciliation |
| 2026-10-05 | [#14](https://github.com/hassan-anari/Wallet-MPC/pull/14) | Phase 5 reviewed fungible-token custody foundation |
| 2026-10-08 | [#25](https://github.com/hassan-anari/Wallet-MPC/pull/25) | Phase 6A self-hosted MPC baseline, disabled outside development |
| 2026-10-08 | [#26](https://github.com/hassan-anari/Wallet-MPC/pull/26) | Phase 6B TLS 1.3 mutual-authenticated transport |
| 2026-10-08 | [#27](https://github.com/hassan-anari/Wallet-MPC/pull/27) | Phase 6C.1 genuine distributed FROST DKG / signer-local stores |
| 2026-10-08 | [#28](https://github.com/hassan-anari/Wallet-MPC/pull/28) | Phase 6C.2 FROST distributed signing and durable nonce safety |
| 2026-10-09 | [#29](https://github.com/hassan-anari/Wallet-MPC/pull/29) | Phase 6D genuine CGGMP24 ECDSA |
| 2026-10-09 | [#30](https://github.com/hassan-anari/Wallet-MPC/pull/30) | Phase 6E root-keyset EVM MPC integration |
| 2026-10-09 | [#31](https://github.com/hassan-anari/Wallet-MPC/pull/31) | Phase 6F-A isolated TRON / TRC-20 |
| 2026-10-10 | [#32](https://github.com/hassan-anari/Wallet-MPC/pull/32) | Phase 6F-B isolated Solana / classic SPL |
| 2026-10-10 | [#33](https://github.com/hassan-anari/Wallet-MPC/pull/33) | Phase 6F-C isolated TON V5R1 / TEP-74; exact audit OPEN |
| 2026-10-11 | [#34](https://github.com/hassan-anari/Wallet-MPC/pull/34) | Phase 6F-D four-chain integrated development acceptance and financial identity/EVM history hardening |

Historical Phase 6F-D merge SHA: **4488016a668283868633eb1a7fa2f64187a93b56**. PR #34 final reviewed feature SHA: **04bb9c621a3aba5a6313bff0c6f5028b4fc803b3**. Different SHAs are expected for merge commits.

## Subsequent orientation and active development (not merged capability)

- 2026-10-11: [PR #35](https://github.com/hassan-anari/Wallet-MPC/pull/35) established
  the authoritative enterprise product/engineering documents; verified main
  `99d005e23f1463ebb245fc451552af944a1fdd1f`.
- [Phase 6G Draft PR #36](https://github.com/hassan-anari/Wallet-MPC/pull/36),
  branch `phase6g-provisioning-foundation`, based on that exact main:
  pinned-source crypto feasibility audit, original-root namespace registration
  and durable non-hardened path reservations with migrations 0027/0028. Unmerged,
  for independent review. Local 10,000-row PostgreSQL benchmark: 46.1376s,
  216.743 reservations/s, 3,579,904 table/index bytes. These are **not issued
  spendable addresses**. See [PHASE6G.md](../PHASE6G.md); exact final head/CI
  links and genuine-service evidence are provided in the Draft PR handoff.
  Initial local evidence: 570 backend tests and genuine CGGMP/mTLS registration
  plus coordinator/DB restart passed (338.10s). GitHub jobs failed before runner
  assignment; final-head Fast/full CI acceptance remains blocked, not waived.
  Supporting code head 09653ef subsequently passed 571 PostgreSQL tests and a
  fresh genuine CGGMP registration/restart case (857.41s). Cargo audit exited 0
  with atomic-polyfill maintenance and pinned scc 2.4.0 unsoundness warnings;
  scc comes through existing everscale-types, uses HashSet in inspected source,
  and requires separate dependency/reachability review. Final documentation
  records this finding without changing crypto dependencies or tested code.

## Significant discovered/fixed failure classes (development)

- Phase 6A–D: move from demo/local signing primitives to genuine independently running DKG/signers, authenticated transport, robust execution identity and nonce safety.
- Phase 6E–F: reviewed network/genesis identity, chain-specific signing/broadcast/finality and token-code matching.
- Phase 6F-D: immutable populated asset financial identity, preventing native/token aliases and root rebinding; safe EVM genesis pins and completion-gated settlement; native network-fee posting; signed recipient serialization fix.
- Phase 6F-D follow-ups: native EVM scanner previously reported false head after partial read and last-64-only scanning; repaired with 64-block verified historical chunks, height/hash checkpoint, atomic deposit-credit/cursor and migration **0025**.
- Phase 6F-D final: ERC-20 formerly used 1,000-block initial lookback and could accept missing/false-empty logs; repaired with genesis backfill, receipt-trie/root corroboration, overlap, fail-closed errors, atomic journals/checkpoints and migration **0026**. Original financial-identity trigger migration **0024** stays.
- PR #34 final [full-gate](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129567244) 14/14 successful, 814 test executions. Real isolated recovery scenario older than 1,000 blocks accepted exactly once; unknown broadcast outcomes remain reserved.

## Scope decisions made during design discussions (NOT historical implemented code)

- Approved target broadened to self-hosted **Custody + Ledger + Exchange APIs + Merchant Payments + Treasury + Governance + Operations + UI**.
- Crypto 2-of-3 signer quorum and multi-human approval policy are explicitly independent. Example rule above USD 500 requires three humans only if configured in future Phase 7; **not active now**.
- Matching engine/order book developed separately, connected by narrow financial API; ledger exclusively owns balances and trade settlement.
- Configurable per-network/per-asset deposit finality, Hot/Warm/Cold, gas station optimization, batch payments, invoice/refund, audit/monitoring are binding target features, not claims of completed implementation.
- TON remains frozen at successful isolated foundation; public Mainnet/sharding/actual TON USDT work deferred. Deferral **does not** imply production approval or waiver of audit P1.
- No new numbered phase, no Bitcoin or bridge by default.

## How to maintain this timeline

On every milestone merge, append date, exact PR/merge SHA, capabilities with implementation-level evidence, tests/CI links, discovered risks, migrations, and changed scope/architecture decisions. Do not overwrite chronology with a guessed percent complete. Use PROJECT_STATUS.md as a separately refreshed current-state view.

## Phase 6G-A merge correction and 6G-B active branch

PR #36 is merged as `24eed19e6e280083793c69c3901f5f746dd0a2fe`.
Its final head `4e0ef58d08196a42a3e308b65b6e67a2459626d7` passed all fourteen
jobs on [full CI run 38142219480, attempt 2](https://github.com/hassan-anari/Base/actions/runs/38142219480/attempts/2),
including the four Fast jobs and genuine four-chain suites. Earlier runner failures
and Fast run 38142190057 remain historical failure evidence; they were not erased.
The successful rerun supersedes the earlier unresolved runner-block status.

Phase 6G-B is based on that exact merge, on `phase6g-b-child-wallets`.
Original-share HD attestation, canonical child derivation, genuine threshold child
signing and additive canonical account/asset associations are implemented in this
single branch. Migrations 0029/0030/0031 leave historical wallet/ledger rows intact.
Final validator, throughput and exact-head CI evidence belongs in
[PHASE6GB.md](../PHASE6GB.md) and the draft review handoff. Unmerged capability
is not counted as shipped. Earlier failed harness/CI attempts remain evidence.
Final Phase 6G-C owns Solana provisioning, lifecycle, rotation/recovery and wallet
security-class foundations; no additional implementation PR split is authorized.

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
