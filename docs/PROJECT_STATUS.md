# Project status — verified snapshot

**Repository:** hassan-anari/Base. **Verified baseline:** `24eed19e6e280083793c69c3901f5f746dd0a2fe`.
**Active branch:** [Phase 6G-B Draft PR #37](https://github.com/hassan-anari/Base/pull/37), unmerged development work.

**2026-10-23: independent review requires changes.** Two newly reproduced P1s
block this draft: R1 coordinator-fabricated HD/child evidence can publish unspendable
addresses; R2 coordinator-only dedication can disable historical root signing.
Repairs add independently pinned signer-origin signatures, custody-authorized
signer-local dedication/use state, migration 0032 and pre-fix evidence quarantine.
Acceptance and independent re-review are required on the new final head. Previous
CI passes below remain historical evidence, not clearance of these findings.
See [current remediation report](PHASE6GB_SECURITY_REVIEW.md). Existing scc P1 stays OPEN.

Verified implementation acceptance at `3670893bdfa6b21e2a99887e1238de5a979658cb`:
[Fast 38262366737](https://github.com/hassan-anari/Base/actions/runs/38262366737)
and [full 38262414457](https://github.com/hassan-anari/Base/actions/runs/38262414457)
passed, all fourteen jobs successful. 600 backend cases and 218 integration
scenarios passed (EVM 44, TRON 5, Solana 2, TON 3, network 162, persistence 1,
integrated 1), with zero required skips; Rust includes genuine child all-pair signing.
Actual 1,000-account issuance measured 1.5302/s, with all original identities
recovered after four-service restart/DB reconnect and no new approvals.
The [security/implementation report](PHASE6GB_SECURITY_REVIEW.md) supplies public
transaction evidence, migrations, benchmark hardware and remaining findings.
Its publication is revalidated on the final draft head; exact final SHA and
Fast/full links are recorded in PR #37. P1 scc remains OPEN. No independent
security acceptance, mainnet activation or merge is claimed.

2026-10-12 verification update: full run
[38181533803](https://github.com/hassan-anari/Base/actions/runs/38181533803),
head `2c22c8b66954444f47f3868ca5df2538c4183764`, failed EVM and its final gate.
The other twelve primary jobs passed, including 600 PostgreSQL backend tests and
TRON/Solana/TON/integrated regressions. Child EVM native/token acceptance and the
1,000-account benchmark passed before a legacy root test failed. Investigation
confirmed permanent DEPOSIT attestation of a shared module root; the root-only
rejection is legitimate, not a missing child grant or production contract defect.
The fixture now uses a fresh dedicated DKG root, retaining original authenticated
legacy signing. A targeted positive/negative credential regression is added;
The fresh focused genuine fixture passed two cases in 212.00s and all 600 backend
cases passed in 153.01s, with no migration drift. New final-SHA Fast and fourteen-job
acceptance were required and are recorded above. Details and exact
final evidence are recorded in [PHASE6GB.md](../PHASE6GB.md) and the existing PR.

PR #36 is merged as `24eed19e6e280083793c69c3901f5f746dd0a2fe`.
Its final head `4e0ef58d08196a42a3e308b65b6e67a2459626d7` passed all fourteen
jobs on [full CI run 38142219480, attempt 2](https://github.com/hassan-anari/Base/actions/runs/38142219480/attempts/2),
including the four Fast jobs and genuine four-chain suites. Earlier runner failures
and Fast run 38142190057 remain historical failure evidence; they were not erased.
The successful rerun supersedes the earlier unresolved runner-block status.

This branch implements genuine original-share HD agreement, upstream SLIP-10
public derivation and CGGMP24 child threshold signing for EVM/TRON, plus immutable
canonical custody accounts and asset views, and end-to-end original machine
request authentication (migrations 0029/0030/0031). It preserves
root-only wallets and the original ledger. See [PHASE6GB.md](../PHASE6GB.md) for
reviewable boundaries and current test evidence. This is not independent audit
acceptance, production permission or completion of Phase 6G-C.

## Shipped into main as development implementation

- One PostgreSQL-backed Django custody/ledger application; append-only double-entry journal and asset-key-based separation. Native/token deposit, withdrawal reservation and settlement flows and four-chain integrated consistency checks.
- Chain registry and controlled RPC source registry; exact token verification and scoped chain policies.
- Self-hosted 2-of-3 independent networked MPC signers: genuine FROST Ed25519 DKG/signing and CGGMP24 threshold ECDSA; durable authenticated coordinator/execution evidence and nonce/recovery discipline.
- EVM native/ERC-20, TRON TRX/TRC-20, Solana SOL/classic SPL, TON native/V5R1/reference TEP-74 *in reviewed isolated-development execution*.
- Phase 6F-D immutable financial asset identity and network-root bindings, integrated cross-family tests, settlement/fee ledger fixes and EVM native/ERC-20 resumable finalized historical scanners.
- Admin/operator-oriented Vue panels for overview/deposits/withdrawals/basic approval/chain-token settings/gas/node/ops; some existing operator API endpoints. **Not** a finished multi-tenant merchant/exchange UI.

## Most recent acceptance evidence

PR [#34](https://github.com/hassan-anari/Wallet-MPC/pull/34) final implementation head 04bb9c621a3aba5a6313bff0c6f5028b4fc803b3, merged as commit 4488016a. Final-SHA [Fast CI](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129528658) passed four required jobs; [full cryptographic gate](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129567244) passed all fourteen, 814 executions (779 pytest, 33 Rust, 2 frontend). One integrated multi-stage isolated scenario reported 8 independently generated roots, 8 deposit credits, 32 confirmed and 4 reconciliation-required attempts, 92 journals/184 postings and genuine native/ERC-20 backfill recovery including >1,000-block token history. This **does not prove production mainnet trust, audits or operator security**.

## Not yet implemented / do not claim otherwise

- Arbitrarily large provisioning throughput, Solana scalable provisioning, production root/child lifecycle, rotation/resharing/recovery and independent Hot/Warm/Cold management. EVM/TRON child provisioning is implemented on this unmerged branch, with measured development acceptance required.
- Human multi-person approval quorum, configurable transaction USD thresholds, governance-controlled policy changes, signer-side independently issued approvals.
- Multi-tenant external exchange financial service APIs (Reserve/Release/Adjust/Trade Settlement/Internal Transfer), merchant invoices/refunds/settlement and signed webhooks.
- Per-asset configurable finality override and broad operational on-chain reconciliation/dispute tooling.
- Complete batch-payments/treasury automation, active production-grade signer separation, independently verified live-network release per chain, merchant/developer UX.
- Independently verified production TON V5R1 external audit mapping; TON public sharding/real USDT/mainnet parity.

## Existing implementation distinctions

- /api/... endpoints currently include /wallet/address, /wallet/create, /wallet/balance/check, /withdrawals/request and admin ledger balances. They do **not** constitute externally authorized, tenant-scoped reserve/trade settlement APIs.
- Withdrawal currently has a basic admin approve/deny step; there is no configurable quorum of independent human approvers.
- UserWallet DB rows and demo derivation do not prove economically scalable issuance of independently spendable MPC addresses.
- ops.Chain.min_confirmations exists; per-asset and risk-based overrides are future features; Solana/TON require chain-native finality rules.
- HotWallet and gas topup/sweep primitives exist; a categorized ops cold_wallet observation does not implement true Cold Storage.
- Production public network routing is deliberately restricted; EVM test/development and isolated TRON/Solana/TON acceptance != operational mainnet.

## Open risks and release exclusions

**P1 OPEN:** independent TON V5R1 exact-artifact audit correspondence; broader chain-specific public-network trust and production security review. TON owner decision: freeze current isolated scope; defer mainnet/sharding/real USDT without blocking other chain families.

**Operational/P2:** EVM archival RPC/backfill capacity, historic diagnostic codes, dependency advisory triage, security of IdP/roles, independently authorized signer infrastructure, multi-tenant financial models, comprehensive production control reviews. Record newly discovered issues by evidence, do not assume absence of hidden vulnerabilities from passing CI.

**Prohibited in this snapshot:** customer funds, production withdrawals, automatic mainnet enablement, fake local signer fallback and unauthorized changes to approved protocol/network identity.

## Entry checkpoint for a future new chat

Read README -> AGENTS -> PRODUCT_VISION -> PROJECT_STATUS -> ROADMAP -> DECISIONS -> SECURITY_MODEL. Fetch latest main and current phase PR. Start Phase 6G only when instructed; no silent TON scope expansion. Aim toward complete exchange/payment API-first product, not signer-only roadmap.


Fresh 2026-10-23 CI additionally identified five post-baseline RustSec advisories in
rustls 0.23.45/webpki 0.103.15, blocking audit and dependent crypto jobs. The scoped
minimum patch correction is rustls 0.23.46/webpki 0.103.16; full final-head revalidation
is mandatory. No audit suppression or MPC protocol upgrade. scc P1 remains OPEN.
