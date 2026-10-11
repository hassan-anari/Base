# Project status — verified snapshot

**Verified on:** 2026-10-11. **Repository:** hassan-anari/Wallet-MPC.
**Verified main:** 99d005e23f1463ebb245fc451552af944a1fdd1f (product source-of-truth PR #35).
**Active work:** Phase 6G first provisioning foundation,
[Draft PR #36](https://github.com/hassan-anari/Wallet-MPC/pull/36), for independent review; unmerged.
Re-verify main and open PRs before subsequent development.

## Phase 6G branch scope — IN PROGRESS, not merged

[PHASE6G.md](../PHASE6G.md) audits the pinned CGGMP/FROST libraries and describes
the first reviewable slice. This branch adds authenticated original-root namespace
registration, immutable network/deployment-owner/HOT/DEPOSIT bindings and
PostgreSQL concurrent/idempotent non-hardened path reservations (0027/0028).
**No addresses are issued; reservations are not spendable wallets.** Warm/Cold,
FROST derivation, child signing, lifecycle automation and production activation
remain unavailable. The 10,000-row reservation benchmark is 216.743/s on local
PostgreSQL 16.15 and explicitly excludes DKG, signing, rent and issuance costs.
Final-head tests/CI and Draft PR reference belong in the review handoff; this
entry is not merged acceptance or Phase 6G completion.
GitHub Fast CI and the requested full cryptographic gate failed before runner
assignment (zero steps); the full suites were skipped. Local passing checks do
not satisfy that final-head gate. See the Draft PR for the latest exact-head
run links and evidence; CI runner execution must be restored before acceptance.
Supporting code head 09653ef passed 571 PostgreSQL tests and fresh genuine-service
registration/restart (857.41s). Cargo audit exited 0 but reported atomic-polyfill
maintenance and scc 2.4.0 unsoundness advisories. The latter remains a P1 dependency
review finding pending reachability assessment; see PHASE6G.md. No dependency or
TON restrictions were changed. An evidence-only final documentation commit does
not change the tested implementation; it still requires exact-head GitHub gates.

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

- Scalable real MPC HD wallet creation for arbitrarily large customer counts; production-ready root/child lifecycle, rotation/resharing/recovery, independent Hot/Warm/Cold product management.
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
