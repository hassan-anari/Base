# Architecture and product decisions (ADRs in compact form)

**Authority:** owner-approved choices, backed by explicit user discussions and implementation evidence. The entries below are durable decisions; newly suggested extras remain proposals until approved. Each material change should append a dated supersession, not quietly rewrite history.

## Accepted — 2026-10-11

| ID | Decision | Consequence |
| --- | --- | --- |
| D-001 | Wallet-MPC is self-hosted API-first enterprise custody **and financial operations** platform. | Signer-only implementation does not satisfy product completion. |
| D-002 | One authoritative append-only double-entry ledger; on-chain data is evidence. | No second wallet/merchant/trade balance source of truth. |
| D-003 | Exchange order book and matching engine are external services. | Narrow authenticated exchange reserve/settlement/event API; no embedded matching. |
| D-004 | Human multi-approver, business policy engine and MPC signer quorum are independent. | Require authorization separation and eventual signer-side checks. |
| D-005 | Support EVM, TRON, Solana as independently activatable families; keep TON isolated scope for now. | TON public Mainnet/sharding/USDT deferred; do not allow this to delay the other production readiness streams. |
| D-006 | Preserve original nine-phase plan, with 7A/7B/7C and 8A/8B/8C/8D subpackages. | Next is 6G; no invented 6F-E phase. |
| D-007 | Prefer broad safe operational customizability. | Expose per-chain/asset/risk finality policy, treasury/gas/batch rules, approvals; never weaken security floor via UI. |
| D-008 | Multi-tenant exchange/merchant use is a binding target. | Per-tenant ledger ownership, API credentials, policy and reporting boundaries need dedicated design. |
| D-009 | Keep Bitcoin, bridge/cross-chain swap, staking, advanced conversion and matching infrastructure outside required release scope. | Optional proposals only, separate authorization. |
| D-010 | Merge of successful isolated acceptance is development completion, not production acceptance. | Independent per-chain production gates and audit remain mandatory. |

## Explicit current deferral: TON

Phase 6F-C/6F-D previously documented eventual public TON parity as a mandatory production deliverable. The owner subsequently decided **not to let TON public-network work delay the remaining roadmap**. Accordingly, TON V5R1/native/reference Jetton isolated integration and tests remain in main; the public-network work, real TON USDT and dynamic shard support are **deferred, requiring renewed explicit authorization**, and TON must not be marketed as production-ready. This is an explicit change of schedule/priority, not evidence that previous safety blockers are solved. Retain external audit correspondence P1 OPEN.

## Proposed, not yet approved as mandatory launch scope

Staking/earn, cross-chain/bridge/swap, high-frequency market-data integrations, cross-venue collateral/liquidity routing, OTC special flows, third-party exchange connectivity, auto-conversion, hosted white-label branding and public proof-of-reserves. These are design opportunities, not roadmap commitments.

## Decision change procedure

Record ID/date/requester/reason, alternatives considered, scope impact, security and migration impact, work package, approved-by and evidence. If a new request affects established goals, update PRODUCT_VISION, PRODUCT_REQUIREMENTS, ROADMAP and PROJECT_STATUS together, then review in a separate PR where feasible.
