# Approved nine-phase roadmap and product work packages

**Version anchor:** 2026-10-11; last development merge Phase 6F-D PR #34. Status is a *development acceptance*, not chain production approval.

## Phases already delivered in development

| Milestone | Primary merged evidence | Status |
| --- | --- | --- |
| 1 Stability | PR #1 | Development baseline |
| 2 Authoritative ledger | PR #2 | Development implementation |
| 3 Chain registry/adapters | PR #3 | Development implementation |
| 4 Native outbound lifecycle | PR #8 | Development implementation |
| 5 Fungible token foundation | PR #14 | Development implementation |
| 6A MPC foundation | PR #25 | Development implementation |
| 6B mTLS transport | PR #26 | Development implementation |
| 6C.1 FROST DKG | PR #27 | Development implementation |
| 6C.2 FROST signing | PR #28 | Development implementation |
| 6D CGGMP ECDSA | PR #29 | Development implementation |
| 6E EVM integration | PR #30 | Isolated/testnet acceptance |
| 6F-A TRON/TRC-20 | PR #31 | Isolated acceptance |
| 6F-B Solana/classic SPL | PR #32 | Isolated acceptance |
| 6F-C TON V5R1/reference TEP-74 | PR #33 | Isolated acceptance only |
| 6F-D four-chain integrated custody | PR #34 | Isolated integrated acceptance |

## Remaining order — do not renumber

### Phase 6G — Scalable wallet provisioning and key lifecycle (NEXT)

Chain-specific **genuine** distributed address provisioning/derivation, keyset scopes and account bindings, Hot/Warm/Cold foundations, signer node/key lifecycle, new root and child lifecycle, auditable rotation, resharing/recovery and tested failure behavior. Explicitly evaluate performance and key security per algorithm, do not infer FROST and ECDSA can use identical HD derivation. Add schema and tenancy extension points, but do not implement all merchant/trade product APIs early.

Gate: no private-key reconstruction, measurable high-volume provisioning, durable identities, no cross-root replay/rebinding, key-loss and restart acceptance, final-SHA CI.

### Phase 7A — Governance and human authorization

RBAC/MFA, multi-person transaction and policy approvals, immutable approval records, policy precedence and USD value freshness; request/approver separation and account/tenant scoping. Implement API/backend then UI in Phase 9. Human quorum distinct from MPC quorum.

### Phase 7B — Risk/compliance

AML/KYT, sanctions provider abstraction, freeze/holds, transaction limits, merchant/customer risk cases, case management and approval to release. No unsupported claims about legal compliance.

### Phase 7C — Signer-side authorization and security evaluation

Independent signing authorization rooted outside a compromised backend's unilateral power; canonical intent/policy-bound tickets, signer verification, security audit and targeted penetration testing. Security findings are tracked to closure or explicitly accepted under the release governance process, never hidden behind CI.

### Phase 8A — Production infrastructure and chain activation

Independently hosted signer security domains, PKI/rotation, backup/restore/disaster recovery drills, secrets, network egress, high availability, forensic logging, production RPC provenance, archive capacity, safe deployments and independent *per-chain* mainnet enablement gates. EVM/TRON/Solana must be independently activatable. **TON public-network work is deferred at owner direction**; do not require TON Mainnet to release other supported chains. Do not treat isolated tests as mainnet proof.

### Phase 8B — Treasury, Gas, Batch

Hot/Warm/Cold liquidity policies, automatic sweeps/refills, fee/cost optimization, independently authorized cold release, batch payouts with partial outcome reconciliation, operational budgets and economic benchmarks.

### Phase 8C — Exchange and merchant financial platform

All ten Exchange Financial API families in API_CONTRACTS.md, tenant-scoped ledger/reservations/trade settlement, merchant onboarding/payment invoices/late/partial/excess/unknown payment cases, refunds/fees/merchant settlements and durable events/webhooks. API backend and contract tests in this phase; advanced UI in Phase 9.

### Phase 8D — Reporting, reconciliation and incident operations

Three-way chain-wallet-ledger reconciliations, asset-vs-liability snapshots, daily close, missing deposits, payout ambiguity, confirmed finance reporting, suspense handling, immutable audit exports, operational cases, alerting and incident response.

### Phase 9 — Product UIs, DX and complete end-to-end validation

Operator/Security/Treasury/Compliance/Merchant/Developer panels, API portal/SDK/documentation, policy editing and simulation UX, monitoring dashboards, E2E exchanges and payment-gateway workflows, load/chaos/restart and production-readiness evidence. UI/API features must already have backend acceptance, not be mere placeholders.

## Deferred and dependency policy

TON Mainnet global -239, validator transitions, dynamic shard split/merge, deployed real Jettons incl independently verified USDT and broad archival trust are **not part of upcoming 6G/7/8 default execution** unless explicit owner approval. Maintain P1 TON audit blocker and never enable public funds. No Phase 6F-E. No Bitcoin, matching engine, bridge or swap by default. Optional innovation must not displace required financial controls.

Each work package can span reviewable PRs; no big-bang implementation. A milestone is DONE only after code/docs/test evidence is merged; PRODUCTION APPROVED requires the separate per-chain and organization gate.
