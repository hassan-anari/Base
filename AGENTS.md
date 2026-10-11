# Wallet-MPC — standing instructions for AI coding agents and contributors

This file defines the mandatory read-before-code workflow. It is guidance for work in the repository, not a bypass of human approvals or security gates.

## Required orientation (every new chat/session/feature branch)

Read README.md, docs/PRODUCT_VISION.md, docs/PROJECT_STATUS.md, docs/ROADMAP.md, docs/DECISIONS.md, docs/ARCHITECTURE.md and docs/SECURITY_MODEL.md. Consult docs/PRODUCT_REQUIREMENTS.md and docs/API_CONTRACTS.md for relevant interfaces. Inspect implementation and existing phase evidence. **Verify current main SHA, active PRs and tests; this file's snapshot is historical.**

If the user's newest explicit decision conflicts with documentation, do not silently rewrite the product. Record the change proposal and seek owner approval when it changes scope/security; respect approved user direction for the task. If a historical document says an earlier phase feature is absent, check newer merged code before inferring present absence.

## Product invariant

Build a self-hosted enterprise custody + **financial core**, not merely an MPC wallet demo. Customer segments: exchanges, payment gateways, payment facilitators, merchants and institutional operators. External order book and matching engine; wallet platform is authoritative for balances, reserves, settlement, fees, on-chain custody and events. No second ledger.

## Security and financial invariants

- Never reconstruct a customer custody private key or substitute local-key signing for genuine MPC acceptance.
- Cryptographic signer quorum is independent of human transaction approval and independent policy enforcement.
- Bind every cryptographic authorization to tenant, keyset, network/genesis, asset, exact signed intent, recipient, amount, fee policy, nonce/sequence, policy version, expiry and operation ID as applicable.
- Preserve ledger double-entry conservation, immutable financial identity, Decimal/base-unit exactness, atomic settlement and idempotency. Never credit from mere wallet balance changes.
- An ambiguous broadcast/signing outcome stays reserved and requires authoritative reconciliation. Never assume timeout means failure.
- Fail closed on uncertain network identity, incomplete history, insufficient confirmations/finality, policy or signer quorum.
- No cross-tenant access, shared authorization scope or silent mutation of populated asset identities.
- Production activation per chain is independently gated. Never infer readiness from green testnet/isolated CI.
- No mainnet/customer funds until the applicable security/operations gates have been independently accepted.

## Scope and sequence

Phase 6F-D is accepted as **development** after PR #34; next Phase 6G key lifecycle/provisioning/Hot-Warm-Cold foundations. Keep original Phase 7A/7B/7C, 8A/8B/8C/8D and 9. TON public network, arbitrary shards and real USDT work are **deferred**; preserve existing TON code and open audit blocker, do not activate or widen it unless owner explicitly changes scope. Bitcoin, bridging, swaps, exchange matching engine and trading order book are out of current scope.

A proposed feature is not an implemented feature. A merged implementation is not production-approved. Label every status accordingly.

## Change workflow / evidence

1. Confirm clean baseline, base/head SHAs and exact scope. Use isolated feature branch, smallest reviewable PR.
2. Review data migration/backfill and compatibility before changing ledger, ownership or on-chain identity.
3. Define acceptance and negative tests, concurrency/restart/failure/unauthorized scenarios and audit trail.
4. Run targeted Fast CI; for MPC/chain/financial-impacting changes run the required final-SHA cryptographic gate. Do not weaken expensive checks to gain speed.
5. Update docs/PROJECT_STATUS.md, docs/DEVELOPMENT_HISTORY.md and affected requirements/decisions **in the same PR** when facts change. Never mark production-readiness from development tests.
6. Supply changed files, commit SHA, CI links, migrations, residual P0/P1/P2 risks, and proof of no production flag relaxation.
7. Stop for independent review. Never auto-merge, approve yourself, or enable customer-fund flows without explicit authorization.

## API-first design guard

Separate API identities and permissions for tenant/customer, exchange engine, merchant, operator, compliance, and signer. Matching-engine credentials only access narrow order-reserve/settlement authority, never generic balance mutation or arbitrary signing. Signed, durable, replayable outgoing event delivery is required. Stable schemas and backwards-compatible versioning are part of acceptance.

See docs/DOCUMENTATION_GOVERNANCE.md for conflict resolution and required documentation updates.
