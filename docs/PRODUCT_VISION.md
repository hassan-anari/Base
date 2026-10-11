# Product vision and scope — Wallet-MPC

**Decision status:** owner-approved product direction, consolidated 2026-10-11. Requirements below describe the **target end state**, not claims of delivered functionality.

## Mission

Deliver an independently deployable, self-hosted, API-first, enterprise-grade digital-asset custody and financial operations platform for centralized exchanges, payment gateways, payment facilitators, institutional treasuries and merchant providers. Customers operate their own security infrastructure without mandatory hosted MPC-custody dependency.

The system must support secure custody, deposits/withdrawals, scalable deposit address provisioning, internal beneficial ownership accounting, trading-system financial settlement, merchant payment acceptance, risk/governance, treasury and observability. Product quality is measured not by the number of supported cryptographic protocols, but by correct, recoverable, usable, operator-controlled financial workflows at scale.

## User personas and outcomes

- **Exchange operator / finance:** see available/reserved/total per customer and asset, total customer liabilities vs controlled on-chain assets, withdrawals requiring attention, hot liquidity, gas capacity, stuck items, daily close and reconciliation.
- **Security administrator:** control and review signer topology, root/keyset lifecycle, privileged policy changes, MFA, approval groups, destination allowlists, immutable audit, emergency freeze.
- **Withdrawal operations:** safe queues, human review, batch payouts, network fee controls, broadcast uncertainty resolution, approval SLA.
- **Compliance / risk:** account freeze, KYT/AML/sanctions decisions, case management, evidence and escalation.
- **Merchant / payment facilitator:** onboarding, tenant API credentials, invoice/payment state, exceptions, refunds, settlement timing, signed webhooks and per-merchant fees.
- **Developer / external exchange engine:** stable versioned APIs for reservations, partial fills, atomic trade settlement, idempotent posting, events and reconciliation; no direct SQL or key access.
- **Auditor:** immutable journal and policy evidence, historical balances, exception reports and replayable financial statements.

## Binding product commitments

1. Single authoritative append-only, double-entry financial ledger with tenant and asset isolation. On-chain wallet balance is observational, not a customer's spendable balance.
2. Real MPC protocols: distributed FROST Ed25519 and CGGMP24 threshold ECDSA as appropriate for approved chains. Human approval, signer-side policy and cryptographic quorum are distinct.
3. EVM, TRON and Solana are target independently activatable production families after independent readiness gates. TON's **existing isolated V5R1 / native / reference TEP-74 foundation is retained**; further public-network parity is deferred by owner decision without being misrepresented as complete.
4. Configurable policy-driven custody and finance: amount/asset/network/risk thresholds, confirmation/finality floors, approval groups, withdrawal velocity, sweep, treasury liquidity, gas budgets, payout scheduling, merchant settings and event delivery. Critical security invariants cannot be disabled through the UI.
5. Secure Hot/Warm/Cold separation, watch-only tracking, independent signers, key lifecycle and recoverability.
6. Exchange integration: Balance, Reserve, Release, Adjust Reservation, Trade Settlement, Fee Accounting, Internal Transfer, Account/Asset Status, Event API, Reconciliation.
7. Payment gateway: merchant management, invoices, paid/partial/overpaid/late handling, secure reconciliation, refunds, fees, settlement and webhooks.
8. Multi-tenant and multi-organization security boundaries, operator/merchant/developer interfaces and full observability/incident workflows.
9. High-volume operations are ledger/API-first, **not blockchain-call-per-trade**. On-chain signing is reserved for true on-chain movement.
10. Explicit evidence-driven phase acceptance; deployment authorization remains a separate business/security gate.

## Boundaries / non-goals

Not an order book, matching engine, pricing engine or spot/futures exchange backend. Those remain independent services using narrow exchange-facing APIs. No Bitcoin in the current roadmap. Do not silently add bridging, cross-chain swaps, derivatives, staking/earn, off-exchange collateral, automatic asset conversion or white-label SaaS as binding release requirements; list such ideas as optional future extensions. KYC/KYB, market data, AML analytics, Travel Rule and banking/payment rails may use optional external integrations governed by jurisdiction and operator policy.

## Practical product acceptance (high-level)

An external exchange can reserve two customers' assets, submit matched-trade executions with partial fill/cancel behavior, atomically settle both sides and fees, replay the same request harmlessly, reconcile and consume durable events. A merchant can create an invoice, receive a verified payment, resolve edge cases, refund under policy and settle with audit evidence. Operators can control hot/cold policies and signer approvals, react to outages and restore from tested backups. All money-moving paths survive concurrency, restart, duplicate delivery and unknown broadcast outcomes without unauthorized movement.

See PRODUCT_REQUIREMENTS.md for detailed acceptance criteria and ROADMAP.md for sequencing.
