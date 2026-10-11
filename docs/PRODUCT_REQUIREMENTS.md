# Product requirements register (target state)

**Reading rule:** *Binding* = approved product scope; *Optional* = candidate future feature; *Implemented dev* = exercised under isolated acceptance only. P0/P1/P2 are **priority within the relevant delivery stage**, not assertions that the issue is already present in production or an audit severity. See PROJECT_STATUS.md for verified now-state.

## 1. Wallet/key management — binding

- **P0 / Phase 6G:** Provision large numbers of truly spendable MPC deposit addresses without a full heavyweight DKG per address. Choose and document chain-specific supported derivation/address strategies; account for gas/address reuse and uniqueness. Verify no accidental shared root/child scope across tenants/chains.
- **P0 / 6G:** Keyset creation/import/activation, independent signer registration, root binding, key class/purpose, replacement and retirement, immutable auditing.
- **P0 / 6G–8A:** Genuine resharing/rotation/recovery/backups, recovery drills, loss-of-signer/insufficient-quorum procedures, encryption/restore security and no unauthorized restoration.
- **P0 / 6G–8B:** Hot/Warm/Cold wallet classes with independent key/policy controls, safe transfer flows and distinct cold exit procedures.
- **P1:** Watch-only and external vault visibility, operator wallet labels, import/migration, organization/merchant wallet grouping, safe address policies.

Acceptance: thousands of non-colliding provisioned addresses in performance tests; independent signer shares never reconstructed; keys reconfigured only via auditable authorized operations; wallet-to-asset/network binding immutable; loss/restart drills pass without leaking assets.

Phase 6G delivery uses exactly three implementation PRs: A (#36 merged), B (this
branch: complete genuine EVM/TRON child custody), C (final: Solana provisioning,
lifecycle, rotation/recovery and Hot/Warm/Cold foundations). B requires original
three-store HD evidence, immutable non-hardened reservation identity, independently
verified child public keys/addresses, genuine 2-of-3 child signatures, finalized
native/token deposit and spend acceptance, and measured complete issuance. Multiple
asset views share one canonical signing account per network/global customer;
asset identity remains separate. Missing HD evidence or quorum fails closed.
See [PHASE6GB.md](../PHASE6GB.md); branch implementation is not production acceptance.

## 2. Authorization and policy — binding

- **P0 / 7A:** Policy Engine by tenant, operation, chain, asset, amount, destination, time, risk, user role, wallet class, velocity. Deterministic precedence, explicit defaults and versioned snapshots.
- **P0 / 7A:** Distinct human approvals (e.g. 3 independent humans for withdrawals over configurable USD threshold) independent of cryptographic 2-of-3 signers; enforce creator-vs-approver separation, conflict of interest, quorum identity and MFA.
- **P0 / 7A–7C:** Policy-change approval/activation windows, dual control on destination allowlists, emergency pause, ticket invalidation on materially changed intent, independent signer-side authorization.
- **P1:** Delegate approvals with expiry, group/task inbox, simulation/dry-run, delayed trusted-recipient change and escalations.

Acceptance: one human cannot count multiple times; approval is bound to immutable transaction intent, price-feed timestamp and policy version; missing/stale USD valuation fails closed when USD rule is applicable; a compromised app alone cannot forge signer permission.

## 3. Deposit/finality and asset policies — binding

- **P0 / 7–8:** Network default + asset override + risk-sensitive minimum confirmation/finality policies, with safe chain-specific floors; version applied at decision time. Reorg reversal/compensation and quarantine workflow.
- **P0:** Exact token code/mint/master verification, native/token accounting isolation, no duplicate credits and fail-closed history gaps.
- **P1 / 8D:** Controlled manual investigation for missing memo/tag, wrong network, under-minimum payment, unidentified funds, unsupported token, stale indexer, archival/pruning or reorg; audited controlled exception management, never direct manual ledger edits.
- **P1 / 8D–9:** Operator rescan/backfill with limits, archival source provenance, per-chain lag/alerts and durable evidence.

Acceptance: negative finality/reorg tests and ledger inverse journals; no moved cursor over missing history; safe migrations and every exception traceable to evidence and an owner.

## 4. Withdrawal, payout and treasury — binding

- **P0 / 7–8:** Approval-linked durable queue, pause/resume, signed bytes and broadcast identity persistence, exact settlement and explicit unknown-outcome status; gas/network fee ceilings and velocity.
- **P0 / 6G–8B:** Multi-class liquidity: configurable wallet targets and source/destination restrictions. Cold cannot inherit automated hot-signing permissions.
- **P1 / 8B:** Triggered sweeping, gas reserves/refill and per-chain funding budgets; liquidity forecasts, shortage alerts, operator overrides.
- **P1 / 8B:** Batch payout strategy chosen by actual chain economics: EVM contract batching only with audited contract and net savings; TRON energy-aware strategy; Solana instruction packing/compute/account limits; TON deferred unless reauthorized. Per-recipient authorization, failure and reconciliation survive partial execution.
- **P1:** Scheduled payout, manual emergency override under elevated governance, wallet rebalancing, fee analytics.

Acceptance: throughput and cost benchmark vs individual sends; no double payments under crash/RPC loss; failed batch affects only appropriately identified recipients; accounting charges fees to correct asset/tenant.

## 5. Exchange financial integration — binding, Phase 8C

Ten mandatory endpoint families: Ledger Balance (available/reserved/total), Reserve, Release, Adjust Reservation, Trade Settlement, Fee Accounting, Internal Transfer, Account/Asset Status, Event API, Reconciliation API.

Trade engine supplies authoritative execution IDs, pair/asset identities, fill/cancel quantities, order IDs and version. Wallet-MPC validates tenant, scope, consistency and limits; double-entry posting is atomic. No matching/order-book logic in custody. Multiple fills/cancels/reordered events, replayed settlement requests and fee rounding are explicitly tested. Multiple account debit locks use deterministic ordering. Internal transfer is journal-only, not blockchain tx.

Acceptance: concurrent orders cannot overspend; retries are idempotent and conflicting payload reuse rejected; both buyer/seller legs and fees settle together or none do; financial decimals/integer units exact; no tenant bleed; events survive receiver outage.

## 6. Merchant payments — binding, Phase 8C

- **P0:** Merchants/organizations, scoped API credentials, invoices with source order ID, amount/asset/network, expiry and optional priced USD quote, destination address assignment, and lifecycle state.
- **P0:** Payment detection -> confirmation -> paid/partial/overpaid/late/wrong-network/duplicate exception routes; never treat webhook delivery failure as payment failure.
- **P0:** Tenant-separated merchant ledger, net/gross/fees, settlement thresholds, manual/scheduled settlement and payout authorization.
- **P0:** Signed replay-resistant webhooks with durable retries, delivery/audit history, re-delivery and inbound dedupe.
- **P1:** Full/partial refund against original credit, fee plan, hosted checkout/QR, reconciliation/export, conversion provider adapter.
- **P2 Optional:** white-label host and branding; do not assume launch requirement.

Acceptance: separate terminal payment vs notification state; under/overpayments and late payments have deterministic reversible financial actions; refund cannot exceed verified refundable amount.

## 7. Risk and compliance — binding framework, Phase 7B

Risk/KYT/AML/sanctions provider plug-ins and internal configurable holds/freeze at account, wallet, asset, tenant, network and global levels. Case ownership, evidence, appeal/release authority, time limits and audit. KYC/KYB and Travel Rule adapt to operator jurisdiction; no hardcoded jurisdictional legal claims. Missing required screening must fail closed (or route to controlled human review under policy), not silently allow.

## 8. Reconciliation/reporting/operations — binding, Phase 8D/9

Three-way chain events/on-chain controlled assets/internal liability ledger reconciliation; unsettled withdrawals, treasury ownership transfers and network costs; suspense account for unidentified money; historical balance snapshots, daily closing, liability-coverage dashboard, audit exports, alerts and incident timeline. Prove backup/restore and secure emergency controls. Signer/RPC lag dashboards, queue SLA, approved rescan, cost/runway analytics, API event delivery traces.

Acceptance: replay from immutable journals yields equal balances; discrepancies cause alert and accountable case, never auto-edit financial history; backup/restart and failover tests retain original signed/outbox identities.

## 9. Developer/API/platform — binding

Authenticated per-tenant scoped service APIs, optional delegated service roles, versioning, webhook signing and rotation, idempotency conflict detection, cursor pagination, robust decimal serialization, change management, rate limits, request correlation and sandbox mode. Operator, merchant and developer UIs with practical task inbox and audited policy edits in Phase 9. Fast CI vs selected full cryptographic final-head gate remain distinct.

## Optional future extensions (not accepted launch commitments)

Staking/earn, off-exchange collateral, OTC-specific suite, cross-chain liquidity routing, swaps/bridges, auto-conversion trading, multi-exchange connectivity, configurable white-label SaaS, general payment fiat rails and public proof-of-reserves. Implement only on later explicit authorization.

## Status disclaimer

As of main 4488016a, much of this register is **not implemented**. In particular tenant isolation, high-scale HD provisioning, approval quorum, trade settlement, merchant/invoice and policy-signing ticket platform are future work. A status must not be promoted without code and passing scope-relevant evidence.

Phase 6G-B child requests must retain the original custody machine authorization
across the coordinator hop. Every signer verifies a once-persisted signature under
the existing private-CA custody identity over the exact original child/root/path/
owner, digest, session, network and source. Substituting another approved child
must fail before nonce work. This does not implement Phase 7 human approvals or
independent policy authority. Historical root-only wallets remain usable; a
provisioning root with such bindings remains unissuable and needs an explicitly
authorized fresh dedicated root. Native operator gas grants must not create
customer liabilities; exact signed and consumed custody provenance distinguishes
them from external customer deposits. Existing historical journals stay intact.
