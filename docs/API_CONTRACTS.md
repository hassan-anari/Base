# Exchange / merchant / custody target API contracts

**Design specification only.** This file does **not** claim the routes exist today. Canonical OpenAPI schemas, validation, endpoint paths and auth infrastructure will be finalized during the assigned roadmap stages. Existing operator /api/wallet/... and /admin/ledger/... routes are not public exchange settlement APIs.

## 1. Transport, identity and financial rules

- Versioned external base path (candidate /api/v1). Idempotency-Key required for all externally retried financial writes; scope it by tenant + operation + external reference. Reuse with differing canonical payload must return conflict.
- Service-to-service mTLS or comparable strong machine identity; tenant-scoped key/role/scope, least privilege, audited rotation, per-service quotas; no caller-supplied tenant override.
- Monetary values encoded as exact decimal strings with asset precision and chain-qualified immutable asset keys, or integer base units. No JSON floating-point monetary values.
- Request correlation and durable immutable event IDs; explicit HTTP conflict vs validation vs unknown-outcome/pending vs temporary availability. No silent success on RPC/indexer uncertainty.
- Mutating requests must carry external source IDs, tenant scope, allowed operation authority and expected versions where appropriate. Every mutation is journaled with actor and policy snapshot.
- Outbox-backed signed webhooks with timestamps, nonce/event ID, retries, at-least-once delivery, dedupe and replay endpoint. Consumers must tolerate duplicate/out-of-order delivery.
- Separately permissioned Exchange Engine, Merchant, Treasury, Operator, Risk, Auditor and Signer identities; Exchange Engine cannot arbitrarily credit balances or sign transactions.

## 2. Ten binding Exchange Financial API families

| Target capability | Command/query and invariant |
| --- | --- |
| Balance API | Per tenant/customer/asset available, reserved/locked, total, as-of journal sequence; read-your-write consistency. |
| Reserve Funds | Reserve order quantity and optional fee budget atomically from available, unique order/execution reference; no overspend. |
| Release Funds | Release remaining unused reservation with idempotency; never unlock amount already settled. |
| Adjust Reservation | Partial-fill/cancel adjustment with expected version, bounded by original reservation and settled fills. |
| Trade Settlement | Multi-leg buyer/seller asset transfers and fees as one DB transaction; deterministic matching-engine execution ID and idempotent replay. |
| Fee Accounting | Configurable taker/maker/merchant/withdrawal/chain costs with precise rounding and beneficial ownership. |
| Internal Transfer | Atomic same-asset account-to-account journal movement with no chain broadcast and valid tenant authorization. |
| Account & Asset Status | Read/modify approved enabled, frozen, suspended, deposit-only, withdrawal-only and risk restrictions through elevated authority. |
| Event API | Durable ordered scopes (per aggregate where guaranteed), webhook/replay for balance/reserve/fill/deposit/withdrawal/invoice/settlement changes. |
| Reconciliation API | Evidence-bound chain-vs-ledger and external-order reconciliation jobs, summaries, mismatches and case resolution states. |

### Example semantic flows (non-binding route names)

**Order reservation**: Exchange authenticates -> submits order-ref, customer account, asset, exact amount, version and expiry -> available debit/reserved credit in one journal -> returns reservation ID, journal/event ID and balance sequence. Duplicate same request returns same reservation; conflicting same key is 409.

**Partial fill**: Exchange submits immutable fill ID, trade pair, buyer/seller reservations, exact executed quantity/quote and maker/taker fee schedule reference -> one atomic multi-asset posting transaction boundary (one or more asset-balanced journals inside one DB transaction) -> updates reservation versions and emits outbox after commit. If any leg fails, none commit.

**Cancellation**: Release only remaining reservation; a late or duplicate fill must resolve by deterministic ordering/version checks, not produce negative available.

**Internal transfer**: No MPC signer needed; reject cross-tenant/cross-asset unauthorized transfer, enforce limits and risk holds; return journal idempotently.

## 3. Custody operational APIs (target evolution)

Wallet/address create/list/retire, chain+asset+tenant binding, keyset/wallet class, per-asset deposit policy; deposit scan/status, withdrawal create/approve/cancel/track, cold treasury transfer, gas refill, batch payout with per-recipient terminal state, network/asset policy editing and locked approvals, whitelists and audit. Existing basic operator endpoints are an implementation starting point only. No arbitrary-signer API exposed to external clients.

## 4. Merchant payment APIs

Merchant create/team/credentials; invoice create with merchant order_ref, amount, asset/network, settlement preferences, expiry, return URLs and optional locked external FX quote. Status includes NEW, DETECTED, CONFIRMING, PARTIAL, PAID, OVERPAID, EXPIRED and REVIEW/REFUND paths; transitions are evidence-driven and versioned, not merely time-triggered. Merchant balances distinguish pending vs available vs reserved and settlement obligations. Refunds reference original invoice and enforce cumulative refunded <= refundable. Webhook delivery is independent of financial outcome; a PAID invoice stays PAID when notification fails.

## 5. Cross-cutting design questions to resolve during implementation

Tenant/legal account ownership semantics, settlement pair precision and fees, quote freshness, event ordering guarantees, policy-governed adjustments, reserve expiry and cancellation races, historical migrated balances, SLA/backpressure, pagination and OpenAPI error taxonomy. Record decisions before DB schema freeze; **do not infer default behaviors from this sketch**. These points are acceptance questions for the relevant phase, not invitations to change the original roadmap.

## Implemented Phase 6G-B internal/operator contracts (this branch)

Existing operator `/api/wallet/address` and `/api/wallet/create` can provision
EVM/TRON children only with explicit `MPC_PROVISIONING_ROOTS` mapping per registry
chain (`keyset_id`, `ownership_scope`), original HD agreement and safe live
development runtime. New issuance accepts address_index=0 only; this is an asset
view, not a caller-selected HD index. Existing legacy wallet lookup is preserved.
Global user_id is an existing ledger principal; these routes do not add external
tenant or merchant authorization. A token view shares the same owned account.

Custody-certificate-only coordinator POST `/v1/keysets/{id}/hd-attestation`
accepts the exact immutable root scope. POST `/v1/keysets/{id}/children` accepts
the original reserved ChildRequest. Both persist three authenticated matching
signer statements. Signer endpoints `/internal/v1/cggmp/hd/attest` and `/child`
accept only the coordinator certificate. Signing requests add optional
`child_authorization` and its canonical `child:<reservation-uuid>:<fingerprint>`
derivation_reference; absence preserves the root-only contract. Arbitrary paths,
root/source replacement, missing approval and cross-network replay are rejected.
`mpc_child_wallet` exposes trusted operator attest/issue commands, without root
creation/activation or a new external signing API. Partial RPC completion leaves
PROVISIONING; retry uses the same customer, namespace and original idempotency key.

Child SignRequest also requires `custody_authorization`, containing the original
custody client certificate chain as DER hex and P-256 ECDSA/SHA-256 signature as
ASN.1 DER hex. Sign the domain `Wallet-MPC/CUSTODY_CHILD_SIGNING_AUTH_V1` followed
by NUL and canonical sorted UTF-8 JSON of SignRequest with that field omitted.
Persist the exact grant once; retries cannot regenerate a different signature.
Signers verify private-CA client authentication, expiry and exact custody URI
before private operations. Dedicated attested DEPOSIT roots reject root-only
signing; legacy roots outside that namespace keep their existing contract.

POST `/v1/keysets/{id}/children` now accepts `{request: ChildRequest,
custody_authorization: {certificate_chain_der_hex, signature_der_hex}}`.
The public approval proof signs `Wallet-MPC/CUSTODY_CHILD_APPROVAL_V1` + NUL +
canonical sorted UTF-8 JSON of the original ChildRequest. All three issuing
signers validate the original custody credential before approval. The envelope
does not change the canonical child identity or authorize a private signature.


PR #37 independent-review correction: `/hd-attestation` now requires
`{statement: {request: HdRequest, dedication_id: <original-keyset-uuid>,
original_role: "UNUSED", target_role: "DEDICATED_DEPOSIT"}, custody_authorization}`.
Sign `Wallet-MPC/CUSTODY_HD_DEDICATION_V1` + NUL + canonical statement JSON.
Each signer independently authenticates custody and lifecycle eligibility before
mutation. Root/child reports now require `signer_signature`, signing the complete
unsigned report under separate SIGNER_HD_ROOT_RECEIPT_V1/SIGNER_CHILD_RECEIPT_V1
domains. All three independently pinned signer identities must verify at Django;
coordinator-supplied certificates and unsigned historical reports are rejected.
Original child/signing grant formats and canonical child references are unchanged.
