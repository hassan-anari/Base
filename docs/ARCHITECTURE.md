# Target architecture and boundaries

**Status:** target/reference architecture; only a subset is implemented in main. See PROJECT_STATUS.md for actual implementation.

## Logical topology

External clients: Exchange Matching Engine / Order Book (independent), Payment Gateways / Merchants, Institutional Treasury, Admin/Operator, Auditors.
  -> Versioned Gateway/API / Tenant Authentication / RBAC / Idempotency / Quotas / Outbox
  -> Financial domain: immutable double-entry Ledger + Reservation + Trade Settlement + Fees
  -> Business domain: Merchant Invoice / Refund / Settlement; Risk/KYT; Policy and Human Approvals; Treasury
  -> Custody orchestrator: Address Provisioning, Indexing, Sweep, Gas, Withdrawal/Broadcast, Reconciliation
  -> Independent MPC authorization boundary / Coordinator / genuine 2-of-3 signer services (mTLS, isolated shares)
  -> independently reviewed EVM, TRON, Solana and currently limited isolated TON network adapters.

All components can share a modular backend initially; **logical ownership boundaries** must still be enforced. A microservice rewrite is not automatically required.

## Financial ownership and data flow

- LedgerAccount, LedgerTransaction and LedgerPosting are canonical for financial balances and liabilities. Every posting balances per asset; never use floats for financial amounts.
- Network events are authenticated inputs to a deterministic deposit/settlement state machine, not sufficient proof without chain-specific finality.
- Asset identity is chain/contract(or mint)/standard/decimals + immutable globally unique asset_key; same symbol across chains does not imply fungibility.
- Asset reservations lock available -> reserved, before any on-chain withdrawal or exchange obligation; unknown on-chain outcome retains reserved until authoritative reconciliation.
- Trade settlement is an *internal* atomic ledger movement of both traded assets and fees. No chain signature, RPC or wallet movement on each trade.
- Customer liabilities, operator treasury balances, network fees, merchant balances and clearing/suspense must be separately attributable by tenant/legal ownership.
- The existing ledger is **not yet tenant-aware for exchange trade settlements**; add tenant boundaries and models deliberately without replacing or retroactively changing established journals.
- Snapshot/reporting/analytics are derived projections, not independent sources of truth.

## Tenant isolation and trust boundaries

Design Tenant/Organization and principals; customer identity is scoped to tenant. Each API credential has explicit tenant/service/role/scopes; never trust caller-supplied user_id as an authorization boundary. Developer/merchant/ops capabilities are separated from signer policy authority. Prevent cross-tenant transaction IDs, account lookups, webhook delivery, wallet/address reuse and funding. Support distinct custody keyset policy and wallet class by tenant as needed, without promising one root per tenant by default.

## Transaction state machine

Persist: request -> policy/risk check -> financial reservation -> required approvals -> independent signer authorization -> original approved payload -> MPC signing -> persist immutable signed bytes -> broadcast -> network-specific authoritative confirmation -> settle ledger + costs. Rejected/denied request may release; ambiguous signed/broadcast result must retain reservation. Retries use original signed identity whenever possible and cannot create a duplicate payout. Pre- and post-restart reconciliation is explicit.

## Signer security

Coordinator stores public/session metadata; signer nodes retain encrypted private shares and nonce/execution tombstones. FROST or CGGMP creates threshold signatures; no complete custody private key is assembled in the backend. Human approval is not signer quorum. Independent signer-side authorization must resist a compromised Django app minting arbitrary transactions; see SECURITY_MODEL.md. Never imply one PostgreSQL DB, one network operator or current CI fixture provides a production trust boundary.

## Chain-specific adapters

Each network has canonical registry, genesis/chain identity, token verification, fee/finality, tx assembly, RPC and scanner recovery policy. Block confirmations alone do not fully model Solana/TON finality. Reorg and consensus evidence must be understood per family. Release gates are per network, not a single global feature flag.

## Lifecycle / throughput constraints

Phase 6G's first unmerged foundation uses a dedicated original CGGMP root per
allocation namespace, with immutable network/genesis, deployment ownership scope,
HOT class and DEPOSIT purpose. PostgreSQL reserves canonical `m/0/index` paths
transactionally and idempotently. A reservation creates neither an address nor a
UserWallet and cannot enter indexing or signing. Future custody account identity
must own one verified child and beneficial owner, with asset views sharing that
account only for the same owner. See [PHASE6G.md](../PHASE6G.md) for feasibility,
security boundaries and deferred child evidence; no tenant API is added early.

Phase 6G should use reviewed chain/algorithm-specific scalable provisioning rather than heavy fresh DKG for every deposit address. EVM/TRON secp256k1 derivation and Ed25519 FROST derivation must not be assumed interchangeable. Root bindings are immutable; resharing/rotation/recovery require versioned, auditable transitions. Hot/warm/cold are separate security classes; cold signing cannot reuse the hot environment's routine authorization.

## Scalability, events, and operability

Introduce reliable transactional outbox/inbox, monotonic event IDs, idempotent consumers, backpressure, bounded retries and DLQs for API webhooks and internal financial events. Use queue-based withdrawal and payout execution; database transaction isolation and lock order must be explicit. Instrument lag, missing chain history, signer availability, reconciliation debt, treasury runway, asset-liability gaps and security policy denials. Backup/restore tests must include both ledger and independently held signing material; avoid confidential leakage to logs/artifacts.

## Compatibility rules

Do not claim old Phase 1–5 docs describe current complete state; those files describe dated baselines. Do not invent production integrations just because DTO/routes or dashboard placeholders exist. Keep migrations additive, auditable and reversal-safe. Never change a settled financial journal to compensate for new behaviors.
