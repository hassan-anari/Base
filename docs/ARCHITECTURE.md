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

Phase 6G-A's immutable canonical `m/0/index` reservation remains the allocation
identity. Phase 6G-B adds original chain code and extended root agreement from
all three independently validated signer stores. The coordinator and every signer
use pinned upstream SLIP-10; Django independently verifies public derivation.
A durable `MpcCustodyAccount` claim precedes external RPC and becomes ISSUED only
after three signer approvals. A reservation alone stays RESERVED and unissuable.
The account's immutable owner/address/key/path/network is authoritative; nullable
`UserWallet.custody_account` supplies asset views sharing that same owner/address.
Existing customer IDs are global ledger principals, not a new tenant namespace.
There is no journal backfill or second ledger. Child authorization is committed
in original transaction, signing request and execution; the original 2-of-3 shares
sign with upstream `set_derivation_path`, and verification uses the child key.
The custody machine signs the entire original child request with its existing
P-256 TLS identity. Each signer verifies that grant across the coordinator hop
against the private CA before nonce work. Migration 0031 persists it once with
the original session; coordinator child substitution invalidates the signature.
This is machine authentication, with independent policy authority still Phase 7.
See [PHASE6GB.md](../PHASE6GB.md) for failure/recovery and throughput limits.

Phase 6G should use reviewed chain/algorithm-specific scalable provisioning rather than heavy fresh DKG for every deposit address. EVM/TRON secp256k1 derivation and Ed25519 FROST derivation must not be assumed interchangeable. Root bindings are immutable; resharing/rotation/recovery require versioned, auditable transitions. Hot/warm/cold are separate security classes; cold signing cannot reuse the hot environment's routine authorization.

## Scalability, events, and operability

Introduce reliable transactional outbox/inbox, monotonic event IDs, idempotent consumers, backpressure, bounded retries and DLQs for API webhooks and internal financial events. Use queue-based withdrawal and payout execution; database transaction isolation and lock order must be explicit. Instrument lag, missing chain history, signer availability, reconciliation debt, treasury runway, asset-liability gaps and security policy denials. Backup/restore tests must include both ledger and independently held signing material; avoid confidential leakage to logs/artifacts.

## Compatibility rules

Do not claim old Phase 1–5 docs describe current complete state; those files describe dated baselines. Do not invent production integrations just because DTO/routes or dashboard placeholders exist. Keep migrations additive, auditable and reversal-safe. Never change a settled financial journal to compensate for new behaviors.

New child approvals include a domain-separated original custody machine proof.
All three signer CAs and P-256 credential profiles are verified before issuance;
identity readiness is established with the original share/HD approval rather than
first discovered during spending. This public approval does not consume an MPC
nonce or alter immutable child identity. Signing uses its separately persisted
original grant.
