# Security, financial trust and production acceptance

## Distinct decision layers

1. **Business policy / Human Approval** — whether operation is allowed; tenant, risk, destination, amount/USD value, wallet class and named human approvers. Example future configurable policy: withdrawal > USD 500 requires three *different authorized humans*; this is neither fixed nor implemented today.
2. **Signer-side independent authorization** — verify an unforgeable short-lived policy/approval-bound signing grant tied to canonical signed operation, keyset, network/genesis, account and policy version. Compromise of a Django process alone must not permit arbitrary signatures.
3. **Cryptographic MPC quorum** — genuine 2-of-3 signer share threshold; no complete private key reconstruction. Two cryptographic signer approvals are NOT two human approvals.

A policy amendment itself may require multi-person quorum, MFA and a delayed activation window. No requester self-approval, voting twice, mutable recipient, replayed grant or expired stale FX price bypass.

## Threats and required controls

- **Backend/API compromise:** least privilege, operator/security separation, signer-side grants outside unilateral backend control, tenant-scoped auth, immutable audit, deny arbitrary unsigned/freeform transactions.
- **Single signer compromise:** encrypted local shares, independent security domains, quorum requirements, nonce use-once, replay prevention; compromise assessment should consider coordinated signer collusion.
- **Ledger fraud and race:** exact Decimal/base-unit, row locking, deterministic account lock order, idempotent journal, immutable populated asset identity, tenant isolation; mutation through privileged SQL is a distinct threat requiring DB permissions and/or triggers.
- **Malicious/stale RPC or reorg:** independent network identity, finality policy, verified receipts/history as applicable, multi-RPC disagreement/recovery, no false-empty logs; fail closed on unprovable history.
- **Ambiguous blockchain delivery:** retain original signed bytes, on-chain identity and reservation. Never infer non-execution from timeout or explorer absence.
- **Insider / treasury abuse:** human quorum, destination allowlist changes with delay, cold exit isolation, operational velocity controls, alerts, emergency freeze.
- **Backup/recovery:** encrypted independently retained signing state and PostgreSQL financial state, documented RPO/RTO, restore drills, stale-share invalidation, key-transition audit.
- **Token/network identity:** immutable network genesis and canonical contract/master/mint/fingerprint; do not treat same ticker as interchangeable asset.
- **Supply-chain / CI artifact leaks:** pin cryptographic dependencies, signed or integrity-checked validator binaries, public evidence allowlists, no shares/nonces/PKI secrets in logs.

## Configuration and finality governance

Allow operator control of non-critical business policy, but enforce reviewed minimum safety floors. EVM deposit confirmation is not an equivalent of Solana finalized commitment or TON proof chain. Snapshot the policy version applied to each credit and withdrawal; require high privilege for changing finality floor, RPC provenance or signing scope.

## Production gates, independently applied per chain

A chain may activate only with reviewed code/protocol and threat model, mainnet/testnet-specific chain identity and token deployments, appropriate independent trust anchors, fail-closed indexes/reorg recovery, distributed signer and PKI/IdP/RBAC separation, fully tested financial accounting, mature runbooks/monitoring/backup/restore, compliance policy, volume/chaos tests and independent security assessments with findings resolved or explicitly governed.

**Not acceptable:** green isolated tests alone, owner willingness to assume risk alone, change of localhost RPC to public endpoint, disabling audit blockers, treating local Node endpoint as honest consensus proof.

**Current**: EVM/TRON/Solana integrations not mainnet-authorized. TON isolated only; exact Wallet V5R1 external audit correspondence P1 OPEN. Dynamic public sharding and actual USDT compatibility not implemented. This owner-approved deferral must not block other independently gated chains, but also cannot authorize TON mainnet.

## Acceptance artifacts

Per PR provide threat-model deltas, proof/identity and exact original signing-intent linkage, ledger invariants, concurrency/restart/replay/unknown-outcome test cases, CI final SHA and job links, migration/backfill plans, monitoring/runbooks and unresolved risk register. Reviews are independent, not self-approved.
