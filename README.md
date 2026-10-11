# Wallet-MPC

**Self-hosted, API-first digital-asset custody and financial platform** for cryptocurrency exchanges, payment gateways, payment facilitators, merchants, and institutional operators.

**Status (2026-10-11):** Phase 6F-D was merged in PR #34 at main commit 4488016a668283868633eb1a7fa2f64187a93b56. Phase 6G is next. Existing EVM, TRON, Solana and TON integrations have genuine isolated-development acceptance, **not production/mainnet authorization**. TON stays at its currently accepted isolated scope until explicitly reprioritized. No customer funds or production withdrawal activation is authorized by these documents.

This is more than an MPC signing service. The target system combines a single authoritative double-entry ledger, a transaction/custody engine, independent MPC signers, human authorization, treasury operations, exchange settlement APIs, merchant payments, risk controls, and operator/developer interfaces. External exchange matching engines and order books remain separate systems.

## Source of truth: reading order

1. [AGENTS.md](AGENTS.md) — mandatory instructions for contributors and coding agents.
2. [Product vision](docs/PRODUCT_VISION.md) — binding scope, customers, commitments and non-goals.
3. [Product requirements](docs/PRODUCT_REQUIREMENTS.md) — capabilities, priority, states and acceptance.
4. [Architecture](docs/ARCHITECTURE.md) — trust boundaries and subsystem ownership.
5. [Roadmap](docs/ROADMAP.md) — original nine phases and work packages.
6. [Project status](docs/PROJECT_STATUS.md) — current merge anchor, blockers and next work.
7. [Development history](docs/DEVELOPMENT_HISTORY.md) — evidence-linked milestones and PR history.
8. [API contracts](docs/API_CONTRACTS.md) — **target** integration contracts, not implemented endpoints.
9. [Security model](docs/SECURITY_MODEL.md) — signing vs human approvals, authorization and gates.
10. [Decisions](docs/DECISIONS.md) — accepted decisions vs proposals and deferrals.
11. [Documentation governance](docs/DOCUMENTATION_GOVERNANCE.md) — update rules, evidence and conflict resolution.

## Existing implementation evidence

- [Authoritative ledger](LEDGER.md), [chain adapters](CHAIN_ADAPTERS.md), [token custody](TOKEN_CUSTODY.md), [native transaction lifecycle](NATIVE_TX_LIFECYCLE.md).
- [Self-hosted MPC](SELF_HOSTED_MPC.md) and the [Rust-side protocol docs](mpc-side/).
- [EVM](PHASE6E.md), [TRON](PHASE6F-A.md), [Solana](PHASE6F-B.md), [TON](PHASE6F-C.md), and [integrated four-chain acceptance](PHASE6F-D.md).
- [PR #34](https://github.com/hassan-anari/Wallet-MPC/pull/34) and [its final cryptographic gate](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38129567244).

Historical phase documents describe their own implementation dates and may contain **superseded forward-looking claims**. Read the status/decision documents for present-day scope, then verify actual behavior in code. Documentation approval is not deployment authorization.
