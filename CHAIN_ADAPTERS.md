# Runtime chain registry and adapters

Phase 3 establishes one production resolution path:

`ops.Chain` + `ops.NodeEndpoint` → immutable `ChainSpec` → family `ChainAdapter`
→ indexer, address validation, and demo derivation/signing routing.

## Authority and bootstrap

`custody.config.DEFAULT_CHAINS` and `DEFAULT_ASSETS` are bootstrap seed data only.
The post-migrate seed creates missing rows and never updates an existing row, so
operator changes survive restarts. Runtime custody reads `ops.Chain` afresh and
uses enabled `ops.NodeEndpoint` RPC rows in deterministic primary/priority/name
order. There is no environment/static fallback: an unknown or disabled chain,
unsupported kind, missing native custody asset, or absent RPC endpoint fails
closed. Database edits are therefore visible without a process restart.

The supported family identifiers are `evm`, `tron`, `solana`, and `ton`.
`CUSTOM_EVM` can select `EvmAdapter` and the parameterized `EvmIndexer` simply
by using `kind=evm`; no `Network` member or factory branch is needed. The old
`Network` enum remains only as a deprecated import shim for external callers
and tests; custody production workflows route using string `chain_id` values.

## Responsibilities and boundaries

`ChainSpec` contains chain identity, family, enabled/testnet state, native asset
and decimals, EVM numeric chain ID, finality, exact `Decimal` sweep threshold,
memo/explorer metadata, and gas settings. Adapters own family address rules,
derivation-purpose/key-family metadata, exact base-unit conversion, and indexer
construction. Business workflows and ledger accounting do not belong there.

`custody.Asset` remains the authoritative custody capability boundary
(`deposit_supported`, `withdrawal_supported`, `sweep_supported`, decimals, and
chain relationship). `ops.Asset` is dashboard/operational metadata and cannot
enable token custody. Only native assets are implemented. Phase 4 will add real
native transaction construction and lifecycle management; Phase 5 will add
reviewed token implementations. Real MPC vendor integration also remains future
work, and `LocalVault` remains explicitly demo-only with fail-closed settings.

Node failover occurs inside each indexer across the canonical resolver's ordered
endpoint list. Exhausted nodes raise an indexer-unavailable error; they are never
reported as a zero balance. Full RPC SSRF hardening is intentionally deferred.
