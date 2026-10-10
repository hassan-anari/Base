# Phase 6F-B — isolated Solana / classic SPL FROST custody

Base: merged main `f8ab03145c76f384cfe9c29bad05351625e25bde` (Phase 6F-A, PR #31).
This is a Draft for independent security review. **Production readiness is not
claimed. Mainnet, public devnet/testnet, and production funds remain disabled.**
TON/Jettons, cross-chain final acceptance, Phase 6G HD provisioning, and Phase 7
administrative governance are outside this change.

## Audit and architecture

The existing Rust coordinator/protocol/signer FROST implementation is reused
without changing its cryptographic contract. Python contains transaction policy,
standard Ed25519 verification, and Solana serialization; it contains no FROST
protocol, coordinator, private share, reconstructed key, or nonce generator.

The audit found that the earlier Django consumer demanded 32-byte ECDSA digests
and `r/s/recovery_id`, root ownership/import supported CGGMP only, Solana RPCs
were unguarded, native finality trusted signature status alone, native indexing
credited positive balance deltas, and blockhash expiration could release a
reservation without historical non-inclusion proof.

Integration reuses `OnchainTransactionAttempt`, `MpcSigningSession`, PostgreSQL
execution advisory locks, parent withdrawal/sweep/gas states, and the existing
append-only double-entry ledger. No parallel financial state machine is added.
The new boundaries are:

- `mpc_solana_network.py`: independent activation, endpoint/genesis identity,
  original blockhash validity, and a ten-block signing/broadcast safety margin.
- `solana_wire.py`: independent legacy message decode, strict instruction/account
  authorization, canonical Ed25519 verification, and local transaction assembly.
- `solana_policy.py`: binary account/mint validation, fee/rent/reserve budgeting,
  exact message preparation, and immutable transaction identity.
- `solana_settlement.py`: original-wire finalized transaction/status consistency
  and native/SPL transfer, fee, rent, and failure rollback evidence.
- `solana_deposits.py`: explicit finalized program transfer attribution and
  bounded resumable scans. Credits and scan cursors commit atomically.
- `solana_costs.py`: exactly-once observed fees and rent in the existing journal.

EVM and TRON remain routed to their existing algorithms, network policies,
assembly, and reconciliation. CGGMP auxiliary evidence checks remain in place.

## Verified FROST roots

Create a SOLANA/FROST_ED25519/ed25519 metadata record matching the original
coordinator keyset UUID. `mpc_keyset import-dkg` reads authenticated coordinator
metadata, verifies the original DKG execution, result fingerprint, fixed
`signer-a/b/c` topology, 2-of-3 threshold, all three durable receipts, their
identical serialized PublicKeyPackage, and their public verification shares.
The existing Rust service validates the upstream package cryptographically.
`activate` authenticates and rechecks the same evidence. Reimport cannot replace
an already recorded DKG identity. FROST has no CGGMP auxiliary-completion condition.

All root bindings require ACTIVE status, correct algorithm/curve/scope/threshold,
canonical original 32-byte public key, and exact Base58 source identity derived
from that public key. Deposit wallets explicitly select `mpc_root_v1` and
`keyset:<original UUID>`; hot wallets explicitly select that same root reference.
`bind_mpc_hot_wallet` authenticates Solana evidence before committing the binding.

`frost_keyset_v1` is an upstream keyset metadata format, **not HD derivation**.
No child derivation, root rebinding to an operator-supplied address, bulk wallet
provisioning, or key export is available. SOLANA auto-provisioning is disabled by
a database constraint. Migration 0019 resets pre-existing unverified SOLANA roots
to CREATING and disables their provisioning; they require authenticated reimport.
Existing addresses must never receive test funds before ownership is verified.

## Activation and network identity

Default settings are `MPC_SOLANA_INTEGRATION_ENABLED=false` and an empty
`MPC_SOLANA_NETWORK`. Activation additionally requires self-hosted MPC, PostgreSQL,
valid existing coordinator mTLS credentials, development environment, live
transaction mode, live indexing, disabled demo mode, SOL chain family, nine
native decimals, a test-only registry entry, and no EVM numeric chain ID.

The operator policy must contain:

```json
{
  "network": "isolated-v1",
  "genesis_hash": "<independently established local genesis Base58 hash>",
  "genesis_source": "validator-genesis-artifact",
  "genesis_artifact_sha256": "<SHA-256 of trusted local genesis.bin>",
  "trusted_endpoints": ["http://127.0.0.1:8899"]
}
```

Pins must come from trusted validator startup/ledger configuration. Reading
`getGenesisHash` from an untrusted endpoint and then allowlisting that answer is
not an acceptable bootstrap. The acceptance harness computes the expected hash
using the offline `agave-ledger-tool genesis-hash` and hashes its local genesis
artifact, then independently compares RPC evidence. Runtime policy relies on the
operator honestly establishing that provenance; it cannot prove provenance from
a JSON configuration alone. Production governance for that configuration is
outside this milestone.

Every selected endpoint is allowlisted using a literal loopback address. Actual
`getGenesisHash` is checked before preparation, signing, broadcast, indexing,
reconciliation, and before using a fallback endpoint. Public mainnet/devnet/testnet
genesis identities and public network labels are forbidden. Redirects are refused.
Solana never falls back to EVM/TRON network checks.

**Trusted RPC consistency is not a light-client proof.** A malicious allowlisted
validator could lie about execution or history. This milestone uses an explicitly
trusted, isolated, disposable local ledger; it does not establish production
Byzantine RPC resilience or public-devnet policy.

## Messages, signatures, and transaction shapes

Only canonical legacy transactions with exactly one writable signer/fee payer,
the original FROST root public key, are reviewed. Extra signers, writable accounts,
unknown programs, hidden instructions, alternate message bytes, and transactions
over Solana's 1232-byte packet limit are rejected. Versioned messages, lookup
addresses, independent additional signatures, and arbitrary-message Django
signing endpoints are unavailable.

The exact stored serialized message is signed directly as `SOLANA_MESSAGE` for
chain `SOL`. SHA-256 is used only as a stored fingerprint, never as the signing
input. Django independently decodes instructions/account flags and compares the
message with the approved transfer shape. Rebuilding an expected message is a
validation comparison; signing and assembly use the original stored bytes.

The algorithm-specific consumer validates keyset, logical session, execution,
selected pair, fingerprint, and exact FROST output contract. It requires canonical
64-byte Ed25519 output, canonical scalar/point encodings, independent cryptography
verification, and Solana's signature verification using the original DKG key.
ECDSA components are not required. Complete signed transaction bytes (hex in the
existing durable field) and the Base58 signature commit before any send RPC.
Assembly and broadcast both verify the message and signer identity.

Native SOL uses one System Program `Transfer` with an exact positive u64 lamport
amount, source fee payer, and authorized destination. Sweeps cap the amount at the
approved balance snapshot minus the actual quoted fee and configured native
reserve. Message/fee convergence happens before identity freezing. New recipient
accounts must receive enough lamports to meet the System account rent minimum.
The source remainder must be zero or meet that minimum too; SPL fee/rent funding
must leave a valid System account balance.
If a sweep's approved snapshot cap would leave a nonzero rent-deficient balance,
preparation reduces the transfer before freezing to retain the required rent.

Classic SPL uses one exact `TransferChecked` instruction, reviewed mint/decimals,
canonical source/destination ATAs derived from owner + Classic Token Program +
mint, and the root authority as fee payer. Binary mint data must be exactly 82
bytes, and token-account data exactly 165 bytes. Program ownership, initialized
state, authority, mint and balance are checked. Frozen, delegated, native-wrapped,
extension-bearing, or unsupported close-authority accounts fail closed.

An absent destination ATA permits one preceding idempotent Associated Token
Program creation instruction bound to the same destination owner, mint, token
program, fee payer, and frozen message. Existing ATAs must match owner/mint/state.
The root source must have native lamports to cover fees and rent; token sweeps use
the existing confirmed gas-grant lifecycle when funding is needed. No separate
fee payer or independent signature is silently introduced.

Reviewed gas settings include `max_fee_lamports`, `max_ata_rent_lamports`, optional
`native_reserve_lamports`, and a bounded `topup_amount` for sweeps. This initial
shape permits **no compute-budget instructions or priority fees**. The identity
freezes the complete fee policy, quote, rent bound, reserve, blockhash context,
last-valid height, message, program/account metadata, mint/ATA identities, operation
and attempt IDs, source/destination, amount, keyset and DKG fingerprint.

A token symbol does not establish mint identity. `verify_token_asset` binds classic
mint metadata to the independently pinned network. Token-2022 is unsupported.
The disposable acceptance asset is not USDT. No actual USDT mint is enabled or
claimed independently verified by this change; an operator must establish its
mint and Classic Token Program identity within the approved network policy.

## Expiration and recovery

Blockhash expiration and a null/pruned signature status are **not proof of
historical non-inclusion**. The former native EXPIRED path now reports
RECONCILIATION_REQUIRED, and the shared lifecycle defensively converts a Solana
EXPIRED result to that nonterminal state. No elapsed height automatically releases
funds, changes blockhash, starts a new logical session/execution, or replaces a
transfer.

| Attempt condition | Authorized recovery |
| --- | --- |
| Preparation failed before any signing/session | Existing proven pre-effect failure handling; no signed transfer exists |
| Frozen message expired before FROST starts | Refuse nonce/signing advancement; retain intent for explicit resolution |
| FROST active, timed out, or nonce consumption uncertain | Recover the same coordinator execution/public receipts only; no fresh rounds |
| Completed signature, not consumed before worker death | Consume the same verified completion even if the blockhash expired; never create a replacement signature |
| Committed signed transaction expired before send | Refuse broadcast; preserve bytes/signature/session/execution and require resolution |
| Submitted or lost broadcast response, including expiration | Retain reservations and original immutable identity; reconcile only that signature |
| Verified finalized original success | Settle once and journal observed costs once |
| Verified finalized original failure | Validate rollback/fee evidence, release once, and journal the actual fee |
| Missing, pruned, conflicting, or insufficient history | Keep RECONCILIATION_REQUIRED; explicit manual reconciliation |

Workers claim PostgreSQL ownership before signing/broadcast/reconciliation.
A crashed BROADCASTING attempt becomes uncertain. Retries of an uncertain attempt
do not issue another send or signing execution. Coordinator restart retains the
original durable UUID; signer nonce loss cannot authorize fresh nonce generation.

There is no automated RPC-based non-inclusion certificate or manual "release by
expiry" command. Operator recovery must obtain authoritative original-outcome
proof, preserve the attempt and signer tombstones, and undergo independent review.
When such proof is unavailable the reservation remains held. Any future manual
resolution workflow must not infer safety from one node's missing history.

## Finalized execution, indexing, and accounting

`sendTransaction` success does not settle funds. Settlement requires finalized
signature status plus actual finalized base64 transaction retrieval, verified
signature, exact original message/blockhash/signer/fee payer, matching slot and
execution result, complete indexed balance metadata, and consistent fee effects.
Native settlement proves the authorized System transfer and exact corroborating
source/destination effects. SPL settlement proves the authorized checked transfer
and owner/mint/program/index-consistent token deltas plus bounded ATA rent. Missing
or conflicting evidence leaves the customer reservation intact.

The existing ledger journals reserve/release/settle/credit at most once. Observed
native network fees debit the SYSTEM/custody `NETWORK_FEE_EXPENSE` account and
credit `TREASURY_ASSET`; ATA rent debits `ATA_RENT_ASSET` and credits `TREASURY_ASSET`.
These are idempotent shared-journal entries, keyed by the original attempt. Rent
remains a recoverable custody account asset, not a customer deposit or network fee.
The new treasury cost postings do not claim a complete treasury valuation or
opening inventory; historical treasury inventory is a future accounting concern.

MPC deposit scans require root ownership and finalized original signed-wire
transactions. Native credits require explicit System transfers, not arbitrary
positive deltas, rent refunds, or aggregate account balance changes. Classic SPL
credits require canonical destination ATA, verified mint/program/decimals, source
ATA owner authority and consistent transfer effects. Each outer/inner instruction
has a distinct event identity. Known custody sources and durable internal outbound
identities (including fee grants) are excluded from customer credits.

Scans process at most four pages of 100 signatures per invocation. A persisted
wallet cursor freezes the scan head/boundary and resumes older history; each page's
credits and cursor advance commit atomically. The checkpoint advances only when
the required bounded history is complete. Missing transactions, malformed evidence,
pruned required history, and non-progressing pagination stop advancement. Concurrent
scanners cannot overwrite a cursor advanced by another worker. First indexing
backfills available local history from genesis; it does not silently truncate to
a recent lookback. Native fee-balance observations for token roots do not manufacture
native deposit wallets or customer credits. Stub/simulated indexers are rejected.

External versioned transactions, unsupported delegate/multisig/PDA transfer shapes,
and complex netted token effects currently require manual handling; they are not
silently credited. RPC pagination cannot prove the completeness of a malicious
node's answers. Archival availability and trustworthy local validator operation
remain operational requirements.

## Acceptance and CI

`mpc-side/integration/test_solana.py` uses fresh FROST DKG, actual coordinator and
three independent mTLS signers, PostgreSQL, and disposable Agave 2.1.21. The pinned
Linux archive is SHA-256
`5da3359e296f1e6c13522b874317cb4cfe33e73301a9dc60b1e1435cc133b397`.
The harness establishes genesis from the local artifact, not RPC bootstrap.
Only public `solana-evidence.json`, inventory, and JUnit results are uploaded.
Private shares, private keys, secret nonces, decrypted stores, PKI and private test
fixtures must never be uploaded.

Development acceptance finalized native withdrawals using A+B, A+C and B+C,
native/SPL root sweeps, classic SPL withdrawal and absent-recipient ATA creation,
confirmed source fee grants, and native/SPL external credits. It verified service
restart, lost accepted broadcast response, one physical broadcast from competing
workers, one ledger settlement per withdrawal, and no internal grant credit. That
expanded run also verified pruned history after actual blockhash expiration, real
finalized failure, distinct same-transaction deposit events, and actual nonce-loss
expiration. Its two genuine tests passed in 422.14 seconds. These are development
results, not proof for a later SHA. Concurrent signing, broadcast and finalized
reconciliation are exercised against PostgreSQL and the genuine services.
Final exact-head evidence belongs to the PR's CI artifacts and handoff.

Fast CI runs cheap deterministic policy/ledger/configuration checks first. Solana
acceptance is separately selectable as `crypto_suite=solana`, parallel with the
existing EVM, TRON, auxiliary-persistence and network suites. It generates no
unrelated CGGMP auxiliary material. Cargo cache reuse and all original scenarios
are preserved. `full-crypto-gate` explicitly requires successful `mpc-solana` along
with every existing required job; failed, skipped or cancelled required jobs fail
the aggregate gate. Every checkout verifies the immutable reviewed PR head.

Focused local commands, with approved local PostgreSQL and existing TLS/test setup:

```sh
pytest backend-side/custody/tests/test_phase6fb_solana.py
pytest backend-side/custody/tests backend-side/ops
PHASE6FB_SOLANA_BIN=/path/to/pinned/solana-release/bin pytest -v -s mpc-side/integration/test_solana.py
```

Final acceptance requires focused regressions, PostgreSQL ledger/concurrency,
EVM/TRON regressions, format/lint/migration/configuration checks, genuine local
Solana/FROST execution, Fast CI, and the complete full cryptographic gate on the
final reviewed SHA. A prior SHA's pass does not satisfy that requirement.

## Scope and future work

No production activation, mainnet funds, public devnet policy, true HD derivation,
mass wallet provisioning, key rotation, Token-2022, arbitrary token accounts,
additional independent signers, versioned messages, priority-fee/compute-budget
instructions, wrapped-native tokens, or automated ambiguous-expiry replacement is
provided. Phase 6G must separately review actual distributed derivation,
provisioning/lifecycle/recovery and ownership evidence. Independent security review
must precede approval of this isolated milestone. Do not merge automatically.
