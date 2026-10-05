# Phase 5 token custody

## Scope and allow-list

Custody recognizes only reviewed **ERC-20**, **TRC-20**, and classic **SPL Token
Program** fungible assets. An asset is identified by `(chain_id, canonical
contract/mint, token_standard)`, never by symbol. Native assets have neither a
contract nor a token standard. TON Jettons, Token-2022, NFTs, TRC-10,
fee-on-transfer, rebasing/reflection/tax tokens, permits, delegation, bridges,
mint/burn workflows, and arbitrary calls are unsupported and fail closed.

Existing preset rows are migration-safe: their capabilities are not enabled and
no verification timestamp is fabricated.

## Operator activation

1. Create or update the token `Asset` with all capabilities disabled.
2. Set the family-correct standard, contract/mint, and decimals.
3. Configure enabled runtime RPC endpoints and reviewed fee/scanning policy.
4. Run `python manage.py verify_token_asset ASSET_KEY`.
5. Inspect its canonical identity and printed fingerprint.
6. Explicitly enable only the reviewed capabilities.

Verification queries the runtime database endpoints. ERC-20 verification checks
bytecode, `decimals()` and `balanceOf`; TRC-20 uses constant-contract calls; SPL
requires a mint owned by `Tokenkeg...` and explicitly rejects Token-2022. The
fingerprint binds chain, canonical contract/mint, decimals, standard, and program.
An identity edit clears verification; every capability check recomputes the
fingerprint, so a stale timestamp has no authority. Verification never activates
an asset.

## Deposits and event identity

A deposit is unique by wallet, asset, transaction, and `event_index`. Native
history receives `native:0`; token identities use `log:N`, `ix:N`, or
`inner:N:M`. Block hashes are retained where available. Ingestion rejects
non-positive/inexact amounts, a wallet/asset mismatch, mutation of an existing
event, and evidence from any contract/mint other than the reviewed identity.
Aggregate balances never create ledger credits.

ERC-20 scanning calls `balanceOf` on the exact contract and uses bounded,
chunked `eth_getLogs` ranges filtered by contract, the Transfer signature, and
indexed destination. An overlap supports reorg observation while concrete log
identity deduplicates replay. Credits remain pending until configured finality.
TRC-20 production ingestion is defined over SolidityNode-solidified blocks and
successful TransactionInfo logs; optional TronGrid APIs are never a correctness
dependency. SPL scans the deterministic ATA using finalized transactions and
individual successful outer/inner classic-token instructions.

The TRC-20 scanner reads bounded solidified blocks and exact SolidityNode
TransactionInfo logs. Its outbound executor persists the node-generated TAPOS
transaction and confirms only an exact solidified Transfer. The SPL executor
constructs classic-program TransferChecked, optionally precedes it with canonical
idempotent ATA creation under a rent cap, and proves the finalized instruction
effect before confirmation.

A scan advances `last_scanned_block`/slot only after all provider work and event
ingestion succeeds. Initial lookback, overlap and log chunk size are bounded by
reviewed chain configuration. Outage and partial-batch failures do not advance it.

## Solana owner and ATA

`UserWallet.deposit_address` remains the MPC-controlled owner pubkey and signing
authority. `asset_account_address` is its deterministic associated token account,
derived from owner, mint, classic Token Program, and Associated Token Program.
An arbitrary account cannot replace it. A missing ATA means zero balance; a
sender may create it on first transfer.

Outbound destinations are owner pubkeys. Their ATA is derived deterministically.
A reviewed implementation may include idempotent ATA creation in the same
transaction only under configured maximum fee and rent caps. Fees/rent are SOL;
they never reduce the exact token amount.

## Durable transaction lifecycle and exact effects

Tokens use the Phase 4 lifecycle, not a parallel one:

`WithdrawalRequest/SweepJob -> OnchainTransactionAttempt -> prepare -> sign ->
persist exact signed payload -> broadcast -> reconcile -> domain/ledger result`.

`base_unit_amount` is token base units, while fee metadata is native units.
ERC-20 prepares `transfer(address,uint256)` with native value zero. TRC-20 uses
`triggersmartcontract`; SPL uses `TransferChecked`. Prepared metadata retains the
contract/mint, parties, amount, nonce/TAPOS/blockhash and fee policy required to
reconstruct the exact intent. EVM native and ERC-20 attempts use the same
source-account nonce allocator, because the network nonce domain is the EOA, not
the asset.

Transaction success alone never confirms a token operation. At finality,
reconciliation must prove an exact allow-listed Transfer log (ERC-20/TRC-20) or
classic token instruction/effect (SPL), including source, destination, identity,
and amount. A successful transaction with missing/mismatched effect remains
reconciliation-required: funds are neither settled nor released. Definitive
execution failure releases a withdrawal exactly once. Broadcast ambiguity keeps
the same signed payload and attempt and never permits a fresh unsafe retry.

## Gas funding and accounting

Token gas is custody operating expense and is never posted to, or subtracted
from, the user's token ledger. Token sweeps check ETH/BNB/custom-EVM native gas,
TRX resource/fee policy, or SOL fees/rent. If insufficient, the sweep owns one
durable linked `GasTopupIntent`; repeated scans reuse it. `BROADCASTED` is not
enough: the token transfer waits for `GasTopupIntent.CONFIRMED`. Advancement
row-locks the sweep and reuses its token attempt. All decisions use integer base
units or `Decimal`, never floats, and are bounded by runtime policy.

The gas intent and its direct sweep link are committed before signing or
broadcast. A configured grant must cover the observed shortfall, and confirmed
gas is followed by a fresh native-balance check. A durable sweep-processing
claim prevents overlapping advancement workers from signing the token transfer
twice.

A withdrawal moves token AVAILABLE to RESERVED, settles only after the exact
confirmed token effect, and releases only after definitive failure. Sweeps move
custody location but not beneficial ownership, so neither token sweep nor native
gas top-up creates a user-ledger posting.

## Remaining limitations

Phase 5 intentionally does not add Celery/outbox processing or a generalized
reorg engine. Canonical block identity is stored and the existing explicit
reversal journal boundary remains available. Providers must offer the reviewed
standard RPC shapes; non-standard token return/event behavior fails closed.
Sweep progression is provided by the idempotent `advance_pending_sweeps`
management command rather than a continuously running task queue.
