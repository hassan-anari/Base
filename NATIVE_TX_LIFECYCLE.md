# Native transaction lifecycle

Phase 4 separates a logical withdrawal, sweep, or gas grant from each concrete
network execution. `OnchainTransactionAttempt` is the authoritative record of
prepared fields, exact base units, fees, signed bytes, network identity and
finality evidence. Historical operations are **not** backfilled: an old
`BROADCASTED` or `RECONCILIATION_REQUIRED` operation without an attempt must be
reconciled manually from its recorded transaction hash and must never be retried.

## State machine

| State | Meaning | Automatic retry safe? |
|---|---|---|
| `PREPARING` | no signing or external effect | yes |
| `PREPARED` | nonce/blockhash/TAPOS and bounded fee persisted | yes |
| `SIGNING` | signer request in progress | only after proving no signature exists |
| `SIGNED` | deterministic network identity and exact payload persisted | rebroadcast same bytes only |
| `BROADCASTING` | RPC call may have had an effect | no |
| `BROADCASTED` | accepted, but not final | no |
| `RECONCILIATION_REQUIRED` | outcome is ambiguous | no |
| `CONFIRMED` | transaction-specific finality evidence succeeded | terminal |
| `FAILED` | authoritative, definitive failure | terminal |

Recovery follows the external-effect boundary. `PREPARING` is prepared again;
`PREPARED` resumes signing from persisted chain fields; an interrupted `SIGNING`
is quarantined because the current signer cannot prove whether it produced a
signature; `SIGNED` rebroadcasts only the persisted bytes; and an interrupted
`BROADCASTING` becomes reconciliation-required without another signature or
transaction being constructed.

The boundary is `prepare -> signer.sign -> assemble -> broadcast -> reconcile`.
The signer neither selects chain fields nor broadcasts. Signed bytes are stored
only to permit replay of the exact authorized transaction across RPC fallbacks;
they are sensitive operational data and are excluded from APIs and logs.

## Key identity and exact values

Hot wallets have an opaque `signing_key_ref`; existing rows remain null and fail
closed until an operator provisions them. User sweeps use the persisted
`UserWallet.derivation_path`. Before signing, the signer derives the address and
compares it with the source. Amounts are `Decimal`; exact conversion rejects
zero, negatives, excess precision and chain-range overflow. Chain calls use only
integer wei, sun, or lamports.

## EVM

All EVM chains share one executor. Fallible gas, fee, and balance preflight runs
before nonce ownership. A PostgreSQL row lock on `(chain_id,address)` then
synchronizes the durable next nonce with RPC `pending`, and the nonce increment
and prepared attempt are committed in one database transaction. A rejected
attempt retains and reuses its lower nonce rather than allocating a gap. The
attempt table additionally has a conditional unique source/nonce constraint.
EIP-1559 is selected when the latest block exposes a base fee;
otherwise legacy gas price is used. Gas, per-gas fees, priority fee and optional
total fee must fit reviewed integer-string caps in `Chain.gas_settings`. The
source must fund value plus the worst-case fee.
Native EVM sweeps use the current source balance minus the bounded worst-case
fee as their exact transfer value; the source remains the fee payer.

The expected hash is derived before sending. Fallback nodes receive identical
signed bytes; timeout is ambiguous, while an exact duplicate is accepted for
that hash. Receipts must match the hash, succeed, and reach the runtime
confirmation threshold.
Execution failure is also non-terminal until that same threshold is reached;
a reorgable `status=0` receipt leaves the business reservation untouched.

## TRON and Solana

TRON preparation uses `wallet/createtransaction`; node-produced TAPOS,
expiration, raw data and txID are persisted. The txID is the signing digest.
FullNode receipt observations are non-terminal. Terminal success or failure
requires the exact txID from `walletsolidity/gettransactioninfobyid`. Missing
FullNode and SolidityNode receipts remain `UNKNOWN`, even after the persisted
expiration. Definitive TRON non-inclusion requires manual reconciliation until
canonical-absence proof is implemented; local wall-clock time is not evidence.
`ref_block_bytes` is never treated as a block height.

Solana uses a real System Program transfer message, recent blockhash and
`lastValidBlockHeight`. The source is the fee payer. For a SOL sweep, the
transferable value is the source balance minus the estimated fee; a separate hot
wallet cannot pay without also signing. Signature status—not aggregate balance—
determines success. An absent signature is definitive only after blockhash
expiry.
TRON failures require an authoritative SolidityNode receipt. Solana errors remain
included/non-terminal until signature status is `finalized`. An absent TRON
transaction remains manual and non-terminal; an absent Solana signature past its
last-valid block height is terminal expiry only after reconciling the original
network identity.

A typed, proven pre-acceptance rejection returns the same attempt to `PREPARED`.
Withdrawal, sweep, and gas intent state becomes retryable while retaining the
same attempt and EVM nonce. Transport ambiguity remains reconciliation-required.

## Domain and ledger boundary

Submission never settles accounting. The repeatable reconciliation service row
locks both attempt and operation. Confirmed withdrawal success calls
`settle_withdrawal()` exactly once. A transaction-specific definitive failure
calls the idempotent reservation release and marks the request failed. Unknown,
pending, below-finality and ambiguous outcomes leave funds reserved. Sweeps and
gas grants never move beneficial-owner ledger balances.

Run `python manage.py reconcile_outbound` to process pending attempts. Multiple
workers are safe because terminal transitions occur under database row locks.

## Modes, TON, and limitations

`CUSTODY_TX_MODE=live` performs family construction and RPC transport.
`CUSTODY_TX_MODE=stub` is accepted only with `CUSTODY_DEMO_MODE=true`; signer
backend and transport mode are independent. Synthetic hashes are forbidden in
live execution.

Built-in TON deposit, withdrawal and sweep capabilities are disabled by data
migration. TON needs a later reviewed signing and authoritative-finality design.
Tokens, real vendor MPC, fee charging/accounting, fee replacement, automated
Celery/outbox scheduling and a reconciliation UI remain out of scope.

## Asset-aware transfer boundary (Phase 5)

Business orchestration now selects a transfer executor by both `chain_id` and
`asset_key`. Native assets retain the Phase 4 family executors; verified tokens
select their reviewed standard executor. Reconciliation uses the same selection,
so a token attempt can never be interpreted as a native transfer. All EVM
executors share the source-account nonce allocator.
