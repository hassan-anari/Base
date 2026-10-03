# Authoritative custody ledger

The `LedgerTransaction` journal and its `LedgerPosting` rows are the source of
truth for internal beneficial ownership. Deposit-address, hot-wallet and
`ops.AddressBalance` values are operational on-chain observations, and
`ops.TransactionLog` is an operational log; none is a user balance.

## Accounts and signed postings

Each asset has user `AVAILABLE` and `RESERVED` accounts and one system
`custody/CUSTODY_CLEARING` account. Positive postings add to an account and
negative postings remove from it. Every transaction is single-asset, contains
no zero line, and sums exactly to zero using `Decimal` arithmetic.

* Confirmed deposit: user available `+X`, clearing `-X`.
* Withdrawal reserve: available `-X`, reserved `+X`.
* Denial/release: reserved `-X`, available `+X`.
* Confirmed withdrawal settlement: reserved `-X`, clearing `+X`.
* Deposit reversal: the exact inverse of its deposit credit.

Journal history is append-only through normal Django model and QuerySet APIs.
Deterministic event keys make domain actions idempotent; a correction is a new
compensating transaction, never an edit. This application boundary does not
claim protection against privileged raw SQL; production deployments should
restrict database privileges and may add database triggers for defense in depth.

## State-machine boundaries

A concrete indexer deposit event remains pending below the configured chain
finality threshold. Its transition to `CONFIRMED` and ledger credit commit in
one database transaction. An authoritative reversal locks the confirmed
deposit and atomically marks it `REVERTED` with its inverse posting. Negative
available balance after a reversal is retained as accounting truth.

A withdrawal request locks the PostgreSQL user ledger accounts, checks
available funds, creates the request and reserves funds in one transaction.
Approval and broadcast leave funds reserved. Denial atomically releases them.
`RECONCILIATION_REQUIRED` deliberately retains the reservation because an
external transfer may have happened. Only authoritative confirmation settles.

Sweeps and gas top-ups move platform-controlled on-chain assets between
custody addresses. They do not change beneficial ownership and therefore
never post to user ledger accounts.

## Migration and future work

The migration creates empty ledger tables and intentionally does **not** infer
historical balances from legacy deposits or withdrawals. Operators must
reconcile pre-migration data explicitly rather than accept fabricated opening
balances. Full reorg scanning, external broadcast reconciliation, an outbox,
fee accounting and real MPC integration remain future work.

This ledger is a financial-accounting foundation; it does **not** make this
repository a production MPC wallet.
