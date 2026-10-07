# Custody stabilization baseline

This repository is **not a production MPC wallet**. `local_key` derives complete
private keys in-process and its broadcasts are synthetic. It is allowed only when
`CUSTODY_DEMO_MODE=true` and a non-empty `LOCAL_KEY_ENCRYPTION_PASSPHRASE` is set.
The `mpc_vendor` adapter remains unimplemented and therefore fails closed.

Generated frontend distributions are not source controlled. CI builds both SPAs,
and deployment packaging must build them into `backend-side/frontend_dist` and
`backend-side/simulator_dist` before Django static collection.

Withdrawal row locks prevent concurrent application workers from passing the
same state guard at once. This is not end-to-end exactly-once delivery: a process
or network failure after external work begins enters `RECONCILIATION_REQUIRED`.
An operator must determine external state before retrying; vendor idempotency and
automated reconciliation remain future integration work.

## Known high-priority follow-up work

* Replace demo credentials/JWT identity handling with the production IdP and
  durable user/RBAC model.
* Implement and independently review a real vendor signer/broadcaster; token
  metadata does not yet mean ERC20/TRC20/SPL/Jetton transfers work end to end.
* Replace floating-point chain adapter values with integer base units throughout.
* Add broadcast reconciliation/outbox handling and production-grade distributed
  locking; SQLite cannot provide PostgreSQL-equivalent concurrency semantics.
* Complete reorg handling and dedicated indexer support. Chain routing remains
  limited by the fixed `Network` enum and adapter factory.
* Resolve the currently reported frontend dependency audit findings (the local
  baseline reports one moderate and seven high findings) in a separate,
  dependency-focused change with UI regression testing.

## Phase 6 production signer

Production custody signing uses the separately deployed, self-hosted 2-of-3 MPC subsystem with
CGGMP24 secp256k1 and FROST Ed25519. `local_key` is demo-only; there is no SaaS signer fallback.
