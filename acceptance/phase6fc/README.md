# Public Phase 6F-C evidence

These are successful local acceptance captures against the preserved disposable
network. They contain public contract/message/transaction identities, original
DKG fingerprints, execution UUIDs, fees and ledger counts. No signer shares,
secret nonces, private validator/faucet keys or private PKI are included.

- `mpc-tvm.json`: genuine independent-process MPC and actual Sandbox TVM. Its
  `network_finality` is false; it cannot prove network finality.
- `isolated-validator.json`: genuine MPC plus actual validator-produced blocks,
  independently verified consensus proof chains and shard/message inclusion.
- `django-ledger.json`: the existing PostgreSQL custody lifecycle against those
  actual processes; ledger counts, original attempts and proof-bound settlement.
- `provenance.json`: independently captured image/genesis identities, pinned
  native verifier and an actual accepted complete masterchain proof result.
- `genesis/`: only public initial chain state/configuration artifacts. BOCs use
  hexadecimal text so reviewers can reconstruct bytes and independently hash
  them. These artifacts contain public on-chain state, not decrypted signer or
  node-key storage.

Pure `terminal_transfer_effect` results retain `network_finality:false` even
inside a network capture. The caller's consensus/inclusion checks are separate;
live Django confirmation records set network finality only after those checks.
These IDs do not identify public mainnet/testnet transactions.

Fresh CI genesis has new validator keys and therefore different zero-state and
transaction hashes. The fixture establishes the new trust root from local
artifacts before accepting running-network claims, then executes the same
verification. The exact final-SHA CI results are linked in the Draft PR.
Neither these captures nor passing CI establish production readiness.
