# Phase 6F-D — Integrated four-chain MPC custody acceptance

Base: `572040a344ac41cacfb60178bba1d205076deb47` (merged Phase 6F-C).
Branch: `phase6fd-integrated-custody`. Development acceptance only. The final
reviewed SHA, required job conclusions, test totals and timings belong in the
Draft PR verification record and the artifacts for that exact SHA. A Fast CI
pass or a partially completed integrated run does not satisfy this milestone.

The original nine-phase roadmap is unchanged. This phase implements no bridge,
swap, atomic cross-chain transfer, new cryptographic protocol, HD derivation,
provisioning automation, resharing, rotation, recovery mechanism, administrative
governance, financial integration or production product work.

## Architecture and audit findings

The audit follows the merged Phase 6E, 6F-A, 6F-B and 6F-C documents and their
actual Django models, registry, ledger, indexers, outbound state machines,
reconciliation, gas station, sweeper, keyset commands, Rust services, encrypted
storage, protocol modules, validator fixtures and CI selection rules.

One Django custody application uses one PostgreSQL database. `Asset.asset_key`
is globally unique; ledger accounts and journal headers use that key, not the
display symbol. Deposits and withdrawals retain their chain and asset; attempts
retain approved operation identity, prepared bytes, network sequence and signed
transaction. `MpcSigningSession` owns one original authenticated coordinator
session/execution and a complete transaction identity. Three independent signer
processes keep encrypted shares and protocol state. Custody never reconstructs
a private key. Existing external fixture faucets fund and deploy test contracts;
they never sign custody withdrawals, sweeps or gas operations.

Demonstrated integration defects and narrow fixes:

* A populated asset's chain, contract, decimals, standard, native designation or
  asset key could be edited through the registry while its globally keyed
  balances remained. PostgreSQL migration `0024` freezes those identity fields
  after the first ledger account and freezes existing populated assets. Account
  insertion and registry mutation lock the same asset row. Deposit validation
  and first credit, and withdrawal validation and reservation, also hold that
  row; validation cannot precede an intervening identity mutation. Display
  symbols and capability switches remain editable. No balance is rewritten and
  no competing ledger is added. Direct bulk updates cannot bypass the trigger.
* A second native asset key could credit the same native chain/address/event
  into another spendable balance. A PostgreSQL reproduction credited both keys
  once for one financial event. Migration `0024` now requires one native asset
  identity per chain, including disabled rows; disabling a former identity does
  not authorize a replacement alias. Existing duplicate native identities abort
  migration for reconciliation rather than silently consolidating balances.
  A disabled populated token could similarly acquire a second financial alias
  for the same chain/contract/standard. A targeted PostgreSQL regression proved
  that account creation succeeded. A separate partial uniqueness constraint on
  populated token identities now rejects this at the first account freeze,
  including concurrently and while the original asset is disabled. Unpopulated
  disabled metadata records retain their existing configuration semantics.
* Root ownership checks verified current scope and network but did not durably
  prevent rebinding original roots after configuration changes. The existing
  keyset now holds append-only chain/network/DKG snapshots. PostgreSQL prevents
  replacement, deletion and cryptographic identity mutation after binding.
  Existing explicit EVM multi-alias use remains possible; an existing alias
  cannot adopt a replacement network. Legacy bindings without sufficient
  original network evidence fail closed, requiring explicit reconciliation.
* TON bindings could be deleted/recreated or duplicated under another address.
  A root now has one immutable original TON binding, protected by a unique
  constraint and database trigger. Reuse across independent genesis instances
  sharing the global ID remains prohibited, including after process restart.
* EVM's numeric chain ID alone did not distinguish isolated validators sharing
  that ID. Development networks now require `MPC_EVM_GENESIS_HASHES`, verified
  per endpoint and frozen with the root/operation. Missing, malformed or changed
  pins fail closed. These are independently controlled local fixtures; genesis
  pinning does not make their ordinary RPC responses Byzantine proofs.
* EVM reconciliation lacked the consumed-MPC-completion and original signed
  identity checks already used by other families. All four now require those
  checks before financial settlement. EVM operation identity also retains its
  minimum confirmation requirement. Errors leave uncertain execution reserved.
* EVM/TRON reconciliation observed fees but did not journal execution expenses.
  Their actual finalized receipt costs now post once to the original chain's
  native treasury/expense accounts inside the existing settlement transaction.
  Original gas/resource caps remain enforced. Existing Solana fee/rent and TON
  fee/Jetton gas postings are retained. Token symbols never select fee accounts.
* EVM indexer and token-metadata reads did not consistently use MPC endpoint
  guards. They now check runtime network identity; native deposit ingestion also
  requires a matching successful receipt in MPC mode.
* Genuine interleaved withdrawal execution exposed valid lowercase EVM
  recipients rejected by the serialization library after reservation. Digest
  and signature assembly now normalize only the serialization copy to checksum
  form. The approved recipient and immutable persisted identity are unchanged;
  both representations encode the same original 20 address bytes.

Migration does not repair historical financial corruption or invent missing
original cryptographic evidence. Conflicting historical bindings abort the
migration. Operators must reconcile conflicts before applying it. SQLite does
not enforce these PostgreSQL triggers and is not MPC acceptance evidence.

## What the evidence establishes

1. Protocol correctness: original CGGMP24 and FROST tests, genuine DKG, fresh
   CGGMP auxiliary generation, distributed signing, encrypted durable storage,
   nonce tombstones and original recovery requirements.
2. Chain execution: independently selectable genuine EVM, TRON, Solana and TON
   suites exercise their own wire formats, supported tokens and finality.
3. Integrated custody: an additional suite uses the same application/database,
   coordinator, three signers and independent roots while operations interleave
   across families. It checks shared financial invariants, authorization
   isolation, outages, duplicates and process recovery.
4. Production readiness: none of the first three supplies production approval,
   multi-operator provenance, organizational governance or operational readiness.

The cryptographic 2-of-3 quorum proves distributed signing. It does not satisfy
administrative multi-person approval. Existing approval audit records and
chain-specific policy checks remain required.

## Shared-environment acceptance matrix

`mpc-side/integration/test_integrated.py` is one independently selected pytest
scenario with multiple required stages. It does not invoke the independent
chain acceptance tests a second time. All stages must execute and pass.

| Boundary | Required integrated exercise |
| --- | --- |
| Roots | Genuine import and activation of separate hot/deposit roots per family: EVM/TRON CGGMP24 secp256k1; Solana/TON FROST Ed25519 |
| Networks | Approved EVM numeric ID/genesis; TRON genesis/checkpoint; Solana offline genesis artifact; TON independently captured zerostate/basestate and verified finality |
| Assets | ETH/ERC-20, TRX/TRC-20, SOL/classic SPL, TON/reference allowlisted TEP-74 Jetton; exact contract/mint/master and six-decimal fixture token metadata |
| Deposits | Real finalized native and token transfers, intended customer attribution and one journal credit per original event |
| Outbound | Approved reservation, genuine MPC signature, durable signed bytes before broadcast, authoritative finality and exactly-once settlement |
| Sweeps/funding | Actual eligible native/token sweeps; bounded MPC gas/resource funding and existing Solana rent/TON Jetton gas policies |
| Concurrency | Overlapping EVM/TRON, EVM/Solana and EVM/TON operations; separate PostgreSQL connections and recorded signing start/completion intervals |
| Isolation | Real TRON RPC process stop while EVM continues; changed TON genesis and wrong Solana FROST root rejected; cross-chain/session authorization replay rejected by original coordinator |
| Uncertainty | Lost Solana broadcast response and withheld finalized history retain the original reservation; actual blockhash expiry remains reconciliation-required; TRON RPC uncertainty remains reserved; no timeout-based release |
| Quorum | One signer stopped with genuine B/C quorum; two signers stopped with no signature/local-key fallback |
| Recovery | Coordinator restart during an original execution; actual Django worker SIGKILL after signed-byte persistence and replacement broadcast; all MPC processes restart with original identities |
| Financial state | Same-symbol token balances stay separate; every journal conserves one asset; costs use native assets; duplicate completion/reconciliation does not post twice; unknown outcomes remain reserved |

EVM remains live through heavy-validator stages. TRON can stop after its stage;
Solana starts subsequently and remains live during TON/fault tests. TON's pinned
Docker network is retained throughout. PostgreSQL and encrypted MPC stores are
not replaced between stages. This is staged validator acceptance with recorded
two-network overlaps, not a claim that four validators execute simultaneously.
The harness aligns the two original MPC dispatches after each chain finishes
genuine preparation. It records dispatch and signature-completion timestamps
and requires positive overlap; the barrier produces no signatures or RPC success.

The isolated EVM gas-funding fixture grants `0.03` ETH because the existing
conservative token requirement is `200000 * 100 gwei = 0.02` ETH. The independent
fixture's `0.005` grant correctly fails that preflight after a native sweep.
Fee caps are unchanged; this adjustment supplies enough bounded fixture funding.

Independent suites retain more detailed chain-specific expiry, missing history,
source contention, nonce persistence, token metadata, cursor/checkpoint,
partial-persistence and replay cases. Their success remains mandatory; integrated
evidence complements those cases rather than treating mocked backend tests as
cryptographic acceptance.

## Reproduction and CI

Use the dependencies and pinned validator artifacts documented in the original
chain phases and `.github/workflows/crypto-suite.yml`. PostgreSQL 16 is required.
Use original `environment.Processes` mTLS identities and binaries built from
the reviewed head. TON must be provisioned once with its pinned digest and
compiled reference hashes. Never recreate TON genesis while reusing its root.

The complete inventory is:

```sh
pytest -x -v -s \
  mpc-side/integration/test_cggmp.py \
  mpc-side/integration/test_cggmp_aux.py \
  mpc-side/integration/test_network.py \
  mpc-side/integration/test_dkg.py \
  mpc-side/integration/test_signing.py \
  mpc-side/integration/test_solana.py \
  mpc-side/integration/test_ton.py \
  mpc-side/integration/test_ton_network.py \
  mpc-side/integration/test_ton_django.py \
  mpc-side/integration/test_integrated.py \
  --crypto-suite=integrated --crypto-manifest=work/crypto/manifest.json \
  --junitxml=work/crypto/results.xml --durations=0
```

Change the selector to `evm`, `tron`, `solana`, `ton`, `aux-persistence` or
`network` for debugging; only `all` with every required job can satisfy the
complete gate. Collection requires the complete inventory even for one selector.
The inventory now contains 214 process scenarios (213 existing, one integrated).
Failure, required skipping, cancellation or incomplete execution fails the gate.

Fast CI includes PostgreSQL financial-identity/race and network-identity
regressions, Django checks/migration consistency, scoped Python formatting/lint,
Rust formatting/clippy/fast tests/audit and frontend checks. The complete gate
also requires crypto preflight, full Rust protocol tests and all seven separately
named process suites. Each checkout verifies `REVIEWED_HEAD_SHA`.

The new suite reuses the pinned validators, dependencies and Rust cache keys.
Its four independent CGGMP roots require genuine fresh auxiliary generation;
this has measurable variable cost. Actual JUnit durations, per-job start/end
times, total gate wall time and sum of runner job seconds must be reported from
the final-head run. Estimates and earlier-SHA passes are supporting evidence only.

`PHASE6FD_DEV_RESUME` is an explicit local harness-debugging option which retains
the original encrypted services and public DKG request IDs after an assertion
failure. CI never sets it and always creates fresh independent private fixtures.
Local dirty-tree or reused-root runs cannot be represented as final-head fresh
CI acceptance. Reuse does not change TON's original genesis restriction.

## Public artifacts and review gate

The integrated suite produces `work/integrated-review/public-evidence.json` with
the reviewed Git SHA/dirty state, independently established network policies,
public keyset scopes/algorithms/DKG fingerprints, original operation identities,
MPC sessions/executions, selected signers, signed-byte hashes, transaction IDs,
actual finality evidence, deposits, journal identities, per-asset balances,
concurrency intervals, fault/recovery outcomes and durations. CI also uploads
public JUnit and selection/timing manifests. Existing suites retain their
original validator/MPC evidence artifacts.

Uploads are explicit allowlists. Never upload signer stores, shares, private
keys, nonce secrets/tombstone contents, authentication tokens, private PKI or
confidential certificates. Public genesis/configuration and finalized chain
proofs are reproducible evidence, not signing material.

Do not mark Phase 6F-D complete until all required jobs for the final head pass.
Record exact CI links, conclusions/counts/timings and any unexecuted scenario in
the Draft PR; then stop for independent security review. Do not merge.

## Production blockers and restrictions

* **P1 OPEN:** Phase 6F-C external TON V5R1 audit correspondence remains OPEN.
  Its exact-artifact production blocker is unchanged, not waived or downgraded.
* Public mainnet activation remains disabled and real customer funds prohibited.
  All original integration switches remain default-disabled and fail closed.
* EVM/TRON/Solana ordinary RPC finality still trusts independently controlled
  isolated fixtures. TON's original verified lite-client/genesis boundary is
  preserved; one operator's local network is not a production multi-operator
  trust model.
* TON supports only native V5R1 custody and the allowlisted reference TEP-74
  master/wallet implementation. This establishes no actual TON USDT support.
* Unsupported chains, child derivation paths, wallet implementations and token
  standards remain rejected. Phase 6G and phases 7–9 remain out of scope.
* Historical evidence conflicts/missing pins and unresolved executions need
  reconciliation; this migration supplies neither historical repair nor a new
  key recovery protocol.

Newly discovered financial identity and rebinding defects require independent
review of the narrow database guards and migration. Passing tests do not
substitute for that review or authorize production deployment.
