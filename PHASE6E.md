# Phase 6E — EVM MPC custody integration

Phase 6E stays within the original nine-phase roadmap. Phase 6D's distributed
CGGMP24 implementation is reused without changing its cryptographic protocols,
mTLS identities, encrypted share storage, or randomness. Phase 6F has not begun.

## Scope and activation

Supported: explicitly bound **root-keyset** EVM addresses, native transfers and
reviewed ERC20 transfers, legacy EIP-155 and EIP-1559 transactions. The runtime
chain identifiers accepted by the Phase 6D contract remain ETH, BSC, MATIC, ARB,
and BASE. Their actual numeric EVM chain IDs come from Django's runtime registry;
an operator alias is never a numeric network identity. Public integration accepts
only the reviewed pairs below, with `is_testnet=true` additionally required:

| Custody alias | Reviewed public testnet | Numeric EVM chain ID |
| --- | --- | --- |
| ETH | Ethereum Sepolia | 11155111 |
| BSC | BNB Smart Chain testnet | 97 |
| MATIC | Polygon Amoy | 80002 |
| ARB | Arbitrum Sepolia | 421614 |
| BASE | Base Sepolia | 84532 |

Other numeric identities, including Optimism mainnet 10, are rejected regardless
of an operator's `is_testnet` label. Disposable custom identities require separate
explicit development authorization; this does not authorize a production RPC.

Default configuration remains disabled (`custody.E011` and runtime guards):

```dotenv
MPC_SIGNER_BACKEND=self_hosted_mpc
MPC_EVM_INTEGRATION_ENABLED=true
MPC_INTEGRATION_ENVIRONMENT=development
MPC_EVM_DEVELOPMENT_CHAINS={"ETH":31337,"BASE":31338}
CUSTODY_DEMO_MODE=false
CUSTODY_TX_MODE=live
MPC_COORDINATOR_URL=https://localhost:8443
MPC_CA_CERT=/path/to/test-ca.crt
MPC_CLIENT_CERT=/path/to/custody.crt
MPC_CLIENT_KEY=/path/to/custody.key
MPC_REQUEST_TIMEOUT_SECONDS=5
```

`MPC_EVM_DEVELOPMENT_CHAINS` defaults to `{}`. This optional JSON mapping authorizes
only the immutable disposable local-chain allowlist **31337 and 31338** for each
permitted custody alias in the `development` environment. Arbitrary numeric
identities, including production IDs explicitly entered in this mapping, are
rejected. The five reviewed public testnet pairs above remain supported.
All enabled primary and fallback RPC endpoints
must use HTTP(S) URLs with a port and literal IPv4/IPv6 loopback addresses
(for example `http://127.0.0.1:8545` or `http://[::1]:8545`). DNS names, including
`localhost`, credentials and fragments are rejected for this mode. Custom remote
RPCs and custom identities in `testnet` mode remain disabled. Use only disposable
chains; a loopback proxy to a production network is not authorized development.
Loopback and numeric-identity checks reduce accidental misuse; they are not
cryptographic proof that a local proxy cannot misrepresent an upstream network.
Production/mainnet activation remains disabled and deployment is outside Phase 6E.

Before preparation/nonce allocation and before coordinator execution, all enabled
RPC endpoints must report the authorized numeric `eth_chainId`. Each native/ERC20
RPC operation independently checks its actual endpoint immediately before use,
including broadcast failover and reconciliation receipt/finality reads. A changed
or mismatched endpoint fails closed; no mismatched fallback receives signed bytes
or supplies settlement evidence. HTTP redirects are not followed. An ambiguous
primary send followed by a mismatched fallback remains reconciliation-required
with the original signed bytes, nonce, session and reserved funds preserved.

`MPC_INTEGRATION_ENVIRONMENT` permits only `development` or `testnet`. The guard
loads and validates the TLS configuration; all requests still require TLS 1.3,
CA and hostname verification, and the coordinator's exact SPIFFE URI. The Rust
service authenticates Django's custody identity. There is no HTTP, local-signer,
or certificate-verification fallback. `local_key` remains demo-only. Non-EVM
MPC execution is disabled by this integration even though Phase 6D protocol
regression tests still exercise TRON and FROST.

This flag establishes technical integration, **not production fund authorization**.
General HD provisioning, resharing/rotation, production infrastructure, and
production/mainnet activation remain disabled or outside this phase. Broader
activation awaits the Phase 6G, 7, and 8 safeguards and separate review.

## Root keysets and ownership

`cggmp_hd_v1` is retained as the existing Rust/Django contract metadata. It does
**not** mean that Phase 6D executes child derivation. Django never derives or
reconstructs any private key. A requested child path produces
`UnsupportedMpcDerivation`; the root key is never substituted for it.

An EVM keyset must have ACTIVE status, CGGMP24_ECDSA/secp256k1/EVM shape, exactly
2-of-3 participants `[signer-a, signer-b, signer-c]`, and persisted DKG execution,
result fingerprint, and canonical compressed public key. Every advancement
fetches authoritative `/v1/keysets/{id}` metadata over authenticated mTLS and
checks the DKG result, durable three-party receipt agreement and auxiliary
completion/readiness against that persisted identity.

Importing authoritative public evidence does not activate it:

```sh
python manage.py mpc_keyset import-dkg --keyset-id <existing-EVM-keyset-uuid>
python manage.py mpc_keyset activate --keyset-id <existing-EVM-keyset-uuid>
python manage.py bind_mpc_hot_wallet --chain ETH --keyset-id <uuid>
python manage.py bind_mpc_hot_wallet --chain ETH --keyset-id <deposit-keyset-uuid> --user-wallet-id <id>
```

A CREATING keyset is allocated through the existing `mpc_keyset create` command;
real coordinator DKG and auxiliary execution must use that same keyset UUID.
`import-dkg` and EVM activation require coordinator evidence. EVM activation
deliberately leaves `active_for_new_wallets=false` to prevent fictional automated
HD provisioning. Legacy keysets are not auto-activated.

The binding command verifies the configured address locally from the public key;
execution additionally validates its authoritative DKG/auxiliary identity. Hot
wallets explicitly store `signing_key_ref=keyset:<uuid>` and the FK. Deposit
wallets additionally store `derivation_version=mpc_root_v1` and
`derivation_path=keyset:<uuid>`. Each source needs its own verified binding to the
actual DKG key controlling that address. A manually entered reference alone
never establishes ownership. Address mismatches fail closed.

## Audited integration boundaries

The existing EVM native/ERC20 builders, durable nonce allocator, independent
signature assembler, broadcast transport, finality monitor, and ledger settlement
were retained. Incomplete boundaries corrected in Phase 6E:

- Session creation did not execute the coordinator's asynchronous protocol.
- Django sent child derivation references to a root-only signing contract.
- Response handling could lose execution identity on immediate completion and
  failed to propagate ambiguous signing state to the transaction and parent.
- Legacy preparation included a `from` descriptor field that must be excluded
  from Ethereum's cryptographic serialization.
- Session fingerprints alone did not bind the complete approved custody intent.
- Concurrent execution could repeat preparation or claim broadcast twice.
- Parent workflows could call an incomplete signature a broadcasted transaction.
- Existing worker advancement consumed signatures but did not continue broadcast.

## Transaction identity and execution

```mermaid
sequenceDiagram
    participant Intent as Approved custody operation
    participant DB as Django/PostgreSQL
    participant Coordinator as mTLS coordinator
    participant MPC as Two independent signers
    participant EVM as Reviewed EVM executor / chain
    Intent->>DB: Claim withdrawal, sweep, or gas intent
    DB->>EVM: Prepare reviewed unsigned transaction
    DB->>DB: Allocate nonce; persist final unsigned payload
    DB->>DB: Freeze full transaction identity + exact 32-byte digest
    DB->>Coordinator: Idempotent create, then explicit execute
    Coordinator->>MPC: Existing interactive CGGMP execution
    DB->>Coordinator: Read authoritative state / reconcile same execution
    MPC-->>Coordinator: Independently verified completion
    Coordinator-->>DB: Execution, signer identities, signature components
    DB->>DB: Recover DKG key; assemble bytes; persist bytes + local hash atomically
    DB->>EVM: Broadcast exactly persisted bytes
    EVM-->>DB: Authoritative receipt and finality
    DB->>DB: Settle withdrawal reservation exactly once
```

The digest is calculated **after** durable nonce allocation from the final
persisted unsigned payload. It is the Ethereum signing prehash and is never
hashed a second time for ECDSA. SHA-256 is used only for metadata fingerprints.
The additive `MpcSigningSession.transaction_identity` field freezes operation
ID/type, runtime and numeric chain IDs, asset/token, source/destination, integer
amount, nonce, complete unsigned payload, fees, keyset public identity, and DKG
fingerprint. `coordinator_request_id` fingerprints that snapshot. Retries
reconstruct and compare both the entire snapshot and exact signing digest before
calling the coordinator. Pre-existing sessions without this snapshot fail closed;
no migration invents transaction or DKG evidence.

The Rust signing request contract is unchanged. Its attempt ID links the digest
and coordinator execution to Django's complete immutable snapshot. Responses
must preserve all request fields, logical session, cryptographic execution,
keyset, threshold signer selection, and payload fingerprint. Signature components,
encoding, parity, scalar ranges and low-s are checked. Django independently
recovers the public key from the **exact persisted prehash**, compares the original
DKG public key and source address, assembles the legacy/typed transaction, and
calculates its hash locally from its signed bytes. The coordinator never
assembles or broadcasts a chain transaction.

## Recovery and accounting

Normal lifecycle:
`PREPARING → PREPARED → SIGNING → SIGNED → BROADCASTING → BROADCASTED → CONFIRMED`.
PostgreSQL advisory ownership serializes resumable advancement, preparation and
broadcast per attempt; a competing worker returns the current durable state.
Row locks atomically persist the session and nonce allocation and consume a
completed signature together with the signed bytes and local transaction hash.
The advisory claim is released on worker death. Runtime activation requires
PostgreSQL; SQLite cannot activate the integration or establish concurrent safety.

One attempt owns one signing session. Create and execute are idempotent for that
same coordinator session. Interactive cryptography runs asynchronously in Rust;
a normal HTTP request does not wait for the whole protocol. Run the existing
worker command repeatedly to poll, consume completed signatures, resume SIGNED
attempts and continue broadcast:

```sh
python manage.py advance_mpc_signing
python manage.py advance_mpc_signing --attempt-id <id>
python manage.py reconcile_outbound
```

Timeouts, transport ambiguity, crashes during broadcast, missing known
coordinator executions, conflicting identities, or invalid signatures require
reconciliation. They never create replacement signing randomness or nonce
allocations. `/reconcile` recovers the existing durable public result; it never
starts a substitute execution. An unknown create response may repost the exact
same logical request only while no coordinator execution identity is known.
A known missing execution fails closed. A coordinator CREATED result permits
execute of that same existing execution, including after a lost create response.

A crash after signature completion permits consumption of the stored result.
A crash after SIGNED permits verification and broadcast of the exact persisted
bytes. A crash after BROADCASTING requires chain reconciliation. Safe, proven
prebroadcast rejection retains the MPC signed bytes and nonce for the identical
transaction; ambiguous acceptance never authorizes another signing or automatic
broadcast. Absent chain evidence remains unresolved rather than releasing funds.

Pending signing keeps withdrawal/gas parents PROCESSING and sweeps
SWEEP_PROCESSING. Uncertainty propagates RECONCILIATION_REQUIRED. Withdrawal
approval evidence and ledger reservation must match the exact intent, and no
release/settlement may already exist. Existing confirmation rules and append-only
ledger idempotency remain authoritative for settlement. Sweeps revalidate active
deposit source, asset, eligibility snapshot, hot destination and confirmed linked
gas intent. Gas top-ups retain their durable intent, known destination and grant
ceiling; there is no special signing bypass or public digest-signing endpoint.

## Verification gates

Fast PR gates: the complete PostgreSQL backend suite (including existing ledger
and transaction concurrency cases), deterministic Phase 6E contracts/recovery,
Django checks and migration consistency, Ruff, Rust fmt/clippy/fast workspace
tests, existing Rust dependency audit, frontend contract tests and both builds.
Test-only local signatures in deterministic tests do not establish MPC acceptance.
The fast frontend job also installs the EVM fixture on Linux and compiles its
Solidity token, catching fixture platform/lockfile failures before fresh-prime
protocol execution. Ganache's bundled macOS-only `fsevents` dependency is optional;
its lockfile retains that classification so npm 10 can install the fixture on Linux.

The **default approval requirement is the full cryptographic gate**, on the exact
reviewed PR head. The final PR #30 correction limited to the development allowlist,
its regressions and this documentation proposes a narrow exception: the full gate
[passed on `bc2c913cae9207f1d6da0ae464d6f0b5eb6c9618`](https://github.com/hassan-anari/Wallet-MPC/actions/runs/37946589711),
while focused regressions and Fast CI separately verify the corrected head.
The full gate is **not rerun on that corrected head**; this supporting evidence
is not an exact-head full pass. Final reviewer acceptance is required, after
verifying no cryptographic, transaction-execution or CI implementation changes.

**Before merge**, a reviewer with label permission adds
`run-full-crypto` to the PR. The `pull_request: labeled` event executes the PR's
workflow without requiring it to exist on the default branch. It uses read-only
contents permissions, no deployment secrets, and never `pull_request_target`.
Every job checks out the immutable event's `pull_request.head.sha`, verifies
`git rev-parse HEAD`, and prints that SHA in its logs and step summary.

Ordinary opened/reopened/synchronize events retain fast checks and skip the full
jobs, even if the label remains attached. To verify a later head, remove and
reapply the label after the final push. In Actions, select the **labeled** run,
compare its reported SHA with the current PR head, and require successful
`rust-crypto`, `mpc-network`, and `full-crypto-gate` jobs, plus the fast jobs.
The aggregate gate fails if either full job fails, is cancelled, or is skipped.
Skipped full jobs on ordinary runs are not a passing approval gate.

Weekly schedules cover default-branch regression only, not an unmerged PR.
`workflow_dispatch full_crypto=true` remains an additional option once that
trigger exists on the default branch; it is not the pre-merge trigger for PR #30.
The full gate retains all Phase 6D tests without reducing protocol,
fresh-prime, replay, restart, fault-injection, FROST or TRON regression coverage:

```sh
cargo test --locked --workspace --manifest-path mpc-side/Cargo.toml
cargo build --locked --manifest-path mpc-side/Cargo.toml --bins --examples
npm ci --prefix mpc-side/integration/evm
pytest -v mpc-side/integration/test_network.py mpc-side/integration/test_dkg.py mpc-side/integration/test_signing.py mpc-side/integration/test_cggmp.py
pytest -v -s mpc-side/integration/test_cggmp_aux.py
```

The new `test_phase6e_real_evm_custody_acceptance` reuses the EVM fresh-prime fixture
within its existing module. It uses real coordinator/three signer binaries,
independent encrypted storage/wrapping keys, TLS 1.3 identities, real DKG,
auxiliary generation and B+C signing with A offline. Two disposable Ganache RPC
chains verify genuine legacy and EIP-1559 native transfers and an ERC20 transfer
through Django's reviewed executors. It covers coordinator restart after durable
completion, concurrent broadcast, accepted-but-lost RPC response, finality and
exactly-once settlement, one-signer rejection, and unsupported child references.
Run only with a disposable PostgreSQL database and no production credentials.
The independently deployed fixture token is acceptance-only.
