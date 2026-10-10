# Phase 6F-C — TON native and TEP-74 custody through FROST

Base: verified Phase 6F-B merge `2db961dce9d5557aed67233be47fcaafc358abd2`.
One Draft PR, unmerged, for independent security review. This continues the
original roadmap. No Phase 6F-D, 6G, 7, 8 or 9 work is included.
**Mainnet, public testnet, production withdrawals and customer funds remain
disabled. Passing isolated acceptance does not establish production readiness.**

## Audit and integration boundary

The previous TON outbound adapter was explicitly unsupported; native TON
capabilities were disabled. Its recent-30 indexer, unauthenticated finality,
memo assumptions and deterministic local address/signing placeholders could not
authorize custody. These paths were replaced or rejected, without re-enabling
the legacy capability presets. There is no assumed TON USDT master.

The existing Rust protocol, authenticated coordinator and three signer services
perform the original FROST Ed25519 2-of-3 DKG/signing. Django freezes policy,
verifies public evidence and builds messages. It contains no FROST protocol or
full private key. Existing `OnchainTransactionAttempt`, `MpcSigningSession`,
`WithdrawalRequest`, `SweepJob`, `GasTopupIntent`, PostgreSQL execution locks,
audit records and append-only double-entry journals remain authoritative.
There is no additional coordinator, ledger or competing operation lifecycle.
EVM, TRON and Solana keep their existing algorithms and execution boundaries.

Reviewed entrypoints include the native/token executors, metadata verification,
registry/configuration, root bindings, payload/consumer, signer adapter,
outbound/reconciliation, sweeper/gas station, indexer service/models, keyset
commands, Rust DKG/signing/coordinator/signer and both CI workflows. The new TON
modules separate serialization, contract identity, network proofs, operation
policy, message effects, indexing and financial posting.

## Exactly one owner wallet: V5R1

The only approved owner wallet is the widely used standard TON Wallet V5R1,
workchain 0, client context version 0/subwallet 0, signatures enabled, with no
extensions or library state. No custom wallet is created. V5R1 encodes network
domain separation in its wallet identifier and StateInit; this avoids adopting
V4R2's more involved replay-policy boundary.

| Contract | Approved representation/code hash |
|---|---|
| Wallet V5R1 | `20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f` |
| Reference Jetton Wallet | `a760d629d5343e76d045017d9dc216fc8a307a8377815feb2b0a5c490e733486` |
| Reference Jetton Master | `f95ba0330b38cdf3459b1e811e5fc6fa6cfee566d7b764455c0468140365a737` |

Wallet sources are pinned from
[`ton-blockchain/wallet-contract-v5`](https://github.com/ton-blockchain/wallet-contract-v5/tree/ff2a9cdb5abe3efdba1e773e4d03a53dea1550b1).
The contract's last source change is `88557ebc33047a95207f6e47ac8aadb102dff744`.
Recompilation with the pinned FunC 0.4.4 toolchain (`func-js` 0.7.0 alias)
matches the exact V5R1 code in pinned `@ton/ton` 16.3.0. Jetton sources are pinned
from `ton-blockchain/token-contract` commit
`1182ad99413242f09925d50e70ccb7e0e09f94d4` and recompile with `func-js` 0.11.0.
Source and artifact licenses are included; standard libraries retain their
LGPL notices. `ton/compile.cjs` checks all three hashes.

An external audit report's correspondence to this exact V5R1 artifact has not
been independently established in this workspace. Standard-version identity,
source recompilation and contract execution are established; the report-to-code
correspondence is an outstanding P1 review input, not an asserted audit result.

Initial data is `is_signature_allowed:1 = 1`, `seqno:uint32 = 0`,
`wallet_id:uint32`, original authenticated DKG public key `uint256`, and empty
extensions dictionary. The wallet identifier is
`(global_id & 0xffffffff) XOR 0x80000000` for the approved context. The address
is `0:<StateInit representation hash>`, independently derived in Python and
Rust. It is never the Base58 public key or the old deterministic placeholder.

Undeployed accounts must have no active code/data and the independently derived
address. Deployment includes that exact approved StateInit. Active accounts
require proof-bound actual code/data, public key, wallet identifier, seqno,
signature enablement and empty extensions. Unknown versions, code hashes,
workchains, identifiers, disabled signatures, plugins/extensions and trailing
state are rejected. Database ACTIVE status alone proves none of these facts.
`ton_wallet_binding` authenticates original DKG evidence before committing the
public binding; root hot-wallet binding rechecks the same evidence. Child
derivation and automatic root provisioning remain unsupported.

Raw addresses preserve workchain. Friendly addresses require valid CRC16,
recognized tags and retained bounce/test flags. Mainnet-friendly addresses are
rejected at authorization. Raw addresses have no network flag; the independently
established global ID, genesis and StateInit supply their network identity.

## DKG and exact signing input

The dedicated keyset has algorithm `FROST_ED25519`, curve `ed25519`, scope `TON`,
threshold 2-of-3 and fixed `signer-a`, `signer-b`, `signer-c` identities. Original
authenticated receipts, execution UUID, result fingerprint and identical
PublicKeyPackage/verification shares are imported and rechecked. Solana retains
scope `SOLANA` and unchanged `SOLANA_MESSAGE` semantics.

The new payload is `TON_V5R1_CELL_HASH`. The V5R1 signing cell contains:

```
signed_external#7369676e
wallet_id:uint32 valid_until:uint32 seqno:uint32
inner_request:(one approved send_msg action, no extended actions)
```

The input to ordinary Ed25519/FROST is exactly the 32-byte representation hash
of that cell. It is neither the BOC nor SHA256(BOC), and no additional digest is
introduced before FROST. Python builds canonical TL-B/BOC; Rust independently
rebuilds the cell, StateInit and source address with `everscale-types` 0.1.2.
The SDK independently produces the same signing-cell hash. Actual TVM and
validator execution verify the resulting signature. Different libraries can
order a BOC DAG differently; Rust checks decoded representation identity while
Django requires its canonical complete BOC.

The sole internal message, amount, destination, bounce flag, comment, send mode,
deployment, Jetton identities, seqno and expiry are immutable authorization
fields. Rust denies unknown authorization fields and arbitrary signing cells.
The Django transaction identity additionally freezes decimals and verified token
metadata and binds approved operation, asset,
original DKG and fee policy. The verified 64-byte signature is appended to the
signing cell, assembled into the external message, consumed once and committed
with the original external BOC/hash before broadcast. Authenticated transport,
execution UUIDs, fingerprints, nonce tombstones and restart recovery are reused.

## Native TON and fees

All values are exact integers in nanoTON (10^9 per TON), converted with Decimal;
financial arithmetic uses no float. Local 80-digit Decimal contexts preserve
full ledger-field precision in conversion, negation, reservation and settlement;
the process-wide Decimal context is unchanged. The only send mode is 3 (pay fees separately
and ignore action errors, as required for V5 external sends). Destination and
payload are frozen. Native comments are opcode zero and at most 96 exact bytes;
Snake/custom bodies are unsupported. Uninitialized native recipients require
nonbounce semantics. Successful external wallet execution or increased seqno
does not settle the intended internal transfer.

Native sweeps retain a 10,000,000 nanoTON fee budget and 20,000,000 nanoTON storage
reserve. Gas funding is at most 0.13 TON, requires that reviewed station policy,
and proves the recipient's original FROST-owned V5R1 state before signing and
broadcast. A grant uses `GasTopupIntent` idempotency and is never customer credit.
Native and Jetton operations at the same owner contract share one sequence.

Genesis storage, gas and forwarding parameters 18/20/21/24/25 are independently
hashed. The upstream verifier proves current configuration against the verified
masterchain root; changed prices fail closed. Fixed budgets are restricted to
these reference contracts and isolated genesis prices. Actual proven transaction
fees plus retained forwarding/IHR fees are posted once by account/transaction
hash. Costs at external recipients are excluded from custody contract fees.

External Jetton recipient funding, less proven returned excesses, is separately
posted to `TOKEN_GAS_EXPENSE`; observed custody transaction fees use
`NETWORK_FEE_EXPENSE`. Both use the existing TON treasury double-entry accounts.
Funding between owned contracts is an internal treasury movement. Scanner and
reconciler serialize cost journal creation under a PostgreSQL transaction lock,
preventing simultaneous duplicate fee postings. Settlement and its financial
postings commit together.

## TEP-74 master, wallets and asynchronous execution

The authoritative token identity is an operator-allowlisted Master address,
not a symbol. Approved master/wallet code hashes, decimals, content hash and
provenance are bound to the metadata fingerprint. Master state must actually
contain the pinned wallet code/content. Python derives each Jetton Wallet
StateInit from owner, Master and code. Proof-bound `get_wallet_address(owner)`
and `get_wallet_data()` are executed locally by the upstream client from proven
states; remote getter output explicitly labelled untrusted is never accepted.
Actual owner, master, code and token balance are checked. Uninitialized recipient
wallets may be deployed by the reference internal transfer; active incorrect
wallets are rejected before signing. Fake masters, wallets and stale metadata
fail closed. No actual USDT identity or implementation compatibility is asserted.

The supported opcodes are transfer `0x0f8a7ea5`, internal_transfer `0x178d4519`,
transfer_notification `0x7362d09c`, and excesses `0xd53276db`. Transfer query ID
is the original owner-wallet seqno, durably associated with that operation.
Token amounts use approved integer base units. The response destination is the
original source owner; custom payload is absent; forward TON is one nanoTON;
forward payload is the reviewed comment; 100,000,000 nanoTON is attached to the
already verified source Jetton Wallet with bounce enabled.

Reconciliation distinguishes signature, external submission, V5 execution,
sender Jetton request execution, recipient Jetton execution, notification and
excesses return. Each link requires the exact prior outgoing/incoming message
hash, account, query ID, amount and owner/master identities. Recipient compute
and action success in the pinned implementation prove token credit. Outgoing
emission or a notification alone cannot settle. Exact excesses must execute at
the source, and their amount informs funding accounting. Partial execution,
recipient failure, bounce, missing history or uncertain returns retain the
original reservation and `RECONCILIATION_REQUIRED`. Verified bounce rollback is
tested; automatic compensation/replacement is deliberately unavailable.

## Sequence ownership and recovery

`SourceAccountSequence.owner_attempt` plus a PostgreSQL source advisory lock
serialize first-row creation and all native/token/funding operations at one V5
contract. The original sequence is committed with preparation. The same attempt
cannot claim another sequence. Another operation requires terminal delivery
evidence for the prior owner and a separately proven next on-chain sequence.
An increased seqno is an additional ownership check, never delivery proof.

Signing freshness and pre-broadcast checks reprove ownership, original seqno,
balances, fee configuration and expiry margin. Expiry is bounded to 30–300
seconds from verified fresh chain time (preparation uses 120 seconds). An expired
signature, RPC timeout, lost response or pruned history does not prove
non-execution and cannot release funds or recreate an uncertain FROST execution.
Committed bytes and identities survive signer/coordinator/Django restart.
The normal recovery path reconciles those bytes. Any future replacement needs
authoritative proof and a separately reviewed explicit transition; none is
silently introduced here.

Outbound history uses bounded 128-block pages with durable original attempt
confirmation progress, frozen masterchain anchor, next parent identity and
relevant proven transaction cells/inclusion identities. Partial asynchronous
chains carry forward to later verified checkpoints. Missing/pruned ancestry
retains progress and reservations. More than 128 relevant operation transactions
requires manual review. No independent transfer or new expiry replaces the
unresolved original operation.

## Deposits and attribution

Only unique original-root-bound owner contracts are enabled. There are no TON HD
deposit children and no shared-address multi-customer credit model. A nonempty,
durably assigned exact invoice/comment is additionally required. Missing or
unknown invoices remain uncredited; cross-asset records sharing an owner address
must belong to the same customer. Conflicting customer ownership is rejected.

Native deposits require finalized actual incoming internal messages, exact
destination/value and successful execution or the narrowly checked nonbounce
uninitialized-account credit phase. Bounced/malformed/unsupported messages are
uncredited and durably audited. Balance deltas do not prove deposits.
Jetton deposits require actual successful incoming internal_transfer at the
verified recipient Jetton Wallet, authentic derived/verified sender wallet,
Master/owner associations and exact memo/amount. A notification is insufficient.
Unreviewed mint/burn/custom flows remain uncredited or unresolved.

Per-account `ton_scan_cursor` records complete progress and bounded backfill
parent/checkpoint identities. Full hash-linked history is resumable to genesis;
there is no last-30 truncation. Credits, observed fees, quarantine audit and scan
cursor commit atomically. Deposit deduplication uses transaction and incoming
message identity, with masterchain/shard/account/lt inclusion persisted in
`Deposit.chain_evidence`. Known internal custody sources, gas grants and sweeps
are excluded. Insufficient historical proof cannot become customer credit.

## Actual isolated network and trust assumptions

Acton Localnet is feasible without an additional development phase. The fixture
uses the Localton image referenced by Acton **1.2.1**, source commit
`13594911b09b0a9bc68910111e0bb88a74161f5b`, with the exact image digest
`sha256:c5dd9dcb3f662c85ec0636c19b85664b69ccad554ef69b6adf3864e7e9e82387`.
Its OCI source revision is `72bf7425d9d034adf81ac7ebd900c7d03182f234`; the image
label says `master`, so it is identified by revision/digest, not a fabricated
release label. The fixture directly invokes its documented Localton tools; an
additional Acton CLI installation is unnecessary. It runs real validator-engine,
consensus and elections, not Sandbox. Observed container memory was about
692 MiB; no external RPC, Kubernetes or persistent CI cluster is needed.

Fresh CI provisioning creates a private named volume, writes global ID **-777**
before genesis and binds HTTP v2/ADNL to host loopback ports 18002/18004. Existing
containers/volumes are refused rather than overwritten. Resumed development
uses capture of the existing preserved network. V3 indexed services are not
needed for the proof path. Only explicitly named public artifacts are exported;
validator/faucet keys, signer storage and private PKI are never uploaded.

Global ID is decoded independently from actual local masterchain and basechain
zero-state BOCs and checked against the physical settings file. Cell root and
BOC file hashes are derived before querying the network and checked against
global configuration and running zero-state identity. Current checkpoints are
untrusted candidates until proof verification. No RPC self-reported checkpoint
or alternate config init block/hardfork may replace genesis.

The exact upstream `lite-client` binary SHA256 is
`da7a4c01c0253106d7360eabec356ab4f17ca7c8f5fa5ab118aecf32432dc2b9`,
TON source commit `3d478cbde854be03a18ab2a59f8fc3c565cf7d14`.
`blkproofchain <local-zero-state> <specific-masterchain-block>` must return a
validated complete chain ending at that exact block. The upstream client
verifies consensus signatures, modern Simplex proof structures and election
transitions. Python independently verifies the full masterchain BOC file/root
hashes and network/shard identity. Its verified shard descriptor anchors a
complete hash-linked shard ancestry; account dictionaries and transaction cells
bind actual account/lt/hash and incoming/outgoing message identities. Proven
account state and locally executed getters are additionally checked.

`pytoniq` is only an **untrusted ADNL byte transport**. Its incomplete modern
proof schema is not a finality authority. A TON Center response, HTTP success,
external-message acceptance or mock response proves no financial outcome.
Fresh masterchain time is required; split/merge and nonzero-workchain histories
are unsupported and fail closed. All endpoints remain loopback; there is no
public explorer/API fallback or redirect path.

Trust rests on locally established genesis/configuration, the pinned container
and native verifier supply chain, the controlled Docker host, its validator
keys, filesystem/DB integrity and the original authenticated MPC services. This
single-operator disposable validator environment does not demonstrate independent
multi-operator Byzantine resilience. It **does** exercise actual validator
blocks, cryptographic consensus proofs, masterchain-anchored shard inclusion and
asynchronous execution. Those are distinct from emulator results.

## Acceptance and CI

`test_ton.py`: real independent mTLS coordinator/signers, fresh TON FROST DKG,
A+B/A+C/B+C signatures, SDK-identical cell hashes, actual TVM deployment, native
withdrawal/sweep, Jetton withdrawal/sweep, duplicate rejection, partial execution,
spoofed notification/internal_transfer, corrupted recipient owner/master failure
and bounce rollback, native bounce, restart, expiry and interrupted nonce
tombstone. The corrupted account is an explicitly injected negative TVM fixture;
it is not claimed to arise from a normal on-chain deployment.

`test_ton_network.py`: separate actual Localton validator acceptance, fresh real
FROST DKG/signing, deployment/native transfer, Jetton withdrawal/sweep, actual
master/wallet getter verification, consensus/masterchain/shard/transaction/message
inclusion, and a native bounce whose transaction chain is independently included.

`test_ton_django.py`: PostgreSQL and actual Rust/validator processes; authenticated
DKG import/activation/root binding, native/Jetton deposits and sweeps, both
withdrawals, original `GasTopupIntent` funding, accepted-broadcast lost response,
coordinator/signers restart and exactly-once reconciliation/credits/costs.
The local completed run records **23 journals, 46 postings, six signing sessions,
and zero native/Jetton reserved balances**. Repeated scans/reconciliation leave
journal counts unchanged. Public IDs/evidence are in `acceptance/phase6fc/`.

Local checks: **477 PostgreSQL backend tests passed, zero skipped**; focused TON
regressions **29 passed**; genuine TON suite **3 passed** (195.93 seconds against
the preserved long-running network); non-protocol Rust workspace **26 passed**;
four original genuine cryptographic protocol tests passed. Configuration,
migration, format/lint and workspace clippy checks passed. Final SHA CI results
and wall-time comparison are linked in the Draft PR after execution.

TON is an independently selectable `crypto_suite=ton` job using pinned npm
dependencies, reproducible contract recompilation and existing Cargo caching.
It does not generate EVM/TRON auxiliary primes. Fast CI checks policy/wire code
and PostgreSQL regressions. The aggregate full gate requires every previous
suite **and TON**, with failed/cancelled/skipped required jobs rejected. Only
public result manifests, JUnit and curated evidence are uploaded. The existing
parallel CI structure is retained. Phase 6F-B's final gate is the baseline:
run `38049401737`, observed first-job-to-final-gate span approximately 27m11s.

## Review restrictions and remaining findings

No unresolved P0 was found by the implemented checks. This is not an independent
security audit. Independent review
of the new authorization, native proof interface, asynchronous accounting and
recovery boundaries is required before any operational use. The explicit P1
input is external audit-report correspondence to the exact wallet artifact.
Missing/pruned history is a fail-closed deterministic regression; this does not
claim a live validator-pruning acceptance experiment. Automatic recovery from
expired or bounced financial operations is unavailable pending independently
reviewed recovery authority. Split/merge, other workchains, other wallet/Jetton
implementations, HD provisioning and actual USDT remain unsupported.

Feature flag defaults remain `MPC_TON_INTEGRATION_ENABLED=false` and empty
`MPC_TON_NETWORK`; approval requires self-hosted MPC, live execution/indexing,
development environment, non-demo operation, test-only TON registry, original
authenticated roots and independently established local network artifacts.
Nothing in this milestone enables public-network or production funds. Keep the
PR Draft and unmerged, and stop for independent security review.
