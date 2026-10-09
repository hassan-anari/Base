# Phase 6F-A — TRON/TRC20 root-keyset custody

Base: merged Phase 6E `e8431bb8b5940a8338ffe7a192b47967a6f36aa6`.
This milestone is a Draft for independent review, not production activation.
6F-B (Solana/SPL) starts only after the owner reviews and merges 6F-A; 6F-C
(TON/Jettons) and 6F-D (cross-chain acceptance) remain separate milestones.
The original nine-phase roadmap is unchanged: 6G owns provisioning, genuine
derivation, keyset lifecycle/rotation/recovery; 7 owns administrative approvals,
MFA and governance; 8 owns production operations and financial integrations;
9 owns frontend productionization and complete UX/E2E validation.

## Audit and retained architecture

Reviewed Django `mpc_signing`, `mpc_binding`, `mpc_payload`, `mpc_identity`,
`outbound`, `native_tx`, `token_tx`, `token_metadata`, `reconciliation`,
`withdrawals`, `sweeper`, `gas_station`, models, runtime chain registry,
signer adapter and indexers; Rust protocol/coordinator/signer contracts; and CI.

The Phase 6D TRON contract already accepts the exact 32-byte TRON prehash and
executes genuine CGGMP24. No Rust protocol, share format, encrypted signer store,
mTLS identity, coordinator API or key-management engine is replaced. Phase 6E's
logical session/execution identity, PostgreSQL ownership, immutable intent,
signature verification and authoritative double-entry ledger are reused.

The audit found EVM-only integration guards and signature assembly; case folding
of TRON sources; node txIDs trusted without protobuf validation; short expiration;
weak native/token receipt correlation; and demo indexing selected from the
environment independently of Django settings. These are addressed in the
existing integration boundaries. No arbitrary digest signing endpoint is added.

## Scope and activation

Supports approved TRX and operator-verified TRC20 withdrawals, explicitly bound
deposit-root sweeps, conservative TRX resource funding, durable completion
recovery and solidified settlement. Mass wallet generation and child derivation
remain disabled. A cryptographic 2-of-3 quorum is not two human approvals.

Both flags default off. EVM behavior remains separately guarded:

```dotenv
MPC_SIGNER_BACKEND=self_hosted_mpc
MPC_TRON_INTEGRATION_ENABLED=true
MPC_INTEGRATION_ENVIRONMENT=development
CUSTODY_DEMO_MODE=false
CUSTODY_TX_MODE=live
CUSTODY_INDEXER_MODE=live
```

The existing PostgreSQL and TLS 1.3 coordinator configuration is required.
`MPC_TRON_NETWORK` is an operator-managed JSON object containing
`network="isolated-v1"`, `genesis_block_id`, `checkpoint_height`,
`checkpoint_block_id`, and `trusted_endpoints`. Checkpoint height must be positive.
All enabled RPCs must be explicitly trusted, literal loopback HTTP(S) endpoints
with ports. Redirects are rejected. Every endpoint is checked before preparation,
signing execution and broadcast; each actual RPC endpoint is checked again before
use, including failover and reconciliation.

TRON does not expose EVM's `eth_chainId`. `getnodeinfo`/software versions, address
prefixes and operator testnet labels cannot prove network identity. The reviewed
policy independently recomputes genesis/checkpoint block-header hashes and
requires the isolated genesis parent marker
`SHA256("Wallet-MPC Phase6F isolated TRON genesis v1")`. Operator pins must come
from independently controlled validator configuration/evidence. Do not copy pins
from an untrusted execution endpoint to authorize it. The acceptance fixture
controls the launched validator binary, genesis and P2P isolation and records its
initial block identities; this is fixture bootstrapping, not public-RPC discovery.

**Public Shasta/Nile, custom remote RPCs, production and mainnet are disabled.**
This is a trusted-node boundary, not a light client or proof that a malicious RPC
is honest. A node unable to establish the reviewed isolated identity is rejected.

## Ownership and transaction construction

Import/activate public DKG evidence using existing `mpc_keyset` commands. TRON
activation now checks authenticated durable three-party DKG and auxiliary
agreement, with ACTIVE CGGMP24_ECDSA/secp256k1/TRON, exactly 2-of-3 independent
participants and the original canonical compressed DKG public key. New-wallet
auto-provisioning stays off. `cggmp_hd_v1` is existing protocol metadata and does
not establish child derivation.

Bind hot and deposit wallets with the existing `bind_mpc_hot_wallet --chain TRX`
command and explicit `keyset:<uuid>` references. Deposit wallets require
`mpc_root_v1`; their source address must be the canonical Base58Check TRON address
derived from the DKG public key. Base58 addresses are case sensitive. An address,
reference or manually populated foreign key alone is insufficient.

`tron_wire` independently serializes the allowlisted protobuf fields of one
TransferContract or TriggerSmartContract and checks `raw_data_hex` and
`txID=SHA256(raw protobuf)`. Native units are exact SUN. Token transfer calldata
must be precisely `transfer(address,uint256)` for the configured verified
contract, recipient and integer amount. Attached TRX/TRC10 values, non-default
permissions, multiple contracts and unknown transaction fields are rejected.
No USDT address is embedded in generic execution logic.

The original node transaction is validated before a **single preparation-time**
expiration extension. `mpc_validity_seconds` is bounded to 300–900 seconds,
well below TRON's 24-hour limit. Timestamp/head skew is bounded; TAPOS reference
height/hash are independently checked and persisted. Raw bytes and txID are
recomputed before freezing intent. Timestamp, expiration, TAPOS, contract and
fee fields never change afterward. Starting signing requires at least 180
seconds remaining; broadcast requires over five seconds. A completed expired
signature is recovered as the original signature and cannot authorize rebuilding.

CGGMP receives the existing exact 32-byte txID without another hash. Django
independently verifies ECDSA, recovers the original DKG public key, checks low-s
scalar ranges and recovery ID 0/1, then persists canonical JSON for TRON's single
65-byte `r || s || v` signature and exact raw transaction before broadcast.

## Resource and token policy

Runtime `gas_settings` must explicitly provide reviewed validity, bandwidth-byte
and SUN-price caps, energy-price/unit caps, TRC20 fee limit and total-fee cap.
For example, the isolated acceptance fixture uses 600 seconds, 1000 bandwidth
bytes, 1000 SUN/byte, 500 SUN/energy, 100000 energy, 50000000 SUN fee limit and
51000000 SUN total budget. These are fixture policy, not mainnet recommendations.

Current chain fee parameters, source account/default owner permission, balance
and resource observations are validated. Token calls require successful bounded
`estimateenergy` and enough TRX for the complete fee limit plus bandwidth. Free
or delegated resources do not reduce the conservative funding requirement.
Native account-creation fees are included where needed. Native sweeps reserve
the conservative fee budget. Resource grants require a known ACTIVE root-bound
destination controlled by its DKG key and may not exceed the configured TRX
`topup_amount`; ambiguous gas intents do not produce another grant.

Operator token verification checks deployed contract identity/bytecode, successful
32-byte ABI decimals/balance responses and ledger precision (0–18 decimals), then
retains the existing fingerprint boundary. Operators must review token behavior;
symbol/display metadata is not identity. Fee-on-transfer, rebasing and unusual
execution shapes are unsupported when exact intended effects cannot be proved.

## Recovery, finality and accounting

The existing lifecycle remains
`PREPARING → PREPARED → SIGNING → SIGNED → BROADCASTING → BROADCASTED → CONFIRMED`.
Uncertainty enters `RECONCILIATION_REQUIRED`. One attempt owns one durable
logical signing session; retries/restarts reuse its execution and randomness.
Completed signatures are consumed once with persisted bytes in one transaction.
PostgreSQL advisory ownership serializes execution, broadcast and reconciliation.
The worker always broadcasts committed bytes. A timeout after a send cannot
authorize another signing session. Failover may submit only the same persisted
transaction, and never to an endpoint failing the network guard.

An additive TRX-only unique constraint prevents the same txID belonging to two
business attempts. Before migration, operators must resolve any historical
duplicate non-null TRX txIDs through accounting review; migration intentionally
fails rather than deleting or reassigning those rows.

Settlement requires consumed independently verified MPC completion, frozen
identity, exact original txID/raw bytes/signature, SolidityNode transaction and
receipt, a matching independently hashed solidified block and actual execution
outcome. Native success requires the intended TransferContract. Token success
also requires exactly one canonical Transfer log from the configured contract
with the intended source, destination and amount. Successful broadcast or an
unrelated successful contract execution cannot settle a withdrawal. Ledger
settlement/release retains existing unique journal keys and locked reservations.

Missing/unknown evidence, expiration and invalid token effects retain reservations.
No automatic non-inclusion/replacement mechanism is claimed: an original uncertain
attempt must be reconciled before any replacement. Only verified solidified
execution failure permits the existing exactly-once release. Expiration alone
never proves non-inclusion. No operator override for arbitrary signing is added.

The TRON MPC indexer uses pinned solidified RPCs and bounded resumable block scans,
actual block/transaction IDs and execution evidence, exact native or verified
token effects, and stable contract/log event identities. Genesis allocations
are excluded. Stub balances are explicitly forbidden with TRON MPC. Initial
lookback and backfill cursor policy must be configured for historical ingestion;
unsupported transaction shapes and internal native contract transfers are not
credited. Public network/indexer operational readiness remains outside this gate.

## Verification record

Deterministic RPC-emulator/local-key tests verify integration boundaries, but are
not MPC or chain acceptance. PostgreSQL suites cover approved native/token
transfers, ownership, exact bytes, tampering, expiration, ambiguous broadcast,
token evidence rejection, resource grants, duplicate txID protection, concurrency
and exactly-once journal outcomes. Existing EVM regressions remain enabled.

The opt-in full gate starts actual independent mTLS signer processes with
independently encrypted share stores, fresh TRON DKG/auxiliary executions and
genuine CGGMP signing. Its TRON acceptance launches pinned unmodified official
java-tron `GreatVoyage-v4.8.2.3` (jar SHA-256
`faef7f4d89b9f154632bbab2db1712c25f02ee37b356013e098558ea994accec`), Java 8,
a disposable single-witness isolated consensus network, and a deployed Solidity
TRC20 contract compiled for TVM-compatible Petersburg. The validator/faucet key
is fixture-only; custody keys are genuine MPC roots, never local keys.

Acceptance checks native withdrawal/sweep, token withdrawal/sweep and real TRX
funding with actual solidified outcomes and balance/log evidence. It injects
worker death after durable signature completion, coordinator/signer restart,
lost RPC response after real broadcast, unavailable quorum, and two competing
broadcast workers. No mocked signature, inclusion, TVM execution or balance
establishes acceptance. `tron-evidence.json` records network pins, real txIDs,
execution identity and solidified outcome; CI uploads it with JUnit results.

Ordinary CI keeps the expensive tests opt-in (`run-full-crypto` / dispatch).
Final review must use the fast CI and full cryptographic gate on the **exact PR
head**, whose SHA each job prints and checks. The Draft PR verification record
contains actual counts, SHA-specific CI links, acceptance results and blockers;
this document does not substitute a historical pass for the final head.

Known limits: isolated validators only; trusted RPC evidence without a light
client; conservative full-burn funding; restricted transaction/token shapes;
bounded indexing requiring operator backfill; no automated ambiguous expiration
release/replacement; no mass provisioning or child derivation; no independent
administrative multi-approval claim; no production readiness claim. Independent
review and repository-owner merge are required before 6F-B.
