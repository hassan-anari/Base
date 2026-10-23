# R1/R2 remediation validation — 2026-10-23

Same Draft PR [#37](https://github.com/hassan-anari/Base/pull/37), base
`24eed19e6e280083793c69c3901f5f746dd0a2fe`. Corrections were published in
`f973cc8fe2a967f9b5e7ebd044a8e82e120b84eb`; scoped TLS patches and expanded
lint coverage in `ac476accfae4ed91bfe31fc0bfce1499831b9a42`.
Independent security re-review remains required. No mainnet or Phase 6G-C work.

## Completed implementation-head checks

[Fast CI 39966436875](https://github.com/hassan-anari/Base/actions/runs/39966436875)
passed at ac476acc. [Full run 39966475502](https://github.com/hassan-anari/Base/actions/runs/39966475502)
correctly failed its aggregate gate: twelve jobs passed; EVM had 44 passing cases
and one failed fixture compatibility case. This is not a fourteen-job pass.

Passing jobs: backend 607 cases, preflight 8, Rust full protocol 6, network 162,
TRON 5, Solana 2, TON 3, auxiliary persistence 1, integrated four-chain 1;
frontend contracts/builds, Rust fmt/Clippy/fast tests and unsuppressed audit passed.
The 31 fast Rust cases overlap five of the six protocol cases: 32 distinct Rust
cases. Crypto inventory remains 219 cases, with all 45 EVM cases required.

The failed lifecycle test changed signer-a's TLS private-key encoding to SEC1
while reusing a module-scoped store containing signed HD receipts created by the
preceding EVM acceptance. Receipt loading correctly rejected the missing supported
receipt identity. The correction uses a separate genuine three-signer DKG/auxiliary
fixture for lifecycle/legacy compatibility and asserts that no HD root receipts
exist before changing the encoding. It never removes, hides or converts existing
store evidence. Production authorization, startup refusal and receipt checks are
unchanged. The whole final-head gate must run again; the PR body records its exact
final SHA, run links and completed results without rewriting this failed history.

## Genuine isolated validator evidence at ac476acc

The EVM child acceptance itself completed successfully before the later fixture
failure. [EVM public evidence](evm-r1-r2-ac476acc.json) records three distinct
children, original root/child identities, independently installed fixture public
pins and all signer-origin receipts. Native child spend:
`0xae25fd3e494e378418738a30d5bd29b3574c20446843a58f61375388b5f457a7`;
ERC-20 child spend:
`0xfe873b87b68c23bb29efda1c19a049abada86512d499fc0cbedb6b925e0a9934`.
Both spent from `0xece29e74270786be69b01c7df9219de2a881debf` with B+C,
original custody grants and confirmed successful receipts. The middle recorded
transaction is a distinct genuine MPC hot-root gas top-up, not a child spend.
Existing acceptance checks finalized attribution, exactly-once balanced journals,
gas-funding exclusion, fee settlement and persisted-byte broadcast recovery.

[TRON public evidence](tron-r1-r2-ac476acc.json) records independent genuine root,
three children and all signer receipts. Native child spend:
`d22129709aa6a6abcdd39f5e25d84a40203f9f3306590732946bbee2eea4f0af`;
TRC-20 child spend:
`dc50875735dbbac09758cf49745060f69d5f233403eb4cac925e793da7fba112`.
Source `TFbU8xe4xoR9xedw6HcurU8bCDFHipPZo4` spent with B+C and original custody
grants. Root and child public keys differ; validator owner/source checks, TAPOS,
resource accounting and finality remain enforced by the original acceptance.

A separate public-key verification script, without importing the application
receipt verifier or reading private keys, verified 12 P-256 signatures per chain
(three root and nine child), distinct pins and three canonical child addresses.
These public fixture pins document test provenance; they do not independently
establish production trust-anchor enrollment or separate host/admin isolation.
No private identity, wrapping key, share, nonce or fixture store is published.

## Complete issuance benchmark at ac476acc

One isolated GitHub runner: Linux 6.17.0-1022-azure x86_64, four logical CPUs,
16,377,732 KiB RAM, Python 3.11.17, PostgreSQL 16.15. The runner reports CPU as
`x86_64`; no unmeasured processor model is inferred. Eight workers issued 1,000
actual customer signing accounts and 1,000 asset views in **633.222s, 1.57922/s**,
including reservation, all-three authenticated signer approval, independent public
verification and durable publication. Exactly 1,000 authenticated child requests;
zero threshold signatures during issuance. No reservation-only throughput claim.

| Stage | Samples | Mean | Maximum |
|---|---:|---:|---:|
| Reservation | 1,000 | 6.876ms | 14.278ms |
| Independent public verification | 2,000 | 4.476ms | 15.273ms |
| Claim/publication save | 2,000 | 6.588ms | 95.385ms |
| Asset attachment | 1,000 | 21.256ms | 36.221ms |
| PostgreSQL FOR UPDATE | 12,000 | 0.516ms | 77.565ms |

Coordinator requests averaged 4.942s, including signer/store work and contention;
this is not exclusive CPU time. SQL latency includes execution and waiting, not
isolated lock-wait attribution. Account table plus indexes occupied 9,437,184 bytes.
Four-service restart took 5.547s; all 1,000 original identities recovered in
69.869s (14.313/s), without new derivation approvals. Reconnected single replay
took 98.587ms. Genuine native signing including preparation/dispatch took 5.912s;
token signing after dispatch took 6.012s. This bounded population is supporting
development evidence, not unlimited capacity or final-head performance after
further implementation changes. Complete raw measurements are in the EVM JSON.

## Residual findings and review boundary

R1 and R2 remain awaiting independent acceptance; neither thread is self-resolved.
Old unsigned evidence remains quarantined and preserved; migration 0032 does not
invent signatures, change ownership, recycle indices or rewrite financial journals.
SQL publication guards check shape/identity; application verification checks ECDSA.
Protected independently enrolled signer pins and trusted DB writers remain explicit
deployment assumptions. Unknown outbound outcomes remain reserved.

**scc 2.4.0 / RUSTSEC-2026-0205 remains P1 OPEN.** Scoped HashSet use does not
constitute independent clearance. The atomic-polyfill maintenance warning also
remains visible. The five fresh rustls/webpki advisories are addressed only by
0.23.46/0.103.16 patch updates, without suppressing audit or changing MPC pins.
Solana scalable provisioning, lifecycle/rotation/recovery and Hot/Warm/Cold
foundations remain exclusively for the final Phase 6G-C PR. No TON scope extension,
production activation, second ledger or merge is authorized here.
