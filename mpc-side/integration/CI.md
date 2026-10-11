# Exact-head cryptographic CI

This changes test scheduling only. It does not change custody behavior, CGGMP24
or FROST, auxiliary generation, nonce consumption, recovery, trust domains,
serialization, authorization, settlement or activation guards.

## Measured sequential baseline

Successful run [37968676516](https://github.com/hassan-anari/Wallet-MPC/actions/runs/37968676516),
reviewed head `ee6f05d6bfc7f3986ffddd5824a7401be9769401`:

| Stage | Actual duration |
| --- | --- |
| Full workflow to successful aggregate gate | 31m56s |
| Rust cache restore action | 10.7s; HIT, approximately 398 MB |
| Cargo compilation | 19.7s |
| Initial CGGMP process tests, 38 cases | 20.6s |
| Auxiliary module, 46 cases | 28m08.9s |
| EVM fresh auxiliary protocol | 317.7s |
| EVM group, 41 cases including shared fixture and acceptance | 411.7s |
| TRON fresh hot-root auxiliary protocol | 376.9s |
| TRON group, four cases including deposit-root generation and real validator acceptance | 958.1s |
| Partial-persistence fault injection, one independent fresh execution | 318.9s |
| Remaining auxiliary cases beyond the three acceptance cases | 83.3s |
| FROST/DKG/network process tests, 124 cases | 89.4s |

Group times are sums of public JUnit case durations, including fixture setup,
call and teardown. The EVM acceptance case alone reports 343.6s and the TRON
acceptance case 942.9s. The old record does not separately time the second TRON
root and java-tron execution; the new record adds these two stage measurements.
Fresh-prime generation has variable duration. Compare actual run wall time,
stage durations and runner consumption rather than treating one entropy sample
as a fixed benchmark. The PR verification record contains the measured after run.

## Layout and acceptance rules

Fast/default PR checks remain backend/PostgreSQL, Rust formatting/Clippy/fast
tests/audit and frontend checks. They run on every ordinary PR update.

The opt-in full gate first requires all fast jobs and a crypto preflight. Preflight
checks integration lint, complete collection and compilation, starts the real
independent mTLS services and disposable EVM validators, and starts the pinned
java-tron validator and executes a disposable faucet contract deployment. This
catches broken runtime, RPC and TVM fixtures before fresh primes. This deployment
is a setup check, not MPC custody acceptance.

Then seven independent jobs run in parallel:

| Suite | Original scenarios | Private fixture ownership |
| --- | --- | --- |
| `evm` | 41 auxiliary, signing, recovery and EVM custody cases | One reused module-scoped `auxiliary_network` |
| `tron` | Three signer-pair cases and genuine TRON custody acceptance | One reused `tron_auxiliary_network`, plus independent deposit root |
| `aux-persistence` | Partial auxiliary persistence fault injection | Its own `Processes` and fresh auxiliary execution |
| `network` | 38 CGGMP keygen and 124 FROST/DKG/network cases | Existing fixtures, local to this job |
| `solana` | Genuine SOL/classic SPL acceptance | Original isolated Agave fixture |
| `ton` | Genuine V5R1/reference Jetton MPC and validator acceptance | Original pinned TON genesis and proof fixtures |
| `integrated` | Shared-ledger four-family workflows, overlapping signing, failures and restarts | One PostgreSQL/MPC environment, staged pinned validators; see `PHASE6F-D.md` |

Tests inside each group remain sequential; shared mutable state is never used
across jobs. No original assertion or cryptographic test is removed or weakened.
The fixture-aware collection guard assigns every original scenario exactly once,
rejects unknown auxiliary scenarios/duplicate inventory, records public node IDs
and phase durations, and fails a selected suite on skipped or unexecuted cases.
The seven suites cover 213 existing scenarios plus one integrated shared-environment scenario.

`Swatinem/rust-cache@v2` remains in use. Preflight restores the existing
`mpc-network` shared key; each suite restores that same build-cache identity.
Each job builds its own required executables from its verified immutable checkout.
No custom build cache or binary distribution is needed unless measurements show
poor reuse. Live signer stores, wrapping keys, auxiliary secret material and
signing nonces stay local to each runner. Uploads are allowlisted public JUnit,
collection/timing manifests and `tron-evidence.json`, retained for seven days.

Every job checks its checkout against `REVIEWED_HEAD_SHA`. The aggregate gate
requires `success` from every fast job, preflight, the full Rust protocol job and
each of the seven separately named process jobs. Failed, cancelled or skipped dependencies fail it;
it also verifies the exact seven-suite selection. Separate required job results
avoid relying on matrix-result aggregation; one failed suite does not cancel the
other independent suites.

## Development and debugging

1. Run focused deterministic tests for individual edits.
2. Run Fast CI on ordinary commits.
3. Run the relevant real-process suite when changing that integration.
4. Run the complete exact-head cryptographic gate at final acceptance or after a
   material signing/security-boundary change. Another SHA's pass is supporting
   evidence only.

For local collection or execution, supply the complete inventory and select one
suite. Configure PostgreSQL, build the existing MPC binaries/examples and install
the existing EVM npm package first; TRON additionally needs the pinned jar and
Java 8 documented in `PHASE6F-A.md`.

```bash
CRYPTO_SUITE=tron # evm, aux-persistence, network or all
pytest -x -v -s \
  mpc-side/integration/test_cggmp.py \
  mpc-side/integration/test_cggmp_aux.py \
  mpc-side/integration/test_network.py \
  mpc-side/integration/test_dkg.py \
  mpc-side/integration/test_signing.py \
  --crypto-suite="$CRYPTO_SUITE" --durations=0 \
  --crypto-manifest=work/crypto/manifest.json \
  --basetemp=work/crypto/fixtures --junitxml=work/crypto/results.xml
```

Add `--collect-only` to verify the partition without generating any shares or
primes. Ordinary pytest commands without `--crypto-suite` retain their previous
behavior.

In Actions, use workflow dispatch with `full_crypto=true` and choose `crypto_suite`
(`evm`, `tron`, `aux-persistence`, `network` or `protocol`) to debug one group.
Choose the exact branch/commit ref. A partial dispatch deliberately cannot satisfy
the full aggregate gate. `crypto_suite=all`, the existing `run-full-crypto` label
event or the scheduled full run executes all required suites. Ordinary commits
do not automatically rerun the expensive gate, even if the label remains present.

Phase 6F-D adds `--crypto-suite=integrated` to the complete inventory and required
aggregate. See [PHASE6F-D.md](../../PHASE6F-D.md) for trust boundaries, public
evidence, fresh-root cost and the final-head review gate. No individual suite is
removed or invoked a second time from within the integrated suite.
