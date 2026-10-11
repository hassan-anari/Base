# Phase 6G — first provisioning foundation, Draft for independent review

Verified base/main: `99d005e23f1463ebb245fc451552af944a1fdd1f` (PR #35).
Draft PR: [#36](https://github.com/hassan-anari/Wallet-MPC/pull/36).
Feature branch: `phase6g-provisioning-foundation`. Phase 6G remains **IN PROGRESS**.
This slice implements **path reservations, not deposit address issuance**. It
does not enable production, change TON, or claim child-key spendability.
The exact final head and CI run URLs are supplied in the Draft PR evidence.

## Acceptance for this slice

1. Authenticate the original active CGGMP DKG and auxiliary three-signer receipts
   over the existing mTLS client before registering an allocation namespace.
2. Freeze one root, one network/genesis, one deployment ownership scope,
   HOT security class, DEPOSIT purpose and explicit path format/version.
3. Concurrent retries reserve one canonical non-hardened path per idempotency
   key; conflicts cannot change the customer owner. No wallet, address, balance,
   signing nonce, private material or financial posting is created.
4. Commit the reservation and counter together. Rollback consumes neither;
   process/connection restart returns the committed original UUID and path.
   Retirement rejects new assignments while preserving existing retry identity.
5. PostgreSQL constraints/triggers prevent identity rebinding, path mutation,
   hardened indices, counter rewind, network additions, deletion and false ISSUED
   states. Preserve all historical wallets, reservations and journal identities.
6. Run concurrency/migration/restart/negative tests, a 10,000-customer reservation
   benchmark, authenticated genuine-service registration, Fast CI and the full
   final-head cryptographic regression gate. No skipped gate counts as a pass.

## Pinned-source feasibility audit

Sources were downloaded from crates.io and their SHA-256 hashes checked against
the repository's unchanged `mpc-side/Cargo.lock`. Cargo 1.90.0 metadata and a
`cargo rustc -p cggmp24-keygen -- --print cfg` check confirmed the enabled feature
graph, including keygen/key-share `hd-wallet`. Upstream API availability is not
independent protocol review or evidence that this application's services use it.

| Crate | Exact version | Archive SHA-256 |
| --- | --- | --- |
| cggmp24 | 0.7.0-alpha.3 | c9a4f50f2c7c98676f10857cda178b6eea8468a8f95edba0745c8c1e288ebd25 |
| cggmp24-keygen | 0.7.0-alpha.3 | 6733c6c00e0df4c3e1d966ab676370b4b35c09f9e8c628339bf15f7c0405ac92 |
| key-share | 0.6.1 | 206b4474f861dedc6fc38e06f7c52c52f1e01180d5284aa62b58844a044fad7d |
| hd-wallet | 0.6.1 | 6522551bb35937363845f39a6d4c49e60bdb35a8f7154ebdd078cab50be97992 |
| frost-ed25519 | 3.0.0 | df345f704e41812a3ab238331a393126f76996c176d204296e289efe946c57f0 |
| frost-core | 3.0.0 | 81ef2787af391c7e8bedc037a3b9ea03dde803fbd93e778e6bb369547800e5cd |
| frost-rerandomized | 3.0.0 | 8f4c5cedd2426728adef2c0b1720f57676354c473836d1ccc50d0f0d1c91942b |

| Capability | Exact upstream support | Application now / decision |
| --- | --- | --- |
| CGGMP root HD material | `GenericKeygenBuilder::new` defaults `hd_enabled=true` with `hd-wallet`; the service uses that builder and does not disable it. `DirtyKeyInfo::chain_code` is optional; `extended_public_key()` requires Some. | Current ceremonies should generate chain codes, but neither DkgReport nor coordinator public evidence attests them. Historical roots must be inspected/attested by their original independent signers; never retrofit an invented chain code. |
| CGGMP public children | `key-share::DirtyKeyInfo::derive_child_public_key::<hd_wallet::Slip10,_>` and `HdWallet::derive_child_public_key_with_path`, using compressed parent public key + 32-byte chain code. | Supported by the pinned library, not exposed by our coordinator or Django. SLIP-10 secp256k1 non-hardened derivation is compatible with BIP32 child derivation; a distributed DKG root is not a BIP32 seed-derived master key. |
| CGGMP child signing | `SigningBuilder::set_derivation_path` derives an additive shift from the root's extended public key inside upstream threshold signing, without private-key reconstruction. | Not wired: `SigningExecution::validate` demands `derivation_reference=None`; source/recovery checks use the original root and signer `cggmp_sign` never sets a path. No derived-child signature or EVM/TRON execution is claimed. |
| Hardened secp256k1 children | The signing/public path APIs require `NonHardenedIndex` (0..2^31-1). Local secret-key SLIP-10 APIs in hd-wallet are not MPC functionality. | Reject hardened values and apostrophes. The reservation service accepts no caller-provided path at all; SQL requires exactly `m/0/<allocated index>`. |
| CGGMP refresh/resharing | Despite general crate prose, this exact `key_refresh.rs` exports `AuxInfoBuilder` for auxiliary (re)generation; it contains no callable core-share refresh or arbitrary membership/threshold resharing entry point. | Existing create-once core/aux files cannot be overwritten. Aux generation is not share refresh. Full-key reconstruction/dealer imports are forbidden. A different reviewed implementation or fresh root + explicit on-chain migration is needed. |
| FROST HD / SLIP-10 | frost-ed25519 exposes no BIP32/SLIP-10 child-key API or chain-code DKG. hd-wallet's Slip10 explicitly excludes Ed25519/Curve25519. | No Ed25519 copying of secp256k1 semantics. Existing SOLANA root references remain explicit `frost_keyset_v1`/`mpc_root_v1`, not HD. No FROST reservations in this slice. |
| FROST rerandomization | `rerandomized::sign_with_randomizer_seed` plus `RandomizedParams::new_from_commitments`/`regenerate_from_seed_and_commitments`; the randomizer hashes fresh signing commitments. Low-level randomizer constructors and deprecated signing APIs also exist. | The recommended API yields a signing-instance-specific key, not a stable preissued address. Reusing a fixed scalar or adapting deprecated APIs needs a separate cryptographic review; presence of constructors is not a reviewed persistent-wallet protocol. Not used. |
| FROST refresh / repair | `keys::refresh::{refresh_dkg_part1,refresh_dkg_part2,refresh_dkg_shares}` supports distributed refresh; `keys::repairable::repair_share_part1/2/3` repairs a participant's lost share via threshold helpers. | Upstream primitives exist; application generation/epoch tracking, authenticated routing, stale-share exclusion, crash handling and production recovery are absent. No refresh/repair endpoint enabled. Repair is not arbitrary resharing or a threshold change. |
| TON | Existing explicit FROST root + exact V5R1 StateInit/network binding. | Entire isolated scope and open P1 audit correspondence remain unchanged. |

Source references: [CGGMP signing builder](https://docs.rs/cggmp24/0.7.0-alpha.3/cggmp24/signing/struct.SigningBuilder.html),
[keygen builder](https://docs.rs/cggmp24-keygen/0.7.0-alpha.3/cggmp24_keygen/struct.GenericKeygenBuilder.html),
[key-share](https://docs.rs/key-share/0.6.1/key_share/),
[hd-wallet](https://docs.rs/hd-wallet/0.6.1/hd_wallet/),
[FROST rerandomized](https://docs.rs/frost-ed25519/3.0.0/frost_ed25519/rerandomized/),
[refresh](https://docs.rs/frost-ed25519/3.0.0/frost_ed25519/keys/refresh/),
[repairable](https://docs.rs/frost-ed25519/3.0.0/frost_ed25519/keys/repairable/).
The downloaded crate source, not prose alone, was used to establish limitations.

## Ownership and derivation architecture for review

`MpcProvisioningRoot` is one-to-one with the original `MpcKeyset`. Registration
requires ACTIVE EVM/TRON CGGMP shape, original DKG/auxiliary evidence and exactly
one frozen network binding. Existing explicitly allowed multi-network signing
roots are preserved but cannot adopt this new dedicated allocation namespace.
The namespace records immutable ownership_scope, chain/network/genesis, original
public key and DKG execution/fingerprint, evidence, DEPOSIT purpose, HOT class
and `cggmp_slip10_nonhardened_v1`. This is **an allocation schema version**, not
a cryptographic capability attestation, and does not replace `cggmp_hd_v1`.
Numeric-only legacy EVM network bindings cannot register a namespace: an explicit
original genesis pin is mandatory in both the service and PostgreSQL trigger.

`MpcDerivationReservation` stores UUID, original root, customer_ref, idempotency
key, unique index, canonical `m/0/index`, and RESERVED status. All indices are
non-hardened. Index 0 in the first component denotes this version's DEPOSIT
purpose; the second is globally monotonic within the dedicated root. Do not
hash customer/asset strings into truncated indices. Do not recycle reservations.
The maximum allocated index is 2^31-1; 2^31 is only the exhausted counter sentinel.

The internal service always locks keyset then namespace. PostgreSQL insertion
locks in that order too and increments the counter in the same transaction.
Unique root/index, root/path and root/idempotency constraints prevent collisions.
Retries compare the customer and trusted ownership scope before returning the
original row, including after retirement. Counter increments caused by duplicate
or failed inserts roll back with the insert. Registration authenticates public
DKG evidence; allocation does not run cryptography or cache signing results.

ownership_scope is an explicit **deployment namespace**, not an implemented
Tenant model or caller-selectable API authority. No new public route, merchant,
exchange or financial API is introduced. Phase 8C must map authenticated tenant
principals and their accounts deliberately; it must not retrofit tenant ownership
by changing existing reservations or financial history.

The next issuance step must persist a verified **custody account** controlling a
child, with one beneficial owner per network/account identity, then expose
asset-specific UserWallet views. Multiple same-chain tokens may use that one
appropriate account for the **same owner**. Asset identity stays in the existing
registry/ledger, not in the child path. Different asset views never authorize
two financial owners of one account. Canonical EVM address normalization and
case-sensitive TRON/Solana identities must be preserved. SPL mint/ATA identities
remain separate from their signing authority. This account/asset-view attachment
is not implemented here; reservations cannot enter any scanner or sweep.

Independent signers must attest original chain code, root and child public key,
path/version, purpose and exact network/genesis. The coordinator and Django must
derive/compare the public child and EVM/TRON address independently, persist that
identity, and verify returned signatures against the child. Original requests,
DKG evidence and share files remain immutable. No fresh DKG per secp256k1 address,
local demonstration derivation, caller-supplied substitute public key or root
fallback is acceptable. Children are unissuable until genuine distributed
signing and real EVM/TRON child transaction acceptance pass.

## Solana feasibility and economic alternatives

There is no safely established stable threshold-HD approach in the currently
integrated FROST API. Per-customer FROST DKG is genuine and much lighter than
CGGMP auxiliary generation, but stores three encrypted artifacts per account
and needs measured DKG/restart throughput before claiming population scalability.
Creating thousands of database rows sharing a root proves neither independent
spendability nor unambiguous customer attribution.

Feasible approaches for a separate Solana review are:

- Dedicated FROST root per customer; amortize the root across SOL and classic SPL
  asset views where valid. Benchmark ceremonies and signer storage, not DB rows.
- Chain-native seeded System accounts (`createAccountWithSeed` /
  `transferWithSeed`) with a genuine FROST root as base signer; address derivation
  is the standard base+seed+owner account address, **not Ed25519 private-key HD**.
  For classic SPL, separately attributed standard token accounts can share an
  MPC authority. One root/mint ATA is not many customer accounts. The current
  custody validators accept neither seeded-source transfers nor arbitrary
  non-ATA token accounts; fee-payer, base/owner/seed binding, rent, authority,
  scanner attribution and token/native sweeps all require new acceptance tests.
- Shared MPC account with strictly verified required attribution data (e.g.
  a Solana memo). This changes deposit UX and parser assumptions, needs explicit
  missing/conflicting-tag handling, and does not create independent MPC wallets.
- A separately reviewed upstream persistent derivation protocol or future
  cryptographic dependency change; never patch a homegrown scalar tweak into FROST.

For seeded accounts, per-account rent and account-creation fees, retained native
reserves, SPL account rent and root fee-payer funding remain real costs. No
Solana scalable issuance implementation or rent benchmark is claimed by this PR.

## Lifecycle and security class boundaries

This slice registers already active original roots; it does not automate DKG,
activation/replacement selection, migration, refresh, restoration or rotation.
`active_for_new_wallets` remains unchanged/disabled by existing commands. Root
retirement cannot delete or reassign a reservation. Existing root signing still
requires ACTIVE and the historical retirement command can block funded root
wallet signing: this is a **remaining P1 lifecycle limitation**, not a new safe
retirement mechanism. Do not retire a funded root as an automatic rotation step.
The next lifecycle review must separate allocation eligibility from spend/drain
eligibility, preserve original operations and reservations, and never replace an
ambiguous signing/broadcast identity. No new authority to release funds exists.

The namespace's HOT class describes only its allowed allocation purpose. It does
not supply bounded production withdrawal policy or constrain the historical
root signing API. WARM/COLD allocation and false ISSUED states are rejected by
DB constraints; no ordinary online key can be advertised as Cold via this model.
Future Warm requires stronger independently enforced policy; Cold needs separate
custody authority/workflow plus Phase 7 governance and Phase 8A isolation. Watch-only
and external vaults must have no internal signing capability. Treasury automation
remains Phase 8B. Existing root-wallet bindings and signing policy are unchanged.

## Migrations, evidence and measured costs

0027 adds empty namespace/reservation tables; 0028 installs PostgreSQL identity
and allocation triggers. No historical wallets, balances, financial reservations,
signing sessions, assets or keyset activation flags are backfilled or rewritten.
Migration tests upgrade from 0026 and compare the legacy wallet record exactly.
Downgrade refuses any registered provisioning root, including an empty one,
because losing immutable allocation scope is unsafe. An empty installation can
downgrade. SQLite can create schema for tooling but allocation fails closed;
SQLite is never concurrency acceptance evidence.

Local PostgreSQL 16.15, eight workers, one contended namespace, 10,000 unique
customers/requests: **46.1376s, 216.743 reservations/s**, 3,579,904 bytes total
reservation table+indexes (357.9904 bytes/reservation). PostgreSQL commits include
the trigger counter update. The root is a synthetic public test fixture: these
figures measure reservation persistence only. Allocation performs zero DKG
ceremonies, zero signing rounds, zero blockchain transactions, and issues zero
addresses. Root generation costs, child attestation latency, chain funding/rent,
signer storage and end-to-end wallet provisioning economics remain unmeasured.
Do not extrapolate these figures to spendable-wallet throughput.

Reproduce with a disposable PostgreSQL and the existing development test env:

```sh
PHASE6G_BENCHMARK_COUNT=10000 pytest -s backend-side/custody/tests/test_phase6g_provisioning.py::test_large_population_reservation_benchmark --basetemp=work/provisioning-benchmark
pytest backend-side/custody/tests/test_phase6g_provisioning.py
pytest -s mpc-side/integration/test_cggmp_aux.py::test_phase6g_authenticated_root_path_reservations
```

The last case reuses one genuine three-service DKG/fresh-prime fixture, verifies
authenticated receipts, exercises concurrent retries and coordinator/DB-connection
restart, and proves no UserWallet was created. Existing EVM/TRON/Solana/TON full
gate scenarios remain intact. It tests genuine **root evidence registration**,
not derived-child signing. Fast tests use public synthetic/mocked metadata solely
for SQL and service behavior. Exact final-SHA CI evidence lives in the Draft PR.

## Findings and next reviewable slice

- No newly identified P0 in the tested reservation boundary; this is not a
  cryptographic audit or assurance of absence of hidden vulnerabilities.
- P1: unimplemented child-chain-code attestation/signing/address issuance;
  FROST persistent derivation unavailable in the reviewed application;
  funded-root retirement semantics; independent signer authorization and real
  Hot/Warm/Cold separation; existing production chain review and TON audit blocker.
- P2: one-root allocation lock contention; signer/storage/rent economics and
  full-population restart benchmarks remain; privileged SQL/trigger-disable
  resistance depends on separately reviewed DB roles/infrastructure. Canonical
  custody account/asset views and future tenant mapping require further review.

Next PR within **the same Phase 6G**: authenticated original CGGMP HD chain-code
attestation + versioned child public derivation and independent agreement,
followed by a separate small PR wiring child threshold signing, Django account
issuance and real EVM/TRON transaction/attribution/restart acceptance. Do not
enable issuance in the public API until the signing/spendability PR passes.
Then review Solana chain-native provisioning, lifecycle generations and governed
Warm/Cold boundaries as independent slices. No Phase 7/8 product APIs or TON
expansion are pulled forward, and no PR is self-approved, merged or deployed.
