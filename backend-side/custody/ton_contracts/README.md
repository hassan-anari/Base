# Approved TON contract artifacts

Only V5R1 owner wallets and the pinned reference TEP-74 master/wallet are accepted.
Code representation hashes are constants in `ton_wire.py` and Rust `ton.rs`.
Every runtime artifact load checks the code hash.

`wallet-v5r1.boc.hex` matches `@ton/ton` 16.3.0 and recompiles from
`ton-blockchain/wallet-contract-v5` commit
`ff2a9cdb5abe3efdba1e773e4d03a53dea1550b1` with FunC 0.4.4 (`func-js` 0.7.0).
`jetton-wallet.boc.hex` and `jetton-minter.boc.hex` recompile from
`ton-blockchain/token-contract` commit
`1182ad99413242f09925d50e70ccb7e0e09f94d4` with `func-js` 0.11.0.

The unchanged sources and pinned compiler/npm lockfile are under
`mpc-side/integration/ton/`. Run `node mpc-side/integration/ton/compile.cjs` after
`npm ci --prefix mpc-side/integration/ton` to check all approved hashes.

Wallet V5 has the included Tonkeeper MIT license. Jetton contracts have the TON
Foundation MIT license in the source directory. FunC standard libraries retain
their LGPL v2-or-later source notices and the included LGPL license.
External audit-report correspondence and operational restrictions are documented
in `PHASE6F-C.md`; source recompilation alone is not a security audit.
