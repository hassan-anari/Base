# Phase 6F-C — limited development acceptance disposition

Recorded on 2026-10-10 for PR #33. This records the written project instruction
and the approval still required; it does not assert that an audit passed.

## Risk and approval record

| Field | Record |
|---|---|
| Risk | P1: external audit-report correspondence to the exact TON Wallet V5R1 artifact is not established. |
| Audit requirement | **OPEN — not completed, resolved, waived for production, or downgraded.** |
| Proposed disposition | Retain the gap as a production-readiness blocker; permit isolated-development milestone completion and consideration of merging development code only after explicit project-owner approval. |
| Identified project risk owner | **@hassan-anari**, owner of `hassan-anari/Wallet-MPC`; risk-owner acknowledgement and limited-acceptance approval are pending. |
| Reviewed implementation SHA | `3fdb6fa2b75a4de436f7435582bebc957f733f8f` |
| Approved wallet code-cell hash | `20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f` |
| Written instruction | The project conversation message dated 2026-10-10, titled “Phase 6F-C — Limited Development Acceptance Disposition”; its operative text is preserved below. |
| Project-owner written approval | **PENDING.** No owner approval, reviewer identity, review URL, signature or approval date has been inferred or invented. |
| PR status | Keep PR #33 Draft and unmerged pending the project owner's explicit written approval of this limited acceptance. |

The risk owner above is identified from repository ownership. The owner must
acknowledge that responsibility when approving; this record does not impersonate
the owner or claim they have already accepted the risk.

## Written project instruction

The requester supplied the following instruction in the project conversation:

> The external audit-report correspondence gap remains OPEN and is not considered resolved.
>
> For the purpose of isolated-development milestone completion only, we may disposition this gap as a documented production-readiness blocker rather than an indefinite blocker to merging development code.
>
> Keep PR #33 unmerged until the project owner approves this limited acceptance.

This is authority to prepare and preserve the limited disposition. The final
sentence retains a separate project-owner approval condition. The preparatory
instruction is not recorded as that final approval.

## Strict acceptance boundary

The disposition applies only to the implementation SHA and wallet code-cell hash
listed above, within the isolated validator development environment. A
documentation-only follow-up does not expand that implementation scope.

- No mainnet, public testnet funds, production deployment or customer assets.
- No representation that this exact wallet artifact passed an independent
  external audit. Standard code identity, source recompilation, SDK comparison,
  genuine MPC/TVM execution and isolated-network acceptance remain separate
  evidence categories; see [PHASE6F-C.md](../../PHASE6F-C.md) and the public
  captures in this directory.
- **Never reuse a TON root keyset across distinct genesis instances sharing the
  same global ID.** Establish each genesis independently and use a fresh TON
  root keyset. Client genesis checks do not change V5R1's intrinsic replay domain.
- Preserve the disabled-by-default TON feature flag, trusted isolated-network
  policy, immutable operation identity, sequence ownership and fail-closed
  treatment of uncertain execution. This documentation changes no code,
  configuration, deployment or financial-operation permission.
- No Phase 6F-D, 6G or other subsequent roadmap work is authorized.

## Production activation prerequisites remain open

Production activation requires both unresolved audit correspondence and targeted
independent review to be addressed explicitly. The project risk owner remains
responsible for tracking these prerequisites:

1. Establish an applicable external report-to-artifact chain: complete report,
   audited/final-fixed source commits, included-file checksums, compiler/build
   configuration, intervening changes and finding-to-fix/retest correspondence.
   If no applicable upstream report is obtainable, commission an independent
   audit of the exact pinned wallet, included library and compiled artifact;
   record the result explicitly without treating the missing upstream
   correspondence as completed.
2. Obtain targeted independent security review of the TON wallet, FROST
   authorization boundary, proof verification, Jetton asynchronous settlement
   and accounting, including recovery and exactly-once financial effects.
3. Resolve applicable findings and obtain explicit written production security
   sign-off naming the implementation SHA, wallet code hash and approved
   operational/network policy. This limited acceptance supplies no such
   sign-off or production authorization.

Any implementation change requires applicable checks and the required final-SHA
cryptographic gate. The project explicitly exempted this documentation-only risk
disposition from repeating the cryptographic gate. Passing isolated-development
CI does not close any production prerequisite above.

## Written owner-approval procedure

The owner must provide an attributable written approval in the PR review record
or project decision record. It must name this disposition, the reviewed SHA and
wallet code hash, acknowledge ownership of the open risk, and accept every
limitation and production prerequisite above. Record its author, date and
permanent review/decision link here once it exists.

Suggested approval text, **unsigned and not an approval**:

> I, @hassan-anari, as project owner and risk owner, approve the Phase 6F-C
> limited isolated-development acceptance disposition for implementation SHA
> `3fdb6fa2b75a4de436f7435582bebc957f733f8f` and Wallet V5R1 code hash
> `20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f`.
> I acknowledge the external audit correspondence remains OPEN as a production
> blocker, accept the documented limitations, prohibit TON root-keyset reuse
> across distinct genesis instances sharing a global ID, and retain audit and
> targeted independent security review as prerequisites for production.

Until an actual owner approval is recorded, PR #33 remains unmerged. No approval
entry is prefilled, and no external audit requirement is marked completed.

## Existing implementation acceptance evidence

- [Fast CI on the reviewed implementation SHA](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38065663436): passed.
- [Complete cryptographic gate on that SHA](https://github.com/hassan-anari/Wallet-MPC/actions/runs/38065685406): all 13 jobs passed.
- [Separate public MPC/TVM and validator evidence](README.md): the evidence and
  its trust assumptions remain unchanged.

These runs cover the reviewed implementation SHA, not a claim that a later
documentation-only head reran the full gate. No infrastructure, genesis,
validator volume, signer material or acceptance result is recreated by this
disposition.
