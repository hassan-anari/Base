# Living source-of-truth governance

The objective is that a new engineer, coding agent or a fresh chat can reconstruct product intent, current development state and the next authorized task from the repository without relying on previous conversation memory.

## Document roles and precedence

1. Verified merged code, migrations, current CI artifacts and independently reviewed acceptance are authoritative for **what is implemented**.
2. Explicit latest owner-approved decisions recorded in DECISIONS / PRODUCT_VISION govern **what should be built**. No document grants permission to weaken technical/security constraints.
3. ROADMAP sequences accepted work; PRODUCT_REQUIREMENTS defines delivery acceptance; ARCHITECTURE and SECURITY_MODEL define required safety boundaries; API_CONTRACTS gives **target** interface semantics.
4. PROJECT_STATUS is a dated factual snapshot and must never claim a future change was merged.
5. DEVELOPMENT_HISTORY is append-only milestone chronology, linked to merged PRs, exact SHAs and CI evidence.
6. Historical phase docs (PHASE*.md, LEDGER, SELF_HOSTED_MPC, STABILIZATION etc.) preserve period-specific details. When older notes conflict with merged implementation, add explicit supersession notes or link current docs rather than erasing audit history.
7. AGENTS.md controls the workflow/read-first checklist; it cannot override user approval or technical safeguards.

## Status vocabulary

- **PROPOSED:** idea, not agreed as mandatory release requirement.
- **APPROVED TARGET:** binding intended capability, not implemented yet.
- **PLANNED:** assigned to future work package with acceptance.
- **IN PROGRESS:** active branch/PR, not merged.
- **IMPLEMENTED (DEV):** merged implementation; its intended function exists in code.
- **VERIFIED (ISOLATED):** measured tests on local/test fixtures and accepted scope; not proof of live operational readiness.
- **PRODUCTION APPROVED:** independently accepted deployment/network/operator gates and explicitly activated.
- **BLOCKED / DEFERRED:** unclosed prerequisites or owner-authorized postponement; not completed or silently waived.
- **SUPERSEDED:** historical description replaced by later verified fact/decision.

A feature may have both IMPLEMENTED (DEV) and BLOCKED FOR PRODUCTION states. Never collapse them into a single green completion flag. P0/P1/P2 issue severity and feature-priority labels must be distinguished.

## Required updates on every substantive PR

- Implementation status in PROJECT_STATUS + relevant requirement acceptance row.
- Append DEVELOPMENT_HISTORY with exact merged PR or proposed PR reference and final-head CI links.
- Update ROADMAP if a package is completed, moved or its dependencies change (no silent new numbered phases).
- Amend DECISIONS for owner-approved product/security decisions, including deferrals.
- Update API_CONTRACTS and examples with tested schemas only when routes actually become available; annotate target examples as proposals.
- Include migrations/backfill, failure/replay cases, auth boundaries and residual P0/P1/P2 risk.
- After merge, reconcile docs with resulting *merge commit* (not just PR head); revalidate main SHA and links.

## Review controls

Documentation-only edits can use Fast CI/docs checks if no functional changes; do not waste 45-minute crypto gate where not necessary. Conversely, a docs-only PR cannot declare a security finding closed without independent evidence. Require link validation, consistent phase names, no secret/private material, no stale deployment statements and no ambiguity between current and target. Owners explicitly approve major scope changes and all production gates.

## New-chat recovery checklist

1. Read README and AGENTS in repository main.
2. Read PRODUCT_VISION, PROJECT_STATUS, ROADMAP, DECISIONS, SECURITY_MODEL, ARCHITECTURE, PRODUCT_REQUIREMENTS and API_CONTRACTS.
3. Fetch live main ref, last merged PRs, current phase branch and CI status; verify docs snapshot remains current.
4. Identify exactly one next authorized milestone and its out-of-scope work; check open audits and per-chain restrictions.
5. Keep the wider enterprise exchange/payment/treasury goal in mind; do not start TON Mainnet or other deferred features.
6. For every PR, provide durable evidence and update documents to make the next chat just as effective.
