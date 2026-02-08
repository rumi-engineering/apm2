# Review Gate Waiver Flow

## Purpose
This document defines the only acceptable override path when `review-gate` blocks a merge.

## Policy
- Overrides are waiver-only. No silent bypasses.
- Every waiver must be repo-committed and traceable to a ticket.
- Waivers are temporary and must include an expiry date.

## Required Artifacts
1. A waiver file in `documents/work/waivers/` named `WVR-XXXX.yaml`.
2. Waiver links to:
   - Blocking PR number
   - Waived commit SHA (40-hex)
   - Blocking category (`security` and/or `code-quality`)
   - Justification and remediation ticket
   - Expiration timestamp
3. PR body (or maintainer comment) references `WVR-XXXX`.

## Waived Commit SHA Semantics
`waiver.references.commit_sha` MUST be bound to the exact code state being risk-accepted.

Two acceptable patterns exist:
1. **Preferred (base-branch waiver)**: The waiver file exists on the PR base branch (e.g., `main`).
   - `commit_sha` MUST equal the PR head SHA being waived.
2. **PR-branch waiver (allowed, waiver-only head commit)**: The waiver file is added on the PR branch.
   - The waiver MUST be introduced in a final, waiver-only commit that changes only waiver artifacts under `documents/work/waivers/`.
   - `commit_sha` MUST equal the immediate parent of the waiver commit (the pre-waiver PR head).
   - If any non-waiver changes are pushed after the waiver commit, the waiver is invalid and must be reissued.

## Approval Requirements
1. Security-domain maintainer approval for security gate waivers.
2. Build/release maintainer approval for code-quality gate waivers.
3. Explicit acknowledgement that the merge is risk-accepted until waiver expiry.

## Operator Procedure
1. Confirm gate failure reason from CI `Review Gate` job output.
2. Create and commit `documents/work/waivers/WVR-XXXX.yaml`.
3. Add `WVR-XXXX` reference in the PR thread.
4. Re-run CI and capture evidence in the linked remediation ticket.
5. Remove or close waiver when remediation lands.
