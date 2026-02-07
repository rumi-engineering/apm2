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
   - Exact head SHA
   - Blocking category (`security` and/or `code-quality`)
   - Justification and remediation ticket
   - Expiration timestamp
3. PR body (or maintainer comment) references `WVR-XXXX`.

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
