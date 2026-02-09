# FAC + GitHub CI Handoff (TCK-00433 / RFC-0018)

## Purpose
This handoff captures the operating philosophy and current implementation state for the FAC-driven GitHub CI projection model.

Primary intent:
- Keep FAC as authority.
- Keep GitHub as projection surface.
- Keep public GitHub logs non-sensitive.
- Keep merge gating deterministic and fail-closed.

## High-Level Philosophy
From recent PRs, the system direction is:
- A single admission workflow (`Forge Admission Cycle`) with two jobs:
  - `Guardian Intelligence / Barrier` (fast trust gate).
  - `apm2 / Forge Admission Cycle` (self-hosted FAC kickoff + projection).
- The `apm2 fac` CLI is the operational control plane for review orchestration.
- `gh` is fallback or metadata tooling only where FAC does not yet expose equivalent functionality.

Operational principle:
- FAC lifecycle state, events, and retries happen on VPS.
- GitHub only receives minimal status projection (1 Hz health line + fail/success exit state).

## Security Boundary Model
Treat GitHub Actions stdout as a public egress boundary.

Security-critical boundary currently implemented in `.github/workflows/forge-admission-cycle.yml`:
- FAC step runs `apm2 fac kickoff --public-projection-only`.
- Stderr is redirected to private local log under `~/.apm2/private/fac/*.log` with strict permissions.
- Stdout is allowlisted by regex to a single health-line shape.
- Any non-health line on stdout fails closed and aborts the workflow.

Rationale:
- Avoid secret leakage into public CI logs.
- Prevent accidental model/tool output from crossing projection boundary.

## Current Workflow Topology
Workflow file: `.github/workflows/forge-admission-cycle.yml`

Triggers:
- `pull_request_target` on `main` for authoritative gate runs.
- `workflow_dispatch` with `pr_number` for controlled retrigger.

Jobs:
- `barrier` (GitHub-hosted):
  - Validates event shape and trust assumptions.
  - Enforces `author_association` allowlist.
  - For `workflow_dispatch`, validates trusted ref and actor repo permission.
- `forge-admission-cycle` (self-hosted):
  - Runs FAC kickoff.
  - Emits only public projection lines.
  - Fails terminally when FAC returns error (no intentional pending hang).

## FAC CLI Surfaces (Primary Ops Path)
Use these first:
- `apm2 fac review dispatch <PR_URL> --type all`
- `apm2 fac review status --pr <PR_NUMBER>`
- `apm2 fac review project --pr <PR_NUMBER>`
- `apm2 fac review tail --pr <PR_NUMBER>`
- `apm2 fac review retrigger --repo guardian-intelligence/apm2 --pr <PR_NUMBER>`

Use `gh` only where FAC is not yet complete:
- Full PR comment body retrieval.
- Certain PR metadata checks during debugging.

## Review Execution Semantics (Current)
- Security and quality reviewers are intended to run in parallel for `--type all`.
- Dispatch is start-or-join and should avoid duplicate reviewers for same PR/SHA/review type.
- Telemetry is event-first:
  - `~/.apm2/review_events.ndjson`
  - `~/.apm2/review_state.json`
  - `~/.apm2/review_pulses/pr<PR>_review_pulse_{security|quality}.json`

## Known Hotspots and Failure Classes
### 1) Projection and status mismatch
Symptoms:
- `sequence_done` event appears while one reviewer still runs or restarts.
- GitHub may show stale or misleading short-term projection.

Hotspot:
- State transitions and terminality checks in `crates/apm2-cli/src/commands/fac_review.rs`.

### 2) Provider/model compatibility drift
Symptoms:
- Gemini model errors (wrong model string).
- Codex usage/rate-limit bursts.

Hotspot:
- Model pool and backend command construction in `crates/apm2-cli/src/commands/fac_review.rs`.

### 3) Kill/probe noise and race behavior
Symptoms:
- `kill: (...) No such process` spam in projected logs.

Status:
- Kill probe output has been suppressed; verify no regression.

### 4) Public log contamination risk
Symptoms:
- Any extra stdout line beyond the 1 Hz health projection.

Hotspot:
- Workflow filtering block in `.github/workflows/forge-admission-cycle.yml`.
- Any new `println!` in FAC kickoff path.

## Temporary Merge Workaround (Until Stable Required Checks)
When gate plumbing is unstable and urgent fix must land:
1. Merge `main` into target PR branch.
2. Re-run FAC workflow from trusted context (`workflow_dispatch` with `pr_number`).
3. Confirm barrier pass and FAC terminal outcome in Actions.
4. If branch protection still references stale required contexts, update ruleset contexts first, then re-run.
5. Merge only after required context is green for current head SHA.

Note:
- Never disable trust controls to force merge.
- Prefer ruleset/context correction over bypass.

## Comprehensive Verification Plan (Not Just Unit Tests)
### Negative/security cases
- Unauthorized PR author (`CONTRIBUTOR`/`NONE`) must fail at `barrier`.
- `workflow_dispatch` from untrusted ref must fail at `barrier`.
- Any non-health stdout from FAC kickoff must fail workflow immediately.
- Verify no secret-bearing strings in GitHub logs for failed and successful runs.

### Functional FAC cases
- `apm2 fac review dispatch --type all` launches both reviewer types.
- `apm2 fac review project` emits 1 Hz projection lines only.
- `apm2 fac review retrigger` causes new GitHub workflow run (projection principle).
- Duplicate dispatch for same PR/SHA behaves idempotently (join, not duplicate spawn).

### Failure and recovery cases
- Reviewer crash produces terminal error signal in FAC telemetry.
- Non-recoverable terminal error fails GitHub workflow (no indefinite pending).
- Restart/fallback behavior is visible in NDJSON events.
- Liveness stall detection produces event and bounded recovery attempt.

### Observation surfaces to capture
- GitHub run logs (public projection only).
- `~/.apm2/review_events.ndjson` timeline.
- `~/.apm2/review_state.json` snapshots before/after transitions.
- `~/.apm2/private/fac/*.log` for private diagnostics.

## Guidance for Reviewer/Implementer RoleSpecs
Instruction priority:
- Use `apm2 fac` commands for lifecycle operations and retriggers.
- Do not use `xtask` review orchestration paths.
- Use `gh` only for remaining gaps (for now: full comment body retrieval).

## Robustness Wishlist (Next Iterations)
1. Strong terminal-state contract:
   - Prevent `sequence_done` while any active reviewer exists.
2. Single source of truth for projection:
   - Derive projection from state machine snapshot, not mixed event heuristics.
3. Explicit idempotency keys:
   - Persist lock key `(repo, pr, sha, review_type)` with lease expiry and owner metadata.
4. Public-output contract tests:
   - Add integration test that fails if kickoff emits non-health stdout.
5. Structured private diagnostics:
   - Add machine-readable failure bundle path in final error line (still non-sensitive).
6. Provider resilience:
   - Preflight model availability and provider quota hints before dispatch.
7. Context binding:
   - Attach projection run to immutable PR head SHA and reject drifted terminal claims.

## Next-Agent Prompt (Copy/Paste)
```text
You are continuing TCK-00433 (RFC-0018) FAC + GitHub CI stabilization.

Mission:
1) Preserve FAC as authority and GitHub as projection-only surface.
2) Preserve strict public log boundary (1 Hz health line only).
3) Ensure terminal fail-closed behavior (no indefinite pending).
4) Keep reviewer operations on `apm2 fac` commands, not xtask.

Required reading before edits:
- documents/reviews/FAC_GITHUB_CI_HANDOFF.md
- .github/workflows/forge-admission-cycle.yml
- crates/apm2-cli/src/commands/fac.rs
- crates/apm2-cli/src/commands/fac_review.rs
- documents/skills/ticket/SKILL.md
- documents/skills/orchestrator-monitor/SKILL.md
- documents/security/THREAT_MODEL.cac.json
- SECURITY.md

Constraints:
- Do not widen stdout output from FAC kickoff path.
- Treat GitHub logs as public egress boundary.
- Keep barrier trust checks fail-closed.
- Keep workflow minimal and deterministic.

Validation bar:
- Unit + scenario tests, including negative auth and output-boundary cases.
- End-to-end local FAC dispatch/status/project/retrigger verification.
- Confirm retrigger from `apm2 fac` creates corresponding GitHub workflow projection run.
- Confirm GitHub workflow fails on terminal FAC error and succeeds on healthy terminal outcome.

Deliverables:
- Code + tests + docs updates.
- Evidence summary with exact commands and key output snippets.
```
