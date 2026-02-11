# Implementation Task: TCK-00468 — RFC-0028 REQ-0008 Projection Isolation and Direct-GitHub Authority Elimination

## REQUIRED READING (read these files BEFORE writing any code)

Read these files in order:
1. `documents/theory/glossary/glossary.json` — APM2 terminology
2. `documents/rfcs/RFC-0028/00_meta.yaml` — RFC meta
3. `documents/rfcs/RFC-0028/HOLONIC_EXTERNAL_IO_SECURITY.md` — Full RFC draft (especially Sections on projection isolation)
4. `documents/rfcs/RFC-0028/requirements/REQ-0008.yaml` — This ticket's requirement
5. `documents/work/tickets/TCK-00468.yaml` — Ticket details
6. `documents/work/tickets/TCK-00462.yaml` — Predecessor ticket (already merged, provides lifecycle receipt typing baseline)
7. `documents/reviews/CI_EXPECTATIONS.md` — CI contract
8. `documents/security/AGENTS.cac.json` — Security posture
9. `documents/security/THREAT_MODEL.cac.json` — Threat model
10. `crates/apm2-daemon/AGENTS.md` — Daemon architecture
11. `crates/apm2-core/AGENTS.md` — Core crate architecture

## Ticket Summary

**TCK-00468**: Enforce production `agent_runtime` exclusion of direct GitHub capability classes (`github_api`, `gh_cli`, `forge_org_admin`, `forge_repo_admin`). Require projection_worker-only write paths with receipt linkage from authoritative internal state. Implement GH-DIRECT stage policy behavior (Stage 0/1/2) with fail-closed default to Stage 2 on ambiguity. Emit structured deny defects for direct runtime GitHub actuation attempts.

## Requirement (REQ-0008)

Production FAC agent runtimes MUST NOT carry direct actuation authority for external projection sinks. External projection, when required, MUST execute only through an isolated projection worker using receipt-bound projection intents derived from internal authoritative state.

### Acceptance Criteria
- Production RoleSpec capability surfaces exclude github_api/gh_cli/admin classes.
- All admissible GitHub projections are receipt-linked to projection_worker execution.
- Any direct gh/GitHub API attempt from agent_runtime is denied with structured security defects.
- Stage-state ambiguity fails closed to hard deny behavior.

## Implementation Plan

1. Add runtime capability-surface checks to projection isolation gate path.
2. Bind projection writes to projection_worker receipt chains.
3. Implement stage-state evaluator and fail-closed default behavior.
4. Add negative tests for direct GitHub API/CLI attempts from agent_runtime context.

## Key RFC-0028 Invariants

- `INV-SIO28-06`: projection surface never becomes authority input
- `pcac_projection_isolation_valid` predicate must be satisfied
- Denied capability classes for agent_runtime: `github_api`, `gh_cli`, `forge_org_admin`, `forge_repo_admin`
- Stage policy:
  - Stage 0: non-production compatibility only
  - Stage 1: production deny-by-default, explicit break-glass only
  - Stage 2: hard deny for all production direct GitHub actuation
  - Unknown/stale/missing/ambiguous → fail closed to Stage 2
- All projection writes must be projection_worker-mediated with receipt linkage
- Structured deny defects emitted for all direct actuation attempts

## Existing Code Context

Look at the already-merged TCK-00462 work for the baseline:
- `git log --oneline | grep TCK-00462` to find relevant commits
- Also look at TCK-00406 (merged PR #569) for authoritative runtime wiring patterns

Key crates and files to work in:
- `crates/apm2-core/src/fac/role_spec.rs` — RoleSpec capability surface definitions
- `crates/apm2-core/src/fac/builtin_roles.rs` — Builtin role definitions (7 roles)
- `crates/apm2-daemon/src/projection/` — Projection worker, GitHub sync
- `crates/apm2-daemon/src/protocol/dispatch.rs` — Dispatch path enforcement
- `crates/apm2-core/src/fac/context_firewall.rs` — Firewall enforcement

## Common Review Findings — MUST AVOID

1. **Missing Production Wiring**: Every `with_X()` builder method MUST be called in ALL production constructor paths in `state.rs` and `main.rs`.
2. **Fail-Open Authorization**: All ambiguous/error states MUST resolve to DENY/FAILURE (fail-closed). Never default to pass.
3. **Unbounded Resources**: Every collection MUST have a hard `MAX_*` constant with deterministic eviction.
4. **Missing Integration Tests**: Tests MUST exercise real production wiring paths, not manual dependency injection.
5. **Serde Default on Security Fields**: Never use `#[serde(default)]` on security-critical enum fields where default is least restrictive.
6. **Missing Caller Authorization**: Every IPC handler MUST bind caller identity to resource authorization.
7. **Proto Workflow**: NEVER edit `apm2.daemon.v1.rs` directly. Edit `.proto`, run `cargo build -p apm2-daemon`, commit both.

## Daemon Implementation Patterns — MUST FOLLOW

- DispatcherState is the production composition root. Every `with_X()` method MUST be called in the DispatcherState builder chain.
- SqliteLeaseValidator MUST override every method production code depends on.
- SQL queries: Always filter by event_type first, use indexed fields, `ORDER BY rowid DESC LIMIT 1`.
- Caller authorization: Every handler must bind caller identity from `ctx.peer_credentials()`.
- Tests: Must use DispatcherState composition, not manual injection. Side-effect assertions mandatory.

## Branch Hygiene — FIRST STEPS

Before making ANY code changes:
```bash
git fetch origin main
git rebase origin/main
git diff --name-only --diff-filter=U  # Must be empty (no conflicts)
```
If conflicts exist, resolve them ALL before writing code.

## MANDATORY Pre-Commit Steps (in this exact order)

You MUST run ALL of these and fix any issues BEFORE committing:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do not push code that fails any of these.

## Push Workflow

After all pre-commit steps pass:
```bash
git add -A
git commit -m "feat(TCK-00468): projection isolation and direct-GitHub authority elimination"
apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```

This pushes, creates/updates the PR, enables auto-merge, and triggers reviews automatically.

## Evidence Required

Your implementation MUST produce:
- Production RoleSpec capability surface exclusion of GitHub classes (test evidence)
- Projection_worker receipt linkage for all GitHub projections (integration test)
- Direct gh/GitHub API denial from agent_runtime with structured defects (negative tests)
- Stage-state evaluator correctness including ambiguity → Stage 2 (unit tests)
