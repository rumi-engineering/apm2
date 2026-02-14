# Codex Task: Grand Projection Decoupling in FAC Review

## Objective

Decouple all GitHub projection logic (auth, comments, publishing, reviewer
identity, CI status, verdict rendering) from the core FAC review modules. The
core FAC is the local truth plane — lifecycle state machine, dispatch, evidence
gates, local state, process management. Everything that shells out to `gh`,
resolves GitHub user identity, renders markdown for GitHub comments, or caches
GitHub API responses is projection and must be cleanly separated.

## Repository

`crates/apm2-cli/src/commands/fac_review/`

## Current Architecture Problem

Projection concerns (GitHub I/O) are threaded through ~10 modules that should
be pure local-truth-plane logic. The `projection.rs` file alone is ~1785 lines
mixing local SHA resolution with GitHub verdict comment management. Multiple
modules independently shell out to `gh` CLI for auth checks, comment posting,
and API queries.

## Target Architecture

### Core FAC modules (NO `gh` calls, NO GitHub types, NO network I/O)

These modules must have zero dependency on `gh` CLI, `github_projection`, or
any GitHub-specific types. They operate entirely on local files, local git
state, and local process management.

| Module | Role |
|--------|------|
| `lifecycle.rs` | State machine, reducer, `apply_event`, `run_done`, `run_verdict_set`, `run_recover` |
| `dispatch.rs` | Agent process spawning, termination, worktree discovery, pending dispatch |
| `orchestrator.rs` | Review agent monitoring loop |
| `state.rs` | Local review run state persistence, file locking, receipts |
| `types.rs` | Shared constants, enums, data structures |
| `events.rs` | Local event log append/read |
| `evidence.rs` | Evidence gate runner |
| `gates.rs` | Gate orchestration |
| `gate_attestation.rs` | Gate attestation computation |
| `gate_cache.rs` | Gate result caching |
| `backend.rs` | LLM backend selection and spawn command building |
| `model_pool.rs` | Model selection, normalization, fallback |
| `detection.rs` | Log pattern detection (rate limits, permission denied) |
| `liveness.rs` | Log-based liveness scanning |
| `pipeline.rs` | Sequential pipeline runner |
| `restart.rs` | Restart strategy determination and execution |
| `timeout_policy.rs` | Timeout configuration |
| `projection_store.rs` | Local projection cache I/O (read/write local JSON files under `~/.apm2/`) |
| `target.rs` | Local git context: branch, remote, HEAD SHA |
| `merge_conflicts.rs` | Local git merge-conflict checking |
| `findings.rs` | Local finding accumulation, selector parsing/rendering |
| `logs.rs` | Local log management with own lifecycle (see dedicated section below) |

### Projection modules (ALL GitHub I/O lives here)

| Module | Role |
|--------|------|
| `github_projection.rs` | Low-level `gh api` wrapper: create/update/fetch comments, PR body, PR create/update, auto-merge. This is the sole `gh` call site for mutations. |
| `github_auth.rs` | **NEW** — Auth boundary: `ensure_gh_cli_ready()`, `resolve_authenticated_gh_login()`, `resolve_local_reviewer_identity()`. Extracted from `barrier.rs` and `projection.rs`. |
| `github_reads.rs` | **NEW** — Read-only GitHub API queries: `fetch_pr_data()`, `fetch_pr_head_sha()` (remote), `fetch_default_branch()`, `resolve_actor_permission()`, `fetch_issue_comment()`. Extracted from `barrier.rs` and `logs.rs`. |
| `verdict_projection.rs` | **NEW** — Verdict comment rendering/parsing/caching: `DecisionComment`, `DecisionEntry`, `IssueComment` types, `parse_decision_comments_for_author()`, `render_decision_comment_body()`, `persist_verdict_projection()`, `run_verdict_show()`, `resolve_termination_authority_for_home()`, `resolve_completion_signal_from_projection_for_home()`, signature computation. All verdict-related projection logic currently in `projection.rs`. |
| `ci_status.rs` | CI status checking and status comment management (already self-contained, stays as projection) |
| `comment.rs` | Review comment posting (already self-contained, stays as projection) |
| `publish.rs` | Review body publishing (already self-contained, stays as projection) |
| `pr_body.rs` | PR body gate-status sync (already self-contained, stays as projection) |
| `push.rs` | Push flow — mixed module, see dedicated section below |
| `prepare.rs` | Review preparation — mixed module, see dedicated section below |
| `barrier.rs` | After extraction: local-only admission control that remains. If empty after extractions, delete. |

## Detailed Move Instructions

### 1. Create `github_auth.rs`

Extract from `projection.rs`:
- `ensure_gh_cli_ready()` (line ~76)
- `resolve_authenticated_gh_login()` (line ~101)
- `resolve_local_reviewer_identity()` (line ~95)

Extract from `barrier.rs`:
- `ensure_gh_cli_ready()` (line ~452) — NOTE: both `barrier.rs` and
  `projection.rs` have copies. Deduplicate into `github_auth.rs`.
- `resolve_authenticated_gh_login()` (line ~478) — same duplication.

Update all callers:
- `ci_status.rs`: `projection::resolve_authenticated_gh_login` → `github_auth::resolve_authenticated_gh_login`
- `comment.rs`: `projection::{ensure_gh_cli_ready, resolve_authenticated_gh_login}` → `github_auth::`
- `logs.rs`: `projection::{ensure_gh_cli_ready, resolve_authenticated_gh_login}` → `github_auth::`
- `publish.rs`: `projection::resolve_local_reviewer_identity` → `github_auth::resolve_local_reviewer_identity`
- `findings.rs`: `projection::resolve_local_reviewer_identity` → `github_auth::resolve_local_reviewer_identity`
- `projection.rs` internal callers → `super::github_auth::`

### 2. Create `github_reads.rs`

Extract from `barrier.rs`:
- `fetch_default_branch()` (line ~345)
- `fetch_pr_data()` (line ~365)
- `resolve_actor_permission()` (line ~380)
- `fetch_pr_head_sha()` (line ~403) — this is the REMOTE GitHub SHA fetch,
  distinct from `fetch_pr_head_sha_local()` which is local-only

Extract from `logs.rs`:
- `fetch_issue_comment()` (line ~243) — the sole `gh api` call in logs.rs

Update all callers:
- `barrier.rs` internal callers → `super::github_reads::`
- `logs.rs` internal callers → `super::github_reads::fetch_issue_comment`
- `prepare.rs`: `barrier::fetch_pr_head_sha` → `github_reads::fetch_pr_head_sha`

### 3. Create `verdict_projection.rs`

Extract from `projection.rs` (these are all in the `// ── Verdict projection + authority helpers` section, lines ~706-1024):
- All verdict-related types: `DecisionComment`, `DecisionEntry`, `IssueComment`, `IssueUser`, `ParsedDecisionComment`, `ProjectionIssueCommentsCache`, `ProjectionReviewerIdentity`, `DecisionShowReport`, `DimensionDecisionView`, `ProjectionCompletionSignal`, `PersistedVerdictProjection`
- All verdict-related constants: `DECISION_MARKER`, `DECISION_SCHEMA`, `PROJECTION_ISSUE_COMMENTS_SCHEMA`, `PROJECTION_REVIEWER_SCHEMA`, `SECURITY_DIMENSION`, `CODE_QUALITY_DIMENSION`, `ACTIVE_DIMENSIONS`
- All verdict-related functions: `run_verdict_show()`, `persist_verdict_projection()`, `resolve_head_sha()` (private), `normalize_decision_dimension()`, `normalize_decision_value()`, `fetch_issue_comments()`, `resolve_expected_author_login()`, `parse_decision_comments_for_author()`, `parse_decision_comment()`, `extract_fenced_yaml()`, `latest_decision_comment()`, `latest_for_sha()`, `build_show_report()`, `build_report_from_payload()`, `build_unknown_dimension_views()`, `aggregate_overall_decision()`, `signature_for_payload()`, `review_type_to_dimension()`, `dimension_to_state_review_type()`, `projection_pr_dir_for_home()`, `load_projection_reviewer_for_home()`, `load_projection_issue_comments_for_home()`, `resolve_termination_authority_for_home()`, `resolve_completion_signal_from_projection_for_home()`, `render_decision_comment_body()`, `create_decision_comment()`, `update_decision_comment()`, `cache_written_decision_comment()`, `emit_show_report()`
- The `DecisionShowReport::with_dimensions()` impl
- The test `resolve_completion_signal_reads_projection_cache`

This new module imports `github_projection` for comment create/update and
`github_auth` for reviewer identity. It does NOT import any core FAC modules
except `projection_store` (for local cache) and `types` (for shared types).

Update all callers:
- `lifecycle.rs`: `projection::persist_verdict_projection` → `verdict_projection::persist_verdict_projection`
- `lifecycle.rs`: `projection::run_verdict_show` → `verdict_projection::run_verdict_show`
- `orchestrator.rs`: `projection::resolve_completion_signal_from_projection_for_home` → `verdict_projection::resolve_completion_signal_from_projection_for_home`
- `mod.rs` (if `run_terminate_inner_for_home` references `projection::resolve_termination_authority_for_home`) → `verdict_projection::`

### 4. Extract `render_comment_with_generated_metadata` from `projection.rs`

This function and its helpers (`strip_existing_metadata_block`,
`build_generated_metadata_block`) render GitHub comment bodies with metadata
blocks. They belong in the projection layer.

Move to: `verdict_projection.rs` or `publish.rs` (since `publish.rs` is the
primary caller and is already a projection module).

Update callers:
- `publish.rs`: `projection::render_comment_with_generated_metadata` → local or `verdict_projection::`

### 5. Clean up `projection.rs`

After extractions 1-4, `projection.rs` should contain ONLY:
- `fetch_pr_head_sha_local()` — local SHA resolution (git rev-parse + projection store)
- Projection state predicates (`projection_state_done`, `projection_state_failed`, etc.)
- `run_project_inner()` — local telemetry-based state rendering
- `render_state_code_from_run_state()` and helpers
- All the existing local projection engine logic

This module should have ZERO `Command::new("gh")` calls and ZERO imports of
`github_projection`. Rename consideration: this module is now purely "local
projection engine" — consider renaming to `projection_engine.rs` to
distinguish from the GitHub projection modules, but this is optional.

### 6. Clean up `logs.rs`

After extracting `fetch_issue_comment()` to `github_reads.rs`:
- `logs.rs` should have ZERO `Command::new("gh")` calls
- Remove `use super::projection::{ensure_gh_cli_ready, resolve_authenticated_gh_login}`
- The selector-zoom logic that needs the GitHub comment body should call
  `github_reads::fetch_issue_comment()` instead of an internal function
- Logs are purely local and manage their own lifecycle: log file discovery,
  log rotation, log content reading, log artifact management

### 7. Clean up `barrier.rs`

After extracting auth helpers to `github_auth.rs` and read helpers to
`github_reads.rs`, audit what remains in `barrier.rs`. The remaining functions
should be local-only admission control logic. If the module is empty or nearly
empty after extraction, delete it and move any remnants to the appropriate
core module.

Current `barrier.rs` functions to audit:
- `resolve_fac_event_context()` — may stay if it's local admission logic
- `fetch_pr_head_sha_local()` — already moved to `projection.rs` in current diff
- Any remaining functions that don't call `gh`

### 8. Handle mixed modules: `push.rs` and `prepare.rs`

**`push.rs`** mixes core FAC logic (running gates, dispatching reviews) with
GitHub projection (creating PRs, enabling auto-merge, syncing PR body). For
now, `push.rs` stays as-is since its projection calls go through
`github_projection::` — it's a coordinator that orchestrates both core and
projection. No immediate action needed, but document that push.rs is the
bridge between core and projection.

**`prepare.rs`** fetches PR data from GitHub (`barrier::fetch_pr_head_sha`).
After extraction, it should import `github_reads::fetch_pr_head_sha` instead
of `barrier::`. Otherwise it stays as-is.

## Constraints

1. **Zero regressions.** Every existing `cargo test -p apm2-cli` test must
   pass. Every existing public API (`pub fn` signatures in `mod.rs`) must
   remain unchanged.

2. **No logic changes.** This is a pure structural refactor. Function bodies
   must be moved verbatim. No behavior changes, no bug fixes, no
   optimizations. If you find a bug, leave it and add a `// TODO:` comment.

3. **Preserve `pub(super)` visibility.** Functions that were `pub` or
   `pub(super)` must remain so. Functions that were private should remain
   private in their new module.

4. **Deduplicate auth helpers.** Both `barrier.rs` and `projection.rs`
   currently have copies of `ensure_gh_cli_ready` and
   `resolve_authenticated_gh_login`. The canonical version goes in
   `github_auth.rs`. Delete all copies.

5. **`mod.rs` declarations.** Add `mod github_auth;`, `mod github_reads;`,
   `mod verdict_projection;` to `mod.rs`. Do not reorder existing module
   declarations.

6. **No new dependencies.** Do not add crates. All moved code uses the same
   imports it had before, just from a different module path.

7. **Format and lint.** `cargo fmt --check` and `cargo clippy --workspace`
   must be clean after the refactor.

8. **Do NOT touch these core modules** (they are already clean):
   `lifecycle.rs`, `dispatch.rs`, `state.rs`, `types.rs`, `events.rs`,
   `evidence.rs`, `gates.rs`, `gate_attestation.rs`, `gate_cache.rs`,
   `timeout_policy.rs`, `orchestrator.rs`, `restart.rs`, `liveness.rs`,
   `detection.rs`, `pipeline.rs`, `model_pool.rs`, `backend.rs`,
   `merge_conflicts.rs`, `projection_store.rs`, `target.rs` — EXCEPT to
   update their `use super::` import paths when a function they call has
   moved to a new module.

## Verification Checklist

```bash
cargo fmt --check
cargo clippy --workspace
cargo test -p apm2-cli
# Confirm no `Command::new("gh")` in core modules:
rg 'Command::new\("gh"\)' crates/apm2-cli/src/commands/fac_review/{lifecycle,dispatch,state,types,events,evidence,gates,gate_attestation,gate_cache,timeout_policy,orchestrator,restart,liveness,detection,pipeline,model_pool,backend,merge_conflicts,projection_store,target,findings,logs,projection}.rs
# Should return zero matches
```

## File-Level Dependency After Refactor

```
Core FAC (no gh):
  types.rs ← events.rs ← state.rs ← lifecycle.rs
                                    ← dispatch.rs ← orchestrator.rs
  evidence.rs ← gates.rs ← push.rs (bridge)
  findings.rs (local accumulation only)
  logs.rs (local lifecycle only)
  projection_store.rs (local cache I/O)
  target.rs (local git context)
  projection.rs (local projection engine: SHA resolution, state rendering)

Projection (gh boundary):
  github_auth.rs (auth primitives)
  github_reads.rs (read-only gh API)
  github_projection.rs (mutating gh API)
  verdict_projection.rs (verdict comment logic)
  ci_status.rs, comment.rs, publish.rs, pr_body.rs (self-contained projection modules)
  push.rs (bridge: core + projection)
  prepare.rs (bridge: core + projection)
```
