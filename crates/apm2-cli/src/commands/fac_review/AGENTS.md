# fac_review

> VPS-oriented, FAC-first review orchestration with multi-model dispatch and CI-aware pipeline management.

## Overview

The `fac_review` module implements the `apm2 fac review *` command family, which orchestrates automated code reviews (security and quality) against GitHub pull requests. It is the most complex command sub-module in the CLI, comprising 33 internal sub-modules.

### Architecture

```
apm2 fac review run --pr <N> --type all
       |
       +-- orchestrator.rs   (main loop: spawn, monitor, restart, collect)
       |      |
       |      +-- dispatch.rs     (idempotent detached dispatch via systemd)
       |      +-- backend.rs      (model backend selection: Codex / Gemini / ClaudeCode)
       |      +-- model_pool.rs   (fallback model pool with priority)
       |      +-- liveness.rs     (stall detection via pulse files)
       |      +-- restart.rs      (CI-state-aware pipeline restart)
       |      +-- merge_conflicts.rs (merge conflict detection)
        |      +-- timeout_policy.rs (uniform bounded test timeout policy)
       |
       +-- state.rs          (ReviewStateFile persistence, pulse files, locking)
       +-- types.rs          (shared types, constants, utility functions)
       +-- events.rs         (NDJSON lifecycle telemetry)
       +-- barrier.rs        (GitHub helper primitives: auth/head/metadata rendering)
       +-- ci_status.rs      (CI check-suite status querying)
       +-- decision.rs       (legacy verdict set/show compatibility helpers)
       +-- detection.rs      (review detection from PR comments)
       +-- evidence.rs       (evidence artifact collection)
       +-- findings.rs       (review findings aggregation)
       +-- gates.rs          (pre-review gate checks: systemd, resources)
       +-- policy_loader.rs  (shared FAC policy loading + managed CARGO_HOME creation)
       +-- gate_attestation.rs (gate attestation recording)
       +-- gate_cache.rs     (gate result caching)
       +-- logs.rs           (review log retrieval by PR/selector)
       +-- pipeline.rs       (end-to-end pipeline: mirror checkout + gates + dispatch)
       +-- prepare.rs        (review input preparation)
       +-- projection.rs     (projection snapshot for GitHub surfaces + PR body gate-status sync)
       +-- projection_store.rs (local canonical projection cache under ~/.apm2/fac_projection)
       +-- github_projection.rs (dedicated GitHub projection writer/read-fallback boundary)
       +-- github_reads.rs   (read-only GitHub API helpers: default branch, PR data, permissions, head SHA)
       +-- push.rs           (branch push with commit signing)
       +-- target.rs         (review target resolution)
```

### Key Behaviors

- **Parallel orchestration**: Security and quality reviews run in parallel when `--type all`.
- **Multi-model fallback**: If a model stalls, the orchestrator cycles through a model pool (`model_pool.rs`).
- **Liveness monitoring**: Pulse files track reviewer health; stall threshold is 90 seconds.
- **Idempotent dispatch**: `DispatchIdempotencyKey` prevents duplicate reviews for the same SHA.
- **SHA freshness**: Reviews are invalidated if PR head moves during execution.
- **Rust-native bounded tests**: FAC constructs `systemd-run` bounded test execution in Rust.
  Timeout and memory containment remain fixed (`600s`, `48G` by default), while CPU
  quota and test/build parallelism are profile-driven (`throughput`, `balanced`,
  `conservative`) with host-aware defaults.
  Supports both user-mode (`--user`) and system-mode (`--system`) backends via
  `APM2_FAC_EXECUTION_BACKEND` env var (TCK-00529). On headless VPS without a user
  D-Bus session, auto-mode falls back to system-mode with a dedicated service user.
  Environment variables passed to the transient systemd unit are derived entirely
  from `FacPolicyV1` via `build_job_environment()` (TCK-00549). No ad-hoc
  allowlists are used. Defense-in-depth: `RUSTC_WRAPPER` and `SCCACHE_*` are
  unconditionally stripped both in `build_policy_setenv_pairs()` and via
  `env_remove_keys` on the spawned process (TCK-00548, INV-ENV-008).
- **NDJSON telemetry**: All lifecycle events are appended to `~/.apm2/review_events.ndjson`.
- **One-shot missing-verdict nudge**: On clean exit without a completion signal, orchestrator resumes the same session once (`SpawnMode::Resume`) with an explicit required `apm2 fac verdict set ...` command; crash/timeout paths still fall through to existing auto-verdict behavior.
- **CI-aware restart**: `apm2 fac restart` analyzes CI check-suite state before restarting.
- **Worktree-aware dispatch**: Detached review dispatch resolves and uses the worktree whose `HEAD` matches target SHA (used by restart and dispatch paths; the pipeline path uses mirror-based lane checkout instead, see TCK-00544).
- **Per-SHA finding comments**: `apm2 fac review comment` writes one finding per comment using an `apm2-finding:v1` marker and `apm2.finding.v1` metadata block.
- **PR body gate status sync**: `apm2 fac push` writes a marker-bounded gate-status section in the PR body with expanded latest SHA and collapsed previous SHA snapshots.
- **Non-interactive GitHub CLI** (TCK-00597): All `gh` CLI calls use `apm2_core::fac::gh_command()` for token-based auth (via credential resolution chain) and lane-scoped `GH_CONFIG_DIR`, removing the dependency on `gh auth login` or `~/.config/gh` state.

## Key Types

### `ReviewRunType`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum ReviewRunType {
    All,
    Security,
    Quality,
}
```

Selects which review types to run.

### `ReviewKind`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewKind {
    Security,
    Quality,
}
```

Internal enum with associated methods for prompt paths, markers, and display strings.

**Contracts:**
- `prompt_path()` returns `documents/reviews/SECURITY_REVIEW_PROMPT.cac.json` or `documents/reviews/CODE_QUALITY_PROMPT.cac.json`.
- `marker()` returns the HTML comment marker used to identify review comments on GitHub.

### `ReviewBackend`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ReviewBackend {
    #[default]
    Codex,
    Gemini,
    ClaudeCode,
}
```

### `ReviewRunStatus`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ReviewRunStatus {
    #[default]
    Pending,
    Alive,
    Done,
    Failed,
    Crashed,
}
```

**Invariants:**
- [INV-STATUS-001] Terminal states are `Done`, `Failed`, and `Crashed` (`is_terminal()` returns `true`).

### `ReviewStateEntry`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewStateEntry {
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    pub log_file: PathBuf,
    pub prompt_file: Option<PathBuf>,
    pub last_message_file: Option<PathBuf>,
    pub review_type: String,
    pub pr_number: u32,
    pub owner_repo: String,
    pub head_sha: String,
    pub restart_count: u32,
    pub model: String,
    pub backend: ReviewBackend,
    pub temp_files: Vec<PathBuf>,
    pub run_id: String,
    pub sequence_number: u32,
    pub terminal_reason: Option<String>,
    pub model_id: Option<String>,
    pub backend_id: Option<String>,
    pub status: ReviewRunStatus,
}
```

Per-reviewer state persisted in `~/.apm2/review_state.json`.

### `ReviewStateFile`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReviewStateFile {
    pub reviewers: BTreeMap<String, ReviewStateEntry>,
}
```

### `ReviewRunState`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRunState {
    pub run_id: String,
    pub owner_repo: String,
    pub pr_number: u32,
    pub head_sha: String,
    pub review_type: String,
    pub reviewer_role: String,
    pub started_at: String,
    pub status: ReviewRunStatus,
    pub terminal_reason: Option<String>,
    pub model_id: Option<String>,
    pub backend_id: Option<String>,
    pub restart_count: u32,
    pub nudge_count: u32,
    pub sequence_number: u32,
    pub previous_run_id: Option<String>,
    pub previous_head_sha: Option<String>,
    pub pid: Option<u32>,
    pub proc_start_time: Option<u64>,
}
```

Deterministic run state persisted at `~/.apm2/reviews/<pr>/<type>/state.json`.

### `DispatchIdempotencyKey`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DispatchIdempotencyKey {
    pub owner_repo: String,
    pub pr_number: u32,
    pub review_type: String,
    pub head_sha: String,
}
```

**Invariants:**
- [INV-IDEM-001] `review_type` is normalized: `"code-quality"` becomes `"quality"`.
- [INV-IDEM-002] `owner_repo` is lowercased and trimmed.
- [INV-IDEM-003] `validate()` enforces 40-hex SHA and `security|quality` type.

### `PulseFile`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulseFile {
    pub head_sha: String,
    pub run_id: Option<String>,
    pub written_at: DateTime<Utc>,
}
```

Written by reviewers to signal liveness; read by the orchestrator for stall detection.

### Summary Types

```rust
pub struct SingleReviewSummary { pub run_id: String, pub success: bool, pub verdict: String, /* ... */ }
pub struct ReviewRunSummary { pub pr_url: String, pub pr_number: u32, pub security: Option<SingleReviewSummary>, pub quality: Option<SingleReviewSummary>, /* ... */ }
pub struct DispatchSummary { pub pr_url: String, pub pr_number: u32, pub head_sha: String, pub dispatch_epoch: u64, pub results: Vec<DispatchReviewResult> }
pub struct BarrierSummary { pub repo: String, pub event_name: String, pub pr_number: u32, /* ... */ }
pub struct KickoffSummary { pub repo: String, pub pr_number: u32, pub terminal_state: String, /* ... */ }
pub struct ProjectionStatus { pub security: String, pub quality: String, pub terminal_failure: bool, /* ... */ }
```

### Re-exports

```rust
pub use lifecycle::VerdictValueArg;
pub use types::ReviewRunType;
```

### Constants (types.rs)

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_RESTART_ATTEMPTS` | 3 | Max review process restarts |
| `STALL_THRESHOLD` | 90s | Liveness stall detection threshold |
| `PULSE_POLL_INTERVAL` | 30s | Pulse file polling interval |
| `TERMINATE_TIMEOUT` | 5s | SIGTERM grace period before SIGKILL |
| `DISPATCH_PENDING_TTL` | 120s | Time-to-live for pending dispatch entries |
| `EVENT_ROTATE_BYTES` | 10 MiB | NDJSON event log rotation threshold |

## Public API

| Function | Description |
|----------|-------------|
| `run_review(repo, pr, type, sha, force, json)` | Run security/quality reviews synchronously |
| `run_dispatch(repo, pr, type, sha, force, json)` | Dispatch reviews as detached processes |
| `run_status(pr_number, type_filter, json)` | Show review run status (optionally one reviewer lane) |
| `run_findings(repo, pr, sha, refresh, json)` | Aggregate review findings with optional cache refresh |
| `run_comment(repo, pr, sha, severity, type, body, json)` | Compatibility shim to append a structured finding |
| `run_prepare(repo, pr, sha, json)` | Prepare review inputs |
| `run_verdict_set(repo, pr, sha, dim, verdict, reason, keep, json)` | Set review verdict |
| `run_verdict_show(repo, pr, sha, json)` | Show review verdicts |
| `run_project(pr, sha, since, after_seq, errors, fail_term, format_json, json)` | Best-effort projection for debug/log surfaces; non-critical by default |
| `run_tail(lines, follow)` | Tail review event log |
| `run_push(repo, remote, branch, ticket)` | Push review branch with commit signing |
| `run_restart(repo, pr, force, json)` | CI-aware pipeline restart |
| `run_pipeline(repo, pr_number, sha)` | End-to-end: dispatch + project |
| `run_logs(pr, repo, selector_type, selector, json)` | Retrieve review logs |
| `run_gates(force, quick, timeout, mem, pids, cpu, gate_profile, json)` | Run pre-review gate checks |

## Related Modules

- [`commands/`](../AGENTS.md) -- Parent command module
- [`fac_pr/`](../fac_pr/AGENTS.md) -- GitHub App credential setup (consumed by review dispatch)
- [`factory/`](../factory/AGENTS.md) -- Factory pipeline commands
- [`client/`](../../client/AGENTS.md) -- Daemon IPC clients

## References

- `~/.apm2/review_events.ndjson`: NDJSON lifecycle telemetry log
- `~/.apm2/review_state.json`: Legacy reviewer state file
- `~/.apm2/reviews/<pr>/<type>/state.json`: Per-run deterministic state
- `~/.apm2/review_pulses/`: Pulse files for liveness detection
- `~/.apm2/review_locks/`: File-based dispatch locks
- `documents/reviews/SECURITY_REVIEW_PROMPT.cac.json`: Security review prompt
- `documents/reviews/CODE_QUALITY_PROMPT.cac.json`: Code quality review prompt

## Ticket Notes

- TCK-00523: Attestation fail-closed fixes.
  - Added `.cargo/config.toml` to gate input digest paths for cargo-based gates.
  - Added `rustfmt --version` to environment digest inputs.
  - Optionally captured `sccache --version` (with fallback when unavailable).
  - Extended command env allowlist with `CARGO_HOME`, `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS`, `NEXTEST_TEST_THREADS`, `RUSTC_WRAPPER`, and `SCCACHE_*`.
- TCK-00518: Gate execution is always local (direct mode). The broker/worker queue mode was removed.
  - `apm2 fac gates` runs all evidence gates locally with bounded test execution via `systemd-run`.
  - `--force` flag wired: bypasses clean-tree requirement (re-run against committed SHA with unrelated modifications).
- TCK-00605: Review findings from review round 1.
  - `maybe_auto_merge_if_ready()` now runs on a background thread (fire-and-forget) so git merge operations do not block the `verdict set` response path. Reviewer agents are no longer at risk of hitting internal timeouts due to slow git operations during auto-merge.
  - `load_findings_bundle()` implements one-time HMAC migration for pre-existing findings bundles: bundles created before HMAC integrity was introduced are migrated on first load (HMAC computed and persisted) rather than rejected. This preserves auto-verdict derivation and `verdict show` for active PRs.
  - `fetch_pr_body_for_projection()` no longer makes a redundant GitHub API call when the first call returns empty and the local snapshot is also empty.
  - Restored `review_artifact_lint` in `post_test_script_gates` in both `run_evidence_gates()` and `run_evidence_gates_with_status()` — the gate was accidentally dropped during bounded-runner refactoring.
  - `run_doctor()` `json_output` parameter is now explicit (no underscore prefix) with documentation that doctor `--pr` intentionally always emits JSON as a machine-readable diagnostic surface.
- TCK-00526: FAC-managed `CARGO_HOME` + env clearing policy enforcement.
  - `policy_loader.rs` (NEW): Shared module extracted from duplicate implementations in `evidence.rs` and `gates.rs`. Provides `load_or_create_fac_policy()` with bounded I/O (`O_NOFOLLOW` + `Read::take` at `MAX_POLICY_SIZE + 1` bytes, no TOCTOU `exists()` check) and `ensure_managed_cargo_home()` with mode `0o700` in operator mode or `0o770` in system-mode, plus permission verification for existing directories (ownership + mode check, CTR-2611). Both `evidence.rs` and `gates.rs` now delegate to this shared module.
  - `gates.rs`: `compute_nextest_test_environment()` loads `FacPolicyV1` and calls `build_job_environment()` to produce a policy-filtered environment. Then calls `ensure_lane_env_dirs()` and `apply_lane_env_overrides()` to set per-lane `HOME`/`TMPDIR`/`XDG_CACHE_HOME`/`XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_STATE_HOME`/`XDG_RUNTIME_DIR` paths under `$APM2_HOME/private/fac/lanes/lane-00` (TCK-00575). Throughput-profile env vars (`NEXTEST_TEST_THREADS`, `CARGO_BUILD_JOBS`) are overlaid after per-lane env isolation. Policy loading delegates to `policy_loader::load_or_create_fac_policy()`.
  - `evidence.rs`: `build_pipeline_test_command()` loads policy and builds policy-filtered environment for bounded pipeline test execution. Policy loading delegates to `policy_loader::load_or_create_fac_policy()`. `build_gate_policy_env()` added to construct policy-filtered env for non-test gates. `run_evidence_gates()` and `run_evidence_gates_with_status()` now pass the policy-filtered environment to ALL gates (fmt, clippy, doc, script gates, workspace integrity), not just the test gate. `run_gate_command_with_heartbeat()` now calls `env_clear()` before applying `extra_env` to enforce default-deny. `WRAPPER_STRIP_KEYS` and `WRAPPER_STRIP_PREFIXES` constants define `RUSTC_WRAPPER` and `SCCACHE_*` keys that are stripped from ALL gate phases (not just bounded test) via `env_remove_keys` on `Command`. `compute_gate_env_remove_keys()` computes the full removal set from both the ambient process env AND the policy-filtered environment (so policy-introduced SCCACHE_* variables are also discovered).
  - `bounded_test_runner.rs`: TCK-00549 replaced ad-hoc `SYSTEMD_SETENV_ALLOWLIST_EXACT`/`SYSTEMD_SETENV_ALLOWLIST_PREFIXES` with policy-driven environment. The bounded executor now accepts a pre-computed `FacPolicyV1` environment and forwards it via `--setenv` args. No ad-hoc allowlists remain; the single source of truth for env filtering is `build_job_environment()`.
- TCK-00575: Per-lane HOME/TMPDIR/XDG env isolation + symlink safety + concurrency.
  - `gates.rs`: `compute_nextest_test_environment()` calls `ensure_lane_env_dirs()` + `apply_lane_env_overrides()` for per-lane env isolation. `run_gates_inner()` acquires an exclusive lane lock on `lane-00` via `LaneManager::acquire_lock()` before any lane operations, preventing concurrent `apm2 fac gates` collisions. Also checks lane-00 for CORRUPT state before execution, refusing to run in a dirty environment (directs user to `apm2 fac lane reset lane-00`).
  - `evidence.rs`: `build_pipeline_test_command()` and `build_gate_policy_env()` accept a `lane_dir` parameter from the actually-locked lane (returned by `allocate_lane_job_logs_dir` / `allocate_evidence_lane_context`) and call `ensure_lane_env_dirs()` + `apply_lane_env_overrides()` using that lane directory, maintaining lock/env coupling. `EvidenceLaneContext` contains `logs_dir`, `lane_dir`, and `_lane_guard` so callers use the correct lane for env overrides. Every FAC gate phase (fmt, clippy, doc, test, script) runs with deterministic lane-local `HOME`/`TMPDIR`/`XDG_CACHE_HOME`/`XDG_CONFIG_HOME`/`XDG_DATA_HOME`/`XDG_STATE_HOME`/`XDG_RUNTIME_DIR` values scoped to the locked lane.
  - `policy.rs`: `ensure_lane_env_dirs()` uses atomic creation (mkdir + handle `AlreadyExists`) instead of `exists()` check, eliminating TOCTOU. `verify_dir_permissions()` is the shared public helper for directory permission verification (symlink rejection, ownership check, mode 0o700 in operator mode/0o770 in system-mode), used by both `verify_lane_env_dir_permissions()` and `verify_cargo_home_permissions()`. UID comparison uses `subtle::ConstantTimeEq`.
  - `policy_loader.rs`: `ensure_managed_cargo_home()` uses atomic creation (mkdir + handle `AlreadyExists`) instead of `exists()` check. `verify_cargo_home_permissions()` delegates to the shared `verify_dir_permissions()` helper in `apm2-core`.
- TCK-00544: Pipeline evidence execution via mirror-based lane checkout (eliminate SHA drift + dirty-attests-clean hazard).
  - `pipeline.rs`: `run_pipeline_inner()` no longer calls `resolve_worktree_for_sha()` to find a caller worktree. Instead, it calls `setup_mirror_lane_workspace()` which: (1) ensures a bare mirror via `RepoMirrorManager::ensure_mirror()` using the GitHub URL derived from the `owner/name` repo slug, (2) acquires an exclusive lane lock via `LaneManager`, (3) checks out the exact target SHA from the mirror to a lane workspace via `RepoMirrorManager::checkout_to_lane()`. The lane workspace is clean by construction (freshly cloned from mirror at exact SHA), eliminating both SHA drift (HEAD cannot move) and dirty-attests-clean (no caller workspace content leaks into the lane). Evidence gates run inside the lane workspace using `run_evidence_gates_with_status_with_lane_context()` instead of `run_evidence_gates_with_status()`, accepting a pre-allocated `EvidenceLaneContext`. JSONL telemetry events added for mirror/checkout lifecycle stages (`mirror_ensure_started`, `mirror_ensure_completed`, `mirror_checkout_started`, `mirror_checkout_completed`).
  - `gate_attestation.rs` (fix round 1): `ATTESTATION_SCHEMA` and `ATTESTATION_DOMAIN` version-bumped from v1 to v2, invalidating all pre-existing cache entries created under old semantics. `input_digest()` now always uses `file_sha256` (actual file content) for existing tracked files instead of preferring `HEAD:{path}` git blob references. This closes the dirty-state cache poisoning vector where a PASS cache entry seeded from dirty workspace content (where HEAD:path returned committed content hash, not actual file content) could hash-collide with a clean lane workspace run for the same SHA. Regression tests added in both `gate_attestation.rs` and `gate_cache.rs` proving: (1) schema is v2, (2) v1 and v2 attestation digests differ, (3) dirty-seeded cache entries are rejected by `check_reuse`.
- TCK-00607: Doctor activity metrics + one-shot reviewer nudge + timeout consistency.
  - `apm2 fac doctor --pr <N>` now surfaces per-agent `tool_call_count`, `log_line_count`, and `nudge_count` keyed by `run_id` when available.
  - Event scanning for doctor is explicitly bounded (`DOCTOR_EVENT_SCAN_MAX_LINES`, `DOCTOR_EVENT_SCAN_MAX_LINE_BYTES`) and scans both current and rotated review event logs.
  - Log counting is bounded (`DOCTOR_LOG_SCAN_MAX_BYTES`, `DOCTOR_LOG_SCAN_MAX_LINES`) to avoid unbounded memory/CPU growth on large logs.
  - `ReviewRunState` persists `nudge_count`; orchestrator emits `nudge_resume` and allows at most one nudge per run (`MAX_MISSING_VERDICT_NUDGES = 1`), disabled via `APM2_FAC_DISABLE_NUDGE`.
- TCK-00573: Sandbox hardening in gate attestation + GateReceipt.
  - `gate_attestation.rs`: `GateResourcePolicy` gains `sandbox_hardening: Option<String>` field, included in attestation digest computation. `from_cli()` accepts `sandbox_hardening: Option<&str>` parameter.
  - `gates.rs` and `evidence.rs`: Updated `GateResourcePolicy::from_cli()` call sites to derive `sandbox_hardening_hash` from the effective policy-driven `SandboxHardeningProfile` (via `policy.sandbox_hardening.content_hash_hex()`), not `SandboxHardeningProfile::default()`. In `evidence.rs`, the hash is carried through `PipelineTestCommand.sandbox_hardening_hash` so attestation binds to the same profile used for execution. Regression tests in `gate_attestation.rs` prove that mutating `sandbox_hardening` (e.g., `private_tmp=false`) changes the resource digest and attestation digest, denying cache reuse across profile drift.
