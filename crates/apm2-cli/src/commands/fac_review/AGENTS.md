# fac_review

> VPS-oriented, FAC-first review orchestration with multi-model dispatch and CI-aware pipeline management.

## Overview

The `fac_review` module implements the `apm2 fac review *` command family, which orchestrates automated code reviews (security and quality) against GitHub pull requests. It is the most complex command sub-module in the CLI, comprising 33 internal sub-modules.

### Architecture

```
apm2 fac doctor --pr <N> --fix
       |
       +-- orchestrator.rs   (reviewer missing-verdict decision machine artifact)
       |      |
       |      +-- dispatch.rs     (idempotent detached dispatch via systemd)
       |      +-- backend.rs      (model backend selection: Codex / Gemini / ClaudeCode)
       |      +-- model_pool.rs   (fallback model pool with priority)
       |      +-- liveness.rs     (stall detection via pulse files)
       |      +-- repair_cycle.rs (CI-state-aware PR fix follow-up cycle)
       |      +-- merge_conflicts.rs (merge conflict detection)
        |      +-- timeout_policy.rs (uniform bounded test timeout policy)
       |
       +-- state.rs          (ReviewStateFile persistence, pulse files, locking)
       +-- types.rs          (shared types, constants, utility functions)
       +-- events.rs         (NDJSON lifecycle telemetry)
       +-- barrier.rs        (GitHub helper primitives: auth/head/metadata rendering)
       +-- ci_status.rs      (CI check-suite status querying)
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

- **Detached dispatch**: Security and quality reviewers are dispatched idempotently and tracked via lifecycle + dispatch markers.
- **Liveness monitoring**: Pulse files track reviewer health; stale/idle lanes surface through doctor diagnostics and repair recommendations.
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
- **CI-aware repair strategy**: Doctor repair planning analyzes CI/check-suite state before applying repair actions.
- **Worktree-aware dispatch**: Detached review dispatch resolves and uses the worktree whose `HEAD` matches target SHA (used by doctor-fix repair and dispatch paths; the pipeline path uses mirror-based lane checkout instead, see TCK-00544).
- **Per-SHA findings**: `apm2 fac review finding` appends one structured finding bound to PR+SHA+dimension.
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
| `run_doctor(repo, pr, fix, json, wait, timeout, exit_on)` | FAC doctor diagnostics and optional repair plan execution |
| `run_findings(repo, pr, sha, json)` | Aggregate review findings for the selected PR/SHA |
| `run_finding(repo, pr, sha, type, severity, summary, details, risk, impact, location, reviewer_id, model_id, backend_id, evidence_pointer, json)` | Append one structured finding |
| `run_prepare(repo, pr, sha, json)` | Prepare review inputs |
| `run_verdict_set(repo, pr, sha, dim, verdict, reason, keep, json)` | Set review verdict |
| `run_verdict_show(repo, pr, sha, json)` | Show review verdicts |
| `run_terminate(repo, pr, type, json)` | Terminate one active reviewer lane with decision-bound authority checks |
| `run_tail(lines, follow)` | Tail review event log |
| `run_push(repo, remote, branch, ticket)` | Push review branch and dispatch review pipeline |
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
- `~/.apm2/review_state.json`: Reviewer run-state index
- `~/.apm2/reviews/<pr>/<type>/state.json`: Per-run deterministic state
- `~/.apm2/review_pulses/`: Pulse files for liveness detection
- `~/.apm2/review_locks/`: File-based dispatch locks
- `documents/reviews/SECURITY_REVIEW_PROMPT.cac.json`: Security review prompt
- `documents/reviews/CODE_QUALITY_PROMPT.cac.json`: Code quality review prompt

## Ticket Notes

- TCK-00621: Single-flight lock liveness and security hardening for `gates.rs`.
  - Lock file opens now enforce `O_NOFOLLOW | O_CLOEXEC` on Unix for both
    acquisition and reaper paths, preventing symlink-target truncation and
    TOCTOU substitution attacks.
  - After acquiring a lock, `single_flight_lock_file_matches_path()` verifies
    the locked file descriptor still matches the lock path inode/dev (and
    `nlink > 0`) before writing owner metadata, closing the reaper/acquirer
    race where two processes could hold "exclusive" locks on different inodes.
  - Stale lock reaping is per-entry fail-soft: malformed/unreadable lock files
    no longer abort the whole scan; remaining entries continue to be processed.
  - PID liveness checks are now platform-specific: Linux uses `/proc/<pid>`,
    non-Linux Unix uses `kill(pid, 0)`, and Windows uses `OpenProcess` probe
    semantics (including `ERROR_ACCESS_DENIED` as "process exists").
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
  - `gates.rs`: `compute_nextest_test_environment()` calls `ensure_lane_env_dirs()` + `apply_lane_env_overrides()` for per-lane env isolation. `run_gates_inner()` acquires an exclusive lane lock on `lane-00` via `LaneManager::acquire_lock()` before any lane operations, preventing concurrent `apm2 fac gates` collisions. Also checks lane-00 for CORRUPT state before execution, refusing to run in a dirty environment (directs user to `apm2 fac doctor --fix`).
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
- TCK-00540/TCK-00619: Gate cache reuse is strict fail-closed.
  - `gate_cache.rs`: `CachedGateResult` persists signed `rfc0028_receipt_bound`/`rfc0029_receipt_bound` flags. `set_with_attestation()` writes both as `false` by default; `bind_receipt_evidence()` / `try_bind_receipt_from_store()` are the only promotion path. `check_reuse()` now unconditionally denies entries missing either binding (`receipt_binding_missing`) and verifies signatures against a single canonical format.
  - `gate_cache.rs` deserialization is strict (`#[serde(deny_unknown_fields)]` on `CachedGateResult`, `GateCacheEntryV2`, and `GateCache`), and migration compatibility paths are removed (no v1 cache fallback, no legacy canonical-bytes format fallback).
  - `fac_worker.rs`: after a successful gates receipt is committed, `fac_review_api::rebind_gate_cache_after_receipt()` still rebinds and re-signs cache entries based on durable RFC-0028/0029 receipt evidence.
- TCK-00573: Sandbox hardening in gate attestation + GateReceipt.
  - `gate_attestation.rs`: `GateResourcePolicy` gains `sandbox_hardening: Option<String>` field, included in attestation digest computation. `from_cli()` accepts `sandbox_hardening: Option<&str>` parameter.
  - `gates.rs` and `evidence.rs`: Updated `GateResourcePolicy::from_cli()` call sites to derive `sandbox_hardening_hash` from the effective policy-driven `SandboxHardeningProfile` (via `policy.sandbox_hardening.content_hash_hex()`), not `SandboxHardeningProfile::default()`. In `evidence.rs`, the hash is carried through `PipelineTestCommand.sandbox_hardening_hash` so attestation binds to the same profile used for execution. Regression tests in `gate_attestation.rs` prove that mutating `sandbox_hardening` (e.g., `private_tmp=false`) changes the resource digest and attestation digest, denying cache reuse across profile drift.
- TCK-00574: Network policy for job units — default deny network for gates, allow only for explicit fetch/warm phases.
  - `bounded_test_runner.rs`: `limits_to_properties()` and `build_bounded_test_command()` accept a `NetworkPolicy` parameter, passed through to `SystemdUnitProperties::from_cli_limits_with_hardening()`. Network policy directives are emitted alongside sandbox hardening in system-mode execution. New `build_bounded_gate_command()` wraps non-test gate commands (rustfmt, clippy, doc) in systemd-run with the same network policy isolation as the test gate (BLOCKER fix round 4).
  - `gates.rs`: Resolves network policy via `resolve_network_policy("gates", policy.network_policy.as_ref())` (deny-all with operator override) and passes it to `build_systemd_bounded_test_command()`. Network policy hash is now included in `GateResourcePolicy::from_cli()` for attestation binding (MAJOR-1 fix round 4).
  - `evidence.rs`: Resolves network policy via `resolve_network_policy("gates", policy.network_policy.as_ref())` (deny-all with operator override) and passes it to `build_systemd_bounded_test_command()` for pipeline evidence execution. Non-test gates (rustfmt, clippy, doc) are now wrapped in systemd-run with network isolation via `build_bounded_gate_command()` in full (non-quick) mode (BLOCKER fix round 4). `PipelineTestCommand` carries `network_policy_hash` for attestation binding. In quick mode, gates run without network isolation (development shortcut).
  - `gate_attestation.rs`: `GateResourcePolicy` gains `network_policy_hash: Option<String>` field (MAJOR-1 fix round 4). `from_cli()` accepts a new `network_policy_hash: Option<&str>` parameter. The hash is included in `resource_digest` computation, ensuring attestation digests change when network policy toggles between allow and deny, preventing cache reuse across policy drift. Regression tests prove deny/allow produce different attestation digests.
- TCK-00541: Gate cache v3 integration into evidence pipeline + review-round fixes.
  - `evidence.rs`: Wired `GateCacheV3` into the evidence gate pipeline. Added `compute_toolchain_fingerprint()` (BLAKE3 of `rustc --version --verbose`), `compute_v3_compound_key()` (builds `V3CompoundKey` from pipeline context), `cache_v3_root()` / `cache_v2_root()` path helpers, and `reuse_decision_with_v3_fallback()` (tries v3 cache first, falls back to v2). `run_evidence_gates_with_status_with_lane_context()` now builds the v3 compound key, loads the v3 cache (with v2 fallback via `load_from_v2_dir()`), and passes a mutable v3 cache through all gate phases. All `reuse_decision_for_gate` calls replaced with `reuse_decision_with_v3_fallback`. `finalize_status_gate_run()` accepts `v3_gate_cache: Option<&mut GateCacheV3>`, copies v2 results into v3, signs v3 entries, and persists the v3 cache alongside v2 for backwards compatibility.
  - `evidence.rs` (BLOCKER fix, PR-741 round 2): v3 hit handling now sources cached payload from v3 independently of v2. Added `CacheSource` enum (`V3`, `V2`, `None`) to `ReuseDecision` in `gate_cache.rs`; `reuse_decision_with_v3_fallback()` returns `hit_v3()` on v3 matches. New `CachedPayload` struct and `resolve_cached_payload()` function route cached data extraction to the correct cache layer based on `ReuseDecision.source`. All 5 reuse sites in `run_evidence_gates_with_status_with_lane_context()` now use `resolve_cached_payload()` instead of hardcoded v2 lookups. `finalize_status_gate_run()` persists v3 first (primary store) then v2 (backward-compat, best-effort). Regression tests: `v3_only_cache_hit_succeeds_without_v2` (proves v3-only hits work when v2 is absent), `v3_preferred_over_v2_when_both_present`.
  - `evidence.rs` (MAJOR security fix, PR-741 round 3): [INV-GCV3-001] V2 fallback for gate reuse disabled. `reuse_decision_with_v3_fallback()` no longer falls back to v2 `reuse_decision_for_gate()` when v3 misses; returns `miss("v3_miss_v2_fallback_disabled")` instead. V2 entries lack RFC-0028/0029 binding proof and cannot satisfy v3 compound-key continuity. `reuse_decision_for_gate()` removed (dead code). `CacheSource::V2`, `ReuseDecision::hit()`, and `GateCache::check_reuse()` annotated `#[allow(dead_code)]`. Regression test `v2_fallback_denied_when_v3_misses` proves v2 fallback is denied.
  - `gate_cache_v3.rs` (MAJOR security fix, PR-741 round 3): [INV-GCV3-001] Added `v2_sourced: bool` field to `GateCacheV3`. `load_from_v2_dir()` sets `v2_sourced = true`. `check_reuse()` unconditionally denies v2-sourced entries with `miss("v2_sourced_no_binding_proof")`. Regression tests: `v2_sourced_entries_denied_by_check_reuse`, `profile_drift_v2_fallback_denied`, `native_v3_entries_remain_reusable`, `v3_disk_roundtrip_not_v2_sourced`, `new_cache_not_v2_sourced`.
  - `evidence.rs` (MAJOR security fix, PR-741 round 4): [INV-GCV3-001] V2 fallback loading structurally removed from evidence pipeline. `v3_cache_loaded` now uses `GateCacheV3::load_from_dir()` only (native v3); the `.or_else(load_from_v2_dir)` fallback removed entirely. `cache_v2_root()` function removed (dead code). `load_from_v2_dir()` documentation updated to restrict usage to diagnostic/migration tooling only. This eliminates the structural gap where v2 entries were assigned the current v3 compound key without cryptographic binding.
  - `gate_cache_v3.rs` (MINOR fix, PR-741 round 4): [INV-GCV3-005] `save_to_dir()` now acquires an exclusive `flock(LOCK_EX)` on `root/.{index_key}.lock` for the duration of the write, serializing concurrent FAC runs targeting the same compound key. Added `acquire_exclusive_blocking()` to `flock_util.rs`. Regression tests: `save_creates_lock_file`, `concurrent_saves_serialized_by_lock`.
  - `evidence.rs` (MAJOR fix, PR-741 round 5): Added `rebind_v3_gate_cache_after_receipt()` — the v3 counterpart of `gate_cache::rebind_gate_cache_after_receipt()`. Loads the persisted v3 cache from disk (using compound key reconstructed from policy_hash, toolchain, sbx_hash, net_hash), calls `try_bind_receipt_from_store()` to promote `rfc0028_receipt_bound`/`rfc0029_receipt_bound` flags, re-signs all entries, and saves back. Exposed via `mod.rs` wrapper. Called from `fac_worker.rs` after v2 rebind so v3 entries gain receipt binding evidence and `check_reuse()` can emit verified hits. Regression tests in `gate_cache_v3.rs`: `check_reuse_hit_after_receipt_rebind_roundtrip` (proves full disk round-trip rebind promotes flags and enables cache hit), `receipt_rebind_no_promotion_on_failed_rfc0028` (proves fail-closed when RFC-0028 trace fails).
  - `gates.rs` (BLOCKER fix, PR-741 round 5): Removed `cache.save()` from the default full-path gates flow (`run_gates_inner`). The v2 `GateCache` is still constructed in-memory for attestation digest computation and metadata backfill consumed by the v3 populate path, but is no longer persisted to disk. This fulfills the TCK-00541 scope requirement: "read v2 but only write v3 in default mode". Regression test: `default_full_run_does_not_write_v2_cache`.
- TCK-00626 (MAJOR fix, PR-772 round 4): `push.rs` non-terminal joined dispatch with `pid=None` now treated as alive (unit-supervised liveness) instead of transient failure. In the systemd detached path, dispatches use unit-based supervision and may not have a PID recorded; treating `pid=None` as dead caused spurious retry loops and duplicate dispatches. PID identity checks (`is_pid_alive_with_identity`) are now only applied when a PID IS present.
- TCK-00626 (BLOCKER fix, PR-772 round 5): 3 code-quality BLOCKERs resolved.
  - **BLOCKER 1 (S2)**: Eliminated dual `V3ReuseDecision`/`CacheDecision` paths. `check_reuse()` now returns `CacheDecision` directly with structured `reason_code` and `first_mismatch_dimension`. Removed `V3ReuseDecision` type, `check_reuse_decision()` wrapper, and `map_reason_to_code()` translator. Evidence pipeline uses `CacheDecision.hit` for verdicts.
  - **BLOCKER 2 (S2)**: Fixed first-mismatch check order. TTL check moved from FIRST to LAST position in the ordered evaluation, after signature/receipt-binding/drift checks. Stale entries with integrity failures now surface `signature_invalid` or `receipt_binding_missing` before `ttl_expired`.
  - **BLOCKER 3 (S4)**: Added table-driven `gate_finished_event_all_reason_codes_table_driven` test in `gates.rs` covering all 11 miss reason codes (`sha_miss`, `gate_miss`, `signature_invalid`, `receipt_binding_missing`, `policy_drift`, `toolchain_drift`, `closure_drift`, `input_drift`, `network_policy_drift`, `sandbox_drift`, `ttl_expired`) plus cache hit, verifying `reason_code` and `first_mismatch_dimension` serialization for each.
- TCK-00627: Warm-path performance SLO instrumentation and verification.
  - `gates.rs` (S1): Added `total_duration_ms`, `cache_hit_count`, `cache_miss_count`, `is_warm_run`, `slo_violation` fields to `GatesSummary`. `run_summary_event()` emits all new fields in the NDJSON run_summary event. `total_duration_ms` computed as `prep_duration_ms.saturating_add(execute_duration_ms)` in `run_gates_inner_detailed()`.
  - `gates.rs` (S2): Added `compute_cache_counts()` (pure function, counts hits/misses from `EvidenceGateResult.cache_decision`) and `compute_warm_path_slo()` (pure function, derives `is_warm_run` and `slo_violation` from counts + prep duration). SLO threshold: `WARM_PATH_PREP_THRESHOLD_MS = 500`. `is_warm_run = true` iff `cache_miss_count == 0 && cache_hit_count > 0 && prep_duration_ms <= 500`. SLO violation emits `eprintln!` warning only, never affects exit code.
  - `gates.rs` (S3): Added `ci_benchmark_warm_path_slo_two_consecutive_runs` test simulating cold (all cache misses) and warm (all cache hits) runs. Asserts: run2.cache_hit_count == run1 gate count, run2.total_duration_ms <= 20% of run1, run2.prep_duration_ms <= 500, run2.is_warm_run == true.
  - `gates.rs` (S4): Added 10 unit regression tests for `compute_warm_path_slo()` and `compute_cache_counts()`: boundary cases (prep == 500, prep == 501), zero-gate edge case, cache miss scenarios, SLO violation string content, exit-code independence, `EvidenceGateResult` integration, and `run_summary_event` field presence verification.
