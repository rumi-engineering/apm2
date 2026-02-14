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
       |      +-- selector.rs     (review model selection logic)
       |      +-- restart.rs      (CI-state-aware pipeline restart)
       |      +-- merge_conflicts.rs (merge conflict detection)
       |      +-- worktree.rs     (SHA-to-worktree resolution for detached dispatch)
       |      +-- timeout_policy.rs (uniform bounded test timeout policy)
       |
       +-- state.rs          (ReviewStateFile persistence, pulse files, locking)
       +-- types.rs          (shared types, constants, utility functions)
       +-- events.rs         (NDJSON lifecycle telemetry)
       +-- barrier.rs        (GitHub helper primitives: auth/head/metadata rendering)
       +-- ci_status.rs      (CI check-suite status querying)
       +-- decision.rs       (review verdict set/show)
       +-- detection.rs      (review detection from PR comments)
       +-- evidence.rs       (evidence artifact collection)
       +-- findings.rs       (review findings aggregation)
       +-- gates.rs          (pre-review gate checks: systemd, resources)
       +-- gate_attestation.rs (gate attestation recording)
       +-- gate_cache.rs     (gate result caching)
       +-- logs.rs           (review log retrieval by PR/selector)
       +-- pipeline.rs       (end-to-end pipeline: dispatch + project)
       +-- prepare.rs        (review input preparation)
       +-- projection.rs     (projection snapshot for GitHub surfaces)
       +-- projection_store.rs (local canonical projection cache under ~/.apm2/fac_projection)
       +-- github_projection.rs (dedicated GitHub projection writer/read-fallback boundary)
       +-- publish.rs        (review comment publishing to GitHub)
       +-- comment.rs        (single SHA-bound finding comment publishing)
       +-- pr_body.rs        (PR body gate-status marker sync + history retention)
       +-- push.rs           (branch push with commit signing)
       +-- target.rs         (review target resolution)
```

### Key Behaviors

- **Parallel orchestration**: Security and quality reviews run in parallel when `--type all`.
- **Multi-model fallback**: If a model stalls, the orchestrator cycles through a model pool (`model_pool.rs`).
- **Liveness monitoring**: Pulse files track reviewer health; stall threshold is 90 seconds.
- **Idempotent dispatch**: `DispatchIdempotencyKey` prevents duplicate reviews for the same SHA.
- **SHA freshness**: Reviews are invalidated if PR head moves during execution.
- **Uniform bounded tests**: Test gate uses a fixed 600s timeout for all workspaces.
- **NDJSON telemetry**: All lifecycle events are appended to `~/.apm2/review_events.ndjson`.
- **CI-aware restart**: `apm2 fac restart` analyzes CI check-suite state before restarting.
- **Worktree-aware dispatch**: Detached review dispatch resolves and uses the worktree whose `HEAD` matches target SHA.
- **Per-SHA finding comments**: `apm2 fac review comment` writes one finding per comment using an `apm2-finding:v1` marker and `apm2.finding.v1` metadata block.
- **PR body gate status sync**: `apm2 fac push` writes a marker-bounded gate-status section in the PR body with expanded latest SHA and collapsed previous SHA snapshots.

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
- `prompt_path()` returns `documents/reviews/SECURITY_REVIEW_PROMPT.md` or `documents/reviews/CODE_QUALITY_PROMPT.md`.
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
pub use decision::VerdictValueArg;
pub use publish::ReviewPublishTypeArg;
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
| `run_comment(repo, pr, sha, severity, type, body, json)` | Publish a single SHA-bound finding comment |
| `run_prepare(repo, pr, sha, json)` | Prepare review inputs |
| `run_publish(repo, pr, sha, type, body, json)` | Publish review comment to GitHub |
| `run_verdict_set(repo, pr, sha, dim, verdict, reason, keep, json)` | Set review verdict |
| `run_verdict_show(repo, pr, sha, json)` | Show review verdicts |
| `run_project(pr, sha, since, after_seq, errors, fail_term, format_json, json)` | Best-effort projection for debug/log surfaces; non-critical by default |
| `run_tail(lines, follow)` | Tail review event log |
| `run_push(repo, remote, branch, ticket)` | Push review branch with commit signing |
| `run_restart(repo, pr, force, json)` | CI-aware pipeline restart |
| `run_pipeline(repo, pr_number, sha)` | End-to-end: dispatch + project |
| `run_logs(pr, repo, selector_type, selector, json)` | Retrieve review logs |
| `run_gates(force, quick, timeout, mem, pids, cpu, json)` | Run pre-review gate checks |

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
- `documents/reviews/SECURITY_REVIEW_PROMPT.md`: Security review prompt
- `documents/reviews/CODE_QUALITY_PROMPT.md`: Code quality review prompt

## Ticket Notes

- TCK-00523: Attestation fail-closed fixes.
  - Added `.cargo/config.toml` to gate input digest paths for cargo-based gates.
  - Added `rustfmt --version` to environment digest inputs.
  - Optionally captured `sccache --version` (with fallback when unavailable).
  - Extended command env allowlist with `CARGO_HOME`, `CARGO_TARGET_DIR`, `CARGO_BUILD_JOBS`, `NEXTEST_TEST_THREADS`, `RUSTC_WRAPPER`, and `SCCACHE_*`.
