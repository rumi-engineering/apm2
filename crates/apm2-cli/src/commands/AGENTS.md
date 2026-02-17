# commands

> CLI command implementations for all `apm2` subcommands.

## Overview

The `commands` module contains the implementation of every CLI subcommand. Each file or sub-module corresponds to a command group dispatched from `main.rs`. Commands use the `client` module for daemon IPC and emit structured output (text or JSON) controlled by `--json` flags.

All command functions return a `u8` exit code or `anyhow::Result<()>`, using values from `crate::exit_codes`.

### Module Map

| File/Module | Command Group | Description |
|-------------|---------------|-------------|
| `daemon.rs` | `apm2 daemon`, `apm2 kill` | Daemon lifecycle management |
| `process.rs` | `apm2 start/stop/restart/reload/list/status/logs` | Process management |
| `creds.rs` | `apm2 creds *` | Credential management |
| `episode.rs` | `apm2 episode *` | Episode lifecycle |
| `work.rs` | `apm2 work claim/status/list` | Work assignment operations |
| `tool.rs` | `apm2 tool request` | Tool execution requests |
| `event.rs` | `apm2 event emit` | Session event emission |
| `evidence.rs` | `apm2 evidence publish` | Evidence artifact publishing |
| `capability.rs` | `apm2 capability request` | Capability token issuance |
| `consensus.rs` | `apm2 consensus *` | Consensus query operations |
| `fac.rs` | `apm2 fac *` | FAC (Factory Automation Cycle) top-level dispatcher |
| `fac_pr/` | `apm2 fac pr *` | GitHub App credential management for PR operations |
| `fac_review/` | `apm2 fac review *` | Review orchestration (security + quality reviews) |
| `fac_queue.rs` | `apm2 fac queue *` | Queue introspection (status with counts, reason stats) |
| `fac_job.rs` | `apm2 fac job *` | Job introspection (show, cancel) with bounded I/O |
| `fac_utils.rs` | _(shared)_ | Shared utilities: queue/fac root resolution, bounded job spec I/O |
| `factory/` | `apm2 factory *` | Factory pipeline (CCP, Impact Map, RFC, Tickets) |
| `cac.rs` | `apm2 cac *` | CAC (Compliance Artifact Chain) operations |
| `coordinate.rs` | `apm2 coordinate *` | Multi-agent coordination commands |
| `export.rs` | `apm2 export *` | Data export operations |
| `pack.rs` | `apm2 pack *` | Pack/bundle operations |
| `role_launch.rs` | `apm2 role-launch *` | Role-based agent launching |

### Security: Session Token Handling

```rust
pub const APM2_SESSION_TOKEN_ENV: &str = "APM2_SESSION_TOKEN";
```

Session-scoped commands accept session tokens via the `APM2_SESSION_TOKEN` environment variable (preferred) or `--session-token` CLI flag (deprecated). The environment variable approach mitigates CWE-214 (visible sensitive information in process listings).

## Key Types

### `FacCommand` (fac.rs)

```rust
#[derive(Debug, Args)]
pub struct FacCommand {
    #[command(subcommand)]
    pub subcommand: FacSubcommand,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}
```

Top-level FAC command dispatcher. Routes to `fac_pr`, `fac_review`, and `factory` sub-modules.

### `FacSubcommand` (fac.rs)

```rust
#[derive(Debug, Subcommand)]
pub enum FacSubcommand {
    Pr(PrArgs),
    Review(ReviewArgs),
    Run { spec_file: PathBuf, format: String },
    Factory(FactoryCommand),
    Gates(GatesArgs),
    Work(WorkArgs),
    Episode(EpisodeArgs),
    Receipt(ReceiptArgs),
    Context(ContextArgs),
    Resume(ResumeArgs),
    Barrier(BarrierArgs),
    Kickoff(KickoffArgs),
    Push(PushArgs),
    Restart(RestartArgs),
    Logs(LogsArgs),
    Pipeline(PipelineArgs),
}
```

### `WorkCommand` / `WorkSubcommand` (work.rs)

```rust
#[derive(Debug, Args)]
pub struct WorkCommand { pub subcommand: WorkSubcommand }

#[derive(Debug, Subcommand)]
pub enum WorkSubcommand {
    Claim(ClaimArgs),
    Status(StatusArgs),
    List,
}
```

### `RoleArg` (work.rs)

```rust
#[derive(Debug, Clone, ValueEnum)]
pub enum RoleArg {
    Implementor,
    Reviewer,
    Architect,
    Operator,
    Monitor,
}
```

Maps CLI role arguments to protocol `WorkRole` values.

### `EventCommand` (event.rs)

```rust
#[derive(Debug, Args)]
pub struct EventCommand { pub subcommand: EventSubcommand }

#[derive(Debug, Subcommand)]
pub enum EventSubcommand {
    Emit(EmitArgs),
}
```

## Public API

### Daemon (daemon.rs)

| Function | Description |
|----------|-------------|
| `run(config, no_daemon)` | Start daemon (spawns `apm2-daemon` binary) |
| `kill(socket_path)` | Send shutdown via `OperatorClient` |
| `collect_doctor_checks(operator_socket, config_path)` | Collect all doctor health checks (TCK-00547) |

#### Doctor Check Categories (TCK-00547)

`collect_doctor_checks` runs checks in these categories:

1. **Host Capability**: cgroup v2 availability, systemd execution backend selection
2. **Control-Plane Readiness**: broker socket reachability, worker liveness (projection probe)
3. **Toolchain**: cargo, cargo-nextest, systemd-run availability
4. **Security Posture**: FAC root permissions (0700/ownership), socket permissions (0600), lane symlink detection
5. **Credentials Posture** (WARN-only): GITHUB_TOKEN/GH_TOKEN, GitHub App config, systemd credential file

Each check produces a `DaemonDoctorCheck` with `name`, `status` (ERROR/WARN/OK), and `message` (including actionable remediation). Credentials checks are WARN-only to avoid blocking local-only workflows.

#### Worker Liveness Path Invariant (TCK-00607)

- The daemon doctor `worker_liveness` probe must mirror daemon cache-path derivation exactly:
  - if `ledger_db_path` is set, cache path is `ledger_db_path.with_extension("projection_cache.db")`
  - otherwise, cache path is `{state_file_parent}/projection_cache.db`
- When daemon is running, doctor probes runtime `--state-file` / `--ledger-db` overrides from `/proc/<pid>/cmdline` (resolved against daemon cwd) before evaluating cache presence. If runtime does not override `--ledger-db`, doctor must fall back to `daemon.ledger_db` from config to match daemon startup precedence. This prevents false negatives when runtime and static paths differ.

#### Systemd Template Invariants (TCK-00608)

- Worker unit templates must invoke `apm2 fac worker --poll-interval-secs <N>`; `--poll-interval` is invalid and will fail argument parsing.
- User-mode daemon and worker templates must allow writes to both `%h/.apm2` and `%h/.local/share/apm2` when `ProtectHome=read-only` is enabled, because default ledger/CAS/state paths are XDG data-dir based.

### Process Management (process.rs)

| Function | Description |
|----------|-------------|
| `start(socket_path, name)` | Start a named process |
| `stop(socket_path, name)` | Stop a named process |
| `restart(socket_path, name)` | Restart a named process |
| `reload(socket_path, name)` | Rolling restart a process |
| `list(socket_path)` | List all managed processes |
| `status(socket_path, name)` | Show process details |
| `info(socket_path, name)` | Show process info |
| `logs(socket_path, name, lines, follow)` | Tail process logs |

### FAC Dispatcher (fac.rs)

| Function | Description |
|----------|-------------|
| `run_fac(cmd, operator_socket, session_socket)` | Route FAC subcommands; returns exit code |

### Work (work.rs)

| Function | Description |
|----------|-------------|
| `run_work(cmd, socket_path)` | Dispatch work claim/status/list |

### Event (event.rs)

| Function | Description |
|----------|-------------|
| `run_event(cmd, socket_path)` | Dispatch event emit |

## Related Modules

- [`client/`](../client/AGENTS.md) -- IPC clients used by all command implementations
- [`fac_pr/`](fac_pr/AGENTS.md) -- GitHub App credential management subcommands
- [`fac_review/`](fac_review/AGENTS.md) -- Review orchestration subcommands
- [`factory/`](factory/AGENTS.md) -- Factory pipeline subcommands
- [`apm2-cli` (crate)](../../AGENTS.md) -- Crate-level CLI architecture

## References

- CWE-214: Invocation of Process Using Visible Sensitive Information
- DD-009: ProtocolServer-only control plane
- `documents/security/SECRETS_MANAGEMENT.cac.json`: Secrets handling policy

## Security / Permission Invariants (Updated for TCK-00536)

- FAC command entry (`run_fac`) now enforces strict ownership and 0700-mode validation on
  `$APM2_HOME` critical subdirectories (`private`, `private/fac`, and related cache/evidence roots).
- Command modules now use shared helpers in `fac_permissions` when creating FAC directories/files so
  sensitive artifacts are created with safe modes (`0700` for directories, `0600` for files).

## Cancel / Stop-Revoke Invariants (Updated for TCK-00533)

- **Bounded I/O** (`fac_job.rs`): `read_job_spec` uses `File::open().take(MAX_SIZE+1)` to prevent
  denial-of-service via special files (procfs, FIFOs, `/dev/zero`). No metadata-only size checks.
- **Receipt-before-move** (`fac_job.rs`): `cancel_pending_job` emits the cancellation receipt
  BEFORE moving the job to `cancelled/`. A job is never in `cancelled/` without a terminal receipt.
- **Fail-closed claimed cancel** (`fac_job.rs`): `cancel_claimed_job` returns a hard error if the
  claimed job spec cannot be read. No success without a `CancellationRequested` receipt.
- **Lane sanitization** (`fac_worker.rs`): `stop_target_unit_exact` rejects `queue_lane` values
  containing characters outside `[A-Za-z0-9_-]` to prevent command injection via unit names.
- **Control-lane refusal receipts** (`fac_worker.rs`): All deny paths in the control-lane
  `stop_revoke` flow emit explicit refusal receipts before moving jobs to `denied/`.
- **RUNNING lease lifecycle** (`fac_worker.rs`): A RUNNING `LaneLeaseV1` is persisted after lane
  acquisition and lane profile loading, before any execution. Every early-return path removes the
  lease. This satisfies the `run_lane_cleanup` RUNNING-state precondition (INV-LANE-CLEANUP-005).
- **Completion-before-cleanup** (`fac_worker.rs`): Lane cleanup runs AFTER job completion receipt
  emission and move to `completed/`. Cleanup failures log warnings and mark lanes corrupt but do
  not retroactively negate a completed job outcome (INV-LANE-CLEANUP-006).
- **Process liveness** (`fac_worker.rs`): Stale lease detection uses `libc::kill(pid, 0)` with
  errno discrimination (ESRCH vs EPERM) instead of shell `kill -0` with `status.success()`.
  EPERM means the process exists but is unpermissioned; the lane is marked corrupt, not idle.

## Warm Command Invariants (Updated for TCK-00579)

- **Lane encoding** (`fac_warm.rs`): The `--lane` flag value is validated using the same
  character set the worker enforces (`[A-Za-z0-9_-]`), length-checked against
  `MAX_QUEUE_LANE_LENGTH`, and encoded in the job spec's `queue_lane` field. Defaults to
  `"bulk"` when omitted. The worker uses `queue_lane` for lane scheduling admission.
- **Atomic denial pipeline in execute_warm_job** (`fac_worker.rs`, TCK-00564 fix round 9):
  All warm job denial paths in `execute_warm_job` (phase validation failure,
  CARGO_HOME/CARGO_TARGET_DIR creation failure, credential mount injection failure,
  containment backend/config errors, and warm execution failure) use
  `commit_claimed_job_via_pipeline` for crash-safe receipt-before-move ordering. Pipeline
  commit failures are handled via `handle_pipeline_commit_failure` which leaves the job
  in `claimed/` for reconcile to repair. No denial returns without an atomic terminal
  queue state transition.
- **Systemd-run containment** (`fac_worker.rs`, `warm.rs`): Warm phase subprocesses
  (which compile untrusted repository code including `build.rs` and proc-macros) are
  wrapped in `systemd-run` transient units with MemoryMax/CPUQuota/TasksMax/RuntimeMaxSec
  constraints from the lane profile (INV-WARM-014). Falls back to uncontained execution
  with a logged warning when `systemd-run` is unavailable. Backend selection uses
  `select_and_validate_backend()` for consistency with bounded test runner.
- **Systemd-run D-Bus connectivity** (`warm.rs`): The systemd-run process inherits the
  parent environment (no `env_clear()` on the systemd-run `Command`) because it needs
  `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` for user-mode D-Bus connectivity.
  The contained child process receives its environment exclusively via `--setenv`
  arguments, which carry the hardened policy-filtered environment.
- **Heartbeat liveness** (`fac_worker.rs`, `warm.rs`): Worker heartbeat is refreshed
  every 5 seconds during warm phase execution via a callback integrated into the
  `try_wait` polling loop (INV-WARM-015). The heartbeat captures the last known
  cycle count and job counters so observers see accurate state during warm phases.
  Prevents the broker from considering the worker dead during hour-long compilation
  phases.
- **Timeout-derived poll cap** (`fac_warm.rs`): The poll iteration cap in `wait_for_receipt`
  is derived from the effective timeout (`timeout / poll_interval + headroom`), not a fixed
  constant. Callers passing `--wait-timeout-secs` above the default (1200s) are no longer
  cut short by the iteration cap.
- **Sandbox hash hoisting** (`fac_worker.rs`, TCK-00573): `process_job()` computes
  `sbx_hash = policy.sandbox_hardening.content_hash_hex()` once at function entry and
  threads it through all denial and execution paths. `handle_stop_revoke()` and
  `execute_warm_job()` accept `sbx_hash: &str` as a parameter instead of recomputing.
  All `emit_job_receipt` calls in `handle_stop_revoke` now pass `Some(sbx_hash)` instead
  of `None`, ensuring stop/revoke receipts bind sandbox posture.
- **GateReceipt sandbox binding** (`fac_worker.rs`, TCK-00573): Both `GateReceiptBuilder`
  chains (exec and warm paths) call `.sandbox_hardening_hash(&sbx_hash)` so the
  cryptographically signed `GateReceipt` binds the hardening profile used during
  execution. This complements the `FacJobReceiptV1` binding done via `emit_job_receipt`.
- **Policy-aware warm spec validation** (`fac_warm.rs`, TCK-00579): The warm enqueue path
  derives a `JobSpecValidationPolicy` from the loaded FAC policy and validates the warm
  spec via `validate_job_spec_with_policy()` before enqueue, failing closed on validation
  error. This enforces repo_id allowlist, bytes_backend allowlist, and filesystem-path
  rejection at enqueue time, matching the gates enqueue path (INV-WARM-CLI-005).
- **Pipeline commit failure handling** (`fac_worker.rs`, TCK-00564 fix round 4, updated
  round 7): Every `commit_claimed_job_via_pipeline` call site checks the returned
  `Result<PathBuf, ReceiptPipelineError>`. On commit failure, the
  `handle_pipeline_commit_failure` helper logs the structured error via `eprintln!` and
  leaves the job in `claimed/` for reconcile to repair. The error type preserves
  specificity (including `TornState` variant) for callers to decide recovery strategy
  (MAJOR-2 fix round 7). If the receipt was persisted before the commit failed (torn
  state), `recover_torn_state` routes the job to the correct terminal directory based
  on the receipt outcome. If the receipt was not persisted, the orphan policy applies.
- **Outcome-aware duplicate detection** (`fac_worker.rs`, TCK-00564 fix round 4, updated
  round 7): The duplicate receipt check in `process_job` uses `find_receipt_for_job`
  instead of `has_receipt_for_job` and routes to the correct terminal directory via
  `outcome_to_terminal_state`. Non-terminal outcomes (e.g., `CancellationRequested`)
  are explicitly handled: the job is skipped without moving and a warning is logged
  (BLOCKER-1 fix round 7). Duplicate moves use the hardened `move_job_to_terminal`
  from `receipt_pipeline.rs` with symlink checks and ownership verification instead of
  `move_to_dir_safe` (BLOCKER-2 fix round 7).
- **Pre-claim validation paths use pipeline** (`fac_worker.rs`, TCK-00564 fix round 7):
  DigestMismatch and ValidationFailed paths that reject jobs before claiming now use
  `commit_claimed_job_via_pipeline` for atomic receipt + move, ensuring no job reaches
  a terminal directory without a persisted receipt (BLOCKER-3 fix round 7).
- **Unified rename_noreplace** (`fac_worker.rs`, TCK-00564 fix round 7): The local
  `rename_noreplace` implementation has been removed. All callers now use the single
  canonical `rename_noreplace` from `apm2_core::fac::receipt_pipeline` (MAJOR-3 fix
  round 7).

## Introspection CLI Invariants (Updated for TCK-00535)

- **Queue status** (`fac_queue.rs`): `apm2 fac queue status` scans the six queue directories
  (`pending`, `claimed`, `completed`, `denied`, `quarantine`, `cancelled`) with bounded
  `read_dir` (MAX_SCAN_ENTRIES=4096) and reports per-directory valid job counts, malformed
  entry counts, oldest job ID and enqueue time, and denial/quarantine reason stats. Job
  counts only increment after successful `read_job_spec_bounded` parse; malformed `.json`
  files are tracked separately to avoid inflating job counts. Reason codes are capped at
  MAX_REASON_CODES=64 to prevent unbounded memory growth from adversarial data.
- **Receipt-based reason stats** (`fac_queue.rs`): `collect_reason_stats` resolves denial
  reasons from the canonical receipt index via `lookup_job_receipt()`, not from `spec.kind`.
  Reason keys use serde-serialized snake_case codes (e.g., `"digest_mismatch"`) for stable
  machine-readable output, not Debug formatting.
- **Job show** (`fac_job.rs`): `apm2 fac job show <job_id>` locates a job across all queue
  directories, reads the spec with bounded I/O (reuses `read_job_spec_bounded` from
  `fac_utils`), resolves the latest receipt from the receipt index, and discovers log
  pointers from the evidence directory and lane logs. Returns NOT_FOUND (exit 12) if the
  job is absent. State labels use canonical directory tokens via `JobState::state_label()`
  (e.g., "quarantine" not "quarantined").
- **Bounded log pointers** (`fac_job.rs`): `discover_log_pointers` caps total discovered
  log paths at MAX_LOG_POINTERS=256 across all scan locations (evidence directory + lane
  logs). The function resolves lanes from `resolve_fac_root().join("lanes")` (the canonical
  FAC root) rather than inferring from queue root parentage. Truncation is reported in both
  text and JSON output via `log_pointers_truncated`.
- **Symlink and FIFO guards** (`fac_utils.rs`, `fac_job.rs`): `read_job_spec_bounded` uses
  an open-once pattern with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` (via
  `OpenOptionsExt::custom_flags` on Unix) to atomically refuse symlinks at the kernel level
  and prevent blocking on FIFOs (named pipes), then calls `fstat` on the opened fd (via
  `File::metadata()`) to verify the target is a regular file. `O_NONBLOCK` prevents a local
  DoS where a FIFO queue entry would block the open(2) call indefinitely waiting for a
  writer; for regular files, `O_NONBLOCK` has no effect. This eliminates the TOCTOU race
  between `symlink_metadata()` and `File::open()` that existed previously, matching the
  established pattern in `fac_secure_io::read_bounded`. `discover_log_pointers` validates
  all scanned directories with `validate_real_directory` and skips symlinked entries via
  `is_symlink_entry`, both using lstat semantics.
- **Reason code overflow** (`fac_queue.rs`): When `MAX_REASON_CODES` distinct reason keys
  are reached in `collect_reason_stats`, new reason codes are aggregated into an `"other"`
  bucket rather than silently dropped, ensuring total counts remain accurate.
- **Scan truncation reporting** (`fac_job.rs`): `discover_log_pointers` sets `truncated =
  true` when `MAX_SCAN_ENTRIES` is hit in any directory scan (evidence, lanes, or logs),
  consistent with the `MAX_LOG_POINTERS` cap reporting.
- **Shared utilities** (`fac_utils.rs`): Queue root resolution (`resolve_queue_root`), FAC
  root resolution (`resolve_fac_root`), bounded job spec reading (`read_job_spec_bounded`),
  and directory validation (`validate_real_directory`) are consolidated in `fac_utils` to
  eliminate cross-module duplication between `fac_queue.rs` and `fac_job.rs`. Constants
  `QUEUE_DIR`, `MAX_SCAN_ENTRIES` are shared.
- **Receipts list --since** (`fac.rs`): `apm2 fac receipts list --since <epoch_secs>` filters
  the receipt index to entries at or after the given UNIX epoch. Deterministic ordering is
  enforced: primary sort by `timestamp_secs` descending, secondary sort by `content_hash`
  ascending for stable tie-breaking. Boundary inclusion is verified by regression test.
