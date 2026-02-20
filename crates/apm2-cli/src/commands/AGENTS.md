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
| `fac_bootstrap.rs` | `apm2 fac bootstrap` | One-shot compute-host provisioning for FESv1 |
| `fac_economics.rs` | `apm2 fac economics *` | Economics profile adoption, rollback, and inspection (TCK-00584) |
| `fac_install.rs` | `apm2 fac install` | Binary install and alignment (INV-PADOPT-004 prevention, TCK-00625) |
| `fac_pr/` | `apm2 fac pr *` | GitHub App credential management for PR operations |
| `fac_review/` | `apm2 fac review *` | Review orchestration (security + quality reviews) |
| `fac_queue.rs` | `apm2 fac queue *` | Queue introspection (status with counts, reason stats) |
| `fac_job.rs` | `apm2 fac job *` | Job introspection (show, cancel) with bounded I/O |
| `fac_caches.rs` | `apm2 fac caches *` | Explicit cache purge (nuke) with hard confirmations and receipts (TCK-00592) |
| `fac_config.rs` | `apm2 fac config *` | FAC configuration introspection (pure read-only; no state mutation) |
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
    Lane(LaneArgs),
    Bootstrap(BootstrapArgs),
    Economics(EconomicsArgs),
    Metrics(MetricsArgs),
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
6. **Secret Verification** (--full only, TCK-00598): When `full` is set, `creds_github_app_secret` attempts to resolve the GitHub App private key via `GitHubAppTokenProvider::resolve_private_key` and reports ERROR if the key is inaccessible. Remediation messages include `--for-systemd` guidance for headless hosts.

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

### Lane Init/Reconcile Commands (fac.rs, TCK-00539)

| Subcommand | Function | Description |
|------------|----------|-------------|
| `apm2 fac lane init` | `run_lane_init()` | Bootstrap a fresh lane pool with directories and default profiles |
| `apm2 fac lane reconcile` | `run_lane_reconcile()` | Repair missing lane directories/profiles, mark unrecoverable lanes CORRUPT |

Both subcommands accept a `--json` flag for structured output. Human-readable
tables are printed by default via `print_lane_init_receipt()` and
`print_lane_reconcile_receipt()`.

**Exit code policy for `run_lane_reconcile`**: non-zero when any of
`lanes_marked_corrupt`, `lanes_failed`, or `infrastructure_failures` is > 0.

**LaneSubcommand** enum variants added:
- `Init(LaneInitArgs)` -- `--json` flag
- `Reconcile(LaneReconcileArgs)` -- `--json` flag
- `MarkCorrupt(LaneMarkCorruptArgs)` -- `--reason`, `--receipt-digest`, `--json` flags (TCK-00570)

### Lane Mark-Corrupt Command (fac.rs, TCK-00570)

| Subcommand | Function | Description |
|------------|----------|-------------|
| `apm2 fac lane mark-corrupt <lane_id> --reason ...` | `run_lane_mark_corrupt()` | Operator tool to manually mark a lane as CORRUPT |

Writes a `corrupt.v1.json` marker under exclusive lane lock. Refuses
RUNNING lanes (use `lane reset --force`) and already-CORRUPT lanes (use
`lane reset` first). Accepts optional `--receipt-digest` to bind the
marker to an evidence artifact. Validates reason and digest against
`MAX_STRING_LENGTH` (512). The marker prevents all future job leases
until cleared via `apm2 fac lane reset`.

### Bootstrap (fac_bootstrap.rs, TCK-00599)

| Subcommand | Function | Description |
|------------|----------|-------------|
| `apm2 fac bootstrap` | `run_bootstrap()` | One-shot compute-host provisioning for FESv1 |

Five-phase provisioning sequence:
1. **Directories**: creates `$APM2_HOME/private/fac/**` tree via `create_dir_restricted` (0o700 user-mode, 0o770 system-mode) (CTR-2611)
2. **Policy**: writes default `FacPolicyV1` (safe no-secrets posture) via `persist_policy()`
3. **Lanes**: initializes lane pool via `LaneManager::init_lanes()`
4. **Services** (optional): installs systemd templates from `contrib/systemd/` (`--user` or `--system`)
5. **Doctor**: runs `collect_doctor_checks()` and gates exit code on result

Flags: `--dry-run` (show planned actions), `--user`/`--system` (systemd install mode), `--json`.

Security invariants:
- [INV-BOOT-001] Directories created via `create_dir_restricted` with restricted permissions at create-time (no TOCTOU chmod window). Uses 0o700 in user-mode, 0o770 in system-mode. Recursive: intermediate directories also get restricted permissions. Symlink paths rejected.
- [INV-BOOT-002] Policy files written with 0o600 permissions
- [INV-BOOT-003] Existing state never destroyed (additive-only)
- [INV-BOOT-004] Doctor checks gate the exit code (fail-closed)
- [INV-BOOT-005] Phase 4 (service installation) degrades gracefully when not in a git repository (e.g. binary releases). Missing templates are skipped with a warning, not fatal.
- [INV-BOOT-006] Installs `apm2-worker@.service` template unit alongside non-templated units for parallel lane-specific workers.

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
  `$APM2_HOME` critical subdirectories (`private`, `private/fac`, and related cache/evidence/legacy roots).
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
- **RFC-0028 token enforcement for stop_revoke** (`fac_job.rs`, `fac_worker.rs`, TCK-00587):
  The cancel command issues a self-signed RFC-0028 channel context token using the persistent
  FAC signing key. The worker validates this token on the control-lane admission path before
  executing stop_revoke. Missing or invalid tokens deny the job fail-closed. This dual-layer
  enforcement (token + queue directory ownership) ensures cancellation requires both signing
  key access and filesystem privilege.
- **Stop/revoke explicit admission trace** (`fac_worker.rs`, TCK-00587): Control-lane
  stop_revoke jobs construct a `StopRevokeAdmissionTrace` before dispatching to
  `handle_stop_revoke()`. All trace fields are derived from actual runtime state:
  `reservation_used` checks total queue capacity, `tick_floor_active` checks lane
  max_wait_ticks against policy threshold, TP fields reflect that TPs are not evaluated
  for control-lane (false = not evaluated). The trace is bound to the receipt via the
  `stop_revoke_admission` field on `FacJobReceiptV1` and included in both v1 and v2
  canonical bytes for replay verification. Anti-starvation is guaranteed by the sort
  order: candidates are sorted `(priority ASC, enqueue_time ASC, job_id ASC)` where
  `StopRevoke` priority=0 is highest, ensuring all stop_revoke jobs in a cycle are
  processed before any lower-priority lane.
- **RUNNING lease lifecycle** (`fac_worker.rs`): A RUNNING `LaneLeaseV1` is persisted after lane
  acquisition and lane profile loading, before any execution. Every early-return path removes the
  lease. This satisfies the `run_lane_cleanup` RUNNING-state precondition (INV-LANE-CLEANUP-005).
- **Completion-before-cleanup** (`fac_worker.rs`): Lane cleanup runs AFTER job completion receipt
  emission and move to `completed/`. Cleanup failures log warnings and mark lanes corrupt but do
  not retroactively negate a completed job outcome (INV-LANE-CLEANUP-006).
- **Process liveness** (`fac_worker.rs`): Stale lease detection uses `libc::kill(pid, 0)` with
  errno discrimination (ESRCH vs EPERM) instead of shell `kill -0` with `status.success()`.
  EPERM means the process exists but is unpermissioned; the lane is marked corrupt, not idle.
- **JSON-only stderr recommendation channel** (`fac_worker.rs`, TCK-00570): The
  `emit_lane_reset_recommendation` function emits exactly one JSON line per recommendation
  to stderr.  No plain-text preamble or human-readable log lines are mixed into the stream.
  Human-readable context is encoded inside the JSON `message` field.  Serialization errors
  are routed through `tracing::warn!` (structured logging) to keep the stderr channel
  JSON-only for downstream automation that consumes newline-delimited JSON.

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
- **Fingerprint-namespaced lane target dir** (`fac_worker.rs`, TCK-00538 fix round 2):
  CARGO_TARGET_DIR within lanes is namespaced by toolchain fingerprint as
  `target-<hex16>` (first 16 hex characters of the fingerprint). This ensures that
  toolchain changes produce a fresh build directory, preventing stale incremental
  compilation artifacts from a different compiler version.
- **Cached toolchain fingerprint** (`fac_worker.rs`, TCK-00538 fix round 3):
  Worker startup resolves the toolchain fingerprint with a cache-first strategy:
  load from `$APM2_HOME/private/fac/toolchain/fingerprint.v1.json` (bounded read,
  O_NOFOLLOW), validate by re-deriving fingerprint from stored raw versions, and
  skip probes if valid. On cache miss/invalid, compute fresh via probes and persist
  atomically with restricted permissions (dir 0o700, file 0o600). Cache write
  failure is non-fatal. Required probes (rustc, cargo) propagate errors for
  fail-closed startup. Process reaping after read completion uses bounded
  `try_wait()` + `kill()` loop (5s timeout) to prevent indefinite blocking.
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
- **Network policy resolution** (`fac_worker.rs`, TCK-00574): `process_job()` resolves
  network policy via `resolve_network_policy(&spec.kind, None)` based on the job kind.
  Gates jobs get deny-all; warm jobs get allow. The resolved `NetworkPolicy` is passed to
  `SystemdUnitProperties::from_lane_profile_with_hardening()` alongside the existing
  sandbox hardening profile.
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
  pointers from the legacy evidence/legacy directories and lane logs. Returns NOT_FOUND (exit 12) if the
  job is absent. State labels use canonical directory tokens via `JobState::state_label()`
  (e.g., "quarantine" not "quarantined").
- **Bounded log pointers** (`fac_job.rs`): `discover_log_pointers` caps total discovered
  log paths at MAX_LOG_POINTERS=256 across all scan locations (legacy directories + lane
  logs). TCK-00589 updated the function to scan both `evidence/` (pre-migration) and
  `legacy/` (post-migration) subdirectories for compatibility reads. The function resolves
  lanes from `resolve_fac_root().join("lanes")` (the canonical FAC root) rather than
  inferring from queue root parentage. Truncation is reported in both text and JSON output
  via `log_pointers_truncated`.
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
- **Receipts merge** (`fac.rs`, TCK-00543): `apm2 fac receipts merge --from <dir> --into <dir>`
  performs set-union merge on receipt digests. Copies receipts from the source directory into
  the target directory only if they do not already exist there. Emits an audit report with:
  duplicates skipped, receipts copied, job_id mismatches (same digest, different job_id),
  and parse failures. Deterministic presentation ordering: `timestamp_secs` descending,
  `content_hash` ascending for tiebreaking. All reads are bounded by `MAX_MERGE_SCAN_FILES`
  (65,536). Writes use atomic temp+rename. Supports `--json` output.

## Config Show Invariants (TCK-00590)

- **Pure introspection** (`fac_config.rs`): `apm2 fac config show` is a read-only
  introspection command. It MUST NOT create files, directories, or persist state.
  All filesystem lookups use non-mutating read paths.
- **Non-mutating boundary_id read** (`fac_config.rs`): The boundary_id lookup uses
  `read_boundary_id()` (non-mutating bounded read-if-present) instead of
  `load_or_default_boundary_id()` (which creates parent directories and persists
  a default boundary_id when the file is missing). Missing boundary_id is reported
  as a warning with a `<not set>` placeholder.
- **Regression test** (`fac_config.rs`):
  `config_show_boundary_id_does_not_create_files_or_directories` proves that
  `read_boundary_id` against an empty APM2 home does not create the `private/`,
  `private/fac/`, or `boundary_id` paths.

## Policy CLI Invariants (Updated for TCK-00561 fix round 2)

- **Stdin support** (`fac_policy.rs`): `apm2 fac policy validate` and `apm2 fac policy adopt`
  accept `<path|->` as an optional positional argument. When the argument is omitted or is `-`,
  input is read from stdin with bounded semantics (`MAX_POLICY_SIZE` cap via `take()` on the
  stdin handle, CTR-1603). Empty stdin returns an explicit error.
- **Operator identity resolution** (`fac_policy.rs`): `run_adopt` and `run_rollback` resolve
  the operator identity from `$USER` / `$LOGNAME` (POSIX), falling back to numeric UID on Unix
  via `nix::unistd::getuid()` (safe wrapper, no `unsafe` block). The identity is formatted as
  `operator:<username>` and passed to the core `adopt_policy`/`rollback_policy` APIs. The
  username is sanitized to `[a-zA-Z0-9._@-]` to prevent control character injection.
- **FAC root resolution** (`fac_policy.rs`): Uses shared `fac_utils::resolve_fac_root()` helper
  instead of a custom implementation with predictable `/tmp` fallback (RSK-1502).
- **Bounded file reads** (`fac_policy.rs`): `read_bounded_file` uses the open-once pattern
  (`O_NOFOLLOW | O_CLOEXEC` at `open(2)` + `fstat` + `take()`) to eliminate the TOCTOU gap
  between symlink validation and file read.

## Economics CLI Invariants (TCK-00584)

- **Hash-or-path input** (`fac_economics.rs`): `apm2 fac economics adopt` accepts
  `<hash|path|->` as an optional positional argument. When the argument starts with `b3-256:`,
  it is treated as a digest for hash-only adoption (validates `b3-256:<64-lowercase-hex>`
  format, records the hash directly without loading a profile file). When it is a path or `-`,
  input is read from file or stdin with bounded semantics (`MAX_ECONOMICS_PROFILE_SIZE` cap
  via `take()` on the stdin handle, CTR-1603). Auto-detects framed vs raw JSON input and adds
  domain framing if needed.
- **Operator identity resolution** (`fac_economics.rs`): `run_adopt` and `run_rollback`
  resolve the operator identity from `$USER` / `$LOGNAME` (POSIX), falling back to numeric
  UID on Unix via `nix::unistd::getuid()` (safe wrapper, no `unsafe` block). The identity
  is formatted as `operator:<username>` and passed to the core
  `adopt_economics_profile`/`rollback_economics_profile` APIs. The username is sanitized to
  `[a-zA-Z0-9._@-]` to prevent control character injection.
- **FAC root resolution** (`fac_economics.rs`): Uses shared `fac_utils::resolve_fac_root()`
  helper instead of a custom implementation with predictable `/tmp` fallback (RSK-1502).
- **Bounded file reads** (`fac_economics.rs`): `read_bounded_file` uses the open-once pattern
  (`O_NOFOLLOW | O_CLOEXEC` at `open(2)` + `fstat` + `take()`) to eliminate the TOCTOU gap
  between symlink validation and file read.
- **Patch hardening on worker path** (`fac_worker.rs`, TCK-00581 fix round 1):
  The `patch_injection` execution path now calls `apply_patch_hardened` instead of
  `apply_patch`, enforcing INV-PH-001 through INV-PH-010 (path traversal rejection,
  absolute path rejection, NUL byte rejection, size bounds, format validation).
  `PatchHardeningDenied` errors map to `DenialReasonCode::PatchHardeningDenied`
  with the denial receipt content hash included in the reason string. The denial
  receipt is also persisted as a standalone file under `fac_root/patch_receipts/`
  for provenance evidence. Lane cleanup runs before the job is moved to `denied/`.
- **Worker economics admission fail-closed** (`fac_worker.rs`, fix rounds 1-2): Step 2.6
  economics admission now branches on the specific error variant from
  `load_admitted_economics_profile_root`: `NoAdmittedRoot` denies the job if the policy's
  `economics_profile_hash` is non-zero (policy requires economics but no root exists to
  verify against — prevents bypass via root file deletion), skips only if the hash is zero
  (backwards compatibility for policies without economics requirements); successful load
  triggers constant-time hash comparison; any other error (I/O, corruption, schema
  mismatch, oversized file) denies the job with
  `DenialReasonCode::EconomicsAdmissionDenied`. Previously, all load errors were treated
  as "no root" which allowed admission bypass via root file tampering (INV-EADOPT-004).

## Metrics CLI (TCK-00551)

- **`apm2 fac metrics`** (`fac.rs`): Local-only observability command that computes
  aggregate metrics from FAC receipts. Accepts `--since <epoch_secs>`,
  `--until <epoch_secs>`, and `--json` flags. Default window is 24 hours
  (`DEFAULT_METRICS_WINDOW_SECS = 86_400`). Uses a two-pass approach: (1) iterate
  ALL receipt headers in the window for accurate aggregate counts and throughput,
  (2) load full receipts (capped at `MAX_METRICS_RECEIPTS = 16384`) for latency
  percentiles and denial-reason breakdowns. Passes `HeaderCounts` to
  `compute_metrics()` so aggregate metrics remain accurate even when full receipt
  loading is truncated. Sets `job_receipts_truncated` and `gc_receipts_truncated`
  flags in the output. Emits JSON only (TCK-00606 S12). Excluded from daemon
  auto-start and listed in `is_local_fac_command()`.

## Caches Nuke CLI (TCK-00592)

- **`apm2 fac caches nuke`** (`fac_caches.rs`): Explicit operator-only command to
  delete bulky FAC caches (lane targets, lane env dirs, cargo_home, sccache,
  gate_cache, gate_cache_v2, gate_cache_v3) with hard confirmations and audit
  receipts. Requires `--i-know-what-im-doing` flag (long form only) or interactive
  "yes" confirmation on a TTY. Fail-closed: denies on non-TTY without the flag.
  Supports `--dry-run` mode (JSON output of what would be deleted). Emits a
  `NukeReceiptV1` to `$APM2_HOME/private/fac/receipts/`. Uses `safe_rmtree_v1`
  for all deletions (INV-NUKE-004). NEVER deletes receipts/ or broker keys
  (INV-NUKE-001, INV-NUKE-002). All deletion paths validated against an explicit
  allow-list with protected directory exclusion (INV-NUKE-003). Excluded from
  daemon auto-start.
- **Receipt persistence is a hard success condition** (INV-NUKE-006): If
  `persist_nuke_receipt` fails, the command returns non-zero exit code and reports
  status as "failure" regardless of deletion outcomes. Destructive work without a
  durable audit trail is never reported as success.
- **No silent truncation of nuke targets**: The plan collects ALL deletion targets
  without truncation. If the plan exceeds `MAX_NUKE_TARGETS` (8192), the command
  fails closed with an explicit error. Per-directory scans are unbounded within the
  overall safety limit.
- **Gate cache coverage**: `FAC_GATE_CACHE_DIRS` constant lists `gate_cache`,
  `gate_cache_v2`, `gate_cache_v3`. These are added to the nuke plan when present
  under the FAC root, using the same allow-list validation and `safe_rmtree_v1`
  deletion as other cache targets.

## Binary Alignment Controls (TCK-00625, INV-PADOPT-004 followup)

Three engineering controls to prevent binary drift between interactive CLI and
systemd service executables:

### FU-001: Doctor binary_alignment check (`daemon.rs`)

- `collect_doctor_checks` now includes a `binary_alignment` check that:
  - Resolves `which apm2` to canonical path
  - Resolves `ExecStart` binary path for each systemd user unit via `systemctl --user show`
  - Computes SHA-256 digests of all resolved binary paths (bounded to 256 MiB, CTR-1603)
  - Emits `WARN` if any digest mismatches with remediation pointing to `apm2 fac install`
  - Emits `WARN` (never `OK`) if no service binary could be resolved (fail-closed)
  - Emits `WARN` for partial verification (some units resolved, others failed)
  - Emits `OK` only when at least one service binary was successfully resolved AND matched
  - Tracks per-unit resolution errors and digest failures separately

### FU-002: `apm2 fac install` subcommand (`fac_install.rs`)

- `apm2 fac install [--json] [--allow-partial] [--workspace-root <PATH>]` performs:
  1. Resolves workspace root from `--workspace-root` flag or from `current_exe()` path (never cwd)
  2. `cargo install --path crates/apm2-cli --force` from trusted workspace root
  3. Symlink `~/.local/bin/apm2 -> ~/.cargo/bin/apm2` (atomic replace via create-temp-then-rename(2))
  4. `systemctl --user restart apm2-daemon.service apm2-worker.service`
  5. Structured output: workspace root, installed path, SHA-256 digest, per-service restart status, restart_failures array
- Fail-closed restart semantics: required service restart failures cause non-zero exit and `success: false`
- `--allow-partial` flag: exits 0 even when restarts fail, but `success` remains false and `restart_failures` populated
- Workspace root discovery: derived from `std::env::current_exe()` (trusted) with 16-level bounded traversal; cwd never used
- Exempt from daemon auto-start (local command)

### FU-003: Worker binary identity event (`fac_worker.rs`)

- `run_fac_worker` emits a `binary_identity` event at startup before the poll loop:
  - `binary_path`: resolved via `std::env::current_exe()` + `canonicalize()`
  - `binary_digest`: `sha256:<hex>` of the running binary (bounded read, CTR-1603)
  - `pid`: current process ID
  - `ts`: ISO-8601 timestamp
- In JSON mode: emitted as NDJSON worker event
- In text mode: emitted as structured key=value to stderr at INFO level
- Non-fatal: digest failures produce error markers, not worker abort

## `fac_queue_submit.rs` — Queue Submission with Service User Gate (TCK-00577)

### Broker-mediated enqueue (TCK-00577)

`enqueue_job` now has two write paths:

1. **Direct path** (`enqueue_direct`): Used when the caller IS the service
   user or `--unsafe-local-write` is active. Writes directly to
   `queue/pending/` with full queue-bounds enforcement.

2. **Broker-mediated path** (`enqueue_via_broker_requests`): Used when the
   service user gate denies (caller is NOT the service user). Writes to
   `queue/broker_requests/` instead. The FAC worker (running as service
   user) promotes valid requests into `pending/` via `promote_broker_requests()`
   in `fac_worker.rs`.

### Broker promotion invariants (TCK-00577 round 2)

- **Queue bounds enforcement**: `promote_broker_requests` calls
  `check_queue_bounds` from `apm2_core::fac::queue_bounds` before each
  promotion. When the pending queue is at capacity, the broker request is
  quarantined with a denial log entry instead of promoted.
- **Enqueue lock discipline**: Each promotion acquires the same
  process-level lockfile (`queue/.enqueue.lock`) used by `enqueue_direct`
  to serialize the check-then-rename sequence. This prevents TOCTOU races
  between concurrent enqueue and promotion operations.
- **No-replace rename**: Promotion uses `move_to_dir_safe` (which
  internally uses `rename_noreplace`) instead of `fs::rename`. Filename
  collisions with existing pending jobs result in a collision-safe
  timestamped filename — existing pending jobs are never overwritten.
- **Fail-closed on lock acquisition failure**: If the enqueue lockfile
  cannot be acquired, the broker request is deferred to the next cycle
  (not promoted).

### Configured policy threading (TCK-00577 round 3)

- **Broker promotion enforces configured policy**: `promote_broker_requests`
  now receives the loaded `FacPolicyV1::queue_bounds_policy` from
  `run_fac_worker`. The hardcoded `QueueBoundsPolicy::default()` is replaced
  so that broker-mediated promotions enforce the same operator-configured
  limits as direct enqueue.

### Service-user ownership validation (TCK-00577 round 3)

- **Worker startup wires ownership check**: `run_fac_worker` validates that
  queue subdirectories (`pending/`, `claimed/`, `completed/`, `denied/`,
  `cancelled/`, `quarantine/`) and `receipts/` are owned by the configured
  FAC service user (via `validate_directory_service_user_ownership`). This
  check runs after directories are created but before the worker loop starts.
  Fail-closed: if the service user cannot be resolved or ownership deviates,
  the worker refuses to start.

### Relaxed startup validation for enqueue-class commands (TCK-00577 round 3)

- **Non-service-user callers reach broker fallback**: The FAC root permissions
  check at `run_fac` uses `validate_fac_root_permissions_relaxed_for_enqueue()`
  for enqueue-class commands (`Push`, `Gates`, `Warm`). This checks mode bits
  and symlink safety but NOT ownership, so non-service-user callers in a
  service-user-owned deployment can reach `enqueue_job` → broker fallback →
  `broker_requests/` (mode 01733). All other commands continue to use strict
  ownership validation.

### Permission hardening on enqueue paths (TCK-00577 round 8)

- **Queue root mode 0711**: Both `enqueue_direct` and
  `enqueue_via_broker_requests` explicitly set the queue root directory to
  mode 0711 after `create_dir_all`. This prevents world-listing of queue
  artifacts when the queue root is first created by an enqueue submission.
  Fail-closed: if `set_permissions` fails, the enqueue is rejected.
- **Pending dir mode 0711**: `enqueue_direct` explicitly sets the pending
  directory to mode 0711.
- **Broker requests mode 01733**: `enqueue_via_broker_requests` explicitly
  sets broker_requests/ to mode 01733 (fail-closed on error).

### ServiceUserNotResolved broker fallback (TCK-00577 round 8)

- **Broker fallback on unresolvable service user**: When
  `check_queue_write_permission` returns `ServiceUserNotResolved` in
  `ServiceUserOnly` mode, `enqueue_job` now falls back to broker-mediated
  enqueue (writes to `broker_requests/`) instead of returning a hard error.
  This allows `apm2 fac push` to succeed on systems where the service user
  has not been provisioned (fresh deployment, dev environment, CI). The
  worker (once provisioned) promotes requests from `broker_requests/` into
  `pending/`. For local-only workflows, inline gate fallback handles
  execution without a running worker.

### FIFO poisoning defense (TCK-00577 round 9)

- **Pre-open file type check**: `promote_broker_requests` calls
  `symlink_metadata()` (lstat) on each entry BEFORE calling `read_bounded`.
  Non-regular files (FIFOs, sockets, devices, symlinks) are quarantined
  without ever being opened. This prevents a local attacker with write
  access to the world-writable `broker_requests/` (mode 01733) from
  creating a FIFO named `*.json` that would block the worker indefinitely
  when opened without `O_NONBLOCK`.
- **Defense-in-depth O_NONBLOCK**: `fac_secure_io::read_bounded` now opens
  files with `O_NONBLOCK` in addition to `O_NOFOLLOW | O_CLOEXEC`. Even if
  the pre-open check were bypassed (TOCTOU between lstat and open), the
  `O_NONBLOCK` flag prevents the `open(2)` syscall from blocking on a FIFO.

### Worker/Broker preflight validation (TCK-00577 round 9)

- **Relaxed validation for Worker and Broker**: `run_fac` now routes
  `FacSubcommand::Worker` and `FacSubcommand::Broker` through the relaxed
  permission validator (`validate_fac_root_permissions_relaxed_for_enqueue`)
  instead of the strict validator. The worker itself sets queue directories
  to mode 0711 and `broker_requests/` to mode 01733 via `ensure_queue_dirs`.
  The strict validator (0700-only) rejects these intentional modes, causing
  worker restart to fail at preflight. The relaxed validator permits
  execute-only traversal bits while still rejecting read/write group/other.

### Non-service-user chmod avoidance (TCK-00577 round 9)

- **Create-only chmod**: `enqueue_via_broker_requests` now tracks whether
  directories existed before the call. For newly-created directories, it
  sets the intended mode (0711 for queue root, 01733 for `broker_requests/`).
  For pre-existing directories (owned by the service user), it validates the
  existing mode is acceptable instead of calling `chmod` (which returns
  EPERM for non-owner callers). This makes the broker fallback work for
  non-service-user processes in service-user deployments.
- **Fail-closed on unsafe pre-existing mode**: Pre-existing directories
  with group/other read bits are rejected with an actionable error message.

### General invariants

- The `broker_requests/` directory uses mode 01733 (sticky + write-only for
  group/other) so non-service-user callers can submit but cannot enumerate
  or tamper with other users' requests.
- Hard gate errors (invalid service user name, env var errors) are NOT
  recoverable via broker fallback and return immediate error.
- `run_push` and `run_blocking_evidence_gates` use the caller-provided
  `write_mode` (from `FacCommand::queue_write_mode()`), NOT a hardcoded
  `UnsafeLocalWrite`.
