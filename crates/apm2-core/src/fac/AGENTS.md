# Forge Admission Cycle (fac) Module

> Evidence gates, projection compromise detection, admission policy enforcement,
> and local broker authority for actuation tokens and economics envelopes.

## Overview

The `apm2_core::fac` module defines control-plane safety logic for admission and
projection integrity. It enforces fail-closed security checks around boundary
decisions, emits signed evidence for critical state transitions, and keeps
authoritative outcomes pinned to CAS+ledger trust roots.

This module includes RFC-0028 REQ-0009 controls for projection compromise
detection, quarantine, and replay recovery.

## broker Submodule (TCK-00510)

The `broker` submodule implements the FAC Broker service: the sole local
authority for issuing actuation tokens and economics/time authority envelopes in
default mode.

### Key Types

- `FacBroker`: The broker authority service. Owns an Ed25519 signing key and
  mutable broker state (tick counter, admitted digests, horizons). Not internally
  synchronized; callers must hold appropriate locks for concurrent access.
- `BrokerState`: Persisted broker state including schema metadata, monotonic tick
  counter, admitted policy digest set, freshness/revocation/convergence hashes,
  convergence receipts, and persisted `health_seq` counter. Serialized to
  canonical JSON. The `health_seq` field uses `#[serde(default)]` for backwards
  compatibility with state files predating TCK-00585.
- `BrokerError`: Fail-closed error taxonomy covering input validation, capacity
  limits, persistence, and deserialization failures.
- `BrokerSignatureVerifier`: Implements `SignatureVerifier` trait from
  `economics::queue_admission` using the broker's Ed25519 public key. Workers use
  this instead of `NoOpVerifier` in default mode.

### Core Capabilities

- RFC-0028 `ChannelContextToken` issuance bound to `job_spec_digest` + `lease_id`
  via `issue_channel_context_token()`.
- RFC-0029 `TimeAuthorityEnvelopeV1` issuance for `boundary_id` + evaluation
  window via `issue_time_authority_envelope()`.
- TP-EIO29-002 freshness horizon refs (`freshness_horizon()`) and revocation
  frontier snapshots (`revocation_frontier()`).
- TP-EIO29-003 convergence horizon refs (`convergence_horizon()`) and convergence
  receipts (`convergence_receipts()`, `add_convergence_receipt()`).
- Policy digest admission tracking (`admit_policy_digest()`,
  `is_policy_digest_admitted()`).
- State serialization/deserialization for persistence (`serialize_state()`,
  `deserialize_state()`).
- Verifying key publication (`verifying_key()`) for real signature verification.
- Worker admission health gate enforcement via
  `evaluate_admission_health_gate()`, the canonical production entry point
  for health-gated admission (TCK-00585).
- Health gate query via `is_admission_health_gate_passed()` for observability.

### Security Invariants (TCK-00510)

- [INV-BRK-001] The broker signing key is never exposed outside the broker
  process boundary. Only the `VerifyingKey` is published.
- [INV-BRK-002] All issued tokens and envelopes are cryptographically signed
  with the broker's Ed25519 key.
- [INV-BRK-003] Fail-closed: missing, stale, or ambiguous authority state
  results in denial.
- [INV-BRK-004] All in-memory collections are bounded by hard `MAX_*` caps
  (`MAX_ADMITTED_POLICY_DIGESTS=256`, `MAX_CONVERGENCE_RECEIPTS=64`).
- [INV-BRK-005] Broker state persistence uses atomic write (temp+rename).
- [INV-BRK-006] Horizon hashes are replay-stable (non-zero) in local-only mode
  via domain-separated BLAKE3 hashing.
- [INV-BRK-007] `deserialize_state()` enforces a strict I/O size limit
  (`MAX_BROKER_STATE_FILE_SIZE = 1 MiB`) **before** JSON parsing to prevent
  OOM from crafted state files with unbounded `Vec` payloads (RSK-1601).
- [INV-BRK-HEALTH-GATE-001] `issue_channel_context_token()` enforces a
  mandatory admission health gate as its first precondition. The gate is a
  boolean `admission_health_gate_passed` flag that is set to `true` only by
  `check_health()` returning `Healthy` or by a successful
  `evaluate_admission_health_gate()`. It defaults to `false` on construction
  and is cleared to `false` on any health check failure or gate evaluation
  failure. This ensures all production token issuance paths through the
  `FacBroker` API are health-gated (fail-closed). The flag is protected by
  the same external lock that guards `&mut self` / `&self` access; no
  interior mutability is used.
- [INV-BRK-008] FAC schema payload parsing uses bounded canonical JSON deserialization
  via `schema_registry::fac_schemas::bounded_from_slice_with_limit` and rejects
  non-canonical inputs.
- All hash comparisons use `subtle::ConstantTimeEq::ct_eq()` consistent with
  INV-PC-001, including `find_admitted_policy_digest()` which uses
  non-short-circuiting iteration.
- CTR-2501 deviation: `current_time_secs()` uses `SystemTime::now()` for token
  `issued_at` timestamps (wall-clock anchored expiry). Documented inline.
- CTR-HEALTH-001 deviation: `check_health()` and `evaluate_admission_health_gate()`
  do not follow PCAC lifecycle. They are control-plane safety predicates, not
  authority-bearing effects. Documented inline.

## scheduler_state Submodule (TCK-00531)

The `scheduler_state` submodule stores RFC-0029 anti-starvation continuity state.
Snapshots are persisted under `$APM2_HOME/private/fac/scheduler/state.v1.json`.

### Key Types

- `SchedulerStateV1`: Versioned, schema-checked snapshot of scheduler backlog and
  anti-starvation metadata.
- `LaneSnapshot`: Per-lane backlog and wait-time snapshot (`lane`, `backlog`,
  `max_wait_ticks`).
- `SCHEDULER_STATE_SCHEMA`: Canonical schema identifier for persisted state.

### Core Capabilities

- Atomic persistence with temp-file write + rename for crash safety.
- Bounded reads with metadata checks before deserialization (`1 MiB` max payload).
- Symlink-safe path handling for load and persist helpers.
- BLAKE3 content-hash computation and verification (`b3-256`).
- Conversion between in-memory `QueueSchedulerState` and persisted snapshots.

### Security Invariants (TCK-00531)

- [INV-SCH-001] Corrupt, oversize, or schema-mismatched scheduler state does
  not crash the worker and is treated as reconstruction required.
- [INV-SCH-002] Persisted scheduler state uses atomic durability guarantees
  (temp-file + rename).
- [INV-SCH-003] Unknown lane names, duplicates, and invalid backlog values are
  rejected during load.
- [INV-SCH-004] Restarted workers preserve anti-starvation continuity for
  `max_wait_ticks` via snapshot restoration.

## broker_health Submodule (TCK-00585)

The `broker_health` submodule implements RFC-0029 invariant health monitoring for
the FAC Broker. The broker periodically self-checks TP001/TP002/TP003 temporal
predicates and emits signed `HealthReceiptV1` receipts. Workers use a policy-driven
health gate to refuse job admission when broker health is degraded.

### Key Types

- `BrokerHealthStatus`: Three-state enum (`Healthy`, `Degraded`, `Failed`).
  Default is `Failed` (fail-closed). `Degraded` is reserved for future use and
  is not currently emitted by `BrokerHealthChecker::check_health`.
- `InvariantCheckResult`: Per-predicate check result carrying `predicate_id`,
  `passed` flag, and optional `deny_reason`. All string fields enforce bounded
  deserialization (`MAX_PREDICATE_ID_LENGTH=64`, `MAX_DENY_REASON_LENGTH=1024`).
- `HealthReceiptV1`: Signed health receipt containing schema metadata, status,
  broker tick, evaluation window hash, individual check results, content hash,
  Ed25519 signature, and signer identity. All string and Vec fields enforce
  bounded deserialization (SEC-CTRL-FAC-0016). `verify()` performs full
  payload-binding verification: recomputes canonical hash from payload fields
  and constant-time compares before signature check.
- `BrokerHealthError`: Error taxonomy for health check input bounds violations,
  validation failures, and verification failures.
- `HealthCheckInput`: Aggregated input bundle for health evaluation, including
  optional envelope, evaluation window, signature verifier, freshness/revocation/
  convergence horizons, convergence receipts, and required authority sets.
- `BrokerHealthChecker`: Stateful checker maintaining a bounded history ring
  (`MAX_HEALTH_HISTORY=64`) and a monotonic `health_seq` counter. Runs
  TP001/TP002/TP003 checks, signs receipts, and tracks history. The `health_seq`
  advances on every health check invocation (including error-path synthetic
  receipts), providing per-invocation freshness independent of broker tick.
  Returns `Result` to enforce input bounds. Can be restored from persisted state
  via `from_persisted_seq(health_seq)` using the `BrokerState::health_seq` value.
- `WorkerHealthPolicy`: Policy enum for worker admission gate. `StrictHealthy`
  (default) requires `Healthy`; `AllowDegraded` permits `Degraded`.
- `WorkerHealthGateError`: Fail-closed error taxonomy for worker health gate
  denial (no receipt, degraded, failed, verification failed, stale health
  sequence).

### Core Capabilities

- Delegates TP predicate validation to existing `economics::queue_admission`
  functions (`validate_envelope_tp001`, `validate_freshness_horizon_tp002`,
  `validate_convergence_horizon_tp003`).
- `FacBroker::check_health()` convenience method wires broker state into the
  health checker. Persists `health_seq` to `BrokerState` after each call.
  Returns `Result` for input bounds enforcement.
- `FacBroker::evaluate_admission_health_gate()` enforces policy-driven admission
  control using the broker's own `current_tick()` and `state.health_seq` as
  minimum floors (preventing caller-supplied staleness). Delegates to
  `evaluate_worker_health_gate()`.
- `evaluate_worker_health_gate()` enforces policy-driven admission control:
  verifies receipt existence, payload integrity (content hash recomputation +
  constant-time comparison), signature authenticity (via `BrokerSignatureVerifier`),
  evaluation window context binding (`expected_eval_window_hash`), receipt
  recency (`min_broker_tick`), health sequence freshness (`min_health_seq`),
  and health status against worker policy.
- Domain-separated BLAKE3 content hash (`apm2.fac_broker.health_receipt.v1`) over
  schema identity, tick, health_seq, eval window hash, status, and all per-check
  results with injective u64 length-prefix framing.
- Bounded deserialization on all string fields (`schema_id`, `schema_version`,
  `predicate_id`, `deny_reason`) and Vec fields (`checks`) during JSON parsing.
- Evaluation window hash included in receipt for boundary context binding.
- `compute_eval_window_hash()` is public for production callers to compute
  the expected `eval_window_hash` before calling the worker health gate.

### Security Invariants (TCK-00585)

- [INV-BH-001] Default `BrokerHealthStatus` is `Failed` (fail-closed). Missing
  or ambiguous health state denies admission.
- [INV-BH-002] Health receipts are Ed25519-signed by the broker key. Workers
  verify signature authenticity before trusting health status.
- [INV-BH-003] Worker health gate denies admission when no receipt exists, when
  verification fails, or when status violates policy.
- [INV-BH-004] All in-memory collections are bounded by hard `MAX_*` caps:
  `MAX_HEALTH_HISTORY=64`, `MAX_HEALTH_FINDINGS=16`,
  `MAX_HEALTH_REQUIRED_AUTHORITY_SETS=64`.
- [INV-BH-005] Health check input bounds are enforced before evaluation:
  `required_authority_sets` is capped at `MAX_HEALTH_REQUIRED_AUTHORITY_SETS`
  with explicit `Err` on overflow.
- [INV-BH-006] `HealthReceiptV1::verify()` recomputes the canonical content
  hash from all payload fields and constant-time compares it against the stored
  `content_hash` before signature verification. This binds the signature to all
  receipt payload fields, preventing post-signing field tampering. Schema ID and
  version are included in the canonical hash.
- [INV-BH-007] All string fields and Vec collections enforce bounded
  deserialization via visitor-based implementations that validate length BEFORE
  ownership allocation, preventing memory exhaustion from malformed JSON
  (RSK-1601, SEC-CTRL-FAC-0016). The `visit_str` path checks length before
  `to_owned()`, closing the Check-After-Allocate OOM-DoS vector.
- [INV-BH-008] Hash computation uses `u64::to_le_bytes()` length prefixes for
  injective framing of variable-length fields.
- [INV-BH-009] Evaluation window hash is included in the receipt payload for
  boundary context binding.
- [INV-BH-010] Worker health gate requires `expected_eval_window_hash` and
  rejects receipts generated for a different evaluation window (context binding,
  anti-replay). Uses constant-time comparison.
- [INV-BH-011] Worker health gate requires `min_broker_tick` and rejects
  receipts with stale broker ticks (recency enforcement, anti-replay).
- [INV-BH-012] On health check input validation errors, a synthetic FAILED
  receipt is persisted so downstream gates cannot continue on a stale HEALTHY
  receipt. The synthetic receipt carries a machine-readable reason.
- [INV-BH-013] A monotonically increasing `health_seq` counter in
  `BrokerHealthChecker` advances on every health check invocation (including
  error-path synthetic receipts). The counter is included in each
  `HealthReceiptV1` and bound into the content hash via `u64::to_le_bytes()`.
  The worker health gate enforces `receipt.health_seq >= min_health_seq` to
  prevent same-tick replay attacks where an old HEALTHY receipt is presented
  after health has degraded but the broker tick has not advanced.
- [INV-BH-014] The `health_seq` counter uses `checked_add` (not
  `wrapping_add`) to detect overflow at `u64::MAX`. On overflow, a synthetic
  FAILED receipt is persisted (SEQ_OVERFLOW predicate) and
  `BrokerHealthError::HealthSeqOverflow` is returned. This is a terminal
  condition requiring broker key/epoch rotation (fail-closed). Synthetic
  receipts in error paths use `saturating_add` to cap at `u64::MAX` without
  wrapping.
- [INV-BH-015] `FacBroker::evaluate_admission_health_gate()` is the
  canonical production entry point for worker admission health gating.
  It wires the broker's verifying key, computes the expected eval window
  hash, and uses `self.current_tick()` and `self.state.health_seq` as
  minimum floors (preventing caller-supplied staleness). Both
  `evaluate_admission_health_gate()` and `check_health()` update the
  broker's `admission_health_gate_passed` flag, which is enforced by
  `issue_channel_context_token()` as a mandatory precondition
  (INV-BRK-HEALTH-GATE-001). `check_health()` also persists
  `health_seq` to `BrokerState` after each call so the counter survives
  daemon restarts. This ensures health gate enforcement is
  active on ALL production admission/token issuance paths through the
  `FacBroker` API.

## broker_health_ipc Submodule (TCK-00600)

The `broker_health_ipc` submodule implements a file-based IPC endpoint for
exposing broker health, version, and readiness to the CLI. The daemon writes
`broker_health.json` after each poller-loop health evaluation; `apm2 fac
services status` reads it to determine broker health independently of systemd
unit state.

### Key Types

- `BrokerHealthIpcV1`: Schema-versioned health status payload with daemon
  version, readiness flag, PID, epoch timestamp, uptime, health status string,
  and optional reason. Uses `deny_unknown_fields` for forward-compatibility
  safety.
- `BrokerHealthIpcStatus`: Read result with freshness evaluation. Carries
  `found`, `fresh`, `ready`, `version`, `pid`, `age_secs`, `uptime_secs`,
  `health_status`, and optional `error`. Stale status (age > 180s) forces
  `ready=false` and `health_status="stale"`.

### Core Functions

- `write_broker_health(fac_root, version, ready, uptime_secs, health_status,
  reason)`: Atomic write (temp+rename) to `<fac_root>/broker_health.json`.
  Called by the daemon's poller loop after each health gate evaluation.
- `read_broker_health(fac_root)`: Bounded read with O_NOFOLLOW + O_NONBLOCK +
  fstat regular-file check + staleness detection. Returns
  `BrokerHealthIpcStatus` (never errors; missing/corrupt files return defaults).

### Security Invariants (TCK-00600)

- [INV-BHI-001] Health status files are bounded to `MAX_BROKER_HEALTH_FILE_SIZE`
  (4 KiB) when read, preventing OOM from crafted files.
- [INV-BHI-002] Health status file reads use bounded I/O with `O_NOFOLLOW |
  O_NONBLOCK | O_CLOEXEC` (Linux) per CTR-1603 and RS-31. Non-regular files
  (FIFOs, devices, sockets) are rejected via fstat after open.
- [INV-BHI-003] Health status writes use atomic write (temp + rename) to prevent
  partial reads.
- [INV-BHI-004] Health status is not authoritative for admission or security
  decisions. It is an observability signal only. The authoritative broker health
  gate is in `broker_health.rs`.

## broker_rate_limits Submodule (TCK-00568)

The `broker_rate_limits` submodule implements RFC-0029 control-plane budget
admission for the FAC Broker. It bounds token issuance, queue enqueue operations,
queue byte throughput, and bundle export byte throughput using configurable limits
with hard caps.

### Key Types

- `ControlPlaneLimits`: Configuration struct with per-dimension limits and hard
  cap validation. Validated via `validate()` before use. Defaults: 10K tokens,
  100K enqueue ops, 10 GiB queue bytes, 10 GiB bundle export bytes.
- `ControlPlaneBudget`: Cumulative counter tracker. Enforces admission-before-mutation
  ordering (INV-CPRL-002). Provides `admit_token_issuance()`,
  `admit_queue_enqueue(ops, bytes)`, and `admit_bundle_export(bytes)` methods.
- `ControlPlaneDenialReceipt`: Structured denial evidence carrying dimension,
  current usage, limit, and requested increment.
- `ControlPlaneDimension`: Enum identifying the budget dimension that was exceeded
  (`TokenIssuance`, `QueueEnqueueOps`, `QueueEnqueueBytes`, `BundleExportBytes`).
- `ControlPlaneBudgetError`: Error taxonomy with `InvalidLimits` and
  `BudgetExceeded` variants. `BudgetExceeded` carries a human-readable reason
  string and a `ControlPlaneDenialReceipt`.

### Hard Caps

- `MAX_TOKEN_ISSUANCE_LIMIT`: 1,000,000
- `MAX_QUEUE_ENQUEUE_LIMIT`: 1,000,000
- `MAX_QUEUE_BYTES_LIMIT`: 64 GiB
- `MAX_BUNDLE_EXPORT_BYTES_LIMIT`: 64 GiB

### Core Capabilities

- Budget admission with `checked_add` arithmetic to prevent counter overflow
  (INV-CPRL-004).
- Fail-closed semantics: zero limits deny all operations immediately
  (INV-CPRL-003).
- Admission-before-mutation ordering: counters only advance on successful
  admission (INV-CPRL-002).
- Hard cap validation prevents misconfiguration above system safety bounds
  (INV-CPRL-001).
- `reset()` clears all counters for window advancement boundaries.
- Serialization round-trip via `serde` for persistence and observability.

### Broker Integration

- `FacBroker` holds a `ControlPlaneBudget` field initialized from default or
  custom limits.
- `issue_channel_context_token()` calls `admit_token_issuance()` before input
  validation (fail-closed gate).
- `admit_queue_enqueue(bytes)` and `admit_bundle_export(bytes)` are public
  methods on `FacBroker` for callers to gate queue and export operations.
- `reset_control_plane_budget()` resets counters at tick advancement boundaries.
- `BrokerError::ControlPlaneBudgetDenied` variant propagates budget errors.
- `DenialReasonCode::ControlPlaneBudgetDenied` variant for receipt integration.

### Security Invariants (TCK-00568)

- [INV-CPRL-001] Limits exceeding hard caps are rejected at construction time.
- [INV-CPRL-002] Counters advance only after successful admission check
  (admission-before-mutation).
- [INV-CPRL-003] Zero limits deny all operations immediately (fail-closed).
- [INV-CPRL-004] All counter arithmetic uses `checked_add`; overflow produces a
  denial receipt, never wrapping.
- [INV-CPRL-005] Budget denial always produces a structured
  `ControlPlaneDenialReceipt` with machine-readable evidence.

## projection_compromise Submodule

The `projection_compromise` submodule implements compromise handling for public
projection surfaces.

### Key Types

- `ProjectionCompromiseError`: Fail-closed error taxonomy for compromise,
  quarantine, and replay-recovery paths.
- `ProjectionChannel`: Projection endpoint descriptor with expected digest and
  quarantine status.
- `ProjectionDivergence`: Digest-bound divergence evidence used to justify
  containment.
- `ProjectionCompromiseSignalV1`: Signed quarantine signal carrying temporal
  authority bindings (`time_authority_ref`, `window_ref`).
- `ProjectionReplayReceiptV1`: Signed durable receipt for replay-based
  reconstruction.
- `SourceTrustSnapshotV1` and `ChannelIdentitySnapshotV1`: Authoritative and
  observed trust snapshots used for divergence and replay validation.
- `ReplaySequenceBoundsV1`: Required contiguous replay range contract.
- `ReconstructedProjectionState`: Deterministic replay output used to verify
  recovery correctness.
- `AuthorityKeyBindingV1`: Trusted signer binding used to validate replay
  receipts.

### Core Controls (RFC-0028 REQ-0009)

- Detect projection divergence against expected CAS+ledger-derived digests.
- Quarantine compromised channels without mutating authoritative trust roots.
- Require signed temporal authority references for compromise decisions.
- Reconstruct projection state from trusted, ordered, signature-verified
  receipts.

### Security Invariants (TCK-00469)

- [INV-PC-001] All cryptographic digest comparisons (expected vs. observed,
  temporal authority refs, window refs, source/sink snapshot digests) use
  `subtle::ConstantTimeEq::ct_eq()` to prevent timing side-channel leakage.
  Variable-time `==`/`!=` on `[u8; 32]` hash values is prohibited in this
  module.

## safe_rmtree Submodule (TCK-00516)

The `safe_rmtree` submodule implements a symlink-safe recursive tree
deletion primitive for lane cleanup and reset operations.

### Key Types

- `SafeRmtreeError`: Fail-closed error taxonomy covering symlink detection,
  boundary violations, filesystem crossing, unexpected file types, permission
  errors, TOCTOU race detection, depth limits, dot-segment rejection, and
  I/O failures.
- `SafeRmtreeOutcome`: Success outcome enum (`Deleted` with file/dir counts,
  or `AlreadyAbsent` for no-op on nonexistent roots).
- `RefusedDeleteReceipt`: Machine-readable evidence for audit trails when
  lane cleanup is refused and the lane should be marked CORRUPT.
- `EntryKind`: Internal enum (`Directory`, `RegularFile`) for fd-relative
  entry type classification.

### Core Capabilities

- `safe_rmtree_v1(root, allowed_parent)`: Primary entry point. Validates
  absolute paths, dot-segment rejection (`.` and `..` components),
  component-wise boundary enforcement, parent ownership validation
  (uid + mode 0o700), and depth-bounded bottom-up deletion.
- On Unix, walks from `allowed_parent` to `root` component-by-component
  using `Dir::openat(O_NOFOLLOW)` at each step (ancestor chain walk). This
  eliminates the TOCTOU gap between symlink validation and root open: every
  `openat` with `O_NOFOLLOW` atomically refuses symlinks at the kernel level.
  The root entry is then operated on via the parent fd (fstatat/openat/
  unlinkat). All recursive operations use:
  - `Dir::openat(parent_fd, name, O_NOFOLLOW | O_DIRECTORY)` for child dirs
  - `unlinkat(parent_fd, name, NoRemoveDir)` for file deletion
  - `unlinkat(parent_fd, name, RemoveDir)` for directory deletion
  - `fstatat(parent_fd, name, AT_SYMLINK_NOFOLLOW)` for type classification
  No `std::fs::read_dir`, `std::fs::remove_dir`, `std::fs::remove_file`, or
  path-based `Dir::open` is used in the recursive delete path.
- `fd_relative_recursive_delete(parent_dir, parent_path, stats, depth,
  root_dev)`: Streaming iteration -- processes entries one-by-one without
  collecting into a Vec, preventing unbounded memory growth. Takes an
  already-open `&nix::dir::Dir` fd. The `parent_path` argument is used ONLY
  for error messages, never for opens or deletes.
- `open_path_via_ancestor_chain(base, components, flags)`: Walks from `base`
  through `components` using `openat(O_NOFOLLOW)` at each step, returning
  the final directory fd. Eliminates TOCTOU between symlink validation and
  directory open.
- `process_entry()`: Processes a single directory entry (recurse into dirs,
  unlink files) via fd-relative operations.
- `reject_dot_segments()`: Rejects (not filters) any path containing `.` or
  `..` components. On Unix, also checks raw path bytes for `/./` and trailing
  `/.` patterns that `Path::components()` silently normalizes away.
- `verify_same_dev_via_fd()`: Compares `st_dev` via `fstat` on the fd (not
  the path) against the root device ID to avoid TOCTOU in filesystem boundary
  checks.
- `classify_dirent_type()`: Classifies `nix::dir::Type` into `EntryKind`,
  returning errors for symlinks and unexpected file types.
- `resolve_entry_kind_via_fstatat()`: Resolves unknown entry types via
  `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the parent dir fd.
- Used by `apm2 fac lane reset` CLI command to safely delete workspace,
  target, and logs subdirectories. The lane reset command acquires an
  exclusive lane lock before any status reads or mutations, holding it across
  the entire operation. On safety violations, the CLI persists a
  `LaneLeaseV1` with `state: Corrupt` to the lane directory for durable
  corruption marking.
- `kill_process_best_effort(pid)`: Returns `bool` indicating success. Verifies
  PID existence via `/proc/<pid>/comm` before signaling (PID reuse safety).
  Handles EPERM and other errors by returning `false` (fail-closed). If kill
  fails, `run_lane_reset` aborts and marks the lane CORRUPT.

### Security Invariants (TCK-00516)

- [INV-RMTREE-001] Symlink detected at any depth causes immediate abort.
  Enforced at the kernel level via `O_NOFOLLOW` on Unix.
- [INV-RMTREE-002] `root` must be strictly under `allowed_parent` by
  component-wise validation (NOT string prefix).
- [INV-RMTREE-003] Cross-filesystem deletion refused by `st_dev` comparison.
  On Unix, uses `fstat` on the opened fd to avoid TOCTOU.
- [INV-RMTREE-004] Unexpected file types (sockets, FIFOs, devices) abort.
- [INV-RMTREE-005] Both paths must be absolute.
- [INV-RMTREE-006] `allowed_parent` must be owned by current user with
  mode 0o700 (no group/other access).
- [INV-RMTREE-007] Non-existent root is a successful no-op.
- [INV-RMTREE-008] Traversal depth bounded by `MAX_TRAVERSAL_DEPTH=128`.
- [INV-RMTREE-009] Directory entries bounded by `MAX_DIR_ENTRIES=10000`.
- [INV-RMTREE-010] Paths containing `.` or `..` components are rejected
  immediately (not filtered). On Unix, raw byte scanning catches `.`
  segments that `Path::components()` silently normalizes away.

### Lane Cleanup State Machine (TCK-00569)

Lane cleanup is part of the authoritative execution lifecycle and uses
`LaneCorruptMarkerV1` for durable fault marking.

**Lifecycle invariant**: A RUNNING `LaneLeaseV1` must be persisted before
any execution begins. The lease is created after lane acquisition and lane
profile loading, binding the current PID, job ID, and lane profile hash.
This ensures the cleanup state machine in `run_lane_cleanup` can verify
its RUNNING-state precondition. On every terminal path (denial, skip,
completion), the lease is removed or transitioned coherently.

**Cleanup ordering**: Lane cleanup runs AFTER job completion (receipt
emission + move to completed/). Cleanup failures do not change the job
outcome; they only mark the lane as Corrupt. This decouples job execution
integrity from infrastructure lifecycle management.

**Cleanup steps**: (1) `git_reset`, (2) `git_clean`, (3) `temp_prune`,
(3b) `env_dir_prune` (TCK-00575: prune `home/`, `xdg_cache/`,
`xdg_config/` via `safe_rmtree_v1`; `tmp/` is already handled by step 3),
(4) `log_quota`.

**Process liveness**: Stale lease detection uses `libc::kill(pid, 0)` with
errno discrimination: ESRCH = dead (safe to recover), EPERM = alive but
unpermissioned (mark corrupt), success = alive (mark corrupt if flock held
by another worker).

### Security Invariants (TCK-00569)

- [INV-LANE-CLEANUP-001] Every lane cleanup attempt emits a
  `LaneCleanupReceiptV1`, including failures.
- [INV-LANE-CLEANUP-002] Cleanup failure must persist `LaneCorruptMarkerV1` with
  `reason` and optional `cleanup_receipt_digest` before transitioning the lane to
  Corrupt state.
- [INV-LANE-CLEANUP-003] `LaneStatusV1` must expose `corrupt_reason` derived
  from any persistent corrupt marker.
- [INV-LANE-CLEANUP-004] Lane log retention is enforced by oldest-first file
  pruning to `MAX_LOG_QUOTA_BYTES`.
- [INV-LANE-CLEANUP-004a] `collect_log_entries` bounds per-directory breadth
  by `MAX_DIR_ENTRIES` (10,000, matching INV-RMTREE-009). Exceeding the limit
  returns `Err` with a DoS-prevention reason, preventing directory-flood
  resource exhaustion.
- [INV-LANE-CLEANUP-005] A RUNNING `LaneLeaseV1` must be persisted before
  job execution and removed on every terminal path.
- [INV-LANE-CLEANUP-006] Job completion (Completed receipt + move to completed/)
  must precede lane cleanup. Cleanup failure must not negate a completed job.
- [INV-LANE-CLEANUP-007] Corrupt marker persistence uses crash-safe durability:
  fsync temp file, atomic rename, fsync directory.
- [INV-LANE-CLEANUP-007a] Receipt persistence (`LaneCleanupReceiptV1::persist`)
  uses the atomic write protocol (CTR-2607): `NamedTempFile` with restrictive
  permissions (0o600 on Unix), `sync_all()` for durability, then atomic rename.
  This matches the durable write pattern used by `LaneCorruptMarkerV1::persist`
  via `atomic_write` in `lane.rs`.
- [INV-LANE-CLEANUP-008] Git commands in lane cleanup use config isolation to
  prevent LPE via malicious `.git/config` entries. `build_isolated_git_command()`
  sets `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, and overrides
  `core.fsmonitor=`, `core.pager=cat`, `core.editor=:` via `-c` flags. This
  prevents a malicious job from planting executable config hooks that would run
  with worker privileges during `git reset` or `git clean`.
- [INV-LANE-CLEANUP-009] Post-checkout denial paths (checkout failure, patch
  failure, containment failure, unsupported source kind) must invoke
  `execute_lane_cleanup` instead of merely removing the lease. This ensures the
  workspace is restored to a clean state and prevents cross-job contamination.
  Cleanup failure on denial paths results in CORRUPT lane marking, same as the
  success path.

### `repo_mirror` — Node-Local Bare Mirror + Lane Checkout

**Core type**: `RepoMirrorManager`
- Manages bare git mirrors under `$APM2_HOME/private/fac/repo_mirror/<repo_id>.git`
- Bounded mirror count: MAX_MIRROR_COUNT (64), LRU eviction
- Symlink-safe: uses `core.symlinks=false` for all checkouts
- Command injection prevention: URL protocol allowlist, `--` separators

**Key methods**:
- `ensure_mirror(repo_id, remote_url)` — Initialize or update bare mirror
- `checkout_to_lane(repo_id, head_sha, workspace, allowed_parent)` — Checkout specific SHA to lane workspace
- `apply_patch(workspace, patch_bytes)` — Apply patch via stdin to git apply, returns BLAKE3 digest

**Security invariants**:
- All git commands use `std::process::Command` (no shell expansion)
- `GIT_TERMINAL_PROMPT=0` prevents interactive prompts
- `core.symlinks=false` prevents symlink creation in workspaces
- `--no-hardlinks` prevents object sharing between mirror and workspace
- Path traversal prevention delegated to `git apply` (standard git safety)

### `execution_backend` — System-mode and user-mode execution backend selection (TCK-00529)

The `execution_backend` submodule implements backend selection for FAC job
execution. On headless VPS environments without a user D-Bus session, jobs
run via `systemd-run --system` with a dedicated service user instead of
`systemd-run --user`.

**Core types**:
- `ExecutionBackend`: Enum with `UserMode` and `SystemMode` variants.
- `SystemModeConfig`: Configuration for system-mode (service user).
- `SystemdRunCommand`: Fully constructed `systemd-run` command specification.

**Key functions**:
- `select_backend()`: Read `APM2_FAC_EXECUTION_BACKEND` env var (`user` |
  `system` | `auto`). Auto-mode probes for user bus availability and falls
  back to system-mode.
- `select_and_validate_backend()`: Like `select_backend()` but validates
  prerequisites (user bus exists for user-mode).
- `build_systemd_run_command()`: Construct the `systemd-run` command for
  either backend with properties from `SystemdUnitProperties`.
- `probe_user_bus()`: Check whether a user D-Bus session bus socket exists.
- `ExecutionBackendError::is_platform_unavailable()`: Classifies errors as
  platform-unavailable (acceptable fallback to uncontained) vs configuration
  errors (fail-closed denial). Platform-unavailable: `UserModeUnavailable`,
  `SystemModeUnavailable`, `SystemdRunNotFound`, `CgroupV2Unavailable`.
  All other variants are configuration errors. Used by warm containment
  setup to enforce fail-closed policy.

**Environment variables**:
- `APM2_FAC_EXECUTION_BACKEND`: `user` | `system` | `auto` (default: `auto`)
- `APM2_FAC_SERVICE_USER`: Service user for system-mode (default: `_apm2-job`)

**Security invariants**:
- [INV-EXEC-001] Backend selection is fail-closed: invalid config → `Err`.
- [INV-EXEC-002] System-mode always sets `User=` property; user-mode never
  does.
- [INV-EXEC-003] Service user name is validated (alphanumeric/dash/underscore,
  bounded length).
- [INV-EXEC-004] Environment variable reads use bounded-length validation.
- [INV-EXEC-005] Command construction is deterministic for same inputs.

### `systemd_properties` — Authoritative lane→systemd unit property mapping

The `systemd_properties` submodule is the single translation layer from
`LaneProfileV1` + `JobConstraints` into executable unit constraints for both
user-mode and system-mode execution backends.

## Core Type

**Core type**: `SystemdUnitProperties`

- Canonical fields:
  - `cpu_quota_percent` → `CPUQuota`
  - `memory_max_bytes` → `MemoryMax`
  - `tasks_max` → `TasksMax`
  - `io_weight` → `IOWeight`
  - `timeout_start_sec` → `TimeoutStartSec`
  - `runtime_max_sec` → `RuntimeMaxSec`
  - `kill_mode` → `KillMode` (default `control-group`)
- Input binding:
  - `from_lane_profile(&LaneProfileV1, Option<&JobConstraints>)`
- Override semantics:
  - `memory_max_bytes` and `test_timeout_seconds` use MIN(job, lane).

## Rendering API

- `to_unit_directives() -> String`: `[Service]` section directives.
- `to_dbus_properties() -> Vec<(String, String)>`: serializable property
  key/value pairs for transient-unit invocation.

## Security Invariants (TCK-00530)

- [INV-SYS-001] Unit limits are generated from persisted lane profile defaults
  or authoritative overrides only; no duplicated ad-hoc calculations in caller
  sites.
- [INV-SYS-001a] Lane-default resource caps enforce a `48 GiB` memory ceiling
  before job constraints; lane constraints cannot raise `MemoryMax` above this
  profile floor.
- [INV-SYS-001b] Lane/default test timeout baseline is `600s` (`MAX_TEST_TIMEOUT_SECONDS`)
  and maps directly to `TimeoutStartSec`; callers must not reintroduce ad-hoc
  `240s` defaults in lane/profile fallback paths.
- [INV-SYS-002] `JobConstraints` values are applied with lane ceiling semantics
  (`min`) so a job cannot increase resource or timeout limits above lane
  defaults.
- [INV-SYS-003] `LaneProfileV1` loading failures fail the job path as a denial
  with machine-readable receipt output, not silent continuation.

## evidence_bundle Submodule (TCK-00527, TCK-00542)

The `evidence_bundle` submodule implements evidence bundle export/import commands
exercising RFC-0028 boundary validation and RFC-0029 receipt validation (local-only).
It also provides a manifest+envelope schema pair for bundle discovery, indexing,
and content-addressed integrity verification (TCK-00542).

### Key Types

- `EvidenceBundleEnvelopeV1`: Self-describing envelope containing a job receipt,
  RFC-0028 boundary check reconstruction data, RFC-0029 economics traces, optional
  policy binding, blob references, and a BLAKE3 content hash. Accepts both legacy
  schema `apm2.fac.evidence_bundle.v1` and canonical schema
  `apm2.fac.evidence_bundle_envelope.v1` on import (backwards compatible).
- `BundleBoundaryCheckV1`: RFC-0028 boundary check reconstruction data carrying all
  fields required by `validate_channel_boundary()`.
- `BundleEconomicsTraceV1`: RFC-0029 economics traces (queue admission + budget
  admission).
- `BundleExportConfig`: Configuration for export carrying optional boundary-check
  substructures (leakage budget, timing channel, disclosure policy, policy binding).
- `EvidenceBundleManifestV1` (TCK-00542): Lightweight outer manifest document for
  bundle discovery and indexing. References the envelope by its content hash, carries
  summary metadata (job_id, outcome, timestamp), a `channel_boundary_checked` flag,
  and a bounded list of manifest entries. Uses `#[serde(deny_unknown_fields)]` for
  strict parsing at the import boundary.
- `EvidenceBundleManifestEntryV1` (TCK-00542): Single entry in a manifest describing
  an evidence artifact by its role, content hash reference, and description. Uses
  `#[serde(deny_unknown_fields)]` for strict parsing.

### Core Capabilities

- `build_evidence_bundle_envelope()`: Builds an envelope from a job receipt and
  export config. Requires RFC-0028 boundary trace, RFC-0029 queue admission trace,
  and RFC-0029 budget admission trace in the receipt (fail-closed on missing traces).
  Computes BLAKE3 content hash with domain-separated, length-prefixed encoding over
  ALL envelope fields using `canonical_bytes_v2()` for the receipt (which includes
  `unsafe_direct`, `policy_hash`, and `canonicalizer_tuple_digest`), plus boundary
  check, economics trace, policy binding, and blob refs.
- `serialize_envelope()`: Serializes the envelope to JSON bytes.
- `import_evidence_bundle()`: Imports and validates an envelope from JSON bytes.
  Enforces: bounded read (MAX_ENVELOPE_SIZE=256 KiB), schema verification,
  per-field length bounds (MAX_JOB_ID_LENGTH, MAX_BLOB_REF_LENGTH), content
  hash integrity, RFC-0028 boundary validation (core defects required zero;
  honestly-absent optional sub-evidence tolerated), RFC-0029 economics receipt
  validation (Allow verdicts required), and policy binding digest matching
  (including cross-field consistency with receipt's policy_hash and
  canonicalizer_tuple_digest).
- `verify_blob_refs()`: Verifies all blob_refs in an imported envelope exist in the
  bundle directory and their BLAKE3 hashes match declared values. Bounded reads,
  path traversal prevention, constant-time hash comparison.
- `build_evidence_bundle_manifest()` (TCK-00542): Builds a manifest from an envelope
  and optional additional entries. Enforces channel boundary check requirement
  (fail-closed on Unknown source with broker_verified=false). Constructs default
  entries for the envelope and each blob reference. Enforces `MAX_MANIFEST_ENTRIES`
  bound. Computes BLAKE3 content hash with domain-separated, length-prefixed encoding
  over all manifest fields.
- `serialize_manifest()` (TCK-00542): Serializes a manifest to JSON bytes.
- `import_evidence_bundle_manifest()` (TCK-00542): Imports and validates a manifest
  from JSON bytes. Enforces: bounded read (MAX_MANIFEST_SIZE=64 KiB), schema
  verification, entry count bound, per-field length bounds (MAX_JOB_ID_LENGTH,
  MAX_OUTCOME_REASON_LENGTH, MAX_ENVELOPE_HASH_REF_LENGTH, MAX_ENTRY_DESCRIPTION_LENGTH),
  content hash integrity (constant-time comparison), and channel_boundary_checked=true
  requirement.

### CLI Commands

- `apm2 fac bundle export <job_id>`: Exports an evidence bundle for a job to
  `$APM2_HOME/private/fac/bundles/<job_id>/`. Validates `job_id` before path
  construction: rejects empty strings, absolute paths, `..` traversal, path
  separators, and any characters outside `[A-Za-z0-9._-]` (path confinement).
  Creates output directory with 0700 mode via `fac_permissions::ensure_dir_with_mode`.
  Writes all files (envelope, blobs) via `fac_permissions::write_fac_file_with_mode`
  (0600 mode, `O_NOFOLLOW`, symlink check). Constructs `BundleExportConfig`
  from authoritative receipt artifacts (policy binding only); leakage budget receipt,
  timing channel budget, and disclosure policy binding are honestly marked absent
  (None) because they do not exist in `FacJobReceiptV1`. Fail-closed on malformed
  policy digests: if `policy_hash` or `canonicalizer_tuple_digest` is absent or
  cannot be decoded to a verified 32-byte digest, export returns
  `MalformedPolicyDigest` error instead of fabricating a placeholder. Discovers
  and exports receipt/spec blobs from the blob store; blob retrieval or write
  failures are fatal (`BlobExportFailed` error).
- `apm2 fac bundle import <path>`: Imports and validates an evidence bundle from a
  file path. Opens with `O_NOFOLLOW` (no symlink following), validates regular file
  via `fstat`, uses bounded streaming read from the same handle (no TOCTOU).
  Rejects bundles that fail RFC-0028 or RFC-0029 validation (fail-closed).
  Verifies all blob_refs exist in the bundle directory and their BLAKE3 hashes
  match declared values (fail-closed on missing or corrupt blobs).

### Security Invariants (TCK-00527)

- [INV-EB-001] Import refuses when `validate_channel_boundary()` returns any
  non-tolerated defects (boundary check invalid or policy binding mismatched).
  Defects from honestly-absent optional sub-evidence (leakage budget, timing
  budget, disclosure policy) are filtered when the corresponding field is None.
- [INV-EB-002] Import refuses when economics receipt traces are missing,
  unverifiable, or carry non-Allow verdicts.
- [INV-EB-003] Envelope reads are bounded by `MAX_ENVELOPE_SIZE` (256 KiB) before
  deserialization. Import uses single-handle open + `fstat` + `Read::take` (no
  TOCTOU between size check and read).
- [INV-EB-004] Envelope content hash uses `canonical_bytes_v2()` which binds ALL
  receipt fields including `unsafe_direct`, `policy_hash`, and
  `canonicalizer_tuple_digest`. Every variable-length field uses length-prefix
  encoding for deterministic framing. Verified via constant-time comparison.
- [INV-EB-005] All collection and string fields are bounded
  (MAX_BUNDLE_BLOB_COUNT=256, MAX_JOB_ID_LENGTH=256, MAX_BLOB_REF_LENGTH=256).
- [INV-EB-006] Policy binding digest matching uses constant-time comparison
  (`subtle::ConstantTimeEq::ct_eq()`), including cross-field consistency checks
  between `receipt.policy_hash` / `receipt.canonicalizer_tuple_digest` and
  `policy_binding` digest fields.
- [INV-EB-007] Import opens files with `O_NOFOLLOW` (Unix) to refuse symlinks at the
  kernel level and validates regular file type via `fstat` on the opened handle.
- [INV-EB-008] Export fails closed when `policy_hash` or `canonicalizer_tuple_digest`
  is absent or malformed (non-hex, wrong length). Returns `MalformedPolicyDigest`
  instead of fabricating placeholder digests.
- [INV-EB-009] Export fails closed when referenced blobs (content_hash, job_spec_digest)
  cannot be retrieved from the blob store or written to the output directory. Returns
  `BlobExportFailed` instead of silently producing an incomplete bundle.
- [INV-EB-010] Export validates `job_id` before path construction: rejects empty,
  absolute paths, `..` traversal, path separators, and non-`[A-Za-z0-9._-]` characters.
  Prevents path confinement escape from FAC root.
- [INV-EB-011] Export creates output directories with mode 0700 via
  `fac_permissions::ensure_dir_with_mode` and writes all files with mode 0600 via
  `fac_permissions::write_fac_file_with_mode` (`O_NOFOLLOW`, symlink check, atomic
  rename). Never uses `std::fs::create_dir_all` or `std::fs::write` for bundle output.
- [INV-EB-012] Import verifies all `blob_refs` exist in the bundle directory and their
  BLAKE3 hashes match declared values. Missing or corrupt blobs cause import failure
  (fail-closed). Blob reads are bounded by `MAX_BLOB_IMPORT_SIZE` (10 MiB).
- [INV-EB-013] Export only includes evidence that actually exists in the source
  receipt. Leakage budget receipt, timing channel budget, and disclosure policy
  binding are marked absent (None) when not present in `FacJobReceiptV1`, rather
  than fabricating placeholder data.
- [INV-MF-001] (TCK-00542) Manifest import refuses manifests larger than
  `MAX_MANIFEST_SIZE` (64 KiB) before deserialization.
- [INV-MF-002] (TCK-00542) Manifest import refuses when schema does not match
  `EVIDENCE_BUNDLE_MANIFEST_SCHEMA` (`apm2.fac.evidence_bundle_manifest.v1`).
- [INV-MF-003] (TCK-00542) Manifest content hash uses domain-separated BLAKE3
  hashing (`MANIFEST_HASH_DOMAIN`) with length-prefixed encoding for all
  variable-length fields. Verified via constant-time comparison.
- [INV-MF-004] (TCK-00542) Manifest import refuses when `entries.len()` exceeds
  `MAX_MANIFEST_ENTRIES` (256).
- [INV-MF-005] (TCK-00542) All manifest string fields are bounded during import:
  `job_id` (MAX_JOB_ID_LENGTH=256), `outcome_reason` (MAX_OUTCOME_REASON_LENGTH=1024),
  `envelope_content_hash` (MAX_ENVELOPE_HASH_REF_LENGTH=256), entry descriptions
  (MAX_ENTRY_DESCRIPTION_LENGTH=512), entry content_hash_refs
  (MAX_ENVELOPE_HASH_REF_LENGTH=256).
- [INV-MF-006] (TCK-00542) Channel boundary check presence is required for both
  manifest construction and import. Construction fails with
  `ChannelBoundaryCheckRequired` when the envelope boundary check indicates an
  unchecked state. Import fails when `channel_boundary_checked` is false.
- [INV-MF-007] (TCK-00542) Both `EvidenceBundleManifestV1` and
  `EvidenceBundleManifestEntryV1` use `#[serde(deny_unknown_fields)]` to reject
  any fields not defined in the struct during deserialization (fail-closed on
  unknown/malformed input).
- [INV-EB-014] (TCK-00542) Envelope import accepts both the legacy schema
  (`apm2.fac.evidence_bundle.v1`) and the canonical schema
  (`apm2.fac.evidence_bundle_envelope.v1`) for backwards compatibility.

## Policy Environment Enforcement (TCK-00526, TCK-00575)

The `policy` module provides centralized environment filtering for all FAC job
execution paths. `FacPolicyV1` env fields (`env_clear`, `env_allowlist_prefixes`,
`env_denylist_prefixes`, `env_set`, `deny_ambient_cargo_home`, `cargo_home`,
`cargo_target_dir`) are enforced at runtime by `build_job_environment()`.

### Per-Lane Env Dir Isolation (TCK-00575)

Per-lane environment directories isolate `HOME`, `TMPDIR`, `XDG_CACHE_HOME`,
and `XDG_CONFIG_HOME` so that FAC jobs do not write into ambient user
directories (`~/.cache`, `~/.cargo`, `~/.config`, etc.).

**Constants**:
- `LANE_ENV_DIR_HOME` (`home`): Per-lane `HOME` directory.
- `LANE_ENV_DIR_TMP` (`tmp`): Per-lane `TMPDIR` directory.
- `LANE_ENV_DIR_XDG_CACHE` (`xdg_cache`): Per-lane `XDG_CACHE_HOME` directory.
- `LANE_ENV_DIR_XDG_CONFIG` (`xdg_config`): Per-lane `XDG_CONFIG_HOME` directory.
- `LANE_ENV_DIRS`: Slice of all four directory names.

**Key Functions**:
- `apply_lane_env_overrides(env, lane_dir)`: Sets `HOME`, `TMPDIR`,
  `XDG_CACHE_HOME`, and `XDG_CONFIG_HOME` to deterministic per-lane paths
  under `lane_dir`. Must be called AFTER `build_job_environment()` so that
  per-lane overrides take final precedence.
- `ensure_lane_env_dirs(lane_dir)`: Creates all four env subdirectories with
  mode 0o700 on Unix (CTR-2611). Idempotent: verifies ownership and
  permissions on existing directories.

**Lifecycle**:
- Created during lane initialization (`LaneManager::ensure_lanes()`).
- Created before gate execution (`ensure_lane_env_dirs()` in `gates.rs`).
- Pruned during lane cleanup (Step 3b: `env_dir_prune`).
- Deleted during lane reset (`apm2 fac lane reset`).

### Key Functions

- `build_job_environment(policy, ambient_env, apm2_home) -> BTreeMap<String, String>`:
  Centralized default-deny environment builder. Algorithm:
  1. Start with empty env (default-deny).
  2. Inherit only variables matching `env_allowlist_prefixes`.
  3. Remove variables matching `env_denylist_prefixes` (denylist wins).
  4. Strip variables listed in `env_clear` (unconditional).
  5. Apply `env_set` overrides (force-set key=value pairs).
  6. Hardcoded containment safety: unconditionally strip `RUSTC_WRAPPER` and
     all `SCCACHE_*` variables regardless of policy configuration (defense-in-depth,
     non-configurable). Runs AFTER `env_set` to ensure policy overrides cannot
     re-introduce these variables.
  7. Enforce managed `CARGO_HOME` when `deny_ambient_cargo_home` is true.
  8. Enforce `CARGO_TARGET_DIR` from policy.
  Output is a deterministic `BTreeMap` (sorted keys).

  The default policy `env_allowlist_prefixes` use narrow prefixes (`RUSTFLAGS`,
  `RUSTDOCFLAGS`, `RUSTUP_`, `RUST_BACKTRACE`, `RUST_LOG`, `RUST_TEST_THREADS`)
  instead of a broad `RUST` prefix to prevent `RUSTC_WRAPPER` admission. The
  default `env_denylist_prefixes` include `RUSTC_WRAPPER` and `SCCACHE_` as
  additional defense-in-depth.

- `FacPolicyV1::resolve_cargo_home(apm2_home) -> Option<PathBuf>`:
  Priority: explicit `cargo_home` > managed path (`$APM2_HOME/private/fac/cargo_home`
  when `deny_ambient_cargo_home` is true) > `None` (ambient allowed).

### Enforcement Sites

- **Shared policy loader** (`fac_review/policy_loader.rs`): Shared module for
  bounded I/O policy loading (`O_NOFOLLOW` + `Read::take` at `MAX_POLICY_SIZE + 1`)
  and managed `CARGO_HOME` creation. Both gates and evidence modules delegate here.
- **Gates** (`fac_review/gates.rs`): `compute_nextest_test_environment()` loads
  policy via `policy_loader::load_or_create_fac_policy()`, calls
  `build_job_environment()`, then calls `ensure_lane_env_dirs()` and
  `apply_lane_env_overrides()` to set per-lane `HOME`/`TMPDIR`/`XDG_*` paths
  (TCK-00575). Lane-derived env vars (`NEXTEST_TEST_THREADS`, `CARGO_BUILD_JOBS`)
  are overlaid after per-lane env isolation.
  `ensure_managed_cargo_home()` delegates to `policy_loader`.
- **Pipeline/Evidence** (`fac_review/evidence.rs`): `build_pipeline_test_command()`
  loads policy via `policy_loader::load_or_create_fac_policy()` and builds
  policy-filtered env for bounded test execution. All gate phases (fmt, clippy,
  doc, script gates) strip `RUSTC_WRAPPER` and `SCCACHE_*` via `env_remove_keys`
  on `Command` (defense-in-depth alongside policy-level stripping).
- **Bounded test runner** (`fac_review/bounded_test_runner.rs`):
  `SYSTEMD_SETENV_ALLOWLIST_EXACT` includes `CARGO_HOME`, `RUSTUP_HOME`, `PATH`,
  `HOME`, `USER`, `LANG` for correct toolchain resolution inside systemd transient
  units.
- **Lane cleanup** (`lane.rs`): Step 3b (`env_dir_prune`) prunes per-lane `home/`,
  `xdg_cache/`, and `xdg_config/` directories via `safe_rmtree_v1`. The `tmp/`
  directory is already handled by the existing temp prune step (Step 3).
- **Lane reset** (`fac.rs`): `run_lane_reset()` deletes all lane subdirectories
  including `home/`, `tmp/`, `xdg_cache/`, `xdg_config/` (TCK-00575).
- **Warm phases** (`fac/warm.rs`, `fac_worker.rs`): `execute_warm_job()` builds
  a hardened environment via `build_job_environment()` before calling
  `execute_warm()`. In the containment path (systemd-run), the hardened env is
  forwarded via `--setenv` arguments; the systemd-run process itself inherits
  the parent environment (needs D-Bus connectivity). In the direct spawn
  fallback path, `env_clear()` + hardened env is used (INV-WARM-012).
  FAC-private state, secrets, and worker authority context are unreachable
  from untrusted `build.rs` and proc-macro code.

### Security Invariants (TCK-00526)

- [INV-ENV-001] Default-deny: ambient environment variables are not inherited unless
  explicitly allowlisted by `env_allowlist_prefixes`.
- [INV-ENV-002] Denylist takes priority over allowlist when both match a variable.
- [INV-ENV-003] `env_clear` unconditionally strips named variables regardless of
  allowlist/denylist.
- [INV-ENV-004] `env_set` overrides are applied before hardcoded containment
  stripping (before CARGO_HOME/TARGET_DIR). Policy-defined values cannot
  override hardcoded safety strips (INV-ENV-008).
- [INV-ENV-005] When `deny_ambient_cargo_home` is true, `CARGO_HOME` is always set
  to the managed path (`$APM2_HOME/private/fac/cargo_home`), preventing reliance on
  `~/.cargo` state.
- [INV-ENV-006] Managed `CARGO_HOME` directory is created with 0o700 permissions
  (CTR-2611) on Unix. Existing directories are verified for correct ownership
  (current user) and permissions (0o700, no group/other access).
- [INV-ENV-007] Output environment is deterministic (`BTreeMap` sorted by key).
- [INV-ENV-008] `RUSTC_WRAPPER` and `SCCACHE_*` are unconditionally stripped by
  `build_job_environment()` regardless of policy configuration (hardcoded
  defense-in-depth). This step runs AFTER `env_set` overrides so that even a
  malicious policy using `env_set` to re-introduce these variables is defeated.
  This prevents compiler injection even if a custom policy inadvertently
  re-admits these variables via allowlist prefixes or env_set overrides.
- [INV-ENV-009] Default `env_allowlist_prefixes` use narrow prefixes (`RUSTFLAGS`,
  `RUSTDOCFLAGS`, `RUSTUP_`, `RUST_BACKTRACE`, `RUST_LOG`, `RUST_TEST_THREADS`)
  to prevent broad `RUST` prefix from admitting `RUSTC_WRAPPER`.
- [INV-ENV-010] Per-lane env dirs (`home/`, `tmp/`, `xdg_cache/`, `xdg_config/`)
  are created with mode 0o700 on Unix (CTR-2611). Existing directories are
  verified for current-user ownership and restrictive permissions (no
  group/other access). Verification failure is fatal.
- [INV-ENV-011] `apply_lane_env_overrides()` must be called AFTER
  `build_job_environment()` so that per-lane `HOME`/`TMPDIR`/`XDG_*` values
  take final precedence over any ambient or policy-set values.
- [INV-ENV-012] Per-lane env dirs are pruned during lane cleanup (Step 3b,
  `env_dir_prune`) and deleted during lane reset. Prune failure marks the
  lane CORRUPT via `LaneCorruptMarkerV1`.
- [INV-LANE-ENV-001] `verify_dir_permissions()` is the shared public helper
  for directory permission verification. Both `verify_lane_env_dir_permissions()`
  and `verify_cargo_home_permissions()` delegate to it. Uses `symlink_metadata`
  (not `metadata`) to prevent isolation escape via planted symlinks. A symlink
  at any lane env directory path (e.g., `home` -> `~/.ssh`) is rejected with
  an explicit error. This prevents an attacker from redirecting lane-isolated
  directories to sensitive ambient user locations.
- [INV-LANE-ENV-002] `ensure_lane_env_dirs()` and `ensure_managed_cargo_home()`
  use atomic directory creation (mkdir + handle `AlreadyExists`) instead of
  checking `exists()` first, eliminating the TOCTOU window between stat and
  create.
- [INV-LANE-ENV-003] UID comparisons in `verify_dir_permissions()` use
  `subtle::ConstantTimeEq` for constant-time comparison, consistent with
  project style (INV-PC-001).
- [INV-LANE-ENV-004] `apm2 fac gates` acquires an exclusive lane lock on
  `lane-00` via `LaneManager::acquire_lock()` before any lane operations
  (env dir creation, gate execution). This prevents concurrent gate runs
  from colliding on the shared synthetic lane directory.
- [INV-LANE-ENV-005] `apm2 fac gates` checks lane-00 status before executing.
  If the lane is CORRUPT (from a previous failed run), gate execution is
  refused with an error directing the user to run `apm2 fac lane reset lane-00`.
- [INV-LANE-ENV-006] Per-lane env isolation is applied in ALL FAC execution
  paths: `gates.rs` (via `compute_nextest_test_environment`), `evidence.rs`
  (via `build_pipeline_test_command` and `build_gate_policy_env`). In the
  evidence path, env overrides use the lane directory from the actually-locked
  lane (returned by `allocate_lane_job_logs_dir`) to maintain lock/env coupling.
  Every FAC gate phase runs with deterministic lane-local `HOME`/`TMPDIR`/`XDG_*`
  values.

## Receipt Versioning (TCK-00518)

The `FacJobReceiptV1` type supports two canonical byte representations:

- **v1** (`canonical_bytes()`): Excludes `unsafe_direct`. Used by existing worker
  receipts and `persist_content_addressed_receipt()`. Domain separator:
  `apm2.fac.job_receipt.content_hash.v1\0`.
- **v2** (`canonical_bytes_v2()`): Includes `unsafe_direct` as a boolean byte.
  Used by CLI gate receipts (`try_build_v2()`) and
  `persist_content_addressed_receipt_v2()`. Domain separator:
  `apm2.fac.job_receipt.content_hash.v2\0`.

Both representations are length-prefixed. The distinct domain separators ensure
no hash collision between v1 and v2 hashes for identical receipt content.

## receipt_index Submodule (TCK-00560)

The `receipt_index` submodule implements a non-authoritative, rebuildable index
for fast job/receipt lookup. The index lives under
`$APM2_HOME/private/fac/receipts/index/` and maps `job_id` to the latest receipt
content hash, and content hash to parsed header fields (outcome, timestamp,
queue_lane, etc.).

### Key Types

- `ReceiptIndexV1`: In-memory index with `job_index` (job_id → content_hash) and
  `header_index` (content_hash → `ReceiptHeaderV1`). Supports incremental update,
  full rebuild from receipt store, atomic persistence, and bounded-read loading.
- `ReceiptHeaderV1`: Parsed header fields extracted from `FacJobReceiptV1`
  (content_hash, job_id, outcome, timestamp_secs, queue_lane, unsafe_direct).

### Core Capabilities

- `rebuild_from_store(receipts_dir)`: Scan all receipt files, parse, build index.
  Bounded by `MAX_REBUILD_SCAN_FILES` (65536).
- `incremental_update(receipts_dir, receipt)`: Load-or-rebuild index, upsert new
  receipt header, persist atomically.
- `load_or_rebuild(receipts_dir)`: Load index from disk, rebuild on missing/corrupt.
- `persist(receipts_dir)`: Atomic write using `NamedTempFile` (random temp name +
  fsync + rename) to index subdirectory. Prevents symlink attacks.
- `latest_digest_for_job(job_id)`: O(1) lookup of latest receipt hash for a job.
- `header_for_digest(content_hash)`: O(1) lookup of parsed header by content hash.
- Both `persist_content_addressed_receipt` and `persist_content_addressed_receipt_v2`
  call `incremental_update` as a best-effort post-persist step.

### Consumer Helpers (TCK-00560)

- `lookup_job_receipt(receipts_dir, job_id)`: Index-first O(1) job receipt lookup
  with bounded directory scan fallback. Verifies content-addressed integrity
  (BLAKE3 hash) before returning — on mismatch, treats as index corruption and
  falls back to directory scan. Primary consumer entry point.
- `has_receipt_for_job(receipts_dir, job_id)`: Index-first O(1) receipt existence
  check with full verification. Loads the receipt via `load_receipt_bounded`
  (O_NOFOLLOW + size cap), verifies `receipt.job_id == requested_job_id` and
  content-hash integrity before returning true. Falls back to bounded directory
  scan. Used by the worker for duplicate detection.
- `list_receipt_headers(receipts_dir)`: List all indexed headers sorted by
  timestamp (most recent first). No directory scanning.
- CLI: `apm2 fac receipts list` — list indexed receipts.
- CLI: `apm2 fac receipts status <job_id>` — look up latest receipt for a job.
- CLI: `apm2 fac receipts reindex` — force full rebuild from receipt store.

### Production Consumer Wiring (TCK-00560)

All receipt-touching hot paths consult the index first:

- **Worker duplicate detection** (`fac_worker::process_job`): Before processing
  any job, `has_receipt_for_job` checks the index for an existing receipt. Jobs
  with receipts are skipped, avoiding redundant processing and directory scans.
- **Receipt persistence** (`persist_content_addressed_receipt`,
  `persist_content_addressed_receipt_v2`): Both call `incremental_update` after
  writing the receipt file, keeping the index current.
- **CLI receipt list** (`apm2 fac receipts list`): Uses `list_receipt_headers`
  (index-only, no directory scan).
- **CLI receipt status** (`apm2 fac receipts status`): Uses `lookup_job_receipt`
  (index-first with fallback).
- **CLI receipt reindex** (`apm2 fac receipts reindex`): Full rebuild from store.
- **Receipt persistence** error handling: Both `persist_content_addressed_receipt`
  and `persist_content_addressed_receipt_v2` log warnings on `incremental_update`
  failure and delete the stale index to force rebuild on next read.
- **Gates**: Use their own gate-result cache (`gate_cache.rs`), not the job receipt
  store. No index wiring needed.
- **Metrics**: Daemon and consensus metrics modules do not reference the job receipt
  store. No index wiring needed.
- **GC/Quarantine**: Persist GC receipts (different type), do not scan job receipts.

### Security Invariants (TCK-00560)

- [INV-IDX-001] Index is non-authoritative. It is treated as attacker-writable
  cache under A2 assumptions. Never trusted for authorization/admission/caching.
- [INV-IDX-002] All in-memory collections bounded by `MAX_INDEX_ENTRIES` (16384)
  and `MAX_JOB_INDEX_ENTRIES` (16384). Overflow returns Err, not truncation.
  Upsert checks ALL capacities before ANY mutation (no dangling entries).
- [INV-IDX-003] Index file reads use open-once with `O_NOFOLLOW` + bounded
  streaming reads from the same handle (no stat-then-read TOCTOU).
- [INV-IDX-004] Rebuild scans count EVERY directory entry (not just `.json`
  files) toward `MAX_REBUILD_SCAN_FILES` (65536). Adversarial non-JSON entries
  cannot bypass the scan cap.
- [INV-IDX-005] Corrupt/missing index triggers automatic rebuild from receipt
  store. System correctness never depends on index availability.
- [INV-IDX-006] Index persistence uses `NamedTempFile` with random name, fsync,
  and atomic rename. No predictable temp paths.
- [INV-IDX-007] Individual receipt file reads during rebuild use open-once with
  `O_NOFOLLOW` + bounded streaming reads (no stat-then-read TOCTOU).
- [INV-IDX-008] `lookup_job_receipt` verifies content-addressed integrity by
  recomputing the BLAKE3 hash (v1 and v2 schemes) of loaded receipts against the
  index key. Hash mismatch triggers fallback to directory scan (fail-closed).

## sd_notify Submodule (TCK-00600)

The `sd_notify` submodule implements the systemd notification protocol for
Type=notify services. It provides zero-dependency sd_notify(3) support using
Unix datagram sockets to `$NOTIFY_SOCKET`.

### Key Types

- `WatchdogTicker`: Tracks watchdog ping interval and last-ping time using
  monotonic `Instant`. Reads `WATCHDOG_USEC` from environment at construction.
  If `WATCHDOG_USEC` is absent or zero, the ticker is disabled (no-op pings).
  Ping interval is `WATCHDOG_USEC / 2` (systemd recommendation), with a minimum
  floor of 1 second.

### Core Functions

- `notify_ready()`: Sends `READY=1` to systemd. Called once after service
  initialization is complete (socket bind for daemon, broker connection for
  worker).
- `notify_stopping()`: Sends `STOPPING=1` to systemd. Called at the start of
  graceful shutdown.
- `notify_watchdog()`: Sends `WATCHDOG=1` to systemd. Called periodically by
  `WatchdogTicker::ping_if_due()`.
- `notify_status(msg)`: Sends `STATUS=<msg>` to systemd for human-readable
  status in `systemctl status` output.

### Security Invariants (TCK-00600)

- [INV-SDN-001] `NOTIFY_SOCKET` path is validated: must be absolute or abstract
  (starts with `/` or `@`), and bounded by `MAX_NOTIFY_SOCKET_PATH` (108 bytes,
  matching the OS `sockaddr_un.sun_path` limit).
- [INV-SDN-002] All notify functions return `bool` (success/failure), never
  panic. Missing `NOTIFY_SOCKET` is a silent no-op (non-systemd environments).
- [INV-SDN-003] `WatchdogTicker` uses monotonic `Instant` for interval tracking
  (INV-2501 compliance). No wall-clock time dependency.
- [INV-SDN-004] Minimum ping interval is 1 second to prevent excessive
  datagram traffic while supporting short `WatchdogSec` configurations.
- [INV-SDN-005] Abstract Unix sockets (prefixed with `@`) use raw
  `libc::sendto` with a manually constructed `sockaddr_un` where
  `sun_path[0] = 0` followed by the socket name bytes. Standard
  `UnixDatagram::send_to` cannot address abstract sockets (it expects
  filesystem paths). Filesystem path sockets use standard `send_to`.

## worker_heartbeat Submodule (TCK-00600)

The `worker_heartbeat` submodule implements a cross-process liveness signal for
the FAC worker. The worker writes a JSON heartbeat file on each poll cycle;
`apm2 fac services status` reads it to determine worker health beyond what
systemd process monitoring provides.

### Key Types

- `WorkerHeartbeatV1`: Schema-versioned heartbeat payload with PID, Unix
  timestamp, cycle count, cumulative job stats, and self-reported health status.
- `HeartbeatStatus`: Read result indicating whether the heartbeat file was
  found, whether it is fresh (within `MAX_HEARTBEAT_AGE_SECS`), the age in
  seconds, PID, and health status string.

### Core Functions

- `write_heartbeat(fac_root, cycle_count, jobs_completed, jobs_denied,
  jobs_quarantined, health_status)`: Atomic write (temp+rename) to
  `<fac_root>/worker_heartbeat.json`.
- `read_heartbeat(fac_root)`: Bounded read with staleness detection. Returns
  `HeartbeatStatus` (never errors; missing/corrupt files return default).

### Security Invariants (TCK-00600)

- [INV-WHB-001] Heartbeat file writes use atomic temp+rename to prevent partial
  reads.
- [INV-WHB-002] Heartbeat file reads use `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`
  (Linux) to refuse symlinks at the kernel level and avoid blocking on FIFOs.
  Non-regular files are rejected via fstat after open. Reads are bounded by
  `MAX_HEARTBEAT_FILE_SIZE` (8 KiB) using `Read::take()` before deserialization
  (CTR-1603, RS-31). On non-Linux, falls back to `symlink_metadata` check.
- [INV-WHB-003] Schema mismatch or parse failure returns a default
  `HeartbeatStatus` with `found: false` (fail-open for observability, not
  authority).
- [INV-WHB-004] Staleness is detected by comparing `timestamp_unix` against
  current time with `MAX_HEARTBEAT_AGE_SECS` (120 seconds) threshold.
- [INV-WHB-005] The heartbeat file is not authoritative for admission or
  security decisions. It is an observability signal only.

## warm Submodule (TCK-00525)

The `warm` submodule implements lane-scoped prewarming with content-addressed
receipts. Warm reduces cold-start probability for subsequent gates by
pre-populating build caches in the lane target namespace.

### Key Types

- `WarmReceiptV1`: Content-addressed receipt capturing per-phase exit codes,
  durations, tool versions, and BLAKE3 content hash. All fields use bounded
  deserialization (SEC-CTRL-FAC-0016).
- `WarmPhaseResult`: Per-phase execution result with bounded string fields.
- `WarmPhase`: Selectable warm phase enum (Fetch, Build, Nextest, Clippy, Doc).
- `WarmToolVersions`: Tool version snapshot with bounded optional string fields.
- `WarmError`: Error taxonomy covering invalid phases, bounds violations,
  execution failures, timeouts, containment failures, and hash mismatches.
- `WarmContainment`: Systemd transient unit containment configuration for warm
  phase subprocesses (backend, properties, optional system-mode config).

### Core Capabilities

- `execute_warm(phases, ..., containment, heartbeat_fn)`: Execute warm phases
  and produce a `WarmReceiptV1`. Accepts optional `WarmContainment` for
  systemd-run transient unit wrapping and optional heartbeat callback for
  liveness during long-running phases.
- `execute_warm_phase(phase, ..., containment, heartbeat_fn)`: Execute a
  single phase with timeout enforcement via `MAX_PHASE_TIMEOUT_SECS` (1800s).
  Accepts optional containment and heartbeat parameters.
- `collect_tool_versions(hardened_env)`: Bounded stdout collection from version
  probe commands (`MAX_VERSION_OUTPUT_BYTES`). Uses hardened environment
  (INV-WARM-012, defense-in-depth). Version probes use a deadlock-free
  design where the calling thread owns the `Child` directly (no mutex) and
  the helper thread owns only the `ChildStdout` pipe (INV-WARM-013).
- `WarmReceiptV1::verify_content_hash()`: Constant-time hash verification
  via `subtle::ConstantTimeEq`.
- `WarmReceiptV1::persist(receipts_dir)`: Atomic write (temp+rename) with
  size validation.

### Security Invariants (TCK-00525)

- [INV-WARM-001] All string fields bounded by `MAX_*` constants during both
  construction and deserialization (SEC-CTRL-FAC-0016).
- [INV-WARM-002] Warm uses lane target namespace (`CARGO_TARGET_DIR`).
- [INV-WARM-003] Warm uses FAC-managed `CARGO_HOME`.
- [INV-WARM-004] Phase count bounded by `MAX_WARM_PHASES` during both
  construction and deserialization.
- [INV-WARM-005] Content hash uses domain-separated BLAKE3 with
  length-prefixed injective framing.
- [INV-WARM-006] Content hash verification uses constant-time comparison
  via `subtle::ConstantTimeEq` (INV-PC-001 consistency).
- [INV-WARM-007] Phase execution enforces `MAX_PHASE_TIMEOUT_SECS` via
  `Child::try_wait` polling + `Child::kill` on timeout.
- [INV-WARM-008] Tool version collection uses bounded stdout reads
  (`Read::take(MAX_VERSION_OUTPUT_BYTES)`) to prevent OOM.
- [INV-WARM-009] GateReceipt `payload_hash` and `evidence_bundle_hash` bind to
  the serialized `WarmReceiptV1` output (not the input job spec), providing
  verifiable evidence binding.
- [INV-WARM-010] GateReceipt `passed` reflects warm receipt persistence success.
  Persistence failure produces `passed=false` (fail-closed measurement
  integrity).
- [INV-WARM-011] Warm phase subprocesses execute under their own `systemd-run`
  transient units (INV-WARM-014), providing active cgroup containment
  independent of the worker's own unit. Supersedes passive inheritance model.
- [INV-WARM-012] Warm phase subprocesses execute with a hardened environment
  constructed via `build_job_environment()` (default-deny + policy allowlist).
  The ambient process environment is NOT inherited. FAC-private state paths
  and secrets are unreachable from `build.rs` / proc-macro execution.
  `RUSTC_WRAPPER` and `SCCACHE_*` are unconditionally stripped (INV-ENV-008).
  Version probe commands also use the hardened environment (defense-in-depth).
- [INV-WARM-013] Version probe timeout uses a mutex-free design: the calling
  thread owns the `Child` directly and the helper thread owns only the
  `ChildStdout` pipe. This eliminates the deadlock scenario where a helper
  thread holds a child mutex across blocking `wait()` while the timeout path
  needs the same mutex to `kill()` the process. The calling thread retains
  unconditional kill authority regardless of helper thread state.
- [INV-WARM-014] Warm phase subprocesses are executed under `systemd-run`
  transient units with MemoryMax/CPUQuota/TasksMax/RuntimeMaxSec constraints
  matching the lane profile, identical to how standard bounded test jobs are
  contained. Uses `build_systemd_run_command()` from `execution_backend` for
  consistent command construction. Transient unit names are unique per
  lane/job/phase (`apm2-warm-{lane}-{job_id_prefix}-{phase}`) to prevent
  collisions across concurrent workers or rapid re-execution. When
  `systemd-run` is platform-unavailable (container environments, no user
  D-Bus session in auto mode), falls back to direct `Command::spawn` with a
  logged warning. Configuration errors (invalid backend value, invalid
  service user, env var issues) deny the job (fail-closed) rather than
  silently disabling containment. Environment is forwarded via `--setenv`
  arguments. The systemd-run process itself inherits the parent environment
  (no `env_clear()`) because it needs `DBUS_SESSION_BUS_ADDRESS` and
  `XDG_RUNTIME_DIR` for user-mode D-Bus connectivity; the contained child
  process receives its environment exclusively via `--setenv`.
- [INV-WARM-015] Heartbeat refresh is integrated into the warm phase `try_wait`
  polling loop via an optional callback. Invoked every 5 seconds
  (`HEARTBEAT_REFRESH_INTERVAL`) to prevent the worker heartbeat file from
  going stale during long-running warm phases (which can take hours for large
  projects). The heartbeat callback captures the last known cycle count and
  job counters from the worker's main loop so that observers see accurate
  state during warm phases. The callback is passed from the worker into
  `execute_warm`/`execute_warm_phase` and runs synchronously on the same
  thread (no cross-thread sharing).

## reconcile Submodule (TCK-00534)

The `reconcile` submodule implements crash recovery reconciliation for FAC queue
and lane state. After an unclean shutdown (crash, SIGKILL, OOM-kill), the queue
and lane state can become inconsistent. This module detects and repairs
inconsistencies deterministically on worker startup.

### Key Types

- `ReconcileError`: Error taxonomy covering lane errors, I/O failures, bounded
  collection overflow, serialization errors, and move failures (`MoveFailed`).
- `OrphanedJobPolicy`: Policy enum for handling claimed jobs without a running
  lane (`Requeue` or `MarkFailed`). Default is `Requeue`.
- `LaneRecoveryAction`: Per-lane action taken during reconciliation
  (`StaleLeaseCleared`, `AlreadyConsistent`, `MarkedCorrupt`).
- `QueueRecoveryAction`: Per-job action taken during queue reconciliation
  (`Requeued`, `MarkedFailed`, `StillActive`).
- `ReconcileReceiptV1`: Structured receipt emitted after each reconciliation
  pass, persisted to `$APM2_HOME/private/fac/receipts/reconcile/` for
  auditability.

### Core Capabilities

- `reconcile_on_startup(fac_root, queue_root, orphan_policy, dry_run)`: Main
  entry point. Runs two-phase recovery:
  1. **Lane reconciliation** (`reconcile_lanes`): Scans all lanes for stale
     leases (PID dead + lock not held). Stale leases are recovered through
     the CLEANUP state transition (`recover_stale_lease`) to reach IDLE.
     Ambiguous PID state (EPERM) triggers durable CORRUPT marking
     (fail-closed) with `LaneCorruptMarkerV1` persistence.
  2. **Queue reconciliation** (`reconcile_queue`): Scans `queue/claimed/` for
     orphaned jobs not backed by any active lane. Rejects symlinks and
     non-regular file types. Applies configured policy (requeue to `pending/`
     or mark failed to `denied/`). Move failures are propagated, not swallowed.
     Returns `QueueReconcileResult` with partial counts and optional error
     (mirroring Phase 1's `LaneReconcileResult` pattern) so partial receipts
     include accurate `claimed_files_inspected` counts.
- `ReconcileReceiptV1::load()`: Bounded receipt deserialization with size cap,
  schema validation (rejects non-matching `schema` field), and post-parse
  bounds validation.
- Dry-run mode: report what would be done without mutating state (receipt
  persistence is best-effort).
- Apply mode: receipt persistence is mandatory (fail-closed).
- Idempotent: running reconciliation multiple times produces correct results.
- Called automatically on worker startup with `OrphanedJobPolicy::Requeue`.
  Worker startup aborts if reconciliation fails.
- CLI: `apm2 fac reconcile --dry-run|--apply [--orphan-policy requeue|mark-failed]`.

### Security Invariants (TCK-00534)

- [INV-RECON-001] No job is silently dropped; all outcomes recorded as receipts.
  Receipt persistence is mandatory in apply mode (fail-closed); dry-run mode
  uses best-effort persistence. Worker startup aborts on reconciliation failure
  to prevent processing jobs with inconsistent queue/lane state. If Phase 1
  (lane reconciliation) fails after mutating some lanes, a partial receipt
  containing the completed Phase 1 actions is persisted before the error is
  propagated. Similarly, if Phase 1 succeeds but Phase 2 (queue reconciliation)
  fails, a partial receipt containing Phase 1 actions is persisted before the
  Phase 2 error is propagated. In both cases, this ensures lane and queue
  recovery mutations are never silently lost. If partial receipt persistence
  also fails, a combined error is returned that includes both the phase
  failure context and the persistence failure context, so apply-mode mutations
  never lack durable receipt evidence.
- [INV-RECON-002] Stale lease detection is fail-closed: ambiguous PID state
  (EPERM) marks lane CORRUPT (not recovered). Corrupt marker persistence
  failure is a hard error in apply mode — ambiguous states must not proceed
  without durable corruption evidence, because subsequent startups would not
  see the lane as corrupt and could attempt unsafe recovery. Corrupt lanes
  with alive PIDs contribute their job_id to the active_job_ids set, preventing
  queue reconciliation from treating those jobs as orphans.
- [INV-RECON-003] All in-memory collections are bounded by hard `MAX_*`
  constants (`MAX_LANE_RECOVERY_ACTIONS=64`,
  `MAX_QUEUE_RECOVERY_ACTIONS=4096`). Receipt deserialization enforces
  `MAX_RECEIPT_FILE_SIZE` (1 MiB) via `bounded_read_file` before parsing,
  plus `MAX_DESERIALIZED_LANE_ACTIONS` and `MAX_DESERIALIZED_QUEUE_ACTIONS`
  bounds after parsing.
- [INV-RECON-004] Reconciliation is idempotent and safe to call on every
  startup.
- [INV-RECON-005] Queue reads are bounded (`MAX_CLAIMED_SCAN_ENTRIES=4096`).
  Every directory entry (including symlinks, directories, and special files)
  counts toward the scan cap BEFORE file-type filtering. This prevents
  adversarial flooding of non-regular entries to bypass the scan budget.
- [INV-RECON-006] Stale lease recovery routes through the CLEANUP state
  transition (`recover_stale_lease`): the lease is persisted as CLEANUP state,
  best-effort filesystem cleanup runs (tmp/ and per-lane env dir pruning via
  `safe_rmtree_v1`), then the lease is removed to reach IDLE. This mirrors
  the normal lane cleanup lifecycle and prevents cross-job contamination from
  stale files. Git reset/clean is excluded because the workspace path is not
  stored in the lease record and git state after a crash may be arbitrary
  (the workspace will be re-checked-out on next job assignment). If any
  cleanup step fails, the lane is marked CORRUPT via `LaneCorruptMarkerV1`
  and the worker continues startup (the corrupt marker is the fail-closed
  safety net — the lane will not accept new jobs until explicitly reset via
  `apm2 fac lane reset`). This prevents crash loops in SystemMode where
  `safe_rmtree_v1` rejects 0o770 lane directory permissions
  (INV-RMTREE-006). CLEANUP persist failure is a hard error — lease
  removal is blocked without durable CLEANUP evidence to prevent silent
  lifecycle bypass.
- [INV-RECON-007] Move operations are fail-closed: `move_file_safe` propagates
  rename failures as `ReconcileError::MoveFailed`. Queue reconciliation counters
  only increment after confirmed rename success. Requeue failures attempt
  fallback to denied before returning an error. Exception: `NotFound` on rename
  is treated as success ("already handled by another worker") to support
  concurrent multi-worker reconciliation without startup failures.
- [INV-RECON-008] Queue scanning rejects non-regular files (symlinks, FIFOs,
  block/char devices, sockets) via `entry.file_type()` check.
  `extract_job_id_from_claimed` validates with `symlink_metadata` and reads
  via `open_file_no_follow` (O_NOFOLLOW) to prevent symlink traversal.
  The `queue/claimed` directory itself is verified via `symlink_metadata()`
  before traversal; if it is a symlink, reconciliation fails closed to
  prevent iterating and moving files from outside the queue tree.
- [INV-RECON-009] All filesystem writes use hardened I/O from `lane.rs`:
  directories via `create_dir_restricted` (0o700 on every newly created
  component, not just the leaf — CTR-2611), files via `atomic_write`
  (NamedTempFile + 0o600 permissions + `sync_all` + atomic rename). Receipt
  filenames include nanosecond timestamp + random suffix for collision
  resistance.
- [INV-RECON-010] `move_file_safe` destination names are always unique
  (nanos + random_u32 suffix), eliminating TOCTOU races from
  exists-then-rename patterns.
- [INV-RECON-011] CLI JSON error output uses `serde_json::json!()` +
  `serde_json::to_string()` instead of raw string interpolation, preventing
  malformed JSON from unsanitized error messages.
- [INV-RECON-012] Reconciliation is exempt from AJC lifecycle requirements
  (RS-42, RFC-0027). It runs at startup as an internal crash-recovery
  mechanism before the worker accepts any external authority — it is itself
  the authority reset for crash recovery. Boundary conditions: runs before
  the job-processing loop, no broker tokens issued, mutations limited to
  local queue/lane filesystem state. See `reconcile_on_startup` doc comment
  for the full exemption rationale.
- [INV-RECON-013] `move_file_safe` hardens destination file permissions to
  0o600 after `fs::rename` to prevent information disclosure from preserved
  source permissions (CTR-2611). After a successful rename, chmod failure is
  logged as a warning but does NOT return `Err`, because the file has already
  been moved — returning `Err` would cause the caller to interpret the move
  as failed and attempt a fallback move from the original path (which no
  longer exists), creating unrecorded queue mutations that break
  INV-RECON-001/007.
- [INV-RECON-014] In the `LaneState::Corrupt` branch of `reconcile_lanes`,
  if a durable corrupt marker does not already exist, one is persisted via
  `persist_corrupt_marker`. This ensures that derived corruption states
  (e.g., lock free but PID alive) are durably marked so subsequent restarts
  see the lane as corrupt even if the runtime conditions that triggered the
  derivation have changed.
- [INV-RECON-015] `truncate_string(s, max_len)` guarantees the output length
  is `<= max_len`, including the `"..."` ellipsis suffix when truncation is
  needed. This ensures truncated strings pass downstream `MAX_STRING_LENGTH`
  validation (e.g., `LaneCorruptMarkerV1::load` enforces a strict length
  check on the `reason` field).
- CTR-2501 deviation: `current_timestamp_rfc3339()` and `wall_clock_nanos()`
  use wall-clock time for receipt timestamps and file deduplication suffixes.
  Documented inline with security justification.

## Control-Lane Exception (TCK-00533)

`stop_revoke` jobs bypass the standard RFC-0028 channel context token and
RFC-0029 queue admission flow. This is an explicit, audited policy exception
marked by `CONTROL_LANE_EXCEPTION_AUDITED` in `job_spec.rs`.

### Justification

Control-lane cancellation originates from the local operator (same trust domain
as the queue owner) and requires filesystem-level access proof (queue directory
write capability). A broker-issued token adds no authority beyond what
filesystem capability already proves. All structural and digest validation is
still enforced; only the token requirement is waived.

### Invariants

- `validate_job_spec_control_lane()` enforces all structural/digest validation
  except the token requirement.
- All deny paths in the control-lane flow emit explicit refusal receipts before
  moving jobs to `denied/`.

## containment Submodule (TCK-00548)

The `containment` submodule implements cgroup membership verification for
child processes during FAC job execution. It verifies that child processes
(rustc, nextest, cc, ld, sccache) share the same cgroup hierarchy as the
job unit, preventing cache poisoning via escaped sccache daemons.

### Key Types

- `ContainmentVerdict`: Full verdict with `contained` flag, reference cgroup,
  mismatch list, sccache detection, and auto-disable status.
- `ContainmentMismatch`: Single escaped process with PID, name, expected and
  actual cgroup paths.
- `ContainmentTrace`: Lightweight trace for inclusion in `FacJobReceiptV1`.
- `ContainmentError`: Fail-closed error taxonomy for proc read failures,
  parse failures, and resource bounds.

### Core Capabilities

- `read_cgroup_path(pid)`: Reads the cgroup v2 path from `/proc/<pid>/cgroup`.
- `discover_children(parent_pid)`: BFS discovery of all descendant processes
  via `/proc/*/status` PPid scanning, bounded by `MAX_CHILD_PROCESSES` (2048).
- `verify_containment(reference_pid, sccache_enabled)`: Full containment
  check with sccache auto-disable logic.
- `check_sccache_containment(reference_pid, sccache_enabled)`: Convenience
  function returning `Option<String>` reason if sccache should be disabled.
- `is_cgroup_contained(child_path, reference_path)`: Exact or subtree
  prefix matching with slash separator enforcement.

### Security Invariants (TCK-00548)

- [INV-CONTAIN-001] Fail-closed: unreadable `/proc` entries result in
  mismatch verdict. Default `ContainmentVerdict::default()` has
  `contained: false`.
- [INV-CONTAIN-002] All `/proc` reads bounded by `MAX_PROC_READ_SIZE` (4 KiB).
- [INV-CONTAIN-003] Process discovery bounded by `MAX_CHILD_PROCESSES` (2048)
  and `MAX_PROC_SCAN_ENTRIES` (131072). Overflow returns
  `ContainmentError::ProcScanOverflow` (fail-closed). Excessive `PPid`
  read failures (>50% of scanned PID entries) also return this error.
- [INV-CONTAIN-004] Cgroup path comparison uses exact prefix matching with
  slash separator to prevent `/foo` matching `/foobar`.
- [INV-CONTAIN-005] Process comm names bounded by `MAX_COMM_LENGTH` (64).
- [INV-CONTAIN-006] PID validation rejects 0 and values > `MAX_PID_VALUE`.
- [INV-CONTAIN-007] `ContainmentTrace` is wired into `FacJobReceiptV1` via
  the `emit_job_receipt` function. The builder's `.containment()` method
  populates the receipt's `containment` field from actual verification
  results.
- [INV-CONTAIN-008] Bounded test commands (systemd transient units)
  unconditionally strip sccache env vars (`RUSTC_WRAPPER`, `SCCACHE_*`)
  because cgroup containment cannot be verified for the transient unit
  before it starts. The stripping is enforced in two places: (1) the
  `SYSTEMD_SETENV_ALLOWLIST_EXACT` excludes `RUSTC_WRAPPER` and
  `SYSTEMD_SETENV_ALLOWLIST_PREFIXES` excludes `SCCACHE_*`, preventing
  these keys from appearing in `--setenv` args; (2) `env_remove_keys`
  strips them from the spawned process environment to prevent parent
  env inheritance.
