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
- [INV-SYS-002] `JobConstraints` values are applied with lane ceiling semantics
  (`min`) so a job cannot increase resource or timeout limits above lane
  defaults.
- [INV-SYS-003] `LaneProfileV1` loading failures fail the job path as a denial
  with machine-readable receipt output, not silent continuation.

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
