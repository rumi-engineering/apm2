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
