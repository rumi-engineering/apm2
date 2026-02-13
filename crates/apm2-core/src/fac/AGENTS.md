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
  and convergence receipts. Serialized to canonical JSON.
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
- All hash comparisons use `subtle::ConstantTimeEq::ct_eq()` consistent with
  INV-PC-001, including `find_admitted_policy_digest()` which uses
  non-short-circuiting iteration.
- CTR-2501 deviation: `current_time_secs()` uses `SystemTime::now()` for token
  `issued_at` timestamps (wall-clock anchored expiry). Documented inline.

## broker_health Submodule (TCK-00585)

The `broker_health` submodule implements RFC-0029 invariant health monitoring for
the FAC Broker. The broker periodically self-checks TP001/TP002/TP003 temporal
predicates and emits signed `HealthReceiptV1` receipts. Workers use a policy-driven
health gate to refuse job admission when broker health is degraded.

### Key Types

- `BrokerHealthStatus`: Three-state enum (`Healthy`, `Degraded`, `Failed`).
  Default is `Failed` (fail-closed).
- `InvariantCheckResult`: Per-predicate check result carrying `predicate_id`,
  `passed` flag, and optional `deny_reason`.
- `HealthReceiptV1`: Signed health receipt containing schema metadata, status,
  broker tick, individual check results, content hash, Ed25519 signature, and
  signer identity. Serialized to canonical JSON.
- `HealthCheckInput`: Aggregated input bundle for health evaluation, including
  optional envelope, evaluation window, signature verifier, freshness/revocation/
  convergence horizons, convergence receipts, and required authority sets.
- `BrokerHealthChecker`: Stateful checker maintaining a bounded history ring
  (`MAX_HEALTH_HISTORY=64`). Runs TP001/TP002/TP003 checks, signs receipts, and
  tracks history.
- `WorkerHealthPolicy`: Policy enum for worker admission gate. `StrictHealthy`
  (default) requires `Healthy`; `AllowDegraded` permits `Degraded`.
- `WorkerHealthGateError`: Fail-closed error taxonomy for worker health gate
  denial (no receipt, degraded, failed, invalid signature).

### Core Capabilities

- Delegates TP predicate validation to existing `economics::queue_admission`
  functions (`validate_envelope_tp001`, `validate_freshness_horizon_tp002`,
  `validate_convergence_horizon_tp003`).
- `FacBroker::check_health()` convenience method wires broker state into the
  health checker.
- `evaluate_worker_health_gate()` enforces policy-driven admission control:
  verifies receipt existence, signature authenticity (via `BrokerSignatureVerifier`),
  and health status against worker policy.
- Domain-separated BLAKE3 content hash (`apm2.health_receipt.v1`) over tick,
  status, and per-check results.

### Security Invariants (TCK-00585)

- [INV-BH-001] Default `BrokerHealthStatus` is `Failed` (fail-closed). Missing
  or ambiguous health state denies admission.
- [INV-BH-002] Health receipts are Ed25519-signed by the broker key. Workers
  verify signature authenticity before trusting health status.
- [INV-BH-003] Worker health gate denies admission when no receipt exists, when
  signature verification fails, or when status violates policy.
- [INV-BH-004] All in-memory collections are bounded by hard `MAX_*` caps:
  `MAX_HEALTH_HISTORY=64`, `MAX_HEALTH_FINDINGS=16`,
  `MAX_HEALTH_REQUIRED_AUTHORITY_SETS=64`.
- [INV-BH-005] Health check input bounds are enforced before evaluation:
  required_authority_sets and findings are capped with explicit errors on overflow.

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
