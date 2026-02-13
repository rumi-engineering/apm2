# AdmissionKernel Module

> Plan/execute API with capability-gated effect surfaces for authoritative request admission (RFC-0019 REQ-0023, TCK-00492). Crash-safe effect execution via durable effect journal with fail-closed in-doubt handling (RFC-0019 REQ-0029, TCK-00501).

## Overview

The `admission_kernel` module owns the canonical lifecycle ordering for all authority-bearing request processing: `join -> revalidate -> consume -> effect`. Handlers call `plan()` to obtain a single-use `AdmissionPlanV1`, then `execute()` to consume the plan and receive capability tokens for effect execution.

The module enforces:

1. **Canonical Phase Ordering**: join, revalidate, consume, effect -- no reordering or skipping.
2. **Single-Use Plans**: Plans are non-cloneable, non-copyable, non-serializable. A consumed plan cannot be re-executed even if execution failed mid-way.
3. **Capability-Gated Effects**: `EffectCapability`, `LedgerWriteCapability`, and `QuarantineCapability` tokens are only constructible within this module (`pub(super)` constructors).
4. **Fail-Closed Prerequisites**: Missing ledger state, policy root, or anti-rollback anchor denies for fail-closed tiers.
5. **Daemon-Created Witness Seeds**: With provider provenance binding.
6. **Boundary Output Mediation**: Output held until post-effect checks for fail-closed tiers.
7. **Crash-Safe Effect Execution**: Durable effect journal with `NotStarted -> Started -> Completed` state machine, crash window classification, and fail-closed in-doubt handling for `Unknown` state (TCK-00501).

## Key Types

### `AdmissionKernelV1` (mod.rs)

```rust
pub struct AdmissionKernelV1 {
    pcac_kernel: Arc<dyn AuthorityJoinKernel>,
    ledger_verifier: Option<Arc<dyn LedgerTrustVerifier>>,
    policy_resolver: Option<Arc<dyn PolicyRootResolver>>,
    anti_rollback: Option<Arc<dyn AntiRollbackAnchor>>,
    quarantine_guard: Option<Arc<dyn QuarantineGuard>>,
    witness_provider: WitnessProviderConfig,
    effect_journal: Option<Arc<dyn EffectJournal>>,
}
```

Single entry point for all admission decisions. Uses builder pattern for optional prerequisites.

**Invariants:**

- [INV-AK10] Plan-then-execute ordering is structurally enforced by type system.
- [INV-AK11] Missing prerequisites produce denial for fail-closed tiers, not silent bypass.
- [INV-AK12] Plan state transitions to `Consumed` BEFORE fallible operations to prevent re-execution.

**Contracts:**

- [CTR-AK01] `plan()` validates request, resolves prerequisites, creates witness seeds, executes PCAC join + initial revalidate.
- [CTR-AK02] `execute()` re-resolves all prerequisites for fail-closed tiers (TOCTOU closure), performs fresh revalidation with the verifier-selected anchor, quarantine reservation, durable consume, capability minting, and boundary span initialization. **Anti-rollback anchor commit is deferred to `finalize_anti_rollback()`** which MUST be called by the caller AFTER the authoritative effect succeeds (TCK-00502 BLOCKER-2: pre-commit hazard prevention).
- [CTR-AK03] Monitor tiers may proceed without optional prerequisites and without prerequisite re-checks in `execute()`.
- [CTR-AK04] Enforcement tier is derived from `RiskTier`: `Tier2Plus` -> `FailClosed`, all others -> `Monitor`.
- [CTR-AK05] `LedgerWriteCapability` is only minted for fail-closed tiers (CTR-2617). Monitor tiers receive `None`.
- [CTR-AK06] `build_pcac_join_input()` uses the verifier-selected ledger anchor, NOT the client-supplied `directory_head_hash`, for the AJC's `as_of_ledger_anchor` field.
- [CTR-AK07] Identity evidence level and pointer-only waiver hash are passed through from `KernelRequestV1` to `AuthorityJoinInputV1` (not hardcoded).
- [CTR-AK08] `execute()` constructs and seals `AdmissionBundleV1` BEFORE capability minting and receipt emission. Bundle digest becomes the `AdmissionBindingHash` (TCK-00493).
- [CTR-AK09] `AdmissionResultV1` includes both the sealed `bundle` and `bundle_digest`. The digest is recomputable from the bundle via `content_hash()`.
- [CTR-AK10] `validate_witness_seeds_at_join()` denies fail-closed tiers when seeds have zero provider digests or reused nonces. Monitor tiers require an explicit `MonitorWaiverV1` (TCK-00497). Integrated into `plan()` for fail-closed tiers.
- [CTR-AK11] `finalize_post_effect_witness()` validates post-effect evidence objects against their seeds (seed hash, provider provenance, temporal ordering). Fail-closed tiers deny on missing evidence. Monitor tiers require explicit waiver with expiry enforcement (TCK-00497). Monitor-tier evidence is also checked for seed/provider binding when provided (QUALITY MINOR 1). Integrated into `handle_request_tool` post-effect path.
- [CTR-AK12] `release_boundary_output()` denies output release for fail-closed tiers when evidence hashes are empty. Marks `BoundarySpanV1` as released exactly once (TCK-00497). Integrated into `handle_request_tool` post-effect path.
- [CTR-AK13] `MonitorWaiverV1::validate()` enforces `expires_at_tick` against current tick. Non-zero `expires_at_tick < current_tick` means expired waiver, which is denied (SECURITY MAJOR 2, TCK-00497).
- [CTR-AK14] `WitnessEvidenceV1.measured_values` uses bounded visitor deserialization (`bounded_vec_deser!`) with max `MAX_WITNESS_EVIDENCE_MEASURED_VALUES` to prevent unbounded allocation from untrusted input (QUALITY MAJOR 1 + SECURITY MAJOR 1, TCK-00497).
- [CTR-AK18] `finalize_anti_rollback()` commits the anti-rollback anchor AFTER confirmed effect success. For fail-closed tiers, this advances the external anchor watermark. For monitor tiers, this is a no-op. MUST NOT be called before effect confirmation (pre-commit hazard). Called from all effect-capable handler post-effect paths: `handle_request_tool` (after `DecisionType::Allow`), `handle_emit_event` (after ledger write), and `handle_publish_evidence` (after CAS write) (TCK-00502).
- [CTR-AK19] `verify_anti_rollback()` tolerates `ExternalAnchorUnavailable` from `verify_committed()` as the bootstrap path: on fresh install, no prior anchor exists to protect and the anti-rollback invariant is vacuously satisfied. Other `TrustError` variants still produce denial (TCK-00502 BLOCKER-1).
- [CTR-AK20] `resolve_post_effect_anchor()` queries `LedgerTrustVerifier::validated_state()` for the current verified head AFTER the authoritative effect. Returns the verifier anchor when its height >= the fallback anchor; otherwise returns the fallback. Falls back to the caller-supplied anchor when no verifier is wired or when `validated_state()` errors. MUST be called between effect confirmation and `finalize_anti_rollback()` so the anti-rollback commit advances to the actual post-effect head, not the stale pre-plan anchor (TCK-00502 MAJOR-2).
- [CTR-AK21] `probe_anti_rollback_health()` performs a non-mutating health check via `verify_committed()` (read-only). MUST NOT call `commit()`. Returns `Ok(())` when the anchor verifies or `AdmitError` on failure. Used by the pre-effect circuit breaker to test anti-rollback availability without advancing the anchor watermark (TCK-00502 MINOR-4).
- [CTR-AK22] `execute()` enforces EffectJournal presence for fail-closed tiers (`MissingPrerequisite` if absent) and builds an `EffectJournalBindingV1` that is returned in `AdmissionResultV1.journal_binding`. The caller MUST call `journal.record_started(&binding)` at the true pre-dispatch boundary (TCK-00501).
- [CTR-AK23] `IdempotencyKeyV1` is derived deterministically from `(dedupe_key, request_id, ajc_id)` via domain-separated BLAKE3 and included in `AdmissionResultV1` for propagation to broker/tool calls (TCK-00501). The `dedupe_key` is the stable client-supplied intent identifier (INV-F-06) that persists across retries; `execute()` uses `intent_digest` as the dedupe key. The key is also wired into `ExecutionContext.idempotency_key` for tool handler propagation.
- [CTR-AK24] `check_output_release_permitted()` denies output release for `Unknown` state unless an explicit `InDoubtResolutionV1::AllowReExecution` resolution is provided with matching `request_id` and `idempotency_key`. Fail-closed: no resolution means deny (TCK-00501).

### `KernelRequestV1` (types.rs)

Versioned kernel request input with bounded string fields and non-zero hash validation.

### `AdmissionPlanV1` (types.rs)

Single-use admission plan containing join-time bindings. Not `Clone`, `Copy`, `Serialize`, or `Deserialize`.

### `AdmissionResultV1` (types.rs)

Result of successful execution containing capability tokens, consume receipts, boundary span, witness seeds, idempotency key, effect journal handle, and journal binding. The `leakage_witness_seed` and `timing_witness_seed` fields are carried through from the consumed plan so the runtime post-effect path can invoke `finalize_post_effect_witness` with actual seeds rather than ad-hoc hash-only checks (TCK-00497 QUALITY MAJOR 1). The `idempotency_key`, `effect_journal`, and `journal_binding` fields support crash-safe effect execution (TCK-00501). The `journal_binding` is built by `execute()` but NOT persisted; the caller controls when `record_started` is called to prevent false in-doubt classification (SEC-MAJOR-1 fix).

- [CTR-AK15] Seeds in `AdmissionResultV1` match the plan-time seeds (same content hash).
- [CTR-AK16] Runtime post-effect path MUST use `kernel.finalize_post_effect_witness()` with the result's seeds as the single source of truth for seed/provider/temporal binding validation. Ad-hoc validation is forbidden.
- [CTR-AK17] Monitor tiers MUST construct a `MonitorWaiverV1` and pass it to `finalize_post_effect_witness()`. Silent log-and-continue bypass is forbidden (QUALITY MAJOR 2).
- [CTR-AK21] `idempotency_key` MUST be propagated to all external broker/tool calls that support idempotency. Callers use `idempotency_key.as_hex()` for transport encoding. The key is now propagated into `BrokerToolRequest.idempotency_key` via `with_idempotency_key()` in session dispatch (TCK-00501 MAJOR 1 fix).
- [CTR-AK23] `declared_idempotent` in `KernelRequestV1` is currently hardcoded to `false` because `Capability` does not yet carry this field. This makes `resolve_in_doubt` always deny in production (fail-closed safe). TODO(TCK-00501): source from manifest/capability metadata when the schema is extended.
- [CTR-AK22] Post-effect path MUST call `effect_journal.record_completed()` after successful effect execution. Failure to record completion causes `Unknown` state on crash recovery, which triggers fail-closed in-doubt handling.

### `AdmissionSpineJoinExtV1` (types.rs)

Spine join extension committed into PCAC join. Domain-separated BLAKE3 content hash.

### `WitnessSeedV1` (types.rs)

Witness seed created at join time with provider provenance binding and domain-separated content hash.

### `WitnessEvidenceV1` (types.rs)

Post-effect witness evidence object (TCK-00497). Materialized AFTER the effect executes. Binds daemon-measured values (leakage metrics, timing measurements) to the witness seed committed at join time. For fail-closed tiers, output release is denied unless valid witness evidence is present. Domain-separated BLAKE3 content hash.

**Invariants:**

- [INV-AK30] Evidence `seed_hash` must match the seed's `content_hash()` (constant-time comparison).
- [INV-AK31] Evidence `witness_class`, `request_id`, `session_id` must match the seed's fields.
- [INV-AK32] Evidence `provider_id` and `provider_build_digest` must match the seed (anti-substitution).
- [INV-AK33] Evidence `ht_end` must be >= seed `ht_start` (temporal ordering).
- [INV-AK34] `measured_values` bounded by `MAX_WITNESS_EVIDENCE_MEASURED_VALUES` (16). Bounded visitor deserialization enforced via `bounded_vec_deser!` macro (SECURITY MAJOR 1).

### `MonitorWaiverV1` (types.rs)

Explicit waiver for monitor-tier witness bypass (TCK-00497). Monitor tiers may skip witness enforcement ONLY via explicit waiver. Silent permissive defaults are forbidden. Domain-separated BLAKE3 content hash.

**Invariants:**

- [INV-AK35] Waiver `enforcement_tier` must be `Monitor`, never `FailClosed`.
- [INV-AK36] Waiver `reason` must be non-empty and bounded by `MAX_WAIVER_REASON_LENGTH`.
- [INV-AK37] Waiver hash is included in audit binding (outcome index evidence hashes).
- [INV-AK38] Waiver `expires_at_tick` is enforced against current tick. Non-zero expired waivers are denied (SECURITY MAJOR 2).

### `EffectJournal` trait and `FileBackedEffectJournal` (effect_journal.rs)

Crash-safe effect execution journal (TCK-00501). Tracks effect execution state per `RequestId` with a durable, append-only, file-backed journal. Modeled after `FileBackedConsumeIndex` with exclusive file locking and streaming replay.

**State machine:** `NotStarted -> Started -> Completed`. On crash recovery (replay), entries with `Started` but no `Completed` are classified as `Unknown`. An `Unknown` entry can be resolved to `NotStarted` via `resolve_in_doubt()` (persisted as 'R' tag) when both conditions (idempotent + boundary confirms) are met.

**Key types:**

- `EffectExecutionState`: `NotStarted`, `Started`, `Completed`, `Unknown` -- the four possible states for any effect execution.
- `EffectJournalBindingV1`: Complete pre-effect binding data persisted with journal entry (request digest, ledger anchor, policy root, witness seeds, boundary profile, tier, join ID, selectors). Domain-separated BLAKE3 content hash. Validated before persistence.
- `IdempotencyKeyV1`: Deterministic BLAKE3 key derived from `(dedupe_key, request_id, ajc_id)` with domain separation `"apm2-idempotency-key-v1"`. The `dedupe_key` is the stable client-supplied intent identifier (INV-F-06). Propagated to external systems for deduplication via `ExecutionContext.idempotency_key`.
- `InDoubtResolutionV1`: Resolution for `Unknown` state -- `Deny { reason }` (default, fail-closed) or `AllowReExecution { request_id, idempotency_key, boundary_confirmation, reason }` (requires explicit proof).
- `EffectJournalError`: Structured error type covering I/O, corruption, duplicate entries, bounds overflow, and validation failures.

**Invariants:**

- [INV-AK40] Journal entries are append-only; no in-place mutation or deletion. Tags: 'S' (Started), 'C' (Completed), 'R' (Resolved: Unknown -> NotStarted).
- [INV-AK41] `Started` without `Completed` on replay produces `Unknown`, never silent re-execution.
- [INV-AK42] `Unknown` state denies output release unless explicit `AllowReExecution` resolution with matching `request_id` and `idempotency_key` is provided.
- [INV-AK43] Journal replay tolerates torn tail entries (partial writes from crash) by skipping unparseable trailing lines.
- [INV-AK44] In-memory **active** entry count (`Started`/`Unknown`) bounded by `MAX_JOURNAL_ENTRIES` (100,000). Overflow returns `EffectJournalError::CapacityExhausted`. Terminal entries (`Completed`/`NotStarted`) do not consume active capacity slots.
- [INV-AK59] In-memory **terminal** entry count (`Completed`/`NotStarted`) bounded by `MAX_TERMINAL_ENTRIES` (100,000). Pruning uses O(1) FIFO eviction via `terminal_order: VecDeque<Hash>`. Entries are pushed to the back when they transition to terminal state; eviction pops from the front. Stale keys (entries re-inserted as active after `resolve_in_doubt` + `record_started`) are skipped. Pruning fires automatically: (a) inline during journal replay, (b) at runtime after `record_completed()` and `resolve_in_doubt()`, and (c) as a post-replay safety-net pass. Only in-memory pruning; the on-disk journal retains all records.
- [INV-AK60] Journal file size is checked BEFORE reading (256 MiB limit, `MAX_JOURNAL_FILE_SIZE`). Files exceeding the limit are rejected with `ValidationError` to prevent unbounded allocation.
- [INV-AK61] Journal line length check strictly enforces `MAX_JOURNAL_LINE_LEN` (64,000 bytes) without off-by-one tolerance.
- [INV-AK45] Exclusive file lock (`flock LOCK_EX`) prevents concurrent journal access from multiple daemon instances.
- [INV-AK46] Binding data is validated (`validate()`) before persistence; zero hashes and empty fields are rejected.
- [INV-AK47] `record_started()` rejects duplicate `request_id` entries UNLESS state is `NotStarted` (from `resolve_in_doubt`), which permits re-execution by removing the stale entry before inserting the new binding.
- [INV-AK48] `resolve_in_doubt()` persists resolution atomically (fsync 'R' tag) BEFORE updating in-memory state; prevents infinite resolution loops on crash (TCK-00501 fix).
- [INV-AK49] Fail-closed tiers MUST have an effect journal wired; `execute()` denies with `MissingPrerequisite` if journal is absent for `FailClosed` tier (TCK-00501 fix).
- [INV-AK50] Journal file is created with mode `0o600` (owner-only read/write) to prevent world-readable exposure of request IDs, session IDs, and policy root digests (TCK-00501 fix). Pre-existing files with broader permissions are remediated to `0o600` on open (MINOR-1 fix).
- [INV-AK51] Post-effect path MUST call `record_completed()` after successful effect execution to transition journal state from `Started` to `Completed`; wired in `session_dispatch.rs` (TCK-00501 fix).
- [INV-AK52] C and R journal records enforce exact 64 hex char length (not minimum). Trailing garbage after the hex is rejected as `CorruptEntry` during replay (MAJOR-1 fix, TCK-00501 round 6).
- [INV-AK53] S journal records verify line-key `request_id` matches `binding.request_id`. A mismatch is rejected as `CorruptEntry` during replay to prevent identity confusion between lookup key and authoritative binding (MAJOR-2 fix, TCK-00501 round 6).
- [INV-AK54] Journal replay uses bounded read (`Read::take()` + `read_until()` with `Vec<u8>`) capped at `MAX_JOURNAL_LINE_LEN + 1` bytes per line. Oversized lines are detected BEFORE memory allocation, preventing OOM from malicious/corrupted journal files (BLOCKER fix, TCK-00501 round 7).
- [INV-AK55] `EffectJournalBindingV1` has `#[serde(deny_unknown_fields)]` to reject corrupted/tampered entries with extra JSON fields during replay (MAJOR-2 fix, TCK-00501 round 7).
- [INV-AK56] `EffectJournalError::IoError` preserves `std::io::ErrorKind` for programmatic matching (MAJOR-1 fix, TCK-00501 round 7).
- [INV-AK57] Kernel plan/execute runs whenever `admission_kernel` is wired, regardless of `pcac_lifecycle_gate` presence. The PCAC gate handles authority lifecycle; the kernel additionally provides effect journal crash-safety tracking. Both run when both are wired in production (SEC-MAJOR-2 fix, TCK-00501 round 7).
- [INV-AK58] Permission remediation (`enforce_journal_permissions`) is extracted to a helper function and called at both open and truncation paths (NIT fix, TCK-00501 round 7).

### `EffectCapability`, `LedgerWriteCapability`, `QuarantineCapability` (capabilities.rs)

Capability tokens with `pub(super)` constructors. Non-cloneable, non-copyable, `#[must_use]`.

- [INV-AK01] Only constructible within `admission_kernel` module.
- [INV-AK02] Non-cloneable, non-copyable (single-use).
- [INV-AK03-09] Carry provenance hashes for audit traceability.

### `LedgerTrustVerifier`, `PolicyRootResolver`, `AntiRollbackAnchor` (prerequisites.rs)

Trait interfaces for prerequisite resolution. Concrete implementations provided by the `trust_stack` submodule (TCK-00500).

### `trust_stack` submodule (trust_stack/mod.rs, TCK-00500, TCK-00502)

Concrete implementations of `LedgerTrustVerifier`, `PolicyRootResolver`, and `AntiRollbackAnchor` prerequisite traits, plus supporting infrastructure:

- **`RootTrustBundle`**: Bounded trust anchor with crypto-agile key entries (algorithm ID + key ID + public key bytes). `deny_unknown_fields` serde, domain-separated BLAKE3 content hash. Max 64 keys (`MAX_TRUST_BUNDLE_KEYS`). Supports key rotation/revocation with `active_from_epoch` (inclusive) and `revoked_at_epoch` (exclusive).
- **`TrustBundleKeyEntry`**: Individual key entry with epoch-aware `is_active_at()` validity check.
- **`TrustedSealV1`**: Ledger event payload committing to `LedgerAnchorV1` with signature provenance chaining to the `RootTrustBundle`. Canonical `signing_payload()` for deterministic verification.
- **`ConcreteLedgerTrustVerifier`**: Implements `LedgerTrustVerifier`. Performs checkpoint-bounded startup verification: seal location, seal signature verification, hash chain integrity, HT monotonicity, max seal-to-tip distance enforcement, optional full-chain fallback. Write-once state behind `RwLock<VerifiedState>`.
- **`GovernancePolicyRootResolver`**: Implements `PolicyRootResolver`. Derives `PolicyRootStateV1` deterministically from governance-class events up to a given `LedgerAnchorV1`. Bounded LRU cache (`MAX_POLICY_ROOT_CACHE_ENTRIES` = 64). Rejects unsigned governance events (fail-closed).
- **`SignatureVerifier`** trait: Crypto-agile dispatch. Unknown algorithms return `Err` (fail-closed).
- **`Ed25519SignatureVerifier`**: Default `SignatureVerifier` implementation for ed25519.
- **`LedgerEventSource`** trait: Abstraction over ledger reads for startup verification and governance event scanning.

**Invariants:**

- [INV-TS01] `RootTrustBundle` is bounded by `MAX_TRUST_BUNDLE_KEYS` (64). Empty bundles are rejected.
- [INV-TS02] Key IDs must be unique within a bundle.
- [INV-TS03] Event signature key validity is resolved per-event at the event's `he_time` epoch, not the seal epoch, to correctly handle post-seal key rotations (never "always latest keyset").
- [INV-TS04] Seal signature must chain to an active key in the `RootTrustBundle` at `seal_epoch`.
- [INV-TS05] Hash chain integrity is verified with constant-time comparisons (`subtle::ConstantTimeEq`).
- [INV-TS06] HT monotonicity is enforced (non-decreasing `he_time`).
- [INV-TS07] Seal-to-tip distance exceeding `max_seal_to_tip_distance` fails closed unless `allow_full_chain_fallback` is enabled.
- [INV-TS08] Governance events MUST be signed; unsigned events are rejected.
- [INV-TS09] Policy root cache is bounded by `MAX_POLICY_ROOT_CACHE_ENTRIES` (64) with oldest-epoch eviction.
- [INV-TS10] All `usize` to `u32` casts in hash functions are safe because input lengths are bounded by MAX_* constants.
- [INV-TS11] Chain segment verification binds the first event's `event_hash` to the seal's committed anchor hash (constant-time comparison). Prevents fork substitution.
- [INV-TS12] Incomplete chain reads (event source returns empty before `end_height`) fail closed with `IntegrityFailure`. No silent acceptance of truncated chains.
- [INV-TS13] Chain segment verification enforces strict height continuity: each event's height must equal the expected next height (no gaps, no duplicates, no backward jumps).
- [INV-TS14] Full-chain fallback path validates the seal's anchor `event_hash` at `seal_height` AFTER completing `verify_chain_segment`. An internally valid but unrelated chain is rejected.
- [INV-TS15] Governance event truncation is fail-closed: if `read_governance_events` returns `>= MAX_GOVERNANCE_EVENTS_PER_DERIVATION` events, `derive_policy_root` returns `DerivationFailed` (no silent partial derivation).
- [INV-TS16] `content_hash()` and `active_keyset_digest()` sort keys by `key_id` before hashing to ensure deterministic output regardless of vector insertion order.
- [INV-TS17] `RootTrustBundle::validate()` enforces `schema_version == ROOT_TRUST_BUNDLE_SCHEMA_VERSION` as the first check. Unknown/future schema versions are rejected.
- [INV-TS18] `DurableAntiRollbackAnchor` persists anchor state via `tempfile::NamedTempFile` + `flush()` + `sync_all()` + `persist()` for crash-safe atomic writes with restrictive permissions (0600). File reads bounded by `MAX_ANCHOR_STATE_FILE_SIZE` (8 KiB).
- [INV-TS19] Anti-rollback regression checks enforce: (a) height never decreases, (b) at same height, event hash must match (constant-time comparison). Violations return `ExternalAnchorMismatch`.
- [INV-TS20] `mechanism_id` bounded by `MAX_ANTI_ROLLBACK_MECHANISM_ID_LENGTH` (128). Empty mechanism IDs rejected at construction.
- [INV-TS21] `PersistedAnchorStateV1` uses `deny_unknown_fields` serde and `schema_version` validation for forward-compatible deserialization.
- [INV-TS22] `DurableAntiRollbackAnchor` proof hash uses domain-separated BLAKE3 with length-prefixed framing for all variable fields.
- [INV-TS23] `InMemoryAntiRollbackAnchor` provides identical semantics to `DurableAntiRollbackAnchor` without file I/O (for testing).
- [INV-TS24] `DurableAntiRollbackAnchor` persists a bootstrap receipt file (`.bootstrapped` extension) on first successful `commit()`. On subsequent construction, if the state file is missing but the bootstrap receipt exists, construction fails with `ExternalAnchorUnavailable` (anchor loss after genesis). If both are absent, construction succeeds (fresh install). This prevents an attacker from bypassing anti-rollback protection by deleting the anchor state file after the system has been bootstrapped (TCK-00502 BLOCKER-1).
- [INV-TS25] Bootstrap receipt persistence uses the same atomic write pattern as anchor state (tempfile + rename + fsync) for crash safety.

#### Anti-Rollback Anchor Providers (TCK-00502)

- **`DurableAntiRollbackAnchor`**: File-backed production `AntiRollbackAnchor` implementation. Atomic write (temp + rename) for crash safety. Bounded file read (`MAX_ANCHOR_STATE_FILE_SIZE`). Schema-versioned JSON with `deny_unknown_fields`. `RwLock<Option<PersistedAnchorStateV1>>` synchronization (writers: `commit()`, readers: `latest()`/`verify_committed()`).
- **`InMemoryAntiRollbackAnchor`**: In-memory test `AntiRollbackAnchor` implementation. Same regression/fork checks as `DurableAntiRollbackAnchor` without file persistence.
- **`PersistedAnchorStateV1`**: Serialized anchor state with `schema_version`, `anchor` (`LedgerAnchorV1`), `mechanism_id`, and `proof_hash` (BLAKE3).

### `QuarantineGuard` (mod.rs)

Trait for durable quarantine capacity reservation. Implemented by `DurableQuarantineGuard` in [`quarantine_store`](../quarantine_store/AGENTS.md) (TCK-00496). The `reserve()` method requires a `session_id` parameter for per-session quota isolation; the kernel passes `plan.request.session_id`.

### `EnforcementTier` (types.rs)

Policy-derived enforcement tier: `FailClosed` or `Monitor`.

### `AdmissionBundleV1` (types.rs)

Deterministic, bounded, `deny_unknown_fields` CAS object that captures all normative admission state at seal time. The bundle is sealed BEFORE emission of authoritative receipts/events that reference it. The bundle digest is the v1.1 `AdmissionBindingHash` and is included in all authoritative receipts/events.

**Invariants:**

- [INV-AK20] Bundle is sealed before any receipt/event emission (no digest cycles).
- [INV-AK21] Bundle digest equals `content_hash()` (deterministic BLAKE3 with domain separation). This is a logical binding hash, NOT the CAS storage key.
- [INV-AK22] Bundle validated before sealing (`validate()` checks zero fields and collection bounds).
- [INV-AK23] `deny_unknown_fields` rejects unknown JSON fields at deserialization boundary.
- [INV-AK24] Collection fields bounded by `MAX_BUNDLE_QUARANTINE_ACTIONS` (16). Deserialization enforces bounds via visitor-based counting (no oversized pre-allocation).
- [INV-AK25] Post-effect data (witness evidence hashes) does NOT live in the bundle. The bundle represents the sealed decision to admit; post-effect data belongs in `AdmissionOutcomeIndexV1`.
- [INV-AK26] All string fields use bounded visitor deserialization that checks length DURING parsing, not after allocation.

### `AdmissionOutcomeIndexV1` (types.rs)

Forward index emitted AFTER receipts/events to bridge bundle -> receipt digests without creating digest cycles. Contains `post_effect_witness_evidence_hashes` (populated after effect execution) and `receipt_digests`. Bounded by `MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES` (32) and `MAX_OUTCOME_INDEX_RECEIPT_DIGESTS` (64). Deserialization enforces bounds via visitor-based counting.

### `QuarantineActionV1` (types.rs)

Individual quarantine action record within `AdmissionBundleV1`. Contains `reservation_hash`, `request_id`, and `ajc_id`.

### `AdmitError` (types.rs)

Error type with 17 deterministic denial variants. No "unknown -> allow" path. Includes `ExecutePrerequisiteDrift` for TOCTOU detection between plan and execute, `BundleSealFailure` for bundle validation/serialization failures (TCK-00493), `WitnessEvidenceFailure`/`OutputReleaseDenied`/`WitnessWaiverInvalid` for witness enforcement (TCK-00497), and `BundleSealFailure` (reused) for effect journal `record_started` failures (TCK-00501).

## Phase Ordering

```text
plan():    validate -> prerequisite resolution -> witness seed creation ->
           witness seed validation (fail-closed) -> spine join extension ->
           PCAC join -> PCAC revalidate
execute(): single-use check -> prerequisite re-check (fail-closed) ->
           fresh revalidate (verifier anchor) -> quarantine reserve ->
           durable consume -> bundle construction + validation (TCK-00493) ->
           journal binding build (TCK-00501, deferred to caller) ->
           bundle seal -> idempotency key derivation (TCK-00501) ->
           capability mint (tier-gated) -> boundary span -> result
           [caller: record_started at true pre-dispatch boundary]

POST-EFFECT FINALIZATION (caller responsibility, TCK-00502):
finalize_anti_rollback(): anti-rollback anchor commit (fail-closed tiers only)

Every effect-capable handler (RequestTool, EmitEvent, PublishEvidence)
MUST call finalize_anti_rollback() AFTER confirmed effect success and
BEFORE persisting the AdmissionOutcomeIndexV1.
```

## Public API

- `AdmissionKernelV1`, `WitnessProviderConfig`, `QuarantineGuard`
- `AdmissionPlanV1`, `AdmissionResultV1`, `AdmissionSpineJoinExtV1`
- `AdmissionBundleV1`, `AdmissionOutcomeIndexV1`, `QuarantineActionV1`
- `KernelRequestV1`, `WitnessSeedV1`, `WitnessEvidenceV1`, `MonitorWaiverV1`, `BoundarySpanV1`
- `EnforcementTier`, `AdmitError`
- `EffectCapability`, `LedgerWriteCapability`, `QuarantineCapability`
- `EffectJournal`, `FileBackedEffectJournal`, `EffectExecutionState`, `EffectJournalBindingV1`
- `IdempotencyKeyV1`, `InDoubtResolutionV1`, `EffectJournalError`
- `LedgerTrustVerifier`, `PolicyRootResolver`, `AntiRollbackAnchor`
- `LedgerAnchorV1`, `ValidatedLedgerStateV1`, `ExternalAnchorStateV1`
- `PolicyRootStateV1`, `GovernanceProvenanceV1`
- `TrustError`, `PolicyError`

## Handler Integration (TCK-00494)

The `AdmissionKernel` is wired into `SessionDispatcher` via `with_admission_kernel()`. In authoritative mode (ledger or CAS configured), the `RequestTool` handler enforces a kernel guard and invokes the kernel lifecycle:

- **Fail-closed tiers** (Tier2/3/4 -> `FailClosed` enforcement): requests are denied with `SessionErrorToolNotAllowed` if neither the kernel nor the PCAC `LifecycleGate` is wired. No silent fallback to ungated effect-capable path.
- **Kernel invocation path** (kernel wired, no `LifecycleGate`): `handle_request_tool` invokes `kernel.plan()` with a `KernelRequestV1` built from session state, then `kernel.execute()` with fresh clock/revalidation inputs. Both must succeed; any error produces an immediate deny before broker dispatch.
- **Monitor tiers** (Tier0/1): requests pass the kernel guard without kernel wiring.
- **Non-authoritative mode**: the kernel guard does not fire regardless of tier.

The kernel is wired in production via `DispatcherState::with_persistence_and_adapter_rotation()` and `DispatcherState::with_persistence_and_cas_and_key()`, each creating a dedicated `DurableKernel` with its own `FileBackedConsumeIndex`.

## Related Modules

- [`admission_kernel::trust_stack`](trust_stack/mod.rs) -- `ConcreteLedgerTrustVerifier`, `GovernancePolicyRootResolver`, `RootTrustBundle` (TCK-00500), `DurableAntiRollbackAnchor`, `InMemoryAntiRollbackAnchor` (TCK-00502)
- [`apm2_daemon::quarantine_store`](../quarantine_store/AGENTS.md) -- `DurableQuarantineGuard` (TCK-00496)
- [`apm2_daemon::pcac`](../pcac/AGENTS.md) -- PCAC lifecycle gate (`InProcessKernel`, `LifecycleGate`)
- [`apm2_core::pcac`](../../../apm2-core/src/pcac/AGENTS.md) -- Core PCAC types (`AuthorityJoinKernel`, `RiskTier`, etc.)
- [`apm2_daemon::htf`](../htf/AGENTS.md) -- `HolonicClock` provides tick source
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Session dispatch integration point
- [`apm2_daemon::state`](../state.rs) -- Production wiring (`DispatcherState` constructors)

## References

- RFC-0019: Admission Kernel Architecture
- RFC-0019 section 3.3: Single-use plan semantics
- RFC-0019 section 4.1.1: Spine join extension
- RFC-0019 section 4.2.1: Witness seed creation
- RFC-0019 section 5.2: Capability token forgery defense
- RFC-0019 section 5.3: Canonical phase ordering
- RFC-0019 section 7: Quarantine reservation
- RFC-0019 Appendix A: Prerequisite trait interfaces
- REQ-0023: AdmissionKernel plan/execute + capability-gated effect surfaces
- REQ-0025: Handler refactoring for kernel-gated admission
- REQ-0002: Fail-closed enforcement tiers
- REQ-0004: Lifecycle ordering
- REQ-0024: AdmissionBundleV1 deterministic CAS bundle
- TCK-00492: Implementation ticket (kernel plan/execute API)
- TCK-00493: Implementation ticket (bundle + outcome index)
- TCK-00494: Implementation ticket (handler refactoring + kernel wiring)
- TCK-00497: Implementation ticket (witness closure -- post-effect evidence, monitor waivers, boundary output gating)
- TCK-00500: Implementation ticket (ledger trust stack -- RootTrustBundle, trusted seals, checkpoint-bounded startup, governance-derived PolicyRootResolver)
- TCK-00502: Implementation ticket (anti-rollback anchoring -- DurableAntiRollbackAnchor, InMemoryAntiRollbackAnchor, production wiring, fail-closed tier gating)
- REQ-0028: Ledger trust stack requirements
- REQ-0030: Anti-rollback anchoring requirements
- TCK-00501: Implementation ticket (crash-safe effect execution -- effect journal, idempotency key propagation, fail-closed in-doubt handling)
- REQ-0029: Crash-safe effect execution with durable journal and deterministic recovery
