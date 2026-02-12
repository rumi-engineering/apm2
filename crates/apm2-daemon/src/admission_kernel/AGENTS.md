# AdmissionKernel Module

> Plan/execute API with capability-gated effect surfaces for authoritative request admission (RFC-0019 REQ-0023, TCK-00492).

## Overview

The `admission_kernel` module owns the canonical lifecycle ordering for all authority-bearing request processing: `join -> revalidate -> consume -> effect`. Handlers call `plan()` to obtain a single-use `AdmissionPlanV1`, then `execute()` to consume the plan and receive capability tokens for effect execution.

The module enforces:

1. **Canonical Phase Ordering**: join, revalidate, consume, effect -- no reordering or skipping.
2. **Single-Use Plans**: Plans are non-cloneable, non-copyable, non-serializable. A consumed plan cannot be re-executed even if execution failed mid-way.
3. **Capability-Gated Effects**: `EffectCapability`, `LedgerWriteCapability`, and `QuarantineCapability` tokens are only constructible within this module (`pub(super)` constructors).
4. **Fail-Closed Prerequisites**: Missing ledger state, policy root, or anti-rollback anchor denies for fail-closed tiers.
5. **Daemon-Created Witness Seeds**: With provider provenance binding.
6. **Boundary Output Mediation**: Output held until post-effect checks for fail-closed tiers.

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
}
```

Single entry point for all admission decisions. Uses builder pattern for optional prerequisites.

**Invariants:**

- [INV-AK10] Plan-then-execute ordering is structurally enforced by type system.
- [INV-AK11] Missing prerequisites produce denial for fail-closed tiers, not silent bypass.
- [INV-AK12] Plan state transitions to `Consumed` BEFORE fallible operations to prevent re-execution.

**Contracts:**

- [CTR-AK01] `plan()` validates request, resolves prerequisites, creates witness seeds, executes PCAC join + initial revalidate.
- [CTR-AK02] `execute()` re-resolves all prerequisites for fail-closed tiers (TOCTOU closure), performs fresh revalidation with the verifier-selected anchor, quarantine reservation, durable consume, capability minting, and boundary span initialization.
- [CTR-AK03] Monitor tiers may proceed without optional prerequisites and without prerequisite re-checks in `execute()`.
- [CTR-AK04] Enforcement tier is derived from `RiskTier`: `Tier2Plus` -> `FailClosed`, all others -> `Monitor`.
- [CTR-AK05] `LedgerWriteCapability` is only minted for fail-closed tiers (CTR-2617). Monitor tiers receive `None`.
- [CTR-AK06] `build_pcac_join_input()` uses the verifier-selected ledger anchor, NOT the client-supplied `directory_head_hash`, for the AJC's `as_of_ledger_anchor` field.
- [CTR-AK07] Identity evidence level and pointer-only waiver hash are passed through from `KernelRequestV1` to `AuthorityJoinInputV1` (not hardcoded).
- [CTR-AK08] `execute()` constructs and seals `AdmissionBundleV1` BEFORE capability minting and receipt emission. Bundle digest becomes the `AdmissionBindingHash` (TCK-00493).
- [CTR-AK09] `AdmissionResultV1` includes both the sealed `bundle` and `bundle_digest`. The digest is recomputable from the bundle via `content_hash()`.

### `KernelRequestV1` (types.rs)

Versioned kernel request input with bounded string fields and non-zero hash validation.

### `AdmissionPlanV1` (types.rs)

Single-use admission plan containing join-time bindings. Not `Clone`, `Copy`, `Serialize`, or `Deserialize`.

### `AdmissionResultV1` (types.rs)

Result of successful execution containing capability tokens, consume receipts, and boundary span.

### `AdmissionSpineJoinExtV1` (types.rs)

Spine join extension committed into PCAC join. Domain-separated BLAKE3 content hash.

### `WitnessSeedV1` (types.rs)

Witness seed created at join time with provider provenance binding and domain-separated content hash.

### `EffectCapability`, `LedgerWriteCapability`, `QuarantineCapability` (capabilities.rs)

Capability tokens with `pub(super)` constructors. Non-cloneable, non-copyable, `#[must_use]`.

- [INV-AK01] Only constructible within `admission_kernel` module.
- [INV-AK02] Non-cloneable, non-copyable (single-use).
- [INV-AK03-09] Carry provenance hashes for audit traceability.

### `LedgerTrustVerifier`, `PolicyRootResolver`, `AntiRollbackAnchor` (prerequisites.rs)

Trait interfaces for prerequisite resolution. Implementations provided by TCK-00500.

### `QuarantineGuard` (mod.rs)

Trait for durable quarantine capacity reservation. Implemented by `DurableQuarantineGuard` in [`quarantine_store`](../quarantine_store/AGENTS.md) (TCK-00496).

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

Error type with 14 deterministic denial variants. No "unknown -> allow" path. Includes `ExecutePrerequisiteDrift` for TOCTOU detection between plan and execute and `BundleSealFailure` for bundle validation/serialization failures (TCK-00493).

## Phase Ordering

```text
plan():    validate -> prerequisite resolution -> witness seed creation ->
           spine join extension -> PCAC join -> PCAC revalidate
execute(): single-use check -> prerequisite re-check (fail-closed) ->
           fresh revalidate (verifier anchor) -> quarantine reserve ->
           durable consume -> bundle seal (TCK-00493) ->
           capability mint (tier-gated) -> boundary span -> result
```

## Public API

- `AdmissionKernelV1`, `WitnessProviderConfig`, `QuarantineGuard`
- `AdmissionPlanV1`, `AdmissionResultV1`, `AdmissionSpineJoinExtV1`
- `AdmissionBundleV1`, `AdmissionOutcomeIndexV1`, `QuarantineActionV1`
- `KernelRequestV1`, `WitnessSeedV1`, `BoundarySpanV1`
- `EnforcementTier`, `AdmitError`
- `EffectCapability`, `LedgerWriteCapability`, `QuarantineCapability`
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
