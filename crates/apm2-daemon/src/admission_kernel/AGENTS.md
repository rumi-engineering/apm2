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

Trait for durable quarantine capacity reservation. Implementations provided by TCK-00496.

### `EnforcementTier` (types.rs)

Policy-derived enforcement tier: `FailClosed` or `Monitor`.

### `AdmitError` (types.rs)

Error type with 13 deterministic denial variants. No "unknown -> allow" path. Includes `ExecutePrerequisiteDrift` for TOCTOU detection between plan and execute.

## Phase Ordering

```text
plan():    validate -> prerequisite resolution -> witness seed creation ->
           spine join extension -> PCAC join -> PCAC revalidate
execute(): single-use check -> prerequisite re-check (fail-closed) ->
           fresh revalidate (verifier anchor) -> quarantine reserve ->
           durable consume -> capability mint (tier-gated) -> boundary span ->
           result
```

## Public API

- `AdmissionKernelV1`, `WitnessProviderConfig`, `QuarantineGuard`
- `AdmissionPlanV1`, `AdmissionResultV1`, `AdmissionSpineJoinExtV1`
- `KernelRequestV1`, `WitnessSeedV1`, `BoundarySpanV1`
- `EnforcementTier`, `AdmitError`
- `EffectCapability`, `LedgerWriteCapability`, `QuarantineCapability`
- `LedgerTrustVerifier`, `PolicyRootResolver`, `AntiRollbackAnchor`
- `LedgerAnchorV1`, `ValidatedLedgerStateV1`, `ExternalAnchorStateV1`
- `PolicyRootStateV1`, `GovernanceProvenanceV1`
- `TrustError`, `PolicyError`

## Related Modules

- [`apm2_daemon::pcac`](../pcac/AGENTS.md) -- PCAC lifecycle gate (`InProcessKernel`, `LifecycleGate`)
- [`apm2_core::pcac`](../../../apm2-core/src/pcac/AGENTS.md) -- Core PCAC types (`AuthorityJoinKernel`, `RiskTier`, etc.)
- [`apm2_daemon::htf`](../htf/AGENTS.md) -- `HolonicClock` provides tick source
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Session dispatch integration point

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
- REQ-0002: Fail-closed enforcement tiers
- REQ-0004: Lifecycle ordering
- TCK-00492: Implementation ticket
