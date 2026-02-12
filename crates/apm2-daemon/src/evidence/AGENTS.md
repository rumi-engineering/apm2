# Evidence Module

> Tool receipt generation, evidence binding, signing, flight recording, and retention lifecycle.

## Overview

The `evidence` module handles the full evidence lifecycle within the daemon: creating tool receipts, signing them with Ed25519, binding evidence to CAS hashes, recording events in ring buffers, managing evidence artifact retention via TTL and pinning, and compacting old artifacts with tombstone tracking. Evidence is central to APM2's proof-carrying authority model -- every tool execution produces a signed receipt that binds the episode envelope, policy hash, and evidence references.

```text
evidence/
    |-- receipt.rs         - ToolReceipt, ReceiptKind, and core types
    |-- receipt_builder.rs - Builder pattern for receipt construction
    |-- binding.rs         - Evidence binding for CAS hash collection
    |-- signer.rs          - ReceiptSigner using Ed25519 (TCK-00167)
    |-- verifier.rs        - Receipt verification predicate (TCK-00167)
    |-- keychain.rs        - OS keychain integration for keys (TCK-00167)
    |-- config.rs          - RecorderConfig per risk tier (TCK-00170)
    |-- trigger.rs         - Persistence trigger conditions (TCK-00170)
    |-- recorder.rs        - FlightRecorder implementation (TCK-00170)
    |-- artifact.rs        - EvidenceArtifact with TTL and class (TCK-00171)
    |-- ttl.rs             - TTL enforcement and eviction (TCK-00171)
    |-- pin.rs             - Pin API for evidence retention (TCK-00171)
    |-- tombstone.rs       - Tombstone tracking for compacted artifacts (TCK-00172)
    |-- compaction.rs      - Evidence compaction strategy and jobs (TCK-00172)
    |-- summary.rs         - Compaction receipt generation (TCK-00172)
    `-- cas_access.rs      - CAS access control facade (TCK-00314)
```

## Key Types

### `ToolReceipt`

```rust
pub struct ToolReceipt {
    pub kind: ReceiptKind,
    pub envelope_hash: Hash,
    pub policy_hash: Hash,
    pub canonicalizer_id: CanonicalizerId,
    pub canonicalizer_version: u32,
    pub evidence_refs: Vec<Hash>,
    pub timestamp_ns: u64,
    pub unsigned_bytes_hash: Hash,
    pub signature: Option<Signature>,
    pub signer_identity: Option<SignerIdentity>,
    // ... additional fields
}
```

**Invariants:**

- [INV-EV01] Receipts are immutable after creation.
- [INV-EV02] `canonical_bytes()` excludes signature for signing (unsigned canonical bytes rule).
- [INV-EV03] Evidence refs are sorted for determinism (AD-VERIFY-001).
- [INV-EV04] Evidence refs bounded to `MAX_EVIDENCE_REFS`.

**Contracts:**

- [CTR-EV01] Signature binds all fields to signer identity.
- [CTR-EV02] Constant-time Ed25519 signature verification (CTR-1909).

### `ReceiptSigner`

Signs receipts using Ed25519 with key versioning.

**Contracts:**

- [CTR-EV03] Keys are stored in OS keychain (AD-KEY-001).
- [CTR-EV04] Key rotation increments version number.

### `FlightRecorder`

Ring-buffer-based event recorder that captures tool events, PTY output, and telemetry frames. Configurable per risk tier.

**Invariants:**

- [INV-EV05] Ring buffers are bounded by `MAX_BUFFER_CAPACITY`.
- [INV-EV06] Recorder configuration varies by risk tier (higher tiers get larger buffers).

### `EvidenceArtifact`

```rust
pub struct EvidenceArtifact {
    pub id: ArtifactId,
    pub class: EvidenceClass,
    pub pin_state: PinState,
    pub ttl_secs: u64,
    // ...
}
```

Evidence artifact with TTL and class for retention policy.

**Invariants:**

- [INV-EV07] Pinned artifacts are not evicted regardless of TTL.
- [INV-EV08] Artifact IDs are bounded to `MAX_ARTIFACT_ID_LEN`.

### `TtlEnforcer`

Periodic enforcement of evidence TTL with configurable eviction limits.

**Contracts:**

- [CTR-EV05] `MAX_EVICTIONS_PER_RUN` bounds work per enforcement cycle.
- [CTR-EV06] Eviction emits `EvictionEvent` for audit.

### `PinManager`

Pin API for evidence retention, including defect-triggered grace periods.

### `CompactionJob` / `CompactionStrategy`

Evidence compaction for old artifacts with tombstone tracking and receipt generation.

### `CasAccessFacade`

CAS access control facade that mediates artifact reads/writes with authorization.

## Public API

Key re-exports:

- `ToolReceipt`, `ReceiptKind`, `ReceiptBuilder`, `ReceiptSigning`
- `ReceiptSigner`, `SignerError`, `KeyId`
- `verify_receipt`, `verify_receipt_integrity`, `verify_receipts_batch`
- `FlightRecorder`, `EvidenceBundle`, `ToolEvent`, `RecorderConfig`
- `EvidenceArtifact`, `EvidenceClass`, `PinState`, `ArtifactId`
- `TtlEnforcer`, `TtlEnforcerConfig`, `EvictionEvent`
- `PinManager`, `PinReceipt`, `PinError`
- `CompactionJob`, `CompactionStrategy`, `CompactionReceipt`
- `CasAccessFacade`, `CasAccessType`, `CasAccessError`
- `EvidenceBinding`, `ToolEvidenceCollector`
- `InMemoryKeyStore`, `OsKeychain`, `SigningKeyStore`

## Related Modules

- [`apm2_daemon::cas`](../cas/AGENTS.md) -- Durable CAS backend for artifact storage
- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Episode runtime that produces evidence
- [`apm2_core::evidence`](../../../apm2-core/src/evidence/AGENTS.md) -- Core evidence types and `EvidenceReducer`
- [`apm2_core::crypto`](../../../apm2-core/src/crypto/AGENTS.md) -- Cryptographic primitives

## References

- AD-RECEIPT-001: Tool receipt generation
- AD-VERIFY-001: Deterministic serialization
- AD-KEY-001: Key lifecycle management
- CTR-1303: Bounded collections with `MAX_*` constants
- CTR-1909: Constant-time operations for sensitive comparisons
