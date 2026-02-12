# HMP Module

> Holonic Message Protocol (HMP) -- digest-first channels and admission receipt semantics.

## Overview

The `hmp` module implements the Holonic Message Protocol as specified in RFC-0020 section 7.3. HMP provides digest-first message envelopes for cross-cell communication, where payload bodies are referenced by CAS hash rather than inlined. This separates routing (envelope-level metadata) from content (CAS-resolved bodies), preventing unsolicited large payloads from being parsed before admission checks.

The module also implements the admission pipeline for cross-cell fact imports per RFC-0020 section 2.4.0b, ensuring that replicated bytes without admission receipts are treated as untrusted cache rather than truth-plane facts.

### Digest-First Design

All message payloads are referenced by CAS hash (`body_ref`) rather than inlined. The envelope is validated first, and the body is fetched only if the envelope passes admission checks.

### Channel Class Semantics (RFC-0020 section 7.3)

- **DISCOVERY**: Signed holon/relay endpoint announcements
- **HANDSHAKE**: Session establishment and permeability grant exchange
- **WORK**: Task delegation and tool execution requests
- **EVIDENCE**: Anti-entropy offers, CAS artifact requests/deliveries
- **GOVERNANCE**: Stop/rotation governance messages across cells

## Key Types

### `ChannelClass`

```rust
pub enum ChannelClass {
    Discovery,
    Handshake,
    Work,
    Evidence,
    Governance,
}
```

**Invariants:**

- [INV-HM01] Unknown channel classes are rejected (fail-closed).
- [INV-HM02] `message_class` prefix must be consistent with `channel_class`.
- [INV-HM03] Only `Work` and `Governance` channels can carry authority-bearing messages.

### `HmpMessageV1`

HMP message envelope with digest-first payload references and bounded metadata.

**Invariants:**

- [INV-HM04] Envelope size bounded to `MAX_ENVELOPE_BYTES` (16 KiB).
- [INV-HM05] Causal parent references bounded to `MAX_PARENTS` (64).
- [INV-HM06] All string fields reject control characters (canonicalization safety).
- [INV-HM07] `#[serde(deny_unknown_fields)]` on all boundary structs.

**Contracts:**

- [CTR-HM01] All hash computations use JCS-canonical JSON via `Canonicalizable`.
- [CTR-HM02] Body content is never inlined in the envelope wire shape.

### `BodyRef`

CAS hash + content type for digest-first payload referencing.

### `AdmissionReceiptV1`

Receipt for imported authoritative facts from cross-cell ingestion, binding source cell identity, admitted range/hash set, verification method, and local ledger anchor.

**Invariants:**

- [INV-HM08] Every successful cross-cell import emits an `AdmissionReceiptV1`.
- [INV-HM09] Replicated bytes without receipts are untrusted cache, not truth-plane facts.
- [INV-HM10] Admitted hashes bounded to `MAX_ADMITTED_HASHES` (100,000).

### `ImportReceiptV1`

Typed wrapper around `AdmissionReceiptV1` for specific import categories (ledger ranges, policy roots, permeability grants).

### `DigestFirstFetchPolicy`

```rust
pub struct DigestFirstFetchPolicy {
    pub max_body_bytes: usize,
    pub max_concurrent_fetches: usize,
    pub fetch_timeout_ms: u64,
}
```

Policy governing digest-first body fetching to prevent resource exhaustion.

**Contracts:**

- [CTR-HM03] `check_body_size()` denies bodies exceeding the configured limit.
- [CTR-HM04] Maximum body fetch size: `MAX_BODY_FETCH_BYTES` (16 MiB).

## Public API

### Constants

- `MAX_ENVELOPE_BYTES`: 16,384
- `MAX_PARENTS`: 64
- `MAX_PROTOCOL_ID_LEN`: 128
- `MAX_MESSAGE_CLASS_LEN`: 128
- `MAX_CONTENT_TYPE_LEN`: 256
- `MAX_ADMITTED_HASHES`: 100,000
- `MAX_BODY_FETCH_BYTES`: 16 MiB
- `MAX_CONCURRENT_FETCHES`: 16
- `MAX_ADMISSION_BATCH_SIZE`: 10,000

## Related Modules

- [`apm2_daemon::identity`](../identity/AGENTS.md) -- Canonical identity identifiers for cell/holon addressing
- [`apm2_daemon::cas`](../cas/AGENTS.md) -- CAS backend for body resolution
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Wire protocol for IPC
- [`apm2_core::htf`](../../../apm2-core/src/htf/AGENTS.md) -- `Canonicalizable` trait for hash computation

## References

- RFC-0020 section 7.3: `HMPMessageV1` envelope and classes
- RFC-0020 section 2.4.0b: Admission receipts (normative)
- RFC-0020 section 2.4.0: Control-plane vs data-plane separation
- REQ-0034: Digest-first HMP classes and admission receipts
