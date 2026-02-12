# HSI Contract Module

> HSI Contract Manifest V1 -- canonical inventory of daemon/CLI dispatch routes with deterministic hashing.

## Overview

The `hsi_contract` module implements the Holonic Substrate Interface (HSI) Contract Manifest as specified in RFC-0020 section 3.1. The manifest is a canonical inventory of all daemon and CLI dispatch routes with their semantics annotations (authoritative, idempotency, receipt requirements). The manifest is deterministically serialized and content-addressed via BLAKE3, enabling handshake-time contract binding between CLI and daemon.

Key design principles:

- **Determinism**: Identical code + build inputs produce identical `cli_contract_hash`
- **Completeness**: Missing route semantics annotations fail the build
- **Tiered mismatch policy**: Risk-tier-dependent behavior when hashes diverge during handshake

```text
HSIContractManifestV1
    +-- schema: "apm2.hsi_contract.v1"
    +-- schema_version: "1.0.0"
    +-- cli_version: CliVersion
    +-- routes: Vec<HsiRouteEntry> (sorted by route)
    +-- canonical_bytes() -> Result<Vec<u8>, ManifestValidationError>
    +-- content_hash()   -> Result<String, ManifestValidationError>
```

## Key Types

### `HsiContractManifestV1`

The manifest artifact containing all route entries and their semantics.

**Invariants:**

- [INV-HC01] Routes are sorted lexicographically by `route` field.
- [INV-HC02] Route count bounded to `MAX_ROUTES` (1,024).
- [INV-HC03] All string fields bounded by `MAX_ROUTE_LEN` / `MAX_SCHEMA_ID_LEN`.
- [INV-HC04] `canonical_bytes()` produces deterministic output.

**Contracts:**

- [CTR-HC01] `content_hash()` uses domain separation: `blake3("apm2:apm2.hsi_contract.v1:1.0.0\n" + canonical_bytes)`.
- [CTR-HC02] `build_manifest()` returns error if any route lacks semantics annotations.

### `HsiRouteEntry`

```rust
pub struct HsiRouteEntry {
    pub id: String,
    pub route: String,
    pub stability: StabilityClass,
    pub request_schema: String,
    pub response_schema: String,
    pub semantics: HsiRouteSemantics,
}
```

### `HsiRouteSemantics`

```rust
pub struct HsiRouteSemantics {
    pub authoritative: bool,
    pub idempotency: IdempotencyRequirement,
    pub receipt_required: bool,
}
```

### `StabilityClass`

Route stability classification (Stable, Beta, Experimental, Internal).

### `IdempotencyRequirement`

Idempotency guarantee level for a route.

### `ContractBinding` / `SessionContractBinding`

Handshake-time binding of `cli_contract_hash` and canonicalizer metadata. Exchanged during Hello/HelloAck.

**Contracts:**

- [CTR-HC03] Tier0/Tier1: warn and waive on mismatch.
- [CTR-HC04] Tier2+: deny by default on mismatch (fail-closed).

### `RiskTier` (handshake_binding)

```rust
pub enum RiskTier {
    Tier0, Tier1, Tier2, Tier3, Tier4,
}
```

**Contracts:**

- [CTR-HC05] `allows_mismatch_waiver()` returns `true` only for Tier0/Tier1.
- [CTR-HC06] Unknown or error states during mismatch evaluation result in DENY.

### `ManifestValidationError`

```rust
pub enum ManifestValidationError {
    RoutesNotSorted { before: String, after: String },
    RouteCountOverflow { count: usize },
    StringLengthOverflow { field: String, length: usize, max: usize },
}
```

## Public API

- `HsiContractManifestV1`, `HsiRouteEntry`, `HsiRouteSemantics`
- `CliVersion`, `StabilityClass`, `IdempotencyRequirement`
- `ManifestValidationError`
- `build_manifest` -- Builds the manifest from the route registry
- `ContractBinding`, `SessionContractBinding`, `ContractBindingError`
- `evaluate_mismatch_policy`, `validate_contract_binding`
- `RiskTier`, `MismatchOutcome`, `CanonicalizerInfo`

## Related Modules

- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- Handshake negotiation where contract hash is exchanged
- [`apm2_daemon::identity`](../identity/AGENTS.md) -- Identity types used in contract binding

## References

- RFC-0020 section 3.1: `HSIContractManifestV1`
- RFC-0020 section 3.1.1: Generation and determinism
- RFC-0020 section 3.1.2: `cli_contract_hash` in session handshake
- RFC-0020 section 3.1.3: Fail-closed mismatch behavior
- RFC-0020 section 1.5: `ContentHash` and canonical bytes
- RFC-0020 section 1.5.2: Domain separation
- REQ-0001: `HSIContractManifest` deterministic generation
- REQ-0002: Handshake contract hash and canonicalizer binding
