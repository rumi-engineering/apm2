# Run Manifest Module

> Cryptographically signed execution manifests capturing input/output hashes, routing decisions, and stage timings for reproducibility auditing.

## Overview

The `apm2_core::run_manifest` module provides the infrastructure for creating and verifying cryptographically signed records of pipeline execution. A run manifest is a complete, tamper-evident record of a single pipeline run that enables reproducibility auditing and provenance tracking.

Each manifest captures:

- **Input artifacts** -- BLAKE3 hashes of all input files
- **Output artifacts** -- BLAKE3 hashes of all generated files
- **Routing decisions** -- Which provider handled each pipeline stage
- **Stage timings** -- Duration of each stage in milliseconds
- **CCP grounding** -- Hash of the CCP index used for context

Manifests are signed using Ed25519 from the `apm2_core::crypto` module.

```text
ManifestBuilder
       |
       +--- with_lease_id(id)
       +--- with_routing_profile_id(id)
       +--- with_ccp_index_hash(hash)
       +--- add_input(path, content) --> BLAKE3 hash computed
       +--- add_output(path, content) --> BLAKE3 hash computed
       +--- record_routing_decision(stage, provider)
       +--- record_stage_timing(stage, duration_ms)
       |
       v
RunManifest (deterministic BTreeMap ordering)
       |
       v
sign_manifest(manifest, signer) --> SignedManifest
       |                                |
       |                                +--- manifest_bytes (canonical JSON)
       |                                +--- signature (Ed25519)
       |                                +--- public_key (hex-encoded)
       v
verify_manifest(signed) --> Result<RunManifest, ManifestSignerError>
verify_manifest_with_key(signed, key) --> Result<RunManifest, ManifestSignerError>
```

### Signing Flow

1. Manifest is serialized to canonical JSON (BTreeMap ensures sorted keys)
2. JSON bytes are signed with Ed25519
3. Bytes, signature, and public key are bundled into a `SignedManifest`
4. Verification reverses the process: parse key, verify signature, deserialize manifest

## Key Types

### `RunManifest`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RunManifest {
    pub manifest_id: String,
    pub lease_id: String,
    pub created_at: DateTime<Utc>,
    pub input_hashes: BTreeMap<String, String>,
    pub output_hashes: BTreeMap<String, String>,
    pub routing_profile_id: String,
    pub routing_decisions: BTreeMap<String, String>,
    pub stage_timings: BTreeMap<String, u64>,
    pub ccp_index_hash: String,
}
```

**Invariants:**

- [INV-RM01] Manifests are deterministically serialized: `BTreeMap` ordering ensures canonical JSON representation regardless of insertion order.
- [INV-RM02] UUID v7 manifest IDs enable temporal ordering of manifests.
- [INV-RM03] Signatures cover the canonical representation (the byte output of `canonical_bytes()`).
- [INV-RM04] All BLAKE3 hashes are hex-encoded strings.
- [INV-RM05] Serialization round-trip is lossless: `from_json(to_json(manifest)) == manifest`.

**Contracts:**

- [CTR-RM01] `canonical_bytes()` returns deterministic JSON bytes suitable for signing.
- [CTR-RM02] `content_hash()` returns the BLAKE3 hash of `canonical_bytes()`.

### `ManifestBuilder`

```rust
#[derive(Debug, Default)]
pub struct ManifestBuilder {
    lease_id: Option<String>,
    routing_profile_id: Option<String>,
    ccp_index_hash: Option<String>,
    input_hashes: BTreeMap<String, String>,
    output_hashes: BTreeMap<String, String>,
    routing_decisions: BTreeMap<String, String>,
    stage_timings: BTreeMap<String, u64>,
}
```

**Contracts:**

- [CTR-RM03] `build()` requires `lease_id`, `routing_profile_id`, and `ccp_index_hash` to be set; returns `ManifestError::MissingField` otherwise.
- [CTR-RM04] `build()` generates a UUID v7 manifest ID automatically.
- [CTR-RM05] `build_with_id(id, created_at)` allows deterministic IDs for testing and replay.
- [CTR-RM06] `add_input(path, content)` computes the BLAKE3 hash of `content` and stores the hex-encoded result.
- [CTR-RM07] `add_output(path, content)` computes the BLAKE3 hash of `content` and stores the hex-encoded result.

### `SignedManifest`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest_bytes: Vec<u8>,  // base64-encoded in JSON
    pub signature: Vec<u8>,       // base64-encoded in JSON
    pub public_key: String,       // hex-encoded Ed25519 public key
}
```

**Invariants:**

- [INV-RM06] `manifest_bytes` and `signature` are base64-encoded in their JSON serialization.
- [INV-RM07] `public_key` is hex-encoded and exactly 64 hex characters (32 bytes).
- [INV-RM08] Ed25519 signatures are deterministic: signing the same manifest with the same key produces identical signatures.

**Contracts:**

- [CTR-RM08] `manifest_id()` extracts the manifest ID by deserializing the manifest bytes.
- [CTR-RM09] Serialization round-trip is lossless, and the deserialized `SignedManifest` still verifies.

### `ManifestError`

```rust
pub enum ManifestError {
    MissingField { field: &'static str },
    InvalidValue { field: &'static str, reason: String },
}
```

### `ManifestSignerError`

```rust
pub enum ManifestSignerError {
    VerificationFailed(String),
    DeserializationFailed(String),
    SignerError(SignerError),
}
```

## Public API

### Building Manifests

- `ManifestBuilder::new() -> Self` -- Creates a new builder.
- `ManifestBuilder::with_lease_id(id) -> Self` -- Sets the lease ID (required).
- `ManifestBuilder::with_routing_profile_id(id) -> Self` -- Sets the routing profile ID (required).
- `ManifestBuilder::with_ccp_index_hash(hash) -> Self` -- Sets the CCP index hash (required).
- `ManifestBuilder::add_input(path, content) -> Self` -- Adds an input with auto-computed BLAKE3 hash.
- `ManifestBuilder::add_input_hash(path, hash) -> Self` -- Adds an input with a pre-computed hash.
- `ManifestBuilder::add_output(path, content) -> Self` -- Adds an output with auto-computed BLAKE3 hash.
- `ManifestBuilder::add_output_hash(path, hash) -> Self` -- Adds an output with a pre-computed hash.
- `ManifestBuilder::record_routing_decision(stage, provider) -> Self` -- Records which provider handled a stage.
- `ManifestBuilder::record_stage_timing(stage, duration_ms) -> Self` -- Records stage execution duration.
- `ManifestBuilder::build() -> Result<RunManifest, ManifestError>` -- Builds with auto-generated UUID v7 ID.
- `ManifestBuilder::build_with_id(id, created_at) -> Result<RunManifest, ManifestError>` -- Builds with explicit ID and timestamp.

### Manifest Operations

- `RunManifest::canonical_bytes() -> Vec<u8>` -- Returns deterministic JSON bytes for signing.
- `RunManifest::content_hash() -> [u8; 32]` -- Returns the BLAKE3 hash of canonical bytes.

### Signing and Verification

- `sign_manifest(manifest, signer) -> SignedManifest` -- Signs a manifest with Ed25519.
- `verify_manifest(signed) -> Result<RunManifest, ManifestSignerError>` -- Verifies using the embedded public key.
- `verify_manifest_with_key(signed, expected_key) -> Result<RunManifest, ManifestSignerError>` -- Verifies using a specific expected public key.
- `SignedManifest::manifest_id() -> Result<String, ManifestSignerError>` -- Extracts the manifest ID without full verification.

## Examples

### Building and Signing a Manifest

```rust
use apm2_core::crypto::Signer;
use apm2_core::run_manifest::{ManifestBuilder, sign_manifest, verify_manifest};

let manifest = ManifestBuilder::new()
    .with_lease_id("lease-abc123")
    .with_routing_profile_id("production")
    .with_ccp_index_hash("deadbeef")
    .add_input("requirements.yaml", b"requirement content")
    .add_output("impact_map.yaml", b"generated output")
    .record_routing_decision("impact_map", "claude-opus-4")
    .record_stage_timing("impact_map", 1500)
    .build()
    .unwrap();

let signer = Signer::generate();
let signed = sign_manifest(&manifest, &signer);

// Verify and extract
let verified = verify_manifest(&signed).unwrap();
assert_eq!(verified.lease_id, "lease-abc123");
```

### Deterministic Ordering

```rust
use apm2_core::run_manifest::ManifestBuilder;
use chrono::{TimeZone, Utc};

let ts = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();

// Insertion order does not affect canonical representation
let m1 = ManifestBuilder::new()
    .with_lease_id("lease")
    .with_routing_profile_id("prod")
    .with_ccp_index_hash("hash")
    .add_input_hash("z_input.yaml", "hash_z")
    .add_input_hash("a_input.yaml", "hash_a")
    .build_with_id("id", ts)
    .unwrap();

let m2 = ManifestBuilder::new()
    .with_lease_id("lease")
    .with_routing_profile_id("prod")
    .with_ccp_index_hash("hash")
    .add_input_hash("a_input.yaml", "hash_a")
    .add_input_hash("z_input.yaml", "hash_z")
    .build_with_id("id", ts)
    .unwrap();

assert_eq!(m1.canonical_bytes(), m2.canonical_bytes());
```

## Related Modules

- [`apm2_core::crypto`](../crypto/AGENTS.md) -- `Signer`, `VerifyingKey`, `EventHasher::hash_content()`, Ed25519 signing/verification
- [`apm2_core::model_router`](../model_router/AGENTS.md) -- Routing profiles whose decisions are recorded in manifests
- [`apm2_core::lease`](../lease/AGENTS.md) -- Lease identity referenced by `lease_id`
- [`apm2_core::evidence`](../evidence/AGENTS.md) -- Content-addressed storage for manifest artifacts

## References

- [15 -- Errors, Panics, Diagnostics](/documents/skills/rust-standards/references/15_errors_panics_diagnostics.md) -- error type design with `thiserror`
- [25 -- API Design, stdlib Quality](/documents/skills/rust-standards/references/25_api_design_stdlib_quality.md) -- builder pattern design
- [40 -- Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md) -- deterministic serialization requirements
