# Context Module

> OCAP-based context pack manifests, firewall middleware, and deterministic recipe compilation for file access control and context-as-code.

## Overview

The `apm2_core::context` module implements the Context-as-Code (CAC) infrastructure specified in RFC-0011. It provides three subsystems:

1. **Manifest** (`ContextPackManifest`): OCAP allowlist defining which files an agent may read, with content-hash verification for TOCTOU protection
2. **Firewall** (`DefaultContextFirewall`): Middleware that enforces manifest allowlists with configurable enforcement modes (Warn, SoftFail, HardFail)
3. **Recipe** (`ContextPackRecipe`): Deterministic compilation of hash-pinned selector inputs into reproducible, content-addressed context artifacts with drift fingerprinting

```text
  ContextPackSelectorInput          ContextPackRecipeCompiler
  ┌────────────────────┐            ┌──────────────────────┐
  │ role_spec_hash     │───────────>│ validate_closure()   │
  │ required_reads     │            │ normalize_paths()    │
  │ read_digests       │            │ compile()            │
  │ manifest_hash      │            └──────────┬───────────┘
  │ budget_hash        │                       │
  └────────────────────┘                       ▼
                                  CompiledContextPackRecipe
                                  ┌──────────────────────┐
                                  │ recipe (CAS-stored)  │
                                  │ fingerprint (drift)  │
                                  └──────────────────────┘

  ContextPackManifest              DefaultContextFirewall
  ┌────────────────────┐          ┌──────────────────────┐
  │ entries: [{        │          │ validate_read(path)  │
  │   path,            │─────────>│   ├─ In allowlist?   │
  │   content_hash,    │          │   ├─ Hash matches?   │
  │   access_level     │          │   └─ Mode: Warn /    │
  │ }]                 │          │     SoftFail/HardFail│
  │ seal: blake3(...)  │          └──────────────────────┘
  └────────────────────┘
```

## Key Types

### `ContextPackManifest`

```rust
pub struct ContextPackManifest {
    // Internal fields: manifest_id, profile_id, entries (HashMap),
    // tool_allowlist, write_allowlist, shell_allowlist
}
```

OCAP allowlist for file reads. Entries map normalized paths to content hashes and access levels.

**Invariants:**

- [INV-CX01] Maximum `MAX_ENTRIES` (10,000) entries per manifest
- [INV-CX02] Paths are normalized (no traversal, no redundant separators)
- [INV-CX03] Seal is deterministic: same entries always produce the same BLAKE3 hash
- [INV-CX04] Seal is tamper-evident: any modification changes the hash

**Contracts:**

- [CTR-CX01] `is_allowed(path, hash)` returns `false` for paths not in the manifest
- [CTR-CX02] `is_allowed(path, hash)` returns `false` for hash mismatches (constant-time comparison)
- [CTR-CX03] `seal()` returns the BLAKE3 content hash for `ClaimWorkResponse.context_pack_hash`
- [CTR-CX04] `verify_seal(expected)` detects tampering

### `ManifestEntry`

```rust
pub struct ManifestEntry {
    // path, content_hash, stable_id, access_level
}
```

Individual file entry with path, BLAKE3 content hash, optional stable ID, and access level.

### `AccessLevel`

```rust
pub enum AccessLevel {
    Read,          // Basic read access
    ReadWithZoom,  // Read with content hash verification
}
```

**Contracts:**

- [CTR-CX05] `ReadWithZoom` requires content hash match on every read
- [CTR-CX06] `Read` allows reads without hash verification (hash still stored for auditing)

### `ToolClass`

```rust
#[repr(u8)]
#[non_exhaustive]
pub enum ToolClass {
    Read = 0, Write = 1, Execute = 2, Network = 3, Git = 4,
    Inference = 5, Artifact = 6, ListFiles = 7, Search = 8,
}
```

Coarse-grained tool capability categorization. Canonical definition for the system; re-exported by `apm2-daemon`.

**Invariants:**

- [INV-CX05] Explicit discriminant values maintain semver stability
- [INV-CX06] `from_u32()` validates the full u32 range to prevent truncation attacks

**Contracts:**

- [CTR-CX07] `parse(s)` rejects names longer than `MAX_TOOL_CLASS_NAME_LEN` (64 bytes)

### `ContextPackManifestBuilder`

Builder pattern for constructing manifests:

```rust
let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
    .add_entry(ManifestEntryBuilder::new("/src/main.rs", [0x42; 32]).build())
    .build();
```

### `FirewallMode`

```rust
pub enum FirewallMode {
    Warn,      // Log warning, allow read
    SoftFail,  // Return error, allow retry (default)
    HardFail,  // Return error, terminate session
}
```

### `DefaultContextFirewall`

```rust
pub struct DefaultContextFirewall<'a> {
    // manifest reference, mode
}
```

Middleware that validates file reads against a manifest allowlist.

**Invariants:**

- [INV-CX07] All reads outside the allowlist are denied (or warned in Warn mode)
- [INV-CX08] Path normalization prevents traversal attacks
- [INV-CX09] Path length bounded by `MAX_PATH_LENGTH` (4096) to prevent DoS

**Contracts:**

- [CTR-CX08] `validate_read(path, hash)` returns `Ok` for allowed reads, `Err(ContextFirewallError)` for denied
- [CTR-CX09] `FirewallDecision` audit events emitted for all denials
- [CTR-CX10] TOCTOU protection: runtime content hash verified against manifest (CTX-TOCTOU-001)

### `ContextAwareValidator` (trait)

```rust
pub trait ContextAwareValidator {
    fn validate_read(&self, path: &str, content_hash: Option<&[u8; 32]>)
        -> Result<ValidationResult, ContextFirewallError>;
}
```

Trait for context-aware validation, implemented by `DefaultContextFirewall`.

### `ContextPackRecipe`

```rust
pub struct ContextPackRecipe {
    // schema, version, role_spec_hash, required_read_paths,
    // required_read_digests_hash, context_manifest_hash, budget_profile_hash
}
```

Deterministic, content-addressed recipe for context pack compilation. Stored in CAS.

**Invariants:**

- [INV-CX10] Required read paths are sorted canonically
- [INV-CX11] No duplicate paths after normalization
- [INV-CX12] All paths are workspace-relative, no absolute paths or traversal

### `ContextPackRecipeCompiler`

Compiles `ContextPackSelectorInput` into `CompiledContextPackRecipe` with:
- Path normalization and closure validation
- Symlink rejection
- Workspace boundary enforcement
- Drift fingerprint generation
- Selector closure completeness gate (RFC-0029 REQ-0002): high-risk tiers (Tier1+) require complete loss-profile declarations for every selector digest

**Contracts:**

- [CTR-CX11] Rejects paths outside workspace boundaries
- [CTR-CX12] Rejects symlink paths (prevents escape)
- [CTR-CX13] Enforces `MAX_REQUIRED_READ_PATHS` (10,000), `MAX_AGGREGATE_COMPONENTS` (100,000)
- [CTR-CX14] Selector closure completeness: Tier1+ selectors without complete loss profiles are denied with `SelectorClosureIncomplete` reason code

### `DriftFingerprint`

Content hash of the compiled recipe used for run-to-run comparison and incremental rebuild detection.

### `DriftFingerprintBinding`

Binds a drift fingerprint to a specific work object, epoch, and timestamp for persistence.

### `RecipeCompilerError`

```rust
#[non_exhaustive]
pub enum RecipeCompilerError {
    SelectorClosure { code: RecipeCompilerReasonCode, message, path },
    RecipeValidation { code, message },
    CasError { code, message },
    // ...
}
```

Machine-readable error codes via `RecipeCompilerReasonCode` for structured error handling.

## Public API

### Manifest

- `ContextPackManifestBuilder::new(id, profile_id)` - Start building a manifest
- `ContextPackManifest::is_allowed(path, hash)` - Check if a read is permitted
- `ContextPackManifest::seal()` - Compute BLAKE3 seal hash
- `ContextPackManifest::verify_seal(expected)` - Tamper detection
- `normalize_path(path)` - Normalize a path for manifest lookup
- `shell_pattern_matches(pattern, path)` - Shell allowlist pattern matching

### Firewall

- `DefaultContextFirewall::new(manifest, mode)` - Create firewall middleware
- `ContextAwareValidator::validate_read(path, hash)` - Validate a file read

### Recipe

- `ContextPackRecipeCompiler::compile(input, workspace_root)` - Compile a recipe
- `load_fingerprint_from_cas(cas, hash)` - Load a fingerprint from CAS
- `reconstruct_from_receipts(cas, receipt_hashes)` - Reconstruct recipe from CAS receipts

## Resource Limit Constants

| Constant | Value | Purpose |
|---|---|---|
| `MAX_ENTRIES` | 10,000 | Max manifest entries |
| `MAX_PATH_LENGTH` | 4,096 | Max path length in bytes |
| `MAX_PATH_COMPONENTS` | 256 | Max path segments |
| `MAX_TOOL_ALLOWLIST` | 100 | Max tool classes per manifest |
| `MAX_WRITE_ALLOWLIST` | 1,000 | Max write-allowed paths |
| `MAX_SHELL_ALLOWLIST` | 500 | Max shell patterns |
| `MAX_SHELL_PATTERN_LEN` | 1,024 | Max shell pattern length |
| `MAX_REQUIRED_READ_PATHS` | 10,000 | Max recipe required reads |
| `MAX_AGGREGATE_COMPONENTS` | 100,000 | Max total path components per compile |
| `MAX_RECIPE_ARTIFACT_BYTES` | 1 MiB | Max recipe size for CAS replay |

## Examples

### Building and Using a Manifest

```rust
use apm2_core::context::{
    AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder,
};

let manifest = ContextPackManifestBuilder::new("manifest-001", "profile-001")
    .add_entry(
        ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
            .stable_id("main")
            .access_level(AccessLevel::Read)
            .build(),
    )
    .build();

assert!(manifest.is_allowed("/project/src/main.rs", None).unwrap());
assert!(!manifest.is_allowed("/etc/passwd", None).unwrap());
```

### Firewall Enforcement

```rust
use apm2_core::context::firewall::{
    ContextAwareValidator, DefaultContextFirewall, FirewallMode,
};

let firewall = DefaultContextFirewall::new(&manifest, FirewallMode::SoftFail);

// Allowed read
let result = firewall.validate_read("/project/src/main.rs", None);
assert!(result.is_ok());

// Denied read (not in allowlist)
let result = firewall.validate_read("/etc/passwd", None);
assert!(result.is_err());
```

### `ProofCache` (RFC-0029 REQ-0003)

```rust
pub struct ProofCache {
    // entries: HashMap<[u8; 32], CachedProofEntry>  (bounded)
    // policy: ProofCachePolicy
    // metrics: ProofCacheMetrics
}
```

Bounded, policy-gated proof cache for verification amortization. Maps proof keys (BLAKE3 hashes of admission inputs) to cached verification results with TTL-based freshness and generation-based revocation invalidation.

**Invariants:**

- [INV-CX20] Cache entries are bounded by `MAX_PROOF_CACHE_ENTRIES` (100,000); overflow returns `Err`, never evicts silently
- [INV-CX21] Stale entries (TTL exceeded) produce deterministic deny with `StaleCacheEntry`
- [INV-CX22] Revoked entries (older revocation generation) produce deterministic deny with `RevokedCacheEntry`
- [INV-CX23] Cache reuse is policy-gated: `allow_reuse=false` disables cache hits entirely

**Contracts:**

- [CTR-CX20] `lookup(key, tick)` returns `Hit`/`Miss`/`Err(Defect)` — never silently serves stale data
- [CTR-CX21] `insert(key, result, tick)` enforces capacity bounds atomically (check-then-insert with `&mut self`)
- [CTR-CX22] `verify_batch(inputs, tick, verifier_fn)` deduplicates by proof key, serves cache hits, computes only misses, returns results in input order
- [CTR-CX23] `invalidate_generation()` bumps revocation generation counter (saturating), invalidating all older entries on next lookup

**Resource Limits:**

| Constant | Value | Purpose |
|---|---|---|
| `MAX_PROOF_CACHE_ENTRIES` | 100,000 | Hard cap on cache entries |
| `DEFAULT_MAX_TTL_TICKS` | 1,000 | Default freshness TTL |

## Related Modules

- [`apm2_core::evidence`](../evidence/AGENTS.md) - `ContentAddressedStore` used by recipe compilation
- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing for seals and content verification
- [`apm2_core::determinism`](../determinism/AGENTS.md) - `canonicalize_json` used by recipe serialization
- [`apm2_core::channel`](../channel/AGENTS.md) - `context_firewall_verified` flag in boundary checks
- [`apm2_core::budget`](../budget/AGENTS.md) - Budget profile hash in recipe selectors

## References

- [RFC-0011: Context-as-Code (CAC) v1](../../../../documents/rfcs/RFC-0011/) - Canonical Context Pipeline
- [RFC-0015: Forge Admission Cycle](../../../../documents/rfcs/RFC-0015/) - OCAP containment model
- [APM2 Rust Standards: API Design](/documents/skills/rust-standards/references/25_api_design_stdlib_quality.md) - Builder pattern conventions
