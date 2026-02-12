# RFC Framer Module

> Generates complete RFC directory structures grounded in CCP (Code Context Protocol) artifacts, ensuring all file references are validated and cryptographically anchored.

## Overview

The `apm2_core::rfc_framer` module sits in the APM2 factory pipeline between PRD authoring and ticket decomposition. It takes a PRD's Impact Map and CCP index as inputs and produces a fully-structured RFC directory with 10 canonical sections, each grounded in the existing codebase inventory.

```text
PRD Artifacts                      RFC Output
evidence/prd/PRD-NNNN/             documents/rfcs/RFC-NNNN/
  ccp/ccp_index.json      --->      00_meta.yaml        (with CCP grounding)
  impact_map/impact_map.yaml         01_problem_and_imports.yaml
                                     02_design_decisions.yaml
documents/prds/PRD-NNNN/             03_trust_boundaries.yaml
  00_meta.yaml             --->      04_contracts_and_versioning.yaml
                                     05_rollout_and_ops.yaml
         |                           06_ticket_decomposition.yaml
         v                           07_test_and_evidence.yaml
   +--------------+                  08_risks_and_open_questions.yaml
   | RFC Framer   |                  09_governance_and_gates.yaml
   +------+-------+
          |
   +------v----------+
   | CCP Grounding   | <-- BLAKE3 hash of CCP index, component refs
   +-----------------+
```

The framer enforces key properties:

- **CCP Grounding**: Every RFC captures the CCP index hash at frame time for staleness detection
- **Path Validation**: File references are validated against CCP inventory (fail-closed)
- **Atomic Writes**: All section files use write-then-rename for crash safety
- **Deterministic Output**: YAML is canonicalized for reproducible content hashing

## Key Types

### `RfcFrameError`

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RfcFrameError {
    Grounding(GroundingError),
    PathValidation(PathValidationError),
    ReadError { path: String, reason: String },
    WriteError { path: String, reason: String },
    DirectoryCreationError { path: String, reason: String },
    ImpactMapNotFound { path: String },
    ImpactMapParseError { reason: String },
    PrdNotFound { path: String },
    CanonicalizeError(CanonicalizeError),
    AtomicWriteError(AtomicWriteError),
    YamlSerializationError { reason: String },
    PathTraversalError { path: String, reason: String },
    FileTooLarge { path: String, size: u64, max_size: u64 },
    RfcAlreadyExists { path: String },
}
```

**Invariants:**

- [INV-RF01] `PathTraversalError` is returned for any PRD or RFC ID containing `/`, `\`, or `..`. This prevents directory traversal attacks.
- [INV-RF02] `FileTooLarge` enforces a 10 MB maximum on all input files.

### `RfcSectionType`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfcSectionType {
    Meta,                   // 00_meta.yaml
    ProblemAndImports,      // 01_problem_and_imports.yaml
    DesignDecisions,        // 02_design_decisions.yaml
    TrustBoundaries,        // 03_trust_boundaries.yaml
    ContractsAndVersioning, // 04_contracts_and_versioning.yaml
    RolloutAndOps,          // 05_rollout_and_ops.yaml
    TicketDecomposition,    // 06_ticket_decomposition.yaml
    TestAndEvidence,        // 07_test_and_evidence.yaml
    RisksAndOpenQuestions,  // 08_risks_and_open_questions.yaml
    GovernanceAndGates,     // 09_governance_and_gates.yaml
}
```

**Invariants:**

- [INV-RF03] `filename()` returns a stable, deterministic filename for each section type.
- [INV-RF04] `all()` returns all 10 section types in canonical order (00 through 09).

**Contracts:**

- [CTR-RF01] `filename()` maps are bijective -- each section type has exactly one filename and vice versa.

### `RfcSection`

```rust
#[derive(Debug, Clone)]
pub struct RfcSection {
    pub section_type: RfcSectionType,
    pub content: String,
}
```

### `RfcFrameOptions`

```rust
#[derive(Debug, Clone, Default)]
pub struct RfcFrameOptions {
    pub force: bool,
    pub dry_run: bool,
    pub skip_validation: bool,
}
```

**Contracts:**

- [CTR-RF02] When `dry_run` is `true`, all generation and validation executes but no files are written.
- [CTR-RF03] When `force` is `false` (default), `RfcAlreadyExists` is returned if the RFC directory already exists.
- [CTR-RF04] When `skip_validation` is `false` (default), file paths are validated against CCP.

### `RfcFrame`

```rust
#[derive(Debug, Clone)]
pub struct RfcFrame {
    pub rfc_id: String,
    pub prd_id: String,
    pub title: String,
    pub ccp_grounding: CcpGrounding,
    pub sections: Vec<RfcSection>,
    pub generated_at: DateTime<Utc>,
}
```

**Invariants:**

- [INV-RF05] `sections` always contains exactly 10 elements, one per `RfcSectionType`.
- [INV-RF06] `sections` are sorted by filename for deterministic output.

### `RfcFrameResult`

```rust
#[derive(Debug, Clone)]
pub struct RfcFrameResult {
    pub frame: RfcFrame,
    pub ccp_grounding: CcpGrounding,
    pub output_dir: PathBuf,
    pub dry_run: bool,
}
```

### `CcpGrounding` (from `grounding` submodule)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CcpGrounding {
    pub ccp_index_ref: String,
    pub ccp_index_hash: String,
    pub impact_map_ref: String,
    pub rationale: String,
    pub component_references: Vec<ComponentReference>,
    pub grounded_at: Option<DateTime<Utc>>,
}
```

**Invariants:**

- [INV-RF07] `ccp_index_hash` is the first 7 hex characters of the BLAKE3 hash of the CCP index file content.
- [INV-RF08] `component_references` are sorted by `id` for deterministic output.

**Contracts:**

- [CTR-RF05] `from_artifacts(repo_root, prd_id)` reads CCP index and Impact Map, extracts component references, and computes the index hash. Fails if either artifact is missing.

### `ComponentReference`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentReference {
    pub id: String,
    pub r#ref: String,
    pub rationale: String,
}
```

### `GroundingError`

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GroundingError {
    ReadError { path: String, reason: String },
    CcpIndexNotFound { path: String },
    CcpIndexParseError { reason: String },
    ImpactMapNotFound { path: String },
    ImpactMapParseError { reason: String },
    PathValidation(PathValidationError),
    PathTraversalError { path: String, reason: String },
    FileTooLarge { path: String, size: u64, max_size: u64 },
}
```

### `PathValidationError`

```rust
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum PathValidationError {
    FileNotFound { path: String },
    FileAlreadyExists { path: String },
    Multiple { errors: Vec<Self> },
}
```

### `RfcFileReferences`

```rust
#[derive(Debug, Clone, Default)]
pub struct RfcFileReferences {
    pub files_to_create: Vec<String>,
    pub files_to_modify: Vec<String>,
}
```

**Contracts:**

- [CTR-RF06] `from_yaml(yaml)` extracts and deduplicates file references from RFC ticket decomposition YAML. Both string and `{path: ...}` formats are supported.

## Public API

### `frame_rfc(repo_root, prd_id, rfc_id, options) -> Result<RfcFrameResult, RfcFrameError>`

Main entry point. Loads Impact Map and CCP artifacts, creates CCP grounding, generates all 10 RFC sections, and writes them atomically to the output directory.

### `CcpGrounding::from_artifacts(repo_root, prd_id) -> Result<CcpGrounding, GroundingError>`

Creates CCP grounding from CCP index and Impact Map artifacts. Computes BLAKE3 hash of the CCP index and extracts component references.

### `validate_paths(repo_root, prd_id, files_to_modify, files_to_create) -> Result<PathValidationResult, GroundingError>`

Validates file paths against the CCP file inventory. `files_to_modify` must exist; `files_to_create` must not exist.

### `RfcFileReferences::from_yaml(yaml) -> Self`

Extracts and deduplicates file references from RFC ticket decomposition YAML.

### `RfcSectionType::{filename, all}()`

Query methods for section type properties.

## Examples

### Framing an RFC

```rust
use std::path::Path;
use apm2_core::rfc_framer::{RfcFrameOptions, frame_rfc};

let result = frame_rfc(
    Path::new("/repo/root"),
    "PRD-0005",
    "RFC-0011",
    &RfcFrameOptions::default(),
)?;

println!("RFC framed at: {}", result.output_dir.display());
println!("CCP index hash: {}", result.ccp_grounding.ccp_index_hash);
println!("Components referenced: {}", result.ccp_grounding.component_references.len());
```

### Dry Run with Grounding Inspection

```rust
use std::path::Path;
use apm2_core::rfc_framer::{RfcFrameOptions, frame_rfc};

let result = frame_rfc(
    Path::new("/repo/root"),
    "PRD-0005",
    "RFC-0020",
    &RfcFrameOptions {
        dry_run: true,
        skip_validation: true,
        ..Default::default()
    },
)?;

// Inspect grounding without writing files
for comp in &result.ccp_grounding.component_references {
    println!("  Component: {} - {}", comp.id, comp.rationale);
}
```

## Related Modules

- [`apm2_core::ticket_emitter`](../ticket_emitter/AGENTS.md) - Consumes the `06_ticket_decomposition.yaml` produced by this module
- [`apm2_core::impact_map`](../impact_map/AGENTS.md) - Produces the Impact Map that feeds into RFC framing
- [`apm2_core::determinism`](../determinism/AGENTS.md) - Provides `canonicalize_yaml` and `write_atomic` used by the framer
- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing used for CCP index grounding

## References

- [RFC-0019: Automated FAC v0](/documents/rfcs/RFC-0019/) - End-to-end ingestion, review episode, durable receipt, GitHub projection
- [RFC Template](/documents/rfcs/template/) - Standard RFC directory structure and section schema
- [APM2 Rust Standards - Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md) - Deterministic output requirements
