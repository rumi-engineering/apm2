# Ticket Emitter Module

> Decomposes RFC ticket decomposition sections into atomic, implementable ticket YAML files with stable IDs, validated paths, and verification commands.

## Overview

The `apm2_core::ticket_emitter` module is part of the APM2 factory pipeline that converts high-level RFC specifications into concrete work items. It sits between the RFC authoring step and the work execution loop, producing ticket artifacts that drive the Forge Admission Cycle (FAC).

```text
RFC Directory                          Ticket Output
documents/rfcs/RFC-NNNN/              documents/work/tickets/
  06_ticket_decomposition.yaml  --->    TCK-00001.yaml
                                        TCK-00002.yaml
         |                              TCK-00003.yaml
         v
   +----------------+
   | Ticket Emitter |
   +------+---------+
          |
   +------v---------+
   | Path Validation | <-- CCP index or filesystem
   +----------------+
```

The emitter enforces several security and correctness properties:

- **Idempotency**: Ticket IDs are stable across re-runs (derived from decomposition, not generated randomly)
- **Path safety**: All file paths are validated against CCP inventory or filesystem, with traversal protection
- **Atomic writes**: Output files use write-then-rename to prevent partial writes
- **Deterministic output**: YAML is canonicalized for reproducible content hashing

## Key Types

### `TicketEmitError`

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TicketEmitError {
    DecompositionNotFound { path: String },
    DecompositionParseError { reason: String },
    ReadError { path: String, reason: String },
    WriteError { path: String, reason: String },
    DirectoryCreationError { path: String, reason: String },
    PathValidation(TicketValidationError),
    CanonicalizeError(CanonicalizeError),
    AtomicWriteError(AtomicWriteError),
    YamlSerializationError { reason: String },
    PathTraversalError { path: String, reason: String },
    FileTooLarge { path: String, size: u64, max_size: u64 },
    RfcNotFound { path: String },
    NoTickets,
    TicketIdConflict { id: String },
}
```

**Invariants:**

- [INV-TE01] `PathTraversalError` is returned for any RFC ID not matching `RFC-NNNN` (4-8 digits) or any ticket ID not matching `TCK-NNNNN` (exactly 5 digits). This prevents path traversal and shell injection.
- [INV-TE02] `FileTooLarge` enforces a 10 MB maximum on input files to prevent denial-of-service.

### `TicketEmitOptions`

```rust
#[derive(Debug, Clone, Default)]
pub struct TicketEmitOptions {
    pub force: bool,
    pub dry_run: bool,
    pub skip_validation: bool,
    pub prd_id: Option<String>,
}
```

**Contracts:**

- [CTR-TE01] When `dry_run` is `true`, no files are written to disk but all validation and generation steps execute normally.
- [CTR-TE02] When `force` is `true`, existing ticket files are overwritten without conflict errors.
- [CTR-TE03] When `skip_validation` is `false` (default), all file paths referenced in tickets are validated against CCP or filesystem. Validation failure is a hard error (fail-closed).

### `EmittedTicket`

```rust
#[derive(Debug, Clone)]
pub struct EmittedTicket {
    pub id: String,
    pub title: String,
    pub status: String,
    pub rfc_id: String,
    pub requirement_ids: Vec<String>,
    pub depends_on: Vec<String>,
    pub summary: String,
    pub files_to_create: Vec<TicketFile>,
    pub files_to_modify: Vec<TicketFile>,
    pub implementation_steps: Vec<ImplementationStep>,
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    pub test_requirements: Vec<TestRequirement>,
    pub notes: String,
    pub yaml_content: String,
}
```

**Invariants:**

- [INV-TE03] `id` always matches the pattern `TCK-NNNNN` (5 digits, validated at parse time).
- [INV-TE04] `test_requirements` is never empty; if the decomposition provides no verification commands, defaults are generated.
- [INV-TE05] `yaml_content` is canonicalized YAML produced by `determinism::canonicalize_yaml`.
- [INV-TE06] `depends_on` references are resolved to stable ticket IDs from the same decomposition.

### `TicketEmitResult`

```rust
#[derive(Debug, Clone)]
pub struct TicketEmitResult {
    pub tickets: Vec<EmittedTicket>,
    pub rfc_id: String,
    pub output_dir: PathBuf,
    pub dry_run: bool,
    pub warnings: Vec<String>,
}
```

### `TicketFile`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketFile {
    pub path: String,
    pub purpose: Option<String>,
    pub changes: Option<String>,
}
```

### `ImplementationStep`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationStep {
    pub step: u32,
    pub action: String,
    pub details: String,
}
```

### `AcceptanceCriterion`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceCriterion {
    pub criterion: String,
    pub verification: String,
}
```

### `TestRequirement`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRequirement {
    pub test_id: String,
    pub description: String,
    pub verification_command: String,
}
```

### `TicketValidationError` (from `validation` submodule)

```rust
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum TicketValidationError {
    FileNotFound { path: String, ticket_id: String },
    FileAlreadyExists { path: String, ticket_id: String },
    PathTraversal { path: String, ticket_id: String },
    AbsolutePath { path: String, ticket_id: String },
    CcpIndexNotFound { path: String },
    CcpIndexParseError { reason: String },
    Multiple { errors: Vec<Self> },
}
```

**Invariants:**

- [INV-TE07] Validation errors are aggregated, not early-returned. All paths are checked before reporting.
- [INV-TE08] Path traversal (`..`) and absolute paths are always rejected, regardless of CCP availability.

### `TicketValidationResult`

```rust
#[derive(Debug, Clone)]
pub struct TicketValidationResult {
    pub validated_existing: Vec<FileReference>,
    pub validated_new: Vec<FileReference>,
    pub errors: Vec<TicketValidationError>,
}
```

**Contracts:**

- [CTR-TE04] `is_valid()` returns `true` only when `errors` is empty.
- [CTR-TE05] `into_result()` converts to `Result<(), TicketValidationError>`, aggregating multiple errors into `Multiple`.

## Public API

### `emit_tickets(repo_root, rfc_id, options) -> Result<TicketEmitResult, TicketEmitError>`

Main entry point. Loads the RFC's `06_ticket_decomposition.yaml`, generates stable ticket IDs, validates paths, generates verification commands, and writes ticket files atomically.

### `validate_ticket_paths(repo_root, prd_id, tickets) -> Result<TicketValidationResult, TicketValidationError>`

Validates file paths across multiple tickets against CCP inventory (if `prd_id` provided) or filesystem. Returns aggregated validation results.

## Examples

### Emitting Tickets from an RFC

```rust
use std::path::Path;
use apm2_core::ticket_emitter::{TicketEmitOptions, emit_tickets};

let result = emit_tickets(
    Path::new("/repo/root"),
    "RFC-0010",
    &TicketEmitOptions::default(),
)?;

println!("Emitted {} tickets to {}", result.tickets.len(), result.output_dir.display());
for ticket in &result.tickets {
    println!("  {}: {} (deps: {:?})", ticket.id, ticket.title, ticket.depends_on);
}
```

### Dry Run with Validation

```rust
use std::path::Path;
use apm2_core::ticket_emitter::{TicketEmitOptions, emit_tickets};

let result = emit_tickets(
    Path::new("/repo/root"),
    "RFC-0019",
    &TicketEmitOptions {
        dry_run: true,
        skip_validation: false,
        prd_id: Some("PRD-0005".to_string()),
        ..Default::default()
    },
)?;

// No files written, but all validation ran
assert!(result.dry_run);
```

## Related Modules

- [`apm2_core::rfc_framer`](../rfc_framer/AGENTS.md) - Generates the RFC structure that ticket_emitter consumes
- [`apm2_core::impact_map`](../impact_map/AGENTS.md) - Impact Map that maps PRD requirements to CCP components
- [`apm2_core::determinism`](../determinism/AGENTS.md) - Provides `canonicalize_yaml` and `write_atomic` used by the emitter
- [`apm2_core::work`](../work/AGENTS.md) - Work item lifecycle; consumes tickets produced by this module

## References

- [RFC-0019: Automated FAC v0](/documents/rfcs/RFC-0019/) - End-to-end ingestion, review episode, durable receipt, GitHub projection
- [Ticket Schema Template](/documents/work/tickets/) - Standard ticket YAML schema
- [APM2 Rust Standards - Testing Evidence and CI](/documents/skills/rust-standards/references/20_testing_evidence_and_ci.md) - Verification command patterns
