# CCP Module

> Canonical Context Pipeline: semantic codebase discovery via component atlas, crate dependency graph, and content-addressed CCP index generation.

## Overview

The `apm2_core::ccp` module implements the Code Context Protocol pipeline for RFC-0011 (Context-as-Code). It generates a semantic inventory of the codebase that grounds all RFC file path references and enables deterministic, content-addressed context compilation.

The pipeline has three stages:

1. **Component Atlas** (`build_component_atlas`): Discovers AGENTS.md files, parses invariants/contracts/extension points, and generates stable component IDs
2. **Crate Graph** (`build_crate_graph`): Builds a deterministic dependency graph of workspace crates via `cargo metadata`
3. **CCP Index** (`build_ccp_index`): Combines atlas and graph with a file inventory into a unified, content-addressed artifact with BLAKE3 hashing for incremental rebuild detection

```text
  Repository Root
       │
       ├── build_component_atlas()
       │     │
       │     ├── Discover AGENTS.md files
       │     ├── Parse [INV-NNNN], [CTR-NNNN], [EXT-NNNN]
       │     ├── Generate COMP-{UPPER_SNAKE_CASE} IDs
       │     └── ──> ComponentAtlas
       │
       ├── build_crate_graph()
       │     │
       │     ├── Invoke `cargo metadata` (sanitized env, 30s timeout)
       │     ├── Extract workspace crates + dependency edges
       │     ├── Generate CRATE-{UPPER_SNAKE_CASE} IDs
       │     └── ──> CrateGraph
       │
       └── build_ccp_index()
             │
             ├── ComponentAtlas + CrateGraph + FileInventory
             ├── BLAKE3 content hash over canonical form
             └── ──> CcpIndex (content-addressed)
```

## Key Types

### `ComponentAtlas`

```rust
pub struct ComponentAtlas {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub repo_root: PathBuf,
    pub components: Vec<Component>,
}
```

Complete component atlas for a repository. Components are sorted by ID for deterministic output.

**Invariants:**

- [INV-CC01] Component IDs are deterministic: same crate name always produces same ID
- [INV-CC02] Component list is sorted by ID for deterministic output
- [INV-CC03] AGENTS.md discovery is sorted alphabetically for determinism

### `Component`

```rust
pub struct Component {
    pub id: String,
    pub name: String,
    pub crate_path: PathBuf,
    pub component_type: ComponentType,
    pub description: String,
    pub agents_md_path: Option<PathBuf>,
    pub invariants: Vec<Invariant>,
    pub contracts: Vec<Contract>,
    pub extension_points: Vec<ExtensionPoint>,
}
```

A component in the codebase (typically a crate), with parsed invariants/contracts/extension points from its AGENTS.md.

### `Invariant`

```rust
pub struct Invariant {
    pub id: String,
    pub description: String,
}
```

An invariant extracted from AGENTS.md (e.g., `[INV-0001]`).

### `Contract`

```rust
pub struct Contract {
    pub id: String,
    pub description: String,
}
```

A contract extracted from AGENTS.md (e.g., `[CTR-0001]`).

### `ExtensionPoint`

```rust
pub struct ExtensionPoint {
    pub id: String,
    pub description: String,
    pub stability: Stability,
}
```

An extension point with stability level (`Unstable`, `Stable`, `Deprecated`).

### `ComponentType`

```rust
pub enum ComponentType {
    Library,
    Binary,
    Skill,
}
```

### `Stability`

```rust
pub enum Stability {
    Unstable,
    Stable,
    Deprecated,
}
```

### `CrateGraph`

```rust
pub struct CrateGraph {
    pub schema_version: String,
    pub generated_at: DateTime<Utc>,
    pub workspace_root: PathBuf,
    pub crates: Vec<CrateNode>,
    pub edges: Vec<DependencyEdge>,
}
```

Complete crate dependency graph for a workspace.

**Invariants:**

- [INV-CC04] Graph output is deterministic: same workspace always produces identical graph
- [INV-CC05] Only workspace crates are included as nodes
- [INV-CC06] Edges represent actual dependencies from `Cargo.toml`
- [INV-CC07] Nodes sorted by ID, edges sorted by `(from, to, dep_type)`

### `CrateNode`

```rust
pub struct CrateNode {
    pub id: String,
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub crate_type: CrateType,
    pub features: Vec<String>,
}
```

**Contracts:**

- [CTR-CC01] ID format: `CRATE-{UPPER_SNAKE_CASE}` (e.g., `CRATE-APM2_CORE`)

### `CrateType`

```rust
pub enum CrateType {
    Lib,
    Bin,
    ProcMacro,
}
```

### `DependencyEdge`

```rust
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub dep_type: DependencyType,
    pub version_req: String,
    pub features: Vec<String>,
    pub optional: bool,
}
```

### `DependencyType`

```rust
pub enum DependencyType {
    Normal,
    Dev,
    Build,
}
```

### `CcpError`

```rust
#[non_exhaustive]
pub enum CcpError {
    ReadError { path, reason },
    ParseError { path, reason },
    DiscoveryError { path, reason },
    InvalidRepoRoot { path },
    FileTooLarge { path, size, max_size },
}
```

### `CrateGraphError`

```rust
#[non_exhaustive]
pub enum CrateGraphError {
    CargoInvocationError { reason },
    MetadataParseError { reason },
    InvalidWorkspaceRoot { path },
    OutputTooLarge { size, max_size },
    CargoError { stderr },
    SubprocessTimeout { timeout_secs },
    ReaderThreadPanic,
}
```

**Contracts:**

- [CTR-CC02] `build_crate_graph` requires a valid cargo workspace root
- [CTR-CC03] Errors are returned explicitly, not swallowed
- [CTR-CC04] Cargo subprocess has 30-second timeout (SEC-0003)
- [CTR-CC05] Cargo environment is sanitized: only `PATH`, `HOME`, `CARGO_HOME`, `RUSTUP_HOME` passed through (SEC-0001)

## Public API

### Component Atlas

- `build_component_atlas(repo_root: &Path) -> Result<ComponentAtlas, CcpError>` - Discover and parse all components
- `generate_component_id(crate_name: &str) -> String` - Generate `COMP-{UPPER_SNAKE}` ID

### Crate Graph

- `build_crate_graph(workspace_root: &Path) -> Result<CrateGraph, CrateGraphError>` - Build dependency graph
- `generate_crate_id(crate_name: &str) -> String` - Generate `CRATE-{UPPER_SNAKE}` ID
- `find_dependencies(graph: &CrateGraph, crate_id: &str) -> Vec<&DependencyEdge>` - Find outgoing edges
- `find_dependents(graph: &CrateGraph, crate_id: &str) -> Vec<&DependencyEdge>` - Find incoming edges

### CCP Index (via `index` submodule)

The `index` submodule provides `CcpIndex`, `FileInventory`, `SourceFile`, and `CcpBuildOptions` for combined index generation with incremental rebuild support.

**Contracts:**

- [CTR-CC06] Index hash is deterministic: same inputs produce identical hash (BLAKE3)
- [CTR-CC07] File inventory sorted by path for reproducible output
- [CTR-CC08] Atomic writes ensure no partial/corrupt files on crash
- [CTR-CC09] Only files within repo root are processed (path traversal prevention)

## Security Properties

| ID | Property |
|---|---|
| SEC-0001 | Cargo subprocess environment sanitized |
| SEC-0002 | Strict typed JSON parsing for cargo metadata |
| SEC-0003 | 30-second subprocess timeout |
| SEC-0004 | Bounded file reads (10 MB for AGENTS.md, 1 MB for Cargo.toml) |

## Examples

### Building a Component Atlas

```rust
use std::path::Path;
use apm2_core::ccp::build_component_atlas;

let atlas = build_component_atlas(Path::new("/repo/root")).unwrap();
for component in &atlas.components {
    println!(
        "{}: {} invariants, {} extension points",
        component.id,
        component.invariants.len(),
        component.extension_points.len()
    );
}
```

### Building a Crate Graph

```rust
use std::path::Path;
use apm2_core::ccp::{build_crate_graph, find_dependencies};

let graph = build_crate_graph(Path::new("/repo/root")).unwrap();
println!("Workspace has {} crates", graph.crates.len());

for edge in &graph.edges {
    println!("{} -> {} ({:?})", edge.from, edge.to, edge.dep_type);
}
```

### Generating Component IDs

```rust
use apm2_core::ccp::generate_component_id;

assert_eq!(generate_component_id("apm2-core"), "COMP-APM2_CORE");
assert_eq!(generate_component_id("my_crate"), "COMP-MY_CRATE");
```

## Related Modules

- [`apm2_core::context`](../context/AGENTS.md) - Context pack manifests and recipes that consume CCP output
- [`apm2_core::evidence`](../evidence/AGENTS.md) - `ContentAddressedStore` for CCP index artifacts
- [`apm2_core::determinism`](../determinism/AGENTS.md) - `canonicalize_yaml`, `write_atomic` used by index generation
- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing for content addressing

## References

- [RFC-0011: Context-as-Code (CAC) v1](../../../../documents/rfcs/RFC-0011/) - Canonical Context Pipeline specification
- [RFC-0003: Holonic Coordination Framework](../../../../documents/rfcs/RFC-0003/) - Holonic boundary model informing component discovery
- [APM2 Rust Standards: Testing Evidence](/documents/skills/rust-standards/references/20_testing_evidence_and_ci.md) - Determinism testing patterns
