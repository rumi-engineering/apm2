# factory

> Factory pipeline commands for AI-assisted code generation from PRD to implementation tickets.

## Overview

The `factory` module implements the `apm2 factory *` command family, which orchestrates an end-to-end pipeline from Product Requirements Documents (PRDs) to atomic implementation tickets. The pipeline chains four stages in strict order:

```
PRD ──> CCP Build ──> Impact Map ──> RFC Frame ──> Ticket Emit
```

Each stage can be invoked independently or chained via the `compile` command.

### Sub-modules

| File | Command | Description |
|------|---------|-------------|
| `run.rs` | `apm2 factory run` | Run a Markdown spec with an AI CLI adapter |
| `ccp.rs` | `apm2 factory ccp build` | Build CCP (Code Context Protocol) index |
| `impact_map.rs` | `apm2 factory impact-map build` | Map PRD requirements to CCP components |
| `rfc.rs` | `apm2 factory rfc frame` | Generate RFC skeleton with CCP grounding |
| `tickets.rs` | `apm2 factory tickets emit` | Decompose RFC into atomic implementation tickets |
| `compile.rs` | `apm2 factory compile` | End-to-end pipeline (all four stages) |
| `refactor.rs` | `apm2 factory refactor radar` | Refactor radar analysis for maintenance recommendations |

## Key Types

### `CcpCommand` / `CcpSubcommand` (ccp.rs)

```rust
#[derive(Debug, Args)]
pub struct CcpCommand {
    pub subcommand: CcpSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CcpSubcommand {
    Build(CcpBuildArgs),
}
```

### `CcpBuildArgs` (ccp.rs)

```rust
#[derive(Debug, Args)]
pub struct CcpBuildArgs {
    #[arg(long, required = true)]
    pub prd: String,
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    #[arg(long, default_value = "false")]
    pub force: bool,
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    #[arg(long, default_value = "text")]
    pub format: String,
}
```

### `ImpactMapCommand` / `ImpactMapSubcommand` (impact_map.rs)

```rust
#[derive(Debug, Args)]
pub struct ImpactMapCommand {
    pub subcommand: ImpactMapSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ImpactMapSubcommand {
    Build(ImpactMapBuildArgs),
}
```

### `ImpactMapBuildArgs` (impact_map.rs)

```rust
#[derive(Debug, Args)]
pub struct ImpactMapBuildArgs {
    #[arg(long, required = true)]
    pub prd: String,
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    #[arg(long, default_value = "false")]
    pub force: bool,
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    #[arg(long, default_value = "text")]
    pub format: String,
}
```

### `RfcCommand` / `RfcSubcommand` (rfc.rs)

```rust
#[derive(Debug, Args)]
pub struct RfcCommand {
    pub subcommand: RfcSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RfcSubcommand {
    Frame(RfcFrameArgs),
}
```

### `RfcFrameArgs` (rfc.rs)

```rust
#[derive(Debug, Args)]
pub struct RfcFrameArgs {
    #[arg(long, required = true)]
    pub prd: String,
    #[arg(long, required = true)]
    pub rfc: String,
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    #[arg(long, default_value = "false")]
    pub force: bool,
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    #[arg(long, default_value = "false")]
    pub skip_validation: bool,
    #[arg(long, default_value = "text")]
    pub format: String,
}
```

### `TicketsCommand` / `TicketsSubcommand` (tickets.rs)

```rust
#[derive(Debug, Args)]
pub struct TicketsCommand {
    pub subcommand: TicketsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum TicketsSubcommand {
    Emit(TicketsEmitArgs),
}
```

### `TicketsEmitArgs` (tickets.rs)

```rust
#[derive(Debug, Args)]
pub struct TicketsEmitArgs {
    #[arg(long, required = true)]
    pub rfc: String,
    #[arg(long)]
    pub prd: Option<String>,
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    #[arg(long, default_value = "false")]
    pub force: bool,
    #[arg(long, default_value = "false")]
    pub dry_run: bool,
    #[arg(long, default_value = "false")]
    pub skip_validation: bool,
    #[arg(long, default_value = "text")]
    pub format: String,
}
```

### `CompileArgs` (compile.rs)

```rust
#[derive(Debug, Args)]
pub struct CompileArgs {
    #[arg(long, required = true)]
    pub prd: String,
    #[arg(long)]
    pub rfc: Option<String>,
    #[arg(long, default_value = "local")]
    pub profile: String,
    // ... additional fields for dry_run, format, output_dir, etc.
}
```

**Invariants:**
- [INV-COMPILE-001] Stages execute in strict order; no stage skipping.
- [INV-COMPILE-002] Each stage receives output from previous stage.
- [INV-COMPILE-003] Errors halt pipeline immediately with context.
- [INV-COMPILE-004] Dry-run produces no filesystem modifications.

**Contracts:**
- [CTR-COMPILE-001] PRD ID must match `^PRD-\d{4,}$`.
- [CTR-COMPILE-002] RFC ID is auto-generated if not provided.
- [CTR-COMPILE-003] Routing profile must exist if specified.

### `RefactorCommand` / `RefactorSubcommand` (refactor.rs)

```rust
#[derive(Debug, Args)]
pub struct RefactorCommand {
    pub subcommand: RefactorSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RefactorSubcommand {
    Radar(RefactorRadarArgs),
}
```

### `RefactorRadarArgs` (refactor.rs)

```rust
#[derive(Debug, Args)]
pub struct RefactorRadarArgs {
    #[arg(long, default_value = "7d")]
    pub window: String,
    #[arg(long, default_value_t = DEFAULT_MAX_RECOMMENDATIONS)]
    pub max_items: usize,
    #[arg(long, default_value = "false")]
    pub ignore_breaker: bool,
    #[arg(long, default_value_t = DEFAULT_BACKLOG_THRESHOLD)]
    pub backlog_threshold: usize,
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    #[arg(long, default_value = "yaml")]
    pub format: String,
}
```

## Public API

| Function | Description |
|----------|-------------|
| `run(spec_file, format)` | Run a Markdown spec with Claude Code adapter (async) |
| `run_ccp(cmd)` | Dispatch CCP subcommand |
| `run_ccp_build(args)` | Build CCP index for a PRD |
| `run_impact_map(cmd)` | Dispatch Impact Map subcommand |
| `run_impact_map_build(args)` | Build impact map for a PRD |
| `run_rfc(cmd)` | Dispatch RFC subcommand |
| `run_rfc_frame(args)` | Frame an RFC from Impact Map and CCP artifacts |
| `run_tickets(cmd)` | Dispatch Tickets subcommand |
| `run_tickets_emit(args)` | Emit tickets from RFC decomposition |
| `run_refactor(cmd)` | Dispatch Refactor subcommand |

The `run` function (from `run.rs`) is re-exported at the module level via `pub use run::run`.

## Related Modules

- [`commands/`](../AGENTS.md) -- Parent command module
- [`fac_review/`](../fac_review/AGENTS.md) -- Review orchestration (complementary pipeline)
- [`apm2_core::ccp`](../../../../apm2-core/) -- CCP index building implementation
- [`apm2_core::impact_map`](../../../../apm2-core/) -- Impact map building implementation
- [`apm2_core::rfc_framer`](../../../../apm2-core/) -- RFC framing implementation
- [`apm2_core::ticket_emitter`](../../../../apm2-core/) -- Ticket emission implementation
- [`apm2_core::refactor_radar`](../../../../apm2-core/) -- Refactor radar implementation
- [`apm2_core::adapter`](../../../../apm2-core/) -- Claude Code adapter for `factory run`

## References

- `evidence/prd/<PRD-ID>/`: Default output directory for compile pipeline artifacts
- PRD ID format: `PRD-\d{4,}` (e.g., `PRD-0005`)
- RFC ID format: `RFC-\d{4,}` (e.g., `RFC-0011`)
