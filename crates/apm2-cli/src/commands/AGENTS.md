# commands

> CLI command implementations for all `apm2` subcommands.

## Overview

The `commands` module contains the implementation of every CLI subcommand. Each file or sub-module corresponds to a command group dispatched from `main.rs`. Commands use the `client` module for daemon IPC and emit structured output (text or JSON) controlled by `--json` flags.

All command functions return a `u8` exit code or `anyhow::Result<()>`, using values from `crate::exit_codes`.

### Module Map

| File/Module | Command Group | Description |
|-------------|---------------|-------------|
| `daemon.rs` | `apm2 daemon`, `apm2 kill` | Daemon lifecycle management |
| `process.rs` | `apm2 start/stop/restart/reload/list/status/logs` | Process management |
| `creds.rs` | `apm2 creds *` | Credential management |
| `episode.rs` | `apm2 episode *` | Episode lifecycle |
| `work.rs` | `apm2 work claim/status/list` | Work assignment operations |
| `tool.rs` | `apm2 tool request` | Tool execution requests |
| `event.rs` | `apm2 event emit` | Session event emission |
| `evidence.rs` | `apm2 evidence publish` | Evidence artifact publishing |
| `capability.rs` | `apm2 capability request` | Capability token issuance |
| `consensus.rs` | `apm2 consensus *` | Consensus query operations |
| `fac.rs` | `apm2 fac *` | FAC (Factory Automation Cycle) top-level dispatcher |
| `fac_pr/` | `apm2 fac pr *` | GitHub App credential management for PR operations |
| `fac_review/` | `apm2 fac review *` | Review orchestration (security + quality reviews) |
| `factory/` | `apm2 factory *` | Factory pipeline (CCP, Impact Map, RFC, Tickets) |
| `cac.rs` | `apm2 cac *` | CAC (Compliance Artifact Chain) operations |
| `coordinate.rs` | `apm2 coordinate *` | Multi-agent coordination commands |
| `export.rs` | `apm2 export *` | Data export operations |
| `pack.rs` | `apm2 pack *` | Pack/bundle operations |
| `role_launch.rs` | `apm2 role-launch *` | Role-based agent launching |

### Security: Session Token Handling

```rust
pub const APM2_SESSION_TOKEN_ENV: &str = "APM2_SESSION_TOKEN";
```

Session-scoped commands accept session tokens via the `APM2_SESSION_TOKEN` environment variable (preferred) or `--session-token` CLI flag (deprecated). The environment variable approach mitigates CWE-214 (visible sensitive information in process listings).

## Key Types

### `FacCommand` (fac.rs)

```rust
#[derive(Debug, Args)]
pub struct FacCommand {
    #[command(subcommand)]
    pub subcommand: FacSubcommand,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}
```

Top-level FAC command dispatcher. Routes to `fac_pr`, `fac_review`, and `factory` sub-modules.

### `FacSubcommand` (fac.rs)

```rust
#[derive(Debug, Subcommand)]
pub enum FacSubcommand {
    Pr(PrArgs),
    Review(ReviewArgs),
    Run { spec_file: PathBuf, format: String },
    Factory(FactoryCommand),
    Gates(GatesArgs),
    Work(WorkArgs),
    Episode(EpisodeArgs),
    Receipt(ReceiptArgs),
    Context(ContextArgs),
    Resume(ResumeArgs),
    Barrier(BarrierArgs),
    Kickoff(KickoffArgs),
    Push(PushArgs),
    Restart(RestartArgs),
    Logs(LogsArgs),
    Pipeline(PipelineArgs),
}
```

### `WorkCommand` / `WorkSubcommand` (work.rs)

```rust
#[derive(Debug, Args)]
pub struct WorkCommand { pub subcommand: WorkSubcommand }

#[derive(Debug, Subcommand)]
pub enum WorkSubcommand {
    Claim(ClaimArgs),
    Status(StatusArgs),
    List,
}
```

### `RoleArg` (work.rs)

```rust
#[derive(Debug, Clone, ValueEnum)]
pub enum RoleArg {
    Implementor,
    Reviewer,
    Architect,
    Operator,
    Monitor,
}
```

Maps CLI role arguments to protocol `WorkRole` values.

### `EventCommand` (event.rs)

```rust
#[derive(Debug, Args)]
pub struct EventCommand { pub subcommand: EventSubcommand }

#[derive(Debug, Subcommand)]
pub enum EventSubcommand {
    Emit(EmitArgs),
}
```

## Public API

### Daemon (daemon.rs)

| Function | Description |
|----------|-------------|
| `run(config, no_daemon)` | Start daemon (spawns `apm2-daemon` binary) |
| `kill(socket_path)` | Send shutdown via `OperatorClient` |
| `collect_doctor_checks(operator_socket, config_path)` | Collect all doctor health checks (TCK-00547) |

#### Doctor Check Categories (TCK-00547)

`collect_doctor_checks` runs checks in these categories:

1. **Host Capability**: cgroup v2 availability, systemd execution backend selection
2. **Control-Plane Readiness**: broker socket reachability, worker liveness (projection probe)
3. **Toolchain**: cargo, cargo-nextest, systemd-run availability
4. **Security Posture**: FAC root permissions (0700/ownership), socket permissions (0600), lane symlink detection
5. **Credentials Posture** (WARN-only): GITHUB_TOKEN/GH_TOKEN, GitHub App config, systemd credential file

Each check produces a `DaemonDoctorCheck` with `name`, `status` (ERROR/WARN/OK), and `message` (including actionable remediation). Credentials checks are WARN-only to avoid blocking local-only workflows.

### Process Management (process.rs)

| Function | Description |
|----------|-------------|
| `start(socket_path, name)` | Start a named process |
| `stop(socket_path, name)` | Stop a named process |
| `restart(socket_path, name)` | Restart a named process |
| `reload(socket_path, name)` | Rolling restart a process |
| `list(socket_path)` | List all managed processes |
| `status(socket_path, name)` | Show process details |
| `info(socket_path, name)` | Show process info |
| `logs(socket_path, name, lines, follow)` | Tail process logs |

### FAC Dispatcher (fac.rs)

| Function | Description |
|----------|-------------|
| `run_fac(cmd, operator_socket, session_socket)` | Route FAC subcommands; returns exit code |

### Work (work.rs)

| Function | Description |
|----------|-------------|
| `run_work(cmd, socket_path)` | Dispatch work claim/status/list |

### Event (event.rs)

| Function | Description |
|----------|-------------|
| `run_event(cmd, socket_path)` | Dispatch event emit |

## Related Modules

- [`client/`](../client/AGENTS.md) -- IPC clients used by all command implementations
- [`fac_pr/`](fac_pr/AGENTS.md) -- GitHub App credential management subcommands
- [`fac_review/`](fac_review/AGENTS.md) -- Review orchestration subcommands
- [`factory/`](factory/AGENTS.md) -- Factory pipeline subcommands
- [`apm2-cli` (crate)](../../AGENTS.md) -- Crate-level CLI architecture

## References

- CWE-214: Invocation of Process Using Visible Sensitive Information
- DD-009: ProtocolServer-only control plane
- `documents/security/SECRETS_MANAGEMENT.cac.json`: Secrets handling policy

## Security / Permission Invariants (Updated for TCK-00536)

- FAC command entry (`run_fac`) now enforces strict ownership and 0700-mode validation on
  `$APM2_HOME` critical subdirectories (`private`, `private/fac`, and related cache/evidence roots).
- Command modules now use shared helpers in `fac_permissions` when creating FAC directories/files so
  sensitive artifacts are created with safe modes (`0700` for directories, `0600` for files).
