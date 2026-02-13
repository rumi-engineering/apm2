# Config Module

> Configuration parsing and management for APM2 ecosystem files (TOML/JSON).

## Overview

The `apm2_core::config` module provides the configuration layer for APM2, enabling declarative definition of process ecosystems including daemon settings, credential profiles, and process specifications. This module serves as the entry point for loading and validating ecosystem configuration from TOML files.

Configuration flows through a hierarchical structure:
1. `EcosystemConfig` - top-level container
2. `DaemonConfig` - system-level paths and socket configuration
3. `CredentialProfileConfig` - credential profile definitions
4. `ProcessConfig` - individual process specifications with embedded sub-configurations

The module re-exports configuration types from related modules (`credentials`, `health`, `log`, `restart`, `shutdown`) to provide a unified configuration surface.

## Key Types

### `EcosystemConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EcosystemConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub credentials: Vec<CredentialProfileConfig>,
    #[serde(default)]
    pub processes: Vec<ProcessConfig>,
}
```

**Invariants:**
- [INV-CFG-01] All `serde(default)` attributes ensure partial TOML files parse without error
- [INV-CFG-02] Process names within `processes` should be unique (enforced at validation time, not parse time)

**Contracts:**
- [CTR-CFG-01] `from_file()` and `from_toml()` return `Result<Self, ConfigError>` - never panic on malformed input
- [CTR-CFG-02] Serialization via `to_toml()` produces valid TOML that can round-trip through `from_toml()`

### `DaemonConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_pid_file")]
    pub pid_file: PathBuf,          // Default: /var/run/apm2/apm2.pid
    pub operator_socket: PathBuf,   // Required - privileged operations (mode 0600)
    pub session_socket: PathBuf,    // Required - session-scoped operations (mode 0660)
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,           // Default: /var/log/apm2
    #[serde(default = "default_state_file")]
    pub state_file: PathBuf,        // Default: /var/lib/apm2/state.json
    #[serde(default)]
    pub audit: AuditConfig,         // Audit event retention policy
    #[serde(default)]
    pub cas_path: Option<PathBuf>,  // Optional CAS directory (TCK-00383)
}
```

**CAS Configuration (TCK-00383):**
- `cas_path`: Optional path to the durable content-addressed storage (CAS) directory. When provided, the daemon wires `ToolBroker`, `DurableCas`, ledger event emitter, and holonic clock via `with_persistence_and_cas()`. Without this, session-scoped operations (tool execution, event emission, evidence publishing) fail closed.
- **Security constraints**: The path must be absolute, must not contain symbolic link components, and the directory is created with mode 0700 (owner-only access). Existing directories are verified to be owned by the daemon UID with no group/other permissions. Violations cause fail-closed initialization failure.

**Dual-Socket Architecture (TCK-00249, TCK-00280):**
- `operator_socket`: Used for privileged operations (process control, credential management). Mode 0600 restricts to owner.
- `session_socket`: Used for session-scoped operations (status queries). Mode 0660 allows group access.
- Both fields are **required** when a `[daemon]` section is present - serde validation will fail if omitted.
- The legacy `socket` field is no longer supported (DD-009 fail-closed validation).

**Invariants:**
- [INV-CFG-03] All paths have sensible FHS-compliant defaults for Unix systems
- [INV-CFG-04] `Default` implementation provides sensible defaults for programmatic use
- [INV-CFG-10] `operator_socket` and `session_socket` are required in TOML config (TCK-00280)

### `AuditConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,    // Default: 30 days
    #[serde(default = "default_audit_max_size_bytes")]
    pub max_size_bytes: u64,    // Default: 1 GB
}
```

**Invariants:**
- [INV-CFG-09] Retention policy defaults to 30 days / 1GB to prevent disk exhaustion

### `CredentialProfileConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProfileConfig {
    pub id: String,                              // Unique identifier
    pub provider: String,                        // AI provider (claude, gemini, openai)
    pub auth_method: String,                     // Authentication method
    #[serde(default)]
    pub refresh_before_expiry: Option<String>,   // Token refresh timing
}
```

**Invariants:**
- [INV-CFG-05] `id` must be non-empty and unique across all credential profiles in an ecosystem

**Contracts:**
- [CTR-CFG-03] Profile IDs are referenced by `ProcessConfig.credentials.profile` - invalid references are detected at validation time

### `ProcessConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub name: String,                            // Process name (must be unique)
    pub command: String,                         // Command to execute
    #[serde(default)]
    pub args: Vec<String>,                       // Command arguments
    #[serde(default)]
    pub cwd: Option<PathBuf>,                    // Working directory
    #[serde(default)]
    pub env: HashMap<String, String>,            // Environment variables
    #[serde(default = "default_instances")]
    pub instances: u32,                          // Number of instances (default: 1)
    #[serde(default)]
    pub restart: RestartConfig,                  // Restart policy
    #[serde(default)]
    pub health: Option<HealthCheckConfig>,       // Health check configuration
    #[serde(default)]
    pub log: LogConfig,                          // Log configuration
    #[serde(default)]
    pub shutdown: ShutdownConfig,                // Shutdown configuration
    #[serde(default)]
    pub credentials: Option<CredentialConfig>,   // Credential binding
}
```

**Invariants:**
- [INV-CFG-06] `name` must be non-empty and unique across all processes in an ecosystem
- [INV-CFG-07] `command` must be non-empty
- [INV-CFG-08] `instances` defaults to 1 and represents the number of parallel instances to spawn

**Contracts:**
- [CTR-CFG-04] Embedded configurations (`RestartConfig`, `HealthCheckConfig`, `LogConfig`, `ShutdownConfig`, `CredentialConfig`) are re-exported from their respective modules

### `ConfigError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read configuration file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse configuration: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("failed to serialize configuration: {0}")]
    Serialize(#[from] toml::ser::Error),

    #[error("configuration validation failed: {0}")]
    Validation(String),
}
```

**Contracts:**
- [CTR-CFG-05] Error types are structured to allow callers to branch on cause (CTR-0703)
- [CTR-CFG-06] `Display` messages are stable and actionable

## Public API

### Loading Configuration

```rust
impl EcosystemConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError>;

    /// Parse configuration from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, ConfigError>;

    /// Serialize configuration to TOML.
    pub fn to_toml(&self) -> Result<String, ConfigError>;
}
```

All parsing methods return `Result` - untrusted input cannot trigger panics (RSK-0701).

## Examples

### Minimal Configuration

```rust
use apm2_core::config::EcosystemConfig;

let toml = r#"
    [[processes]]
    name = "test"
    command = "echo"
"#;

let config = EcosystemConfig::from_toml(toml)?;
assert_eq!(config.processes.len(), 1);
assert_eq!(config.processes[0].name, "test");
```

### Full Configuration

```rust
use apm2_core::config::EcosystemConfig;

let toml = r#"
    [daemon]
    pid_file = "/tmp/apm2.pid"
    operator_socket = "/tmp/apm2/operator.sock"
    session_socket = "/tmp/apm2/session.sock"

    [[credentials]]
    id = "claude-work"
    provider = "claude"
    auth_method = "session_token"

    [[processes]]
    name = "claude-code"
    command = "claude"
    args = ["--session", "project"]
    instances = 2

    [processes.restart]
    max_restarts = 5

    [processes.credentials]
    profile = "claude-work"
    hot_swap = true
"#;

let config = EcosystemConfig::from_toml(toml)?;
assert_eq!(config.daemon.pid_file.to_str(), Some("/tmp/apm2.pid"));
assert_eq!(config.daemon.operator_socket.to_str(), Some("/tmp/apm2/operator.sock"));
assert_eq!(config.daemon.session_socket.to_str(), Some("/tmp/apm2/session.sock"));
assert_eq!(config.credentials.len(), 1);
assert_eq!(config.processes[0].instances, 2);
```

### Invalid Configuration (Missing Sockets)

```rust
use apm2_core::config::EcosystemConfig;

// This will fail - operator_socket and session_socket are required
let toml = r#"
    [daemon]
    pid_file = "/tmp/apm2.pid"

    [[processes]]
    name = "test"
    command = "echo"
"#;

let result = EcosystemConfig::from_toml(toml);
assert!(result.is_err()); // Missing required socket fields
```

### Invalid Configuration (Legacy Socket)

```rust
use apm2_core::config::EcosystemConfig;

// This will fail - legacy 'socket' field is rejected (DD-009)
let toml = r#"
    [daemon]
    pid_file = "/tmp/apm2.pid"
    socket = "/tmp/apm2.sock"  # REJECTED - use operator_socket and session_socket

    [[processes]]
    name = "test"
    command = "echo"
"#;

let result = EcosystemConfig::from_toml(toml);
assert!(result.is_err()); // DD-009: legacy socket rejected
```

### `ProjectionSinkProfileConfig` (TCK-00507)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSinkProfileConfig {
    pub outage_window_ticks: u64,
    pub replay_window_ticks: u64,
    pub churn_tolerance: u32,
    pub partition_tolerance: u32,
    pub trusted_signers: Vec<String>,   // Hex-encoded Ed25519 public keys
}
```

Per-sink continuity profile for economics gate input assembly. Configured under `[daemon.projection.sinks.<sink_id>]`.

**Security:** Trusted signer keys are validated eagerly at config parse time. Invalid hex, wrong key length (not 32 bytes), odd-length hex, non-hex characters, or empty signers lists prevent daemon startup.

**Invariants:**
- [INV-CFG-13] Sink count bounded by `MAX_PROJECTION_SINKS` (64).
- [INV-CFG-14] Trusted signers per sink bounded by `MAX_TRUSTED_SIGNERS_PER_SINK` (32).
- [INV-CFG-15] All trusted signer hex strings decode to valid 32-byte Ed25519 public keys.
- [INV-CFG-16] Validation at startup -- not lazily at first use.
- [INV-CFG-17] When projection sinks are configured, at least 2 sinks are required (REQ-0009 multi-sink continuity). Exactly 1 sink is rejected at startup. Zero sinks (no projection configured) are allowed (TCK-00502 MAJOR-3).

**Contracts:**
- [CTR-CFG-07] `ProjectionConfig::validate_sink_profiles()` runs at `from_toml()` time.
- [CTR-CFG-08] Invalid signer keys produce `ConfigError::Validation`, halting daemon startup.

## Embedded Configuration Types

The following types are imported from other modules and embedded in `ProcessConfig`:

| Field | Type | Module | Purpose |
|-------|------|--------|---------|
| `restart` | `RestartConfig` | `apm2_core::restart` | Restart policy with backoff strategies |
| `health` | `HealthCheckConfig` | `apm2_core::health` | HTTP/TCP/script health checks |
| `log` | `LogConfig` | `apm2_core::log` | Log paths, rotation, timestamping |
| `shutdown` | `ShutdownConfig` | `apm2_core::shutdown` | Graceful shutdown with timeouts |
| `credentials` | `CredentialConfig` | `apm2_core::credentials` | Credential binding and hot-swap |

## Invariant Summary

```
INV-CFG-01  serde(default) ensures partial TOML parsing
INV-CFG-02  Process names should be unique (validation-time)
INV-CFG-03  DaemonConfig paths have FHS-compliant defaults
INV-CFG-04  Default impl provides sensible defaults for programmatic use
INV-CFG-05  Credential profile IDs must be unique
INV-CFG-06  Process names must be non-empty and unique
INV-CFG-07  Process command must be non-empty
INV-CFG-08  instances defaults to 1
INV-CFG-09  Audit retention defaults to 30 days / 1GB
INV-CFG-10  operator_socket and session_socket are required in TOML (TCK-00280)
INV-CFG-11  Legacy 'socket' field is rejected with DD-009 error
INV-CFG-12  cas_path must be absolute, symlink-free, and created with mode 0700 (TCK-00383)
INV-CFG-13  Projection sink count bounded by MAX_PROJECTION_SINKS (TCK-00507)
INV-CFG-14  Trusted signers per sink bounded by MAX_TRUSTED_SIGNERS_PER_SINK (TCK-00507)
INV-CFG-15  All trusted signer hex decode to valid Ed25519 public keys (TCK-00507)
INV-CFG-16  Signer key validation runs at startup, not lazily (TCK-00507)
INV-CFG-17  Minimum 2 sinks required when projection configured (TCK-00502)
```

## Contract Summary

```
CTR-CFG-01  from_file/from_toml return Result, never panic on input
CTR-CFG-02  to_toml round-trips through from_toml
CTR-CFG-03  Profile IDs referenced by ProcessConfig are validated
CTR-CFG-04  Embedded configs re-exported from respective modules
CTR-CFG-05  ConfigError is structured for cause branching
CTR-CFG-06  Error Display messages are stable
CTR-CFG-07  validate_sink_profiles runs at from_toml time (TCK-00507)
CTR-CFG-08  Invalid signer keys produce ConfigError::Validation (TCK-00507)
```

## Related Modules

- [`apm2_core::credentials`](../credentials/AGENTS.md) - Credential profiles and hot-swapping; provides `CredentialConfig`
- [`apm2_core::health`](../health/AGENTS.md) - Health check mechanisms; provides `HealthCheckConfig`
- [`apm2_core::log`](../log/AGENTS.md) - Log collection and rotation; provides `LogConfig`
- [`apm2_core::restart`](../restart/AGENTS.md) - Restart policies and backoff; provides `RestartConfig`
- [`apm2_core::shutdown`](../shutdown/AGENTS.md) - Graceful shutdown handling; provides `ShutdownConfig`
- [`apm2_core::process`](../process/AGENTS.md) - Process spawning and management (consumes `ProcessConfig`)
- [`apm2_core::supervisor`](../supervisor/AGENTS.md) - Process supervision (consumes `EcosystemConfig`)
