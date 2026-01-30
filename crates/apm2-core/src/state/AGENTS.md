# State Module

> Persists daemon and process state to disk for crash recovery and restart resilience.

## Overview

The state module provides durable persistence for the APM2 daemon, enabling recovery of process configurations and runtime state after daemon restarts or crashes. It implements an atomic write-through persistence model using temporary files and renames to ensure state integrity even during unexpected termination.

The module follows a **lazy persistence** pattern: state is tracked via a dirty flag and only written to disk when explicitly requested or when the dirty flag is set. This balances durability requirements with I/O efficiency.

```text
+---------------+
|   Supervisor  |  Manages runtime ProcessHandle instances
+-------+-------+
        | register/update
        v
+---------------+
| StateManager  |  Tracks dirty flag, coordinates persistence
+-------+-------+
        | save_if_dirty()
        v
+---------------+
|PersistedState |  Serializable snapshot of daemon state
+-------+-------+
        | serde_json
        v
+---------------+
| state.json    |  Atomic file write (temp + rename)
+---------------+
```

## Key Types

### `PersistedState`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    /// Version of the state format.
    pub version: u32,
    /// Time when state was saved.
    pub saved_at: DateTime<Utc>,
    /// Daemon start time.
    pub daemon_started_at: DateTime<Utc>,
    /// Process specifications.
    pub specs: HashMap<ProcessId, ProcessSpec>,
    /// Process instance states.
    pub instances: Vec<PersistedProcessInstance>,
}
```

**Invariants:**
- [INV-0101] `version` is monotonically increasing; newer versions can read older formats
- [INV-0102] `saved_at` is updated on every `save()` call
- [INV-0103] `specs` and `instances` maintain referential integrity: every instance's `spec_id` exists in `specs`

**Contracts:**
- [CTR-0101] `load()` rejects state files with `version > CURRENT_VERSION` to prevent forward-incompatibility
- [CTR-0102] `save()` performs atomic write (write to `.tmp`, then rename) to prevent partial writes
- [CTR-0103] `remove_spec()` cascades to remove all associated instances (referential integrity)

### `PersistedProcessInstance`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedProcessInstance {
    /// Process specification ID.
    pub spec_id: ProcessId,
    /// Instance index.
    pub instance_index: u32,
    /// Process state.
    pub state: ProcessState,
    /// OS process ID (if running).
    pub pid: Option<u32>,
    /// Time when started.
    pub started_at: Option<DateTime<Utc>>,
    /// Number of restarts.
    pub restart_count: u32,
    /// Last restart time.
    pub last_restart: Option<DateTime<Utc>>,
    /// Bound credential profile ID.
    pub credential_profile: Option<String>,
}
```

**Invariants:**
- [INV-0201] `(spec_id, instance_index)` forms a unique key within `PersistedState.instances`
- [INV-0202] `pid` is `Some` only when `state.is_running()` would return true at save time
- [INV-0203] Default state is `ProcessState::Stopped { exit_code: None }`

**Contracts:**
- [CTR-0201] `new()` creates instance in stopped state with zeroed counters

### `StateManager`

```rust
#[derive(Debug)]
pub struct StateManager {
    /// Path to state file.
    path: PathBuf,
    /// Current state.
    state: PersistedState,
    /// Whether state has unsaved changes.
    dirty: bool,
}
```

**Invariants:**
- [INV-0301] `dirty` flag is set on any mutation via `state_mut()`
- [INV-0302] `dirty` flag is cleared only after successful `save()` or `save_if_dirty()`
- [INV-0303] `path` is immutable for the lifetime of the manager

**Contracts:**
- [CTR-0301] `state_mut()` always sets `dirty = true` before returning mutable reference
- [CTR-0302] `save_if_dirty()` is a no-op when `dirty == false`
- [CTR-0303] `load_or_create()` sets `dirty = true` when creating new state (to ensure initial persistence)

### `StateError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parse error.
    #[error("failed to parse state: {0}")]
    Parse(#[from] serde_json::Error),
    /// JSON serialize error.
    #[error("failed to serialize state: {0}")]
    Serialize(serde_json::Error),
    /// Unsupported state version.
    #[error("unsupported state version: {0}")]
    UnsupportedVersion(u32),
}
```

**Contracts:**
- [CTR-0401] `Io` and `Parse` use `#[from]` for ergonomic error conversion
- [CTR-0402] `Serialize` is separate from `Parse` to distinguish read vs write failures
- [CTR-0403] `UnsupportedVersion` enables forward-compatibility rejection

## Public API

### `PersistedState::new() -> Self`

Creates a new empty persisted state with current timestamps and `CURRENT_VERSION`.

### `PersistedState::load(path: &Path) -> Result<Self, StateError>`

Loads state from a JSON file. Validates version compatibility before returning.

**Errors:**
- `StateError::Io`: File cannot be read
- `StateError::Parse`: JSON is malformed or schema mismatch
- `StateError::UnsupportedVersion`: File version exceeds `CURRENT_VERSION`

### `PersistedState::save(&mut self, path: &Path) -> Result<(), StateError>`

Atomically saves state to disk. Updates `saved_at` timestamp before writing.

**Atomic Write Pattern:**
1. Create parent directories if needed
2. Serialize to pretty JSON
3. Write to `{path}.tmp`
4. Rename `{path}.tmp` to `{path}` (atomic on POSIX)

**Errors:**
- `StateError::Io`: Directory creation, write, or rename failed
- `StateError::Serialize`: Serialization failed (should not occur with valid types)

### `PersistedState::add_spec(&mut self, spec: ProcessSpec)`

Adds or updates a process specification. Keyed by `ProcessId`.

### `PersistedState::remove_spec(&mut self, id: &ProcessId)`

Removes a process specification and all associated instances. Maintains referential integrity.

### `PersistedState::update_instance(&mut self, instance: PersistedProcessInstance)`

Upserts a process instance. If an instance with matching `(spec_id, instance_index)` exists, it is replaced; otherwise, the instance is appended.

### `StateManager::new(path: PathBuf) -> Self`

Creates a new state manager targeting the given file path. Does not perform I/O.

### `StateManager::load_or_create(&mut self) -> Result<(), StateError>`

Loads existing state from disk, or initializes new state if file does not exist.

### `StateManager::state(&self) -> &PersistedState`

Returns immutable reference to current state.

### `StateManager::state_mut(&mut self) -> &mut PersistedState`

Returns mutable reference to current state. **Sets dirty flag.**

### `StateManager::save_if_dirty(&mut self) -> Result<(), StateError>`

Persists state only if dirty flag is set. Clears dirty flag on success.

### `StateManager::save(&mut self) -> Result<(), StateError>`

Forces state persistence regardless of dirty flag.

### `StateManager::mark_dirty(&mut self)`

Explicitly sets the dirty flag. Useful when external mutations require persistence.

### `StateManager::is_dirty(&self) -> bool`

Returns current dirty flag state.

## State Format

The persisted state uses JSON with pretty-printing for human readability:

```json
{
  "version": 1,
  "saved_at": "2025-01-15T10:30:00Z",
  "daemon_started_at": "2025-01-15T08:00:00Z",
  "specs": {
    "550e8400-e29b-41d4-a716-446655440000": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "claude-code",
      "command": "claude",
      "args": ["--session", "project"],
      "instances": 1,
      "restart": { "policy": "always", "max_retries": 5 },
      ...
    }
  },
  "instances": [
    {
      "spec_id": "550e8400-e29b-41d4-a716-446655440000",
      "instance_index": 0,
      "state": "Running",
      "pid": 12345,
      "started_at": "2025-01-15T10:00:00Z",
      "restart_count": 2,
      "last_restart": "2025-01-15T09:30:00Z",
      "credential_profile": "claude-work"
    }
  ]
}
```

## Examples

### Basic State Persistence

```rust
use apm2_core::state::{StateManager, PersistedProcessInstance};
use apm2_core::process::{ProcessSpec, ProcessState};
use std::path::PathBuf;

// Initialize state manager
let mut manager = StateManager::new(PathBuf::from("/var/lib/apm2/state.json"));
manager.load_or_create()?;

// Register a process
let spec = ProcessSpec::builder()
    .name("claude-code")
    .command("claude")
    .build();
let spec_id = spec.id;

manager.state_mut().add_spec(spec);

// Update instance state
let instance = PersistedProcessInstance {
    spec_id,
    instance_index: 0,
    state: ProcessState::Running,
    pid: Some(12345),
    started_at: Some(chrono::Utc::now()),
    restart_count: 0,
    last_restart: None,
    credential_profile: Some("claude-work".to_string()),
};
manager.state_mut().update_instance(instance);

// Persist to disk
manager.save_if_dirty()?;
```

### Recovery After Restart

```rust
use apm2_core::state::StateManager;
use std::path::PathBuf;

let mut manager = StateManager::new(PathBuf::from("/var/lib/apm2/state.json"));
manager.load_or_create()?;

// Iterate over previously registered processes
for (id, spec) in &manager.state().specs {
    println!("Recovering process: {} ({})", spec.name, id);
}

// Find processes that were running before restart
for instance in &manager.state().instances {
    if instance.state.is_running() {
        println!(
            "Process {} instance {} was running (PID: {:?})",
            instance.spec_id, instance.instance_index, instance.pid
        );
        // Attempt to reattach or restart...
    }
}
```

### Periodic Persistence

```rust
use apm2_core::state::StateManager;
use std::time::Duration;

async fn persistence_loop(mut manager: StateManager) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        if let Err(e) = manager.save_if_dirty() {
            eprintln!("Failed to persist state: {}", e);
        }
    }
}
```

## Recovery Semantics

On daemon restart, the state module enables the following recovery behaviors:

1. **Process Reregistration**: All `ProcessSpec` entries are restored to the supervisor
2. **PID Verification**: For instances with `pid: Some(...)`, the daemon can check if the process still exists
3. **Credential Rebinding**: The `credential_profile` field preserves credential associations
4. **Restart Counter Continuity**: `restart_count` persists across daemon restarts

**Note:** The state module does not automatically restart processes; it provides the data for the supervisor to make restart decisions.

## Related Modules

- [`apm2_core::process`](../process/AGENTS.md) - Defines `ProcessId`, `ProcessSpec`, `ProcessState` used in persistence
- [`apm2_core::supervisor`](../supervisor/AGENTS.md) - Uses `StateManager` for process registration persistence
- [`apm2_core::credentials`](../credentials/AGENTS.md) - Credential profiles referenced by `credential_profile` field
- [`apm2_core::restart`](../restart/AGENTS.md) - Restart configuration persisted with `ProcessSpec`

## Design Decisions

### Atomic Writes via Rename

The module uses the temp-file-then-rename pattern to ensure atomic state updates:

```rust
let temp_path = path.with_extension("tmp");
std::fs::write(&temp_path, content)?;
std::fs::rename(&temp_path, path)?;
```

This guarantees that readers always see either the old complete state or the new complete state, never a partial write.

### Dirty Flag Pattern

The dirty flag pattern optimizes I/O by tracking modifications:

- Mutations through `state_mut()` automatically set `dirty = true`
- `save_if_dirty()` is a no-op when clean, enabling frequent calls without I/O overhead
- Explicit `mark_dirty()` supports external mutation tracking

### Version Field for Migration

The `version` field enables future schema evolution:

```rust
if state.version > Self::CURRENT_VERSION {
    return Err(StateError::UnsupportedVersion(state.version));
}
```

Older daemons reject newer state formats (fail-closed), while newer daemons can implement migration logic for older formats.

## References

- rust-textbook [Chapter 16: I/O Protocol Boundaries](/documents/skills/rust-standards/references/31_io_protocol_boundaries.md) - Atomic file write patterns
- rust-textbook [Chapter 07: Errors, Panics, Diagnostics](/documents/skills/rust-standards/references/15_errors_panics_diagnostics.md) - Error type design with `thiserror`
