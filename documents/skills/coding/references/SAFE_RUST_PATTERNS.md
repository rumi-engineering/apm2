# Safe Rust Patterns Catalog

This document catalogs 15 safe Rust patterns used throughout the APM2 codebase. Use these patterns to avoid introducing unsafe code.

---

## 2.1 Concurrent State: Arc + RwLock

**Pattern:** Wrap shared state in `Arc<T>` for shared ownership and `RwLock<T>` for interior mutability with multiple readers.

**Example from:** `crates/apm2-daemon/src/state.rs:19-30`

```rust
/// Shared daemon state protected by `Arc<RwLock<...>>`.
pub type SharedState = Arc<DaemonStateHandle>;

/// Handle to daemon state with interior mutability.
pub struct DaemonStateHandle {
    /// The inner mutable state.
    inner: RwLock<DaemonState>,
    /// Shutdown flag (atomic for lock-free checking).
    shutdown: AtomicBool,
    /// Time when the daemon started.
    started_at: DateTime<Utc>,
}
```

**When to use:**
- Multiple async tasks need read/write access to shared state
- Read operations are more frequent than writes
- You need `Send + Sync` for async contexts

**Why it's safe:** The compiler enforces lock acquisition before access, preventing data races.

---

## 2.2 Type-Safe Identifiers: Newtype Pattern

**Pattern:** Wrap primitive types in single-field structs to prevent mixing up semantically different IDs.

**Example from:** `crates/apm2-core/src/process/mod.rs:22-44`

```rust
/// Unique identifier for a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(Uuid);

impl ProcessId {
    /// Create a new random process ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
```

**Example from:** `crates/apm2-core/src/credentials/profile.rs:10-25`

```rust
/// Unique identifier for a credential profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(String);

impl ProfileId {
    /// Create a new profile ID from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}
```

**When to use:**
- IDs that should not be mixed (process IDs vs. profile IDs)
- Values with semantic meaning beyond their primitive type
- When you want compiler errors instead of runtime bugs

**Why it's safe:** The compiler prevents accidentally passing a `ProfileId` where a `ProcessId` is expected.

---

## 2.3 Safe Object Construction: Builder Pattern

**Pattern:** Use a builder struct with fluent methods to construct complex objects, validating required fields at build time.

**Example from:** `crates/apm2-core/src/process/mod.rs:94-218`

```rust
/// Builder for `ProcessSpec`.
#[derive(Debug, Default)]
pub struct ProcessSpecBuilder {
    name: Option<String>,
    command: Option<String>,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    instances: u32,
    // ... more fields
}

impl ProcessSpecBuilder {
    /// Set the process name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Build the `ProcessSpec`.
    #[must_use]
    pub fn build(self) -> ProcessSpec {
        ProcessSpec {
            id: ProcessId::new(),
            name: self.name.expect("name is required"),
            command: self.command.expect("command is required"),
            // ... validate and construct
        }
    }
}
```

**Usage:**
```rust
let spec = ProcessSpec::builder()
    .name("my-process")
    .command("echo")
    .args(["hello", "world"])
    .build();
```

**When to use:**
- Objects with many optional fields
- Construction that requires validation
- When you want compile-time or runtime enforcement of required fields

**Why it's safe:** Required fields are validated at build time; invalid states cannot be constructed.

---

## 2.4 Sensitive Data: Secrecy Crate

**Pattern:** Use `SecretString` from the `secrecy` crate to hold sensitive data, preventing accidental logging.

**Example from:** `crates/apm2-core/src/credentials/profile.rs:84-114`

```rust
use secrecy::SecretString;

/// Authentication method and credentials.
pub enum AuthMethod {
    /// OAuth 2.0 authentication.
    OAuth {
        /// Access token.
        access_token: SecretString,
        /// Refresh token (if available).
        refresh_token: Option<SecretString>,
        // ...
    },

    /// API key authentication.
    ApiKey {
        /// API key value.
        key: SecretString,
    },
}
```

**Accessing the secret:**
```rust
use secrecy::ExposeSecret;

let key: &str = api_key.expose_secret();
```

**When to use:**
- API keys, tokens, passwords
- Any data that should never appear in logs
- Credentials that need secure memory handling

**Why it's safe:** `SecretString` does not implement `Display` or `Debug` with the actual value, preventing accidental exposure in logs.

---

## 2.5 State Machines: Enum with Predicates

**Pattern:** Model states as enum variants with predicate methods for querying state categories.

**Example from:** `crates/apm2-core/src/process/mod.rs:220-267`

```rust
/// Process state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is starting up.
    Starting,
    /// Process is running normally.
    Running,
    /// Process is running but failing health checks.
    Unhealthy,
    /// Process is being stopped gracefully.
    Stopping,
    /// Process has stopped (graceful exit).
    Stopped { exit_code: Option<i32> },
    /// Process has crashed unexpectedly.
    Crashed { exit_code: Option<i32> },
    /// Process was terminated by signal.
    Terminated,
}

impl ProcessState {
    /// Returns `true` if the process is in a running state.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Unhealthy)
    }

    /// Returns `true` if the process has exited.
    #[must_use]
    pub const fn has_exited(&self) -> bool {
        matches!(
            self,
            Self::Stopped { .. } | Self::Crashed { .. } | Self::Terminated
        )
    }
}
```

**When to use:**
- Objects with distinct states
- When state transitions need to be explicit
- When you need to query "categories" of states

**Why it's safe:** Exhaustive pattern matching ensures all states are handled; the compiler catches missing cases.

---

## 2.6 Error Handling: Result + thiserror

**Pattern:** Define custom error enums with `#[derive(thiserror::Error)]` for structured error handling.

**Example from:** `crates/apm2-core/src/credentials/store.rs:269-287`

```rust
/// Errors from the credential store.
#[derive(Debug, thiserror::Error)]
pub enum CredentialStoreError {
    /// Profile not found.
    #[error("credential profile not found: {0}")]
    NotFound(String),

    /// Keyring error.
    #[error("keyring error: {0}")]
    Keyring(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Lock poisoned.
    #[error("internal lock poisoned")]
    LockPoisoned,
}
```

**Usage:**
```rust
pub fn get(&self, profile_id: &ProfileId) -> Result<CredentialProfile, CredentialStoreError> {
    // ...
    Err(CredentialStoreError::NotFound(profile_id.to_string()))
}
```

**When to use:**
- Any fallible operation
- When errors need to be categorized
- When error messages should be user-friendly

**Why it's safe:** Forces callers to handle errors explicitly; no silent failures.

---

## 2.7 Atomic File Operations: Write-Then-Rename

**Pattern:** Write to a temporary file, then atomically rename to the target path.

**Example from:** `crates/apm2-core/src/state/mod.rs:70-85`

```rust
pub fn save(&mut self, path: &std::path::Path) -> Result<(), StateError> {
    self.saved_at = Utc::now();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StateError::Io)?;
    }

    // Write to temp file first, then rename (atomic)
    let temp_path = path.with_extension("tmp");
    let content = serde_json::to_string_pretty(self).map_err(StateError::Serialize)?;
    std::fs::write(&temp_path, content).map_err(StateError::Io)?;
    std::fs::rename(&temp_path, path).map_err(StateError::Io)?;

    Ok(())
}
```

**When to use:**
- Saving configuration or state files
- Any file write that must not corrupt data on crash
- When multiple processes might read the file

**Why it's safe:** `rename()` is atomic on POSIX systems; readers never see partial writes.

---

## 2.8 Failure Containment: Circuit Breaker

**Pattern:** Track failures and stop retrying when a threshold is reached.

**Example from:** `crates/apm2-core/src/restart/mod.rs:161-308`

```rust
/// Manages restart decisions and history.
pub struct RestartManager {
    /// Restart configuration.
    config: RestartConfig,
    /// Restart history (within the restart window).
    history: Vec<RestartEntry>,
    /// Current backoff attempt counter.
    backoff_attempt: u32,
    /// Whether the circuit breaker is open (preventing restarts).
    circuit_open: bool,
    /// Time when the circuit breaker opened.
    circuit_opened_at: Option<DateTime<Utc>>,
}

impl RestartManager {
    /// Check if a restart should be allowed.
    #[must_use]
    pub fn should_restart(&self, exit_code: Option<i32>) -> bool {
        // Check circuit breaker
        if self.circuit_open {
            return false;
        }
        // ... additional checks
    }

    /// Record a successful run (uptime exceeded `min_uptime`).
    pub const fn record_success(&mut self) {
        self.backoff_attempt = 0;
        self.circuit_open = false;
        self.circuit_opened_at = None;
    }
}
```

**When to use:**
- Restart loops that could overwhelm the system
- External service calls that might fail repeatedly
- Any retry logic with exponential backoff

**Why it's safe:** Prevents runaway resource consumption from repeated failures.

---

## 2.9 Compiler Enforcement: #[must_use]

**Pattern:** Annotate functions whose return values should not be ignored.

**Usage throughout codebase:** 42+ functions are annotated with `#[must_use]`.

**Examples:**
```rust
#[must_use]
pub fn new() -> Self { ... }

#[must_use]
pub const fn is_running(&self) -> bool { ... }

#[must_use]
pub fn should_restart(&self, exit_code: Option<i32>) -> bool { ... }
```

**When to use:**
- Functions returning `Result` or `Option`
- Constructor functions (`new()`)
- Predicate functions (`is_*()`, `has_*()`, `should_*()`)
- Pure functions with no side effects

**Why it's safe:** The compiler warns when return values are ignored, catching bugs where callers forget to handle results.

---

## 2.10 Safe Path Construction

**Pattern:** Never interpolate user-provided identifiers directly into file paths. Sanitize input or use a mapping to prevent path traversal.

**Example of what to avoid:**
```rust
// UNSAFE: actor_id could be "../../../etc/passwd"
let path = PathBuf::from("keys").join(actor_id);
```

**Safe Alternative:**
```rust
// Validate the identifier format
if !actor_id.chars().all(|c| c.is_ascii_alphanumeric()) {
    return Err(Error::InvalidId);
}
let path = PathBuf::from("keys").join(actor_id);
```

**When to use:**
- Any time a file path is constructed from external input (IDs, names, etc.)
- When storing user-specific data on disk

**Why it's safe:** Prevents path traversal vulnerabilities where an attacker can escape the intended directory.

---

## 2.11 Canonical Data Representation

**Pattern:** Define a single, canonical representation for critical constants (like genesis hashes) and normalize data at system boundaries.

**Example:**
```rust
/// The canonical representation of the genesis previous hash (32 zero bytes).
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

pub fn normalize_hash(hash: Option<&[u8]>) -> [u8; 32] {
    match hash {
        Some(h) if h.len() == 32 => {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(h);
            buf
        }
        _ => GENESIS_PREV_HASH,
    }
}
```

**When to use:**
- Cross-layer data exchange (Crypto -> Proto -> DB)
- Default or "null" values for cryptographic identifiers

**Why it's safe:** Prevents verification failures caused by inconsistent representations of the same semantic value.

---

## 2.12 Secure Directory Creation

**Pattern:** Use platform-specific extensions like `DirBuilderExt` to set restrictive permissions *atomically* during directory creation.

**Example (Unix):**
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700); // Private to the user
    builder.create(path)?;
}
```

**When to use:**
- Creating directories for sensitive data (keys, credentials)
- Multi-user environments where default permissions are too permissive

**Why it's safe:** Prevents a race condition where a directory is created with wide permissions before `chmod` can restrict it.

---

## 2.13 Cryptographic Canonicalization (Ordering)

**Pattern:** When signing or hashing collections of items, always apply a deterministic sort order before serialization.

**Example:**
```rust
pub fn prepare_for_signing(mut items: Vec<Item>) -> Vec<u8> {
    // Sort by a stable key to ensure deterministic output
    items.sort_by(|a, b| a.id.cmp(&b.id));
    serialize(&items)
}
```

**When to use:**
- Signing Protobuf repeated fields
- Hashing sets or maps
- Any multi-party signature verification

**Why it's safe:** Ensures that semantically identical data always produces the same signature, regardless of how it was collected in memory.

---

## 2.14 Platform Portability Guards

**Pattern:** Explicitly gate any use of platform-specific modules or extensions with `#[cfg(...)]`.

**Example:**
```rust
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub fn get_inode(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let meta = std::fs::metadata(path).ok()?;
        Some(meta.ino())
    }
    #[cfg(not(unix))]
    {
        None
    }
}
```

**When to use:**
- Using `std::os::unix` or `std::os::windows`
- Calling platform-specific syscalls
- File system operations that vary by OS

**Why it's safe:** Prevents compilation failures and unexpected behavior when the code is ported to other operating systems.

---

## 2.15 Consistency in State Management

**Pattern:** Ensure that in-memory state implementations and persistent storage implementations exhibit identical behavior for edge cases (e.g., overwrites).

**Pattern:** If a `FileStore` returns an error on an existing key, the `MemoryStore` should not silently overwrite it.

**When to use:**
- Implementing traits for multiple backends
- Switching between mock and production implementations

**Why it's safe:** Prevents "it works in tests but fails in production" bugs where the mock behavior diverges from real-world constraints.

---

## 2.16 Restart Monotonicity

**Pattern:** Ensure restart counters and attempt numbers always increase monotonically, never resetting unintentionally.

**Example from:** `crates/apm2-ledger/src/reducers/session.rs`

```rust
/// Error when restart attempt is not greater than previous.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("restart attempt {attempted} must be greater than previous attempt {previous}")]
    RestartAttemptNotMonotonic { attempted: u32, previous: u32 },
    // ...
}

/// Store last_restart_attempt in terminal states.
pub enum SessionState {
    Terminated {
        terminated_at: DateTime<Utc>,
        last_restart_attempt: u32,
    },
    Quarantined {
        quarantined_at: DateTime<Utc>,
        last_restart_attempt: u32,
    },
    // ...
}

impl SessionState {
    /// Get the last restart attempt number for terminal states.
    pub fn last_restart_attempt(&self) -> Option<u32> {
        match self {
            Self::Terminated { last_restart_attempt, .. } => Some(*last_restart_attempt),
            Self::Quarantined { last_restart_attempt, .. } => Some(*last_restart_attempt),
            _ => None,
        }
    }
}

/// In the reducer, enforce monotonicity.
fn handle_started(&mut self, event: SessionStarted) -> Result<(), SessionError> {
    if let Some(prev) = self.state.last_restart_attempt() {
        if event.restart_attempt <= prev {
            return Err(SessionError::RestartAttemptNotMonotonic {
                attempted: event.restart_attempt,
                previous: prev,
            });
        }
    }
    // ... proceed with state transition
}
```

**When to use:**
- Session restart logic with attempt counters
- Any counter that should never decrease (sequence numbers, version numbers)
- Event sourcing systems where replay attacks must be prevented

**Why it's safe:** Prevents "zombie session" replay attacks where a terminated session restarts with a stale attempt number, potentially resetting state and violating ledger immutability.

---

# Anti-Patterns (Lessons Learned)

This section documents patterns that have caused real bugs in the APM2 codebase. Learn from these mistakes to avoid repeating them.

---

## ANTI-1: Shell Argument Escaping for Complex Strings

**Anti-Pattern:** Passing complex strings (containing quotes, backticks, special characters) directly as shell command arguments.

**Real Example (from PR #59):**

The security review prompt contained markdown with backticks, nested quotes, and special characters that broke shell escaping:

```rust
// BROKEN: Complex string passed as shell argument
let prompt = r#"Review the following code for:
- SQL injection via `user_input`
- Command injection in `shell_exec()`
"#;

cmd!("gemini", "-p", prompt).run()?;
// Fails with: "Syntax error: end of file unexpected"
```

**Fix:** Write complex strings to a temporary file and use stdin redirection:

```rust
use tempfile::NamedTempFile;
use std::io::Write;

// Write prompt to temp file
let mut temp = NamedTempFile::new()?;
temp.write_all(prompt.as_bytes())?;
let temp_path = temp.path();

// Redirect from file instead of passing as argument
cmd!("sh", "-c", format!("gemini --yolo < '{}'", temp_path.display())).run()?;
```

**When this matters:**
- Invoking AI CLI tools (Gemini, Claude, Codex) with prompts
- Any string containing backticks, quotes, or shell metacharacters
- Multi-line strings with complex formatting

**Prevention:**
- Use file-based input for any prompt longer than one line
- Test with prompts containing: backticks, single quotes, double quotes, dollar signs, newlines
- Consider using `std::process::Command` with `.stdin(Stdio::piped())` for programmatic input

---

## ANTI-2: Predictable Temp File Names

**Anti-Pattern:** Creating temporary files with predictable names based on PID or timestamp.

**Real Example (from PR #59):**

```rust
// VULNERABLE: Predictable temp file path
let temp_path = std::env::temp_dir().join(format!("prompt-{}.txt", std::process::id()));
std::fs::write(&temp_path, prompt)?;
// Attacker can predict path and create symlink before this runs
```

**Attack Scenario:**
1. Attacker predicts next PID (or just creates symlinks for PID range)
2. Creates symlink: `/tmp/prompt-12345.txt -> /etc/cron.d/malicious`
3. Your process writes "prompt" content to the symlink target
4. Attacker gains code execution via cron

**Fix:** Use the `tempfile` crate which creates files with random names and restrictive permissions:

```rust
use tempfile::NamedTempFile;
use std::io::Write;

// SAFE: Random filename, restrictive permissions (0600), RAII cleanup
let mut temp = NamedTempFile::new()?;
temp.write_all(prompt.as_bytes())?;

// For background processes that outlive the current scope:
let (_, path) = temp.keep()?;  // Transfers ownership, file persists
// Remember to clean up `path` when done
```

**When this matters:**
- Any temporary file in a shared directory (`/tmp`, `std::env::temp_dir()`)
- Multi-user systems or containers with shared temp directories
- Background processes that create files before forking

**Prevention:**
- Always use `tempfile::NamedTempFile` or `tempfile::TempDir`
- Never construct temp paths from predictable values (PID, timestamp, username)
- Set restrictive permissions (0600) if you must create files manually

---

## ANTI-3: Incomplete Struct Field Updates

**Anti-Pattern:** Adding a new field to a struct but missing updates in some code paths (constructors, pattern matches, serialization).

**Real Example (from PR #58):**

When adding restart tracking to `SessionState`, the initial implementation forgot to:
1. Store `last_restart_attempt` in `Terminated` and `Quarantined` variants
2. Add a helper method to retrieve it from terminal states
3. Update all match arms that destructure the enum

```rust
// INCOMPLETE: New field added to Running but not to terminal states
pub enum SessionState {
    Running {
        started_at: DateTime<Utc>,
        restart_attempt: u32,  // New field added here
    },
    Terminated {
        terminated_at: DateTime<Utc>,
        // Missing: last_restart_attempt
    },
}

// Later code can't check monotonicity because terminal states don't track it!
```

**Fix:** Add the field to ALL relevant variants and add exhaustive helpers:

```rust
pub enum SessionState {
    Running {
        started_at: DateTime<Utc>,
        restart_attempt: u32,
    },
    Terminated {
        terminated_at: DateTime<Utc>,
        last_restart_attempt: u32,  // Now tracked
    },
    Quarantined {
        quarantined_at: DateTime<Utc>,
        last_restart_attempt: u32,  // Now tracked
    },
}

impl SessionState {
    /// Exhaustive helper ensures all variants are considered.
    pub fn last_restart_attempt(&self) -> Option<u32> {
        match self {
            Self::Running { restart_attempt, .. } => Some(*restart_attempt),
            Self::Terminated { last_restart_attempt, .. } => Some(*last_restart_attempt),
            Self::Quarantined { last_restart_attempt, .. } => Some(*last_restart_attempt),
            Self::Starting | Self::Pending => None,
        }
    }
}
```

**When this matters:**
- Enums with data-carrying variants
- Structs with many fields (especially builders)
- State machines where invariants must hold across all states

**Prevention:**
- Use `#[non_exhaustive]` on public enums to force explicit handling of new variants
- Write exhaustive match statements (avoid `_ =>` wildcards for enums you control)
- Add a test that constructs every variant and round-trips through serialization
- Run `cargo clippy` with `clippy::match_wildcard_for_single_variants`
