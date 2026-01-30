# Credentials Module

> Secure storage, retrieval, and hot-swapping of credentials for AI CLI tools (Claude Code, Gemini CLI, Codex CLI).

## Overview

The `apm2_core::credentials` module provides a credential management subsystem for APM2's process supervision framework. It handles the complete lifecycle of authentication credentials: secure storage via OS keyring integration, runtime retrieval with in-memory caching, hot-swapping for zero-downtime credential rotation, and automatic OAuth token refresh.

This module implements the security requirements outlined in the [APM2 Rust Standards] [CTR-1901]: threat models include resource exhaustion, logic bugs in authorization, and supply chain considerations. Secrets are stored using the `secrecy` crate to prevent accidental exposure via `Debug` or logging.

**Architectural Position**: The credentials module is consumed by `apm2_core::process` to inject credentials into spawned agent processes. It integrates with the process supervision layer to enable credential rotation without restart via configurable signal delivery.

## Key Types

### `ProfileId`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(String);
```

**Invariants:**
- [INV-CRED-001] ProfileId is a non-empty string identifier used as the keyring entry key.

**Contracts:**
- [CTR-CRED-001] ProfileId must be unique within a CredentialStore instance.

### `Provider`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Claude,   // Anthropic Claude
    Gemini,   // Google Gemini
    OpenAI,   // OpenAI (GPT, Codex)
    Custom,   // Custom/other provider
}
```

**Invariants:**
- [INV-CRED-002] Provider parsing is case-insensitive and supports aliases (`"anthropic"` -> `Claude`, `"google"` -> `Gemini`, `"gpt"` -> `OpenAI`).

**Contracts:**
- [CTR-CRED-002] `FromStr` implementation is infallible for known providers and returns `Err` for unknown strings.

### `AuthMethod`

```rust
pub enum AuthMethod {
    OAuth {
        access_token: SecretString,
        refresh_token: Option<SecretString>,
        expires_at: Option<DateTime<Utc>>,
        scopes: Vec<String>,
    },
    SessionToken {
        token: SecretString,
        cookie_jar: Option<PathBuf>,
        expires_at: Option<DateTime<Utc>>,
    },
    ApiKey {
        key: SecretString,
    },
}
```

**Invariants:**
- [INV-CRED-003] All secret values use `SecretString` to prevent accidental exposure via `Debug` or logging.
- [INV-CRED-004] `expires_at` is `Some` for time-bounded credentials, `None` for non-expiring credentials (e.g., API keys).

**Contracts:**
- [CTR-CRED-003] `is_expired()` returns `false` for `ApiKey` variant (API keys do not expire).
- [CTR-CRED-004] `expires_within(duration)` computes against `Utc::now()` and the stored expiration time.

### `CredentialProfile`

```rust
#[derive(Debug, Clone)]
pub struct CredentialProfile {
    pub id: ProfileId,
    pub provider: Provider,
    pub label: Option<String>,
    pub auth: AuthMethod,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}
```

**Invariants:**
- [INV-CRED-005] `created_at <= updated_at` always holds.
- [INV-CRED-006] `last_used_at` is `None` until `mark_used()` is called.

**Contracts:**
- [CTR-CRED-005] `new()` initializes both `created_at` and `updated_at` to `Utc::now()`.
- [CTR-CRED-006] `is_expired()` delegates to `self.auth.is_expired()`.

### `CredentialProfileMetadata`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProfileMetadata {
    pub id: String,
    pub provider: String,
    pub label: Option<String>,
    pub auth_method: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}
```

**Invariants:**
- [INV-CRED-007] Metadata excludes all secret values; safe for logging and external exposure.

**Contracts:**
- [CTR-CRED-007] `From<&CredentialProfile>` extracts only non-secret fields.

### `CredentialStore`

```rust
pub struct CredentialStore {
    service_name: String,
    cache: RwLock<HashMap<ProfileId, CredentialProfile>>,
}
```

**Invariants:**
- [INV-CRED-008] Secrets are stored in OS keyring, not in memory. The cache holds full profiles for convenience but secrets are authoritative in the keyring.
- [INV-CRED-009] Cache access is synchronized via `RwLock` for thread-safety.

**Contracts:**
- [CTR-CRED-008] `store()` writes to both keyring and cache atomically (keyring first, then cache).
- [CTR-CRED-009] `get()` checks cache first, falls back to keyring on cache miss.
- [CTR-CRED-010] `remove()` deletes from keyring first, then cache.

### `HotSwapConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotSwapConfig {
    pub signal: String,                    // Default: "SIGHUP"
    pub env_injection: bool,               // Default: true
    pub config_file_path: Option<PathBuf>,
    pub graceful_drain: Duration,          // Default: 5s
    pub validate_before_swap: bool,        // Default: true
    pub rollback_on_failure: bool,         // Default: true
}
```

**Invariants:**
- [INV-CRED-010] Default configuration enables validation and rollback for safe credential rotation.

**Contracts:**
- [CTR-CRED-011] `graceful_drain` specifies the wait duration for in-flight requests before applying new credentials.

### `HotSwapState`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotSwapState {
    Idle,
    Validating,
    Draining,
    Applying,
    Completed,
    RollingBack,
    Failed(String),
}
```

**Invariants:**
- [INV-CRED-011] State machine transitions: `Idle -> Validating -> Draining -> Applying -> Completed`.
- [INV-CRED-012] Failure at any stage triggers `RollingBack` (if configured) or `Failed`.

### `HotSwapManager`

```rust
#[derive(Debug)]
pub struct HotSwapManager {
    config: HotSwapConfig,
    state: HotSwapState,
    previous_profile: Option<String>,
}
```

**Invariants:**
- [INV-CRED-013] Only one hot-swap operation can be in progress at a time.
- [INV-CRED-014] `previous_profile` is stored for rollback capability.

**Contracts:**
- [CTR-CRED-012] `start_swap()` returns `HotSwapError::AlreadyInProgress` if `is_in_progress()` is true.
- [CTR-CRED-013] `is_in_progress()` returns true for `Validating`, `Draining`, `Applying`, `RollingBack` states.

### `RefreshConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshConfig {
    pub enabled: bool,                     // Default: true
    pub refresh_before_expiry: Duration,   // Default: 5 minutes
    pub max_attempts: u32,                 // Default: 3
    pub retry_delay: Duration,             // Default: 30s
    pub token_endpoint: Option<String>,
}
```

**Invariants:**
- [INV-CRED-015] `refresh_before_expiry` determines the window before expiration when refresh is triggered.

**Contracts:**
- [CTR-CRED-014] Refresh scheduling computes `refresh_at = expires_at - refresh_before_expiry`.

### `RefreshState`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshState {
    NotNeeded,
    Scheduled { at: DateTime<Utc> },
    InProgress { attempt: u32 },
    Completed { new_expiry: DateTime<Utc> },
    Failed { error: String, attempts: u32 },
}
```

**Invariants:**
- [INV-CRED-016] `attempt` is 1-based.
- [INV-CRED-017] `attempts` in `Failed` tracks total attempts made.

### `RefreshManager`

```rust
#[derive(Debug)]
pub struct RefreshManager {
    config: RefreshConfig,
    state: RefreshState,
    last_refresh: Option<DateTime<Utc>>,
    consecutive_failures: u32,
}
```

**Invariants:**
- [INV-CRED-018] `consecutive_failures` resets to 0 on successful refresh.

**Contracts:**
- [CTR-CRED-015] `needs_refresh(expires_at)` returns `false` if `config.enabled` is `false`.
- [CTR-CRED-016] `can_retry()` returns `false` when `attempts >= max_attempts`.

### `CredentialConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub profile: String,
    pub hot_swap: bool,                                    // Default: false
    pub hot_swap_signal: String,                           // Default: "SIGHUP"
    pub auto_refresh: bool,                                // Default: false
    pub env_mapping: HashMap<String, String>,
    pub config_file: Option<PathBuf>,
}
```

**Invariants:**
- [INV-CRED-019] `env_mapping` maps profile field names to environment variable names for injection.

**Contracts:**
- [CTR-CRED-017] Used by `ProcessSpec` to bind credentials to spawned processes.

## Public API

### `CredentialStore::new(service_name) -> Self`

Creates a new credential store with the specified keyring service name.

### `CredentialStore::store(profile) -> Result<(), CredentialStoreError>`

Stores a credential profile. Serializes auth data to JSON and stores in OS keyring. Updates in-memory cache.

### `CredentialStore::get(profile_id) -> Result<CredentialProfile, CredentialStoreError>`

Retrieves a credential profile. Checks cache first, then keyring. Deserializes auth data from JSON.

### `CredentialStore::remove(profile_id) -> Result<(), CredentialStoreError>`

Removes a credential profile from both keyring and cache.

### `CredentialStore::list() -> Result<Vec<ProfileId>, CredentialStoreError>`

Lists all cached profile IDs. Note: only returns profiles that have been loaded into cache.

### `CredentialStore::exists(profile_id) -> Result<bool, CredentialStoreError>`

Checks if a profile exists in the cache.

### `HotSwapManager::new(config) -> Self`

Creates a new hot-swap manager with the specified configuration.

### `HotSwapManager::start_swap(current_profile) -> Result<(), HotSwapError>`

Initiates a hot-swap operation. Stores current profile for potential rollback.

### `HotSwapManager::begin_drain() / begin_apply() / complete() / fail(reason)`

State machine transitions for the hot-swap lifecycle.

### `RefreshManager::new(config) -> Self`

Creates a new refresh manager with the specified configuration.

### `RefreshManager::needs_refresh(expires_at) -> bool`

Determines if a refresh is needed based on the expiration time and configuration.

### `RefreshManager::schedule(expires_at) / begin_refresh() / complete(new_expiry) / fail(error)`

State machine transitions for the token refresh lifecycle.

## Error Types

### `CredentialError`

Top-level credential errors:
- `ProfileNotFound(String)` - Requested profile does not exist
- `Storage(CredentialStoreError)` - Storage layer failure
- `HotSwapFailed(String)` - Hot-swap operation failed
- `RefreshFailed(String)` - Token refresh failed
- `Invalid(String)` - Invalid credential data

### `CredentialStoreError`

Storage-specific errors:
- `NotFound(String)` - Profile not in keyring
- `Keyring(String)` - OS keyring operation failed
- `Serialization(String)` - JSON serialization/deserialization failed
- `LockPoisoned` - Internal RwLock poisoned

### `HotSwapError`

Hot-swap specific errors:
- `AlreadyInProgress` - Concurrent swap attempted
- `NotInProgress` - Operation on idle manager
- `SignalFailed(String)` - Process signal delivery failed
- `ConfigUpdateFailed(String)` - Config file update failed
- `ValidationFailed(String)` - New credential validation failed

### `RefreshError`

Token refresh specific errors:
- `NoRefreshToken` - OAuth refresh token not available
- `NoTokenEndpoint` - Token endpoint URL not configured
- `HttpFailed(String)` - HTTP request to token endpoint failed
- `InvalidResponse(String)` - Invalid response from token endpoint
- `MaxRetriesExceeded` - Exceeded configured retry limit

## Examples

### Creating and storing a credential profile

```rust
use apm2_core::credentials::{
    AuthMethod, CredentialProfile, CredentialStore, ProfileId, Provider,
};
use secrecy::SecretString;

// Create store backed by OS keyring
let store = CredentialStore::new("apm2");

// Create API key profile
let profile = CredentialProfile::new(
    ProfileId::new("anthropic-prod"),
    Provider::Claude,
    AuthMethod::ApiKey {
        key: SecretString::from("sk-ant-...".to_string()),
    },
).with_label("Production API Key");

// Store in keyring
store.store(profile)?;

// Retrieve later
let profile = store.get(&ProfileId::new("anthropic-prod"))?;
```

### Hot-swapping credentials

```rust
use apm2_core::credentials::{HotSwapConfig, HotSwapManager, HotSwapState};
use std::time::Duration;

let config = HotSwapConfig {
    signal: "SIGHUP".to_string(),
    graceful_drain: Duration::from_secs(10),
    validate_before_swap: true,
    rollback_on_failure: true,
    ..Default::default()
};

let mut manager = HotSwapManager::new(config);

// Start swap operation
manager.start_swap("old-profile".to_string())?;
assert!(matches!(*manager.state(), HotSwapState::Validating));

// Progress through states
manager.begin_drain();
manager.begin_apply();
manager.complete();

assert!(!manager.is_in_progress());
```

### Automatic token refresh

```rust
use apm2_core::credentials::{RefreshConfig, RefreshManager};
use chrono::{Duration as ChronoDuration, Utc};
use std::time::Duration;

let config = RefreshConfig {
    enabled: true,
    refresh_before_expiry: Duration::from_secs(300), // 5 minutes
    max_attempts: 3,
    retry_delay: Duration::from_secs(30),
    token_endpoint: Some("https://oauth.example.com/token".to_string()),
};

let mut manager = RefreshManager::new(config);

// Check if refresh needed
let expires_at = Utc::now() + ChronoDuration::minutes(2);
if manager.needs_refresh(Some(expires_at)) {
    manager.begin_refresh();
    // ... perform actual refresh ...
    let new_expiry = Utc::now() + ChronoDuration::hours(1);
    manager.complete(new_expiry);
}
```

### Process credential binding

```rust
use apm2_core::credentials::CredentialConfig;
use std::collections::HashMap;

let config = CredentialConfig {
    profile: "anthropic-prod".to_string(),
    hot_swap: true,
    hot_swap_signal: "SIGHUP".to_string(),
    auto_refresh: false, // API keys don't expire
    env_mapping: {
        let mut m = HashMap::new();
        m.insert("key".to_string(), "ANTHROPIC_API_KEY".to_string());
        m
    },
    config_file: None,
};

// Used in ProcessSpec for spawning agent processes
```

## Related Modules

- [`apm2_core::process`](../process/AGENTS.md) - Process supervision; consumes `CredentialConfig` for credential injection
- [`apm2_core::config`](../config/AGENTS.md) - Ecosystem configuration; includes credential profile definitions
- [`apm2_core::adapter`](../adapter/AGENTS.md) - Agent adapters; use credentials for provider authentication

## Security Considerations

Following [APM2 Rust Standards] [CTR-1901] and [RSK-1903]:

1. **Secret Handling**: All sensitive values use `secrecy::SecretString` which:
   - Implements `Zeroize` for memory clearing on drop
   - Does not implement `Display` or `Debug` exposing the secret
   - Requires explicit `expose_secret()` to access the value

2. **Keyring Storage**: Secrets are stored in the OS-native keyring (Keychain on macOS, Secret Service on Linux, Credential Manager on Windows) rather than in files or memory.

3. **Serialization Safety**: `CredentialProfileMetadata` provides a secret-free view for logging and external communication.

4. **Lock Poisoning**: `LockPoisoned` error is returned if the internal `RwLock` is poisoned (e.g., due to a panic during a write operation), preventing use of potentially corrupted state.

## References

- [APM2 Rust Standards] [API Design](/documents/skills/rust-standards/references/18_api_design_and_semver.md) - Explicit Public API Contracts
- [APM2 Rust Standards] [API Design](/documents/skills/rust-standards/references/18_api_design_and_semver.md) - Visibility Enforces Invariants
- [APM2 Rust Standards] [Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - [CTR-1901] (threat model)
- [APM2 Rust Standards] [Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - [RSK-1903] (unsafe code escalation)
- [secrecy crate documentation](https://docs.rs/secrecy/)
- [keyring crate documentation](https://docs.rs/keyring/)
