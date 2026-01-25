# Log Module

> Provides log management, rotation, streaming, and secret redaction for managed processes.

## Overview

The `apm2_core::log` module handles log collection and configuration for processes managed by APM2. It provides:

1. **Log Configuration** - Configures stdout/stderr capture, file destinations, and rotation policies
2. **Log Rotation** - Size-based, daily, or hourly rotation with compression support
3. **Structured Log Lines** - Timestamped log entries with process and stream metadata
4. **Secret Redaction** - Automatic detection and masking of sensitive data (API keys, tokens, credentials)

This module is used by:
- `apm2_core::config` - `LogConfig` is part of process configuration files
- `apm2_core::process` - `ProcessSpec` includes log configuration for each managed process

## Key Types

### `LogConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub out_file: Option<PathBuf>,
    pub err_file: Option<PathBuf>,
    pub combined_file: Option<PathBuf>,
    pub merge_stderr: bool,
    pub rotation: Option<LogRotationConfig>,
    pub timestamp: bool,
    pub timestamp_format: String,
}
```

**Invariants:**
- [INV-LOG-0001] If `merge_stderr` is `true`, stderr output is redirected to the same destination as stdout
- [INV-LOG-0002] If no file paths are specified, logs go to the combined file (if set)
- [INV-LOG-0003] Default timestamp format is `%Y-%m-%d %H:%M:%S%.3f`

**Contracts:**
- [CTR-LOG-0001] All path fields must be valid filesystem paths when provided
- [CTR-LOG-0002] `timestamp_format` must be a valid `chrono` strftime format string

### `LogRotationConfig`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    pub max_size: u64,      // Default: 10 MB
    pub max_files: u32,     // Default: 10
    pub compress: bool,     // Default: false
    pub mode: RotationMode, // Default: Size
}
```

**Invariants:**
- [INV-LOG-0010] `max_size` defaults to 10 MiB (10 * 1024 * 1024 bytes)
- [INV-LOG-0011] `max_files` defaults to 10 rotated files retained

**Contracts:**
- [CTR-LOG-0010] `max_size` must be greater than zero for size-based rotation

### `RotationMode`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationMode {
    #[default]
    Size,   // Rotate based on file size
    Daily,  // Rotate daily
    Hourly, // Rotate hourly
}
```

### `LogLine`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub stream: LogStream,
    pub process_name: String,
    pub instance: u32,
    pub content: String,
}
```

**Invariants:**
- [INV-LOG-0020] `timestamp` is always in UTC
- [INV-LOG-0021] `instance` is a zero-indexed identifier for process instances

### `LogStream`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogStream {
    Stdout,
    Stderr,
}
```

### `LogManager`

```rust
#[derive(Debug)]
pub struct LogManager {
    config: LogConfig,
    process_name: String,
    instance: u32,
    stdout_size: u64,
    stderr_size: u64,
}
```

**Invariants:**
- [INV-LOG-0030] `stdout_size` and `stderr_size` track cumulative bytes written since last rotation
- [INV-LOG-0031] Size tracking resets to zero after calling `reset_stdout_size()` or `reset_stderr_size()`

**Contracts:**
- [CTR-LOG-0030] `new()` is `const fn` - no allocations or I/O at construction time
- [CTR-LOG-0031] All size-tracking methods are `const fn` for deterministic behavior

### `SecretRedactor`

```rust
#[derive(Debug, Clone, Default)]
pub struct SecretRedactor {
    custom_patterns: Vec<Regex>,
}
```

**Invariants:**
- [INV-LOG-0040] Built-in patterns detect common secret formats (API keys, tokens, credentials)
- [INV-LOG-0041] Returns `Cow::Borrowed` when no redaction is needed (zero-copy optimization)

**Contracts:**
- [CTR-LOG-0040] `with_pattern()` panics if the provided regex pattern is invalid
- [CTR-LOG-0041] `redact()` is infallible - always returns a valid string

### `LogError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("failed to create log file: {0}")]
    CreateFailed(#[from] std::io::Error),

    #[error("failed to rotate log file: {0}")]
    RotationFailed(String),

    #[error("log directory does not exist: {0}")]
    DirectoryNotFound(PathBuf),
}
```

## Public API

### Log Management

```rust
impl LogManager {
    pub const fn new(config: LogConfig, process_name: String, instance: u32) -> Self;
    pub fn stdout_path(&self) -> Option<PathBuf>;
    pub fn stderr_path(&self) -> Option<PathBuf>;
    pub fn format_line(&self, content: &str, stream: LogStream) -> String;
    pub fn needs_stdout_rotation(&self) -> bool;
    pub fn needs_stderr_rotation(&self) -> bool;
    pub const fn record_stdout_bytes(&mut self, bytes: u64);
    pub const fn record_stderr_bytes(&mut self, bytes: u64);
    pub const fn reset_stdout_size(&mut self);
    pub const fn reset_stderr_size(&mut self);
    pub const fn config(&self) -> &LogConfig;
    pub fn process_name(&self) -> &str;
    pub const fn instance(&self) -> u32;
}
```

### Secret Redaction

```rust
impl SecretRedactor {
    pub fn new() -> Self;
    pub fn with_pattern(self, pattern: &str) -> Self;
    pub fn redact<'a>(&self, input: &'a str) -> Cow<'a, str>;
    pub fn is_sensitive_env_name(name: &str) -> bool;
    pub fn redact_env_value<'a>(name: &str, value: &'a str) -> Cow<'a, str>;
}

// Convenience functions
pub fn redact(input: &str) -> Cow<'_, str>;
pub fn is_sensitive_env_name(name: &str) -> bool;
```

### Built-in Secret Patterns

The `SecretRedactor` detects these secret types by default:

| Pattern Name | Example Match |
|--------------|---------------|
| `anthropic_api_key` | `sk-ant-api03-...` |
| `openai_api_key` | `sk-proj-...` |
| `google_api_key` | `AIza...` |
| `aws_access_key` | `AKIA...` |
| `aws_secret_key` | `aws_secret_access_key=...` |
| `github_token` | `ghp_...`, `gho_...`, `ghu_...` |
| `slack_token` | `xoxb-...`, `xoxp-...` |
| `bearer_token` | `Bearer eyJ...` |
| `private_key` | `-----BEGIN PRIVATE KEY-----` |
| `generic_api_key` | `api_key=...` |
| `generic_token` | `access_token=...` |
| `generic_secret` | `password=...` |

### Sensitive Environment Variable Names

The following patterns mark environment variables as sensitive:

- `*api_key*`, `*secret*`, `*token*`, `*password*`, `*credential*`
- `ANTHROPIC_*`, `OPENAI_*`, `CLAUDE_*`, `AWS_*`, `GOOGLE_*`
- `GITHUB_TOKEN`, `GH_TOKEN`

## Examples

### Basic Log Configuration

```rust
use apm2_core::log::{LogConfig, LogRotationConfig, RotationMode, LogManager, LogStream};
use std::path::PathBuf;

let config = LogConfig {
    out_file: Some(PathBuf::from("/var/log/myapp/stdout.log")),
    err_file: Some(PathBuf::from("/var/log/myapp/stderr.log")),
    combined_file: None,
    merge_stderr: false,
    rotation: Some(LogRotationConfig {
        max_size: 50 * 1024 * 1024, // 50 MB
        max_files: 5,
        compress: true,
        mode: RotationMode::Size,
    }),
    timestamp: true,
    timestamp_format: "%Y-%m-%d %H:%M:%S%.3f".to_string(),
};

let mut manager = LogManager::new(config, "my-process".to_string(), 0);

// Format a log line with timestamp
let line = manager.format_line("Application started", LogStream::Stdout);
// Result: "[2024-01-15 10:30:45.123] [stdout] Application started"

// Track bytes written
manager.record_stdout_bytes(line.len() as u64);

// Check if rotation is needed
if manager.needs_stdout_rotation() {
    // Perform rotation...
    manager.reset_stdout_size();
}
```

### Secret Redaction

```rust
use apm2_core::log::{SecretRedactor, redact, is_sensitive_env_name};

// Using the default redactor
let input = "API key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
let output = redact(input);
assert!(output.contains("[REDACTED]"));
assert!(!output.contains("sk-ant"));

// Custom patterns
let redactor = SecretRedactor::new()
    .with_pattern(r"internal-secret-\d+");

let input = "Found: internal-secret-12345";
let output = redactor.redact(input);
assert!(output.contains("[REDACTED]"));

// Environment variable handling
if is_sensitive_env_name("ANTHROPIC_API_KEY") {
    let safe_value = SecretRedactor::redact_env_value("ANTHROPIC_API_KEY", "sk-ant-...");
    // safe_value == "[REDACTED]"
}
```

### TOML Configuration

```toml
[[processes]]
name = "claude-code"
command = "claude"

[processes.log]
out_file = "/var/log/apm2/claude-code/stdout.log"
err_file = "/var/log/apm2/claude-code/stderr.log"
merge_stderr = false
timestamp = true
timestamp_format = "%Y-%m-%d %H:%M:%S%.3f"

[processes.log.rotation]
max_size = 10485760  # 10 MB
max_files = 10
compress = true
mode = "size"  # or "daily", "hourly"
```

## Related Modules

- [`apm2_core::config`](../config/) - Uses `LogConfig` in ecosystem configuration files
- [`apm2_core::process`](../process/) - `ProcessSpec` includes log configuration for each managed process
- [`apm2_core::credentials`](../credentials/) - Secret redaction protects credential values in logs
