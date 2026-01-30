# Tool Module

> Protocol Buffers-based agent-kernel communication protocol implementing default-deny, least-privilege, fail-closed security.

## Overview

The `apm2_core::tool` module defines the wire protocol for agent tool requests and kernel responses. This is the primary interface through which AI agents request actions from the APM2 kernel, including filesystem operations, shell execution, git operations, inference calls, and artifact publishing.

This module integrates with three core APM2 architectural patterns:

1. **Protocol Buffers Encoding**: All messages use prost-generated types for deterministic, canonical encoding
2. **Defense-in-Depth Validation**: Malformed requests are rejected before reaching the policy engine
3. **Audit Trail**: All requests and responses are logged to the ledger for compliance and forensics

### Request Flow

```
Agent
  |
  v
ToolRequest (protobuf)
  |
  v
Validator.validate()
  |  [REJECT if malformed]
  v
Policy Engine
  |  [DENY if not explicitly allowed]
  v
Kernel Execution
  |
  v
ToolResponse (protobuf)
  |
  v
Agent
```

### Security Model

The tool protocol implements three security principles:

- **Default-deny**: All requests denied unless explicitly allowed by policy
- **Least-privilege**: Agents can only request tools in their lease scope
- **Fail-closed**: Any validation or policy error results in denial

## Key Types

### `ToolRequest`

```rust
#[derive(Eq, Hash)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ToolRequest {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(string, tag = "2")]
    pub session_token: String,
    #[prost(string, tag = "3")]
    pub dedupe_key: String,
    #[prost(oneof = "tool_request::Tool", tags = "10, 11, 12, 13, 14, 15, 16")]
    pub tool: Option<tool_request::Tool>,
}

pub mod tool_request {
    #[derive(Eq, Hash)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Tool {
        FileRead(super::FileRead),
        FileWrite(super::FileWrite),
        FileEdit(super::FileEdit),
        ShellExec(super::ShellExec),
        GitOp(super::GitOperation),
        Inference(super::InferenceCall),
        ArtifactPublish(super::ArtifactPublish),
    }
}
```

**Invariants:**
- [INV-0001] `request_id` must be non-empty and <= 256 characters
- [INV-0002] `session_token` must be non-empty and <= 256 characters
- [INV-0003] `dedupe_key` must be <= 256 characters (can be empty)
- [INV-0004] Exactly one tool variant must be specified

**Contracts:**
- [CTR-0001] Encoding is deterministic: same request produces identical bytes
- [CTR-0002] Decode-encode roundtrip preserves all fields exactly
- [CTR-0003] If `dedupe_key` is set, kernel returns cached results for identical keys within the same session

### `FileRead`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileRead {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(uint64, tag = "2")]
    pub offset: u64,
    #[prost(uint64, tag = "3")]
    pub limit: u64,
}
```

**Invariants:**
- [INV-0005] `path` must be non-empty and <= 4096 characters
- [INV-0006] `path` must not contain null bytes
- [INV-0007] `path` must not contain path traversal sequences (`..`)
- [INV-0008] `limit` must be <= 1 GB (1,073,741,824 bytes)

**Contracts:**
- [CTR-0004] `limit = 0` means read entire file (no limit)
- [CTR-0005] `offset = 0` means read from beginning
- [CTR-0006] Relative paths resolved against session's working directory

### `FileWrite`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileWrite {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(bytes = "vec", tag = "2")]
    pub content: Vec<u8>,
    #[prost(bool, tag = "3")]
    pub create_only: bool,
    #[prost(bool, tag = "4")]
    pub append: bool,
}
```

**Invariants:**
- [INV-0009] `path` must be non-empty and <= 4096 characters
- [INV-0010] `path` must not contain null bytes or path traversal sequences
- [INV-0011] `content` must be <= 100 MB (104,857,600 bytes)
- [INV-0012] `create_only` and `append` cannot both be true (mutually exclusive)

**Contracts:**
- [CTR-0007] `create_only = true`: Fail if file exists
- [CTR-0008] `append = true`: Append to existing file instead of overwriting

### `FileEdit`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileEdit {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(string, tag = "2")]
    pub old_content: String,
    #[prost(string, tag = "3")]
    pub new_content: String,
}
```

**Invariants:**
- [INV-0013] `path` must be non-empty and <= 4096 characters
- [INV-0014] `old_content` must be non-empty and <= 10 MB
- [INV-0015] `new_content` must be <= 10 MB

**Contracts:**
- [CTR-0009] Operation is atomic: either succeeds completely or fails without modifying the file
- [CTR-0010] `old_content` must match exactly once in the file; multiple matches cause failure

### `ShellExec`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ShellExec {
    #[prost(string, tag = "1")]
    pub command: String,
    #[prost(string, tag = "2")]
    pub cwd: String,
    #[prost(uint64, tag = "3")]
    pub timeout_ms: u64,
    #[prost(bool, tag = "4")]
    pub network_access: bool,
    #[prost(string, repeated, tag = "5")]
    pub env: Vec<String>,
}
```

**Invariants:**
- [INV-0016] `command` must be non-empty and <= 1 MB
- [INV-0017] `cwd` must be <= 4096 characters (can be empty)
- [INV-0018] `timeout_ms` must be <= 3,600,000 (1 hour)
- [INV-0019] `env` must have <= 1000 items (DoS protection)
- [INV-0020] Each `env` entry must be <= 32 KB and contain exactly one `=`

**Contracts:**
- [CTR-0011] `cwd` empty means use session's working directory
- [CTR-0012] `timeout_ms = 0` means use default timeout
- [CTR-0013] Policy may deny `network_access` even if requested
- [CTR-0014] `env` format: `["KEY=VALUE", ...]` (not a map for protobuf compatibility)

### `GitOperation`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GitOperation {
    #[prost(string, tag = "1")]
    pub operation: String,
    #[prost(string, repeated, tag = "2")]
    pub args: Vec<String>,
    #[prost(string, tag = "3")]
    pub cwd: String,
}
```

**Invariants:**
- [INV-0021] `operation` must be one of: `CLONE`, `FETCH`, `PULL`, `DIFF`, `COMMIT`, `PUSH`, `STATUS`, `LOG`, `BRANCH`, `CHECKOUT`, `MERGE`, `REBASE`, `ADD`, `RESET`, `STASH`, `TAG`, `REMOTE`, `SHOW`
- [INV-0022] `args` must have <= 1000 items
- [INV-0023] Each `args` entry must be <= 32 KB
- [INV-0024] `cwd` must be <= 4096 characters

**Contracts:**
- [CTR-0015] Git operations are mediated separately from `ShellExec` for granular policy
- [CTR-0016] Policy can allow `DIFF` but deny `PUSH` within the same session

### `InferenceCall`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InferenceCall {
    #[prost(string, tag = "1")]
    pub provider: String,
    #[prost(string, tag = "2")]
    pub model: String,
    #[prost(bytes = "vec", tag = "3")]
    pub prompt_hash: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub max_tokens: u64,
    #[prost(uint32, tag = "5")]
    pub temperature_scaled: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub system_prompt_hash: Vec<u8>,
}
```

**Invariants:**
- [INV-0025] `provider` must be non-empty and <= 256 characters
- [INV-0026] `model` must be non-empty and <= 256 characters
- [INV-0027] `prompt_hash` must be exactly 32 bytes (BLAKE3 hash)
- [INV-0028] `max_tokens` must be <= 1,000,000
- [INV-0029] `system_prompt_hash` must be empty or exactly 32 bytes

**Contracts:**
- [CTR-0017] `temperature_scaled` is `temperature * 100` (e.g., 70 = 0.70)
- [CTR-0018] Prompts are stored in CAS and referenced by hash (avoids transmitting large prompts)
- [CTR-0019] Policy may restrict providers, models, and per-session cost limits

### `ArtifactPublish`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ArtifactPublish {
    #[prost(string, tag = "1")]
    pub artifact_id: String,
    #[prost(bytes = "vec", tag = "2")]
    pub content_hash: Vec<u8>,
    #[prost(string, tag = "3")]
    pub category: String,
    #[prost(string, repeated, tag = "4")]
    pub metadata: Vec<String>,
}
```

**Invariants:**
- [INV-0030] `artifact_id` must be non-empty and <= 256 characters
- [INV-0031] `content_hash` must be exactly 32 bytes (BLAKE3 hash)
- [INV-0032] `category` must be non-empty and <= 256 characters
- [INV-0033] `metadata` must have <= 1000 items
- [INV-0034] Each `metadata` entry must be <= 32 KB and contain exactly one `=`

**Contracts:**
- [CTR-0020] Content must already be stored in CAS before publishing
- [CTR-0021] Artifacts are immutable once published

### `ToolResponse`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ToolResponse {
    #[prost(string, tag = "1")]
    pub request_id: String,
    #[prost(oneof = "tool_response::Result", tags = "2, 3, 4")]
    pub result: Option<tool_response::Result>,
}

pub mod tool_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        Success(super::ToolSuccess),
        Denied(super::ToolDenied),
        Error(super::ToolError),
    }
}
```

**Contracts:**
- [CTR-0022] Every `ToolRequest` receives exactly one `ToolResponse`
- [CTR-0023] `request_id` in response must match the request

### `ToolSuccess`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ToolSuccess {
    #[prost(bytes = "vec", tag = "1")]
    pub result_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub inline_result: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub budget_consumed: u64,
    #[prost(uint64, tag = "4")]
    pub duration_ms: u64,
}
```

**Contracts:**
- [CTR-0024] Large results (> 1 MB) stored in CAS; `result_hash` contains the hash
- [CTR-0025] Small results returned inline via `inline_result`

### `ToolDenied`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ToolDenied {
    #[prost(string, tag = "1")]
    pub rule_id: String,
    #[prost(string, tag = "2")]
    pub rationale_code: String,
    #[prost(string, tag = "3")]
    pub message: String,
}
```

**Contracts:**
- [CTR-0026] `rule_id` identifies the policy rule that caused denial
- [CTR-0027] `rationale_code` is machine-readable (e.g., `SHELL_EXEC_DENIED`)
- [CTR-0028] `message` is human-readable for debugging

### `ToolError`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ToolError {
    #[prost(string, tag = "1")]
    pub error_code: String,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(bool, tag = "3")]
    pub retryable: bool,
    #[prost(uint64, tag = "4")]
    pub retry_after_ms: u64,
}
```

**Contracts:**
- [CTR-0029] `retryable = true` indicates transient error (e.g., rate limiting)
- [CTR-0030] `retry_after_ms > 0` suggests minimum backoff before retry

### `ValidationError`

```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValidationError {
    #[prost(string, tag = "1")]
    pub field: String,
    #[prost(string, tag = "2")]
    pub rule: String,
    #[prost(string, tag = "3")]
    pub message: String,
}
```

**Contracts:**
- [CTR-0031] `field` identifies the problematic field (e.g., `file_read.path`)
- [CTR-0032] `rule` identifies the validation rule violated (e.g., `max_length`, `required`)

### `Validator` Trait

```rust
pub trait Validator {
    fn validate(&self) -> ValidationResult;
}

pub type ValidationResult = Result<(), Vec<ValidationError>>;
```

**Contracts:**
- [CTR-0033] Returns all validation errors in a single call (not fail-fast)
- [CTR-0034] Empty error list means request is valid

## Validation Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_ID_LEN` | 256 | Maximum identifier length |
| `MAX_PATH_LEN` | 4096 | Maximum file path length |
| `MAX_READ_LIMIT` | 1 GB | Maximum file read size |
| `MAX_WRITE_SIZE` | 100 MB | Maximum file write size |
| `MAX_EDIT_SIZE` | 10 MB | Maximum edit content size |
| `MAX_COMMAND_LEN` | 1 MB | Maximum shell command length |
| `MAX_TIMEOUT_MS` | 3,600,000 | Maximum timeout (1 hour) |
| `MAX_ARG_LEN` | 32 KB | Maximum single argument size |
| `MAX_TOKENS` | 1,000,000 | Maximum inference tokens |
| `HASH_SIZE` | 32 | BLAKE3 hash size in bytes |
| `MAX_REPEATED_ITEMS` | 1000 | Maximum repeated field entries |

## Public API

### `ToolRequest::validate(&self) -> ValidationResult`

Validates the request against all rules. Returns `Ok(())` if valid, or a vector of `ValidationError` describing all violations.

### `prost::Message::encode_to_vec(&self) -> Vec<u8>`

Encodes the message to Protocol Buffers format. Encoding is deterministic and canonical.

### `prost::Message::decode(buf: &[u8]) -> Result<Self, DecodeError>`

Decodes a Protocol Buffers message from bytes.

## Examples

### Creating and Validating a File Read Request

```rust
use apm2_core::tool::{FileRead, ToolRequest, tool_request, Validator};
use prost::Message;

let request = ToolRequest {
    request_id: "req-001".to_string(),
    session_token: "session-abc".to_string(),
    dedupe_key: String::new(),
    tool: Some(tool_request::Tool::FileRead(FileRead {
        path: "/workspace/src/main.rs".to_string(),
        offset: 0,
        limit: 0, // Read entire file
    })),
};

// Validate before sending
match request.validate() {
    Ok(()) => {
        let bytes = request.encode_to_vec();
        // Send bytes to kernel...
    }
    Err(errors) => {
        for e in errors {
            eprintln!("Validation error in {}: {} ({})", e.field, e.message, e.rule);
        }
    }
}
```

### Creating a Shell Execution Request

```rust
use apm2_core::tool::{ShellExec, ToolRequest, tool_request};

let request = ToolRequest {
    request_id: "req-002".to_string(),
    session_token: "session-abc".to_string(),
    dedupe_key: String::new(),
    tool: Some(tool_request::Tool::ShellExec(ShellExec {
        command: "cargo test --release".to_string(),
        cwd: "/workspace".to_string(),
        timeout_ms: 300_000, // 5 minutes
        network_access: false,
        env: vec![
            "RUST_BACKTRACE=1".to_string(),
            "CARGO_TERM_COLOR=always".to_string(),
        ],
    })),
};
```

### Handling Tool Responses

```rust
use apm2_core::tool::{ToolResponse, tool_response};
use prost::Message;

let bytes: Vec<u8> = /* received from kernel */;
let response = ToolResponse::decode(bytes.as_slice()).expect("decode failed");

match response.result {
    Some(tool_response::Result::Success(success)) => {
        println!("Success! Budget consumed: {}", success.budget_consumed);
        println!("Duration: {}ms", success.duration_ms);
        if !success.inline_result.is_empty() {
            println!("Result: {}", String::from_utf8_lossy(&success.inline_result));
        }
    }
    Some(tool_response::Result::Denied(denied)) => {
        eprintln!("Denied by rule {}: {}", denied.rule_id, denied.message);
    }
    Some(tool_response::Result::Error(error)) => {
        eprintln!("Error {}: {}", error.error_code, error.message);
        if error.retryable {
            eprintln!("Retry after {}ms", error.retry_after_ms);
        }
    }
    None => {
        eprintln!("Response missing result");
    }
}
```

### Publishing an Artifact

```rust
use apm2_core::tool::{ArtifactPublish, ToolRequest, tool_request};

let content_hash: Vec<u8> = /* BLAKE3 hash of content already stored in CAS */;

let request = ToolRequest {
    request_id: "req-003".to_string(),
    session_token: "session-abc".to_string(),
    dedupe_key: String::new(),
    tool: Some(tool_request::Tool::ArtifactPublish(ArtifactPublish {
        artifact_id: "test-results-001".to_string(),
        content_hash,
        category: "test_results".to_string(),
        metadata: vec![
            "format=junit".to_string(),
            "suite=integration".to_string(),
        ],
    })),
};
```

## Trust Boundaries

### Validation Trust Boundary

Validation is a **defense-in-depth** layer that catches malformed input before it reaches security-critical code paths. It is NOT a replacement for policy evaluation. The validator assumes:

1. **Untrusted input**: All request data originates from potentially malicious agents
2. **DoS protection**: Repeated fields and content sizes are bounded
3. **Path safety**: Path traversal sequences are rejected (defense-in-depth; policy/execution layers also enforce sandboxing)

### Policy Trust Boundary

After validation, the policy engine determines authorization:

1. **Session authentication**: `session_token` must match an active session
2. **Lease scope**: Requested tool must be in the session's lease scope
3. **Policy rules**: Specific allow/deny rules for paths, commands, providers

### Execution Trust Boundary

Even after policy approval, execution is sandboxed:

1. **Filesystem isolation**: Operations confined to allowed paths
2. **Process isolation**: Shell commands run with restricted privileges
3. **Network isolation**: Network access requires explicit policy grant

## Related Modules

- [`apm2_core::evidence`](../evidence/AGENTS.md) - CAS storage for artifact content and large results
- [`apm2_core::session`](../session/AGENTS.md) - Session management and `session_token` validation
- [`apm2_core::lease`](../lease/AGENTS.md) - Lease scope and authority boundaries
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Audit logging of all tool requests and responses
- [`apm2_core::crypto`](../crypto/AGENTS.md) - BLAKE3 hashing for `content_hash` and `prompt_hash`

## References

- [31 — I/O Protocol Boundaries](/documents/skills/rust-standards/references/31_io_protocol_boundaries.md) - wire protocol design patterns
- [34 — Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - input validation and trust boundaries
- [25 — API Design, stdlib Quality](/documents/skills/rust-standards/references/25_api_design_stdlib_quality.md) - protobuf message design
