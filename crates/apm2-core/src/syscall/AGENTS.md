# Syscall Module

> Kernel syscall mediation layer for workspace-confined filesystem operations with path traversal protection and BLAKE3 content tracking.

## Overview

The `apm2_core::syscall` module implements the execution layer for tool requests after policy authorization. It bridges the gap between policy-authorized tool requests (from `apm2_core::policy`) and their actual execution on the host filesystem.

```text
ToolRequest --> PolicyEngine::evaluate() --> [ALLOWED] --> FilesystemHandler
                                                                |
                                               validate_path() (traversal + confinement)
                                                                |
                                               read_file() / write_file() / edit_file()
                                                                |
                                             FileOperationResult (content + BLAKE3 hash)
                                                   + ModificationRecord (for ledger audit)
```

### Security Model

The filesystem handler implements **default-deny, least-privilege, fail-closed** at every layer:

1. **Path validation**: All paths are checked for `..` traversal sequences before any I/O.
2. **Workspace confinement**: Resolved paths MUST be within the configured workspace root.
3. **Symlink resolution**: Symlinks are followed (configurable) and verified to remain within workspace. Resolution depth is bounded by `MAX_SYMLINK_DEPTH` (40).
4. **TOCTOU mitigation**: Read operations use `O_NOFOLLOW` on Unix to prevent symlink swap attacks between validation and open. Write/edit operations use atomic temp-file-and-rename.
5. **Content hashing**: All file contents are tracked via BLAKE3 hashes for audit and integrity verification.
6. **Size limits**: Read, write, and edit operations enforce configurable maximum content sizes.

### Blocking I/O Contract

All methods in `FilesystemHandler` perform blocking filesystem I/O using `std::fs`. When called from an async context, these methods MUST be executed within `tokio::task::spawn_blocking` to prevent blocking the async runtime.

## Key Types

### `FilesystemConfig`

```rust
#[derive(Debug, Clone)]
pub struct FilesystemConfig {
    workspace_root: PathBuf,
    max_read_size: usize,    // default: 100MB
    max_write_size: usize,   // default: 100MB
    max_edit_size: usize,    // default: 10MB
    follow_symlinks: bool,   // default: true
}
```

Configuration for the filesystem handler. All paths must resolve within `workspace_root`.

**Invariants:**

- [INV-SC01] **Workspace root canonicalization**: `workspace_root` is canonicalized at construction time to an absolute, symlink-resolved path.
- [INV-SC02] **Confinement boundary**: No file operation may access paths outside `workspace_root` after symlink resolution.

**Contracts:**

- [CTR-SC01] `FilesystemConfig::new(path)` panics if the workspace root cannot be canonicalized. Use `FilesystemConfig::builder(path).build()` for fallible construction.

### `FilesystemHandler`

```rust
#[derive(Debug, Clone)]
pub struct FilesystemHandler {
    config: FilesystemConfig,
}
```

Filesystem mediation handler. Handles file read, write, and edit operations with workspace confinement and security validation.

**Contracts:**

- [CTR-SC02] `validate_path(path, must_exist) -> Result<PathBuf, SyscallError>` checks for traversal sequences, resolves symlinks, and verifies confinement. Returns the canonical path on success.
- [CTR-SC03] `read_file(path, offset, limit) -> Result<FileOperationResult, SyscallError>` validates the path, reads content with optional offset/limit, and returns BLAKE3-hashed content.
- [CTR-SC04] `write_file(path, content, create_only, append) -> Result<ModificationRecord, SyscallError>` validates the path, writes via atomic temp-file-and-rename, and returns before/after hashes.
- [CTR-SC05] `edit_file(path, old_text, new_text) -> Result<ModificationRecord, SyscallError>` validates the path, performs exact single-match search-and-replace via atomic write, and returns before/after hashes.

### `ModificationRecord`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModificationRecord {
    pub path: PathBuf,
    pub operation: FileOperation,
    pub hash_before: Option<[u8; 32]>,
    pub hash_after: [u8; 32],
    pub size_after: u64,
    pub duration_ms: u64,
}
```

Record of a file modification for ledger audit. Contains BLAKE3 hashes before and after the operation.

**Invariants:**

- [INV-SC03] **Hash integrity**: `hash_before` is `None` only for newly created files. `hash_after` is always populated.
- [INV-SC04] **Atomic modifications**: Write and edit operations use temp-file-and-rename to prevent partial modifications observable by concurrent readers.

### `FileOperation` (enum)

```rust
pub enum FileOperation {
    Read,
    Write,
    Create,
    Append,
    Edit,
}
```

### `FileOperationResult`

```rust
#[derive(Debug, Clone)]
pub struct FileOperationResult {
    pub content: Vec<u8>,
    pub content_hash: [u8; 32],
    pub size: u64,
    pub duration_ms: u64,
}
```

### `SyscallError` (enum)

```rust
pub enum SyscallError {
    PathValidation { path, reason },
    PathOutsideWorkspace { path, workspace },
    PathTraversal { path },
    FileNotFound { path },
    FileAlreadyExists { path },
    NotAFile { path },
    EditNotFound { path },
    EditMultipleMatches { path, count },
    PermissionDenied { path },
    Io { path, source },
    OffsetBeyondFile { offset, file_size },
    ContentTooLarge { size, limit },
    SymlinkDepthExceeded { path, depth },
    Timeout { timeout_ms },
}
```

**Invariants:**

- [INV-SC05] **Machine-readable error codes**: Every variant maps to a unique `error_code()` string (e.g., `PATH_TRAVERSAL_DETECTED`, `PATH_OUTSIDE_WORKSPACE`).
- [INV-SC06] **Retryability classification**: `is_retryable()` returns `true` only for transient failures (`Io`, `Timeout`). All path/validation errors are non-retryable.

## Public API

### Configuration

- `FilesystemConfig::new(workspace_root) -> FilesystemConfig`
- `FilesystemConfig::builder(workspace_root) -> FilesystemConfigBuilder`
- `FilesystemConfigBuilder::max_write_size(size) -> Self`
- `FilesystemConfigBuilder::max_edit_size(size) -> Self`
- `FilesystemConfigBuilder::follow_symlinks(bool) -> Self`
- `FilesystemConfigBuilder::build() -> Result<FilesystemConfig, SyscallError>`

### File Operations

- `FilesystemHandler::new(config) -> FilesystemHandler`
- `FilesystemHandler::validate_path(path, must_exist) -> Result<PathBuf, SyscallError>`
- `FilesystemHandler::read_file(path, offset, limit) -> Result<FileOperationResult, SyscallError>`
- `FilesystemHandler::write_file(path, content, create_only, append) -> Result<ModificationRecord, SyscallError>`
- `FilesystemHandler::edit_file(path, old_text, new_text) -> Result<ModificationRecord, SyscallError>`

## Examples

### Reading a File

```rust
use apm2_core::syscall::{FilesystemHandler, FilesystemConfig};

let config = FilesystemConfig::new("/workspace");
let handler = FilesystemHandler::new(config);

// Read entire file -- returns content + BLAKE3 hash
let result = handler.read_file("/workspace/src/main.rs", 0, 0)?;
println!("Read {} bytes, hash: {:?}", result.size, result.content_hash);

// Read with offset and limit
let partial = handler.read_file("/workspace/src/main.rs", 100, 50)?;
```

### Writing and Editing Files

```rust
use apm2_core::syscall::{FilesystemHandler, FilesystemConfig};

let config = FilesystemConfig::new("/workspace");
let handler = FilesystemHandler::new(config);

// Write a file (atomic temp-file-and-rename)
let record = handler.write_file(
    "/workspace/output.txt",
    b"Hello, World!",
    false, // not create_only
    false, // not append
)?;
println!("Before: {:?}, After: {:?}", record.hash_before, record.hash_after);

// Edit with exact search-and-replace (must match exactly once)
let edit_record = handler.edit_file(
    "/workspace/src/main.rs",
    "old_function_name",
    "new_function_name",
)?;
```

### Async Usage

```rust
use apm2_core::syscall::{FilesystemHandler, FilesystemConfig};

let config = FilesystemConfig::new("/workspace");
let handler = FilesystemHandler::new(config);

// MUST use spawn_blocking in async context
let result = tokio::task::spawn_blocking(move || {
    handler.read_file("/workspace/README.md", 0, 0)
}).await??;
```

## Related Modules

- [`apm2_core::policy`](../policy/AGENTS.md) - Policy evaluation engine (authorizes requests before syscall execution)
- [`apm2_core::tool`](../tool/) - Tool request types (`FileRead`, `FileWrite`, `FileEdit`)
- [`apm2_core::ledger`](../ledger/AGENTS.md) - Append-only event storage (modification records are logged)
- [`apm2_core::pcac`](../pcac/AGENTS.md) - PCAC authority lifecycle (gates side effects before syscall execution)

## References

- [RFC-0001] APM2 Kernel Architecture -- syscall mediation, workspace confinement, default-deny execution
- [APM2 Rust Standards] [Time, Monotonicity, Determinism](/documents/skills/rust-standards/references/40_time_monotonicity_determinism.md) - TOCTOU mitigation patterns
