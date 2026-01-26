//! Syscall mediation layer for agent-kernel communication.
//!
//! This module provides the mediation layer for tool execution. It bridges
//! the gap between tool requests (defined in the `tool` module) and their
//! actual execution on the host system.
//!
//! # Architecture
//!
//! The syscall layer implements a **request/response protocol** where:
//! 1. Agents submit tool requests
//! 2. The policy engine evaluates authorization
//! 3. This module executes allowed requests
//! 4. Results are returned and logged to the ledger
//!
//! # Security Model
//!
//! All syscall handlers implement **default-deny, least-privilege,
//! fail-closed**:
//!
//! - **Workspace restriction**: File operations are confined to the workspace
//!   root
//! - **Path validation**: Paths are normalized and checked for traversal
//!   attacks
//! - **Symlink resolution**: Symlinks are resolved to prevent escape
//! - **Content hashing**: File modifications are tracked via BLAKE3 hashes
//! - **Audit logging**: All operations are logged to the ledger
//!
//! # Handlers
//!
//! - [`filesystem`]: File read, write, and edit operations
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::syscall::{FilesystemHandler, FilesystemConfig};
//! use apm2_core::tool::FileRead;
//!
//! let config = FilesystemConfig::new("/workspace");
//! let handler = FilesystemHandler::new(config);
//!
//! // Execute a file read request
//! let request = FileRead {
//!     path: "/workspace/src/main.rs".to_string(),
//!     offset: 0,
//!     limit: 0,
//! };
//!
//! let result = handler.read(&request).await?;
//! println!("Read {} bytes", result.content.len());
//! ```

mod error;
pub mod filesystem;

pub use error::SyscallError;
pub use filesystem::{
    FileOperation, FileOperationResult, FilesystemConfig, FilesystemHandler, ModificationRecord,
};
