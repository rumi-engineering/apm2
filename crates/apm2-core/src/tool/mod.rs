//! Tool request/response protocol for agent-kernel communication.
//!
//! This module provides the protocol for agents to request tool execution
//! from the kernel. All tool requests are validated before being passed
//! to the policy engine for authorization.
//!
//! # Security Model
//!
//! The tool protocol implements a **default-deny, least-privilege,
//! fail-closed** security model:
//!
//! - **Default-deny**: All requests are denied unless explicitly allowed by
//!   policy
//! - **Least-privilege**: Agents can only request tools they need for their
//!   task
//! - **Fail-closed**: Any error in validation or policy evaluation results in
//!   denial
//!
//! # Request Flow
//!
//! 1. Agent sends [`ToolRequest`] to kernel
//! 2. Request is validated (malformed requests are rejected)
//! 3. Policy engine evaluates the request against active policy
//! 4. If allowed, kernel executes the tool and returns [`ToolResponse`]
//! 5. Results are logged to the ledger for audit
//!
//! # Example
//!
//! ```rust
//! use apm2_core::tool::{FileRead, ToolRequest, tool_request};
//! use prost::Message;
//!
//! // Create a file read request
//! let request = ToolRequest {
//!     request_id: "req-001".to_string(),
//!     session_token: "session-abc".to_string(),
//!     dedupe_key: String::new(),
//!     tool: Some(tool_request::Tool::FileRead(FileRead {
//!         path: "/path/to/file.txt".to_string(),
//!         offset: 0,
//!         limit: 0, // Read entire file
//!     })),
//! };
//!
//! // Encode to bytes for transmission
//! let bytes = request.encode_to_vec();
//!
//! // Decode on the receiving end
//! let decoded = ToolRequest::decode(bytes.as_slice()).unwrap();
//! assert_eq!(decoded.request_id, "req-001");
//! ```

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::match_single_binding,
    clippy::redundant_closure,
    clippy::struct_field_names,
    missing_docs
)]
mod generated {
    include!("apm2.tool.v1.rs");
}

pub mod fs;
pub mod inference;
pub mod shell;
mod validation;

#[cfg(test)]
mod tests;

pub use generated::*;
pub use validation::{ValidationResult, Validator};
