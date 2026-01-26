//! Ticket Emitter module for decomposing RFCs into atomic implementation
//! tickets.
//!
//! This module provides the foundation for generating atomic, implementable
//! tickets from RFC ticket decomposition sections. The ticket emitter ensures
//! all generated tickets have stable IDs, validated file paths against CCP, and
//! verification commands derived from acceptance criteria.
//!
//! # Overview
//!
//! The ticket emitter takes two primary inputs:
//! - An RFC's `06_ticket_decomposition.yaml` section
//! - The CCP index for file path validation
//!
//! It produces individual ticket YAML files following the ticket schema:
//! - `schema_version`: Schema version for compatibility
//! - `template_version`: Template version for consistency
//! - `ticket`: Core ticket metadata (id, title, status, `rfc_id`,
//!   `requirement_ids`)
//! - `implementation`: Summary, files, steps
//! - `acceptance_criteria`: Verification criteria
//! - `test_requirements`: Test definitions with verification commands
//!
//! # Invariants
//!
//! - [INV-EMITTER-001] Ticket IDs are stable across re-runs (idempotent)
//! - [INV-EMITTER-002] All file paths are validated against CCP or filesystem
//! - [INV-EMITTER-003] Every emitted ticket has verification commands
//! - [INV-EMITTER-004] Generated tickets use deterministic YAML output
//!
//! # Contracts
//!
//! - [CTR-EMITTER-001] `emit_tickets` requires valid RFC decomposition
//! - [CTR-EMITTER-002] Output directory is created atomically
//! - [CTR-EMITTER-003] All writes use atomic file operations
//! - [CTR-EMITTER-004] Path validation rejects parent directory traversal
//!
//! # Security
//!
//! - [SEC-EMITTER-001] File reads are bounded to prevent denial-of-service
//! - [SEC-EMITTER-002] Path traversal is prevented by validation
//! - [SEC-EMITTER-003] Only files within repo root are processed
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//!
//! use apm2_core::ticket_emitter::{TicketEmitOptions, emit_tickets};
//!
//! let result = emit_tickets(
//!     Path::new("/repo/root"),
//!     "RFC-0010",
//!     &TicketEmitOptions::default(),
//! )
//! .unwrap();
//!
//! println!("Emitted {} tickets", result.tickets.len());
//! for ticket in &result.tickets {
//!     println!("  {}: {}", ticket.id, ticket.title);
//! }
//! ```

pub mod emitter;
pub mod validation;

// Re-export primary API
pub use emitter::{
    EmittedTicket, TicketEmitError, TicketEmitOptions, TicketEmitResult, emit_tickets,
};
pub use validation::{TicketValidationError, TicketValidationResult, validate_ticket_paths};
