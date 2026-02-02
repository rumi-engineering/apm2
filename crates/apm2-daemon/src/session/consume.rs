// AGENT-AUTHORED (TCK-00211)
//! CONSUME mode session handler with context firewall integration.
//!
//! This module provides session handling for CONSUME mode sessions, which are
//! constrained to read only files explicitly listed in the context pack
//! manifest.
//!
//! # RFC-0015: FAC Context Firewall Integration
//!
//! Per RFC-0015 (File Access Control), CONSUME mode sessions operate under
//! strict allowlist enforcement:
//!
//! 1. Each session is initialized with a [`ContextPackManifest`] from the RCP
//! 2. All file read requests are validated against the manifest
//! 3. Reads outside the allowlist trigger `CONTEXT_MISS` termination
//! 4. A [`ContextRefinementRequest`] is emitted to the coordinator
//!
//! # `CONTEXT_MISS` Flow
//!
//! ```text
//! FileRead request
//!       │
//!       ▼
//! ContextAwareValidator::validate_read()
//!       │
//!       ├── Ok(Allowed) ──► proceed with read
//!       │
//!       └── Err(NotInAllowlist) ──┐
//!                                 │
//!                                 ▼
//!                    ┌────────────────────────┐
//!                    │ Emit SessionTerminated │
//!                    │ (rationale=CONTEXT_MISS)│
//!                    └────────────────────────┘
//!                                 │
//!                                 ▼
//!                    ┌────────────────────────┐
//!                    │ Emit ContextRefinement │
//!                    │     Request            │
//!                    └────────────────────────┘
//!                                 │
//!                                 ▼
//!                    Coordinator reissues with
//!                    refined pack
//! ```
//!
//! # Security Model
//!
//! - **Default-deny**: All reads are denied unless explicitly allowed
//! - **Allowlist enforcement**: Only files in the manifest can be read
//! - **Content hash verification**: Optional integrity verification
//! - **Audit trail**: All denials emit events for traceability

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::episode::decision::SessionTerminationInfo;
use apm2_core::context::firewall::{ContextAwareValidator, DefaultContextFirewall, FirewallMode};
use apm2_core::context::{ContextPackManifest, ToolClass};
use apm2_core::coordination::{ContextRefinementRequest, CoordinationEvent};
use apm2_core::tool::{ToolRequest, tool_request};

/// Maximum number of refinement attempts before giving up.
pub const MAX_REFINEMENT_ATTEMPTS: u32 = 10;

/// Session termination rationale code for context miss.
pub const TERMINATION_RATIONALE_CONTEXT_MISS: &str = "CONTEXT_MISS";

/// Exit classification for context miss termination.
pub const EXIT_CLASSIFICATION_CONTEXT_MISS: &str = "FAILURE";

// =============================================================================
// ConsumeSessionError
// =============================================================================

/// Errors that can occur during CONSUME mode session handling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConsumeSessionError {
    /// Context miss: file read not in manifest allowlist.
    #[error("context miss: path '{path}' not in manifest '{manifest_id}'")]
    ContextMiss {
        /// The path that was attempted.
        path: String,
        /// The manifest ID.
        manifest_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Maximum refinement attempts exceeded.
    #[error("maximum refinement attempts ({max}) exceeded for work '{work_id}'")]
    MaxRefinementsExceeded {
        /// The work item ID.
        work_id: String,
        /// Maximum allowed attempts.
        max: u32,
    },

    /// Session not in CONSUME mode.
    #[error("session is not in CONSUME mode")]
    NotConsumeMode,

    /// Invalid manifest.
    #[error("invalid manifest: {message}")]
    InvalidManifest {
        /// Error description.
        message: String,
    },

    /// Tool class not allowed in manifest.
    ///
    /// Per TCK-00254, tool requests are validated against the manifest's
    /// `tool_allowlist`. This error is returned when the requested tool class
    /// is not in the allowlist (fail-closed semantics).
    #[error("tool class '{tool_class}' not in manifest allowlist for '{manifest_id}'")]
    ToolNotAllowed {
        /// The tool class that was denied.
        tool_class: String,
        /// The manifest ID.
        manifest_id: String,
    },

    /// Write path not allowed in manifest.
    ///
    /// Per TCK-00254, write operations are validated against the manifest's
    /// `write_allowlist`. This error is returned when the write path is not
    /// in the allowlist (fail-closed semantics).
    #[error("write path '{path}' not in manifest allowlist for '{manifest_id}'")]
    WritePathNotAllowed {
        /// The path that was denied.
        path: String,
        /// The manifest ID.
        manifest_id: String,
    },

    /// Shell command not allowed in manifest.
    ///
    /// Per TCK-00254, shell execution requests are validated against the
    /// manifest's `shell_allowlist`. This error is returned when the command
    /// does not match any allowed pattern (fail-closed semantics).
    #[error("shell command '{command}' not in manifest allowlist for '{manifest_id}'")]
    ShellCommandNotAllowed {
        /// The command that was denied.
        command: String,
        /// The manifest ID.
        manifest_id: String,
    },
}

// =============================================================================
// ConsumeSessionContext
// =============================================================================

/// Context for a CONSUME mode session.
///
/// This struct holds the state needed for context firewall enforcement,
/// including the manifest, firewall mode, and refinement tracking.
#[derive(Debug, Clone)]
pub struct ConsumeSessionContext {
    /// Session ID.
    pub session_id: String,

    /// Coordination ID (if bound to a coordination).
    pub coordination_id: Option<String>,

    /// Work item ID being processed.
    pub work_id: String,

    /// The context pack manifest defining allowed files.
    manifest: Arc<ContextPackManifest>,

    /// Firewall enforcement mode.
    mode: FirewallMode,

    /// Number of refinement attempts so far.
    refinement_count: u32,
}

impl ConsumeSessionContext {
    /// Creates a new CONSUME session context.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID
    /// * `coordination_id` - The coordination ID (if applicable)
    /// * `work_id` - The work item ID
    /// * `manifest` - The context pack manifest
    /// * `mode` - The firewall enforcement mode
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        coordination_id: Option<String>,
        work_id: impl Into<String>,
        manifest: ContextPackManifest,
        mode: FirewallMode,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            coordination_id,
            work_id: work_id.into(),
            manifest: Arc::new(manifest),
            mode,
            refinement_count: 0,
        }
    }

    /// Creates a context with a specified refinement count.
    ///
    /// Used when retrying after a context refinement.
    #[must_use]
    pub const fn with_refinement_count(mut self, count: u32) -> Self {
        self.refinement_count = count;
        self
    }

    /// Returns the manifest.
    #[must_use]
    pub fn manifest(&self) -> &ContextPackManifest {
        &self.manifest
    }

    /// Returns the manifest ID.
    #[must_use]
    pub fn manifest_id(&self) -> &str {
        &self.manifest.manifest_id
    }

    /// Returns the firewall mode.
    #[must_use]
    pub const fn mode(&self) -> FirewallMode {
        self.mode
    }

    /// Returns the refinement count.
    #[must_use]
    pub const fn refinement_count(&self) -> u32 {
        self.refinement_count
    }

    /// Increments the refinement count.
    pub const fn increment_refinement_count(&mut self) {
        self.refinement_count += 1;
    }

    /// Checks if refinement attempts are exhausted.
    #[must_use]
    pub const fn refinements_exhausted(&self) -> bool {
        self.refinement_count >= MAX_REFINEMENT_ATTEMPTS
    }
}

// =============================================================================
// ConsumeSessionHandler
// =============================================================================

/// Handler for CONSUME mode sessions with context firewall integration.
///
/// This handler validates all file read requests against the manifest allowlist
/// and handles `CONTEXT_MISS` termination with refinement request emission.
#[derive(Debug, Clone)]
pub struct ConsumeSessionHandler {
    /// The session context.
    context: ConsumeSessionContext,
}

impl ConsumeSessionHandler {
    /// Creates a new CONSUME session handler.
    ///
    /// # Arguments
    ///
    /// * `context` - The session context with manifest and configuration
    #[must_use]
    pub const fn new(context: ConsumeSessionContext) -> Self {
        Self { context }
    }

    /// Returns the session context.
    #[must_use]
    pub const fn context(&self) -> &ConsumeSessionContext {
        &self.context
    }

    /// Validates a file read request against the manifest.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to validate
    /// * `content_hash` - Optional content hash for integrity verification
    ///
    /// # Returns
    ///
    /// `Ok(())` if the read is allowed, or an error if the path is not in
    /// the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ConsumeSessionError::ContextMiss`] if the path is not in
    /// the manifest allowlist.
    pub fn validate_read(
        &self,
        path: &str,
        content_hash: Option<&[u8; 32]>,
    ) -> Result<(), ConsumeSessionError> {
        // Create firewall for this validation (avoids lifetime issues with stored
        // reference)
        let firewall = DefaultContextFirewall::new(&self.context.manifest, self.context.mode);
        match firewall.validate_read(path, content_hash) {
            Ok(_) => Ok(()),
            Err(e) => {
                let reason = e.to_string();
                // SECURITY: Truncate path BEFORE creating the error to prevent
                // local DoS via oversized paths in error variants. The truncation
                // is applied at the earliest entry point before any String
                // allocation of untrusted input.
                Err(ConsumeSessionError::ContextMiss {
                    path: ContextRefinementRequest::truncate_path_str(path),
                    manifest_id: self.context.manifest_id().to_string(),
                    reason,
                })
            },
        }
    }

    /// Creates a context refinement request for a context miss.
    ///
    /// This should be called when a `CONTEXT_MISS` error occurs to generate
    /// the event that triggers context refinement.
    ///
    /// # Arguments
    ///
    /// * `missed_path` - The path that was not in the manifest
    ///
    /// # Returns
    ///
    /// A `ContextRefinementRequest` event payload.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn create_refinement_request(&self, missed_path: &str) -> ContextRefinementRequest {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        ContextRefinementRequest::from_context_miss(
            &self.context.session_id,
            self.context.coordination_id.clone(),
            &self.context.work_id,
            self.context.manifest_id(),
            missed_path,
            self.context.refinement_count,
            timestamp,
        )
    }

    /// Creates a coordination event for context refinement request.
    #[must_use]
    pub fn create_refinement_event(&self, missed_path: &str) -> CoordinationEvent {
        CoordinationEvent::ContextRefinementRequest(self.create_refinement_request(missed_path))
    }

    /// Handles a `CONTEXT_MISS` error by creating termination and refinement
    /// events.
    ///
    /// # Arguments
    ///
    /// * `error` - The context miss error
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - Session termination info (rationale code, exit classification)
    /// - Context refinement request event
    ///
    /// # Errors
    ///
    /// Returns [`ConsumeSessionError::MaxRefinementsExceeded`] if the maximum
    /// refinement attempts have been reached.
    pub fn handle_context_miss(
        &self,
        error: &ConsumeSessionError,
    ) -> Result<(SessionTerminationInfo, CoordinationEvent), ConsumeSessionError> {
        let ConsumeSessionError::ContextMiss { path, .. } = error else {
            return Err(error.clone());
        };

        // Check if refinements are exhausted
        if self.context.refinements_exhausted() {
            return Err(ConsumeSessionError::MaxRefinementsExceeded {
                work_id: self.context.work_id.clone(),
                max: MAX_REFINEMENT_ATTEMPTS,
            });
        }

        let termination_info = SessionTerminationInfo::new(
            &self.context.session_id,
            TERMINATION_RATIONALE_CONTEXT_MISS,
            EXIT_CLASSIFICATION_CONTEXT_MISS,
        );

        let refinement_event = self.create_refinement_event(path);

        Ok((termination_info, refinement_event))
    }

    /// Terminates the session with a specific classification and rationale.
    ///
    /// # Arguments
    ///
    /// * `classification` - Exit classification (SUCCESS, FAILURE)
    /// * `rationale` - Rationale code
    ///
    /// # Returns
    ///
    /// Session termination info.
    #[must_use]
    pub fn terminate_session(
        &self,
        classification: impl Into<String>,
        rationale: impl Into<String>,
    ) -> SessionTerminationInfo {
        SessionTerminationInfo::new(&self.context.session_id, rationale, classification)
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Validates a tool request against a manifest for CONSUME mode.
///
/// This is a convenience function that extracts the path from a `FileRead`
/// request and validates it against the manifest.
///
/// # Arguments
///
/// * `request` - The tool request
/// * `manifest` - The context pack manifest
/// * `mode` - The firewall enforcement mode
///
/// # Returns
///
/// `Ok(())` if the request is allowed or not a `FileRead`.
/// `Err(ConsumeSessionError::ContextMiss)` if the path is not in the manifest.
/// `Err(ConsumeSessionError::NotConsumeMode)` if not in consumption mode.
/// `Err(ConsumeSessionError::ToolNotAllowed)` if the tool class is not in the
/// manifest's `tool_allowlist`.
pub fn validate_tool_request(
    request: &ToolRequest,
    manifest: &ContextPackManifest,
    mode: FirewallMode,
) -> Result<(), ConsumeSessionError> {
    // Only validate FileRead in consumption mode
    if !request.consumption_mode {
        return Err(ConsumeSessionError::NotConsumeMode);
    }

    let Some(tool) = &request.tool else {
        return Ok(()); // No tool, nothing to validate
    };

    // TCK-00254: Check tool allowlist (fail-closed semantics)
    // Map the tool variant to a ToolClass and check against the allowlist.
    let tool_class = tool_to_tool_class(tool);
    if !manifest.tool_allowlist.contains(&tool_class) {
        return Err(ConsumeSessionError::ToolNotAllowed {
            tool_class: tool_class.to_string(),
            manifest_id: manifest.manifest_id.clone(),
        });
    }

    // Validate based on tool type
    match tool {
        tool_request::Tool::FileRead(read) => {
            // Validate path against manifest entries
            let firewall = DefaultContextFirewall::new(manifest, mode);
            match firewall.validate_read(&read.path, None) {
                Ok(_) => Ok(()),
                Err(e) => {
                    // SECURITY: Truncate path BEFORE creating the error to prevent
                    // local DoS via oversized paths in error variants.
                    Err(ConsumeSessionError::ContextMiss {
                        path: ContextRefinementRequest::truncate_path_str(&read.path),
                        manifest_id: manifest.manifest_id.clone(),
                        reason: e.to_string(),
                    })
                },
            }
        },
        tool_request::Tool::FileWrite(write) => {
            // TCK-00254: Validate write path against write_allowlist (fail-closed)
            let path = std::path::Path::new(&write.path);
            if !manifest.is_write_path_allowed(path) {
                return Err(ConsumeSessionError::WritePathNotAllowed {
                    path: ContextRefinementRequest::truncate_path_str(&write.path),
                    manifest_id: manifest.manifest_id.clone(),
                });
            }
            Ok(())
        },
        tool_request::Tool::FileEdit(edit) => {
            // TCK-00254: Validate edit path against write_allowlist (fail-closed)
            let path = std::path::Path::new(&edit.path);
            if !manifest.is_write_path_allowed(path) {
                return Err(ConsumeSessionError::WritePathNotAllowed {
                    path: ContextRefinementRequest::truncate_path_str(&edit.path),
                    manifest_id: manifest.manifest_id.clone(),
                });
            }
            Ok(())
        },
        tool_request::Tool::ShellExec(exec) => {
            // TCK-00254: Validate shell command against shell_allowlist (fail-closed)
            if !manifest.is_shell_command_allowed(&exec.command) {
                // SECURITY: Truncate command to prevent oversized error variants
                let truncated_command = if exec.command.len() > 256 {
                    format!("{}...", &exec.command[..256])
                } else {
                    exec.command.clone()
                };
                return Err(ConsumeSessionError::ShellCommandNotAllowed {
                    command: truncated_command,
                    manifest_id: manifest.manifest_id.clone(),
                });
            }
            Ok(())
        },
        // Other tool types don't require additional path/command validation
        _ => Ok(()),
    }
}

/// Maps a `tool_request::Tool` variant to its corresponding `ToolClass`.
///
/// This helper function enables tool allowlist validation in CONSUME mode
/// per TCK-00254.
const fn tool_to_tool_class(tool: &tool_request::Tool) -> ToolClass {
    match tool {
        tool_request::Tool::FileRead(_) => ToolClass::Read,
        tool_request::Tool::FileWrite(_) | tool_request::Tool::FileEdit(_) => ToolClass::Write,
        tool_request::Tool::ShellExec(_) => ToolClass::Execute,
        tool_request::Tool::GitOp(_) => ToolClass::Git,
        tool_request::Tool::Inference(_) => ToolClass::Inference,
        tool_request::Tool::ArtifactPublish(_) | tool_request::Tool::ArtifactFetch(_) => {
            ToolClass::Artifact
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
/// Unit tests for the CONSUME mode session handler.
mod tests {
    use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

    use super::*;

    fn create_test_manifest() -> ContextPackManifest {
        ContextPackManifestBuilder::new("test-manifest-001", "test-profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
                    .stable_id("src-main")
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .add_entry(
                ManifestEntryBuilder::new("/project/README.md", [0xAB; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            // TCK-00254: Include allowlists for test compatibility
            .tool_allowlist(vec![ToolClass::Read, ToolClass::Execute])
            // Allow "ls" command for shell execution tests
            .shell_allowlist(vec!["ls".to_string()])
            .build()
    }

    fn create_test_context() -> ConsumeSessionContext {
        ConsumeSessionContext::new(
            "session-001",
            Some("coord-001".to_string()),
            "work-001",
            create_test_manifest(),
            FirewallMode::HardFail,
        )
    }

    // =========================================================================
    // ConsumeSessionContext Tests
    // =========================================================================

    #[test]
    fn test_context_creation() {
        let context = create_test_context();

        assert_eq!(context.session_id, "session-001");
        assert_eq!(context.coordination_id, Some("coord-001".to_string()));
        assert_eq!(context.work_id, "work-001");
        assert_eq!(context.manifest_id(), "test-manifest-001");
        assert_eq!(context.mode(), FirewallMode::HardFail);
        assert_eq!(context.refinement_count(), 0);
    }

    #[test]
    fn test_context_with_refinement_count() {
        let context = create_test_context().with_refinement_count(5);

        assert_eq!(context.refinement_count(), 5);
    }

    #[test]
    fn test_refinements_exhausted() {
        let mut context = create_test_context();

        assert!(!context.refinements_exhausted());

        // Increment to max
        for _ in 0..MAX_REFINEMENT_ATTEMPTS {
            context.increment_refinement_count();
        }

        assert!(context.refinements_exhausted());
    }

    // =========================================================================
    // ConsumeSessionHandler Tests
    // =========================================================================

    #[test]
    fn test_handler_validate_allowed_path() {
        let context = create_test_context();
        let handler = ConsumeSessionHandler::new(context);

        // Allowed path
        let result = handler.validate_read("/project/src/main.rs", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handler_validate_denied_path() {
        let context = create_test_context();
        let handler = ConsumeSessionHandler::new(context);

        // Denied path (not in manifest)
        let result = handler.validate_read("/etc/passwd", None);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ConsumeSessionError::ContextMiss { path, manifest_id, .. }
            if path == "/etc/passwd" && manifest_id == "test-manifest-001"
        ));
    }

    #[test]
    fn test_handler_create_refinement_request() {
        let context = create_test_context();
        let handler = ConsumeSessionHandler::new(context);

        let request = handler.create_refinement_request("/etc/passwd");

        assert_eq!(request.session_id, "session-001");
        assert_eq!(request.coordination_id, Some("coord-001".to_string()));
        assert_eq!(request.work_id, "work-001");
        assert_eq!(request.manifest_id, "test-manifest-001");
        assert_eq!(request.missed_path, "/etc/passwd");
        assert_eq!(request.rationale_code, "CONTEXT_MISS");
        assert_eq!(request.refinement_count, 0);
    }

    #[test]
    fn test_handler_handle_context_miss() {
        let context = create_test_context();
        let handler = ConsumeSessionHandler::new(context);

        let error = ConsumeSessionError::ContextMiss {
            path: "/etc/passwd".to_string(),
            manifest_id: "test-manifest-001".to_string(),
            reason: "Not in allowlist".to_string(),
        };

        let result = handler.handle_context_miss(&error);
        assert!(result.is_ok());

        let (term_info, event) = result.unwrap();
        assert_eq!(term_info.session_id, "session-001");
        assert_eq!(term_info.rationale_code, TERMINATION_RATIONALE_CONTEXT_MISS);
        assert_eq!(
            term_info.exit_classification,
            EXIT_CLASSIFICATION_CONTEXT_MISS
        );

        assert!(matches!(
            event,
            CoordinationEvent::ContextRefinementRequest(req)
            if req.missed_path == "/etc/passwd"
        ));
    }

    #[test]
    fn test_handler_handle_context_miss_exhausted() {
        let context = create_test_context().with_refinement_count(MAX_REFINEMENT_ATTEMPTS);
        let handler = ConsumeSessionHandler::new(context);

        let error = ConsumeSessionError::ContextMiss {
            path: "/etc/passwd".to_string(),
            manifest_id: "test-manifest-001".to_string(),
            reason: "Not in allowlist".to_string(),
        };

        let result = handler.handle_context_miss(&error);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ConsumeSessionError::MaxRefinementsExceeded { work_id, max }
            if work_id == "work-001" && max == MAX_REFINEMENT_ATTEMPTS
        ));
    }

    // =========================================================================
    // validate_tool_request Tests
    // =========================================================================

    #[test]
    fn test_validate_tool_request_allowed() {
        let manifest = create_test_manifest();

        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req-001".to_string(),
            session_token: "token".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(apm2_core::tool::FileRead {
                path: "/project/src/main.rs".to_string(),
                offset: 0,
                limit: 0,
            })),
        };

        let result = validate_tool_request(&request, &manifest, FirewallMode::HardFail);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tool_request_denied() {
        let manifest = create_test_manifest();

        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req-001".to_string(),
            session_token: "token".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(apm2_core::tool::FileRead {
                path: "/etc/passwd".to_string(),
                offset: 0,
                limit: 0,
            })),
        };

        let result = validate_tool_request(&request, &manifest, FirewallMode::HardFail);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ConsumeSessionError::ContextMiss { .. }));
    }

    #[test]
    fn test_validate_tool_request_not_consume_mode() {
        let manifest = create_test_manifest();

        let request = ToolRequest {
            consumption_mode: false, // Not in consume mode
            request_id: "req-001".to_string(),
            session_token: "token".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(apm2_core::tool::FileRead {
                path: "/etc/passwd".to_string(),
                offset: 0,
                limit: 0,
            })),
        };

        let result = validate_tool_request(&request, &manifest, FirewallMode::HardFail);
        assert!(matches!(result, Err(ConsumeSessionError::NotConsumeMode)));
    }

    #[test]
    fn test_validate_tool_request_non_file_read() {
        let manifest = create_test_manifest();

        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req-001".to_string(),
            session_token: "token".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ShellExec(apm2_core::tool::ShellExec {
                command: "ls".to_string(),
                cwd: String::new(),
                timeout_ms: 0,
                env: Vec::new(),
                network_access: false,
            })),
        };

        // Non-FileRead requests pass through path validation (tool allowlist passes)
        let result = validate_tool_request(&request, &manifest, FirewallMode::HardFail);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tool_request_tool_not_allowed() {
        // Create manifest with only Read allowed (no Write)
        let manifest = ContextPackManifestBuilder::new("test-manifest-002", "test-profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .tool_allowlist(vec![ToolClass::Read]) // Only Read allowed
            .build();

        // Try to write - should be denied
        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req-001".to_string(),
            session_token: "token".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileWrite(apm2_core::tool::FileWrite {
                path: "/project/src/main.rs".to_string(),
                content: vec![],
                create_only: false,
                append: false,
            })),
        };

        let result = validate_tool_request(&request, &manifest, FirewallMode::HardFail);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(
            matches!(err, ConsumeSessionError::ToolNotAllowed { tool_class, manifest_id }
            if tool_class == "Write" && manifest_id == "test-manifest-002")
        );
    }

    #[test]
    fn test_validate_tool_request_empty_allowlist_denies_all() {
        // Create manifest with empty tool_allowlist (fail-closed)
        let manifest = ContextPackManifestBuilder::new("test-manifest-003", "test-profile-001")
            .add_entry(
                ManifestEntryBuilder::new("/project/src/main.rs", [0x42; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            // No tool_allowlist means empty, which denies all tools
            .build();

        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req-001".to_string(),
            session_token: "token".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(apm2_core::tool::FileRead {
                path: "/project/src/main.rs".to_string(),
                offset: 0,
                limit: 0,
            })),
        };

        // Even FileRead should be denied with empty allowlist
        let result = validate_tool_request(&request, &manifest, FirewallMode::HardFail);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, ConsumeSessionError::ToolNotAllowed { .. }));
    }

    // =========================================================================
    // SessionTerminationInfo Tests
    // =========================================================================

    #[test]
    fn test_session_termination_info_context_miss() {
        let info = SessionTerminationInfo::new(
            "session-001",
            TERMINATION_RATIONALE_CONTEXT_MISS,
            EXIT_CLASSIFICATION_CONTEXT_MISS,
        );

        assert_eq!(info.session_id, "session-001");
        assert_eq!(info.rationale_code, TERMINATION_RATIONALE_CONTEXT_MISS);
        assert_eq!(info.exit_classification, EXIT_CLASSIFICATION_CONTEXT_MISS);
    }
}
