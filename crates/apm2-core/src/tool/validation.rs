//! Request validation for tool protocol messages.
//!
//! This module provides validation logic for [`ToolRequest`] messages before
//! they are passed to the policy engine. Validation ensures that requests
//! are well-formed and can be safely evaluated.
//!
//! # Security Considerations
//!
//! Validation is a **defense-in-depth** layer that catches malformed input
//! before it reaches security-critical code paths. It is NOT a replacement
//! for policy evaluation, which determines whether a request should be allowed.
//!
//! # Validation Rules
//!
//! ## Common Rules (all requests)
//! - `request_id` must be non-empty and ≤256 characters
//! - `session_token` must be non-empty and ≤256 characters
//! - `dedupe_key` must be ≤256 characters (can be empty)
//! - Exactly one tool type must be specified
//!
//! ## `FileRead`
//! - `path` must be non-empty and ≤4096 characters
//! - `path` must not contain null bytes
//! - `limit` must be ≤1GB (prevents memory exhaustion)
//!
//! ## `FileWrite`
//! - `path` must be non-empty and ≤4096 characters
//! - `path` must not contain null bytes
//! - `content` must be ≤100MB
//! - `create_only` and `append` cannot both be true
//!
//! ## `FileEdit`
//! - `path` must be non-empty and ≤4096 characters
//! - `path` must not contain null bytes
//! - `old_content` must be non-empty and ≤10MB
//! - `new_content` must be ≤10MB
//!
//! ## `ShellExec`
//! - `command` must be non-empty and ≤1MB
//! - `cwd` must be ≤4096 characters (can be empty)
//! - `timeout_ms` must be ≤1 hour (3,600,000 ms)
//! - Each env var must be ≤32KB and contain exactly one `=`
//!
//! ## `GitOperation`
//! - `operation` must be a known operation type
//! - Each arg must be ≤32KB
//! - `cwd` must be ≤4096 characters (can be empty)
//!
//! ## `InferenceCall`
//! - `provider` must be non-empty and ≤256 characters
//! - `model` must be non-empty and ≤256 characters
//! - `prompt_hash` must be exactly 32 bytes (BLAKE3 hash)
//! - `max_tokens` must be ≤1M tokens
//!
//! ## `ArtifactPublish`
//! - `artifact_id` must be non-empty and ≤256 characters
//! - `content_hash` must be exactly 32 bytes (BLAKE3 hash)
//! - `category` must be non-empty and ≤256 characters
//! - Each metadata entry must be ≤32KB and contain exactly one `=`

use super::{
    ArtifactFetch, ArtifactPublish, FileEdit, FileRead, FileWrite, GitOperation, InferenceCall,
    ShellExec, ToolRequest, ValidationError, tool_request,
};

/// Maximum length for `request_id`, `session_token`, and similar identifiers.
const MAX_ID_LEN: usize = 256;

/// Maximum length for file paths.
const MAX_PATH_LEN: usize = 4096;

/// Maximum file read limit (1GB).
const MAX_READ_LIMIT: u64 = 1024 * 1024 * 1024;

/// Maximum file write size (100MB).
const MAX_WRITE_SIZE: usize = 100 * 1024 * 1024;

/// Maximum edit content size (10MB).
const MAX_EDIT_SIZE: usize = 10 * 1024 * 1024;

/// Maximum command length (1MB).
const MAX_COMMAND_LEN: usize = 1024 * 1024;

/// Maximum timeout (1 hour in milliseconds).
const MAX_TIMEOUT_MS: u64 = 3_600_000;

/// Maximum single argument/env var size (32KB).
const MAX_ARG_LEN: usize = 32 * 1024;

/// Maximum token count for inference (1M tokens).
const MAX_TOKENS: u64 = 1_000_000;

/// Expected hash size (BLAKE3 = 32 bytes).
const HASH_SIZE: usize = 32;

/// Maximum number of items in repeated fields (prevents denial-of-service via
/// unbounded lists).
const MAX_REPEATED_ITEMS: usize = 1000;

/// Known git operations.
const KNOWN_GIT_OPS: &[&str] = &[
    "CLONE", "FETCH", "PULL", "DIFF", "COMMIT", "PUSH", "STATUS", "LOG", "BRANCH", "CHECKOUT",
    "MERGE", "REBASE", "ADD", "RESET", "STASH", "TAG", "REMOTE", "SHOW",
];

/// Result of validation: either Ok or a list of validation errors.
pub type ValidationResult = Result<(), Vec<ValidationError>>;

/// Validator for tool requests.
///
/// The validator checks that requests are well-formed before they are
/// passed to the policy engine. This is a defense-in-depth measure that
/// catches malformed input early.
pub trait Validator {
    /// Validate the request, returning Ok if valid or a list of errors.
    ///
    /// # Errors
    ///
    /// Returns a list of [`ValidationError`] if any validation rules are
    /// violated.
    fn validate(&self) -> ValidationResult;
}

impl Validator for ToolRequest {
    fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();

        // Validate common fields
        validate_id(&self.request_id, "request_id", &mut errors);
        validate_id(&self.session_token, "session_token", &mut errors);
        validate_optional_id(&self.dedupe_key, "dedupe_key", &mut errors);

        // Validate tool-specific fields
        match &self.tool {
            Some(tool_request::Tool::FileRead(req)) => validate_file_read(req, &mut errors),
            Some(tool_request::Tool::FileWrite(req)) => validate_file_write(req, &mut errors),
            Some(tool_request::Tool::FileEdit(req)) => validate_file_edit(req, &mut errors),
            Some(tool_request::Tool::ShellExec(req)) => validate_shell_exec(req, &mut errors),
            Some(tool_request::Tool::GitOp(req)) => validate_git_operation(req, &mut errors),
            Some(tool_request::Tool::Inference(req)) => validate_inference_call(req, &mut errors),
            Some(tool_request::Tool::ArtifactPublish(req)) => {
                validate_artifact_publish(req, &mut errors);
            },
            Some(tool_request::Tool::ArtifactFetch(req)) => {
                validate_artifact_fetch(req, &mut errors);
            },
            None => {
                errors.push(ValidationError {
                    field: "tool".to_string(),
                    rule: "required".to_string(),
                    message: "A tool type must be specified".to_string(),
                });
            },
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Validate a required identifier field.
fn validate_id(value: &str, field: &str, errors: &mut Vec<ValidationError>) {
    if value.is_empty() {
        errors.push(ValidationError {
            field: field.to_string(),
            rule: "required".to_string(),
            message: format!("{field} must be non-empty"),
        });
    } else if value.len() > MAX_ID_LEN {
        errors.push(ValidationError {
            field: field.to_string(),
            rule: "max_length".to_string(),
            message: format!("{field} must be at most {MAX_ID_LEN} characters"),
        });
    }
}

/// Validate an optional identifier field.
fn validate_optional_id(value: &str, field: &str, errors: &mut Vec<ValidationError>) {
    if value.len() > MAX_ID_LEN {
        errors.push(ValidationError {
            field: field.to_string(),
            rule: "max_length".to_string(),
            message: format!("{field} must be at most {MAX_ID_LEN} characters"),
        });
    }
}

/// Validate a file path.
///
/// Defense-in-depth: Rejects path traversal attempts (`..`) even though
/// the policy/execution layers must also enforce sandboxing.
fn validate_path(path: &str, field: &str, errors: &mut Vec<ValidationError>) {
    if path.is_empty() {
        errors.push(ValidationError {
            field: field.to_string(),
            rule: "required".to_string(),
            message: format!("{field} must be non-empty"),
        });
    } else if path.len() > MAX_PATH_LEN {
        errors.push(ValidationError {
            field: field.to_string(),
            rule: "max_length".to_string(),
            message: format!("{field} must be at most {MAX_PATH_LEN} characters"),
        });
    } else if path.contains('\0') {
        errors.push(ValidationError {
            field: field.to_string(),
            rule: "no_null_bytes".to_string(),
            message: format!("{field} must not contain null bytes"),
        });
    } else if contains_path_traversal(path) {
        errors.push(ValidationError {
            field: field.to_string(),
            rule: "no_path_traversal".to_string(),
            message: format!("{field} must not contain path traversal sequences (..)"),
        });
    }
}

/// Check if a path contains path traversal sequences.
///
/// This is a defense-in-depth measure. Returns true if the path:
/// - Contains `..` as a path component (e.g., `foo/../bar`, `../secret`)
/// - Starts with `..` (e.g., `../etc/passwd`)
fn contains_path_traversal(path: &str) -> bool {
    // Split by both forward and back slashes for cross-platform safety
    for component in path.split(['/', '\\']) {
        if component == ".." {
            return true;
        }
    }
    false
}

/// Validate a file read request.
fn validate_file_read(req: &FileRead, errors: &mut Vec<ValidationError>) {
    validate_path(&req.path, "file_read.path", errors);

    if req.limit > MAX_READ_LIMIT {
        errors.push(ValidationError {
            field: "file_read.limit".to_string(),
            rule: "max_value".to_string(),
            message: format!("limit must be at most {MAX_READ_LIMIT} bytes (1GB)"),
        });
    }
}

/// Validate a file write request.
fn validate_file_write(req: &FileWrite, errors: &mut Vec<ValidationError>) {
    validate_path(&req.path, "file_write.path", errors);

    if req.content.len() > MAX_WRITE_SIZE {
        errors.push(ValidationError {
            field: "file_write.content".to_string(),
            rule: "max_size".to_string(),
            message: format!("content must be at most {MAX_WRITE_SIZE} bytes (100MB)"),
        });
    }

    if req.create_only && req.append {
        errors.push(ValidationError {
            field: "file_write".to_string(),
            rule: "mutually_exclusive".to_string(),
            message: "create_only and append cannot both be true".to_string(),
        });
    }
}

/// Validate a file edit request.
fn validate_file_edit(req: &FileEdit, errors: &mut Vec<ValidationError>) {
    validate_path(&req.path, "file_edit.path", errors);

    if req.old_content.is_empty() {
        errors.push(ValidationError {
            field: "file_edit.old_content".to_string(),
            rule: "required".to_string(),
            message: "old_content must be non-empty".to_string(),
        });
    } else if req.old_content.len() > MAX_EDIT_SIZE {
        errors.push(ValidationError {
            field: "file_edit.old_content".to_string(),
            rule: "max_size".to_string(),
            message: format!("old_content must be at most {MAX_EDIT_SIZE} bytes (10MB)"),
        });
    }

    if req.new_content.len() > MAX_EDIT_SIZE {
        errors.push(ValidationError {
            field: "file_edit.new_content".to_string(),
            rule: "max_size".to_string(),
            message: format!("new_content must be at most {MAX_EDIT_SIZE} bytes (10MB)"),
        });
    }
}

/// Validate a shell exec request.
fn validate_shell_exec(req: &ShellExec, errors: &mut Vec<ValidationError>) {
    if req.command.is_empty() {
        errors.push(ValidationError {
            field: "shell_exec.command".to_string(),
            rule: "required".to_string(),
            message: "command must be non-empty".to_string(),
        });
    } else if req.command.len() > MAX_COMMAND_LEN {
        errors.push(ValidationError {
            field: "shell_exec.command".to_string(),
            rule: "max_length".to_string(),
            message: format!("command must be at most {MAX_COMMAND_LEN} bytes (1MB)"),
        });
    }

    if req.cwd.len() > MAX_PATH_LEN {
        errors.push(ValidationError {
            field: "shell_exec.cwd".to_string(),
            rule: "max_length".to_string(),
            message: format!("cwd must be at most {MAX_PATH_LEN} characters"),
        });
    }

    if req.timeout_ms > MAX_TIMEOUT_MS {
        errors.push(ValidationError {
            field: "shell_exec.timeout_ms".to_string(),
            rule: "max_value".to_string(),
            message: format!("timeout_ms must be at most {MAX_TIMEOUT_MS} (1 hour)"),
        });
    }

    // Prevent DoS via unbounded repeated fields
    if req.env.len() > MAX_REPEATED_ITEMS {
        errors.push(ValidationError {
            field: "shell_exec.env".to_string(),
            rule: "max_items".to_string(),
            message: format!("env must have at most {MAX_REPEATED_ITEMS} items"),
        });
    }

    for (i, env) in req.env.iter().enumerate() {
        if env.len() > MAX_ARG_LEN {
            errors.push(ValidationError {
                field: format!("shell_exec.env[{i}]"),
                rule: "max_length".to_string(),
                message: format!("env var must be at most {MAX_ARG_LEN} bytes"),
            });
        }
        if !env.contains('=') {
            errors.push(ValidationError {
                field: format!("shell_exec.env[{i}]"),
                rule: "format".to_string(),
                message: "env var must contain exactly one '=' (KEY=VALUE format)".to_string(),
            });
        }
    }
}

/// Validate a git operation request.
fn validate_git_operation(req: &GitOperation, errors: &mut Vec<ValidationError>) {
    if req.operation.is_empty() {
        errors.push(ValidationError {
            field: "git_op.operation".to_string(),
            rule: "required".to_string(),
            message: "operation must be non-empty".to_string(),
        });
    } else if !KNOWN_GIT_OPS.contains(&req.operation.as_str()) {
        errors.push(ValidationError {
            field: "git_op.operation".to_string(),
            rule: "known_operation".to_string(),
            message: format!("operation must be one of: {}", KNOWN_GIT_OPS.join(", ")),
        });
    }

    // Prevent DoS via unbounded repeated fields
    if req.args.len() > MAX_REPEATED_ITEMS {
        errors.push(ValidationError {
            field: "git_op.args".to_string(),
            rule: "max_items".to_string(),
            message: format!("args must have at most {MAX_REPEATED_ITEMS} items"),
        });
    }

    for (i, arg) in req.args.iter().enumerate() {
        if arg.len() > MAX_ARG_LEN {
            errors.push(ValidationError {
                field: format!("git_op.args[{i}]"),
                rule: "max_length".to_string(),
                message: format!("arg must be at most {MAX_ARG_LEN} bytes"),
            });
        }
    }

    if req.cwd.len() > MAX_PATH_LEN {
        errors.push(ValidationError {
            field: "git_op.cwd".to_string(),
            rule: "max_length".to_string(),
            message: format!("cwd must be at most {MAX_PATH_LEN} characters"),
        });
    }
}

/// Validate an inference call request.
fn validate_inference_call(req: &InferenceCall, errors: &mut Vec<ValidationError>) {
    validate_id(&req.provider, "inference.provider", errors);
    validate_id(&req.model, "inference.model", errors);

    if req.prompt_hash.len() != HASH_SIZE {
        errors.push(ValidationError {
            field: "inference.prompt_hash".to_string(),
            rule: "hash_size".to_string(),
            message: format!("prompt_hash must be exactly {HASH_SIZE} bytes"),
        });
    }

    if req.max_tokens > MAX_TOKENS {
        errors.push(ValidationError {
            field: "inference.max_tokens".to_string(),
            rule: "max_value".to_string(),
            message: format!("max_tokens must be at most {MAX_TOKENS}"),
        });
    }

    // system_prompt_hash is optional (can be empty), but if set must be 32 bytes
    if !req.system_prompt_hash.is_empty() && req.system_prompt_hash.len() != HASH_SIZE {
        errors.push(ValidationError {
            field: "inference.system_prompt_hash".to_string(),
            rule: "hash_size".to_string(),
            message: format!("system_prompt_hash must be exactly {HASH_SIZE} bytes if provided"),
        });
    }
}

/// Validate an artifact publish request.
fn validate_artifact_publish(req: &ArtifactPublish, errors: &mut Vec<ValidationError>) {
    validate_id(&req.artifact_id, "artifact_publish.artifact_id", errors);
    validate_id(&req.category, "artifact_publish.category", errors);

    if req.content_hash.len() != HASH_SIZE {
        errors.push(ValidationError {
            field: "artifact_publish.content_hash".to_string(),
            rule: "hash_size".to_string(),
            message: format!("content_hash must be exactly {HASH_SIZE} bytes"),
        });
    }

    // Prevent DoS via unbounded repeated fields
    if req.metadata.len() > MAX_REPEATED_ITEMS {
        errors.push(ValidationError {
            field: "artifact_publish.metadata".to_string(),
            rule: "max_items".to_string(),
            message: format!("metadata must have at most {MAX_REPEATED_ITEMS} items"),
        });
    }

    for (i, meta) in req.metadata.iter().enumerate() {
        if meta.len() > MAX_ARG_LEN {
            errors.push(ValidationError {
                field: format!("artifact_publish.metadata[{i}]"),
                rule: "max_length".to_string(),
                message: format!("metadata entry must be at most {MAX_ARG_LEN} bytes"),
            });
        }
        if !meta.contains('=') {
            errors.push(ValidationError {
                field: format!("artifact_publish.metadata[{i}]"),
                rule: "format".to_string(),
                message: "metadata entry must contain exactly one '=' (KEY=VALUE format)"
                    .to_string(),
            });
        }
    }
}

/// Validate an artifact fetch request.
fn validate_artifact_fetch(req: &ArtifactFetch, errors: &mut Vec<ValidationError>) {
    // stable_id is optional, but if present must be ≤1024 chars (DCP limit)
    if req.stable_id.len() > 1024 {
        errors.push(ValidationError {
            field: "artifact_fetch.stable_id".to_string(),
            rule: "max_length".to_string(),
            message: "stable_id must be at most 1024 characters".to_string(),
        });
    }

    // content_hash is optional, but if present must be 32 bytes (BLAKE3)
    if !req.content_hash.is_empty() && req.content_hash.len() != 32 {
        errors.push(ValidationError {
            field: "artifact_fetch.content_hash".to_string(),
            rule: "hash_length".to_string(),
            message: "content_hash must be exactly 32 bytes (BLAKE3)".to_string(),
        });
    }

    // expected_hash optional, same rules as content_hash
    if !req.expected_hash.is_empty() && req.expected_hash.len() != 32 {
        errors.push(ValidationError {
            field: "artifact_fetch.expected_hash".to_string(),
            rule: "hash_length".to_string(),
            message: "expected_hash must be exactly 32 bytes (BLAKE3)".to_string(),
        });
    }

    // At least one of stable_id or content_hash must be provided
    if req.stable_id.is_empty() && req.content_hash.is_empty() {
        errors.push(ValidationError {
            field: "artifact_fetch".to_string(),
            rule: "required".to_string(),
            message: "either stable_id or content_hash must be provided".to_string(),
        });
    }

    // max_bytes limit (100MB safety cap matching write size)
    if req.max_bytes > (MAX_WRITE_SIZE as u64) {
        errors.push(ValidationError {
            field: "artifact_fetch.max_bytes".to_string(),
            rule: "max_value".to_string(),
            message: format!("max_bytes must be at most {MAX_WRITE_SIZE}"),
        });
    }

    // format optional, max length check
    if req.format.len() > 32 {
        errors.push(ValidationError {
            field: "artifact_fetch.format".to_string(),
            rule: "max_length".to_string(),
            message: "format must be at most 32 characters".to_string(),
        });
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    fn make_valid_file_read() -> ToolRequest {
        ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(FileRead {
                path: "/path/to/file.txt".to_string(),
                offset: 0,
                limit: 0,
            })),
        }
    }

    #[test]
    fn test_valid_file_read() {
        let req = make_valid_file_read();
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_missing_request_id() {
        let mut req = make_valid_file_read();
        req.request_id = String::new();
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "request_id"));
    }

    #[test]
    fn test_missing_session_token() {
        let mut req = make_valid_file_read();
        req.session_token = String::new();
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "session_token"));
    }

    #[test]
    fn test_missing_tool() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: None,
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "tool"));
    }

    #[test]
    fn test_file_read_empty_path() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(FileRead {
                path: String::new(),
                offset: 0,
                limit: 0,
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "file_read.path"));
    }

    #[test]
    fn test_file_read_null_in_path() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(FileRead {
                path: "/path/to\0/file.txt".to_string(),
                offset: 0,
                limit: 0,
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.rule == "no_null_bytes"));
    }

    #[test]
    fn test_file_read_excessive_limit() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(FileRead {
                path: "/path/to/file.txt".to_string(),
                offset: 0,
                limit: MAX_READ_LIMIT + 1,
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "file_read.limit"));
    }

    #[test]
    fn test_file_write_valid() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileWrite(FileWrite {
                path: "/path/to/file.txt".to_string(),
                content: b"hello world".to_vec(),
                create_only: false,
                append: false,
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_file_write_conflicting_flags() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileWrite(FileWrite {
                path: "/path/to/file.txt".to_string(),
                content: b"hello world".to_vec(),
                create_only: true,
                append: true,
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.rule == "mutually_exclusive"));
    }

    #[test]
    fn test_shell_exec_valid() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ShellExec(ShellExec {
                command: "ls -la".to_string(),
                cwd: String::new(),
                timeout_ms: 30_000,
                network_access: false,
                env: vec!["PATH=/usr/bin".to_string()],
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_shell_exec_invalid_env() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ShellExec(ShellExec {
                command: "ls -la".to_string(),
                cwd: String::new(),
                timeout_ms: 30_000,
                network_access: false,
                env: vec!["INVALID_NO_EQUALS".to_string()],
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "shell_exec.env[0]"));
    }

    #[test]
    fn test_git_op_valid() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::GitOp(GitOperation {
                operation: "DIFF".to_string(),
                args: vec!["--cached".to_string()],
                cwd: String::new(),
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_git_op_unknown_operation() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::GitOp(GitOperation {
                operation: "UNKNOWN".to_string(),
                args: vec![],
                cwd: String::new(),
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.rule == "known_operation"));
    }

    #[test]
    fn test_inference_call_valid() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "anthropic".to_string(),
                model: "claude-3-opus".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 4096,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_inference_call_invalid_hash() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "anthropic".to_string(),
                model: "claude-3-opus".to_string(),
                prompt_hash: vec![0u8; 16], // Wrong size
                max_tokens: 4096,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "inference.prompt_hash"));
    }

    #[test]
    fn test_artifact_publish_valid() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactPublish(ArtifactPublish {
                artifact_id: "art-001".to_string(),
                content_hash: vec![0u8; 32],
                category: "test_results".to_string(),
                metadata: vec!["key=value".to_string()],
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_artifact_publish_invalid_metadata() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactPublish(ArtifactPublish {
                artifact_id: "art-001".to_string(),
                content_hash: vec![0u8; 32],
                category: "test_results".to_string(),
                metadata: vec!["no_equals_sign".to_string()],
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "artifact_publish.metadata[0]")
        );
    }

    #[test]
    fn test_file_edit_valid() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileEdit(FileEdit {
                path: "/path/to/file.txt".to_string(),
                old_content: "old text".to_string(),
                new_content: "new text".to_string(),
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_file_edit_empty_old_content() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileEdit(FileEdit {
                path: "/path/to/file.txt".to_string(),
                old_content: String::new(),
                new_content: "new text".to_string(),
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "file_edit.old_content"));
    }

    #[test]
    fn test_file_read_path_traversal() {
        // Test ".." segment
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(FileRead {
                path: "/path/to/../secret.txt".to_string(),
                offset: 0,
                limit: 0,
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.rule == "no_path_traversal"));

        // Test start with ".."
        let req2 = ToolRequest {
            consumption_mode: false,
            request_id: "req-002".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(FileRead {
                path: "../etc/passwd".to_string(),
                offset: 0,
                limit: 0,
            })),
        };
        let result2 = req2.validate();
        assert!(result2.is_err());
        let errors2 = result2.unwrap_err();
        assert!(errors2.iter().any(|e| e.rule == "no_path_traversal"));
    }

    #[test]
    fn test_shell_exec_too_many_env_vars() {
        let env_vars: Vec<String> = (0..=MAX_REPEATED_ITEMS)
            .map(|i| format!("VAR{i}=val"))
            .collect();

        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ShellExec(ShellExec {
                command: "env".to_string(),
                cwd: String::new(),
                timeout_ms: 1000,
                network_access: false,
                env: env_vars,
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.rule == "max_items"));
    }

    #[test]
    fn test_git_op_too_many_args() {
        let args: Vec<String> = (0..=MAX_REPEATED_ITEMS)
            .map(|i| format!("--arg{i}"))
            .collect();

        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::GitOp(GitOperation {
                operation: "DIFF".to_string(),
                args,
                cwd: String::new(),
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.rule == "max_items"));
        assert!(errors.iter().any(|e| e.field == "git_op.args"));
    }

    #[test]
    fn test_artifact_publish_too_many_metadata() {
        let metadata: Vec<String> = (0..=MAX_REPEATED_ITEMS)
            .map(|i| format!("key{i}=value"))
            .collect();

        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactPublish(ArtifactPublish {
                artifact_id: "art-001".to_string(),
                content_hash: vec![0u8; 32],
                category: "test".to_string(),
                metadata,
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.rule == "max_items"));
        assert!(
            errors
                .iter()
                .any(|e| e.field == "artifact_publish.metadata")
        );
    }
}

#[cfg(test)]
mod artifact_fetch_tests {
    use super::*;

    #[test]
    fn test_artifact_fetch_valid_stable_id() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: "org:ticket:TCK-001".to_string(),
                content_hash: Vec::new(),
                expected_hash: Vec::new(),
                max_bytes: 1024,
                format: "json".to_string(),
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_artifact_fetch_valid_content_hash() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: String::new(),
                content_hash: vec![0xaa; 32], // 32 bytes = valid BLAKE3 hash
                expected_hash: Vec::new(),
                max_bytes: 1024,
                format: String::new(),
            })),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_artifact_fetch_missing_identifiers() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: String::new(),
                content_hash: Vec::new(),
                expected_hash: Vec::new(),
                max_bytes: 1024,
                format: String::new(),
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "artifact_fetch"));
    }

    #[test]
    fn test_artifact_fetch_invalid_content_hash() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: String::new(),
                content_hash: vec![0xaa; 16], // 16 bytes = invalid (should be 32)
                expected_hash: Vec::new(),
                max_bytes: 1024,
                format: String::new(),
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.field == "artifact_fetch.content_hash")
        );
    }

    #[test]
    fn test_artifact_fetch_max_bytes_exceeded() {
        let req = ToolRequest {
            consumption_mode: false,
            request_id: "req-001".to_string(),
            session_token: "session-abc".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: "org:test".to_string(),
                content_hash: Vec::new(),
                expected_hash: Vec::new(),
                max_bytes: (MAX_WRITE_SIZE + 1) as u64,
                format: String::new(),
            })),
        };
        let result = req.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "artifact_fetch.max_bytes"));
    }
}
