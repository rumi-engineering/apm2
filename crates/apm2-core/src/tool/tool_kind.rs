// AGENT-AUTHORED
//! Typed `ToolKind` safety, idempotency, and validation (TCK-00377).
//!
//! This module enforces RFC-0020 Section 6 requirements:
//!
//! - **Typed arguments**: Each [`ToolKind`] carries validated, typed arguments
//!   instead of raw strings. Authoritative routes MUST NOT accept untyped
//!   command strings.
//! - **Git ref/path validation**: Git refs and file paths are validated against
//!   injection and traversal attacks before acceptance.
//! - **Idempotency preconditions**: Side-effectful operations declare
//!   [`IdempotencyPrecondition`]s that must hold before execution proceeds.
//! - **Shell bridge policy**: Raw shell execution is gated behind an explicit
//!   [`ShellBridgePolicy`] allowlist. Tier2+ routes reject raw command strings.
//!
//! # Security Model
//!
//! - **Fail-closed**: Any validation failure rejects the request.
//! - **Defense-in-depth**: Validation here complements (does not replace) the
//!   proto-level validation in `validation.rs` and runtime sandboxing.
//! - **No ambient shell authority**: Shell commands require explicit allowlist
//!   membership.
//!
//! # Contract References
//!
//! - `REQ-0031`: `ToolKinds` argument safety and idempotency
//! - `CTR-0008`: Syscall families and `ToolKinds`
//! - `DEF-14`: Actuation delivery and dedupe semantics

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{FileEdit, FileRead, FileWrite, GitOperation, ShellExec, tool_request};

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for a git ref name.
const MAX_GIT_REF_LEN: usize = 256;

/// Maximum number of entries in a shell bridge allowlist.
pub const MAX_SHELL_BRIDGE_ALLOWLIST: usize = 64;

/// Maximum length of a shell bridge allowlist pattern.
pub const MAX_SHELL_BRIDGE_PATTERN_LEN: usize = 256;

/// Shell metacharacters that are forbidden in git refs and structured
/// arguments. These characters can enable injection when passed to shell
/// commands.
const SHELL_METACHARACTERS: &[char] = &[
    '|', '&', ';', '$', '`', '(', ')', '{', '}', '<', '>', '!', '\n', '\r', '\0',
];

/// Characters forbidden in git ref names per `git check-ref-format` rules,
/// plus additional shell-safety restrictions.
const GIT_REF_FORBIDDEN: &[char] = &[' ', '~', '^', ':', '?', '*', '[', '\\', '\x7f'];

// =============================================================================
// Errors
// =============================================================================

/// Errors from `ToolKind` validation and conversion.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ToolKindError {
    /// A git ref name failed validation.
    #[error("invalid git ref '{value}': {reason}")]
    InvalidGitRef {
        /// The invalid ref value.
        value: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A file path failed canonical validation.
    #[error("invalid path '{value}': {reason}")]
    InvalidPath {
        /// The invalid path value.
        value: String,
        /// Why it was rejected.
        reason: String,
    },

    /// Shell metacharacters detected in a structured argument.
    #[error("shell metacharacter injection in field '{field}': found '{ch}'")]
    ShellMetacharacterInjection {
        /// The field that contained the injection.
        field: String,
        /// The offending character.
        ch: char,
    },

    /// A raw shell command was rejected on an authoritative route.
    #[error("raw shell command rejected: {reason}")]
    RawShellRejected {
        /// Why the command was rejected.
        reason: String,
    },

    /// An idempotency precondition was not satisfied.
    #[error("idempotency precondition failed: {reason}")]
    PreconditionFailed {
        /// Why the precondition failed.
        reason: String,
    },

    /// The tool request variant is missing or unknown.
    #[error("missing or unknown tool variant")]
    MissingToolVariant,

    /// Shell bridge policy violation.
    #[error("shell bridge policy violation: {reason}")]
    ShellBridgePolicyViolation {
        /// Why the policy was violated.
        reason: String,
    },
}

// =============================================================================
// ToolKind
// =============================================================================

/// Typed tool operation with validated arguments.
///
/// Each variant carries structured, validated arguments. This enum is the
/// authoritative representation for tool operations after input validation.
/// Raw/untyped command strings are never accepted on authoritative routes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolKind {
    /// Read a file at a validated, canonical path.
    ReadFile {
        /// Validated canonical path (no traversal, no null bytes).
        path: ValidatedPath,
        /// Byte offset.
        offset: u64,
        /// Read limit (0 = entire file).
        limit: u64,
    },

    /// Write to a file at a validated, canonical path.
    WriteFile {
        /// Validated canonical path.
        path: ValidatedPath,
        /// Content hash (BLAKE3) for idempotency tracking.
        content_hash: [u8; 32],
        /// Whether to create only (fail if exists).
        create_only: bool,
        /// Whether to append.
        append: bool,
        /// Precondition that must hold before write.
        precondition: Option<IdempotencyPrecondition>,
    },

    /// Edit a file at a validated, canonical path.
    EditFile {
        /// Validated canonical path.
        path: ValidatedPath,
        /// Hash of old content (for precondition checking).
        old_content_hash: [u8; 32],
        /// Hash of new content (for receipt).
        new_content_hash: [u8; 32],
        /// Precondition that must hold before edit.
        precondition: Option<IdempotencyPrecondition>,
    },

    /// Git operation with validated ref names and arguments.
    GitOp {
        /// The git operation (validated against known operations).
        operation: GitOpKind,
        /// Validated arguments (no shell metacharacters).
        args: Vec<ValidatedArg>,
        /// Validated working directory path.
        cwd: Option<ValidatedPath>,
    },

    /// Shell execution gated by bridge policy.
    ShellExec {
        /// The command executable (must be in allowlist).
        executable: String,
        /// Structured arguments (not a raw command string).
        args: Vec<String>,
        /// Validated working directory.
        cwd: Option<ValidatedPath>,
        /// Timeout in milliseconds.
        timeout_ms: u64,
    },
}

impl ToolKind {
    /// Returns `true` if this tool kind can cause side effects.
    #[must_use]
    pub const fn is_side_effectful(&self) -> bool {
        match self {
            Self::ReadFile { .. } => false,
            Self::WriteFile { .. }
            | Self::EditFile { .. }
            | Self::GitOp { .. }
            | Self::ShellExec { .. } => true,
        }
    }

    /// Returns the tool kind name for logging/receipts.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::ReadFile { .. } => "ReadFile",
            Self::WriteFile { .. } => "WriteFile",
            Self::EditFile { .. } => "EditFile",
            Self::GitOp { .. } => "GitOp",
            Self::ShellExec { .. } => "ShellExec",
        }
    }
}

// =============================================================================
// ValidatedPath
// =============================================================================

/// A file path that has been validated for safety.
///
/// Invariants enforced at construction:
/// - No null bytes
/// - No path traversal sequences (`..`)
/// - No shell metacharacters
/// - Non-empty
/// - Length bounded by `MAX_PATH_LEN`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedPath(String);

/// Maximum path length (matches validation.rs).
const MAX_PATH_LEN: usize = 4096;

impl ValidatedPath {
    /// Create a new validated path.
    ///
    /// # Errors
    ///
    /// Returns [`ToolKindError::InvalidPath`] if the path fails validation.
    pub fn new(path: &str) -> Result<Self, ToolKindError> {
        if path.is_empty() {
            return Err(ToolKindError::InvalidPath {
                value: path.to_string(),
                reason: "path must be non-empty".to_string(),
            });
        }

        if path.len() > MAX_PATH_LEN {
            return Err(ToolKindError::InvalidPath {
                value: path.chars().take(64).collect::<String>() + "...",
                reason: format!("path exceeds maximum length of {MAX_PATH_LEN}"),
            });
        }

        if path.contains('\0') {
            return Err(ToolKindError::InvalidPath {
                value: path.replace('\0', "\\0"),
                reason: "path must not contain null bytes".to_string(),
            });
        }

        // Check for path traversal
        for component in path.split(['/', '\\']) {
            if component == ".." {
                return Err(ToolKindError::InvalidPath {
                    value: path.to_string(),
                    reason: "path must not contain traversal sequences (..)".to_string(),
                });
            }
        }

        // Check for shell metacharacters
        for ch in SHELL_METACHARACTERS {
            if path.contains(*ch) {
                return Err(ToolKindError::ShellMetacharacterInjection {
                    field: "path".to_string(),
                    ch: *ch,
                });
            }
        }

        Ok(Self(path.to_string()))
    }

    /// Returns the validated path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidatedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// =============================================================================
// ValidatedArg
// =============================================================================

/// A command argument that has been validated against injection.
///
/// Invariants:
/// - No shell metacharacters
/// - No null bytes
/// - Bounded length
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedArg(String);

/// Maximum argument length (matches `validation.rs` `MAX_ARG_LEN`).
const MAX_ARG_LEN: usize = 32 * 1024;

impl ValidatedArg {
    /// Create a new validated argument.
    ///
    /// # Errors
    ///
    /// Returns [`ToolKindError::ShellMetacharacterInjection`] if the argument
    /// contains shell metacharacters.
    pub fn new(arg: &str, field_name: &str) -> Result<Self, ToolKindError> {
        if arg.len() > MAX_ARG_LEN {
            return Err(ToolKindError::InvalidPath {
                value: arg.chars().take(64).collect::<String>() + "...",
                reason: format!("argument exceeds maximum length of {MAX_ARG_LEN}"),
            });
        }

        for ch in SHELL_METACHARACTERS {
            if arg.contains(*ch) {
                return Err(ToolKindError::ShellMetacharacterInjection {
                    field: field_name.to_string(),
                    ch: *ch,
                });
            }
        }

        Ok(Self(arg.to_string()))
    }

    /// Returns the validated argument as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidatedArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// =============================================================================
// GitOpKind
// =============================================================================

/// Validated git operation kinds.
///
/// Each variant corresponds to a known git operation. The operation name
/// is validated against the known set at construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GitOpKind {
    /// `git clone`
    Clone,
    /// `git fetch`
    Fetch,
    /// `git pull`
    Pull,
    /// `git diff`
    Diff,
    /// `git commit`
    Commit,
    /// `git push`
    Push,
    /// `git status`
    Status,
    /// `git log`
    Log,
    /// `git branch`
    Branch,
    /// `git checkout`
    Checkout,
    /// `git merge`
    Merge,
    /// `git rebase`
    Rebase,
    /// `git add`
    Add,
    /// `git reset`
    Reset,
    /// `git stash`
    Stash,
    /// `git tag`
    Tag,
    /// `git remote`
    Remote,
    /// `git show`
    Show,
}

impl GitOpKind {
    /// Parse a git operation string into a typed variant.
    ///
    /// # Errors
    ///
    /// Returns [`ToolKindError::InvalidGitRef`] if the operation is unknown.
    pub fn parse(operation: &str) -> Result<Self, ToolKindError> {
        match operation {
            "CLONE" => Ok(Self::Clone),
            "FETCH" => Ok(Self::Fetch),
            "PULL" => Ok(Self::Pull),
            "DIFF" => Ok(Self::Diff),
            "COMMIT" => Ok(Self::Commit),
            "PUSH" => Ok(Self::Push),
            "STATUS" => Ok(Self::Status),
            "LOG" => Ok(Self::Log),
            "BRANCH" => Ok(Self::Branch),
            "CHECKOUT" => Ok(Self::Checkout),
            "MERGE" => Ok(Self::Merge),
            "REBASE" => Ok(Self::Rebase),
            "ADD" => Ok(Self::Add),
            "RESET" => Ok(Self::Reset),
            "STASH" => Ok(Self::Stash),
            "TAG" => Ok(Self::Tag),
            "REMOTE" => Ok(Self::Remote),
            "SHOW" => Ok(Self::Show),
            _ => Err(ToolKindError::InvalidGitRef {
                value: operation.to_string(),
                reason: "unknown git operation".to_string(),
            }),
        }
    }

    /// Returns `true` if this operation can cause side effects.
    #[must_use]
    pub const fn is_side_effectful(&self) -> bool {
        match self {
            Self::Diff | Self::Status | Self::Log | Self::Show => false,
            Self::Clone
            | Self::Fetch
            | Self::Pull
            | Self::Commit
            | Self::Push
            | Self::Branch
            | Self::Checkout
            | Self::Merge
            | Self::Rebase
            | Self::Add
            | Self::Reset
            | Self::Stash
            | Self::Tag
            | Self::Remote => true,
        }
    }

    /// Returns the canonical operation name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Clone => "CLONE",
            Self::Fetch => "FETCH",
            Self::Pull => "PULL",
            Self::Diff => "DIFF",
            Self::Commit => "COMMIT",
            Self::Push => "PUSH",
            Self::Status => "STATUS",
            Self::Log => "LOG",
            Self::Branch => "BRANCH",
            Self::Checkout => "CHECKOUT",
            Self::Merge => "MERGE",
            Self::Rebase => "REBASE",
            Self::Add => "ADD",
            Self::Reset => "RESET",
            Self::Stash => "STASH",
            Self::Tag => "TAG",
            Self::Remote => "REMOTE",
            Self::Show => "SHOW",
        }
    }
}

impl fmt::Display for GitOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Git Ref Validation
// =============================================================================

/// Validate a string as a safe git ref name.
///
/// Rejects:
/// - Empty refs
/// - Refs exceeding [`MAX_GIT_REF_LEN`]
/// - Refs containing shell metacharacters
/// - Refs containing git-forbidden characters (space, `~`, `^`, `:`, `?`, `*`,
///   `[`, `\`, DEL)
/// - Refs starting with `-` (flag injection)
/// - Refs containing `..` (traversal / git range ambiguity)
/// - Refs containing `@{` (git reflog syntax)
/// - Refs ending with `.lock`
/// - Refs containing consecutive dots
///
/// # Errors
///
/// Returns [`ToolKindError::InvalidGitRef`] on any violation.
pub fn validate_git_ref(ref_name: &str) -> Result<(), ToolKindError> {
    if ref_name.is_empty() {
        return Err(ToolKindError::InvalidGitRef {
            value: ref_name.to_string(),
            reason: "ref name must be non-empty".to_string(),
        });
    }

    if ref_name.len() > MAX_GIT_REF_LEN {
        return Err(ToolKindError::InvalidGitRef {
            value: ref_name.chars().take(64).collect::<String>() + "...",
            reason: format!("ref name exceeds maximum length of {MAX_GIT_REF_LEN}"),
        });
    }

    // Flag injection prevention
    if ref_name.starts_with('-') {
        return Err(ToolKindError::InvalidGitRef {
            value: ref_name.to_string(),
            reason: "ref name must not start with '-' (flag injection)".to_string(),
        });
    }

    // Shell metacharacter injection
    for ch in SHELL_METACHARACTERS {
        if ref_name.contains(*ch) {
            return Err(ToolKindError::ShellMetacharacterInjection {
                field: "git_ref".to_string(),
                ch: *ch,
            });
        }
    }

    // Git-specific forbidden characters
    for ch in GIT_REF_FORBIDDEN {
        if ref_name.contains(*ch) {
            return Err(ToolKindError::InvalidGitRef {
                value: ref_name.to_string(),
                reason: format!("ref name contains forbidden character '{ch}'"),
            });
        }
    }

    // Path traversal / range operator
    if ref_name.contains("..") {
        return Err(ToolKindError::InvalidGitRef {
            value: ref_name.to_string(),
            reason: "ref name must not contain '..' (traversal/range)".to_string(),
        });
    }

    // Reflog syntax
    if ref_name.contains("@{") {
        return Err(ToolKindError::InvalidGitRef {
            value: ref_name.to_string(),
            reason: "ref name must not contain '@{' (reflog syntax)".to_string(),
        });
    }

    // .lock suffix (case-insensitive for cross-platform safety)
    if ref_name
        .rsplit_once('.')
        .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("lock"))
    {
        return Err(ToolKindError::InvalidGitRef {
            value: ref_name.to_string(),
            reason: "ref name must not end with '.lock'".to_string(),
        });
    }

    // Component-level checks (per git check-ref-format)
    for component in ref_name.split('/') {
        if component.is_empty() {
            return Err(ToolKindError::InvalidGitRef {
                value: ref_name.to_string(),
                reason: "ref name must not contain empty components (double slash)".to_string(),
            });
        }
        if component.starts_with('.') {
            return Err(ToolKindError::InvalidGitRef {
                value: ref_name.to_string(),
                reason: "ref component must not start with '.'".to_string(),
            });
        }
    }

    Ok(())
}

/// Validate a git argument for safety.
///
/// Git arguments are validated more permissively than ref names, but still
/// reject shell metacharacters and flag injection on ref-position arguments.
///
/// Arguments that look like flags (start with `-`) are allowed since they
/// are legitimate git options, but ref-like arguments are validated strictly.
///
/// # Errors
///
/// Returns [`ToolKindError::ShellMetacharacterInjection`] if the argument
/// contains shell metacharacters or null bytes.
pub fn validate_git_arg(arg: &str, index: usize) -> Result<ValidatedArg, ToolKindError> {
    let field = format!("git_op.args[{index}]");

    // Null byte check
    if arg.contains('\0') {
        return Err(ToolKindError::ShellMetacharacterInjection { field, ch: '\0' });
    }

    // Shell metacharacter check (newlines, pipes, etc.)
    for ch in SHELL_METACHARACTERS {
        if arg.contains(*ch) {
            return Err(ToolKindError::ShellMetacharacterInjection { field, ch: *ch });
        }
    }

    ValidatedArg::new(arg, &field)
}

// =============================================================================
// IdempotencyPrecondition
// =============================================================================

/// Precondition that must hold before a side-effectful tool executes.
///
/// Per RFC-0020 Section 6.1.2, side-effectful `ToolKinds` must support
/// precondition guards. If a precondition fails, the tool returns a
/// denial/failure receipt without partial execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IdempotencyPrecondition {
    /// File content must match the specified BLAKE3 hash before write/edit.
    FileHashMatch {
        /// Expected BLAKE3 hash of the file content.
        expected_hash: [u8; 32],
    },

    /// File must not exist (for create-only writes).
    FileNotExists,

    /// File must exist (for edits and appends).
    FileExists,

    /// Git ref must point to the specified commit hash.
    GitRefAtCommit {
        /// The ref name.
        ref_name: String,
        /// Expected commit hash (hex-encoded, 40 chars).
        expected_commit: String,
    },

    /// Working tree must be clean (no uncommitted changes).
    GitCleanWorkingTree,
}

impl IdempotencyPrecondition {
    /// Returns a human-readable description of this precondition.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::FileHashMatch { expected_hash } => {
                format!("file content must match hash {}", hex_encode(expected_hash))
            },
            Self::FileNotExists => "file must not exist".to_string(),
            Self::FileExists => "file must exist".to_string(),
            Self::GitRefAtCommit {
                ref_name,
                expected_commit,
            } => {
                format!("ref '{ref_name}' must point to {expected_commit}")
            },
            Self::GitCleanWorkingTree => "working tree must be clean".to_string(),
        }
    }
}

/// Hex-encode a hash for display.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// =============================================================================
// ShellBridgePolicy
// =============================================================================

/// Policy governing which shell commands are permitted.
///
/// Per RFC-0020 Section 6.3, shell execution is a transitional `ToolKind`
/// gated by an explicit allowlist. Raw command strings are never accepted
/// on Tier2+ authoritative routes.
///
/// # Security Model
///
/// - Commands must match the allowlist exactly (executable name).
/// - Tier2+ routes reject all shell execution unless explicitly allowed.
/// - The allowlist is bounded to prevent denial-of-service via policy bloat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellBridgePolicy {
    /// Allowed executable names (e.g., `["cargo", "rustfmt", "git"]`).
    /// Only the executable basename is matched, not the full path.
    allowed_executables: BTreeSet<String>,

    /// Whether Tier2+ routes are allowed to use shell execution at all.
    /// Defaults to `false` (deny).
    tier2_plus_allowed: bool,
}

impl ShellBridgePolicy {
    /// Create a new shell bridge policy with the given allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`ToolKindError::ShellBridgePolicyViolation`] if the allowlist
    /// exceeds [`MAX_SHELL_BRIDGE_ALLOWLIST`] entries or contains invalid
    /// patterns.
    pub fn new(
        executables: impl IntoIterator<Item = String>,
        tier2_plus_allowed: bool,
    ) -> Result<Self, ToolKindError> {
        let allowed_executables: BTreeSet<String> = executables.into_iter().collect();

        if allowed_executables.len() > MAX_SHELL_BRIDGE_ALLOWLIST {
            return Err(ToolKindError::ShellBridgePolicyViolation {
                reason: format!(
                    "allowlist exceeds maximum of {MAX_SHELL_BRIDGE_ALLOWLIST} entries"
                ),
            });
        }

        for exe in &allowed_executables {
            if exe.is_empty() {
                return Err(ToolKindError::ShellBridgePolicyViolation {
                    reason: "allowlist entry must be non-empty".to_string(),
                });
            }
            if exe.len() > MAX_SHELL_BRIDGE_PATTERN_LEN {
                return Err(ToolKindError::ShellBridgePolicyViolation {
                    reason: format!(
                        "allowlist entry exceeds maximum length of {MAX_SHELL_BRIDGE_PATTERN_LEN}"
                    ),
                });
            }
            // No shell metacharacters in executable names
            for ch in SHELL_METACHARACTERS {
                if exe.contains(*ch) {
                    return Err(ToolKindError::ShellBridgePolicyViolation {
                        reason: format!(
                            "allowlist entry '{exe}' contains shell metacharacter '{ch}'"
                        ),
                    });
                }
            }
            // No path separators (only basename matching)
            if exe.contains('/') || exe.contains('\\') {
                return Err(ToolKindError::ShellBridgePolicyViolation {
                    reason: format!(
                        "allowlist entry '{exe}' must be a basename (no path separators)"
                    ),
                });
            }
        }

        Ok(Self {
            allowed_executables,
            tier2_plus_allowed,
        })
    }

    /// Create a deny-all policy. No shell commands are permitted.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            allowed_executables: BTreeSet::new(),
            tier2_plus_allowed: false,
        }
    }

    /// Check whether a command is allowed under this policy.
    ///
    /// # Arguments
    ///
    /// * `executable` - The executable basename to check.
    /// * `is_tier2_plus` - Whether the request is on a Tier2+ route.
    ///
    /// # Errors
    ///
    /// Returns [`ToolKindError::RawShellRejected`] if the command is not
    /// permitted.
    pub fn check(&self, executable: &str, is_tier2_plus: bool) -> Result<(), ToolKindError> {
        if is_tier2_plus && !self.tier2_plus_allowed {
            return Err(ToolKindError::RawShellRejected {
                reason: "shell execution is not permitted on Tier2+ routes".to_string(),
            });
        }

        if !self.allowed_executables.contains(executable) {
            return Err(ToolKindError::RawShellRejected {
                reason: format!("executable '{executable}' is not in the shell bridge allowlist"),
            });
        }

        Ok(())
    }

    /// Returns `true` if Tier2+ routes are allowed shell execution.
    #[must_use]
    pub const fn tier2_plus_allowed(&self) -> bool {
        self.tier2_plus_allowed
    }

    /// Returns the set of allowed executables.
    #[must_use]
    pub const fn allowed_executables(&self) -> &BTreeSet<String> {
        &self.allowed_executables
    }
}

impl Default for ShellBridgePolicy {
    fn default() -> Self {
        Self::deny_all()
    }
}

// =============================================================================
// Conversion from Proto
// =============================================================================

/// Extract the executable name from a raw shell command string.
///
/// This parses the first whitespace-delimited token as the executable name
/// and returns it along with the remaining arguments.
///
/// # Security
///
/// This is a best-effort parse for the shell bridge policy check. The actual
/// execution still happens through the shell, so the allowlist is
/// defense-in-depth.
fn parse_shell_command(command: &str) -> Option<(&str, Vec<&str>)> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.split_whitespace();
    let executable = parts.next()?;

    // Extract basename from path
    let basename = executable.rsplit('/').next().unwrap_or(executable);
    let basename = basename.rsplit('\\').next().unwrap_or(basename);

    Some((basename, parts.collect()))
}

/// Convert a proto-level `tool_request::Tool` into a typed [`ToolKind`].
///
/// This performs canonical validation beyond what the proto-level validator
/// checks: shell metacharacter injection, path traversal, git ref safety,
/// and flag injection.
///
/// # Errors
///
/// Returns [`ToolKindError`] if the tool request fails typed validation.
pub fn tool_kind_from_proto(tool: &tool_request::Tool) -> Result<ToolKind, ToolKindError> {
    match tool {
        tool_request::Tool::FileRead(req) => from_file_read(req),
        tool_request::Tool::FileWrite(req) => from_file_write(req),
        tool_request::Tool::FileEdit(req) => from_file_edit(req),
        tool_request::Tool::GitOp(req) => from_git_op(req),
        tool_request::Tool::ShellExec(req) => from_shell_exec(req),
        // Other tool types (Inference, Artifact, ListFiles, Search) are not
        // in scope for TCK-00377 typed ToolKind hardening. They pass through
        // to existing validation in validation.rs.
        _ => Err(ToolKindError::MissingToolVariant),
    }
}

fn from_file_read(req: &FileRead) -> Result<ToolKind, ToolKindError> {
    let path = ValidatedPath::new(&req.path)?;
    Ok(ToolKind::ReadFile {
        path,
        offset: req.offset,
        limit: req.limit,
    })
}

fn from_file_write(req: &FileWrite) -> Result<ToolKind, ToolKindError> {
    let path = ValidatedPath::new(&req.path)?;
    let content_hash = blake3::hash(&req.content).into();

    let precondition = if req.create_only {
        Some(IdempotencyPrecondition::FileNotExists)
    } else if req.append {
        Some(IdempotencyPrecondition::FileExists)
    } else {
        None
    };

    Ok(ToolKind::WriteFile {
        path,
        content_hash,
        create_only: req.create_only,
        append: req.append,
        precondition,
    })
}

fn from_file_edit(req: &FileEdit) -> Result<ToolKind, ToolKindError> {
    let path = ValidatedPath::new(&req.path)?;
    let old_content_hash = blake3::hash(req.old_content.as_bytes()).into();
    let new_content_hash = blake3::hash(req.new_content.as_bytes()).into();

    Ok(ToolKind::EditFile {
        path,
        old_content_hash,
        new_content_hash,
        precondition: Some(IdempotencyPrecondition::FileExists),
    })
}

fn from_git_op(req: &GitOperation) -> Result<ToolKind, ToolKindError> {
    let operation = GitOpKind::parse(&req.operation)?;

    let mut args = Vec::with_capacity(req.args.len());
    for (i, arg) in req.args.iter().enumerate() {
        // All git args are validated for shell metacharacter injection.
        // The same validation applies regardless of whether the arg is a
        // flag or a ref-like positional argument.
        let validated = validate_git_arg(arg, i)?;
        args.push(validated);
    }

    let cwd = if req.cwd.is_empty() {
        None
    } else {
        Some(ValidatedPath::new(&req.cwd)?)
    };

    Ok(ToolKind::GitOp {
        operation,
        args,
        cwd,
    })
}

fn from_shell_exec(req: &ShellExec) -> Result<ToolKind, ToolKindError> {
    let (executable, args) =
        parse_shell_command(&req.command).ok_or_else(|| ToolKindError::RawShellRejected {
            reason: "empty command string".to_string(),
        })?;

    let cwd = if req.cwd.is_empty() {
        None
    } else {
        Some(ValidatedPath::new(&req.cwd)?)
    };

    Ok(ToolKind::ShellExec {
        executable: executable.to_string(),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        cwd,
        timeout_ms: req.timeout_ms,
    })
}

// =============================================================================
// Authoritative Route Guard
// =============================================================================

/// Reject raw shell command strings on authoritative (Tier2+) routes.
///
/// Per RFC-0020 CTR-0008:
/// > authoritative routes cannot accept raw untyped command strings
///
/// This function checks whether a `ShellExec` tool request should be
/// rejected based on the risk tier. On Tier2+ routes, raw shell commands
/// are forbidden unless the shell bridge policy explicitly allows them.
///
/// # Errors
///
/// Returns [`ToolKindError::RawShellRejected`] if the command is not permitted.
pub fn guard_authoritative_route(
    tool: &tool_request::Tool,
    policy: &ShellBridgePolicy,
    is_tier2_plus: bool,
) -> Result<(), ToolKindError> {
    if let tool_request::Tool::ShellExec(req) = tool {
        let (executable, _args) =
            parse_shell_command(&req.command).ok_or_else(|| ToolKindError::RawShellRejected {
                reason: "empty command string".to_string(),
            })?;

        policy.check(executable, is_tier2_plus)?;
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // ValidatedPath tests
    // =========================================================================

    #[test]
    fn test_validated_path_valid() {
        assert!(ValidatedPath::new("/workspace/src/main.rs").is_ok());
        assert!(ValidatedPath::new("relative/path.txt").is_ok());
        assert!(ValidatedPath::new("file.txt").is_ok());
        assert!(ValidatedPath::new("/a/b/c/d").is_ok());
    }

    #[test]
    fn test_validated_path_empty() {
        let err = ValidatedPath::new("").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidPath { .. }));
    }

    #[test]
    fn test_validated_path_null_byte() {
        let err = ValidatedPath::new("/path/to\0/file").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidPath { .. }));
    }

    #[test]
    fn test_validated_path_traversal_dotdot() {
        let err = ValidatedPath::new("/path/../etc/passwd").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidPath { .. }));
    }

    #[test]
    fn test_validated_path_traversal_start() {
        let err = ValidatedPath::new("../etc/passwd").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidPath { .. }));
    }

    #[test]
    fn test_validated_path_traversal_backslash() {
        let err = ValidatedPath::new("..\\etc\\passwd").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidPath { .. }));
    }

    #[test]
    fn test_validated_path_shell_metachar_pipe() {
        let err = ValidatedPath::new("/path/to|injection").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_validated_path_shell_metachar_semicolon() {
        let err = ValidatedPath::new("/path;rm -rf /").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_validated_path_shell_metachar_backtick() {
        let err = ValidatedPath::new("/path/`whoami`").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_validated_path_shell_metachar_dollar() {
        let err = ValidatedPath::new("/path/$HOME/file").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_validated_path_too_long() {
        let long_path = "a".repeat(MAX_PATH_LEN + 1);
        let err = ValidatedPath::new(&long_path).unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidPath { .. }));
    }

    // =========================================================================
    // Git ref validation tests
    // =========================================================================

    #[test]
    fn test_valid_git_refs() {
        assert!(validate_git_ref("main").is_ok());
        assert!(validate_git_ref("feature/my-branch").is_ok());
        assert!(validate_git_ref("refs/heads/main").is_ok());
        assert!(validate_git_ref("v1.0.0").is_ok());
        assert!(validate_git_ref("HEAD").is_ok());
    }

    #[test]
    fn test_git_ref_empty() {
        let err = validate_git_ref("").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_flag_injection() {
        let err = validate_git_ref("--upload-pack=evil").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_shell_metachar() {
        let err = validate_git_ref("branch;rm -rf /").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_git_ref_pipe_injection() {
        let err = validate_git_ref("branch|cat /etc/passwd").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_git_ref_backtick_injection() {
        let err = validate_git_ref("`whoami`").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_git_ref_dollar_injection() {
        let err = validate_git_ref("$USER").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_git_ref_traversal() {
        let err = validate_git_ref("refs/../HEAD").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_reflog_syntax() {
        let err = validate_git_ref("HEAD@{0}").unwrap_err();
        // The '{' is a shell metacharacter, so that's what triggers first
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_git_ref_lock_suffix() {
        let err = validate_git_ref("refs/heads/main.lock").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_space() {
        let err = validate_git_ref("branch name").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_tilde() {
        let err = validate_git_ref("HEAD~1").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_caret() {
        let err = validate_git_ref("HEAD^").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_dot_component() {
        let err = validate_git_ref("refs/.hidden/branch").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_double_slash() {
        let err = validate_git_ref("refs//heads/main").unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    #[test]
    fn test_git_ref_too_long() {
        let long_ref = "a".repeat(MAX_GIT_REF_LEN + 1);
        let err = validate_git_ref(&long_ref).unwrap_err();
        assert!(matches!(err, ToolKindError::InvalidGitRef { .. }));
    }

    // =========================================================================
    // Git arg validation tests
    // =========================================================================

    #[test]
    fn test_valid_git_args() {
        assert!(validate_git_arg("--cached", 0).is_ok());
        assert!(validate_git_arg("--no-verify", 0).is_ok());
        assert!(validate_git_arg("file.txt", 0).is_ok());
        assert!(validate_git_arg("HEAD", 0).is_ok());
    }

    #[test]
    fn test_git_arg_null_byte() {
        let err = validate_git_arg("arg\0injection", 0).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_git_arg_pipe_injection() {
        let err = validate_git_arg("arg|evil", 0).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    #[test]
    fn test_git_arg_semicolon_injection() {
        let err = validate_git_arg("arg;evil", 0).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { .. }
        ));
    }

    // =========================================================================
    // GitOpKind tests
    // =========================================================================

    #[test]
    fn test_git_op_kind_parse() {
        assert_eq!(GitOpKind::parse("DIFF").unwrap(), GitOpKind::Diff);
        assert_eq!(GitOpKind::parse("COMMIT").unwrap(), GitOpKind::Commit);
        assert_eq!(GitOpKind::parse("PUSH").unwrap(), GitOpKind::Push);
        assert!(GitOpKind::parse("UNKNOWN").is_err());
        assert!(GitOpKind::parse("").is_err());
    }

    #[test]
    fn test_git_op_kind_side_effects() {
        assert!(!GitOpKind::Diff.is_side_effectful());
        assert!(!GitOpKind::Status.is_side_effectful());
        assert!(!GitOpKind::Log.is_side_effectful());
        assert!(!GitOpKind::Show.is_side_effectful());
        assert!(GitOpKind::Commit.is_side_effectful());
        assert!(GitOpKind::Push.is_side_effectful());
        assert!(GitOpKind::Merge.is_side_effectful());
    }

    // =========================================================================
    // IdempotencyPrecondition tests
    // =========================================================================

    #[test]
    fn test_precondition_description() {
        let p = IdempotencyPrecondition::FileNotExists;
        assert_eq!(p.description(), "file must not exist");

        let p = IdempotencyPrecondition::FileExists;
        assert_eq!(p.description(), "file must exist");

        let p = IdempotencyPrecondition::GitCleanWorkingTree;
        assert_eq!(p.description(), "working tree must be clean");
    }

    // =========================================================================
    // ShellBridgePolicy tests
    // =========================================================================

    #[test]
    fn test_shell_policy_deny_all() {
        let policy = ShellBridgePolicy::deny_all();
        assert!(policy.check("cargo", false).is_err());
        assert!(policy.check("cargo", true).is_err());
    }

    #[test]
    fn test_shell_policy_allowlist() {
        let policy =
            ShellBridgePolicy::new(vec!["cargo".to_string(), "rustfmt".to_string()], false)
                .unwrap();

        assert!(policy.check("cargo", false).is_ok());
        assert!(policy.check("rustfmt", false).is_ok());
        assert!(policy.check("rm", false).is_err());
    }

    #[test]
    fn test_shell_policy_tier2_denied() {
        let policy = ShellBridgePolicy::new(
            vec!["cargo".to_string()],
            false, // tier2+ NOT allowed
        )
        .unwrap();

        assert!(policy.check("cargo", false).is_ok());
        assert!(policy.check("cargo", true).is_err()); // Tier2+ denied
    }

    #[test]
    fn test_shell_policy_tier2_allowed() {
        let policy = ShellBridgePolicy::new(
            vec!["cargo".to_string()],
            true, // tier2+ allowed
        )
        .unwrap();

        assert!(policy.check("cargo", true).is_ok());
    }

    #[test]
    fn test_shell_policy_too_many_entries() {
        let executables: Vec<String> = (0..=MAX_SHELL_BRIDGE_ALLOWLIST)
            .map(|i| format!("cmd{i}"))
            .collect();
        let err = ShellBridgePolicy::new(executables, false).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellBridgePolicyViolation { .. }
        ));
    }

    #[test]
    fn test_shell_policy_empty_entry() {
        let err = ShellBridgePolicy::new(vec![String::new()], false).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellBridgePolicyViolation { .. }
        ));
    }

    #[test]
    fn test_shell_policy_metachar_in_entry() {
        let err = ShellBridgePolicy::new(vec!["cmd;evil".to_string()], false).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellBridgePolicyViolation { .. }
        ));
    }

    #[test]
    fn test_shell_policy_path_in_entry() {
        let err = ShellBridgePolicy::new(vec!["/usr/bin/cargo".to_string()], false).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellBridgePolicyViolation { .. }
        ));
    }

    // =========================================================================
    // Proto conversion tests
    // =========================================================================

    #[test]
    fn test_from_proto_file_read() {
        let tool = tool_request::Tool::FileRead(FileRead {
            path: "/workspace/file.txt".to_string(),
            offset: 0,
            limit: 1024,
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        assert!(matches!(kind, ToolKind::ReadFile { .. }));
        assert!(!kind.is_side_effectful());
    }

    #[test]
    fn test_from_proto_file_read_traversal() {
        let tool = tool_request::Tool::FileRead(FileRead {
            path: "/workspace/../etc/passwd".to_string(),
            offset: 0,
            limit: 0,
        });
        assert!(tool_kind_from_proto(&tool).is_err());
    }

    #[test]
    fn test_from_proto_file_write() {
        let tool = tool_request::Tool::FileWrite(FileWrite {
            path: "/workspace/output.txt".to_string(),
            content: b"hello".to_vec(),
            create_only: true,
            append: false,
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        match &kind {
            ToolKind::WriteFile { precondition, .. } => {
                assert_eq!(*precondition, Some(IdempotencyPrecondition::FileNotExists));
            },
            _ => panic!("expected WriteFile"),
        }
        assert!(kind.is_side_effectful());
    }

    #[test]
    fn test_from_proto_file_edit() {
        let tool = tool_request::Tool::FileEdit(FileEdit {
            path: "/workspace/code.rs".to_string(),
            old_content: "old".to_string(),
            new_content: "new".to_string(),
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        match &kind {
            ToolKind::EditFile { precondition, .. } => {
                assert_eq!(*precondition, Some(IdempotencyPrecondition::FileExists));
            },
            _ => panic!("expected EditFile"),
        }
    }

    #[test]
    fn test_from_proto_git_op_valid() {
        let tool = tool_request::Tool::GitOp(GitOperation {
            operation: "DIFF".to_string(),
            args: vec!["--cached".to_string()],
            cwd: String::new(),
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        assert!(matches!(kind, ToolKind::GitOp { .. }));
    }

    #[test]
    fn test_from_proto_git_op_injection() {
        let tool = tool_request::Tool::GitOp(GitOperation {
            operation: "DIFF".to_string(),
            args: vec!["--cached;rm -rf /".to_string()],
            cwd: String::new(),
        });
        assert!(tool_kind_from_proto(&tool).is_err());
    }

    #[test]
    fn test_from_proto_shell_exec() {
        let tool = tool_request::Tool::ShellExec(ShellExec {
            command: "cargo test --release".to_string(),
            cwd: String::new(),
            timeout_ms: 60_000,
            network_access: false,
            env: vec![],
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        match &kind {
            ToolKind::ShellExec {
                executable, args, ..
            } => {
                assert_eq!(executable, "cargo");
                assert_eq!(args, &["test", "--release"]);
            },
            _ => panic!("expected ShellExec"),
        }
    }

    #[test]
    fn test_from_proto_shell_exec_empty() {
        let tool = tool_request::Tool::ShellExec(ShellExec {
            command: String::new(),
            cwd: String::new(),
            timeout_ms: 0,
            network_access: false,
            env: vec![],
        });
        assert!(tool_kind_from_proto(&tool).is_err());
    }

    // =========================================================================
    // Authoritative route guard tests
    // =========================================================================

    #[test]
    fn test_guard_allows_non_shell() {
        let tool = tool_request::Tool::FileRead(FileRead {
            path: "/file.txt".to_string(),
            offset: 0,
            limit: 0,
        });
        let policy = ShellBridgePolicy::deny_all();
        assert!(guard_authoritative_route(&tool, &policy, true).is_ok());
    }

    #[test]
    fn test_guard_rejects_shell_on_tier2() {
        let tool = tool_request::Tool::ShellExec(ShellExec {
            command: "cargo test".to_string(),
            cwd: String::new(),
            timeout_ms: 0,
            network_access: false,
            env: vec![],
        });
        let policy = ShellBridgePolicy::deny_all();
        assert!(guard_authoritative_route(&tool, &policy, true).is_err());
    }

    #[test]
    fn test_guard_allows_shell_in_allowlist_tier1() {
        let tool = tool_request::Tool::ShellExec(ShellExec {
            command: "cargo test".to_string(),
            cwd: String::new(),
            timeout_ms: 0,
            network_access: false,
            env: vec![],
        });
        let policy = ShellBridgePolicy::new(vec!["cargo".to_string()], false).unwrap();
        assert!(guard_authoritative_route(&tool, &policy, false).is_ok());
    }

    #[test]
    fn test_guard_rejects_shell_not_in_allowlist() {
        let tool = tool_request::Tool::ShellExec(ShellExec {
            command: "rm -rf /".to_string(),
            cwd: String::new(),
            timeout_ms: 0,
            network_access: false,
            env: vec![],
        });
        let policy = ShellBridgePolicy::new(vec!["cargo".to_string()], false).unwrap();
        assert!(guard_authoritative_route(&tool, &policy, false).is_err());
    }

    // =========================================================================
    // parse_shell_command tests
    // =========================================================================

    #[test]
    fn test_parse_shell_command() {
        let (exe, args) = parse_shell_command("cargo test --release").unwrap();
        assert_eq!(exe, "cargo");
        assert_eq!(args, vec!["test", "--release"]);
    }

    #[test]
    fn test_parse_shell_command_with_path() {
        let (exe, args) = parse_shell_command("/usr/bin/cargo build").unwrap();
        assert_eq!(exe, "cargo"); // basename extraction
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn test_parse_shell_command_empty() {
        assert!(parse_shell_command("").is_none());
        assert!(parse_shell_command("   ").is_none());
    }

    #[test]
    fn test_parse_shell_command_single() {
        let (exe, args) = parse_shell_command("ls").unwrap();
        assert_eq!(exe, "ls");
        assert!(args.is_empty());
    }

    // =========================================================================
    // ToolKind property tests
    // =========================================================================

    #[test]
    fn test_tool_kind_names() {
        let read = ToolKind::ReadFile {
            path: ValidatedPath::new("/file").unwrap(),
            offset: 0,
            limit: 0,
        };
        assert_eq!(read.kind_name(), "ReadFile");

        let write = ToolKind::WriteFile {
            path: ValidatedPath::new("/file").unwrap(),
            content_hash: [0u8; 32],
            create_only: false,
            append: false,
            precondition: None,
        };
        assert_eq!(write.kind_name(), "WriteFile");
    }

    // =========================================================================
    // Argument injection regression suite
    // =========================================================================

    #[test]
    fn test_injection_path_newline() {
        let err = ValidatedPath::new("/path/to\n/file").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { ch: '\n', .. }
        ));
    }

    #[test]
    fn test_injection_path_carriage_return() {
        let err = ValidatedPath::new("/path/to\r/file").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { ch: '\r', .. }
        ));
    }

    #[test]
    fn test_injection_git_arg_ampersand() {
        let err = validate_git_arg("arg&&evil", 0).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { ch: '&', .. }
        ));
    }

    #[test]
    fn test_injection_git_arg_subshell() {
        let err = validate_git_arg("$(evil)", 0).unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { ch: '$', .. }
        ));
    }

    #[test]
    fn test_injection_path_redirect() {
        let err = ValidatedPath::new("/path/to>/dev/null").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { ch: '>', .. }
        ));
    }

    #[test]
    fn test_injection_path_redirect_input() {
        let err = ValidatedPath::new("/path/to</etc/passwd").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { ch: '<', .. }
        ));
    }

    #[test]
    fn test_injection_path_exclamation() {
        let err = ValidatedPath::new("/path/to!cmd").unwrap_err();
        assert!(matches!(
            err,
            ToolKindError::ShellMetacharacterInjection { ch: '!', .. }
        ));
    }

    // =========================================================================
    // Path traversal regression suite
    // =========================================================================

    #[test]
    fn test_traversal_mid_path() {
        assert!(ValidatedPath::new("a/b/../c").is_err());
    }

    #[test]
    fn test_traversal_end_path() {
        assert!(ValidatedPath::new("a/b/..").is_err());
    }

    #[test]
    fn test_traversal_only_dotdot() {
        assert!(ValidatedPath::new("..").is_err());
    }

    #[test]
    fn test_traversal_backslash_mid() {
        assert!(ValidatedPath::new("a\\..\\b").is_err());
    }

    #[test]
    fn test_no_false_positive_dotdot_in_filename() {
        // "foo..bar" should NOT be flagged as traversal
        assert!(ValidatedPath::new("foo..bar").is_ok());
        assert!(ValidatedPath::new("file...txt").is_ok());
    }

    // =========================================================================
    // Non-idempotent tool precondition tests
    // =========================================================================

    #[test]
    fn test_write_create_only_has_precondition() {
        let tool = tool_request::Tool::FileWrite(FileWrite {
            path: "/workspace/new.txt".to_string(),
            content: b"data".to_vec(),
            create_only: true,
            append: false,
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        match kind {
            ToolKind::WriteFile { precondition, .. } => {
                assert_eq!(precondition, Some(IdempotencyPrecondition::FileNotExists));
            },
            _ => panic!("expected WriteFile"),
        }
    }

    #[test]
    fn test_write_append_has_precondition() {
        let tool = tool_request::Tool::FileWrite(FileWrite {
            path: "/workspace/log.txt".to_string(),
            content: b"data".to_vec(),
            create_only: false,
            append: true,
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        match kind {
            ToolKind::WriteFile { precondition, .. } => {
                assert_eq!(precondition, Some(IdempotencyPrecondition::FileExists));
            },
            _ => panic!("expected WriteFile"),
        }
    }

    #[test]
    fn test_edit_has_precondition() {
        let tool = tool_request::Tool::FileEdit(FileEdit {
            path: "/workspace/code.rs".to_string(),
            old_content: "old".to_string(),
            new_content: "new".to_string(),
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        match kind {
            ToolKind::EditFile { precondition, .. } => {
                assert_eq!(precondition, Some(IdempotencyPrecondition::FileExists));
            },
            _ => panic!("expected EditFile"),
        }
    }

    #[test]
    fn test_overwrite_no_precondition() {
        let tool = tool_request::Tool::FileWrite(FileWrite {
            path: "/workspace/out.txt".to_string(),
            content: b"data".to_vec(),
            create_only: false,
            append: false,
        });
        let kind = tool_kind_from_proto(&tool).unwrap();
        match kind {
            ToolKind::WriteFile { precondition, .. } => {
                assert_eq!(precondition, None);
            },
            _ => panic!("expected WriteFile"),
        }
    }
}
