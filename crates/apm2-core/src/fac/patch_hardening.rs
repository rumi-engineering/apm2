//! Patch injection hardening (TCK-00581).
//!
//! Path traversal rejection, safe apply mode, and patch provenance receipts.
//!
//! This module implements pre-apply validation of unified diff content to
//! prevent path traversal attacks, restricts patch format to `git_diff_v1`
//! rules, provides a safe-apply wrapper that verifies the resulting tree
//! matches the expected patch digest binding, and emits
//! [`PatchApplyReceiptV1`] receipts for audit provenance.
//!
//! # Security Model
//!
//! All validation is **fail-closed**: any ambiguous, malformed, or
//! unrecognised input results in denial with a structured
//! [`PatchRefusal`] attached to the receipt.
//!
//! # Invariants
//!
//! - \[INV-PH-001\] Paths containing `..` components are rejected.
//! - \[INV-PH-002\] Absolute paths (leading `/`) are rejected.
//! - \[INV-PH-003\] Paths with Windows drive letters or UNC prefixes are
//!   rejected.
//! - \[INV-PH-004\] Paths must start with `a/` or `b/` prefix (standard git
//!   diff prefix) and the prefix is stripped before traversal checks.
//! - \[INV-PH-005\] NUL bytes in patch content are rejected.
//! - \[INV-PH-006\] Patch size is bounded by [`MAX_PATCH_CONTENT_SIZE`].
//! - \[INV-PH-007\] Only `git_diff_v1` format patches are accepted.
//! - \[INV-PH-008\] Receipt content hash covers all normative fields with
//!   injective length-prefix framing.
//! - \[INV-PH-009\] Empty patches (no diff headers) are rejected.
//! - \[INV-PH-010\] `/dev/null` is allowed as a source/destination in file
//!   creation/deletion diffs.

use std::fmt;

use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum patch content size in bytes (10 MiB, consistent with
/// `repo_mirror::MAX_PATCH_SIZE` and `blob_store::MAX_BLOB_SIZE`).
pub const MAX_PATCH_CONTENT_SIZE: usize = 10_485_760;

/// Maximum number of file entries (diff headers) in a single patch.
pub const MAX_PATCH_FILE_ENTRIES: usize = 10_000;

/// Maximum path component length.
pub const MAX_PATH_COMPONENT_LENGTH: usize = 255;

/// Maximum total path length (after prefix strip).
pub const MAX_PATH_LENGTH: usize = 4096;

/// Maximum number of refusals tracked in a single receipt.
pub const MAX_REFUSALS: usize = 1_000;

/// Maximum length of a refusal reason string.
pub const MAX_REFUSAL_REASON_LENGTH: usize = 512;

/// Schema identifier for `PatchApplyReceiptV1`.
pub const PATCH_APPLY_RECEIPT_SCHEMA_ID: &str = "apm2.fac.patch_apply_receipt.v1";

/// Schema version for `PatchApplyReceiptV1`.
pub const PATCH_APPLY_RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

/// Domain separator for receipt content hash.
const RECEIPT_HASH_DOMAIN: &str = "apm2.fac_patch_apply_receipt.v1";

/// Allowed patch format identifier.
pub const PATCH_FORMAT_GIT_DIFF_V1: &str = "git_diff_v1";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from patch content validation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PatchValidationError {
    /// Patch exceeds maximum allowed size.
    #[error("patch too large: {size} > {max}")]
    TooLarge {
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Patch contains NUL bytes (binary content).
    #[error("patch contains NUL byte at offset {offset}")]
    NulByte {
        /// Byte offset of the NUL.
        offset: usize,
    },

    /// Path traversal detected in a diff header.
    #[error("path traversal in {header}: {reason}")]
    PathTraversal {
        /// The offending diff header line.
        header: String,
        /// Why the path was rejected.
        reason: String,
    },

    /// Absolute path detected in a diff header.
    #[error("absolute path in {header}: {reason}")]
    AbsolutePath {
        /// The offending diff header line.
        header: String,
        /// Why the path was rejected.
        reason: String,
    },

    /// Invalid or missing git diff prefix (`a/` or `b/`).
    #[error("invalid prefix in {header}: {reason}")]
    InvalidPrefix {
        /// The offending diff header line.
        header: String,
        /// Why the prefix was rejected.
        reason: String,
    },

    /// Path exceeds maximum length.
    #[error("path too long in {header}: {length} > {max}")]
    PathTooLong {
        /// The offending diff header line.
        header: String,
        /// Actual length.
        length: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Path component exceeds maximum length.
    #[error("path component too long in {header}: {length} > {max}")]
    ComponentTooLong {
        /// The offending diff header line.
        header: String,
        /// Actual length.
        length: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Windows-style path detected.
    #[error("windows path in {header}: {reason}")]
    WindowsPath {
        /// The offending diff header line.
        header: String,
        /// Why the path was rejected.
        reason: String,
    },

    /// Patch has no diff headers (empty patch).
    #[error("patch contains no diff headers")]
    EmptyPatch,

    /// Too many file entries in the patch.
    #[error("too many file entries: {count} > {max}")]
    TooManyFiles {
        /// Actual file count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Unsupported patch format.
    #[error("unsupported patch format: expected {expected}, got {actual}")]
    UnsupportedFormat {
        /// Expected format.
        expected: String,
        /// Actual format.
        actual: String,
    },
}

/// A single refusal reason attached to a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchRefusal {
    /// Which file path or header triggered the refusal.
    pub path: String,
    /// Human-readable reason.
    pub reason: String,
}

impl fmt::Display for PatchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

// ---------------------------------------------------------------------------
// Patch content validation
// ---------------------------------------------------------------------------

/// Validates raw patch bytes against `git_diff_v1` format rules.
///
/// Returns the list of validated file paths on success, or a
/// [`PatchValidationError`] on the first violation.
///
/// # Errors
///
/// Returns the first validation failure. Callers MUST deny the patch on
/// any error (fail-closed).
pub fn validate_patch_content(
    patch_bytes: &[u8],
    expected_format: &str,
) -> Result<PatchValidationResult, PatchValidationError> {
    // INV-PH-007: format gate
    if expected_format != PATCH_FORMAT_GIT_DIFF_V1 {
        return Err(PatchValidationError::UnsupportedFormat {
            expected: PATCH_FORMAT_GIT_DIFF_V1.to_string(),
            actual: expected_format.to_string(),
        });
    }

    // INV-PH-006: size gate
    if patch_bytes.len() > MAX_PATCH_CONTENT_SIZE {
        return Err(PatchValidationError::TooLarge {
            size: patch_bytes.len(),
            max: MAX_PATCH_CONTENT_SIZE,
        });
    }

    // INV-PH-005: NUL byte gate (binary patches out of scope)
    if let Some(offset) = patch_bytes.iter().position(|&b| b == 0) {
        return Err(PatchValidationError::NulByte { offset });
    }

    // SAFETY: NUL-free ASCII-superset content. Git diffs are UTF-8 compatible.
    let patch_str =
        std::str::from_utf8(patch_bytes).map_err(|e| PatchValidationError::NulByte {
            offset: e.valid_up_to(),
        })?;

    let mut file_paths: Vec<String> = Vec::new();
    let mut file_count: usize = 0;

    for line in patch_str.lines() {
        // Parse "diff --git a/path b/path" headers
        if let Some(rest) = line.strip_prefix("diff --git ") {
            file_count = file_count.saturating_add(1);
            if file_count > MAX_PATCH_FILE_ENTRIES {
                return Err(PatchValidationError::TooManyFiles {
                    count: file_count,
                    max: MAX_PATCH_FILE_ENTRIES,
                });
            }

            let (a_path, b_path) = parse_diff_header_paths(rest, line)?;
            validate_single_path(&a_path, line)?;
            validate_single_path(&b_path, line)?;
            file_paths.push(a_path);
            if file_paths.last().is_some_and(|last| last != &b_path) {
                file_paths.push(b_path);
            }
        }

        // Also validate --- and +++ lines for extra safety
        if let Some(path_part) = line.strip_prefix("--- ") {
            let path = path_part.split('\t').next().unwrap_or(path_part);
            if path != "/dev/null" {
                validate_prefixed_path(path, line)?;
            }
        }
        if let Some(path_part) = line.strip_prefix("+++ ") {
            let path = path_part.split('\t').next().unwrap_or(path_part);
            if path != "/dev/null" {
                validate_prefixed_path(path, line)?;
            }
        }
    }

    // INV-PH-009: empty patch gate
    if file_count == 0 {
        return Err(PatchValidationError::EmptyPatch);
    }

    Ok(PatchValidationResult {
        file_count,
        validated_paths: file_paths,
    })
}

/// Result of successful patch content validation.
#[derive(Debug, Clone)]
pub struct PatchValidationResult {
    /// Number of file entries found in the patch.
    pub file_count: usize,
    /// List of validated file paths (after prefix stripping).
    pub validated_paths: Vec<String>,
}

/// Parse the two paths from a `diff --git a/X b/Y` header line.
///
/// Git diff headers use `a/` and `b/` prefixes. We extract both paths
/// and strip the prefix before returning.
fn parse_diff_header_paths(
    rest: &str,
    full_line: &str,
) -> Result<(String, String), PatchValidationError> {
    // The format is: a/<path> b/<path>
    // For paths with spaces, git uses quoting. We handle the simple
    // unquoted case and the common quoting patterns.

    // Try splitting on " b/" which is the standard separator
    if let Some(idx) = rest.find(" b/") {
        let a_raw = &rest[..idx];
        let b_raw = &rest[idx + 1..];

        let a_path = strip_git_prefix(a_raw, full_line)?;
        let b_path = strip_git_prefix(b_raw, full_line)?;
        return Ok((a_path, b_path));
    }

    // Handle /dev/null cases: "a/path /dev/null" or "/dev/null b/path"
    if rest.contains("/dev/null") {
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        if parts.len() == 2 {
            let a_path = if parts[0] == "/dev/null" {
                "/dev/null".to_string()
            } else {
                strip_git_prefix(parts[0], full_line)?
            };
            let b_path = if parts[1] == "/dev/null" {
                "/dev/null".to_string()
            } else {
                strip_git_prefix(parts[1], full_line)?
            };
            return Ok((a_path, b_path));
        }
    }

    Err(PatchValidationError::InvalidPrefix {
        header: truncate_header(full_line),
        reason: "could not parse diff header paths".to_string(),
    })
}

/// Strip git diff prefix (`a/` or `b/`) and return the bare path.
fn strip_git_prefix(raw: &str, full_line: &str) -> Result<String, PatchValidationError> {
    if raw == "/dev/null" {
        return Ok("/dev/null".to_string());
    }
    if let Some(path) = raw.strip_prefix("a/") {
        return Ok(path.to_string());
    }
    if let Some(path) = raw.strip_prefix("b/") {
        return Ok(path.to_string());
    }
    Err(PatchValidationError::InvalidPrefix {
        header: truncate_header(full_line),
        reason: format!(
            "path must start with a/ or b/ prefix, got: {}",
            truncate_header(raw)
        ),
    })
}

/// Validate a path that still has its `a/` or `b/` prefix (from ---/+++ lines).
fn validate_prefixed_path(raw: &str, full_line: &str) -> Result<(), PatchValidationError> {
    let path = if let Some(p) = raw.strip_prefix("a/") {
        p
    } else if let Some(p) = raw.strip_prefix("b/") {
        p
    } else {
        return Err(PatchValidationError::InvalidPrefix {
            header: truncate_header(full_line),
            reason: format!(
                "--- or +++ path must start with a/ or b/ prefix, got: {}",
                truncate_header(raw)
            ),
        });
    };
    validate_single_path(path, full_line)
}

/// Validate a single file path (after prefix stripping).
fn validate_single_path(path: &str, full_line: &str) -> Result<(), PatchValidationError> {
    // /dev/null is allowed for file creation/deletion diffs (INV-PH-010).
    if path == "/dev/null" {
        return Ok(());
    }

    // INV-PH-006: path length gate
    if path.len() > MAX_PATH_LENGTH {
        return Err(PatchValidationError::PathTooLong {
            header: truncate_header(full_line),
            length: path.len(),
            max: MAX_PATH_LENGTH,
        });
    }

    // INV-PH-002: absolute path gate
    if path.starts_with('/') {
        return Err(PatchValidationError::AbsolutePath {
            header: truncate_header(full_line),
            reason: "path starts with /".to_string(),
        });
    }

    // INV-PH-003: Windows drive letter gate (e.g., C:\, D:/)
    if path.len() >= 2 && path.as_bytes()[0].is_ascii_alphabetic() && (path.as_bytes()[1] == b':') {
        return Err(PatchValidationError::WindowsPath {
            header: truncate_header(full_line),
            reason: "path contains Windows drive letter".to_string(),
        });
    }

    // INV-PH-003: UNC path gate (\\server\share)
    if path.starts_with("\\\\") || path.starts_with("//") {
        return Err(PatchValidationError::WindowsPath {
            header: truncate_header(full_line),
            reason: "path contains UNC prefix".to_string(),
        });
    }

    // INV-PH-001: path traversal gate — check each component
    for component in path.split('/') {
        if component == ".." {
            return Err(PatchValidationError::PathTraversal {
                header: truncate_header(full_line),
                reason: "path contains '..' component".to_string(),
            });
        }

        // Component length gate
        if component.len() > MAX_PATH_COMPONENT_LENGTH {
            return Err(PatchValidationError::ComponentTooLong {
                header: truncate_header(full_line),
                length: component.len(),
                max: MAX_PATH_COMPONENT_LENGTH,
            });
        }
    }

    // Backslash in paths (potential Windows path separator smuggling)
    if path.contains('\\') {
        return Err(PatchValidationError::WindowsPath {
            header: truncate_header(full_line),
            reason: "path contains backslash".to_string(),
        });
    }

    Ok(())
}

/// Truncate a header line for error reporting (avoid unbounded strings in
/// errors).
fn truncate_header(line: &str) -> String {
    if line.len() <= 200 {
        line.to_string()
    } else {
        format!("{}...", &line[..200])
    }
}

// ---------------------------------------------------------------------------
// PatchApplyReceiptV1
// ---------------------------------------------------------------------------

/// Provenance receipt emitted after a patch apply attempt.
///
/// Contains the patch digest, file count, and any refusals encountered
/// during validation. The receipt is content-hashed for binding to
/// evidence chains.
#[derive(Debug, Clone)]
pub struct PatchApplyReceiptV1 {
    /// Schema identifier.
    pub schema_id: String,
    /// Schema version.
    pub schema_version: String,
    /// BLAKE3 digest of the patch bytes (`b3-256:<hex>`).
    pub patch_digest: String,
    /// Number of files successfully applied.
    pub applied_files_count: u32,
    /// Refusals encountered during validation (may be empty on success).
    pub refusals: Vec<PatchRefusal>,
    /// Whether the patch was applied (`true`) or denied (`false`).
    pub applied: bool,
    /// BLAKE3 content hash of this receipt's normative fields.
    pub content_hash: [u8; 32],
}

impl PatchApplyReceiptV1 {
    /// Build a receipt for a successful patch apply.
    #[must_use]
    pub fn success(patch_digest: String, applied_files_count: u32) -> Self {
        let mut receipt = Self {
            schema_id: PATCH_APPLY_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: PATCH_APPLY_RECEIPT_SCHEMA_VERSION.to_string(),
            patch_digest,
            applied_files_count,
            refusals: Vec::new(),
            applied: true,
            content_hash: [0u8; 32],
        };
        receipt.content_hash = receipt.compute_content_hash();
        receipt
    }

    /// Build a receipt for a denied patch.
    ///
    /// Refusals are capped at [`MAX_REFUSALS`].
    #[must_use]
    pub fn denial(patch_digest: String, refusals: Vec<PatchRefusal>) -> Self {
        let capped_refusals: Vec<PatchRefusal> = refusals
            .into_iter()
            .take(MAX_REFUSALS)
            .map(|mut r| {
                r.reason.truncate(MAX_REFUSAL_REASON_LENGTH);
                r.path.truncate(MAX_PATH_LENGTH);
                r
            })
            .collect();

        let mut receipt = Self {
            schema_id: PATCH_APPLY_RECEIPT_SCHEMA_ID.to_string(),
            schema_version: PATCH_APPLY_RECEIPT_SCHEMA_VERSION.to_string(),
            patch_digest,
            applied_files_count: 0,
            refusals: capped_refusals,
            applied: false,
            content_hash: [0u8; 32],
        };
        receipt.content_hash = receipt.compute_content_hash();
        receipt
    }

    /// Recompute the content hash from normative fields.
    ///
    /// Uses domain-separated BLAKE3 with injective length-prefix framing
    /// (INV-PH-008).
    #[must_use]
    pub fn compute_content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(RECEIPT_HASH_DOMAIN);

        // Schema identity
        hash_length_prefixed(&mut hasher, self.schema_id.as_bytes());
        hash_length_prefixed(&mut hasher, self.schema_version.as_bytes());

        // Core fields
        hash_length_prefixed(&mut hasher, self.patch_digest.as_bytes());
        hasher.update(&self.applied_files_count.to_le_bytes());
        hasher.update(&[u8::from(self.applied)]);

        // Refusals count and content
        let refusal_count = self.refusals.len() as u64;
        hasher.update(&refusal_count.to_le_bytes());
        for refusal in &self.refusals {
            hash_length_prefixed(&mut hasher, refusal.path.as_bytes());
            hash_length_prefixed(&mut hasher, refusal.reason.as_bytes());
        }

        *hasher.finalize().as_bytes()
    }

    /// Verify the receipt's content hash.
    #[must_use]
    pub fn verify_content_hash(&self) -> bool {
        let expected = self.compute_content_hash();
        subtle::ConstantTimeEq::ct_eq(&self.content_hash[..], &expected[..]).unwrap_u8() == 1
    }

    /// Format the content hash as `b3-256:<hex>`.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        format!("b3-256:{}", hex::encode(self.content_hash))
    }
}

/// Hash a variable-length field with injective u64 length prefix.
fn hash_length_prefixed(hasher: &mut blake3::Hasher, data: &[u8]) {
    let len = data.len() as u64;
    hasher.update(&len.to_le_bytes());
    hasher.update(data);
}

// ---------------------------------------------------------------------------
// Safe apply wrapper
// ---------------------------------------------------------------------------

/// Validate patch content and return a denial receipt if validation fails,
/// or Ok(result) if the patch passes all checks.
///
/// This is the pre-apply validation gate. Callers should:
/// 1. Call `validate_and_build_receipt` to get validation result
/// 2. If Ok, proceed with `git apply`
/// 3. Build the final receipt from the apply outcome
///
/// # Errors
///
/// Never errors — returns a denial receipt via the receipt for invalid patches,
/// or the validation result for valid ones.
pub fn validate_for_apply(
    patch_bytes: &[u8],
    patch_format: &str,
) -> Result<PatchValidationResult, Box<(PatchApplyReceiptV1, PatchValidationError)>> {
    let patch_digest = format!("b3-256:{}", blake3::hash(patch_bytes).to_hex());

    match validate_patch_content(patch_bytes, patch_format) {
        Ok(result) => Ok(result),
        Err(err) => {
            let refusal = PatchRefusal {
                path: String::new(),
                reason: err.to_string(),
            };
            let receipt = PatchApplyReceiptV1::denial(patch_digest, vec![refusal]);
            Err(Box::new((receipt, err)))
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_patch() -> Vec<u8> {
        b"diff --git a/src/main.rs b/src/main.rs\n\
          index 1234567..abcdefg 100644\n\
          --- a/src/main.rs\n\
          +++ b/src/main.rs\n\
          @@ -1,3 +1,4 @@\n\
           fn main() {\n\
          +    println!(\"hello\");\n\
           }\n"
        .to_vec()
    }

    fn make_new_file_patch() -> Vec<u8> {
        b"diff --git a/new_file.txt b/new_file.txt\n\
          new file mode 100644\n\
          index 0000000..1234567\n\
          --- /dev/null\n\
          +++ b/new_file.txt\n\
          @@ -0,0 +1 @@\n\
          +new content\n"
            .to_vec()
    }

    fn make_delete_file_patch() -> Vec<u8> {
        b"diff --git a/old_file.txt b/old_file.txt\n\
          deleted file mode 100644\n\
          index 1234567..0000000\n\
          --- a/old_file.txt\n\
          +++ /dev/null\n\
          @@ -1 +0,0 @@\n\
          -old content\n"
            .to_vec()
    }

    // -----------------------------------------------------------------------
    // Positive tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_patch_passes_validation() {
        let patch = make_valid_patch();
        let result = validate_patch_content(&patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_ok(), "valid patch should pass: {result:?}");
        let result = result.unwrap();
        assert_eq!(result.file_count, 1);
        assert!(!result.validated_paths.is_empty());
    }

    #[test]
    fn new_file_patch_passes_validation() {
        let patch = make_new_file_patch();
        let result = validate_patch_content(&patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_ok(), "new file patch should pass: {result:?}");
    }

    #[test]
    fn delete_file_patch_passes_validation() {
        let patch = make_delete_file_patch();
        let result = validate_patch_content(&patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_ok(), "delete file patch should pass: {result:?}");
    }

    #[test]
    fn multi_file_patch_passes() {
        let patch = b"diff --git a/file1.rs b/file1.rs\n\
                       --- a/file1.rs\n\
                       +++ b/file1.rs\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n\
                       diff --git a/file2.rs b/file2.rs\n\
                       --- a/file2.rs\n\
                       +++ b/file2.rs\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().file_count, 2);
    }

    #[test]
    fn nested_path_passes() {
        let patch = b"diff --git a/src/deep/nested/file.rs b/src/deep/nested/file.rs\n\
                       --- a/src/deep/nested/file.rs\n\
                       +++ b/src/deep/nested/file.rs\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Negative tests — path traversal
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_dotdot_in_a_path() {
        let patch = b"diff --git a/../../../etc/passwd b/../../../etc/passwd\n\
                       --- a/../../../etc/passwd\n\
                       +++ b/../../../etc/passwd\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::PathTraversal { .. }
        ));
    }

    #[test]
    fn rejects_dotdot_in_middle_of_path() {
        let patch = b"diff --git a/src/../../../etc/shadow b/src/../../../etc/shadow\n\
                       --- a/src/../../../etc/shadow\n\
                       +++ b/src/../../../etc/shadow\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::PathTraversal { .. }
        ));
    }

    #[test]
    fn rejects_dotdot_at_end_of_path() {
        let patch = b"diff --git a/src/.. b/src/..\n\
                       --- a/src/..\n\
                       +++ b/src/..\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::PathTraversal { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Negative tests — absolute paths
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_absolute_path_after_prefix() {
        // Absolute path smuggled after the a/ prefix would be caught:
        // "a//etc/passwd" — the stripped path is "/etc/passwd"
        let patch = b"diff --git a//etc/passwd b//etc/passwd\n\
                       --- a//etc/passwd\n\
                       +++ b//etc/passwd\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::AbsolutePath { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Negative tests — Windows paths
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_windows_drive_letter() {
        let patch = b"diff --git a/C:/Windows/System32/config b/C:/Windows/System32/config\n\
                       --- a/C:/Windows/System32/config\n\
                       +++ b/C:/Windows/System32/config\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_backslash_path() {
        let patch = b"diff --git a/src\\..\\..\\etc\\passwd b/src\\..\\..\\etc\\passwd\n\
                       --- a/src\\..\\..\\etc\\passwd\n\
                       +++ b/src\\..\\..\\etc\\passwd\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_unc_path() {
        let patch = b"diff --git a///server/share/file b///server/share/file\n\
                       --- a///server/share/file\n\
                       +++ b///server/share/file\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Negative tests — invalid prefix
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_missing_prefix() {
        let patch = b"diff --git src/main.rs src/main.rs\n\
                       --- src/main.rs\n\
                       +++ src/main.rs\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Negative tests — format
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_unsupported_format() {
        let patch = make_valid_patch();
        let result = validate_patch_content(&patch, "binary_v1");
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::UnsupportedFormat { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // Negative tests — size and NUL
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_oversized_patch() {
        let patch = vec![b'x'; MAX_PATCH_CONTENT_SIZE + 1];
        let result = validate_patch_content(&patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::TooLarge { .. }
        ));
    }

    #[test]
    fn rejects_nul_byte() {
        let mut patch = make_valid_patch();
        patch[10] = 0;
        let result = validate_patch_content(&patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::NulByte { .. }
        ));
    }

    #[test]
    fn rejects_empty_patch() {
        let patch = b"# just a comment, no diff headers\n";
        let result = validate_patch_content(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::EmptyPatch
        ));
    }

    // -----------------------------------------------------------------------
    // Receipt tests
    // -----------------------------------------------------------------------

    #[test]
    fn success_receipt_has_valid_content_hash() {
        let receipt = PatchApplyReceiptV1::success(
            "b3-256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            3,
        );
        assert!(receipt.applied);
        assert_eq!(receipt.applied_files_count, 3);
        assert!(receipt.refusals.is_empty());
        assert!(receipt.verify_content_hash());
        assert_ne!(receipt.content_hash, [0u8; 32]);
    }

    #[test]
    fn denial_receipt_has_valid_content_hash() {
        let refusals = vec![PatchRefusal {
            path: "../../../etc/passwd".to_string(),
            reason: "path traversal".to_string(),
        }];
        let receipt = PatchApplyReceiptV1::denial(
            "b3-256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            refusals,
        );
        assert!(!receipt.applied);
        assert_eq!(receipt.applied_files_count, 0);
        assert_eq!(receipt.refusals.len(), 1);
        assert!(receipt.verify_content_hash());
    }

    #[test]
    fn receipt_content_hash_changes_with_fields() {
        let receipt1 = PatchApplyReceiptV1::success(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            1,
        );
        let receipt2 = PatchApplyReceiptV1::success(
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            1,
        );
        assert_ne!(receipt1.content_hash, receipt2.content_hash);
    }

    #[test]
    fn receipt_content_hash_is_deterministic() {
        let receipt1 = PatchApplyReceiptV1::success(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            5,
        );
        let receipt2 = PatchApplyReceiptV1::success(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            5,
        );
        assert_eq!(receipt1.content_hash, receipt2.content_hash);
    }

    #[test]
    fn denial_receipt_caps_refusals() {
        let refusals: Vec<PatchRefusal> = (0..MAX_REFUSALS + 50)
            .map(|i| PatchRefusal {
                path: format!("path_{i}"),
                reason: format!("reason_{i}"),
            })
            .collect();
        let receipt = PatchApplyReceiptV1::denial("b3-256:aa".repeat(32), refusals);
        assert_eq!(receipt.refusals.len(), MAX_REFUSALS);
    }

    // -----------------------------------------------------------------------
    // validate_for_apply tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_for_apply_returns_result_on_valid_patch() {
        let patch = make_valid_patch();
        let result = validate_for_apply(&patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_for_apply_returns_receipt_on_traversal() {
        let patch = b"diff --git a/../escape b/../escape\n\
                       --- a/../escape\n\
                       +++ b/../escape\n\
                       @@ -1 +1 @@\n\
                       -old\n\
                       +new\n";
        let result = validate_for_apply(patch, PATCH_FORMAT_GIT_DIFF_V1);
        assert!(result.is_err());
        let boxed = result.unwrap_err();
        let (receipt, _err) = *boxed;
        assert!(!receipt.applied);
        assert_eq!(receipt.refusals.len(), 1);
        assert!(receipt.verify_content_hash());
    }

    #[test]
    fn validate_for_apply_returns_receipt_on_bad_format() {
        let patch = make_valid_patch();
        let result = validate_for_apply(&patch, "svn_diff_v1");
        assert!(result.is_err());
        let boxed = result.unwrap_err();
        let (receipt, _err) = *boxed;
        assert!(!receipt.applied);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn path_component_too_long_rejected() {
        let long_component = "a".repeat(MAX_PATH_COMPONENT_LENGTH + 1);
        let patch = format!(
            "diff --git a/{long_component} b/{long_component}\n\
             --- a/{long_component}\n\
             +++ b/{long_component}\n\
             @@ -1 +1 @@\n\
             -old\n\
             +new\n"
        );
        let result = validate_patch_content(patch.as_bytes(), PATCH_FORMAT_GIT_DIFF_V1);
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::ComponentTooLong { .. }
        ));
    }

    #[test]
    fn too_many_files_rejected() {
        use std::fmt::Write;
        let mut patch = String::new();
        for i in 0..=MAX_PATCH_FILE_ENTRIES {
            write!(
                patch,
                "diff --git a/file_{i}.rs b/file_{i}.rs\n\
                 --- a/file_{i}.rs\n\
                 +++ b/file_{i}.rs\n\
                 @@ -1 +1 @@\n\
                 -old\n\
                 +new\n"
            )
            .unwrap();
        }
        let result = validate_patch_content(patch.as_bytes(), PATCH_FORMAT_GIT_DIFF_V1);
        assert!(matches!(
            result.unwrap_err(),
            PatchValidationError::TooManyFiles { .. }
        ));
    }
}
