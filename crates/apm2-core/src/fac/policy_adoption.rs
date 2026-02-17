// AGENT-AUTHORED (TCK-00561)
//! Policy adoption protocol: broker-admitted `FacPolicyHash` rotation.
//!
//! This module implements the full lifecycle for adopting and rolling back
//! FAC policies in default mode. The broker maintains an admitted policy
//! digest under `$APM2_HOME/private/fac/broker/admitted_policy_root.v1`
//! (digest only; non-secret). Adoption is atomic (temp + rename), with
//! the previous digest retained in `admitted_policy_root.prev.v1` for
//! rollback.
//!
//! Every adoption and rollback emits a durable
//! `PolicyAdoptionReceiptV1` with old/new digests, actor identity, reason
//! string, and a domain-separated BLAKE3 content hash.
//!
//! # Security Invariants
//!
//! - [INV-PADOPT-001] Adoption requires schema + hash validation before
//!   acceptance (no arbitrary file acceptance).
//! - [INV-PADOPT-002] Atomic persistence via temp + rename with fsync
//!   (CTR-2607).
//! - [INV-PADOPT-003] Rollback to `prev` is atomic and emits a receipt.
//! - [INV-PADOPT-004] Workers refuse actuation tokens whose policy binding
//!   mismatches the admitted digest (fail-closed).
//! - [INV-PADOPT-005] Receipt content hash uses domain-separated BLAKE3 with
//!   injective length-prefix framing (CTR-2612).
//! - [INV-PADOPT-006] All string fields are bounded for DoS prevention
//!   (CTR-1303).
//! - [INV-PADOPT-007] File reads are bounded before deserialization (CTR-1603).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::policy::{FacPolicyError, FacPolicyV1, compute_policy_hash, deserialize_policy};

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for the persisted admitted policy root.
pub const ADMITTED_POLICY_ROOT_SCHEMA: &str = "apm2.fac.admitted_policy_root.v1";

/// Schema identifier for policy adoption receipts.
pub const POLICY_ADOPTION_RECEIPT_SCHEMA: &str = "apm2.fac.policy_adoption_receipt.v1";

/// Filename for the current admitted policy root.
const ADMITTED_POLICY_ROOT_FILENAME: &str = "admitted_policy_root.v1.json";

/// Filename for the previous admitted policy root (rollback).
const ADMITTED_POLICY_ROOT_PREV_FILENAME: &str = "admitted_policy_root.prev.v1.json";

/// Domain separator for policy adoption receipt content hashing.
const ADOPTION_RECEIPT_HASH_DOMAIN: &[u8] = b"apm2.fac.policy_adoption_receipt.v1\0";

/// Maximum serialized size of the admitted policy root file (bytes).
/// Protects against memory-exhaustion during bounded reads (CTR-1603).
const MAX_ADMITTED_ROOT_FILE_SIZE: usize = 4_096;

/// Maximum serialized size of a policy adoption receipt (bytes).
const MAX_ADOPTION_RECEIPT_SIZE: usize = 8_192;

/// Maximum length for reason strings in receipts.
const MAX_REASON_LENGTH: usize = 1_024;

/// Maximum length for actor identity strings.
const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum length for schema string fields.
const MAX_SCHEMA_STRING_LENGTH: usize = 128;

/// Directory name under broker root where adoption state is persisted.
const BROKER_SUBDIR: &str = "broker";

/// Receipts directory under fac root.
const RECEIPTS_DIR: &str = "receipts";

// =============================================================================
// Error Types
// =============================================================================

/// Errors produced by policy adoption operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyAdoptionError {
    /// The policy failed schema + hash validation.
    #[error("policy validation failed: {0}")]
    PolicyValidation(#[from] FacPolicyError),

    /// The computed policy hash does not match the expected hash.
    #[error("policy hash mismatch: computed {computed}, expected {expected}")]
    HashMismatch {
        /// Computed hash.
        computed: String,
        /// Expected hash.
        expected: String,
    },

    /// No admitted policy root exists (nothing to show or rollback).
    #[error("no admitted policy root found at {path}")]
    NoAdmittedRoot {
        /// Path where the admitted root was expected.
        path: String,
    },

    /// No previous policy root exists (nothing to roll back to).
    #[error("no previous policy root found at {path}; rollback not possible")]
    NoPreviousRoot {
        /// Path where the previous root was expected.
        path: String,
    },

    /// Persistence operation failed.
    #[error("persistence error: {detail}")]
    Persistence {
        /// Detail about the persistence failure.
        detail: String,
    },

    /// I/O error during read.
    #[error("I/O error: {detail}")]
    Io {
        /// Detail.
        detail: String,
    },

    /// Serialization error.
    #[error("serialization error: {detail}")]
    Serialization {
        /// Detail.
        detail: String,
    },

    /// File exceeds the maximum allowed size (bounded read).
    #[error("file size {size} exceeds maximum {max}")]
    FileTooLarge {
        /// Actual size.
        size: u64,
        /// Maximum allowed size.
        max: usize,
    },

    /// String field exceeds allowed length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum length.
        max: usize,
    },

    /// The new policy hash is the same as the currently admitted hash
    /// (no-op adoption).
    #[error("policy already admitted with hash {hash}")]
    AlreadyAdmitted {
        /// The hash that is already admitted.
        hash: String,
    },
}

// =============================================================================
// Types
// =============================================================================

/// Persisted admitted policy root. Stored as a small JSON file containing
/// only the admitted policy hash and schema metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedPolicyRootV1 {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// The BLAKE3 policy hash string (e.g. `b3-256:<hex>`).
    pub admitted_policy_hash: String,
    /// Unix timestamp (seconds) of the adoption event.
    pub adopted_at_unix_secs: u64,
    /// Actor who performed the adoption.
    pub actor_id: String,
}

impl AdmittedPolicyRootV1 {
    /// Validate all field bounds.
    fn validate(&self) -> Result<(), PolicyAdoptionError> {
        validate_bounded_string("schema", &self.schema, MAX_SCHEMA_STRING_LENGTH)?;
        validate_bounded_string(
            "schema_version",
            &self.schema_version,
            MAX_SCHEMA_STRING_LENGTH,
        )?;
        validate_bounded_string(
            "admitted_policy_hash",
            &self.admitted_policy_hash,
            MAX_SCHEMA_STRING_LENGTH,
        )?;
        validate_bounded_string("actor_id", &self.actor_id, MAX_ACTOR_ID_LENGTH)?;
        Ok(())
    }
}

/// The action performed in an adoption receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAdoptionAction {
    /// A new policy was adopted.
    Adopt,
    /// The policy was rolled back to a previous version.
    Rollback,
}

impl std::fmt::Display for PolicyAdoptionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adopt => write!(f, "adopt"),
            Self::Rollback => write!(f, "rollback"),
        }
    }
}

/// Durable receipt for policy adoption/rollback events.
///
/// Contains `old_digest`, `new_digest`, actor identity, reason string,
/// and a domain-separated BLAKE3 content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAdoptionReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Action performed.
    pub action: PolicyAdoptionAction,
    /// Previous admitted policy hash (empty string if none).
    pub old_digest: String,
    /// New admitted policy hash.
    pub new_digest: String,
    /// Actor who performed the operation (e.g. "operator:local").
    pub actor_id: String,
    /// Human-readable reason for the operation.
    pub reason: String,
    /// Unix timestamp (seconds) of the event.
    pub timestamp_unix_secs: u64,
    /// BLAKE3 content hash of this receipt (domain-separated).
    pub content_hash: String,
}

impl PolicyAdoptionReceiptV1 {
    /// Validate all field bounds.
    fn validate(&self) -> Result<(), PolicyAdoptionError> {
        validate_bounded_string("schema", &self.schema, MAX_SCHEMA_STRING_LENGTH)?;
        validate_bounded_string(
            "schema_version",
            &self.schema_version,
            MAX_SCHEMA_STRING_LENGTH,
        )?;
        validate_bounded_string("old_digest", &self.old_digest, MAX_SCHEMA_STRING_LENGTH)?;
        validate_bounded_string("new_digest", &self.new_digest, MAX_SCHEMA_STRING_LENGTH)?;
        validate_bounded_string("actor_id", &self.actor_id, MAX_ACTOR_ID_LENGTH)?;
        validate_bounded_string("reason", &self.reason, MAX_REASON_LENGTH)?;
        validate_bounded_string("content_hash", &self.content_hash, MAX_SCHEMA_STRING_LENGTH)?;
        Ok(())
    }
}

// =============================================================================
// Core Functions
// =============================================================================

/// Returns the path to the broker directory under fac root.
fn broker_dir(fac_root: &Path) -> PathBuf {
    fac_root.join(BROKER_SUBDIR)
}

/// Returns the path to the current admitted policy root file.
fn admitted_root_path(fac_root: &Path) -> PathBuf {
    broker_dir(fac_root).join(ADMITTED_POLICY_ROOT_FILENAME)
}

/// Returns the path to the previous admitted policy root file.
fn prev_root_path(fac_root: &Path) -> PathBuf {
    broker_dir(fac_root).join(ADMITTED_POLICY_ROOT_PREV_FILENAME)
}

/// Returns the receipts directory.
fn receipts_dir(fac_root: &Path) -> PathBuf {
    fac_root.join(RECEIPTS_DIR)
}

/// Read the current admitted policy root, if it exists.
///
/// # Errors
///
/// Returns [`PolicyAdoptionError::Io`] on I/O failure,
/// [`PolicyAdoptionError::FileTooLarge`] if the file exceeds bounds,
/// [`PolicyAdoptionError::NoAdmittedRoot`] if no admitted root exists.
pub fn load_admitted_policy_root(
    fac_root: &Path,
) -> Result<AdmittedPolicyRootV1, PolicyAdoptionError> {
    let path = admitted_root_path(fac_root);
    load_bounded_json::<AdmittedPolicyRootV1>(&path, MAX_ADMITTED_ROOT_FILE_SIZE).and_then(|r| {
        r.validate()?;
        Ok(r)
    })
}

/// Check whether a given policy hash matches the currently admitted
/// policy root.
///
/// Returns `true` if the admitted root exists and its hash matches
/// (constant-time comparison). Returns `false` if no admitted root
/// exists or if the hashes differ.
#[must_use]
pub fn is_policy_hash_admitted(fac_root: &Path, policy_hash: &str) -> bool {
    match load_admitted_policy_root(fac_root) {
        Ok(root) => {
            let admitted_bytes = root.admitted_policy_hash.as_bytes();
            let check_bytes = policy_hash.as_bytes();
            if admitted_bytes.len() != check_bytes.len() {
                return false;
            }
            bool::from(admitted_bytes.ct_eq(check_bytes))
        },
        Err(_) => false,
    }
}

/// Validate a policy from raw bytes: deserialize, validate schema +
/// fields, compute hash.
///
/// Returns the validated policy and its hash string on success.
///
/// # Errors
///
/// Returns [`PolicyAdoptionError`] on validation failure.
pub fn validate_policy_bytes(bytes: &[u8]) -> Result<(FacPolicyV1, String), PolicyAdoptionError> {
    let policy = deserialize_policy(bytes)?;
    let hash = compute_policy_hash(&policy)
        .map_err(|e| PolicyAdoptionError::Serialization { detail: e })?;
    Ok((policy, hash))
}

/// Adopt a new policy: validate, persist the admitted digest atomically,
/// and emit a durable receipt.
///
/// 1. Validates the policy (schema + bounds).
/// 2. Computes its hash.
/// 3. Checks against the current admitted root (rejects no-op adoption).
/// 4. Persists the new admitted root via temp + rename (CTR-2607).
/// 5. Retains the previous root in `admitted_policy_root.prev.v1.json`.
/// 6. Emits a `PolicyAdoptionReceiptV1`.
///
/// # Errors
///
/// Returns [`PolicyAdoptionError`] on validation, persistence, or
/// serialization failures.
pub fn adopt_policy(
    fac_root: &Path,
    policy_bytes: &[u8],
    actor_id: &str,
    reason: &str,
) -> Result<(AdmittedPolicyRootV1, PolicyAdoptionReceiptV1), PolicyAdoptionError> {
    validate_bounded_string("actor_id", actor_id, MAX_ACTOR_ID_LENGTH)?;
    validate_bounded_string("reason", reason, MAX_REASON_LENGTH)?;

    // Step 1-2: validate and compute hash.
    let (_policy, policy_hash) = validate_policy_bytes(policy_bytes)?;

    // Step 3: load current admitted root and check for no-op.
    let old_digest = match load_admitted_policy_root(fac_root) {
        Ok(root) => {
            let old_bytes = root.admitted_policy_hash.as_bytes();
            let new_bytes = policy_hash.as_bytes();
            if old_bytes.len() == new_bytes.len() && bool::from(old_bytes.ct_eq(new_bytes)) {
                return Err(PolicyAdoptionError::AlreadyAdmitted { hash: policy_hash });
            }
            root.admitted_policy_hash
        },
        Err(PolicyAdoptionError::NoAdmittedRoot { .. }) => String::new(),
        Err(e) => return Err(e),
    };

    // CTR-2501 deviation: `SystemTime::now()` for adoption timestamp
    // (wall-clock anchored audit trail). Documented inline.
    #[allow(clippy::disallowed_methods)]
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Step 4-5: persist new admitted root atomically.
    let new_root = AdmittedPolicyRootV1 {
        schema: ADMITTED_POLICY_ROOT_SCHEMA.to_string(),
        schema_version: "1.0.0".to_string(),
        admitted_policy_hash: policy_hash.clone(),
        adopted_at_unix_secs: now_secs,
        actor_id: actor_id.to_string(),
    };
    new_root.validate()?;

    persist_admitted_root_atomic(fac_root, &new_root)?;

    // Step 6: emit receipt.
    let receipt = build_and_persist_receipt(
        fac_root,
        PolicyAdoptionAction::Adopt,
        &old_digest,
        &policy_hash,
        actor_id,
        reason,
        now_secs,
    )?;

    Ok((new_root, receipt))
}

/// Rollback to the previous admitted policy root.
///
/// 1. Loads the previous admitted root from
///    `admitted_policy_root.prev.v1.json`.
/// 2. Persists it as the current root via temp + rename.
/// 3. Emits a rollback receipt.
///
/// # Errors
///
/// Returns [`PolicyAdoptionError`] if no previous root exists, or on
/// persistence failures.
pub fn rollback_policy(
    fac_root: &Path,
    actor_id: &str,
    reason: &str,
) -> Result<(AdmittedPolicyRootV1, PolicyAdoptionReceiptV1), PolicyAdoptionError> {
    validate_bounded_string("actor_id", actor_id, MAX_ACTOR_ID_LENGTH)?;
    validate_bounded_string("reason", reason, MAX_REASON_LENGTH)?;

    // Load current root (to record old_digest).
    let current_digest = match load_admitted_policy_root(fac_root) {
        Ok(root) => root.admitted_policy_hash,
        Err(PolicyAdoptionError::NoAdmittedRoot { .. }) => String::new(),
        Err(e) => return Err(e),
    };

    // Load previous root.
    let prev_path = prev_root_path(fac_root);
    let prev_root =
        load_bounded_json::<AdmittedPolicyRootV1>(&prev_path, MAX_ADMITTED_ROOT_FILE_SIZE)
            .map_err(|_| PolicyAdoptionError::NoPreviousRoot {
                path: prev_path.display().to_string(),
            })?;
    prev_root.validate()?;

    // CTR-2501 deviation: wall-clock anchored audit trail for rollback.
    #[allow(clippy::disallowed_methods)]
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the rolled-back root with fresh timestamp.
    let rolled_back_root = AdmittedPolicyRootV1 {
        schema: ADMITTED_POLICY_ROOT_SCHEMA.to_string(),
        schema_version: "1.0.0".to_string(),
        admitted_policy_hash: prev_root.admitted_policy_hash.clone(),
        adopted_at_unix_secs: now_secs,
        actor_id: actor_id.to_string(),
    };
    rolled_back_root.validate()?;

    // Persist as current root (atomic).
    // Note: we do NOT update prev — the prev file stays as the last
    // rollback point. A subsequent adopt will overwrite prev with the
    // current root.
    persist_admitted_root_atomic(fac_root, &rolled_back_root)?;

    // Emit rollback receipt.
    let receipt = build_and_persist_receipt(
        fac_root,
        PolicyAdoptionAction::Rollback,
        &current_digest,
        &prev_root.admitted_policy_hash,
        actor_id,
        reason,
        now_secs,
    )?;

    Ok((rolled_back_root, receipt))
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Reject symlinks on a path. Uses `symlink_metadata` to detect symlinks
/// without following them (closing the TOCTOU gap for symlink-following
/// writes, per f-722-security-1771347582402872-0).
///
/// Returns `Ok(())` if the path does not exist (caller may be about to
/// create it) or if it is a regular file/directory. Returns
/// `Err(PolicyAdoptionError::Persistence)` if the path is a symlink.
fn reject_symlink(path: &Path) -> Result<(), PolicyAdoptionError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(PolicyAdoptionError::Persistence {
                    detail: format!(
                        "refusing to operate on symlink at {} (security: symlink-following rejected)",
                        path.display()
                    ),
                });
            }
            Ok(())
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PolicyAdoptionError::Persistence {
            detail: format!("cannot stat {}: {e}", path.display()),
        }),
    }
}

/// Write bytes to a file atomically via `NamedTempFile` + fsync + persist.
///
/// Uses `tempfile::NamedTempFile::new_in(dir)` which creates the temp file
/// with a random name and `O_EXCL` flags, eliminating the symlink TOCTOU
/// race that existed with predictable temp paths
/// (f-722-security-1771348924639728-0, RSK-1502).
///
/// Sets permissions to 0o600 on Unix before persist.
fn atomic_write_file(
    dir: &Path,
    _temp_name: &str,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), PolicyAdoptionError> {
    // Reject symlinks on the final destination before rename.
    reject_symlink(final_path)?;

    // NamedTempFile::new_in uses O_EXCL + random name: no symlink TOCTOU.
    let mut named_temp =
        tempfile::NamedTempFile::new_in(dir).map_err(|e| PolicyAdoptionError::Persistence {
            detail: format!("cannot create NamedTempFile in {}: {e}", dir.display()),
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        named_temp.as_file().set_permissions(perms).map_err(|e| {
            PolicyAdoptionError::Persistence {
                detail: format!("cannot set permissions on temp file: {e}"),
            }
        })?;
    }

    named_temp
        .as_file_mut()
        .write_all(bytes)
        .map_err(|e| PolicyAdoptionError::Persistence {
            detail: format!("cannot write temp file: {e}"),
        })?;
    named_temp
        .as_file()
        .sync_all()
        .map_err(|e| PolicyAdoptionError::Persistence {
            detail: format!("cannot sync temp file: {e}"),
        })?;

    // Atomic rename to final destination via persist().
    named_temp
        .persist(final_path)
        .map_err(|e| PolicyAdoptionError::Persistence {
            detail: format!("cannot persist temp file -> {}: {e}", final_path.display()),
        })?;

    Ok(())
}

/// Persist the admitted policy root atomically. Snapshots the current
/// file to `.prev` via temp+rename before writing the new file.
///
/// All paths are validated against symlinks before writes to close the
/// TOCTOU gap identified in f-722-security-1771347582402872-0.
///
/// The prev-file backup uses temp+rename (not `fs::copy`) to maintain
/// atomic checkpoint semantics, per f-722-code_quality-1771347577305561-0.
fn persist_admitted_root_atomic(
    fac_root: &Path,
    root: &AdmittedPolicyRootV1,
) -> Result<(), PolicyAdoptionError> {
    let dir = broker_dir(fac_root);
    fs::create_dir_all(&dir).map_err(|e| PolicyAdoptionError::Persistence {
        detail: format!("cannot create broker dir {}: {e}", dir.display()),
    })?;

    // Validate the broker directory itself is not a symlink.
    reject_symlink(&dir)?;

    let current_path = admitted_root_path(fac_root);
    let prev_path_val = prev_root_path(fac_root);

    // If a current root exists, snapshot it to prev via temp+rename
    // (atomic checkpoint, not fs::copy which can produce partial writes).
    // Uses load_bounded_json's open-once pattern for bounded reads
    // (f-722-security-1771348934962474-0: prevents memory exhaustion if
    // the root file was maliciously replaced with a massive file).
    reject_symlink(&current_path)?;
    if current_path.exists() {
        let current_root: AdmittedPolicyRootV1 =
            load_bounded_json(&current_path, MAX_ADMITTED_ROOT_FILE_SIZE)?;
        let current_bytes = serde_json::to_vec_pretty(&current_root).map_err(|e| {
            PolicyAdoptionError::Serialization {
                detail: format!("cannot re-serialize current root for prev snapshot: {e}"),
            }
        })?;
        atomic_write_file(
            &dir,
            ".admitted_policy_root.prev.v1.json.tmp",
            &prev_path_val,
            &current_bytes,
        )?;
    }

    // Write new root to temp file, then atomic rename.
    let bytes =
        serde_json::to_vec_pretty(root).map_err(|e| PolicyAdoptionError::Serialization {
            detail: format!("cannot serialize admitted root: {e}"),
        })?;

    atomic_write_file(
        &dir,
        ".admitted_policy_root.v1.json.tmp",
        &current_path,
        &bytes,
    )?;

    // Sync directory for durability.
    let dir_handle = fs::File::open(&dir).map_err(|e| PolicyAdoptionError::Persistence {
        detail: format!("cannot open broker dir for sync: {e}"),
    })?;
    dir_handle
        .sync_all()
        .map_err(|e| PolicyAdoptionError::Persistence {
            detail: format!("cannot sync broker dir: {e}"),
        })?;

    Ok(())
}

/// Build and persist a policy adoption receipt.
fn build_and_persist_receipt(
    fac_root: &Path,
    action: PolicyAdoptionAction,
    old_digest: &str,
    new_digest: &str,
    actor_id: &str,
    reason: &str,
    timestamp_unix_secs: u64,
) -> Result<PolicyAdoptionReceiptV1, PolicyAdoptionError> {
    let content_hash = compute_adoption_receipt_hash(
        action,
        old_digest,
        new_digest,
        actor_id,
        reason,
        timestamp_unix_secs,
    );

    let receipt = PolicyAdoptionReceiptV1 {
        schema: POLICY_ADOPTION_RECEIPT_SCHEMA.to_string(),
        schema_version: "1.0.0".to_string(),
        action,
        old_digest: old_digest.to_string(),
        new_digest: new_digest.to_string(),
        actor_id: actor_id.to_string(),
        reason: reason.to_string(),
        timestamp_unix_secs,
        content_hash: content_hash.clone(),
    };
    receipt.validate()?;

    // Persist receipt to receipts directory.
    let receipts = receipts_dir(fac_root);
    fs::create_dir_all(&receipts).map_err(|e| PolicyAdoptionError::Persistence {
        detail: format!("cannot create receipts dir {}: {e}", receipts.display()),
    })?;

    // Validate receipts directory is not a symlink.
    reject_symlink(&receipts)?;

    // Use content hash (without prefix) as filename.
    let hash_suffix = content_hash
        .strip_prefix("b3-256:")
        .unwrap_or(&content_hash);
    let receipt_filename = format!("policy_{action}_{hash_suffix}.json");
    let receipt_path = receipts.join(&receipt_filename);
    let temp_receipt_name = format!(".{receipt_filename}.tmp");

    let receipt_bytes =
        serde_json::to_vec_pretty(&receipt).map_err(|e| PolicyAdoptionError::Serialization {
            detail: format!("cannot serialize adoption receipt: {e}"),
        })?;

    // Use atomic_write_file which validates symlinks and does temp+rename.
    atomic_write_file(&receipts, &temp_receipt_name, &receipt_path, &receipt_bytes)?;

    // Sync receipts directory for durability (CTR-2607, CTR-1502).
    // Ensures the directory entry from the atomic rename is persisted
    // (f-722-security-1771348938905787-0).
    let receipts_dir_handle =
        fs::File::open(&receipts).map_err(|e| PolicyAdoptionError::Persistence {
            detail: format!("cannot open receipts dir for sync: {e}"),
        })?;
    receipts_dir_handle
        .sync_all()
        .map_err(|e| PolicyAdoptionError::Persistence {
            detail: format!("cannot sync receipts dir: {e}"),
        })?;

    Ok(receipt)
}

/// Compute domain-separated BLAKE3 content hash for a policy adoption
/// receipt. Uses injective u64 length-prefix framing per INV-PADOPT-005.
fn compute_adoption_receipt_hash(
    action: PolicyAdoptionAction,
    old_digest: &str,
    new_digest: &str,
    actor_id: &str,
    reason: &str,
    timestamp_unix_secs: u64,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ADOPTION_RECEIPT_HASH_DOMAIN);

    // Injective framing: length-prefix each variable-length field.
    let action_str = action.to_string();
    hasher.update(&(action_str.len() as u64).to_le_bytes());
    hasher.update(action_str.as_bytes());

    hasher.update(&(old_digest.len() as u64).to_le_bytes());
    hasher.update(old_digest.as_bytes());

    hasher.update(&(new_digest.len() as u64).to_le_bytes());
    hasher.update(new_digest.as_bytes());

    hasher.update(&(actor_id.len() as u64).to_le_bytes());
    hasher.update(actor_id.as_bytes());

    hasher.update(&(reason.len() as u64).to_le_bytes());
    hasher.update(reason.as_bytes());

    hasher.update(&timestamp_unix_secs.to_le_bytes());

    format!("b3-256:{}", hasher.finalize().to_hex())
}

/// Read and deserialize a bounded JSON file using the open-once pattern.
///
/// Opens with `O_NOFOLLOW | O_CLOEXEC` (Unix) to atomically refuse symlinks
/// at the kernel level, then verifies via `fstat` (handle-based) that the fd
/// is a regular file. Reads at most `max_size + 1` bytes via `take()` to
/// enforce the size limit without a TOCTOU gap between stat and read
/// (f-722-security-1771348928218169-0, CTR-1603, INV-PADOPT-007).
fn load_bounded_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    max_size: usize,
) -> Result<T, PolicyAdoptionError> {
    use std::fs::OpenOptions;
    use std::io::Read as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    // Open-once: O_NOFOLLOW rejects symlinks at open(2), no TOCTOU gap.
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PolicyAdoptionError::NoAdmittedRoot {
                path: path.display().to_string(),
            }
        } else {
            PolicyAdoptionError::Io {
                detail: format!(
                    "cannot open {} (symlink rejected fail-closed): {e}",
                    path.display()
                ),
            }
        }
    })?;

    // fstat on the opened fd -- not the path -- to verify regular file.
    // This cannot race because the fd is already bound to the inode.
    let metadata = file.metadata().map_err(|e| PolicyAdoptionError::Io {
        detail: format!("cannot fstat {}: {e}", path.display()),
    })?;
    if !metadata.is_file() {
        return Err(PolicyAdoptionError::Io {
            detail: format!("not a regular file (fail-closed): {}", path.display()),
        });
    }

    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(PolicyAdoptionError::FileTooLarge {
            size: file_size,
            max: max_size,
        });
    }

    // Bounded read via take() -- never reads more than max_size + 1 bytes.
    let limit = (max_size as u64).saturating_add(1);
    let mut bounded_reader = file.take(limit);
    #[allow(clippy::cast_possible_truncation)]
    let mut bytes = Vec::with_capacity((file_size as usize).min(max_size));
    bounded_reader
        .read_to_end(&mut bytes)
        .map_err(|e| PolicyAdoptionError::Io {
            detail: format!("cannot read {}: {e}", path.display()),
        })?;
    if bytes.len() > max_size {
        return Err(PolicyAdoptionError::FileTooLarge {
            size: bytes.len() as u64,
            max: max_size,
        });
    }

    serde_json::from_slice(&bytes).map_err(|e| PolicyAdoptionError::Serialization {
        detail: format!("cannot parse {}: {e}", path.display()),
    })
}

/// Validate that a string field does not exceed the allowed length.
const fn validate_bounded_string(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), PolicyAdoptionError> {
    if value.len() > max {
        return Err(PolicyAdoptionError::StringTooLong {
            field,
            actual: value.len(),
            max,
        });
    }
    Ok(())
}

/// Deserialize and validate a policy adoption receipt from bytes.
///
/// # Errors
///
/// Returns [`PolicyAdoptionError`] if the receipt exceeds size bounds,
/// fails to parse, or has invalid field values.
pub fn deserialize_adoption_receipt(
    bytes: &[u8],
) -> Result<PolicyAdoptionReceiptV1, PolicyAdoptionError> {
    if bytes.len() > MAX_ADOPTION_RECEIPT_SIZE {
        return Err(PolicyAdoptionError::FileTooLarge {
            size: bytes.len() as u64,
            max: MAX_ADOPTION_RECEIPT_SIZE,
        });
    }
    let receipt: PolicyAdoptionReceiptV1 =
        serde_json::from_slice(bytes).map_err(|e| PolicyAdoptionError::Serialization {
            detail: format!("cannot parse adoption receipt: {e}"),
        })?;
    receipt.validate()?;
    Ok(receipt)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::fac::policy::MAX_POLICY_SIZE;

    fn make_default_policy_bytes() -> Vec<u8> {
        let policy = FacPolicyV1::default_policy();
        serde_json::to_vec_pretty(&policy).expect("serialize default policy")
    }

    #[test]
    fn test_adopt_policy_creates_admitted_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        let (root, receipt) = adopt_policy(
            fac_root,
            &policy_bytes,
            "operator:local",
            "initial policy adoption",
        )
        .expect("adopt");

        assert_eq!(root.schema, ADMITTED_POLICY_ROOT_SCHEMA);
        assert!(!root.admitted_policy_hash.is_empty());
        assert_eq!(receipt.action, PolicyAdoptionAction::Adopt);
        assert!(receipt.old_digest.is_empty());
        assert_eq!(receipt.new_digest, root.admitted_policy_hash);
        assert_eq!(receipt.actor_id, "operator:local");

        // Verify the file exists.
        let loaded = load_admitted_policy_root(fac_root).expect("load admitted root");
        assert_eq!(loaded.admitted_policy_hash, root.admitted_policy_hash);
    }

    #[test]
    fn test_adopt_policy_rotates_to_prev() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        let (first_root, _) = adopt_policy(fac_root, &policy_bytes, "operator:local", "initial")
            .expect("first adopt");

        // Mutate policy to get a different hash.
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");

        let (second_root, receipt) =
            adopt_policy(fac_root, &second_bytes, "operator:local", "update policy")
                .expect("second adopt");

        assert_ne!(
            first_root.admitted_policy_hash,
            second_root.admitted_policy_hash
        );
        assert_eq!(receipt.old_digest, first_root.admitted_policy_hash);
        assert_eq!(receipt.new_digest, second_root.admitted_policy_hash);

        // Verify prev file exists with first root's hash.
        let prev = load_bounded_json::<AdmittedPolicyRootV1>(
            &prev_root_path(fac_root),
            MAX_ADMITTED_ROOT_FILE_SIZE,
        )
        .expect("load prev");
        assert_eq!(prev.admitted_policy_hash, first_root.admitted_policy_hash);
    }

    #[test]
    fn test_adopt_policy_rejects_duplicate() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        adopt_policy(fac_root, &policy_bytes, "operator:local", "initial").expect("first adopt");

        let result = adopt_policy(fac_root, &policy_bytes, "operator:local", "duplicate");
        assert!(
            matches!(result, Err(PolicyAdoptionError::AlreadyAdmitted { .. })),
            "should reject duplicate adoption, got: {result:?}"
        );
    }

    #[test]
    fn test_rollback_restores_previous() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        let (first_root, _) = adopt_policy(fac_root, &policy_bytes, "operator:local", "initial")
            .expect("first adopt");

        // Adopt a different policy.
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let (second_root, _) = adopt_policy(fac_root, &second_bytes, "operator:local", "update")
            .expect("second adopt");

        // Rollback.
        let (rolled_back, receipt) =
            rollback_policy(fac_root, "operator:local", "reverting due to issue")
                .expect("rollback");

        assert_eq!(
            rolled_back.admitted_policy_hash,
            first_root.admitted_policy_hash
        );
        assert_eq!(receipt.action, PolicyAdoptionAction::Rollback);
        assert_eq!(receipt.old_digest, second_root.admitted_policy_hash);
        assert_eq!(receipt.new_digest, first_root.admitted_policy_hash);

        // Verify current root is back to first.
        let current = load_admitted_policy_root(fac_root).expect("load current");
        assert_eq!(
            current.admitted_policy_hash,
            first_root.admitted_policy_hash
        );
    }

    #[test]
    fn test_rollback_fails_without_previous() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        adopt_policy(fac_root, &policy_bytes, "operator:local", "initial").expect("adopt");

        // Remove the prev file.
        let _ = fs::remove_file(prev_root_path(fac_root));

        let result = rollback_policy(fac_root, "operator:local", "rollback");
        assert!(
            matches!(result, Err(PolicyAdoptionError::NoPreviousRoot { .. })),
            "should fail without previous root, got: {result:?}"
        );
    }

    #[test]
    fn test_is_policy_hash_admitted_matches() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        let (root, _) =
            adopt_policy(fac_root, &policy_bytes, "operator:local", "initial").expect("adopt");

        assert!(is_policy_hash_admitted(
            fac_root,
            &root.admitted_policy_hash
        ));
        assert!(!is_policy_hash_admitted(
            fac_root,
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_is_policy_hash_admitted_false_when_no_root() {
        let tmp = tempdir().expect("tempdir");
        assert!(!is_policy_hash_admitted(tmp.path(), "b3-256:aa"));
    }

    #[test]
    fn test_validate_policy_bytes_succeeds() {
        let policy_bytes = make_default_policy_bytes();
        let (policy, hash) = validate_policy_bytes(&policy_bytes).expect("validate");
        assert_eq!(policy.schema, "apm2.fac.policy.v1");
        assert!(hash.starts_with("b3-256:"));
    }

    #[test]
    fn test_validate_policy_bytes_rejects_invalid() {
        let result = validate_policy_bytes(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_policy_bytes_rejects_oversized() {
        let oversized = vec![b' '; MAX_POLICY_SIZE + 1];
        let result = validate_policy_bytes(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn test_adoption_receipt_hash_is_deterministic() {
        let h1 = compute_adoption_receipt_hash(
            PolicyAdoptionAction::Adopt,
            "old",
            "new",
            "actor",
            "reason",
            12345,
        );
        let h2 = compute_adoption_receipt_hash(
            PolicyAdoptionAction::Adopt,
            "old",
            "new",
            "actor",
            "reason",
            12345,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_adoption_receipt_hash_changes_on_action() {
        let h1 = compute_adoption_receipt_hash(
            PolicyAdoptionAction::Adopt,
            "old",
            "new",
            "actor",
            "reason",
            12345,
        );
        let h2 = compute_adoption_receipt_hash(
            PolicyAdoptionAction::Rollback,
            "old",
            "new",
            "actor",
            "reason",
            12345,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_adoption_receipt_roundtrip() {
        let receipt = PolicyAdoptionReceiptV1 {
            schema: POLICY_ADOPTION_RECEIPT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            action: PolicyAdoptionAction::Adopt,
            old_digest: String::new(),
            new_digest: "b3-256:aabbccdd".to_string(),
            actor_id: "operator:local".to_string(),
            reason: "test".to_string(),
            timestamp_unix_secs: 1000,
            content_hash: "b3-256:11223344".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&receipt).expect("serialize");
        let restored = deserialize_adoption_receipt(&bytes).expect("deserialize");
        assert_eq!(receipt, restored);
    }

    #[test]
    fn test_bounded_string_rejects_oversized() {
        let result = validate_bounded_string(
            "test",
            &"x".repeat(MAX_REASON_LENGTH + 1),
            MAX_REASON_LENGTH,
        );
        assert!(matches!(
            result,
            Err(PolicyAdoptionError::StringTooLong { .. })
        ));
    }

    #[test]
    fn test_adopt_rejects_oversized_actor() {
        let tmp = tempdir().expect("tempdir");
        let policy_bytes = make_default_policy_bytes();
        let long_actor = "x".repeat(MAX_ACTOR_ID_LENGTH + 1);
        let result = adopt_policy(tmp.path(), &policy_bytes, &long_actor, "reason");
        assert!(matches!(
            result,
            Err(PolicyAdoptionError::StringTooLong {
                field: "actor_id",
                ..
            })
        ));
    }

    #[test]
    fn test_adopt_rejects_oversized_reason() {
        let tmp = tempdir().expect("tempdir");
        let policy_bytes = make_default_policy_bytes();
        let long_reason = "x".repeat(MAX_REASON_LENGTH + 1);
        let result = adopt_policy(tmp.path(), &policy_bytes, "actor", &long_reason);
        assert!(matches!(
            result,
            Err(PolicyAdoptionError::StringTooLong {
                field: "reason",
                ..
            })
        ));
    }

    #[test]
    fn test_load_admitted_root_rejects_symlink() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let broker = broker_dir(fac_root);
        fs::create_dir_all(&broker).expect("create broker dir");

        // Create a real file and a symlink to it.
        let real_file = tmp.path().join("real_root.json");
        let root = AdmittedPolicyRootV1 {
            schema: ADMITTED_POLICY_ROOT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            admitted_policy_hash: "b3-256:aa".to_string(),
            adopted_at_unix_secs: 0,
            actor_id: "test".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&root).expect("serialize");
        fs::write(&real_file, &bytes).expect("write real file");

        #[cfg(unix)]
        {
            let symlink_path = admitted_root_path(fac_root);
            std::os::unix::fs::symlink(&real_file, &symlink_path).expect("create symlink");

            let result = load_admitted_policy_root(fac_root);
            assert!(result.is_err(), "should reject symlink, got: {result:?}");
        }
    }

    #[test]
    fn test_receipt_persisted_to_receipts_dir() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        let (_, receipt) =
            adopt_policy(fac_root, &policy_bytes, "operator:local", "test").expect("adopt");

        let receipts = receipts_dir(fac_root);
        assert!(receipts.exists(), "receipts directory should exist");

        // Find the receipt file.
        let entries: Vec<_> = fs::read_dir(&receipts)
            .expect("read receipts dir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one receipt should be persisted");

        let receipt_bytes = fs::read(entries[0].path()).expect("read receipt");
        let loaded = deserialize_adoption_receipt(&receipt_bytes).expect("deserialize");
        assert_eq!(loaded.content_hash, receipt.content_hash);
    }

    #[test]
    fn test_no_admitted_root_returns_error() {
        let tmp = tempdir().expect("tempdir");
        let result = load_admitted_policy_root(tmp.path());
        assert!(
            matches!(result, Err(PolicyAdoptionError::NoAdmittedRoot { .. })),
            "should return NoAdmittedRoot, got: {result:?}"
        );
    }

    /// Worker mismatch simulation: test that `is_policy_hash_admitted`
    /// returns false for a non-matching hash (fail-closed behavior that
    /// workers rely on, INV-PADOPT-004).
    #[test]
    fn test_worker_refuses_mismatched_policy() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        adopt_policy(fac_root, &policy_bytes, "operator:local", "initial").expect("adopt");

        // Simulate a worker checking with a wrong hash.
        let wrong_hash = "b3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(
            !is_policy_hash_admitted(fac_root, wrong_hash),
            "worker must refuse mismatched policy (fail-closed, INV-PADOPT-004)"
        );
    }

    // =====================================================================
    // Symlink rejection tests (f-722-security-1771347582402872-0)
    // =====================================================================

    /// Verify that `reject_symlink` correctly identifies symlinks.
    #[cfg(unix)]
    #[test]
    fn test_reject_symlink_on_regular_file() {
        let tmp = tempdir().expect("tempdir");
        let real = tmp.path().join("real.txt");
        fs::write(&real, b"data").expect("write");
        assert!(reject_symlink(&real).is_ok(), "regular file should pass");

        let link = tmp.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = reject_symlink(&link);
        assert!(err.is_err(), "symlink should be rejected");
    }

    /// Verify that adoption rejects symlinked current admitted root.
    #[cfg(unix)]
    #[test]
    fn test_adopt_rejects_symlink_on_current_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        // First adoption to create a real current root.
        adopt_policy(fac_root, &policy_bytes, "operator:local", "initial").expect("first adopt");

        // Replace current root with a symlink.
        let current = admitted_root_path(fac_root);
        let target = tmp.path().join("evil_target.json");
        fs::copy(&current, &target).expect("copy to target");
        fs::remove_file(&current).expect("remove current");
        std::os::unix::fs::symlink(&target, &current).expect("create symlink");

        // Second adoption should fail because current root is a symlink.
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let result = adopt_policy(fac_root, &second_bytes, "operator:local", "update");
        // The symlink is rejected either at load time or at persist time.
        assert!(result.is_err(), "should reject symlinked current root");
    }

    /// Verify that adoption rejects symlinked prev root path.
    #[cfg(unix)]
    #[test]
    fn test_adopt_rejects_symlink_on_prev_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        // First adoption.
        adopt_policy(fac_root, &policy_bytes, "operator:local", "initial").expect("first adopt");

        // Place a symlink at the prev path before second adoption.
        let prev = prev_root_path(fac_root);
        let target = tmp.path().join("evil_prev.json");
        fs::write(&target, b"{}").expect("write target");
        // Remove the real prev if it exists.
        let _ = fs::remove_file(&prev);
        std::os::unix::fs::symlink(&target, &prev).expect("create symlink at prev");

        // Second adoption should fail because prev path is a symlink.
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let result = adopt_policy(fac_root, &second_bytes, "operator:local", "update");
        assert!(
            result.is_err(),
            "should reject symlinked prev root path, got: {result:?}"
        );
    }

    /// Verify that receipt persistence rejects symlinked receipts directory.
    #[cfg(unix)]
    #[test]
    fn test_adopt_rejects_symlink_on_receipts_dir() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();

        // Create the receipts directory as a symlink.
        let receipts = receipts_dir(fac_root);
        let evil_dir = tmp.path().join("evil_receipts");
        fs::create_dir_all(&evil_dir).expect("create evil dir");
        // Ensure the parent exists so the symlink can be created.
        if let Some(parent) = receipts.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        std::os::unix::fs::symlink(&evil_dir, &receipts).expect("create symlink");

        let policy_bytes = make_default_policy_bytes();
        let result = adopt_policy(fac_root, &policy_bytes, "operator:local", "initial");
        assert!(
            result.is_err(),
            "should reject symlinked receipts dir, got: {result:?}"
        );
    }

    /// Verify that `reject_symlink` allows non-existent paths (about to be
    /// created).
    #[test]
    fn test_reject_symlink_nonexistent_path() {
        let tmp = tempdir().expect("tempdir");
        let nonexistent = tmp.path().join("does_not_exist.json");
        assert!(
            reject_symlink(&nonexistent).is_ok(),
            "non-existent path should be allowed"
        );
    }

    // =====================================================================
    // Atomic backup tests (f-722-code_quality-1771347577305561-0)
    // =====================================================================

    /// Verify that the prev file is atomically written (not partially
    /// written) by checking it is always valid JSON after adoption.
    #[test]
    fn test_prev_file_is_valid_json_after_rotation() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        // First adopt.
        let (first_root, _) = adopt_policy(fac_root, &policy_bytes, "operator:local", "initial")
            .expect("first adopt");

        // Second adopt with different policy.
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        adopt_policy(fac_root, &second_bytes, "operator:local", "update").expect("second adopt");

        // Verify prev is valid JSON and matches first root.
        let prev_bytes = fs::read(prev_root_path(fac_root)).expect("read prev");
        let prev: AdmittedPolicyRootV1 =
            serde_json::from_slice(&prev_bytes).expect("prev should be valid JSON");
        assert_eq!(prev.admitted_policy_hash, first_root.admitted_policy_hash);
    }

    /// Verify `atomic_write_file` creates a well-formed file.
    #[test]
    fn test_atomic_write_file_creates_correct_content() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let final_path = dir.join("output.json");
        let content = b"{\"test\": true}";

        atomic_write_file(dir, ".output.json.tmp", &final_path, content).expect("write");

        let read_back = fs::read(&final_path).expect("read");
        assert_eq!(read_back, content);

        // Temp file should not exist after successful rename.
        assert!(!dir.join(".output.json.tmp").exists());
    }

    /// Verify that rollback still works correctly after the atomic backup
    /// changes.
    #[test]
    fn test_rollback_correctness_after_atomic_backup() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        // First adopt.
        let (first_root, _) = adopt_policy(fac_root, &policy_bytes, "operator:local", "initial")
            .expect("first adopt");

        // Second adopt.
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let (second_root, _) = adopt_policy(fac_root, &second_bytes, "operator:local", "update")
            .expect("second adopt");

        // Verify current is second, prev is first.
        let current = load_admitted_policy_root(fac_root).expect("load current");
        assert_eq!(
            current.admitted_policy_hash,
            second_root.admitted_policy_hash
        );

        // Rollback.
        let (rolled_back, receipt) =
            rollback_policy(fac_root, "operator:local", "revert").expect("rollback");
        assert_eq!(
            rolled_back.admitted_policy_hash,
            first_root.admitted_policy_hash
        );
        assert_eq!(receipt.old_digest, second_root.admitted_policy_hash);
        assert_eq!(receipt.new_digest, first_root.admitted_policy_hash);

        // Verify current is now first.
        let after_rollback = load_admitted_policy_root(fac_root).expect("load after rollback");
        assert_eq!(
            after_rollback.admitted_policy_hash,
            first_root.admitted_policy_hash
        );
    }

    // =====================================================================
    // Actor identity tests (f-722-security-1771347580085305-0)
    // =====================================================================

    /// Verify that adoption receipts preserve the actor identity passed
    /// in (not hard-coded).
    #[test]
    fn test_adoption_receipt_records_custom_actor() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        let (root, receipt) = adopt_policy(
            fac_root,
            &policy_bytes,
            "operator:alice",
            "custom actor test",
        )
        .expect("adopt");
        assert_eq!(receipt.actor_id, "operator:alice");
        assert_eq!(root.actor_id, "operator:alice");
    }

    /// Verify that rollback receipts preserve the actor identity.
    #[test]
    fn test_rollback_receipt_records_custom_actor() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        adopt_policy(fac_root, &policy_bytes, "operator:alice", "initial").expect("first adopt");

        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        adopt_policy(fac_root, &second_bytes, "operator:alice", "update").expect("second adopt");

        let (root, receipt) =
            rollback_policy(fac_root, "operator:bob", "rollback by bob").expect("rollback");
        assert_eq!(receipt.actor_id, "operator:bob");
        assert_eq!(root.actor_id, "operator:bob");
    }

    // =====================================================================
    // Open-once pattern tests (f-722-security-1771348928218169-0)
    // =====================================================================

    /// Verify that `load_bounded_json` rejects symlinks via `O_NOFOLLOW`
    /// at the kernel level (no TOCTOU gap).
    #[cfg(unix)]
    #[test]
    fn test_load_bounded_json_rejects_symlink_via_o_nofollow() {
        let tmp = tempdir().expect("tempdir");
        let real_file = tmp.path().join("real.json");
        let root = AdmittedPolicyRootV1 {
            schema: ADMITTED_POLICY_ROOT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            admitted_policy_hash: "b3-256:aa".to_string(),
            adopted_at_unix_secs: 0,
            actor_id: "test".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&root).expect("serialize");
        fs::write(&real_file, &bytes).expect("write real file");

        let symlink_path = tmp.path().join("symlink.json");
        std::os::unix::fs::symlink(&real_file, &symlink_path).expect("create symlink");

        // Real file should load fine.
        let result: Result<AdmittedPolicyRootV1, _> =
            load_bounded_json(&real_file, MAX_ADMITTED_ROOT_FILE_SIZE);
        assert!(result.is_ok(), "real file should load: {result:?}");

        // Symlink MUST be rejected at open(2) via O_NOFOLLOW.
        let result: Result<AdmittedPolicyRootV1, _> =
            load_bounded_json(&symlink_path, MAX_ADMITTED_ROOT_FILE_SIZE);
        assert!(
            result.is_err(),
            "symlink must be rejected by O_NOFOLLOW: {result:?}"
        );
    }

    /// Verify that `load_bounded_json` rejects oversized files.
    #[test]
    fn test_load_bounded_json_rejects_oversized_file() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("big.json");
        // Create a file larger than the max allowed size.
        let large_content = vec![b' '; MAX_ADMITTED_ROOT_FILE_SIZE + 100];
        fs::write(&path, &large_content).expect("write oversized file");

        let result: Result<AdmittedPolicyRootV1, _> =
            load_bounded_json(&path, MAX_ADMITTED_ROOT_FILE_SIZE);
        assert!(
            matches!(result, Err(PolicyAdoptionError::FileTooLarge { .. })),
            "should reject oversized file: {result:?}"
        );
    }

    // =====================================================================
    // NamedTempFile atomic write tests (f-722-security-1771348924639728-0)
    // =====================================================================

    /// Verify that `atomic_write_file` using `NamedTempFile` creates
    /// correct content and leaves no temp artifacts.
    #[test]
    fn test_atomic_write_via_named_tempfile() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let final_path = dir.join("namedtemp_output.json");
        let content = b"{\"namedtempfile\": true}";

        atomic_write_file(dir, ".unused_name.tmp", &final_path, content).expect("write");

        let read_back = fs::read(&final_path).expect("read");
        assert_eq!(read_back, content);
    }

    /// Verify that bounded reads in `persist_admitted_root_atomic`
    /// reject oversized current root files (f-722-security-1771348934962474-0).
    #[test]
    fn test_persist_rejects_oversized_current_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let policy_bytes = make_default_policy_bytes();

        // First adoption creates a valid current root.
        adopt_policy(fac_root, &policy_bytes, "operator:local", "initial").expect("first adopt");

        // Replace the current root with an oversized file.
        let current = admitted_root_path(fac_root);
        let oversized = vec![b'{'; MAX_ADMITTED_ROOT_FILE_SIZE + 100];
        fs::write(&current, &oversized).expect("write oversized");

        // Second adoption should fail during bounded read of current root.
        let mut policy = FacPolicyV1::default_policy();
        policy.deny_ambient_cargo_home = false;
        let second_bytes = serde_json::to_vec_pretty(&policy).expect("serialize");
        let result = adopt_policy(fac_root, &second_bytes, "operator:local", "update");
        assert!(
            result.is_err(),
            "should reject oversized current root during rotation: {result:?}"
        );
    }
}
