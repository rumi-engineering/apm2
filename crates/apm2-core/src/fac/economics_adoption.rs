// AGENT-AUTHORED (TCK-00584)
//! Economics profile adoption protocol.
//!
//! Broker-admitted `economics_profile_hash` rotation with rollback.
//! This module implements the full lifecycle for adopting and rolling back
//! economics profiles in default mode. The broker maintains an admitted
//! economics profile digest under
//! `$APM2_HOME/private/fac/broker/admitted_economics_profile.v1.json`
//! (digest only; non-secret). Adoption is atomic (temp + rename), with
//! the previous digest retained in
//! `admitted_economics_profile.prev.v1.json` for rollback.
//!
//! Every adoption and rollback emits a durable
//! `EconomicsAdoptionReceiptV1` with old/new digests, actor identity,
//! reason string, and a domain-separated BLAKE3 content hash.
//!
//! # Security Invariants
//!
//! - [INV-EADOPT-001] Adoption requires schema + hash validation before
//!   acceptance (no arbitrary file acceptance).
//! - [INV-EADOPT-002] Atomic persistence via temp + rename with fsync
//!   (CTR-2607).
//! - [INV-EADOPT-003] Rollback to `prev` is atomic and emits a receipt.
//! - [INV-EADOPT-004] Workers refuse budget admissions whose profile binding
//!   mismatches the admitted digest (fail-closed).
//! - [INV-EADOPT-005] Receipt content hash uses domain-separated BLAKE3 with
//!   injective length-prefix framing (CTR-2612).
//! - [INV-EADOPT-006] All string fields are bounded for DoS prevention
//!   (CTR-1303).
//! - [INV-EADOPT-007] File reads are bounded before deserialization (CTR-1603).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::economics::profile::{EconomicsProfile, EconomicsProfileError};

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for the persisted admitted economics profile root.
pub const ADMITTED_ECONOMICS_PROFILE_SCHEMA: &str = "apm2.fac.admitted_economics_profile.v1";

/// Schema identifier for economics adoption receipts.
pub const ECONOMICS_ADOPTION_RECEIPT_SCHEMA: &str = "apm2.fac.economics_adoption_receipt.v1";

/// Filename for the current admitted economics profile root.
const ADMITTED_ECONOMICS_PROFILE_FILENAME: &str = "admitted_economics_profile.v1.json";

/// Filename for the previous admitted economics profile root (rollback).
const ADMITTED_ECONOMICS_PROFILE_PREV_FILENAME: &str = "admitted_economics_profile.prev.v1.json";

/// Domain separator for economics adoption receipt content hashing.
const ADOPTION_RECEIPT_HASH_DOMAIN: &[u8] = b"apm2.fac.economics_adoption_receipt.v1\0";

/// Maximum serialized size of the admitted economics profile root file
/// (bytes). Protects against memory-exhaustion during bounded reads
/// (CTR-1603).
const MAX_ADMITTED_ROOT_FILE_SIZE: usize = 4_096;

/// Maximum serialized size of an economics adoption receipt (bytes).
const MAX_ADOPTION_RECEIPT_SIZE: usize = 8_192;

/// Maximum serialized size of an economics profile file (bytes).
/// Economics profiles are bounded: 15 budget entries + lifecycle cost
/// vector + control plane limits + schema metadata.
pub const MAX_ECONOMICS_PROFILE_SIZE: usize = 32_768;

/// Maximum length for reason strings in receipts.
const MAX_REASON_LENGTH: usize = 1_024;

/// Maximum length for actor identity strings.
const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Maximum length for schema string fields.
const MAX_SCHEMA_STRING_LENGTH: usize = 128;

/// Directory name under fac root where adoption state is persisted.
const BROKER_SUBDIR: &str = "broker";

/// Receipts directory under fac root.
const RECEIPTS_DIR: &str = "receipts";

// =============================================================================
// Error Types
// =============================================================================

/// Errors produced by economics profile adoption operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EconomicsAdoptionError {
    /// The economics profile failed schema + hash validation.
    #[error("economics profile validation failed: {detail}")]
    ProfileValidation {
        /// Detail about the validation failure.
        detail: String,
    },

    /// The computed profile hash does not match the expected hash.
    #[error("economics profile hash mismatch: computed {computed}, expected {expected}")]
    HashMismatch {
        /// Computed hash.
        computed: String,
        /// Expected hash.
        expected: String,
    },

    /// No admitted economics profile root exists (nothing to show or
    /// rollback).
    #[error("no admitted economics profile root found at {path}")]
    NoAdmittedRoot {
        /// Path where the admitted root was expected.
        path: String,
    },

    /// No previous economics profile root exists (nothing to roll back
    /// to).
    #[error("no previous economics profile root found at {path}; rollback not possible")]
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

    /// The new profile hash is the same as the currently admitted hash
    /// (no-op adoption).
    #[error("economics profile already admitted with hash {hash}")]
    AlreadyAdmitted {
        /// The hash that is already admitted.
        hash: String,
    },

    /// Schema identifier does not match the expected value.
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema identifier.
        expected: &'static str,
        /// Actual schema identifier.
        actual: String,
    },

    /// Schema version is not supported.
    #[error("unsupported schema version: {version} (supported: {supported})")]
    UnsupportedSchemaVersion {
        /// Actual version found.
        version: String,
        /// Supported version(s).
        supported: &'static str,
    },

    /// The provided digest string is malformed (wrong prefix, invalid hex,
    /// wrong length).
    #[error("invalid digest: {detail}")]
    InvalidDigest {
        /// Detail about the validation failure.
        detail: String,
    },
}

impl From<EconomicsProfileError> for EconomicsAdoptionError {
    fn from(e: EconomicsProfileError) -> Self {
        Self::ProfileValidation {
            detail: e.to_string(),
        }
    }
}

// =============================================================================
// Types
// =============================================================================

/// Supported schema version for `AdmittedEconomicsProfileRootV1`.
const ADMITTED_ROOT_SUPPORTED_VERSION: &str = "1.0.0";

/// Supported schema version for `EconomicsAdoptionReceiptV1`.
const ADOPTION_RECEIPT_SUPPORTED_VERSION: &str = "1.0.0";

/// Persisted admitted economics profile root. Stored as a small JSON file
/// containing only the admitted profile hash and schema metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedEconomicsProfileRootV1 {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// The BLAKE3 profile hash string (e.g. `b3-256:<hex>`).
    pub admitted_profile_hash: String,
    /// Unix timestamp (seconds) of the adoption event.
    pub adopted_at_unix_secs: u64,
    /// Actor who performed the adoption.
    pub actor_id: String,
}

impl AdmittedEconomicsProfileRootV1 {
    /// Validate schema identity, version compatibility, and field bounds.
    fn validate(&self) -> Result<(), EconomicsAdoptionError> {
        if self.schema != ADMITTED_ECONOMICS_PROFILE_SCHEMA {
            return Err(EconomicsAdoptionError::SchemaMismatch {
                expected: ADMITTED_ECONOMICS_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if self.schema_version != ADMITTED_ROOT_SUPPORTED_VERSION {
            return Err(EconomicsAdoptionError::UnsupportedSchemaVersion {
                version: self.schema_version.clone(),
                supported: ADMITTED_ROOT_SUPPORTED_VERSION,
            });
        }
        validate_bounded_string("schema", &self.schema, MAX_SCHEMA_STRING_LENGTH)?;
        validate_bounded_string(
            "schema_version",
            &self.schema_version,
            MAX_SCHEMA_STRING_LENGTH,
        )?;
        validate_bounded_string(
            "admitted_profile_hash",
            &self.admitted_profile_hash,
            MAX_SCHEMA_STRING_LENGTH,
        )?;
        validate_bounded_string("actor_id", &self.actor_id, MAX_ACTOR_ID_LENGTH)?;
        Ok(())
    }
}

/// The action performed in an economics adoption receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicsAdoptionAction {
    /// A new economics profile was adopted.
    Adopt,
    /// The economics profile was rolled back to a previous version.
    Rollback,
}

impl std::fmt::Display for EconomicsAdoptionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adopt => write!(f, "adopt"),
            Self::Rollback => write!(f, "rollback"),
        }
    }
}

/// Durable receipt for economics profile adoption/rollback events.
///
/// Contains `old_digest`, `new_digest`, actor identity, reason string,
/// and a domain-separated BLAKE3 content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicsAdoptionReceiptV1 {
    /// Schema identifier.
    pub schema: String,
    /// Schema version.
    pub schema_version: String,
    /// Action performed.
    pub action: EconomicsAdoptionAction,
    /// Previous admitted profile hash (empty string if none).
    pub old_digest: String,
    /// New admitted profile hash.
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

impl EconomicsAdoptionReceiptV1 {
    /// Validate schema identity, version compatibility, and field bounds.
    fn validate(&self) -> Result<(), EconomicsAdoptionError> {
        if self.schema != ECONOMICS_ADOPTION_RECEIPT_SCHEMA {
            return Err(EconomicsAdoptionError::SchemaMismatch {
                expected: ECONOMICS_ADOPTION_RECEIPT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if self.schema_version != ADOPTION_RECEIPT_SUPPORTED_VERSION {
            return Err(EconomicsAdoptionError::UnsupportedSchemaVersion {
                version: self.schema_version.clone(),
                supported: ADOPTION_RECEIPT_SUPPORTED_VERSION,
            });
        }
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

/// Returns the path to the current admitted economics profile root file.
fn admitted_root_path(fac_root: &Path) -> PathBuf {
    broker_dir(fac_root).join(ADMITTED_ECONOMICS_PROFILE_FILENAME)
}

/// Returns the path to the previous admitted economics profile root file.
fn prev_root_path(fac_root: &Path) -> PathBuf {
    broker_dir(fac_root).join(ADMITTED_ECONOMICS_PROFILE_PREV_FILENAME)
}

/// Returns the receipts directory.
fn receipts_dir(fac_root: &Path) -> PathBuf {
    fac_root.join(RECEIPTS_DIR)
}

/// Read the current admitted economics profile root, if it exists.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError::Io`] on I/O failure,
/// [`EconomicsAdoptionError::FileTooLarge`] if the file exceeds bounds,
/// [`EconomicsAdoptionError::NoAdmittedRoot`] if no admitted root exists.
pub fn load_admitted_economics_profile_root(
    fac_root: &Path,
) -> Result<AdmittedEconomicsProfileRootV1, EconomicsAdoptionError> {
    let path = admitted_root_path(fac_root);
    load_bounded_json::<AdmittedEconomicsProfileRootV1>(&path, MAX_ADMITTED_ROOT_FILE_SIZE)
        .and_then(|r| {
            r.validate()?;
            Ok(r)
        })
}

/// Check whether a given economics profile hash matches the currently
/// admitted economics profile root.
///
/// Returns `true` if the admitted root exists and its hash matches
/// (constant-time comparison). Returns `false` if no admitted root
/// exists or if the hashes differ.
#[must_use]
pub fn is_economics_profile_hash_admitted(fac_root: &Path, profile_hash: &str) -> bool {
    match load_admitted_economics_profile_root(fac_root) {
        Ok(root) => {
            let admitted_bytes = root.admitted_profile_hash.as_bytes();
            let check_bytes = profile_hash.as_bytes();
            if admitted_bytes.len() != check_bytes.len() {
                return false;
            }
            bool::from(admitted_bytes.ct_eq(check_bytes))
        },
        Err(_) => false,
    }
}

/// Validate an economics profile from raw JSON bytes: deserialize,
/// validate schema + fields, compute hash.
///
/// Returns the validated profile and its hash string on success.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError`] on validation failure.
pub fn validate_economics_profile_bytes(
    bytes: &[u8],
) -> Result<(EconomicsProfile, String), EconomicsAdoptionError> {
    if bytes.len() > MAX_ECONOMICS_PROFILE_SIZE {
        return Err(EconomicsAdoptionError::FileTooLarge {
            size: bytes.len() as u64,
            max: MAX_ECONOMICS_PROFILE_SIZE,
        });
    }

    // Parse the profile from its framed representation (domain prefix +
    // canonical JSON).
    let profile = EconomicsProfile::from_framed_bytes(bytes)?;
    let hash_bytes = profile.profile_hash()?;
    let hash_str = format!("b3-256:{}", hex::encode(hash_bytes));
    Ok((profile, hash_str))
}

/// Validate an economics profile from raw canonical JSON bytes (without
/// the domain prefix framing). Wraps the bytes with the domain prefix
/// before delegating to `validate_economics_profile_bytes`.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError`] on validation failure.
pub fn validate_economics_profile_json_bytes(
    json_bytes: &[u8],
) -> Result<(EconomicsProfile, String), EconomicsAdoptionError> {
    use crate::economics::profile::ECONOMICS_PROFILE_HASH_DOMAIN;

    // Build the framed payload: domain prefix + canonical JSON.
    let mut framed = Vec::with_capacity(ECONOMICS_PROFILE_HASH_DOMAIN.len() + json_bytes.len());
    framed.extend_from_slice(ECONOMICS_PROFILE_HASH_DOMAIN);
    framed.extend_from_slice(json_bytes);
    validate_economics_profile_bytes(&framed)
}

/// Adopt a new economics profile: validate, persist the admitted digest
/// atomically, and emit a durable receipt.
///
/// 1. Validates the profile (schema + bounds).
/// 2. Computes its hash.
/// 3. Checks against the current admitted root (rejects no-op adoption).
/// 4. Persists the new admitted root via temp + rename (CTR-2607).
/// 5. Retains the previous root in `admitted_economics_profile.prev.v1.json`.
/// 6. Emits an `EconomicsAdoptionReceiptV1`.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError`] on validation, persistence, or
/// serialization failures.
pub fn adopt_economics_profile(
    fac_root: &Path,
    profile_bytes: &[u8],
    actor_id: &str,
    reason: &str,
) -> Result<(AdmittedEconomicsProfileRootV1, EconomicsAdoptionReceiptV1), EconomicsAdoptionError> {
    validate_bounded_string("actor_id", actor_id, MAX_ACTOR_ID_LENGTH)?;
    validate_bounded_string("reason", reason, MAX_REASON_LENGTH)?;

    // Step 1-2: validate and compute hash.
    let (_profile, profile_hash) = validate_economics_profile_bytes(profile_bytes)?;

    // Step 3: load current admitted root and check for no-op.
    let old_digest = match load_admitted_economics_profile_root(fac_root) {
        Ok(root) => {
            let old_bytes = root.admitted_profile_hash.as_bytes();
            let new_bytes = profile_hash.as_bytes();
            if old_bytes.len() == new_bytes.len() && bool::from(old_bytes.ct_eq(new_bytes)) {
                return Err(EconomicsAdoptionError::AlreadyAdmitted { hash: profile_hash });
            }
            root.admitted_profile_hash
        },
        Err(EconomicsAdoptionError::NoAdmittedRoot { .. }) => String::new(),
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
    let new_root = AdmittedEconomicsProfileRootV1 {
        schema: ADMITTED_ECONOMICS_PROFILE_SCHEMA.to_string(),
        schema_version: "1.0.0".to_string(),
        admitted_profile_hash: profile_hash.clone(),
        adopted_at_unix_secs: now_secs,
        actor_id: actor_id.to_string(),
    };
    new_root.validate()?;

    // Step 5: emit receipt BEFORE persisting root.
    // Transactional ordering: if receipt persistence fails, the root is
    // never committed, so the durable receipt invariant is maintained.
    // If receipt succeeds but root fails, the receipt is an orphan (safe).
    //
    // RESIDUAL RISK (f-726-security-1771355420177259-0): These two writes
    // (receipt then root) are NOT atomic as a unit. If the process crashes
    // after the receipt is synced but before the root file is renamed, an
    // orphan receipt will exist without the adoption taking effect. This is
    // an acceptable fail-safe: the previous policy remains active (deny-by-
    // default), the orphan receipt is auditable, and retry will succeed
    // idempotently (the no-op check will be retried against the old root).
    // A future improvement could use a WAL or lock-file protocol to
    // provide strict receipt-root atomicity.
    let receipt = build_and_persist_receipt(
        fac_root,
        EconomicsAdoptionAction::Adopt,
        &old_digest,
        &profile_hash,
        actor_id,
        reason,
        now_secs,
    )?;

    // Step 6: persist new admitted root atomically (only after receipt).
    persist_admitted_root_atomic(fac_root, &new_root)?;

    Ok((new_root, receipt))
}

/// Prefix for BLAKE3-256 digest strings.
const B3_256_PREFIX: &str = "b3-256:";

/// Validate that a digest string is a well-formed `b3-256:<64-hex>` value.
///
/// Returns the validated digest string on success.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError::InvalidDigest`] if:
/// - The string does not start with `b3-256:`.
/// - The hex portion is not exactly 64 characters.
/// - The hex portion contains non-hex characters.
pub fn validate_digest_string(digest: &str) -> Result<(), EconomicsAdoptionError> {
    let hex_part = digest.strip_prefix(B3_256_PREFIX).ok_or_else(|| {
        EconomicsAdoptionError::InvalidDigest {
            detail: format!(
                "digest must start with '{B3_256_PREFIX}', got: {}",
                digest.chars().take(20).collect::<String>()
            ),
        }
    })?;

    if hex_part.len() != 64 {
        return Err(EconomicsAdoptionError::InvalidDigest {
            detail: format!(
                "digest hex portion must be exactly 64 characters, got {} characters",
                hex_part.len()
            ),
        });
    }

    // Validate hex characters (lowercase only for canonical form).
    if !hex_part
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(EconomicsAdoptionError::InvalidDigest {
            detail: "digest hex portion must contain only lowercase hex characters (0-9, a-f)"
                .to_string(),
        });
    }

    Ok(())
}

/// Returns `true` if the given string looks like a `b3-256:` digest.
///
/// This is a quick syntactic check (prefix match) used to distinguish
/// digest arguments from file paths in CLI argument routing.
#[must_use]
pub fn looks_like_digest(s: &str) -> bool {
    s.starts_with(B3_256_PREFIX)
}

/// Adopt an economics profile by its pre-computed digest hash.
///
/// Unlike [`adopt_economics_profile`], this function does NOT require the
/// full profile bytes. It accepts a validated `b3-256:<hex>` digest string
/// and records it as the admitted economics profile hash. This is useful
/// when the operator already knows the digest (e.g., from a policy or
/// upstream coordination) and does not have the profile file locally.
///
/// 1. Validates the digest format (`b3-256:<64-hex-lowercase>`).
/// 2. Checks against the current admitted root (rejects no-op adoption).
/// 3. Persists the new admitted root via temp + rename (CTR-2607).
/// 4. Retains the previous root for rollback.
/// 5. Emits an `EconomicsAdoptionReceiptV1`.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError`] on validation, persistence, or
/// serialization failures.
pub fn adopt_economics_profile_by_hash(
    fac_root: &Path,
    digest: &str,
    actor_id: &str,
    reason: &str,
) -> Result<(AdmittedEconomicsProfileRootV1, EconomicsAdoptionReceiptV1), EconomicsAdoptionError> {
    validate_bounded_string("actor_id", actor_id, MAX_ACTOR_ID_LENGTH)?;
    validate_bounded_string("reason", reason, MAX_REASON_LENGTH)?;

    // Step 1: validate digest format.
    validate_digest_string(digest)?;

    // Step 2: load current admitted root and check for no-op.
    let old_digest = match load_admitted_economics_profile_root(fac_root) {
        Ok(root) => {
            let old_bytes = root.admitted_profile_hash.as_bytes();
            let new_bytes = digest.as_bytes();
            if old_bytes.len() == new_bytes.len() && bool::from(old_bytes.ct_eq(new_bytes)) {
                return Err(EconomicsAdoptionError::AlreadyAdmitted {
                    hash: digest.to_string(),
                });
            }
            root.admitted_profile_hash
        },
        Err(EconomicsAdoptionError::NoAdmittedRoot { .. }) => String::new(),
        Err(e) => return Err(e),
    };

    // CTR-2501 deviation: `SystemTime::now()` for adoption timestamp
    // (wall-clock anchored audit trail). Documented inline.
    #[allow(clippy::disallowed_methods)]
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Step 3: build new admitted root.
    let new_root = AdmittedEconomicsProfileRootV1 {
        schema: ADMITTED_ECONOMICS_PROFILE_SCHEMA.to_string(),
        schema_version: "1.0.0".to_string(),
        admitted_profile_hash: digest.to_string(),
        adopted_at_unix_secs: now_secs,
        actor_id: actor_id.to_string(),
    };
    new_root.validate()?;

    // Step 4: emit receipt BEFORE persisting root.
    // Transactional ordering: receipt-before-root ensures the durable
    // receipt invariant is maintained (same as adopt_economics_profile).
    let receipt = build_and_persist_receipt(
        fac_root,
        EconomicsAdoptionAction::Adopt,
        &old_digest,
        digest,
        actor_id,
        reason,
        now_secs,
    )?;

    // Step 5: persist new admitted root atomically (only after receipt).
    persist_admitted_root_atomic(fac_root, &new_root)?;

    Ok((new_root, receipt))
}

/// Rollback to the previous admitted economics profile root.
///
/// 1. Loads the previous admitted root from
///    `admitted_economics_profile.prev.v1.json`.
/// 2. Persists it as the current root via temp + rename.
/// 3. Emits a rollback receipt.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError`] if no previous root exists, or on
/// persistence failures.
pub fn rollback_economics_profile(
    fac_root: &Path,
    actor_id: &str,
    reason: &str,
) -> Result<(AdmittedEconomicsProfileRootV1, EconomicsAdoptionReceiptV1), EconomicsAdoptionError> {
    validate_bounded_string("actor_id", actor_id, MAX_ACTOR_ID_LENGTH)?;
    validate_bounded_string("reason", reason, MAX_REASON_LENGTH)?;

    // Load current root (to record old_digest).
    let current_digest = match load_admitted_economics_profile_root(fac_root) {
        Ok(root) => root.admitted_profile_hash,
        Err(EconomicsAdoptionError::NoAdmittedRoot { .. }) => String::new(),
        Err(e) => return Err(e),
    };

    // Load previous root.
    let prev_path = prev_root_path(fac_root);
    let prev_root = load_bounded_json::<AdmittedEconomicsProfileRootV1>(
        &prev_path,
        MAX_ADMITTED_ROOT_FILE_SIZE,
    )
    .map_err(|_| EconomicsAdoptionError::NoPreviousRoot {
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
    let rolled_back_root = AdmittedEconomicsProfileRootV1 {
        schema: ADMITTED_ECONOMICS_PROFILE_SCHEMA.to_string(),
        schema_version: "1.0.0".to_string(),
        admitted_profile_hash: prev_root.admitted_profile_hash.clone(),
        adopted_at_unix_secs: now_secs,
        actor_id: actor_id.to_string(),
    };
    rolled_back_root.validate()?;

    // Emit rollback receipt BEFORE persisting root.
    // Transactional ordering: receipt-before-root ensures the durable
    // receipt invariant is never violated. An orphan receipt (receipt
    // written but root fails) is safe; a committed root without a receipt
    // is not.
    //
    // RESIDUAL RISK: same non-atomic receipt+root window as in
    // `adopt_economics_profile` — see comment there for analysis.
    let receipt = build_and_persist_receipt(
        fac_root,
        EconomicsAdoptionAction::Rollback,
        &current_digest,
        &prev_root.admitted_profile_hash,
        actor_id,
        reason,
        now_secs,
    )?;

    // Persist as current root (atomic) -- only after receipt.
    // Note: we do NOT update prev -- the prev file stays as the last
    // rollback point. A subsequent adopt will overwrite prev with the
    // current root.
    persist_admitted_root_atomic(fac_root, &rolled_back_root)?;

    Ok((rolled_back_root, receipt))
}

// =============================================================================
// Internal Helpers
// =============================================================================

/// Reject symlinks on a path. Uses `symlink_metadata` to detect symlinks
/// without following them (closing the TOCTOU gap for symlink-following
/// writes).
///
/// Returns `Ok(())` if the path does not exist (caller may be about to
/// create it) or if it is a regular file/directory. Returns
/// `Err(EconomicsAdoptionError::Persistence)` if the path is a symlink.
fn reject_symlink(path: &Path) -> Result<(), EconomicsAdoptionError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(EconomicsAdoptionError::Persistence {
                    detail: format!(
                        "refusing to operate on symlink at {} \
                         (security: symlink-following rejected)",
                        path.display()
                    ),
                });
            }
            Ok(())
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(EconomicsAdoptionError::Persistence {
            detail: format!("cannot stat {}: {e}", path.display()),
        }),
    }
}

/// Write bytes to a file atomically via `NamedTempFile` + fsync + persist.
///
/// Uses `tempfile::NamedTempFile::new_in(dir)` which creates the temp
/// file with a random name and `O_EXCL` flags, eliminating the symlink
/// TOCTOU race (RSK-1502).
///
/// Sets permissions to 0o600 on Unix before persist.
fn atomic_write_file(
    dir: &Path,
    _temp_name: &str,
    final_path: &Path,
    bytes: &[u8],
) -> Result<(), EconomicsAdoptionError> {
    // Reject symlinks on the final destination before rename.
    reject_symlink(final_path)?;

    // NamedTempFile::new_in uses O_EXCL + random name: no symlink TOCTOU.
    let mut named_temp =
        tempfile::NamedTempFile::new_in(dir).map_err(|e| EconomicsAdoptionError::Persistence {
            detail: format!("cannot create NamedTempFile in {}: {e}", dir.display()),
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        named_temp.as_file().set_permissions(perms).map_err(|e| {
            EconomicsAdoptionError::Persistence {
                detail: format!("cannot set permissions on temp file: {e}"),
            }
        })?;
    }

    named_temp
        .as_file_mut()
        .write_all(bytes)
        .map_err(|e| EconomicsAdoptionError::Persistence {
            detail: format!("cannot write temp file: {e}"),
        })?;
    named_temp
        .as_file()
        .sync_all()
        .map_err(|e| EconomicsAdoptionError::Persistence {
            detail: format!("cannot sync temp file: {e}"),
        })?;

    // Atomic rename to final destination via persist().
    named_temp
        .persist(final_path)
        .map_err(|e| EconomicsAdoptionError::Persistence {
            detail: format!("cannot persist temp file -> {}: {e}", final_path.display()),
        })?;

    Ok(())
}

/// Persist the admitted economics profile root atomically. Snapshots the
/// current file to `.prev` via temp+rename before writing the new file.
///
/// All paths are validated against symlinks before writes to close the
/// TOCTOU gap.
///
/// The prev-file backup uses temp+rename (not `fs::copy`) to maintain
/// atomic checkpoint semantics.
fn persist_admitted_root_atomic(
    fac_root: &Path,
    root: &AdmittedEconomicsProfileRootV1,
) -> Result<(), EconomicsAdoptionError> {
    let dir = broker_dir(fac_root);
    fs::create_dir_all(&dir).map_err(|e| EconomicsAdoptionError::Persistence {
        detail: format!("cannot create broker dir {}: {e}", dir.display()),
    })?;

    // Validate the broker directory itself is not a symlink.
    reject_symlink(&dir)?;

    let current_path = admitted_root_path(fac_root);
    let prev_path_val = prev_root_path(fac_root);

    // If a current root exists, snapshot it to prev via temp+rename
    // (atomic checkpoint, not fs::copy which can produce partial writes).
    // Uses load_bounded_json's open-once pattern for bounded reads.
    reject_symlink(&current_path)?;
    if current_path.exists() {
        let current_root: AdmittedEconomicsProfileRootV1 =
            load_bounded_json(&current_path, MAX_ADMITTED_ROOT_FILE_SIZE)?;
        let current_bytes = serde_json::to_vec_pretty(&current_root).map_err(|e| {
            EconomicsAdoptionError::Serialization {
                detail: format!("cannot re-serialize current root for prev snapshot: {e}"),
            }
        })?;
        atomic_write_file(
            &dir,
            ".admitted_economics_profile.prev.v1.json.tmp",
            &prev_path_val,
            &current_bytes,
        )?;
    }

    // Write new root to temp file, then atomic rename.
    let bytes =
        serde_json::to_vec_pretty(root).map_err(|e| EconomicsAdoptionError::Serialization {
            detail: format!("cannot serialize admitted root: {e}"),
        })?;

    atomic_write_file(
        &dir,
        ".admitted_economics_profile.v1.json.tmp",
        &current_path,
        &bytes,
    )?;

    // Sync directory for durability.
    let dir_handle = fs::File::open(&dir).map_err(|e| EconomicsAdoptionError::Persistence {
        detail: format!("cannot open broker dir for sync: {e}"),
    })?;
    dir_handle
        .sync_all()
        .map_err(|e| EconomicsAdoptionError::Persistence {
            detail: format!("cannot sync broker dir: {e}"),
        })?;

    Ok(())
}

/// Build and persist an economics adoption receipt.
fn build_and_persist_receipt(
    fac_root: &Path,
    action: EconomicsAdoptionAction,
    old_digest: &str,
    new_digest: &str,
    actor_id: &str,
    reason: &str,
    timestamp_unix_secs: u64,
) -> Result<EconomicsAdoptionReceiptV1, EconomicsAdoptionError> {
    let content_hash = compute_adoption_receipt_hash(
        action,
        old_digest,
        new_digest,
        actor_id,
        reason,
        timestamp_unix_secs,
    );

    let receipt = EconomicsAdoptionReceiptV1 {
        schema: ECONOMICS_ADOPTION_RECEIPT_SCHEMA.to_string(),
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
    fs::create_dir_all(&receipts).map_err(|e| EconomicsAdoptionError::Persistence {
        detail: format!("cannot create receipts dir {}: {e}", receipts.display()),
    })?;

    // Validate receipts directory is not a symlink.
    reject_symlink(&receipts)?;

    // Use content hash (without prefix) as filename.
    let hash_suffix = content_hash
        .strip_prefix("b3-256:")
        .unwrap_or(&content_hash);
    let receipt_filename = format!("economics_{action}_{hash_suffix}.json");
    let receipt_path = receipts.join(&receipt_filename);
    let temp_receipt_name = format!(".{receipt_filename}.tmp");

    let receipt_bytes =
        serde_json::to_vec_pretty(&receipt).map_err(|e| EconomicsAdoptionError::Serialization {
            detail: format!("cannot serialize adoption receipt: {e}"),
        })?;

    // Use atomic_write_file which validates symlinks and does temp+rename.
    atomic_write_file(&receipts, &temp_receipt_name, &receipt_path, &receipt_bytes)?;

    // Sync receipts directory for durability (CTR-2607, CTR-1502).
    let receipts_dir_handle =
        fs::File::open(&receipts).map_err(|e| EconomicsAdoptionError::Persistence {
            detail: format!("cannot open receipts dir for sync: {e}",),
        })?;
    receipts_dir_handle
        .sync_all()
        .map_err(|e| EconomicsAdoptionError::Persistence {
            detail: format!("cannot sync receipts dir: {e}"),
        })?;

    Ok(receipt)
}

/// Compute domain-separated BLAKE3 content hash for an economics
/// adoption receipt. Uses injective u64 length-prefix framing per
/// INV-EADOPT-005.
fn compute_adoption_receipt_hash(
    action: EconomicsAdoptionAction,
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

/// Read a bounded file using the open-once pattern.
///
/// Opens with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` (Unix) to:
/// - Atomically refuse symlinks at the kernel level (`O_NOFOLLOW`).
/// - Prevent inherited fd leaks (`O_CLOEXEC`).
/// - Prevent indefinite blocking on FIFOs/named pipes (`O_NONBLOCK`).
///
/// After `fstat` confirms a regular file, `O_NONBLOCK` is cleared via
/// `fcntl(F_SETFL)` for portable correctness.
///
/// Reads at most `max_size + 1` bytes via `take()` to enforce the size
/// limit without a TOCTOU gap (CTR-1603, INV-EADOPT-007).
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError::NoAdmittedRoot`] if the file does
/// not exist, [`EconomicsAdoptionError::FileTooLarge`] if it exceeds
/// `max_size`, [`EconomicsAdoptionError::Io`] on other I/O failures.
pub fn read_bounded_file(path: &Path, max_size: usize) -> Result<Vec<u8>, EconomicsAdoptionError> {
    use std::fs::OpenOptions;
    use std::io::Read as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    // Open-once: O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK.
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }

    let file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            EconomicsAdoptionError::NoAdmittedRoot {
                path: path.display().to_string(),
            }
        } else {
            EconomicsAdoptionError::Io {
                detail: format!(
                    "cannot open {} (symlink rejected fail-closed): {e}",
                    path.display()
                ),
            }
        }
    })?;

    // fstat on the opened fd -- not the path -- to verify regular file.
    let metadata = file.metadata().map_err(|e| EconomicsAdoptionError::Io {
        detail: format!("cannot fstat {}: {e}", path.display()),
    })?;
    if !metadata.is_file() {
        return Err(EconomicsAdoptionError::Io {
            detail: format!("not a regular file (fail-closed): {}", path.display()),
        });
    }

    // Clear O_NONBLOCK now that fstat confirmed regular file.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // Safety: `fcntl(F_GETFL)` and `fcntl(F_SETFL)` are safe system
        // calls on a valid, open file descriptor.
        #[allow(unsafe_code)]
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags != -1 {
            #[allow(unsafe_code)]
            let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
        }
    }

    let file_size = metadata.len();
    if file_size > max_size as u64 {
        return Err(EconomicsAdoptionError::FileTooLarge {
            size: file_size,
            max: max_size,
        });
    }

    // Bounded read via take() -- never reads more than max_size + 1.
    let limit = (max_size as u64).saturating_add(1);
    let mut bounded_reader = file.take(limit);
    #[allow(clippy::cast_possible_truncation)]
    let mut bytes = Vec::with_capacity((file_size as usize).min(max_size));
    bounded_reader
        .read_to_end(&mut bytes)
        .map_err(|e| EconomicsAdoptionError::Io {
            detail: format!("cannot read {}: {e}", path.display()),
        })?;
    if bytes.len() > max_size {
        return Err(EconomicsAdoptionError::FileTooLarge {
            size: bytes.len() as u64,
            max: max_size,
        });
    }

    Ok(bytes)
}

/// Read and deserialize a bounded JSON file using the open-once pattern.
///
/// Delegates to [`read_bounded_file`] for the open-once + bounded-read
/// pattern, then deserializes the result as JSON.
fn load_bounded_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    max_size: usize,
) -> Result<T, EconomicsAdoptionError> {
    let bytes = read_bounded_file(path, max_size)?;
    serde_json::from_slice(&bytes).map_err(|e| EconomicsAdoptionError::Serialization {
        detail: format!("cannot parse {}: {e}", path.display()),
    })
}

/// Validate that a string field does not exceed the allowed length.
const fn validate_bounded_string(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), EconomicsAdoptionError> {
    if value.len() > max {
        return Err(EconomicsAdoptionError::StringTooLong {
            field,
            actual: value.len(),
            max,
        });
    }
    Ok(())
}

/// Deserialize and validate an economics adoption receipt from bytes.
///
/// # Errors
///
/// Returns [`EconomicsAdoptionError`] if the receipt exceeds size bounds,
/// fails to parse, or has invalid field values.
pub fn deserialize_adoption_receipt(
    bytes: &[u8],
) -> Result<EconomicsAdoptionReceiptV1, EconomicsAdoptionError> {
    if bytes.len() > MAX_ADOPTION_RECEIPT_SIZE {
        return Err(EconomicsAdoptionError::FileTooLarge {
            size: bytes.len() as u64,
            max: MAX_ADOPTION_RECEIPT_SIZE,
        });
    }
    let receipt: EconomicsAdoptionReceiptV1 =
        serde_json::from_slice(bytes).map_err(|e| EconomicsAdoptionError::Serialization {
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
    use crate::economics::profile::EconomicsProfile;

    fn make_default_profile_framed_bytes() -> Vec<u8> {
        let profile = EconomicsProfile::default_baseline();
        profile.framed_bytes().expect("framed bytes")
    }

    #[test]
    fn test_adopt_economics_profile_creates_admitted_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        let (root, receipt) = adopt_economics_profile(
            fac_root,
            &profile_bytes,
            "operator:local",
            "initial economics profile adoption",
        )
        .expect("adopt");

        assert_eq!(root.schema, ADMITTED_ECONOMICS_PROFILE_SCHEMA);
        assert!(!root.admitted_profile_hash.is_empty());
        assert_eq!(receipt.action, EconomicsAdoptionAction::Adopt);
        assert!(receipt.old_digest.is_empty());
        assert_eq!(receipt.new_digest, root.admitted_profile_hash);
        assert_eq!(receipt.actor_id, "operator:local");

        // Verify the file exists.
        let loaded = load_admitted_economics_profile_root(fac_root).expect("load admitted root");
        assert_eq!(loaded.admitted_profile_hash, root.admitted_profile_hash);
    }

    #[test]
    fn test_adopt_economics_profile_rotates_to_prev() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        let (first_root, _) =
            adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "initial")
                .expect("first adopt");

        // Create a different profile to get a different hash.
        let mut profile = EconomicsProfile::default_baseline();
        // Modify to produce a different hash.
        profile.lifecycle_cost_vector.c_join = 42;
        let second_bytes = profile.framed_bytes().expect("framed bytes");

        let (second_root, receipt) = adopt_economics_profile(
            fac_root,
            &second_bytes,
            "operator:local",
            "update economics profile",
        )
        .expect("second adopt");

        assert_ne!(
            first_root.admitted_profile_hash,
            second_root.admitted_profile_hash
        );
        assert_eq!(receipt.old_digest, first_root.admitted_profile_hash);
        assert_eq!(receipt.new_digest, second_root.admitted_profile_hash);

        // Verify prev file exists with first root's hash.
        let prev = load_bounded_json::<AdmittedEconomicsProfileRootV1>(
            &prev_root_path(fac_root),
            MAX_ADMITTED_ROOT_FILE_SIZE,
        )
        .expect("load prev");
        assert_eq!(prev.admitted_profile_hash, first_root.admitted_profile_hash);
    }

    #[test]
    fn test_adopt_economics_profile_rejects_duplicate() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "initial")
            .expect("first adopt");

        let result =
            adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "duplicate");
        assert!(
            matches!(result, Err(EconomicsAdoptionError::AlreadyAdmitted { .. })),
            "should reject duplicate adoption, got: {result:?}"
        );
    }

    #[test]
    fn test_rollback_restores_previous() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        let (first_root, _) =
            adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "initial")
                .expect("first adopt");

        // Adopt a different profile.
        let mut profile = EconomicsProfile::default_baseline();
        profile.lifecycle_cost_vector.c_join = 42;
        let second_bytes = profile.framed_bytes().expect("framed bytes");
        let (second_root, _) =
            adopt_economics_profile(fac_root, &second_bytes, "operator:local", "update")
                .expect("second adopt");

        // Rollback.
        let (rolled_back, receipt) =
            rollback_economics_profile(fac_root, "operator:local", "reverting due to issue")
                .expect("rollback");

        assert_eq!(
            rolled_back.admitted_profile_hash,
            first_root.admitted_profile_hash
        );
        assert_eq!(receipt.action, EconomicsAdoptionAction::Rollback);
        assert_eq!(receipt.old_digest, second_root.admitted_profile_hash);
        assert_eq!(receipt.new_digest, first_root.admitted_profile_hash);

        // Verify current root is back to first.
        let current = load_admitted_economics_profile_root(fac_root).expect("load current");
        assert_eq!(
            current.admitted_profile_hash,
            first_root.admitted_profile_hash
        );
    }

    #[test]
    fn test_rollback_fails_without_previous() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "initial")
            .expect("adopt");

        // Remove the prev file.
        let _ = fs::remove_file(prev_root_path(fac_root));

        let result = rollback_economics_profile(fac_root, "operator:local", "rollback");
        assert!(
            matches!(result, Err(EconomicsAdoptionError::NoPreviousRoot { .. })),
            "should fail without previous root, got: {result:?}"
        );
    }

    #[test]
    fn test_is_economics_profile_hash_admitted_matches() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        let (root, _) =
            adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "initial")
                .expect("adopt");

        assert!(is_economics_profile_hash_admitted(
            fac_root,
            &root.admitted_profile_hash
        ));
        assert!(!is_economics_profile_hash_admitted(
            fac_root,
            "b3-256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_is_economics_profile_hash_admitted_false_when_no_root() {
        let tmp = tempdir().expect("tempdir");
        assert!(!is_economics_profile_hash_admitted(tmp.path(), "b3-256:aa"));
    }

    #[test]
    fn test_validate_economics_profile_bytes_succeeds() {
        let profile_bytes = make_default_profile_framed_bytes();
        let (_profile, hash) = validate_economics_profile_bytes(&profile_bytes).expect("validate");
        assert!(hash.starts_with("b3-256:"));
    }

    #[test]
    fn test_validate_economics_profile_bytes_rejects_invalid() {
        let result = validate_economics_profile_bytes(b"not valid");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_economics_profile_bytes_rejects_oversized() {
        let oversized = vec![b' '; MAX_ECONOMICS_PROFILE_SIZE + 1];
        let result = validate_economics_profile_bytes(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn test_adoption_receipt_hash_is_deterministic() {
        let h1 = compute_adoption_receipt_hash(
            EconomicsAdoptionAction::Adopt,
            "old",
            "new",
            "actor",
            "reason",
            12345,
        );
        let h2 = compute_adoption_receipt_hash(
            EconomicsAdoptionAction::Adopt,
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
            EconomicsAdoptionAction::Adopt,
            "old",
            "new",
            "actor",
            "reason",
            12345,
        );
        let h2 = compute_adoption_receipt_hash(
            EconomicsAdoptionAction::Rollback,
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
        let receipt = EconomicsAdoptionReceiptV1 {
            schema: ECONOMICS_ADOPTION_RECEIPT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            action: EconomicsAdoptionAction::Adopt,
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
            Err(EconomicsAdoptionError::StringTooLong { .. })
        ));
    }

    #[test]
    fn test_adopt_rejects_oversized_actor() {
        let tmp = tempdir().expect("tempdir");
        let profile_bytes = make_default_profile_framed_bytes();
        let long_actor = "x".repeat(MAX_ACTOR_ID_LENGTH + 1);
        let result = adopt_economics_profile(tmp.path(), &profile_bytes, &long_actor, "reason");
        assert!(matches!(
            result,
            Err(EconomicsAdoptionError::StringTooLong {
                field: "actor_id",
                ..
            })
        ));
    }

    #[test]
    fn test_adopt_rejects_oversized_reason() {
        let tmp = tempdir().expect("tempdir");
        let profile_bytes = make_default_profile_framed_bytes();
        let long_reason = "x".repeat(MAX_REASON_LENGTH + 1);
        let result = adopt_economics_profile(tmp.path(), &profile_bytes, "actor", &long_reason);
        assert!(matches!(
            result,
            Err(EconomicsAdoptionError::StringTooLong {
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
        let root = AdmittedEconomicsProfileRootV1 {
            schema: ADMITTED_ECONOMICS_PROFILE_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            admitted_profile_hash: "b3-256:aa".to_string(),
            adopted_at_unix_secs: 0,
            actor_id: "test".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&root).expect("serialize");
        fs::write(&real_file, &bytes).expect("write real file");

        #[cfg(unix)]
        {
            let symlink_path = admitted_root_path(fac_root);
            std::os::unix::fs::symlink(&real_file, &symlink_path).expect("create symlink");

            let result = load_admitted_economics_profile_root(fac_root);
            assert!(result.is_err(), "should reject symlink, got: {result:?}");
        }
    }

    #[test]
    fn test_receipt_persisted_to_receipts_dir() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        let (_, receipt) =
            adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "test")
                .expect("adopt");

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
        let result = load_admitted_economics_profile_root(tmp.path());
        assert!(
            matches!(result, Err(EconomicsAdoptionError::NoAdmittedRoot { .. })),
            "should return NoAdmittedRoot, got: {result:?}"
        );
    }

    /// Worker mismatch simulation: test that
    /// `is_economics_profile_hash_admitted` returns false for a
    /// non-matching hash (fail-closed behavior that workers rely on,
    /// INV-EADOPT-004).
    #[test]
    fn test_worker_refuses_mismatched_economics_profile() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "initial")
            .expect("adopt");

        // Simulate a worker checking with a wrong hash.
        let wrong_hash = "b3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(
            !is_economics_profile_hash_admitted(fac_root, wrong_hash),
            "worker must refuse mismatched profile (fail-closed, INV-EADOPT-004)"
        );
    }

    // =================================================================
    // Symlink rejection tests
    // =================================================================

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

    #[test]
    fn test_reject_symlink_nonexistent_path() {
        let tmp = tempdir().expect("tempdir");
        let nonexistent = tmp.path().join("does_not_exist.json");
        assert!(
            reject_symlink(&nonexistent).is_ok(),
            "non-existent path should be allowed"
        );
    }

    // =================================================================
    // Atomic write tests
    // =================================================================

    #[test]
    fn test_atomic_write_file_creates_correct_content() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let final_path = dir.join("output.json");
        let content = b"{\"test\": true}";

        atomic_write_file(dir, ".output.json.tmp", &final_path, content).expect("write");

        let read_back = fs::read(&final_path).expect("read");
        assert_eq!(read_back, content);
    }

    // =================================================================
    // Schema/version validation tests
    // =================================================================

    #[test]
    fn test_admitted_root_rejects_wrong_schema() {
        let root = AdmittedEconomicsProfileRootV1 {
            schema: "wrong.schema.id".to_string(),
            schema_version: "1.0.0".to_string(),
            admitted_profile_hash: "b3-256:aa".to_string(),
            adopted_at_unix_secs: 0,
            actor_id: "test".to_string(),
        };
        let result = root.validate();
        assert!(
            matches!(result, Err(EconomicsAdoptionError::SchemaMismatch { .. })),
            "should reject wrong schema, got: {result:?}"
        );
    }

    #[test]
    fn test_admitted_root_rejects_wrong_version() {
        let root = AdmittedEconomicsProfileRootV1 {
            schema: ADMITTED_ECONOMICS_PROFILE_SCHEMA.to_string(),
            schema_version: "99.0.0".to_string(),
            admitted_profile_hash: "b3-256:aa".to_string(),
            adopted_at_unix_secs: 0,
            actor_id: "test".to_string(),
        };
        let result = root.validate();
        assert!(
            matches!(
                result,
                Err(EconomicsAdoptionError::UnsupportedSchemaVersion { .. })
            ),
            "should reject wrong version, got: {result:?}"
        );
    }

    #[test]
    fn test_admitted_root_accepts_correct_schema_and_version() {
        let root = AdmittedEconomicsProfileRootV1 {
            schema: ADMITTED_ECONOMICS_PROFILE_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            admitted_profile_hash: "b3-256:aa".to_string(),
            adopted_at_unix_secs: 0,
            actor_id: "test".to_string(),
        };
        assert!(
            root.validate().is_ok(),
            "correct schema+version should pass"
        );
    }

    #[test]
    fn test_receipt_rejects_wrong_schema() {
        let receipt = EconomicsAdoptionReceiptV1 {
            schema: "wrong.receipt.schema".to_string(),
            schema_version: "1.0.0".to_string(),
            action: EconomicsAdoptionAction::Adopt,
            old_digest: String::new(),
            new_digest: "b3-256:aa".to_string(),
            actor_id: "test".to_string(),
            reason: "test".to_string(),
            timestamp_unix_secs: 0,
            content_hash: "b3-256:bb".to_string(),
        };
        let result = receipt.validate();
        assert!(
            matches!(result, Err(EconomicsAdoptionError::SchemaMismatch { .. })),
            "should reject wrong receipt schema, got: {result:?}"
        );
    }

    #[test]
    fn test_receipt_rejects_wrong_version() {
        let receipt = EconomicsAdoptionReceiptV1 {
            schema: ECONOMICS_ADOPTION_RECEIPT_SCHEMA.to_string(),
            schema_version: "2.0.0".to_string(),
            action: EconomicsAdoptionAction::Adopt,
            old_digest: String::new(),
            new_digest: "b3-256:aa".to_string(),
            actor_id: "test".to_string(),
            reason: "test".to_string(),
            timestamp_unix_secs: 0,
            content_hash: "b3-256:bb".to_string(),
        };
        let result = receipt.validate();
        assert!(
            matches!(
                result,
                Err(EconomicsAdoptionError::UnsupportedSchemaVersion { .. })
            ),
            "should reject wrong receipt version, got: {result:?}"
        );
    }

    #[test]
    fn test_receipt_accepts_correct_schema_and_version() {
        let receipt = EconomicsAdoptionReceiptV1 {
            schema: ECONOMICS_ADOPTION_RECEIPT_SCHEMA.to_string(),
            schema_version: "1.0.0".to_string(),
            action: EconomicsAdoptionAction::Adopt,
            old_digest: String::new(),
            new_digest: "b3-256:aa".to_string(),
            actor_id: "test".to_string(),
            reason: "test".to_string(),
            timestamp_unix_secs: 0,
            content_hash: "b3-256:bb".to_string(),
        };
        assert!(
            receipt.validate().is_ok(),
            "correct receipt schema+version should pass"
        );
    }

    // =================================================================
    // FIFO / named pipe rejection tests
    // =================================================================

    #[cfg(unix)]
    #[test]
    fn test_read_bounded_file_rejects_fifo() {
        let tmp = tempdir().expect("tempdir");
        let fifo_path = tmp.path().join("test.fifo");
        nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        let result = read_bounded_file(&fifo_path, 4096);
        assert!(result.is_err(), "FIFO must be rejected: {result:?}");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("not a regular file"),
            "FIFO rejection should indicate non-regular file, got: {err}"
        );
    }

    // =================================================================
    // Receipt-before-root transactional ordering tests
    // =================================================================

    #[test]
    fn test_adopt_receipt_exists_before_root_on_success() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        let (root, receipt) =
            adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "ordering test")
                .expect("adopt");

        // Both receipt and root should exist on success.
        let receipts = receipts_dir(fac_root);
        let receipt_entries: Vec<_> = fs::read_dir(&receipts)
            .expect("read receipts dir")
            .filter_map(Result::ok)
            .collect();
        assert!(
            !receipt_entries.is_empty(),
            "receipt must be persisted on successful adoption"
        );
        let loaded_root = load_admitted_economics_profile_root(fac_root).expect("load root");
        assert_eq!(
            loaded_root.admitted_profile_hash,
            root.admitted_profile_hash
        );
        assert_eq!(receipt.action, EconomicsAdoptionAction::Adopt);
    }

    #[test]
    fn test_rollback_receipt_exists_before_root_on_success() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let profile_bytes = make_default_profile_framed_bytes();

        let (first_root, _) =
            adopt_economics_profile(fac_root, &profile_bytes, "operator:local", "initial")
                .expect("first adopt");

        let mut profile = EconomicsProfile::default_baseline();
        profile.lifecycle_cost_vector.c_join = 42;
        let second_bytes = profile.framed_bytes().expect("framed bytes");
        adopt_economics_profile(fac_root, &second_bytes, "operator:local", "update")
            .expect("second adopt");

        let (rolled_back, receipt) =
            rollback_economics_profile(fac_root, "operator:local", "rollback ordering test")
                .expect("rollback");

        assert_eq!(
            rolled_back.admitted_profile_hash,
            first_root.admitted_profile_hash
        );
        assert_eq!(receipt.action, EconomicsAdoptionAction::Rollback);

        // Count receipts: initial adopt + update adopt + rollback = 3.
        let receipts = receipts_dir(fac_root);
        let receipt_entries: Vec<_> = fs::read_dir(&receipts)
            .expect("read receipts dir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(
            receipt_entries.len(),
            3,
            "should have 3 receipts (2 adopts + 1 rollback)"
        );
    }

    // =================================================================
    // Fail-closed regression tests (fix round 1: f-726-security,
    // f-726-code_quality)
    //
    // These tests prove that corrupted or tampered admitted-economics root
    // files produce hard errors distinct from NoAdmittedRoot, so the worker
    // admission path can distinguish "root not yet adopted" (backwards-compat
    // skip) from "root load failed" (fail-closed deny).
    // =================================================================

    /// Corrupted (non-JSON) root file must return a `Serialization` error,
    /// NOT `NoAdmittedRoot`. This is the core regression for INV-EADOPT-004
    /// fail-closed behavior: if the worker treated corruption as "no root",
    /// it would bypass admission.
    #[test]
    fn test_load_corrupted_root_returns_serialization_error() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let broker = broker_dir(fac_root);
        fs::create_dir_all(&broker).expect("create broker dir");

        // Write garbage bytes to the admitted root path.
        let root_path = admitted_root_path(fac_root);
        fs::write(&root_path, b"THIS IS NOT JSON").expect("write corrupted root");

        let result = load_admitted_economics_profile_root(fac_root);
        assert!(
            matches!(result, Err(EconomicsAdoptionError::Serialization { .. })),
            "corrupted root must return Serialization error, got: {result:?}"
        );
    }

    /// Truncated JSON root file must return a Serialization error.
    #[test]
    fn test_load_truncated_root_returns_serialization_error() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let broker = broker_dir(fac_root);
        fs::create_dir_all(&broker).expect("create broker dir");

        // Write truncated JSON.
        let root_path = admitted_root_path(fac_root);
        fs::write(&root_path, b"{\"schema\": \"apm2.fac.admitted_econ").expect("write truncated");

        let result = load_admitted_economics_profile_root(fac_root);
        assert!(
            matches!(result, Err(EconomicsAdoptionError::Serialization { .. })),
            "truncated root must return Serialization error, got: {result:?}"
        );
    }

    /// Valid JSON but wrong schema in root file must return `SchemaMismatch`.
    #[test]
    fn test_load_root_wrong_schema_returns_schema_mismatch() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let broker = broker_dir(fac_root);
        fs::create_dir_all(&broker).expect("create broker dir");

        let bad_root = AdmittedEconomicsProfileRootV1 {
            schema: "attacker.injected.schema".to_string(),
            schema_version: "1.0.0".to_string(),
            admitted_profile_hash: "b3-256:aa".to_string(),
            adopted_at_unix_secs: 0,
            actor_id: "test".to_string(),
        };
        let bytes = serde_json::to_vec_pretty(&bad_root).expect("serialize");
        let root_path = admitted_root_path(fac_root);
        fs::write(&root_path, &bytes).expect("write bad-schema root");

        let result = load_admitted_economics_profile_root(fac_root);
        assert!(
            matches!(result, Err(EconomicsAdoptionError::SchemaMismatch { .. })),
            "wrong-schema root must return SchemaMismatch, got: {result:?}"
        );
    }

    /// Oversized root file must return `FileTooLarge`.
    #[test]
    fn test_load_oversized_root_returns_file_too_large() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let broker = broker_dir(fac_root);
        fs::create_dir_all(&broker).expect("create broker dir");

        // Write a file that exceeds MAX_ADMITTED_ROOT_FILE_SIZE.
        let root_path = admitted_root_path(fac_root);
        let oversized = vec![b' '; MAX_ADMITTED_ROOT_FILE_SIZE + 1];
        fs::write(&root_path, &oversized).expect("write oversized root");

        let result = load_admitted_economics_profile_root(fac_root);
        assert!(
            matches!(result, Err(EconomicsAdoptionError::FileTooLarge { .. })),
            "oversized root must return FileTooLarge, got: {result:?}"
        );
    }

    /// `is_economics_profile_hash_admitted` must return false when the
    /// root file is corrupted (not just when it is missing). This is the
    /// regression test for the function that the worker calls.
    #[test]
    fn test_is_economics_profile_hash_admitted_false_on_corrupted_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let broker = broker_dir(fac_root);
        fs::create_dir_all(&broker).expect("create broker dir");

        // Write garbage to the root file.
        let root_path = admitted_root_path(fac_root);
        fs::write(&root_path, b"CORRUPTED").expect("write corrupted root");

        assert!(
            !is_economics_profile_hash_admitted(fac_root, "b3-256:aa"),
            "corrupted root must cause admission to return false (fail-closed)"
        );
    }

    /// Verify that the error variant from
    /// `load_admitted_economics_profile_root` for a corrupted file is NOT
    /// `NoAdmittedRoot`. This proves the worker can distinguish corruption
    /// from absence and deny accordingly.
    #[test]
    fn test_corrupted_root_error_is_not_no_admitted_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let broker = broker_dir(fac_root);
        fs::create_dir_all(&broker).expect("create broker dir");

        let root_path = admitted_root_path(fac_root);
        fs::write(&root_path, b"{}").expect("write empty JSON");

        let result = load_admitted_economics_profile_root(fac_root);
        assert!(result.is_err(), "empty JSON should fail validation");
        assert!(
            !matches!(result, Err(EconomicsAdoptionError::NoAdmittedRoot { .. })),
            "empty JSON must NOT be reported as NoAdmittedRoot (would allow fail-open bypass)"
        );
    }

    // =================================================================
    // Digest validation tests (TCK-00584 fix round 3)
    // =================================================================

    #[test]
    fn test_validate_digest_string_valid() {
        let valid = "b3-256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        assert!(validate_digest_string(valid).is_ok());
    }

    #[test]
    fn test_validate_digest_string_wrong_prefix() {
        let result = validate_digest_string(
            "sha256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        );
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "wrong prefix should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_digest_string_too_short() {
        let result = validate_digest_string("b3-256:aabbccdd");
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "short hex should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_digest_string_too_long() {
        let result = validate_digest_string(
            "b3-256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd0011223300",
        );
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "long hex should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_digest_string_uppercase_hex() {
        let result = validate_digest_string(
            "b3-256:AABBCCDD00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        );
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "uppercase hex should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_digest_string_non_hex_chars() {
        let result = validate_digest_string(
            "b3-256:gghhiijj00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        );
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "non-hex chars should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_digest_string_empty() {
        let result = validate_digest_string("");
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "empty string should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_looks_like_digest() {
        assert!(looks_like_digest("b3-256:aa"));
        assert!(looks_like_digest(
            "b3-256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
        ));
        assert!(!looks_like_digest("./profile.json"));
        assert!(!looks_like_digest("/tmp/profile.json"));
        assert!(!looks_like_digest("-"));
        assert!(!looks_like_digest(""));
    }

    // =================================================================
    // Hash-only adoption tests (TCK-00584 fix round 3)
    // =================================================================

    #[test]
    fn test_adopt_by_hash_creates_admitted_root() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let digest = "b3-256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

        let (root, receipt) =
            adopt_economics_profile_by_hash(fac_root, digest, "operator:local", "hash adoption")
                .expect("adopt by hash");

        assert_eq!(root.admitted_profile_hash, digest);
        assert_eq!(root.schema, ADMITTED_ECONOMICS_PROFILE_SCHEMA);
        assert_eq!(receipt.action, EconomicsAdoptionAction::Adopt);
        assert!(receipt.old_digest.is_empty());
        assert_eq!(receipt.new_digest, digest);
        assert_eq!(receipt.actor_id, "operator:local");

        // Verify the admitted root persisted correctly.
        let loaded = load_admitted_economics_profile_root(fac_root).expect("load admitted root");
        assert_eq!(loaded.admitted_profile_hash, digest);
    }

    #[test]
    fn test_adopt_by_hash_rejects_duplicate() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let digest = "b3-256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

        adopt_economics_profile_by_hash(fac_root, digest, "operator:local", "first")
            .expect("first adopt by hash");

        let result =
            adopt_economics_profile_by_hash(fac_root, digest, "operator:local", "duplicate");
        assert!(
            matches!(result, Err(EconomicsAdoptionError::AlreadyAdmitted { .. })),
            "should reject duplicate hash adoption, got: {result:?}"
        );
    }

    #[test]
    fn test_adopt_by_hash_rejects_malformed_digest() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();

        // Wrong prefix.
        let result = adopt_economics_profile_by_hash(
            fac_root,
            "sha256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
            "operator:local",
            "bad prefix",
        );
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "wrong prefix should fail, got: {result:?}"
        );

        // Too short.
        let result =
            adopt_economics_profile_by_hash(fac_root, "b3-256:aabb", "operator:local", "short");
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "short hex should fail, got: {result:?}"
        );

        // Uppercase hex.
        let result = adopt_economics_profile_by_hash(
            fac_root,
            "b3-256:AABBCCDD00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
            "operator:local",
            "uppercase",
        );
        assert!(
            matches!(result, Err(EconomicsAdoptionError::InvalidDigest { .. })),
            "uppercase hex should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_adopt_by_hash_rotates_to_prev() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let digest1 = "b3-256:1111111100112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
        let digest2 = "b3-256:2222222200112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

        let (first_root, _) =
            adopt_economics_profile_by_hash(fac_root, digest1, "operator:local", "first")
                .expect("first adopt");

        let (second_root, receipt) =
            adopt_economics_profile_by_hash(fac_root, digest2, "operator:local", "second")
                .expect("second adopt");

        assert_ne!(
            first_root.admitted_profile_hash,
            second_root.admitted_profile_hash
        );
        assert_eq!(receipt.old_digest, first_root.admitted_profile_hash);
        assert_eq!(receipt.new_digest, second_root.admitted_profile_hash);

        // Verify prev file exists with first hash.
        let prev = load_bounded_json::<AdmittedEconomicsProfileRootV1>(
            &prev_root_path(fac_root),
            MAX_ADMITTED_ROOT_FILE_SIZE,
        )
        .expect("load prev");
        assert_eq!(prev.admitted_profile_hash, first_root.admitted_profile_hash);
    }

    #[test]
    fn test_adopt_by_hash_receipt_persisted() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let digest = "b3-256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

        let (_, receipt) =
            adopt_economics_profile_by_hash(fac_root, digest, "operator:local", "test")
                .expect("adopt by hash");

        let receipts = receipts_dir(fac_root);
        assert!(receipts.exists(), "receipts directory should exist");

        let entries: Vec<_> = fs::read_dir(&receipts)
            .expect("read receipts dir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one receipt should be persisted");

        let receipt_bytes = fs::read(entries[0].path()).expect("read receipt");
        let loaded = deserialize_adoption_receipt(&receipt_bytes).expect("deserialize");
        assert_eq!(loaded.content_hash, receipt.content_hash);
    }

    /// Verify that hash-adopted profiles are admitted by
    /// `is_economics_profile_hash_admitted` (worker path).
    #[test]
    fn test_hash_adopted_profile_is_admitted() {
        let tmp = tempdir().expect("tempdir");
        let fac_root = tmp.path();
        let digest = "b3-256:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";

        adopt_economics_profile_by_hash(fac_root, digest, "operator:local", "test")
            .expect("adopt by hash");

        assert!(
            is_economics_profile_hash_admitted(fac_root, digest),
            "hash-adopted profile must be admitted"
        );

        let wrong = "b3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(
            !is_economics_profile_hash_admitted(fac_root, wrong),
            "wrong hash must not be admitted"
        );
    }
}
