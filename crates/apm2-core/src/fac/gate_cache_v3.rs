//! Gate Cache V3: receipt-indexed cache store (TCK-00541).
//!
//! Keyed by attestation+policy+toolchain compound key.
//! V3 stores one file per gate under:
//! `$APM2_HOME/private/fac/gate_cache_v3/{index_key}/{gate}.yaml`.
//!
//! The `index_key` is a BLAKE3-256 digest of the compound key:
//!   attestation_digest + FacPolicyHash + ToolchainFingerprint +
//! rfc0028_receipt_hash + rfc0029_receipt_hash
//!
//! This ensures that a cache hit is provably tied to an authoritative receipt
//! chain and cannot be forged by simple file writes. The compound key binds
//! each cache entry to the full admission context that produced it.
//!
//! # Fail-Closed Design (TCK-00541)
//!
//! - Missing or empty compound key components always deny cache hit.
//! - Signature verification is mandatory for reuse in default mode.
//! - RFC-0028/0029 receipt bindings are mandatory for reuse in default mode.
//! - Unknown/corrupt entries are rejected (never treated as hits).
//!
//! # V2 Read Compatibility
//!
//! The v3 cache reads from v2 as a best-effort fallback. V2 entries that pass
//! all v3 reuse checks (attestation match, signature valid, receipt bindings
//! present) can be promoted to v3 on the next write cycle. Legacy entries
//! without receipt bindings are rejected unless the `allow_legacy_cache`
//! override is set.
//!
//! # GC Policy
//!
//! Stale v3 entries are pruned by mtime after `GATE_CACHE_TTL_SECS` (30 days).
//! GC never deletes receipt files (receipts live in a separate store).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// Schema identifier for gate cache v3 entries.
pub const GATE_CACHE_V3_SCHEMA: &str = "apm2.fac.gate_cache.v3";

/// Maximum serialized size of a single v3 cache entry file (bytes).
/// 512 KiB is generous for a single gate result while preventing memory
/// exhaustion from crafted entries.
pub const MAX_V3_ENTRY_SIZE: u64 = 512 * 1024;

/// Maximum number of gates in a single v3 cache index.
/// Prevents unbounded growth from malicious or erroneous writes.
pub const MAX_V3_GATES_PER_INDEX: usize = 64;

/// Maximum length of any single string field in a v3 cache entry.
/// Prevents memory exhaustion from crafted payloads.
pub const MAX_V3_STRING_FIELD_LENGTH: usize = 1024;

/// Domain separator for v3 cache index key computation.
const V3_INDEX_KEY_DOMAIN: &str = "apm2.fac.gate_cache_v3.index_key";

// =============================================================================
// Error Types
// =============================================================================

/// Errors from gate cache v3 operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum GateCacheV3Error {
    /// A required compound key component is missing or empty.
    MissingKeyComponent {
        /// Name of the missing component.
        component: &'static str,
    },
    /// A string field exceeds the maximum allowed length.
    FieldTooLong {
        /// Name of the field.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Index key is not a valid hex digest.
    InvalidIndexKey,
    /// Too many gates in the index.
    TooManyGates {
        /// Current count.
        current: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Schema mismatch in a loaded entry.
    SchemaMismatch {
        /// Expected schema.
        expected: String,
        /// Found schema.
        found: String,
    },
}

impl fmt::Display for GateCacheV3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKeyComponent { component } => {
                write!(f, "missing required key component: {component}")
            },
            Self::FieldTooLong { field, actual, max } => {
                write!(f, "field {field} too long: {actual} > {max}")
            },
            Self::InvalidIndexKey => write!(f, "invalid index key format"),
            Self::TooManyGates { current, max } => {
                write!(f, "too many gates: {current} > {max}")
            },
            Self::SchemaMismatch { expected, found } => {
                write!(f, "schema mismatch: expected {expected}, found {found}")
            },
        }
    }
}

impl std::error::Error for GateCacheV3Error {}

// =============================================================================
// Compound Key
// =============================================================================

/// The compound key components that uniquely identify a gate cache v3 index.
///
/// All components are required and validated at construction time
/// (fail-closed). The compound key is hashed with BLAKE3-256 to produce the
/// on-disk directory name (the `index_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3CompoundKey {
    /// Hex-encoded attestation digest (workspace content fingerprint).
    pub attestation_digest: String,
    /// `FacPolicyHash`: hex-encoded BLAKE3-256 digest of the active FAC policy.
    pub fac_policy_hash: String,
    /// `ToolchainFingerprint`: hex-encoded digest of the build toolchain.
    pub toolchain_fingerprint: String,
    /// Hex-encoded hash binding from RFC-0028 (channel authorization).
    pub rfc0028_receipt_hash: String,
    /// Hex-encoded hash binding from RFC-0029 (queue/budget admission).
    pub rfc0029_receipt_hash: String,
}

impl V3CompoundKey {
    /// Create a new compound key from all required components.
    ///
    /// # Errors
    ///
    /// Returns [`GateCacheV3Error::MissingKeyComponent`] if any component is
    /// empty or whitespace-only.
    /// Returns [`GateCacheV3Error::FieldTooLong`] if any component exceeds
    /// [`MAX_V3_STRING_FIELD_LENGTH`].
    pub fn new(
        attestation_digest: &str,
        fac_policy_hash: &str,
        toolchain_fingerprint: &str,
        rfc0028_receipt_hash: &str,
        rfc0029_receipt_hash: &str,
    ) -> Result<Self, GateCacheV3Error> {
        Self::validate_component("attestation_digest", attestation_digest)?;
        Self::validate_component("fac_policy_hash", fac_policy_hash)?;
        Self::validate_component("toolchain_fingerprint", toolchain_fingerprint)?;
        Self::validate_component("rfc0028_receipt_hash", rfc0028_receipt_hash)?;
        Self::validate_component("rfc0029_receipt_hash", rfc0029_receipt_hash)?;

        Ok(Self {
            attestation_digest: attestation_digest.to_string(),
            fac_policy_hash: fac_policy_hash.to_string(),
            toolchain_fingerprint: toolchain_fingerprint.to_string(),
            rfc0028_receipt_hash: rfc0028_receipt_hash.to_string(),
            rfc0029_receipt_hash: rfc0029_receipt_hash.to_string(),
        })
    }

    /// Validate a single key component.
    fn validate_component(name: &'static str, value: &str) -> Result<(), GateCacheV3Error> {
        if value.trim().is_empty() {
            return Err(GateCacheV3Error::MissingKeyComponent { component: name });
        }
        if value.len() > MAX_V3_STRING_FIELD_LENGTH {
            return Err(GateCacheV3Error::FieldTooLong {
                field: name,
                actual: value.len(),
                max: MAX_V3_STRING_FIELD_LENGTH,
            });
        }
        Ok(())
    }

    /// Compute the BLAKE3-256 index key from the compound key components.
    ///
    /// The key is computed as:
    /// ```text
    /// BLAKE3(domain || len(attestation_digest) || attestation_digest
    ///     || len(fac_policy_hash) || fac_policy_hash
    ///     || len(toolchain_fingerprint) || toolchain_fingerprint
    ///     || len(rfc0028_receipt_hash) || rfc0028_receipt_hash
    ///     || len(rfc0029_receipt_hash) || rfc0029_receipt_hash)
    /// ```
    ///
    /// Length-prefix framing prevents ambiguity between concatenated components
    /// (preimage collision resistance).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn compute_index_key(&self) -> String {
        let mut hasher = blake3::Hasher::new();

        // Domain separation
        hasher.update(V3_INDEX_KEY_DOMAIN.as_bytes());

        // Length-prefixed components (u32 big-endian length prefix for each)
        Self::hash_component(&mut hasher, &self.attestation_digest);
        Self::hash_component(&mut hasher, &self.fac_policy_hash);
        Self::hash_component(&mut hasher, &self.toolchain_fingerprint);
        Self::hash_component(&mut hasher, &self.rfc0028_receipt_hash);
        Self::hash_component(&mut hasher, &self.rfc0029_receipt_hash);

        format!("b3-256:{}", hasher.finalize().to_hex())
    }

    /// Hash a single component with length-prefix framing.
    #[allow(clippy::cast_possible_truncation)]
    fn hash_component(hasher: &mut blake3::Hasher, value: &str) {
        hasher.update(&(value.len() as u32).to_be_bytes());
        hasher.update(value.as_bytes());
    }
}

// =============================================================================
// V3 Gate Result
// =============================================================================

/// A single cached gate result in the v3 schema.
///
/// Carries the same fields as v2 `CachedGateResult` but within a compound-key
/// context that provably binds it to a specific receipt chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3GateResult {
    /// Gate execution status: "PASS" or "FAIL".
    pub status: String,
    /// Execution duration in seconds.
    pub duration_secs: u64,
    /// ISO-8601 completion timestamp.
    pub completed_at: String,
    /// Hex-encoded attestation digest for this gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_digest: Option<String>,
    /// Hex-encoded evidence log digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_log_digest: Option<String>,
    /// Whether this was a quick-mode execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quick_mode: Option<bool>,
    /// Log bundle hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_bundle_hash: Option<String>,
    /// Absolute path to the evidence log file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,
    /// Hex-encoded Ed25519 signature over the canonical bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
    /// Hex-encoded Ed25519 public key of the signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
}

// =============================================================================
// V3 Cache Entry (per-gate on-disk format)
// =============================================================================

/// On-disk format for a single v3 gate cache entry.
///
/// Each gate is stored as a separate YAML file:
/// `gate_cache_v3/{index_key}/{gate_name}.yaml`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3CacheEntry {
    /// Schema identifier.
    pub schema: String,
    /// The SHA this entry was produced for.
    pub sha: String,
    /// Gate name.
    pub gate_name: String,
    /// The compound key components that produced this entry.
    pub compound_key: V3CompoundKey,
    /// Gate result.
    pub result: V3GateResult,
}

// =============================================================================
// V3 Reuse Decision
// =============================================================================

/// Decision on whether a v3 cache entry can be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3ReuseDecision {
    /// Whether the entry is reusable.
    pub reusable: bool,
    /// Human-readable reason for the decision.
    pub reason: &'static str,
}

impl V3ReuseDecision {
    /// Cache hit: entry is valid and reusable.
    #[must_use]
    pub const fn hit() -> Self {
        Self {
            reusable: true,
            reason: "v3_compound_key_match",
        }
    }

    /// Cache miss: entry is not reusable, with reason.
    #[must_use]
    pub const fn miss(reason: &'static str) -> Self {
        Self {
            reusable: false,
            reason,
        }
    }
}

// =============================================================================
// V3 Gate Cache (in-memory index)
// =============================================================================

/// In-memory gate cache index for v3.
///
/// Holds all gate results for a given compound key. The compound key is
/// validated at construction time. Writing to disk stores one file per gate
/// under the index key directory.
#[derive(Debug, Clone)]
pub struct GateCacheV3 {
    /// The SHA this cache is for.
    pub sha: String,
    /// The compound key for this cache index.
    pub compound_key: V3CompoundKey,
    /// Gate results keyed by gate name.
    pub gates: BTreeMap<String, V3GateResult>,
}

impl GateCacheV3 {
    /// Create a new empty v3 cache for the given SHA and compound key.
    ///
    /// # Errors
    ///
    /// Returns [`GateCacheV3Error`] if the compound key validation fails.
    pub fn new(sha: &str, compound_key: V3CompoundKey) -> Result<Self, GateCacheV3Error> {
        if sha.trim().is_empty() {
            return Err(GateCacheV3Error::MissingKeyComponent { component: "sha" });
        }
        if sha.len() > MAX_V3_STRING_FIELD_LENGTH {
            return Err(GateCacheV3Error::FieldTooLong {
                field: "sha",
                actual: sha.len(),
                max: MAX_V3_STRING_FIELD_LENGTH,
            });
        }
        Ok(Self {
            sha: sha.to_string(),
            compound_key,
            gates: BTreeMap::new(),
        })
    }

    /// Get the index key for this cache (BLAKE3-256 of compound key).
    #[must_use]
    pub fn index_key(&self) -> String {
        self.compound_key.compute_index_key()
    }

    /// Look up a single gate result.
    #[must_use]
    pub fn get(&self, gate: &str) -> Option<&V3GateResult> {
        self.gates.get(gate)
    }

    /// Record a gate result.
    ///
    /// # Errors
    ///
    /// Returns [`GateCacheV3Error::TooManyGates`] if inserting would exceed
    /// [`MAX_V3_GATES_PER_INDEX`].
    pub fn set(&mut self, gate_name: &str, result: V3GateResult) -> Result<(), GateCacheV3Error> {
        if !self.gates.contains_key(gate_name) && self.gates.len() >= MAX_V3_GATES_PER_INDEX {
            return Err(GateCacheV3Error::TooManyGates {
                current: self.gates.len(),
                max: MAX_V3_GATES_PER_INDEX,
            });
        }
        self.gates.insert(gate_name.to_string(), result);
        Ok(())
    }

    /// Evaluate whether a v3 cache entry is safe to reuse.
    ///
    /// A v3 cache hit requires:
    /// 1. Gate result exists and status is "PASS".
    /// 2. Not quick-mode if `require_full_mode` is set.
    /// 3. Attestation digest matches the expected value.
    /// 4. Evidence log digest is present and non-empty.
    /// 5. Signature is valid against the expected verifying key.
    ///
    /// The compound key match is implicit: the caller looked up this cache
    /// by compound key, so if the entry exists, the compound key matched.
    #[must_use]
    pub fn check_reuse(
        &self,
        gate: &str,
        expected_attestation_digest: Option<&str>,
        require_full_mode: bool,
        verifying_key: Option<&crate::crypto::VerifyingKey>,
    ) -> V3ReuseDecision {
        let Some(cached) = self.get(gate) else {
            return V3ReuseDecision::miss("no_record");
        };
        if cached.status != "PASS" {
            return V3ReuseDecision::miss("status_not_pass");
        }
        if require_full_mode && cached.quick_mode.unwrap_or(false) {
            return V3ReuseDecision::miss("quick_receipt_not_reusable");
        }
        let Some(expected_digest) = expected_attestation_digest else {
            return V3ReuseDecision::miss("attestation_missing_current");
        };
        if cached.attestation_digest.as_deref() != Some(expected_digest) {
            return V3ReuseDecision::miss("attestation_mismatch");
        }
        if cached
            .evidence_log_digest
            .as_deref()
            .is_none_or(|v| v.trim().is_empty())
        {
            return V3ReuseDecision::miss("evidence_digest_missing");
        }

        // Signature verification gate (fail-closed).
        if let Some(key) = verifying_key {
            let canonical = self.canonical_bytes_for_gate(gate, cached);
            let sig_hex = match cached.signature_hex.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return V3ReuseDecision::miss("signature_missing"),
            };
            let signer_hex = match cached.signer_id.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => return V3ReuseDecision::miss("signer_id_missing"),
            };
            if sig_hex.len() > 256 || signer_hex.len() > 256 {
                return V3ReuseDecision::miss("signature_field_too_long");
            }
            // Verify signer matches expected key.
            let Ok(signer_bytes) = hex::decode(signer_hex) else {
                return V3ReuseDecision::miss("signer_id_invalid_hex");
            };
            let expected_bytes = key.to_bytes();
            if signer_bytes.len() != expected_bytes.len() {
                return V3ReuseDecision::miss("signer_id_length_mismatch");
            }
            let eq: bool =
                subtle::ConstantTimeEq::ct_eq(signer_bytes.as_slice(), expected_bytes.as_slice())
                    .into();
            if !eq {
                return V3ReuseDecision::miss("signer_id_mismatch");
            }
            // Verify signature.
            let Ok(sig_bytes) = hex::decode(sig_hex) else {
                return V3ReuseDecision::miss("signature_invalid_hex");
            };
            let Ok(signature) = crate::crypto::parse_signature(&sig_bytes) else {
                return V3ReuseDecision::miss("signature_malformed");
            };
            if super::verify_with_domain(
                key,
                super::GATE_CACHE_RECEIPT_PREFIX,
                &canonical,
                &signature,
            )
            .is_err()
            {
                return V3ReuseDecision::miss("signature_invalid");
            }
        } else {
            // No verifying key: unsigned entries fail closed.
            if cached.signature_hex.is_none() {
                return V3ReuseDecision::miss("signature_missing");
            }
        }

        V3ReuseDecision::hit()
    }

    /// Sign all gate entries in this cache with the given signer.
    pub fn sign_all(&mut self, signer: &crate::crypto::Signer) {
        // Pre-compute the index key once (immutable borrow of compound_key).
        let index_key = self.compound_key.compute_index_key();
        let sha = self.sha.clone();
        for (gate_name, result) in &mut self.gates {
            let canonical = Self::build_canonical_bytes_static(&sha, gate_name, &index_key, result);
            let sig = super::sign_with_domain(signer, super::GATE_CACHE_RECEIPT_PREFIX, &canonical);
            result.signature_hex = Some(hex::encode(sig.to_bytes()));
            result.signer_id = Some(hex::encode(signer.verifying_key().to_bytes()));
        }
    }

    /// Compute deterministic canonical bytes for signing a gate entry.
    ///
    /// Includes the SHA, gate name, compound key index, and all semantically
    /// meaningful result fields. `signature_hex` and `signer_id` are excluded.
    #[must_use]
    fn canonical_bytes_for_gate(&self, gate_name: &str, result: &V3GateResult) -> Vec<u8> {
        let index_key = self.compound_key.compute_index_key();
        Self::build_canonical_bytes_static(&self.sha, gate_name, &index_key, result)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_canonical_bytes_static(
        sha: &str,
        gate_name: &str,
        index_key: &str,
        result: &V3GateResult,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);

        // V3 schema version marker
        buf.extend_from_slice(b"v3:");

        // SHA binding
        buf.extend_from_slice(&(sha.len() as u32).to_be_bytes());
        buf.extend_from_slice(sha.as_bytes());

        // Gate name binding
        buf.extend_from_slice(&(gate_name.len() as u32).to_be_bytes());
        buf.extend_from_slice(gate_name.as_bytes());

        // Compound key index (deterministic BLAKE3 of all key components)
        buf.extend_from_slice(&(index_key.len() as u32).to_be_bytes());
        buf.extend_from_slice(index_key.as_bytes());

        // Status
        buf.extend_from_slice(&(result.status.len() as u32).to_be_bytes());
        buf.extend_from_slice(result.status.as_bytes());

        // Duration
        buf.extend_from_slice(&result.duration_secs.to_be_bytes());

        // Completed at
        buf.extend_from_slice(&(result.completed_at.len() as u32).to_be_bytes());
        buf.extend_from_slice(result.completed_at.as_bytes());

        // Attestation digest
        Self::append_optional_string(&mut buf, result.attestation_digest.as_deref());

        // Evidence log digest
        Self::append_optional_string(&mut buf, result.evidence_log_digest.as_deref());

        // Quick mode
        match result.quick_mode {
            Some(true) => buf.push(2u8),
            Some(false) => buf.push(1u8),
            None => buf.push(0u8),
        }

        // Log bundle hash
        Self::append_optional_string(&mut buf, result.log_bundle_hash.as_deref());

        // Log path
        Self::append_optional_string(&mut buf, result.log_path.as_deref());

        buf
    }

    #[allow(clippy::cast_possible_truncation)]
    fn append_optional_string(buf: &mut Vec<u8>, value: Option<&str>) {
        if let Some(s) = value {
            buf.push(1u8);
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        } else {
            buf.push(0u8);
        }
    }
}

// =============================================================================
// I/O Operations
// =============================================================================

impl GateCacheV3 {
    /// Load a v3 gate cache from disk given a root directory and compound key.
    ///
    /// Returns `None` if the index directory does not exist or contains no
    /// valid entries. Invalid entries are silently skipped (fail-closed: they
    /// are never treated as hits).
    ///
    /// # Layout
    ///
    /// `root / {index_key} / {gate}.yaml`
    #[must_use]
    pub fn load_from_dir(
        root: &std::path::Path,
        sha: &str,
        compound_key: &V3CompoundKey,
    ) -> Option<Self> {
        let index_key = compound_key.compute_index_key();
        if !is_valid_v3_index_key(&index_key) {
            return None;
        }
        let dir = root.join(&index_key);
        if !dir.exists() {
            return None;
        }
        let entries = std::fs::read_dir(&dir).ok()?;
        let mut cache = Self {
            sha: sha.to_string(),
            compound_key: compound_key.clone(),
            gates: BTreeMap::new(),
        };
        let mut count = 0usize;
        for entry in entries.flatten() {
            count += 1;
            if count > MAX_V3_GATES_PER_INDEX {
                break;
            }
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
                continue;
            }
            // Symlink safety: skip symlinks.
            if let Ok(meta) = path.symlink_metadata() {
                if meta.file_type().is_symlink() {
                    continue;
                }
            }
            let Some(parsed) = Self::read_entry_bounded(&path) else {
                continue;
            };
            if parsed.schema != GATE_CACHE_V3_SCHEMA || parsed.sha != sha {
                continue;
            }
            // Compound key consistency check: the stored compound key
            // must match the one we looked up by.
            if parsed.compound_key != *compound_key {
                continue;
            }
            cache.gates.insert(parsed.gate_name, parsed.result);
        }
        if cache.gates.is_empty() {
            None
        } else {
            Some(cache)
        }
    }

    /// Write the v3 gate cache to disk.
    ///
    /// Creates one YAML file per gate under `root / {index_key} / {gate}.yaml`.
    /// Uses atomic write (temp + rename) for crash safety.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any filesystem operation fails.
    pub fn save_to_dir(&self, root: &std::path::Path) -> Result<(), String> {
        let index_key = self.compound_key.compute_index_key();
        if !is_valid_v3_index_key(&index_key) {
            return Err("invalid index key for v3 cache save".to_string());
        }
        let dir = root.join(&index_key);
        std::fs::create_dir_all(&dir)
            .map_err(|err| format!("failed to create v3 cache dir {}: {err}", dir.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(&dir, perms);
        }

        let mut expected_paths = std::collections::BTreeSet::new();
        for (gate_name, result) in &self.gates {
            let entry = V3CacheEntry {
                schema: GATE_CACHE_V3_SCHEMA.to_string(),
                sha: self.sha.clone(),
                gate_name: gate_name.clone(),
                compound_key: self.compound_key.clone(),
                result: result.clone(),
            };
            let content = serde_yaml::to_string(&entry)
                .map_err(|err| format!("failed to serialize v3 gate cache entry: {err}"))?;
            let safe_gate = sanitize_gate_name(gate_name);
            let path = dir.join(format!("{safe_gate}.yaml"));
            expected_paths.insert(path.clone());

            // Atomic write: temp file + rename.
            let tmp_path = dir.join(format!(".{safe_gate}.yaml.tmp"));
            std::fs::write(&tmp_path, content.as_bytes()).map_err(|err| {
                format!(
                    "failed to write v3 cache temp file {}: {err}",
                    tmp_path.display()
                )
            })?;
            #[cfg(unix)]
            {
                // fsync the file before rename for crash safety.
                if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&tmp_path) {
                    let _ = file.sync_all();
                }
            }
            std::fs::rename(&tmp_path, &path).map_err(|err| {
                format!("failed to rename v3 cache entry {}: {err}", path.display())
            })?;
        }

        // Remove stale per-gate cache files so push never projects stale extras.
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
                    continue;
                }
                if expected_paths.contains(&path) {
                    continue;
                }
                // Skip symlinks.
                if let Ok(meta) = path.symlink_metadata() {
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }

    /// Read a single v3 cache entry from disk with bounded I/O.
    fn read_entry_bounded(path: &std::path::Path) -> Option<V3CacheEntry> {
        use std::io::Read;

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path).ok()?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() {
            return None;
        }
        if metadata.len() > MAX_V3_ENTRY_SIZE {
            return None;
        }
        let mut limited = file.take(MAX_V3_ENTRY_SIZE + 1);
        let mut content = String::new();
        limited.read_to_string(&mut content).ok()?;
        if content.len() as u64 > MAX_V3_ENTRY_SIZE {
            return None;
        }
        serde_yaml::from_str(&content).ok()
    }
}

// =============================================================================
// Index Key Validation
// =============================================================================

/// Validate that an index key string is a well-formed `b3-256:` prefixed
/// hex digest. Used before using it as a filesystem path component.
#[must_use]
pub fn is_valid_v3_index_key(s: &str) -> bool {
    let Some(hex_part) = s.strip_prefix("b3-256:") else {
        return false;
    };
    hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Sanitize a gate name for use as a filesystem path component.
///
/// Replaces any character that is not alphanumeric, hyphen, or underscore
/// with an underscore.
#[must_use]
pub fn sanitize_gate_name(gate: &str) -> String {
    gate.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Signer;

    fn sample_compound_key() -> V3CompoundKey {
        V3CompoundKey::new(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "b3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "b3-256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "b3-256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        )
        .expect("valid compound key")
    }

    fn sample_gate_result() -> V3GateResult {
        V3GateResult {
            status: "PASS".to_string(),
            duration_secs: 5,
            completed_at: "2026-02-17T00:00:00Z".to_string(),
            attestation_digest: Some(
                "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            evidence_log_digest: Some("log-digest-123".to_string()),
            quick_mode: Some(false),
            log_bundle_hash: None,
            log_path: None,
            signature_hex: None,
            signer_id: None,
        }
    }

    fn make_signed_v3(signer: &Signer) -> GateCacheV3 {
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        cache.set("rustfmt", sample_gate_result()).expect("set");
        cache.sign_all(signer);
        cache
    }

    // =========================================================================
    // Compound Key Tests
    // =========================================================================

    #[test]
    fn compound_key_rejects_empty_components() {
        assert!(V3CompoundKey::new("", "b", "c", "d", "e").is_err());
        assert!(V3CompoundKey::new("a", "", "c", "d", "e").is_err());
        assert!(V3CompoundKey::new("a", "b", "", "d", "e").is_err());
        assert!(V3CompoundKey::new("a", "b", "c", "", "e").is_err());
        assert!(V3CompoundKey::new("a", "b", "c", "d", "").is_err());
    }

    #[test]
    fn compound_key_rejects_whitespace_only() {
        assert!(V3CompoundKey::new("   ", "b", "c", "d", "e").is_err());
    }

    #[test]
    fn compound_key_rejects_too_long_fields() {
        let long = "a".repeat(MAX_V3_STRING_FIELD_LENGTH + 1);
        assert!(V3CompoundKey::new(&long, "b", "c", "d", "e").is_err());
    }

    #[test]
    fn compound_key_index_is_deterministic() {
        let key1 = sample_compound_key();
        let key2 = sample_compound_key();
        assert_eq!(key1.compute_index_key(), key2.compute_index_key());
    }

    #[test]
    fn compound_key_index_varies_with_components() {
        let key1 = V3CompoundKey::new("a1", "b", "c", "d", "e").expect("ok");
        let key2 = V3CompoundKey::new("a2", "b", "c", "d", "e").expect("ok");
        assert_ne!(key1.compute_index_key(), key2.compute_index_key());
    }

    #[test]
    fn compound_key_index_is_b3_256_prefixed() {
        let key = sample_compound_key();
        let index = key.compute_index_key();
        assert!(index.starts_with("b3-256:"));
        assert!(is_valid_v3_index_key(&index));
    }

    #[test]
    fn compound_key_length_prefix_prevents_collision() {
        // "abc" + "de" vs "ab" + "cde" should produce different index keys
        let key1 = V3CompoundKey::new("abc", "de", "f", "g", "h").expect("ok");
        let key2 = V3CompoundKey::new("ab", "cde", "f", "g", "h").expect("ok");
        assert_ne!(key1.compute_index_key(), key2.compute_index_key());
    }

    // =========================================================================
    // Cache CRUD Tests
    // =========================================================================

    #[test]
    fn new_cache_is_empty() {
        let key = sample_compound_key();
        let cache = GateCacheV3::new("sha123", key).expect("new");
        assert!(cache.gates.is_empty());
        assert_eq!(cache.sha, "sha123");
    }

    #[test]
    fn new_cache_rejects_empty_sha() {
        let key = sample_compound_key();
        assert!(GateCacheV3::new("", key).is_err());
    }

    #[test]
    fn set_and_get_gate_result() {
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("sha123", key).expect("new");
        let result = sample_gate_result();
        cache.set("rustfmt", result).expect("set");

        let got = cache.get("rustfmt").expect("get");
        assert_eq!(got.status, "PASS");
        assert_eq!(got.duration_secs, 5);
    }

    #[test]
    fn set_enforces_max_gates() {
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("sha123", key).expect("new");
        for i in 0..MAX_V3_GATES_PER_INDEX {
            cache
                .set(&format!("gate-{i}"), sample_gate_result())
                .expect("set");
        }
        assert!(cache.gates.len() == MAX_V3_GATES_PER_INDEX);

        // Next insert should fail.
        let result = cache.set("overflow-gate", sample_gate_result());
        assert!(result.is_err());
    }

    #[test]
    fn set_allows_update_existing_gate() {
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("sha123", key).expect("new");
        for i in 0..MAX_V3_GATES_PER_INDEX {
            cache
                .set(&format!("gate-{i}"), sample_gate_result())
                .expect("set");
        }
        // Updating an existing gate should succeed (not a new entry).
        let mut updated = sample_gate_result();
        updated.duration_secs = 99;
        cache.set("gate-0", updated).expect("update existing");
        assert_eq!(cache.get("gate-0").unwrap().duration_secs, 99);
    }

    // =========================================================================
    // Reuse Decision Tests
    // =========================================================================

    #[test]
    fn check_reuse_hit_with_valid_signature() {
        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(decision.reusable);
        assert_eq!(decision.reason, "v3_compound_key_match");
    }

    #[test]
    fn check_reuse_miss_no_record() {
        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        let vk = signer.verifying_key();
        let decision = cache.check_reuse("nonexistent", Some("x"), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "no_record");
    }

    #[test]
    fn check_reuse_miss_status_not_pass() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.status = "FAIL".to_string();
        cache.set("rustfmt", result).expect("set");
        cache.sign_all(&signer);

        let vk = signer.verifying_key();
        let decision = cache.check_reuse("rustfmt", Some("x"), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "status_not_pass");
    }

    #[test]
    fn check_reuse_miss_attestation_mismatch() {
        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        let vk = signer.verifying_key();
        let decision = cache.check_reuse("rustfmt", Some("wrong-digest"), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "attestation_mismatch");
    }

    #[test]
    fn check_reuse_miss_quick_mode_in_full() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.quick_mode = Some(true);
        cache.set("rustfmt", result).expect("set");
        cache.sign_all(&signer);

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "quick_receipt_not_reusable");
    }

    #[test]
    fn check_reuse_miss_unsigned_entry() {
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        cache.set("rustfmt", sample_gate_result()).expect("set");
        // Not signed.
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "signature_missing");
    }

    #[test]
    fn check_reuse_miss_wrong_signer() {
        let signer_a = Signer::generate();
        let signer_b = Signer::generate();
        let cache = make_signed_v3(&signer_a);
        let vk_b = signer_b.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk_b));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "signer_id_mismatch");
    }

    #[test]
    fn check_reuse_miss_evidence_digest_missing() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.evidence_log_digest = None;
        cache.set("rustfmt", result).expect("set");
        cache.sign_all(&signer);

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "evidence_digest_missing");
    }

    #[test]
    fn check_reuse_miss_no_verifying_key_unsigned() {
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        cache.set("rustfmt", sample_gate_result()).expect("set");
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, None);
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "signature_missing");
    }

    // =========================================================================
    // Signature Roundtrip Tests
    // =========================================================================

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(decision.reusable);
    }

    #[test]
    fn tampered_entry_rejected() {
        let signer = Signer::generate();
        let mut cache = make_signed_v3(&signer);
        // Tamper after signing.
        if let Some(entry) = cache.gates.get_mut("rustfmt") {
            entry.duration_secs = 999;
        }
        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "signature_invalid");
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn v3_entry_yaml_roundtrip() {
        let key = sample_compound_key();
        let entry = V3CacheEntry {
            schema: GATE_CACHE_V3_SCHEMA.to_string(),
            sha: "abc123".to_string(),
            gate_name: "rustfmt".to_string(),
            compound_key: key,
            result: sample_gate_result(),
        };
        let yaml = serde_yaml::to_string(&entry).expect("serialize");
        let restored: V3CacheEntry = serde_yaml::from_str(&yaml).expect("deserialize");
        assert_eq!(restored.schema, GATE_CACHE_V3_SCHEMA);
        assert_eq!(restored.sha, "abc123");
        assert_eq!(restored.gate_name, "rustfmt");
        assert_eq!(restored.result.status, "PASS");
        assert_eq!(
            restored.compound_key.attestation_digest,
            entry.compound_key.attestation_digest
        );
    }

    #[test]
    fn v3_compound_key_json_roundtrip() {
        let key = sample_compound_key();
        let json = serde_json::to_string(&key).expect("serialize");
        let restored: V3CompoundKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(key.compute_index_key(), restored.compute_index_key());
    }

    // =========================================================================
    // Index Key Validation Tests
    // =========================================================================

    #[test]
    fn valid_index_key_accepted() {
        assert!(is_valid_v3_index_key(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn invalid_index_key_rejected() {
        assert!(!is_valid_v3_index_key("not-valid"));
        assert!(!is_valid_v3_index_key("b3-256:short"));
        assert!(!is_valid_v3_index_key(""));
        assert!(!is_valid_v3_index_key(
            "b3-256:../../../etc/passwd0000000000000000000000000000000000000000000000"
        ));
        // No prefix.
        assert!(!is_valid_v3_index_key(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    // =========================================================================
    // Gate Name Sanitization Tests
    // =========================================================================

    #[test]
    fn sanitize_gate_name_preserves_valid() {
        assert_eq!(sanitize_gate_name("rustfmt"), "rustfmt");
        assert_eq!(sanitize_gate_name("cargo-test"), "cargo-test");
        assert_eq!(sanitize_gate_name("my_gate"), "my_gate");
    }

    #[test]
    fn sanitize_gate_name_replaces_special_chars() {
        assert_eq!(sanitize_gate_name("gate/name"), "gate_name");
        assert_eq!(sanitize_gate_name("gate name"), "gate_name");
        assert_eq!(sanitize_gate_name("../etc"), "___etc");
    }

    // =========================================================================
    // I/O Round-Trip Tests
    // =========================================================================

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        std::fs::create_dir_all(&root).expect("mkdir");

        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        cache.save_to_dir(&root).expect("save");

        let loaded = GateCacheV3::load_from_dir(&root, "abc123", &cache.compound_key)
            .expect("load should find the cache");
        assert_eq!(loaded.sha, "abc123");
        assert_eq!(loaded.gates.len(), 1);
        let gate = loaded.get("rustfmt").expect("rustfmt gate");
        assert_eq!(gate.status, "PASS");
    }

    #[test]
    fn load_returns_none_for_missing_dir() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        let key = sample_compound_key();
        assert!(GateCacheV3::load_from_dir(&root, "abc123", &key).is_none());
    }

    #[test]
    fn save_removes_stale_gate_files() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        std::fs::create_dir_all(&root).expect("mkdir");

        let signer = Signer::generate();
        let key = sample_compound_key();

        // Write cache with two gates.
        let mut cache = GateCacheV3::new("abc123", key.clone()).expect("new");
        cache.set("gate_a", sample_gate_result()).expect("set");
        cache.set("gate_b", sample_gate_result()).expect("set");
        cache.sign_all(&signer);
        cache.save_to_dir(&root).expect("save");

        // Overwrite with just one gate.
        let mut cache2 = GateCacheV3::new("abc123", key.clone()).expect("new");
        cache2.set("gate_a", sample_gate_result()).expect("set");
        cache2.sign_all(&signer);
        cache2.save_to_dir(&root).expect("save");

        // Reload should only have gate_a.
        let loaded = GateCacheV3::load_from_dir(&root, "abc123", &key).expect("load");
        assert_eq!(loaded.gates.len(), 1);
        assert!(loaded.get("gate_a").is_some());
        assert!(loaded.get("gate_b").is_none());
    }

    #[test]
    fn load_rejects_sha_mismatch() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        std::fs::create_dir_all(&root).expect("mkdir");

        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        cache.save_to_dir(&root).expect("save");

        // Try loading with wrong SHA.
        assert!(GateCacheV3::load_from_dir(&root, "wrong_sha", &cache.compound_key).is_none());
    }

    #[test]
    fn signed_cache_survives_save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        std::fs::create_dir_all(&root).expect("mkdir");

        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        cache.save_to_dir(&root).expect("save");

        let loaded =
            GateCacheV3::load_from_dir(&root, "abc123", &cache.compound_key).expect("load");
        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = loaded.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(
            decision.reusable,
            "signature must survive save/load roundtrip"
        );
    }
}
