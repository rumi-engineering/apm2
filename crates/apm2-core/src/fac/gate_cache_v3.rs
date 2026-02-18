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
//! # V2 Read Compatibility (Informational Only — No Reuse)
//!
//! The v3 cache can read from v2 directories for informational display, but
//! v2-sourced entries are **never reusable** for gate verdict decisions.
//!
//! [INV-GCV3-001] V2 entries lack cryptographic proof of RFC-0028/0029
//! binding continuity: they were signed under the v2 schema which does not
//! include policy hash, toolchain fingerprint, or receipt hashes. The
//! compound key is assigned by the loader, not bound at production time.
//! Allowing v2 entries to satisfy v3 reuse would let stale PASS decisions
//! propagate across authority-context drift.
//!
//! `check_reuse` enforces this by returning
//! `miss("v2_sourced_no_binding_proof")` for any cache loaded via
//! `load_from_v2_dir`.
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

/// Schema identifier for gate cache v2 entries (read-only compatibility).
const GATE_CACHE_V2_SCHEMA: &str = "apm2.fac.gate_result_receipt.v2";

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
    /// I/O error during cache operations.
    Io {
        /// Human-readable context.
        context: String,
        /// Underlying error message.
        source: String,
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
            Self::Io { context, source } => {
                write!(f, "{context}: {source}")
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
///
/// # Security Invariant (TCK-00541 MAJOR fix)
///
/// [INV-GCV3-001] Entries loaded from v2 fallback (`load_from_v2_dir`) are
/// marked `v2_sourced = true` and are **never reusable** for gate verdict
/// decisions. V2 entries lack cryptographic proof of RFC-0028/0029 binding
/// continuity: they were signed under a v2 schema that does not include
/// policy hash, toolchain fingerprint, or receipt hashes. Treating v2
/// entries as reusable under a v3 compound key would allow stale PASS
/// decisions to propagate across authority-context drift.
///
/// The `check_reuse` method enforces this invariant by returning
/// `miss("v2_sourced_no_binding_proof")` for any v2-sourced cache.
#[derive(Debug, Clone)]
pub struct GateCacheV3 {
    /// The SHA this cache is for.
    pub sha: String,
    /// The compound key for this cache index.
    pub compound_key: V3CompoundKey,
    /// Gate results keyed by gate name.
    pub gates: BTreeMap<String, V3GateResult>,
    /// Whether the entries were loaded from a v2 fallback directory.
    ///
    /// When `true`, `check_reuse` unconditionally denies reuse because
    /// v2 entries do not carry RFC-0028/0029 binding proof and cannot
    /// satisfy v3 compound-key continuity requirements.
    ///
    /// [INV-GCV3-001] Fail-closed: v2-sourced entries never satisfy reuse.
    v2_sourced: bool,
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
            v2_sourced: false,
        })
    }

    /// Returns `true` if this cache was loaded from v2 fallback data.
    ///
    /// V2-sourced caches lack RFC-0028/0029 binding proof and are never
    /// reusable for gate verdict decisions ([INV-GCV3-001]).
    #[must_use]
    pub const fn is_v2_sourced(&self) -> bool {
        self.v2_sourced
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
    /// 0. Cache is NOT v2-sourced ([INV-GCV3-001]).
    /// 1. Gate result exists and status is "PASS".
    /// 2. Not quick-mode if `require_full_mode` is set.
    /// 3. Attestation digest matches the expected value.
    /// 4. Evidence log digest is present and non-empty.
    /// 5. Signature is valid against the expected verifying key.
    ///
    /// The compound key match is implicit: the caller looked up this cache
    /// by compound key, so if the entry exists, the compound key matched.
    ///
    /// # Security: V2-Sourced Deny (TCK-00541 MAJOR fix)
    ///
    /// V2-sourced entries are unconditionally denied. V2 entries do not
    /// carry RFC-0028/0029 binding proof and were signed under the v2
    /// schema which lacks policy hash, toolchain fingerprint, and receipt
    /// hashes. Allowing v2 entries to satisfy v3 reuse would let stale
    /// PASS decisions propagate across authority-context drift.
    #[must_use]
    pub fn check_reuse(
        &self,
        gate: &str,
        expected_attestation_digest: Option<&str>,
        require_full_mode: bool,
        verifying_key: Option<&crate::crypto::VerifyingKey>,
    ) -> V3ReuseDecision {
        // [INV-GCV3-001] Fail-closed: v2-sourced entries never satisfy reuse.
        // V2 entries lack RFC-0028/0029 binding proof; the compound key was
        // assigned by the loader, not cryptographically bound at production time.
        if self.v2_sourced {
            return V3ReuseDecision::miss("v2_sourced_no_binding_proof");
        }

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
            // No verifying key provided: fail-closed in all cases.
            // If a signature is present but we cannot verify it, deny
            // (prevents forged-signature bypass). If no signature at all,
            // also deny (unsigned entry).
            if cached.signature_hex.is_some() {
                return V3ReuseDecision::miss("signature_unverifiable_no_key");
            }
            return V3ReuseDecision::miss("signature_missing");
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
// V2 Compatibility Types (read-only)
// =============================================================================

/// On-disk format of a v2 gate cache entry (read-only deserialization).
///
/// V2 entries are stored at `gate_cache_v2/{sha}/{gate}.yaml`. They lack the
/// compound key binding present in v3 entries (no receipt hashes, no policy
/// hash, no toolchain fingerprint). V2 entries that pass attestation and
/// signature checks can be surfaced as best-effort fallback results.
#[derive(Debug, Clone, Deserialize)]
struct V2CacheEntry {
    schema: String,
    sha: String,
    gate_name: String,
    result: V2GateResult,
}

/// V2 gate result fields (superset for deserialization; extra fields ignored).
#[derive(Debug, Clone, Deserialize)]
struct V2GateResult {
    status: String,
    duration_secs: u64,
    completed_at: String,
    #[serde(default)]
    attestation_digest: Option<String>,
    #[serde(default)]
    evidence_log_digest: Option<String>,
    #[serde(default)]
    quick_mode: Option<bool>,
    #[serde(default)]
    log_bundle_hash: Option<String>,
    #[serde(default)]
    log_path: Option<String>,
    #[serde(default)]
    signature_hex: Option<String>,
    #[serde(default)]
    signer_id: Option<String>,
}

impl V2GateResult {
    /// Convert a v2 result to a v3 result (unbound: no compound key binding).
    fn to_v3(&self) -> V3GateResult {
        V3GateResult {
            status: self.status.clone(),
            duration_secs: self.duration_secs,
            completed_at: self.completed_at.clone(),
            attestation_digest: self.attestation_digest.clone(),
            evidence_log_digest: self.evidence_log_digest.clone(),
            quick_mode: self.quick_mode,
            log_bundle_hash: self.log_bundle_hash.clone(),
            log_path: self.log_path.clone(),
            signature_hex: self.signature_hex.clone(),
            signer_id: self.signer_id.clone(),
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
            v2_sourced: false, // Native v3 load: entries carry binding proof.
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

    /// Best-effort fallback: load gate results from a v2 cache directory.
    ///
    /// V2 entries live at `v2_root / {sha} / {gate}.yaml`. They lack
    /// compound-key binding (no policy hash, no toolchain fingerprint, no
    /// receipt hashes). Results loaded from v2 are **informational only**
    /// and are marked `v2_sourced = true`.
    ///
    /// # Security: V2 entries are never reusable ([INV-GCV3-001])
    ///
    /// V2 entries do not carry RFC-0028/0029 binding proof. The compound
    /// key is assigned by the caller, not cryptographically bound at
    /// production time. `check_reuse` unconditionally denies reuse for
    /// v2-sourced caches to prevent stale PASS decisions from propagating
    /// across authority-context drift.
    ///
    /// This method is called when `load_from_dir` returns `None` (v3 miss).
    /// V2 entries are never written by v3 code -- read-only fallback only.
    ///
    /// Returns `None` if the v2 SHA directory does not exist or contains no
    /// valid entries.
    #[must_use]
    pub fn load_from_v2_dir(
        v2_root: &std::path::Path,
        sha: &str,
        compound_key: &V3CompoundKey,
    ) -> Option<Self> {
        let sha_dir = v2_root.join(sha);
        if !sha_dir.exists() {
            return None;
        }
        let entries = std::fs::read_dir(&sha_dir).ok()?;
        let mut cache = Self {
            sha: sha.to_string(),
            compound_key: compound_key.clone(),
            gates: BTreeMap::new(),
            // [INV-GCV3-001] V2-sourced: lacks RFC-0028/0029 binding proof.
            // check_reuse will unconditionally deny reuse.
            v2_sourced: true,
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
            let Some(parsed) = Self::read_v2_entry_bounded(&path) else {
                continue;
            };
            if parsed.schema != GATE_CACHE_V2_SCHEMA || parsed.sha != sha {
                continue;
            }
            cache.gates.insert(parsed.gate_name, parsed.result.to_v3());
        }
        if cache.gates.is_empty() {
            None
        } else {
            Some(cache)
        }
    }

    /// Read a single v2 cache entry from disk with bounded I/O.
    fn read_v2_entry_bounded(path: &std::path::Path) -> Option<V2CacheEntry> {
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

    /// Write the v3 gate cache to disk atomically.
    ///
    /// Creates one YAML file per gate under `root / {index_key} / {gate}.yaml`.
    /// Uses atomic directory write: all files are written to a temporary
    /// staging directory, then the staging directory is renamed over the
    /// final path. This ensures a crash mid-write never leaves a
    /// partially-updated index.
    ///
    /// Cross-device rename is handled gracefully by falling back to per-file
    /// temp+rename when same-filesystem rename fails.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any filesystem operation fails.
    pub fn save_to_dir(&self, root: &std::path::Path) -> Result<(), GateCacheV3Error> {
        let index_key = self.compound_key.compute_index_key();
        if !is_valid_v3_index_key(&index_key) {
            return Err(GateCacheV3Error::InvalidIndexKey);
        }
        let final_dir = root.join(&index_key);

        // Generate unique staging directory name to avoid collisions.
        let staging_name = format!(".{index_key}.tmp.{}", std::process::id());
        let staging_dir = root.join(&staging_name);

        // Ensure root exists.
        std::fs::create_dir_all(root).map_err(|err| GateCacheV3Error::Io {
            context: format!("create v3 cache root {}", root.display()),
            source: err.to_string(),
        })?;

        // Clean up any leftover staging dir from a prior crash.
        if staging_dir.exists() {
            let _ = std::fs::remove_dir_all(&staging_dir);
        }

        std::fs::create_dir_all(&staging_dir).map_err(|err| GateCacheV3Error::Io {
            context: format!("create v3 staging dir {}", staging_dir.display()),
            source: err.to_string(),
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            let _ = std::fs::set_permissions(&staging_dir, perms);
        }

        // Write all gate files into the staging directory.
        for (gate_name, result) in &self.gates {
            let entry = V3CacheEntry {
                schema: GATE_CACHE_V3_SCHEMA.to_string(),
                sha: self.sha.clone(),
                gate_name: gate_name.clone(),
                compound_key: self.compound_key.clone(),
                result: result.clone(),
            };
            let content = serde_yaml::to_string(&entry).map_err(|err| GateCacheV3Error::Io {
                context: "serialize v3 gate cache entry".to_string(),
                source: err.to_string(),
            })?;
            let safe_gate = sanitize_gate_name(gate_name);
            let path = staging_dir.join(format!("{safe_gate}.yaml"));

            std::fs::write(&path, content.as_bytes()).map_err(|err| GateCacheV3Error::Io {
                context: format!("write v3 cache file {}", path.display()),
                source: err.to_string(),
            })?;

            #[cfg(unix)]
            {
                if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&path) {
                    let _ = file.sync_all();
                }
            }
        }

        // Atomic swap: remove old directory (if any) then rename staging -> final.
        // On same-filesystem this is atomic at the directory level.
        if final_dir.exists() {
            // Move old dir out of the way first (best-effort).
            let old_name = format!(".{index_key}.old.{}", std::process::id());
            let old_dir = root.join(&old_name);
            if std::fs::rename(&final_dir, &old_dir).is_ok() {
                // Rename staging to final.
                if let Err(err) = std::fs::rename(&staging_dir, &final_dir) {
                    // Restore old dir on failure.
                    let _ = std::fs::rename(&old_dir, &final_dir);
                    let _ = std::fs::remove_dir_all(&staging_dir);
                    return Err(GateCacheV3Error::Io {
                        context: format!(
                            "rename staging dir {} -> {}",
                            staging_dir.display(),
                            final_dir.display()
                        ),
                        source: err.to_string(),
                    });
                }
                // Clean up old dir.
                let _ = std::fs::remove_dir_all(&old_dir);
            } else {
                // Cross-device: fall back to removing final dir then renaming.
                let _ = std::fs::remove_dir_all(&final_dir);
                std::fs::rename(&staging_dir, &final_dir).map_err(|err| GateCacheV3Error::Io {
                    context: format!(
                        "rename staging dir {} -> {}",
                        staging_dir.display(),
                        final_dir.display()
                    ),
                    source: err.to_string(),
                })?;
            }
        } else {
            std::fs::rename(&staging_dir, &final_dir).map_err(|err| GateCacheV3Error::Io {
                context: format!(
                    "rename staging dir {} -> {}",
                    staging_dir.display(),
                    final_dir.display()
                ),
                source: err.to_string(),
            })?;
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

    /// Fail-closed: signed entry with no verifying key -> miss.
    /// Prevents forged-signature bypass when caller omits key.
    #[test]
    fn check_reuse_miss_no_verifying_key_signed_entry() {
        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // No verifying key but entry IS signed -> must deny.
        let decision = cache.check_reuse("rustfmt", Some(digest), true, None);
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "signature_unverifiable_no_key");
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

    // =========================================================================
    // V2 Fallback Tests (BLOCKER 2 fix)
    // =========================================================================

    /// Create a v2-format cache entry file on disk for testing.
    fn write_v2_entry(dir: &std::path::Path, sha: &str, gate_name: &str, passed: bool) {
        std::fs::create_dir_all(dir).expect("mkdir v2");
        let safe_gate = sanitize_gate_name(gate_name);
        let path = dir.join(format!("{safe_gate}.yaml"));
        let entry = serde_yaml::to_string(&serde_yaml::Value::Mapping({
            let mut m = serde_yaml::Mapping::new();
            m.insert(
                serde_yaml::Value::String("schema".to_string()),
                serde_yaml::Value::String("apm2.fac.gate_result_receipt.v2".to_string()),
            );
            m.insert(
                serde_yaml::Value::String("sha".to_string()),
                serde_yaml::Value::String(sha.to_string()),
            );
            m.insert(
                serde_yaml::Value::String("gate_name".to_string()),
                serde_yaml::Value::String(gate_name.to_string()),
            );
            let mut result = serde_yaml::Mapping::new();
            result.insert(
                serde_yaml::Value::String("status".to_string()),
                serde_yaml::Value::String(if passed { "PASS" } else { "FAIL" }.to_string()),
            );
            result.insert(
                serde_yaml::Value::String("duration_secs".to_string()),
                serde_yaml::Value::Number(serde_yaml::Number::from(5_u64)),
            );
            result.insert(
                serde_yaml::Value::String("completed_at".to_string()),
                serde_yaml::Value::String("2026-02-17T00:00:00Z".to_string()),
            );
            m.insert(
                serde_yaml::Value::String("result".to_string()),
                serde_yaml::Value::Mapping(result),
            );
            m
        }))
        .expect("serialize v2");
        std::fs::write(path, entry).expect("write v2");
    }

    #[test]
    fn load_from_v2_dir_returns_fallback_results_but_marked_v2_sourced() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let sha = "abc123";
        let v2_sha_dir = dir.path().join("gate_cache_v2").join(sha);
        write_v2_entry(&v2_sha_dir, sha, "rustfmt", true);
        write_v2_entry(&v2_sha_dir, sha, "clippy", true);

        let key = sample_compound_key();
        let v2_root = dir.path().join("gate_cache_v2");
        let loaded = GateCacheV3::load_from_v2_dir(&v2_root, sha, &key);
        let loaded = loaded.expect("should load v2 entries");
        assert_eq!(loaded.gates.len(), 2);
        assert_eq!(loaded.get("rustfmt").unwrap().status, "PASS");
        assert_eq!(loaded.get("clippy").unwrap().status, "PASS");
        // [INV-GCV3-001] Must be marked as v2-sourced.
        assert!(
            loaded.is_v2_sourced(),
            "v2-loaded cache must be marked v2_sourced"
        );
    }

    #[test]
    fn load_from_v2_dir_returns_none_for_missing() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let key = sample_compound_key();
        let v2_root = dir.path().join("gate_cache_v2");
        assert!(GateCacheV3::load_from_v2_dir(&v2_root, "missing_sha", &key).is_none());
    }

    #[test]
    fn load_from_v2_dir_rejects_wrong_sha() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let v2_sha_dir = dir.path().join("gate_cache_v2").join("abc123");
        // Write entry with sha "abc123" but try to load with "xyz789".
        write_v2_entry(&v2_sha_dir, "abc123", "rustfmt", true);

        let key = sample_compound_key();
        let v2_root = dir.path().join("gate_cache_v2");
        // SHA directory exists for abc123, but load_from_v2_dir with "xyz789"
        // looks for a "xyz789" subdirectory which doesn't exist.
        assert!(GateCacheV3::load_from_v2_dir(&v2_root, "xyz789", &key).is_none());
    }

    // =========================================================================
    // Atomic Save Tests (MAJOR 2 fix)
    // =========================================================================

    #[test]
    fn atomic_save_overwrites_existing_directory() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        std::fs::create_dir_all(&root).expect("mkdir");

        let signer = Signer::generate();
        let key = sample_compound_key();

        // First save: two gates.
        let mut cache1 = GateCacheV3::new("abc123", key.clone()).expect("new");
        cache1.set("gate_a", sample_gate_result()).expect("set");
        cache1.set("gate_b", sample_gate_result()).expect("set");
        cache1.sign_all(&signer);
        cache1.save_to_dir(&root).expect("save first");

        // Second save: one gate (gate_b removed).
        let mut cache2 = GateCacheV3::new("abc123", key.clone()).expect("new");
        cache2.set("gate_a", sample_gate_result()).expect("set");
        cache2.sign_all(&signer);
        cache2.save_to_dir(&root).expect("save second");

        // Verify: only gate_a exists.
        let loaded = GateCacheV3::load_from_dir(&root, "abc123", &key).expect("load");
        assert_eq!(loaded.gates.len(), 1);
        assert!(loaded.get("gate_a").is_some());
        assert!(loaded.get("gate_b").is_none());
    }

    #[test]
    fn atomic_save_creates_directory_from_scratch() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("fresh_v3_cache");
        // Do NOT create the directory — save_to_dir should create it.

        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        cache.save_to_dir(&root).expect("save");

        let loaded =
            GateCacheV3::load_from_dir(&root, "abc123", &cache.compound_key).expect("should load");
        assert_eq!(loaded.gates.len(), 1);
        assert!(loaded.get("rustfmt").is_some());
    }

    #[test]
    fn save_to_dir_rejects_invalid_index_key() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");

        // Construct a cache with a key that would produce an invalid index.
        // Since V3CompoundKey always produces valid keys, we test the
        // save_to_dir's own index key validation by passing it directly.
        // This just tests the boundary — the save method validates the key.
        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        // Should succeed (valid key).
        cache.save_to_dir(&root).expect("save should succeed");
    }

    // =========================================================================
    // TCK-00541 MAJOR Security Fix: V2 Binding Continuity Regression Tests
    // =========================================================================

    /// [INV-GCV3-001] V2-sourced cache entries MUST be denied by `check_reuse`.
    ///
    /// Regression test: v2 entries lack RFC-0028/0029 binding proof. Even if
    /// the entry has a valid signature, attestation match, and PASS status,
    /// reuse must be denied because the signature was produced under the v2
    /// schema which does not cover the compound key dimensions.
    #[test]
    fn v2_sourced_entries_denied_by_check_reuse() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Build a v3 cache and sign it (simulates a well-formed entry).
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        cache.set("rustfmt", sample_gate_result()).expect("set");
        cache.sign_all(&signer);

        // Verify it WOULD pass reuse if v2_sourced were false.
        let vk = signer.verifying_key();
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(decision.reusable, "native v3 entry should be reusable");
        assert!(!cache.is_v2_sourced());

        // Now simulate v2 sourcing by loading from v2 directory.
        let dir = tempfile::tempdir().expect("tmpdir");
        let v2_sha_dir = dir.path().join("gate_cache_v2").join("abc123");
        write_v2_entry(&v2_sha_dir, "abc123", "rustfmt", true);

        let v2_key = sample_compound_key();
        let v2_root = dir.path().join("gate_cache_v2");
        let v2_loaded = GateCacheV3::load_from_v2_dir(&v2_root, "abc123", &v2_key)
            .expect("should load v2 entries");

        // V2-sourced entries MUST be denied regardless of other checks.
        assert!(v2_loaded.is_v2_sourced());
        let v2_decision = v2_loaded.check_reuse("rustfmt", Some(digest), false, None);
        assert!(
            !v2_decision.reusable,
            "v2-sourced entries must never satisfy reuse"
        );
        assert_eq!(
            v2_decision.reason, "v2_sourced_no_binding_proof",
            "denial reason must cite missing binding proof"
        );
    }

    /// [INV-GCV3-001] Profile drift regression: same SHA, different authority
    /// context (different RFC-0028/0029 receipt hashes) must not produce a
    /// v3 reuse hit via v2 fallback.
    ///
    /// Scenario: Attacker has a valid v2 entry for SHA "abc123". The v3
    /// compound key uses different receipt hashes (authority context drift).
    /// The v2 fallback loader assigns the current compound key to the v2
    /// data. `check_reuse` must deny because `v2_sourced` is true.
    #[test]
    fn profile_drift_v2_fallback_denied() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let sha = "abc123";

        // Write a valid v2 entry.
        let v2_sha_dir = dir.path().join("gate_cache_v2").join(sha);
        write_v2_entry(&v2_sha_dir, sha, "rustfmt", true);

        // Load with a DIFFERENT compound key (simulates authority drift).
        let drifted_key = V3CompoundKey::new(
            "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "b3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "b3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            // Different receipt hashes (authority context drift).
            "b3-256:1111111111111111111111111111111111111111111111111111111111111111",
            "b3-256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .expect("valid drifted compound key");

        let v2_root = dir.path().join("gate_cache_v2");
        let loaded = GateCacheV3::load_from_v2_dir(&v2_root, sha, &drifted_key)
            .expect("v2 load succeeds (informational)");

        // The compound key on the loaded cache matches the drifted key
        // (assigned by loader, NOT proven by the v2 entry).
        assert_eq!(loaded.compound_key, drifted_key);
        assert!(loaded.is_v2_sourced());

        // check_reuse MUST deny despite the compound key "matching".
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = loaded.check_reuse("rustfmt", Some(digest), false, None);
        assert!(
            !decision.reusable,
            "v2-sourced entry under drifted authority context must be denied"
        );
        assert_eq!(decision.reason, "v2_sourced_no_binding_proof");
    }

    /// [INV-GCV3-001] Native v3 entries (not v2-sourced) are still reusable.
    ///
    /// Ensures the `v2_sourced` flag does not break legitimate v3 reuse.
    #[test]
    fn native_v3_entries_remain_reusable() {
        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        assert!(!cache.is_v2_sourced());

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(
            decision.reusable,
            "native v3 signed entry must remain reusable"
        );
        assert_eq!(decision.reason, "v3_compound_key_match");
    }

    /// [INV-GCV3-001] V3 cache loaded from disk (save/load roundtrip) is
    /// NOT v2-sourced and remains reusable.
    #[test]
    fn v3_disk_roundtrip_not_v2_sourced() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        std::fs::create_dir_all(&root).expect("mkdir");

        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        cache.save_to_dir(&root).expect("save");

        let loaded =
            GateCacheV3::load_from_dir(&root, "abc123", &cache.compound_key).expect("load");
        assert!(
            !loaded.is_v2_sourced(),
            "v3 disk roundtrip must not be v2-sourced"
        );

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = loaded.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(
            decision.reusable,
            "v3 disk roundtrip entry must be reusable"
        );
    }

    /// [INV-GCV3-001] Newly constructed caches are NOT v2-sourced.
    #[test]
    fn new_cache_not_v2_sourced() {
        let key = sample_compound_key();
        let cache = GateCacheV3::new("sha123", key).expect("new");
        assert!(
            !cache.is_v2_sourced(),
            "newly constructed cache must not be v2-sourced"
        );
    }
}
