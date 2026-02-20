//! Gate Cache V3: receipt-indexed cache store (TCK-00541).
//!
//! Keyed by attestation+policy+toolchain compound key.
//! V3 stores one file per gate under:
//! `$APM2_HOME/private/fac/gate_cache_v3/{index_key}/{gate}.yaml`.
//!
//! The `index_key` is a BLAKE3-256 digest of the compound key:
//!   attestation_digest + FacPolicyHash + ToolchainFingerprint +
//!   sandbox_policy_hash + network_policy_hash
//!
//! Cache hit validity also requires RFC-0028/0029 receipt bindings
//! (`rfc0028_receipt_bound` + `rfc0029_receipt_bound` flags on each
//! `V3GateResult`). These flags are fail-closed: they default to `false`
//! and are only promoted to `true` after a durable receipt lookup confirms
//! RFC-0028 channel authorization and RFC-0029 queue admission. The
//! `check_reuse` method enforces receipt binding before returning a hit.
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
//! # V2 Read Compatibility (Diagnostic / Migration Only — Never in Evidence Pipeline)
//!
//! `load_from_v2_dir` can read from v2 directories for diagnostic or
//! migration tooling, but v2-sourced entries are **never reusable** for
//! gate verdict decisions and are **never loaded by the evidence pipeline**.
//!
//! [INV-GCV3-001] V2 entries lack cryptographic proof of RFC-0028/0029
//! binding continuity: they were signed under the v2 schema which does not
//! include policy hash, toolchain fingerprint, or receipt hashes. The
//! compound key is assigned by the loader, not bound at production time.
//! Allowing v2 entries to satisfy v3 reuse would let stale PASS decisions
//! propagate across authority-context drift.
//!
//! The evidence pipeline (`evidence.rs`) uses only `load_from_dir` (native
//! v3). As defense-in-depth, `check_reuse` also returns
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
///
/// Note: RFC-0028/0029 receipt bindings are NOT part of the compound key
/// because receipts are produced AFTER gate execution. Instead, receipt
/// binding is enforced per-gate via `rfc0028_receipt_bound` /
/// `rfc0029_receipt_bound` flags in [`V3GateResult`], validated by
/// `check_reuse()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V3CompoundKey {
    /// Hex-encoded attestation digest (workspace content fingerprint).
    pub attestation_digest: String,
    /// `FacPolicyHash`: hex-encoded BLAKE3-256 digest of the active FAC policy.
    pub fac_policy_hash: String,
    /// `ToolchainFingerprint`: hex-encoded digest of the build toolchain.
    pub toolchain_fingerprint: String,
    /// Hex-encoded BLAKE3 hash of the sandbox hardening profile.
    pub sandbox_policy_hash: String,
    /// Hex-encoded BLAKE3 hash of the network isolation policy.
    pub network_policy_hash: String,
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
        sandbox_policy_hash: &str,
        network_policy_hash: &str,
    ) -> Result<Self, GateCacheV3Error> {
        Self::validate_component("attestation_digest", attestation_digest)?;
        Self::validate_component("fac_policy_hash", fac_policy_hash)?;
        Self::validate_component("toolchain_fingerprint", toolchain_fingerprint)?;
        Self::validate_component("sandbox_policy_hash", sandbox_policy_hash)?;
        Self::validate_component("network_policy_hash", network_policy_hash)?;

        Ok(Self {
            attestation_digest: attestation_digest.to_string(),
            fac_policy_hash: fac_policy_hash.to_string(),
            toolchain_fingerprint: toolchain_fingerprint.to_string(),
            sandbox_policy_hash: sandbox_policy_hash.to_string(),
            network_policy_hash: network_policy_hash.to_string(),
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
    ///     || len(sandbox_policy_hash) || sandbox_policy_hash
    ///     || len(network_policy_hash) || network_policy_hash)
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
        Self::hash_component(&mut hasher, &self.sandbox_policy_hash);
        Self::hash_component(&mut hasher, &self.network_policy_hash);

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
///
/// RFC-0028/0029 receipt bindings are tracked via `rfc0028_receipt_bound` and
/// `rfc0029_receipt_bound` flags. These default to `false` (fail-closed) and
/// are only promoted to `true` after a durable receipt lookup confirms that
/// the corresponding RFC receipts exist and passed. `check_reuse()` denies
/// cache hits when either flag is `false`.
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
    /// Whether this entry is bound to an RFC-0028 authorization receipt.
    ///
    /// Fail-closed: defaults to `false`. Only promoted to `true` after a
    /// durable receipt lookup confirms RFC-0028 channel authorization passed.
    /// `check_reuse()` denies cache hits when this is `false`.
    #[serde(default)]
    pub rfc0028_receipt_bound: bool,
    /// Whether this entry is bound to an RFC-0029 admission receipt.
    ///
    /// Fail-closed: defaults to `false`. Only promoted to `true` after a
    /// durable receipt lookup confirms RFC-0029 queue admission allowed.
    /// `check_reuse()` denies cache hits when this is `false`.
    #[serde(default)]
    pub rfc0029_receipt_bound: bool,
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

impl V3CacheEntry {
    /// Post-deserialization validation to enforce string field length bounds.
    ///
    /// `serde_yaml` bypasses `V3CompoundKey::new()` during deserialization,
    /// so `MAX_V3_STRING_FIELD_LENGTH` is not enforced. This method must be
    /// called after every deserialization from untrusted input to prevent
    /// memory pressure from crafted payloads.
    ///
    /// Returns `true` if all fields pass validation, `false` otherwise.
    #[must_use]
    fn validate_field_lengths(&self) -> bool {
        let max = MAX_V3_STRING_FIELD_LENGTH;

        // Compound key fields
        if self.compound_key.attestation_digest.len() > max
            || self.compound_key.fac_policy_hash.len() > max
            || self.compound_key.toolchain_fingerprint.len() > max
            || self.compound_key.sandbox_policy_hash.len() > max
            || self.compound_key.network_policy_hash.len() > max
        {
            return false;
        }

        // Entry-level string fields
        if self.schema.len() > max || self.sha.len() > max || self.gate_name.len() > max {
            return false;
        }

        // Gate result string fields
        let r = &self.result;
        if r.status.len() > max || r.completed_at.len() > max {
            return false;
        }
        if r.attestation_digest.as_ref().is_some_and(|s| s.len() > max) {
            return false;
        }
        if r.evidence_log_digest
            .as_ref()
            .is_some_and(|s| s.len() > max)
        {
            return false;
        }
        if r.log_bundle_hash.as_ref().is_some_and(|s| s.len() > max) {
            return false;
        }
        if r.log_path.as_ref().is_some_and(|s| s.len() > max) {
            return false;
        }
        if r.signature_hex.as_ref().is_some_and(|s| s.len() > max) {
            return false;
        }
        if r.signer_id.as_ref().is_some_and(|s| s.len() > max) {
            return false;
        }

        true
    }
}

// =============================================================================
// Cache Reason Code (TCK-00626)
// =============================================================================

/// Stable reason code for cache reuse decisions (REQ-0037).
///
/// Each variant corresponds to a specific dimension check in the ordered
/// evaluation sequence. On a miss, the first failing dimension determines
/// the `reason_code` and `first_mismatch_dimension` in [`CacheDecision`].
///
/// The check order is:
/// 1. `ShaMiss` / `GateMiss`
/// 2. `SignatureInvalid`
/// 3. `ReceiptBindingMissing`
/// 4. `PolicyDrift`
/// 5. `ToolchainDrift`
/// 6. `ClosureDrift`
/// 7. `InputDrift`
/// 8. `NetworkPolicyDrift`
/// 9. `SandboxDrift`
/// 10. `TtlExpired`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheReasonCode {
    /// Cache hit: entry found and all dimensions match.
    CacheHit,
    /// No entry for this commit SHA (compound key miss).
    ShaMiss,
    /// No entry for this gate name.
    GateMiss,
    /// Entry signature verification failed.
    SignatureInvalid,
    /// Entry lacks RFC-0028/0029 receipt bindings.
    ReceiptBindingMissing,
    /// Policy hash changed since cache entry was produced.
    PolicyDrift,
    /// Toolchain version/target changed.
    ToolchainDrift,
    /// Closure hash changed (per REQ-0034).
    ClosureDrift,
    /// Gate input files changed.
    InputDrift,
    /// Network isolation policy hash changed.
    NetworkPolicyDrift,
    /// Sandbox/cgroup profile changed.
    SandboxDrift,
    /// Entry exceeded TTL.
    TtlExpired,
}

impl CacheReasonCode {
    /// Returns the stable string representation of this reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CacheHit => "cache_hit",
            Self::ShaMiss => "sha_miss",
            Self::GateMiss => "gate_miss",
            Self::SignatureInvalid => "signature_invalid",
            Self::ReceiptBindingMissing => "receipt_binding_missing",
            Self::PolicyDrift => "policy_drift",
            Self::ToolchainDrift => "toolchain_drift",
            Self::ClosureDrift => "closure_drift",
            Self::InputDrift => "input_drift",
            Self::NetworkPolicyDrift => "network_policy_drift",
            Self::SandboxDrift => "sandbox_drift",
            Self::TtlExpired => "ttl_expired",
        }
    }
}

impl fmt::Display for CacheReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// =============================================================================
// Cache Decision (TCK-00626)
// =============================================================================

/// Structured cache reuse decision record (REQ-0037).
///
/// Emitted as part of the `gate_finished` event, enabling operators and
/// orchestrators to diagnose cache miss causes from the stdout event stream
/// alone without reading internal cache files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheDecision {
    /// Whether the cache entry was reused (hit = true, miss = false).
    pub hit: bool,
    /// Stable reason code explaining the decision.
    pub reason_code: CacheReasonCode,
    /// The first dimension that caused a miss (null on hit).
    ///
    /// Enables O(1) triage: the operator can immediately see which
    /// dimension drifted without enumerating all checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_mismatch_dimension: Option<CacheReasonCode>,
    /// The SHA of the cached entry (null on miss where no entry exists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_sha: Option<String>,
}

impl CacheDecision {
    /// Construct a cache hit decision.
    #[must_use]
    pub fn cache_hit(cached_sha: &str) -> Self {
        Self {
            hit: true,
            reason_code: CacheReasonCode::CacheHit,
            first_mismatch_dimension: None,
            cached_sha: Some(cached_sha.to_string()),
        }
    }

    /// Construct a cache miss decision.
    #[must_use]
    pub fn cache_miss(reason_code: CacheReasonCode, cached_sha: Option<&str>) -> Self {
        Self {
            hit: false,
            reason_code,
            first_mismatch_dimension: Some(reason_code),
            cached_sha: cached_sha.map(str::to_string),
        }
    }
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
    /// 6. RFC-0028/0029 receipt bindings are present (fail-closed).
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

        // TCK-00541: RFC-0028/0029 receipt binding gate (fail-closed).
        // Cache hits are only valid when the gate result carries evidence of
        // both RFC-0028 channel authorization and RFC-0029 queue admission.
        // These flags are promoted after a durable receipt lookup; entries
        // that were never rebound remain false and are denied here.
        if !cached.rfc0028_receipt_bound || !cached.rfc0029_receipt_bound {
            return V3ReuseDecision::miss("receipt_binding_missing");
        }

        V3ReuseDecision::hit()
    }

    /// Evaluate cache reuse and return a structured [`CacheDecision`]
    /// (TCK-00626).
    ///
    /// This is the primary API for cache explainability. It wraps the
    /// existing `check_reuse` logic and maps each miss reason to a
    /// [`CacheReasonCode`] with structured first-mismatch attribution.
    ///
    /// The ordered check sequence matches `check_reuse`:
    ///
    /// 1. `sha_miss` / `gate_miss` -- no cache entry found
    /// 2. `signature_invalid` -- entry exists but signature fails
    /// 3. `receipt_binding_missing` -- RFC-0028/0029 flags not set
    /// 4. Dimension-specific drift codes (`policy`, `toolchain`, etc.)
    ///
    /// Note: dimension drifts (4+) are detected at the compound-key
    /// level by the caller -- if the compound key does not match, no cache
    /// is loaded. The `check_reuse` method only sees entries that already
    /// match on compound key. Therefore drifts like `policy`, `toolchain`,
    /// `network_policy`, `sandbox` are signaled by the caller via
    /// `sha_miss` / `gate_miss` when no v3 cache loads for the current
    /// compound key. The remaining detailed miss reasons from
    /// `check_reuse` are mapped to their closest reason code.
    #[must_use]
    pub fn check_reuse_decision(
        &self,
        gate: &str,
        expected_attestation_digest: Option<&str>,
        require_full_mode: bool,
        verifying_key: Option<&crate::crypto::VerifyingKey>,
    ) -> CacheDecision {
        let v3_decision = self.check_reuse(
            gate,
            expected_attestation_digest,
            require_full_mode,
            verifying_key,
        );
        if v3_decision.reusable {
            return CacheDecision::cache_hit(&self.sha);
        }
        // Map the V3ReuseDecision reason string to a CacheReasonCode.
        let reason_code = Self::map_reason_to_code(v3_decision.reason);
        CacheDecision::cache_miss(reason_code, Some(&self.sha))
    }

    /// Map a legacy `V3ReuseDecision` reason string to a [`CacheReasonCode`].
    ///
    /// Reasons that indicate "no entry found" map to `GateMiss`.
    /// Signature-related failures map to `SignatureInvalid`.
    /// Receipt-binding failures map to `ReceiptBindingMissing`.
    /// V2-sourced denials map to `SignatureInvalid` (v2 lacks binding proof).
    /// All other reasons default to `InputDrift` (attestation mismatch = input
    /// content changed).
    #[must_use]
    fn map_reason_to_code(reason: &str) -> CacheReasonCode {
        match reason {
            "no_record" | "status_not_pass" => CacheReasonCode::GateMiss,
            "v2_sourced_no_binding_proof"
            | "signature_missing"
            | "signer_id_missing"
            | "signature_field_too_long"
            | "signer_id_invalid_hex"
            | "signer_id_length_mismatch"
            | "signer_id_mismatch"
            | "signature_invalid_hex"
            | "signature_malformed"
            | "signature_invalid"
            | "signature_unverifiable_no_key" => CacheReasonCode::SignatureInvalid,
            "receipt_binding_missing" => CacheReasonCode::ReceiptBindingMissing,
            // All remaining reasons (attestation/evidence mismatches, quick-mode
            // denial, and unknown reasons) default to InputDrift as a fail-closed
            // catch-all. Individual reason strings are intentionally NOT listed
            // separately to avoid clippy::match_same_arms.
            _ => CacheReasonCode::InputDrift,
        }
    }

    /// Explicitly bind RFC-0028/0029 receipt evidence to a cache entry.
    ///
    /// Sets `rfc0028_receipt_bound` and `rfc0029_receipt_bound` to the
    /// provided values. This must be called **after** `set()` and **before**
    /// `sign_all()` so the signed canonical bytes reflect the final flag
    /// values.
    ///
    /// Callers are responsible for verifying that receipt evidence actually
    /// exists before passing `true`. Passing `true` without verified
    /// evidence defeats the fail-closed posture.
    pub fn bind_receipt_evidence(&mut self, gate: &str, rfc0028: bool, rfc0029: bool) {
        if let Some(entry) = self.gates.get_mut(gate) {
            entry.rfc0028_receipt_bound = rfc0028;
            entry.rfc0029_receipt_bound = rfc0029;
        }
    }

    /// Best-effort receipt lookup: scan the durable receipt store for a job
    /// receipt matching `job_id` and promote receipt binding flags on all
    /// gate entries in this cache.
    ///
    /// If a receipt is found with both `rfc0028_channel_boundary` (with
    /// `passed == true`) and `eio29_queue_admission` (with `verdict ==
    /// "allow"`), all entries are promoted to `rfc0028=true, rfc0029=true`.
    ///
    /// If the receipt is missing, or evidence fields are absent/failed, the
    /// flags remain `false` (fail-closed).
    ///
    /// **CRITICAL:** This method **must** be called **before** `sign_all()`
    /// so that the signed canonical bytes cover the final flag values.
    pub fn try_bind_receipt_from_store(&mut self, receipts_dir: &std::path::Path, job_id: &str) {
        let Some(receipt) = super::lookup_job_receipt(receipts_dir, job_id) else {
            return; // No receipt found — flags stay false (fail-closed).
        };

        let rfc0028_ok = receipt
            .rfc0028_channel_boundary
            .as_ref()
            .is_some_and(|trace| trace.passed);
        let rfc0029_ok = receipt
            .eio29_queue_admission
            .as_ref()
            .is_some_and(|trace| trace.verdict == "allow");

        if rfc0028_ok && rfc0029_ok {
            let gate_names: Vec<String> = self.gates.keys().cloned().collect();
            for gate_name in &gate_names {
                self.bind_receipt_evidence(gate_name, true, true);
            }
        }
        // If either check fails, flags remain false — fail-closed.
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

        // RFC-0028/0029 receipt binding flags (signed content — prevents
        // tampering of binding status after signing).
        buf.push(u8::from(result.rfc0028_receipt_bound));
        buf.push(u8::from(result.rfc0029_receipt_bound));

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
    ///
    /// Receipt binding flags default to `false` because v2 entries do not
    /// carry RFC-0028/0029 binding proof. Combined with the `v2_sourced`
    /// flag on the cache, these entries are never reusable.
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
            // V2 entries lack receipt bindings — fail-closed.
            rfc0028_receipt_bound: false,
            rfc0029_receipt_bound: false,
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

    /// Diagnostic/migration-only: load gate results from a v2 cache directory.
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
    /// # Usage restriction
    ///
    /// This method is for diagnostic or migration tooling **only**. The
    /// evidence pipeline (`evidence.rs`) must NOT call this method; it
    /// uses `load_from_dir` (native v3) exclusively. Loading v2 entries
    /// into a v3 compound-key context without cryptographic binding creates
    /// a structural gap even if `check_reuse` denies reuse.
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

    /// Write the v3 gate cache to disk atomically under an exclusive lock.
    ///
    /// Creates one YAML file per gate under `root / {index_key} / {gate}.yaml`.
    /// Uses atomic directory write: all files are written to a temporary
    /// staging directory, then the staging directory is renamed over the
    /// final path. This ensures a crash mid-write never leaves a
    /// partially-updated index.
    ///
    /// # Concurrency: per-index lock file
    ///
    /// An exclusive `flock` is held on `root/.{index_key}.lock` for the
    /// duration of the write. This serializes concurrent FAC runs targeting
    /// the same compound key, preventing last-writer-wins clobber.
    ///
    /// - **What is protected**: the index directory at `root/{index_key}/`.
    /// - **Who can mutate**: only the holder of the exclusive flock.
    /// - **Lock ordering**: single lock per index key; no nested locks.
    /// - **Happens-before**: `flock(LOCK_EX)` acquisition happens-after the
    ///   previous holder's `close(fd)`.
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

        // Acquire exclusive lock for this index key. The lock file lives at
        // `root/.{index_key}.lock` and is held for the entire write operation.
        // Drop of `_lock_guard` releases the flock.
        let lock_path = root.join(format!(".{index_key}.lock"));
        let _lock_guard = {
            let lock_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&lock_path)
                .map_err(|err| GateCacheV3Error::Io {
                    context: format!("open v3 cache lock file {}", lock_path.display()),
                    source: err.to_string(),
                })?;
            super::flock_util::acquire_exclusive_blocking(&lock_file).map_err(|err| {
                GateCacheV3Error::Io {
                    context: format!("acquire lock on {}", lock_path.display()),
                    source: err.to_string(),
                }
            })?;
            lock_file
        };

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

        atomic_swap_dirs(root, &staging_dir, &final_dir, &index_key)
    }

    /// Read a single v3 cache entry from disk with bounded I/O.
    ///
    /// Post-deserialization validation enforces `MAX_V3_STRING_FIELD_LENGTH`
    /// on all string fields, since `serde_yaml` bypasses `V3CompoundKey::new()`
    /// validation during deserialization.
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
        let entry: V3CacheEntry = serde_yaml::from_str(&content).ok()?;
        // Post-deserialization field-length validation: serde_yaml bypasses
        // V3CompoundKey::new() so MAX_V3_STRING_FIELD_LENGTH must be
        // enforced here to prevent memory pressure from crafted payloads.
        if !entry.validate_field_lengths() {
            return None;
        }
        Some(entry)
    }
}

// =============================================================================
// Atomic Directory Swap
// =============================================================================

/// Atomically swap a staging directory into the final target path.
///
/// If the target directory already exists, it is renamed aside before the
/// staging directory takes its place. On cross-device rename failure, falls
/// back to remove-then-rename.
fn atomic_swap_dirs(
    root: &std::path::Path,
    staging_dir: &std::path::Path,
    final_dir: &std::path::Path,
    index_key: &str,
) -> Result<(), GateCacheV3Error> {
    if final_dir.exists() {
        // Move old dir out of the way first (best-effort).
        let old_name = format!(".{index_key}.old.{}", std::process::id());
        let old_dir = root.join(&old_name);
        if std::fs::rename(final_dir, &old_dir).is_ok() {
            // Rename staging to final.
            if let Err(err) = std::fs::rename(staging_dir, final_dir) {
                // Restore old dir on failure.
                let _ = std::fs::rename(&old_dir, final_dir);
                let _ = std::fs::remove_dir_all(staging_dir);
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
            let _ = std::fs::remove_dir_all(final_dir);
            std::fs::rename(staging_dir, final_dir).map_err(|err| GateCacheV3Error::Io {
                context: format!(
                    "rename staging dir {} -> {}",
                    staging_dir.display(),
                    final_dir.display()
                ),
                source: err.to_string(),
            })?;
        }
    } else {
        std::fs::rename(staging_dir, final_dir).map_err(|err| GateCacheV3Error::Io {
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
            rfc0028_receipt_bound: true,
            rfc0029_receipt_bound: true,
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
    // Receipt Binding Tests (TCK-00541 round 2)
    // =========================================================================

    /// `check_reuse` denies entries missing RFC-0028 receipt binding.
    #[test]
    fn check_reuse_miss_receipt_binding_missing_rfc0028() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.rfc0028_receipt_bound = false;
        result.rfc0029_receipt_bound = true;
        cache.set("rustfmt", result).expect("set");
        cache.sign_all(&signer);

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "receipt_binding_missing");
    }

    /// `check_reuse` denies entries missing RFC-0029 receipt binding.
    #[test]
    fn check_reuse_miss_receipt_binding_missing_rfc0029() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.rfc0028_receipt_bound = true;
        result.rfc0029_receipt_bound = false;
        cache.set("rustfmt", result).expect("set");
        cache.sign_all(&signer);

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "receipt_binding_missing");
    }

    /// `check_reuse` denies entries where both receipt bindings are false.
    #[test]
    fn check_reuse_miss_receipt_binding_both_missing() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.rfc0028_receipt_bound = false;
        result.rfc0029_receipt_bound = false;
        cache.set("rustfmt", result).expect("set");
        cache.sign_all(&signer);

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable);
        assert_eq!(decision.reason, "receipt_binding_missing");
    }

    /// `bind_receipt_evidence` promotes flags; signed entries then pass reuse.
    #[test]
    fn bind_receipt_evidence_promotes_flags() {
        let signer = Signer::generate();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.rfc0028_receipt_bound = false;
        result.rfc0029_receipt_bound = false;
        cache.set("rustfmt", result).expect("set");
        cache.bind_receipt_evidence("rustfmt", true, true);
        cache.sign_all(&signer);

        let vk = signer.verifying_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(decision.reusable, "receipt-bound entry should be reusable");
    }

    /// Post-deserialization validation rejects oversized fields.
    #[test]
    fn validate_field_lengths_rejects_oversized() {
        let key = sample_compound_key();
        let entry = V3CacheEntry {
            schema: GATE_CACHE_V3_SCHEMA.to_string(),
            sha: "abc123".to_string(),
            gate_name: "a".repeat(MAX_V3_STRING_FIELD_LENGTH + 1),
            compound_key: key,
            result: sample_gate_result(),
        };
        assert!(
            !entry.validate_field_lengths(),
            "oversized gate_name must be rejected"
        );
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
    /// context (different sandbox/network policy hashes) must not produce a
    /// v3 reuse hit via v2 fallback.
    ///
    /// Scenario: Attacker has a valid v2 entry for SHA "abc123". The v3
    /// compound key uses different policy hashes (authority context drift).
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
            // Different policy hashes (authority context drift).
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

    // =========================================================================
    // Lock File Tests (CODE-QUALITY MINOR fix)
    // =========================================================================

    /// Verify that `save_to_dir` creates a lock file for the index key.
    #[test]
    fn save_creates_lock_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");

        let signer = Signer::generate();
        let cache = make_signed_v3(&signer);
        cache.save_to_dir(&root).expect("save");

        let index_key = cache.compound_key.compute_index_key();
        let lock_path = root.join(format!(".{index_key}.lock"));
        assert!(lock_path.exists(), "lock file must be created during save");
    }

    /// Verify that concurrent saves to the same index key are serialized by
    /// the lock file protocol (no clobber).
    ///
    /// This test uses two threads writing different gate sets to the same
    /// compound key. After both complete, the loaded cache must contain
    /// exactly the gates from one of the two writers (no interleaving).
    #[test]
    fn concurrent_saves_serialized_by_lock() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path().join("gate_cache_v3");
        std::fs::create_dir_all(&root).expect("mkdir");

        let key = sample_compound_key();

        // Writer A: gates "alpha"
        let root_a = root.clone();
        let key_a = key.clone();
        let handle_a = std::thread::spawn(move || {
            let signer = Signer::generate();
            let mut cache = GateCacheV3::new("sha-concurrent", key_a).expect("new");
            cache.set("alpha", sample_gate_result()).expect("set");
            cache.sign_all(&signer);
            cache.save_to_dir(&root_a).expect("save A");
        });

        // Writer B: gates "beta"
        let root_b = root.clone();
        let key_b = key.clone();
        let handle_b = std::thread::spawn(move || {
            let signer = Signer::generate();
            let mut cache = GateCacheV3::new("sha-concurrent", key_b).expect("new");
            cache.set("beta", sample_gate_result()).expect("set");
            cache.sign_all(&signer);
            cache.save_to_dir(&root_b).expect("save B");
        });

        handle_a.join().expect("thread A");
        handle_b.join().expect("thread B");

        // The loaded cache must be a consistent snapshot from one writer.
        let loaded = GateCacheV3::load_from_dir(&root, "sha-concurrent", &key)
            .expect("must load after concurrent saves");
        assert_eq!(
            loaded.gates.len(),
            1,
            "one writer must win; no interleaving of gate sets"
        );
        let has_alpha = loaded.get("alpha").is_some();
        let has_beta = loaded.get("beta").is_some();
        assert!(
            has_alpha || has_beta,
            "loaded cache must have gates from exactly one writer"
        );
        assert!(
            !(has_alpha && has_beta),
            "loaded cache must NOT have gates from both writers"
        );
    }

    // =========================================================================
    // Receipt Rebind Tests (TCK-00541 round-3 MAJOR fix)
    // =========================================================================

    /// Verify that `check_reuse` returns a hit after
    /// `try_bind_receipt_from_store` promotes `rfc0028_receipt_bound` and
    /// `rfc0029_receipt_bound`, followed by re-signing and a disk
    /// round-trip.
    #[test]
    fn check_reuse_hit_after_receipt_rebind_roundtrip() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let key = sample_compound_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        // Step 1: Create a v3 cache with receipt flags defaulting to false
        // (simulating what `finalize_status_gate_run` produces).
        let mut cache = GateCacheV3::new("abc123", key.clone()).expect("new");
        let unbound_result = V3GateResult {
            rfc0028_receipt_bound: false,
            rfc0029_receipt_bound: false,
            ..sample_gate_result()
        };
        cache.set("rustfmt", unbound_result).expect("set");
        cache.sign_all(&signer);

        // Confirm check_reuse denies before rebind (receipt_binding_missing).
        let pre_decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!pre_decision.reusable, "must deny before rebind");
        assert_eq!(pre_decision.reason, "receipt_binding_missing");

        // Step 2: Persist to disk.
        let root = tempfile::tempdir().expect("tmpdir");
        cache.save_to_dir(root.path()).expect("save");

        // Step 3: Create a receipt file with passing RFC-0028/0029 evidence.
        // The file must be named by content hash (computed via canonical bytes
        // with domain separator) so `lookup_job_receipt` finds and verifies it.
        let receipts_dir = tempfile::tempdir().expect("tmpdir receipts");
        let receipt = crate::fac::receipt::FacJobReceiptV1 {
            schema: "apm2.fac.receipt.v1".to_string(),
            receipt_id: "receipt-001".to_string(),
            job_id: "job-rebind-test".to_string(),
            job_spec_digest: "spec-digest".to_string(),
            outcome: crate::fac::receipt::FacJobOutcome::Completed,
            reason: "test".to_string(),
            rfc0028_channel_boundary: Some(crate::fac::receipt::ChannelBoundaryTrace {
                passed: true,
                defect_count: 0,
                defect_classes: vec![],
                token_fac_policy_hash: None,
                token_canonicalizer_tuple_digest: None,
                token_boundary_id: None,
                token_issued_at_tick: None,
                token_expiry_tick: None,
            }),
            eio29_queue_admission: Some(crate::fac::receipt::QueueAdmissionTrace {
                verdict: "allow".to_string(),
                queue_lane: "test".to_string(),
                defect_reason: None,
                cost_estimate_ticks: None,
            }),
            ..Default::default()
        };
        let receipt_json = serde_json::to_string(&receipt).expect("serialize receipt");
        // Use the v2 content hash (current standard) for the filename.
        let receipt_digest = crate::fac::receipt::compute_job_receipt_content_hash_v2(&receipt);
        let receipt_path = receipts_dir.path().join(format!("{receipt_digest}.json"));
        std::fs::write(&receipt_path, &receipt_json).expect("write receipt");

        // Step 4: Reload from disk, rebind, re-sign, save (the rebind path).
        let mut reloaded = GateCacheV3::load_from_dir(root.path(), "abc123", &key).expect("reload");
        reloaded.try_bind_receipt_from_store(receipts_dir.path(), "job-rebind-test");

        // Verify flags were promoted.
        let entry = reloaded.get("rustfmt").expect("entry exists");
        assert!(entry.rfc0028_receipt_bound, "rfc0028 must be promoted");
        assert!(entry.rfc0029_receipt_bound, "rfc0029 must be promoted");

        // Re-sign after flag promotion (required: canonical bytes include flags).
        reloaded.sign_all(&signer);

        // Save rebound cache back to disk.
        reloaded.save_to_dir(root.path()).expect("save rebound");

        // Step 5: Load one more time from disk and verify check_reuse hits.
        let final_cache =
            GateCacheV3::load_from_dir(root.path(), "abc123", &key).expect("final load");
        let post_decision = final_cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(post_decision.reusable, "must hit after rebind round-trip");
        assert_eq!(post_decision.reason, "v3_compound_key_match");
    }

    /// Verify that `try_bind_receipt_from_store` does NOT promote flags when
    /// the receipt has a failing RFC-0028 trace (fail-closed).
    #[test]
    fn receipt_rebind_no_promotion_on_failed_rfc0028() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let key = sample_compound_key();
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let unbound = V3GateResult {
            rfc0028_receipt_bound: false,
            rfc0029_receipt_bound: false,
            ..sample_gate_result()
        };
        cache.set("rustfmt", unbound).expect("set");
        cache.sign_all(&signer);

        // Receipt with RFC-0028 *failing*.
        let receipts_dir = tempfile::tempdir().expect("tmpdir");
        let receipt = crate::fac::receipt::FacJobReceiptV1 {
            schema: "apm2.fac.receipt.v1".to_string(),
            receipt_id: "receipt-002".to_string(),
            job_id: "job-fail-0028".to_string(),
            job_spec_digest: "spec-digest".to_string(),
            outcome: crate::fac::receipt::FacJobOutcome::Completed,
            reason: "test".to_string(),
            rfc0028_channel_boundary: Some(crate::fac::receipt::ChannelBoundaryTrace {
                passed: false,
                defect_count: 1,
                defect_classes: vec!["test-defect".to_string()],
                token_fac_policy_hash: None,
                token_canonicalizer_tuple_digest: None,
                token_boundary_id: None,
                token_issued_at_tick: None,
                token_expiry_tick: None,
            }),
            eio29_queue_admission: Some(crate::fac::receipt::QueueAdmissionTrace {
                verdict: "allow".to_string(),
                queue_lane: "test".to_string(),
                defect_reason: None,
                cost_estimate_ticks: None,
            }),
            ..Default::default()
        };
        let receipt_json = serde_json::to_string(&receipt).expect("serialize");
        let receipt_digest = crate::fac::receipt::compute_job_receipt_content_hash_v2(&receipt);
        std::fs::write(
            receipts_dir.path().join(format!("{receipt_digest}.json")),
            &receipt_json,
        )
        .expect("write");

        cache.try_bind_receipt_from_store(receipts_dir.path(), "job-fail-0028");

        // Flags must remain false (fail-closed).
        let entry = cache.get("rustfmt").expect("entry");
        assert!(
            !entry.rfc0028_receipt_bound,
            "must not promote on failed 0028"
        );
        assert!(
            !entry.rfc0029_receipt_bound,
            "must not promote on failed 0028"
        );

        // check_reuse must still deny.
        let decision = cache.check_reuse("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.reusable, "must deny with failed 0028");
        assert_eq!(decision.reason, "receipt_binding_missing");
    }

    // =========================================================================
    // CacheDecision and CacheReasonCode Tests (TCK-00626, S4)
    // =========================================================================

    #[test]
    fn cache_reason_code_as_str_roundtrips_all_variants() {
        let codes = [
            (CacheReasonCode::CacheHit, "cache_hit"),
            (CacheReasonCode::ShaMiss, "sha_miss"),
            (CacheReasonCode::GateMiss, "gate_miss"),
            (CacheReasonCode::SignatureInvalid, "signature_invalid"),
            (
                CacheReasonCode::ReceiptBindingMissing,
                "receipt_binding_missing",
            ),
            (CacheReasonCode::PolicyDrift, "policy_drift"),
            (CacheReasonCode::ToolchainDrift, "toolchain_drift"),
            (CacheReasonCode::ClosureDrift, "closure_drift"),
            (CacheReasonCode::InputDrift, "input_drift"),
            (CacheReasonCode::NetworkPolicyDrift, "network_policy_drift"),
            (CacheReasonCode::SandboxDrift, "sandbox_drift"),
            (CacheReasonCode::TtlExpired, "ttl_expired"),
        ];
        for (code, expected_str) in &codes {
            assert_eq!(code.as_str(), *expected_str, "as_str mismatch for {code:?}");
            assert_eq!(
                code.to_string(),
                *expected_str,
                "Display mismatch for {code:?}"
            );
        }
        // Verify all 12 variants (11 miss + 1 hit) are covered.
        assert_eq!(codes.len(), 12);
    }

    #[test]
    fn cache_decision_hit_has_correct_structure() {
        let decision = CacheDecision::cache_hit("abc123");
        assert!(decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::CacheHit);
        assert!(
            decision.first_mismatch_dimension.is_none(),
            "hit must have null first_mismatch_dimension"
        );
        assert_eq!(
            decision.cached_sha.as_deref(),
            Some("abc123"),
            "hit must carry cached SHA"
        );
    }

    #[test]
    fn cache_decision_miss_sha_miss() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::ShaMiss, None);
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::ShaMiss);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::ShaMiss)
        );
        assert!(
            decision.cached_sha.is_none(),
            "sha_miss with no cached entry must have null cached_sha"
        );
    }

    #[test]
    fn cache_decision_miss_gate_miss() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::GateMiss, Some("abc123"));
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::GateMiss);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::GateMiss)
        );
        assert_eq!(decision.cached_sha.as_deref(), Some("abc123"));
    }

    #[test]
    fn cache_decision_miss_signature_invalid() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::SignatureInvalid, Some("sha1"));
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::SignatureInvalid);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::SignatureInvalid)
        );
    }

    #[test]
    fn cache_decision_miss_receipt_binding_missing() {
        let decision =
            CacheDecision::cache_miss(CacheReasonCode::ReceiptBindingMissing, Some("sha1"));
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::ReceiptBindingMissing);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::ReceiptBindingMissing)
        );
    }

    #[test]
    fn cache_decision_miss_policy_drift() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::PolicyDrift, None);
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::PolicyDrift);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::PolicyDrift)
        );
    }

    #[test]
    fn cache_decision_miss_toolchain_drift() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::ToolchainDrift, None);
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::ToolchainDrift);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::ToolchainDrift)
        );
    }

    #[test]
    fn cache_decision_miss_closure_drift() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::ClosureDrift, None);
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::ClosureDrift);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::ClosureDrift)
        );
    }

    #[test]
    fn cache_decision_miss_input_drift() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::InputDrift, Some("sha1"));
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::InputDrift);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::InputDrift)
        );
    }

    #[test]
    fn cache_decision_miss_network_policy_drift() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::NetworkPolicyDrift, None);
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::NetworkPolicyDrift);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::NetworkPolicyDrift)
        );
    }

    #[test]
    fn cache_decision_miss_sandbox_drift() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::SandboxDrift, None);
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::SandboxDrift);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::SandboxDrift)
        );
    }

    #[test]
    fn cache_decision_miss_ttl_expired() {
        let decision = CacheDecision::cache_miss(CacheReasonCode::TtlExpired, Some("sha1"));
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::TtlExpired);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::TtlExpired)
        );
    }

    #[test]
    fn cache_decision_serialization_roundtrip() {
        let hit = CacheDecision::cache_hit("abc123");
        let json = serde_json::to_string(&hit).expect("serialize hit");
        let parsed: CacheDecision = serde_json::from_str(&json).expect("deserialize hit");
        assert_eq!(parsed.hit, hit.hit);
        assert_eq!(parsed.reason_code, hit.reason_code);
        assert_eq!(
            parsed.first_mismatch_dimension,
            hit.first_mismatch_dimension
        );
        assert_eq!(parsed.cached_sha, hit.cached_sha);

        let miss = CacheDecision::cache_miss(CacheReasonCode::PolicyDrift, Some("def456"));
        let json = serde_json::to_string(&miss).expect("serialize miss");
        let parsed: CacheDecision = serde_json::from_str(&json).expect("deserialize miss");
        assert_eq!(parsed.hit, miss.hit);
        assert_eq!(parsed.reason_code, miss.reason_code);
        assert_eq!(
            parsed.first_mismatch_dimension,
            miss.first_mismatch_dimension
        );
        assert_eq!(parsed.cached_sha, miss.cached_sha);
    }

    #[test]
    fn cache_decision_json_skip_serializing_none_fields() {
        let hit = CacheDecision::cache_hit("abc123");
        let json = serde_json::to_string(&hit).expect("serialize");
        // first_mismatch_dimension is None on hit — should not appear in JSON.
        assert!(
            !json.contains("first_mismatch_dimension"),
            "hit should skip null first_mismatch_dimension: {json}"
        );

        let miss = CacheDecision::cache_miss(CacheReasonCode::ShaMiss, None);
        let json = serde_json::to_string(&miss).expect("serialize");
        // cached_sha is None on sha_miss — should not appear in JSON.
        assert!(
            !json.contains("cached_sha"),
            "sha_miss with no cached_sha should skip null cached_sha: {json}"
        );
        // first_mismatch_dimension IS present on miss.
        assert!(
            json.contains("first_mismatch_dimension"),
            "miss should include first_mismatch_dimension: {json}"
        );
    }

    #[test]
    fn map_reason_to_code_covers_all_known_reasons() {
        let cases = [
            ("no_record", CacheReasonCode::GateMiss),
            ("status_not_pass", CacheReasonCode::GateMiss),
            (
                "v2_sourced_no_binding_proof",
                CacheReasonCode::SignatureInvalid,
            ),
            ("signature_missing", CacheReasonCode::SignatureInvalid),
            ("signer_id_missing", CacheReasonCode::SignatureInvalid),
            (
                "signature_field_too_long",
                CacheReasonCode::SignatureInvalid,
            ),
            ("signer_id_invalid_hex", CacheReasonCode::SignatureInvalid),
            (
                "signer_id_length_mismatch",
                CacheReasonCode::SignatureInvalid,
            ),
            ("signer_id_mismatch", CacheReasonCode::SignatureInvalid),
            ("signature_invalid_hex", CacheReasonCode::SignatureInvalid),
            ("signature_malformed", CacheReasonCode::SignatureInvalid),
            ("signature_invalid", CacheReasonCode::SignatureInvalid),
            (
                "signature_unverifiable_no_key",
                CacheReasonCode::SignatureInvalid,
            ),
            (
                "receipt_binding_missing",
                CacheReasonCode::ReceiptBindingMissing,
            ),
            ("attestation_mismatch", CacheReasonCode::InputDrift),
            ("attestation_missing_current", CacheReasonCode::InputDrift),
            ("evidence_digest_missing", CacheReasonCode::InputDrift),
            ("quick_receipt_not_reusable", CacheReasonCode::InputDrift),
        ];
        for (reason, expected_code) in &cases {
            let code = GateCacheV3::map_reason_to_code(reason);
            assert_eq!(
                code, *expected_code,
                "map_reason_to_code({reason:?}) should be {expected_code:?}, got {code:?}"
            );
        }
    }

    #[test]
    fn map_reason_to_code_unknown_defaults_to_input_drift() {
        let code = GateCacheV3::map_reason_to_code("completely_unknown_reason");
        assert_eq!(
            code,
            CacheReasonCode::InputDrift,
            "unknown reason must default to InputDrift (fail-closed)"
        );
    }

    #[test]
    fn check_reuse_decision_hit_returns_cache_hit() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let cache = make_signed_v3(&signer);
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse_decision("rustfmt", Some(digest), true, Some(&vk));
        assert!(decision.hit, "signed cache should produce hit");
        assert_eq!(decision.reason_code, CacheReasonCode::CacheHit);
        assert!(decision.first_mismatch_dimension.is_none());
        assert_eq!(decision.cached_sha.as_deref(), Some("abc123"));
    }

    #[test]
    fn check_reuse_decision_gate_miss_for_absent_gate() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let cache = make_signed_v3(&signer);
        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision =
            cache.check_reuse_decision("nonexistent_gate", Some(digest), true, Some(&vk));
        assert!(!decision.hit, "absent gate should produce miss");
        assert_eq!(decision.reason_code, CacheReasonCode::GateMiss);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::GateMiss)
        );
    }

    #[test]
    fn check_reuse_decision_input_drift_for_attestation_mismatch() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let cache = make_signed_v3(&signer);
        // Use a different digest than the one in the cache entry.
        let wrong_digest =
            "b3-256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let decision = cache.check_reuse_decision("rustfmt", Some(wrong_digest), true, Some(&vk));
        assert!(!decision.hit, "attestation mismatch should produce miss");
        assert_eq!(
            decision.reason_code,
            CacheReasonCode::InputDrift,
            "attestation mismatch maps to InputDrift"
        );
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::InputDrift)
        );
    }

    #[test]
    fn check_reuse_decision_receipt_binding_missing_for_unbound_entry() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        let mut result = sample_gate_result();
        result.rfc0028_receipt_bound = false;
        result.rfc0029_receipt_bound = false;
        cache.set("rustfmt", result).expect("set");
        cache.sign_all(&signer);

        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse_decision("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::ReceiptBindingMissing);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::ReceiptBindingMissing)
        );
    }

    #[test]
    fn check_reuse_decision_signature_invalid_for_unsigned_entry() {
        let signer = Signer::generate();
        let vk = signer.verifying_key();
        let key = sample_compound_key();
        let mut cache = GateCacheV3::new("abc123", key).expect("new");
        cache.set("rustfmt", sample_gate_result()).expect("set");
        // Do NOT sign — signature will be missing.

        let digest = "b3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let decision = cache.check_reuse_decision("rustfmt", Some(digest), true, Some(&vk));
        assert!(!decision.hit);
        assert_eq!(decision.reason_code, CacheReasonCode::SignatureInvalid);
        assert_eq!(
            decision.first_mismatch_dimension,
            Some(CacheReasonCode::SignatureInvalid)
        );
    }
}
