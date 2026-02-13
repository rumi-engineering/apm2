// AGENT-AUTHORED
//! `AdmissionKernel` types: request, plan, result, spine join extension,
//! witness seeds, and boundary mediation (RFC-0019 §§3–8, Appendix A).
//!
//! All types enforce bounded fields, `deny_unknown_fields` where
//! digest-stable, and versioned naming per §1.3.
//!
//! # Security Model
//!
//! - [`AdmissionPlanV1`] is single-use, non-cloneable, non-serializable across
//!   trust boundaries (RFC-0019 §3.3).
//! - [`AdmissionSpineJoinExtV1`] commits to all spine-required bindings so the
//!   join hash is collision-free (RFC-0019 §4.1.1).
//! - [`WitnessSeedV1`] is daemon-created with provider provenance binding
//!   (RFC-0019 §4.2.1).

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityJoinCertificateV1,
    IdentityEvidenceLevel, PcacPolicyKnobs, RiskTier,
};
use serde::{Deserialize, Serialize};

use super::capabilities::{EffectCapability, LedgerWriteCapability, QuarantineCapability};
use super::prerequisites::LedgerAnchorV1;

// =============================================================================
// Bounded deserialization helpers (SECURITY BLOCKER 2, TCK-00492)
// =============================================================================

/// Bounded deserialization module (SECURITY: visitor-based bounds enforcement).
///
/// Prevents denial-of-service via unbounded allocation when deserializing
/// string and collection fields from untrusted input. Uses serde `Visitor`
/// patterns that enforce length/count limits DURING parsing, before
/// allocating the full payload.
///
/// # String Visitor
///
/// The `bounded_string_deser!` macro generates a `Visitor` that intercepts
/// `visit_str` / `visit_string` and rejects strings exceeding `MAX_*`
/// bytes BEFORE copying into a new `String`. This prevents an attacker
/// from forcing allocation of a multi-gigabyte string that is only
/// rejected post-allocation.
///
/// # Vec Visitor
///
/// The `bounded_vec_deser!` macro generates a `Visitor` that consumes a
/// JSON array element-by-element via `SeqAccess`, counting entries and
/// rejecting the payload as soon as the count exceeds `MAX_*`. This
/// prevents pre-allocation of an oversized `Vec` from a malicious
/// `serde_json` size hint.
mod bounded_deser {
    use serde::{self, Deserializer, de};

    /// Macro to generate bounded string deserializer functions with a
    /// visitor that enforces the limit DURING parsing (before allocation).
    macro_rules! bounded_string_deser {
        ($fn_name:ident, $max:expr) => {
            pub fn $fn_name<'de, D>(deserializer: D) -> Result<String, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct BoundedStringVisitor;

                impl<'de> de::Visitor<'de> for BoundedStringVisitor {
                    type Value = String;

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(f, "a string of at most {} bytes", $max)
                    }

                    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                        if v.len() > $max {
                            return Err(E::custom(concat!(
                                "string exceeds maximum length of ",
                                stringify!($max),
                                " bytes"
                            )));
                        }
                        Ok(v.to_owned())
                    }

                    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                        if v.len() > $max {
                            return Err(E::custom(concat!(
                                "string exceeds maximum length of ",
                                stringify!($max),
                                " bytes"
                            )));
                        }
                        Ok(v)
                    }
                }

                deserializer.deserialize_str(BoundedStringVisitor)
            }
        };
    }

    /// Macro to generate bounded `Vec<T>` deserializer functions with a
    /// visitor that enforces the count limit DURING parsing. The visitor
    /// consumes elements one-by-one via `SeqAccess` and rejects as soon
    /// as the count exceeds `$max`, preventing oversized pre-allocation.
    macro_rules! bounded_vec_deser {
        ($fn_name:ident, $elem_ty:ty, $max:expr) => {
            pub fn $fn_name<'de, D>(deserializer: D) -> Result<Vec<$elem_ty>, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct BoundedVecVisitor;

                impl<'de> de::Visitor<'de> for BoundedVecVisitor {
                    type Value = Vec<$elem_ty>;

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(f, "a sequence of at most {} elements", $max)
                    }

                    fn visit_seq<A: de::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<Self::Value, A::Error> {
                        // Cap pre-allocation to MAX to prevent a malicious
                        // size hint from causing a massive allocation.
                        let cap = seq.size_hint().unwrap_or(0).min($max);
                        let mut vec = Vec::with_capacity(cap);

                        while let Some(elem) = seq.next_element::<$elem_ty>()? {
                            if vec.len() >= $max {
                                return Err(de::Error::custom(concat!(
                                    "sequence exceeds maximum of ",
                                    stringify!($max),
                                    " elements"
                                )));
                            }
                            vec.push(elem);
                        }

                        Ok(vec)
                    }
                }

                deserializer.deserialize_seq(BoundedVecVisitor)
            }
        };
    }

    // Bounded string deserializers for each field type.
    // These enforce MAX_* limits DURING deserialization via Visitor,
    // preventing attackers from forcing large allocations.
    bounded_string_deser!(deser_kernel_string, super::MAX_KERNEL_STRING_LENGTH);
    bounded_string_deser!(deser_tool_class, super::MAX_TOOL_CLASS_LENGTH);
    bounded_string_deser!(deser_boundary_profile, super::MAX_BOUNDARY_PROFILE_LENGTH);
    bounded_string_deser!(
        deser_witness_provider_id,
        super::MAX_WITNESS_PROVIDER_ID_LENGTH
    );
    bounded_string_deser!(deser_witness_class, super::MAX_KERNEL_STRING_LENGTH);
    bounded_string_deser!(deser_waiver_reason, super::MAX_WAIVER_REASON_LENGTH);

    // Bounded Vec deserializers for collection fields.
    // These enforce MAX_* limits DURING deserialization via SeqAccess Visitor,
    // preventing oversized pre-allocation from malicious size hints.
    bounded_vec_deser!(
        deser_quarantine_actions,
        super::QuarantineActionV1,
        super::MAX_BUNDLE_QUARANTINE_ACTIONS
    );
    bounded_vec_deser!(
        deser_receipt_digests,
        apm2_core::crypto::Hash,
        super::MAX_OUTCOME_INDEX_RECEIPT_DIGESTS
    );
    bounded_vec_deser!(
        deser_post_effect_witness_evidence_hashes,
        apm2_core::crypto::Hash,
        super::MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES
    );
    bounded_vec_deser!(
        deser_measured_values,
        apm2_core::crypto::Hash,
        super::MAX_WITNESS_EVIDENCE_MEASURED_VALUES
    );
}

// =============================================================================
// Resource limits
// =============================================================================

/// Maximum length for string fields in kernel request types.
pub const MAX_KERNEL_STRING_LENGTH: usize = 256;

/// Maximum length for the tool class identifier.
pub const MAX_TOOL_CLASS_LENGTH: usize = 128;

/// Maximum length for the boundary profile identifier.
pub const MAX_BOUNDARY_PROFILE_LENGTH: usize = 128;

/// Maximum length for the mechanism identifier in external anchors.
pub const MAX_MECHANISM_ID_LENGTH: usize = 128;

/// Maximum length for the algorithm identifier in governance provenance.
pub const MAX_ALGORITHM_ID_LENGTH: usize = 64;

/// Maximum length for the witness provider identifier.
pub const MAX_WITNESS_PROVIDER_ID_LENGTH: usize = 256;

/// Maximum length for a monitor-tier waiver reason string.
pub const MAX_WAIVER_REASON_LENGTH: usize = 512;

/// Maximum number of measured values in a witness evidence object.
pub const MAX_WITNESS_EVIDENCE_MEASURED_VALUES: usize = 16;

// =============================================================================
// Enforcement tier
// =============================================================================

/// Policy-derived enforcement tier for admission decisions.
///
/// Tiers are NOT compile-time constants; they MUST be derived from
/// policy root and `tool_class`/`boundary_profile` per RFC-0019 §1.1.
///
/// # Fail-Closed Semantics
///
/// `FailClosed` tiers deny on missing authoritative prerequisites.
/// `Monitor` tiers may proceed with warnings but MUST NOT execute
/// effects that require authoritative enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementTier {
    /// Fail-closed: deny on missing prerequisites.
    FailClosed,
    /// Monitor-only: log violations but allow (non-authoritative).
    Monitor,
}

impl std::fmt::Display for EnforcementTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailClosed => write!(f, "fail_closed"),
            Self::Monitor => write!(f, "monitor"),
        }
    }
}

// =============================================================================
// KernelRequestV1
// =============================================================================

/// Versioned kernel request input (RFC-0019 §5.3 phase A).
///
/// Captures all bindings needed by `AdmissionKernel` to plan and execute
/// an admission decision. Constructed by handlers from transport/protocol
/// structs.
///
/// # Bounded Fields
///
/// All string and collection fields enforce explicit size limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRequestV1 {
    /// Stable request identifier (daemon-generated or HSI-derived).
    pub request_id: Hash,
    /// Session identifier for the requesting session.
    pub session_id: String,
    /// Tool class identifier (determines enforcement tier).
    pub tool_class: String,
    /// Boundary profile identifier.
    pub boundary_profile_id: String,
    /// PCAC risk tier for this request.
    pub risk_tier: RiskTier,
    /// Effect descriptor digest (tool identity + arguments hash).
    pub effect_descriptor_digest: Hash,
    /// Intent digest for PCAC binding.
    pub intent_digest: Hash,
    /// HSI contract manifest digest.
    pub hsi_contract_manifest_digest: Hash,
    /// HSI envelope binding digest.
    pub hsi_envelope_binding_digest: Hash,
    /// Stop/budget profile digest.
    pub stop_budget_digest: Hash,
    /// PCAC policy knobs for this request.
    pub pcac_policy: PcacPolicyKnobs,
    /// Whether declared idempotent by the tool descriptor.
    pub declared_idempotent: bool,
    /// Lease ID for the requesting session.
    pub lease_id: String,
    /// Identity proof hash.
    pub identity_proof_hash: Hash,
    /// Capability manifest hash at request time.
    pub capability_manifest_hash: Hash,
    /// Current time envelope reference (HTF).
    pub time_envelope_ref: Hash,
    /// Current freshness witness tick.
    pub freshness_witness_tick: u64,
    /// Directory head hash.
    pub directory_head_hash: Hash,
    /// Freshness policy hash.
    pub freshness_policy_hash: Hash,
    /// Current revocation head hash.
    pub revocation_head_hash: Hash,
    /// Identity evidence level for this request (`Verified` or `PointerOnly`).
    ///
    /// For Tier2+ (fail-closed) paths, this is expected to be `Verified`.
    /// `PointerOnly` at Tier2+ requires a non-`None`
    /// `pointer_only_waiver_hash`.
    pub identity_evidence_level: IdentityEvidenceLevel,
    /// Optional pointer-only waiver hash.
    ///
    /// Required when `identity_evidence_level` is `PointerOnly` at Tier2+.
    /// The waiver hash references a governance policy waiver allowing
    /// pointer-only identity evidence for the given request context.
    pub pointer_only_waiver_hash: Option<Hash>,
}

impl KernelRequestV1 {
    /// Validate all boundary constraints on this kernel request.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violation found (fail-closed).
    pub fn validate(&self) -> Result<(), AdmitError> {
        const ZERO: Hash = [0u8; 32];

        // String length bounds
        if self.session_id.is_empty() || self.session_id.len() > MAX_KERNEL_STRING_LENGTH {
            return Err(AdmitError::InvalidRequest {
                reason: "session_id empty or exceeds maximum length".into(),
            });
        }
        if self.tool_class.is_empty() || self.tool_class.len() > MAX_TOOL_CLASS_LENGTH {
            return Err(AdmitError::InvalidRequest {
                reason: "tool_class empty or exceeds maximum length".into(),
            });
        }
        if self.boundary_profile_id.is_empty()
            || self.boundary_profile_id.len() > MAX_BOUNDARY_PROFILE_LENGTH
        {
            return Err(AdmitError::InvalidRequest {
                reason: "boundary_profile_id empty or exceeds maximum length".into(),
            });
        }
        if self.lease_id.is_empty() || self.lease_id.len() > MAX_KERNEL_STRING_LENGTH {
            return Err(AdmitError::InvalidRequest {
                reason: "lease_id empty or exceeds maximum length".into(),
            });
        }

        // Required hash fields must be non-zero
        if self.request_id == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "request_id is zero".into(),
            });
        }
        if self.intent_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "intent_digest is zero".into(),
            });
        }
        if self.effect_descriptor_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "effect_descriptor_digest is zero".into(),
            });
        }
        if self.identity_proof_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "identity_proof_hash is zero".into(),
            });
        }
        if self.capability_manifest_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "capability_manifest_hash is zero".into(),
            });
        }
        if self.time_envelope_ref == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "time_envelope_ref is zero".into(),
            });
        }
        if self.freshness_witness_tick == 0 {
            return Err(AdmitError::InvalidRequest {
                reason: "freshness_witness_tick is zero".into(),
            });
        }
        if self.directory_head_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "directory_head_hash is zero".into(),
            });
        }
        if self.freshness_policy_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "freshness_policy_hash is zero".into(),
            });
        }
        // QUALITY MAJOR 1 (TCK-00492): Non-zero checks for ALL mandatory
        // digest fields. These were previously missing, allowing requests
        // with unbound digests to pass validation.
        if self.hsi_contract_manifest_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "hsi_contract_manifest_digest is zero".into(),
            });
        }
        if self.hsi_envelope_binding_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "hsi_envelope_binding_digest is zero".into(),
            });
        }
        if self.stop_budget_digest == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "stop_budget_digest is zero".into(),
            });
        }
        if self.revocation_head_hash == ZERO {
            return Err(AdmitError::InvalidRequest {
                reason: "revocation_head_hash is zero".into(),
            });
        }

        Ok(())
    }
}

// =============================================================================
// AdmissionSpineJoinExtV1
// =============================================================================

/// Spine join extension object (RFC-0019 §4.1.1).
///
/// Committed into the PCAC join input to ensure the join hash covers
/// all spine-required bindings without mutating `AuthorityJoinInputV1`.
///
/// # Digest Stability
///
/// The content hash uses domain-separated canonical bytes with
/// deterministic field ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionSpineJoinExtV1 {
    /// Stable request identifier.
    pub request_id: Hash,
    /// Session identifier.
    #[serde(deserialize_with = "bounded_deser::deser_kernel_string")]
    pub session_id: String,
    /// Tool class identifier.
    #[serde(deserialize_with = "bounded_deser::deser_tool_class")]
    pub tool_class: String,
    /// Boundary profile identifier.
    #[serde(deserialize_with = "bounded_deser::deser_boundary_profile")]
    pub boundary_profile_id: String,
    /// Policy-derived enforcement tier.
    pub enforcement_tier: EnforcementTier,
    /// HSI contract manifest digest.
    pub hsi_contract_manifest_digest: Hash,
    /// HSI envelope binding digest.
    pub hsi_envelope_binding_digest: Hash,
    /// Canonical request digest.
    pub canonical_request_digest: Hash,
    /// Effect descriptor digest.
    pub effect_descriptor_digest: Hash,
    /// Whether the effect is declared idempotent.
    pub declared_idempotent: bool,
    /// Stop/budget digest for boundary arbitration.
    pub stop_budget_digest: Hash,
    /// Selected ledger anchor (including `ledger_id`).
    pub ledger_anchor: LedgerAnchorV1,
    /// Policy root digest.
    pub policy_root_digest: Hash,
    /// Policy root epoch (monotonic generation).
    pub policy_root_epoch: u64,
    /// Leakage witness seed hash.
    pub leakage_witness_seed_hash: Hash,
    /// Timing witness seed hash.
    pub timing_witness_seed_hash: Hash,
}

impl AdmissionSpineJoinExtV1 {
    /// Compute a deterministic content hash for this extension.
    ///
    /// Uses domain-separated BLAKE3 hashing over all fields in
    /// canonical order.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String fields are bounded by MAX_* constants (<=256), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-admission-spine-join-ext-v1");
        hasher.update(&self.request_id);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&(self.session_id.len() as u32).to_le_bytes());
        hasher.update(self.tool_class.as_bytes());
        hasher.update(&(self.tool_class.len() as u32).to_le_bytes());
        hasher.update(self.boundary_profile_id.as_bytes());
        hasher.update(&(self.boundary_profile_id.len() as u32).to_le_bytes());
        hasher.update(match self.enforcement_tier {
            EnforcementTier::FailClosed => &[0x01],
            EnforcementTier::Monitor => &[0x02],
        });
        hasher.update(&self.hsi_contract_manifest_digest);
        hasher.update(&self.hsi_envelope_binding_digest);
        hasher.update(&self.canonical_request_digest);
        hasher.update(&self.effect_descriptor_digest);
        hasher.update(&[u8::from(self.declared_idempotent)]);
        hasher.update(&self.stop_budget_digest);
        // Inline ledger anchor fields for deterministic digest
        hasher.update(&self.ledger_anchor.ledger_id);
        hasher.update(&self.ledger_anchor.event_hash);
        hasher.update(&self.ledger_anchor.height.to_le_bytes());
        hasher.update(&self.ledger_anchor.he_time.to_le_bytes());
        hasher.update(&self.policy_root_digest);
        hasher.update(&self.policy_root_epoch.to_le_bytes());
        hasher.update(&self.leakage_witness_seed_hash);
        hasher.update(&self.timing_witness_seed_hash);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// WitnessSeedV1
// =============================================================================

/// Witness seed object created at join time (RFC-0019 §4.2.1).
///
/// Binds the request to a future witness object. Created by the daemon
/// (not the client) with provider provenance binding.
///
/// # Digest Domain Separation
///
/// Content hash: `b"apm2-witness-seed-v1" || witness_class || request_id ||
/// session_id_len || session_id || tool_class_len || tool_class ||
/// boundary_profile_id_len || boundary_profile_id || ledger_anchor_hash ||
/// ht_start_le || nonce || provider_id_len || provider_id ||
/// provider_build_digest`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSeedV1 {
    /// Witness class (e.g., "leakage", "timing").
    #[serde(deserialize_with = "bounded_deser::deser_witness_class")]
    pub witness_class: String,
    /// Stable request identifier.
    pub request_id: Hash,
    /// Session identifier.
    #[serde(deserialize_with = "bounded_deser::deser_kernel_string")]
    pub session_id: String,
    /// Tool class identifier.
    #[serde(deserialize_with = "bounded_deser::deser_tool_class")]
    pub tool_class: String,
    /// Boundary profile identifier.
    #[serde(deserialize_with = "bounded_deser::deser_boundary_profile")]
    pub boundary_profile_id: String,
    /// Ledger anchor hash at seed creation time.
    pub ledger_anchor_hash: Hash,
    /// Holonic time at seed creation (start of request).
    pub ht_start: u64,
    /// Cryptographic nonce for uniqueness.
    pub nonce: Hash,
    /// Witness provider identifier (module id / build digest).
    #[serde(deserialize_with = "bounded_deser::deser_witness_provider_id")]
    pub provider_id: String,
    /// Witness provider build digest for measurement binding.
    pub provider_build_digest: Hash,
}

impl WitnessSeedV1 {
    /// Compute a deterministic content hash for this witness seed.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String fields are bounded by MAX_* constants (<=256), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-witness-seed-v1");
        hasher.update(self.witness_class.as_bytes());
        hasher.update(&(self.witness_class.len() as u32).to_le_bytes());
        hasher.update(&self.request_id);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&(self.session_id.len() as u32).to_le_bytes());
        hasher.update(self.tool_class.as_bytes());
        hasher.update(&(self.tool_class.len() as u32).to_le_bytes());
        hasher.update(self.boundary_profile_id.as_bytes());
        hasher.update(&(self.boundary_profile_id.len() as u32).to_le_bytes());
        hasher.update(&self.ledger_anchor_hash);
        hasher.update(&self.ht_start.to_le_bytes());
        hasher.update(&self.nonce);
        hasher.update(self.provider_id.as_bytes());
        hasher.update(&(self.provider_id.len() as u32).to_le_bytes());
        hasher.update(&self.provider_build_digest);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// WitnessEvidenceV1
// =============================================================================

/// Post-effect witness evidence object (RFC-0028 REQ-0004, TCK-00497).
///
/// Materialized AFTER the effect executes. Binds daemon-measured values
/// (leakage metrics, timing measurements) to the witness seed that was
/// committed at join time. For fail-closed tiers, output release is
/// denied unless valid witness evidence is present.
///
/// # Digest Domain Separation
///
/// Content hash: `b"apm2-witness-evidence-v1" || witness_class_len ||
/// witness_class || seed_hash || request_id || session_id_len ||
/// session_id || ht_end_le || measured_values_count || measured_values...
/// || provider_id_len || provider_id || provider_build_digest`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessEvidenceV1 {
    /// Witness class (must match the seed's class, e.g., "leakage", "timing").
    #[serde(deserialize_with = "bounded_deser::deser_witness_class")]
    pub witness_class: String,
    /// Content hash of the [`WitnessSeedV1`] this evidence fulfills.
    pub seed_hash: Hash,
    /// Stable request identifier (must match the seed's `request_id`).
    pub request_id: Hash,
    /// Session identifier (must match the seed's `session_id`).
    #[serde(deserialize_with = "bounded_deser::deser_kernel_string")]
    pub session_id: String,
    /// Holonic time at evidence finalization (end of effect).
    pub ht_end: u64,
    /// Daemon-measured values. Bounded by
    /// [`MAX_WITNESS_EVIDENCE_MEASURED_VALUES`]. Each entry is a
    /// domain-separated hash of a (key, value) measurement.
    /// Deserialization enforces the limit via visitor-based counting
    /// (no oversized pre-allocation from malicious size hints).
    #[serde(deserialize_with = "bounded_deser::deser_measured_values")]
    pub measured_values: Vec<Hash>,
    /// Witness provider identifier (must match the seed's `provider_id`).
    #[serde(deserialize_with = "bounded_deser::deser_witness_provider_id")]
    pub provider_id: String,
    /// Witness provider build digest (must match the seed's
    /// `provider_build_digest`).
    pub provider_build_digest: Hash,
}

impl WitnessEvidenceV1 {
    /// Compute a deterministic content hash for this witness evidence.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String fields bounded by MAX_* (<=512), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-witness-evidence-v1");
        hasher.update(self.witness_class.as_bytes());
        hasher.update(&(self.witness_class.len() as u32).to_le_bytes());
        hasher.update(&self.seed_hash);
        hasher.update(&self.request_id);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&(self.session_id.len() as u32).to_le_bytes());
        hasher.update(&self.ht_end.to_le_bytes());
        hasher.update(&(self.measured_values.len() as u32).to_le_bytes());
        for mv in &self.measured_values {
            hasher.update(mv);
        }
        hasher.update(self.provider_id.as_bytes());
        hasher.update(&(self.provider_id.len() as u32).to_le_bytes());
        hasher.update(&self.provider_build_digest);
        *hasher.finalize().as_bytes()
    }

    /// Validate boundary constraints on this witness evidence.
    ///
    /// # Errors
    ///
    /// Returns the first violation found (fail-closed).
    pub fn validate(&self) -> Result<(), AdmitError> {
        const ZERO: Hash = [0u8; 32];

        if self.witness_class.is_empty() || self.witness_class.len() > MAX_KERNEL_STRING_LENGTH {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: "witness_class empty or exceeds maximum length".into(),
            });
        }
        if self.seed_hash == ZERO {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: "seed_hash is zero (unbound evidence)".into(),
            });
        }
        if self.request_id == ZERO {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: "request_id is zero".into(),
            });
        }
        if self.session_id.is_empty() || self.session_id.len() > MAX_KERNEL_STRING_LENGTH {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: "session_id empty or exceeds maximum length".into(),
            });
        }
        if self.ht_end == 0 {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: "ht_end is zero (missing finalization timestamp)".into(),
            });
        }
        if self.measured_values.len() > MAX_WITNESS_EVIDENCE_MEASURED_VALUES {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: format!(
                    "measured_values exceeds maximum of {MAX_WITNESS_EVIDENCE_MEASURED_VALUES}, \
                     got {}",
                    self.measured_values.len()
                ),
            });
        }
        if self.provider_id.is_empty() || self.provider_id.len() > MAX_WITNESS_PROVIDER_ID_LENGTH {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: "provider_id empty or exceeds maximum length".into(),
            });
        }
        if self.provider_build_digest == ZERO {
            return Err(AdmitError::WitnessEvidenceFailure {
                reason: "provider_build_digest is zero (unbound measurement)".into(),
            });
        }
        Ok(())
    }
}

// =============================================================================
// MonitorWaiverV1
// =============================================================================

/// Explicit waiver for monitor-tier witness bypass (TCK-00497).
///
/// Monitor tiers may skip witness enforcement ONLY when an explicit
/// waiver is provided. Silent permissive defaults are forbidden.
/// The waiver is committed into the admission decision for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorWaiverV1 {
    /// Waiver identifier (governance-issued or policy-derived).
    pub waiver_id: Hash,
    /// Human-readable reason for the waiver (bounded).
    #[serde(deserialize_with = "bounded_deser::deser_waiver_reason")]
    pub reason: String,
    /// Tick at which this waiver expires (0 = no expiry, but
    /// governance must periodically re-issue).
    pub expires_at_tick: u64,
    /// Request ID this waiver applies to.
    pub request_id: Hash,
    /// Enforcement tier this waiver targets (must be Monitor).
    pub enforcement_tier: EnforcementTier,
}

impl MonitorWaiverV1 {
    /// Compute a deterministic content hash for this waiver.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // reason bounded by MAX_WAIVER_REASON_LENGTH (512), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-monitor-waiver-v1");
        hasher.update(&self.waiver_id);
        hasher.update(self.reason.as_bytes());
        hasher.update(&(self.reason.len() as u32).to_le_bytes());
        hasher.update(&self.expires_at_tick.to_le_bytes());
        hasher.update(&self.request_id);
        hasher.update(match self.enforcement_tier {
            EnforcementTier::FailClosed => &[0x01],
            EnforcementTier::Monitor => &[0x02],
        });
        *hasher.finalize().as_bytes()
    }

    /// Validate boundary constraints on this waiver, including expiry
    /// enforcement against the current tick.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - The current holonic time tick. If `expires_at_tick`
    ///   is non-zero and less than `current_tick`, the waiver is considered
    ///   expired and validation fails.
    ///
    /// # Errors
    ///
    /// Returns the first violation found (fail-closed).
    pub fn validate(&self, current_tick: u64) -> Result<(), AdmitError> {
        const ZERO: Hash = [0u8; 32];

        if self.waiver_id == ZERO {
            return Err(AdmitError::WitnessWaiverInvalid {
                reason: "waiver_id is zero".into(),
            });
        }
        if self.reason.is_empty() || self.reason.len() > MAX_WAIVER_REASON_LENGTH {
            return Err(AdmitError::WitnessWaiverInvalid {
                reason: "reason empty or exceeds maximum length".into(),
            });
        }
        if self.request_id == ZERO {
            return Err(AdmitError::WitnessWaiverInvalid {
                reason: "request_id is zero".into(),
            });
        }
        if self.enforcement_tier != EnforcementTier::Monitor {
            return Err(AdmitError::WitnessWaiverInvalid {
                reason: "waiver is only valid for Monitor tier, not FailClosed".into(),
            });
        }
        // SECURITY MAJOR 2 (TCK-00497): Enforce waiver expiry.
        // A non-zero expires_at_tick that is less than the current tick
        // means the waiver has expired. Expired waivers MUST NOT bypass
        // witness enforcement — otherwise a stale waiver could be reused
        // indefinitely.
        if self.expires_at_tick != 0 && self.expires_at_tick < current_tick {
            return Err(AdmitError::WitnessWaiverInvalid {
                reason: format!(
                    "waiver expired: expires_at_tick ({}) < current_tick ({})",
                    self.expires_at_tick, current_tick
                ),
            });
        }
        Ok(())
    }
}

// =============================================================================
// PlanState — internal state machine for single-use enforcement
// =============================================================================

/// Internal state for plan lifecycle enforcement.
///
/// Tracks whether a plan has been executed to enforce single-use
/// semantics per RFC-0019 §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlanState {
    /// Plan is ready to execute.
    Ready,
    /// Plan has been consumed (execute was called).
    Consumed,
}

// =============================================================================
// AdmissionPlanV1
// =============================================================================

/// Single-use admission plan (RFC-0019 §3.3, Appendix A).
///
/// Contains all join-time bindings and is consumed exactly once by
/// `execute()`. Re-execution is structurally denied.
///
/// # Single-Use Semantics
///
/// - Non-cloneable, non-copyable.
/// - Non-serializable across trust boundaries (no Serialize/Deserialize).
/// - `execute()` transitions `state` from `Ready` to `Consumed`; second call
///   returns `AdmitError::PlanAlreadyConsumed`.
///
/// # Durability
///
/// Join-time bindings (`as_of` anchor, policy root, seeds) are captured
/// in the plan for restart-safe retry behavior.
pub struct AdmissionPlanV1 {
    /// Internal state for single-use enforcement.
    pub(super) state: PlanState,
    /// The AJC produced by the join phase.
    pub(super) certificate: AuthorityJoinCertificateV1,
    /// Spine join extension committed into the join.
    pub(super) spine_ext: AdmissionSpineJoinExtV1,
    /// Leakage witness seed.
    pub(super) leakage_witness_seed: WitnessSeedV1,
    /// Timing witness seed.
    pub(super) timing_witness_seed: WitnessSeedV1,
    /// The original kernel request (for execute-phase revalidation).
    pub(super) request: KernelRequestV1,
    /// Policy-derived enforcement tier.
    pub(super) enforcement_tier: EnforcementTier,
    /// Selected ledger anchor at plan time.
    pub(super) as_of_ledger_anchor: LedgerAnchorV1,
    /// Policy root state at plan time.
    pub(super) policy_root_digest: Hash,
    /// Policy root epoch at plan time.
    pub(super) policy_root_epoch: u64,
}

// Intentionally no Clone, Copy, Serialize, or Deserialize implementations.

impl std::fmt::Debug for AdmissionPlanV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionPlanV1")
            .field("state", &self.state)
            .field("ajc_id", &hex::encode(self.certificate.ajc_id))
            .field(
                "spine_ext_hash",
                &hex::encode(self.spine_ext.content_hash()),
            )
            .field(
                "leakage_seed_hash",
                &hex::encode(self.leakage_witness_seed.content_hash()),
            )
            .field(
                "timing_seed_hash",
                &hex::encode(self.timing_witness_seed.content_hash()),
            )
            .field("request_id", &hex::encode(self.request.request_id))
            .field("enforcement_tier", &self.enforcement_tier)
            .field(
                "as_of_ledger_anchor_hash",
                &hex::encode(self.as_of_ledger_anchor.content_hash()),
            )
            .field("policy_root_digest", &hex::encode(self.policy_root_digest))
            .field("policy_root_epoch", &self.policy_root_epoch)
            .finish()
    }
}

// =============================================================================
// Resource limits — AdmissionBundleV1
// =============================================================================

/// Maximum number of quarantine actions in an admission bundle.
pub const MAX_BUNDLE_QUARANTINE_ACTIONS: usize = 16;

/// Maximum number of post-effect witness evidence hashes in an admission
/// bundle.
pub const MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES: usize = 32;

/// Maximum number of receipt digests in an `AdmissionOutcomeIndexV1`.
pub const MAX_OUTCOME_INDEX_RECEIPT_DIGESTS: usize = 64;

// =============================================================================
// QuarantineActionV1
// =============================================================================

/// A quarantine action committed at bundle seal time (RFC-0019 §7).
///
/// Records the type and reservation hash for a quarantine action that
/// was reserved as part of admission. This is sealed into the bundle
/// BEFORE any receipts/events reference it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineActionV1 {
    /// Quarantine reservation hash (proves capacity was reserved).
    pub reservation_hash: Hash,
    /// Request ID associated with this quarantine action.
    pub request_id: Hash,
    /// AJC ID that authorized this quarantine action.
    pub ajc_id: Hash,
}

// =============================================================================
// AdmissionBundleV1 (RFC-0019 REQ-0024, TCK-00493)
// =============================================================================

/// Deterministic, bounded, `deny_unknown_fields` CAS admission bundle.
///
/// Sealed BEFORE emission of authoritative receipts/events that reference
/// its digest. The bundle digest IS the v1.1 `AdmissionBindingHash`
/// (semantic equality) and MUST be included in all authoritative
/// receipts/events.
///
/// # Digest Cycle Avoidance
///
/// This bundle MUST NOT include hashes/ids of receipts/events created
/// after the bundle is sealed. Discovery of "what receipts were emitted"
/// uses reverse-edge correlation: receipts carry the bundle digest.
///
/// # Fields (RFC-0019 §8.2 Normative Fields)
///
/// - HSI envelope bindings
/// - Authoritative policy-root reference + provenance
/// - AJC id + join/consume selector digests
/// - Intent digest + consume-time intent digest
/// - Witness SEED hashes + post-effect witness evidence hashes/refs
/// - Effect digest
/// - Quarantine actions
/// - HT/HE anchors for audit
///
/// # Security Model
///
/// - Bounded: all collection fields have hard `MAX_*` limits.
/// - `deny_unknown_fields`: rejects unknown JSON fields at deserialization.
/// - Deterministic digest via domain-separated BLAKE3 with canonical ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionBundleV1 {
    /// Schema version for forward compatibility.
    pub schema_version: u32,

    // -- Session + HSI envelope bindings --
    /// Stable request identifier.
    pub request_id: Hash,
    /// Session identifier.
    #[serde(deserialize_with = "bounded_deser::deser_kernel_string")]
    pub session_id: String,
    /// HSI contract manifest digest.
    pub hsi_contract_manifest_digest: Hash,
    /// HSI envelope binding digest.
    pub hsi_envelope_binding_digest: Hash,

    // -- Authoritative policy-root reference + provenance --
    /// Policy root digest at admission time.
    pub policy_root_digest: Hash,
    /// Policy root epoch (monotonic generation).
    pub policy_root_epoch: u64,

    // -- AJC id + join/consume selector digests --
    /// AJC ID that authorized this admission.
    pub ajc_id: Hash,
    /// Authority join hash (join selector digest).
    pub authority_join_hash: Hash,
    /// Consume selector digest (effect selector).
    pub consume_selector_digest: Hash,

    // -- Intent digests --
    /// Intent digest at join time.
    pub intent_digest: Hash,
    /// Consume-time intent digest (should match join-time for valid admission).
    pub consume_time_intent_digest: Hash,

    // -- Witness SEED hashes --
    /// Leakage witness seed content hash.
    pub leakage_witness_seed_hash: Hash,
    /// Timing witness seed content hash.
    pub timing_witness_seed_hash: Hash,

    // -- Effect digest --
    /// Effect descriptor digest (tool identity + arguments hash).
    pub effect_descriptor_digest: Hash,

    // -- Quarantine actions --
    /// Quarantine actions committed at bundle seal time. Bounded by
    /// `MAX_BUNDLE_QUARANTINE_ACTIONS`. Deserialization enforces the
    /// limit via visitor-based counting (no oversized pre-allocation).
    #[serde(deserialize_with = "bounded_deser::deser_quarantine_actions")]
    pub quarantine_actions: Vec<QuarantineActionV1>,

    // -- HT/HE anchors for audit --
    /// Ledger anchor at admission time.
    pub ledger_anchor: LedgerAnchorV1,
    /// Time envelope reference (HTF) at admission.
    pub time_envelope_ref: Hash,
    /// Freshness witness tick at admission.
    pub freshness_witness_tick: u64,
    /// Revocation head hash at consume time.
    pub revocation_head_hash: Hash,

    // -- Enforcement context --
    /// Policy-derived enforcement tier.
    pub enforcement_tier: EnforcementTier,
    /// Spine join extension content hash (binds to all spine fields).
    pub spine_ext_hash: Hash,
    /// Stop/budget profile digest.
    pub stop_budget_digest: Hash,
    /// Risk tier for this admission.
    pub risk_tier: RiskTier,
}

/// Current schema version for `AdmissionBundleV1`.
pub const ADMISSION_BUNDLE_SCHEMA_VERSION: u32 = 1;

impl AdmissionBundleV1 {
    /// Validate all boundary constraints on this bundle.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violation found (fail-closed).
    pub fn validate(&self) -> Result<(), AdmitError> {
        const ZERO: Hash = [0u8; 32];

        if self.schema_version != ADMISSION_BUNDLE_SCHEMA_VERSION {
            return Err(AdmitError::BundleSealFailure {
                reason: format!(
                    "unsupported schema_version: expected {ADMISSION_BUNDLE_SCHEMA_VERSION}, got {}",
                    self.schema_version
                ),
            });
        }

        // Bounded collection checks
        if self.quarantine_actions.len() > MAX_BUNDLE_QUARANTINE_ACTIONS {
            return Err(AdmitError::BundleSealFailure {
                reason: format!(
                    "quarantine_actions exceeds maximum of \
                     {MAX_BUNDLE_QUARANTINE_ACTIONS}, got {}",
                    self.quarantine_actions.len()
                ),
            });
        }

        // Required hash fields must be non-zero
        if self.request_id == ZERO {
            return Err(AdmitError::BundleSealFailure {
                reason: "request_id is zero".into(),
            });
        }
        if self.ajc_id == ZERO {
            return Err(AdmitError::BundleSealFailure {
                reason: "ajc_id is zero".into(),
            });
        }
        if self.intent_digest == ZERO {
            return Err(AdmitError::BundleSealFailure {
                reason: "intent_digest is zero".into(),
            });
        }

        // String length bounds
        if self.session_id.is_empty() || self.session_id.len() > MAX_KERNEL_STRING_LENGTH {
            return Err(AdmitError::BundleSealFailure {
                reason: "session_id empty or exceeds maximum length".into(),
            });
        }

        Ok(())
    }

    /// Compute the deterministic content hash (digest) for this bundle.
    ///
    /// This digest IS the v1.1 `AdmissionBindingHash` — a **logical
    /// binding hash** for semantic equality of the admission decision.
    /// It is NOT the CAS storage key. The CAS storage key is derived
    /// from `to_canonical_bytes()` (`serde_json` serialization), while
    /// this hash is a domain-separated BLAKE3 digest over normative
    /// fields in canonical order. The two serve different purposes:
    ///
    /// - `content_hash()` / `bundle_digest`: logical identity for receipts,
    ///   events, and cross-component binding references.
    /// - `to_canonical_bytes()`: byte-level representation for
    ///   content-addressed storage (CAS) keying.
    ///
    /// # Digest Stability
    ///
    /// Field ordering MUST NOT change across versions. New optional
    /// fields MUST be appended (never inserted) to maintain backward
    /// compatibility.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String fields bounded by MAX_* (<=256), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-admission-bundle-v1");
        hasher.update(&self.schema_version.to_le_bytes());

        // Session + HSI envelope bindings
        hasher.update(&self.request_id);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&(self.session_id.len() as u32).to_le_bytes());
        hasher.update(&self.hsi_contract_manifest_digest);
        hasher.update(&self.hsi_envelope_binding_digest);

        // Policy-root reference + provenance
        hasher.update(&self.policy_root_digest);
        hasher.update(&self.policy_root_epoch.to_le_bytes());

        // AJC id + selectors
        hasher.update(&self.ajc_id);
        hasher.update(&self.authority_join_hash);
        hasher.update(&self.consume_selector_digest);

        // Intent digests
        hasher.update(&self.intent_digest);
        hasher.update(&self.consume_time_intent_digest);

        // Witness SEED hashes
        hasher.update(&self.leakage_witness_seed_hash);
        hasher.update(&self.timing_witness_seed_hash);

        // Effect digest
        hasher.update(&self.effect_descriptor_digest);

        // Quarantine actions (length-prefixed array)
        hasher.update(&(self.quarantine_actions.len() as u32).to_le_bytes());
        for qa in &self.quarantine_actions {
            hasher.update(&qa.reservation_hash);
            hasher.update(&qa.request_id);
            hasher.update(&qa.ajc_id);
        }

        // HT/HE anchors
        hasher.update(&self.ledger_anchor.ledger_id);
        hasher.update(&self.ledger_anchor.event_hash);
        hasher.update(&self.ledger_anchor.height.to_le_bytes());
        hasher.update(&self.ledger_anchor.he_time.to_le_bytes());
        hasher.update(&self.time_envelope_ref);
        hasher.update(&self.freshness_witness_tick.to_le_bytes());
        hasher.update(&self.revocation_head_hash);

        // Enforcement context
        hasher.update(match self.enforcement_tier {
            EnforcementTier::FailClosed => &[0x01],
            EnforcementTier::Monitor => &[0x02],
        });
        hasher.update(&self.spine_ext_hash);
        hasher.update(&self.stop_budget_digest);
        hasher.update(match self.risk_tier {
            RiskTier::Tier0 => &[0x00],
            RiskTier::Tier1 => &[0x01],
            RiskTier::Tier2Plus => &[0x02],
            _ => &[0xFF], // Unknown variant — deterministic fallback tag.
        });

        *hasher.finalize().as_bytes()
    }

    /// Serialize to canonical JSON bytes for CAS storage.
    ///
    /// # Errors
    ///
    /// Returns `AdmitError::BundleSealFailure` if serialization fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AdmitError> {
        serde_json::to_vec(self).map_err(|e| AdmitError::BundleSealFailure {
            reason: format!("bundle serialization failed: {e}"),
        })
    }
}

// =============================================================================
// AdmissionOutcomeIndexV1 (RFC-0019 REQ-0024, TCK-00493)
// =============================================================================

/// Forward index emitted AFTER authoritative receipts/events are created.
///
/// This object references the already-sealed `AdmissionBundleV1` digest
/// and lists the receipt/event digests that were emitted for this
/// admission. It is emitted post-bundle to avoid digest cycles.
///
/// Post-effect witness evidence hashes live here (not in the bundle)
/// because they are populated AFTER the effect executes, which is after
/// bundle sealing. Placing them in the bundle would mutate the sealed
/// content hash and orphan the original `AdmissionBindingHash`.
///
/// # Digest Cycle Avoidance
///
/// The bundle is sealed BEFORE receipts/events. This index is created
/// AFTER receipts/events and references the bundle digest (not vice
/// versa). The bundle NEVER references receipt/event IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionOutcomeIndexV1 {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Digest of the sealed `AdmissionBundleV1` this index references.
    pub bundle_digest: Hash,
    /// Request ID for correlation.
    pub request_id: Hash,
    /// AJC ID for correlation.
    pub ajc_id: Hash,
    /// Post-effect witness evidence hashes (populated after effect
    /// execution). These live in the outcome index rather than the
    /// bundle because the bundle is sealed BEFORE the effect executes.
    /// Bounded by `MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES`.
    /// Deserialization enforces the limit via visitor-based counting.
    #[serde(deserialize_with = "bounded_deser::deser_post_effect_witness_evidence_hashes")]
    pub post_effect_witness_evidence_hashes: Vec<Hash>,
    /// Receipt/event digests emitted for this admission. Bounded by
    /// `MAX_OUTCOME_INDEX_RECEIPT_DIGESTS`. Deserialization enforces
    /// the limit via visitor-based counting (no oversized pre-allocation).
    #[serde(deserialize_with = "bounded_deser::deser_receipt_digests")]
    pub receipt_digests: Vec<Hash>,
}

/// Current schema version for `AdmissionOutcomeIndexV1`.
pub const ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION: u32 = 1;

impl AdmissionOutcomeIndexV1 {
    /// Validate all boundary constraints on this outcome index.
    ///
    /// # Errors
    ///
    /// Returns a description of the first violation found (fail-closed).
    pub fn validate(&self) -> Result<(), AdmitError> {
        const ZERO: Hash = [0u8; 32];

        if self.schema_version != ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION {
            return Err(AdmitError::BundleSealFailure {
                reason: format!(
                    "unsupported outcome index schema_version: expected \
                     {ADMISSION_OUTCOME_INDEX_SCHEMA_VERSION}, got {}",
                    self.schema_version
                ),
            });
        }

        if self.post_effect_witness_evidence_hashes.len() > MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES {
            return Err(AdmitError::BundleSealFailure {
                reason: format!(
                    "post_effect_witness_evidence_hashes exceeds maximum of \
                     {MAX_BUNDLE_POST_EFFECT_WITNESS_HASHES}, got {}",
                    self.post_effect_witness_evidence_hashes.len()
                ),
            });
        }

        if self.receipt_digests.len() > MAX_OUTCOME_INDEX_RECEIPT_DIGESTS {
            return Err(AdmitError::BundleSealFailure {
                reason: format!(
                    "receipt_digests exceeds maximum of \
                     {MAX_OUTCOME_INDEX_RECEIPT_DIGESTS}, got {}",
                    self.receipt_digests.len()
                ),
            });
        }

        if self.bundle_digest == ZERO {
            return Err(AdmitError::BundleSealFailure {
                reason: "bundle_digest is zero in outcome index".into(),
            });
        }

        if self.request_id == ZERO {
            return Err(AdmitError::BundleSealFailure {
                reason: "request_id is zero in outcome index".into(),
            });
        }

        Ok(())
    }

    /// Compute the deterministic content hash for this outcome index.
    ///
    /// This is a **logical binding hash** (domain-separated BLAKE3),
    /// not the CAS storage key. See [`AdmissionBundleV1::content_hash`]
    /// for the distinction between logical hash and CAS key.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Collections bounded by MAX_* constants (<=64), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-admission-outcome-index-v1");
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.bundle_digest);
        hasher.update(&self.request_id);
        hasher.update(&self.ajc_id);
        // Post-effect witness evidence hashes (length-prefixed array)
        hasher.update(&(self.post_effect_witness_evidence_hashes.len() as u32).to_le_bytes());
        for h in &self.post_effect_witness_evidence_hashes {
            hasher.update(h);
        }
        // Receipt digests (length-prefixed array)
        hasher.update(&(self.receipt_digests.len() as u32).to_le_bytes());
        for d in &self.receipt_digests {
            hasher.update(d);
        }
        *hasher.finalize().as_bytes()
    }

    /// Serialize to canonical JSON bytes for CAS storage.
    ///
    /// # Errors
    ///
    /// Returns `AdmitError::BundleSealFailure` if serialization fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AdmitError> {
        serde_json::to_vec(self).map_err(|e| AdmitError::BundleSealFailure {
            reason: format!("outcome index serialization failed: {e}"),
        })
    }
}

// =============================================================================
// BoundarySpanV1
// =============================================================================

/// In-kernel boundary mediation span (RFC-0019 §1.1, §5.3 phase M-N).
///
/// Buffers/governs outputs until post-effect checks complete for
/// fail-closed tiers. Output is released only after witness finalization
/// and boundary admissibility checks pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundarySpanV1 {
    /// Request ID this span mediates.
    pub request_id: Hash,
    /// Whether output is currently held (not yet released).
    pub output_held: bool,
    /// Enforcement tier for this boundary span.
    pub enforcement_tier: EnforcementTier,
}

// =============================================================================
// AdmissionResultV1
// =============================================================================

/// Result of successful admission plan execution (RFC-0019 Appendix A).
///
/// Contains the sealed admission bundle, its digest, capability tokens
/// for effect execution, and lifecycle receipts.
///
/// Witness seeds are carried through from the plan so the runtime
/// post-effect path can invoke `finalize_post_effect_witness` with the
/// actual seeds (not just their hashes). This closes the gap where the
/// runtime path previously did ad-hoc hash-only validation instead of
/// calling the kernel's canonical validator (QUALITY MAJOR 1, TCK-00497).
pub struct AdmissionResultV1 {
    /// Digest of the sealed `AdmissionBundleV1` CAS object
    /// (v1.1 `AdmissionBindingHash`).
    pub bundle_digest: Hash,
    /// The sealed `AdmissionBundleV1` ready for CAS storage.
    /// Sealed BEFORE any authoritative receipts/events reference it.
    pub bundle: AdmissionBundleV1,
    /// Capability token for effect execution.
    pub effect_capability: EffectCapability,
    /// Capability token for authoritative ledger writes.
    ///
    /// `Some` only for fail-closed tiers that have passed all prerequisite
    /// checks. `None` for monitor tiers — monitor-tier requests MUST NOT
    /// perform authoritative ledger writes (CTR-2617: fail-closed
    /// capabilities).
    pub ledger_write_capability: Option<LedgerWriteCapability>,
    /// Capability token for quarantine insertion (if applicable).
    pub quarantine_capability: Option<QuarantineCapability>,
    /// The consumed authority witness.
    pub consumed_witness: AuthorityConsumedV1,
    /// The durable consume record.
    pub consume_record: AuthorityConsumeRecordV1,
    /// Boundary span for output mediation.
    pub boundary_span: BoundarySpanV1,
    /// Leakage witness seed from plan time (TCK-00497 QUALITY MAJOR 1).
    ///
    /// Carried through from the consumed plan so the runtime post-effect
    /// path can pass the actual seed (not just its hash) to
    /// `AdmissionKernelV1::finalize_post_effect_witness`. This enables
    /// full seed/provider binding validation instead of ad-hoc hash-only
    /// checks.
    pub leakage_witness_seed: WitnessSeedV1,
    /// Timing witness seed from plan time (TCK-00497 QUALITY MAJOR 1).
    ///
    /// See `leakage_witness_seed` for rationale.
    pub timing_witness_seed: WitnessSeedV1,
    /// Idempotency key for propagation into tool/broker adapter calls
    /// (TCK-00501, REQ-0029).
    ///
    /// Deterministically derived from `RequestId` + AJC ID. External
    /// systems that support idempotency keys should use this to
    /// deduplicate effect execution.
    pub idempotency_key: super::effect_journal::IdempotencyKeyV1,
    /// Reference to the effect execution journal for post-effect
    /// completion recording (TCK-00501).
    ///
    /// The caller MUST call `record_completed(request_id)` after
    /// successful effect execution to transition the journal state
    /// from `Started` to `Completed`. Without this, the next restart
    /// will classify the effect as `Unknown` (in-doubt).
    ///
    /// `None` when no effect journal is wired.
    pub effect_journal: Option<std::sync::Arc<dyn super::effect_journal::EffectJournal>>,
    /// Pre-built journal binding data for the caller to call
    /// `record_started` at the true pre-dispatch boundary
    /// (TCK-00501 SEC-MAJOR-1 fix).
    ///
    /// The caller MUST call `journal.record_started(&binding)` just
    /// before the actual effect dispatch (`broker.execute()` for tool
    /// requests, or ledger/CAS writes for session endpoints). This
    /// ensures `Started` entries are only created when the effect is
    /// truly about to be dispatched, preventing false in-doubt
    /// classification from intervening failures.
    ///
    /// `None` when no effect journal is wired.
    pub journal_binding: Option<super::effect_journal::EffectJournalBindingV1>,
}

// Intentionally no Clone or Serialize — capability tokens are non-cloneable.

impl std::fmt::Debug for AdmissionResultV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionResultV1")
            .field("bundle_digest", &hex::encode(self.bundle_digest))
            .field("bundle_ajc_id", &hex::encode(self.bundle.ajc_id))
            .field("effect_capability", &self.effect_capability)
            .field("ledger_write_capability", &self.ledger_write_capability)
            .field("quarantine_capability", &self.quarantine_capability)
            .field("consumed_witness", &self.consumed_witness)
            .field("consume_record", &self.consume_record)
            .field("boundary_span", &self.boundary_span)
            .field(
                "leakage_seed_hash",
                &hex::encode(self.leakage_witness_seed.content_hash()),
            )
            .field(
                "timing_seed_hash",
                &hex::encode(self.timing_witness_seed.content_hash()),
            )
            .field("idempotency_key", &hex::encode(self.idempotency_key.key))
            .field("has_effect_journal", &self.effect_journal.is_some())
            .field("has_journal_binding", &self.journal_binding.is_some())
            .finish()
    }
}

// =============================================================================
// AdmitError
// =============================================================================

/// Error type for admission kernel operations.
///
/// All variants represent deterministic denials (fail-closed). There is
/// no "unknown -> allow" path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitError {
    /// Request validation failed.
    InvalidRequest {
        /// Bounded reason string.
        reason: String,
    },
    /// Ledger trust verification failed.
    LedgerTrustFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Policy root resolution failed.
    PolicyRootFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Anti-rollback anchor verification failed.
    AntiRollbackFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// PCAC join was denied.
    JoinDenied {
        /// Bounded reason string.
        reason: String,
    },
    /// PCAC revalidation was denied.
    RevalidationDenied {
        /// Bounded reason string.
        reason: String,
    },
    /// PCAC consume was denied (includes intent mismatch, already consumed).
    ConsumeDenied {
        /// Bounded reason string.
        reason: String,
    },
    /// Witness seed creation failed.
    WitnessSeedFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Plan has already been consumed (single-use enforcement).
    PlanAlreadyConsumed,
    /// Quarantine capacity could not be reserved for fail-closed tier.
    QuarantineReservationFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Boundary mediation failed (output cannot be held/released).
    BoundaryMediationFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Missing prerequisite for fail-closed tier.
    MissingPrerequisite {
        /// Name of the missing prerequisite.
        prerequisite: String,
    },
    /// A prerequisite drifted between plan and execute (TOCTOU protection).
    ///
    /// This error is raised when a fail-closed tier detects that a
    /// prerequisite (ledger anchor, policy root, anti-rollback) changed
    /// between `plan()` and `execute()`.
    ExecutePrerequisiteDrift {
        /// Which prerequisite drifted.
        prerequisite: String,
        /// Bounded reason string.
        reason: String,
    },
    /// Bundle sealing failed (validation, serialization, or CAS storage).
    BundleSealFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Post-effect witness evidence is missing or invalid (TCK-00497).
    ///
    /// For fail-closed tiers, output release is denied when witness
    /// evidence is missing, incomplete, or fails validation.
    WitnessEvidenceFailure {
        /// Bounded reason string.
        reason: String,
    },
    /// Boundary output release denied (TCK-00497).
    ///
    /// Fail-closed tiers deny output release when post-effect witness
    /// evidence is missing or invalid. The output remains held.
    OutputReleaseDenied {
        /// Bounded reason string.
        reason: String,
    },
    /// Monitor-tier witness waiver is invalid (TCK-00497).
    ///
    /// Monitor tiers require an explicit waiver to bypass witness
    /// enforcement. This error is raised when the waiver is missing,
    /// expired, or structurally invalid.
    WitnessWaiverInvalid {
        /// Bounded reason string.
        reason: String,
    },
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest { reason } => write!(f, "invalid request: {reason}"),
            Self::LedgerTrustFailure { reason } => {
                write!(f, "ledger trust failure: {reason}")
            },
            Self::PolicyRootFailure { reason } => {
                write!(f, "policy root failure: {reason}")
            },
            Self::AntiRollbackFailure { reason } => {
                write!(f, "anti-rollback failure: {reason}")
            },
            Self::JoinDenied { reason } => write!(f, "join denied: {reason}"),
            Self::RevalidationDenied { reason } => {
                write!(f, "revalidation denied: {reason}")
            },
            Self::ConsumeDenied { reason } => write!(f, "consume denied: {reason}"),
            Self::WitnessSeedFailure { reason } => {
                write!(f, "witness seed failure: {reason}")
            },
            Self::PlanAlreadyConsumed => write!(f, "plan already consumed (single-use)"),
            Self::QuarantineReservationFailure { reason } => {
                write!(f, "quarantine reservation failure: {reason}")
            },
            Self::BoundaryMediationFailure { reason } => {
                write!(f, "boundary mediation failure: {reason}")
            },
            Self::MissingPrerequisite { prerequisite } => {
                write!(f, "missing prerequisite: {prerequisite}")
            },
            Self::ExecutePrerequisiteDrift {
                prerequisite,
                reason,
            } => {
                write!(f, "execute prerequisite drift: {prerequisite}: {reason}")
            },
            Self::BundleSealFailure { reason } => {
                write!(f, "bundle seal failure: {reason}")
            },
            Self::WitnessEvidenceFailure { reason } => {
                write!(f, "witness evidence failure: {reason}")
            },
            Self::OutputReleaseDenied { reason } => {
                write!(f, "output release denied: {reason}")
            },
            Self::WitnessWaiverInvalid { reason } => {
                write!(f, "witness waiver invalid: {reason}")
            },
        }
    }
}

impl std::error::Error for AdmitError {}
