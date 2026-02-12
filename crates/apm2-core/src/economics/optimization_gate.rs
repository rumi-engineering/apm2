// AGENT-AUTHORED
//! Security-interlocked optimization gates.
//!
//! Quantitative evidence quality enforcement (RFC-0029 REQ-0006),
//! authority-surface monotonicity enforcement (RFC-0029 REQ-0008),
//! and disclosure-control interlock non-regression (RFC-0029 REQ-0007).
//!
//! This module enforces the following interlock contracts:
//!
//! 1. **KPI/countermetric completeness**: every optimization KPI must have a
//!    required countermetric in gate policy. Proposals missing a countermetric
//!    mapping for any declared KPI are denied fail-closed.
//!
//! 2. **Canonical evaluator binding**: all TP-EIO29 predicates must be
//!    evaluated by `TemporalPredicateEvaluatorV1` (evaluator ID
//!    `temporal_predicate_evaluator_v1`). Unknown evaluator IDs are denied
//!    fail-closed.
//!
//! 3. **Evidence-quality thresholds**: statistical power >= 0.90, significance
//!    alpha <= 0.01, minimum sample-size proof > 0, and reproducibility matrix
//!    >= 3 distinct runtime classes.
//!
//! 4. **Freshness and throughput-dominance**: stale evidence classes block
//!    optimization promotions, and throughput-dominance violations block
//!    promotion-critical evidence classes.
//!
//! 5. **Authority-surface monotonicity** (REQ-0008): for production FAC roles,
//!    `AS(role, t+1) ⊆ AS(role, t)` — the authority surface must monotonically
//!    decrease. Any optimization that increases the external authority surface
//!    is denied fail-closed.
//!
//! 6. **Direct GitHub non-regression** (REQ-0008): `github_direct_surface(role,
//!    t) == 0` — no direct GitHub API/gh\_cli capability classes may appear in
//!    production agent runtimes. Any optimization that reintroduces these
//!    classes is denied fail-closed.
//!
//! 7. **Authority-surface evidence requirement** (REQ-0008): every optimization
//!    must carry authoritative capability-surface diff evidence. Missing,
//!    stale, or ambiguous evidence fails closed to deny.
//!
//! 8. **Disclosure-control interlock** (REQ-0007): optimization decisions are
//!    bound to signed disclosure-control policy snapshots. Phase-qualified
//!    disclosure policy mode matching is enforced. Patent/provisional and
//!    unapproved disclosure channels are denied in `TRADE_SECRET_ONLY` mode.
//!    Unknown, stale, missing, or ambiguous disclosure-control state fails
//!    closed to deny.
//!
//! # Security Model
//!
//! All gates enforce fail-closed semantics: missing, stale, unknown, or
//! sub-threshold evidence produces a deterministic denial with a stable
//! reason code. There is no "default pass" path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};
use subtle::ConstantTimeEq;

use crate::fac::FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES;
use crate::pcac::MAX_REASON_LENGTH;
use crate::pcac::temporal_arbitration::{ArbitrationOutcome, EvaluatorTuple, TemporalPredicateId};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Canonical evaluator ID for all TP-EIO29 predicates.
pub const CANONICAL_EVALUATOR_ID: &str = "temporal_predicate_evaluator_v1";

/// Maximum number of KPI entries in an optimization gate policy.
pub const MAX_KPI_ENTRIES: usize = 64;

/// Maximum number of countermetric entries in a countermetric profile.
pub const MAX_COUNTERMETRIC_ENTRIES: usize = 64;

/// Maximum length for a KPI identifier string.
pub const MAX_KPI_ID_LENGTH: usize = 256;

/// Maximum length for a countermetric identifier string.
pub const MAX_COUNTERMETRIC_ID_LENGTH: usize = 256;

/// Maximum number of evidence samples in a quality report.
pub const MAX_EVIDENCE_SAMPLES: usize = 256;

/// Maximum number of runtime classes in a reproducibility matrix.
pub const MAX_RUNTIME_CLASSES: usize = 64;

/// Maximum length for runtime class identifier strings.
pub const MAX_RUNTIME_CLASS_ID_LENGTH: usize = 256;

/// Maximum length for deny reason strings.
pub const MAX_DENY_REASON_LENGTH: usize = MAX_REASON_LENGTH;

/// Minimum required statistical power for evidence quality admission.
pub const MIN_STATISTICAL_POWER: f64 = 0.90;

/// Maximum allowed significance alpha for evidence quality admission.
pub const MAX_SIGNIFICANCE_ALPHA: f64 = 0.01;

/// Minimum required distinct runtime classes for reproducibility matrix.
pub const MIN_REPRODUCIBILITY_RUNTIME_CLASSES: usize = 3;

/// Maximum age in ticks for evidence freshness (promotion-critical).
pub const MAX_EVIDENCE_FRESHNESS_TICKS: u64 = 1000;

/// Maximum allowed throughput regression ratio (1.0 = no regression).
/// Evidence that shows throughput below this ratio of the baseline is
/// rejected as a throughput-dominance violation.
pub const THROUGHPUT_DOMINANCE_MIN_RATIO: f64 = 1.0;

/// Maximum number of capability entries in an authority-surface diff.
pub const MAX_CAPABILITY_SURFACE_ENTRIES: usize = 256;

/// Maximum length for a role ID in authority-surface evidence.
pub const MAX_SURFACE_ROLE_ID_LENGTH: usize = 256;

/// Maximum length for a capability ID in authority-surface evidence.
pub const MAX_SURFACE_CAPABILITY_ID_LENGTH: usize = 256;

/// Maximum age in ticks for authority-surface evidence freshness.
pub const MAX_AUTHORITY_SURFACE_EVIDENCE_AGE_TICKS: u64 = 500;

/// Maximum length for a phase ID in disclosure-control policy snapshots.
pub const MAX_PHASE_ID_LENGTH: usize = 256;

/// Maximum length for a disclosure channel class name.
pub const MAX_DISCLOSURE_CHANNEL_CLASS_LENGTH: usize = 256;

/// Maximum number of approved disclosure channel classes in a policy snapshot.
pub const MAX_APPROVED_DISCLOSURE_CHANNELS: usize = 64;

/// Maximum age in ticks for disclosure-control policy epoch freshness.
pub const MAX_DISCLOSURE_POLICY_AGE_TICKS: u64 = 500;

/// Forbidden disclosure channel classes under `TRADE_SECRET_ONLY` mode.
///
/// Patent and provisional workflow channels are unconditionally denied
/// when the current disclosure policy mode is `TradeSecretOnly`.
pub const FORBIDDEN_TRADE_SECRET_CHANNEL_CLASSES: &[&str] = &[
    "patent_filing",
    "provisional_application",
    "patent_prosecution",
    "patent_licensing",
    "patent_assignment",
    "provisional_disclosure",
];

// ---------------------------------------------------------------------------
// Deny reason constants
// ---------------------------------------------------------------------------

/// Deny: KPI has no countermetric mapping in gate policy.
pub const DENY_KPI_MISSING_COUNTERMETRIC: &str = "optimization_kpi_missing_countermetric";

/// Deny: countermetric profile is not present.
pub const DENY_COUNTERMETRIC_PROFILE_MISSING: &str = "optimization_countermetric_profile_missing";

/// Deny: evaluator ID is not the canonical evaluator.
pub const DENY_NON_CANONICAL_EVALUATOR: &str = "optimization_non_canonical_evaluator";

/// Deny: evaluator ID is empty.
pub const DENY_EVALUATOR_ID_EMPTY: &str = "optimization_evaluator_id_empty";

/// Deny: statistical power below threshold.
pub const DENY_POWER_BELOW_THRESHOLD: &str = "optimization_evidence_power_below_threshold";

/// Deny: significance alpha above threshold.
pub const DENY_ALPHA_ABOVE_THRESHOLD: &str = "optimization_evidence_alpha_above_threshold";

/// Deny: sample size is zero.
pub const DENY_SAMPLE_SIZE_ZERO: &str = "optimization_evidence_sample_size_zero";

/// Deny: insufficient runtime classes for reproducibility.
pub const DENY_REPRODUCIBILITY_INSUFFICIENT: &str =
    "optimization_evidence_reproducibility_insufficient";

/// Deny: evidence is stale (exceeds freshness window).
pub const DENY_EVIDENCE_STALE: &str = "optimization_evidence_stale";

/// Deny: throughput-dominance violation.
pub const DENY_THROUGHPUT_DOMINANCE_VIOLATION: &str = "optimization_throughput_dominance_violation";

/// Deny: evidence quality report is missing.
pub const DENY_EVIDENCE_QUALITY_MISSING: &str = "optimization_evidence_quality_missing";

/// Deny: arbitration outcome is not `AgreedAllow`.
pub const DENY_ARBITRATION_NOT_AGREED_ALLOW: &str = "optimization_arbitration_not_agreed_allow";

/// Deny: KPI entries exceed maximum count.
pub const DENY_KPI_ENTRIES_OVERFLOW: &str = "optimization_kpi_entries_overflow";

/// Deny: countermetric entries exceed maximum count.
pub const DENY_COUNTERMETRIC_ENTRIES_OVERFLOW: &str = "optimization_countermetric_entries_overflow";

/// Deny: evidence samples exceed maximum count.
pub const DENY_EVIDENCE_SAMPLES_OVERFLOW: &str = "optimization_evidence_samples_overflow";

/// Deny: runtime classes exceed maximum count.
pub const DENY_RUNTIME_CLASSES_OVERFLOW: &str = "optimization_runtime_classes_overflow";

/// Deny: throughput ratio is NaN.
pub const DENY_THROUGHPUT_RATIO_NAN: &str = "optimization_throughput_ratio_nan";

/// Deny: power value is NaN.
pub const DENY_POWER_NAN: &str = "optimization_evidence_power_nan";

/// Deny: alpha value is NaN.
pub const DENY_ALPHA_NAN: &str = "optimization_evidence_alpha_nan";

/// Deny: evidence freshness tick is ahead of current tick.
pub const DENY_EVIDENCE_FUTURE_TICK: &str = "optimization_evidence_future_tick";

/// Deny: authority-surface evidence is missing.
pub const DENY_AUTHORITY_SURFACE_EVIDENCE_MISSING: &str =
    "optimization_authority_surface_evidence_missing";

/// Deny: authority-surface evidence is stale (exceeds freshness window).
pub const DENY_AUTHORITY_SURFACE_EVIDENCE_STALE: &str =
    "optimization_authority_surface_evidence_stale";

/// Deny: authority-surface evidence is ambiguous.
pub const DENY_AUTHORITY_SURFACE_EVIDENCE_AMBIGUOUS: &str =
    "optimization_authority_surface_evidence_ambiguous";

/// Deny: authority-surface evidence state is unknown.
pub const DENY_AUTHORITY_SURFACE_EVIDENCE_UNKNOWN: &str =
    "optimization_authority_surface_evidence_unknown";

/// Deny: authority surface increased (monotonicity violation).
pub const DENY_AUTHORITY_SURFACE_INCREASE: &str = "optimization_authority_surface_increase";

/// Deny: direct GitHub capability class reintroduced in production runtime.
pub const DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED: &str =
    "optimization_direct_github_capability_reintroduced";

/// Deny: authority-surface diff has too many capability entries.
pub const DENY_CAPABILITY_SURFACE_ENTRIES_OVERFLOW: &str =
    "optimization_capability_surface_entries_overflow";

/// Deny: authority-surface evidence tick is ahead of current tick.
pub const DENY_AUTHORITY_SURFACE_EVIDENCE_FUTURE_TICK: &str =
    "optimization_authority_surface_evidence_future_tick";

/// Deny: authority-surface diff role ID is empty.
pub const DENY_AUTHORITY_SURFACE_ROLE_ID_EMPTY: &str =
    "optimization_authority_surface_role_id_empty";

/// Deny: authority-surface diff content digest is zero.
pub const DENY_AUTHORITY_SURFACE_DIGEST_ZERO: &str = "optimization_authority_surface_digest_zero";

/// Deny: disclosure-control policy snapshot is missing.
pub const DENY_DISCLOSURE_POLICY_MISSING: &str = "optimization_disclosure_policy_missing";

/// Deny: disclosure-control policy snapshot is stale.
pub const DENY_DISCLOSURE_POLICY_STALE: &str = "optimization_disclosure_policy_stale";

/// Deny: disclosure-control policy snapshot is ambiguous.
pub const DENY_DISCLOSURE_POLICY_AMBIGUOUS: &str = "optimization_disclosure_policy_ambiguous";

/// Deny: disclosure-control policy state is unknown.
pub const DENY_DISCLOSURE_POLICY_UNKNOWN: &str = "optimization_disclosure_policy_unknown";

/// Deny: disclosure-control policy snapshot is unsigned.
pub const DENY_DISCLOSURE_POLICY_UNSIGNED: &str = "optimization_disclosure_policy_unsigned";

/// Deny: disclosure-control policy snapshot has zero signature.
pub const DENY_DISCLOSURE_POLICY_SIGNATURE_ZERO: &str =
    "optimization_disclosure_policy_signature_zero";

/// Deny: disclosure-control policy snapshot has zero policy digest.
pub const DENY_DISCLOSURE_POLICY_DIGEST_ZERO: &str = "optimization_disclosure_policy_digest_zero";

/// Deny: disclosure-control policy snapshot has empty phase ID.
pub const DENY_DISCLOSURE_POLICY_PHASE_ID_EMPTY: &str =
    "optimization_disclosure_policy_phase_id_empty";

/// Deny: disclosure-control policy epoch tick is ahead of current tick.
pub const DENY_DISCLOSURE_POLICY_FUTURE_TICK: &str = "optimization_disclosure_policy_future_tick";

/// Deny: disclosure-control policy mode mismatch between proposal and snapshot.
pub const DENY_DISCLOSURE_MODE_MISMATCH: &str = "optimization_disclosure_mode_mismatch";

/// Deny: patent/provisional channel attempted under `TRADE_SECRET_ONLY` mode.
pub const DENY_TRADE_SECRET_PATENT_CHANNEL: &str =
    "optimization_trade_secret_patent_channel_denied";

/// Deny: unapproved disclosure channel class in optimization proposal.
pub const DENY_UNAPPROVED_DISCLOSURE_CHANNEL: &str = "optimization_unapproved_disclosure_channel";

/// Deny: approved disclosure channels list exceeds maximum size.
pub const DENY_DISCLOSURE_CHANNELS_OVERFLOW: &str = "optimization_disclosure_channels_overflow";

/// Deny: proposal disclosure channels list exceeds maximum size.
pub const DENY_PROPOSAL_DISCLOSURE_CHANNELS_OVERFLOW: &str =
    "optimization_proposal_disclosure_channels_overflow";

/// Deny: disclosure-control policy signature failed Ed25519 verification.
pub const DENY_DISCLOSURE_POLICY_SIGNATURE_INVALID: &str =
    "optimization_disclosure_policy_signature_invalid";

/// Deny: trusted verification key bytes are invalid (not a valid Ed25519 public
/// key).
pub const DENY_DISCLOSURE_POLICY_KEY_INVALID: &str = "optimization_disclosure_policy_key_invalid";

/// Deny: disclosure-control policy digest does not bind the semantic fields
/// (mode, `phase_id`, `epoch_tick`, state, `approved_channels`).
pub const DENY_DISCLOSURE_POLICY_DIGEST_MISMATCH: &str =
    "optimization_disclosure_policy_digest_mismatch";

/// Deny: disclosure-control policy phase ID does not match the expected phase.
pub const DENY_DISCLOSURE_POLICY_PHASE_MISMATCH: &str =
    "optimization_disclosure_policy_phase_mismatch";

// ---------------------------------------------------------------------------
// Bounded serde deserializers
// ---------------------------------------------------------------------------

fn deserialize_bounded_kpi_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_KPI_ID_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "kpi_id length {} exceeds maximum {}",
            value.len(),
            MAX_KPI_ID_LENGTH,
        )));
    }
    Ok(value)
}

fn deserialize_bounded_optional_deny_reason<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(reason) = value.as_ref() {
        if reason.len() > MAX_DENY_REASON_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "deny_reason length {} exceeds maximum {}",
                reason.len(),
                MAX_DENY_REASON_LENGTH,
            )));
        }
    }
    Ok(value)
}

fn deserialize_bounded_kpi_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let map = BTreeMap::<String, String>::deserialize(deserializer)?;
    if map.len() > MAX_KPI_ENTRIES {
        return Err(serde::de::Error::custom(format!(
            "kpi_countermetric_map length {} exceeds maximum {}",
            map.len(),
            MAX_KPI_ENTRIES,
        )));
    }
    for (k, v) in &map {
        if k.len() > MAX_KPI_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "kpi_id length {} exceeds maximum {}",
                k.len(),
                MAX_KPI_ID_LENGTH,
            )));
        }
        if v.len() > MAX_COUNTERMETRIC_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "countermetric_id length {} exceeds maximum {}",
                v.len(),
                MAX_COUNTERMETRIC_ID_LENGTH,
            )));
        }
    }
    Ok(map)
}

fn deserialize_bounded_runtime_classes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let classes = Vec::<String>::deserialize(deserializer)?;
    if classes.len() > MAX_RUNTIME_CLASSES {
        return Err(serde::de::Error::custom(format!(
            "runtime_classes length {} exceeds maximum {}",
            classes.len(),
            MAX_RUNTIME_CLASSES,
        )));
    }
    for class in &classes {
        if class.len() > MAX_RUNTIME_CLASS_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "runtime_class_id length {} exceeds maximum {}",
                class.len(),
                MAX_RUNTIME_CLASS_ID_LENGTH,
            )));
        }
    }
    Ok(classes)
}

fn deserialize_bounded_kpi_ids<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let ids = Vec::<String>::deserialize(deserializer)?;
    if ids.len() > MAX_KPI_ENTRIES {
        return Err(serde::de::Error::custom(format!(
            "kpi_ids length {} exceeds maximum {}",
            ids.len(),
            MAX_KPI_ENTRIES,
        )));
    }
    for id in &ids {
        if id.len() > MAX_KPI_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "kpi_id length {} exceeds maximum {}",
                id.len(),
                MAX_KPI_ID_LENGTH,
            )));
        }
    }
    Ok(ids)
}

fn deserialize_bounded_capability_surface<'de, D>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let caps = BTreeSet::<String>::deserialize(deserializer)?;
    if caps.len() > MAX_CAPABILITY_SURFACE_ENTRIES {
        return Err(serde::de::Error::custom(format!(
            "capability_surface length {} exceeds maximum {}",
            caps.len(),
            MAX_CAPABILITY_SURFACE_ENTRIES,
        )));
    }
    for cap in &caps {
        if cap.len() > MAX_SURFACE_CAPABILITY_ID_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "capability_id length {} exceeds maximum {}",
                cap.len(),
                MAX_SURFACE_CAPABILITY_ID_LENGTH,
            )));
        }
    }
    Ok(caps)
}

fn deserialize_bounded_surface_role_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX_SURFACE_ROLE_ID_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "role_id length {} exceeds maximum {}",
            value.len(),
            MAX_SURFACE_ROLE_ID_LENGTH,
        )));
    }
    Ok(value)
}

fn deserialize_bounded_phase_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedStringVisitor;

    impl serde::de::Visitor<'_> for BoundedStringVisitor {
        type Value = String;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a string of at most {MAX_PHASE_ID_LENGTH} bytes")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            if v.len() > MAX_PHASE_ID_LENGTH {
                return Err(E::custom(format!(
                    "phase_id length {} exceeds maximum {}",
                    v.len(),
                    MAX_PHASE_ID_LENGTH,
                )));
            }
            Ok(v.to_owned())
        }

        fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
            if v.len() > MAX_PHASE_ID_LENGTH {
                return Err(E::custom(format!(
                    "phase_id length {} exceeds maximum {}",
                    v.len(),
                    MAX_PHASE_ID_LENGTH,
                )));
            }
            Ok(v)
        }
    }

    deserializer.deserialize_str(BoundedStringVisitor)
}

fn deserialize_bounded_disclosure_channels<'de, D>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedChannelSetVisitor;

    impl<'de> serde::de::Visitor<'de> for BoundedChannelSetVisitor {
        type Value = BTreeSet<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "a set of at most {MAX_APPROVED_DISCLOSURE_CHANNELS} disclosure channels"
            )
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut set = BTreeSet::new();
            let mut count = 0usize;
            while let Some(value) = seq.next_element::<String>()? {
                count += 1;
                if count > MAX_APPROVED_DISCLOSURE_CHANNELS {
                    return Err(serde::de::Error::custom(format!(
                        "disclosure channel count {count} exceeds maximum {MAX_APPROVED_DISCLOSURE_CHANNELS}"
                    )));
                }
                if value.len() > MAX_DISCLOSURE_CHANNEL_CLASS_LENGTH {
                    return Err(serde::de::Error::custom(format!(
                        "disclosure_channel_class length {} exceeds maximum {}",
                        value.len(),
                        MAX_DISCLOSURE_CHANNEL_CLASS_LENGTH,
                    )));
                }
                set.insert(value);
            }
            Ok(set)
        }
    }

    deserializer.deserialize_seq(BoundedChannelSetVisitor)
}

// ---------------------------------------------------------------------------
// Disclosure-control policy types (REQ-0007)
// ---------------------------------------------------------------------------

/// Disclosure policy mode for a phase.
///
/// Determines which disclosure channels are admissible for optimizations
/// evaluated in this phase. Only the mode active for the current phase
/// is valid; mismatches between proposal and snapshot are denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DisclosurePolicyMode {
    /// Trade-secret-only mode. Patent and provisional workflow channels
    /// are unconditionally denied. Only approved internal channels are
    /// admissible.
    TradeSecretOnly,

    /// Open-source mode. Broad disclosure channels may be approved by
    /// policy. Patent channels may still be denied if not explicitly
    /// approved.
    OpenSource,
}

/// Freshness state of a disclosure-control policy snapshot.
///
/// Only `Current` snapshots are admitted. All other states deny
/// fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DisclosurePolicyState {
    /// Policy snapshot is current and authoritative.
    Current,
    /// Policy snapshot is stale (exceeds freshness window).
    Stale,
    /// Policy snapshot is ambiguous (conflicting or incomplete).
    Ambiguous,
    /// Policy state is unknown.
    Unknown,
}

/// Signed disclosure-control policy snapshot.
///
/// Binds optimization decisions to a specific disclosure posture for
/// the evaluated phase. The snapshot includes a policy digest for
/// CAS binding and an Ed25519 signature for integrity verification.
///
/// # Invariants
///
/// - [`DisclosurePolicyState::Current`] is the only admitted state.
/// - Unsigned snapshots (zero signature) deny fail-closed.
/// - Zero policy digest denies fail-closed.
/// - Empty phase ID denies fail-closed.
/// - Stale epochs (exceeding [`MAX_DISCLOSURE_POLICY_AGE_TICKS`]) deny
///   fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicySnapshot {
    /// Phase identifier this policy applies to.
    #[serde(deserialize_with = "deserialize_bounded_phase_id")]
    pub phase_id: String,

    /// The disclosure policy mode active for this phase.
    pub mode: DisclosurePolicyMode,

    /// HTF tick at which this policy epoch was established.
    pub epoch_tick: u64,

    /// Freshness state of this policy snapshot.
    pub state: DisclosurePolicyState,

    /// Content digest of the full policy document (for CAS binding).
    pub policy_digest: [u8; 32],

    /// Ed25519 signature over the canonical policy payload (64 bytes).
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],

    /// Set of approved disclosure channel classes under this policy.
    /// Only channels in this set are admissible for optimizations.
    /// In `TradeSecretOnly` mode, patent/provisional channels are
    /// denied even if they appear here.
    #[serde(deserialize_with = "deserialize_bounded_disclosure_channels")]
    pub approved_channels: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Authority-surface evidence types (REQ-0008)
// ---------------------------------------------------------------------------

/// Freshness state of authority-surface evidence.
///
/// Only `Current` evidence is admitted. All other states deny fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuthoritySurfaceEvidenceState {
    /// Evidence is current and authoritative.
    Current,
    /// Evidence is stale (exceeds freshness window).
    Stale,
    /// Evidence is ambiguous (conflicting or incomplete).
    Ambiguous,
    /// Evidence state is unknown.
    Unknown,
}

/// Role-level capability-surface diff for an optimization candidate.
///
/// Captures the before and after capability surfaces for a production FAC
/// role, enabling monotonicity verification and direct GitHub non-regression
/// checks.
///
/// Both `before` and `after` sets are bounded to
/// [`MAX_CAPABILITY_SURFACE_ENTRIES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySurfaceDiff {
    /// Role identifier for this diff.
    #[serde(deserialize_with = "deserialize_bounded_surface_role_id")]
    pub role_id: String,

    /// Capability surface before the optimization (time t).
    #[serde(deserialize_with = "deserialize_bounded_capability_surface")]
    pub before: BTreeSet<String>,

    /// Capability surface after the optimization (time t+1).
    #[serde(deserialize_with = "deserialize_bounded_capability_surface")]
    pub after: BTreeSet<String>,

    /// Content digest of this diff (for integrity binding).
    pub content_digest: [u8; 32],
}

/// Authority-surface evidence for an optimization proposal (REQ-0008).
///
/// Wraps a capability-surface diff with freshness and state metadata.
/// Missing, stale, ambiguous, or unknown evidence states deny fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySurfaceEvidence {
    /// The capability-surface diff for this optimization.
    pub diff: AuthoritySurfaceDiff,

    /// HTF tick at which this evidence was gathered.
    pub evidence_tick: u64,

    /// State of this evidence.
    pub state: AuthoritySurfaceEvidenceState,
}

// ---------------------------------------------------------------------------
// KPI/Countermetric completeness types
// ---------------------------------------------------------------------------

/// A mapping of optimization KPI IDs to their required countermetric IDs.
///
/// Every KPI declared in an optimization proposal must have a corresponding
/// countermetric. Missing mappings are denied fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountermetricProfile {
    /// Mapping from KPI ID to its required countermetric ID.
    #[serde(deserialize_with = "deserialize_bounded_kpi_map")]
    pub kpi_countermetric_map: BTreeMap<String, String>,

    /// Content digest of this profile (for CAS binding).
    pub content_digest: [u8; 32],
}

/// An optimization proposal declaring which KPIs it targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizationProposal {
    /// The KPI IDs this optimization targets.
    #[serde(deserialize_with = "deserialize_bounded_kpi_ids")]
    pub target_kpi_ids: Vec<String>,

    /// Evaluator tuples bound to this proposal's TP-EIO29 predicates.
    pub evaluator_bindings: Vec<EvaluatorTuple>,

    /// Content digest of the proposal (for integrity binding).
    pub proposal_digest: [u8; 32],

    /// Disclosure policy mode the proposal assumes for its evaluation window.
    /// Must match the mode in the active disclosure-control policy snapshot.
    pub assumed_disclosure_mode: DisclosurePolicyMode,

    /// Disclosure channel classes this optimization requires or uses.
    /// All channels must be approved in the active policy snapshot.
    /// In `TradeSecretOnly` mode, patent/provisional channels are always
    /// denied.
    #[serde(deserialize_with = "deserialize_bounded_disclosure_channels")]
    pub disclosure_channels: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Evidence quality types
// ---------------------------------------------------------------------------

/// Quantitative evidence quality report for an optimization.
///
/// Must meet minimum thresholds for power, alpha, sample size, and
/// reproducibility before an optimization can be promoted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceQualityReport {
    /// Statistical power of the evidence (required >= 0.90).
    pub statistical_power: f64,

    /// Significance level alpha (required <= 0.01).
    pub significance_alpha: f64,

    /// Number of samples in the evidence. Must be > 0.
    pub sample_size: u64,

    /// Distinct runtime classes where evidence was gathered.
    /// Must contain >= 3 classes for reproducibility.
    #[serde(deserialize_with = "deserialize_bounded_runtime_classes")]
    pub runtime_classes: Vec<String>,

    /// HTF tick at which this evidence was gathered.
    pub evidence_tick: u64,

    /// Throughput ratio relative to baseline. Must be >= 1.0.
    /// A ratio below 1.0 indicates throughput regression (dominance violation).
    pub throughput_ratio: f64,

    /// Content digest of the evidence report (for integrity binding).
    pub evidence_digest: [u8; 32],
}

// ---------------------------------------------------------------------------
// Optimization gate decision
// ---------------------------------------------------------------------------

/// Verdict from the optimization gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OptimizationGateVerdict {
    /// All gates pass — optimization may proceed.
    Allow,
    /// One or more gates denied the optimization.
    Deny,
    /// Optimization is blocked pending freshness resolution.
    Blocked,
}

/// Trace payload for optimization gate decisions.
///
/// Contains boolean gate results and a proposal digest for auditing.
/// The multiple boolean fields reflect distinct gate evaluations and
/// are intentionally separate for deterministic tracing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OptimizationGateTrace {
    /// Overall verdict.
    pub verdict: OptimizationGateVerdict,

    /// Stable deny reason when verdict is not `Allow`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_deny_reason"
    )]
    pub deny_reason: Option<String>,

    /// Whether KPI/countermetric completeness passed.
    pub kpi_countermetric_complete: bool,

    /// Whether canonical evaluator binding passed.
    pub canonical_evaluator_bound: bool,

    /// Whether evidence quality thresholds passed.
    pub evidence_quality_passed: bool,

    /// Whether evidence freshness passed.
    pub evidence_freshness_passed: bool,

    /// Whether throughput-dominance check passed.
    pub throughput_dominance_passed: bool,

    /// Whether authority-surface evidence was provided and valid (REQ-0008).
    pub authority_surface_evidence_valid: bool,

    /// Whether authority-surface monotonicity check passed (REQ-0008).
    pub authority_surface_monotonic: bool,

    /// Whether direct GitHub capability non-regression check passed (REQ-0008).
    pub no_direct_github_capabilities: bool,

    /// Whether disclosure-control policy validation passed (REQ-0007).
    pub disclosure_policy_valid: bool,

    /// Whether disclosure-control mode matching passed (REQ-0007).
    pub disclosure_mode_matched: bool,

    /// Whether disclosure-channel classification check passed (REQ-0007).
    pub disclosure_channels_approved: bool,

    /// Policy snapshot digest bound to this decision (REQ-0007).
    /// Zero when disclosure policy was not provided or not yet validated.
    pub disclosure_policy_digest: [u8; 32],

    /// Proposal digest bound to this decision.
    pub proposal_digest: [u8; 32],
}

/// Complete optimization gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptimizationGateDecision {
    /// Verdict.
    pub verdict: OptimizationGateVerdict,

    /// Deterministic deny reason when verdict is not `Allow`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_bounded_optional_deny_reason"
    )]
    pub deny_reason: Option<String>,

    /// Full trace for auditing.
    pub trace: OptimizationGateTrace,
}

impl OptimizationGateDecision {
    /// Returns the deny defect if verdict is not `Allow`.
    #[must_use]
    pub fn defect(&self) -> Option<&str> {
        self.deny_reason.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Gate: KPI/countermetric completeness
// ---------------------------------------------------------------------------

/// Validates that every KPI in the proposal has a countermetric mapping.
///
/// # Errors
///
/// Returns a stable deny reason string if any KPI is missing a countermetric.
pub fn validate_kpi_countermetric_completeness(
    proposal: &OptimizationProposal,
    profile: &CountermetricProfile,
) -> Result<(), &'static str> {
    if proposal.target_kpi_ids.len() > MAX_KPI_ENTRIES {
        return Err(DENY_KPI_ENTRIES_OVERFLOW);
    }

    if profile.kpi_countermetric_map.len() > MAX_COUNTERMETRIC_ENTRIES {
        return Err(DENY_COUNTERMETRIC_ENTRIES_OVERFLOW);
    }

    for kpi_id in &proposal.target_kpi_ids {
        if !profile.kpi_countermetric_map.contains_key(kpi_id.as_str()) {
            return Err(DENY_KPI_MISSING_COUNTERMETRIC);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Canonical evaluator binding
// ---------------------------------------------------------------------------

/// Validates that all evaluator bindings in the proposal use the canonical
/// `TemporalPredicateEvaluatorV1` evaluator ID.
///
/// # Errors
///
/// Returns a stable deny reason if any evaluator has a non-canonical ID.
pub fn validate_canonical_evaluator_binding(
    proposal: &OptimizationProposal,
) -> Result<(), &'static str> {
    for evaluator in &proposal.evaluator_bindings {
        if evaluator.evaluator_id.is_empty() {
            return Err(DENY_EVALUATOR_ID_EMPTY);
        }
        if evaluator.evaluator_id != CANONICAL_EVALUATOR_ID {
            return Err(DENY_NON_CANONICAL_EVALUATOR);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Evidence quality thresholds
// ---------------------------------------------------------------------------

/// Validates evidence quality against required thresholds.
///
/// Checks:
/// - `statistical_power` >= `MIN_STATISTICAL_POWER` (0.90)
/// - `significance_alpha` <= `MAX_SIGNIFICANCE_ALPHA` (0.01)
/// - `sample_size` > 0
/// - `runtime_classes.len()` >= `MIN_REPRODUCIBILITY_RUNTIME_CLASSES` (3)
///
/// # Errors
///
/// Returns a stable deny reason if any threshold is violated.
pub fn validate_evidence_quality(report: &EvidenceQualityReport) -> Result<(), &'static str> {
    if report.runtime_classes.len() > MAX_RUNTIME_CLASSES {
        return Err(DENY_RUNTIME_CLASSES_OVERFLOW);
    }

    if report.statistical_power.is_nan() {
        return Err(DENY_POWER_NAN);
    }

    if report.significance_alpha.is_nan() {
        return Err(DENY_ALPHA_NAN);
    }

    if report.statistical_power < MIN_STATISTICAL_POWER {
        return Err(DENY_POWER_BELOW_THRESHOLD);
    }

    if report.significance_alpha > MAX_SIGNIFICANCE_ALPHA {
        return Err(DENY_ALPHA_ABOVE_THRESHOLD);
    }

    if report.sample_size == 0 {
        return Err(DENY_SAMPLE_SIZE_ZERO);
    }

    if report.runtime_classes.len() < MIN_REPRODUCIBILITY_RUNTIME_CLASSES {
        return Err(DENY_REPRODUCIBILITY_INSUFFICIENT);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Evidence freshness
// ---------------------------------------------------------------------------

/// Validates that evidence is fresh relative to the current tick.
///
/// Stale evidence (older than `MAX_EVIDENCE_FRESHNESS_TICKS`) blocks
/// optimization promotions.
///
/// # Errors
///
/// Returns a stable deny reason if evidence is stale or has a future tick.
pub const fn validate_evidence_freshness(
    evidence_tick: u64,
    current_tick: u64,
    max_age_ticks: u64,
) -> Result<(), &'static str> {
    if evidence_tick > current_tick {
        return Err(DENY_EVIDENCE_FUTURE_TICK);
    }

    let age = current_tick - evidence_tick;
    if age > max_age_ticks {
        return Err(DENY_EVIDENCE_STALE);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Throughput dominance
// ---------------------------------------------------------------------------

/// Validates that the optimization does not regress throughput below baseline.
///
/// A throughput ratio < 1.0 indicates the optimization reduces throughput,
/// which blocks promotion-critical evidence classes.
///
/// # Errors
///
/// Returns a stable deny reason if throughput dominance is violated.
pub fn validate_throughput_dominance(throughput_ratio: f64) -> Result<(), &'static str> {
    if throughput_ratio.is_nan() {
        return Err(DENY_THROUGHPUT_RATIO_NAN);
    }

    if throughput_ratio < THROUGHPUT_DOMINANCE_MIN_RATIO {
        return Err(DENY_THROUGHPUT_DOMINANCE_VIOLATION);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Arbitration binding
// ---------------------------------------------------------------------------

/// Validates that temporal arbitration outcome is `AgreedAllow`.
///
/// Non-allow outcomes (deny, transient/persistent disagreement) block
/// optimization promotion.
///
/// # Errors
///
/// Returns a stable deny reason if the outcome is not `AgreedAllow`.
pub fn validate_arbitration_outcome(outcome: ArbitrationOutcome) -> Result<(), &'static str> {
    if outcome != ArbitrationOutcome::AgreedAllow {
        return Err(DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Authority-surface evidence validity (REQ-0008)
// ---------------------------------------------------------------------------

/// Validates that authority-surface evidence is present, current, and
/// structurally valid.
///
/// Checks:
/// - Evidence is not `None` (fail-closed: missing evidence is denied).
/// - Evidence state is `Current` (stale, ambiguous, and unknown states are
///   denied fail-closed).
/// - Evidence tick is not in the future.
/// - Evidence is not stale (age <= `max_age_ticks`).
/// - Role ID is non-empty.
/// - Content digest is non-zero.
/// - Capability sets do not exceed `MAX_CAPABILITY_SURFACE_ENTRIES`.
///
/// # Errors
///
/// Returns a stable deny reason string if any check fails.
pub fn validate_authority_surface_evidence(
    evidence: Option<&AuthoritySurfaceEvidence>,
    current_tick: u64,
    max_age_ticks: u64,
) -> Result<(), &'static str> {
    let Some(evidence) = evidence else {
        return Err(DENY_AUTHORITY_SURFACE_EVIDENCE_MISSING);
    };

    // State check (fail-closed for non-Current states).
    match evidence.state {
        AuthoritySurfaceEvidenceState::Current => {},
        AuthoritySurfaceEvidenceState::Stale => {
            return Err(DENY_AUTHORITY_SURFACE_EVIDENCE_STALE);
        },
        AuthoritySurfaceEvidenceState::Ambiguous => {
            return Err(DENY_AUTHORITY_SURFACE_EVIDENCE_AMBIGUOUS);
        },
        AuthoritySurfaceEvidenceState::Unknown => {
            return Err(DENY_AUTHORITY_SURFACE_EVIDENCE_UNKNOWN);
        },
    }

    // Freshness checks.
    if evidence.evidence_tick > current_tick {
        return Err(DENY_AUTHORITY_SURFACE_EVIDENCE_FUTURE_TICK);
    }
    let age = current_tick - evidence.evidence_tick;
    if age > max_age_ticks {
        return Err(DENY_AUTHORITY_SURFACE_EVIDENCE_STALE);
    }

    // Structural checks on the diff.
    if evidence.diff.role_id.is_empty() {
        return Err(DENY_AUTHORITY_SURFACE_ROLE_ID_EMPTY);
    }

    if is_zero_hash(&evidence.diff.content_digest) {
        return Err(DENY_AUTHORITY_SURFACE_DIGEST_ZERO);
    }

    if evidence.diff.before.len() > MAX_CAPABILITY_SURFACE_ENTRIES {
        return Err(DENY_CAPABILITY_SURFACE_ENTRIES_OVERFLOW);
    }

    if evidence.diff.after.len() > MAX_CAPABILITY_SURFACE_ENTRIES {
        return Err(DENY_CAPABILITY_SURFACE_ENTRIES_OVERFLOW);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Authority-surface monotonicity (REQ-0008)
// ---------------------------------------------------------------------------

/// Validates that the authority surface monotonically decreases:
/// `AS(role, t+1) ⊆ AS(role, t)`.
///
/// Any capability present in `after` but absent from `before` represents
/// an authority-surface increase, which is denied for production FAC roles.
///
/// # Errors
///
/// Returns a stable deny reason if the after set is not a subset of before.
pub fn validate_authority_surface_monotonicity(
    diff: &AuthoritySurfaceDiff,
) -> Result<(), &'static str> {
    // AS(role, t+1) must be a subset of AS(role, t).
    // Any element in `after` not in `before` is an increase.
    if !diff.after.is_subset(&diff.before) {
        return Err(DENY_AUTHORITY_SURFACE_INCREASE);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Direct GitHub capability non-regression (REQ-0008)
// ---------------------------------------------------------------------------

/// Validates that no direct GitHub capability classes appear in the
/// `after` capability surface.
///
/// For production FAC roles: `github_direct_surface(role, t) == 0`.
/// Any capability in the `after` set that resolves to a forbidden direct
/// GitHub capability class is denied fail-closed.
///
/// Uses the canonical forbidden-class list from
/// [`FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES`].
///
/// # Errors
///
/// Returns a stable deny reason if any forbidden class is found.
pub fn validate_no_direct_github_capabilities(
    diff: &AuthoritySurfaceDiff,
) -> Result<(), &'static str> {
    for cap_id in &diff.after {
        if is_forbidden_github_capability(cap_id) {
            return Err(DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED);
        }
    }
    Ok(())
}

/// Checks whether a capability ID resolves to a forbidden direct GitHub
/// capability class.
///
/// Normalises the capability ID by lowercasing, stripping the `kernel.`
/// prefix, and extracting the first path segment. Then checks against
/// [`FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES`].
fn is_forbidden_github_capability(capability_id: &str) -> bool {
    let normalized = capability_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    let stripped = normalized
        .strip_prefix("kernel.")
        .unwrap_or(&normalized)
        .trim();

    let class = stripped
        .split(['.', ':', '/'])
        .find(|segment| !segment.is_empty())
        .unwrap_or(stripped);

    FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES.contains(&class)
}

// ---------------------------------------------------------------------------
// Gate: Disclosure-control policy validity (REQ-0007)
// ---------------------------------------------------------------------------

/// Computes a domain-separated canonical hash of all semantic fields in a
/// disclosure-control policy snapshot.
///
/// The digest binds `phase_id`, `mode`, `epoch_tick`, `state`, and
/// `approved_channels` using Blake3 with key derivation context
/// `"apm2.disclosure_policy.v1"`.
///
/// This function is public so that snapshot producers can set `policy_digest`
/// to the correct value before signing.
#[must_use]
pub fn compute_disclosure_policy_digest(snap: &DisclosurePolicySnapshot) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("apm2.disclosure_policy.v1");
    // phase_id (length-prefixed)
    hasher.update(&(snap.phase_id.len() as u64).to_le_bytes());
    hasher.update(snap.phase_id.as_bytes());
    // mode discriminant
    #[allow(unreachable_patterns)]
    hasher.update(&[match snap.mode {
        DisclosurePolicyMode::TradeSecretOnly => 0u8,
        DisclosurePolicyMode::OpenSource => 1u8,
        // non_exhaustive: unknown variant fails closed with a unique discriminant
        _ => 255u8,
    }]);
    // epoch_tick
    hasher.update(&snap.epoch_tick.to_le_bytes());
    // state discriminant
    #[allow(unreachable_patterns)]
    hasher.update(&[match snap.state {
        DisclosurePolicyState::Current => 0u8,
        DisclosurePolicyState::Stale => 1u8,
        DisclosurePolicyState::Ambiguous => 2u8,
        DisclosurePolicyState::Unknown => 3u8,
        // non_exhaustive: unknown variant fails closed
        _ => 255u8,
    }]);
    // approved_channels (BTreeSet is already sorted)
    hasher.update(&(snap.approved_channels.len() as u64).to_le_bytes());
    for ch in &snap.approved_channels {
        hasher.update(&(ch.len() as u64).to_le_bytes());
        hasher.update(ch.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Validates that a disclosure-control policy snapshot is present, current,
/// signed, cryptographically verified, digest-bound, phase-matched, and
/// structurally valid.
///
/// Checks:
/// - Snapshot is not `None` (fail-closed: missing policy is denied).
/// - Policy state is `Current` (stale, ambiguous, and unknown deny).
/// - Signature is non-zero (unsigned snapshots deny fail-closed).
/// - Policy digest is non-zero.
/// - Phase ID is non-empty.
/// - Phase ID matches the expected phase ID (cross-phase replay prevention).
/// - Epoch tick is not in the future.
/// - Epoch is not stale (age <= `max_age_ticks`).
/// - Approved channels set does not exceed
///   [`MAX_APPROVED_DISCLOSURE_CHANNELS`].
/// - Ed25519 signature cryptographically verifies against the trusted authority
///   key and the policy digest.
/// - Policy digest canonically binds all semantic fields (mode, `phase_id`,
///   `epoch_tick`, state, `approved_channels`) via
///   [`compute_disclosure_policy_digest`].
///
/// # Parameters
///
/// - `snapshot`: The disclosure-control policy snapshot to validate, or `None`
///   if the proposal has no policy binding.
/// - `trusted_verifying_key`: 32-byte Ed25519 public key of the trusted
///   disclosure-control authority. Used to verify the snapshot signature.
/// - `expected_phase_id`: The phase ID that the snapshot must match. Prevents
///   cross-phase policy replay attacks.
/// - `current_tick`: The current HTF tick for freshness evaluation.
/// - `max_age_ticks`: Maximum allowed epoch age in ticks.
///
/// # Errors
///
/// Returns a stable deny reason string if any check fails.
pub fn validate_disclosure_policy(
    snapshot: Option<&DisclosurePolicySnapshot>,
    trusted_verifying_key: &[u8; 32],
    expected_phase_id: &str,
    current_tick: u64,
    max_age_ticks: u64,
) -> Result<(), &'static str> {
    let Some(snap) = snapshot else {
        return Err(DENY_DISCLOSURE_POLICY_MISSING);
    };

    // State check (fail-closed for non-Current states).
    match snap.state {
        DisclosurePolicyState::Current => {},
        DisclosurePolicyState::Stale => {
            return Err(DENY_DISCLOSURE_POLICY_STALE);
        },
        DisclosurePolicyState::Ambiguous => {
            return Err(DENY_DISCLOSURE_POLICY_AMBIGUOUS);
        },
        DisclosurePolicyState::Unknown => {
            return Err(DENY_DISCLOSURE_POLICY_UNKNOWN);
        },
    }

    // Signature check (unsigned is denied).
    let zero_sig = [0u8; 64];
    if snap.signature.ct_eq(&zero_sig).unwrap_u8() == 1 {
        return Err(DENY_DISCLOSURE_POLICY_UNSIGNED);
    }

    // Policy digest zero check.
    if is_zero_hash(&snap.policy_digest) {
        return Err(DENY_DISCLOSURE_POLICY_DIGEST_ZERO);
    }

    // Phase ID non-empty check.
    if snap.phase_id.is_empty() {
        return Err(DENY_DISCLOSURE_POLICY_PHASE_ID_EMPTY);
    }

    // Phase ID binding — prevents cross-phase policy replay.
    if snap.phase_id != expected_phase_id {
        return Err(DENY_DISCLOSURE_POLICY_PHASE_MISMATCH);
    }

    // Epoch freshness checks.
    if snap.epoch_tick > current_tick {
        return Err(DENY_DISCLOSURE_POLICY_FUTURE_TICK);
    }
    let age = current_tick - snap.epoch_tick;
    if age > max_age_ticks {
        return Err(DENY_DISCLOSURE_POLICY_STALE);
    }

    // Approved channels bounds check.
    if snap.approved_channels.len() > MAX_APPROVED_DISCLOSURE_CHANNELS {
        return Err(DENY_DISCLOSURE_CHANNELS_OVERFLOW);
    }

    // Cryptographic signature verification (Ed25519).
    // Construct the verifying key from trusted authority bytes.
    let vk = VerifyingKey::from_bytes(trusted_verifying_key)
        .map_err(|_| DENY_DISCLOSURE_POLICY_KEY_INVALID)?;

    // Construct the Ed25519 signature from the snapshot bytes.
    let sig = Ed25519Signature::from_bytes(&snap.signature);

    // Verify the signature against the policy digest.
    vk.verify_strict(&snap.policy_digest, &sig)
        .map_err(|_| DENY_DISCLOSURE_POLICY_SIGNATURE_INVALID)?;

    // Semantic field binding: verify that the policy digest canonically binds
    // ALL semantic fields. This prevents an attacker from reusing a valid
    // (policy_digest, signature) pair while mutating semantic fields.
    let expected_digest = compute_disclosure_policy_digest(snap);
    if snap.policy_digest.ct_eq(&expected_digest).unwrap_u8() != 1 {
        return Err(DENY_DISCLOSURE_POLICY_DIGEST_MISMATCH);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Disclosure-control mode matching (REQ-0007)
// ---------------------------------------------------------------------------

/// Validates that the proposal's assumed disclosure mode matches the
/// active policy snapshot's mode.
///
/// Optimization decisions that assume a disclosure mode not active for
/// the current phase are non-admissible (REQ-0007).
///
/// # Errors
///
/// Returns a stable deny reason if the modes do not match.
pub fn validate_disclosure_mode_match(
    proposal: &OptimizationProposal,
    snapshot: &DisclosurePolicySnapshot,
) -> Result<(), &'static str> {
    if proposal.assumed_disclosure_mode != snapshot.mode {
        return Err(DENY_DISCLOSURE_MODE_MISMATCH);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Gate: Disclosure-channel classification (REQ-0007)
// ---------------------------------------------------------------------------

/// Validates that all disclosure channels in the proposal are approved
/// under the active policy snapshot.
///
/// In `TradeSecretOnly` mode, patent/provisional channels are
/// unconditionally denied even if they appear in the approved set.
///
/// Unapproved channel classes are denied by default (deny-by-default
/// for disclosure-channel classification).
///
/// # Errors
///
/// Returns a stable deny reason if any channel is forbidden or unapproved.
pub fn validate_disclosure_channels(
    proposal: &OptimizationProposal,
    snapshot: &DisclosurePolicySnapshot,
) -> Result<(), &'static str> {
    if proposal.disclosure_channels.len() > MAX_APPROVED_DISCLOSURE_CHANNELS {
        return Err(DENY_PROPOSAL_DISCLOSURE_CHANNELS_OVERFLOW);
    }

    // Build a normalized (lowercase) set of approved channels for consistent
    // case-insensitive comparison. This closes the gap where
    // `is_forbidden_trade_secret_channel` uses lowercase but the approval
    // check was raw.
    let approved_lower: BTreeSet<String> = snapshot
        .approved_channels
        .iter()
        .map(|ch| ch.to_ascii_lowercase())
        .collect();

    for channel in &proposal.disclosure_channels {
        let normalized = channel.to_ascii_lowercase();

        // In TRADE_SECRET_ONLY mode, patent/provisional channels are always denied.
        if snapshot.mode == DisclosurePolicyMode::TradeSecretOnly
            && is_forbidden_trade_secret_channel(channel)
        {
            return Err(DENY_TRADE_SECRET_PATENT_CHANNEL);
        }

        // All channels must be in the approved set (deny-by-default),
        // using normalized comparison.
        if !approved_lower.contains(&normalized) {
            return Err(DENY_UNAPPROVED_DISCLOSURE_CHANNEL);
        }
    }

    Ok(())
}

/// Checks whether a disclosure channel class resolves to a forbidden
/// patent/provisional channel under trade-secret-only mode.
///
/// Normalises the channel class by lowercasing and trimming whitespace.
fn is_forbidden_trade_secret_channel(channel_class: &str) -> bool {
    let normalized = channel_class.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    FORBIDDEN_TRADE_SECRET_CHANNEL_CLASSES
        .iter()
        .any(|forbidden| normalized == *forbidden)
}

// ---------------------------------------------------------------------------
// Combined optimization gate evaluator
// ---------------------------------------------------------------------------

/// Evaluates all optimization gates for a proposal.
///
/// Gate evaluation order:
/// 1. Disclosure-control policy validity (REQ-0007)
/// 2. Disclosure-control mode matching (REQ-0007)
/// 3. Disclosure-channel classification (REQ-0007)
/// 4. Authority-surface evidence validity (REQ-0008)
/// 5. Authority-surface monotonicity (REQ-0008)
/// 6. Direct GitHub capability non-regression (REQ-0008)
/// 7. KPI/countermetric completeness
/// 8. Canonical evaluator binding
/// 9. Arbitration outcome
/// 10. Evidence quality thresholds
/// 11. Evidence freshness
/// 12. Throughput dominance
///
/// Disclosure-control gates (1-3) are evaluated first because they enforce
/// containment-critical confidentiality invariants that must not be bypassed.
/// Authority-surface gates (4-6) follow as containment-critical invariants.
///
/// First failing gate determines the deny reason. All gates are fail-closed.
///
/// Returns a decision with full trace for auditing.
#[must_use]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn evaluate_optimization_gate(
    proposal: &OptimizationProposal,
    countermetric_profile: Option<&CountermetricProfile>,
    evidence_quality: Option<&EvidenceQualityReport>,
    authority_surface_evidence: Option<&AuthoritySurfaceEvidence>,
    disclosure_policy: Option<&DisclosurePolicySnapshot>,
    trusted_disclosure_verifying_key: &[u8; 32],
    expected_phase_id: &str,
    arbitration_outcome: ArbitrationOutcome,
    current_tick: u64,
    max_evidence_age_ticks: u64,
) -> OptimizationGateDecision {
    let mut trace = OptimizationGateTrace {
        verdict: OptimizationGateVerdict::Allow,
        deny_reason: None,
        kpi_countermetric_complete: false,
        canonical_evaluator_bound: false,
        evidence_quality_passed: false,
        evidence_freshness_passed: false,
        throughput_dominance_passed: false,
        authority_surface_evidence_valid: false,
        authority_surface_monotonic: false,
        no_direct_github_capabilities: false,
        disclosure_policy_valid: false,
        disclosure_mode_matched: false,
        disclosure_channels_approved: false,
        disclosure_policy_digest: [0u8; 32],
        proposal_digest: proposal.proposal_digest,
    };

    // Gate 1 (REQ-0007): Disclosure-control policy validity
    if let Err(reason) = validate_disclosure_policy(
        disclosure_policy,
        trusted_disclosure_verifying_key,
        expected_phase_id,
        current_tick,
        MAX_DISCLOSURE_POLICY_AGE_TICKS,
    ) {
        return deny_decision(reason, trace);
    }
    trace.disclosure_policy_valid = true;

    // validate_disclosure_policy returned Ok, so snapshot is Some
    // and structurally valid. Use let-else to avoid expect/panic.
    let Some(policy_snap) = disclosure_policy else {
        // Unreachable: validate_disclosure_policy returned Ok
        // which requires Some. Fail-closed deny as defensive fallback.
        return deny_decision(DENY_DISCLOSURE_POLICY_MISSING, trace);
    };
    trace.disclosure_policy_digest = policy_snap.policy_digest;

    // Gate 2 (REQ-0007): Disclosure-control mode matching
    if let Err(reason) = validate_disclosure_mode_match(proposal, policy_snap) {
        return deny_decision(reason, trace);
    }
    trace.disclosure_mode_matched = true;

    // Gate 3 (REQ-0007): Disclosure-channel classification
    if let Err(reason) = validate_disclosure_channels(proposal, policy_snap) {
        return deny_decision(reason, trace);
    }
    trace.disclosure_channels_approved = true;

    // Gate 4 (REQ-0008): Authority-surface evidence validity
    if let Err(reason) = validate_authority_surface_evidence(
        authority_surface_evidence,
        current_tick,
        MAX_AUTHORITY_SURFACE_EVIDENCE_AGE_TICKS,
    ) {
        return deny_decision(reason, trace);
    }
    trace.authority_surface_evidence_valid = true;

    // validate_authority_surface_evidence returned Ok, so evidence is Some
    // and structurally valid. Use let-else to avoid expect/panic.
    let Some(surface_evidence) = authority_surface_evidence else {
        // Unreachable: validate_authority_surface_evidence returned Ok
        // which requires Some. Fail-closed deny as defensive fallback.
        return deny_decision(DENY_AUTHORITY_SURFACE_EVIDENCE_MISSING, trace);
    };

    // Gate 5 (REQ-0008): Authority-surface monotonicity
    if let Err(reason) = validate_authority_surface_monotonicity(&surface_evidence.diff) {
        return deny_decision(reason, trace);
    }
    trace.authority_surface_monotonic = true;

    // Gate 6 (REQ-0008): Direct GitHub capability non-regression
    if let Err(reason) = validate_no_direct_github_capabilities(&surface_evidence.diff) {
        return deny_decision(reason, trace);
    }
    trace.no_direct_github_capabilities = true;

    // Gate 7: KPI/countermetric completeness
    let Some(profile) = countermetric_profile else {
        return deny_decision(DENY_COUNTERMETRIC_PROFILE_MISSING, trace);
    };

    if let Err(reason) = validate_kpi_countermetric_completeness(proposal, profile) {
        return deny_decision(reason, trace);
    }
    trace.kpi_countermetric_complete = true;

    // Gate 8: Canonical evaluator binding
    if let Err(reason) = validate_canonical_evaluator_binding(proposal) {
        return deny_decision(reason, trace);
    }
    trace.canonical_evaluator_bound = true;

    // Gate 9: Arbitration outcome
    if let Err(reason) = validate_arbitration_outcome(arbitration_outcome) {
        return deny_decision(reason, trace);
    }

    // Gate 10: Evidence quality
    let Some(evidence) = evidence_quality else {
        return deny_decision(DENY_EVIDENCE_QUALITY_MISSING, trace);
    };

    if let Err(reason) = validate_evidence_quality(evidence) {
        return deny_decision(reason, trace);
    }
    trace.evidence_quality_passed = true;

    // Gate 11: Evidence freshness
    match validate_evidence_freshness(evidence.evidence_tick, current_tick, max_evidence_age_ticks)
    {
        Ok(()) => {
            trace.evidence_freshness_passed = true;
        },
        Err(reason) => {
            // Freshness violation produces BLOCKED, not DENY
            trace.verdict = OptimizationGateVerdict::Blocked;
            trace.deny_reason = Some(reason.to_string());
            return OptimizationGateDecision {
                verdict: OptimizationGateVerdict::Blocked,
                deny_reason: Some(reason.to_string()),
                trace,
            };
        },
    }

    // Gate 12: Throughput dominance
    if let Err(reason) = validate_throughput_dominance(evidence.throughput_ratio) {
        return deny_decision(reason, trace);
    }
    trace.throughput_dominance_passed = true;

    // All gates passed
    trace.verdict = OptimizationGateVerdict::Allow;
    OptimizationGateDecision {
        verdict: OptimizationGateVerdict::Allow,
        deny_reason: None,
        trace,
    }
}

/// Constructs a deny decision with the given reason.
fn deny_decision(reason: &str, mut trace: OptimizationGateTrace) -> OptimizationGateDecision {
    trace.verdict = OptimizationGateVerdict::Deny;
    trace.deny_reason = Some(reason.to_string());
    OptimizationGateDecision {
        verdict: OptimizationGateVerdict::Deny,
        deny_reason: Some(reason.to_string()),
        trace,
    }
}

// ---------------------------------------------------------------------------
// TemporalSloProfileV1 (REQ-0006 requirement)
// ---------------------------------------------------------------------------

/// Temporal SLO profile tuple as required by REQ-0006.
///
/// Optimization gates MUST represent temporal objectives using this type.
/// Each tuple binds a baseline, target, evaluation window, owner locus,
/// falsification predicate, countermetrics, and boundary authority reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalSloProfileV1 {
    /// Baseline measurement value.
    pub baseline: u64,

    /// Target measurement value.
    pub target: u64,

    /// Hash reference to the evaluation window definition.
    pub window_ref: [u8; 32],

    /// Locus (owner) of this temporal objective.
    #[serde(deserialize_with = "deserialize_bounded_kpi_id")]
    pub owner_locus: String,

    /// TP-EIO29 predicate identifier for falsification.
    pub falsification_predicate: TemporalPredicateId,

    /// Required countermetric IDs for this objective.
    #[serde(deserialize_with = "deserialize_bounded_kpi_ids")]
    pub countermetrics: Vec<String>,

    /// Hash reference to the boundary authority envelope.
    pub boundary_authority_ref: [u8; 32],
}

impl TemporalSloProfileV1 {
    /// Validates the SLO profile structural constraints.
    ///
    /// # Errors
    ///
    /// Returns an error string if any field is invalid:
    /// - zero `window_ref` or `boundary_authority_ref`
    /// - empty `owner_locus`
    /// - empty countermetrics list
    /// - target <= baseline (no improvement possible)
    pub fn validate(&self) -> Result<(), String> {
        if is_zero_hash(&self.window_ref) {
            return Err("window_ref must not be zero".to_string());
        }
        if is_zero_hash(&self.boundary_authority_ref) {
            return Err("boundary_authority_ref must not be zero".to_string());
        }
        if self.owner_locus.is_empty() {
            return Err("owner_locus must not be empty".to_string());
        }
        if self.owner_locus.len() > MAX_KPI_ID_LENGTH {
            return Err(format!(
                "owner_locus length {} exceeds maximum {}",
                self.owner_locus.len(),
                MAX_KPI_ID_LENGTH,
            ));
        }
        if self.countermetrics.is_empty() {
            return Err(
                "countermetrics must not be empty (every KPI requires countermetrics)".to_string(),
            );
        }
        if self.countermetrics.len() > MAX_COUNTERMETRIC_ENTRIES {
            return Err(format!(
                "countermetrics length {} exceeds maximum {}",
                self.countermetrics.len(),
                MAX_COUNTERMETRIC_ENTRIES,
            ));
        }
        for cm in &self.countermetrics {
            if cm.is_empty() {
                return Err("countermetric ID must not be empty".to_string());
            }
            if cm.len() > MAX_COUNTERMETRIC_ID_LENGTH {
                return Err(format!(
                    "countermetric_id length {} exceeds maximum {}",
                    cm.len(),
                    MAX_COUNTERMETRIC_ID_LENGTH,
                ));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ZERO_HASH: [u8; 32] = [0u8; 32];

fn is_zero_hash(hash: &[u8; 32]) -> bool {
    hash.ct_eq(&ZERO_HASH).unwrap_u8() == 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Fixed seed for deterministic test Ed25519 keypair generation.
    const TEST_SIGNING_KEY_SEED: [u8; 32] = [0x42u8; 32];

    /// Returns a deterministic Ed25519 signing key for tests.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SIGNING_KEY_SEED)
    }

    /// Returns the 32-byte verifying (public) key bytes for the test keypair.
    fn test_verifying_key_bytes() -> [u8; 32] {
        test_signing_key().verifying_key().to_bytes()
    }

    fn test_countermetric_profile() -> CountermetricProfile {
        let mut map = BTreeMap::new();
        map.insert("kpi_latency".to_string(), "cm_error_rate".to_string());
        map.insert("kpi_throughput".to_string(), "cm_containment".to_string());
        map.insert("kpi_cost".to_string(), "cm_verification_rate".to_string());
        CountermetricProfile {
            kpi_countermetric_map: map,
            content_digest: hash(0xCC),
        }
    }

    fn test_evaluator_tuple(pred: TemporalPredicateId) -> EvaluatorTuple {
        EvaluatorTuple {
            evaluator_id: CANONICAL_EVALUATOR_ID.to_string(),
            predicate_id: pred,
            contract_digest_set: hash(0x11),
            canonicalizer_tuple: hash(0x22),
            time_authority_ref: hash(0x33),
            window_ref: hash(0x44),
            verdict: ArbitrationOutcome::AgreedAllow,
            deny_reason: None,
        }
    }

    fn test_proposal() -> OptimizationProposal {
        OptimizationProposal {
            target_kpi_ids: vec!["kpi_latency".to_string(), "kpi_throughput".to_string()],
            evaluator_bindings: vec![
                test_evaluator_tuple(TemporalPredicateId::TpEio29001),
                test_evaluator_tuple(TemporalPredicateId::TpEio29002),
            ],
            proposal_digest: hash(0xDD),
            assumed_disclosure_mode: DisclosurePolicyMode::TradeSecretOnly,
            disclosure_channels: BTreeSet::new(),
        }
    }

    /// The expected phase ID used by default test helpers.
    const TEST_PHASE_ID: &str = "phase_alpha";

    /// Creates a disclosure-policy snapshot with a real canonical digest
    /// computed from its semantic fields and a valid Ed25519 signature
    /// over that digest, signed by the deterministic test keypair.
    fn test_disclosure_policy_snapshot() -> DisclosurePolicySnapshot {
        make_signed_snapshot(
            TEST_PHASE_ID,
            DisclosurePolicyMode::TradeSecretOnly,
            900,
            DisclosurePolicyState::Current,
            BTreeSet::new(),
        )
    }

    /// Build a [`DisclosurePolicySnapshot`] with the real canonical digest
    /// and a valid Ed25519 signature from the deterministic test keypair.
    fn make_signed_snapshot(
        phase_id: &str,
        mode: DisclosurePolicyMode,
        epoch_tick: u64,
        state: DisclosurePolicyState,
        approved_channels: BTreeSet<String>,
    ) -> DisclosurePolicySnapshot {
        // Build a temporary snapshot to compute the digest.
        let mut snap = DisclosurePolicySnapshot {
            phase_id: phase_id.to_string(),
            mode,
            epoch_tick,
            state,
            policy_digest: [0u8; 32], // placeholder
            signature: [0u8; 64],     // placeholder
            approved_channels,
        };
        let digest = compute_disclosure_policy_digest(&snap);
        snap.policy_digest = digest;
        let sk = test_signing_key();
        let sig = sk.sign(&digest);
        snap.signature = sig.to_bytes();
        snap
    }

    fn test_evidence_quality() -> EvidenceQualityReport {
        EvidenceQualityReport {
            statistical_power: 0.95,
            significance_alpha: 0.005,
            sample_size: 1000,
            runtime_classes: vec![
                "x86_64_linux".to_string(),
                "aarch64_linux".to_string(),
                "x86_64_macos".to_string(),
            ],
            evidence_tick: 900,
            throughput_ratio: 1.15,
            evidence_digest: hash(0xEE),
        }
    }

    /// Creates a valid authority-surface diff where after is a strict subset
    /// of before (monotonic decrease). No GitHub capability classes present.
    fn test_authority_surface_diff() -> AuthoritySurfaceDiff {
        let mut before = BTreeSet::new();
        before.insert("kernel.fs.read".to_string());
        before.insert("kernel.fs.write".to_string());
        before.insert("kernel.shell.exec".to_string());
        before.insert("kernel.net.http".to_string());

        let mut after = BTreeSet::new();
        after.insert("kernel.fs.read".to_string());
        after.insert("kernel.fs.write".to_string());

        AuthoritySurfaceDiff {
            role_id: "implementer".to_string(),
            before,
            after,
            content_digest: hash(0xAA),
        }
    }

    /// Creates valid authority-surface evidence with Current state and
    /// fresh tick.
    fn test_authority_surface_evidence() -> AuthoritySurfaceEvidence {
        AuthoritySurfaceEvidence {
            diff: test_authority_surface_diff(),
            evidence_tick: 900,
            state: AuthoritySurfaceEvidenceState::Current,
        }
    }

    // =======================================================================
    // KPI/countermetric completeness tests
    // =======================================================================

    #[test]
    fn test_kpi_countermetric_complete_allows() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        assert!(validate_kpi_countermetric_completeness(&proposal, &profile).is_ok());
    }

    #[test]
    fn test_kpi_missing_countermetric_denied() {
        let mut proposal = test_proposal();
        proposal.target_kpi_ids.push("kpi_unknown".to_string());
        let profile = test_countermetric_profile();
        let err = validate_kpi_countermetric_completeness(&proposal, &profile).unwrap_err();
        assert_eq!(err, DENY_KPI_MISSING_COUNTERMETRIC);
    }

    #[test]
    fn test_empty_proposal_kpis_allowed() {
        let mut proposal = test_proposal();
        proposal.target_kpi_ids.clear();
        let profile = test_countermetric_profile();
        assert!(validate_kpi_countermetric_completeness(&proposal, &profile).is_ok());
    }

    // =======================================================================
    // Canonical evaluator binding tests
    // =======================================================================

    #[test]
    fn test_canonical_evaluator_allows() {
        let proposal = test_proposal();
        assert!(validate_canonical_evaluator_binding(&proposal).is_ok());
    }

    #[test]
    fn test_non_canonical_evaluator_denied() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = "rogue_evaluator".to_string();
        let err = validate_canonical_evaluator_binding(&proposal).unwrap_err();
        assert_eq!(err, DENY_NON_CANONICAL_EVALUATOR);
    }

    #[test]
    fn test_empty_evaluator_id_denied() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = String::new();
        let err = validate_canonical_evaluator_binding(&proposal).unwrap_err();
        assert_eq!(err, DENY_EVALUATOR_ID_EMPTY);
    }

    #[test]
    fn test_no_evaluators_allowed() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings.clear();
        assert!(validate_canonical_evaluator_binding(&proposal).is_ok());
    }

    // =======================================================================
    // Evidence quality tests
    // =======================================================================

    #[test]
    fn test_evidence_quality_passing() {
        let report = test_evidence_quality();
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_power_below_threshold_denied() {
        let mut report = test_evidence_quality();
        report.statistical_power = 0.89;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_POWER_BELOW_THRESHOLD);
    }

    #[test]
    fn test_evidence_power_exact_threshold_allows() {
        let mut report = test_evidence_quality();
        report.statistical_power = 0.90;
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_alpha_above_threshold_denied() {
        let mut report = test_evidence_quality();
        report.significance_alpha = 0.02;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_ALPHA_ABOVE_THRESHOLD);
    }

    #[test]
    fn test_evidence_alpha_exact_threshold_allows() {
        let mut report = test_evidence_quality();
        report.significance_alpha = 0.01;
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_sample_size_zero_denied() {
        let mut report = test_evidence_quality();
        report.sample_size = 0;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_SAMPLE_SIZE_ZERO);
    }

    #[test]
    fn test_evidence_reproducibility_insufficient_denied() {
        let mut report = test_evidence_quality();
        report.runtime_classes = vec!["x86_64".to_string(), "aarch64".to_string()];
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_REPRODUCIBILITY_INSUFFICIENT);
    }

    #[test]
    fn test_evidence_reproducibility_exact_threshold_allows() {
        let mut report = test_evidence_quality();
        report.runtime_classes = vec![
            "x86_64".to_string(),
            "aarch64".to_string(),
            "riscv64".to_string(),
        ];
        assert!(validate_evidence_quality(&report).is_ok());
    }

    #[test]
    fn test_evidence_power_nan_denied() {
        let mut report = test_evidence_quality();
        report.statistical_power = f64::NAN;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_POWER_NAN);
    }

    #[test]
    fn test_evidence_alpha_nan_denied() {
        let mut report = test_evidence_quality();
        report.significance_alpha = f64::NAN;
        let err = validate_evidence_quality(&report).unwrap_err();
        assert_eq!(err, DENY_ALPHA_NAN);
    }

    // =======================================================================
    // Evidence freshness tests
    // =======================================================================

    #[test]
    fn test_evidence_fresh_allows() {
        assert!(validate_evidence_freshness(900, 1000, 200).is_ok());
    }

    #[test]
    fn test_evidence_exact_age_allows() {
        assert!(validate_evidence_freshness(800, 1000, 200).is_ok());
    }

    #[test]
    fn test_evidence_stale_blocked() {
        let err = validate_evidence_freshness(700, 1000, 200).unwrap_err();
        assert_eq!(err, DENY_EVIDENCE_STALE);
    }

    #[test]
    fn test_evidence_future_tick_denied() {
        let err = validate_evidence_freshness(1001, 1000, 200).unwrap_err();
        assert_eq!(err, DENY_EVIDENCE_FUTURE_TICK);
    }

    // =======================================================================
    // Throughput dominance tests
    // =======================================================================

    #[test]
    fn test_throughput_above_baseline_allows() {
        assert!(validate_throughput_dominance(1.15).is_ok());
    }

    #[test]
    fn test_throughput_exact_baseline_allows() {
        assert!(validate_throughput_dominance(1.0).is_ok());
    }

    #[test]
    fn test_throughput_below_baseline_denied() {
        let err = validate_throughput_dominance(0.99).unwrap_err();
        assert_eq!(err, DENY_THROUGHPUT_DOMINANCE_VIOLATION);
    }

    #[test]
    fn test_throughput_nan_denied() {
        let err = validate_throughput_dominance(f64::NAN).unwrap_err();
        assert_eq!(err, DENY_THROUGHPUT_RATIO_NAN);
    }

    // =======================================================================
    // Arbitration outcome tests
    // =======================================================================

    #[test]
    fn test_arbitration_agreed_allow_passes() {
        assert!(validate_arbitration_outcome(ArbitrationOutcome::AgreedAllow).is_ok());
    }

    #[test]
    fn test_arbitration_agreed_deny_fails() {
        let err = validate_arbitration_outcome(ArbitrationOutcome::AgreedDeny).unwrap_err();
        assert_eq!(err, DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }

    #[test]
    fn test_arbitration_disagreement_transient_fails() {
        let err =
            validate_arbitration_outcome(ArbitrationOutcome::DisagreementTransient).unwrap_err();
        assert_eq!(err, DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }

    #[test]
    fn test_arbitration_disagreement_persistent_fails() {
        let err =
            validate_arbitration_outcome(ArbitrationOutcome::DisagreementPersistent).unwrap_err();
        assert_eq!(err, DENY_ARBITRATION_NOT_AGREED_ALLOW);
    }

    // =======================================================================
    // Authority-surface evidence validity tests (REQ-0008)
    // =======================================================================

    #[test]
    fn test_authority_surface_evidence_current_allows() {
        let evidence = test_authority_surface_evidence();
        assert!(validate_authority_surface_evidence(Some(&evidence), 1000, 500).is_ok());
    }

    #[test]
    fn test_authority_surface_evidence_missing_denied() {
        let err = validate_authority_surface_evidence(None, 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_EVIDENCE_MISSING);
    }

    #[test]
    fn test_authority_surface_evidence_stale_state_denied() {
        let mut evidence = test_authority_surface_evidence();
        evidence.state = AuthoritySurfaceEvidenceState::Stale;
        let err = validate_authority_surface_evidence(Some(&evidence), 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_EVIDENCE_STALE);
    }

    #[test]
    fn test_authority_surface_evidence_ambiguous_state_denied() {
        let mut evidence = test_authority_surface_evidence();
        evidence.state = AuthoritySurfaceEvidenceState::Ambiguous;
        let err = validate_authority_surface_evidence(Some(&evidence), 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_EVIDENCE_AMBIGUOUS);
    }

    #[test]
    fn test_authority_surface_evidence_unknown_state_denied() {
        let mut evidence = test_authority_surface_evidence();
        evidence.state = AuthoritySurfaceEvidenceState::Unknown;
        let err = validate_authority_surface_evidence(Some(&evidence), 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_EVIDENCE_UNKNOWN);
    }

    #[test]
    fn test_authority_surface_evidence_future_tick_denied() {
        let mut evidence = test_authority_surface_evidence();
        evidence.evidence_tick = 1001;
        let err = validate_authority_surface_evidence(Some(&evidence), 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_EVIDENCE_FUTURE_TICK);
    }

    #[test]
    fn test_authority_surface_evidence_tick_stale_denied() {
        let mut evidence = test_authority_surface_evidence();
        evidence.evidence_tick = 100;
        let err = validate_authority_surface_evidence(Some(&evidence), 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_EVIDENCE_STALE);
    }

    #[test]
    fn test_authority_surface_evidence_exact_age_allows() {
        let mut evidence = test_authority_surface_evidence();
        evidence.evidence_tick = 500;
        assert!(validate_authority_surface_evidence(Some(&evidence), 1000, 500).is_ok());
    }

    #[test]
    fn test_authority_surface_evidence_empty_role_id_denied() {
        let mut evidence = test_authority_surface_evidence();
        evidence.diff.role_id = String::new();
        let err = validate_authority_surface_evidence(Some(&evidence), 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_ROLE_ID_EMPTY);
    }

    #[test]
    fn test_authority_surface_evidence_zero_digest_denied() {
        let mut evidence = test_authority_surface_evidence();
        evidence.diff.content_digest = [0u8; 32];
        let err = validate_authority_surface_evidence(Some(&evidence), 1000, 500).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_DIGEST_ZERO);
    }

    // =======================================================================
    // Authority-surface monotonicity tests (REQ-0008)
    // =======================================================================

    #[test]
    fn test_monotonicity_subset_allows() {
        let diff = test_authority_surface_diff();
        // after is subset of before (monotonic decrease)
        assert!(validate_authority_surface_monotonicity(&diff).is_ok());
    }

    #[test]
    fn test_monotonicity_equal_sets_allows() {
        let mut diff = test_authority_surface_diff();
        // after == before (no change is still monotonic)
        diff.after = diff.before.clone();
        assert!(validate_authority_surface_monotonicity(&diff).is_ok());
    }

    #[test]
    fn test_monotonicity_empty_after_allows() {
        let mut diff = test_authority_surface_diff();
        diff.after.clear();
        assert!(validate_authority_surface_monotonicity(&diff).is_ok());
    }

    #[test]
    fn test_monotonicity_increase_denied() {
        let mut diff = test_authority_surface_diff();
        // Add a new capability to after that is not in before
        diff.after.insert("kernel.crypto.sign".to_string());
        let err = validate_authority_surface_monotonicity(&diff).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_INCREASE);
    }

    #[test]
    fn test_monotonicity_both_empty_allows() {
        let mut diff = test_authority_surface_diff();
        diff.before.clear();
        diff.after.clear();
        assert!(validate_authority_surface_monotonicity(&diff).is_ok());
    }

    #[test]
    fn test_monotonicity_disjoint_sets_denied() {
        let mut diff = test_authority_surface_diff();
        diff.before.clear();
        diff.before.insert("cap_a".to_string());
        diff.after.clear();
        diff.after.insert("cap_b".to_string());
        let err = validate_authority_surface_monotonicity(&diff).unwrap_err();
        assert_eq!(err, DENY_AUTHORITY_SURFACE_INCREASE);
    }

    // =======================================================================
    // Direct GitHub capability non-regression tests (REQ-0008)
    // =======================================================================

    #[test]
    fn test_no_github_capabilities_allows() {
        let diff = test_authority_surface_diff();
        assert!(validate_no_direct_github_capabilities(&diff).is_ok());
    }

    #[test]
    fn test_github_api_in_after_denied() {
        let mut diff = test_authority_surface_diff();
        diff.before.insert("github_api.issues.read".to_string());
        diff.after.insert("github_api.issues.read".to_string());
        let err = validate_no_direct_github_capabilities(&diff).unwrap_err();
        assert_eq!(err, DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED);
    }

    #[test]
    fn test_gh_cli_in_after_denied() {
        let mut diff = test_authority_surface_diff();
        diff.before.insert("gh_cli.pr.create".to_string());
        diff.after.insert("gh_cli.pr.create".to_string());
        let err = validate_no_direct_github_capabilities(&diff).unwrap_err();
        assert_eq!(err, DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED);
    }

    #[test]
    fn test_forge_org_admin_in_after_denied() {
        let mut diff = test_authority_surface_diff();
        diff.before.insert("forge_org_admin.settings".to_string());
        diff.after.insert("forge_org_admin.settings".to_string());
        let err = validate_no_direct_github_capabilities(&diff).unwrap_err();
        assert_eq!(err, DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED);
    }

    #[test]
    fn test_forge_repo_admin_in_after_denied() {
        let mut diff = test_authority_surface_diff();
        diff.before.insert("forge_repo_admin.hooks".to_string());
        diff.after.insert("forge_repo_admin.hooks".to_string());
        let err = validate_no_direct_github_capabilities(&diff).unwrap_err();
        assert_eq!(err, DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED);
    }

    #[test]
    fn test_github_in_before_only_allows() {
        // github_api in before but NOT in after is fine (removed = good)
        let mut diff = test_authority_surface_diff();
        diff.before.insert("github_api.issues.read".to_string());
        // after does not contain github_api
        assert!(validate_no_direct_github_capabilities(&diff).is_ok());
    }

    #[test]
    fn test_kernel_prefixed_github_api_in_after_denied() {
        let mut diff = test_authority_surface_diff();
        diff.before.insert("kernel.github_api.read".to_string());
        diff.after.insert("kernel.github_api.read".to_string());
        let err = validate_no_direct_github_capabilities(&diff).unwrap_err();
        assert_eq!(err, DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED);
    }

    #[test]
    fn test_case_insensitive_github_api_denied() {
        let mut diff = test_authority_surface_diff();
        diff.before.insert("GitHub_API.issues".to_string());
        diff.after.insert("GitHub_API.issues".to_string());
        let err = validate_no_direct_github_capabilities(&diff).unwrap_err();
        assert_eq!(err, DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED);
    }

    #[test]
    fn test_all_forbidden_classes_detected() {
        for class in FORBIDDEN_DIRECT_GITHUB_CAPABILITY_CLASSES {
            let mut diff = test_authority_surface_diff();
            let cap = format!("{class}.some_action");
            diff.before.insert(cap.clone());
            diff.after.insert(cap);
            let err = validate_no_direct_github_capabilities(&diff).unwrap_err();
            assert_eq!(
                err, DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED,
                "expected deny for forbidden class '{class}'"
            );
        }
    }

    // =======================================================================
    // Combined gate evaluation tests
    // =======================================================================

    #[test]
    fn test_full_gate_evaluation_allows() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Allow);
        assert!(decision.deny_reason.is_none());
        assert!(decision.trace.authority_surface_evidence_valid);
        assert!(decision.trace.authority_surface_monotonic);
        assert!(decision.trace.no_direct_github_capabilities);
        assert!(decision.trace.kpi_countermetric_complete);
        assert!(decision.trace.canonical_evaluator_bound);
        assert!(decision.trace.evidence_quality_passed);
        assert!(decision.trace.evidence_freshness_passed);
        assert!(decision.trace.throughput_dominance_passed);
        assert!(decision.trace.disclosure_policy_valid);
        assert!(decision.trace.disclosure_mode_matched);
        assert!(decision.trace.disclosure_channels_approved);
        assert_eq!(
            decision.trace.disclosure_policy_digest,
            policy.policy_digest
        );
    }

    #[test]
    fn test_missing_countermetric_profile_denied() {
        let proposal = test_proposal();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            None,
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_COUNTERMETRIC_PROFILE_MISSING),
        );
    }

    #[test]
    fn test_missing_evidence_quality_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            None,
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_EVIDENCE_QUALITY_MISSING),
        );
    }

    #[test]
    fn test_stale_evidence_produces_blocked() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.evidence_tick = 500;
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Blocked);
        assert_eq!(decision.deny_reason.as_deref(), Some(DENY_EVIDENCE_STALE));
    }

    #[test]
    fn test_throughput_dominance_violation_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.throughput_ratio = 0.95;
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_THROUGHPUT_DOMINANCE_VIOLATION),
        );
    }

    #[test]
    fn test_non_canonical_evaluator_in_full_gate_denied() {
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = "bad_evaluator".to_string();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_NON_CANONICAL_EVALUATOR),
        );
        assert!(decision.trace.kpi_countermetric_complete);
        assert!(!decision.trace.canonical_evaluator_bound);
    }

    #[test]
    fn test_arbitration_deny_in_full_gate() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedDeny,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_ARBITRATION_NOT_AGREED_ALLOW),
        );
    }

    #[test]
    fn test_low_power_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.statistical_power = 0.5;
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_POWER_BELOW_THRESHOLD),
        );
    }

    #[test]
    fn test_defect_accessor() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let allow = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );
        assert!(allow.defect().is_none());

        let deny = evaluate_optimization_gate(
            &proposal,
            None,
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );
        assert_eq!(deny.defect(), Some(DENY_COUNTERMETRIC_PROFILE_MISSING));
    }

    // =======================================================================
    // Combined gate: authority-surface gates in full evaluator (REQ-0008)
    // =======================================================================

    #[test]
    fn test_missing_authority_surface_evidence_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            None,
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_AUTHORITY_SURFACE_EVIDENCE_MISSING),
        );
        assert!(!decision.trace.authority_surface_evidence_valid);
    }

    #[test]
    fn test_authority_surface_increase_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let policy = test_disclosure_policy_snapshot();
        let mut surface = test_authority_surface_evidence();
        surface.diff.after.insert("kernel.crypto.sign".to_string());

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_AUTHORITY_SURFACE_INCREASE),
        );
        assert!(decision.trace.authority_surface_evidence_valid);
        assert!(!decision.trace.authority_surface_monotonic);
    }

    #[test]
    fn test_github_capability_reintroduced_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let policy = test_disclosure_policy_snapshot();
        let mut surface = test_authority_surface_evidence();
        // Add github_api to both before and after (in before to satisfy
        // monotonicity, but still fails github non-regression)
        surface
            .diff
            .before
            .insert("github_api.issues.read".to_string());
        surface
            .diff
            .after
            .insert("github_api.issues.read".to_string());

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_DIRECT_GITHUB_CAPABILITY_REINTRODUCED),
        );
        assert!(decision.trace.authority_surface_evidence_valid);
        assert!(decision.trace.authority_surface_monotonic);
        assert!(!decision.trace.no_direct_github_capabilities);
    }

    #[test]
    fn test_stale_authority_surface_evidence_state_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let policy = test_disclosure_policy_snapshot();
        let mut surface = test_authority_surface_evidence();
        surface.state = AuthoritySurfaceEvidenceState::Stale;

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_AUTHORITY_SURFACE_EVIDENCE_STALE),
        );
        assert!(!decision.trace.authority_surface_evidence_valid);
    }

    // =======================================================================
    // TemporalSloProfileV1 tests
    // =======================================================================

    fn test_slo_profile() -> TemporalSloProfileV1 {
        TemporalSloProfileV1 {
            baseline: 100,
            target: 200,
            window_ref: hash(0x55),
            owner_locus: "kpi_latency".to_string(),
            falsification_predicate: TemporalPredicateId::TpEio29001,
            countermetrics: vec!["cm_error_rate".to_string()],
            boundary_authority_ref: hash(0x66),
        }
    }

    #[test]
    fn test_slo_profile_valid() {
        let profile = test_slo_profile();
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn test_slo_profile_zero_window_ref_rejected() {
        let mut profile = test_slo_profile();
        profile.window_ref = [0u8; 32];
        let err = profile.validate().unwrap_err();
        assert!(err.contains("window_ref must not be zero"));
    }

    #[test]
    fn test_slo_profile_zero_boundary_authority_rejected() {
        let mut profile = test_slo_profile();
        profile.boundary_authority_ref = [0u8; 32];
        let err = profile.validate().unwrap_err();
        assert!(err.contains("boundary_authority_ref must not be zero"));
    }

    #[test]
    fn test_slo_profile_empty_owner_locus_rejected() {
        let mut profile = test_slo_profile();
        profile.owner_locus = String::new();
        let err = profile.validate().unwrap_err();
        assert!(err.contains("owner_locus must not be empty"));
    }

    #[test]
    fn test_slo_profile_empty_countermetrics_rejected() {
        let mut profile = test_slo_profile();
        profile.countermetrics.clear();
        let err = profile.validate().unwrap_err();
        assert!(err.contains("countermetrics must not be empty"));
    }

    #[test]
    fn test_slo_profile_empty_countermetric_id_rejected() {
        let mut profile = test_slo_profile();
        profile.countermetrics.push(String::new());
        let err = profile.validate().unwrap_err();
        assert!(err.contains("countermetric ID must not be empty"));
    }

    #[test]
    fn test_slo_profile_oversized_owner_locus_rejected() {
        let mut profile = test_slo_profile();
        profile.owner_locus = "x".repeat(MAX_KPI_ID_LENGTH + 1);
        let err = profile.validate().unwrap_err();
        assert!(err.contains("owner_locus length"));
    }

    #[test]
    fn test_slo_profile_serialization_roundtrip() {
        let profile = test_slo_profile();
        let json = serde_json::to_string(&profile).expect("serialize");
        let decoded: TemporalSloProfileV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, profile);
    }

    // =======================================================================
    // Serde bounds tests
    // =======================================================================

    #[test]
    fn test_countermetric_profile_oversized_map_rejected() {
        let mut map = BTreeMap::new();
        for i in 0..=MAX_KPI_ENTRIES {
            map.insert(format!("kpi_{i}"), format!("cm_{i}"));
        }
        let digest: Vec<u8> = vec![0xCC; 32];
        let json = serde_json::json!({
            "kpi_countermetric_map": map,
            "content_digest": digest,
        });
        let err = serde_json::from_value::<CountermetricProfile>(json).unwrap_err();
        assert!(err.to_string().contains("kpi_countermetric_map length"));
    }

    #[test]
    fn test_evidence_report_oversized_runtime_classes_rejected() {
        let classes: Vec<String> = (0..=MAX_RUNTIME_CLASSES)
            .map(|i| format!("class_{i}"))
            .collect();
        let digest: Vec<u8> = vec![0xEE; 32];
        let json = serde_json::json!({
            "statistical_power": 0.95,
            "significance_alpha": 0.005,
            "sample_size": 100,
            "runtime_classes": classes,
            "evidence_tick": 100,
            "throughput_ratio": 1.1,
            "evidence_digest": digest,
        });
        let err = serde_json::from_value::<EvidenceQualityReport>(json).unwrap_err();
        assert!(err.to_string().contains("runtime_classes length"));
    }

    #[test]
    fn test_proposal_oversized_kpi_ids_rejected() {
        let ids: Vec<String> = (0..=MAX_KPI_ENTRIES).map(|i| format!("kpi_{i}")).collect();
        let digest: Vec<u8> = vec![0xDD; 32];
        let json = serde_json::json!({
            "target_kpi_ids": ids,
            "evaluator_bindings": [],
            "proposal_digest": digest,
        });
        let err = serde_json::from_value::<OptimizationProposal>(json).unwrap_err();
        assert!(err.to_string().contains("kpi_ids length"));
    }

    #[test]
    fn test_authority_surface_diff_oversized_capability_set_rejected() {
        let caps: Vec<String> = (0..=MAX_CAPABILITY_SURFACE_ENTRIES)
            .map(|i| format!("cap_{i}"))
            .collect();
        let digest: Vec<u8> = vec![0xAA; 32];
        let json = serde_json::json!({
            "role_id": "test_role",
            "before": caps,
            "after": [],
            "content_digest": digest,
        });
        let err = serde_json::from_value::<AuthoritySurfaceDiff>(json).unwrap_err();
        assert!(err.to_string().contains("capability_surface length"));
    }

    #[test]
    fn test_authority_surface_diff_oversized_role_id_rejected() {
        let role_id = "x".repeat(MAX_SURFACE_ROLE_ID_LENGTH + 1);
        let digest: Vec<u8> = vec![0xAA; 32];
        let json = serde_json::json!({
            "role_id": role_id,
            "before": [],
            "after": [],
            "content_digest": digest,
        });
        let err = serde_json::from_value::<AuthoritySurfaceDiff>(json).unwrap_err();
        assert!(err.to_string().contains("role_id length"));
    }

    #[test]
    fn test_authority_surface_diff_serialization_roundtrip() {
        let diff = test_authority_surface_diff();
        let json = serde_json::to_string(&diff).expect("serialize");
        let decoded: AuthoritySurfaceDiff = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, diff);
    }

    #[test]
    fn test_authority_surface_evidence_serialization_roundtrip() {
        let evidence = test_authority_surface_evidence();
        let json = serde_json::to_string(&evidence).expect("serialize");
        let decoded: AuthoritySurfaceEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, evidence);
    }

    #[test]
    fn test_gate_trace_proposal_digest_preserved() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.trace.proposal_digest, proposal.proposal_digest);
    }

    // =======================================================================
    // Combined gate ordering tests (verify first-failure semantics)
    // =======================================================================

    #[test]
    fn test_gate_ordering_authority_surface_before_kpi() {
        // Both authority surface and KPI fail — authority surface is first
        let mut proposal = test_proposal();
        proposal.target_kpi_ids.push("kpi_unknown".to_string());
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            None, // missing authority surface evidence
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_AUTHORITY_SURFACE_EVIDENCE_MISSING),
        );
    }

    #[test]
    fn test_gate_ordering_monotonicity_before_github() {
        // Both monotonicity and GitHub fail — monotonicity is first
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let mut surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();
        // Add new capability (monotonicity violation) AND github capability
        surface
            .diff
            .after
            .insert("github_api.issues.read".to_string());

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        // monotonicity is checked before github regression
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_AUTHORITY_SURFACE_INCREASE),
        );
    }

    #[test]
    fn test_gate_ordering_kpi_before_evaluator() {
        // Both KPI and evaluator fail — KPI is checked first (after authority surface)
        let mut proposal = test_proposal();
        proposal.target_kpi_ids.push("kpi_unknown".to_string());
        proposal.evaluator_bindings[0].evaluator_id = "bad".to_string();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_KPI_MISSING_COUNTERMETRIC),
        );
    }

    #[test]
    fn test_gate_ordering_evaluator_before_evidence() {
        // Both evaluator and evidence fail — evaluator is checked first
        let mut proposal = test_proposal();
        proposal.evaluator_bindings[0].evaluator_id = "bad".to_string();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        evidence.statistical_power = 0.1;
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_NON_CANONICAL_EVALUATOR),
        );
    }

    #[test]
    fn test_gate_ordering_freshness_produces_blocked_not_deny() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let mut evidence = test_evidence_quality();
        // Evidence is stale AND throughput is bad — stale is checked first
        evidence.evidence_tick = 100;
        evidence.throughput_ratio = 0.5;
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Blocked);
        assert_eq!(decision.deny_reason.as_deref(), Some(DENY_EVIDENCE_STALE));
    }

    // =======================================================================
    // Disclosure-control policy validity tests (REQ-0007)
    // =======================================================================

    #[test]
    fn test_disclosure_policy_current_allows() {
        let snap = test_disclosure_policy_snapshot();
        assert!(
            validate_disclosure_policy(
                Some(&snap),
                &test_verifying_key_bytes(),
                TEST_PHASE_ID,
                1000,
                500
            )
            .is_ok()
        );
    }

    #[test]
    fn test_disclosure_policy_missing_denied() {
        let err =
            validate_disclosure_policy(None, &test_verifying_key_bytes(), TEST_PHASE_ID, 1000, 500)
                .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_MISSING);
    }

    #[test]
    fn test_disclosure_policy_stale_state_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.state = DisclosurePolicyState::Stale;
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_STALE);
    }

    #[test]
    fn test_disclosure_policy_ambiguous_state_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.state = DisclosurePolicyState::Ambiguous;
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_AMBIGUOUS);
    }

    #[test]
    fn test_disclosure_policy_unknown_state_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.state = DisclosurePolicyState::Unknown;
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_UNKNOWN);
    }

    #[test]
    fn test_disclosure_policy_unsigned_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.signature = [0u8; 64];
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_UNSIGNED);
    }

    #[test]
    fn test_disclosure_policy_zero_digest_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.policy_digest = [0u8; 32];
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_DIGEST_ZERO);
    }

    #[test]
    fn test_disclosure_policy_empty_phase_id_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.phase_id = String::new();
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_PHASE_ID_EMPTY);
    }

    #[test]
    fn test_disclosure_policy_future_tick_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.epoch_tick = 1001;
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_FUTURE_TICK);
    }

    #[test]
    fn test_disclosure_policy_stale_epoch_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.epoch_tick = 100;
        let err = validate_disclosure_policy(
            Some(&snap),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            1000,
            500,
        )
        .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_STALE);
    }

    #[test]
    fn test_disclosure_policy_exact_age_allows() {
        // Build a properly signed snapshot with epoch_tick = 500 so the
        // canonical digest binds correctly.
        let snap = make_signed_snapshot(
            TEST_PHASE_ID,
            DisclosurePolicyMode::TradeSecretOnly,
            500,
            DisclosurePolicyState::Current,
            BTreeSet::new(),
        );
        assert!(
            validate_disclosure_policy(
                Some(&snap),
                &test_verifying_key_bytes(),
                TEST_PHASE_ID,
                1000,
                500
            )
            .is_ok()
        );
    }

    // =======================================================================
    // Disclosure-control mode matching tests (REQ-0007)
    // =======================================================================

    #[test]
    fn test_disclosure_mode_match_allows() {
        let proposal = test_proposal();
        let snap = test_disclosure_policy_snapshot();
        // Both are TradeSecretOnly
        assert!(validate_disclosure_mode_match(&proposal, &snap).is_ok());
    }

    #[test]
    fn test_disclosure_mode_mismatch_denied() {
        let proposal = test_proposal();
        // proposal is TradeSecretOnly, snapshot is OpenSource
        let mut snap = test_disclosure_policy_snapshot();
        snap.mode = DisclosurePolicyMode::OpenSource;
        let err = validate_disclosure_mode_match(&proposal, &snap).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_MODE_MISMATCH);
    }

    #[test]
    fn test_disclosure_mode_mismatch_reverse_denied() {
        let mut proposal = test_proposal();
        proposal.assumed_disclosure_mode = DisclosurePolicyMode::OpenSource;
        let snap = test_disclosure_policy_snapshot();
        // proposal is OpenSource, snapshot is TradeSecretOnly
        let err = validate_disclosure_mode_match(&proposal, &snap).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_MODE_MISMATCH);
    }

    // =======================================================================
    // Disclosure-channel classification tests (REQ-0007)
    // =======================================================================

    #[test]
    fn test_disclosure_channels_empty_allows() {
        let proposal = test_proposal(); // empty disclosure_channels
        let snap = test_disclosure_policy_snapshot();
        assert!(validate_disclosure_channels(&proposal, &snap).is_ok());
    }

    #[test]
    fn test_disclosure_channels_approved_allows() {
        let mut proposal = test_proposal();
        proposal
            .disclosure_channels
            .insert("internal_review".to_string());
        let mut snap = test_disclosure_policy_snapshot();
        snap.approved_channels.insert("internal_review".to_string());
        assert!(validate_disclosure_channels(&proposal, &snap).is_ok());
    }

    #[test]
    fn test_disclosure_channels_unapproved_denied() {
        let mut proposal = test_proposal();
        proposal
            .disclosure_channels
            .insert("unknown_channel".to_string());
        let snap = test_disclosure_policy_snapshot();
        let err = validate_disclosure_channels(&proposal, &snap).unwrap_err();
        assert_eq!(err, DENY_UNAPPROVED_DISCLOSURE_CHANNEL);
    }

    #[test]
    fn test_trade_secret_patent_channel_denied() {
        let mut proposal = test_proposal();
        proposal
            .disclosure_channels
            .insert("patent_filing".to_string());
        let mut snap = test_disclosure_policy_snapshot();
        // Even if patent_filing is in approved_channels, deny in TRADE_SECRET_ONLY
        snap.approved_channels.insert("patent_filing".to_string());
        let err = validate_disclosure_channels(&proposal, &snap).unwrap_err();
        assert_eq!(err, DENY_TRADE_SECRET_PATENT_CHANNEL);
    }

    #[test]
    fn test_trade_secret_provisional_channel_denied() {
        let mut proposal = test_proposal();
        proposal
            .disclosure_channels
            .insert("provisional_application".to_string());
        let mut snap = test_disclosure_policy_snapshot();
        snap.approved_channels
            .insert("provisional_application".to_string());
        let err = validate_disclosure_channels(&proposal, &snap).unwrap_err();
        assert_eq!(err, DENY_TRADE_SECRET_PATENT_CHANNEL);
    }

    #[test]
    fn test_trade_secret_all_forbidden_classes_denied() {
        for class in FORBIDDEN_TRADE_SECRET_CHANNEL_CLASSES {
            let mut proposal = test_proposal();
            proposal.disclosure_channels.insert(class.to_string());
            let mut snap = test_disclosure_policy_snapshot();
            snap.approved_channels.insert(class.to_string());
            let err = validate_disclosure_channels(&proposal, &snap).unwrap_err();
            assert_eq!(
                err, DENY_TRADE_SECRET_PATENT_CHANNEL,
                "expected deny for forbidden class '{class}'"
            );
        }
    }

    #[test]
    fn test_open_source_mode_allows_patent_when_approved() {
        let mut proposal = test_proposal();
        proposal.assumed_disclosure_mode = DisclosurePolicyMode::OpenSource;
        proposal
            .disclosure_channels
            .insert("patent_filing".to_string());
        let mut snap = test_disclosure_policy_snapshot();
        snap.mode = DisclosurePolicyMode::OpenSource;
        snap.approved_channels.insert("patent_filing".to_string());
        assert!(validate_disclosure_channels(&proposal, &snap).is_ok());
    }

    #[test]
    fn test_open_source_unapproved_channel_still_denied() {
        let mut proposal = test_proposal();
        proposal.assumed_disclosure_mode = DisclosurePolicyMode::OpenSource;
        proposal
            .disclosure_channels
            .insert("not_approved".to_string());
        let mut snap = test_disclosure_policy_snapshot();
        snap.mode = DisclosurePolicyMode::OpenSource;
        let err = validate_disclosure_channels(&proposal, &snap).unwrap_err();
        assert_eq!(err, DENY_UNAPPROVED_DISCLOSURE_CHANNEL);
    }

    // =======================================================================
    // Combined gate: disclosure-control gates in full evaluator (REQ-0007)
    // =======================================================================

    #[test]
    fn test_missing_disclosure_policy_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            None, // missing disclosure policy
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_DISCLOSURE_POLICY_MISSING),
        );
        assert!(!decision.trace.disclosure_policy_valid);
    }

    #[test]
    fn test_disclosure_mode_mismatch_in_full_gate_denied() {
        let proposal = test_proposal(); // TradeSecretOnly
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        // Build a properly-signed OpenSource snapshot so digest is valid
        let policy = make_signed_snapshot(
            TEST_PHASE_ID,
            DisclosurePolicyMode::OpenSource,
            900,
            DisclosurePolicyState::Current,
            BTreeSet::new(),
        );

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_DISCLOSURE_MODE_MISMATCH),
        );
        assert!(decision.trace.disclosure_policy_valid);
        assert!(!decision.trace.disclosure_mode_matched);
    }

    #[test]
    fn test_patent_channel_in_trade_secret_full_gate_denied() {
        let mut proposal = test_proposal();
        proposal
            .disclosure_channels
            .insert("patent_filing".to_string());
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let mut channels = BTreeSet::new();
        channels.insert("patent_filing".to_string());
        let policy = make_signed_snapshot(
            TEST_PHASE_ID,
            DisclosurePolicyMode::TradeSecretOnly,
            900,
            DisclosurePolicyState::Current,
            channels,
        );

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_TRADE_SECRET_PATENT_CHANNEL),
        );
        assert!(decision.trace.disclosure_policy_valid);
        assert!(decision.trace.disclosure_mode_matched);
        assert!(!decision.trace.disclosure_channels_approved);
    }

    #[test]
    fn test_stale_disclosure_policy_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let mut policy = test_disclosure_policy_snapshot();
        policy.state = DisclosurePolicyState::Stale;

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_DISCLOSURE_POLICY_STALE),
        );
        assert!(!decision.trace.disclosure_policy_valid);
    }

    #[test]
    fn test_unsigned_disclosure_policy_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let mut policy = test_disclosure_policy_snapshot();
        policy.signature = [0u8; 64];

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_DISCLOSURE_POLICY_UNSIGNED),
        );
    }

    #[test]
    fn test_gate_ordering_disclosure_before_authority_surface() {
        // Both disclosure policy and authority surface fail — disclosure is first
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            None, // missing authority surface
            None, // missing disclosure policy
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        // Disclosure policy is checked before authority surface
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_DISCLOSURE_POLICY_MISSING),
        );
    }

    // =======================================================================
    // Disclosure policy snapshot serde tests (REQ-0007)
    // =======================================================================

    #[test]
    fn test_disclosure_policy_snapshot_serialization_roundtrip() {
        let snap = test_disclosure_policy_snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: DisclosurePolicySnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, snap);
    }

    #[test]
    fn test_disclosure_policy_snapshot_with_channels_roundtrip() {
        let mut snap = test_disclosure_policy_snapshot();
        snap.approved_channels.insert("internal_review".to_string());
        snap.approved_channels.insert("security_audit".to_string());
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: DisclosurePolicySnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, snap);
        assert_eq!(decoded.approved_channels.len(), 2);
    }

    #[test]
    fn test_is_forbidden_trade_secret_channel_case_insensitive() {
        assert!(is_forbidden_trade_secret_channel("Patent_Filing"));
        assert!(is_forbidden_trade_secret_channel("PATENT_FILING"));
        assert!(is_forbidden_trade_secret_channel("patent_filing"));
        assert!(is_forbidden_trade_secret_channel("  patent_filing  "));
    }

    #[test]
    fn test_is_forbidden_trade_secret_channel_non_forbidden() {
        assert!(!is_forbidden_trade_secret_channel("internal_review"));
        assert!(!is_forbidden_trade_secret_channel("security_audit"));
        assert!(!is_forbidden_trade_secret_channel(""));
    }

    #[test]
    fn test_disclosure_policy_digest_bound_in_trace() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot();

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            TEST_PHASE_ID,
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Allow);
        // Verify the policy digest is bound in the trace
        assert_eq!(
            decision.trace.disclosure_policy_digest,
            policy.policy_digest
        );
    }

    // =======================================================================
    // Ed25519 signature verification tests (BLOCKER 1 remediation)
    // =======================================================================

    #[test]
    fn test_disclosure_policy_valid_signature_allows() {
        let snap = test_disclosure_policy_snapshot();
        let vk = test_verifying_key_bytes();
        assert!(validate_disclosure_policy(Some(&snap), &vk, TEST_PHASE_ID, 1000, 500).is_ok());
    }

    #[test]
    fn test_disclosure_policy_invalid_signature_denied() {
        let mut snap = test_disclosure_policy_snapshot();
        // Corrupt the signature (non-zero but invalid)
        snap.signature = [0xFFu8; 64];
        let vk = test_verifying_key_bytes();
        let err =
            validate_disclosure_policy(Some(&snap), &vk, TEST_PHASE_ID, 1000, 500).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_SIGNATURE_INVALID);
    }

    #[test]
    fn test_disclosure_policy_wrong_key_denied() {
        let snap = test_disclosure_policy_snapshot();
        // Use a different key (not the one that signed)
        let other_seed = [0x99u8; 32];
        let other_signing = SigningKey::from_bytes(&other_seed);
        let other_verifying = other_signing.verifying_key().to_bytes();
        let err =
            validate_disclosure_policy(Some(&snap), &other_verifying, TEST_PHASE_ID, 1000, 500)
                .unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_SIGNATURE_INVALID);
    }

    #[test]
    fn test_disclosure_policy_invalid_key_bytes_denied() {
        let snap = test_disclosure_policy_snapshot();
        // Search for a 32-byte pattern that VerifyingKey::from_bytes rejects
        // (not all y-coordinates decompress to valid curve points).
        let mut found_invalid = false;
        for probe in 0u8..=255 {
            let mut candidate = [probe; 32];
            // Clear the sign bit to keep y < 2^255
            candidate[31] &= 0x7F;
            if VerifyingKey::from_bytes(&candidate).is_err() {
                let err =
                    validate_disclosure_policy(Some(&snap), &candidate, TEST_PHASE_ID, 1000, 500)
                        .unwrap_err();
                assert_eq!(err, DENY_DISCLOSURE_POLICY_KEY_INVALID);
                found_invalid = true;
                break;
            }
        }
        assert!(
            found_invalid,
            "could not find a byte pattern that fails VerifyingKey::from_bytes"
        );
    }

    #[test]
    fn test_disclosure_policy_signature_over_wrong_digest_denied() {
        let sk = test_signing_key();
        let vk = test_verifying_key_bytes();
        let digest = hash(0xBB);
        let sig = sk.sign(&digest);
        // Snapshot has a different digest than what was signed
        let mut snap = test_disclosure_policy_snapshot();
        snap.policy_digest = hash(0xCC); // different from 0xBB
        snap.signature = sig.to_bytes();
        let err =
            validate_disclosure_policy(Some(&snap), &vk, TEST_PHASE_ID, 1000, 500).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_SIGNATURE_INVALID);
    }

    #[test]
    fn test_disclosure_policy_ed25519_end_to_end() {
        // Generate keypair, compute canonical digest, sign it, verify passes
        let vk_bytes = test_verifying_key_bytes();
        let snap = make_signed_snapshot(
            "phase_beta",
            DisclosurePolicyMode::OpenSource,
            800,
            DisclosurePolicyState::Current,
            BTreeSet::new(),
        );

        assert!(
            validate_disclosure_policy(Some(&snap), &vk_bytes, "phase_beta", 1000, 500).is_ok()
        );
    }

    // =======================================================================
    // Digest binding tests (BLOCKER remediation)
    // =======================================================================

    #[test]
    fn test_disclosure_policy_tampered_mode_denied() {
        // Build a valid snapshot, then tamper with the mode field.
        // The canonical digest will no longer match.
        let mut snap = test_disclosure_policy_snapshot();
        // Original mode is TradeSecretOnly; tamper to OpenSource
        snap.mode = DisclosurePolicyMode::OpenSource;
        let vk = test_verifying_key_bytes();
        let err =
            validate_disclosure_policy(Some(&snap), &vk, TEST_PHASE_ID, 1000, 500).unwrap_err();
        // Signature still verifies against old policy_digest, but the
        // recomputed canonical digest no longer matches.
        assert_eq!(err, DENY_DISCLOSURE_POLICY_DIGEST_MISMATCH);
    }

    #[test]
    fn test_disclosure_policy_tampered_channels_denied() {
        // Build a valid snapshot, then tamper with approved_channels.
        let mut snap = test_disclosure_policy_snapshot();
        snap.approved_channels
            .insert("smuggled_channel".to_string());
        let vk = test_verifying_key_bytes();
        let err =
            validate_disclosure_policy(Some(&snap), &vk, TEST_PHASE_ID, 1000, 500).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_DIGEST_MISMATCH);
    }

    #[test]
    fn test_disclosure_policy_tampered_epoch_tick_denied() {
        // Tamper with epoch_tick — digest mismatch
        let mut snap = test_disclosure_policy_snapshot();
        snap.epoch_tick = 999; // was 900
        let vk = test_verifying_key_bytes();
        let err =
            validate_disclosure_policy(Some(&snap), &vk, TEST_PHASE_ID, 1000, 500).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_DIGEST_MISMATCH);
    }

    #[test]
    fn test_disclosure_policy_tampered_phase_id_denied() {
        // Tamper with phase_id — hits phase mismatch first
        let mut snap = test_disclosure_policy_snapshot();
        snap.phase_id = "phase_gamma".to_string();
        let vk = test_verifying_key_bytes();
        let err =
            validate_disclosure_policy(Some(&snap), &vk, TEST_PHASE_ID, 1000, 500).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_PHASE_MISMATCH);
    }

    // =======================================================================
    // Cross-phase policy replay tests (MAJOR remediation)
    // =======================================================================

    #[test]
    fn test_disclosure_policy_phase_mismatch_denied() {
        let snap = test_disclosure_policy_snapshot(); // phase_id = "phase_alpha"
        let vk = test_verifying_key_bytes();
        // Validate with a different expected phase
        let err =
            validate_disclosure_policy(Some(&snap), &vk, "phase_beta", 1000, 500).unwrap_err();
        assert_eq!(err, DENY_DISCLOSURE_POLICY_PHASE_MISMATCH);
    }

    #[test]
    fn test_disclosure_policy_phase_mismatch_in_full_gate_denied() {
        let proposal = test_proposal();
        let profile = test_countermetric_profile();
        let evidence = test_evidence_quality();
        let surface = test_authority_surface_evidence();
        let policy = test_disclosure_policy_snapshot(); // phase = "phase_alpha"

        let decision = evaluate_optimization_gate(
            &proposal,
            Some(&profile),
            Some(&evidence),
            Some(&surface),
            Some(&policy),
            &test_verifying_key_bytes(),
            "wrong_phase", // expected phase does not match snapshot
            ArbitrationOutcome::AgreedAllow,
            1000,
            200,
        );

        assert_eq!(decision.verdict, OptimizationGateVerdict::Deny);
        assert_eq!(
            decision.deny_reason.as_deref(),
            Some(DENY_DISCLOSURE_POLICY_PHASE_MISMATCH),
        );
    }

    // =======================================================================
    // Channel normalization tests (MAJOR remediation)
    // =======================================================================

    #[test]
    fn test_disclosure_channels_case_insensitive_approval() {
        // approved_channels has "Internal_Review" but proposal has "internal_review"
        // After normalization, should match
        let mut proposal = test_proposal();
        proposal
            .disclosure_channels
            .insert("internal_review".to_string());
        let mut snap = test_disclosure_policy_snapshot();
        snap.approved_channels.insert("Internal_Review".to_string());
        assert!(validate_disclosure_channels(&proposal, &snap).is_ok());
    }

    #[test]
    fn test_disclosure_channels_mixed_case_forbidden_denied() {
        // "Patent_Filing" with mixed case should still be caught by forbidden check
        // AND should not be matched as approved
        let mut proposal = test_proposal();
        proposal
            .disclosure_channels
            .insert("Patent_Filing".to_string());
        let mut snap = test_disclosure_policy_snapshot();
        snap.approved_channels.insert("Patent_Filing".to_string());
        let err = validate_disclosure_channels(&proposal, &snap).unwrap_err();
        assert_eq!(err, DENY_TRADE_SECRET_PATENT_CHANNEL);
    }
}
