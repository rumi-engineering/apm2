//! FAC launch projection contracts for auditor/orchestrator consumers.
//!
//! These contracts provide digest-first envelopes so consumers can verify
//! replay consistency independently from daemon-local process memory.

use serde::{Deserialize, Serialize};

use crate::determinism::canonicalize_json;

/// Errors returned while producing digest-first projection envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionContractError {
    /// JSON serialization failed.
    Serialization {
        /// Serialization error detail.
        message: String,
    },
    /// Canonicalization failed.
    Canonicalization {
        /// Canonicalization error detail.
        message: String,
    },
}

impl std::fmt::Display for ProjectionContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization { message } => {
                write!(f, "projection serialization failed: {message}")
            },
            Self::Canonicalization { message } => {
                write!(f, "projection canonicalization failed: {message}")
            },
        }
    }
}

impl std::error::Error for ProjectionContractError {}

/// Fail-closed uncertainty taxonomy for launch projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionUncertainty {
    /// Required lineage evidence is missing or malformed.
    MissingLineageEvidence,
    /// Required boundary-conformance evidence is missing or malformed.
    BoundaryConformanceUnverifiable,
    /// Liveness evidence is missing or malformed.
    MissingLivenessEvidence,
    /// No authoritative receipt tick is available.
    MissingAuthoritativeReceiptTick,
}

/// Auditor-facing projection for launch lineage and boundary conformance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditorLaunchProjectionV1 {
    /// Total number of authoritative receipt events considered.
    pub authoritative_receipt_count: u32,
    /// Number of receipts with complete lineage fields.
    pub complete_lineage_receipt_count: u32,
    /// Number of receipts passing boundary-conformance checks.
    pub boundary_conformant_receipt_count: u32,
    /// True when all authoritative receipts have complete lineage evidence.
    pub lineage_complete: bool,
    /// True when all authoritative receipts satisfy boundary conformance.
    pub boundary_conformant: bool,
    /// Fail-closed uncertainty flags.
    pub uncertainty_flags: Vec<ProjectionUncertainty>,
    /// Authoritative admissibility verdict. False on any uncertainty.
    pub admissible: bool,
}

impl AuditorLaunchProjectionV1 {
    /// Creates a normalized auditor projection.
    #[must_use]
    pub fn new(
        authoritative_receipt_count: u32,
        complete_lineage_receipt_count: u32,
        boundary_conformant_receipt_count: u32,
        lineage_complete: bool,
        boundary_conformant: bool,
        mut uncertainty_flags: Vec<ProjectionUncertainty>,
    ) -> Self {
        normalize_uncertainty_flags(&mut uncertainty_flags);
        let admissible = uncertainty_flags.is_empty() && lineage_complete && boundary_conformant;

        Self {
            authoritative_receipt_count,
            complete_lineage_receipt_count,
            boundary_conformant_receipt_count,
            lineage_complete,
            boundary_conformant,
            uncertainty_flags,
            admissible,
        }
    }
}

/// Orchestrator-facing projection for launch liveness and receipt progression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestratorLaunchProjectionV1 {
    /// Number of currently active runs.
    pub active_runs: u32,
    /// Most recent authoritative receipt tick when available.
    pub last_authoritative_receipt_tick: Option<u64>,
    /// Aggregate restart count from authoritative lifecycle evidence.
    pub restart_count: u32,
    /// Fail-closed uncertainty flags.
    pub uncertainty_flags: Vec<ProjectionUncertainty>,
    /// Authoritative admissibility verdict. False on any uncertainty.
    pub admissible: bool,
}

impl OrchestratorLaunchProjectionV1 {
    /// Creates a normalized orchestrator projection.
    #[must_use]
    pub fn new(
        active_runs: u32,
        last_authoritative_receipt_tick: Option<u64>,
        restart_count: u32,
        mut uncertainty_flags: Vec<ProjectionUncertainty>,
    ) -> Self {
        normalize_uncertainty_flags(&mut uncertainty_flags);
        let admissible = uncertainty_flags.is_empty();

        Self {
            active_runs,
            last_authoritative_receipt_tick,
            restart_count,
            uncertainty_flags,
            admissible,
        }
    }
}

/// Digest-first envelope for canonical projection bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionDigestEnvelopeV1 {
    /// BLAKE3 digest of `canonical_projection_json`.
    pub projection_digest: [u8; 32],
    /// Canonical JSON bytes of the projection payload.
    #[serde(with = "serde_bytes")]
    pub canonical_projection_json: Vec<u8>,
}

/// Produces JCS-canonical projection bytes.
///
/// # Errors
///
/// Returns [`ProjectionContractError`] when serialization/canonicalization
/// fails.
pub fn canonical_projection_json<T: Serialize>(
    projection: &T,
) -> Result<Vec<u8>, ProjectionContractError> {
    let projection_json = serde_json::to_string(projection).map_err(|error| {
        ProjectionContractError::Serialization {
            message: error.to_string(),
        }
    })?;
    let canonical_json = canonicalize_json(&projection_json).map_err(|error| {
        ProjectionContractError::Canonicalization {
            message: error.to_string(),
        }
    })?;

    Ok(canonical_json.into_bytes())
}

/// Computes the projection digest from canonical projection bytes.
#[must_use]
pub fn compute_projection_digest(canonical_projection_json: &[u8]) -> [u8; 32] {
    *blake3::hash(canonical_projection_json).as_bytes()
}

/// Produces a digest-first envelope for a projection payload.
///
/// # Errors
///
/// Returns [`ProjectionContractError`] when serialization/canonicalization
/// fails.
pub fn digest_first_projection<T: Serialize>(
    projection: &T,
) -> Result<ProjectionDigestEnvelopeV1, ProjectionContractError> {
    let canonical_projection_json = canonical_projection_json(projection)?;
    let projection_digest = compute_projection_digest(&canonical_projection_json);
    Ok(ProjectionDigestEnvelopeV1 {
        projection_digest,
        canonical_projection_json,
    })
}

fn normalize_uncertainty_flags(flags: &mut Vec<ProjectionUncertainty>) {
    flags.sort_unstable();
    flags.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_first_projection_is_deterministic() {
        let projection = AuditorLaunchProjectionV1::new(2, 2, 2, true, true, Vec::new());

        let first = digest_first_projection(&projection).expect("envelope should be generated");
        let second = digest_first_projection(&projection).expect("envelope should be generated");

        assert_eq!(first, second, "digest-first output must be deterministic");
    }

    #[test]
    fn projection_digest_changes_when_payload_changes() {
        let projection_a = OrchestratorLaunchProjectionV1::new(1, Some(7), 0, Vec::new());
        let projection_b = OrchestratorLaunchProjectionV1::new(2, Some(7), 0, Vec::new());

        let envelope_a =
            digest_first_projection(&projection_a).expect("envelope A should be generated");
        let envelope_b =
            digest_first_projection(&projection_b).expect("envelope B should be generated");

        assert_ne!(
            envelope_a.projection_digest, envelope_b.projection_digest,
            "digest must change when projection fields change"
        );
    }

    #[test]
    fn auditor_projection_is_fail_closed_on_uncertainty() {
        let projection = AuditorLaunchProjectionV1::new(
            0,
            0,
            0,
            false,
            false,
            vec![ProjectionUncertainty::MissingLineageEvidence],
        );
        assert!(
            !projection.admissible,
            "uncertain projections must be non-admissible"
        );
    }

    #[test]
    fn orchestrator_projection_dedups_uncertainty_flags() {
        let projection = OrchestratorLaunchProjectionV1::new(
            0,
            None,
            0,
            vec![
                ProjectionUncertainty::MissingLivenessEvidence,
                ProjectionUncertainty::MissingLivenessEvidence,
                ProjectionUncertainty::MissingAuthoritativeReceiptTick,
            ],
        );

        assert_eq!(
            projection.uncertainty_flags,
            vec![
                ProjectionUncertainty::MissingLivenessEvidence,
                ProjectionUncertainty::MissingAuthoritativeReceiptTick
            ],
            "projection constructor must normalize uncertainty flags"
        );
    }
}
