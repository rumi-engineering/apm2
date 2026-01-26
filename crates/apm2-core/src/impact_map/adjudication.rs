//! Adjudication logic for duplication risk detection and net-new
//! classification.
//!
//! This module analyzes mapped requirements to:
//! - Detect duplication risks when multiple extension points could satisfy a
//!   requirement
//! - Classify unmapped requirements as "net-new substrate"
//! - Generate warnings and recommendations for human review
//!
//! # Adjudication Philosophy
//!
//! Adjudication produces warnings, not errors. The impact map is intended to
//! inform human decision-making, not to block progress. Requirements flagged
//! for review should be examined by an architect before RFC emission.
//!
//! # Severity Levels
//!
//! - **High**: Multiple high-confidence extension points with similar fit
//!   scores
//! - **Medium**: Multiple medium-confidence candidates with potential overlap
//! - **Low**: Minor ambiguity that should be documented but is likely
//!   resolvable

use serde::{Deserialize, Serialize};

use super::mapper::{FitScore, MappedRequirement};

/// Severity level for duplication risks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DuplicationSeverity {
    /// High severity: multiple high-confidence extension points.
    High,
    /// Medium severity: potential overlap between candidates.
    Medium,
    /// Low severity: minor ambiguity.
    Low,
}

/// A duplication risk identified during adjudication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicationRisk {
    /// Requirement ID with the duplication risk.
    pub requirement_id: String,
    /// Severity of the duplication risk.
    pub severity: DuplicationSeverity,
    /// IDs of competing extension points.
    pub competing_extension_points: Vec<String>,
    /// IDs of competing components.
    pub competing_components: Vec<String>,
    /// Rationale for the duplication risk.
    pub rationale: String,
    /// Recommendation for resolution.
    pub recommendation: String,
}

/// Classification for requirements without strong component matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetNewClassification {
    /// Requirement ID classified as net-new.
    pub requirement_id: String,
    /// Requirement title.
    pub requirement_title: String,
    /// Reason for net-new classification.
    pub reason: String,
    /// Suggested approach for implementation.
    pub suggested_approach: String,
}

/// Result of adjudication analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjudicationResult {
    /// Duplication risks identified.
    pub duplication_risks: Vec<DuplicationRisk>,
    /// Requirements classified as net-new substrate.
    pub net_new_requirements: Vec<NetNewClassification>,
    /// Total requirements analyzed.
    pub total_requirements: usize,
    /// Requirements with high-confidence matches.
    pub high_confidence_count: usize,
    /// Requirements needing review.
    pub needs_review_count: usize,
}

/// Analyzes mapped requirements for duplication risks and net-new
/// classification.
///
/// # Arguments
///
/// * `mappings` - The mapped requirements to analyze
///
/// # Returns
///
/// An `AdjudicationResult` containing identified risks and classifications.
#[must_use]
pub fn adjudicate_mappings(mappings: &[MappedRequirement]) -> AdjudicationResult {
    let mut duplication_risks = Vec::new();
    let mut net_new_requirements = Vec::new();
    let mut high_confidence_count = 0;
    let mut needs_review_count = 0;

    for mapping in mappings {
        // Check for high-confidence matches
        let has_high_confidence = mapping
            .candidates
            .iter()
            .any(|c| c.fit_score == FitScore::High);

        if has_high_confidence {
            high_confidence_count += 1;
        }

        if mapping.needs_review {
            needs_review_count += 1;
        }

        // Check for duplication risks
        if let Some(risk) = detect_duplication_risk(mapping) {
            duplication_risks.push(risk);
        }

        // Check for net-new classification
        if let Some(classification) = classify_as_net_new(mapping) {
            net_new_requirements.push(classification);
        }
    }

    // Sort for determinism
    duplication_risks.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));
    net_new_requirements.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));

    AdjudicationResult {
        duplication_risks,
        net_new_requirements,
        total_requirements: mappings.len(),
        high_confidence_count,
        needs_review_count,
    }
}

/// Detects duplication risks for a single mapped requirement.
fn detect_duplication_risk(mapping: &MappedRequirement) -> Option<DuplicationRisk> {
    // Count candidates by fit score
    let high_count = mapping
        .candidates
        .iter()
        .filter(|c| c.fit_score == FitScore::High)
        .count();
    let medium_count = mapping
        .candidates
        .iter()
        .filter(|c| c.fit_score == FitScore::Medium)
        .count();

    // Collect extension points from high/medium candidates
    let extension_points: Vec<String> = mapping
        .candidates
        .iter()
        .filter(|c| c.fit_score == FitScore::High || c.fit_score == FitScore::Medium)
        .filter_map(|c| c.extension_point_id.clone())
        .collect();

    let unique_extension_points: std::collections::HashSet<_> = extension_points.iter().collect();

    // Collect competing components
    let competing_components: Vec<String> = mapping
        .candidates
        .iter()
        .filter(|c| c.fit_score == FitScore::High || c.fit_score == FitScore::Medium)
        .map(|c| c.component_id.clone())
        .collect();

    let unique_components: std::collections::HashSet<_> = competing_components.iter().collect();

    // High severity: multiple high-confidence extension points
    if high_count >= 2 && unique_extension_points.len() >= 2 {
        return Some(DuplicationRisk {
            requirement_id: mapping.requirement_id.clone(),
            severity: DuplicationSeverity::High,
            competing_extension_points: unique_extension_points
                .iter()
                .map(|s| (*s).clone())
                .collect(),
            competing_components: unique_components.iter().map(|s| (*s).clone()).collect(),
            rationale: format!(
                "Multiple high-confidence extension points ({high_count}) could satisfy this requirement"
            ),
            recommendation: "Review requirement scope and select the most appropriate extension point. \
                Consider whether the requirement should be split into multiple smaller requirements."
                .to_string(),
        });
    }

    // Medium severity: multiple medium-confidence candidates across different
    // components
    if medium_count >= 2 && unique_components.len() >= 2 {
        return Some(DuplicationRisk {
            requirement_id: mapping.requirement_id.clone(),
            severity: DuplicationSeverity::Medium,
            competing_extension_points: unique_extension_points
                .iter()
                .map(|s| (*s).clone())
                .collect(),
            competing_components: unique_components.iter().map(|s| (*s).clone()).collect(),
            rationale: format!(
                "Multiple components ({}) could potentially satisfy this requirement",
                unique_components.len()
            ),
            recommendation: "Clarify requirement boundaries and determine primary ownership. \
                Document the decision in the RFC."
                .to_string(),
        });
    }

    // Low severity: high confidence match but also medium candidates in other
    // components
    if high_count == 1 && medium_count >= 1 && unique_components.len() >= 2 {
        return Some(DuplicationRisk {
            requirement_id: mapping.requirement_id.clone(),
            severity: DuplicationSeverity::Low,
            competing_extension_points: unique_extension_points
                .iter()
                .map(|s| (*s).clone())
                .collect(),
            competing_components: unique_components.iter().map(|s| (*s).clone()).collect(),
            rationale: "Primary match identified but alternative components exist".to_string(),
            recommendation: "Document why the primary match was chosen over alternatives."
                .to_string(),
        });
    }

    None
}

/// Classifies a requirement as net-new if it has no strong matches.
fn classify_as_net_new(mapping: &MappedRequirement) -> Option<NetNewClassification> {
    // No candidates at all
    if mapping.candidates.is_empty() {
        return Some(NetNewClassification {
            requirement_id: mapping.requirement_id.clone(),
            requirement_title: mapping.requirement_title.clone(),
            reason: "No matching components found in CCP index".to_string(),
            suggested_approach: "This requirement needs a new module. \
                Create a justification in the RFC's design decisions section."
                .to_string(),
        });
    }

    // Only low-confidence matches
    let has_high_or_medium = mapping
        .candidates
        .iter()
        .any(|c| c.fit_score == FitScore::High || c.fit_score == FitScore::Medium);

    if !has_high_or_medium {
        return Some(NetNewClassification {
            requirement_id: mapping.requirement_id.clone(),
            requirement_title: mapping.requirement_title.clone(),
            reason: "Only low-confidence matches found (similarity < 0.4)".to_string(),
            suggested_approach: "Consider whether this requirement extends existing functionality \
                or needs new infrastructure. Document the decision with rationale."
                .to_string(),
        });
    }

    None
}

#[cfg(test)]
pub mod tests {
    use super::super::mapper::{CandidateComponent, FitScore, MappedRequirement};
    use super::*;

    /// Creates a test mapped requirement with specified candidates.
    fn create_test_mapping(
        id: &str,
        candidates: Vec<(FitScore, &str, Option<&str>)>,
    ) -> MappedRequirement {
        let candidates: Vec<CandidateComponent> = candidates
            .into_iter()
            .map(|(score, comp_id, ext_id)| CandidateComponent {
                component_id: comp_id.to_string(),
                component_name: format!("{comp_id}-name"),
                fit_score: score,
                rationale: "Test rationale".to_string(),
                extension_point_id: ext_id.map(String::from),
                similarity_score: match score {
                    FitScore::High => 0.7,
                    FitScore::Medium => 0.5,
                    FitScore::Low => 0.35,
                },
            })
            .collect();

        let needs_review =
            candidates.is_empty() || !candidates.iter().any(|c| c.fit_score == FitScore::High);

        MappedRequirement {
            requirement_id: id.to_string(),
            requirement_title: format!("Test requirement {id}"),
            requirement_statement: "Test statement".to_string(),
            candidates,
            needs_review,
        }
    }

    /// UT-114-03: Test duplication risk detection - high severity.
    #[test]
    fn test_detect_duplication_high_severity() {
        let mapping = create_test_mapping(
            "REQ-0001",
            vec![
                (FitScore::High, "COMP-A", Some("EXT-A-001")),
                (FitScore::High, "COMP-B", Some("EXT-B-001")),
            ],
        );

        let risk = detect_duplication_risk(&mapping);
        assert!(risk.is_some());
        let risk = risk.unwrap();
        assert_eq!(risk.severity, DuplicationSeverity::High);
        assert_eq!(risk.competing_components.len(), 2);
    }

    /// UT-114-03: Test duplication risk detection - medium severity.
    #[test]
    fn test_detect_duplication_medium_severity() {
        let mapping = create_test_mapping(
            "REQ-0001",
            vec![
                (FitScore::Medium, "COMP-A", Some("EXT-A-001")),
                (FitScore::Medium, "COMP-B", Some("EXT-B-001")),
            ],
        );

        let risk = detect_duplication_risk(&mapping);
        assert!(risk.is_some());
        let risk = risk.unwrap();
        assert_eq!(risk.severity, DuplicationSeverity::Medium);
    }

    /// UT-114-03: Test duplication risk detection - low severity.
    #[test]
    fn test_detect_duplication_low_severity() {
        let mapping = create_test_mapping(
            "REQ-0001",
            vec![
                (FitScore::High, "COMP-A", Some("EXT-A-001")),
                (FitScore::Medium, "COMP-B", Some("EXT-B-001")),
            ],
        );

        let risk = detect_duplication_risk(&mapping);
        assert!(risk.is_some());
        let risk = risk.unwrap();
        assert_eq!(risk.severity, DuplicationSeverity::Low);
    }

    /// UT-114-03: Test no duplication risk for single match.
    #[test]
    fn test_no_duplication_single_match() {
        let mapping = create_test_mapping(
            "REQ-0001",
            vec![(FitScore::High, "COMP-A", Some("EXT-A-001"))],
        );

        let risk = detect_duplication_risk(&mapping);
        assert!(risk.is_none());
    }

    /// UT-114-03: Test net-new classification - no candidates.
    #[test]
    fn test_net_new_no_candidates() {
        let mapping = create_test_mapping("REQ-0001", vec![]);

        let classification = classify_as_net_new(&mapping);
        assert!(classification.is_some());
        let classification = classification.unwrap();
        assert!(classification.reason.contains("No matching components"));
    }

    /// UT-114-03: Test net-new classification - only low confidence.
    #[test]
    fn test_net_new_low_confidence_only() {
        let mapping = create_test_mapping(
            "REQ-0001",
            vec![
                (FitScore::Low, "COMP-A", None),
                (FitScore::Low, "COMP-B", None),
            ],
        );

        let classification = classify_as_net_new(&mapping);
        assert!(classification.is_some());
        let classification = classification.unwrap();
        assert!(classification.reason.contains("low-confidence"));
    }

    /// UT-114-03: Test no net-new classification for good match.
    #[test]
    fn test_no_net_new_good_match() {
        let mapping = create_test_mapping(
            "REQ-0001",
            vec![(FitScore::High, "COMP-A", Some("EXT-A-001"))],
        );

        let classification = classify_as_net_new(&mapping);
        assert!(classification.is_none());
    }

    /// UT-114-03: Test full adjudication.
    #[test]
    fn test_full_adjudication() {
        let mappings = vec![
            // Good match
            create_test_mapping(
                "REQ-0001",
                vec![(FitScore::High, "COMP-A", Some("EXT-A-001"))],
            ),
            // Duplication risk
            create_test_mapping(
                "REQ-0002",
                vec![
                    (FitScore::High, "COMP-A", Some("EXT-A-001")),
                    (FitScore::High, "COMP-B", Some("EXT-B-001")),
                ],
            ),
            // Net-new
            create_test_mapping("REQ-0003", vec![]),
        ];

        let result = adjudicate_mappings(&mappings);

        assert_eq!(result.total_requirements, 3);
        assert_eq!(result.high_confidence_count, 2); // REQ-0001 and REQ-0002
        assert_eq!(result.needs_review_count, 1); // REQ-0003 (no candidates)
        assert_eq!(result.duplication_risks.len(), 1);
        assert_eq!(result.net_new_requirements.len(), 1);
    }

    /// Test adjudication result sorting for determinism.
    #[test]
    fn test_adjudication_sorting() {
        let mappings = vec![
            create_test_mapping("REQ-0003", vec![]),
            create_test_mapping("REQ-0001", vec![]),
            create_test_mapping("REQ-0002", vec![]),
        ];

        let result = adjudicate_mappings(&mappings);

        // Net-new requirements should be sorted by ID
        assert_eq!(result.net_new_requirements[0].requirement_id, "REQ-0001");
        assert_eq!(result.net_new_requirements[1].requirement_id, "REQ-0002");
        assert_eq!(result.net_new_requirements[2].requirement_id, "REQ-0003");
    }
}
