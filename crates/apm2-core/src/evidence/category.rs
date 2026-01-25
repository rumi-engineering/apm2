//! Evidence category classification.
//!
//! Categories organize evidence artifacts by their purpose and verification
//! requirements. Each category maps to specific evidence artifact types
//! defined in the PRD.

use serde::{Deserialize, Serialize};

use super::error::EvidenceError;

/// Category classification for evidence artifacts.
///
/// Categories determine how artifacts are organized, indexed, and verified.
/// Each category corresponds to evidence artifact types in the PRD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EvidenceCategory {
    /// Test execution results and coverage reports.
    TestResults,

    /// Lint reports and static analysis outputs.
    LintReports,

    /// Build artifacts and compilation outputs.
    BuildArtifacts,

    /// Security scan results and vulnerability reports.
    SecurityScans,

    /// Code review records and approval signatures.
    ReviewRecords,

    /// Audit logs and compliance records.
    AuditLogs,

    /// Configuration snapshots and environment captures.
    ConfigSnapshots,

    /// Documentation artifacts and generated docs.
    Documentation,

    /// Benchmark results and performance metrics.
    Benchmarks,

    /// Deployment records and release artifacts.
    DeploymentRecords,
}

impl std::fmt::Display for EvidenceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl EvidenceCategory {
    /// Parses an evidence category from a string.
    ///
    /// Accepts both `SCREAMING_SNAKE_CASE` (canonical) and `snake_case`
    /// formats.
    ///
    /// # Errors
    ///
    /// Returns `EvidenceError::InvalidCategory` if the string is not a
    /// recognized category.
    pub fn parse(s: &str) -> Result<Self, EvidenceError> {
        match s.to_uppercase().as_str() {
            "TEST_RESULTS" => Ok(Self::TestResults),
            "LINT_REPORTS" => Ok(Self::LintReports),
            "BUILD_ARTIFACTS" => Ok(Self::BuildArtifacts),
            "SECURITY_SCANS" => Ok(Self::SecurityScans),
            "REVIEW_RECORDS" => Ok(Self::ReviewRecords),
            "AUDIT_LOGS" => Ok(Self::AuditLogs),
            "CONFIG_SNAPSHOTS" => Ok(Self::ConfigSnapshots),
            "DOCUMENTATION" => Ok(Self::Documentation),
            "BENCHMARKS" => Ok(Self::Benchmarks),
            "DEPLOYMENT_RECORDS" => Ok(Self::DeploymentRecords),
            _ => Err(EvidenceError::InvalidCategory {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the canonical string representation of this category.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TestResults => "TEST_RESULTS",
            Self::LintReports => "LINT_REPORTS",
            Self::BuildArtifacts => "BUILD_ARTIFACTS",
            Self::SecurityScans => "SECURITY_SCANS",
            Self::ReviewRecords => "REVIEW_RECORDS",
            Self::AuditLogs => "AUDIT_LOGS",
            Self::ConfigSnapshots => "CONFIG_SNAPSHOTS",
            Self::Documentation => "DOCUMENTATION",
            Self::Benchmarks => "BENCHMARKS",
            Self::DeploymentRecords => "DEPLOYMENT_RECORDS",
        }
    }

    /// Returns all known categories.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::TestResults,
            Self::LintReports,
            Self::BuildArtifacts,
            Self::SecurityScans,
            Self::ReviewRecords,
            Self::AuditLogs,
            Self::ConfigSnapshots,
            Self::Documentation,
            Self::Benchmarks,
            Self::DeploymentRecords,
        ]
    }

    /// Returns whether this category typically requires verification commands.
    #[must_use]
    pub const fn requires_verification(&self) -> bool {
        match self {
            Self::TestResults
            | Self::LintReports
            | Self::SecurityScans
            | Self::BuildArtifacts
            | Self::Benchmarks => true,
            Self::ReviewRecords
            | Self::AuditLogs
            | Self::ConfigSnapshots
            | Self::Documentation
            | Self::DeploymentRecords => false,
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_category_parse() {
        assert_eq!(
            EvidenceCategory::parse("TEST_RESULTS").unwrap(),
            EvidenceCategory::TestResults
        );
        assert_eq!(
            EvidenceCategory::parse("test_results").unwrap(),
            EvidenceCategory::TestResults
        );
        assert_eq!(
            EvidenceCategory::parse("LINT_REPORTS").unwrap(),
            EvidenceCategory::LintReports
        );
        assert_eq!(
            EvidenceCategory::parse("BUILD_ARTIFACTS").unwrap(),
            EvidenceCategory::BuildArtifacts
        );
        assert_eq!(
            EvidenceCategory::parse("SECURITY_SCANS").unwrap(),
            EvidenceCategory::SecurityScans
        );
        assert_eq!(
            EvidenceCategory::parse("REVIEW_RECORDS").unwrap(),
            EvidenceCategory::ReviewRecords
        );
        assert_eq!(
            EvidenceCategory::parse("AUDIT_LOGS").unwrap(),
            EvidenceCategory::AuditLogs
        );
        assert_eq!(
            EvidenceCategory::parse("CONFIG_SNAPSHOTS").unwrap(),
            EvidenceCategory::ConfigSnapshots
        );
        assert_eq!(
            EvidenceCategory::parse("DOCUMENTATION").unwrap(),
            EvidenceCategory::Documentation
        );
        assert_eq!(
            EvidenceCategory::parse("BENCHMARKS").unwrap(),
            EvidenceCategory::Benchmarks
        );
        assert_eq!(
            EvidenceCategory::parse("DEPLOYMENT_RECORDS").unwrap(),
            EvidenceCategory::DeploymentRecords
        );
    }

    #[test]
    fn test_category_parse_unknown_fails() {
        let result = EvidenceCategory::parse("UNKNOWN");
        assert!(matches!(result, Err(EvidenceError::InvalidCategory { .. })));

        let result = EvidenceCategory::parse("");
        assert!(matches!(result, Err(EvidenceError::InvalidCategory { .. })));

        let result = EvidenceCategory::parse("garbage");
        assert!(matches!(result, Err(EvidenceError::InvalidCategory { .. })));
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(EvidenceCategory::TestResults.as_str(), "TEST_RESULTS");
        assert_eq!(EvidenceCategory::LintReports.as_str(), "LINT_REPORTS");
        assert_eq!(EvidenceCategory::BuildArtifacts.as_str(), "BUILD_ARTIFACTS");
        assert_eq!(EvidenceCategory::SecurityScans.as_str(), "SECURITY_SCANS");
        assert_eq!(EvidenceCategory::ReviewRecords.as_str(), "REVIEW_RECORDS");
        assert_eq!(EvidenceCategory::AuditLogs.as_str(), "AUDIT_LOGS");
        assert_eq!(
            EvidenceCategory::ConfigSnapshots.as_str(),
            "CONFIG_SNAPSHOTS"
        );
        assert_eq!(EvidenceCategory::Documentation.as_str(), "DOCUMENTATION");
        assert_eq!(EvidenceCategory::Benchmarks.as_str(), "BENCHMARKS");
        assert_eq!(
            EvidenceCategory::DeploymentRecords.as_str(),
            "DEPLOYMENT_RECORDS"
        );
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", EvidenceCategory::TestResults), "TEST_RESULTS");
    }

    #[test]
    fn test_category_all() {
        let all = EvidenceCategory::all();
        assert_eq!(all.len(), 10);
        assert!(all.contains(&EvidenceCategory::TestResults));
        assert!(all.contains(&EvidenceCategory::LintReports));
        assert!(all.contains(&EvidenceCategory::DeploymentRecords));
    }

    #[test]
    fn test_category_requires_verification() {
        assert!(EvidenceCategory::TestResults.requires_verification());
        assert!(EvidenceCategory::LintReports.requires_verification());
        assert!(EvidenceCategory::SecurityScans.requires_verification());
        assert!(EvidenceCategory::BuildArtifacts.requires_verification());
        assert!(EvidenceCategory::Benchmarks.requires_verification());

        assert!(!EvidenceCategory::ReviewRecords.requires_verification());
        assert!(!EvidenceCategory::AuditLogs.requires_verification());
        assert!(!EvidenceCategory::ConfigSnapshots.requires_verification());
        assert!(!EvidenceCategory::Documentation.requires_verification());
        assert!(!EvidenceCategory::DeploymentRecords.requires_verification());
    }

    #[test]
    fn test_category_roundtrip() {
        for category in EvidenceCategory::all() {
            let s = category.as_str();
            let parsed = EvidenceCategory::parse(s).unwrap();
            assert_eq!(*category, parsed);
        }
    }
}
