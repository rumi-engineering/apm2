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

    /// Bootstrap schema artifacts (immutable trust root).
    BootstrapSchema,

    /// FAC work context entry evidence (RFC-0032).
    ///
    /// Anchors the serialized `WorkContextEntry` CAS schema describing the
    /// execution context for a unit of work (ticket bindings, dependency
    /// graph, scope constraints).
    WorkContextEntry,

    /// FAC work authority bindings evidence (RFC-0032).
    ///
    /// Anchors the serialized `WorkAuthorityBindings` CAS schema describing
    /// the authority chain and delegation bindings attached to a work unit
    /// (custody, responsibility domains, PCAC policy references).
    WorkAuthorityBindings,

    /// FAC work loop profile evidence (RFC-0032).
    ///
    /// Anchors the serialized `WorkLoopProfile` CAS schema describing the
    /// execution loop telemetry for a work unit (iteration counts, gate
    /// pass/fail history, resource consumption envelope).
    WorkLoopProfile,
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
            "BOOTSTRAP_SCHEMA" => Ok(Self::BootstrapSchema),
            "WORK_CONTEXT_ENTRY" => Ok(Self::WorkContextEntry),
            "WORK_AUTHORITY_BINDINGS" => Ok(Self::WorkAuthorityBindings),
            "WORK_LOOP_PROFILE" => Ok(Self::WorkLoopProfile),
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
            Self::BootstrapSchema => "BOOTSTRAP_SCHEMA",
            Self::WorkContextEntry => "WORK_CONTEXT_ENTRY",
            Self::WorkAuthorityBindings => "WORK_AUTHORITY_BINDINGS",
            Self::WorkLoopProfile => "WORK_LOOP_PROFILE",
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
            Self::BootstrapSchema,
            Self::WorkContextEntry,
            Self::WorkAuthorityBindings,
            Self::WorkLoopProfile,
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
            | Self::DeploymentRecords
            | Self::BootstrapSchema
            | Self::WorkContextEntry
            | Self::WorkAuthorityBindings
            | Self::WorkLoopProfile => false,
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
        assert_eq!(
            EvidenceCategory::parse("BOOTSTRAP_SCHEMA").unwrap(),
            EvidenceCategory::BootstrapSchema
        );
        assert_eq!(
            EvidenceCategory::parse("bootstrap_schema").unwrap(),
            EvidenceCategory::BootstrapSchema
        );
        assert_eq!(
            EvidenceCategory::parse("WORK_CONTEXT_ENTRY").unwrap(),
            EvidenceCategory::WorkContextEntry
        );
        assert_eq!(
            EvidenceCategory::parse("work_context_entry").unwrap(),
            EvidenceCategory::WorkContextEntry
        );
        assert_eq!(
            EvidenceCategory::parse("WORK_AUTHORITY_BINDINGS").unwrap(),
            EvidenceCategory::WorkAuthorityBindings
        );
        assert_eq!(
            EvidenceCategory::parse("work_authority_bindings").unwrap(),
            EvidenceCategory::WorkAuthorityBindings
        );
        assert_eq!(
            EvidenceCategory::parse("WORK_LOOP_PROFILE").unwrap(),
            EvidenceCategory::WorkLoopProfile
        );
        assert_eq!(
            EvidenceCategory::parse("work_loop_profile").unwrap(),
            EvidenceCategory::WorkLoopProfile
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
        assert_eq!(
            EvidenceCategory::BootstrapSchema.as_str(),
            "BOOTSTRAP_SCHEMA"
        );
        assert_eq!(
            EvidenceCategory::WorkContextEntry.as_str(),
            "WORK_CONTEXT_ENTRY"
        );
        assert_eq!(
            EvidenceCategory::WorkAuthorityBindings.as_str(),
            "WORK_AUTHORITY_BINDINGS"
        );
        assert_eq!(
            EvidenceCategory::WorkLoopProfile.as_str(),
            "WORK_LOOP_PROFILE"
        );
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", EvidenceCategory::TestResults), "TEST_RESULTS");
    }

    #[test]
    fn test_category_all() {
        let all = EvidenceCategory::all();
        assert_eq!(all.len(), 14);
        assert!(all.contains(&EvidenceCategory::TestResults));
        assert!(all.contains(&EvidenceCategory::LintReports));
        assert!(all.contains(&EvidenceCategory::DeploymentRecords));
        assert!(all.contains(&EvidenceCategory::BootstrapSchema));
        assert!(all.contains(&EvidenceCategory::WorkContextEntry));
        assert!(all.contains(&EvidenceCategory::WorkAuthorityBindings));
        assert!(all.contains(&EvidenceCategory::WorkLoopProfile));
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
        assert!(!EvidenceCategory::BootstrapSchema.requires_verification());
        assert!(!EvidenceCategory::WorkContextEntry.requires_verification());
        assert!(!EvidenceCategory::WorkAuthorityBindings.requires_verification());
        assert!(!EvidenceCategory::WorkLoopProfile.requires_verification());
    }

    #[test]
    fn test_category_roundtrip() {
        for category in EvidenceCategory::all() {
            let s = category.as_str();
            let parsed = EvidenceCategory::parse(s).unwrap();
            assert_eq!(*category, parsed);
        }
    }

    /// RFC-0032 Phase 1: round-trip stability for FAC evidence anchor
    /// categories.
    ///
    /// Verifies that each new category:
    /// 1. Survives `as_str()` -> `parse()` round-trip with exact token
    ///    equality.
    /// 2. Survives case-insensitive `parse()` from lowercase form.
    /// 3. Has a stable canonical string that does not change across
    ///    serialization/deserialization (serde round-trip via JSON).
    #[test]
    fn test_rfc0032_fac_category_roundtrip_stability() {
        let fac_categories = [
            (EvidenceCategory::WorkContextEntry, "WORK_CONTEXT_ENTRY"),
            (
                EvidenceCategory::WorkAuthorityBindings,
                "WORK_AUTHORITY_BINDINGS",
            ),
            (EvidenceCategory::WorkLoopProfile, "WORK_LOOP_PROFILE"),
        ];

        for (variant, expected_str) in fac_categories {
            // as_str() produces the expected canonical token
            assert_eq!(
                variant.as_str(),
                expected_str,
                "as_str() mismatch for {variant:?}"
            );

            // parse(canonical) round-trips exactly
            let parsed =
                EvidenceCategory::parse(expected_str).expect("parse canonical should succeed");
            assert_eq!(parsed, variant, "parse(canonical) mismatch for {variant:?}");

            // parse(lowercase) round-trips via case-insensitive path
            let lower = expected_str.to_lowercase();
            let parsed_lower =
                EvidenceCategory::parse(&lower).expect("parse lowercase should succeed");
            assert_eq!(
                parsed_lower, variant,
                "parse(lowercase) mismatch for {variant:?}"
            );

            // Display uses the canonical string
            assert_eq!(
                format!("{variant}"),
                expected_str,
                "Display mismatch for {variant:?}"
            );

            // Serde JSON round-trip stability
            let json =
                serde_json::to_string(&variant).expect("serde_json::to_string should succeed");
            let deserialized: EvidenceCategory =
                serde_json::from_str(&json).expect("serde_json::from_str should succeed");
            assert_eq!(
                deserialized, variant,
                "serde JSON round-trip mismatch for {variant:?}"
            );
        }
    }

    /// Verify that existing category canonical strings have not changed
    /// (backwards compatibility).
    #[test]
    fn test_existing_category_strings_unchanged() {
        let expected = [
            (EvidenceCategory::TestResults, "TEST_RESULTS"),
            (EvidenceCategory::LintReports, "LINT_REPORTS"),
            (EvidenceCategory::BuildArtifacts, "BUILD_ARTIFACTS"),
            (EvidenceCategory::SecurityScans, "SECURITY_SCANS"),
            (EvidenceCategory::ReviewRecords, "REVIEW_RECORDS"),
            (EvidenceCategory::AuditLogs, "AUDIT_LOGS"),
            (EvidenceCategory::ConfigSnapshots, "CONFIG_SNAPSHOTS"),
            (EvidenceCategory::Documentation, "DOCUMENTATION"),
            (EvidenceCategory::Benchmarks, "BENCHMARKS"),
            (EvidenceCategory::DeploymentRecords, "DEPLOYMENT_RECORDS"),
            (EvidenceCategory::BootstrapSchema, "BOOTSTRAP_SCHEMA"),
        ];

        for (variant, expected_str) in expected {
            assert_eq!(
                variant.as_str(),
                expected_str,
                "existing category string changed for {variant:?}"
            );
        }
    }
}
