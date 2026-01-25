//! Data classification for evidence artifacts.
//!
//! All evidence artifacts must be classified according to their sensitivity.
//! Classification determines:
//! - Access control policies
//! - Retention requirements
//! - Redaction rules
//! - Progressive disclosure behavior

use serde::{Deserialize, Serialize};

use super::error::EvidenceError;

/// Data classification levels for evidence artifacts.
///
/// Classification levels follow industry-standard data governance practices
/// and determine how artifacts are handled, stored, and disclosed.
///
/// # Ordering
///
/// Classifications are ordered from least to most sensitive:
/// `Public < Internal < Confidential < Restricted`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DataClassification {
    /// Public data with no access restrictions.
    ///
    /// Examples: Open source code, public documentation, non-sensitive
    /// configuration.
    Public       = 0,

    /// Internal data for organization use only.
    ///
    /// Examples: Internal documentation, non-sensitive logs, test results
    /// without credentials.
    Internal     = 1,

    /// Confidential data requiring access controls.
    ///
    /// Examples: Source code, internal APIs, business logic, detailed
    /// error messages.
    Confidential = 2,

    /// Restricted data with strict access controls.
    ///
    /// Examples: Credentials, API keys, PII, security audit findings,
    /// cryptographic keys.
    Restricted   = 3,
}

impl std::fmt::Display for DataClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl DataClassification {
    /// Parses a data classification from a string.
    ///
    /// # Errors
    ///
    /// Returns `EvidenceError::InvalidClassification` if the string is not a
    /// recognized classification.
    pub fn parse(s: &str) -> Result<Self, EvidenceError> {
        match s.to_uppercase().as_str() {
            "PUBLIC" => Ok(Self::Public),
            "INTERNAL" => Ok(Self::Internal),
            "CONFIDENTIAL" => Ok(Self::Confidential),
            "RESTRICTED" => Ok(Self::Restricted),
            _ => Err(EvidenceError::InvalidClassification {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the canonical string representation of this classification.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::Restricted => "RESTRICTED",
        }
    }

    /// Returns whether this classification requires progressive disclosure.
    ///
    /// Progressive disclosure means only the hash is shared by default;
    /// content must be explicitly requested.
    #[must_use]
    pub const fn requires_progressive_disclosure(&self) -> bool {
        matches!(self, Self::Confidential | Self::Restricted)
    }

    /// Returns whether this classification requires redaction in logs.
    #[must_use]
    pub const fn requires_log_redaction(&self) -> bool {
        matches!(self, Self::Restricted)
    }

    /// Returns the default retention period in days.
    ///
    /// More sensitive data typically has shorter retention to minimize
    /// exposure risk.
    #[must_use]
    pub const fn default_retention_days(&self) -> u32 {
        match self {
            Self::Public => 365 * 7,   // 7 years
            Self::Internal => 365 * 3, // 3 years
            Self::Confidential => 365, // 1 year
            Self::Restricted => 90,    // 90 days
        }
    }

    /// Checks if this classification can be downgraded to a lower level.
    ///
    /// Downgrading (e.g., Restricted -> Internal) requires explicit
    /// authorization and is generally not allowed automatically.
    #[must_use]
    pub const fn can_downgrade_to(&self, target: &Self) -> bool {
        // Only equal or higher classifications are safe without authorization
        *target as u8 >= *self as u8
    }

    /// Returns the minimum classification that can access this data.
    ///
    /// Data can only be accessed by principals with equal or higher clearance.
    #[must_use]
    pub const fn minimum_access_level(&self) -> Self {
        *self
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_classification_parse() {
        assert_eq!(
            DataClassification::parse("PUBLIC").unwrap(),
            DataClassification::Public
        );
        assert_eq!(
            DataClassification::parse("public").unwrap(),
            DataClassification::Public
        );
        assert_eq!(
            DataClassification::parse("INTERNAL").unwrap(),
            DataClassification::Internal
        );
        assert_eq!(
            DataClassification::parse("CONFIDENTIAL").unwrap(),
            DataClassification::Confidential
        );
        assert_eq!(
            DataClassification::parse("RESTRICTED").unwrap(),
            DataClassification::Restricted
        );
    }

    #[test]
    fn test_classification_parse_unknown_fails() {
        let result = DataClassification::parse("UNKNOWN");
        assert!(matches!(
            result,
            Err(EvidenceError::InvalidClassification { .. })
        ));

        let result = DataClassification::parse("");
        assert!(matches!(
            result,
            Err(EvidenceError::InvalidClassification { .. })
        ));

        let result = DataClassification::parse("SECRET");
        assert!(matches!(
            result,
            Err(EvidenceError::InvalidClassification { .. })
        ));
    }

    #[test]
    fn test_classification_as_str() {
        assert_eq!(DataClassification::Public.as_str(), "PUBLIC");
        assert_eq!(DataClassification::Internal.as_str(), "INTERNAL");
        assert_eq!(DataClassification::Confidential.as_str(), "CONFIDENTIAL");
        assert_eq!(DataClassification::Restricted.as_str(), "RESTRICTED");
    }

    #[test]
    fn test_classification_display() {
        assert_eq!(format!("{}", DataClassification::Public), "PUBLIC");
        assert_eq!(format!("{}", DataClassification::Restricted), "RESTRICTED");
    }

    #[test]
    fn test_classification_ordering() {
        assert!(DataClassification::Public < DataClassification::Internal);
        assert!(DataClassification::Internal < DataClassification::Confidential);
        assert!(DataClassification::Confidential < DataClassification::Restricted);
        assert!(DataClassification::Public < DataClassification::Restricted);
    }

    #[test]
    fn test_classification_progressive_disclosure() {
        assert!(!DataClassification::Public.requires_progressive_disclosure());
        assert!(!DataClassification::Internal.requires_progressive_disclosure());
        assert!(DataClassification::Confidential.requires_progressive_disclosure());
        assert!(DataClassification::Restricted.requires_progressive_disclosure());
    }

    #[test]
    fn test_classification_log_redaction() {
        assert!(!DataClassification::Public.requires_log_redaction());
        assert!(!DataClassification::Internal.requires_log_redaction());
        assert!(!DataClassification::Confidential.requires_log_redaction());
        assert!(DataClassification::Restricted.requires_log_redaction());
    }

    #[test]
    fn test_classification_retention_days() {
        assert_eq!(DataClassification::Public.default_retention_days(), 365 * 7);
        assert_eq!(
            DataClassification::Internal.default_retention_days(),
            365 * 3
        );
        assert_eq!(
            DataClassification::Confidential.default_retention_days(),
            365
        );
        assert_eq!(DataClassification::Restricted.default_retention_days(), 90);

        // More sensitive = shorter retention
        assert!(
            DataClassification::Restricted.default_retention_days()
                < DataClassification::Public.default_retention_days()
        );
    }

    #[test]
    fn test_classification_can_downgrade() {
        // Can always "downgrade" to same level (no change)
        assert!(DataClassification::Public.can_downgrade_to(&DataClassification::Public));
        assert!(DataClassification::Restricted.can_downgrade_to(&DataClassification::Restricted));

        // Can "downgrade" to higher level (upgrading is always safe)
        assert!(DataClassification::Public.can_downgrade_to(&DataClassification::Restricted));
        assert!(DataClassification::Internal.can_downgrade_to(&DataClassification::Confidential));

        // Cannot downgrade to lower level
        assert!(!DataClassification::Restricted.can_downgrade_to(&DataClassification::Public));
        assert!(!DataClassification::Confidential.can_downgrade_to(&DataClassification::Internal));
    }

    #[test]
    fn test_classification_roundtrip() {
        for classification in [
            DataClassification::Public,
            DataClassification::Internal,
            DataClassification::Confidential,
            DataClassification::Restricted,
        ] {
            let s = classification.as_str();
            let parsed = DataClassification::parse(s).unwrap();
            assert_eq!(classification, parsed);
        }
    }
}
