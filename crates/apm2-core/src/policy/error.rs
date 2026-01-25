//! Policy-specific error types.

use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur during policy operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// Failed to read policy file.
    #[error("failed to read policy file at {path}: {source}")]
    ReadError {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse policy YAML.
    #[error("failed to parse policy YAML: {0}")]
    ParseError(#[from] serde_yaml::Error),

    /// Policy validation failed.
    #[error("policy validation failed: {message}")]
    ValidationError {
        /// Description of the validation failure.
        message: String,
    },

    /// Invalid policy version.
    #[error("invalid policy version: {version}, expected format: MAJOR.MINOR.PATCH")]
    InvalidVersion {
        /// The invalid version string.
        version: String,
    },

    /// Invalid rule type.
    #[error("invalid rule type: {value}")]
    InvalidRuleType {
        /// The invalid rule type value.
        value: String,
    },

    /// Invalid decision.
    #[error("invalid decision: {value}, expected ALLOW or DENY")]
    InvalidDecision {
        /// The invalid decision value.
        value: String,
    },

    /// Invalid budget type.
    #[error("invalid budget type: {value}")]
    InvalidBudgetType {
        /// The invalid budget type value.
        value: String,
    },

    /// Duplicate rule ID.
    #[error("duplicate rule ID: {rule_id}")]
    DuplicateRuleId {
        /// The duplicate rule ID.
        rule_id: String,
    },

    /// Empty policy (no rules).
    #[error("policy must contain at least one rule")]
    EmptyPolicy,

    /// Missing required field.
    #[error("missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: String,
    },

    /// Invalid glob pattern.
    #[error("invalid glob pattern in rule {rule_id}: {pattern}: {reason}")]
    InvalidGlobPattern {
        /// The rule containing the invalid pattern.
        rule_id: String,
        /// The invalid pattern.
        pattern: String,
        /// Why it's invalid.
        reason: String,
    },

    /// Circular dependency detected in rule conditions.
    #[error("circular dependency detected in rule conditions involving {rule_id}")]
    CircularDependency {
        /// The rule involved in the cycle.
        rule_id: String,
    },
}

impl PolicyError {
    /// Creates a validation error with the given message.
    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::ValidationError {
            message: message.into(),
        }
    }

    /// Creates a missing field error.
    #[must_use]
    pub fn missing_field(field: impl Into<String>) -> Self {
        Self::MissingField {
            field: field.into(),
        }
    }

    /// Creates a duplicate rule ID error.
    #[must_use]
    pub fn duplicate_rule_id(rule_id: impl Into<String>) -> Self {
        Self::DuplicateRuleId {
            rule_id: rule_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        let err = PolicyError::validation("rule order is invalid");
        assert_eq!(
            err.to_string(),
            "policy validation failed: rule order is invalid"
        );
    }

    #[test]
    fn test_missing_field_error_display() {
        let err = PolicyError::missing_field("version");
        assert_eq!(err.to_string(), "missing required field: version");
    }

    #[test]
    fn test_duplicate_rule_id_error_display() {
        let err = PolicyError::duplicate_rule_id("RULE-001");
        assert_eq!(err.to_string(), "duplicate rule ID: RULE-001");
    }

    #[test]
    fn test_invalid_version_error_display() {
        let err = PolicyError::InvalidVersion {
            version: "v1".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "invalid policy version: v1, expected format: MAJOR.MINOR.PATCH"
        );
    }

    #[test]
    fn test_invalid_decision_error_display() {
        let err = PolicyError::InvalidDecision {
            value: "MAYBE".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "invalid decision: MAYBE, expected ALLOW or DENY"
        );
    }

    #[test]
    fn test_empty_policy_error_display() {
        let err = PolicyError::EmptyPolicy;
        assert_eq!(err.to_string(), "policy must contain at least one rule");
    }
}
