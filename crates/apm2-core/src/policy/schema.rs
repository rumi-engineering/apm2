//! Policy schema types.
//!
//! This module defines the YAML schema for APM2 policy files. Policies are
//! the core mechanism for controlling agent behavior through default-deny
//! rules.
//!
//! # Schema Overview
//!
//! ```yaml
//! policy:
//!   version: "1.0.0"
//!   name: "example-policy"
//!   description: "Example policy for demonstration"
//!   rules:
//!     - id: "RULE-001"
//!       type: tool_allow
//!       tool: "fs.read"
//!       paths:
//!         - "/workspace/**"
//!       decision: allow
//!     - id: "RULE-002"
//!       type: budget
//!       budget_type: token
//!       limit: 100000
//!       decision: allow
//!   default_decision: deny
//! ```

use serde::{Deserialize, Serialize};

use super::error::PolicyError;

/// The root policy document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyDocument {
    /// The policy configuration.
    pub policy: Policy,
}

/// A policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Policy {
    /// Semantic version of this policy (e.g., "1.0.0").
    pub version: String,

    /// Human-readable name for this policy.
    pub name: String,

    /// Optional description of what this policy does.
    #[serde(default)]
    pub description: Option<String>,

    /// The list of policy rules, evaluated in order.
    pub rules: Vec<Rule>,

    /// The default decision when no rules match (should be "deny" for
    /// default-deny).
    pub default_decision: Decision,
}

/// A policy rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rule {
    /// Unique identifier for this rule within the policy.
    pub id: String,

    /// The type of rule.
    #[serde(rename = "type")]
    pub rule_type: RuleType,

    /// The decision to make when this rule matches.
    pub decision: Decision,

    /// For tool rules: the tool name pattern to match.
    #[serde(default)]
    pub tool: Option<String>,

    /// For tool rules: path patterns to match.
    #[serde(default)]
    pub paths: Vec<String>,

    /// For tool rules: command patterns to match.
    #[serde(default)]
    pub commands: Vec<String>,

    /// For budget rules: the type of budget.
    #[serde(default)]
    pub budget_type: Option<BudgetType>,

    /// For budget rules: the budget limit.
    #[serde(default)]
    pub limit: Option<u64>,

    /// For network rules: allowed hosts.
    #[serde(default)]
    pub hosts: Vec<String>,

    /// For network rules: allowed ports.
    #[serde(default)]
    pub ports: Vec<u16>,

    /// For consumption mode rules: allowed stable IDs.
    #[serde(default)]
    pub stable_ids: Vec<String>,

    /// Optional condition expression for rule activation.
    #[serde(default)]
    pub condition: Option<String>,

    /// Optional rationale code to include in decision events.
    #[serde(default)]
    pub rationale_code: Option<String>,

    /// Optional human-readable reason for this rule.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The type of a policy rule.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleType {
    /// Rule that allows or denies a specific tool.
    ToolAllow,
    /// Rule that allows or denies specific tool patterns.
    ToolDeny,
    /// Rule that sets budget limits.
    Budget,
    /// Rule for network access control.
    Network,
    /// Rule for filesystem access control.
    Filesystem,
    /// Rule for secrets access control.
    Secrets,
    /// Rule for inference/model access control.
    Inference,
    /// Rule for consumption mode restrictions.
    ConsumptionMode,
}

impl RuleType {
    /// Parses a rule type from a string.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidRuleType` if the string is not a
    /// recognized type.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s.to_lowercase().as_str() {
            "tool_allow" => Ok(Self::ToolAllow),
            "tool_deny" => Ok(Self::ToolDeny),
            "budget" => Ok(Self::Budget),
            "network" => Ok(Self::Network),
            "filesystem" => Ok(Self::Filesystem),
            "secrets" => Ok(Self::Secrets),
            "inference" => Ok(Self::Inference),
            "consumption_mode" => Ok(Self::ConsumptionMode),
            _ => Err(PolicyError::InvalidRuleType {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the string representation of this rule type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ToolAllow => "tool_allow",
            Self::ToolDeny => "tool_deny",
            Self::Budget => "budget",
            Self::Network => "network",
            Self::Filesystem => "filesystem",
            Self::Secrets => "secrets",
            Self::Inference => "inference",
            Self::ConsumptionMode => "consumption_mode",
        }
    }
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A policy decision.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Decision {
    /// Allow the action.
    Allow,
    /// Deny the action (default for default-deny policies).
    #[default]
    Deny,
}

impl Decision {
    /// Parses a decision from a string.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidDecision` if the string is not "allow" or
    /// "deny".
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s.to_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(PolicyError::InvalidDecision {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the string representation of this decision.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// Returns true if this is an allow decision.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns true if this is a deny decision.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The type of budget being limited.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BudgetType {
    /// Token budget for inference calls.
    Token,
    /// Time budget in milliseconds.
    Time,
    /// Budget for number of tool calls.
    ToolCalls,
    /// Budget for number of inference calls.
    InferenceCalls,
    /// Budget for filesystem operations.
    FilesystemOps,
    /// Budget for network operations.
    NetworkOps,
}

impl BudgetType {
    /// Parses a budget type from a string.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidBudgetType` if the string is not a
    /// recognized type.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s.to_lowercase().as_str() {
            "token" => Ok(Self::Token),
            "time" => Ok(Self::Time),
            "tool_calls" => Ok(Self::ToolCalls),
            "inference_calls" => Ok(Self::InferenceCalls),
            "filesystem_ops" => Ok(Self::FilesystemOps),
            "network_ops" => Ok(Self::NetworkOps),
            _ => Err(PolicyError::InvalidBudgetType {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the string representation of this budget type.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Time => "time",
            Self::ToolCalls => "tool_calls",
            Self::InferenceCalls => "inference_calls",
            Self::FilesystemOps => "filesystem_ops",
            Self::NetworkOps => "network_ops",
        }
    }
}

impl std::fmt::Display for BudgetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A parsed and validated policy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion {
    /// Major version number.
    pub major: u32,
    /// Minor version number.
    pub minor: u32,
    /// Patch version number.
    pub patch: u32,
}

impl PolicyVersion {
    /// Creates a new policy version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses a version string in the format "MAJOR.MINOR.PATCH".
    ///
    /// # Errors
    ///
    /// Returns `PolicyError::InvalidVersion` if the string is not a valid
    /// semver version.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(PolicyError::InvalidVersion {
                version: s.to_string(),
            });
        }

        let parse_part = |part: &str| -> Result<u32, PolicyError> {
            part.parse::<u32>()
                .map_err(|_| PolicyError::InvalidVersion {
                    version: s.to_string(),
                })
        };

        Ok(Self {
            major: parse_part(parts[0])?,
            minor: parse_part(parts[1])?,
            patch: parse_part(parts[2])?,
        })
    }
}

impl std::fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_type_parse() {
        assert_eq!(RuleType::parse("tool_allow").unwrap(), RuleType::ToolAllow);
        assert_eq!(RuleType::parse("TOOL_ALLOW").unwrap(), RuleType::ToolAllow);
        assert_eq!(RuleType::parse("tool_deny").unwrap(), RuleType::ToolDeny);
        assert_eq!(RuleType::parse("budget").unwrap(), RuleType::Budget);
        assert_eq!(RuleType::parse("network").unwrap(), RuleType::Network);
        assert_eq!(RuleType::parse("filesystem").unwrap(), RuleType::Filesystem);
        assert_eq!(RuleType::parse("secrets").unwrap(), RuleType::Secrets);
        assert_eq!(RuleType::parse("inference").unwrap(), RuleType::Inference);
        assert_eq!(
            RuleType::parse("consumption_mode").unwrap(),
            RuleType::ConsumptionMode
        );
    }

    #[test]
    fn test_rule_type_parse_invalid() {
        let result = RuleType::parse("unknown");
        assert!(matches!(result, Err(PolicyError::InvalidRuleType { .. })));
    }

    #[test]
    fn test_rule_type_as_str() {
        assert_eq!(RuleType::ToolAllow.as_str(), "tool_allow");
        assert_eq!(RuleType::ToolDeny.as_str(), "tool_deny");
        assert_eq!(RuleType::Budget.as_str(), "budget");
        assert_eq!(RuleType::Network.as_str(), "network");
        assert_eq!(RuleType::Filesystem.as_str(), "filesystem");
        assert_eq!(RuleType::Secrets.as_str(), "secrets");
        assert_eq!(RuleType::Inference.as_str(), "inference");
        assert_eq!(RuleType::ConsumptionMode.as_str(), "consumption_mode");
    }

    #[test]
    fn test_decision_parse() {
        assert_eq!(Decision::parse("allow").unwrap(), Decision::Allow);
        assert_eq!(Decision::parse("ALLOW").unwrap(), Decision::Allow);
        assert_eq!(Decision::parse("deny").unwrap(), Decision::Deny);
        assert_eq!(Decision::parse("DENY").unwrap(), Decision::Deny);
    }

    #[test]
    fn test_decision_parse_invalid() {
        let result = Decision::parse("maybe");
        assert!(matches!(result, Err(PolicyError::InvalidDecision { .. })));
    }

    #[test]
    fn test_decision_as_str() {
        assert_eq!(Decision::Allow.as_str(), "allow");
        assert_eq!(Decision::Deny.as_str(), "deny");
    }

    #[test]
    fn test_decision_is_allow_deny() {
        assert!(Decision::Allow.is_allow());
        assert!(!Decision::Allow.is_deny());
        assert!(!Decision::Deny.is_allow());
        assert!(Decision::Deny.is_deny());
    }

    #[test]
    fn test_decision_default() {
        // Default-deny: the default should be Deny
        assert_eq!(Decision::default(), Decision::Deny);
    }

    #[test]
    fn test_budget_type_parse() {
        assert_eq!(BudgetType::parse("token").unwrap(), BudgetType::Token);
        assert_eq!(BudgetType::parse("TOKEN").unwrap(), BudgetType::Token);
        assert_eq!(BudgetType::parse("time").unwrap(), BudgetType::Time);
        assert_eq!(
            BudgetType::parse("tool_calls").unwrap(),
            BudgetType::ToolCalls
        );
        assert_eq!(
            BudgetType::parse("inference_calls").unwrap(),
            BudgetType::InferenceCalls
        );
        assert_eq!(
            BudgetType::parse("filesystem_ops").unwrap(),
            BudgetType::FilesystemOps
        );
        assert_eq!(
            BudgetType::parse("network_ops").unwrap(),
            BudgetType::NetworkOps
        );
    }

    #[test]
    fn test_budget_type_parse_invalid() {
        let result = BudgetType::parse("unknown");
        assert!(matches!(result, Err(PolicyError::InvalidBudgetType { .. })));
    }

    #[test]
    fn test_budget_type_as_str() {
        assert_eq!(BudgetType::Token.as_str(), "token");
        assert_eq!(BudgetType::Time.as_str(), "time");
        assert_eq!(BudgetType::ToolCalls.as_str(), "tool_calls");
        assert_eq!(BudgetType::InferenceCalls.as_str(), "inference_calls");
        assert_eq!(BudgetType::FilesystemOps.as_str(), "filesystem_ops");
        assert_eq!(BudgetType::NetworkOps.as_str(), "network_ops");
    }

    #[test]
    fn test_policy_version_parse() {
        let v = PolicyVersion::parse("1.0.0").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);

        let v = PolicyVersion::parse("2.10.3").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 10);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_policy_version_parse_invalid() {
        // Missing parts
        assert!(PolicyVersion::parse("1.0").is_err());
        assert!(PolicyVersion::parse("1").is_err());
        assert!(PolicyVersion::parse("").is_err());

        // Non-numeric parts
        assert!(PolicyVersion::parse("a.b.c").is_err());
        assert!(PolicyVersion::parse("1.0.a").is_err());

        // Extra parts
        assert!(PolicyVersion::parse("1.0.0.0").is_err());
    }

    #[test]
    fn test_policy_version_display() {
        let v = PolicyVersion::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_policy_version_ordering() {
        let v1 = PolicyVersion::new(1, 0, 0);
        let v2 = PolicyVersion::new(1, 1, 0);
        let v3 = PolicyVersion::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }
}
