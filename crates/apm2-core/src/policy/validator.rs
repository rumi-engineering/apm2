//! Policy validation.
//!
//! This module provides validation for policy documents to ensure they are
//! well-formed before use.

use std::collections::HashSet;

use super::error::PolicyError;
use super::schema::{Policy, PolicyVersion, Rule, RuleType};

/// Validates a policy document.
///
/// # Errors
///
/// Returns `PolicyError` if the policy is invalid.
pub fn validate_policy(policy: &Policy) -> Result<ValidatedPolicy, PolicyError> {
    // Validate version format
    let version = PolicyVersion::parse(&policy.version)?;

    // Validate name is non-empty
    if policy.name.trim().is_empty() {
        return Err(PolicyError::missing_field("name"));
    }

    // Validate rules
    if policy.rules.is_empty() {
        return Err(PolicyError::EmptyPolicy);
    }

    // Check for duplicate rule IDs
    let mut seen_ids = HashSet::new();
    for rule in &policy.rules {
        if !seen_ids.insert(&rule.id) {
            return Err(PolicyError::duplicate_rule_id(&rule.id));
        }
        validate_rule(rule)?;
    }

    Ok(ValidatedPolicy {
        version,
        name: policy.name.clone(),
        description: policy.description.clone(),
        rule_count: policy.rules.len(),
    })
}

/// Validates a single rule.
fn validate_rule(rule: &Rule) -> Result<(), PolicyError> {
    // Validate rule ID is non-empty
    if rule.id.trim().is_empty() {
        return Err(PolicyError::missing_field("rule.id"));
    }

    // Validate rule-type-specific requirements
    match rule.rule_type {
        RuleType::ToolAllow | RuleType::ToolDeny => {
            validate_tool_rule(rule)?;
        },
        RuleType::Budget => {
            validate_budget_rule(rule)?;
        },
        RuleType::Network => {
            validate_network_rule(rule)?;
        },
        RuleType::Filesystem => {
            validate_filesystem_rule(rule)?;
        },
        // Secrets and Inference rules have no additional requirements
        RuleType::Secrets | RuleType::Inference => {},
    }

    // Validate path patterns if present
    for path in &rule.paths {
        validate_glob_pattern(&rule.id, path)?;
    }

    // Validate command patterns if present
    for cmd in &rule.commands {
        validate_glob_pattern(&rule.id, cmd)?;
    }

    Ok(())
}

/// Validates a tool rule has required fields.
fn validate_tool_rule(rule: &Rule) -> Result<(), PolicyError> {
    // Tool rules should have a tool name or path patterns
    if rule.tool.is_none() && rule.paths.is_empty() && rule.commands.is_empty() {
        return Err(PolicyError::validation(format!(
            "tool rule '{}' must specify 'tool', 'paths', or 'commands'",
            rule.id
        )));
    }

    // If tool is specified, it must be non-empty
    if let Some(ref tool) = rule.tool {
        if tool.trim().is_empty() {
            return Err(PolicyError::validation(format!(
                "tool rule '{}' has empty 'tool' field",
                rule.id
            )));
        }
    }

    Ok(())
}

/// Validates a budget rule has required fields.
fn validate_budget_rule(rule: &Rule) -> Result<(), PolicyError> {
    // Budget rules must have budget_type and limit
    if rule.budget_type.is_none() {
        return Err(PolicyError::validation(format!(
            "budget rule '{}' must specify 'budget_type'",
            rule.id
        )));
    }

    if rule.limit.is_none() {
        return Err(PolicyError::validation(format!(
            "budget rule '{}' must specify 'limit'",
            rule.id
        )));
    }

    // Limit must be positive for meaningful budgets
    if let Some(limit) = rule.limit {
        if limit == 0 {
            return Err(PolicyError::validation(format!(
                "budget rule '{}' has zero limit; use a deny rule instead",
                rule.id
            )));
        }
    }

    Ok(())
}

/// Validates a network rule has required fields.
fn validate_network_rule(rule: &Rule) -> Result<(), PolicyError> {
    // Network rules should have hosts or ports specified
    if rule.hosts.is_empty() && rule.ports.is_empty() {
        return Err(PolicyError::validation(format!(
            "network rule '{}' must specify 'hosts' or 'ports'",
            rule.id
        )));
    }

    // Validate hosts are non-empty strings
    for host in &rule.hosts {
        if host.trim().is_empty() {
            return Err(PolicyError::validation(format!(
                "network rule '{}' has empty host",
                rule.id
            )));
        }
    }

    Ok(())
}

/// Validates a filesystem rule has required fields.
fn validate_filesystem_rule(rule: &Rule) -> Result<(), PolicyError> {
    // Filesystem rules should have paths specified
    if rule.paths.is_empty() {
        return Err(PolicyError::validation(format!(
            "filesystem rule '{}' must specify 'paths'",
            rule.id
        )));
    }

    Ok(())
}

/// Validates a glob pattern is syntactically correct.
///
/// # Security
///
/// This function rejects patterns containing `..` components, which could
/// indicate an attempt to create rules that match path traversal attacks.
/// While the engine blocks traversal in input paths, rejecting `..` in
/// patterns provides defense-in-depth and better policy hygiene.
fn validate_glob_pattern(rule_id: &str, pattern: &str) -> Result<(), PolicyError> {
    // Empty patterns are invalid
    if pattern.is_empty() {
        return Err(PolicyError::InvalidGlobPattern {
            rule_id: rule_id.to_string(),
            pattern: pattern.to_string(),
            reason: "pattern cannot be empty".to_string(),
        });
    }

    // Security: Reject patterns containing ".." path traversal components
    // This prevents creation of rules that might match malicious paths
    for component in pattern.split(['/', '\\']) {
        if component == ".." {
            return Err(PolicyError::InvalidGlobPattern {
                rule_id: rule_id.to_string(),
                pattern: pattern.to_string(),
                reason: "pattern cannot contain '..' path traversal".to_string(),
            });
        }
    }

    // Check for unbalanced brackets
    let mut bracket_depth = 0i32;
    let mut brace_depth = 0i32;
    let mut in_escape = false;

    for ch in pattern.chars() {
        if in_escape {
            in_escape = false;
            continue;
        }

        match ch {
            '\\' => in_escape = true,
            '[' => bracket_depth += 1,
            ']' => {
                bracket_depth -= 1;
                if bracket_depth < 0 {
                    return Err(PolicyError::InvalidGlobPattern {
                        rule_id: rule_id.to_string(),
                        pattern: pattern.to_string(),
                        reason: "unbalanced brackets".to_string(),
                    });
                }
            },
            '{' => brace_depth += 1,
            '}' => {
                brace_depth -= 1;
                if brace_depth < 0 {
                    return Err(PolicyError::InvalidGlobPattern {
                        rule_id: rule_id.to_string(),
                        pattern: pattern.to_string(),
                        reason: "unbalanced braces".to_string(),
                    });
                }
            },
            _ => {},
        }
    }

    if bracket_depth != 0 {
        return Err(PolicyError::InvalidGlobPattern {
            rule_id: rule_id.to_string(),
            pattern: pattern.to_string(),
            reason: "unbalanced brackets".to_string(),
        });
    }

    if brace_depth != 0 {
        return Err(PolicyError::InvalidGlobPattern {
            rule_id: rule_id.to_string(),
            pattern: pattern.to_string(),
            reason: "unbalanced braces".to_string(),
        });
    }

    Ok(())
}

/// A validated policy summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPolicy {
    /// The parsed policy version.
    pub version: PolicyVersion,
    /// The policy name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Number of rules in the policy.
    pub rule_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::{BudgetType, Decision};

    fn make_policy(rules: Vec<Rule>) -> Policy {
        Policy {
            version: "1.0.0".to_string(),
            name: "test-policy".to_string(),
            description: None,
            rules,
            default_decision: Decision::Deny,
        }
    }

    fn make_tool_rule(id: &str, tool: Option<&str>) -> Rule {
        Rule {
            id: id.to_string(),
            rule_type: RuleType::ToolAllow,
            decision: Decision::Allow,
            tool: tool.map(String::from),
            paths: vec![],
            commands: vec![],
            budget_type: None,
            limit: None,
            hosts: vec![],
            ports: vec![],
            condition: None,
            rationale_code: None,
            reason: None,
        }
    }

    fn make_budget_rule(id: &str, budget_type: Option<BudgetType>, limit: Option<u64>) -> Rule {
        Rule {
            id: id.to_string(),
            rule_type: RuleType::Budget,
            decision: Decision::Allow,
            tool: None,
            paths: vec![],
            commands: vec![],
            budget_type,
            limit,
            hosts: vec![],
            ports: vec![],
            condition: None,
            rationale_code: None,
            reason: None,
        }
    }

    #[test]
    fn test_validate_valid_policy() {
        let policy = make_policy(vec![make_tool_rule("RULE-001", Some("fs.read"))]);

        let result = validate_policy(&policy).unwrap();
        assert_eq!(result.version, PolicyVersion::new(1, 0, 0));
        assert_eq!(result.name, "test-policy");
        assert_eq!(result.rule_count, 1);
    }

    #[test]
    fn test_validate_empty_policy_fails() {
        let policy = make_policy(vec![]);
        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::EmptyPolicy)));
    }

    #[test]
    fn test_validate_duplicate_rule_id_fails() {
        let policy = make_policy(vec![
            make_tool_rule("RULE-001", Some("fs.read")),
            make_tool_rule("RULE-001", Some("fs.write")),
        ]);

        let result = validate_policy(&policy);
        assert!(matches!(
            result,
            Err(PolicyError::DuplicateRuleId { rule_id }) if rule_id == "RULE-001"
        ));
    }

    #[test]
    fn test_validate_empty_name_fails() {
        let mut policy = make_policy(vec![make_tool_rule("RULE-001", Some("fs.read"))]);
        policy.name = String::new();

        let result = validate_policy(&policy);
        assert!(matches!(
            result,
            Err(PolicyError::MissingField { field }) if field == "name"
        ));
    }

    #[test]
    fn test_validate_invalid_version_fails() {
        let mut policy = make_policy(vec![make_tool_rule("RULE-001", Some("fs.read"))]);
        policy.version = "invalid".to_string();

        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::InvalidVersion { .. })));
    }

    #[test]
    fn test_validate_tool_rule_requires_tool_or_paths() {
        let policy = make_policy(vec![make_tool_rule("RULE-001", None)]);

        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
    }

    #[test]
    fn test_validate_tool_rule_with_paths_is_valid() {
        let mut rule = make_tool_rule("RULE-001", None);
        rule.paths = vec!["/workspace/**".to_string()];
        let policy = make_policy(vec![rule]);

        let result = validate_policy(&policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tool_rule_with_commands_is_valid() {
        let mut rule = make_tool_rule("RULE-001", None);
        rule.commands = vec!["cargo *".to_string()];
        let policy = make_policy(vec![rule]);

        let result = validate_policy(&policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_budget_rule_requires_budget_type() {
        let policy = make_policy(vec![make_budget_rule("RULE-001", None, Some(1000))]);

        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
    }

    #[test]
    fn test_validate_budget_rule_requires_limit() {
        let policy = make_policy(vec![make_budget_rule(
            "RULE-001",
            Some(BudgetType::Token),
            None,
        )]);

        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
    }

    #[test]
    fn test_validate_budget_rule_rejects_zero_limit() {
        let policy = make_policy(vec![make_budget_rule(
            "RULE-001",
            Some(BudgetType::Token),
            Some(0),
        )]);

        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
    }

    #[test]
    fn test_validate_valid_budget_rule() {
        let policy = make_policy(vec![make_budget_rule(
            "RULE-001",
            Some(BudgetType::Token),
            Some(100_000),
        )]);

        let result = validate_policy(&policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_network_rule_requires_hosts_or_ports() {
        let rule = Rule {
            id: "RULE-001".to_string(),
            rule_type: RuleType::Network,
            decision: Decision::Allow,
            tool: None,
            paths: vec![],
            commands: vec![],
            budget_type: None,
            limit: None,
            hosts: vec![],
            ports: vec![],
            condition: None,
            rationale_code: None,
            reason: None,
        };
        let policy = make_policy(vec![rule]);

        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
    }

    #[test]
    fn test_validate_network_rule_with_hosts_is_valid() {
        let rule = Rule {
            id: "RULE-001".to_string(),
            rule_type: RuleType::Network,
            decision: Decision::Allow,
            tool: None,
            paths: vec![],
            commands: vec![],
            budget_type: None,
            limit: None,
            hosts: vec!["api.example.com".to_string()],
            ports: vec![],
            condition: None,
            rationale_code: None,
            reason: None,
        };
        let policy = make_policy(vec![rule]);

        let result = validate_policy(&policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_filesystem_rule_requires_paths() {
        let rule = Rule {
            id: "RULE-001".to_string(),
            rule_type: RuleType::Filesystem,
            decision: Decision::Allow,
            tool: None,
            paths: vec![],
            commands: vec![],
            budget_type: None,
            limit: None,
            hosts: vec![],
            ports: vec![],
            condition: None,
            rationale_code: None,
            reason: None,
        };
        let policy = make_policy(vec![rule]);

        let result = validate_policy(&policy);
        assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
    }

    #[test]
    fn test_validate_glob_pattern_empty() {
        let result = validate_glob_pattern("RULE-001", "");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { .. })
        ));
    }

    #[test]
    fn test_validate_glob_pattern_unbalanced_brackets() {
        let result = validate_glob_pattern("RULE-001", "[a-z");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { .. })
        ));

        let result = validate_glob_pattern("RULE-001", "a-z]");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { .. })
        ));
    }

    #[test]
    fn test_validate_glob_pattern_unbalanced_braces() {
        let result = validate_glob_pattern("RULE-001", "{a,b");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { .. })
        ));

        let result = validate_glob_pattern("RULE-001", "a,b}");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { .. })
        ));
    }

    #[test]
    fn test_validate_glob_pattern_valid() {
        assert!(validate_glob_pattern("RULE-001", "/workspace/**").is_ok());
        assert!(validate_glob_pattern("RULE-001", "*.rs").is_ok());
        assert!(validate_glob_pattern("RULE-001", "[a-z]*").is_ok());
        assert!(validate_glob_pattern("RULE-001", "{foo,bar}").is_ok());
        assert!(validate_glob_pattern("RULE-001", "\\[escaped\\]").is_ok());
    }

    #[test]
    fn test_validate_glob_pattern_rejects_path_traversal() {
        // Security: Patterns with ".." should be rejected
        let result = validate_glob_pattern("RULE-001", "/workspace/../secret");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { reason, .. }) if reason.contains("traversal")
        ));

        let result = validate_glob_pattern("RULE-001", "../relative");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { reason, .. }) if reason.contains("traversal")
        ));

        let result = validate_glob_pattern("RULE-001", "/path/to/../escape/**");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { reason, .. }) if reason.contains("traversal")
        ));

        // Windows-style separators should also be rejected
        let result = validate_glob_pattern("RULE-001", "..\\windows\\path");
        assert!(matches!(
            result,
            Err(PolicyError::InvalidGlobPattern { reason, .. }) if reason.contains("traversal")
        ));

        // Single dot should be OK (current directory reference)
        assert!(validate_glob_pattern("RULE-001", "./relative").is_ok());
        assert!(validate_glob_pattern("RULE-001", "/path/./here").is_ok());

        // Dots in file names should be OK
        assert!(validate_glob_pattern("RULE-001", "/path/..hidden").is_ok());
        assert!(validate_glob_pattern("RULE-001", "/path/file..txt").is_ok());
    }
}
