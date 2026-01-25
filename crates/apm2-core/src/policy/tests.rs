//! Integration tests for the policy module.

use super::*;

/// Example policy for testing various rule types.
const COMPREHENSIVE_POLICY: &str = r#"
policy:
  version: "1.0.0"
  name: "comprehensive-test-policy"
  description: "Tests all rule types and edge cases"
  rules:
    # Tool rules
    - id: "allow-fs-read"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
        - "/home/user/allowed/**"
      decision: allow
      reason: "Allow reading workspace files"
      rationale_code: "FS_READ_ALLOWED"

    - id: "deny-fs-write-sensitive"
      type: tool_deny
      tool: "fs.write"
      paths:
        - "/etc/**"
        - "/var/**"
      decision: deny
      reason: "Deny writing to system directories"

    # Budget rules
    - id: "token-budget"
      type: budget
      budget_type: token
      limit: 100000
      decision: allow

    - id: "time-budget"
      type: budget
      budget_type: time
      limit: 3600000
      decision: allow
      reason: "1 hour time limit"

    - id: "tool-call-budget"
      type: budget
      budget_type: tool_calls
      limit: 1000
      decision: allow

    # Network rules
    - id: "allow-github-api"
      type: network
      hosts:
        - "api.github.com"
        - "raw.githubusercontent.com"
      ports:
        - 443
      decision: allow

    - id: "allow-inference-api"
      type: network
      hosts:
        - "api.anthropic.com"
        - "api.openai.com"
      ports:
        - 443
      decision: allow

    # Filesystem rules
    - id: "allow-workspace-fs"
      type: filesystem
      paths:
        - "/workspace/**"
      decision: allow

    # Secrets rules
    - id: "allow-secrets"
      type: secrets
      decision: allow
      condition: "lease.scope.includes_secrets"

    # Inference rules
    - id: "allow-inference"
      type: inference
      decision: allow

  default_decision: deny
"#;

#[test]
fn test_parse_comprehensive_policy() {
    let loaded = LoadedPolicy::from_yaml(COMPREHENSIVE_POLICY).unwrap();

    assert_eq!(loaded.version(), "1.0.0");
    assert_eq!(loaded.name(), "comprehensive-test-policy");
    assert_eq!(loaded.rule_count(), 10);
}

#[test]
fn test_policy_hash_is_deterministic() {
    let loaded1 = LoadedPolicy::from_yaml(COMPREHENSIVE_POLICY).unwrap();
    let loaded2 = LoadedPolicy::from_yaml(COMPREHENSIVE_POLICY).unwrap();

    // Hash should be identical for identical content
    assert_eq!(loaded1.content_hash, loaded2.content_hash);
    assert_eq!(loaded1.content_hash_hex(), loaded2.content_hash_hex());
}

#[test]
fn test_policy_hash_differs_for_different_content() {
    let yaml1 = r#"
policy:
  version: "1.0.0"
  name: "policy-1"
  rules:
    - id: "rule-1"
      type: tool_allow
      tool: "fs.read"
      decision: allow
  default_decision: deny
"#;

    let yaml2 = r#"
policy:
  version: "1.0.0"
  name: "policy-2"
  rules:
    - id: "rule-1"
      type: tool_allow
      tool: "fs.write"
      decision: allow
  default_decision: deny
"#;

    let loaded1 = LoadedPolicy::from_yaml(yaml1).unwrap();
    let loaded2 = LoadedPolicy::from_yaml(yaml2).unwrap();

    assert_ne!(loaded1.content_hash, loaded2.content_hash);
}

use crate::events::policy_event;

#[test]
fn test_policy_loaded_event_contains_hash() {
    let loaded = LoadedPolicy::from_yaml(COMPREHENSIVE_POLICY).unwrap();
    let event = create_policy_loaded_event(&loaded);

    match event.event {
        Some(policy_event::Event::Loaded(loaded_event)) => {
            assert_eq!(loaded_event.policy_hash.len(), 32);
            assert_eq!(loaded_event.policy_hash, loaded.content_hash.to_vec());
            assert_eq!(loaded_event.policy_version, "1.0.0");
            assert_eq!(loaded_event.rule_count, 10);
        },
        _ => panic!("Expected PolicyLoaded event"),
    }
}

#[test]
fn test_validate_rejects_empty_rules() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "empty-rules"
  rules: []
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(result, Err(PolicyError::EmptyPolicy)));
}

#[test]
fn test_validate_rejects_duplicate_rule_ids() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "duplicate-ids"
  rules:
    - id: "same-id"
      type: tool_allow
      tool: "fs.read"
      decision: allow
    - id: "same-id"
      type: tool_deny
      tool: "fs.write"
      decision: deny
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(
        result,
        Err(PolicyError::DuplicateRuleId { rule_id }) if rule_id == "same-id"
    ));
}

#[test]
fn test_validate_rejects_invalid_version() {
    let yaml = r#"
policy:
  version: "invalid"
  name: "invalid-version"
  rules:
    - id: "rule-1"
      type: tool_allow
      tool: "fs.read"
      decision: allow
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(result, Err(PolicyError::InvalidVersion { .. })));
}

#[test]
fn test_validate_rejects_budget_without_type() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "missing-budget-type"
  rules:
    - id: "budget-rule"
      type: budget
      limit: 1000
      decision: allow
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
}

#[test]
fn test_validate_rejects_budget_without_limit() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "missing-budget-limit"
  rules:
    - id: "budget-rule"
      type: budget
      budget_type: token
      decision: allow
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
}

#[test]
fn test_validate_rejects_network_without_hosts_or_ports() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "missing-network-config"
  rules:
    - id: "network-rule"
      type: network
      decision: allow
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
}

#[test]
fn test_validate_rejects_filesystem_without_paths() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "missing-fs-paths"
  rules:
    - id: "fs-rule"
      type: filesystem
      decision: allow
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
}

#[test]
fn test_validate_rejects_tool_without_specifier() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "missing-tool-specifier"
  rules:
    - id: "tool-rule"
      type: tool_allow
      decision: allow
  default_decision: deny
"#;

    let result = LoadedPolicy::from_yaml(yaml);
    assert!(matches!(result, Err(PolicyError::ValidationError { .. })));
}

#[test]
fn test_policy_with_default_allow_parses() {
    // Note: This is valid YAML, but security practice dictates default_decision
    // should be deny. The parser allows it for flexibility.
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "default-allow"
  rules:
    - id: "deny-dangerous"
      type: tool_deny
      tool: "dangerous_tool"
      decision: deny
  default_decision: allow
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    assert_eq!(loaded.policy.default_decision, Decision::Allow);
}

#[test]
fn test_all_budget_types_parse() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "all-budgets"
  rules:
    - id: "token"
      type: budget
      budget_type: token
      limit: 100000
      decision: allow
    - id: "time"
      type: budget
      budget_type: time
      limit: 3600000
      decision: allow
    - id: "tool-calls"
      type: budget
      budget_type: tool_calls
      limit: 1000
      decision: allow
    - id: "inference-calls"
      type: budget
      budget_type: inference_calls
      limit: 100
      decision: allow
    - id: "filesystem-ops"
      type: budget
      budget_type: filesystem_ops
      limit: 5000
      decision: allow
    - id: "network-ops"
      type: budget
      budget_type: network_ops
      limit: 500
      decision: allow
  default_decision: deny
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    assert_eq!(loaded.rule_count(), 6);

    // Verify each budget type
    let rules = &loaded.policy.rules;
    assert_eq!(rules[0].budget_type, Some(BudgetType::Token));
    assert_eq!(rules[1].budget_type, Some(BudgetType::Time));
    assert_eq!(rules[2].budget_type, Some(BudgetType::ToolCalls));
    assert_eq!(rules[3].budget_type, Some(BudgetType::InferenceCalls));
    assert_eq!(rules[4].budget_type, Some(BudgetType::FilesystemOps));
    assert_eq!(rules[5].budget_type, Some(BudgetType::NetworkOps));
}

#[test]
fn test_all_rule_types_parse() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "all-rule-types"
  rules:
    - id: "tool-allow"
      type: tool_allow
      tool: "fs.read"
      decision: allow
    - id: "tool-deny"
      type: tool_deny
      tool: "dangerous"
      decision: deny
    - id: "budget"
      type: budget
      budget_type: token
      limit: 1000
      decision: allow
    - id: "network"
      type: network
      hosts:
        - "example.com"
      decision: allow
    - id: "filesystem"
      type: filesystem
      paths:
        - "/tmp/**"
      decision: allow
    - id: "secrets"
      type: secrets
      decision: deny
    - id: "inference"
      type: inference
      decision: allow
  default_decision: deny
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    assert_eq!(loaded.rule_count(), 7);

    let rules = &loaded.policy.rules;
    assert_eq!(rules[0].rule_type, RuleType::ToolAllow);
    assert_eq!(rules[1].rule_type, RuleType::ToolDeny);
    assert_eq!(rules[2].rule_type, RuleType::Budget);
    assert_eq!(rules[3].rule_type, RuleType::Network);
    assert_eq!(rules[4].rule_type, RuleType::Filesystem);
    assert_eq!(rules[5].rule_type, RuleType::Secrets);
    assert_eq!(rules[6].rule_type, RuleType::Inference);
}

#[test]
fn test_glob_patterns_in_paths() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "glob-patterns"
  rules:
    - id: "various-patterns"
      type: filesystem
      paths:
        - "/workspace/**"
        - "/home/*/projects/**"
        - "*.rs"
        - "src/[abc]*.rs"
        - "{foo,bar}/**"
      decision: allow
  default_decision: deny
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    let paths = &loaded.policy.rules[0].paths;

    assert_eq!(paths.len(), 5);
    assert!(paths.contains(&"/workspace/**".to_string()));
    assert!(paths.contains(&"/home/*/projects/**".to_string()));
    assert!(paths.contains(&"*.rs".to_string()));
    assert!(paths.contains(&"src/[abc]*.rs".to_string()));
    assert!(paths.contains(&"{foo,bar}/**".to_string()));
}

#[test]
fn test_policy_with_conditions() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "conditional-policy"
  rules:
    - id: "conditional-secrets"
      type: secrets
      decision: allow
      condition: "lease.scope.includes_secrets && session.actor_id.starts_with('trusted-')"
  default_decision: deny
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    let condition = &loaded.policy.rules[0].condition;

    assert!(condition.is_some());
    assert!(condition.as_ref().unwrap().contains("lease.scope"));
}

#[test]
fn test_policy_with_rationale_codes() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "rationale-codes"
  rules:
    - id: "documented-rule"
      type: tool_allow
      tool: "fs.read"
      decision: allow
      rationale_code: "SEC_001_FS_READ_ALLOWED"
      reason: "Allow filesystem read operations for workspace access"
  default_decision: deny
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    let rule = &loaded.policy.rules[0];

    assert_eq!(
        rule.rationale_code,
        Some("SEC_001_FS_READ_ALLOWED".to_string())
    );
    assert!(rule.reason.is_some());
}

#[test]
fn test_minimal_valid_policy() {
    // The absolute minimum valid policy
    let yaml = r#"
policy:
  version: "0.0.1"
  name: "x"
  rules:
    - id: "r"
      type: tool_allow
      tool: "*"
      decision: deny
  default_decision: deny
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    assert_eq!(loaded.version(), "0.0.1");
    assert_eq!(loaded.name(), "x");
    assert_eq!(loaded.rule_count(), 1);
}

#[test]
fn test_network_rule_with_ports_only() {
    let yaml = r#"
policy:
  version: "1.0.0"
  name: "ports-only"
  rules:
    - id: "https-only"
      type: network
      ports:
        - 443
        - 8443
      decision: allow
  default_decision: deny
"#;

    let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
    let ports = &loaded.policy.rules[0].ports;

    assert_eq!(ports.len(), 2);
    assert!(ports.contains(&443));
    assert!(ports.contains(&8443));
}

#[test]
fn test_policy_version_ordering() {
    assert!(PolicyVersion::new(1, 0, 0) < PolicyVersion::new(1, 0, 1));
    assert!(PolicyVersion::new(1, 0, 0) < PolicyVersion::new(1, 1, 0));
    assert!(PolicyVersion::new(1, 0, 0) < PolicyVersion::new(2, 0, 0));
    assert!(PolicyVersion::new(1, 9, 9) < PolicyVersion::new(2, 0, 0));
}

#[test]
fn test_compute_policy_hash_direct() {
    let content = "test content for hashing";
    let hash = compute_policy_hash(content);

    assert_eq!(hash.len(), 32);

    // Should be deterministic
    let hash2 = compute_policy_hash(content);
    assert_eq!(hash, hash2);
}

#[test]
fn test_invalid_yaml_produces_parse_error() {
    let invalid_yamls = [
        "not valid yaml at all {{{",
        "policy:\n  version: [1, 2, 3]", // version should be string
        "policy:\n  rules: 'not a list'",
        "",
        "   ",
    ];

    for yaml in invalid_yamls {
        let result = LoadedPolicy::from_yaml(yaml);
        assert!(result.is_err(), "Expected error for invalid yaml: {yaml:?}");
    }
}

#[test]
fn test_policy_default_decision_parsing() {
    let allow_yaml = r#"
policy:
  version: "1.0.0"
  name: "allow-default"
  rules:
    - id: "r"
      type: tool_deny
      tool: "bad"
      decision: deny
  default_decision: allow
"#;

    let deny_yaml = r#"
policy:
  version: "1.0.0"
  name: "deny-default"
  rules:
    - id: "r"
      type: tool_allow
      tool: "good"
      decision: allow
  default_decision: deny
"#;

    let allow_loaded = LoadedPolicy::from_yaml(allow_yaml).unwrap();
    let deny_loaded = LoadedPolicy::from_yaml(deny_yaml).unwrap();

    assert!(allow_loaded.policy.default_decision.is_allow());
    assert!(deny_loaded.policy.default_decision.is_deny());
}
