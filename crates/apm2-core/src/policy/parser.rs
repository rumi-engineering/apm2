//! Policy parsing and loading.
//!
//! This module provides functions for parsing policy documents from YAML
//! strings and loading them from files.

use std::path::Path;

use super::error::PolicyError;
use super::schema::{Policy, PolicyDocument};
use super::validator::{ValidatedPolicy, validate_policy};

/// Parses a policy document from a YAML string.
///
/// # Errors
///
/// Returns `PolicyError::ParseError` if the YAML is invalid or doesn't match
/// the expected schema.
pub fn parse_policy(yaml: &str) -> Result<Policy, PolicyError> {
    let doc: PolicyDocument = serde_yaml::from_str(yaml)?;
    Ok(doc.policy)
}

/// Parses and validates a policy document from a YAML string.
///
/// This is the primary entry point for loading policy documents. It both
/// parses the YAML and validates the policy structure.
///
/// # Errors
///
/// Returns `PolicyError` if parsing or validation fails.
pub fn parse_and_validate_policy(yaml: &str) -> Result<(Policy, ValidatedPolicy), PolicyError> {
    let policy = parse_policy(yaml)?;
    let validated = validate_policy(&policy)?;
    Ok((policy, validated))
}

/// Loads a policy document from a file path.
///
/// # Errors
///
/// Returns `PolicyError::ReadError` if the file cannot be read, or
/// `PolicyError::ParseError` if the YAML is invalid.
pub fn load_policy_from_file(path: &Path) -> Result<Policy, PolicyError> {
    let content = std::fs::read_to_string(path).map_err(|e| PolicyError::ReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_policy(&content)
}

/// Loads and validates a policy document from a file path.
///
/// # Errors
///
/// Returns `PolicyError` if reading, parsing, or validation fails.
pub fn load_and_validate_policy_from_file(
    path: &Path,
) -> Result<(Policy, ValidatedPolicy), PolicyError> {
    let content = std::fs::read_to_string(path).map_err(|e| PolicyError::ReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_and_validate_policy(&content)
}

/// Computes a BLAKE3 hash of the policy content.
///
/// This hash is used to identify policy versions and is included in
/// `PolicyLoaded` events for deterministic policy evaluation.
#[must_use]
pub fn compute_policy_hash(content: &str) -> [u8; 32] {
    *blake3::hash(content.as_bytes()).as_bytes()
}

/// Represents a loaded policy with its content hash.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    /// The parsed policy.
    pub policy: Policy,
    /// Validation summary.
    pub validated: ValidatedPolicy,
    /// BLAKE3 hash of the original content.
    pub content_hash: [u8; 32],
}

impl LoadedPolicy {
    /// Creates a new loaded policy from YAML content.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError` if parsing or validation fails.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        let (policy, validated) = parse_and_validate_policy(yaml)?;
        let content_hash = compute_policy_hash(yaml);
        Ok(Self {
            policy,
            validated,
            content_hash,
        })
    }

    /// Loads a policy from a file path.
    ///
    /// # Errors
    ///
    /// Returns `PolicyError` if reading, parsing, or validation fails.
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        let content = std::fs::read_to_string(path).map_err(|e| PolicyError::ReadError {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::from_yaml(&content)
    }

    /// Returns the policy version string.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.policy.version
    }

    /// Returns the policy name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.policy.name
    }

    /// Returns the number of rules in the policy.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.policy.rules.len()
    }

    /// Returns the content hash as a hex string.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        hex_encode(&self.content_hash)
    }
}

/// Encodes bytes as a lowercase hexadecimal string.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            // write! to a String never fails
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::{Decision, RuleType};

    const VALID_POLICY_YAML: &str = r#"
policy:
  version: "1.0.0"
  name: "test-policy"
  description: "A test policy"
  rules:
    - id: "RULE-001"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: allow
    - id: "RULE-002"
      type: budget
      budget_type: token
      limit: 100000
      decision: allow
  default_decision: deny
"#;

    #[test]
    fn test_parse_valid_policy() {
        let policy = parse_policy(VALID_POLICY_YAML).unwrap();

        assert_eq!(policy.version, "1.0.0");
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.description, Some("A test policy".to_string()));
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.default_decision, Decision::Deny);

        // Check first rule
        let rule1 = &policy.rules[0];
        assert_eq!(rule1.id, "RULE-001");
        assert_eq!(rule1.rule_type, RuleType::ToolAllow);
        assert_eq!(rule1.tool, Some("fs.read".to_string()));
        assert_eq!(rule1.paths, vec!["/workspace/**"]);
        assert_eq!(rule1.decision, Decision::Allow);

        // Check second rule
        let rule2 = &policy.rules[1];
        assert_eq!(rule2.id, "RULE-002");
        assert_eq!(rule2.rule_type, RuleType::Budget);
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let result = parse_policy("not: valid: yaml: {{{{");
        assert!(matches!(result, Err(PolicyError::ParseError(_))));
    }

    #[test]
    fn test_parse_missing_required_fields() {
        let yaml = r#"
policy:
  version: "1.0.0"
"#;
        let result = parse_policy(yaml);
        assert!(matches!(result, Err(PolicyError::ParseError(_))));
    }

    #[test]
    fn test_parse_and_validate_policy() {
        let (policy, validated) = parse_and_validate_policy(VALID_POLICY_YAML).unwrap();

        assert_eq!(policy.name, "test-policy");
        assert_eq!(validated.name, "test-policy");
        assert_eq!(validated.rule_count, 2);
    }

    #[test]
    fn test_compute_policy_hash() {
        let hash1 = compute_policy_hash(VALID_POLICY_YAML);
        let hash2 = compute_policy_hash(VALID_POLICY_YAML);

        // Same content should produce same hash
        assert_eq!(hash1, hash2);

        // Different content should produce different hash
        let hash3 = compute_policy_hash("different content");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_loaded_policy_from_yaml() {
        let loaded = LoadedPolicy::from_yaml(VALID_POLICY_YAML).unwrap();

        assert_eq!(loaded.version(), "1.0.0");
        assert_eq!(loaded.name(), "test-policy");
        assert_eq!(loaded.rule_count(), 2);
        assert!(!loaded.content_hash_hex().is_empty());
        assert_eq!(loaded.content_hash_hex().len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_loaded_policy_hash_consistency() {
        let loaded1 = LoadedPolicy::from_yaml(VALID_POLICY_YAML).unwrap();
        let loaded2 = LoadedPolicy::from_yaml(VALID_POLICY_YAML).unwrap();

        assert_eq!(loaded1.content_hash, loaded2.content_hash);
        assert_eq!(loaded1.content_hash_hex(), loaded2.content_hash_hex());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_parse_minimal_policy() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "minimal"
  rules:
    - id: "deny-all"
      type: tool_deny
      tool: "*"
      decision: deny
  default_decision: deny
"#;
        let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
        assert_eq!(loaded.rule_count(), 1);
    }

    #[test]
    fn test_parse_complex_policy() {
        let yaml = r#"
policy:
  version: "2.1.0"
  name: "complex-policy"
  description: "A more complex policy with multiple rule types"
  rules:
    - id: "fs-read-workspace"
      type: filesystem
      paths:
        - "/workspace/**"
        - "/home/user/projects/**"
      decision: allow
      reason: "Allow reading workspace files"

    - id: "network-api"
      type: network
      hosts:
        - "api.github.com"
        - "api.anthropic.com"
      ports:
        - 443
      decision: allow

    - id: "token-budget"
      type: budget
      budget_type: token
      limit: 500000
      decision: allow

    - id: "inference-allowed"
      type: inference
      decision: allow
      rationale_code: "INF_ALLOWED"

  default_decision: deny
"#;
        let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
        assert_eq!(loaded.version(), "2.1.0");
        assert_eq!(loaded.name(), "complex-policy");
        assert_eq!(loaded.rule_count(), 4);
    }
}
