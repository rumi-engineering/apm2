//! Policy evaluation engine for tool request authorization.
//!
//! This module provides the `PolicyEngine` that evaluates tool requests against
//! policy rules following a **default-deny** model. Rules are evaluated in
//! order and the first matching rule determines the decision. If no rule
//! matches, the request is denied.
//!
//! # Security Properties
//!
//! - **Default-deny**: Unmatched requests are always denied
//! - **Fail-closed**: Any evaluation error results in denial
//! - **Deterministic**: Same policy + request always produces same decision
//! - **Audit trail**: Every decision includes `rule_id` for traceability
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::policy::{LoadedPolicy, PolicyEngine};
//! use apm2_core::tool::{FileRead, ToolRequest, tool_request};
//!
//! let yaml = r#"
//! policy:
//!   version: "1.0.0"
//!   name: "example"
//!   rules:
//!     - id: "allow-workspace-read"
//!       type: tool_allow
//!       tool: "fs.read"
//!       paths:
//!         - "/workspace/**"
//!       decision: allow
//!   default_decision: deny
//! "#;
//!
//! let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
//! let engine = PolicyEngine::new(&loaded);
//!
//! let request = ToolRequest {
//!     request_id: "req-001".to_string(),
//!     session_token: "session-abc".to_string(),
//!     dedupe_key: String::new(),
//!     tool: Some(tool_request::Tool::FileRead(FileRead {
//!         path: "/workspace/src/main.rs".to_string(),
//!         offset: 0,
//!         limit: 0,
//!     })),
//! };
//!
//! let result = engine.evaluate(&request);
//! assert!(result.is_allowed());
//! ```

use std::sync::Arc;

use super::parser::LoadedPolicy;
use super::schema::{Decision, Rule, RuleType};
use crate::events::ToolDecided;
use crate::tool::{ToolRequest, tool_request};

/// Special rule ID for default-deny decisions.
pub const DEFAULT_DENY_RULE_ID: &str = "DEFAULT_DENY";

/// Rationale code for default-deny decisions.
pub const DEFAULT_DENY_RATIONALE: &str = "NO_MATCHING_RULE";

/// The policy evaluation engine.
///
/// Evaluates tool requests against a loaded policy following a default-deny
/// model. Rules are evaluated in order; the first matching rule determines
/// the decision.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// The loaded policy with content hash.
    policy: Arc<LoadedPolicy>,
}

impl PolicyEngine {
    /// Creates a new policy engine from a loaded policy.
    #[must_use]
    pub fn new(policy: &LoadedPolicy) -> Self {
        Self {
            policy: Arc::new(policy.clone()),
        }
    }

    /// Creates a new policy engine from an Arc-wrapped loaded policy.
    ///
    /// This is useful when sharing a policy across multiple engines or threads.
    #[must_use]
    pub const fn from_arc(policy: Arc<LoadedPolicy>) -> Self {
        Self { policy }
    }

    /// Returns a reference to the underlying policy.
    #[must_use]
    pub fn policy(&self) -> &LoadedPolicy {
        &self.policy
    }

    /// Returns the policy content hash.
    #[must_use]
    pub fn policy_hash(&self) -> &[u8; 32] {
        &self.policy.content_hash
    }

    /// Evaluates a tool request against the policy.
    ///
    /// Rules are evaluated in order. The first matching rule determines the
    /// decision. If no rule matches, the request is denied according to the
    /// policy's `default_decision` (which should always be `deny` for
    /// default-deny policies).
    ///
    /// # Returns
    ///
    /// An `EvaluationResult` containing the decision and metadata.
    #[must_use]
    pub fn evaluate(&self, request: &ToolRequest) -> EvaluationResult {
        // Extract the tool info from the request
        let Some(tool) = &request.tool else {
            // No tool specified - deny with validation error
            return EvaluationResult::denied(
                DEFAULT_DENY_RULE_ID.to_string(),
                "MISSING_TOOL".to_string(),
                self.policy.content_hash,
                "Tool request must specify a tool".to_string(),
            );
        };

        // Get tool name and context for matching
        let tool_name = get_tool_name(tool);

        // Evaluate rules in order
        for rule in &self.policy.policy.rules {
            if let Some(result) = self.evaluate_rule(rule, tool, &tool_name) {
                return result;
            }
        }

        // No rule matched - apply default decision
        self.apply_default_decision(&tool_name)
    }

    /// Evaluates a single rule against a tool request.
    ///
    /// Returns `Some(EvaluationResult)` if the rule matches, `None` otherwise.
    fn evaluate_rule(
        &self,
        rule: &Rule,
        tool: &tool_request::Tool,
        tool_name: &str,
    ) -> Option<EvaluationResult> {
        // Check if the rule type applies to this tool
        if !Self::rule_applies_to_tool(rule, tool, tool_name) {
            return None;
        }

        // Rule matched - return the decision
        let decision = rule.decision;
        let rule_id = rule.id.clone();
        let rationale_code = rule
            .rationale_code
            .clone()
            .unwrap_or_else(|| format!("{}_MATCHED", rule.rule_type.as_str().to_uppercase()));

        Some(EvaluationResult {
            decision,
            rule_id,
            rationale_code,
            policy_hash: self.policy.content_hash,
            message: rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("Rule {} applied", rule.id)),
            budget_consumed: 0, // Budget tracking is done by caller
        })
    }

    /// Checks if a rule applies to a specific tool request.
    fn rule_applies_to_tool(rule: &Rule, tool: &tool_request::Tool, tool_name: &str) -> bool {
        match rule.rule_type {
            RuleType::ToolAllow | RuleType::ToolDeny => {
                Self::matches_tool_rule(rule, tool, tool_name)
            },
            RuleType::Filesystem => Self::matches_filesystem_rule(rule, tool),
            RuleType::Network => Self::matches_network_rule(rule, tool),
            RuleType::Secrets => Self::matches_secrets_rule(rule, tool),
            RuleType::Inference => Self::matches_inference_rule(rule, tool),
            RuleType::Budget => {
                // Budget rules are checked separately (budget enforcement)
                // They don't apply to individual tool requests
                false
            },
        }
    }

    /// Checks if a `tool_allow`/`tool_deny` rule matches the request.
    fn matches_tool_rule(rule: &Rule, tool: &tool_request::Tool, tool_name: &str) -> bool {
        // Check tool name pattern
        if let Some(ref pattern) = rule.tool {
            if !matches_pattern(pattern, tool_name) {
                return false;
            }
        }

        // Check path patterns for filesystem operations
        match tool {
            tool_request::Tool::FileRead(req) => {
                if !rule.paths.is_empty() {
                    return matches_any_path_pattern(&rule.paths, &req.path);
                }
            },
            tool_request::Tool::FileWrite(req) => {
                if !rule.paths.is_empty() {
                    return matches_any_path_pattern(&rule.paths, &req.path);
                }
            },
            tool_request::Tool::FileEdit(req) => {
                if !rule.paths.is_empty() {
                    return matches_any_path_pattern(&rule.paths, &req.path);
                }
            },
            tool_request::Tool::ShellExec(req) => {
                // Check command patterns
                if !rule.commands.is_empty() {
                    return matches_any_command_pattern(&rule.commands, &req.command);
                }
            },
            tool_request::Tool::GitOp(_)
            | tool_request::Tool::Inference(_)
            | tool_request::Tool::ArtifactPublish(_) => {
                // No path/command restrictions for these by default
            },
        }

        // If no specific restrictions, the tool name match is sufficient
        true
    }

    /// Checks if a filesystem rule matches the request.
    fn matches_filesystem_rule(rule: &Rule, tool: &tool_request::Tool) -> bool {
        // Filesystem rules apply to FileRead, FileWrite, FileEdit
        let path = match tool {
            tool_request::Tool::FileRead(req) => &req.path,
            tool_request::Tool::FileWrite(req) => &req.path,
            tool_request::Tool::FileEdit(req) => &req.path,
            _ => return false,
        };

        if rule.paths.is_empty() {
            // No paths specified - matches all filesystem operations
            return true;
        }

        matches_any_path_pattern(&rule.paths, path)
    }

    /// Checks if a network rule matches the request.
    fn matches_network_rule(rule: &Rule, tool: &tool_request::Tool) -> bool {
        // Network rules apply to ShellExec with network_access
        // and potentially Inference calls
        match tool {
            tool_request::Tool::ShellExec(req) => {
                // Only apply if network access is requested
                if !req.network_access {
                    return false;
                }
                // If rule specifies hosts/ports, we can't fully match here
                // because we don't know the target host from the command.
                // For now, match if network access is requested.
                true
            },
            tool_request::Tool::Inference(_) => {
                // Inference calls always require network
                // Check host restrictions if specified
                if !rule.hosts.is_empty() {
                    // TODO: Match provider URL against hosts
                    // For now, allow if inference is enabled
                }
                true
            },
            _ => false,
        }
    }

    /// Checks if a secrets rule matches the request.
    const fn matches_secrets_rule(_rule: &Rule, _tool: &tool_request::Tool) -> bool {
        // Secrets rules would apply to specific secret access operations
        // This is a placeholder for future implementation
        false
    }

    /// Checks if an inference rule matches the request.
    const fn matches_inference_rule(_rule: &Rule, tool: &tool_request::Tool) -> bool {
        // Inference rules apply to InferenceCall
        matches!(tool, tool_request::Tool::Inference(_))
    }

    /// Applies the default decision when no rule matches.
    fn apply_default_decision(&self, tool_name: &str) -> EvaluationResult {
        match self.policy.policy.default_decision {
            Decision::Allow => EvaluationResult::allowed(
                DEFAULT_DENY_RULE_ID.to_string(),
                "DEFAULT_ALLOW".to_string(),
                self.policy.content_hash,
                format!("No rule matched for {tool_name}; default is allow"),
            ),
            Decision::Deny => EvaluationResult::denied(
                DEFAULT_DENY_RULE_ID.to_string(),
                DEFAULT_DENY_RATIONALE.to_string(),
                self.policy.content_hash,
                format!("No rule matched for {tool_name}; default is deny"),
            ),
        }
    }
}

/// Result of evaluating a tool request against a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationResult {
    /// The decision (allow or deny).
    pub decision: Decision,
    /// The rule ID that matched, or `DEFAULT_DENY` if no rule matched.
    pub rule_id: String,
    /// Machine-readable rationale code for the decision.
    pub rationale_code: String,
    /// BLAKE3 hash of the policy content.
    pub policy_hash: [u8; 32],
    /// Human-readable message explaining the decision.
    pub message: String,
    /// Budget consumed by this evaluation (typically 0; set by caller).
    pub budget_consumed: u64,
}

impl EvaluationResult {
    /// Creates an allow result.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // String is not const-constructible
    pub fn allowed(
        rule_id: String,
        rationale_code: String,
        policy_hash: [u8; 32],
        message: String,
    ) -> Self {
        Self {
            decision: Decision::Allow,
            rule_id,
            rationale_code,
            policy_hash,
            message,
            budget_consumed: 0,
        }
    }

    /// Creates a deny result.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // String is not const-constructible
    pub fn denied(
        rule_id: String,
        rationale_code: String,
        policy_hash: [u8; 32],
        message: String,
    ) -> Self {
        Self {
            decision: Decision::Deny,
            rule_id,
            rationale_code,
            policy_hash,
            message,
            budget_consumed: 0,
        }
    }

    /// Returns true if the decision is allow.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }

    /// Returns true if the decision is deny.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self.decision, Decision::Deny)
    }

    /// Sets the budget consumed.
    #[must_use]
    pub const fn with_budget_consumed(mut self, budget: u64) -> Self {
        self.budget_consumed = budget;
        self
    }

    /// Converts this result to a `ToolDecided` event.
    #[must_use]
    pub fn to_tool_decided(&self, request_id: &str) -> ToolDecided {
        ToolDecided {
            request_id: request_id.to_string(),
            decision: if self.is_allowed() {
                "ALLOW".to_string()
            } else {
                "DENY".to_string()
            },
            rule_id: self.rule_id.clone(),
            policy_hash: self.policy_hash.to_vec(),
            rationale_code: self.rationale_code.clone(),
            budget_consumed: self.budget_consumed,
        }
    }
}

/// Extracts the tool name from a tool request.
fn get_tool_name(tool: &tool_request::Tool) -> String {
    match tool {
        tool_request::Tool::FileRead(_) => "fs.read".to_string(),
        tool_request::Tool::FileWrite(_) => "fs.write".to_string(),
        tool_request::Tool::FileEdit(_) => "fs.edit".to_string(),
        tool_request::Tool::ShellExec(_) => "shell.exec".to_string(),
        tool_request::Tool::GitOp(op) => format!("git.{}", op.operation.to_lowercase()),
        tool_request::Tool::Inference(_) => "inference".to_string(),
        tool_request::Tool::ArtifactPublish(_) => "artifact.publish".to_string(),
    }
}

/// Checks if a pattern matches a value.
///
/// Supports:
/// - Exact match: `"fs.read"` matches `"fs.read"`
/// - Wildcard: `"*"` matches anything
/// - Prefix wildcard: `"fs.*"` matches `"fs.read"`, `"fs.write"`, etc.
fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if let Some(prefix) = pattern.strip_suffix(".*") {
        return value.starts_with(prefix)
            && (value.len() == prefix.len() || value.chars().nth(prefix.len()) == Some('.'));
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    pattern == value
}

/// Checks if a path matches any of the given path patterns.
///
/// Supports glob-like patterns:
/// - `*` matches any single path component
/// - `**` matches zero or more path components
/// - Exact paths are matched literally
fn matches_any_path_pattern(patterns: &[String], path: &str) -> bool {
    for pattern in patterns {
        if matches_path_pattern(pattern, path) {
            return true;
        }
    }
    false
}

/// Checks if a path matches a single path pattern.
fn matches_path_pattern(pattern: &str, path: &str) -> bool {
    // Handle common cases
    if pattern == path {
        return true;
    }

    if pattern == "**" || pattern == "**/*" {
        return true;
    }

    // Normalize paths (remove leading ./ if present)
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let path = path.strip_prefix("./").unwrap_or(path);

    // Handle ** (match any number of directories)
    if pattern.contains("**") {
        return matches_glob_double_star(pattern, path);
    }

    // Handle * (match single component)
    if pattern.contains('*') {
        return matches_glob_single_star(pattern, path);
    }

    // Exact match
    pattern == path
}

/// Matches a pattern containing `**` against a path.
fn matches_glob_double_star(pattern: &str, path: &str) -> bool {
    // Split pattern by **
    let parts: Vec<&str> = pattern.split("**").collect();

    if parts.len() == 2 {
        let prefix = parts[0];
        let suffix = parts[1];

        // Handle "./**" pattern (match anything in current dir)
        if prefix.is_empty() || prefix == "/" {
            if suffix.is_empty() || suffix == "/" {
                return true;
            }
            // Suffix after ** - check if path ends with it
            if let Some(suffix) = suffix.strip_prefix('/') {
                // Path must contain the suffix somewhere
                return path.ends_with(suffix) || path.contains(&format!("/{suffix}"));
            }
            return true;
        }

        // Check prefix
        let prefix = prefix.trim_end_matches('/');
        if !path.starts_with(prefix) {
            return false;
        }

        // Check suffix if present
        if suffix.is_empty() || suffix == "/" {
            return true;
        }

        // Path must end with suffix
        let suffix = suffix.trim_start_matches('/');
        let remaining = &path[prefix.len()..];
        remaining.ends_with(suffix) || remaining.contains(&format!("/{suffix}"))
    } else {
        // Complex pattern - fall back to simple matching
        pattern == path
    }
}

/// Matches a pattern containing single `*` (not `**`) against a path.
fn matches_glob_single_star(pattern: &str, path: &str) -> bool {
    // Split by * and check if parts match
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() != 2 {
        // Multiple stars - complex pattern
        return false;
    }

    let prefix = parts[0];
    let suffix = parts[1];

    // Check prefix and suffix
    if !path.starts_with(prefix) || !path.ends_with(suffix) {
        return false;
    }

    // The matched portion should not contain path separator
    let matched_len = path.len() - prefix.len() - suffix.len();
    if matched_len > 0 {
        let matched = &path[prefix.len()..path.len() - suffix.len()];
        // Single * should not match path separators
        !matched.contains('/')
    } else {
        true
    }
}

/// Checks if a command matches any of the given command patterns.
fn matches_any_command_pattern(patterns: &[String], command: &str) -> bool {
    for pattern in patterns {
        if matches_command_pattern(pattern, command) {
            return true;
        }
    }
    false
}

/// Checks if a command matches a pattern.
///
/// Supports:
/// - Exact match
/// - Prefix match with `*`
/// - Contains match with `*...*`
fn matches_command_pattern(pattern: &str, command: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Check if pattern is a prefix match (e.g., "cargo *")
    if let Some(prefix) = pattern.strip_suffix('*') {
        // Only apply prefix match if there's no other wildcard
        if !prefix.contains('*') {
            return command.starts_with(prefix);
        }
        // Otherwise fall through to handle multiple wildcards
    }

    // Check if pattern contains wildcards
    if pattern.contains('*') {
        // Simple wildcard matching
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return command.starts_with(parts[0]) && command.ends_with(parts[1]);
        }
    }

    // Exact match
    pattern == command
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::{FileEdit, FileRead, FileWrite, GitOperation, InferenceCall, ShellExec};

    fn create_test_policy(yaml: &str) -> LoadedPolicy {
        LoadedPolicy::from_yaml(yaml).expect("valid test policy")
    }

    fn create_file_read_request(path: &str) -> ToolRequest {
        ToolRequest {
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileRead(FileRead {
                path: path.to_string(),
                offset: 0,
                limit: 0,
            })),
        }
    }

    fn create_file_write_request(path: &str) -> ToolRequest {
        ToolRequest {
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileWrite(FileWrite {
                path: path.to_string(),
                content: vec![],
                create_only: false,
                append: false,
            })),
        }
    }

    fn create_shell_exec_request(command: &str) -> ToolRequest {
        ToolRequest {
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ShellExec(ShellExec {
                command: command.to_string(),
                cwd: String::new(),
                timeout_ms: 0,
                network_access: false,
                env: vec![],
            })),
        }
    }

    // ========================================================================
    // Default-Deny Tests
    // ========================================================================

    #[test]
    fn test_default_deny_no_matching_rule() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-specific-file"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/allowed/path.txt"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Request for different file should be denied
        let request = create_file_read_request("/other/file.txt");
        let result = engine.evaluate(&request);

        assert!(result.is_denied());
        assert_eq!(result.rule_id, DEFAULT_DENY_RULE_ID);
        assert_eq!(result.rationale_code, DEFAULT_DENY_RATIONALE);
    }

    #[test]
    fn test_default_deny_empty_policy() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "empty"
  rules:
    - id: "placeholder"
      type: budget
      budget_type: token
      limit: 1000
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Any tool request should be denied (budget rules don't match tools)
        let request = create_file_read_request("/any/path.txt");
        let result = engine.evaluate(&request);

        assert!(result.is_denied());
    }

    // ========================================================================
    // Allow Rule Tests
    // ========================================================================

    #[test]
    fn test_allow_rule_matches() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-workspace"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = create_file_read_request("/workspace/src/main.rs");
        let result = engine.evaluate(&request);

        assert!(result.is_allowed());
        assert_eq!(result.rule_id, "allow-workspace");
    }

    #[test]
    fn test_allow_rule_with_wildcard_tool() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-all-fs"
      type: tool_allow
      tool: "fs.*"
      paths:
        - "**"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Should match fs.read
        let request = create_file_read_request("/any/path.txt");
        let result = engine.evaluate(&request);
        assert!(result.is_allowed());

        // Should match fs.write
        let request = create_file_write_request("/any/path.txt");
        let result = engine.evaluate(&request);
        assert!(result.is_allowed());
    }

    // ========================================================================
    // Deny Rule Tests (Deny Overrides Allow)
    // ========================================================================

    #[test]
    fn test_deny_rule_before_allow() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "deny-secrets"
      type: tool_deny
      tool: "fs.read"
      paths:
        - "/etc/passwd"
        - "/etc/shadow"
      decision: deny
    - id: "allow-all"
      type: tool_allow
      tool: "fs.*"
      paths:
        - "**"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Secret file should be denied (deny rule comes first)
        let request = create_file_read_request("/etc/passwd");
        let result = engine.evaluate(&request);
        assert!(result.is_denied());
        assert_eq!(result.rule_id, "deny-secrets");

        // Other files should be allowed
        let request = create_file_read_request("/home/user/file.txt");
        let result = engine.evaluate(&request);
        assert!(result.is_allowed());
        assert_eq!(result.rule_id, "allow-all");
    }

    #[test]
    fn test_first_matching_rule_wins() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "rule-1"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: allow
      rationale_code: "FIRST_RULE"
    - id: "rule-2"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: deny
      rationale_code: "SECOND_RULE"
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = create_file_read_request("/workspace/file.txt");
        let result = engine.evaluate(&request);

        // First matching rule should win
        assert!(result.is_allowed());
        assert_eq!(result.rule_id, "rule-1");
        assert_eq!(result.rationale_code, "FIRST_RULE");
    }

    // ========================================================================
    // Path Pattern Tests
    // ========================================================================

    #[test]
    fn test_path_pattern_exact_match() {
        assert!(matches_path_pattern("/exact/path.txt", "/exact/path.txt"));
        assert!(!matches_path_pattern("/exact/path.txt", "/other/path.txt"));
    }

    #[test]
    fn test_path_pattern_double_star() {
        // ** matches everything
        assert!(matches_path_pattern("**", "/any/path/here.txt"));
        assert!(matches_path_pattern("**/*", "/any/path/here.txt"));

        // prefix/**
        assert!(matches_path_pattern("/workspace/**", "/workspace/file.txt"));
        assert!(matches_path_pattern(
            "/workspace/**",
            "/workspace/deep/nested/file.txt"
        ));
        assert!(!matches_path_pattern("/workspace/**", "/other/file.txt"));

        // ./** (current directory)
        assert!(matches_path_pattern("./**", "./src/main.rs"));
        assert!(matches_path_pattern("./**", "src/main.rs"));
    }

    #[test]
    fn test_path_pattern_single_star() {
        // Single * should not match path separators
        assert!(matches_path_pattern(
            "/workspace/*.txt",
            "/workspace/file.txt"
        ));
        assert!(!matches_path_pattern(
            "/workspace/*.txt",
            "/workspace/nested/file.txt"
        ));
    }

    // ========================================================================
    // Command Pattern Tests
    // ========================================================================

    #[test]
    fn test_command_pattern_exact() {
        assert!(matches_command_pattern("cargo test", "cargo test"));
        assert!(!matches_command_pattern("cargo test", "cargo build"));
    }

    #[test]
    fn test_command_pattern_prefix() {
        assert!(matches_command_pattern("cargo *", "cargo test"));
        assert!(matches_command_pattern("cargo *", "cargo build --release"));
        assert!(!matches_command_pattern("cargo *", "npm install"));
    }

    #[test]
    fn test_command_pattern_wildcard() {
        assert!(matches_command_pattern("*", "anything"));
        assert!(matches_command_pattern("*", "cargo test"));
    }

    // ========================================================================
    // Tool Name Pattern Tests
    // ========================================================================

    #[test]
    fn test_tool_pattern_exact() {
        assert!(matches_pattern("fs.read", "fs.read"));
        assert!(!matches_pattern("fs.read", "fs.write"));
    }

    #[test]
    fn test_tool_pattern_wildcard() {
        assert!(matches_pattern("*", "fs.read"));
        assert!(matches_pattern("*", "shell.exec"));
    }

    #[test]
    fn test_tool_pattern_prefix() {
        assert!(matches_pattern("fs.*", "fs.read"));
        assert!(matches_pattern("fs.*", "fs.write"));
        assert!(!matches_pattern("fs.*", "shell.exec"));
    }

    // ========================================================================
    // Evaluation Result Tests
    // ========================================================================

    #[test]
    fn test_evaluation_result_to_tool_decided() {
        let result = EvaluationResult::allowed(
            "test-rule".to_string(),
            "TEST_ALLOWED".to_string(),
            [0u8; 32],
            "Test message".to_string(),
        )
        .with_budget_consumed(100);

        let decided = result.to_tool_decided("req-123");

        assert_eq!(decided.request_id, "req-123");
        assert_eq!(decided.decision, "ALLOW");
        assert_eq!(decided.rule_id, "test-rule");
        assert_eq!(decided.rationale_code, "TEST_ALLOWED");
        assert_eq!(decided.budget_consumed, 100);
        assert_eq!(decided.policy_hash.len(), 32);
    }

    #[test]
    fn test_evaluation_result_deny_to_tool_decided() {
        let result = EvaluationResult::denied(
            "deny-rule".to_string(),
            "ACCESS_DENIED".to_string(),
            [1u8; 32],
            "Access denied".to_string(),
        );

        let decided = result.to_tool_decided("req-456");

        assert_eq!(decided.decision, "DENY");
        assert_eq!(decided.rule_id, "deny-rule");
    }

    // ========================================================================
    // Missing Tool Tests
    // ========================================================================

    #[test]
    fn test_missing_tool_denied() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-all"
      type: tool_allow
      tool: "*"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = ToolRequest {
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: None, // No tool specified
        };

        let result = engine.evaluate(&request);

        assert!(result.is_denied());
        assert_eq!(result.rationale_code, "MISSING_TOOL");
    }

    // ========================================================================
    // Shell Exec Tests
    // ========================================================================

    #[test]
    fn test_shell_exec_command_pattern() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-cargo"
      type: tool_allow
      tool: "shell.exec"
      commands:
        - "cargo *"
      decision: allow
    - id: "deny-rm"
      type: tool_deny
      tool: "shell.exec"
      commands:
        - "rm *"
      decision: deny
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Cargo commands should be allowed
        let request = create_shell_exec_request("cargo test");
        let result = engine.evaluate(&request);
        assert!(result.is_allowed());

        // rm commands should be denied
        let request = create_shell_exec_request("rm -rf /");
        let result = engine.evaluate(&request);
        assert!(result.is_denied());
        assert_eq!(result.rule_id, "deny-rm");

        // Other commands should be denied by default
        let request = create_shell_exec_request("ls -la");
        let result = engine.evaluate(&request);
        assert!(result.is_denied());
        assert_eq!(result.rule_id, DEFAULT_DENY_RULE_ID);
    }

    // ========================================================================
    // Inference Tests
    // ========================================================================

    #[test]
    fn test_inference_rule() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-inference"
      type: inference
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = ToolRequest {
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "anthropic".to_string(),
                model: "claude-3".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 1000,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };

        let result = engine.evaluate(&request);
        assert!(result.is_allowed());
        assert_eq!(result.rule_id, "allow-inference");
    }

    // ========================================================================
    // Policy Hash Tests
    // ========================================================================

    #[test]
    fn test_policy_hash_included() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-all"
      type: tool_allow
      tool: "*"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = create_file_read_request("/any/path.txt");
        let result = engine.evaluate(&request);

        // Policy hash should be non-zero and match
        assert_eq!(result.policy_hash, policy.content_hash);
        assert_ne!(result.policy_hash, [0u8; 32]);
    }

    // ========================================================================
    // Git Operation Tests
    // ========================================================================

    #[test]
    fn test_git_operation_matching() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-git-read"
      type: tool_allow
      tool: "git.*"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = ToolRequest {
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::GitOp(GitOperation {
                operation: "DIFF".to_string(),
                args: vec!["--cached".to_string()],
                cwd: String::new(),
            })),
        };

        let result = engine.evaluate(&request);
        assert!(result.is_allowed());
    }

    // ========================================================================
    // Filesystem Rule Tests
    // ========================================================================

    #[test]
    fn test_filesystem_rule_matches_all_file_ops() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-workspace"
      type: filesystem
      paths:
        - "/workspace/**"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // FileRead
        let request = create_file_read_request("/workspace/file.txt");
        assert!(engine.evaluate(&request).is_allowed());

        // FileWrite
        let request = create_file_write_request("/workspace/file.txt");
        assert!(engine.evaluate(&request).is_allowed());

        // FileEdit
        let request = ToolRequest {
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::FileEdit(FileEdit {
                path: "/workspace/file.txt".to_string(),
                old_content: "old".to_string(),
                new_content: "new".to_string(),
            })),
        };
        assert!(engine.evaluate(&request).is_allowed());
    }

    // ========================================================================
    // Proptest Fuzz Tests
    // ========================================================================

    mod fuzz {
        use proptest::prelude::*;

        use super::*;

        // Strategy for generating valid file paths
        fn path_strategy() -> impl Strategy<Value = String> {
            prop_oneof![
                // Absolute paths
                "[/][a-z]{1,10}(/[a-z]{1,10}){0,5}(\\.[a-z]{1,4})?".prop_map(String::from),
                // Relative paths
                "[a-z]{1,10}(/[a-z]{1,10}){0,5}(\\.[a-z]{1,4})?".prop_map(String::from),
                // Workspace paths
                Just("/workspace/".to_string()),
                Just("/workspace/src/main.rs".to_string()),
                Just("./src/lib.rs".to_string()),
            ]
        }

        // Strategy for generating shell commands
        fn command_strategy() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("cargo test".to_string()),
                Just("cargo build".to_string()),
                Just("npm install".to_string()),
                Just("ls -la".to_string()),
                Just("rm -rf /".to_string()),
                "[a-z]{1,10}( -[a-z]{1,5})*( [a-z/\\.]{1,20})?".prop_map(String::from),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Property: Default-deny policy should always deny when no rules match
            #[test]
            fn prop_default_deny_always_denies_unmatched(path in path_strategy()) {
                let yaml = r#"
policy:
  version: "1.0.0"
  name: "empty"
  rules:
    - id: "placeholder"
      type: budget
      budget_type: token
      limit: 1000
      decision: allow
  default_decision: deny
"#;
                let policy = create_test_policy(yaml);
                let engine = PolicyEngine::new(&policy);

                let request = create_file_read_request(&path);
                let result = engine.evaluate(&request);

                // Budget rules don't match file operations, so should always be denied
                prop_assert!(result.is_denied());
                prop_assert_eq!(&result.rule_id, DEFAULT_DENY_RULE_ID);
            }

            /// Property: Exact path match should always allow
            #[test]
            fn prop_exact_path_match_allows(path in path_strategy()) {
                // Escape special YAML characters in the path
                let escaped_path = path.replace('\\', "\\\\").replace('"', "\\\"");
                let yaml = format!(r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-exact"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "{escaped_path}"
      decision: allow
  default_decision: deny
"#);
                if let Ok(policy) = LoadedPolicy::from_yaml(&yaml) {
                    let engine = PolicyEngine::new(&policy);
                    let request = create_file_read_request(&path);
                    let result = engine.evaluate(&request);

                    prop_assert!(result.is_allowed());
                    prop_assert_eq!(&result.rule_id, "allow-exact");
                }
            }

            /// Property: Wildcard tool should match all file operations
            #[test]
            fn prop_wildcard_tool_matches_all(path in path_strategy()) {
                let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-all"
      type: tool_allow
      tool: "*"
      paths:
        - "**"
      decision: allow
  default_decision: deny
"#;
                let policy = create_test_policy(yaml);
                let engine = PolicyEngine::new(&policy);

                let request = create_file_read_request(&path);
                let result = engine.evaluate(&request);

                prop_assert!(result.is_allowed());
            }

            /// Property: Deny rules should override subsequent allow rules
            #[test]
            fn prop_deny_overrides_allow(path in path_strategy()) {
                let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "deny-all"
      type: tool_deny
      tool: "*"
      paths:
        - "**"
      decision: deny
    - id: "allow-all"
      type: tool_allow
      tool: "*"
      paths:
        - "**"
      decision: allow
  default_decision: deny
"#;
                let policy = create_test_policy(yaml);
                let engine = PolicyEngine::new(&policy);

                let request = create_file_read_request(&path);
                let result = engine.evaluate(&request);

                // First rule (deny) should win
                prop_assert!(result.is_denied());
                prop_assert_eq!(&result.rule_id, "deny-all");
            }

            /// Property: Shell commands matching allow pattern should be allowed
            #[test]
            fn prop_shell_allow_pattern_matches(cmd in command_strategy()) {
                if cmd.starts_with("cargo") {
                    let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-cargo"
      type: tool_allow
      tool: "shell.exec"
      commands:
        - "cargo *"
      decision: allow
  default_decision: deny
"#;
                    let policy = create_test_policy(yaml);
                    let engine = PolicyEngine::new(&policy);

                    let request = create_shell_exec_request(&cmd);
                    let result = engine.evaluate(&request);

                    prop_assert!(result.is_allowed());
                }
            }

            /// Property: Evaluation result should always include valid policy hash
            #[test]
            fn prop_result_includes_policy_hash(path in path_strategy()) {
                let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "rule"
      type: tool_allow
      tool: "fs.read"
      decision: allow
  default_decision: deny
"#;
                let policy = create_test_policy(yaml);
                let engine = PolicyEngine::new(&policy);

                let request = create_file_read_request(&path);
                let result = engine.evaluate(&request);

                // Hash should always be set and match the policy
                prop_assert_eq!(result.policy_hash, policy.content_hash);
                prop_assert_ne!(result.policy_hash, [0u8; 32]);
            }

            /// Property: ToolDecided conversion should preserve all fields
            #[test]
            fn prop_tool_decided_preserves_fields(
                request_id in "[a-z]{1,10}-[0-9]{1,5}",
                budget in 0u64..10000u64
            ) {
                let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "test-rule"
      type: tool_allow
      tool: "fs.read"
      decision: allow
      rationale_code: "TEST_CODE"
  default_decision: deny
"#;
                let policy = create_test_policy(yaml);
                let engine = PolicyEngine::new(&policy);

                let request = create_file_read_request("/test/path.txt");
                let result = engine.evaluate(&request).with_budget_consumed(budget);
                let decided = result.to_tool_decided(&request_id);

                prop_assert_eq!(&decided.request_id, &request_id);
                prop_assert_eq!(&decided.rule_id, &result.rule_id);
                prop_assert_eq!(&decided.rationale_code, &result.rationale_code);
                prop_assert_eq!(decided.budget_consumed, budget);
                prop_assert_eq!(decided.policy_hash.len(), 32);
            }

            /// Property: Path pattern matching should be deterministic
            #[test]
            fn prop_path_matching_is_deterministic(
                pattern in "[/]?[a-z*]{1,5}(/[a-z*]{1,5})*",
                path in "[/]?[a-z]{1,5}(/[a-z]{1,5})*"
            ) {
                let result1 = matches_path_pattern(&pattern, &path);
                let result2 = matches_path_pattern(&pattern, &path);
                prop_assert_eq!(result1, result2);
            }
        }
    }
}
