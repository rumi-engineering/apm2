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
//! - **Path traversal protection**: Paths containing `..` are always rejected
//!
//! # Path Pattern Limitations
//!
//! The current implementation supports limited glob patterns:
//!
//! - **Exact match**: `/path/to/file.txt`
//! - **Double-star** (`**`): Matches any number of path components
//!   - `**` or `**/*` - matches everything
//!   - `/prefix/**` - matches anything under prefix
//! - **Single-star** (`*`): Matches a single path component (no slashes)
//!   - `/dir/*.txt` - matches files ending in `.txt` directly in `/dir`
//!
//! **Not supported** (patterns fall back to exact match):
//! - Multiple wildcards: `src/*/*.rs`, `test/**/*.json`
//! - Complex patterns: `{a,b}`, `[0-9]`
//!
//! For complex matching needs, consider using multiple simpler rules.
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
//! let request = ToolRequest { consumption_mode: false,
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

use super::event::create_policy_violation_event;
use super::parser::LoadedPolicy;
use super::schema::{Decision, Rule, RuleType};
use crate::budget::BudgetTracker;
use crate::events::{PolicyEvent, ToolDecided};
use crate::tool::{ToolRequest, tool_request};

/// Special rule ID for default-deny decisions.
pub const DEFAULT_DENY_RULE_ID: &str = "DEFAULT_DENY";

/// Rule ID used when a request is denied due to budget exceeded.
pub const BUDGET_EXCEEDED_RULE_ID: &str = "BUDGET_EXCEEDED";

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
            if let Some(result) =
                self.evaluate_rule(rule, tool, &tool_name, request.consumption_mode)
            {
                return result;
            }
        }

        // No rule matched - apply default decision
        self.apply_default_decision(&tool_name)
    }

    /// Evaluates a tool request against the policy with budget enforcement.
    ///
    /// This method first checks if any budget is exceeded. If so, the request
    /// is immediately denied with the `BUDGET_EXCEEDED` rule ID. Otherwise,
    /// normal policy evaluation proceeds.
    ///
    /// # Budget Enforcement
    ///
    /// Budget checks are performed **before** policy evaluation as a
    /// fail-closed gate. This ensures that:
    /// - Requests are denied when any budget is exceeded
    /// - Policy rules cannot override budget limits
    /// - Budget exhaustion is caught even for otherwise-allowed operations
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use apm2_core::budget::{BudgetConfig, BudgetTracker};
    /// use apm2_core::policy::{LoadedPolicy, PolicyEngine};
    ///
    /// let policy = LoadedPolicy::from_yaml("...").unwrap();
    /// let engine = PolicyEngine::new(&policy);
    /// let tracker = BudgetTracker::new("session-123", BudgetConfig::default());
    ///
    /// let result = engine.evaluate_with_budget(&request, &tracker);
    /// if result.is_denied() && result.rule_id == "BUDGET_EXCEEDED" {
    ///     // Handle budget exceeded - emit BudgetExceeded event
    /// }
    /// ```
    #[must_use]
    pub fn evaluate_with_budget(
        &self,
        request: &ToolRequest,
        budget_tracker: &BudgetTracker,
    ) -> EvaluationResult {
        // Check budget first (fail-closed gate)
        if let Some(exceeded_type) = budget_tracker.first_exceeded() {
            return EvaluationResult::denied(
                BUDGET_EXCEEDED_RULE_ID.to_string(),
                format!("{}_BUDGET_EXCEEDED", exceeded_type.as_str()),
                self.policy.content_hash,
                format!(
                    "{} budget exceeded: consumed {} of {} limit",
                    exceeded_type,
                    budget_tracker.consumed(exceeded_type),
                    budget_tracker.limit(exceeded_type)
                ),
            );
        }

        // Budget OK - proceed with normal policy evaluation
        self.evaluate(request)
    }

    /// Evaluates a single rule against a tool request.
    ///
    /// Returns `Some(EvaluationResult)` if the rule matches, `None` otherwise.
    fn evaluate_rule(
        &self,
        rule: &Rule,
        tool: &tool_request::Tool,
        tool_name: &str,
        consumption_mode: bool,
    ) -> Option<EvaluationResult> {
        // Check if the rule type applies to this tool
        if !Self::rule_applies_to_tool(rule, tool, tool_name, consumption_mode) {
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
    fn rule_applies_to_tool(
        rule: &Rule,
        tool: &tool_request::Tool,
        tool_name: &str,
        consumption_mode: bool,
    ) -> bool {
        match rule.rule_type {
            RuleType::ToolAllow | RuleType::ToolDeny => {
                // If consumption_mode is true, standard tool rules DO NOT apply to
                // ArtifactFetch
                if consumption_mode && matches!(tool, tool_request::Tool::ArtifactFetch(_)) {
                    return false;
                }
                Self::matches_tool_rule(rule, tool, tool_name)
            },
            RuleType::ConsumptionMode => {
                if !consumption_mode {
                    return false;
                }
                Self::matches_consumption_mode_rule(rule, tool)
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
    ///
    /// # Security
    ///
    /// This function always blocks path traversal attempts in filesystem
    /// operations, even when no specific path restrictions are configured.
    /// This prevents "allow all fs operations" rules from being exploited.
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
                // Security: Always block traversal, even with empty paths
                if contains_path_traversal(&req.path) {
                    return false;
                }
                if !rule.paths.is_empty() {
                    return matches_any_path_pattern(&rule.paths, &req.path);
                }
            },
            tool_request::Tool::FileWrite(req) => {
                // Security: Always block traversal, even with empty paths
                if contains_path_traversal(&req.path) {
                    return false;
                }
                if !rule.paths.is_empty() {
                    return matches_any_path_pattern(&rule.paths, &req.path);
                }
            },
            tool_request::Tool::FileEdit(req) => {
                // Security: Always block traversal, even with empty paths
                if contains_path_traversal(&req.path) {
                    return false;
                }
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
            | tool_request::Tool::ArtifactPublish(_)
            | tool_request::Tool::ArtifactFetch(_) => {
                // No path/command restrictions for these by default
            },
        }

        // If no specific restrictions, the tool name match is sufficient
        true
    }

    /// Checks if a filesystem rule matches the request.
    ///
    /// # Security
    ///
    /// This function always checks for path traversal components (`..`) even
    /// when no specific paths are configured. This ensures that an "allow all
    /// paths" rule cannot be exploited via directory traversal attacks.
    fn matches_filesystem_rule(rule: &Rule, tool: &tool_request::Tool) -> bool {
        // Filesystem rules apply to FileRead, FileWrite, FileEdit
        let path = match tool {
            tool_request::Tool::FileRead(req) => &req.path,
            tool_request::Tool::FileWrite(req) => &req.path,
            tool_request::Tool::FileEdit(req) => &req.path,
            _ => return false,
        };

        // Security: Always block path traversal attempts, even for rules
        // that don't specify explicit path restrictions. This prevents
        // "allow all" rules from being exploited via ../../../etc/passwd.
        if contains_path_traversal(path) {
            return false;
        }

        if rule.paths.is_empty() {
            // No paths specified - matches all filesystem operations
            // (traversal already blocked above)
            return true;
        }

        matches_any_path_pattern(&rule.paths, path)
    }

    /// Checks if a network rule matches the request.
    ///
    /// # Security
    ///
    /// Network rules follow fail-closed semantics. If a rule specifies host
    /// restrictions but we cannot verify the request's target host, the rule
    /// does NOT match (fails closed). This prevents host restrictions from
    /// being bypassed.
    fn matches_network_rule(rule: &Rule, tool: &tool_request::Tool) -> bool {
        // Network rules apply to ShellExec with network_access
        // and potentially Inference calls
        match tool {
            tool_request::Tool::ShellExec(req) => {
                // Only apply if network access is requested
                if !req.network_access {
                    return false;
                }
                // Security: If rule specifies hosts/ports, we can't fully match
                // here because we don't know the target host from the command.
                // Fail closed: if hosts are specified but can't be verified, don't match.
                if !rule.hosts.is_empty() {
                    // Cannot verify shell command targets - fail closed
                    return false;
                }
                // No host restrictions - match if network access is requested
                true
            },
            tool_request::Tool::Inference(req) => {
                // Inference calls always require network
                // Security: If host restrictions are specified, verify the provider
                if !rule.hosts.is_empty() {
                    // Check if the provider matches any allowed host
                    // Fail closed: if provider doesn't match any host, don't match
                    //
                    // Security: Use strict matching to prevent confusion attacks.
                    // - Exact match: "anthropic" matches only "anthropic"
                    // - Subdomain match: "anthropic" also allows "api.anthropic" (provider ends
                    //   with ".{host}")
                    // - Full domain match: "anthropic.com" matches "anthropic.com" or
                    //   "api.anthropic.com"
                    //
                    // NEVER use `contains` - it would allow "google.malicious.com"
                    // to match a rule allowing "google".
                    let provider_matches = rule.hosts.iter().any(|host| {
                        // Exact match
                        req.provider == *host
                            // Provider is a subdomain of host (e.g., "api.anthropic" for "anthropic")
                            || req.provider.ends_with(&format!(".{host}"))
                    });
                    if !provider_matches {
                        return false;
                    }
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

    /// Checks if a consumption mode rule matches the request.
    fn matches_consumption_mode_rule(rule: &Rule, tool: &tool_request::Tool) -> bool {
        let tool_request::Tool::ArtifactFetch(req) = tool else {
            return false;
        };

        // Content-hash-only fetch is never allowed by a consumption_mode rule
        if req.stable_id.is_empty() {
            return false;
        }

        if rule.stable_ids.is_empty() {
            // No specific IDs listed - matches all stable_id fetches
            return true;
        }

        rule.stable_ids.contains(&req.stable_id)
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

    /// Converts this result to a `PolicyViolation` event if denied.
    ///
    /// Returns `None` if the decision was `Allow`.
    #[must_use]
    pub fn to_policy_violation_event(&self, session_id: &str) -> Option<PolicyEvent> {
        if self.is_allowed() {
            return None;
        }

        Some(create_policy_violation_event(
            session_id.to_string(),
            self.rationale_code.clone(), // Use rationale code as violation type
            self.rule_id.clone(),
            self.message.clone(),
        ))
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
        tool_request::Tool::ArtifactFetch(_) => "artifact.fetch".to_string(),
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

/// Checks if a path contains path traversal components.
///
/// Returns `true` if the path contains `..` components that could be used
/// to escape directory restrictions. This is a security check to prevent
/// path traversal attacks.
///
/// # Security
///
/// This function checks for both `/` and `\` separators to handle
/// cross-platform path formats. While APM2 primarily targets Unix systems,
/// checking for both separators provides defense-in-depth against path
/// manipulation attacks that might use Windows-style separators.
fn contains_path_traversal(path: &str) -> bool {
    // Split path by both / and \ to handle cross-platform paths
    // This provides defense-in-depth against path manipulation attacks
    for component in path.split(['/', '\\']) {
        if component == ".." {
            return true;
        }
    }
    false
}

/// Checks if a path matches a single path pattern.
///
/// # Security
///
/// This function rejects paths containing `..` components to prevent
/// path traversal attacks. A path like `/workspace/../etc/passwd` will
/// never match a pattern like `/workspace/**` even though it textually
/// starts with `/workspace/`.
fn matches_path_pattern(pattern: &str, path: &str) -> bool {
    // Security: reject paths with traversal components
    // This prevents attacks like /workspace/../etc/passwd matching /workspace/**
    if contains_path_traversal(path) {
        return false;
    }

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
///
/// # Security
///
/// This function ensures path component boundaries are respected:
/// - `/workspace/**` must NOT match `/workspaces` (different directory)
/// - `**/Cargo.toml` must NOT match `/Cargo.toml.bak` (different file)
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
            // Suffix after ** - must match exact path component at end
            if let Some(suffix) = suffix.strip_prefix('/') {
                // Security: Must match exactly at end of path (full component)
                // e.g., **/Cargo.toml must NOT match /Cargo.toml.bak
                return path.ends_with(&format!("/{suffix}")) || path == suffix;
            }
            return true;
        }

        // Check prefix with path component boundary
        let prefix = prefix.trim_end_matches('/');
        if !path.starts_with(prefix) {
            return false;
        }

        // Security: Ensure prefix matches a full path component
        // /workspace/** must NOT match /workspaces
        let remaining_after_prefix = &path[prefix.len()..];
        if !remaining_after_prefix.is_empty()
            && !remaining_after_prefix.starts_with('/')
            && prefix != "/"
        {
            // The path continues without a separator, so it's a different directory
            // e.g., prefix="/workspace" but path="/workspaces/file"
            return false;
        }

        // Check suffix if present
        if suffix.is_empty() || suffix == "/" {
            return true;
        }

        // Path must end with suffix (as a complete component)
        let suffix = suffix.trim_start_matches('/');
        // Security: suffix must match a complete path component at the end
        // e.g., **/Cargo.toml must NOT match /foo/Cargo.toml.bak
        remaining_after_prefix.ends_with(&format!("/{suffix}"))
            || remaining_after_prefix
                .strip_prefix('/')
                .is_some_and(|r| r == suffix)
    } else {
        // Complex pattern - fall back to simple matching
        pattern == path
    }
}

/// Matches a pattern containing single `*` (not `**`) against a path.
///
/// # Safety
///
/// This function guards against arithmetic underflow by checking that
/// the path is long enough to contain both prefix and suffix.
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

    // Security: Guard against arithmetic underflow
    // If path is shorter than prefix + suffix combined, the match is ambiguous
    // e.g., pattern "a*a" with path "a" would underflow
    if path.len() < prefix.len() + suffix.len() {
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
            consumption_mode: false,
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
            consumption_mode: false,
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
            consumption_mode: false,
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
    fn test_path_pattern_component_boundaries() {
        // Security: Prefix must match full path component
        // /workspace/** must NOT match /workspaces (different directory)
        assert!(!matches_path_pattern("/workspace/**", "/workspaces"));
        assert!(!matches_path_pattern(
            "/workspace/**",
            "/workspaces/file.txt"
        ));
        assert!(!matches_path_pattern("/workspace/**", "/workspace-backup"));
        assert!(!matches_path_pattern(
            "/workspace/**",
            "/workspace-backup/file.txt"
        ));

        // But should match /workspace exactly and its children
        assert!(matches_path_pattern("/workspace/**", "/workspace"));
        assert!(matches_path_pattern("/workspace/**", "/workspace/"));
        assert!(matches_path_pattern("/workspace/**", "/workspace/file.txt"));

        // Security: Suffix must match exact file name at end
        // **/Cargo.toml must NOT match /Cargo.toml.bak
        assert!(!matches_path_pattern("**/Cargo.toml", "/Cargo.toml.bak"));
        assert!(!matches_path_pattern(
            "**/Cargo.toml",
            "/foo/Cargo.toml.bak"
        ));
        assert!(!matches_path_pattern(
            "**/Cargo.toml",
            "/foo/Cargo.toml.backup"
        ));

        // But should match exact Cargo.toml
        assert!(matches_path_pattern("**/Cargo.toml", "/Cargo.toml"));
        assert!(matches_path_pattern("**/Cargo.toml", "/foo/Cargo.toml"));
        assert!(matches_path_pattern("**/Cargo.toml", "/foo/bar/Cargo.toml"));
        assert!(matches_path_pattern("**/Cargo.toml", "Cargo.toml"));
    }

    #[test]
    fn test_single_star_underflow_protection() {
        // Security: Prevent arithmetic underflow with overlapping prefix/suffix
        // Pattern "a*a" with path "a" should NOT panic
        assert!(!matches_path_pattern("a*a", "a"));
        assert!(!matches_path_pattern("ab*ab", "ab"));
        assert!(!matches_path_pattern("/foo*bar", "/foo"));
        assert!(!matches_path_pattern("/foo*bar", "/bar"));

        // But should match when there's actually content between
        assert!(matches_path_pattern("a*a", "axa"));
        assert!(matches_path_pattern("a*a", "aa"));
        assert!(matches_path_pattern("/foo*.txt", "/foobar.txt"));
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
    // Path Traversal Security Tests
    // ========================================================================

    #[test]
    fn test_path_traversal_blocked() {
        // Path traversal attempts should never match any pattern
        // This is a critical security property to prevent directory escape

        // Basic traversal attempts
        assert!(!matches_path_pattern(
            "/workspace/**",
            "/workspace/../etc/passwd"
        ));
        assert!(!matches_path_pattern(
            "/workspace/**",
            "/workspace/src/../../../etc/passwd"
        ));
        assert!(!matches_path_pattern(
            "/safe/**",
            "/safe/../dangerous/file.txt"
        ));

        // Even if the path textually starts with the allowed prefix
        assert!(!matches_path_pattern(
            "/allowed/**",
            "/allowed/../forbidden/secret.key"
        ));

        // Traversal at various positions
        assert!(!matches_path_pattern("**", "/workspace/../outside"));
        assert!(!matches_path_pattern("/a/b/**", "/a/b/../c/file.txt"));
        assert!(!matches_path_pattern(
            "/root/**",
            "/root/sub/../../../etc/shadow"
        ));

        // Single dot is OK (current directory)
        assert!(matches_path_pattern(
            "/workspace/**",
            "/workspace/./file.txt"
        ));
        assert!(matches_path_pattern(
            "/workspace/**",
            "/workspace/src/./main.rs"
        ));
    }

    #[test]
    fn test_contains_path_traversal() {
        // Should detect .. components
        assert!(contains_path_traversal("/a/../b"));
        assert!(contains_path_traversal("../relative"));
        assert!(contains_path_traversal("/absolute/.."));
        assert!(contains_path_traversal("/path/to/../../../escape"));

        // Should not flag legitimate paths
        assert!(!contains_path_traversal("/normal/path/file.txt"));
        assert!(!contains_path_traversal("/workspace/src/main.rs"));
        assert!(!contains_path_traversal("relative/path"));
        assert!(!contains_path_traversal("/path/with./dots.in.name"));
        assert!(!contains_path_traversal("/path/.hidden/file"));

        // Single dot is OK
        assert!(!contains_path_traversal("/path/./current"));
        assert!(!contains_path_traversal("./relative"));
    }

    #[test]
    fn test_path_traversal_denied_in_policy() {
        // Integration test: verify policy engine denies traversal attempts
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

        // Normal access should be allowed
        let request = create_file_read_request("/workspace/src/main.rs");
        assert!(engine.evaluate(&request).is_allowed());

        // Traversal attempt should be denied
        let request = create_file_read_request("/workspace/../etc/passwd");
        let result = engine.evaluate(&request);
        assert!(result.is_denied());
        assert_eq!(result.rule_id, DEFAULT_DENY_RULE_ID);

        // More complex traversal
        let request = create_file_read_request("/workspace/deep/../../etc/shadow");
        assert!(engine.evaluate(&request).is_denied());
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

    #[test]
    fn test_evaluation_result_to_policy_violation_event() {
        use crate::events::policy_event;

        // Deny result should produce an event
        let result = EvaluationResult::denied(
            "deny-rule".to_string(),
            "ACCESS_DENIED".to_string(),
            [0u8; 32],
            "Access denied details".to_string(),
        );

        let event = result.to_policy_violation_event("session-123");
        assert!(event.is_some());

        match event.unwrap().event {
            Some(policy_event::Event::Violation(v)) => {
                assert_eq!(v.session_id, "session-123");
                assert_eq!(v.violation_type, "ACCESS_DENIED");
                assert_eq!(v.rule_id, "deny-rule");
                assert_eq!(v.details, "Access denied details");
            },
            _ => panic!("Expected Violation event"),
        }

        // Allow result should NOT produce an event
        let result = EvaluationResult::allowed(
            "allow-rule".to_string(),
            "ACCESS_ALLOWED".to_string(),
            [0u8; 32],
            "Access allowed".to_string(),
        );

        let event = result.to_policy_violation_event("session-123");
        assert!(event.is_none());
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
            consumption_mode: false,
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
            consumption_mode: false,
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
    // Network Rule Fail-Closed Tests
    // ========================================================================

    #[test]
    fn test_network_rule_inference_host_restriction_fail_closed() {
        // Security: If a network rule specifies hosts but the inference provider
        // doesn't match any host, the rule should NOT match (fail closed).
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-anthropic-only"
      type: network
      hosts:
        - "anthropic"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Anthropic provider should match
        let request = ToolRequest {
            consumption_mode: false,
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

        // Different provider should NOT match (fail closed)
        let request = ToolRequest {
            consumption_mode: false,
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "openai".to_string(),
                model: "gpt-4".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 1000,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        let result = engine.evaluate(&request);
        // Should be denied because the network rule doesn't match (fail closed)
        // and default is deny
        assert!(result.is_denied());
    }

    #[test]
    fn test_inference_host_confusion_attack_prevention() {
        // Security: Test that inference host matching prevents confusion attacks.
        // If "google" is allowed, "google.malicious.com" must NOT match.
        // If "anthropic.com" is allowed, providers containing "thropic" must NOT match.
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-google-only"
      type: network
      hosts:
        - "google"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Exact match should work
        let request = ToolRequest {
            consumption_mode: false,
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "google".to_string(),
                model: "gemini".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 1000,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        assert!(engine.evaluate(&request).is_allowed());

        // Subdomain of allowed host should work (api.google)
        let request = ToolRequest {
            consumption_mode: false,
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "api.google".to_string(),
                model: "gemini".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 1000,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        assert!(engine.evaluate(&request).is_allowed());

        // SECURITY: Malicious domain with allowed name as prefix MUST be rejected
        // "google.malicious.com" should NOT match "google"
        let request = ToolRequest {
            consumption_mode: false,
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "google.malicious.com".to_string(),
                model: "fake-model".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 1000,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        assert!(
            engine.evaluate(&request).is_denied(),
            "google.malicious.com should NOT match allowed host 'google'"
        );

        // SECURITY: Similar name should NOT match via contains
        // "google-proxy" should NOT match "google"
        let request = ToolRequest {
            consumption_mode: false,
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "google-proxy".to_string(),
                model: "fake-model".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 1000,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        assert!(
            engine.evaluate(&request).is_denied(),
            "google-proxy should NOT match allowed host 'google'"
        );

        // SECURITY: Substring match should NOT work
        // "oogle" should NOT match "google"
        let request = ToolRequest {
            consumption_mode: false,
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::Inference(InferenceCall {
                provider: "oogle".to_string(),
                model: "fake-model".to_string(),
                prompt_hash: vec![0u8; 32],
                max_tokens: 1000,
                temperature_scaled: 70,
                system_prompt_hash: vec![],
            })),
        };
        assert!(
            engine.evaluate(&request).is_denied(),
            "oogle should NOT match allowed host 'google'"
        );
    }

    #[test]
    fn test_network_rule_shell_exec_host_restriction_fail_closed() {
        // Security: Network rules with hosts specified cannot match ShellExec
        // because we can't verify the target host from the command.
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-specific-host"
      type: network
      hosts:
        - "api.example.com"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Shell exec with network access should NOT match because hosts are specified
        // but we can't verify the target (fail closed)
        let request = ToolRequest {
            consumption_mode: false,
            request_id: "test-req".to_string(),
            session_token: "test-session".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ShellExec(ShellExec {
                command: "curl https://api.example.com/data".to_string(),
                cwd: String::new(),
                timeout_ms: 0,
                network_access: true,
                env: vec![],
            })),
        };
        let result = engine.evaluate(&request);
        // Should be denied because we can't verify the host from the shell command
        assert!(result.is_denied());
    }

    // ========================================================================
    // Cross-Platform Path Traversal Tests
    // ========================================================================

    #[test]
    fn test_path_traversal_windows_separator() {
        // Security: Path traversal with Windows-style separators should also be blocked
        assert!(contains_path_traversal("..\\etc\\passwd"));
        assert!(contains_path_traversal("/workspace\\..\\secret"));
        assert!(contains_path_traversal("a\\..\\b"));

        // Mixed separators
        assert!(contains_path_traversal("/a/b\\../c"));

        // Should not match path patterns
        assert!(!matches_path_pattern(
            "/workspace/**",
            "/workspace\\..\\secret"
        ));
        assert!(!matches_path_pattern("**", "a\\..\\b"));
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
            consumption_mode: false,
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
            consumption_mode: false,
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

    #[test]
    fn test_tool_rule_empty_paths_blocks_traversal() {
        // Security: A tool_allow rule with empty paths (allow all fs operations)
        // must still block path traversal attempts. This prevents
        // ../../../etc/passwd from bypassing security via an "allow all" rule.
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-all-fs"
      type: tool_allow
      tool: "fs.*"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        // Normal paths should be allowed
        let request = create_file_read_request("/home/user/file.txt");
        assert!(engine.evaluate(&request).is_allowed());

        // Path traversal must be blocked even with empty paths list
        let request = create_file_read_request("/workspace/../etc/passwd");
        let result = engine.evaluate(&request);
        assert!(
            result.is_denied(),
            "Path traversal should be denied even with empty paths rule"
        );

        // More traversal attempts
        let request = create_file_read_request("../../../etc/shadow");
        assert!(engine.evaluate(&request).is_denied());

        let request = create_file_write_request("/safe/../../dangerous");
        assert!(engine.evaluate(&request).is_denied());
    }

    // ========================================================================
    // Budget Integration Tests
    // ========================================================================

    #[test]
    fn test_evaluate_with_budget_allows_when_budget_ok() {
        use crate::budget::{BudgetConfig, BudgetTracker};

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
        let tracker = BudgetTracker::new("session-123", BudgetConfig::default());

        let request = create_file_read_request("/any/file.txt");
        let result = engine.evaluate_with_budget(&request, &tracker);

        assert!(result.is_allowed());
        assert_eq!(result.rule_id, "allow-all");
    }

    #[test]
    fn test_evaluate_with_budget_denies_when_token_budget_exceeded() {
        use crate::budget::{BudgetConfig, BudgetTracker, BudgetType};

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

        let config = BudgetConfig::builder().token_budget(1000).build();
        let mut tracker = BudgetTracker::new("session-123", config);

        // Exceed the token budget
        tracker.charge(BudgetType::Token, 1500).unwrap();

        let request = create_file_read_request("/any/file.txt");
        let result = engine.evaluate_with_budget(&request, &tracker);

        // Should be denied due to budget exceeded
        assert!(result.is_denied());
        assert_eq!(result.rule_id, BUDGET_EXCEEDED_RULE_ID);
        assert_eq!(result.rationale_code, "TOKEN_BUDGET_EXCEEDED");
        assert!(result.message.contains("TOKEN budget exceeded"));
    }

    #[test]
    fn test_evaluate_with_budget_denies_when_tool_call_budget_exceeded() {
        use crate::budget::{BudgetConfig, BudgetTracker, BudgetType};

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

        let config = BudgetConfig::builder().tool_call_budget(10).build();
        let mut tracker = BudgetTracker::new("session-456", config);

        // Exceed the tool call budget
        for _ in 0..15 {
            tracker.charge(BudgetType::ToolCalls, 1).unwrap();
        }

        let request = create_shell_exec_request("cargo test");
        let result = engine.evaluate_with_budget(&request, &tracker);

        assert!(result.is_denied());
        assert_eq!(result.rule_id, BUDGET_EXCEEDED_RULE_ID);
        assert_eq!(result.rationale_code, "TOOL_CALLS_BUDGET_EXCEEDED");
    }

    #[test]
    fn test_evaluate_with_budget_denies_when_time_budget_exceeded() {
        use crate::budget::{BudgetConfig, BudgetTracker};

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

        // Create a tracker with a very short time budget
        let config = BudgetConfig::builder()
            .time_budget_ms(1)  // 1ms
            .build();
        let tracker = BudgetTracker::new("session-789", config);

        // Wait for time budget to expire
        std::thread::sleep(std::time::Duration::from_millis(5));

        let request = create_file_read_request("/any/file.txt");
        let result = engine.evaluate_with_budget(&request, &tracker);

        assert!(result.is_denied());
        assert_eq!(result.rule_id, BUDGET_EXCEEDED_RULE_ID);
        assert_eq!(result.rationale_code, "TIME_BUDGET_EXCEEDED");
    }

    #[test]
    fn test_evaluate_with_budget_budget_check_precedes_policy() {
        use crate::budget::{BudgetConfig, BudgetTracker, BudgetType};

        // Even with a deny-all policy, budget exceeded should take precedence
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "deny-all"
      type: tool_deny
      tool: "*"
      decision: deny
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let config = BudgetConfig::builder().token_budget(100).build();
        let mut tracker = BudgetTracker::new("session-123", config);
        tracker.charge(BudgetType::Token, 200).unwrap();

        let request = create_file_read_request("/any/file.txt");
        let result = engine.evaluate_with_budget(&request, &tracker);

        // Should be denied due to budget, not the deny-all rule
        assert!(result.is_denied());
        assert_eq!(result.rule_id, BUDGET_EXCEEDED_RULE_ID);
        // NOT "deny-all"
    }

    #[test]
    fn test_evaluate_with_budget_unlimited_budget_allows() {
        use crate::budget::{BudgetConfig, BudgetTracker, BudgetType};

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

        // Unlimited budgets should not trigger exceeded
        let config = BudgetConfig::unlimited();
        let mut tracker = BudgetTracker::new("session-123", config);

        // Even with massive consumption, unlimited means not exceeded
        tracker.charge(BudgetType::Token, u64::MAX - 10).unwrap();
        tracker
            .charge(BudgetType::ToolCalls, u64::MAX - 10)
            .unwrap();

        let request = create_file_read_request("/any/file.txt");
        let result = engine.evaluate_with_budget(&request, &tracker);

        assert!(result.is_allowed());
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

            /// Property: Path traversal attempts should always be denied
            ///
            /// This is a critical security property: any path containing ".."
            /// must never match any pattern, regardless of the pattern used.
            #[test]
            fn prop_path_traversal_always_denied(
                prefix in "/[a-z]{1,10}",
                traversal_depth in 1usize..5,
                suffix in "[a-z]{1,10}"
            ) {
                // Construct a path with traversal: /prefix/../../../suffix
                let traversal = "../".repeat(traversal_depth);
                let malicious_path = format!("{prefix}/{traversal}{suffix}");

                // This should never match any pattern
                assert!(!matches_path_pattern("**", &malicious_path));
                let prefix_pattern = format!("{prefix}/**");
                assert!(!matches_path_pattern(&prefix_pattern, &malicious_path));
                assert!(!matches_path_pattern("/**", &malicious_path));

                // Verify the helper function detects it
                assert!(contains_path_traversal(&malicious_path));
            }

            /// Property: Path traversal in policy evaluation should always deny
            #[test]
            fn prop_policy_denies_traversal(
                allowed_dir in "/[a-z]{1,8}",
                traversal_depth in 1usize..4,
                target_file in "[a-z]{1,8}/[a-z]{1,8}"
            ) {
                let yaml = format!(r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-dir"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "{allowed_dir}/**"
      decision: allow
  default_decision: deny
"#);
                if let Ok(policy) = LoadedPolicy::from_yaml(&yaml) {
                    let engine = PolicyEngine::new(&policy);

                    // Normal access within allowed dir should work
                    let safe_path = format!("{allowed_dir}/file.txt");
                    let safe_request = create_file_read_request(&safe_path);
                    assert!(engine.evaluate(&safe_request).is_allowed());

                    // Traversal attempt should be denied
                    let traversal = "../".repeat(traversal_depth);
                    let malicious_path = format!("{allowed_dir}/{traversal}{target_file}");
                    let malicious_request = create_file_read_request(&malicious_path);
                    assert!(engine.evaluate(&malicious_request).is_denied());
                }
            }
        }
    }
}

// ========================================================================

#[cfg(test)]
mod consumption_tests {
    use super::*;
    use crate::tool::{ArtifactFetch, ToolRequest, tool_request};

    fn create_test_policy(yaml: &str) -> LoadedPolicy {
        LoadedPolicy::from_yaml(yaml).expect("valid test policy")
    }

    #[test]
    fn test_consumption_mode_denies_content_hash_only() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-fetch"
      type: consumption_mode
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req".to_string(),
            session_token: "sess".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: String::new(),
                content_hash: vec![0xaa; 32], // 32 bytes = valid BLAKE3 hash
                expected_hash: Vec::new(),
                max_bytes: 0,
                format: String::new(),
            })),
        };

        // Should be denied because stable_id is empty
        assert!(engine.evaluate(&request).is_denied());
    }

    #[test]
    fn test_consumption_mode_allows_stable_id() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-fetch"
      type: consumption_mode
      stable_ids: ["org:ticket:TCK-001"]
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req".to_string(),
            session_token: "sess".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: "org:ticket:TCK-001".to_string(),
                content_hash: Vec::new(),
                expected_hash: Vec::new(),
                max_bytes: 0,
                format: String::new(),
            })),
        };

        assert!(engine.evaluate(&request).is_allowed());
    }

    #[test]
    fn test_consumption_mode_denies_unlisted_stable_id() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "allow-fetch"
      type: consumption_mode
      stable_ids: ["org:ticket:TCK-001"]
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = ToolRequest {
            consumption_mode: true,
            request_id: "req".to_string(),
            session_token: "sess".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: "org:ticket:TCK-002".to_string(),
                content_hash: Vec::new(),
                expected_hash: Vec::new(),
                max_bytes: 0,
                format: String::new(),
            })),
        };

        assert!(engine.evaluate(&request).is_denied());
    }

    #[test]
    fn test_normal_mode_ignores_consumption_rules() {
        let yaml = r#"
policy:
  version: "1.0.0"
  name: "test"
  rules:
    - id: "consumption-rule"
      type: consumption_mode
      decision: deny # Should be ignored in normal mode
    - id: "allow-tool"
      type: tool_allow
      tool: "artifact.fetch"
      decision: allow
  default_decision: deny
"#;
        let policy = create_test_policy(yaml);
        let engine = PolicyEngine::new(&policy);

        let request = ToolRequest {
            consumption_mode: false,
            request_id: "req".to_string(),
            session_token: "sess".to_string(),
            dedupe_key: String::new(),
            tool: Some(tool_request::Tool::ArtifactFetch(ArtifactFetch {
                stable_id: String::new(),
                content_hash: vec![0xaa; 32], // 32 bytes = valid BLAKE3 hash
                expected_hash: Vec::new(),
                max_bytes: 0,
                format: String::new(),
            })),
        };

        // Should be allowed by tool_allow rule, consumption rule ignored
        let result = engine.evaluate(&request);
        assert!(result.is_allowed());
        assert_eq!(result.rule_id, "allow-tool");
    }
}
