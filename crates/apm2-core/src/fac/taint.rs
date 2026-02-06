// AGENT-AUTHORED
//! Taint tracking for prompt-injection resistance (TCK-00339, REQ-0016).
//!
//! This module implements taint classification and flow policy enforcement
//! for untrusted inputs flowing through the evidence pipeline. All content
//! entering from external sources (diffs, tool outputs, web content) is
//! tagged with a [`TaintTag`] that propagates through evidence pointers
//! and context compilation.
//!
//! # Design Overview
//!
//! The taint system classifies inputs into trust levels:
//!
//! - [`TaintLevel::Trusted`]: Kernel-generated, CAS-verified content
//! - [`TaintLevel::Attested`]: Content with a verified attestation chain
//! - [`TaintLevel::Untrusted`]: External content (diffs, tool output, web)
//! - [`TaintLevel::Adversarial`]: Known-hostile content (user-supplied prompts)
//!
//! Each input carries a [`TaintTag`] with its classification, source, and
//! a content hash for audit. The [`TaintPolicy`] defines what flows are
//! allowed between taint levels and target contexts. Forbidden flows are
//! denied and recorded as [`TaintViolation`] events.
//!
//! # Security Properties
//!
//! - **Fail-Closed**: Unknown taint levels default to [`TaintLevel::Untrusted`]
//! - **Propagation**: Taint tags propagate through evidence pointers; the
//!   highest (least-trusted) taint level wins in aggregation
//! - **Audit**: All policy decisions are recorded with full context
//! - **Deterministic**: Policy evaluation is pure and deterministic
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::taint::{
//!     TaintLevel, TaintPolicy, TaintSource, TaintTag, TargetContext,
//! };
//!
//! // Tag a diff as untrusted
//! let tag =
//!     TaintTag::new(TaintLevel::Untrusted, TaintSource::Diff, [0x42; 32]);
//!
//! // Check if it can flow into a receipt
//! let policy = TaintPolicy::default();
//! let decision = policy.evaluate(&tag, TargetContext::Receipt);
//! assert!(
//!     !decision.allowed,
//!     "untrusted content must not flow into receipts"
//! );
//! ```
//!
//! # Contract References
//!
//! - TCK-00339: Security hardening: prompt-injection resistance via evidence
//!   taint tracking
//! - REQ-0016: Taint tracking prevents untrusted content from silently
//!   influencing decisions
//! - TB-0006: `ContextPack` Firewall Boundary

use serde::{Deserialize, Serialize};

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for source description strings.
pub const MAX_SOURCE_DESCRIPTION_LEN: usize = 512;

/// Maximum length for violation description strings.
pub const MAX_VIOLATION_DESCRIPTION_LEN: usize = 2048;

/// Maximum length for policy rule ID strings.
pub const MAX_POLICY_RULE_ID_LEN: usize = 256;

/// Maximum number of taint tags in an aggregation set.
pub const MAX_TAINT_TAGS: usize = 1024;

/// Maximum number of custom flow rules in a policy.
pub const MAX_FLOW_RULES: usize = 256;

// =============================================================================
// TaintLevel
// =============================================================================

/// Classification of trust for a content input.
///
/// Levels are ordered from most trusted (lowest numeric value) to least
/// trusted (highest). When aggregating multiple taint tags, the highest
/// (least-trusted) level propagates.
///
/// # Ordering
///
/// `Trusted < Attested < Untrusted < Adversarial`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum TaintLevel {
    /// Kernel-generated content with CAS integrity verification.
    ///
    /// Examples: policy configurations, capability manifests, internal
    /// state that has been hash-verified from CAS.
    Trusted     = 0,

    /// Content with a verified attestation chain.
    ///
    /// Examples: CI results with signed attestations, tool outputs from
    /// sandboxed execution with verified receipts.
    Attested    = 1,

    /// External content without attestation.
    ///
    /// Examples: git diffs, raw tool outputs, file contents read from
    /// workspace, search results.
    Untrusted   = 2,

    /// Known-hostile or adversarial content.
    ///
    /// Examples: user-supplied prompts, web content, content that has
    /// been flagged by echo-trap detection.
    Adversarial = 3,
}

impl TaintLevel {
    /// Returns the numeric code for this taint level.
    #[must_use]
    pub const fn to_code(self) -> u8 {
        self as u8
    }

    /// Creates a taint level from its numeric code.
    ///
    /// Returns `None` for invalid codes, enforcing fail-closed semantics.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Trusted),
            1 => Some(Self::Attested),
            2 => Some(Self::Untrusted),
            3 => Some(Self::Adversarial),
            _ => None,
        }
    }

    /// Returns `true` if this level is at least as trusted as the given level.
    #[must_use]
    pub const fn is_at_least(self, minimum: Self) -> bool {
        (self as u8) <= (minimum as u8)
    }

    /// Returns `true` if this level represents untrusted or adversarial
    /// content.
    #[must_use]
    pub const fn is_untrusted(self) -> bool {
        matches!(self, Self::Untrusted | Self::Adversarial)
    }

    /// Returns the display name for this level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Attested => "ATTESTED",
            Self::Untrusted => "UNTRUSTED",
            Self::Adversarial => "ADVERSARIAL",
        }
    }
}

impl std::fmt::Display for TaintLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// TaintSource
// =============================================================================

/// Classification of the origin of tainted content.
///
/// Each source type has a default taint level that can be overridden by
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum TaintSource {
    /// Git diff content (patch hunks, file changes).
    Diff,

    /// Tool execution output (stdout/stderr).
    ToolOutput,

    /// Web content fetched from external URLs.
    WebContent,

    /// File content read from workspace.
    FileRead,

    /// Search/navigation results from workspace.
    SearchResult,

    /// User-supplied prompt or instruction.
    UserPrompt,

    /// Kernel-internal content (policies, manifests, config).
    KernelInternal,

    /// CAS-verified content retrieved by hash.
    CasVerified,

    /// Content from an attested CI pipeline.
    CiAttested,
}

impl TaintSource {
    /// Returns the default taint level for this source type.
    ///
    /// This provides the baseline classification. Policy rules may
    /// upgrade (increase trust) or downgrade (decrease trust) from
    /// this baseline.
    #[must_use]
    pub const fn default_level(self) -> TaintLevel {
        match self {
            Self::KernelInternal | Self::CasVerified => TaintLevel::Trusted,
            Self::CiAttested => TaintLevel::Attested,
            Self::Diff | Self::ToolOutput | Self::FileRead | Self::SearchResult => {
                TaintLevel::Untrusted
            },
            Self::WebContent | Self::UserPrompt => TaintLevel::Adversarial,
        }
    }

    /// Returns the display name for this source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Diff => "DIFF",
            Self::ToolOutput => "TOOL_OUTPUT",
            Self::WebContent => "WEB_CONTENT",
            Self::FileRead => "FILE_READ",
            Self::SearchResult => "SEARCH_RESULT",
            Self::UserPrompt => "USER_PROMPT",
            Self::KernelInternal => "KERNEL_INTERNAL",
            Self::CasVerified => "CAS_VERIFIED",
            Self::CiAttested => "CI_ATTESTED",
        }
    }
}

impl std::fmt::Display for TaintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// TaintTag
// =============================================================================

/// A taint classification tag attached to content flowing through the pipeline.
///
/// Each tag carries:
/// - The taint level (trust classification)
/// - The source type (origin classification)
/// - A BLAKE3 content hash for audit binding
///
/// Tags propagate through evidence pointers. When content is aggregated,
/// the highest (least-trusted) taint level propagates.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintTag {
    /// Trust level classification.
    pub level: TaintLevel,

    /// Origin classification.
    pub source: TaintSource,

    /// BLAKE3 hash of the tagged content (32 bytes) for audit binding.
    #[serde(with = "serde_bytes")]
    pub content_hash: [u8; 32],
}

impl TaintTag {
    /// Creates a new taint tag.
    #[must_use]
    pub const fn new(level: TaintLevel, source: TaintSource, content_hash: [u8; 32]) -> Self {
        Self {
            level,
            source,
            content_hash,
        }
    }

    /// Creates a taint tag using the default level for the given source.
    #[must_use]
    pub const fn from_source(source: TaintSource, content_hash: [u8; 32]) -> Self {
        Self {
            level: source.default_level(),
            source,
            content_hash,
        }
    }

    /// Returns `true` if this tag represents untrusted or adversarial content.
    #[must_use]
    pub const fn is_untrusted(&self) -> bool {
        self.level.is_untrusted()
    }

    /// Returns canonical bytes for deterministic hashing/signing.
    ///
    /// Encoding: `level(1) || source(1) || content_hash(32)`
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(self.level.to_code());
        bytes.push(self.source as u8);
        bytes.extend_from_slice(&self.content_hash);
        bytes
    }
}

impl std::fmt::Display for TaintTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TaintTag(level={}, source={}, hash={})",
            self.level,
            self.source,
            hex::encode(&self.content_hash[..8])
        )
    }
}

// =============================================================================
// TargetContext
// =============================================================================

/// Target context where tainted content might flow.
///
/// Each context has a minimum trust level required for content to flow
/// into it. Flows below the minimum are denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum TargetContext {
    /// High-authority prompt sent to an LLM for decision-making.
    ///
    /// Minimum trust: `Attested` (untrusted content must not silently
    /// influence high-authority prompts).
    HighAuthorityPrompt,

    /// Signed receipt or attestation artifact.
    ///
    /// Minimum trust: `Trusted` (only kernel-verified content may
    /// flow into signed receipts).
    Receipt,

    /// Evidence artifact stored in CAS for audit.
    ///
    /// Minimum trust: `Untrusted` (all content can flow into evidence
    /// for audit purposes, but is tagged).
    EvidenceArtifact,

    /// Context pack compilation for an episode.
    ///
    /// Minimum trust: `Attested` (context packs should contain
    /// verified content only; untrusted content must be explicitly
    /// tagged and bounded).
    ContextPack,

    /// Policy evaluation input.
    ///
    /// Minimum trust: `Trusted` (policy inputs must be kernel-verified
    /// to prevent policy bypass via injection).
    PolicyInput,

    /// Tool argument compilation.
    ///
    /// Minimum trust: `Untrusted` (tool args can contain untrusted
    /// content but adversarial content is denied).
    ToolArgument,

    /// Ledger event emission.
    ///
    /// Minimum trust: `Attested` (ledger events carry authority and
    /// must not be influenced by raw untrusted content).
    LedgerEvent,
}

impl TargetContext {
    /// Returns the minimum taint level required to flow into this context.
    ///
    /// Content with a taint level higher (less trusted) than this minimum
    /// is denied.
    #[must_use]
    pub const fn minimum_trust(self) -> TaintLevel {
        match self {
            Self::Receipt | Self::PolicyInput => TaintLevel::Trusted,
            Self::HighAuthorityPrompt | Self::ContextPack | Self::LedgerEvent => {
                TaintLevel::Attested
            },
            Self::EvidenceArtifact | Self::ToolArgument => TaintLevel::Untrusted,
        }
    }

    /// Returns the display name for this context.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HighAuthorityPrompt => "HIGH_AUTHORITY_PROMPT",
            Self::Receipt => "RECEIPT",
            Self::EvidenceArtifact => "EVIDENCE_ARTIFACT",
            Self::ContextPack => "CONTEXT_PACK",
            Self::PolicyInput => "POLICY_INPUT",
            Self::ToolArgument => "TOOL_ARGUMENT",
            Self::LedgerEvent => "LEDGER_EVENT",
        }
    }
}

impl std::fmt::Display for TargetContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// TaintFlowDecision
// =============================================================================

/// Result of evaluating a taint flow against policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintFlowDecision {
    /// Whether the flow is allowed.
    pub allowed: bool,

    /// The tag that was evaluated.
    pub tag: TaintTag,

    /// The target context.
    pub target: TargetContext,

    /// The policy rule that produced this decision.
    pub rule_id: String,

    /// Human-readable rationale.
    pub rationale: String,
}

impl TaintFlowDecision {
    /// Creates an allowed decision.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // String arguments can't be const
    fn allow(tag: TaintTag, target: TargetContext, rule_id: String, rationale: String) -> Self {
        Self {
            allowed: true,
            tag,
            target,
            rule_id,
            rationale,
        }
    }

    /// Creates a denied decision.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // String arguments can't be const
    fn deny(tag: TaintTag, target: TargetContext, rule_id: String, rationale: String) -> Self {
        Self {
            allowed: false,
            tag,
            target,
            rule_id,
            rationale,
        }
    }
}

// =============================================================================
// TaintViolation
// =============================================================================

/// Record of a forbidden taint flow that was denied.
///
/// This is emitted as part of `PolicyViolation` or `ReviewBlockedRecorded`
/// events when untrusted content attempts to flow into a restricted context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintViolation {
    /// The taint tag of the denied content.
    pub tag: TaintTag,

    /// The target context that was protected.
    pub target: TargetContext,

    /// The policy rule that triggered the denial.
    pub rule_id: String,

    /// Human-readable description of the violation.
    pub description: String,
}

impl TaintViolation {
    /// Creates a new taint violation from a denied flow decision.
    #[must_use]
    pub fn from_decision(decision: &TaintFlowDecision) -> Self {
        Self {
            tag: decision.tag.clone(),
            target: decision.target,
            rule_id: decision.rule_id.clone(),
            description: truncate_string(decision.rationale.clone(), MAX_VIOLATION_DESCRIPTION_LEN),
        }
    }

    /// Returns a summary suitable for `PersistTrigger::PolicyViolation`.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "taint flow denied: {} content from {} cannot flow into {}",
            self.tag.level, self.tag.source, self.target
        )
    }
}

// =============================================================================
// FlowRule
// =============================================================================

/// A custom flow rule that overrides the default taint policy.
///
/// Rules are evaluated in order; the first matching rule wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRule {
    /// Unique identifier for this rule.
    pub rule_id: String,

    /// Source filter (if `None`, matches all sources).
    pub source: Option<TaintSource>,

    /// Level filter (if `None`, matches all levels).
    pub level: Option<TaintLevel>,

    /// Target filter (if `None`, matches all targets).
    pub target: Option<TargetContext>,

    /// Whether to allow (`true`) or deny (`false`) matching flows.
    pub allow: bool,

    /// Human-readable rationale for this rule.
    pub rationale: String,
}

// =============================================================================
// TaintPolicy
// =============================================================================

/// Policy governing taint flow between sources and target contexts.
///
/// The default policy enforces the minimum trust levels defined by each
/// [`TargetContext`]. Custom [`FlowRule`]s can override defaults for
/// specific source/level/target combinations.
///
/// # Fail-Closed Semantics
///
/// If no rule matches and the default check fails, the flow is denied.
/// There is no implicit allow path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintPolicy {
    /// Custom flow rules evaluated in order (first match wins).
    pub rules: Vec<FlowRule>,

    /// Whether to enforce strict mode (deny all untrusted flows to any
    /// context that requires attested or higher).
    pub strict_mode: bool,
}

impl Default for TaintPolicy {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            strict_mode: true,
        }
    }
}

impl TaintPolicy {
    /// Creates a new policy with no custom rules and strict mode enabled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a permissive policy that allows all flows (for testing only).
    ///
    /// # Security
    ///
    /// This MUST NOT be used in production paths. It exists only for tests
    /// that need to bypass taint checking temporarily.
    #[must_use]
    #[cfg(any(test, feature = "test-utils"))]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() in body can't be const
    pub fn permissive() -> Self {
        Self {
            rules: Vec::new(),
            strict_mode: false,
        }
    }

    /// Adds a custom flow rule.
    ///
    /// Returns `self` for chaining. Rules are evaluated in insertion order.
    ///
    /// # Panics
    ///
    /// Panics if the rule count exceeds `MAX_FLOW_RULES`.
    #[must_use]
    pub fn with_rule(mut self, rule: FlowRule) -> Self {
        assert!(
            self.rules.len() < MAX_FLOW_RULES,
            "flow rule limit exceeded: max {MAX_FLOW_RULES}"
        );
        self.rules.push(rule);
        self
    }

    /// Evaluates whether a tainted content flow is allowed.
    ///
    /// # Algorithm
    ///
    /// 1. Check custom rules in order (first match wins)
    /// 2. If no custom rule matches, apply default policy:
    ///    - If `strict_mode` is enabled, check `tag.level <=
    ///      target.minimum_trust()`
    ///    - If `strict_mode` is disabled, allow all flows
    #[must_use]
    pub fn evaluate(&self, tag: &TaintTag, target: TargetContext) -> TaintFlowDecision {
        // Step 1: Check custom rules (first match wins)
        for rule in &self.rules {
            if rule_matches(rule, tag, target) {
                return if rule.allow {
                    TaintFlowDecision::allow(
                        tag.clone(),
                        target,
                        rule.rule_id.clone(),
                        rule.rationale.clone(),
                    )
                } else {
                    TaintFlowDecision::deny(
                        tag.clone(),
                        target,
                        rule.rule_id.clone(),
                        rule.rationale.clone(),
                    )
                };
            }
        }

        // Step 2: Default policy
        let minimum = target.minimum_trust();

        if !self.strict_mode {
            return TaintFlowDecision::allow(
                tag.clone(),
                target,
                "DEFAULT_PERMISSIVE".to_string(),
                "strict mode disabled; all flows allowed".to_string(),
            );
        }

        if tag.level.is_at_least(minimum) {
            TaintFlowDecision::allow(
                tag.clone(),
                target,
                "DEFAULT_TRUST_CHECK".to_string(),
                format!(
                    "{} content (level={}) meets minimum trust for {} (requires={})",
                    tag.source, tag.level, target, minimum,
                ),
            )
        } else {
            TaintFlowDecision::deny(
                tag.clone(),
                target,
                "DEFAULT_TRUST_CHECK".to_string(),
                format!(
                    "{} content (level={}) does not meet minimum trust for {} (requires={})",
                    tag.source, tag.level, target, minimum,
                ),
            )
        }
    }

    /// Evaluates a flow and returns a violation if denied.
    ///
    /// This is a convenience method that combines `evaluate()` with
    /// `TaintViolation::from_decision()`.
    ///
    /// # Errors
    ///
    /// Returns `TaintViolation` if the flow is denied by the taint policy.
    pub fn check_flow(&self, tag: &TaintTag, target: TargetContext) -> Result<(), TaintViolation> {
        let decision = self.evaluate(tag, target);
        if decision.allowed {
            Ok(())
        } else {
            Err(TaintViolation::from_decision(&decision))
        }
    }
}

/// Checks if a flow rule matches the given tag and target.
fn rule_matches(rule: &FlowRule, tag: &TaintTag, target: TargetContext) -> bool {
    // Check source filter
    if let Some(source) = rule.source {
        if tag.source != source {
            return false;
        }
    }

    // Check level filter
    if let Some(level) = rule.level {
        if tag.level != level {
            return false;
        }
    }

    // Check target filter
    if let Some(rule_target) = rule.target {
        if target != rule_target {
            return false;
        }
    }

    true
}

// =============================================================================
// TaintAggregator
// =============================================================================

/// Aggregates multiple taint tags and computes the effective taint level.
///
/// When content from multiple sources is combined (e.g., context pack
/// compilation), the aggregate taint level is the maximum (least-trusted)
/// of all individual tags. This ensures that taint propagates conservatively.
///
/// # Example
///
/// ```rust
/// use apm2_core::fac::taint::{
///     TaintAggregator, TaintLevel, TaintSource, TaintTag,
/// };
///
/// let mut agg = TaintAggregator::new();
/// agg.add(TaintTag::from_source(TaintSource::CasVerified, [0x01; 32]));
/// agg.add(TaintTag::from_source(TaintSource::Diff, [0x02; 32]));
///
/// // Aggregate level is the highest (least-trusted)
/// assert_eq!(agg.effective_level(), TaintLevel::Untrusted);
/// ```
#[derive(Debug, Clone, Default)]
pub struct TaintAggregator {
    tags: Vec<TaintTag>,
}

impl TaintAggregator {
    /// Creates a new empty aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a taint tag to the aggregation.
    ///
    /// # Panics
    ///
    /// Panics if the tag count exceeds `MAX_TAINT_TAGS`.
    pub fn add(&mut self, tag: TaintTag) {
        assert!(
            self.tags.len() < MAX_TAINT_TAGS,
            "taint tag limit exceeded: max {MAX_TAINT_TAGS}"
        );
        self.tags.push(tag);
    }

    /// Returns the effective (aggregate) taint level.
    ///
    /// This is the maximum (least-trusted) level across all tags.
    /// Returns `TaintLevel::Trusted` if no tags have been added
    /// (empty aggregation is trusted by default since there is
    /// no untrusted content to propagate).
    #[must_use]
    pub fn effective_level(&self) -> TaintLevel {
        self.tags
            .iter()
            .map(|t| t.level)
            .max()
            .unwrap_or(TaintLevel::Trusted)
    }

    /// Returns all tags in the aggregation.
    #[must_use]
    pub fn tags(&self) -> &[TaintTag] {
        &self.tags
    }

    /// Returns the number of tags in the aggregation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Returns `true` if no tags have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Validates that the aggregate taint level is allowed for the target.
    ///
    /// This checks the effective level against the policy for the given
    /// target context.
    #[must_use]
    pub fn validate_for_target(
        &self,
        policy: &TaintPolicy,
        target: TargetContext,
    ) -> Vec<TaintViolation> {
        let mut violations = Vec::new();
        for tag in &self.tags {
            if let Err(violation) = policy.check_flow(tag, target) {
                violations.push(violation);
            }
        }
        violations
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Truncates a string to the maximum length, preserving valid UTF-8.
fn truncate_string(s: String, max_len: usize) -> String {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TaintLevel Tests
    // =========================================================================

    #[test]
    fn test_taint_level_ordering() {
        assert!(TaintLevel::Trusted < TaintLevel::Attested);
        assert!(TaintLevel::Attested < TaintLevel::Untrusted);
        assert!(TaintLevel::Untrusted < TaintLevel::Adversarial);
    }

    #[test]
    fn test_taint_level_is_at_least() {
        assert!(TaintLevel::Trusted.is_at_least(TaintLevel::Trusted));
        assert!(TaintLevel::Trusted.is_at_least(TaintLevel::Attested));
        assert!(TaintLevel::Trusted.is_at_least(TaintLevel::Untrusted));
        assert!(TaintLevel::Attested.is_at_least(TaintLevel::Attested));
        assert!(TaintLevel::Attested.is_at_least(TaintLevel::Untrusted));
        assert!(!TaintLevel::Untrusted.is_at_least(TaintLevel::Attested));
        assert!(!TaintLevel::Adversarial.is_at_least(TaintLevel::Untrusted));
    }

    #[test]
    fn test_taint_level_is_untrusted() {
        assert!(!TaintLevel::Trusted.is_untrusted());
        assert!(!TaintLevel::Attested.is_untrusted());
        assert!(TaintLevel::Untrusted.is_untrusted());
        assert!(TaintLevel::Adversarial.is_untrusted());
    }

    #[test]
    fn test_taint_level_roundtrip() {
        for code in 0..=3u8 {
            let level = TaintLevel::from_code(code).unwrap();
            assert_eq!(level.to_code(), code);
        }
        assert!(TaintLevel::from_code(4).is_none());
        assert!(TaintLevel::from_code(255).is_none());
    }

    #[test]
    fn test_taint_level_display() {
        assert_eq!(TaintLevel::Trusted.to_string(), "TRUSTED");
        assert_eq!(TaintLevel::Attested.to_string(), "ATTESTED");
        assert_eq!(TaintLevel::Untrusted.to_string(), "UNTRUSTED");
        assert_eq!(TaintLevel::Adversarial.to_string(), "ADVERSARIAL");
    }

    // =========================================================================
    // TaintSource Tests
    // =========================================================================

    #[test]
    fn test_taint_source_default_levels() {
        assert_eq!(
            TaintSource::KernelInternal.default_level(),
            TaintLevel::Trusted
        );
        assert_eq!(
            TaintSource::CasVerified.default_level(),
            TaintLevel::Trusted
        );
        assert_eq!(
            TaintSource::CiAttested.default_level(),
            TaintLevel::Attested
        );
        assert_eq!(TaintSource::Diff.default_level(), TaintLevel::Untrusted);
        assert_eq!(
            TaintSource::ToolOutput.default_level(),
            TaintLevel::Untrusted
        );
        assert_eq!(TaintSource::FileRead.default_level(), TaintLevel::Untrusted);
        assert_eq!(
            TaintSource::SearchResult.default_level(),
            TaintLevel::Untrusted
        );
        assert_eq!(
            TaintSource::WebContent.default_level(),
            TaintLevel::Adversarial
        );
        assert_eq!(
            TaintSource::UserPrompt.default_level(),
            TaintLevel::Adversarial
        );
    }

    #[test]
    fn test_taint_source_display() {
        assert_eq!(TaintSource::Diff.to_string(), "DIFF");
        assert_eq!(TaintSource::ToolOutput.to_string(), "TOOL_OUTPUT");
        assert_eq!(TaintSource::WebContent.to_string(), "WEB_CONTENT");
    }

    // =========================================================================
    // TaintTag Tests
    // =========================================================================

    #[test]
    fn test_taint_tag_from_source() {
        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        assert_eq!(tag.level, TaintLevel::Untrusted);
        assert_eq!(tag.source, TaintSource::Diff);
        assert_eq!(tag.content_hash, [0x42; 32]);
    }

    #[test]
    fn test_taint_tag_is_untrusted() {
        let trusted = TaintTag::from_source(TaintSource::CasVerified, [0x01; 32]);
        assert!(!trusted.is_untrusted());

        let untrusted = TaintTag::from_source(TaintSource::Diff, [0x02; 32]);
        assert!(untrusted.is_untrusted());

        let adversarial = TaintTag::from_source(TaintSource::WebContent, [0x03; 32]);
        assert!(adversarial.is_untrusted());
    }

    #[test]
    fn test_taint_tag_canonical_bytes_deterministic() {
        let tag1 = TaintTag::new(TaintLevel::Untrusted, TaintSource::Diff, [0x42; 32]);
        let tag2 = TaintTag::new(TaintLevel::Untrusted, TaintSource::Diff, [0x42; 32]);
        assert_eq!(tag1.canonical_bytes(), tag2.canonical_bytes());
    }

    #[test]
    fn test_taint_tag_canonical_bytes_different_for_different_inputs() {
        let tag1 = TaintTag::new(TaintLevel::Untrusted, TaintSource::Diff, [0x42; 32]);
        let tag2 = TaintTag::new(TaintLevel::Trusted, TaintSource::Diff, [0x42; 32]);
        assert_ne!(tag1.canonical_bytes(), tag2.canonical_bytes());
    }

    #[test]
    fn test_taint_tag_display() {
        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        let display = tag.to_string();
        assert!(display.contains("UNTRUSTED"));
        assert!(display.contains("DIFF"));
    }

    #[test]
    fn test_taint_tag_serialization_roundtrip() {
        let tag = TaintTag::new(TaintLevel::Adversarial, TaintSource::WebContent, [0xAB; 32]);
        let json = serde_json::to_string(&tag).unwrap();
        let deserialized: TaintTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, deserialized);
    }

    // =========================================================================
    // TargetContext Tests
    // =========================================================================

    #[test]
    fn test_target_context_minimum_trust() {
        assert_eq!(TargetContext::Receipt.minimum_trust(), TaintLevel::Trusted);
        assert_eq!(
            TargetContext::PolicyInput.minimum_trust(),
            TaintLevel::Trusted
        );
        assert_eq!(
            TargetContext::HighAuthorityPrompt.minimum_trust(),
            TaintLevel::Attested
        );
        assert_eq!(
            TargetContext::ContextPack.minimum_trust(),
            TaintLevel::Attested
        );
        assert_eq!(
            TargetContext::LedgerEvent.minimum_trust(),
            TaintLevel::Attested
        );
        assert_eq!(
            TargetContext::EvidenceArtifact.minimum_trust(),
            TaintLevel::Untrusted
        );
        assert_eq!(
            TargetContext::ToolArgument.minimum_trust(),
            TaintLevel::Untrusted
        );
    }

    // =========================================================================
    // TaintPolicy Tests
    // =========================================================================

    #[test]
    fn test_default_policy_denies_untrusted_to_receipt() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::Receipt);

        assert!(!decision.allowed);
        assert_eq!(decision.rule_id, "DEFAULT_TRUST_CHECK");
    }

    #[test]
    fn test_default_policy_allows_trusted_to_receipt() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::CasVerified, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::Receipt);

        assert!(decision.allowed);
    }

    #[test]
    fn test_default_policy_denies_untrusted_to_high_authority_prompt() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::ToolOutput, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::HighAuthorityPrompt);

        assert!(!decision.allowed);
    }

    #[test]
    fn test_default_policy_allows_attested_to_high_authority_prompt() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::CiAttested, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::HighAuthorityPrompt);

        assert!(decision.allowed);
    }

    #[test]
    fn test_default_policy_allows_untrusted_to_evidence_artifact() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::EvidenceArtifact);

        assert!(decision.allowed);
    }

    #[test]
    fn test_default_policy_denies_adversarial_to_evidence_artifact() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::WebContent, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::EvidenceArtifact);

        assert!(!decision.allowed);
    }

    #[test]
    fn test_default_policy_denies_adversarial_to_tool_argument() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::UserPrompt, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::ToolArgument);

        assert!(!decision.allowed);
    }

    #[test]
    fn test_custom_rule_overrides_default() {
        // Allow untrusted diffs into evidence artifacts even with strict mode
        let policy = TaintPolicy::default().with_rule(FlowRule {
            rule_id: "ALLOW_DIFF_TO_EVIDENCE".to_string(),
            source: Some(TaintSource::Diff),
            level: None,
            target: Some(TargetContext::EvidenceArtifact),
            allow: true,
            rationale: "diffs are expected evidence content".to_string(),
        });

        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::EvidenceArtifact);

        assert!(decision.allowed);
        assert_eq!(decision.rule_id, "ALLOW_DIFF_TO_EVIDENCE");
    }

    #[test]
    fn test_custom_deny_rule() {
        // Explicitly deny CI attested content from tool arguments
        let policy = TaintPolicy::default().with_rule(FlowRule {
            rule_id: "DENY_CI_TO_TOOL".to_string(),
            source: Some(TaintSource::CiAttested),
            level: None,
            target: Some(TargetContext::ToolArgument),
            allow: false,
            rationale: "CI content must not be used as tool arguments".to_string(),
        });

        let tag = TaintTag::from_source(TaintSource::CiAttested, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::ToolArgument);

        assert!(!decision.allowed);
        assert_eq!(decision.rule_id, "DENY_CI_TO_TOOL");
    }

    #[test]
    fn test_first_matching_rule_wins() {
        let policy = TaintPolicy::default()
            .with_rule(FlowRule {
                rule_id: "RULE_1_ALLOW".to_string(),
                source: Some(TaintSource::Diff),
                level: None,
                target: None,
                allow: true,
                rationale: "first rule".to_string(),
            })
            .with_rule(FlowRule {
                rule_id: "RULE_2_DENY".to_string(),
                source: Some(TaintSource::Diff),
                level: None,
                target: None,
                allow: false,
                rationale: "second rule".to_string(),
            });

        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        let decision = policy.evaluate(&tag, TargetContext::Receipt);

        // First matching rule wins
        assert!(decision.allowed);
        assert_eq!(decision.rule_id, "RULE_1_ALLOW");
    }

    #[test]
    fn test_check_flow_returns_violation_on_deny() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);

        let result = policy.check_flow(&tag, TargetContext::Receipt);
        assert!(result.is_err());

        let violation = result.unwrap_err();
        assert_eq!(violation.tag, tag);
        assert_eq!(violation.target, TargetContext::Receipt);
        assert!(!violation.summary().is_empty());
    }

    #[test]
    fn test_check_flow_returns_ok_on_allow() {
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::CasVerified, [0x42; 32]);

        let result = policy.check_flow(&tag, TargetContext::Receipt);
        assert!(result.is_ok());
    }

    // =========================================================================
    // TaintViolation Tests
    // =========================================================================

    #[test]
    fn test_taint_violation_summary() {
        let violation = TaintViolation {
            tag: TaintTag::from_source(TaintSource::Diff, [0x42; 32]),
            target: TargetContext::Receipt,
            rule_id: "DEFAULT_TRUST_CHECK".to_string(),
            description: "test violation".to_string(),
        };

        let summary = violation.summary();
        assert!(summary.contains("UNTRUSTED"));
        assert!(summary.contains("DIFF"));
        assert!(summary.contains("RECEIPT"));
    }

    #[test]
    fn test_taint_violation_serialization_roundtrip() {
        let violation = TaintViolation {
            tag: TaintTag::from_source(TaintSource::WebContent, [0xAB; 32]),
            target: TargetContext::HighAuthorityPrompt,
            rule_id: "TEST_RULE".to_string(),
            description: "test description".to_string(),
        };

        let json = serde_json::to_string(&violation).unwrap();
        let deserialized: TaintViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(violation, deserialized);
    }

    // =========================================================================
    // TaintAggregator Tests
    // =========================================================================

    #[test]
    fn test_aggregator_empty_is_trusted() {
        let agg = TaintAggregator::new();
        assert_eq!(agg.effective_level(), TaintLevel::Trusted);
        assert!(agg.is_empty());
        assert_eq!(agg.len(), 0);
    }

    #[test]
    fn test_aggregator_propagates_highest_level() {
        let mut agg = TaintAggregator::new();
        agg.add(TaintTag::from_source(TaintSource::CasVerified, [0x01; 32]));
        agg.add(TaintTag::from_source(TaintSource::Diff, [0x02; 32]));

        assert_eq!(agg.effective_level(), TaintLevel::Untrusted);
        assert_eq!(agg.len(), 2);
    }

    #[test]
    fn test_aggregator_adversarial_propagates() {
        let mut agg = TaintAggregator::new();
        agg.add(TaintTag::from_source(TaintSource::CasVerified, [0x01; 32]));
        agg.add(TaintTag::from_source(TaintSource::CiAttested, [0x02; 32]));
        agg.add(TaintTag::from_source(TaintSource::WebContent, [0x03; 32]));

        assert_eq!(agg.effective_level(), TaintLevel::Adversarial);
    }

    #[test]
    fn test_aggregator_validate_for_target() {
        let mut agg = TaintAggregator::new();
        agg.add(TaintTag::from_source(TaintSource::CasVerified, [0x01; 32]));
        agg.add(TaintTag::from_source(TaintSource::Diff, [0x02; 32]));

        let policy = TaintPolicy::default();

        // All tags should be OK for evidence artifacts
        let violations = agg.validate_for_target(&policy, TargetContext::EvidenceArtifact);
        assert!(violations.is_empty());

        // The diff tag should fail for receipts
        let violations = agg.validate_for_target(&policy, TargetContext::Receipt);
        assert_eq!(
            violations.len(),
            1,
            "exactly one tag should violate the receipt policy"
        );
        assert_eq!(violations[0].tag.source, TaintSource::Diff);
    }

    #[test]
    fn test_aggregator_tags_accessor() {
        let mut agg = TaintAggregator::new();
        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        agg.add(tag.clone());

        assert_eq!(agg.tags().len(), 1);
        assert_eq!(agg.tags()[0], tag);
    }

    // =========================================================================
    // Fail-Closed Semantics Tests
    // =========================================================================

    #[test]
    fn test_fail_closed_unknown_level_code() {
        // Unknown level codes return None (fail-closed)
        assert!(TaintLevel::from_code(42).is_none());
    }

    #[test]
    fn test_fail_closed_strict_mode_default() {
        // Default policy has strict mode enabled
        let policy = TaintPolicy::default();
        assert!(policy.strict_mode);
    }

    #[test]
    fn test_all_adversarial_flows_to_high_contexts_denied() {
        // Adversarial content must be denied from ALL high-trust contexts
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::WebContent, [0x42; 32]);

        let high_contexts = [
            TargetContext::Receipt,
            TargetContext::PolicyInput,
            TargetContext::HighAuthorityPrompt,
            TargetContext::ContextPack,
            TargetContext::LedgerEvent,
            TargetContext::EvidenceArtifact,
            TargetContext::ToolArgument,
        ];

        for context in &high_contexts {
            let decision = policy.evaluate(&tag, *context);
            assert!(
                !decision.allowed,
                "adversarial content must be denied from {context}"
            );
        }
    }

    #[test]
    fn test_all_untrusted_flows_to_receipt_denied() {
        // All untrusted sources must be denied from receipts
        let policy = TaintPolicy::default();
        let untrusted_sources = [
            TaintSource::Diff,
            TaintSource::ToolOutput,
            TaintSource::FileRead,
            TaintSource::SearchResult,
        ];

        for source in &untrusted_sources {
            let tag = TaintTag::from_source(*source, [0x42; 32]);
            let decision = policy.evaluate(&tag, TargetContext::Receipt);
            assert!(
                !decision.allowed,
                "untrusted {source} content must be denied from receipts"
            );
        }
    }

    // =========================================================================
    // Integration: Policy with ReasonCode mapping
    // =========================================================================

    #[test]
    fn test_violation_maps_to_policy_denied_reason() {
        // TaintViolation should produce information that maps to
        // ReasonCode::PolicyDenied in ReviewBlockedRecorded
        let policy = TaintPolicy::default();
        let tag = TaintTag::from_source(TaintSource::Diff, [0x42; 32]);
        let result = policy.check_flow(&tag, TargetContext::Receipt);

        let violation = result.unwrap_err();
        let summary = violation.summary();

        // The summary should contain enough info for a PolicyViolation trigger
        assert!(summary.contains("taint flow denied"));
        assert!(summary.contains("UNTRUSTED"));
    }

    // =========================================================================
    // Truncation Tests
    // =========================================================================

    #[test]
    fn test_truncate_string() {
        let short = "hello".to_string();
        assert_eq!(truncate_string(short.clone(), 10), short);

        let long = "a".repeat(3000);
        let truncated = truncate_string(long, MAX_VIOLATION_DESCRIPTION_LEN);
        assert!(truncated.len() <= MAX_VIOLATION_DESCRIPTION_LEN);
    }
}
