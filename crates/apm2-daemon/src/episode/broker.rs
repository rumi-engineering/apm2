//! Tool broker for capability-validated tool execution.
//!
//! This module implements the `ToolBroker` per CTR-DAEMON-004. The broker
//! validates tool requests against capability manifests and policies,
//! checks the dedupe cache for idempotent replay, and manages tool execution.
//!
//! # Architecture
//!
//! ```text
//! ToolBroker
//!     ├── capabilities: CapabilityValidator (from TCK-00163)
//!     ├── dedupe_cache: DedupeCache
//!     ├── policy: PolicyEngine (stub - future ticket)
//!     └── cas: ContentAddressedStore (stub - future ticket)
//!
//! Request Flow:
//!     1. validate() - Check request structure
//!     2. lookup_dedupe() - Check cache for idempotent replay
//!     3. validate_capability() - Check against capability manifest
//!     4. evaluate_policy() - Check against policy rules (TODO)
//!     5. execute() - Run the tool and charge budget
//! ```
//!
//! # Security Model
//!
//! Per AD-TOOL-002:
//! - All tool requests MUST be validated against capability manifests
//! - Capabilities are sealed references that cannot be forged
//! - Policy rules provide additional coarse-grained control
//! - Dedupe cache enables idempotent replay for reliability
//!
//! # Contract References
//!
//! - CTR-DAEMON-004: `ToolBroker` structure
//! - AD-TOOL-002: Capability manifests as sealed references
//! - CTR-1303: Bounded collections with MAX_* constants

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;

use apm2_core::context::ContextPackManifest;
use apm2_core::context::firewall::{
    ContextAwareValidator, ContextRiskTier, DefaultContextFirewall, FirewallViolationDefect,
    RiskTierFirewallPolicy, ToctouVerifier, ValidationResult,
};
use apm2_core::policy::{Decision as CoreDecision, LoadedPolicy, PolicyEngine};
use thiserror::Error;
use tracing::{debug, instrument, warn};

use super::capability::{
    CapabilityDecision, CapabilityError, CapabilityManifest, CapabilityValidator, DenyReason,
    ManifestLoadError, ManifestLoader,
};
use super::decision::{
    BrokerToolRequest, BudgetDelta, Credential, DedupeKey, RequestValidationError,
    SessionTerminationInfo, ToolDecision, ToolResult,
};
use super::dedupe::{DedupeCache, DedupeCacheConfig, SharedDedupeCache};
use super::error::EpisodeId;
use super::executor::ContentAddressedStore;
use super::runtime::Hash;
use super::tool_class::ToolClass;
use crate::evidence::keychain::{GitHubCredentialStore, SshCredentialStore};
use crate::metrics::SharedMetricsRegistry;

// =============================================================================
// BrokerError
// =============================================================================

/// Errors that can occur during broker operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrokerError {
    /// Request validation failed.
    #[error("request validation failed: {0}")]
    RequestValidation(#[from] RequestValidationError),

    /// Capability validation failed.
    #[error("capability error: {0}")]
    CapabilityError(#[from] CapabilityError),

    /// Manifest loading failed.
    #[error("manifest load error: {0}")]
    ManifestLoadError(#[from] ManifestLoadError),

    /// Broker not initialized.
    #[error("broker not initialized: call initialize() first")]
    NotInitialized,

    /// Budget exceeded.
    #[error("budget exceeded: {resource}")]
    BudgetExceeded {
        /// The resource that was exceeded.
        resource: String,
    },

    /// Tool execution failed.
    #[error("tool execution failed: {message}")]
    ExecutionFailed {
        /// Error message.
        message: String,
    },

    /// Internal error.
    #[error("internal broker error: {message}")]
    Internal {
        /// Error message.
        message: String,
    },

    /// Context pack not found in CAS (TCK-00326).
    ///
    /// Per RFC-0019, this triggers `ReviewBlockedRecorded` emission
    /// with `reason_code` `MISSING_ARTIFACT`.
    #[error("context pack not found in CAS: hash {hash}")]
    ContextPackNotFound {
        /// Hex-encoded hash of the missing context pack.
        hash: String,
    },

    /// Context pack seal verification failed (TCK-00326).
    ///
    /// Per RFC-0019, this triggers `ReviewBlockedRecorded` emission
    /// with `reason_code` `INVALID_BUNDLE`.
    #[error("context pack seal invalid: {reason}")]
    ContextPackSealInvalid {
        /// Reason for seal verification failure.
        reason: String,
    },

    /// Context pack deserialization failed (TCK-00326).
    #[error("context pack deserialization failed: {reason}")]
    ContextPackDeserializationFailed {
        /// Reason for deserialization failure.
        reason: String,
    },

    /// Context pack integrity check failed (TCK-00326).
    ///
    /// The blake3 hash of the retrieved content does not match the expected
    /// `context_pack_hash`. This could indicate CAS corruption or tampering.
    #[error("context pack integrity mismatch: expected {expected}, computed {computed}")]
    ContextPackIntegrityMismatch {
        /// Expected hash (from the request).
        expected: String,
        /// Computed hash (from blake3 of the retrieved content).
        computed: String,
    },
}

impl BrokerError {
    /// Returns the error kind as a string identifier.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::RequestValidation(_) => "request_validation",
            Self::CapabilityError(_) => "capability_error",
            Self::ManifestLoadError(_) => "manifest_load_error",
            Self::NotInitialized => "not_initialized",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::ExecutionFailed { .. } => "execution_failed",
            Self::Internal { .. } => "internal",
            Self::ContextPackNotFound { .. } => "context_pack_not_found",
            Self::ContextPackSealInvalid { .. } => "context_pack_seal_invalid",
            Self::ContextPackDeserializationFailed { .. } => "context_pack_deserialization_failed",
            Self::ContextPackIntegrityMismatch { .. } => "context_pack_integrity_mismatch",
        }
    }

    /// Returns `true` if this error is retriable.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        matches!(self, Self::ExecutionFailed { .. })
    }

    /// Returns `true` if this error should trigger `ReviewBlockedRecorded`
    /// (TCK-00326).
    ///
    /// Per RFC-0019, context pack errors should emit a `ReviewBlockedRecorded`
    /// event to the ledger for audit and fail-closed behavior.
    #[must_use]
    pub const fn should_emit_review_blocked(&self) -> bool {
        matches!(
            self,
            Self::ContextPackNotFound { .. }
                | Self::ContextPackSealInvalid { .. }
                | Self::ContextPackDeserializationFailed { .. }
                | Self::ContextPackIntegrityMismatch { .. }
        )
    }
}

// =============================================================================
// PolicyEngine Integration (TCK-00292)
//
// Real policy engine integration with deny-by-default behavior.
// Per RFC-0018 HEF requirements, policy evaluation is fail-closed.
// =============================================================================

/// Policy evaluation result.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Request is allowed by policy.
    Allow {
        /// Optional rule ID that allowed the request.
        rule_id: Option<String>,
    },

    /// Request is denied by policy.
    Deny {
        /// Rule ID that denied the request.
        rule_id: String,
        /// Reason for denial.
        reason: String,
    },
}

/// Rule ID for deny-by-default when no policy is configured.
pub const NO_POLICY_RULE_ID: &str = "NO_POLICY_CONFIGURED";

/// Rationale for deny-by-default when no policy is configured.
pub const NO_POLICY_RATIONALE: &str = "POLICY_MISSING";

const ROLE_ALLOWLIST_POLICY_VERSION: &str = "1.0.0";
const ROLE_ALLOWLIST_RULE_PREFIX: &str = "ALLOW_ROLE_TOOL";
const ROLE_ALLOWLIST_DENY_ALL_RULE_ID: &str = "DENY_ALL_TOOLS";

/// Policy engine wrapper for the tool broker (TCK-00292).
///
/// Integrates the real `PolicyEngine` from `apm2-core` and implements
/// deny-by-default when policy is missing or invalid.
///
/// # Security Properties
///
/// - **Fail-closed**: Returns deny when policy is missing or evaluation fails
/// - **Default-deny**: No stub allow path; all requests require valid policy
/// - **Real policy hash**: Propagates actual policy content hash in decisions
#[derive(Debug, Clone)]
pub struct BrokerPolicyEngine {
    /// The underlying policy engine (if configured).
    engine: Option<PolicyEngine>,
    /// Hash of the policy version (zeros if no policy is configured).
    policy_hash: Hash,
}

impl Default for BrokerPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerPolicyEngine {
    /// Creates a new broker policy engine with no policy configured.
    ///
    /// Per TCK-00292, requests will be denied by default when no policy
    /// is configured (fail-closed behavior).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            engine: None,
            policy_hash: [0u8; 32],
        }
    }

    /// Creates a broker policy engine from a loaded policy.
    #[must_use]
    pub fn from_policy(policy: &LoadedPolicy) -> Self {
        let engine = PolicyEngine::new(policy);
        let policy_hash = *engine.policy_hash();
        Self {
            engine: Some(engine),
            policy_hash,
        }
    }

    /// Creates a broker policy engine from an Arc-wrapped loaded policy.
    #[must_use]
    pub fn from_arc(policy: Arc<LoadedPolicy>) -> Self {
        let engine = PolicyEngine::from_arc(policy);
        let policy_hash = *engine.policy_hash();
        Self {
            engine: Some(engine),
            policy_hash,
        }
    }

    /// Creates a deny-by-default policy engine from a role tool allowlist.
    ///
    /// The resulting policy has one allow rule per unique tool pattern and a
    /// default deny fallback. Empty allowlists produce an explicit deny-all
    /// policy (still with default deny).
    pub fn from_tool_allowlist(
        policy_name: &str,
        tool_allowlist: &[ToolClass],
    ) -> Result<Self, BrokerError> {
        let mut patterns = BTreeSet::new();
        for tool in tool_allowlist {
            patterns.insert(tool_class_to_policy_pattern(*tool));
        }

        let mut rules_yaml = String::new();
        for (idx, pattern) in patterns.iter().enumerate() {
            write!(
                rules_yaml,
                "    - id: \"{ROLE_ALLOWLIST_RULE_PREFIX}-{idx:04}\"\n      type: tool_allow\n      tool: \"{pattern}\"\n      decision: allow\n"
            )
            .expect("writing to String is infallible");
        }

        // Policy parser requires at least one rule. When the role allowlist is
        // empty, emit an explicit deny-all rule.
        if patterns.is_empty() {
            write!(
                rules_yaml,
                "    - id: \"{ROLE_ALLOWLIST_DENY_ALL_RULE_ID}\"\n      type: tool_deny\n      tool: \"*\"\n      decision: deny\n"
            )
            .expect("writing to String is infallible");
        }

        let policy_yaml = format!(
            "policy:\n  version: \"{ROLE_ALLOWLIST_POLICY_VERSION}\"\n  name: \"{policy_name}\"\n  rules:\n{rules_yaml}  default_decision: deny\n"
        );

        let loaded = LoadedPolicy::from_yaml(&policy_yaml).map_err(|e| BrokerError::Internal {
            message: format!("failed to build role allowlist policy: {e}"),
        })?;
        Ok(Self::from_policy(&loaded))
    }

    /// Returns `true` if a policy is configured.
    #[must_use]
    pub const fn has_policy(&self) -> bool {
        self.engine.is_some()
    }

    /// Evaluates a request against policy.
    ///
    /// Per TCK-00292, implements deny-by-default:
    /// - If no policy is configured, the request is denied
    /// - If policy evaluation fails, the request is denied
    /// - Only explicit allow rules permit requests
    #[must_use]
    pub fn evaluate(&self, request: &BrokerToolRequest) -> PolicyDecision {
        let Some(ref engine) = self.engine else {
            warn!(
                request_id = %request.request_id,
                "policy evaluation denied: no policy configured"
            );
            return PolicyDecision::Deny {
                rule_id: NO_POLICY_RULE_ID.to_string(),
                reason: "No policy configured; deny by default".to_string(),
            };
        };

        let policy_request = request.to_policy_request();
        let result = engine.evaluate(&policy_request);

        match result.decision {
            CoreDecision::Allow => PolicyDecision::Allow {
                rule_id: Some(result.rule_id),
            },
            CoreDecision::Deny => PolicyDecision::Deny {
                rule_id: result.rule_id,
                reason: result.message,
            },
            _ => PolicyDecision::Deny {
                rule_id: result.rule_id,
                reason: format!("Unknown decision; denying by default: {}", result.message),
            },
        }
    }

    /// Returns the policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> Hash {
        self.policy_hash
    }
}

const fn tool_class_to_policy_pattern(tool: ToolClass) -> &'static str {
    match tool {
        ToolClass::Read => "fs.read",
        ToolClass::Write => "fs.write",
        ToolClass::Execute | ToolClass::Network => "shell.exec",
        ToolClass::Git => "git.*",
        ToolClass::Inference => "inference",
        ToolClass::Artifact => "artifact.fetch",
        ToolClass::ListFiles => "fs.list_files",
        ToolClass::Search => "fs.search",
        _ => "*",
    }
}

/// Stub policy engine for test compatibility.
///
/// **DEPRECATED**: Use `BrokerPolicyEngine` for production code.
#[derive(Debug, Clone, Default)]
#[cfg(test)]
pub struct StubPolicyEngine {
    policy_hash: Hash,
}

#[cfg(test)]
impl StubPolicyEngine {
    /// Creates a new stub policy engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy_hash: [0u8; 32],
        }
    }

    /// Evaluates a request against policy (stub always allows).
    #[must_use]
    pub const fn evaluate(&self, _request: &BrokerToolRequest) -> PolicyDecision {
        PolicyDecision::Allow { rule_id: None }
    }

    /// Returns the policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> Hash {
        self.policy_hash
    }
}

// =============================================================================
// ContentAddressedStore Stub (TCK-00293: TEST ONLY)
//
// Per TCK-00293, the stub is retained ONLY for tests. Production code MUST
// use `DurableCas` via `new_shared_broker_with_cas()` or `.with_cas()`.
// =============================================================================

// =============================================================================
// RiskTier <-> ContextRiskTier Conversion (TCK-00375)
// =============================================================================

/// Converts the daemon's `RiskTier` to the firewall's `ContextRiskTier`.
///
/// This conversion is infallible because both enums have the same variants.
/// If a new `RiskTier` variant is added without a corresponding
/// `ContextRiskTier`, this will fail at compile time (fail-closed).
impl From<super::envelope::RiskTier> for ContextRiskTier {
    fn from(tier: super::envelope::RiskTier) -> Self {
        match tier {
            super::envelope::RiskTier::Tier0 => Self::Tier0,
            super::envelope::RiskTier::Tier1 => Self::Tier1,
            super::envelope::RiskTier::Tier2 => Self::Tier2,
            super::envelope::RiskTier::Tier3 => Self::Tier3,
            super::envelope::RiskTier::Tier4 => Self::Tier4,
        }
    }
}

/// Stub content-addressed store for testing.
///
/// **WARNING**: This stub does NOT persist artifacts across daemon restarts.
/// Per TCK-00293 and RFC-0018 HEF requirements, production code MUST use
/// [`crate::cas::DurableCas`] instead.
///
/// # When to Use
///
/// - Unit tests where persistence is not required
/// - Integration tests that mock CAS behavior
///
/// # Production Usage
///
/// Production code MUST use [`crate::cas::DurableCas`]:
///
/// ```rust,ignore
/// use apm2_daemon::cas::{DurableCas, DurableCasConfig};
/// use apm2_daemon::episode::{new_shared_broker_with_cas, ToolBrokerConfig};
///
/// let cas = Arc::new(DurableCas::new(DurableCasConfig::new("/var/lib/apm2/cas"))?);
/// let broker = new_shared_broker_with_cas(ToolBrokerConfig::default(), cas);
/// ```
#[derive(Debug, Clone, Default)]
pub struct StubContentAddressedStore;

impl StubContentAddressedStore {
    /// Creates a new stub CAS.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Retrieves content by hash (stub always returns None).
    #[must_use]
    pub const fn retrieve(&self, _hash: &Hash) -> Option<Vec<u8>> {
        None
    }

    /// Stores content and returns its hash.
    #[must_use]
    pub fn store(&self, content: &[u8]) -> Hash {
        *blake3::hash(content).as_bytes()
    }
}

// =============================================================================
// ToolBrokerConfig
// =============================================================================

/// Configuration for the tool broker.
#[derive(Debug, Clone)]
pub struct ToolBrokerConfig {
    /// Dedupe cache configuration.
    pub dedupe_config: DedupeCacheConfig,

    /// Whether to check policy (default: true).
    pub check_policy: bool,

    /// Whether to use dedupe cache (default: true).
    pub use_dedupe_cache: bool,
}

impl Default for ToolBrokerConfig {
    fn default() -> Self {
        Self {
            dedupe_config: DedupeCacheConfig::default(),
            check_policy: true,
            use_dedupe_cache: true,
        }
    }
}

impl ToolBrokerConfig {
    /// Creates a config with a custom dedupe config.
    #[must_use]
    pub const fn with_dedupe_config(mut self, config: DedupeCacheConfig) -> Self {
        self.dedupe_config = config;
        self
    }

    /// Disables policy checking.
    #[must_use]
    pub const fn without_policy_check(mut self) -> Self {
        self.check_policy = false;
        self
    }

    /// Disables dedupe caching.
    #[must_use]
    pub const fn without_dedupe_cache(mut self) -> Self {
        self.use_dedupe_cache = false;
        self
    }
}

// =============================================================================
// ToolBroker
// =============================================================================

/// Tool broker for capability-validated tool execution.
///
/// The broker validates tool requests against capability manifests and
/// policies, checks the dedupe cache for idempotent replay, and manages
/// tool execution.
///
/// # Lifecycle
///
/// 1. Create broker with `new()`
/// 2. Initialize with manifest via `initialize()` or
///    `initialize_with_manifest()`
/// 3. Process requests via `request()`
/// 4. Execute allowed requests via `execute()`
///
/// # Thread Safety
///
/// `ToolBroker` is `Send + Sync` via internal synchronization.
/// All operations are async and may block waiting for locks.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::broker::{ToolBroker, ToolBrokerConfig};
///
/// let broker = ToolBroker::new(test_config_without_policy());
///
/// // Initialize with a capability manifest
/// broker.initialize_with_manifest(manifest).await?;
///
/// // Process a request
/// let decision = broker.request(episode_id, tool_request, timestamp_ns).await?;
///
/// match decision {
///     ToolDecision::Allow { .. } => {
///         // Execute the tool
///         let result = broker.execute(episode_id, decision, timestamp_ns).await?;
///     },
///     ToolDecision::Deny { reason, .. } => {
///         // Log denial
///     },
///     ToolDecision::DedupeCacheHit { result, .. } => {
///         // Use cached result
///     },
/// }
/// ```
pub struct ToolBroker<L: ManifestLoader = super::capability::StubManifestLoader> {
    /// Configuration.
    config: ToolBrokerConfig,

    /// Capability validator (set after initialization).
    validator: tokio::sync::RwLock<Option<CapabilityValidator>>,

    /// Dedupe cache for idempotent replay.
    dedupe_cache: SharedDedupeCache,

    /// Policy engine (TCK-00292).
    ///
    /// Uses `BrokerPolicyEngine` with deny-by-default behavior.
    /// Set via `set_policy()` or `with_policy()` before processing requests
    /// when `check_policy` is enabled.
    policy: BrokerPolicyEngine,

    /// Content-addressed store for evidence artifacts (TCK-00293).
    ///
    /// Per RFC-0018 HEF requirements, the CAS stores artifacts durably with
    /// content addressing. In production, this should be a `DurableCas`
    /// instance. For tests, `StubContentAddressedStore` provides an
    /// in-memory fallback.
    #[allow(dead_code)]
    cas: Arc<dyn ContentAddressedStore>,

    /// Optional manifest loader for CAS-based initialization.
    #[allow(dead_code)]
    loader: Option<Arc<L>>,

    /// Context pack manifest for firewall enforcement (TCK-00261).
    context_manifest: tokio::sync::RwLock<Option<Arc<ContextPackManifest>>>,

    /// GitHub credential store for broker-mediated access (TCK-00262).
    ///
    /// Per RFC-0017 TB-003, credentials are held by the daemon and never
    /// exposed to session processes. The broker fetches credentials from
    /// this store when processing Git/Network tool requests.
    github_store: Option<Arc<dyn GitHubCredentialStore>>,

    /// SSH credential store for broker-mediated access (TCK-00263).
    ///
    /// Per RFC-0017 TB-003, SSH credentials (`SSH_AUTH_SOCK`) are held by the
    /// daemon and never exposed to session processes. The broker uses this
    /// store to provide SSH agent access for Git SSH operations.
    ssh_store: Option<Arc<dyn SshCredentialStore>>,

    /// Prometheus metrics registry for daemon health observability (TCK-00268).
    ///
    /// When present, the broker emits metrics for:
    /// - `tool_mediation_latency`: After each tool mediation decision
    /// - `context_firewall_denial`: When context firewall denies a request
    /// - `session_terminated`: When context firewall triggers termination
    ///
    /// # Integration Status
    ///
    /// **NOTE**: The `ToolBroker` is not currently instantiated in `main.rs`.
    /// It is used by the `PrivilegedDispatcher` binary protocol path which is
    /// not yet wired into the daemon's connection handling.
    ///
    /// These metrics will become active when the binary protocol and tool
    /// mediation flows are integrated into the daemon. Until then, they are
    /// exercised only in unit tests.
    ///
    /// TODO(TCK-FUTURE): Wire `ToolBroker` into `main.rs` via
    /// `PrivilegedDispatcher` to enable tool mediation metrics.
    metrics: Option<SharedMetricsRegistry>,

    /// Risk-tier-aware firewall enforcement policy (TCK-00375).
    ///
    /// Maps risk tiers to firewall enforcement modes. Tier3+ violations
    /// ALWAYS use `HardFail` (mandatory session termination) per REQ-0029.
    firewall_policy: RiskTierFirewallPolicy,

    /// Accumulated firewall violation defects (TCK-00375).
    ///
    /// Per REQ-0029, Tier3+ violations MUST emit defects. This vec collects
    /// defects for the caller to drain and emit to the event ledger.
    /// Uses per-invocation collection (not shared buffer) per review pattern.
    firewall_defects: tokio::sync::Mutex<Vec<FirewallViolationDefect>>,
}

impl<L: ManifestLoader + Send + Sync> ToolBroker<L> {
    /// Creates a new tool broker with the given configuration.
    #[must_use]
    pub fn new(config: ToolBrokerConfig) -> Self {
        let dedupe_cache = Arc::new(DedupeCache::new(config.dedupe_config.clone()));

        Self {
            config,
            validator: tokio::sync::RwLock::new(None),
            dedupe_cache,
            policy: BrokerPolicyEngine::new(),
            cas: Arc::new(StubContentAddressedStore::new()),
            loader: None,
            context_manifest: tokio::sync::RwLock::new(None),
            github_store: None,
            ssh_store: None,
            metrics: None,
            firewall_policy: RiskTierFirewallPolicy::default(),
            firewall_defects: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new tool broker with a manifest loader.
    #[must_use]
    pub fn with_loader(config: ToolBrokerConfig, loader: Arc<L>) -> Self {
        let dedupe_cache = Arc::new(DedupeCache::new(config.dedupe_config.clone()));

        Self {
            config,
            validator: tokio::sync::RwLock::new(None),
            dedupe_cache,
            policy: BrokerPolicyEngine::new(),
            cas: Arc::new(StubContentAddressedStore::new()),
            loader: Some(loader),
            context_manifest: tokio::sync::RwLock::new(None),
            github_store: None,
            ssh_store: None,
            metrics: None,
            firewall_policy: RiskTierFirewallPolicy::default(),
            firewall_defects: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new tool broker with a GitHub credential store.
    ///
    /// Per RFC-0017 TB-003, credentials are held by the daemon only. This
    /// constructor enables credential mediation for Git/Network operations.
    #[must_use]
    pub fn with_github_store(
        config: ToolBrokerConfig,
        github_store: Arc<dyn GitHubCredentialStore>,
    ) -> Self {
        let dedupe_cache = Arc::new(DedupeCache::new(config.dedupe_config.clone()));

        Self {
            config,
            validator: tokio::sync::RwLock::new(None),
            dedupe_cache,
            policy: BrokerPolicyEngine::new(),
            cas: Arc::new(StubContentAddressedStore::new()),
            loader: None,
            context_manifest: tokio::sync::RwLock::new(None),
            github_store: Some(github_store),
            ssh_store: None,
            metrics: None,
            firewall_policy: RiskTierFirewallPolicy::default(),
            firewall_defects: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new tool broker with an SSH credential store.
    ///
    /// Per RFC-0017 TB-003 and TCK-00263, SSH credentials (`SSH_AUTH_SOCK`) are
    /// held by the daemon only. This constructor enables credential mediation
    /// for Git SSH operations.
    #[must_use]
    pub fn with_ssh_store(
        config: ToolBrokerConfig,
        ssh_store: Arc<dyn SshCredentialStore>,
    ) -> Self {
        let dedupe_cache = Arc::new(DedupeCache::new(config.dedupe_config.clone()));

        Self {
            config,
            validator: tokio::sync::RwLock::new(None),
            dedupe_cache,
            policy: BrokerPolicyEngine::new(),
            cas: Arc::new(StubContentAddressedStore::new()),
            loader: None,
            context_manifest: tokio::sync::RwLock::new(None),
            github_store: None,
            ssh_store: Some(ssh_store),
            metrics: None,
            firewall_policy: RiskTierFirewallPolicy::default(),
            firewall_defects: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new tool broker with both GitHub and SSH credential stores.
    ///
    /// Per RFC-0017 TB-003, credentials are held by the daemon only. This
    /// constructor enables credential mediation for both HTTPS and SSH Git
    /// operations.
    #[must_use]
    pub fn with_credential_stores(
        config: ToolBrokerConfig,
        github_store: Arc<dyn GitHubCredentialStore>,
        ssh_store: Arc<dyn SshCredentialStore>,
    ) -> Self {
        let dedupe_cache = Arc::new(DedupeCache::new(config.dedupe_config.clone()));

        Self {
            config,
            validator: tokio::sync::RwLock::new(None),
            dedupe_cache,
            policy: BrokerPolicyEngine::new(),
            cas: Arc::new(StubContentAddressedStore::new()),
            loader: None,
            context_manifest: tokio::sync::RwLock::new(None),
            github_store: Some(github_store),
            ssh_store: Some(ssh_store),
            metrics: None,
            firewall_policy: RiskTierFirewallPolicy::default(),
            firewall_defects: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Adds a metrics registry to the broker (TCK-00268).
    ///
    /// When set, the broker will emit metrics for:
    /// - `tool_mediation_latency`: After each tool mediation decision
    /// - `context_firewall_denial`: When context firewall denies a request
    /// - `session_terminated`: When context firewall triggers termination
    ///
    /// # Integration Status
    ///
    /// **NOTE**: This method is currently only exercised in tests. The
    /// `ToolBroker` is not yet wired into `main.rs`. See the `metrics`
    /// field documentation for details.
    #[must_use]
    pub fn with_metrics(mut self, metrics: SharedMetricsRegistry) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Sets the risk-tier-aware firewall policy (TCK-00375).
    ///
    /// Per REQ-0029, Tier3+ violations always use `HardFail` regardless of
    /// this policy. This method controls the mode for lower tiers.
    #[must_use]
    pub const fn with_firewall_policy(mut self, policy: RiskTierFirewallPolicy) -> Self {
        self.firewall_policy = policy;
        self
    }

    /// Drains accumulated firewall violation defects (TCK-00375).
    ///
    /// Per REQ-0029, the caller MUST emit these defects to the event ledger
    /// after processing tool requests. The defects are cleared after draining.
    ///
    /// # Returns
    ///
    /// A `Vec` of defects accumulated since the last drain call.
    pub async fn drain_firewall_defects(&self) -> Vec<FirewallViolationDefect> {
        let mut defects = self.firewall_defects.lock().await;
        std::mem::take(&mut *defects)
    }

    /// Verifies TOCTOU hash consistency for file content (TCK-00375).
    ///
    /// This method should be called after a read operation succeeds but
    /// before the content is delivered to the agent. It verifies that the
    /// runtime content matches the hash recorded in the manifest.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path (normalized)
    /// * `content` - The file content bytes read at runtime
    /// * `risk_tier` - The current episode's risk tier
    ///
    /// # Returns
    ///
    /// `Ok(())` if the hash matches or if no manifest is loaded.
    /// `Err(BrokerError)` if the hash mismatches.
    ///
    /// # Security
    ///
    /// Per REQ-0029, TOCTOU mismatches detected at Tier3+ will:
    /// 1. Emit a mandatory `FirewallViolationDefect`
    /// 2. Return an error that should trigger session termination
    pub async fn verify_toctou(
        &self,
        path: &str,
        content: &[u8],
        risk_tier: super::envelope::RiskTier,
    ) -> Result<(), BrokerError> {
        let context_manifest = self.context_manifest.read().await;
        let Some(manifest) = context_manifest.as_ref() else {
            // No context manifest loaded; TOCTOU check not applicable
            return Ok(());
        };

        // Look up the entry for this path
        let normalized =
            apm2_core::context::normalize_path(path).map_err(|e| BrokerError::Internal {
                message: format!("TOCTOU path normalization failed: {e}"),
            })?;

        let Some(entry) = manifest.get_entry_normalized(&normalized) else {
            // Path not in manifest; this should have been caught by the
            // allowlist check already. If we get here, it's a logic error.
            return Err(BrokerError::Internal {
                message: format!("TOCTOU: path {normalized} passed allowlist but has no entry"),
            });
        };

        let ctx_risk_tier: ContextRiskTier = risk_tier.into();
        let mode = self.firewall_policy.mode_for_tier(ctx_risk_tier);

        if let Err(e) = ToctouVerifier::verify_for_firewall(
            content,
            entry.content_hash(),
            &manifest.manifest_id,
            &normalized,
            mode,
        ) {
            // TCK-00375: Emit mandatory defect for Tier3+ violations
            if ctx_risk_tier.is_high_risk() {
                let defect = FirewallViolationDefect::toctou_mismatch(
                    risk_tier.tier(),
                    &manifest.manifest_id,
                    &normalized,
                );
                self.firewall_defects.lock().await.push(defect);
            }

            // Emit metrics if available
            if let Some(ref metrics) = self.metrics {
                metrics
                    .daemon_metrics()
                    .context_firewall_denied("TOCTOU_MISMATCH");
                if e.should_terminate_session() {
                    metrics
                        .daemon_metrics()
                        .session_terminated("TOCTOU_MISMATCH");
                }
            }

            warn!(
                path = %normalized,
                risk_tier = risk_tier.tier(),
                should_terminate = e.should_terminate_session(),
                "TOCTOU hash mismatch detected"
            );

            return Err(BrokerError::Internal {
                message: e.to_string(),
            });
        }

        Ok(())
    }

    /// Sets the content-addressed store for evidence artifacts (TCK-00293).
    ///
    /// Per RFC-0018 HEF requirements and TCK-00293, the CAS stores artifacts
    /// durably with content addressing. In production, this should be a
    /// `DurableCas` instance. The default `StubContentAddressedStore` is only
    /// for tests and will not persist artifacts across restarts.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use apm2_daemon::cas::{DurableCas, DurableCasConfig};
    /// use apm2_daemon::episode::{ToolBroker, ToolBrokerConfig};
    ///
    /// let cas_config = DurableCasConfig::new("/var/lib/apm2/cas");
    /// let cas = Arc::new(DurableCas::new(cas_config)?);
    /// let broker = ToolBroker::new(ToolBrokerConfig::default())
    ///     .with_cas(cas);
    /// ```
    #[must_use]
    pub fn with_cas(mut self, cas: Arc<dyn ContentAddressedStore>) -> Self {
        self.cas = cas;
        self
    }

    /// Returns `true` if a GitHub credential store is configured.
    #[must_use]
    pub fn has_github_store(&self) -> bool {
        self.github_store.is_some()
    }

    /// Returns `true` if an SSH credential store is configured.
    #[must_use]
    pub fn has_ssh_store(&self) -> bool {
        self.ssh_store.is_some()
    }

    /// Returns `true` if a policy is configured (TCK-00292).
    #[must_use]
    pub const fn has_policy(&self) -> bool {
        self.policy.has_policy()
    }

    /// Sets the policy engine from a loaded policy (TCK-00292).
    pub fn set_policy(&mut self, policy: &LoadedPolicy) {
        self.policy = BrokerPolicyEngine::from_policy(policy);
    }

    /// Sets the policy engine from an Arc-wrapped loaded policy (TCK-00292).
    pub fn set_policy_arc(&mut self, policy: Arc<LoadedPolicy>) {
        self.policy = BrokerPolicyEngine::from_arc(policy);
    }

    /// Sets a deny-by-default policy derived from role tool allowlist entries.
    ///
    /// This is used in production session bootstrap to ensure policy checks
    /// enforce the role-scoped tool surface.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Internal`] if policy materialization fails.
    pub fn set_policy_from_tool_allowlist(
        &mut self,
        policy_name: &str,
        tool_allowlist: &[ToolClass],
    ) -> Result<(), BrokerError> {
        self.policy = BrokerPolicyEngine::from_tool_allowlist(policy_name, tool_allowlist)?;
        Ok(())
    }

    /// Creates a builder-style broker with a policy configured (TCK-00292).
    #[must_use]
    pub fn with_policy(mut self, policy: &LoadedPolicy) -> Self {
        self.policy = BrokerPolicyEngine::from_policy(policy);
        self
    }

    /// Creates a builder-style broker with an Arc-wrapped policy (TCK-00292).
    #[must_use]
    pub fn with_policy_arc(mut self, policy: Arc<LoadedPolicy>) -> Self {
        self.policy = BrokerPolicyEngine::from_arc(policy);
        self
    }

    /// Returns `true` if SSH agent is available for broker-mediated operations
    /// (TCK-00263).
    ///
    /// This checks if an SSH agent is available, either via a per-session
    /// socket stored in the keychain, or via the daemon-wide `SSH_AUTH_SOCK`.
    ///
    /// # Arguments
    ///
    /// * `session_context` - Optional session context for per-session lookup
    pub async fn is_ssh_agent_available(
        &self,
        session_context: Option<&super::decision::SessionContext>,
    ) -> bool {
        let Some(store) = self.ssh_store.as_ref() else {
            return false;
        };

        // First check per-session SSH agent socket if session context provided
        if let Some(ctx) = session_context {
            if let Some(ref session_id) = ctx.ssh_session_id {
                // Try to get per-session SSH_AUTH_SOCK from keychain
                if let Ok(path) = tokio::task::spawn_blocking({
                    let store = Arc::clone(store);
                    let session_id = session_id.clone();
                    move || store.get_ssh_auth_sock(&session_id)
                })
                .await
                .unwrap_or(Err(crate::evidence::keychain::KeychainError::LockPoisoned))
                {
                    // Check if the socket exists
                    if std::path::Path::new(&path).exists() {
                        return true;
                    }
                }
            }
        }

        // Fall back to daemon-wide SSH agent check
        // REMOVED for security: Sessions MUST NOT access the daemon's SSH agent.
        // store.is_ssh_agent_available()
        false
    }

    /// Gets the `SSH_AUTH_SOCK` path for broker-mediated Git SSH operations
    /// (TCK-00263).
    ///
    /// Per RFC-0017 TB-003, this returns the `SSH_AUTH_SOCK` path for use in
    /// subprocess environment. The session process NEVER has direct access to
    /// this path - it's only used by the broker when executing git commands.
    ///
    /// # Priority Order (TCK-00263)
    ///
    /// 1. Per-session SSH agent socket (if `session_context` is provided and
    ///    has `ssh_session_id` with a stored socket path)
    /// 2. Daemon-wide `SSH_AUTH_SOCK` (fallback)
    ///
    /// # Arguments
    ///
    /// * `session_context` - Optional session context for per-session lookup
    ///
    /// # Returns
    ///
    /// `Some(path)` if SSH agent is available, `None` otherwise.
    pub async fn get_ssh_auth_sock_for_subprocess(
        &self,
        session_context: Option<&super::decision::SessionContext>,
    ) -> Option<String> {
        let store = self.ssh_store.as_ref()?;

        // Only use per-session SSH agent socket (TCK-00263)
        // Per security review, we must NOT fall back to the daemon's SSH agent
        // as that would leak operator credentials to sessions.
        if let Some(ctx) = session_context {
            if let Some(ref session_id) = ctx.ssh_session_id {
                // Try to get per-session SSH_AUTH_SOCK from keychain using spawn_blocking
                // to avoid blocking I/O in async context
                if let Ok(Ok(path)) = tokio::task::spawn_blocking({
                    let store = Arc::clone(store);
                    let session_id = session_id.clone();
                    move || store.get_ssh_auth_sock(&session_id)
                })
                .await
                {
                    // Verify the socket exists
                    if std::path::Path::new(&path).exists() {
                        debug!(session_id = %session_id, "using per-session SSH agent socket");
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    /// Fetches a credential for a tool request if applicable.
    ///
    /// Per RFC-0017 TB-003 (Credential Isolation Boundary), credentials are
    /// held by the daemon and never exposed to session processes. This method
    /// fetches credentials for Git/Network tool classes when:
    /// 1. A GitHub credential store is configured with an installation ID, OR
    /// 2. An SSH credential store is configured with an available SSH agent
    ///
    /// # Credential Priority (TCK-00263)
    ///
    /// For Git tool class:
    /// 1. First try GitHub token (for HTTPS remotes)
    /// 2. Fall back to `SSH_AUTH_SOCK` (for SSH remotes, checking per-session
    ///    socket first)
    ///
    /// For Network tool class:
    /// - Only GitHub tokens are applicable
    ///
    /// # Arguments
    ///
    /// * `tool_class` - The tool class being requested
    /// * `session_context` - Optional session context for credential lookup
    ///
    /// # Returns
    ///
    /// `Some(Credential)` if credentials were successfully fetched,
    /// `None` if no credential store is configured or credentials are not
    /// available.
    async fn fetch_credential_for_request(
        &self,
        tool_class: ToolClass,
        session_context: Option<&super::decision::SessionContext>,
    ) -> Option<Credential> {
        // Only fetch credentials for Git and Network tool classes
        if !matches!(tool_class, ToolClass::Git | ToolClass::Network) {
            return None;
        }

        // Try GitHub credentials first (for HTTPS remotes)
        if let Some(cred) = self
            .fetch_github_credential_for_request(tool_class, session_context)
            .await
        {
            return Some(cred);
        }

        // For Git tool class, also try SSH credentials (TCK-00263)
        if tool_class == ToolClass::Git {
            if let Some(cred) = self.fetch_ssh_credential_for_request(session_context).await {
                return Some(cred);
            }
        }

        None
    }

    /// Fetches GitHub credentials for a tool request.
    ///
    /// Per TCK-00262, this checks for GitHub installation ID from the session
    /// context and fetches the corresponding token from the GitHub credential
    /// store.
    ///
    /// # Arguments
    ///
    /// * `tool_class` - The tool class being requested (for logging)
    /// * `session_context` - Optional session context containing GitHub
    ///   installation ID
    async fn fetch_github_credential_for_request(
        &self,
        tool_class: ToolClass,
        session_context: Option<&super::decision::SessionContext>,
    ) -> Option<Credential> {
        // Check if we have a credential store configured
        let store = self.github_store.as_ref()?;

        // Check if we have an installation ID from the session context
        let ctx = session_context?;
        let installation_id = ctx.github_installation_id.as_ref()?;

        // Fetch the token from the store using spawn_blocking to avoid
        // blocking I/O in async context (keyring crate uses blocking I/O)
        let store = Arc::clone(store);
        let installation_id = installation_id.clone();
        let tool_class_for_log = tool_class;

        match tokio::task::spawn_blocking(move || store.get_token(&installation_id)).await {
            Ok(Ok(token)) => {
                debug!(
                    tool_class = ?tool_class_for_log,
                    "GitHub credential fetched for tool request"
                );
                Some(Credential::new(token))
            },
            Ok(Err(e)) => {
                warn!(
                    tool_class = ?tool_class_for_log,
                    error = %e,
                    "failed to fetch GitHub credential for tool request"
                );
                None
            },
            Err(e) => {
                warn!(
                    tool_class = ?tool_class_for_log,
                    error = %e,
                    "spawn_blocking panicked while fetching GitHub credential"
                );
                None
            },
        }
    }

    /// Fetches SSH credentials for a tool request (TCK-00263).
    ///
    /// Per RFC-0017 TB-003, this returns the `SSH_AUTH_SOCK` path as a
    /// credential. The session process NEVER has direct access to this path -
    /// it's only used by the broker when executing git commands in subprocess.
    ///
    /// # Priority Order (TCK-00263)
    ///
    /// 1. Per-session SSH agent socket (if `session_context` is provided and
    ///    has `ssh_session_id` with a stored socket path)
    /// 2. Daemon-wide `SSH_AUTH_SOCK` (fallback)
    ///
    /// # Arguments
    ///
    /// * `session_context` - Optional session context for per-session lookup
    ///
    /// # Returns
    ///
    /// `Some(Credential)` containing the `SSH_AUTH_SOCK` path if available,
    /// `None` if SSH agent is not available.
    async fn fetch_ssh_credential_for_request(
        &self,
        session_context: Option<&super::decision::SessionContext>,
    ) -> Option<Credential> {
        // Use the helper that implements priority order
        let auth_sock = self
            .get_ssh_auth_sock_for_subprocess(session_context)
            .await?;

        debug!("SSH credential (SSH_AUTH_SOCK) fetched for tool request");
        Some(Credential::new(auth_sock))
    }

    /// Initializes the broker with a capability manifest from CAS.
    ///
    /// # Arguments
    ///
    /// * `manifest_hash` - BLAKE3 hash of the manifest in CAS
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be loaded or validated.
    #[instrument(skip(self), fields(manifest_hash = %hex::encode(&manifest_hash[..8])))]
    pub async fn initialize(&self, manifest_hash: Hash) -> Result<(), BrokerError> {
        let loader = self.loader.as_ref().ok_or_else(|| BrokerError::Internal {
            message: "no manifest loader configured".to_string(),
        })?;

        let manifest = loader.load_manifest(&manifest_hash)?;
        self.initialize_with_manifest(manifest).await
    }

    /// Initializes the broker with a capability manifest directly.
    ///
    /// This is useful when the manifest is already available (e.g., from
    /// the episode envelope).
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest is invalid or expired.
    #[instrument(skip(self, manifest), fields(manifest_id = %manifest.manifest_id))]
    pub async fn initialize_with_manifest(
        &self,
        manifest: CapabilityManifest,
    ) -> Result<(), BrokerError> {
        let validator = CapabilityValidator::new(manifest)?;

        let mut guard = self.validator.write().await;
        *guard = Some(validator);

        debug!("broker initialized with capability manifest");
        Ok(())
    }

    /// Initializes the broker with a context pack manifest for firewalling.
    ///
    /// Per TCK-00261, this enables the context firewall which terminates
    /// the session on any access violation.
    #[instrument(skip(self, manifest), fields(manifest_id = %manifest.manifest_id))]
    pub async fn initialize_with_context_manifest(
        &self,
        manifest: ContextPackManifest,
    ) -> Result<(), BrokerError> {
        let mut guard = self.context_manifest.write().await;
        *guard = Some(Arc::new(manifest));
        debug!("broker initialized with context pack manifest");
        Ok(())
    }

    /// Initializes the broker's context firewall from a CAS-stored context pack
    /// (TCK-00326).
    ///
    /// This method:
    /// 1. Loads the sealed `ContextPackManifest` from CAS using its hash
    /// 2. Verifies the seal integrity
    /// 3. Initializes the context firewall for subsequent tool requests
    ///
    /// # Fail-Closed Behavior
    ///
    /// Per RFC-0019, this method fails closed on:
    /// - Missing context pack: [`BrokerError::ContextPackNotFound`]
    /// - Invalid seal: [`BrokerError::ContextPackSealInvalid`]
    /// - Deserialization failure:
    ///   [`BrokerError::ContextPackDeserializationFailed`]
    ///
    /// All of these errors should trigger `ReviewBlockedRecorded` emission
    /// by the caller.
    ///
    /// # Arguments
    ///
    /// * `context_pack_hash` - BLAKE3 hash of the sealed `ContextPackManifest`
    ///   in CAS
    ///
    /// # Errors
    ///
    /// Returns an error if the context pack cannot be loaded, deserialized,
    /// or fails seal verification.
    #[instrument(skip(self), fields(context_pack_hash = %hex::encode(&context_pack_hash[..8])))]
    pub async fn initialize_context_from_hash(
        &self,
        context_pack_hash: &Hash,
    ) -> Result<(), BrokerError> {
        // Load from CAS
        let content = self.cas.retrieve(context_pack_hash).ok_or_else(|| {
            BrokerError::ContextPackNotFound {
                hash: hex::encode(context_pack_hash),
            }
        })?;

        // TCK-00326: Verify content integrity - compute blake3(content) and assert
        // it matches context_pack_hash before processing. This prevents CAS poisoning
        // attacks where a malicious actor could substitute content.
        let computed_hash = blake3::hash(&content);
        if computed_hash.as_bytes() != context_pack_hash {
            return Err(BrokerError::ContextPackIntegrityMismatch {
                expected: hex::encode(context_pack_hash),
                computed: hex::encode(computed_hash.as_bytes()),
            });
        }

        // Deserialize
        let mut manifest: ContextPackManifest = serde_json::from_slice(&content).map_err(|e| {
            BrokerError::ContextPackDeserializationFailed {
                reason: e.to_string(),
            }
        })?;

        // Rebuild index after deserialization
        manifest.rebuild_index();

        // Verify seal integrity
        manifest
            .verify_seal()
            .map_err(|e| BrokerError::ContextPackSealInvalid {
                reason: e.to_string(),
            })?;

        // Initialize firewall with verified manifest
        self.initialize_with_context_manifest(manifest).await?;

        debug!(
            context_pack_hash = %hex::encode(context_pack_hash),
            "context firewall initialized from CAS"
        );
        Ok(())
    }

    /// Seals a `ContextPackManifest` and stores it in CAS (TCK-00326).
    ///
    /// This method:
    /// 1. Verifies the manifest's seal
    /// 2. Serializes it to canonical JSON
    /// 3. Stores it in CAS
    /// 4. Returns the CAS hash for reference
    ///
    /// # Authority Binding
    ///
    /// The returned hash should be embedded in episode envelopes and review
    /// artifacts for authority binding per RFC-0019.
    ///
    /// # Arguments
    ///
    /// * `manifest` - The `ContextPackManifest` to seal and store
    ///
    /// # Returns
    ///
    /// The CAS hash of the stored manifest (which should match
    /// `manifest.manifest_hash()`).
    ///
    /// # Errors
    ///
    /// Returns an error if seal verification fails.
    #[instrument(skip(self, manifest), fields(manifest_id = %manifest.manifest_id))]
    pub fn seal_and_store_context_pack(
        &self,
        manifest: &ContextPackManifest,
    ) -> Result<Hash, BrokerError> {
        // Verify seal is valid
        manifest
            .verify_seal()
            .map_err(|e| BrokerError::ContextPackSealInvalid {
                reason: e.to_string(),
            })?;

        // Serialize to JSON (canonical through serde)
        let content = serde_json::to_vec(manifest).map_err(|e| BrokerError::Internal {
            message: format!("failed to serialize context pack: {e}"),
        })?;

        // Store in CAS
        let hash = self.cas.store(&content);

        debug!(
            manifest_id = %manifest.manifest_id,
            cas_hash = %hex::encode(hash),
            "context pack sealed and stored in CAS"
        );

        Ok(hash)
    }

    /// Returns the context pack hash if a context manifest is loaded.
    ///
    /// This is useful for embedding the hash in review artifacts and receipts.
    pub async fn context_pack_hash(&self) -> Option<Hash> {
        self.context_manifest
            .read()
            .await
            .as_ref()
            .map(|m| m.manifest_hash())
    }

    /// Returns `true` if the broker has been initialized.
    pub async fn is_initialized(&self) -> bool {
        self.validator.read().await.is_some()
    }

    /// Returns a reference to the capability manifest if initialized.
    pub async fn manifest(&self) -> Option<CapabilityManifest> {
        self.validator
            .read()
            .await
            .as_ref()
            .map(|v| v.manifest().clone())
    }

    /// Processes a tool request and returns a decision.
    ///
    /// This is the main entry point for tool request validation. It:
    /// 1. Validates the request structure
    /// 2. Validates against context firewall (if configured) [TCK-00261]
    /// 3. Validates against capability manifests (OCAP check)
    /// 4. Evaluates policy rules
    /// 5. Checks dedupe cache (only for authorized requests)
    ///
    /// # Security
    ///
    /// Per AD-TOOL-002, the cache lookup MUST occur AFTER capability validation
    /// to prevent authorization bypass. An attacker cannot use cache hits to
    /// circumvent capability checks.
    ///
    /// Per TCK-00263, session-specific state (like `github_installation_id` and
    /// `ssh_session_id`) MUST be passed via `session_context` rather than
    /// stored on the broker to prevent cross-session credential leaks.
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to process
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    /// * `session_context` - Optional session context for credential lookups
    ///
    /// # Returns
    ///
    /// A `ToolDecision` indicating whether the request is allowed, denied,
    /// terminated, or matched a cached result.
    ///
    /// # Errors
    ///
    /// Returns an error if the broker is not initialized or request
    /// validation fails.
    #[instrument(skip(self, request, session_context), fields(request_id = %request.request_id))]
    pub async fn request(
        &self,
        request: &BrokerToolRequest,
        timestamp_ns: u64,
        session_context: Option<&super::decision::SessionContext>,
    ) -> Result<ToolDecision, BrokerError> {
        // TCK-00268: Record start time for latency metrics
        let start_time = std::time::Instant::now();

        // Step 1: Validate request structure
        request.validate()?;

        // Step 2: Validate against context firewall (TCK-00261, TCK-00286)
        // This must happen before capability checks because a firewall violation
        // triggers session termination, which is more severe than a capability denial.
        //
        // Per TCK-00286 security review:
        // - Read operations: Check path against manifest entries (fail if path is None)
        // - Write operations: Check path against write_allowlist (if configured)
        // - Execute operations: Check command against shell_allowlist (if configured)
        //
        // NOTE: DefaultContextFirewall::new() is instantiated per-request. This is
        // acceptable overhead since the struct is lightweight (borrows manifest
        // reference) and avoids storing additional state in the broker.
        // TCK-00268: Helper for tool class label
        let tool_id = match request.tool_class {
            super::tool_class::ToolClass::Read => "read",
            super::tool_class::ToolClass::Write => "write",
            super::tool_class::ToolClass::Execute => "execute",
            super::tool_class::ToolClass::Network => "network",
            super::tool_class::ToolClass::Git => "git",
            super::tool_class::ToolClass::Inference => "inference",
            super::tool_class::ToolClass::Artifact => "artifact",
            super::tool_class::ToolClass::ListFiles => "list_files",
            super::tool_class::ToolClass::Search => "search",
            _ => "unknown",
        };

        if let Some(context_manifest) = self.context_manifest.read().await.as_ref() {
            // TCK-00375: Determine firewall mode based on risk tier
            let ctx_risk_tier: ContextRiskTier = request.risk_tier.into();
            let tier_mode = self.firewall_policy.mode_for_tier(ctx_risk_tier);

            // Helper to create termination decision and emit metrics
            // NOTE: We use episode_id as session_id here because the broker operates
            // at the episode layer. Session-level identifiers are not available at
            // this point in the call stack. The episode_id provides sufficient
            // traceability for audit purposes.
            let make_terminate = |rationale: &str| {
                // TCK-00268: Emit context firewall denial, session termination, and tool
                // mediation metrics
                if let Some(ref metrics) = self.metrics {
                    let latency = start_time.elapsed().as_secs_f64();
                    metrics.daemon_metrics().context_firewall_denied(rationale);
                    metrics.daemon_metrics().session_terminated(rationale);
                    metrics.daemon_metrics().record_tool_mediation_latency(
                        tool_id,
                        "terminate",
                        latency,
                    );
                }
                ToolDecision::Terminate {
                    request_id: request.request_id.clone(),
                    termination_info: Box::new(SessionTerminationInfo::new(
                        request.episode_id.to_string(),
                        rationale,
                        "FAILURE",
                    )),
                    refinement_event: None,
                }
            };

            // TCK-00375: Helper to emit mandatory defect for Tier3+ violations.
            // Per REQ-0029, Tier3+ violations MUST emit defects.
            let emit_defect = |defect: FirewallViolationDefect| async move {
                self.firewall_defects.lock().await.push(defect);
            };

            match request.tool_class {
                super::tool_class::ToolClass::Read
                | super::tool_class::ToolClass::ListFiles
                | super::tool_class::ToolClass::Search => {
                    // TCK-00286 [MEDIUM]: Fail-closed if path is None
                    let Some(ref path) = request.path else {
                        warn!(
                            request_id = %request.request_id,
                            "context firewall violation: Read/Navigation request missing path"
                        );
                        // TCK-00375: Emit defect for Tier3+ no-path violations
                        if ctx_risk_tier.is_high_risk() {
                            let defect = FirewallViolationDefect::allowlist_denied(
                                request.risk_tier.tier(),
                                &context_manifest.manifest_id,
                                "<no_path>",
                            );
                            emit_defect(defect).await;
                        }
                        return Ok(make_terminate("CONTEXT_READ_NO_PATH"));
                    };

                    // TCK-00375: Use risk-tier-aware firewall mode
                    let firewall = DefaultContextFirewall::new(context_manifest, tier_mode);
                    let path_str = path.to_string_lossy();

                    match firewall.validate_read(&path_str, None) {
                        Ok(ValidationResult::Allowed) => {
                            // Path is in the manifest and allowed; proceed to
                            // capability checks.
                        },
                        Ok(ValidationResult::Warned { event }) => {
                            // TCK-00375 BLOCKER 3 FIX: Warn mode returned a
                            // warning for a path that would have been denied.
                            // Per REQ-0029, out-of-pack reads MUST always be
                            // denied regardless of tier mode.  The Warn mode
                            // only applies to *in-pack* policy tweaks; it must
                            // NOT allow out-of-pack access.
                            warn!(
                                path = %path_str,
                                risk_tier = request.risk_tier.tier(),
                                rule_id = %event.rule_id,
                                "context firewall violation (Warned treated as deny per REQ-0029)"
                            );

                            // Emit mandatory defect for Tier3+ violations
                            if ctx_risk_tier.is_high_risk() {
                                let defect = FirewallViolationDefect::allowlist_denied(
                                    request.risk_tier.tier(),
                                    &context_manifest.manifest_id,
                                    &path_str,
                                );
                                emit_defect(defect).await;
                            }

                            // Always deny out-of-pack reads: terminate for
                            // Tier3+ or HardFail; soft-deny otherwise.
                            if ctx_risk_tier.is_high_risk()
                                || tier_mode == apm2_core::context::firewall::FirewallMode::HardFail
                            {
                                return Ok(make_terminate("CONTEXT_MISS"));
                            }

                            return Ok(ToolDecision::Deny {
                                request_id: request.request_id.clone(),
                                reason: DenyReason::PolicyDenied {
                                    rule_id: "CONTEXT_FIREWALL".to_string(),
                                    reason: format!(
                                        "out-of-pack read denied (warned): {}",
                                        event.reason,
                                    ),
                                },
                                rule_id: Some("CONTEXT_FIREWALL".to_string()),
                                policy_hash: self.policy.policy_hash(),
                            });
                        },
                        Ok(ValidationResult::Denied { event }) => {
                            // Firewall returned an explicit Denied result (this
                            // can happen if a future firewall mode returns Ok(Denied)).
                            warn!(
                                path = %path_str,
                                risk_tier = request.risk_tier.tier(),
                                rule_id = %event.rule_id,
                                "context firewall violation (Denied)"
                            );
                            if ctx_risk_tier.is_high_risk() {
                                let defect = FirewallViolationDefect::allowlist_denied(
                                    request.risk_tier.tier(),
                                    &context_manifest.manifest_id,
                                    &path_str,
                                );
                                emit_defect(defect).await;
                            }
                            return Ok(make_terminate("CONTEXT_MISS"));
                        },
                        Err(e) => {
                            warn!(
                                path = %path_str,
                                risk_tier = request.risk_tier.tier(),
                                error = %e,
                                "context firewall violation"
                            );

                            // TCK-00375: Emit mandatory defect for Tier3+ violations
                            if ctx_risk_tier.is_high_risk() {
                                let defect = if e.is_toctou_mismatch() {
                                    FirewallViolationDefect::toctou_mismatch(
                                        request.risk_tier.tier(),
                                        &context_manifest.manifest_id,
                                        &path_str,
                                    )
                                } else {
                                    FirewallViolationDefect::allowlist_denied(
                                        request.risk_tier.tier(),
                                        &context_manifest.manifest_id,
                                        &path_str,
                                    )
                                };
                                emit_defect(defect).await;
                            }

                            // TCK-00375: Tier3+ always terminates
                            if e.should_terminate_session() || ctx_risk_tier.is_high_risk() {
                                return Ok(make_terminate("CONTEXT_MISS"));
                            }

                            // Non-Tier3+ with non-terminating error: still deny but
                            // don't terminate (SoftFail behavior)
                            return Ok(ToolDecision::Deny {
                                request_id: request.request_id.clone(),
                                reason: DenyReason::PolicyDenied {
                                    rule_id: "CONTEXT_FIREWALL".to_string(),
                                    reason: e.to_string(),
                                },
                                rule_id: Some("CONTEXT_FIREWALL".to_string()),
                                policy_hash: self.policy.policy_hash(),
                            });
                        },
                    }
                },
                super::tool_class::ToolClass::Write => {
                    // TCK-00286 [HIGH]: Check write_allowlist if configured
                    if !context_manifest.write_allowlist.is_empty() {
                        // Fail-closed if path is None when write_allowlist is configured
                        let Some(ref path) = request.path else {
                            warn!(
                                request_id = %request.request_id,
                                "context firewall violation: Write request missing path"
                            );
                            if ctx_risk_tier.is_high_risk() {
                                let defect = FirewallViolationDefect::allowlist_denied(
                                    request.risk_tier.tier(),
                                    &context_manifest.manifest_id,
                                    "<no_path>",
                                );
                                emit_defect(defect).await;
                            }
                            return Ok(make_terminate("CONTEXT_WRITE_NO_PATH"));
                        };

                        if !context_manifest.is_write_path_allowed(path) {
                            warn!(
                                path = %path.display(),
                                "context firewall violation: path not in write_allowlist"
                            );
                            if ctx_risk_tier.is_high_risk() {
                                let defect = FirewallViolationDefect::allowlist_denied(
                                    request.risk_tier.tier(),
                                    &context_manifest.manifest_id,
                                    &path.to_string_lossy(),
                                );
                                emit_defect(defect).await;
                            }
                            return Ok(make_terminate("CONTEXT_WRITE_DENIED"));
                        }
                    }
                },
                super::tool_class::ToolClass::Execute => {
                    // TCK-00286 [HIGH]: Check shell_allowlist if configured
                    if !context_manifest.shell_allowlist.is_empty() {
                        // Fail-closed if shell_command is None when shell_allowlist is configured
                        let Some(ref command) = request.shell_command else {
                            warn!(
                                request_id = %request.request_id,
                                "context firewall violation: Execute request missing shell_command"
                            );
                            if ctx_risk_tier.is_high_risk() {
                                let defect = FirewallViolationDefect::allowlist_denied(
                                    request.risk_tier.tier(),
                                    &context_manifest.manifest_id,
                                    "<no_command>",
                                );
                                emit_defect(defect).await;
                            }
                            return Ok(make_terminate("CONTEXT_EXEC_NO_CMD"));
                        };

                        if !context_manifest.is_shell_command_allowed(command) {
                            warn!(
                                command = %command,
                                "context firewall violation: command not in shell_allowlist"
                            );
                            if ctx_risk_tier.is_high_risk() {
                                let defect = FirewallViolationDefect::allowlist_denied(
                                    request.risk_tier.tier(),
                                    &context_manifest.manifest_id,
                                    command,
                                );
                                emit_defect(defect).await;
                            }
                            return Ok(make_terminate("CONTEXT_EXEC_DENIED"));
                        }
                    }
                },
                // Other tool classes (Network, Git, Inference, Artifact) are not
                // currently subject to context firewall restrictions.
                _ => {},
            }
        }

        // Step 3: Validate against capability manifest (OCAP check)
        // SECURITY: This MUST happen before cache lookup to prevent authorization
        // bypass
        let validator = self.validator.read().await;
        let validator = validator.as_ref().ok_or(BrokerError::NotInitialized)?;

        let cap_request = request.to_capability_request();
        let cap_decision = validator.validate(&cap_request);

        let capability_id = match cap_decision {
            CapabilityDecision::Allow { capability_id } => capability_id,
            CapabilityDecision::Deny { reason } => {
                debug!(reason = %reason, "capability denied");
                // TCK-00268: Emit tool mediation latency metric for deny
                if let Some(ref metrics) = self.metrics {
                    let latency = start_time.elapsed().as_secs_f64();
                    metrics
                        .daemon_metrics()
                        .record_tool_mediation_latency(tool_id, "deny", latency);
                }
                return Ok(ToolDecision::Deny {
                    request_id: request.request_id.clone(),
                    reason,
                    rule_id: None,
                    policy_hash: self.policy.policy_hash(),
                });
            },
        };

        // Step 4: Evaluate policy (if enabled)
        // SECURITY: Policy evaluation must also happen before cache lookup
        if self.config.check_policy {
            if let PolicyDecision::Deny { rule_id, reason } = self.policy.evaluate(request) {
                warn!(rule_id = %rule_id, reason = %reason, "policy denied");
                // TCK-00268: Emit tool mediation latency metric for policy deny
                if let Some(ref metrics) = self.metrics {
                    let latency = start_time.elapsed().as_secs_f64();
                    metrics
                        .daemon_metrics()
                        .record_tool_mediation_latency(tool_id, "deny", latency);
                }
                return Ok(ToolDecision::Deny {
                    request_id: request.request_id.clone(),
                    // F02: Use PolicyDenied reason instead of misleading NoMatchingCapability
                    reason: DenyReason::PolicyDenied {
                        rule_id: rule_id.clone(),
                        reason,
                    },
                    rule_id: Some(rule_id),
                    policy_hash: self.policy.policy_hash(),
                });
            }
        }

        // Step 5: Check dedupe cache (only for authorized requests)
        // SECURITY: Cache lookup occurs AFTER authorization to prevent bypass attacks
        if self.config.use_dedupe_cache {
            if let Some(cached) = self
                .lookup_dedupe(&request.episode_id, &request.dedupe_key, timestamp_ns)
                .await
            {
                debug!(dedupe_key = %request.dedupe_key, "dedupe cache hit");
                // TCK-00268: Emit tool mediation latency metric for cache hit
                if let Some(ref metrics) = self.metrics {
                    let latency = start_time.elapsed().as_secs_f64();
                    metrics.daemon_metrics().record_tool_mediation_latency(
                        tool_id,
                        "cache_hit",
                        latency,
                    );
                }
                return Ok(ToolDecision::DedupeCacheHit {
                    request_id: request.request_id.clone(),
                    result: Box::new(cached),
                });
            }
        }

        // Request is authorized - return Allow decision
        // Step 6: Fetch credentials for Git/Network tools (TCK-00262, TCK-00263)
        // Per RFC-0017 TB-003, credentials are attached by the broker, never
        // exposed to session processes directly. Session context is used to
        // look up session-specific credentials without storing them on the broker.
        let credential = self
            .fetch_credential_for_request(request.tool_class, session_context)
            .await;

        debug!(capability_id = %capability_id, has_credential = credential.is_some(), "request allowed");

        // TCK-00268: Emit tool mediation latency metric for allow
        if let Some(ref metrics) = self.metrics {
            let latency = start_time.elapsed().as_secs_f64();
            metrics
                .daemon_metrics()
                .record_tool_mediation_latency(tool_id, "allow", latency);
        }

        Ok(ToolDecision::Allow {
            request_id: request.request_id.clone(),
            capability_id,
            rule_id: if self.config.check_policy {
                // Extract rule_id from policy decision if available
                match self.policy.evaluate(request) {
                    PolicyDecision::Allow { rule_id } => rule_id,
                    PolicyDecision::Deny { .. } => None, // Already handled above
                }
            } else {
                None
            },
            policy_hash: self.policy.policy_hash(),
            budget_delta: BudgetDelta::single_call(),
            credential,
        })
    }

    /// Executes a tool and returns the result.
    ///
    /// This should only be called for `Allow` decisions. The result is
    /// stored in the dedupe cache for future idempotent replay.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - Episode this execution belongs to
    /// * `decision` - The Allow decision from `request()`
    /// * `result` - The result of tool execution (from external executor)
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    ///
    /// # Note
    ///
    /// This method stores results in the dedupe cache but does NOT actually
    /// execute tools. Tool execution is handled by the episode runtime.
    /// This method is for recording results after execution.
    ///
    /// # Errors
    ///
    /// Returns an error if the decision is not an Allow.
    #[instrument(skip(self, decision, result), fields(request_id = decision.request_id()))]
    pub async fn record_result(
        &self,
        episode_id: EpisodeId,
        decision: &ToolDecision,
        dedupe_key: DedupeKey,
        result: ToolResult,
        timestamp_ns: u64,
    ) -> Result<(), BrokerError> {
        // Verify this is an Allow decision
        if !decision.is_allowed() {
            return Err(BrokerError::Internal {
                message: "cannot record result for non-Allow decision".to_string(),
            });
        }

        // Store in dedupe cache
        if self.config.use_dedupe_cache {
            self.dedupe_cache
                .insert(episode_id, dedupe_key, result, timestamp_ns)
                .await;
        }

        debug!("recorded tool result");
        Ok(())
    }

    /// Looks up a cached result by dedupe key for a specific episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode making the request (for isolation)
    /// * `key` - The dedupe key to lookup
    /// * `timestamp_ns` - Current timestamp (for TTL check)
    ///
    /// # Security
    ///
    /// The `episode_id` MUST be verified to prevent cross-episode information
    /// leakage. A cached result is only returned if it belongs to the
    /// requesting episode.
    ///
    /// # Returns
    ///
    /// The cached result if found, not expired, and belongs to the same
    /// episode.
    pub async fn lookup_dedupe(
        &self,
        episode_id: &EpisodeId,
        key: &DedupeKey,
        timestamp_ns: u64,
    ) -> Option<ToolResult> {
        if !self.config.use_dedupe_cache {
            return None;
        }
        self.dedupe_cache.get(episode_id, key, timestamp_ns).await
    }

    /// Evicts all cached results for an episode.
    ///
    /// This should be called when an episode terminates.
    ///
    /// # Returns
    ///
    /// The number of entries evicted.
    pub async fn evict_episode(&self, episode_id: &EpisodeId) -> usize {
        self.dedupe_cache.evict_by_episode(episode_id).await
    }

    /// Returns the dedupe cache statistics.
    pub async fn cache_stats(&self) -> super::dedupe::DedupeCacheStats {
        self.dedupe_cache.stats().await
    }
}

impl<L: ManifestLoader> std::fmt::Debug for ToolBroker<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolBroker")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// SharedToolBroker
// =============================================================================

/// Shared reference to a tool broker.
pub type SharedToolBroker<L = super::capability::StubManifestLoader> = Arc<ToolBroker<L>>;

/// Thread-safe registry of per-session brokers.
///
/// Stores one initialized broker per session to prevent cross-session
/// capability and policy leakage.
#[derive(Debug)]
pub struct SessionBrokerRegistry<L: ManifestLoader = super::capability::StubManifestLoader> {
    brokers: std::sync::RwLock<HashMap<String, SharedToolBroker<L>>>,
}

impl<L: ManifestLoader> Default for SessionBrokerRegistry<L> {
    fn default() -> Self {
        Self {
            brokers: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

impl<L: ManifestLoader> SessionBrokerRegistry<L> {
    /// Creates an empty session broker registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers (or replaces) a session broker.
    pub fn register(&self, session_id: impl Into<String>, broker: SharedToolBroker<L>) {
        let mut guard = self.brokers.write().expect("lock poisoned");
        guard.insert(session_id.into(), broker);
    }

    /// Looks up a broker by session ID.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<SharedToolBroker<L>> {
        let guard = self.brokers.read().expect("lock poisoned");
        guard.get(session_id).cloned()
    }

    /// Removes a session broker.
    pub fn remove(&self, session_id: &str) {
        let mut guard = self.brokers.write().expect("lock poisoned");
        guard.remove(session_id);
    }

    /// Removes and returns a session broker.
    #[must_use]
    pub fn remove_and_return(&self, session_id: &str) -> Option<SharedToolBroker<L>> {
        let mut guard = self.brokers.write().expect("lock poisoned");
        guard.remove(session_id)
    }

    /// Restores a previously removed session broker.
    pub fn restore(&self, session_id: impl Into<String>, broker: SharedToolBroker<L>) {
        let mut guard = self.brokers.write().expect("lock poisoned");
        guard.insert(session_id.into(), broker);
    }

    /// Returns the number of registered brokers.
    #[must_use]
    pub fn len(&self) -> usize {
        let guard = self.brokers.read().expect("lock poisoned");
        guard.len()
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Shared reference to a per-session broker registry.
pub type SharedSessionBrokerRegistry<L = super::capability::StubManifestLoader> =
    Arc<SessionBrokerRegistry<L>>;

/// Creates a new shared tool broker.
///
/// **Note**: This constructor uses `StubContentAddressedStore` which does not
/// persist artifacts across restarts. For production use, prefer
/// [`new_shared_broker_with_cas`] with a `DurableCas` instance.
#[must_use]
pub fn new_shared_broker<L: ManifestLoader + Send + Sync>(
    config: ToolBrokerConfig,
) -> SharedToolBroker<L> {
    Arc::new(ToolBroker::new(config))
}

/// Creates a new shared tool broker with a durable CAS backend (TCK-00293).
///
/// Per RFC-0018 HEF requirements and TCK-00293, evidence artifacts must be
/// durable and content-addressed for FAC v0. This constructor requires a CAS
/// implementation to be provided, ensuring production paths use durable
/// storage.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::cas::{DurableCas, DurableCasConfig};
/// use apm2_daemon::episode::{new_shared_broker_with_cas, ToolBrokerConfig};
///
/// let cas_config = DurableCasConfig::new("/var/lib/apm2/cas");
/// let cas = Arc::new(DurableCas::new(cas_config)?);
/// let broker = new_shared_broker_with_cas(ToolBrokerConfig::default(), cas);
/// ```
#[must_use]
pub fn new_shared_broker_with_cas<L: ManifestLoader + Send + Sync>(
    config: ToolBrokerConfig,
    cas: Arc<dyn ContentAddressedStore>,
) -> SharedToolBroker<L> {
    Arc::new(ToolBroker::new(config).with_cas(cas))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::episode::capability::{Capability, CapabilityManifest, StubManifestLoader};
    use crate::episode::envelope::RiskTier;
    use crate::episode::scope::CapabilityScope;
    use crate::episode::tool_class::ToolClass;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("ep-test-broker").unwrap()
    }

    fn test_dedupe_key(suffix: &str) -> DedupeKey {
        DedupeKey::new(format!("broker-key-{suffix}"))
    }

    fn test_args_hash() -> Hash {
        [42u8; 32]
    }

    fn timestamp_ns(secs: u64) -> u64 {
        secs * 1_000_000_000
    }

    fn make_read_capability(id: &str, paths: Vec<PathBuf>) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Read,
            scope: CapabilityScope {
                root_paths: paths,
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    fn make_manifest(caps: Vec<Capability>) -> CapabilityManifest {
        // Collect tool classes from capabilities for the allowlist
        let tool_classes: Vec<ToolClass> = caps.iter().map(|c| c.tool_class).collect();
        CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(caps)
            .tool_allowlist(tool_classes)
            .build()
            .unwrap()
    }

    fn make_request(id: &str, tool_class: ToolClass, path: Option<&str>) -> BrokerToolRequest {
        let mut req = BrokerToolRequest::new(
            id,
            test_episode_id(),
            tool_class,
            test_dedupe_key(id),
            test_args_hash(),
            RiskTier::Tier0,
        );
        if let Some(p) = path {
            req = req.with_path(p);
        }
        req
    }

    /// Creates a test config with policy checking disabled.
    ///
    /// Per TCK-00292, existing tests that focus on capability validation,
    /// dedupe cache, credentials, etc. should disable policy checking.
    fn test_config_without_policy() -> ToolBrokerConfig {
        ToolBrokerConfig::default().without_policy_check()
    }

    #[tokio::test]
    async fn test_broker_not_initialized() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        assert!(!broker.is_initialized().await);

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let result = broker.request(&request, timestamp_ns(0), None).await;

        assert!(matches!(result, Err(BrokerError::NotInitialized)));
    }

    #[tokio::test]
    async fn test_broker_initialize_with_manifest() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);

        broker.initialize_with_manifest(manifest).await.unwrap();

        assert!(broker.is_initialized().await);
        assert!(broker.manifest().await.is_some());
    }

    #[tokio::test]
    async fn test_broker_request_allowed() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { capability_id, .. } = decision {
            assert_eq!(capability_id, "cap-read");
        }
    }

    #[tokio::test]
    async fn test_broker_request_denied_no_capability() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Request Write capability when only Read is available
        let request = make_request("req-1", ToolClass::Write, Some("/workspace/file.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_denied());
    }

    #[tokio::test]
    async fn test_broker_request_denied_path_not_allowed() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Request path outside of allowed scope
        let request = make_request("req-1", ToolClass::Read, Some("/etc/passwd"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_denied());
        if let ToolDecision::Deny { reason, .. } = decision {
            assert!(matches!(reason, DenyReason::PathNotAllowed { .. }));
        }
    }

    #[tokio::test]
    async fn test_broker_dedupe_cache_hit() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));

        // First request - should be allowed
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();
        assert!(decision.is_allowed());

        // Record a result
        let result = ToolResult::success(
            "req-1",
            b"file contents".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            timestamp_ns(0),
        );

        broker
            .record_result(
                test_episode_id(),
                &decision,
                request.dedupe_key.clone(),
                result,
                timestamp_ns(0),
            )
            .await
            .unwrap();

        // Second request with same dedupe key - should be cache hit
        let decision2 = broker
            .request(&request, timestamp_ns(1), None)
            .await
            .unwrap();
        assert!(decision2.is_cache_hit());

        if let ToolDecision::DedupeCacheHit { result, .. } = decision2 {
            assert_eq!(result.output, b"file contents");
        }
    }

    #[tokio::test]
    async fn test_broker_evict_episode() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Make requests and record results
        for i in 0..3 {
            let request = make_request(
                &format!("req-{i}"),
                ToolClass::Read,
                Some("/workspace/file.rs"),
            );
            let decision = broker
                .request(&request, timestamp_ns(i), None)
                .await
                .unwrap();

            let result = ToolResult::success(
                format!("req-{i}"),
                b"output".to_vec(),
                BudgetDelta::single_call(),
                Duration::from_millis(100),
                timestamp_ns(i),
            );

            broker
                .record_result(
                    test_episode_id(),
                    &decision,
                    request.dedupe_key,
                    result,
                    timestamp_ns(i),
                )
                .await
                .unwrap();
        }

        let stats = broker.cache_stats().await;
        assert_eq!(stats.entry_count, 3);

        // Evict episode
        let evicted = broker.evict_episode(&test_episode_id()).await;
        assert_eq!(evicted, 3);

        let stats = broker.cache_stats().await;
        assert_eq!(stats.entry_count, 0);
    }

    #[tokio::test]
    async fn test_broker_without_dedupe_cache() {
        let config = test_config_without_policy().without_dedupe_cache();
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(config);

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));

        // First request
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();
        assert!(decision.is_allowed());

        // Record result (won't actually cache)
        let result = ToolResult::success(
            "req-1",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            timestamp_ns(0),
        );
        broker
            .record_result(
                test_episode_id(),
                &decision,
                request.dedupe_key.clone(),
                result,
                timestamp_ns(0),
            )
            .await
            .unwrap();

        // Second request - should still be allowed (no cache)
        let decision2 = broker
            .request(&request, timestamp_ns(1), None)
            .await
            .unwrap();
        assert!(decision2.is_allowed());
        assert!(!decision2.is_cache_hit());
    }

    #[tokio::test]
    async fn test_broker_without_policy_check() {
        let config = ToolBrokerConfig::default().without_policy_check();
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(config);

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { rule_id, .. } = decision {
            assert!(rule_id.is_none());
        }
    }

    #[tokio::test]
    async fn test_broker_request_validation_error() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create request with empty ID
        let request = BrokerToolRequest::new(
            "",
            test_episode_id(),
            ToolClass::Read,
            test_dedupe_key("bad"),
            test_args_hash(),
            RiskTier::Tier0,
        );

        let result = broker.request(&request, timestamp_ns(0), None).await;
        assert!(matches!(result, Err(BrokerError::RequestValidation(_))));
    }

    #[tokio::test]
    async fn test_broker_record_result_not_allowed() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Try to record result for a Deny decision
        let deny_decision = ToolDecision::Deny {
            request_id: "req-1".to_string(),
            reason: DenyReason::NoMatchingCapability {
                tool_class: ToolClass::Write,
            },
            rule_id: None,
            policy_hash: [0u8; 32],
        };

        let result = ToolResult::success(
            "req-1",
            b"output".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            timestamp_ns(0),
        );

        let err = broker
            .record_result(
                test_episode_id(),
                &deny_decision,
                test_dedupe_key("1"),
                result,
                timestamp_ns(0),
            )
            .await;

        assert!(matches!(err, Err(BrokerError::Internal { .. })));
    }

    #[tokio::test]
    async fn test_broker_error_kinds() {
        let err = BrokerError::NotInitialized;
        assert_eq!(err.kind(), "not_initialized");
        assert!(!err.is_retriable());

        let err = BrokerError::ExecutionFailed {
            message: "test".to_string(),
        };
        assert_eq!(err.kind(), "execution_failed");
        assert!(err.is_retriable());
    }

    #[tokio::test]
    async fn test_stub_policy_engine() {
        let policy = StubPolicyEngine::new();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = policy.evaluate(&request);

        assert!(matches!(decision, PolicyDecision::Allow { rule_id: None }));
        assert_eq!(policy.policy_hash(), [0u8; 32]);
    }

    #[tokio::test]
    async fn test_stub_cas() {
        let cas = StubContentAddressedStore::new();

        // Retrieve returns None
        let hash = [0u8; 32];
        assert!(cas.retrieve(&hash).is_none());

        // Store returns hash
        let content = b"test content";
        let stored_hash = cas.store(content);
        assert_eq!(stored_hash.len(), 32);
    }

    // =========================================================================
    // TCK-00293: DurableCas wiring tests
    // =========================================================================

    #[tokio::test]
    async fn test_broker_with_cas() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};

        // Create a durable CAS (use subdirectory so DurableCas creates it with 0700)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create broker with durable CAS via builder pattern
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(cas);

        // Verify broker is created (basic smoke test)
        assert!(!broker.is_initialized().await);
    }

    #[tokio::test]
    async fn test_new_shared_broker_with_cas() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};

        // Create a durable CAS (use subdirectory so DurableCas creates it with 0700)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create shared broker with durable CAS
        let broker: SharedToolBroker<StubManifestLoader> =
            new_shared_broker_with_cas(test_config_without_policy(), cas);

        // Verify broker is created (basic smoke test)
        assert!(!broker.is_initialized().await);
    }

    // =========================================================================
    // Security Tests
    // =========================================================================

    #[tokio::test]
    async fn test_security_authorization_before_cache() {
        // This test verifies the CRITICAL security fix: cache lookup occurs
        // AFTER capability validation. An unauthorized request must NOT
        // receive a cache hit even if a valid cached result exists.
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Initialize with Read capability only (no Write)
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create a valid Read request and execute it to populate the cache
        let read_request = make_request("req-read-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = broker
            .request(&read_request, timestamp_ns(0), None)
            .await
            .unwrap();
        assert!(decision.is_allowed(), "read request should be allowed");

        // Record a result to populate the cache
        let result = ToolResult::success(
            "req-read-1",
            b"cached file contents".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            timestamp_ns(0),
        );
        broker
            .record_result(
                test_episode_id(),
                &decision,
                read_request.dedupe_key.clone(),
                result,
                timestamp_ns(0),
            )
            .await
            .unwrap();

        // Now create a Write request with the SAME dedupe key
        // This simulates an attacker trying to use cache hits to bypass authorization
        let mut write_request =
            make_request("req-write-1", ToolClass::Write, Some("/workspace/file.rs"));
        write_request.dedupe_key = read_request.dedupe_key.clone(); // Same dedupe key!

        // The Write request should be DENIED (not a cache hit)
        // Authorization check must happen before cache lookup
        let write_decision = broker
            .request(&write_request, timestamp_ns(1), None)
            .await
            .unwrap();
        assert!(
            write_decision.is_denied(),
            "write request must be denied, not served from cache"
        );
        assert!(
            !write_decision.is_cache_hit(),
            "unauthorized request must not receive cache hit"
        );
    }

    #[tokio::test]
    async fn test_security_cross_episode_cache_isolation() {
        // This test verifies the HIGH security fix: cache entries are isolated
        // by episode. One episode cannot read another episode's cached data.
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let episode1 = EpisodeId::new("ep-security-1").unwrap();
        let episode2 = EpisodeId::new("ep-security-2").unwrap();

        // Create a request for episode 1
        let request1 = BrokerToolRequest::new(
            "req-ep1",
            episode1.clone(),
            ToolClass::Read,
            test_dedupe_key("shared-key"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/secret.txt");

        let decision1 = broker
            .request(&request1, timestamp_ns(0), None)
            .await
            .unwrap();
        assert!(decision1.is_allowed());

        // Record result for episode 1
        let result = ToolResult::success(
            "req-ep1",
            b"episode 1 secret data".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            timestamp_ns(0),
        );
        broker
            .record_result(
                episode1.clone(),
                &decision1,
                request1.dedupe_key.clone(),
                result,
                timestamp_ns(0),
            )
            .await
            .unwrap();

        // Episode 1 should get a cache hit
        let decision1_again = broker
            .request(&request1, timestamp_ns(1), None)
            .await
            .unwrap();
        assert!(
            decision1_again.is_cache_hit(),
            "episode 1 should get cache hit for its own data"
        );

        // Create a request for episode 2 with the SAME dedupe key
        let request2 = BrokerToolRequest::new(
            "req-ep2",
            episode2.clone(),
            ToolClass::Read,
            test_dedupe_key("shared-key"), // Same key as episode 1!
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/secret.txt");

        // Episode 2 must NOT get a cache hit from episode 1's data
        let decision2 = broker
            .request(&request2, timestamp_ns(2), None)
            .await
            .unwrap();
        assert!(
            !decision2.is_cache_hit(),
            "episode 2 must not receive cache hit from episode 1's data"
        );
        assert!(
            decision2.is_allowed(),
            "episode 2's request should be allowed (but not cached)"
        );
    }

    #[tokio::test]
    async fn test_security_cache_hit_after_authorization() {
        // This test verifies that authorized requests DO get cache hits
        // after authorization passes.
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));

        // First request - should be allowed
        let decision1 = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();
        assert!(decision1.is_allowed());

        // Record result
        let result = ToolResult::success(
            "req-1",
            b"file contents".to_vec(),
            BudgetDelta::single_call(),
            Duration::from_millis(100),
            timestamp_ns(0),
        );
        broker
            .record_result(
                test_episode_id(),
                &decision1,
                request.dedupe_key.clone(),
                result,
                timestamp_ns(0),
            )
            .await
            .unwrap();

        // Second request with same dedupe key - should get cache hit
        // (after authorization passes)
        let decision2 = broker
            .request(&request, timestamp_ns(1), None)
            .await
            .unwrap();
        assert!(
            decision2.is_cache_hit(),
            "authorized request should get cache hit"
        );

        if let ToolDecision::DedupeCacheHit { result, .. } = decision2 {
            assert_eq!(result.output, b"file contents");
        }
    }

    // =========================================================================
    // Context Firewall Tests (TCK-00286)
    //
    // These tests verify the context firewall integration in the broker,
    // including fail-closed behavior for Read, Write, and Execute operations.
    // =========================================================================

    /// Helper to create a context pack manifest with specified allowlists.
    fn make_context_manifest(
        entries: Vec<(&str, [u8; 32])>,
        write_paths: Vec<PathBuf>,
        shell_patterns: Vec<String>,
    ) -> apm2_core::context::ContextPackManifest {
        use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

        let mut builder = ContextPackManifestBuilder::new("ctx-manifest-test", "profile-test");

        for (path, hash) in entries {
            builder = builder.add_entry(
                ManifestEntryBuilder::new(path, hash)
                    .access_level(AccessLevel::Read)
                    .build(),
            );
        }

        if !write_paths.is_empty() {
            builder = builder.write_allowlist(write_paths);
        }
        if !shell_patterns.is_empty() {
            builder = builder.shell_allowlist(shell_patterns);
        }

        builder.build()
    }

    /// Helper to make a write capability.
    fn make_write_capability(id: &str, paths: Vec<PathBuf>) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Write,
            scope: CapabilityScope {
                root_paths: paths,
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    /// Helper to make an execute capability.
    fn make_execute_capability(id: &str) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Execute,
            scope: CapabilityScope {
                root_paths: Vec::new(),
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    #[tokio::test]
    async fn test_initialize_with_context_manifest() {
        // TCK-00286: Basic initialization test
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );

        let result = broker
            .initialize_with_context_manifest(context_manifest)
            .await;
        assert!(result.is_ok(), "should initialize with context manifest");
    }

    #[tokio::test]
    async fn test_context_firewall_allows_permitted_read() {
        // TCK-00286: Read request for allowed path proceeds to capability checks
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing reads from /workspace
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest allowing /workspace/allowed.rs
        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request should be allowed (both context firewall and capability check pass)
        let request = make_request(
            "req-allowed",
            ToolClass::Read,
            Some("/workspace/allowed.rs"),
        );
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_allowed(),
            "read request for allowed path should be permitted"
        );
    }

    #[tokio::test]
    async fn test_context_firewall_terminates_on_denied_read() {
        // TCK-00286: Read request for path NOT in manifest returns Terminate
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing reads from /workspace
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest allowing ONLY /workspace/allowed.rs
        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request for path NOT in context manifest should terminate
        let request = make_request("req-denied", ToolClass::Read, Some("/workspace/secret.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_terminate(),
            "read request for denied path should terminate session"
        );
        if let ToolDecision::Terminate {
            termination_info, ..
        } = decision
        {
            assert_eq!(termination_info.rationale_code, "CONTEXT_MISS");
        }
    }

    #[tokio::test]
    async fn test_context_firewall_terminates_on_read_without_path() {
        // TCK-00286 [MEDIUM]: Read request with path: None when context firewall
        // active returns Terminate (fail-closed)
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest (any entries - the point is firewall is active)
        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request with NO path should terminate (fail-closed)
        let request = make_request("req-no-path", ToolClass::Read, None);
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_terminate(),
            "read request without path should terminate when context firewall is active"
        );
        if let ToolDecision::Terminate {
            termination_info, ..
        } = decision
        {
            assert_eq!(termination_info.rationale_code, "CONTEXT_READ_NO_PATH");
        }
    }

    #[tokio::test]
    async fn test_context_firewall_terminates_on_denied_write() {
        // TCK-00286 [HIGH]: Write request outside write_allowlist returns Terminate
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing writes to /workspace
        // We give capability manifest a broad write allowlist, so it passes capability
        // check. The context firewall should then terminate on paths outside
        // ITS allowlist.
        let tool_classes = vec![ToolClass::Write];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_write_capability(
                "cap-write",
                vec![PathBuf::from("/workspace")],
            )])
            .tool_allowlist(tool_classes)
            .write_allowlist(vec![PathBuf::from("/workspace")]) // Broad capability
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest with write_allowlist for /workspace/allowed ONLY
        // This is more restrictive than the capability manifest
        let context_manifest = make_context_manifest(
            Vec::new(), // no read entries needed for this test
            vec![PathBuf::from("/workspace/allowed")],
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request to write outside context's allowed path should terminate
        let request = make_request(
            "req-write-denied",
            ToolClass::Write,
            Some("/workspace/secret.txt"),
        );
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_terminate(),
            "write request outside context write_allowlist should terminate, got: {decision:?}"
        );
        if let ToolDecision::Terminate {
            termination_info, ..
        } = decision
        {
            assert_eq!(termination_info.rationale_code, "CONTEXT_WRITE_DENIED");
        }
    }

    #[tokio::test]
    async fn test_context_firewall_allows_permitted_write() {
        // TCK-00286: Write request within write_allowlist proceeds
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing writes to /workspace
        // NOTE: Both CapabilityManifest and ContextPackManifest have write_allowlist
        // Both must allow the path for the request to succeed.
        let tool_classes = vec![ToolClass::Write];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_write_capability(
                "cap-write",
                vec![PathBuf::from("/workspace")],
            )])
            .tool_allowlist(tool_classes)
            .write_allowlist(vec![PathBuf::from("/workspace/allowed")])
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest with write_allowlist for /workspace/allowed
        let context_manifest = make_context_manifest(
            Vec::new(),
            vec![PathBuf::from("/workspace/allowed")],
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request to write inside allowed path should proceed
        let request = make_request(
            "req-write-allowed",
            ToolClass::Write,
            Some("/workspace/allowed/file.txt"),
        );
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_allowed(),
            "write request within write_allowlist should be allowed, got: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_context_firewall_terminates_on_denied_execute() {
        // TCK-00286 [HIGH]: Execute request outside shell_allowlist returns Terminate
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing execute with broad shell allowlist
        // The context firewall should then terminate on commands outside ITS allowlist.
        let tool_classes = vec![ToolClass::Execute];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_execute_capability("cap-exec")])
            .tool_allowlist(tool_classes)
            .shell_allowlist(vec!["*".to_string()]) // Broad capability (allows anything)
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest with shell_allowlist for cargo ONLY
        // This is more restrictive than the capability manifest
        let context_manifest =
            make_context_manifest(Vec::new(), Vec::new(), vec!["cargo *".to_string()]);
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request to execute rm command should terminate
        let mut request = make_request("req-exec-denied", ToolClass::Execute, None);
        request = request.with_shell_command("rm -rf /");
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_terminate(),
            "execute request outside context shell_allowlist should terminate, got: {decision:?}"
        );
        if let ToolDecision::Terminate {
            termination_info, ..
        } = decision
        {
            assert_eq!(termination_info.rationale_code, "CONTEXT_EXEC_DENIED");
        }
    }

    #[tokio::test]
    async fn test_context_firewall_allows_permitted_execute() {
        // TCK-00286: Execute request matching shell_allowlist proceeds
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing execute with matching shell allowlist
        // Both capability and context manifests must allow the command.
        let tool_classes = vec![ToolClass::Execute];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_execute_capability("cap-exec")])
            .tool_allowlist(tool_classes)
            .shell_allowlist(vec!["cargo *".to_string()])
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest with shell_allowlist for cargo
        let context_manifest =
            make_context_manifest(Vec::new(), Vec::new(), vec!["cargo *".to_string()]);
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request to execute cargo command should proceed
        let mut request = make_request("req-exec-allowed", ToolClass::Execute, None);
        request = request.with_shell_command("cargo build --release");
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_allowed(),
            "execute request matching shell_allowlist should be allowed, got: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_context_firewall_execute_no_command() {
        // TCK-00286: Execute request without shell_command when shell_allowlist
        // configured returns Terminate (fail-closed)
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing execute
        // NOTE: We need to configure capability manifest's shell_allowlist too
        // but the context firewall check happens FIRST, so it should terminate
        // before capability validation.
        let tool_classes = vec![ToolClass::Execute];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_execute_capability("cap-exec")])
            .tool_allowlist(tool_classes)
            .shell_allowlist(vec!["cargo *".to_string()])
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest with shell_allowlist
        let context_manifest =
            make_context_manifest(Vec::new(), Vec::new(), vec!["cargo *".to_string()]);
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request without shell_command should terminate
        let request = make_request("req-exec-no-cmd", ToolClass::Execute, None);
        // Note: not calling with_shell_command
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_terminate(),
            "execute request without shell_command should terminate when shell_allowlist configured, got: {decision:?}"
        );
        if let ToolDecision::Terminate {
            termination_info, ..
        } = decision
        {
            assert_eq!(termination_info.rationale_code, "CONTEXT_EXEC_NO_CMD");
        }
    }

    #[tokio::test]
    async fn test_context_firewall_write_no_path() {
        // TCK-00286: Write request without path when write_allowlist
        // configured returns Terminate (fail-closed)
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing writes
        // NOTE: Context firewall check happens FIRST, so missing path will
        // trigger terminate before capability validation.
        let tool_classes = vec![ToolClass::Write];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_write_capability(
                "cap-write",
                vec![PathBuf::from("/workspace")],
            )])
            .tool_allowlist(tool_classes)
            .write_allowlist(vec![PathBuf::from("/workspace/allowed")])
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest with write_allowlist
        let context_manifest = make_context_manifest(
            Vec::new(),
            vec![PathBuf::from("/workspace/allowed")],
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request without path should terminate
        let request = make_request("req-write-no-path", ToolClass::Write, None);
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_terminate(),
            "write request without path should terminate when write_allowlist configured, got: {decision:?}"
        );
        if let ToolDecision::Terminate {
            termination_info, ..
        } = decision
        {
            assert_eq!(termination_info.rationale_code, "CONTEXT_WRITE_NO_PATH");
        }
    }

    #[tokio::test]
    async fn test_context_firewall_empty_allowlist_bypasses_check() {
        // TCK-00286: When context's write_allowlist/shell_allowlist are empty,
        // the context firewall check is bypassed (only capability check applies)
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing writes and execute
        // The capability manifest needs its own allowlists configured.
        let tool_classes = vec![ToolClass::Write, ToolClass::Execute];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![
                make_write_capability("cap-write", vec![PathBuf::from("/workspace")]),
                make_execute_capability("cap-exec"),
            ])
            .tool_allowlist(tool_classes)
            .write_allowlist(vec![PathBuf::from("/workspace")]) // Capability allows /workspace
            .shell_allowlist(vec!["*".to_string()]) // Capability allows any command
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Set up context manifest with EMPTY write_allowlist and shell_allowlist
        // Empty context allowlists = bypass context firewall for those operations
        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])], // read entries only
            Vec::new(),                                  /* empty write_allowlist - bypass
                                                          * context check */
            Vec::new(), // empty shell_allowlist - bypass context check
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Write request should proceed (empty context allowlist = no context firewall
        // check)
        let write_request = make_request("req-write", ToolClass::Write, Some("/workspace/any.txt"));
        let write_decision = broker
            .request(&write_request, timestamp_ns(0), None)
            .await
            .unwrap();
        assert!(
            write_decision.is_allowed(),
            "write should be allowed when context write_allowlist is empty, got: {write_decision:?}"
        );

        // Execute request should proceed (empty context allowlist = no context firewall
        // check)
        let mut exec_request = make_request("req-exec", ToolClass::Execute, None);
        exec_request = exec_request.with_shell_command("any command");
        let exec_decision = broker
            .request(&exec_request, timestamp_ns(1), None)
            .await
            .unwrap();
        assert!(
            exec_decision.is_allowed(),
            "execute should be allowed when context shell_allowlist is empty, got: {exec_decision:?}"
        );
    }

    // =========================================================================
    // Credential Broker Tests (TCK-00262)
    //
    // These tests verify the credential broker functionality per RFC-0017 TB-003
    // (Credential Isolation Boundary). Credentials are held by the daemon and
    // mediated to tool requests for Git/Network operations.
    // =========================================================================

    /// Helper to make a Git capability.
    fn make_git_capability(id: &str, paths: Vec<PathBuf>) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Git,
            scope: CapabilityScope {
                root_paths: paths,
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    /// Helper to make a Network capability.
    fn make_network_capability(id: &str) -> Capability {
        Capability {
            capability_id: id.to_string(),
            tool_class: ToolClass::Network,
            scope: CapabilityScope {
                root_paths: Vec::new(),
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }
    }

    #[tokio::test]
    async fn test_credential_broker_has_github_store() {
        // TCK-00262: Test has_github_store() method
        use crate::evidence::keychain::InMemoryGitHubCredentialStore;

        // Without store
        let broker_no_store: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy());
        assert!(!broker_no_store.has_github_store());

        // With store
        let store = Arc::new(InMemoryGitHubCredentialStore::new());
        let broker_with_store: ToolBroker<StubManifestLoader> =
            ToolBroker::with_github_store(test_config_without_policy(), store);
        assert!(broker_with_store.has_github_store());
    }

    #[tokio::test]
    async fn test_session_context_creation() {
        // TCK-00263: Test SessionContext builder pattern
        use super::super::decision::SessionContext;

        // Empty context
        let ctx = SessionContext::new();
        assert!(!ctx.has_github_installation());
        assert!(!ctx.has_ssh_session());

        // With GitHub installation ID
        let ctx = SessionContext::new().with_github_installation_id("install-123");
        assert!(ctx.has_github_installation());
        assert_eq!(ctx.github_installation_id.as_ref().unwrap(), "install-123");
        assert!(!ctx.has_ssh_session());

        // With SSH session ID
        let ctx = SessionContext::new().with_ssh_session_id("session-456");
        assert!(!ctx.has_github_installation());
        assert!(ctx.has_ssh_session());
        assert_eq!(ctx.ssh_session_id.as_ref().unwrap(), "session-456");

        // With both
        let ctx = SessionContext::new()
            .with_github_installation_id("install-123")
            .with_ssh_session_id("session-456");
        assert!(ctx.has_github_installation());
        assert!(ctx.has_ssh_session());
    }

    #[tokio::test]
    async fn test_credential_broker_attaches_credential_for_git() {
        // TCK-00262: Git tool requests should have credentials attached
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemoryGitHubCredentialStore;

        let store = Arc::new(InMemoryGitHubCredentialStore::new());
        // Store a token for our installation
        store
            .store_token("install-456", "ghp_test_token_12345")
            .unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_github_store(test_config_without_policy(), store);

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create session context with installation ID
        let session_ctx = SessionContext::new().with_github_installation_id("install-456");

        // Make Git request
        let request = BrokerToolRequest::new(
            "req-git-1",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-1"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_some(),
                "Git request should have credential attached"
            );
            assert_eq!(credential.unwrap().expose_secret(), "ghp_test_token_12345");
        }
    }

    #[tokio::test]
    async fn test_credential_broker_attaches_credential_for_network() {
        // TCK-00262: Network tool requests should have credentials attached
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemoryGitHubCredentialStore;

        let store = Arc::new(InMemoryGitHubCredentialStore::new());
        store
            .store_token("install-789", "ghp_network_token")
            .unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_github_store(test_config_without_policy(), store);

        // Set up manifest with Network capability
        let tool_classes = vec![ToolClass::Network];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_network_capability("cap-network")])
            .tool_allowlist(tool_classes)
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create session context with installation ID
        let session_ctx = SessionContext::new().with_github_installation_id("install-789");

        // Make Network request
        let request = BrokerToolRequest::new(
            "req-network-1",
            test_episode_id(),
            ToolClass::Network,
            test_dedupe_key("network-1"),
            test_args_hash(),
            RiskTier::Tier0,
        );

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_some(),
                "Network request should have credential attached"
            );
            assert_eq!(credential.unwrap().expose_secret(), "ghp_network_token");
        }
    }

    #[tokio::test]
    async fn test_credential_broker_no_credential_for_read() {
        // TCK-00262: Read tool requests should NOT have credentials attached
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemoryGitHubCredentialStore;

        let store = Arc::new(InMemoryGitHubCredentialStore::new());
        store.store_token("install-abc", "ghp_token").unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_github_store(test_config_without_policy(), store);

        // Set up manifest with Read capability
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create session context with installation ID
        let session_ctx = SessionContext::new().with_github_installation_id("install-abc");

        // Make Read request
        let request = make_request("req-read", ToolClass::Read, Some("/workspace/file.rs"));

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Read request should NOT have credential attached"
            );
        }
    }

    #[tokio::test]
    async fn test_credential_broker_no_credential_without_store() {
        // TCK-00262: Without a credential store, Git requests have no credential
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Make Git request (no store configured)
        let request = BrokerToolRequest::new(
            "req-git-no-store",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-no-store"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Git request without store should have no credential"
            );
        }
    }

    #[tokio::test]
    async fn test_credential_broker_no_credential_without_installation_id() {
        // TCK-00262: With store but no installation ID, Git requests have no credential
        use crate::evidence::keychain::InMemoryGitHubCredentialStore;

        let store = Arc::new(InMemoryGitHubCredentialStore::new());
        store.store_token("install-xyz", "ghp_token").unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_github_store(test_config_without_policy(), store);

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Do NOT set installation ID

        // Make Git request
        let request = BrokerToolRequest::new(
            "req-git-no-id",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-no-id"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Git request without installation ID should have no credential"
            );
        }
    }

    #[tokio::test]
    async fn test_credential_broker_missing_token_returns_none() {
        // TCK-00262: If token lookup fails, request still succeeds but without
        // credential
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemoryGitHubCredentialStore;

        let store = Arc::new(InMemoryGitHubCredentialStore::new());
        // Do NOT store any tokens

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_github_store(test_config_without_policy(), store);

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create session context with installation ID (but no token stored for this ID)
        let session_ctx = SessionContext::new().with_github_installation_id("install-missing");

        // Make Git request
        let request = BrokerToolRequest::new(
            "req-git-missing",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-missing"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        // Request should still be allowed, just without credential
        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Git request with missing token should have no credential"
            );
        }
    }

    #[tokio::test]
    async fn test_credential_is_redacted_in_debug() {
        // TCK-00262: Verify Credential debug output is redacted
        let credential = Credential::new("super_secret_token");
        let debug_output = format!("{credential:?}");

        assert!(
            !debug_output.contains("super_secret_token"),
            "Credential should not expose secret in debug output"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Credential debug should show [REDACTED]"
        );
    }

    // =========================================================================
    // SSH Credential Broker Tests (TCK-00263)
    //
    // These tests verify the SSH credential broker functionality per RFC-0017
    // TB-003 (Credential Isolation Boundary). SSH_AUTH_SOCK is held by the
    // daemon and mediated to tool requests for Git SSH operations.
    // =========================================================================

    #[tokio::test]
    async fn test_ssh_broker_has_ssh_store() {
        // TCK-00263: Test has_ssh_store() method
        use crate::evidence::keychain::InMemorySshCredentialStore;

        // Without store
        let broker_no_store: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy());
        assert!(!broker_no_store.has_ssh_store());

        // With store
        let store = Arc::new(InMemorySshCredentialStore::new());
        let broker_with_store: ToolBroker<StubManifestLoader> =
            ToolBroker::with_ssh_store(test_config_without_policy(), store);
        assert!(broker_with_store.has_ssh_store());
    }

    #[tokio::test]
    async fn test_session_context_for_ssh() {
        // TCK-00263: Test SessionContext with SSH session ID
        use super::super::decision::SessionContext;

        // Create session context with SSH session ID
        let ctx = SessionContext::new().with_ssh_session_id("session-123");
        assert!(ctx.has_ssh_session());
        assert_eq!(ctx.ssh_session_id.as_ref().unwrap(), "session-123");

        // Create session context with both GitHub and SSH
        let ctx = SessionContext::new()
            .with_github_installation_id("install-abc")
            .with_ssh_session_id("session-xyz");
        assert!(ctx.has_github_installation());
        assert!(ctx.has_ssh_session());
    }

    #[tokio::test]
    async fn test_ssh_broker_agent_availability() {
        // TCK-00263: Test SSH agent availability detection
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemorySshCredentialStore;

        // Without SSH store
        let broker_no_store: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy());
        assert!(!broker_no_store.is_ssh_agent_available(None).await);

        // Without per-session agent (should return false even if daemon agent exists)
        let store_with_daemon = Arc::new(InMemorySshCredentialStore::with_daemon_auth_sock(
            "/tmp/ssh-agent.sock".to_string(),
        ));
        let broker_with_daemon: ToolBroker<StubManifestLoader> =
            ToolBroker::with_ssh_store(test_config_without_policy(), store_with_daemon);

        // Assert broker reports unavailable because we ignore daemon agent
        assert!(!broker_with_daemon.is_ssh_agent_available(None).await);
        assert!(
            broker_with_daemon
                .get_ssh_auth_sock_for_subprocess(None)
                .await
                .is_none()
        );

        // With per-session agent and temp file
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("agent.sock");
        std::fs::write(&socket_path, "").unwrap();
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let store_session = Arc::new(InMemorySshCredentialStore::new());
        store_session
            .store_ssh_auth_sock("session-1", &socket_path_str)
            .unwrap();

        let broker_session: ToolBroker<StubManifestLoader> =
            ToolBroker::with_ssh_store(test_config_without_policy(), store_session);

        let ctx = SessionContext::new().with_ssh_session_id("session-1");

        assert!(broker_session.is_ssh_agent_available(Some(&ctx)).await);
        assert_eq!(
            broker_session
                .get_ssh_auth_sock_for_subprocess(Some(&ctx))
                .await,
            Some(socket_path_str)
        );
    }

    #[tokio::test]
    async fn test_ssh_broker_attaches_credential_for_git() {
        // TCK-00263: Git tool requests should have SSH credentials attached when
        // GitHub credentials are not available
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemorySshCredentialStore;

        // Create a temp file for the socket so exists() returns true
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("ssh-agent.sock");
        std::fs::write(&socket_path, "").unwrap();
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let store = Arc::new(InMemorySshCredentialStore::new());
        store
            .store_ssh_auth_sock("session-git", &socket_path_str)
            .unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_ssh_store(test_config_without_policy(), store);

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let session_ctx = SessionContext::new().with_ssh_session_id("session-git");

        // Make Git request (no GitHub credentials configured)
        let request = BrokerToolRequest::new(
            "req-git-ssh",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-ssh"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_some(),
                "Git request should have SSH credential attached"
            );
            // The credential contains the SSH_AUTH_SOCK path
            assert_eq!(credential.unwrap().expose_secret(), socket_path_str);
        }
    }

    #[tokio::test]
    async fn test_ssh_broker_no_credential_without_store() {
        // TCK-00263: Without SSH store, Git requests have no SSH credential
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Make Git request (no store configured)
        let request = BrokerToolRequest::new(
            "req-git-no-store",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-no-store"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Git request without store should have no credential"
            );
        }
    }

    #[tokio::test]
    async fn test_ssh_broker_no_credential_without_agent() {
        // TCK-00263: With SSH store but no agent, Git requests have no credential
        use crate::evidence::keychain::InMemorySshCredentialStore;

        let store = Arc::new(InMemorySshCredentialStore::new());
        // Note: No daemon auth sock set, so agent is not available

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_ssh_store(test_config_without_policy(), store);

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Make Git request
        let request = BrokerToolRequest::new(
            "req-git-no-agent",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-no-agent"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Git request without agent should have no credential"
            );
        }
    }

    #[tokio::test]
    async fn test_ssh_broker_github_takes_priority() {
        // TCK-00263: GitHub credentials take priority over SSH credentials
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::{
            InMemoryGitHubCredentialStore, InMemorySshCredentialStore,
        };

        let github_store = Arc::new(InMemoryGitHubCredentialStore::new());
        github_store
            .store_token("install-priority", "ghp_github_token")
            .unwrap();

        let ssh_store = Arc::new(InMemorySshCredentialStore::new());
        ssh_store
            .store_ssh_auth_sock("session-ssh-priority", "/tmp/ssh-agent.sock")
            .unwrap();

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::with_credential_stores(
            test_config_without_policy(),
            github_store,
            ssh_store,
        );

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create session context with GitHub installation ID
        let session_ctx = SessionContext::new()
            .with_github_installation_id("install-priority")
            .with_ssh_session_id("session-ssh-priority");

        // Make Git request
        let request = BrokerToolRequest::new(
            "req-git-priority",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-priority"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(credential.is_some(), "Git request should have credential");
            // Should be GitHub token, not SSH_AUTH_SOCK
            assert_eq!(credential.unwrap().expose_secret(), "ghp_github_token");
        }
    }

    #[tokio::test]
    async fn test_ssh_broker_fallback_to_ssh() {
        // TCK-00263: When GitHub credential fails, fall back to SSH
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::{
            InMemoryGitHubCredentialStore, InMemorySshCredentialStore,
        };

        // Create a temp file for the socket so exists() returns true
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("ssh-agent.sock");
        std::fs::write(&socket_path, "").unwrap();
        let socket_path_str = socket_path.to_string_lossy().to_string();

        let github_store = Arc::new(InMemoryGitHubCredentialStore::new());
        // Note: No token stored for our installation ID

        // Use new() instead of with_daemon_auth_sock()
        let ssh_store = Arc::new(InMemorySshCredentialStore::new());
        // Configure per-session socket
        ssh_store
            .store_ssh_auth_sock("session-ssh-1", &socket_path_str)
            .unwrap();

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::with_credential_stores(
            test_config_without_policy(),
            github_store,
            ssh_store,
        );

        // Set up manifest with Git capability
        let manifest = make_manifest(vec![make_git_capability(
            "cap-git",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Create session context with GitHub installation ID AND SSH session ID
        let session_ctx = SessionContext::new()
            .with_github_installation_id("install-missing")
            .with_ssh_session_id("session-ssh-1");

        // Make Git request
        let request = BrokerToolRequest::new(
            "req-git-fallback",
            test_episode_id(),
            ToolClass::Git,
            test_dedupe_key("git-fallback"),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path("/workspace/repo");

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_some(),
                "Git request should fall back to SSH credential"
            );
            // Should be SSH_AUTH_SOCK since GitHub token was not found
            assert_eq!(credential.unwrap().expose_secret(), socket_path_str);
        }
    }

    #[tokio::test]
    async fn test_ssh_broker_no_credential_for_read() {
        // TCK-00263: Read tool requests should NOT have SSH credentials
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemorySshCredentialStore;

        let store = Arc::new(InMemorySshCredentialStore::new());
        store
            .store_ssh_auth_sock("session-read", "/tmp/ssh-agent.sock")
            .unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_ssh_store(test_config_without_policy(), store);

        // Set up manifest with Read capability
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Session context with SSH session
        let session_ctx = SessionContext::new().with_ssh_session_id("session-read");

        // Make Read request
        let request = make_request("req-read", ToolClass::Read, Some("/workspace/file.rs"));

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Read request should NOT have SSH credential attached"
            );
        }
    }

    #[tokio::test]
    async fn test_ssh_broker_no_credential_for_network() {
        // TCK-00263: Network tool requests should NOT have SSH credentials
        // (SSH is only for Git operations)
        use super::super::decision::SessionContext;
        use crate::evidence::keychain::InMemorySshCredentialStore;

        let store = Arc::new(InMemorySshCredentialStore::new());
        store
            .store_ssh_auth_sock("session-network", "/tmp/ssh-agent.sock")
            .unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::with_ssh_store(test_config_without_policy(), store);

        // Set up manifest with Network capability
        let tool_classes = vec![ToolClass::Network];
        let manifest = CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(vec![make_network_capability("cap-network")])
            .tool_allowlist(tool_classes)
            .build()
            .unwrap();
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Session context
        let session_ctx = SessionContext::new().with_ssh_session_id("session-network");

        // Make Network request
        let request = BrokerToolRequest::new(
            "req-network",
            test_episode_id(),
            ToolClass::Network,
            test_dedupe_key("network"),
            test_args_hash(),
            RiskTier::Tier0,
        );

        let decision = broker
            .request(&request, timestamp_ns(0), Some(&session_ctx))
            .await
            .unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { credential, .. } = decision {
            assert!(
                credential.is_none(),
                "Network request should NOT have SSH credential (SSH is for Git only)"
            );
        }
    }

    #[tokio::test]
    async fn test_ssh_credential_is_redacted_in_debug() {
        // TCK-00263: Verify SSH credential (SSH_AUTH_SOCK path) is redacted in debug
        let credential = Credential::new("/run/user/1000/ssh-agent.sock");
        let debug_output = format!("{credential:?}");

        assert!(
            !debug_output.contains("ssh-agent"),
            "SSH credential should not expose path in debug output"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Credential debug should show [REDACTED]"
        );
    }

    // =========================================================================
    // TCK-00292: Policy Engine Integration Tests
    // =========================================================================

    #[tokio::test]
    async fn tool_broker_policy_engine_deny_when_no_policy() {
        // TCK-00292: Broker denies requests when no policy is configured
        let policy = BrokerPolicyEngine::new();

        assert!(!policy.has_policy());
        assert_eq!(policy.policy_hash(), [0u8; 32]);

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = policy.evaluate(&request);

        match decision {
            PolicyDecision::Deny { rule_id, reason } => {
                assert_eq!(rule_id, NO_POLICY_RULE_ID);
                assert!(reason.contains("No policy configured"));
            },
            PolicyDecision::Allow { .. } => {
                panic!("Request should be denied when no policy is configured");
            },
        }
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_from_tool_allowlist() {
        let policy =
            BrokerPolicyEngine::from_tool_allowlist("session-allowlist", &[ToolClass::Read])
                .expect("allowlist policy should build");

        let read_request = make_request("req-read", ToolClass::Read, Some("/workspace/file.rs"));
        let write_request = make_request("req-write", ToolClass::Write, Some("/workspace/file.rs"));

        assert!(
            matches!(policy.evaluate(&read_request), PolicyDecision::Allow { .. }),
            "Read should be allowed by allowlist-derived policy"
        );
        assert!(
            matches!(policy.evaluate(&write_request), PolicyDecision::Deny { .. }),
            "Write should be denied when absent from allowlist"
        );
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_empty_allowlist_builds_deny_all() {
        let policy = BrokerPolicyEngine::from_tool_allowlist("session-empty", &[])
            .expect("empty allowlist policy should build");

        assert!(
            policy.has_policy(),
            "empty allowlist should still load policy"
        );

        let read_request = make_request("req-read", ToolClass::Read, Some("/workspace/file.rs"));
        assert!(
            matches!(policy.evaluate(&read_request), PolicyDecision::Deny { .. }),
            "Empty allowlist must deny all tools"
        );
    }

    #[tokio::test]
    async fn session_broker_registry_roundtrip() {
        let registry: SessionBrokerRegistry<StubManifestLoader> = SessionBrokerRegistry::new();
        let broker: SharedToolBroker<StubManifestLoader> =
            Arc::new(ToolBroker::new(test_config_without_policy()));

        assert!(registry.is_empty());
        registry.register("S-REG-1", Arc::clone(&broker));
        assert_eq!(registry.len(), 1);
        assert!(registry.get("S-REG-1").is_some());

        let removed = registry.remove_and_return("S-REG-1");
        assert!(removed.is_some());
        assert!(registry.get("S-REG-1").is_none());

        registry.restore("S-REG-1", removed.expect("removed broker should exist"));
        assert!(registry.get("S-REG-1").is_some());

        registry.remove("S-REG-1");
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_allow_with_valid_policy() {
        use apm2_core::policy::LoadedPolicy;

        let policy_yaml = r#"
policy:
  version: "1.0.0"
  name: "test-allow-policy"
  rules:
    - id: "allow-workspace-read"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: allow
  default_decision: deny
"#;

        let loaded = LoadedPolicy::from_yaml(policy_yaml).unwrap();
        let policy = BrokerPolicyEngine::from_policy(&loaded);

        assert!(policy.has_policy());
        assert_ne!(policy.policy_hash(), [0u8; 32]);

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = policy.evaluate(&request);

        match decision {
            PolicyDecision::Allow { rule_id } => {
                assert!(rule_id.is_some());
                assert_eq!(rule_id.unwrap(), "allow-workspace-read");
            },
            PolicyDecision::Deny { .. } => {
                panic!("Request should be allowed by policy");
            },
        }
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_deny_by_default() {
        use apm2_core::policy::LoadedPolicy;

        let policy_yaml = r#"
policy:
  version: "1.0.0"
  name: "test-deny-policy"
  rules:
    - id: "allow-specific-file"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/allowed/file.txt"
      decision: allow
  default_decision: deny
"#;

        let loaded = LoadedPolicy::from_yaml(policy_yaml).unwrap();
        let policy = BrokerPolicyEngine::from_policy(&loaded);

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/not-allowed.rs"));
        let decision = policy.evaluate(&request);

        assert!(matches!(decision, PolicyDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_real_policy_hash() {
        use apm2_core::policy::LoadedPolicy;

        let policy_yaml = r#"
policy:
  version: "1.0.0"
  name: "test-hash-policy"
  rules:
    - id: "allow-all-read"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "**"
      decision: allow
  default_decision: deny
"#;

        let loaded = LoadedPolicy::from_yaml(policy_yaml).unwrap();
        let expected_hash = loaded.content_hash;

        let mut broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(ToolBrokerConfig::default());
        broker.set_policy(&loaded);

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        match decision {
            ToolDecision::Allow { policy_hash, .. } | ToolDecision::Deny { policy_hash, .. } => {
                assert_eq!(policy_hash, expected_hash);
            },
            _ => {},
        }
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_broker_integration() {
        use apm2_core::policy::LoadedPolicy;

        let policy_yaml = r#"
policy:
  version: "1.0.0"
  name: "integration-test-policy"
  rules:
    - id: "allow-workspace-read"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: allow
  default_decision: deny
"#;

        let loaded = LoadedPolicy::from_yaml(policy_yaml).unwrap();

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(ToolBrokerConfig::default()).with_policy(&loaded);

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let allowed_request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let allowed_decision = broker
            .request(&allowed_request, timestamp_ns(0), None)
            .await
            .unwrap();
        assert!(allowed_decision.is_allowed());

        let outside_request = make_request("req-2", ToolClass::Read, Some("/etc/passwd"));
        let outside_decision = broker
            .request(&outside_request, timestamp_ns(1), None)
            .await
            .unwrap();
        assert!(outside_decision.is_denied());
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_deny_no_policy_with_check_enabled() {
        // TCK-00292: Broker denies when check_policy is enabled but no policy is set
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_denied());
        if let ToolDecision::Deny {
            reason, rule_id, ..
        } = decision
        {
            assert_eq!(rule_id, Some(NO_POLICY_RULE_ID.to_string()));
            assert!(matches!(reason, DenyReason::PolicyDenied { .. }));
        }
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_has_policy_methods() {
        use apm2_core::policy::LoadedPolicy;

        let mut broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(ToolBrokerConfig::default());

        assert!(!broker.has_policy());

        let policy_yaml = r#"
policy:
  version: "1.0.0"
  name: "test-policy"
  rules:
    - id: "allow-read"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: allow
  default_decision: deny
"#;

        let loaded = LoadedPolicy::from_yaml(policy_yaml).unwrap();
        broker.set_policy(&loaded);

        assert!(broker.has_policy());
    }

    #[tokio::test]
    async fn tool_broker_policy_engine_with_policy_arc() {
        use std::sync::Arc;

        use apm2_core::policy::LoadedPolicy;

        let policy_yaml = r#"
policy:
  version: "1.0.0"
  name: "shared-policy"
  rules:
    - id: "allow-read"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "**"
      decision: allow
  default_decision: deny
"#;

        let loaded = Arc::new(LoadedPolicy::from_yaml(policy_yaml).unwrap());
        let expected_hash = loaded.content_hash;

        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(ToolBrokerConfig::default()).with_policy_arc(Arc::clone(&loaded));

        assert!(broker.has_policy());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        if let ToolDecision::Allow { policy_hash, .. } = decision {
            assert_eq!(policy_hash, expected_hash);
        }
    }

    #[tokio::test]
    async fn test_broker_list_files_allowed() {
        use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Manifest allowing /workspace/src/main.rs
        let context_manifest = ContextPackManifestBuilder::new("ctx-1", "prof-1")
            .add_entry(
                ManifestEntryBuilder::new("/workspace/src/main.rs", [0u8; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Capability allowing ListFiles
        let manifest = make_manifest(vec![Capability {
            capability_id: "cap-ls".to_string(),
            tool_class: ToolClass::ListFiles,
            scope: CapabilityScope {
                root_paths: vec![PathBuf::from("/workspace")],
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Request ListFiles for allowed path
        let request = make_request(
            "req-ls",
            ToolClass::ListFiles,
            Some("/workspace/src/main.rs"),
        );
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_broker_list_files_denied_by_firewall() {
        use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Manifest allowing /workspace/src/main.rs
        let context_manifest = ContextPackManifestBuilder::new("ctx-1", "prof-1")
            .add_entry(
                ManifestEntryBuilder::new("/workspace/src/main.rs", [0u8; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Capability allowing ListFiles
        let manifest = make_manifest(vec![Capability {
            capability_id: "cap-ls".to_string(),
            tool_class: ToolClass::ListFiles,
            scope: CapabilityScope {
                root_paths: vec![PathBuf::from("/workspace")],
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Request ListFiles for denied path
        let request = make_request("req-ls", ToolClass::ListFiles, Some("/etc/passwd"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_terminate());
    }

    #[tokio::test]
    async fn test_broker_search_allowed() {
        use apm2_core::context::{AccessLevel, ContextPackManifestBuilder, ManifestEntryBuilder};

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Manifest allowing /workspace/src/main.rs
        let context_manifest = ContextPackManifestBuilder::new("ctx-1", "prof-1")
            .add_entry(
                ManifestEntryBuilder::new("/workspace/src/main.rs", [0u8; 32])
                    .access_level(AccessLevel::Read)
                    .build(),
            )
            .build();
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Capability allowing Search
        let manifest = make_manifest(vec![Capability {
            capability_id: "cap-search".to_string(),
            tool_class: ToolClass::Search,
            scope: CapabilityScope {
                root_paths: vec![PathBuf::from("/workspace")],
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier0,
        }]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Request Search for allowed path
        let request = make_request(
            "req-search",
            ToolClass::Search,
            Some("/workspace/src/main.rs"),
        )
        .with_query("fn main");
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
    }

    // =========================================================================
    // TCK-00326: Context Pack Storage Tests
    //
    // Tests for `seal_and_store_context_pack` and `initialize_context_from_hash`
    // methods that enable context pack persistence via CAS.
    // =========================================================================

    #[tokio::test]
    async fn test_seal_and_store_context_pack_success() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};
        use crate::episode::executor::ContentAddressedStore as CasTrait;

        // Create a durable CAS (use subdirectory so DurableCas creates it with 0700)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create broker with durable CAS
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(cas.clone());

        // Create a valid context manifest
        let manifest = make_context_manifest(
            vec![("/workspace/file.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );

        // Seal and store should succeed
        let result = broker.seal_and_store_context_pack(&manifest);
        assert!(result.is_ok(), "seal_and_store_context_pack should succeed");

        let stored_hash = result.unwrap();

        // The stored hash is the CAS hash (blake3 of serialized JSON),
        // which differs from manifest_hash() (semantic content hash).
        // This is intentional: CAS addresses by content, manifest seals by semantics.

        // Verify content is actually in CAS (use trait method explicitly)
        let retrieved = CasTrait::retrieve(cas.as_ref(), &stored_hash);
        assert!(
            retrieved.is_some(),
            "content should be retrievable from CAS"
        );

        // Verify the retrieved content deserializes back to the same manifest
        let retrieved_content = retrieved.unwrap();
        let mut recovered: apm2_core::context::ContextPackManifest =
            serde_json::from_slice(&retrieved_content).expect("should deserialize");
        recovered.rebuild_index();

        assert_eq!(
            manifest.manifest_hash(),
            recovered.manifest_hash(),
            "recovered manifest should have same semantic hash"
        );
    }

    #[tokio::test]
    async fn test_seal_and_store_context_pack_invalid_seal() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};

        // Create a durable CAS (use subdirectory so DurableCas creates it with 0700)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create broker with durable CAS
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(cas);

        // Create a manifest with corrupted hash via JSON (simulating tampering)
        let json = r#"{"manifest_id":"manifest-001","manifest_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"profile_id":"profile-001","entries":[]}"#;
        let mut tampered_manifest: apm2_core::context::ContextPackManifest =
            serde_json::from_str(json).unwrap();
        tampered_manifest.rebuild_index();

        // seal_and_store should fail with ContextPackSealInvalid
        let result = broker.seal_and_store_context_pack(&tampered_manifest);
        assert!(
            matches!(result, Err(BrokerError::ContextPackSealInvalid { .. })),
            "should fail with ContextPackSealInvalid for tampered manifest, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_initialize_context_from_hash_success() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};

        // Create a durable CAS (use subdirectory so DurableCas creates it with 0700)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create broker with durable CAS
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(cas.clone());

        // Create and store a valid context manifest
        let manifest = make_context_manifest(
            vec![("/workspace/file.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        let stored_hash = broker
            .seal_and_store_context_pack(&manifest)
            .expect("store should succeed");

        // Initialize from hash should succeed
        let result = broker.initialize_context_from_hash(&stored_hash).await;
        assert!(
            result.is_ok(),
            "initialize_context_from_hash should succeed, got {result:?}"
        );

        // Verify the context firewall is now active by checking manifest is loaded.
        // Note: context_pack_hash() returns the manifest's semantic hash
        // (manifest_hash()), not the CAS address. This is intentional - the
        // manifest doesn't know its CAS address.
        let context_hash = broker.context_pack_hash().await;
        assert!(
            context_hash.is_some(),
            "context pack should be loaded after initialization"
        );
        // The loaded manifest hash should equal the original manifest hash
        assert_eq!(
            context_hash.unwrap(),
            manifest.manifest_hash(),
            "loaded context pack should have the same semantic hash as the original"
        );
    }

    #[tokio::test]
    async fn test_initialize_context_from_hash_not_found() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};

        // Create a durable CAS (empty; use subdir for 0700 permissions)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create broker with durable CAS
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(cas);

        // Try to initialize from a hash that doesn't exist in CAS
        let nonexistent_hash = [0xAB; 32];
        let result = broker.initialize_context_from_hash(&nonexistent_hash).await;

        assert!(
            matches!(result, Err(BrokerError::ContextPackNotFound { .. })),
            "should fail with ContextPackNotFound for missing hash, got {result:?}"
        );

        if let Err(BrokerError::ContextPackNotFound { hash }) = result {
            assert_eq!(
                hash,
                hex::encode(nonexistent_hash),
                "error should contain the missing hash"
            );
        }
    }

    #[tokio::test]
    async fn test_initialize_context_from_hash_integrity_mismatch() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};
        use crate::episode::executor::ContentAddressedStore as CasTrait;

        // Define the poisoned CAS struct at the start of the function (before
        // statements) to simulate a CAS poisoning attack where content doesn't
        // match the hash.
        #[derive(Debug)]
        struct PoisonedCas {
            inner: Arc<DurableCas>,
            poison_hash: [u8; 32],
            poisoned_content: Vec<u8>,
        }

        impl CasTrait for PoisonedCas {
            fn store(&self, content: &[u8]) -> Hash {
                // Use trait method on inner
                CasTrait::store(self.inner.as_ref(), content)
            }

            fn retrieve(&self, hash: &Hash) -> Option<Vec<u8>> {
                if hash == &self.poison_hash {
                    // Return different content than what the hash represents
                    Some(self.poisoned_content.clone())
                } else {
                    // Use trait method on inner
                    CasTrait::retrieve(self.inner.as_ref(), hash)
                }
            }
        }

        // Create a durable CAS (use subdirectory so DurableCas creates it with 0700)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create broker with durable CAS
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(cas.clone());

        // Create and store a valid context manifest
        let manifest = make_context_manifest(
            vec![("/workspace/file.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        let stored_hash = broker
            .seal_and_store_context_pack(&manifest)
            .expect("store should succeed");

        // Create a poisoned CAS that returns different content for our hash
        let poisoned_cas = Arc::new(PoisonedCas {
            inner: cas,
            poison_hash: stored_hash,
            poisoned_content: b"totally different content".to_vec(),
        });

        // Create a new broker with the poisoned CAS
        let poisoned_broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(poisoned_cas);

        // Try to initialize from the hash - should fail with integrity mismatch
        let result = poisoned_broker
            .initialize_context_from_hash(&stored_hash)
            .await;

        assert!(
            matches!(
                result,
                Err(BrokerError::ContextPackIntegrityMismatch { .. })
            ),
            "should fail with ContextPackIntegrityMismatch for poisoned CAS, got {result:?}"
        );

        if let Err(BrokerError::ContextPackIntegrityMismatch { expected, computed }) = result {
            assert_eq!(
                expected,
                hex::encode(stored_hash),
                "expected hash should match the requested hash"
            );
            // Computed hash should be the hash of the poisoned content
            let expected_computed =
                hex::encode(blake3::hash(b"totally different content").as_bytes());
            assert_eq!(
                computed, expected_computed,
                "computed hash should be the hash of the poisoned content"
            );
        }
    }

    #[tokio::test]
    async fn test_initialize_context_from_hash_invalid_seal() {
        use tempfile::TempDir;

        use crate::cas::{DurableCas, DurableCasConfig};
        use crate::episode::executor::ContentAddressedStore as CasTrait;

        // Create a durable CAS (use subdirectory so DurableCas creates it with 0700)
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path().join("cas"));
        let cas = Arc::new(DurableCas::new(cas_config).unwrap());

        // Create a tampered manifest JSON with wrong hash
        let tampered_json = r#"{"manifest_id":"manifest-tampered","manifest_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"profile_id":"profile-001","entries":[]}"#;
        let tampered_bytes = tampered_json.as_bytes();

        // Store the tampered content directly in CAS (use trait method)
        let content_hash = CasTrait::store(cas.as_ref(), tampered_bytes);

        // Create broker with the CAS
        let broker: ToolBroker<StubManifestLoader> =
            ToolBroker::new(test_config_without_policy()).with_cas(cas);

        // Try to initialize from the hash - should fail with invalid seal
        let result = broker.initialize_context_from_hash(&content_hash).await;

        assert!(
            matches!(result, Err(BrokerError::ContextPackSealInvalid { .. })),
            "should fail with ContextPackSealInvalid for tampered manifest, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_context_pack_error_kinds() {
        // Test the error kind strings for context pack errors
        let not_found = BrokerError::ContextPackNotFound {
            hash: "abc123".to_string(),
        };
        assert_eq!(not_found.kind(), "context_pack_not_found");
        assert!(not_found.should_emit_review_blocked());
        assert!(!not_found.is_retriable());

        let seal_invalid = BrokerError::ContextPackSealInvalid {
            reason: "hash mismatch".to_string(),
        };
        assert_eq!(seal_invalid.kind(), "context_pack_seal_invalid");
        assert!(seal_invalid.should_emit_review_blocked());
        assert!(!seal_invalid.is_retriable());

        let integrity_mismatch = BrokerError::ContextPackIntegrityMismatch {
            expected: "abc".to_string(),
            computed: "def".to_string(),
        };
        assert_eq!(integrity_mismatch.kind(), "context_pack_integrity_mismatch");
        assert!(integrity_mismatch.should_emit_review_blocked());
        assert!(!integrity_mismatch.is_retriable());

        let deserialization_failed = BrokerError::ContextPackDeserializationFailed {
            reason: "invalid json".to_string(),
        };
        assert_eq!(
            deserialization_failed.kind(),
            "context_pack_deserialization_failed"
        );
        assert!(deserialization_failed.should_emit_review_blocked());
        assert!(!deserialization_failed.is_retriable());
    }

    // =========================================================================
    // TCK-00375 BLOCKER 3: Warn mode MUST deny out-of-pack reads
    //
    // Per REQ-0029, out-of-pack reads must ALWAYS be denied regardless of
    // the firewall mode.  Even Warn mode must not permit out-of-pack access.
    // =========================================================================

    #[tokio::test]
    async fn test_warn_mode_denies_out_of_pack_reads() {
        // TCK-00375 BLOCKER 3: Even with Warn firewall policy for low tiers,
        // out-of-pack reads MUST be denied (not just warned).
        use apm2_core::context::firewall::FirewallMode;

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy())
            .with_firewall_policy(RiskTierFirewallPolicy {
                low_risk_mode: FirewallMode::Warn,
                medium_risk_mode: FirewallMode::Warn,
            });

        // Set up capability manifest allowing reads from /workspace
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Context manifest allows ONLY /workspace/allowed.rs
        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request for out-of-pack path — MUST be denied even in Warn mode
        let request = make_request("req-oop", ToolClass::Read, Some("/workspace/secret.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            !decision.is_allowed(),
            "out-of-pack read MUST be denied even in Warn mode, got: {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_warn_mode_allows_in_pack_reads() {
        // TCK-00375: Warn mode for in-pack allowed paths should still succeed
        use apm2_core::context::firewall::FirewallMode;

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy())
            .with_firewall_policy(RiskTierFirewallPolicy {
                low_risk_mode: FirewallMode::Warn,
                medium_risk_mode: FirewallMode::Warn,
            });

        // Set up capability manifest allowing reads from /workspace
        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Context manifest allows /workspace/allowed.rs
        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request for in-pack path — should be allowed
        let request = make_request("req-inpack", ToolClass::Read, Some("/workspace/allowed.rs"));
        let decision = broker
            .request(&request, timestamp_ns(0), None)
            .await
            .unwrap();

        assert!(
            decision.is_allowed(),
            "in-pack read should be allowed in Warn mode, got: {decision:?}"
        );
    }

    // =========================================================================
    // TCK-00375 BLOCKER 2: Defect emission for Tier3+ violations
    //
    // Per REQ-0029, Tier3+ violations MUST emit FirewallViolationDefect.
    // Verify that defects are accumulated and drainable.
    // =========================================================================

    #[tokio::test]
    async fn test_tier3_violation_emits_defect() {
        // TCK-00375 BLOCKER 2: Tier3+ firewall violations MUST produce
        // drainable defects.
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Set up capability manifest allowing reads from /workspace at Tier3
        let caps = vec![Capability {
            capability_id: "cap-read-t3".to_string(),
            tool_class: ToolClass::Read,
            scope: CapabilityScope {
                root_paths: vec![PathBuf::from("/workspace")],
                allowed_patterns: Vec::new(),
                size_limits: super::super::scope::SizeLimits::default_limits(),
                network_policy: None,
            },
            risk_tier_required: RiskTier::Tier3,
        }];
        let manifest = make_manifest(caps);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Context manifest allows ONLY /workspace/allowed.rs
        let context_manifest = make_context_manifest(
            vec![("/workspace/allowed.rs", [0x42; 32])],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Request for out-of-pack path at Tier3 — should terminate AND emit defect
        let mut req = BrokerToolRequest::new(
            "req-t3-deny",
            test_episode_id(),
            ToolClass::Read,
            test_dedupe_key("t3-deny"),
            test_args_hash(),
            RiskTier::Tier3,
        );
        req = req.with_path("/workspace/secret.rs");
        let decision = broker.request(&req, timestamp_ns(0), None).await.unwrap();

        assert!(
            decision.is_terminate(),
            "Tier3 out-of-pack read must terminate, got: {decision:?}"
        );

        // Drain defects — there should be at least one
        let defects = broker.drain_firewall_defects().await;
        assert!(
            !defects.is_empty(),
            "Tier3+ violation MUST emit at least one FirewallViolationDefect"
        );
        assert_eq!(defects[0].risk_tier, 3);
        assert_eq!(defects[0].path, "/workspace/secret.rs");
    }

    // =========================================================================
    // TCK-00375 BLOCKER 1: TOCTOU verification is callable and functional
    //
    // verify_toctou() must detect content hash mismatches.
    // =========================================================================

    #[tokio::test]
    async fn test_verify_toctou_detects_mismatch() {
        // TCK-00375 BLOCKER 1: verify_toctou must fail when content differs
        // from the manifest hash.
        let content = b"fn main() { println!(\"hello\"); }";
        let correct_hash = *blake3::hash(content).as_bytes();

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        // Context manifest with the correct hash
        let context_manifest = make_context_manifest(
            vec![("/workspace/main.rs", correct_hash)],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Verify with correct content — should pass
        let result = broker
            .verify_toctou("/workspace/main.rs", content, RiskTier::Tier0)
            .await;
        assert!(result.is_ok(), "correct content should pass TOCTOU check");

        // Verify with tampered content — should fail
        let tampered = b"fn main() { std::process::exit(1); }";
        let result = broker
            .verify_toctou("/workspace/main.rs", tampered, RiskTier::Tier0)
            .await;
        assert!(result.is_err(), "tampered content must fail TOCTOU check");
    }

    #[tokio::test]
    async fn test_verify_toctou_emits_defect_for_tier3() {
        // TCK-00375 BLOCKER 1+2: verify_toctou at Tier3 must emit a defect
        let content = b"fn main() {}";
        let correct_hash = *blake3::hash(content).as_bytes();

        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(test_config_without_policy());

        let context_manifest = make_context_manifest(
            vec![("/workspace/main.rs", correct_hash)],
            Vec::new(),
            Vec::new(),
        );
        broker
            .initialize_with_context_manifest(context_manifest)
            .await
            .unwrap();

        // Tampered content at Tier3
        let tampered = b"rm -rf /";
        let result = broker
            .verify_toctou("/workspace/main.rs", tampered, RiskTier::Tier3)
            .await;
        assert!(result.is_err(), "TOCTOU mismatch must fail");

        let defects = broker.drain_firewall_defects().await;
        assert!(
            !defects.is_empty(),
            "Tier3 TOCTOU mismatch MUST emit a defect"
        );
        assert_eq!(
            defects[0].violation_type,
            apm2_core::context::firewall::FirewallViolationType::ToctouMismatch,
        );
        assert_eq!(defects[0].risk_tier, 3);
    }
}
