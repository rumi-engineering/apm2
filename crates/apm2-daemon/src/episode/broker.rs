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

use std::sync::Arc;

use apm2_core::context::ContextPackManifest;
use apm2_core::context::firewall::{ContextAwareValidator, DefaultContextFirewall, FirewallMode};
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
        }
    }

    /// Returns `true` if this error is retriable.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        matches!(self, Self::ExecutionFailed { .. })
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
    /// * `manifest_override` - Optional manifest override for per-session
    ///   capabilities (TCK-00317). If provided, this manifest is used instead
    ///   of the broker's global manifest.
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
    #[instrument(skip(self, request, session_context, manifest_override), fields(request_id = %request.request_id))]
    pub async fn request(
        &self,
        request: &BrokerToolRequest,
        timestamp_ns: u64,
        session_context: Option<&super::decision::SessionContext>,
        manifest_override: Option<&CapabilityManifest>,
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
                        return Ok(make_terminate("CONTEXT_READ_NO_PATH"));
                    };

                    let firewall =
                        DefaultContextFirewall::new(context_manifest, FirewallMode::HardFail);
                    let path_str = path.to_string_lossy();

                    if let Err(e) = firewall.validate_read(&path_str, None) {
                        warn!(path = %path_str, error = %e, "context firewall violation");
                        return Ok(make_terminate("CONTEXT_MISS"));
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
                            return Ok(make_terminate("CONTEXT_WRITE_NO_PATH"));
                        };

                        if !context_manifest.is_write_path_allowed(path) {
                            warn!(
                                path = %path.display(),
                                "context firewall violation: path not in write_allowlist"
                            );
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
                            return Ok(make_terminate("CONTEXT_EXEC_NO_CMD"));
                        };

                        if !context_manifest.is_shell_command_allowed(command) {
                            warn!(
                                command = %command,
                                "context firewall violation: command not in shell_allowlist"
                            );
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
        let cap_decision = if let Some(manifest) = manifest_override {
            // TCK-00317: Use per-session manifest if provided
            // Create a temporary validator for this request
            let validator = CapabilityValidator::new(manifest.clone())?;
            let cap_request = request.to_capability_request();
            validator.validate(&cap_request)
        } else {
            // Fall back to broker-global manifest (if initialized)
            let validator_guard = self.validator.read().await;
            let validator = validator_guard.as_ref().ok_or(BrokerError::NotInitialized)?;
            let cap_request = request.to_capability_request();
            validator.validate(&cap_request)
        };

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
        let result = broker.request(&request, timestamp_ns(0), None, None).await;

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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(1), None, None)
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
                .request(&request, timestamp_ns(i), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(1), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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

        let result = broker.request(&request, timestamp_ns(0), None, None).await;
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

        // Create a durable CAS
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path());
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

        // Create a durable CAS
        let temp_dir = TempDir::new().unwrap();
        let cas_config = DurableCasConfig::new(temp_dir.path());
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
            .request(&read_request, timestamp_ns(0), None, None)
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
            .request(&write_request, timestamp_ns(1), None, None)
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
            .request(&request1, timestamp_ns(0), None, None)
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
            .request(&request1, timestamp_ns(1), None, None)
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
            .request(&request2, timestamp_ns(2), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(1), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&write_request, timestamp_ns(0), None, None)
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
            .request(&exec_request, timestamp_ns(1), None, None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), Some(&session_ctx), None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&allowed_request, timestamp_ns(0), None, None)
            .await
            .unwrap();
        assert!(allowed_decision.is_allowed());

        let outside_request = make_request("req-2", ToolClass::Read, Some("/etc/passwd"));
        let outside_decision = broker
            .request(&outside_request, timestamp_ns(1), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
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
            .request(&request, timestamp_ns(0), None, None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
    }
}
