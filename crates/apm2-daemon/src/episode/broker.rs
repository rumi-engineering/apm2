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

use thiserror::Error;
use tracing::{debug, instrument, warn};

use super::capability::{
    CapabilityDecision, CapabilityError, CapabilityManifest, CapabilityValidator, DenyReason,
    ManifestLoadError, ManifestLoader,
};
use super::decision::{
    BrokerToolRequest, BudgetDelta, DedupeKey, RequestValidationError, ToolDecision, ToolResult,
};
use super::dedupe::{DedupeCache, DedupeCacheConfig, SharedDedupeCache};
use super::error::EpisodeId;
use super::runtime::Hash;

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
// PolicyEngine Stub
//
// TODO: Full PolicyEngine integration in a future ticket.
// This stub provides the interface without actual policy evaluation.
// =============================================================================

/// Policy evaluation result.
///
/// TODO: This will be replaced with the actual `PolicyEngine` types in a future
/// ticket.
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

/// Stub policy engine.
///
/// TODO: Replace with actual `PolicyEngine` from `apm2_core` in a future
/// ticket.
#[derive(Debug, Clone, Default)]
pub struct StubPolicyEngine {
    /// Hash of the policy version (stub uses zeros).
    policy_hash: Hash,
}

impl StubPolicyEngine {
    /// Creates a new stub policy engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy_hash: [0u8; 32],
        }
    }

    /// Evaluates a request against policy.
    ///
    /// The stub always allows requests.
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
// ContentAddressedStore Stub
//
// TODO: Full CAS integration in a future ticket.
// This stub provides the interface without actual storage.
// =============================================================================

/// Stub content-addressed store.
///
/// TODO: Replace with actual CAS implementation in a future ticket.
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
/// let broker = ToolBroker::new(ToolBrokerConfig::default());
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

    /// Policy engine.
    ///
    /// TODO: Replace with `Arc<PolicyEngine>` in a future ticket.
    policy: StubPolicyEngine,

    /// Content-addressed store.
    ///
    /// TODO: Replace with `Arc<ContentAddressedStore>` in a future ticket.
    #[allow(dead_code)]
    cas: Arc<StubContentAddressedStore>,

    /// Optional manifest loader for CAS-based initialization.
    #[allow(dead_code)]
    loader: Option<Arc<L>>,
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
            policy: StubPolicyEngine::new(),
            cas: Arc::new(StubContentAddressedStore::new()),
            loader: None,
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
            policy: StubPolicyEngine::new(),
            cas: Arc::new(StubContentAddressedStore::new()),
            loader: Some(loader),
        }
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
    /// 2. Checks the dedupe cache for cached results
    /// 3. Validates against capability manifests
    /// 4. Evaluates policy rules
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to process
    /// * `timestamp_ns` - Current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// A `ToolDecision` indicating whether the request is allowed, denied,
    /// or matched a cached result.
    ///
    /// # Errors
    ///
    /// Returns an error if the broker is not initialized or request
    /// validation fails.
    #[instrument(skip(self, request), fields(request_id = %request.request_id))]
    pub async fn request(
        &self,
        request: &BrokerToolRequest,
        timestamp_ns: u64,
    ) -> Result<ToolDecision, BrokerError> {
        // Step 1: Validate request structure
        request.validate()?;

        // Step 2: Check dedupe cache
        if self.config.use_dedupe_cache {
            if let Some(cached) = self.lookup_dedupe(&request.dedupe_key, timestamp_ns).await {
                debug!(dedupe_key = %request.dedupe_key, "dedupe cache hit");
                return Ok(ToolDecision::DedupeCacheHit {
                    request_id: request.request_id.clone(),
                    result: Box::new(cached),
                });
            }
        }

        // Step 3: Validate against capability manifest
        let validator = self.validator.read().await;
        let validator = validator.as_ref().ok_or(BrokerError::NotInitialized)?;

        let cap_request = request.to_capability_request();
        let cap_decision = validator.validate(&cap_request);

        let capability_id = match cap_decision {
            CapabilityDecision::Allow { capability_id } => capability_id,
            CapabilityDecision::Deny { reason } => {
                debug!(reason = %reason, "capability denied");
                return Ok(ToolDecision::Deny {
                    request_id: request.request_id.clone(),
                    reason,
                    rule_id: None,
                    policy_hash: self.policy.policy_hash(),
                });
            },
        };

        // Step 4: Evaluate policy (if enabled)
        if self.config.check_policy {
            match self.policy.evaluate(request) {
                PolicyDecision::Allow { rule_id } => {
                    debug!(capability_id = %capability_id, "request allowed");
                    Ok(ToolDecision::Allow {
                        request_id: request.request_id.clone(),
                        capability_id,
                        rule_id,
                        policy_hash: self.policy.policy_hash(),
                        budget_delta: BudgetDelta::single_call(),
                    })
                },
                PolicyDecision::Deny { rule_id, reason } => {
                    warn!(rule_id = %rule_id, reason = %reason, "policy denied");
                    Ok(ToolDecision::Deny {
                        request_id: request.request_id.clone(),
                        reason: DenyReason::NoMatchingCapability {
                            tool_class: request.tool_class,
                        },
                        rule_id: Some(rule_id),
                        policy_hash: self.policy.policy_hash(),
                    })
                },
            }
        } else {
            // Policy check disabled
            debug!(capability_id = %capability_id, "request allowed (no policy check)");
            Ok(ToolDecision::Allow {
                request_id: request.request_id.clone(),
                capability_id,
                rule_id: None,
                policy_hash: self.policy.policy_hash(),
                budget_delta: BudgetDelta::single_call(),
            })
        }
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

    /// Looks up a cached result by dedupe key.
    ///
    /// # Arguments
    ///
    /// * `key` - The dedupe key to lookup
    /// * `timestamp_ns` - Current timestamp (for TTL check)
    ///
    /// # Returns
    ///
    /// The cached result if found and not expired.
    pub async fn lookup_dedupe(&self, key: &DedupeKey, timestamp_ns: u64) -> Option<ToolResult> {
        if !self.config.use_dedupe_cache {
            return None;
        }
        self.dedupe_cache.get(key, timestamp_ns).await
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
#[must_use]
pub fn new_shared_broker<L: ManifestLoader + Send + Sync>(
    config: ToolBrokerConfig,
) -> SharedToolBroker<L> {
    Arc::new(ToolBroker::new(config))
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
        CapabilityManifest::builder("test-manifest")
            .delegator("test-delegator")
            .capabilities(caps)
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

    #[tokio::test]
    async fn test_broker_not_initialized() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

        assert!(!broker.is_initialized().await);

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let result = broker.request(&request, timestamp_ns(0)).await;

        assert!(matches!(result, Err(BrokerError::NotInitialized)));
    }

    #[tokio::test]
    async fn test_broker_initialize_with_manifest() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

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
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));
        let decision = broker.request(&request, timestamp_ns(0)).await.unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { capability_id, .. } = decision {
            assert_eq!(capability_id, "cap-read");
        }
    }

    #[tokio::test]
    async fn test_broker_request_denied_no_capability() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Request Write capability when only Read is available
        let request = make_request("req-1", ToolClass::Write, Some("/workspace/file.rs"));
        let decision = broker.request(&request, timestamp_ns(0)).await.unwrap();

        assert!(decision.is_denied());
    }

    #[tokio::test]
    async fn test_broker_request_denied_path_not_allowed() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        // Request path outside of allowed scope
        let request = make_request("req-1", ToolClass::Read, Some("/etc/passwd"));
        let decision = broker.request(&request, timestamp_ns(0)).await.unwrap();

        assert!(decision.is_denied());
        if let ToolDecision::Deny { reason, .. } = decision {
            assert!(matches!(reason, DenyReason::PathNotAllowed { .. }));
        }
    }

    #[tokio::test]
    async fn test_broker_dedupe_cache_hit() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));

        // First request - should be allowed
        let decision = broker.request(&request, timestamp_ns(0)).await.unwrap();
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
        let decision2 = broker.request(&request, timestamp_ns(1)).await.unwrap();
        assert!(decision2.is_cache_hit());

        if let ToolDecision::DedupeCacheHit { result, .. } = decision2 {
            assert_eq!(result.output, b"file contents");
        }
    }

    #[tokio::test]
    async fn test_broker_evict_episode() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

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
            let decision = broker.request(&request, timestamp_ns(i)).await.unwrap();

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
        let config = ToolBrokerConfig::default().without_dedupe_cache();
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(config);

        let manifest = make_manifest(vec![make_read_capability(
            "cap-read",
            vec![PathBuf::from("/workspace")],
        )]);
        broker.initialize_with_manifest(manifest).await.unwrap();

        let request = make_request("req-1", ToolClass::Read, Some("/workspace/file.rs"));

        // First request
        let decision = broker.request(&request, timestamp_ns(0)).await.unwrap();
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
        let decision2 = broker.request(&request, timestamp_ns(1)).await.unwrap();
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
        let decision = broker.request(&request, timestamp_ns(0)).await.unwrap();

        assert!(decision.is_allowed());
        if let ToolDecision::Allow { rule_id, .. } = decision {
            assert!(rule_id.is_none());
        }
    }

    #[tokio::test]
    async fn test_broker_request_validation_error() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

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

        let result = broker.request(&request, timestamp_ns(0)).await;
        assert!(matches!(result, Err(BrokerError::RequestValidation(_))));
    }

    #[tokio::test]
    async fn test_broker_record_result_not_allowed() {
        let broker: ToolBroker<StubManifestLoader> = ToolBroker::new(ToolBrokerConfig::default());

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
}
