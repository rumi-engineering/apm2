//! Adapter registry for managing harness adapters.
//!
//! This module provides the [`AdapterRegistry`] for registering and looking up
//! harness adapters by type. Per AD-LAYER-001 and AD-ADAPT-001, the registry
//! acts as a factory for per-episode Holon instances.
//!
//! # Profile-Based Selection (TCK-00328)
//!
//! Per RFC-0019 Addendum, adapter profiles are CAS-addressed artifacts. Profile
//! selection is explicit by hash; **ambient defaults are forbidden**.
//!
//! The registry supports two modes:
//!
//! 1. **Legacy Mode**: Uses `with_defaults()` for backward compatibility with
//!    existing tests. This mode is **deprecated** and will be removed.
//!
//! 2. **Profile Mode**: Uses `with_profile()` to load an
//!    `AgentAdapterProfileV1` from CAS by hash. This is the preferred mode for
//!    production use.
//!
//! # Usage (Profile Mode - Recommended)
//!
//! ```rust,ignore
//! use apm2_daemon::episode::registry::AdapterRegistry;
//! use apm2_core::fac::AgentAdapterProfileV1;
//!
//! // Load profile from CAS by hash
//! let registry = AdapterRegistry::with_profile(&cas, &profile_hash)?;
//!
//! // Profile hash is recorded for attribution
//! let hash = registry.profile_hash().expect("profile was loaded");
//! ```
//!
//! # Usage (Legacy Mode - Deprecated)
//!
//! ```rust,ignore
//! use apm2_daemon::episode::registry::AdapterRegistry;
//! use apm2_daemon::episode::adapter::AdapterType;
//! use apm2_daemon::episode::raw_adapter::RawAdapter;
//!
//! let mut registry = AdapterRegistry::new();
//! registry.register(Box::new(RawAdapter::new()));
//!
//! // Get adapter reference for spawning
//! let adapter = registry.get(AdapterType::Raw).unwrap();
//! assert_eq!(adapter.adapter_type(), AdapterType::Raw);
//!
//! // Create per-episode Holon instance
//! let holon = registry.create_holon(AdapterType::Raw).unwrap();
//! ```

use std::collections::HashMap;

use apm2_core::evidence::ContentAddressedStore;
use apm2_core::fac::{AgentAdapterProfileError, AgentAdapterProfileV1};

use super::adapter::{AdapterType, HarnessAdapter};
use super::claude_code::{ClaudeCodeAdapter, ClaudeCodeHolon};
use super::raw_adapter::{RawAdapter, RawAdapterHolon};

/// Error type for adapter registry operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AdapterRegistryError {
    /// Failed to load profile from CAS.
    #[error("failed to load profile from CAS: {0}")]
    ProfileLoadFailed(String),

    /// Profile validation failed.
    #[error("profile validation failed: {0}")]
    ProfileInvalid(String),



    /// No profile hash available (legacy mode).
    #[error("no profile hash available: registry was created in legacy mode")]
    NoProfileHash,
}

impl From<AgentAdapterProfileError> for AdapterRegistryError {
    fn from(e: AgentAdapterProfileError) -> Self {
        Self::ProfileLoadFailed(e.to_string())
    }
}

/// Registry for harness adapters.
///
/// Provides a centralized location for registering and retrieving adapters
/// by their type. The registry owns the adapter instances and acts as a
/// factory for per-episode Holon instances.
///
/// # Profile-Based Selection (TCK-00328)
///
/// Per RFC-0019 Addendum, adapter profiles are CAS-addressed artifacts.
/// The registry records the `profile_hash` for attribution in ledger events.
///
/// Use [`with_profile`](Self::with_profile) for production use:
///
/// ```rust,ignore
/// let registry = AdapterRegistry::with_profile(&cas, &profile_hash)?;
/// let hash = registry.profile_hash().expect("profile loaded");
/// ```
///
/// # Factory Pattern
///
/// Per AD-LAYER-001 and AD-ADAPT-001, the registry provides:
/// - Singleton adapter instances for resource management (semaphores, etc.)
/// - Factory method [`create_holon`](Self::create_holon) for per-episode
///   execution handles
///
/// This separation ensures thread-safe operation in a concurrent daemon.
///
/// # Thread Safety
///
/// The registry itself is not internally synchronized. Wrap in `Arc<RwLock<_>>`
/// if concurrent access is needed.
#[derive(Default)]
pub struct AdapterRegistry {
    /// Registered adapters by type.
    adapters: HashMap<AdapterType, Box<dyn HarnessAdapter>>,
    /// CAS hash of the loaded profile (TCK-00328).
    ///
    /// This is `Some` when the registry was created via `with_profile()`,
    /// and `None` when created via legacy methods (`new()`, `with_defaults()`).
    /// The hash is used for ledger attribution per SEC-CTRL-FAC-0015.
    profile_hash: Option<[u8; 32]>,
    /// The loaded profile configuration (TCK-00328).
    ///
    /// Stored for reference by execution code that needs profile parameters.
    profile: Option<AgentAdapterProfileV1>,
}

impl AdapterRegistry {
    /// Create a new empty adapter registry.
    ///
    /// # Note
    ///
    /// This creates a registry in legacy mode with no profile hash.
    /// For production use, prefer [`with_profile`](Self::with_profile).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new registry with default adapters registered.
    ///
    /// # Deprecation Notice (TCK-00328)
    ///
    /// This method uses ambient defaults, which is **deprecated** per RFC-0019
    /// Addendum. For production use, prefer
    /// [`with_profile`](Self::with_profile) to load a CAS-addressed profile
    /// by hash.
    ///
    /// This method is retained for backward compatibility with existing tests.
    ///
    /// This registers:
    /// - [`RawAdapter`] for [`AdapterType::Raw`]
    /// - [`ClaudeCodeAdapter`] for [`AdapterType::ClaudeCode`]
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(RawAdapter::new()));
        registry.register(Box::new(ClaudeCodeAdapter::new()));
        registry
    }

    /// Create a new registry from a CAS-addressed profile (TCK-00328).
    ///
    /// Per RFC-0019 Addendum, adapter profiles are CAS-addressed artifacts.
    /// Profile selection is explicit by hash; ambient defaults are forbidden.
    ///
    /// # Arguments
    ///
    /// * `cas` - Content-addressed store to load the profile from
    /// * `profile_hash` - BLAKE3 hash of the profile to load
    ///
    /// # Returns
    ///
    /// A configured registry with the appropriate adapters registered based
    /// on the profile's `adapter_mode`.
    ///
    /// # Errors
    ///
    /// Returns `AdapterRegistryError` if:
    /// - Profile cannot be loaded from CAS
    /// - Profile fails validation
    /// - Profile uses an unsupported adapter mode
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let registry = AdapterRegistry::with_profile(&cas, &profile_hash)?;
    ///
    /// // Profile hash is available for attribution
    /// let hash = registry.profile_hash().expect("profile was loaded");
    /// ```
    pub fn with_profile(
        cas: &dyn ContentAddressedStore,
        profile_hash: &[u8; 32],
    ) -> Result<Self, AdapterRegistryError> {
        // Load profile from CAS
        let profile = AgentAdapterProfileV1::load_from_cas(cas, profile_hash)?;

        // Create registry based on profile configuration
        let mut registry = Self {
            adapters: HashMap::new(),
            profile_hash: Some(*profile_hash),
            profile: Some(profile.clone()),
        };

        // Register adapters
        // Note: All adapter modes currently use the same set of adapters for FAC v0.
        // As we implement specific bridging logic (e.g. MCP), this may diverge.
        registry.register(Box::new(ClaudeCodeAdapter::new()));
        registry.register(Box::new(RawAdapter::new()));

        Ok(registry)
    }

    /// Returns the CAS hash of the loaded profile (TCK-00328).
    ///
    /// This hash is used for ledger attribution per SEC-CTRL-FAC-0015.
    /// Returns `None` if the registry was created in legacy mode.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let registry = AdapterRegistry::with_profile(&cas, &hash)?;
    /// assert_eq!(registry.profile_hash(), Some(&hash));
    ///
    /// let legacy = AdapterRegistry::with_defaults();
    /// assert!(legacy.profile_hash().is_none());
    /// ```
    #[must_use]
    pub const fn profile_hash(&self) -> Option<&[u8; 32]> {
        self.profile_hash.as_ref()
    }

    /// Returns the loaded profile configuration (TCK-00328).
    ///
    /// Returns `None` if the registry was created in legacy mode.
    #[must_use]
    pub const fn profile(&self) -> Option<&AgentAdapterProfileV1> {
        self.profile.as_ref()
    }

    /// Returns `true` if this registry was created with an explicit profile.
    ///
    /// Per RFC-0019 Addendum, production use should always have a profile.
    /// Legacy mode (no profile) is deprecated.
    #[must_use]
    pub const fn has_profile(&self) -> bool {
        self.profile_hash.is_some()
    }

    /// Register an adapter.
    ///
    /// If an adapter of the same type is already registered, it will be
    /// replaced and the old adapter returned.
    ///
    /// # Arguments
    ///
    /// * `adapter` - The adapter to register
    ///
    /// # Returns
    ///
    /// The previously registered adapter of the same type, if any.
    pub fn register(
        &mut self,
        adapter: Box<dyn HarnessAdapter>,
    ) -> Option<Box<dyn HarnessAdapter>> {
        let adapter_type = adapter.adapter_type();
        self.adapters.insert(adapter_type, adapter)
    }

    /// Get an adapter by type.
    ///
    /// # Arguments
    ///
    /// * `adapter_type` - The type of adapter to retrieve
    ///
    /// # Returns
    ///
    /// A reference to the adapter, or `None` if not registered.
    #[must_use]
    pub fn get(&self, adapter_type: AdapterType) -> Option<&dyn HarnessAdapter> {
        self.adapters.get(&adapter_type).map(AsRef::as_ref)
    }

    /// Check if an adapter type is registered.
    #[must_use]
    pub fn contains(&self, adapter_type: AdapterType) -> bool {
        self.adapters.contains_key(&adapter_type)
    }

    /// Remove an adapter by type.
    ///
    /// # Returns
    ///
    /// The removed adapter, or `None` if not registered.
    pub fn remove(&mut self, adapter_type: AdapterType) -> Option<Box<dyn HarnessAdapter>> {
        self.adapters.remove(&adapter_type)
    }

    /// Returns the number of registered adapters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Returns true if no adapters are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    /// Returns an iterator over registered adapter types.
    pub fn adapter_types(&self) -> impl Iterator<Item = AdapterType> + '_ {
        self.adapters.keys().copied()
    }

    /// Creates a per-episode `RawAdapterHolon` instance.
    ///
    /// Per AD-LAYER-001 and AD-ADAPT-001, this factory method creates a fresh
    /// Holon instance for each episode.
    ///
    /// # Arguments
    ///
    /// * `adapter_type` - Must be [`AdapterType::Raw`]
    ///
    /// # Returns
    ///
    /// A boxed `RawAdapterHolon`, or `None` if not registered.
    #[must_use]
    pub fn create_raw_holon(&self) -> Option<Box<RawAdapterHolon>> {
        self.adapters.get(&AdapterType::Raw).and_then(|adapter| {
            let raw_adapter = adapter.as_any().downcast_ref::<RawAdapter>()?;
            Some(raw_adapter.create_holon())
        })
    }

    /// Creates a per-episode `ClaudeCodeHolon` instance.
    ///
    /// Per AD-LAYER-001 and AD-ADAPT-001, this factory method creates a fresh
    /// Holon instance for each episode with Claude Code parsing.
    ///
    /// # Returns
    ///
    /// A boxed `ClaudeCodeHolon`, or `None` if not registered.
    #[must_use]
    pub fn create_claude_code_holon(&self) -> Option<Box<ClaudeCodeHolon>> {
        self.adapters
            .get(&AdapterType::ClaudeCode)
            .and_then(|adapter| {
                let cc_adapter = adapter.as_any().downcast_ref::<ClaudeCodeAdapter>()?;
                Some(cc_adapter.create_holon())
            })
    }

    /// Creates a per-episode Holon instance for the specified adapter type.
    ///
    /// Per AD-LAYER-001 and AD-ADAPT-001, this factory method creates a fresh
    /// Holon instance for each episode, ensuring:
    /// - Thread-safe state isolation between concurrent episodes
    /// - Proper resource sharing (semaphores) with the singleton adapter
    /// - Independent lifecycle management per episode
    ///
    /// # Arguments
    ///
    /// * `adapter_type` - The type of adapter to create a Holon for
    ///
    /// # Returns
    ///
    /// A boxed Holon instance, or `None` if the adapter type is not registered
    /// or doesn't support Holon creation.
    ///
    /// # Note
    ///
    /// This method returns `Box<RawAdapterHolon>` for backwards compatibility.
    /// For Claude Code holons, use
    /// [`create_claude_code_holon`](Self::create_claude_code_holon).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let registry = AdapterRegistry::with_defaults();
    /// let holon = registry.create_holon(AdapterType::Raw).unwrap();
    /// holon.intake(config, "lease-123")?;
    /// let result = holon.execute_episode(&ctx)?;
    /// ```
    #[must_use]
    pub fn create_holon(&self, adapter_type: AdapterType) -> Option<Box<RawAdapterHolon>> {
        match adapter_type {
            AdapterType::Raw => self.create_raw_holon(),
            AdapterType::ClaudeCode => {
                // Return None for backwards compatibility
                // Use create_claude_code_holon() for ClaudeCode adapters
                None
            },
        }
    }
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field("adapter_types", &self.adapters.keys().collect::<Vec<_>>())
            .field("has_profile", &self.profile_hash.is_some())
            .field(
                "profile_hash",
                &self.profile_hash.map(|h| hex::encode(&h[..8])),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use apm2_holon::Holon;

    use super::*;

    #[test]
    fn test_registry_new_empty() {
        let registry = AdapterRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = AdapterRegistry::new();

        let adapter = Box::new(RawAdapter::new());
        let old = registry.register(adapter);

        assert!(old.is_none());
        assert_eq!(registry.len(), 1);
        assert!(registry.contains(AdapterType::Raw));

        let retrieved = registry.get(AdapterType::Raw);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().adapter_type(), AdapterType::Raw);
    }

    #[test]
    fn test_registry_get_nonexistent() {
        let registry = AdapterRegistry::new();
        assert!(registry.get(AdapterType::Raw).is_none());
        assert!(registry.get(AdapterType::ClaudeCode).is_none());
    }

    #[test]
    fn test_registry_register_replaces() {
        let mut registry = AdapterRegistry::new();

        registry.register(Box::new(RawAdapter::new()));
        let old = registry.register(Box::new(RawAdapter::new()));

        assert!(old.is_some());
        assert_eq!(old.unwrap().adapter_type(), AdapterType::Raw);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_registry_remove() {
        let mut registry = AdapterRegistry::new();
        registry.register(Box::new(RawAdapter::new()));

        let removed = registry.remove(AdapterType::Raw);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().adapter_type(), AdapterType::Raw);
        assert!(registry.is_empty());
    }

    #[test]
    fn test_registry_remove_nonexistent() {
        let mut registry = AdapterRegistry::new();
        let removed = registry.remove(AdapterType::Raw);
        assert!(removed.is_none());
    }

    #[test]
    fn test_registry_with_defaults() {
        let registry = AdapterRegistry::with_defaults();

        assert!(!registry.is_empty());
        assert!(registry.contains(AdapterType::Raw));
        assert!(registry.contains(AdapterType::ClaudeCode));

        let raw = registry.get(AdapterType::Raw).unwrap();
        assert_eq!(raw.adapter_type(), AdapterType::Raw);

        let claude = registry.get(AdapterType::ClaudeCode).unwrap();
        assert_eq!(claude.adapter_type(), AdapterType::ClaudeCode);
    }

    #[test]
    fn test_registry_adapter_types_iterator() {
        let mut registry = AdapterRegistry::new();
        registry.register(Box::new(RawAdapter::new()));

        let types: Vec<_> = registry.adapter_types().collect();
        assert_eq!(types.len(), 1);
        assert!(types.contains(&AdapterType::Raw));
    }

    #[test]
    fn test_registry_debug() {
        let registry = AdapterRegistry::with_defaults();
        let debug_str = format!("{registry:?}");
        assert!(debug_str.contains("AdapterRegistry"));
        assert!(debug_str.contains("Raw"));
    }

    // =========================================================================
    // Holon Factory Tests
    // =========================================================================

    #[test]
    fn test_registry_create_holon_raw() {
        let registry = AdapterRegistry::with_defaults();
        let holon = registry.create_holon(AdapterType::Raw);
        assert!(holon.is_some());

        let holon = holon.unwrap();
        assert_eq!(holon.type_name(), "RawAdapterHolon");
    }

    #[test]
    fn test_registry_create_raw_holon() {
        let registry = AdapterRegistry::with_defaults();
        let holon = registry.create_raw_holon();
        assert!(holon.is_some());
        assert_eq!(holon.unwrap().type_name(), "RawAdapterHolon");
    }

    #[test]
    fn test_registry_create_claude_code_holon() {
        let registry = AdapterRegistry::with_defaults();
        let holon = registry.create_claude_code_holon();
        assert!(holon.is_some());
        assert_eq!(holon.unwrap().type_name(), "ClaudeCodeHolon");
    }

    #[test]
    fn test_registry_create_holon_unregistered() {
        let registry = AdapterRegistry::new();
        let holon = registry.create_holon(AdapterType::Raw);
        assert!(holon.is_none());
    }

    #[test]
    fn test_registry_create_holon_claude_code_returns_none() {
        // create_holon returns None for ClaudeCode for backwards compatibility
        // Use create_claude_code_holon instead
        let registry = AdapterRegistry::with_defaults();
        let holon = registry.create_holon(AdapterType::ClaudeCode);
        assert!(holon.is_none());
    }

    #[test]
    fn test_registry_create_multiple_holons() {
        let registry = AdapterRegistry::with_defaults();

        // Should be able to create multiple holons
        let holon1 = registry.create_holon(AdapterType::Raw);
        let holon2 = registry.create_holon(AdapterType::Raw);

        assert!(holon1.is_some());
        assert!(holon2.is_some());

        // They should be independent instances
        let holon1 = holon1.unwrap();
        let holon2 = holon2.unwrap();

        assert_eq!(holon1.type_name(), "RawAdapterHolon");
        assert_eq!(holon2.type_name(), "RawAdapterHolon");
    }

    #[test]
    fn test_registry_create_multiple_claude_code_holons() {
        let registry = AdapterRegistry::with_defaults();

        let holon1 = registry.create_claude_code_holon();
        let holon2 = registry.create_claude_code_holon();

        assert!(holon1.is_some());
        assert!(holon2.is_some());

        assert_eq!(holon1.unwrap().type_name(), "ClaudeCodeHolon");
        assert_eq!(holon2.unwrap().type_name(), "ClaudeCodeHolon");
    }

    // =========================================================================
    // TCK-00328: Profile-Based Selection Tests
    // =========================================================================

    #[test]
    fn test_legacy_registry_has_no_profile() {
        // Legacy with_defaults() mode has no profile hash
        let registry = AdapterRegistry::with_defaults();
        assert!(!registry.has_profile());
        assert!(registry.profile_hash().is_none());
        assert!(registry.profile().is_none());
    }

    #[test]
    fn test_new_registry_has_no_profile() {
        // Empty registry has no profile hash
        let registry = AdapterRegistry::new();
        assert!(!registry.has_profile());
        assert!(registry.profile_hash().is_none());
        assert!(registry.profile().is_none());
    }

    #[test]
    fn test_profile_registry_from_cas() {
        use std::collections::BTreeMap;

        use apm2_core::evidence::MemoryCas;
        use apm2_core::fac::{
            AdapterMode, AgentAdapterProfileV1, BudgetDefaults, EvidencePolicy, HealthChecks,
            InputMode, OutputMode, VersionProbe,
        };

        // Create a valid profile
        let profile = AgentAdapterProfileV1::builder()
            .profile_id("claude-code-test-v1")
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/claude")
            .args_template(vec!["-p".to_string()])
            .env_template(vec![("CLAUDE_NO_TOOLS".to_string(), "1".to_string())])
            .cwd("/workspace")
            .requires_pty(false)
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .permission_mode_map(BTreeMap::new())
            .capability_map(BTreeMap::new())
            .version_probe(VersionProbe::new(
                "claude --version",
                r"claude (\d+\.\d+\.\d+)",
            ))
            .health_checks(HealthChecks::default())
            .budget_defaults(BudgetDefaults::default())
            .evidence_policy(EvidencePolicy::default())
            .build()
            .expect("valid profile");

        // Store in CAS
        let cas = MemoryCas::new();
        let hash = profile.store_in_cas(&cas).expect("store should succeed");

        // Create registry from profile
        let registry =
            AdapterRegistry::with_profile(&cas, &hash).expect("should load profile from CAS");

        // Verify profile is loaded
        assert!(registry.has_profile());
        assert_eq!(registry.profile_hash(), Some(&hash));
        assert!(registry.profile().is_some());
        assert_eq!(
            registry.profile().unwrap().profile_id,
            "claude-code-test-v1"
        );

        // Verify adapters are registered
        assert!(registry.contains(AdapterType::ClaudeCode));
        assert!(registry.contains(AdapterType::Raw));
    }

    #[test]
    fn test_profile_registry_load_fails_for_missing_hash() {
        use apm2_core::evidence::MemoryCas;

        let cas = MemoryCas::new();
        let fake_hash = [0x42u8; 32];

        // Should fail to load non-existent profile
        let result = AdapterRegistry::with_profile(&cas, &fake_hash);
        assert!(result.is_err());

        match result {
            Err(AdapterRegistryError::ProfileLoadFailed(_)) => {
                // Expected
            },
            other => panic!("Expected ProfileLoadFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_profile_hash_available_for_attribution() {
        use apm2_core::evidence::MemoryCas;
        use apm2_core::fac::{
            AdapterMode, AgentAdapterProfileV1, InputMode, OutputMode, VersionProbe,
        };

        let profile = AgentAdapterProfileV1::builder()
            .profile_id("test-profile")
            .adapter_mode(AdapterMode::StructuredOutput)
            .command("/usr/bin/agent")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Jsonl)
            .version_probe(VersionProbe::new("agent --version", r"v(\d+)"))
            .build()
            .expect("valid profile");

        let cas = MemoryCas::new();
        let hash = profile.store_in_cas(&cas).expect("store should succeed");

        let registry = AdapterRegistry::with_profile(&cas, &hash).expect("load profile");

        // Profile hash should be available for ledger attribution
        let profile_hash = registry.profile_hash().expect("has profile hash");
        assert_eq!(*profile_hash, hash);

        // Hash can be encoded for ledger events
        let hex_hash = hex::encode(profile_hash);
        assert_eq!(hex_hash.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_profile_debug_shows_hash() {
        use apm2_core::evidence::MemoryCas;
        use apm2_core::fac::{
            AdapterMode, AgentAdapterProfileV1, InputMode, OutputMode, VersionProbe,
        };

        let profile = AgentAdapterProfileV1::builder()
            .profile_id("debug-test")
            .adapter_mode(AdapterMode::BlackBox)
            .command("/usr/bin/test")
            .cwd("/workspace")
            .input_mode(InputMode::Stdin)
            .output_mode(OutputMode::Raw)
            .version_probe(VersionProbe::new("test --version", r"v(\d+)"))
            .build()
            .expect("valid profile");

        let cas = MemoryCas::new();
        let hash = profile.store_in_cas(&cas).expect("store should succeed");

        let registry = AdapterRegistry::with_profile(&cas, &hash).expect("load profile");
        let debug_str = format!("{registry:?}");

        // Debug should show has_profile and partial hash
        assert!(debug_str.contains("has_profile: true"));
        assert!(debug_str.contains("profile_hash"));
    }

    #[test]
    fn test_legacy_debug_shows_no_profile() {
        let registry = AdapterRegistry::with_defaults();
        let debug_str = format!("{registry:?}");

        assert!(debug_str.contains("has_profile: false"));
    }
}

// =============================================================================
// Session Registry (TCK-00259)
// =============================================================================

use std::collections::VecDeque;
use std::sync::RwLock;

use crate::session::{SessionRegistry, SessionRegistryError, SessionState};

/// Maximum number of sessions tracked in the session registry.
///
/// Per CTR-1303: In-memory stores must have `max_entries` limit to prevent
/// denial-of-service via memory exhaustion.
pub const MAX_SESSIONS: usize = 10_000;

/// Internal state for the session registry.
///
/// This struct consolidates all mutable state under a single lock to prevent
/// deadlocks from lock ordering issues (AB/BA lock inversion).
#[derive(Debug, Default)]
struct RegistryState {
    /// Insertion order queue for LRU eviction.
    queue: VecDeque<String>,
    /// Sessions indexed by session ID.
    by_id: HashMap<String, SessionState>,
    /// Session ID lookup by ephemeral handle.
    by_handle: HashMap<String, String>,
}

/// In-memory session registry for tracking active sessions.
///
/// # Capacity Limits (CTR-1303)
///
/// This registry enforces a maximum of [`MAX_SESSIONS`] entries to prevent
/// memory exhaustion. When the limit is reached, the oldest entry (by insertion
/// order) is evicted to make room for the new session.
///
/// # Thread Safety
///
/// Uses a single `RwLock<RegistryState>` to prevent deadlocks from lock
/// ordering issues. All operations acquire only one lock.
#[derive(Debug, Default)]
pub struct InMemorySessionRegistry {
    /// Consolidated state under a single lock to prevent deadlocks.
    state: RwLock<RegistryState>,
}

impl InMemorySessionRegistry {
    /// Creates a new empty session registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionRegistry for InMemorySessionRegistry {
    fn register_session(&self, session: SessionState) -> Result<(), SessionRegistryError> {
        let mut state = self.state.write().expect("lock poisoned");

        if state.by_id.contains_key(&session.session_id) {
            return Err(SessionRegistryError::DuplicateSessionId {
                session_id: session.session_id,
            });
        }

        // CTR-1303: Evict oldest entry if at capacity
        while state.by_id.len() >= MAX_SESSIONS {
            if let Some(oldest_key) = state.queue.pop_front() {
                if let Some(evicted) = state.by_id.remove(&oldest_key) {
                    state.by_handle.remove(&evicted.ephemeral_handle);
                }
            } else {
                break;
            }
        }

        let session_id = session.session_id.clone();
        let handle = session.ephemeral_handle.clone();
        state.queue.push_back(session_id.clone());
        state.by_handle.insert(handle, session_id.clone());
        state.by_id.insert(session_id, session);
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Option<SessionState> {
        let state = self.state.read().expect("lock poisoned");
        state.by_id.get(session_id).cloned()
    }

    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState> {
        let state = self.state.read().expect("lock poisoned");
        let session_id = state.by_handle.get(handle)?;
        state.by_id.get(session_id).cloned()
    }
}

impl InMemorySessionRegistry {
    /// Returns all active sessions for recovery purposes.
    ///
    /// This is used during crash recovery to identify sessions that need
    /// `LEASE_REVOKED` signals.
    pub fn all_sessions(&self) -> Vec<SessionState> {
        let state = self.state.read().expect("lock poisoned");
        state.by_id.values().cloned().collect()
    }

    /// Removes a session by ID.
    ///
    /// Used during crash recovery to clean up sessions after sending
    /// `LEASE_REVOKED` signals.
    pub fn remove_session(&self, session_id: &str) -> Option<SessionState> {
        let mut state = self.state.write().expect("lock poisoned");

        if let Some(session) = state.by_id.remove(session_id) {
            state.by_handle.remove(&session.ephemeral_handle);
            state.queue.retain(|id| id != session_id);
            Some(session)
        } else {
            None
        }
    }

    /// Clears all sessions.
    ///
    /// Used during crash recovery after sending all `LEASE_REVOKED` signals.
    pub fn clear(&self) {
        let mut state = self.state.write().expect("lock poisoned");
        state.by_id.clear();
        state.by_handle.clear();
        state.queue.clear();
    }

    /// Returns the number of active sessions.
    pub fn len(&self) -> usize {
        let state = self.state.read().expect("lock poisoned");
        state.by_id.len()
    }

    /// Returns true if there are no active sessions.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// Crash Recovery Manager (TCK-00267)
// =============================================================================

use std::time::{Duration, Instant};

use crate::protocol::messages::{LeaseRevoked, LeaseRevokedReason, RecoverSessionsResponse};

/// Default timeout for crash recovery (5 seconds per acceptance criteria).
pub const DEFAULT_RECOVERY_TIMEOUT_MS: u32 = 5000;

/// Result of the crash recovery process.
#[derive(Debug, Clone)]
pub struct RecoveryResult {
    /// Number of sessions that were recovered.
    pub sessions_recovered: u32,
    /// Number of orphaned processes cleaned up.
    pub orphaned_processes_cleaned: u32,
    /// Number of `LEASE_REVOKED` signals sent.
    pub lease_revoked_signals_sent: u32,
    /// Time taken for recovery (milliseconds).
    pub recovery_time_ms: u32,
}

impl From<RecoveryResult> for RecoverSessionsResponse {
    fn from(result: RecoveryResult) -> Self {
        Self {
            sessions_recovered: result.sessions_recovered,
            orphaned_processes_cleaned: result.orphaned_processes_cleaned,
            lease_revoked_signals_sent: result.lease_revoked_signals_sent,
            recovery_time_ms: result.recovery_time_ms,
        }
    }
}

/// Manager for crash recovery operations.
///
/// Per TCK-00267, this handles:
/// 1. Loading persistent state on daemon startup
/// 2. Sending `LEASE_REVOKED` signals to recovered sessions
/// 3. Cleaning up orphaned processes
/// 4. Completing recovery within 5 seconds
///
/// # Recovery Workflow
///
/// ```text
/// daemon startup
///      |
///      v
/// load_persistent_state() -- Load any saved session state
///      |
///      v
/// for each recovered session:
///   send_lease_revoked() -- Notify session their lease is invalid
///      |
///      v
/// cleanup_orphaned_processes() -- Kill any orphaned session processes
///      |
///      v
/// recovery complete (must be within 5s)
/// ```
#[derive(Debug)]
pub struct RecoveryManager {
    /// Timeout for recovery operations.
    timeout: Duration,
}

impl Default for RecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryManager {
    /// Creates a new recovery manager with the default timeout.
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_millis(u64::from(DEFAULT_RECOVERY_TIMEOUT_MS)),
        }
    }

    /// Creates a new recovery manager with a custom timeout.
    #[must_use]
    pub fn with_timeout(timeout_ms: u32) -> Self {
        Self {
            timeout: Duration::from_millis(u64::from(timeout_ms)),
        }
    }

    /// Returns the configured timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Creates a `LEASE_REVOKED` message for a session.
    ///
    /// This message informs the session that its lease is no longer valid
    /// and it must re-authenticate before continuing.
    #[must_use]
    pub fn create_lease_revoked(
        session: &SessionState,
        reason: LeaseRevokedReason,
        message: Option<String>,
    ) -> LeaseRevoked {
        LeaseRevoked {
            session_id: session.session_id.clone(),
            lease_id: session.lease_id.clone(),
            reason: reason as i32,
            revoked_at_ns: current_timestamp_ns(),
            message,
        }
    }

    /// Performs crash recovery for all sessions in the registry.
    ///
    /// This method:
    /// 1. Collects all sessions from the registry
    /// 2. Creates `LEASE_REVOKED` signals for each session
    /// 3. Cleans up orphaned processes
    /// 4. Clears the registry
    ///
    /// # Returns
    ///
    /// Returns `Ok(RecoveryResult)` if recovery completed within the timeout,
    /// or `Err(RecoveryError)` if the timeout was exceeded.
    ///
    /// # Arguments
    ///
    /// * `registry` - The session registry to recover from
    /// * `signal_sender` - Callback to send `LEASE_REVOKED` signals to sessions
    #[allow(clippy::cast_possible_truncation)] // Recovery timeout is always < 5s, well within u32
    pub fn recover_sessions<F>(
        &self,
        registry: &InMemorySessionRegistry,
        mut signal_sender: F,
    ) -> Result<RecoveryResult, RecoveryError>
    where
        F: FnMut(&LeaseRevoked) -> Result<(), RecoveryError>,
    {
        let start = Instant::now();
        let deadline = start + self.timeout;

        // Collect all sessions
        let sessions = registry.all_sessions();
        let sessions_recovered = sessions.len() as u32;

        // Send `LEASE_REVOKED` to each session
        let mut lease_revoked_signals_sent = 0u32;
        for session in &sessions {
            // Check timeout
            if Instant::now() > deadline {
                return Err(RecoveryError::Timeout {
                    elapsed_ms: start.elapsed().as_millis() as u32,
                    timeout_ms: self.timeout.as_millis() as u32,
                });
            }

            let signal = Self::create_lease_revoked(
                session,
                LeaseRevokedReason::LeaseRevokedDaemonRestart,
                Some("Daemon restarted, lease invalidated".to_string()),
            );

            signal_sender(&signal)?;
            lease_revoked_signals_sent += 1;
        }

        // Check timeout before cleanup
        if Instant::now() > deadline {
            return Err(RecoveryError::Timeout {
                elapsed_ms: start.elapsed().as_millis() as u32,
                timeout_ms: self.timeout.as_millis() as u32,
            });
        }

        // Cleanup orphaned processes
        let orphaned_processes_cleaned = self.cleanup_orphaned_processes(&sessions)?;

        // Clear the registry after recovery
        registry.clear();

        let recovery_time_ms = start.elapsed().as_millis() as u32;

        // Final timeout check
        if recovery_time_ms > self.timeout.as_millis() as u32 {
            return Err(RecoveryError::Timeout {
                elapsed_ms: recovery_time_ms,
                timeout_ms: self.timeout.as_millis() as u32,
            });
        }

        Ok(RecoveryResult {
            sessions_recovered,
            orphaned_processes_cleaned,
            lease_revoked_signals_sent,
            recovery_time_ms,
        })
    }

    /// Cleans up orphaned session processes.
    ///
    /// This looks for processes that were spawned by previous sessions and
    /// sends them SIGTERM to terminate gracefully.
    ///
    /// # Note
    ///
    /// In a real implementation, this would:
    /// 1. Read PID files from a known location
    /// 2. Check if those processes are still running
    /// 3. Send SIGTERM (and SIGKILL after timeout) to orphaned processes
    ///
    /// For now, we assume no persistent PID tracking (sessions are in-memory
    /// only), so there are no orphaned processes to clean up.
    ///
    /// Future enhancement: Add PID file tracking to detect and kill orphaned
    /// processes.
    #[allow(
        clippy::unused_self,
        clippy::unnecessary_wraps,
        clippy::missing_const_for_fn
    )]
    fn cleanup_orphaned_processes(&self, _sessions: &[SessionState]) -> Result<u32, RecoveryError> {
        Ok(0)
    }
}

/// Error type for recovery operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RecoveryError {
    /// Recovery timed out.
    #[error("recovery timeout: {elapsed_ms}ms elapsed, timeout is {timeout_ms}ms")]
    Timeout {
        /// Elapsed time in milliseconds.
        elapsed_ms: u32,
        /// Configured timeout in milliseconds.
        timeout_ms: u32,
    },

    /// Failed to send `LEASE_REVOKED` signal.
    #[error("failed to send `LEASE_REVOKED` signal: {message}")]
    SignalFailed {
        /// Error message.
        message: String,
    },

    /// Process cleanup failed.
    #[error("failed to cleanup orphaned processes: {message}")]
    CleanupFailed {
        /// Error message.
        message: String,
    },
}

/// Returns the current timestamp in nanoseconds since epoch.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

// =============================================================================
// Persistent Session Registry (TCK-00266)
// =============================================================================

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Maximum file size for state files (10 MB).
///
/// Per SEC-003, this prevents denial-of-service via unbounded memory allocation
/// when loading maliciously crafted state files.
const MAX_STATE_FILE_SIZE: u64 = 10 * 1024 * 1024;

use serde::{Deserialize, Serialize};

/// Persistable session state that excludes sensitive credentials.
///
/// Per SEC-001, the `lease_id` field is a bearer token that MUST NOT be
/// persisted to disk. Sessions loaded from disk will need to re-authenticate
/// with the credential broker.
///
/// This struct mirrors [`SessionState`] but omits the `lease_id` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistableSessionState {
    /// Unique session identifier.
    pub session_id: String,
    /// Work ID this session is associated with.
    pub work_id: String,
    /// Role claimed for this session.
    pub role: i32,
    /// Ephemeral handle for IPC communication.
    pub ephemeral_handle: String,
    /// Policy resolution reference.
    pub policy_resolved_ref: String,
    /// Hash of the capability manifest for this session.
    pub capability_manifest_hash: Vec<u8>,
    /// Episode ID in the runtime (if created).
    pub episode_id: Option<String>,
}

impl From<&SessionState> for PersistableSessionState {
    fn from(session: &SessionState) -> Self {
        Self {
            session_id: session.session_id.clone(),
            work_id: session.work_id.clone(),
            role: session.role,
            ephemeral_handle: session.ephemeral_handle.clone(),
            policy_resolved_ref: session.policy_resolved_ref.clone(),
            capability_manifest_hash: session.capability_manifest_hash.clone(),
            episode_id: session.episode_id.clone(),
        }
    }
}

impl From<PersistableSessionState> for SessionState {
    fn from(persistable: PersistableSessionState) -> Self {
        Self {
            session_id: persistable.session_id,
            work_id: persistable.work_id,
            role: persistable.role,
            ephemeral_handle: persistable.ephemeral_handle,
            // Sessions loaded from disk have no valid lease - they must re-authenticate
            lease_id: String::new(),
            policy_resolved_ref: persistable.policy_resolved_ref,
            capability_manifest_hash: persistable.capability_manifest_hash,
            episode_id: persistable.episode_id,
        }
    }
}

/// Serializable state file format for persistent session registry.
///
/// Per TCK-00266 and DD-005, the state file is JSON for human readability
/// and debugging.
///
/// # Security (SEC-001)
///
/// This file uses [`PersistableSessionState`] which excludes the `lease_id`
/// bearer token to prevent credential leakage to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentStateFile {
    /// Version of the state file format for future compatibility.
    version: u32,
    /// Active sessions persisted to disk (without credentials).
    sessions: Vec<PersistableSessionState>,
}

impl Default for PersistentStateFile {
    fn default() -> Self {
        Self {
            version: 1,
            sessions: Vec::new(),
        }
    }
}

/// Error type for persistent session registry operations.
#[derive(Debug, thiserror::Error)]
pub enum PersistentRegistryError {
    /// I/O error during state file operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Session registry error.
    #[error("Session registry error: {0}")]
    Registry(#[from] SessionRegistryError),

    /// State file version mismatch.
    #[error("State file version {found} is not supported (expected {expected})")]
    VersionMismatch {
        /// The version found in the file.
        found: u32,
        /// The expected version.
        expected: u32,
    },

    /// State file exceeds maximum allowed size.
    ///
    /// Per SEC-003, this prevents denial-of-service via unbounded memory
    /// allocation.
    #[error("State file size {size} bytes exceeds maximum allowed size {max} bytes")]
    FileTooLarge {
        /// The actual file size.
        size: u64,
        /// The maximum allowed size.
        max: u64,
    },
}

/// Persistent session registry for crash recovery.
///
/// Per TCK-00266 and DD-005, this registry wraps [`InMemorySessionRegistry`]
/// and persists session state to a JSON file using atomic writes
/// (write-to-temp + rename).
///
/// # Atomic Writes
///
/// To prevent corruption from crashes during writes, this registry:
/// 1. Serializes state to JSON
/// 2. Writes to a temporary file (same directory, `.tmp` suffix)
/// 3. Calls `fsync()` on the temp file
/// 4. Atomically renames temp file to the state file path
///
/// # Recovery
///
/// On startup, call [`load_from_file`](Self::load_from_file) to restore
/// session state from the state file.
///
/// # Thread Safety
///
/// Uses the same `RwLock` strategy as [`InMemorySessionRegistry`].
#[derive(Debug)]
pub struct PersistentSessionRegistry {
    /// In-memory registry for fast lookups.
    inner: InMemorySessionRegistry,
    /// Path to the state file.
    state_file_path: PathBuf,
}

impl PersistentSessionRegistry {
    /// Creates a new persistent registry with the given state file path.
    ///
    /// This does NOT load existing state. Call
    /// [`load_from_file`](Self::load_from_file) to restore state after
    /// creation.
    #[must_use]
    pub fn new(state_file_path: impl AsRef<Path>) -> Self {
        Self {
            inner: InMemorySessionRegistry::new(),
            state_file_path: state_file_path.as_ref().to_path_buf(),
        }
    }

    /// Creates a new persistent registry and loads existing state from the
    /// file.
    ///
    /// If the state file does not exist, returns an empty registry.
    /// If the state file exists but cannot be parsed, returns an error.
    ///
    /// # Security
    ///
    /// - SEC-001: Sessions are loaded without `lease_id` (they must
    ///   re-authenticate)
    /// - SEC-003: File size is checked before reading to prevent
    ///   denial-of-service via memory exhaustion
    pub fn load_from_file(
        state_file_path: impl AsRef<Path>,
    ) -> Result<Self, PersistentRegistryError> {
        let path = state_file_path.as_ref();
        let registry = Self::new(path);

        if path.exists() {
            // SEC-003: Open file first, then check metadata to avoid TOCTOU
            let file = File::open(path)?;
            let metadata = file.metadata()?;
            let file_size = metadata.len();

            if file_size > MAX_STATE_FILE_SIZE {
                return Err(PersistentRegistryError::FileTooLarge {
                    size: file_size,
                    max: MAX_STATE_FILE_SIZE,
                });
            }

            // SEC-003: Use BufReader with Read::take for bounded reads (DoS protection)
            let reader = BufReader::new(file.take(MAX_STATE_FILE_SIZE));
            let state_file: PersistentStateFile = serde_json::from_reader(reader)?;

            // Version check for future compatibility
            if state_file.version != 1 {
                return Err(PersistentRegistryError::VersionMismatch {
                    found: state_file.version,
                    expected: 1,
                });
            }

            // Load sessions into in-memory registry
            // SEC-001: PersistableSessionState converts to SessionState with empty lease_id
            for persistable_session in state_file.sessions {
                let session = SessionState::from(persistable_session);
                // Ignore duplicate errors during recovery (shouldn't happen with valid file)
                let _ = registry.inner.register_session(session);
            }
        }

        Ok(registry)
    }

    /// Returns the path to the state file.
    #[must_use]
    pub fn state_file_path(&self) -> &Path {
        &self.state_file_path
    }

    /// Persists the current state to the state file atomically.
    ///
    /// Uses write-to-temp + rename pattern to prevent corruption.
    ///
    /// # Security
    ///
    /// - SEC-001: Sessions are converted to [`PersistableSessionState`] which
    ///   excludes the `lease_id` bearer token to prevent credential leakage.
    /// - SEC-002: File is created with mode 0600 (owner read/write only) to
    ///   prevent unauthorized access.
    fn persist(&self) -> Result<(), PersistentRegistryError> {
        let state = self.inner.state.read().expect("lock poisoned");

        // SEC-001: Convert to PersistableSessionState to exclude lease_id
        let state_file = PersistentStateFile {
            version: 1,
            sessions: state
                .by_id
                .values()
                .map(PersistableSessionState::from)
                .collect(),
        };

        // Serialize to JSON with pretty printing for human readability
        let json = serde_json::to_string_pretty(&state_file)?;

        // Write to temp file in same directory (for atomic rename)
        let temp_path = self.state_file_path.with_extension("tmp");

        // Ensure parent directory exists
        if let Some(parent) = self.state_file_path.parent() {
            #[cfg(unix)]
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700) // SEC-002: Owner access only
                .create(parent)?;

            #[cfg(not(unix))]
            fs::create_dir_all(parent)?;
        }

        // Write to temp file with SEC-002 secure permissions
        {
            #[cfg(unix)]
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600) // SEC-002: Owner read/write only
                .open(&temp_path)?;

            #[cfg(not(unix))]
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;

            let mut file = file;
            file.write_all(json.as_bytes())?;
            file.sync_all()?; // fsync to ensure durability
        }

        // Atomic rename
        fs::rename(&temp_path, &self.state_file_path)?;

        // Durability: fsync the parent directory to ensure the rename is committed
        if let Some(parent) = self.state_file_path.parent() {
            let dir = File::open(parent)?;
            dir.sync_all()?;
        }

        Ok(())
    }

    /// Returns the number of active sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        let state = self.inner.state.read().expect("lock poisoned");
        state.by_id.len()
    }

    /// Returns all active sessions.
    ///
    /// Useful for recovery flows that need to emit `LEASE_REVOKED` to all
    /// sessions.
    #[must_use]
    pub fn all_sessions(&self) -> Vec<SessionState> {
        let state = self.inner.state.read().expect("lock poisoned");
        state.by_id.values().cloned().collect()
    }
}

impl SessionRegistry for PersistentSessionRegistry {
    fn register_session(&self, session: SessionState) -> Result<(), SessionRegistryError> {
        // Register in memory first
        self.inner.register_session(session)?;

        // Persist to disk (convert error to RegistrationFailed)
        self.persist()
            .map_err(|e| SessionRegistryError::RegistrationFailed {
                message: format!("Failed to persist state: {e}"),
            })?;

        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Option<SessionState> {
        self.inner.get_session(session_id)
    }

    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState> {
        self.inner.get_session_by_handle(handle)
    }
}

#[cfg(test)]
mod session_registry_tests {
    use super::*;

    /// Helper to create a test session with a given ID and handle.
    fn make_session(id: &str, handle: &str) -> SessionState {
        SessionState {
            session_id: id.to_string(),
            work_id: format!("work-{id}"),
            role: 1,
            ephemeral_handle: handle.to_string(),
            lease_id: format!("lease-{id}"),
            policy_resolved_ref: "policy-ref".to_string(),
            capability_manifest_hash: vec![],
            episode_id: None,
        }
    }

    // =========================================================================
    // Basic Registration and Retrieval Tests
    // =========================================================================

    #[test]
    fn test_register_and_get_session() {
        let registry = InMemorySessionRegistry::new();
        let session = make_session("sess-1", "handle-1");

        registry.register_session(session).unwrap();

        let retrieved = registry.get_session("sess-1");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.session_id, "sess-1");
        assert_eq!(retrieved.ephemeral_handle, "handle-1");
        assert_eq!(retrieved.work_id, "work-sess-1");
    }

    #[test]
    fn test_get_nonexistent_session() {
        let registry = InMemorySessionRegistry::new();
        assert!(registry.get_session("nonexistent").is_none());
    }

    #[test]
    fn test_register_multiple_sessions() {
        let registry = InMemorySessionRegistry::new();

        registry
            .register_session(make_session("sess-1", "handle-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "handle-2"))
            .unwrap();
        registry
            .register_session(make_session("sess-3", "handle-3"))
            .unwrap();

        assert!(registry.get_session("sess-1").is_some());
        assert!(registry.get_session("sess-2").is_some());
        assert!(registry.get_session("sess-3").is_some());
    }

    // =========================================================================
    // Duplicate Session ID Handling Tests
    // =========================================================================

    #[test]
    fn test_duplicate_session_id_rejected() {
        let registry = InMemorySessionRegistry::new();

        registry
            .register_session(make_session("sess-1", "handle-1"))
            .unwrap();

        let result = registry.register_session(make_session("sess-1", "handle-2"));
        assert!(result.is_err());

        match result.unwrap_err() {
            SessionRegistryError::DuplicateSessionId { session_id } => {
                assert_eq!(session_id, "sess-1");
            },
            other @ SessionRegistryError::RegistrationFailed { .. } => {
                panic!("Expected DuplicateSessionId, got: {other:?}")
            },
        }
    }

    #[test]
    fn test_duplicate_session_preserves_original() {
        let registry = InMemorySessionRegistry::new();

        let original = make_session("sess-1", "handle-original");
        registry.register_session(original).unwrap();

        // Try to register duplicate
        let duplicate = make_session("sess-1", "handle-duplicate");
        let _ = registry.register_session(duplicate);

        // Original should be preserved
        let retrieved = registry.get_session("sess-1").unwrap();
        assert_eq!(retrieved.ephemeral_handle, "handle-original");
    }

    // =========================================================================
    // Lookup by Handle Tests
    // =========================================================================

    #[test]
    fn test_get_session_by_handle() {
        let registry = InMemorySessionRegistry::new();
        let session = make_session("sess-1", "handle-1");

        registry.register_session(session).unwrap();

        let retrieved = registry.get_session_by_handle("handle-1");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.session_id, "sess-1");
        assert_eq!(retrieved.ephemeral_handle, "handle-1");
    }

    #[test]
    fn test_get_session_by_nonexistent_handle() {
        let registry = InMemorySessionRegistry::new();
        registry
            .register_session(make_session("sess-1", "handle-1"))
            .unwrap();

        assert!(registry.get_session_by_handle("nonexistent").is_none());
    }

    #[test]
    fn test_handle_lookup_with_multiple_sessions() {
        let registry = InMemorySessionRegistry::new();

        registry
            .register_session(make_session("sess-1", "handle-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "handle-2"))
            .unwrap();
        registry
            .register_session(make_session("sess-3", "handle-3"))
            .unwrap();

        // Each handle should map to its session
        assert_eq!(
            registry
                .get_session_by_handle("handle-1")
                .unwrap()
                .session_id,
            "sess-1"
        );
        assert_eq!(
            registry
                .get_session_by_handle("handle-2")
                .unwrap()
                .session_id,
            "sess-2"
        );
        assert_eq!(
            registry
                .get_session_by_handle("handle-3")
                .unwrap()
                .session_id,
            "sess-3"
        );
    }

    // =========================================================================
    // LRU Eviction Tests
    // =========================================================================

    #[test]
    fn test_lru_eviction_at_capacity() {
        // Use a smaller capacity for testing
        let registry = InMemorySessionRegistry::new();

        // Fill to MAX_SESSIONS
        for i in 0..MAX_SESSIONS {
            let session = make_session(&format!("sess-{i}"), &format!("handle-{i}"));
            registry.register_session(session).unwrap();
        }

        // Verify first session exists
        assert!(registry.get_session("sess-0").is_some());

        // Register one more - should evict sess-0 (oldest)
        registry
            .register_session(make_session("sess-new", "handle-new"))
            .unwrap();

        // sess-0 should be evicted
        assert!(registry.get_session("sess-0").is_none());
        assert!(registry.get_session_by_handle("handle-0").is_none());

        // New session should exist
        assert!(registry.get_session("sess-new").is_some());
        assert!(registry.get_session_by_handle("handle-new").is_some());

        // sess-1 should still exist (it's now the oldest)
        assert!(registry.get_session("sess-1").is_some());
    }

    #[test]
    fn test_lru_eviction_order() {
        let registry = InMemorySessionRegistry::new();

        // Fill to capacity
        for i in 0..MAX_SESSIONS {
            let session = make_session(&format!("sess-{i}"), &format!("handle-{i}"));
            registry.register_session(session).unwrap();
        }

        // Register 3 more sessions
        for i in 0..3 {
            let session = make_session(&format!("new-{i}"), &format!("new-handle-{i}"));
            registry.register_session(session).unwrap();
        }

        // First 3 sessions should be evicted (FIFO order)
        assert!(registry.get_session("sess-0").is_none());
        assert!(registry.get_session("sess-1").is_none());
        assert!(registry.get_session("sess-2").is_none());

        // Session 3 should still exist
        assert!(registry.get_session("sess-3").is_some());

        // All new sessions should exist
        assert!(registry.get_session("new-0").is_some());
        assert!(registry.get_session("new-1").is_some());
        assert!(registry.get_session("new-2").is_some());
    }

    #[test]
    fn test_eviction_cleans_up_handle_index() {
        let registry = InMemorySessionRegistry::new();

        // Fill to capacity
        for i in 0..MAX_SESSIONS {
            let session = make_session(&format!("sess-{i}"), &format!("handle-{i}"));
            registry.register_session(session).unwrap();
        }

        // Evict first session
        registry
            .register_session(make_session("sess-new", "handle-new"))
            .unwrap();

        // Handle index for evicted session should be cleaned up
        assert!(registry.get_session_by_handle("handle-0").is_none());
    }

    // =========================================================================
    // Persistent Registry Security Tests (SEC-001, SEC-002, SEC-003)
    // =========================================================================

    #[test]
    fn test_sec001_state_file_excludes_lease_id() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let registry = PersistentSessionRegistry::new(path);

        // Register a session with a lease_id
        let mut session = make_session("sess-1", "handle-1");
        session.lease_id = "super-secret-lease-token".to_string();
        registry.register_session(session).unwrap();

        // Read the state file contents directly
        let contents = std::fs::read_to_string(path).unwrap();

        // SEC-001: The lease_id MUST NOT appear in the persisted file
        assert!(
            !contents.contains("super-secret-lease-token"),
            "State file contains lease_id: {contents}"
        );
        assert!(
            !contents.contains("lease_id"),
            "State file contains lease_id field: {contents}"
        );

        // Verify other session data IS present
        assert!(contents.contains("sess-1"));
        assert!(contents.contains("handle-1"));
        assert!(contents.contains("work-sess-1"));
    }

    #[test]
    fn test_sec001_loaded_sessions_have_empty_lease_id() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Register a session with a lease_id
        {
            let registry = PersistentSessionRegistry::new(path);
            let mut session = make_session("sess-1", "handle-1");
            session.lease_id = "original-lease-token".to_string();
            registry.register_session(session).unwrap();
        }

        // Load from file in a new registry
        let loaded_registry = PersistentSessionRegistry::load_from_file(path).unwrap();
        let loaded_session = loaded_registry.get_session("sess-1").unwrap();

        // SEC-001: Loaded sessions should have empty lease_id (must re-authenticate)
        assert!(
            loaded_session.lease_id.is_empty(),
            "Loaded session has non-empty lease_id: {}",
            loaded_session.lease_id
        );

        // Other fields should be preserved
        assert_eq!(loaded_session.session_id, "sess-1");
        assert_eq!(loaded_session.ephemeral_handle, "handle-1");
        assert_eq!(loaded_session.work_id, "work-sess-1");
    }

    #[cfg(unix)]
    #[test]
    fn test_sec002_state_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let registry = PersistentSessionRegistry::new(path);
        registry
            .register_session(make_session("sess-1", "handle-1"))
            .unwrap();

        // SEC-002: File permissions should be 0600 (owner read/write only)
        let metadata = std::fs::metadata(path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "State file has wrong permissions: {mode:o} (expected 600)"
        );
    }

    #[test]
    fn test_sec003_rejects_oversized_files() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();

        // Create a file larger than MAX_STATE_FILE_SIZE (10 MB)
        #[allow(clippy::cast_possible_truncation)]
        let oversized_size = (MAX_STATE_FILE_SIZE as usize) + 1;
        let oversized_content = vec![b'x'; oversized_size];
        temp_file.write_all(&oversized_content).unwrap();
        temp_file.flush().unwrap();

        let path = temp_file.path();

        // SEC-003: Should reject oversized files
        let result = PersistentSessionRegistry::load_from_file(path);
        assert!(result.is_err());

        match result.unwrap_err() {
            PersistentRegistryError::FileTooLarge { size, max } => {
                assert!(size > MAX_STATE_FILE_SIZE);
                assert_eq!(max, MAX_STATE_FILE_SIZE);
            },
            other => panic!("Expected FileTooLarge error, got: {other:?}"),
        }
    }

    #[test]
    fn test_persistent_registry_round_trip() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Register multiple sessions
        {
            let registry = PersistentSessionRegistry::new(path);
            registry
                .register_session(make_session("sess-1", "handle-1"))
                .unwrap();
            registry
                .register_session(make_session("sess-2", "handle-2"))
                .unwrap();
        }

        // Load from file in a new registry
        let loaded_registry = PersistentSessionRegistry::load_from_file(path).unwrap();

        // Verify all sessions are loaded
        assert!(loaded_registry.get_session("sess-1").is_some());
        assert!(loaded_registry.get_session("sess-2").is_some());
        assert!(loaded_registry.get_session_by_handle("handle-1").is_some());
        assert!(loaded_registry.get_session_by_handle("handle-2").is_some());
    }

    #[test]
    fn test_persistent_registry_nonexistent_file() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("nonexistent.json");

        // Should succeed with empty registry when file doesn't exist
        let registry = PersistentSessionRegistry::load_from_file(&path).unwrap();
        assert_eq!(registry.session_count(), 0);
    }
}

// =============================================================================
// TCK-00267: `LEASE_REVOKED` Signal and Crash Recovery Tests
// =============================================================================

#[cfg(test)]
mod tck_00267 {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    /// Helper to create a test session with given parameters.
    fn make_session(id: &str, handle: &str, lease_id: &str) -> SessionState {
        SessionState {
            session_id: id.to_string(),
            work_id: format!("work-{id}"),
            role: 1,
            ephemeral_handle: handle.to_string(),
            lease_id: lease_id.to_string(),
            policy_resolved_ref: "policy-ref".to_string(),
            capability_manifest_hash: vec![],
            episode_id: None,
        }
    }

    // =========================================================================
    // AC1: Sessions receive `LEASE_REVOKED` within 5s
    // =========================================================================

    /// TCK-00267 AC1: ``LEASE_REVOKED`` signal is sent to recovered sessions.
    #[test]
    fn lease_revoked_signal_sent_to_recovered_sessions() {
        let registry = InMemorySessionRegistry::new();

        // Register test sessions
        registry
            .register_session(make_session("sess-1", "handle-1", "lease-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "handle-2", "lease-2"))
            .unwrap();
        registry
            .register_session(make_session("sess-3", "handle-3", "lease-3"))
            .unwrap();

        // Create recovery manager with default 5s timeout
        let recovery_manager = RecoveryManager::new();

        // Track signals sent
        let signals_sent = Arc::new(AtomicU32::new(0));
        let signals_clone = Arc::clone(&signals_sent);

        // Perform recovery
        let result = recovery_manager
            .recover_sessions(&registry, |signal| {
                // Verify signal structure
                assert!(!signal.session_id.is_empty());
                assert!(!signal.lease_id.is_empty());
                assert_eq!(
                    signal.reason,
                    LeaseRevokedReason::LeaseRevokedDaemonRestart as i32
                );
                assert!(signal.revoked_at_ns > 0);

                signals_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("recovery should succeed");

        // Verify all sessions received `LEASE_REVOKED`
        assert_eq!(result.sessions_recovered, 3);
        assert_eq!(result.lease_revoked_signals_sent, 3);
        assert_eq!(signals_sent.load(Ordering::SeqCst), 3);
    }

    /// TCK-00267 AC1: Recovery completes within 5 seconds.
    #[test]
    fn recovery_completes_within_5_seconds() {
        let registry = InMemorySessionRegistry::new();

        // Register multiple sessions
        for i in 0..100 {
            registry
                .register_session(make_session(
                    &format!("sess-{i}"),
                    &format!("handle-{i}"),
                    &format!("lease-{i}"),
                ))
                .unwrap();
        }

        let recovery_manager = RecoveryManager::new();
        let start = Instant::now();

        // Perform recovery
        let result = recovery_manager
            .recover_sessions(&registry, |_signal| {
                // Simulate minimal processing time
                std::thread::sleep(Duration::from_micros(100));
                Ok(())
            })
            .expect("recovery should succeed");

        let elapsed = start.elapsed();

        // Verify timing requirement: must complete within 5 seconds
        assert!(
            elapsed < Duration::from_secs(5),
            "Recovery took {elapsed:?}, exceeds 5 second limit",
        );

        // Also verify the reported time is accurate
        assert!(
            result.recovery_time_ms < 5000,
            "Reported recovery time {} ms exceeds 5000 ms",
            result.recovery_time_ms
        );
    }

    /// TCK-00267 AC1: Recovery times out if processing takes too long.
    #[test]
    fn recovery_timeout_when_signal_processing_slow() {
        let registry = InMemorySessionRegistry::new();

        // Register a few sessions
        for i in 0..3 {
            registry
                .register_session(make_session(
                    &format!("sess-{i}"),
                    &format!("handle-{i}"),
                    &format!("lease-{i}"),
                ))
                .unwrap();
        }

        // Create manager with very short timeout for testing
        let recovery_manager = RecoveryManager::with_timeout(50); // 50ms timeout

        // Perform recovery with slow signal sender
        let result = recovery_manager.recover_sessions(&registry, |_signal| {
            // Simulate slow processing that will exceed timeout
            std::thread::sleep(Duration::from_millis(30));
            Ok(())
        });

        // Should timeout
        assert!(result.is_err());
        match result.unwrap_err() {
            RecoveryError::Timeout { .. } => {
                // Expected
            },
            other => panic!("Expected Timeout error, got: {other:?}"),
        }
    }

    /// TCK-00267: ``LEASE_REVOKED`` message has correct reason for daemon
    /// restart.
    #[test]
    fn lease_revoked_has_daemon_restart_reason() {
        let session = make_session("sess-1", "handle-1", "lease-1");

        let signal = RecoveryManager::create_lease_revoked(
            &session,
            LeaseRevokedReason::LeaseRevokedDaemonRestart,
            Some("Daemon restarted".to_string()),
        );

        assert_eq!(signal.session_id, "sess-1");
        assert_eq!(signal.lease_id, "lease-1");
        assert_eq!(
            signal.reason,
            LeaseRevokedReason::LeaseRevokedDaemonRestart as i32
        );
        assert!(signal.revoked_at_ns > 0);
        assert_eq!(signal.message, Some("Daemon restarted".to_string()));
    }

    /// TCK-00267: `RecoveryResult` converts to `RecoverSessionsResponse`
    /// correctly.
    #[test]
    fn recovery_result_to_proto_response() {
        let result = RecoveryResult {
            sessions_recovered: 5,
            orphaned_processes_cleaned: 2,
            lease_revoked_signals_sent: 5,
            recovery_time_ms: 150,
        };

        let response: RecoverSessionsResponse = result.into();

        assert_eq!(response.sessions_recovered, 5);
        assert_eq!(response.orphaned_processes_cleaned, 2);
        assert_eq!(response.lease_revoked_signals_sent, 5);
        assert_eq!(response.recovery_time_ms, 150);
    }

    // =========================================================================
    // AC2: No orphaned processes after recovery
    // =========================================================================

    /// TCK-00267 AC2: Registry is cleared after successful recovery.
    #[test]
    fn registry_cleared_after_recovery() {
        let registry = InMemorySessionRegistry::new();

        // Register sessions
        registry
            .register_session(make_session("sess-1", "handle-1", "lease-1"))
            .unwrap();
        registry
            .register_session(make_session("sess-2", "handle-2", "lease-2"))
            .unwrap();

        assert_eq!(registry.len(), 2);

        let recovery_manager = RecoveryManager::new();

        // Perform recovery
        recovery_manager
            .recover_sessions(&registry, |_| Ok(()))
            .expect("recovery should succeed");

        // Registry should be cleared after recovery
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    /// TCK-00267 AC2: Recovery reports orphaned process cleanup count.
    #[test]
    fn recovery_reports_orphaned_process_count() {
        let registry = InMemorySessionRegistry::new();
        let recovery_manager = RecoveryManager::new();

        let result = recovery_manager
            .recover_sessions(&registry, |_| Ok(()))
            .expect("recovery should succeed");

        // Currently no PID tracking, so orphaned count is 0
        // When PID tracking is implemented, this test should be updated
        assert_eq!(result.orphaned_processes_cleaned, 0);
    }

    /// TCK-00267: Recovery handles empty registry gracefully.
    #[test]
    fn recovery_handles_empty_registry() {
        let registry = InMemorySessionRegistry::new();
        let recovery_manager = RecoveryManager::new();

        let result = recovery_manager
            .recover_sessions(&registry, |_| {
                panic!("Should not be called for empty registry")
            })
            .expect("recovery should succeed");

        assert_eq!(result.sessions_recovered, 0);
        assert_eq!(result.lease_revoked_signals_sent, 0);
        assert_eq!(result.orphaned_processes_cleaned, 0);
        assert!(result.recovery_time_ms < 100); // Should be very fast
    }

    /// TCK-00267: Recovery handles signal send failure.
    #[test]
    fn recovery_handles_signal_send_failure() {
        let registry = InMemorySessionRegistry::new();

        registry
            .register_session(make_session("sess-1", "handle-1", "lease-1"))
            .unwrap();

        let recovery_manager = RecoveryManager::new();

        let result = recovery_manager.recover_sessions(&registry, |_| {
            Err(RecoveryError::SignalFailed {
                message: "Connection refused".to_string(),
            })
        });

        // Should propagate the error
        assert!(result.is_err());
        match result.unwrap_err() {
            RecoveryError::SignalFailed { message } => {
                assert!(message.contains("Connection refused"));
            },
            other => panic!("Expected SignalFailed error, got: {other:?}"),
        }
    }

    /// TCK-00267: Default recovery timeout is 5 seconds.
    #[test]
    fn default_recovery_timeout_is_5_seconds() {
        assert_eq!(DEFAULT_RECOVERY_TIMEOUT_MS, 5000);

        let recovery_manager = RecoveryManager::new();
        assert_eq!(recovery_manager.timeout(), Duration::from_millis(5000));
    }

    /// TCK-00267: Custom recovery timeout is respected.
    #[test]
    fn custom_recovery_timeout_is_respected() {
        let recovery_manager = RecoveryManager::with_timeout(1000);
        assert_eq!(recovery_manager.timeout(), Duration::from_millis(1000));

        let recovery_manager_short = RecoveryManager::with_timeout(100);
        assert_eq!(recovery_manager_short.timeout(), Duration::from_millis(100));
    }

    /// TCK-00267: ``LEASE_REVOKED`` reasons cover all revocation scenarios.
    #[test]
    fn lease_revoked_reason_variants() {
        // Verify all reason variants are defined
        let reasons = [
            LeaseRevokedReason::Unspecified,
            LeaseRevokedReason::LeaseRevokedDaemonRestart,
            LeaseRevokedReason::LeaseRevokedExpired,
            LeaseRevokedReason::LeaseRevokedByOperator,
            LeaseRevokedReason::LeaseRevokedPolicyViolation,
        ];

        // Verify each has distinct i32 value
        let values: Vec<i32> = reasons.iter().map(|r| *r as i32).collect();
        assert_eq!(values, vec![0, 1, 2, 3, 4]);
    }
}
