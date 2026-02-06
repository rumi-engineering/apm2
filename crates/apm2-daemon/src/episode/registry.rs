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
            profile: Some(profile),
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

use crate::session::{SessionRegistry, SessionRegistryError, SessionState, SessionTerminationInfo};

/// Maximum number of sessions tracked in the session registry.
///
/// Per CTR-1303: In-memory stores must have `max_entries` limit to prevent
/// denial-of-service via memory exhaustion.
pub const MAX_SESSIONS: usize = 10_000;

/// Maximum number of terminated session entries retained (TCK-00385).
///
/// Per CTR-1303: The terminated-session store must also be bounded to
/// prevent unbounded memory growth under high session churn. When this
/// limit is reached, the oldest entries (by `terminated_at` timestamp)
/// are evicted to make room.
pub const MAX_TERMINATED_SESSIONS: usize = 10_000;

/// TTL for terminated session entries in seconds (TCK-00385).
///
/// Terminated sessions are preserved in the registry for this duration
/// so that `SessionStatus` queries return useful termination details
/// instead of "session not found". After this TTL, entries are cleaned up
/// to prevent unbounded memory growth.
pub const TERMINATED_SESSION_TTL_SECS: u64 = 300; // 5 minutes

/// Known termination reasons for session end-of-life (TCK-00385, MAJOR 1).
///
/// This enum provides a strict allowlist of termination reasons that may
/// appear in the `termination_reason` field of `SessionStatusResponse`.
/// Unknown or free-form strings from internal code are normalized to
/// [`TerminationReason::Unknown`] before being sent on the wire.
///
/// # Wire Representation
///
/// Each variant maps to a lowercase string constant suitable for the
/// protobuf `termination_reason` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminationReason {
    /// Normal clean exit.
    Normal,
    /// Session process crashed.
    Crash,
    /// Session exceeded its time budget.
    Timeout,
    /// Session quarantined by policy engine.
    Quarantined,
    /// Session exceeded its token budget.
    BudgetExhausted,
    /// Context miss triggered refinement termination.
    ContextMiss,
    /// Unknown or unrecognized reason (normalized from free-form input).
    Unknown,
}

impl TerminationReason {
    /// Returns the canonical wire-format string for this reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Crash => "crash",
            Self::Timeout => "timeout",
            Self::Quarantined => "quarantined",
            Self::BudgetExhausted => "budget_exhausted",
            Self::ContextMiss => "CONTEXT_MISS",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a string into a known `TerminationReason`.
    ///
    /// Unrecognized strings are mapped to [`TerminationReason::Unknown`]
    /// rather than being passed through as free-form text.
    #[must_use]
    pub fn from_reason_str(s: &str) -> Self {
        match s {
            "normal" => Self::Normal,
            "crash" => Self::Crash,
            "timeout" => Self::Timeout,
            "quarantined" => Self::Quarantined,
            "budget_exhausted" => Self::BudgetExhausted,
            "CONTEXT_MISS" => Self::ContextMiss,
            _ => Self::Unknown,
        }
    }

    /// All known termination reason variants (excluding `Unknown`).
    pub const ALL_KNOWN: &'static [Self] = &[
        Self::Normal,
        Self::Crash,
        Self::Timeout,
        Self::Quarantined,
        Self::BudgetExhausted,
        Self::ContextMiss,
    ];
}

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A terminated session entry preserved for TTL-based cleanup (TCK-00385).
#[derive(Debug, Clone)]
struct TerminatedEntry {
    /// The termination details.
    info: SessionTerminationInfo,
    /// The session state at time of termination (for status queries).
    session: SessionState,
    /// Monotonic expiry instant (for TTL cleanup).
    expires_at: Instant,
}

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
    /// Terminated session entries preserved for TTL-based queries (TCK-00385).
    ///
    /// Keyed by session ID. Entries are cleaned up when their TTL expires.
    terminated: HashMap<String, TerminatedEntry>,
}

/// In-memory session registry for tracking active sessions.
///
/// # Capacity Limits (CTR-1303)
///
/// This registry enforces a maximum of [`MAX_SESSIONS`] entries to prevent
/// memory exhaustion. When the limit is reached, the oldest entry (by insertion
/// order) is evicted to make room for the new session.
///
/// # TCK-00385: Termination Tracking
///
/// When a session terminates, its entry is moved to a separate
/// terminated-entries map with a TTL of [`TERMINATED_SESSION_TTL_SECS`].
/// Subsequent `SessionStatus` queries for that session return TERMINATED state
/// with exit details. Expired entries are lazily cleaned up on each write
/// operation.
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

        // TCK-00385 MINOR 1: Centralize TTL cleanup on all write paths.
        // Lazily clean up expired terminated entries during registration
        // (not only during mark_terminated) to prevent stale entries from
        // accumulating when no sessions are being terminated.
        let now = Instant::now();
        state.terminated.retain(|_, entry| entry.expires_at > now);

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

    fn get_session_by_work_id(&self, work_id: &str) -> Option<SessionState> {
        let state = self.state.read().expect("lock poisoned");
        state.by_id.values().find(|s| s.work_id == work_id).cloned()
    }

    fn mark_terminated(
        &self,
        session_id: &str,
        info: SessionTerminationInfo,
    ) -> Result<bool, SessionRegistryError> {
        let mut state = self.state.write().expect("lock poisoned");

        // Lazily clean up expired terminated entries on write
        let now = Instant::now();
        state.terminated.retain(|_, entry| entry.expires_at > now);

        // Move the session from active to terminated
        if let Some(session) = state.by_id.remove(session_id) {
            state.by_handle.remove(&session.ephemeral_handle);
            state.queue.retain(|id| id != session_id);

            // CTR-1303 / BLOCKER 1: Enforce MAX_TERMINATED_SESSIONS cap.
            // If at capacity, evict the oldest entry (earliest expires_at).
            while state.terminated.len() >= MAX_TERMINATED_SESSIONS {
                let oldest_key = state
                    .terminated
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    state.terminated.remove(&key);
                } else {
                    break;
                }
            }

            let entry = TerminatedEntry {
                info,
                session,
                expires_at: now + Duration::from_secs(TERMINATED_SESSION_TTL_SECS),
            };
            state.terminated.insert(session_id.to_string(), entry);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_termination_info(&self, session_id: &str) -> Option<SessionTerminationInfo> {
        let state = self.state.read().expect("lock poisoned");
        let entry = state.terminated.get(session_id)?;

        // Check TTL -- return None if expired (lazy cleanup happens on writes)
        if Instant::now() > entry.expires_at {
            return None;
        }

        Some(entry.info.clone())
    }

    fn get_terminated_session(
        &self,
        session_id: &str,
    ) -> Option<(SessionState, SessionTerminationInfo)> {
        let state = self.state.read().expect("lock poisoned");
        let entry = state.terminated.get(session_id)?;

        if Instant::now() > entry.expires_at {
            return None;
        }

        Some((entry.session.clone(), entry.info.clone()))
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

    /// Clears all active and terminated sessions.
    ///
    /// Used during crash recovery after sending all `LEASE_REVOKED` signals.
    /// Also clears terminated entries so that `clear_and_persist` (which
    /// writes an empty `terminated: []` to disk) is consistent with the
    /// in-memory state. Without this, a full clear would write empty
    /// terminated entries to disk but leave stale entries in memory.
    pub fn clear(&self) {
        let mut state = self.state.write().expect("lock poisoned");
        state.by_id.clear();
        state.by_handle.clear();
        state.queue.clear();
        state.terminated.clear();
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

    /// Returns the number of terminated sessions still in the TTL window
    /// (TCK-00385).
    pub fn terminated_count(&self) -> usize {
        let state = self.state.read().expect("lock poisoned");
        let now = Instant::now();
        state
            .terminated
            .values()
            .filter(|e| e.expires_at > now)
            .count()
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

/// Returns the current wall-clock time as seconds since Unix epoch.
///
/// Used by the persistent registry to serialize absolute expiry timestamps
/// (SEC-MAJOR-1).
fn wall_clock_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
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

/// Serializable representation of a terminated session entry (TCK-00385 BLOCKER
/// 2).
///
/// This struct pairs a terminated session's state with its termination info
/// and absolute wall-clock timestamps so that terminated entries survive daemon
/// restarts without downtime extending the effective TTL.
///
/// # SEC-MAJOR-1: Absolute Expiry
///
/// We persist the absolute wall-clock expiry timestamp
/// (`expires_at_epoch_secs`) and the issuance timestamp
/// (`issued_at_epoch_secs`) rather than a relative remaining-seconds value. On
/// reload the expiry is enforced strictly against the current wall clock, so
/// any downtime between persist and reload is correctly accounted for and
/// expired entries are compacted on startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistableTerminatedEntry {
    /// The session state at time of termination.
    session: PersistableSessionState,
    /// Termination details.
    info: SessionTerminationInfo,
    /// Wall-clock epoch seconds when this entry was created (for auditing).
    ///
    /// Defaults to 0 for backward compatibility with pre-migration state files.
    #[serde(default)]
    issued_at_epoch_secs: u64,
    /// Wall-clock epoch seconds when this entry expires.
    ///
    /// On reload, entries whose `expires_at_epoch_secs` is in the past are
    /// discarded. Defaults to 0 so that legacy state files fall back to the
    /// `ttl_remaining_secs` field.
    #[serde(default)]
    expires_at_epoch_secs: u64,
    /// Legacy field: remaining TTL in seconds at the time of serialization.
    ///
    /// Kept for backward compatibility with state files written before the
    /// absolute-expiry migration. Ignored when `expires_at_epoch_secs` is
    /// present and non-zero.
    #[serde(default)]
    ttl_remaining_secs: u64,
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
/// SEC-MAJOR-2: `deny_unknown_fields` re-applied so that malformed or
/// tampered state files are rejected on load rather than silently dropping
/// unrecognized keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentStateFile {
    /// Version of the state file format for future compatibility.
    version: u32,
    /// Active sessions persisted to disk (without credentials).
    sessions: Vec<PersistableSessionState>,
    /// Terminated sessions preserved for TTL-based queries (TCK-00385 BLOCKER
    /// 2).
    ///
    /// Defaults to empty for backward compatibility with v1 state files that
    /// lack this field.
    #[serde(default)]
    terminated: Vec<PersistableTerminatedEntry>,
}

impl Default for PersistentStateFile {
    fn default() -> Self {
        Self {
            version: 1,
            sessions: Vec::new(),
            terminated: Vec::new(),
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

    /// State file contains duplicate session IDs, indicating data corruption.
    ///
    /// Per Security Review v5 MAJOR 1, duplicate session IDs must be treated
    /// as corruption rather than silently keeping the first entry. Duplicate
    /// IDs in the state file indicate either file corruption or a bug in
    /// the persist logic that must not be masked.
    #[error("Corrupted state file: duplicate session ID {session_id:?}")]
    CorruptedDuplicateSessionId {
        /// The duplicated session ID.
        session_id: String,
    },

    /// State file contains more active sessions than the `MAX_SESSIONS` cap.
    ///
    /// Per Security Review BLOCKER 1 (PR #434): the recovery load path must
    /// fail-closed rather than silently evicting excess sessions. Eviction
    /// during load would drop sessions without running recovery side-effects
    /// (lease revocation, work claim cleanup), causing those sessions to
    /// permanently disappear from the recovery pipeline. Startup must abort
    /// so the operator can investigate the over-cap state file.
    #[error(
        "State file session count {count} exceeds MAX_SESSIONS ({max}); \
         startup aborted (fail-closed, no silent eviction)"
    )]
    TooManySessions {
        /// Number of sessions in the state file.
        count: usize,
        /// The maximum allowed session count.
        max: usize,
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

            // Security Review BLOCKER 1 (PR #434): Fail-closed if the state
            // file contains more sessions than MAX_SESSIONS. The recovery load
            // path must NOT silently evict excess sessions, because eviction
            // would drop sessions without running recovery side-effects (lease
            // revocation, work claim cleanup). Those evicted sessions would
            // permanently disappear from the recovery pipeline.
            if state_file.sessions.len() > MAX_SESSIONS {
                return Err(PersistentRegistryError::TooManySessions {
                    count: state_file.sessions.len(),
                    max: MAX_SESSIONS,
                });
            }

            // SEC-MAJOR-2: Collect active session IDs for collision detection.
            let mut active_ids: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            // Load sessions into in-memory registry
            // SEC-001: PersistableSessionState converts to SessionState with empty lease_id
            //
            // Security Review v5 MAJOR 1: Detect duplicate session IDs as
            // corruption rather than silently keeping the first entry. Use a
            // HashSet to track IDs seen so far and fail on duplicates.
            let mut seen_ids = std::collections::HashSet::with_capacity(state_file.sessions.len());
            for persistable_session in state_file.sessions {
                active_ids.insert(persistable_session.session_id.clone());
                let session = SessionState::from(persistable_session);
                if !seen_ids.insert(session.session_id.clone()) {
                    return Err(PersistentRegistryError::CorruptedDuplicateSessionId {
                        session_id: session.session_id,
                    });
                }
                registry
                    .inner
                    .register_session(session)
                    .map_err(PersistentRegistryError::from)?;
            }

            // TCK-00385 BLOCKER 2: Reload terminated entries.
            // SEC-MAJOR-1: Use absolute wall-clock expiry timestamps.
            // Entries whose absolute expiry is in the past are compacted on
            // startup rather than being loaded.  For backward compatibility
            // with state files that lack `expires_at_epoch_secs`, we fall
            // back to the legacy `ttl_remaining_secs` field (clamped).
            if !state_file.terminated.is_empty() {
                let now_mono = Instant::now();
                let now_wall = wall_clock_secs();
                let mut inner_state = registry.inner.state.write().expect("lock poisoned");
                for persisted_entry in state_file.terminated {
                    let session_id = persisted_entry.session.session_id.clone();

                    // SEC-MAJOR-2: Reject entries that collide with active
                    // sessions. A session cannot be both active and terminated.
                    if active_ids.contains(&session_id) {
                        continue;
                    }

                    // Determine remaining TTL from absolute expiry or legacy field.
                    let remaining_secs = if persisted_entry.expires_at_epoch_secs > 0 {
                        // Absolute expiry: compute remaining against wall clock.
                        persisted_entry
                            .expires_at_epoch_secs
                            .saturating_sub(now_wall)
                    } else {
                        // Legacy fallback: use relative TTL, clamped.
                        persisted_entry
                            .ttl_remaining_secs
                            .min(TERMINATED_SESSION_TTL_SECS)
                    };

                    if remaining_secs == 0 {
                        continue; // Expired, compact on startup
                    }

                    // Clamp to maximum TTL to prevent stale entries from lingering
                    let clamped = remaining_secs.min(TERMINATED_SESSION_TTL_SECS);

                    let entry = TerminatedEntry {
                        info: persisted_entry.info,
                        session: SessionState::from(persisted_entry.session),
                        expires_at: now_mono + Duration::from_secs(clamped),
                    };
                    inner_state.terminated.insert(session_id, entry);
                }

                // MAJOR 1 fix: Enforce MAX_TERMINATED_SESSIONS cap after
                // loading all entries. Use the same eviction policy as
                // runtime insertion: evict the oldest entries (earliest
                // expires_at) until we are within the cap. This prevents
                // churned/tampered state files from exceeding the bound.
                while inner_state.terminated.len() > MAX_TERMINATED_SESSIONS {
                    let oldest_key = inner_state
                        .terminated
                        .iter()
                        .min_by_key(|(_, e)| e.expires_at)
                        .map(|(k, _)| k.clone());
                    if let Some(key) = oldest_key {
                        inner_state.terminated.remove(&key);
                    } else {
                        break;
                    }
                }
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
        // TCK-00385 BLOCKER 2: Also serialize terminated entries
        // SEC-MAJOR-1: Use absolute wall-clock expiry timestamps so downtime
        // does not silently extend terminated-entry lifetimes.
        let now_mono = Instant::now();
        let now_wall = wall_clock_secs();
        let terminated: Vec<PersistableTerminatedEntry> = state
            .terminated
            .iter()
            .filter(|(_, entry)| entry.expires_at > now_mono)
            .map(|(_, entry)| {
                // Convert monotonic remaining duration into an absolute
                // wall-clock expiry.
                let remaining = entry.expires_at.duration_since(now_mono).as_secs();
                let expires_at_epoch = now_wall.saturating_add(remaining);
                // issued_at = expires_at - TTL (approximate; the original
                // issuance timestamp is not stored in TerminatedEntry, but
                // we can derive it from the TTL constant).
                let issued_at_epoch = expires_at_epoch.saturating_sub(TERMINATED_SESSION_TTL_SECS);
                PersistableTerminatedEntry {
                    session: PersistableSessionState::from(&entry.session),
                    info: entry.info.clone(),
                    issued_at_epoch_secs: issued_at_epoch,
                    expires_at_epoch_secs: expires_at_epoch,
                    ttl_remaining_secs: remaining,
                }
            })
            .collect();

        let state_file = PersistentStateFile {
            version: 1,
            sessions: state
                .by_id
                .values()
                .map(PersistableSessionState::from)
                .collect(),
            terminated,
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

    /// Clears all sessions from the in-memory registry and persists the empty
    /// state to disk (TCK-00387).
    ///
    /// This makes crash recovery idempotent: after clearing, a second startup
    /// will load an empty state file and find no sessions to recover.
    ///
    /// # Fail-Closed Ordering (Security Review v4 BLOCKER 1)
    ///
    /// Persists the empty state to disk BEFORE clearing in-memory state.
    /// If persist fails, in-memory state is left intact so that a subsequent
    /// startup reload from the (unchanged) state file will re-discover the
    /// sessions for retry. This prevents the hazard where in-memory state is
    /// cleared but the disk still holds old sessions, causing repeated
    /// recovery side-effects on restart.
    ///
    /// # Errors
    ///
    /// Returns `PersistentRegistryError` if persisting the cleared state fails.
    /// In-memory state is NOT cleared on persist failure (fail-closed).
    pub fn clear_and_persist(&self) -> Result<(), PersistentRegistryError> {
        // Persist the empty state file FIRST (fail-closed ordering).
        // We temporarily build the empty state file content while still
        // holding the old in-memory state, then write it. Only after a
        // successful persist do we clear in-memory state.
        self.persist_empty_state()?;
        self.inner.clear();
        Ok(())
    }

    /// Persists an empty state file to disk without modifying in-memory state.
    ///
    /// Used by [`clear_and_persist`] to ensure fail-closed ordering: the disk
    /// state is updated before the in-memory state is cleared.
    fn persist_empty_state(&self) -> Result<(), PersistentRegistryError> {
        let state_file = PersistentStateFile {
            version: 1,
            sessions: Vec::new(),
            terminated: Vec::new(),
        };

        let json = serde_json::to_string_pretty(&state_file)?;

        // Write to temp file in same directory (for atomic rename)
        let temp_path = self.state_file_path.with_extension("tmp");

        // Ensure parent directory exists
        if let Some(parent) = self.state_file_path.parent() {
            #[cfg(unix)]
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;

            #[cfg(not(unix))]
            fs::create_dir_all(parent)?;
        }

        // Write to temp file with secure permissions
        {
            #[cfg(unix)]
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;

            #[cfg(not(unix))]
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;

            let mut file = file;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        // Atomic rename
        fs::rename(&temp_path, &self.state_file_path)?;

        // Durability: fsync the parent directory
        if let Some(parent) = self.state_file_path.parent() {
            let dir = File::open(parent)?;
            dir.sync_all()?;
        }

        Ok(())
    }

    /// Persists the current state minus the given session IDs to disk,
    /// without modifying in-memory state.
    ///
    /// Used by [`clear_sessions_by_ids`] to ensure fail-closed ordering: the
    /// disk state is updated before the in-memory state is modified.
    fn persist_without_sessions(
        &self,
        session_ids_to_remove: &[String],
    ) -> Result<(), PersistentRegistryError> {
        let state = self.inner.state.read().expect("lock poisoned");

        // Build state file excluding the sessions to be removed
        let ids_to_remove: std::collections::HashSet<&str> =
            session_ids_to_remove.iter().map(String::as_str).collect();

        // Preserve terminated entries (same logic as persist())
        let now_mono = Instant::now();
        let now_wall = wall_clock_secs();
        let terminated: Vec<PersistableTerminatedEntry> = state
            .terminated
            .iter()
            .filter(|(_, entry)| entry.expires_at > now_mono)
            .map(|(_, entry)| {
                let remaining = entry.expires_at.duration_since(now_mono).as_secs();
                let expires_at_epoch = now_wall.saturating_add(remaining);
                let issued_at_epoch = expires_at_epoch.saturating_sub(TERMINATED_SESSION_TTL_SECS);
                PersistableTerminatedEntry {
                    session: PersistableSessionState::from(&entry.session),
                    info: entry.info.clone(),
                    issued_at_epoch_secs: issued_at_epoch,
                    expires_at_epoch_secs: expires_at_epoch,
                    ttl_remaining_secs: remaining,
                }
            })
            .collect();

        let state_file = PersistentStateFile {
            version: 1,
            sessions: state
                .by_id
                .iter()
                .filter(|(id, _)| !ids_to_remove.contains(id.as_str()))
                .map(|(_, v)| PersistableSessionState::from(v))
                .collect(),
            terminated,
        };
        drop(state);

        let json = serde_json::to_string_pretty(&state_file)?;

        // Write to temp file in same directory (for atomic rename)
        let temp_path = self.state_file_path.with_extension("tmp");

        // Ensure parent directory exists
        if let Some(parent) = self.state_file_path.parent() {
            #[cfg(unix)]
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;

            #[cfg(not(unix))]
            fs::create_dir_all(parent)?;
        }

        // Write to temp file with secure permissions
        {
            #[cfg(unix)]
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;

            #[cfg(not(unix))]
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)?;

            let mut file = file;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }

        // Atomic rename
        fs::rename(&temp_path, &self.state_file_path)?;

        // Durability: fsync the parent directory
        if let Some(parent) = self.state_file_path.parent() {
            let dir = File::open(parent)?;
            dir.sync_all()?;
        }

        Ok(())
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

    fn get_session_by_work_id(&self, work_id: &str) -> Option<SessionState> {
        self.inner.get_session_by_work_id(work_id)
    }

    fn mark_terminated(
        &self,
        session_id: &str,
        info: SessionTerminationInfo,
    ) -> Result<bool, SessionRegistryError> {
        // SEC-BLOCKER: Idempotent termination under partial failure.
        //
        // We move the session from active to terminated in memory, then
        // attempt to persist. If persistence fails we rollback the in-memory
        // state (move the session back to active) so that on restart we do
        // not have a stale ACTIVE entry on disk while in-memory state says
        // TERMINATED.  The caller can retry the same session_id and the
        // operation remains idempotent.
        let found = self.inner.mark_terminated(session_id, info)?;

        if found {
            if let Err(persist_err) = self.persist() {
                // Rollback: put the session back in the active set.
                // We retrieve it from the terminated map and re-register.
                let mut state = self.inner.state.write().expect("lock poisoned");
                if let Some(entry) = state.terminated.remove(session_id) {
                    let session = entry.session;
                    let sid = session.session_id.clone();
                    let handle = session.ephemeral_handle.clone();
                    state.queue.push_back(sid.clone());
                    state.by_handle.insert(handle, sid.clone());
                    state.by_id.insert(sid, session);
                }
                drop(state);

                return Err(SessionRegistryError::RegistrationFailed {
                    message: format!("Failed to persist termination state: {persist_err}"),
                });
            }
        }

        Ok(found)
    }

    fn get_termination_info(&self, session_id: &str) -> Option<SessionTerminationInfo> {
        self.inner.get_termination_info(session_id)
    }

    fn get_terminated_session(
        &self,
        session_id: &str,
    ) -> Option<(SessionState, SessionTerminationInfo)> {
        SessionRegistry::get_terminated_session(&self.inner, session_id)
    }

    /// Returns all sessions for crash recovery (TCK-00387).
    ///
    /// Unlike the default (empty) implementation, the persistent registry
    /// returns sessions that were loaded from the state file.
    fn all_sessions_for_recovery(&self) -> Vec<SessionState> {
        self.all_sessions()
    }

    /// Clears all sessions and persists the empty state (TCK-00387).
    ///
    /// This makes crash recovery idempotent: after clearing, a second
    /// startup will see no sessions to recover.
    fn clear_all_sessions(&self) -> Result<(), SessionRegistryError> {
        self.clear_and_persist()
            .map_err(|e| SessionRegistryError::RegistrationFailed {
                message: format!("Failed to clear and persist: {e}"),
            })
    }

    /// Removes specific sessions by ID and persists the updated state.
    ///
    /// Used after partial/truncated recovery so only the recovered subset is
    /// removed, preserving any sessions that were not yet processed.
    ///
    /// # Fail-Closed Ordering (Security Review v4 BLOCKER 1)
    ///
    /// Computes the post-removal state and persists it to disk BEFORE
    /// removing sessions from in-memory state. If persist fails, in-memory
    /// state is left intact so that the on-disk state file (unchanged) will
    /// re-discover the sessions for retry on next startup.
    fn clear_sessions_by_ids(&self, session_ids: &[String]) -> Result<(), SessionRegistryError> {
        // Persist the projected state (with sessions removed) FIRST.
        // We read the current in-memory state, compute what it would look
        // like after removal, persist that, then actually remove in-memory.
        self.persist_without_sessions(session_ids).map_err(|e| {
            SessionRegistryError::RegistrationFailed {
                message: format!("Failed to persist after partial clear: {e}"),
            }
        })?;

        // Persist succeeded -- now safe to clear in-memory state.
        for id in session_ids {
            self.inner.remove_session(id);
        }
        Ok(())
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

    // =========================================================================
    // Corruption Tests: Duplicate Session IDs (Security Review v5 MAJOR 1)
    // =========================================================================

    /// Security Review v5 MAJOR 1: Duplicate session IDs in a state file must
    /// be treated as corruption and fail the load, not silently keep the first.
    #[test]
    fn test_duplicate_session_ids_detected_as_corruption() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();

        // Write a state file with duplicate session IDs
        let corrupt_json = serde_json::json!({
            "version": 1,
            "sessions": [
                {
                    "session_id": "sess-dup",
                    "work_id": "work-1",
                    "role": 1,
                    "ephemeral_handle": "handle-1",
                    "policy_resolved_ref": "policy-ref",
                    "capability_manifest_hash": [],
                    "episode_id": null
                },
                {
                    "session_id": "sess-dup",
                    "work_id": "work-2",
                    "role": 1,
                    "ephemeral_handle": "handle-2",
                    "policy_resolved_ref": "policy-ref",
                    "capability_manifest_hash": [],
                    "episode_id": null
                }
            ]
        });
        temp_file
            .write_all(corrupt_json.to_string().as_bytes())
            .unwrap();
        temp_file.flush().unwrap();

        let path = temp_file.path();
        let result = PersistentSessionRegistry::load_from_file(path);
        assert!(result.is_err(), "load_from_file must fail on duplicate IDs");

        match result.unwrap_err() {
            PersistentRegistryError::CorruptedDuplicateSessionId { session_id } => {
                assert_eq!(session_id, "sess-dup");
            },
            other => panic!("Expected CorruptedDuplicateSessionId error, got: {other:?}"),
        }
    }

    /// Unique session IDs in a state file must load successfully (no false
    /// positive from duplicate detection).
    #[test]
    fn test_unique_session_ids_load_successfully() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();

        let valid_json = serde_json::json!({
            "version": 1,
            "sessions": [
                {
                    "session_id": "sess-1",
                    "work_id": "work-1",
                    "role": 1,
                    "ephemeral_handle": "handle-1",
                    "policy_resolved_ref": "policy-ref",
                    "capability_manifest_hash": [],
                    "episode_id": null
                },
                {
                    "session_id": "sess-2",
                    "work_id": "work-2",
                    "role": 1,
                    "ephemeral_handle": "handle-2",
                    "policy_resolved_ref": "policy-ref",
                    "capability_manifest_hash": [],
                    "episode_id": null
                }
            ]
        });
        temp_file
            .write_all(valid_json.to_string().as_bytes())
            .unwrap();
        temp_file.flush().unwrap();

        let path = temp_file.path();
        let registry = PersistentSessionRegistry::load_from_file(path)
            .expect("unique session IDs must load successfully");
        assert_eq!(registry.session_count(), 2);
    }

    /// Multiple duplicate pairs in a state file: detection should catch the
    /// first duplicate encountered.
    #[test]
    fn test_multiple_duplicate_pairs_detected() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();

        let corrupt_json = serde_json::json!({
            "version": 1,
            "sessions": [
                {
                    "session_id": "sess-A",
                    "work_id": "work-1",
                    "role": 1,
                    "ephemeral_handle": "h1",
                    "policy_resolved_ref": "p",
                    "capability_manifest_hash": [],
                    "episode_id": null
                },
                {
                    "session_id": "sess-B",
                    "work_id": "work-2",
                    "role": 1,
                    "ephemeral_handle": "h2",
                    "policy_resolved_ref": "p",
                    "capability_manifest_hash": [],
                    "episode_id": null
                },
                {
                    "session_id": "sess-A",
                    "work_id": "work-3",
                    "role": 1,
                    "ephemeral_handle": "h3",
                    "policy_resolved_ref": "p",
                    "capability_manifest_hash": [],
                    "episode_id": null
                }
            ]
        });
        temp_file
            .write_all(corrupt_json.to_string().as_bytes())
            .unwrap();
        temp_file.flush().unwrap();

        let result = PersistentSessionRegistry::load_from_file(temp_file.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            PersistentRegistryError::CorruptedDuplicateSessionId { session_id } => {
                assert_eq!(session_id, "sess-A", "Should detect the first duplicate");
            },
            other => panic!("Expected CorruptedDuplicateSessionId, got: {other:?}"),
        }
    }

    // =========================================================================
    // SECURITY BLOCKER 1: Over-cap active sessions rejected at load (PR #434)
    // =========================================================================

    /// Regression test: `load_from_file` MUST reject state files with more
    /// active sessions than `MAX_SESSIONS` rather than silently evicting the
    /// excess. Silent eviction during load would drop sessions without running
    /// recovery side-effects (lease revocation, work claim cleanup).
    #[test]
    fn test_load_rejects_over_cap_sessions() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();

        // Build a state file with MAX_SESSIONS + 1 sessions
        let sessions: Vec<serde_json::Value> = (0..=MAX_SESSIONS)
            .map(|i| {
                serde_json::json!({
                    "session_id": format!("sess-{i}"),
                    "work_id": format!("work-{i}"),
                    "role": 1,
                    "ephemeral_handle": format!("handle-{i}"),
                    "policy_resolved_ref": "policy-ref",
                    "capability_manifest_hash": [],
                    "episode_id": null
                })
            })
            .collect();

        let state_json = serde_json::json!({
            "version": 1,
            "sessions": sessions
        });
        temp_file
            .write_all(state_json.to_string().as_bytes())
            .unwrap();
        temp_file.flush().unwrap();

        let result = PersistentSessionRegistry::load_from_file(temp_file.path());
        assert!(
            result.is_err(),
            "load_from_file must reject state files with > MAX_SESSIONS entries"
        );

        match result.unwrap_err() {
            PersistentRegistryError::TooManySessions { count, max } => {
                assert_eq!(count, MAX_SESSIONS + 1);
                assert_eq!(max, MAX_SESSIONS);
            },
            other => panic!("Expected TooManySessions error, got: {other:?}"),
        }
    }

    /// Regression test: `load_from_file` allows exactly `MAX_SESSIONS` (not
    /// off-by-one) since the check is strictly greater-than.
    #[test]
    fn test_load_allows_exactly_max_sessions() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp_file = NamedTempFile::new().unwrap();

        // Build a state file with exactly MAX_SESSIONS sessions
        let sessions: Vec<serde_json::Value> = (0..MAX_SESSIONS)
            .map(|i| {
                serde_json::json!({
                    "session_id": format!("sess-{i}"),
                    "work_id": format!("work-{i}"),
                    "role": 1,
                    "ephemeral_handle": format!("handle-{i}"),
                    "policy_resolved_ref": "policy-ref",
                    "capability_manifest_hash": [],
                    "episode_id": null
                })
            })
            .collect();

        let state_json = serde_json::json!({
            "version": 1,
            "sessions": sessions
        });
        temp_file
            .write_all(state_json.to_string().as_bytes())
            .unwrap();
        temp_file.flush().unwrap();

        let result = PersistentSessionRegistry::load_from_file(temp_file.path());
        assert!(
            result.is_ok(),
            "load_from_file must allow exactly MAX_SESSIONS entries"
        );
        assert_eq!(result.unwrap().session_count(), MAX_SESSIONS);
    }

    // =========================================================================
    // QUALITY MAJOR 1: clear_and_persist clears terminated entries (PR #434)
    // =========================================================================

    /// Regression test: `clear_and_persist` must clear terminated entries from
    /// in-memory state to be consistent with the empty state file it writes.
    /// Before this fix, `InMemorySessionRegistry::clear` only cleared active
    /// session maps, leaving terminated entries in memory while writing an
    /// empty `terminated: []` to disk.
    #[test]
    fn test_clear_and_persist_clears_terminated_entries() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        let registry = PersistentSessionRegistry::new(&state_path);

        // Register a session
        registry
            .register_session(make_session("sess-1", "handle-1"))
            .unwrap();

        // Terminate it (move from active to terminated)
        let info = SessionTerminationInfo {
            session_id: "sess-1".to_string(),
            rationale_code: "normal".to_string(),
            exit_classification: "SUCCESS".to_string(),
            exit_code: Some(0),
            terminated_at_ns: 1_000_000_000,
            actual_tokens_consumed: None,
        };
        let found = registry.mark_terminated("sess-1", info).unwrap();
        assert!(found, "session should be found and terminated");

        // Verify terminated entry exists in memory
        assert!(
            registry.get_termination_info("sess-1").is_some(),
            "terminated entry should exist before clear"
        );

        // Clear and persist
        registry.clear_and_persist().unwrap();

        // Verify terminated entry is also cleared from memory
        assert!(
            registry.get_termination_info("sess-1").is_none(),
            "terminated entry must be cleared by clear_and_persist"
        );
        assert_eq!(registry.session_count(), 0);

        // Verify state file reflects empty state
        let reloaded = PersistentSessionRegistry::load_from_file(&state_path).unwrap();
        assert_eq!(reloaded.session_count(), 0);
        assert!(
            reloaded.get_termination_info("sess-1").is_none(),
            "terminated entry must not survive reload after clear_and_persist"
        );
    }

    /// Regression test: after `clear_all_sessions` + restart, both active and
    /// terminated entries are gone. Exercises the full lifecycle through the
    /// `SessionRegistry` trait.
    #[test]
    fn test_clear_all_sessions_then_restart_is_empty() {
        use crate::session::SessionRegistry as SR;

        let temp_dir = tempfile::TempDir::new().unwrap();
        let state_path = temp_dir.path().join("state.json");

        // Phase 1: Create active + terminated state
        {
            let registry = PersistentSessionRegistry::new(&state_path);

            registry
                .register_session(make_session("active-1", "h-active-1"))
                .unwrap();
            registry
                .register_session(make_session("term-1", "h-term-1"))
                .unwrap();

            let info = SessionTerminationInfo {
                session_id: "term-1".to_string(),
                rationale_code: "crash".to_string(),
                exit_classification: "FAILURE".to_string(),
                exit_code: Some(1),
                terminated_at_ns: 1_000_000_000,
                actual_tokens_consumed: None,
            };
            SR::mark_terminated(&registry, "term-1", info).unwrap();

            // Verify both exist
            assert!(registry.get_session("active-1").is_some());
            assert!(SR::get_termination_info(&registry, "term-1").is_some());

            // Clear all sessions via the trait method
            SR::clear_all_sessions(&registry).unwrap();

            // Verify everything is gone in memory
            assert!(registry.get_session("active-1").is_none());
            assert!(SR::get_termination_info(&registry, "term-1").is_none());
        }

        // Phase 2: Simulate restart
        let reloaded = PersistentSessionRegistry::load_from_file(&state_path).unwrap();
        assert_eq!(reloaded.session_count(), 0);
        assert!(reloaded.get_termination_info("term-1").is_none());
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

// =============================================================================
// TCK-00385: Security Fix Tests (BLOCKER 1, BLOCKER 2, MAJOR 1)
// =============================================================================

#[cfg(test)]
mod tck_00385_security_fixes {
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
    // BLOCKER 1: Unbounded terminated-session store
    // =========================================================================

    /// BLOCKER 1: Terminated session map is bounded at
    /// `MAX_TERMINATED_SESSIONS`.
    ///
    /// Stress test proving memory stays bounded even under high churn:
    /// register many sessions, terminate them all, and verify the terminated
    /// map never exceeds the cap.
    #[test]
    fn terminated_store_bounded_under_churn() {
        let registry = InMemorySessionRegistry::new();

        // Churn through more sessions than MAX_TERMINATED_SESSIONS.
        // We process in batches to stay within MAX_SESSIONS active limit.
        let total_terminations = MAX_TERMINATED_SESSIONS + 500;
        let batch_size = MAX_SESSIONS;

        let mut terminated_so_far = 0usize;

        while terminated_so_far < total_terminations {
            let this_batch = batch_size.min(total_terminations - terminated_so_far);

            // Register a batch of sessions
            for i in 0..this_batch {
                let idx = terminated_so_far + i;
                let session = make_session(&format!("churn-{idx}"), &format!("handle-churn-{idx}"));
                registry
                    .register_session(session)
                    .expect("registration should succeed");
            }

            // Terminate them all
            for i in 0..this_batch {
                let idx = terminated_so_far + i;
                let info = SessionTerminationInfo::new(format!("churn-{idx}"), "normal", "SUCCESS");
                registry
                    .mark_terminated(&format!("churn-{idx}"), info)
                    .unwrap();
            }

            terminated_so_far += this_batch;

            // Invariant: terminated map never exceeds MAX_TERMINATED_SESSIONS
            let state = registry.state.read().expect("lock poisoned");
            assert!(
                state.terminated.len() <= MAX_TERMINATED_SESSIONS,
                "Terminated store exceeded cap: {} > {}",
                state.terminated.len(),
                MAX_TERMINATED_SESSIONS
            );
        }

        // Final check: terminated count is at most MAX_TERMINATED_SESSIONS
        let state = registry.state.read().expect("lock poisoned");
        assert!(
            state.terminated.len() <= MAX_TERMINATED_SESSIONS,
            "Final terminated store size {} exceeds cap {}",
            state.terminated.len(),
            MAX_TERMINATED_SESSIONS,
        );
    }

    /// BLOCKER 1: Oldest terminated entries are evicted when the cap is hit.
    #[test]
    fn terminated_store_evicts_oldest() {
        let registry = InMemorySessionRegistry::new();

        // Register and terminate exactly MAX_TERMINATED_SESSIONS sessions
        for i in 0..MAX_TERMINATED_SESSIONS {
            let session = make_session(&format!("evict-{i}"), &format!("handle-evict-{i}"));
            registry.register_session(session).unwrap();
            let info = SessionTerminationInfo::new(format!("evict-{i}"), "normal", "SUCCESS");
            registry
                .mark_terminated(&format!("evict-{i}"), info)
                .unwrap();
        }

        // Verify the first entry still exists (map is exactly at cap)
        assert!(
            registry.get_termination_info("evict-0").is_some(),
            "First entry should still exist at cap"
        );

        // Add one more, which should evict the oldest
        let overflow = make_session("evict-overflow", "handle-evict-overflow");
        registry.register_session(overflow).unwrap();
        let info = SessionTerminationInfo::new("evict-overflow", "normal", "SUCCESS");
        registry.mark_terminated("evict-overflow", info).unwrap();

        // The overflow entry should exist
        assert!(
            registry.get_termination_info("evict-overflow").is_some(),
            "Overflow entry should exist"
        );

        // Total should still be at most MAX_TERMINATED_SESSIONS
        let state = registry.state.read().expect("lock poisoned");
        assert!(
            state.terminated.len() <= MAX_TERMINATED_SESSIONS,
            "Size {} should be <= {}",
            state.terminated.len(),
            MAX_TERMINATED_SESSIONS
        );
    }

    // =========================================================================
    // BLOCKER 2: Crash-window regression test for PersistentSessionRegistry
    // =========================================================================

    /// BLOCKER 2: After `mark_terminated()`, a crash-recovery reload must NOT
    /// resurrect the session as active.
    ///
    /// This test simulates:
    /// 1. Register a session in `PersistentSessionRegistry` (persisted as
    ///    active)
    /// 2. Mark it terminated (should persist the removal from active set)
    /// 3. Reload from file (simulating crash recovery)
    /// 4. Verify the session is NOT in the active set
    #[test]
    fn persistent_mark_terminated_no_stale_active_resurrection() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        // Step 1: Register a session
        let registry = PersistentSessionRegistry::new(&path);
        let session = make_session("persist-term-1", "handle-pt-1");
        registry.register_session(session).expect("should register");

        // Verify session is active and persisted
        assert!(registry.get_session("persist-term-1").is_some());
        assert!(path.exists(), "State file should exist after register");

        // Step 2: Mark terminated (should persist removal from active set)
        let info = SessionTerminationInfo::new("persist-term-1", "normal", "SUCCESS");
        assert!(
            registry
                .mark_terminated("persist-term-1", info)
                .expect("mark_terminated should not fail"),
            "mark_terminated should succeed"
        );

        // Step 3: Simulate crash recovery by loading from file
        let recovered =
            PersistentSessionRegistry::load_from_file(&path).expect("should load from file");

        // Step 4: Session MUST NOT be in active set (no stale resurrection)
        assert!(
            recovered.get_session("persist-term-1").is_none(),
            "Terminated session MUST NOT be resurrected as active after crash recovery"
        );
        assert_eq!(
            recovered.session_count(),
            0,
            "No active sessions should remain after termination + recovery"
        );
    }

    /// BLOCKER 2: Multiple sessions, only the terminated one is removed.
    #[test]
    fn persistent_mark_terminated_preserves_other_sessions() {
        use tempfile::NamedTempFile;

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        let registry = PersistentSessionRegistry::new(&path);
        registry
            .register_session(make_session("keep-1", "h-keep-1"))
            .unwrap();
        registry
            .register_session(make_session("terminate-1", "h-term-1"))
            .unwrap();
        registry
            .register_session(make_session("keep-2", "h-keep-2"))
            .unwrap();

        // Terminate only one
        let info = SessionTerminationInfo::new("terminate-1", "crash", "FAILURE");
        registry.mark_terminated("terminate-1", info).unwrap();

        // Recover
        let recovered = PersistentSessionRegistry::load_from_file(&path).unwrap();

        assert!(
            recovered.get_session("keep-1").is_some(),
            "Non-terminated session keep-1 should survive recovery"
        );
        assert!(
            recovered.get_session("keep-2").is_some(),
            "Non-terminated session keep-2 should survive recovery"
        );
        assert!(
            recovered.get_session("terminate-1").is_none(),
            "Terminated session should not be resurrected"
        );
        assert_eq!(recovered.session_count(), 2);
    }

    // =========================================================================
    // MAJOR 1: TerminationReason enum tests
    // =========================================================================

    /// MAJOR 1: All known reasons round-trip through
    /// `from_reason_str`/`as_str`.
    #[test]
    fn termination_reason_known_reasons_round_trip() {
        for reason in TerminationReason::ALL_KNOWN {
            let s = reason.as_str();
            let parsed = TerminationReason::from_reason_str(s);
            assert_eq!(*reason, parsed, "Round-trip failed for {s}");
        }
    }

    /// MAJOR 1: Unknown/free-form strings are normalized to Unknown.
    #[test]
    fn termination_reason_unknown_normalized() {
        let garbage = TerminationReason::from_reason_str("arbitrary_garbage_value");
        assert_eq!(garbage, TerminationReason::Unknown);
        assert_eq!(garbage.as_str(), "unknown");

        let empty = TerminationReason::from_reason_str("");
        assert_eq!(empty, TerminationReason::Unknown);

        let injection = TerminationReason::from_reason_str("<script>alert(1)</script>");
        assert_eq!(injection, TerminationReason::Unknown);
    }

    /// MAJOR 1: Display impl matches `as_str`.
    #[test]
    fn termination_reason_display() {
        assert_eq!(TerminationReason::Normal.to_string(), "normal");
        assert_eq!(TerminationReason::Crash.to_string(), "crash");
        assert_eq!(TerminationReason::ContextMiss.to_string(), "CONTEXT_MISS");
        assert_eq!(TerminationReason::Unknown.to_string(), "unknown");
    }

    /// MAJOR 1: All proto-documented reasons are in the allowlist.
    #[test]
    fn termination_reason_covers_proto_documented_values() {
        // These are the values documented in the proto file comment:
        // "normal, crash, timeout, quarantined, budget_exhausted"
        let proto_values = [
            "normal",
            "crash",
            "timeout",
            "quarantined",
            "budget_exhausted",
        ];
        for v in proto_values {
            let reason = TerminationReason::from_reason_str(v);
            assert_ne!(
                reason,
                TerminationReason::Unknown,
                "Proto-documented value '{v}' should be a known reason"
            );
        }
    }

    // =========================================================================
    // MAJOR: PersistentSessionRegistry persist failure is observable
    // =========================================================================

    /// MAJOR fix: `PersistentSessionRegistry::mark_terminated` returns Err
    /// when persistence fails (e.g., read-only path).
    #[test]
    fn persistent_mark_terminated_returns_err_on_persist_failure() {
        // Create a registry pointing to a path that will fail to write
        // (non-existent directory with no permission to create).
        let bad_path = "/proc/nonexistent_dir/impossible_file.json";
        let registry = PersistentSessionRegistry::new(bad_path);

        // Register a session -- this will also fail to persist, but the
        // in-memory state is updated. For this test we directly use the
        // inner registry to seed the session.
        let session = make_session("fail-persist-1", "handle-fp-1");
        registry
            .inner
            .register_session(session)
            .expect("in-memory register should succeed");

        let info = SessionTerminationInfo::new("fail-persist-1", "normal", "SUCCESS");
        let result = registry.mark_terminated("fail-persist-1", info);

        assert!(
            result.is_err(),
            "mark_terminated should return Err when persistence fails"
        );

        match result.unwrap_err() {
            SessionRegistryError::RegistrationFailed { message } => {
                assert!(
                    message.contains("persist"),
                    "Error message should mention persistence: {message}"
                );
            },
            other @ SessionRegistryError::DuplicateSessionId { .. } => {
                panic!("Expected RegistrationFailed, got: {other:?}")
            },
        }
    }

    /// MAJOR fix: `InMemorySessionRegistry::mark_terminated` always returns
    /// Ok (no persistence).
    #[test]
    fn in_memory_mark_terminated_returns_ok() {
        let registry = InMemorySessionRegistry::new();
        let session = make_session("ok-1", "handle-ok-1");
        registry.register_session(session).unwrap();

        let info = SessionTerminationInfo::new("ok-1", "normal", "SUCCESS");
        let result = registry.mark_terminated("ok-1", info);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Non-existent session returns Ok(false)
        let info2 = SessionTerminationInfo::new("no-such", "normal", "SUCCESS");
        let result2 = registry.mark_terminated("no-such", info2);
        assert!(result2.is_ok());
        assert!(!result2.unwrap());
    }

    // =========================================================================
    // MINOR: session_id normalization in mark_terminated
    // =========================================================================

    /// MINOR fix: When `SessionTerminationInfo.session_id` contains an
    /// `episode_id`, the registry stores it under the correct `session_id` key
    /// and the info can be retrieved.
    #[test]
    fn mark_terminated_with_episode_id_in_info_still_works() {
        let registry = InMemorySessionRegistry::new();
        let session = make_session("real-session-id", "handle-norm");
        registry.register_session(session).unwrap();

        // Info has episode_id in its session_id field (simulating broker bug)
        let mut info = SessionTerminationInfo::new("episode-id-not-session", "normal", "SUCCESS");
        // Caller normalizes before calling mark_terminated
        info.session_id = "real-session-id".to_string();

        assert!(registry.mark_terminated("real-session-id", info).unwrap());

        let retrieved = registry
            .get_termination_info("real-session-id")
            .expect("Should find termination info");
        assert_eq!(
            retrieved.session_id, "real-session-id",
            "Stored info should have the normalized session_id"
        );
    }

    // =========================================================================
    // BLOCKER 2: Terminated state persisted across restart
    // =========================================================================

    /// BLOCKER 2: After `mark_terminated()`, a crash-recovery reload must
    /// preserve the TERMINATED status. The session must NOT reappear as
    /// active, and `get_termination_info` must return the stored info.
    #[test]
    fn persistent_terminated_state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terminated_persist.json");

        // Step 1: Register and terminate a session
        {
            let registry = PersistentSessionRegistry::new(&path);
            let session = make_session("term-persist-1", "handle-tp-1");
            registry.register_session(session).unwrap();

            let info =
                SessionTerminationInfo::new("term-persist-1", "crash", "FAILURE").with_exit_code(1);
            assert!(
                registry.mark_terminated("term-persist-1", info).unwrap(),
                "mark_terminated should succeed"
            );

            // Verify in-memory terminated state before crash
            assert!(
                registry.get_session("term-persist-1").is_none(),
                "Session should NOT be in active set"
            );
            assert!(
                registry.get_termination_info("term-persist-1").is_some(),
                "Termination info should be available"
            );
        }

        // Step 2: Simulate daemon restart by loading from persisted file
        {
            let recovered =
                PersistentSessionRegistry::load_from_file(&path).expect("should load from file");

            // Session should NOT reappear as active
            assert!(
                recovered.get_session("term-persist-1").is_none(),
                "Terminated session must NOT resurrect as active after restart"
            );

            // Termination info should be preserved
            let info = recovered
                .get_termination_info("term-persist-1")
                .expect("Termination info must survive restart");
            assert_eq!(info.rationale_code, "crash");
            assert_eq!(info.exit_classification, "FAILURE");
            assert_eq!(info.exit_code, Some(1));

            // get_terminated_session should also work
            let (session, term_info) = recovered
                .get_terminated_session("term-persist-1")
                .expect("Terminated session entry must survive restart");
            assert_eq!(session.session_id, "term-persist-1");
            assert_eq!(session.work_id, "work-term-persist-1");
            assert_eq!(term_info.rationale_code, "crash");
        }
    }

    /// BLOCKER 2: Multiple sessions -- only terminated ones appear in the
    /// terminated store after reload; active sessions remain active.
    #[test]
    fn persistent_terminated_coexists_with_active_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coexist.json");

        {
            let registry = PersistentSessionRegistry::new(&path);
            registry
                .register_session(make_session("active-1", "h-a1"))
                .unwrap();
            registry
                .register_session(make_session("term-1", "h-t1"))
                .unwrap();
            registry
                .register_session(make_session("active-2", "h-a2"))
                .unwrap();

            let info = SessionTerminationInfo::new("term-1", "normal", "SUCCESS");
            registry.mark_terminated("term-1", info).unwrap();
        }

        {
            let recovered = PersistentSessionRegistry::load_from_file(&path).expect("should load");

            assert!(
                recovered.get_session("active-1").is_some(),
                "active-1 should survive"
            );
            assert!(
                recovered.get_session("active-2").is_some(),
                "active-2 should survive"
            );
            assert!(
                recovered.get_session("term-1").is_none(),
                "term-1 should NOT be active"
            );
            assert!(
                recovered.get_termination_info("term-1").is_some(),
                "term-1 termination info should be present"
            );
        }
    }

    /// BLOCKER 2: Expired terminated entries (TTL = 0) are skipped on reload.
    #[test]
    fn persistent_terminated_expired_entries_skipped_on_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("expired.json");

        // Manually write a state file with a terminated entry that has already
        // expired (absolute expiry in the past).
        let state_file = PersistentStateFile {
            version: 1,
            sessions: vec![],
            terminated: vec![PersistableTerminatedEntry {
                session: PersistableSessionState {
                    session_id: "expired-1".to_string(),
                    work_id: "work-expired-1".to_string(),
                    role: 1,
                    ephemeral_handle: "h-exp".to_string(),
                    policy_resolved_ref: String::new(),
                    capability_manifest_hash: vec![],
                    episode_id: None,
                },
                info: SessionTerminationInfo::new("expired-1", "timeout", "FAILURE"),
                issued_at_epoch_secs: 1_000_000,
                // Expiry in the distant past
                expires_at_epoch_secs: 1_000_001,
                ttl_remaining_secs: 0,
            }],
        };
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&path, json).unwrap();

        let recovered = PersistentSessionRegistry::load_from_file(&path).expect("should load");

        assert!(
            recovered.get_termination_info("expired-1").is_none(),
            "Expired terminated entry (TTL=0) should be skipped on reload"
        );
    }

    // =========================================================================
    // MINOR 1: TTL cleanup runs on register_session
    // =========================================================================

    /// MINOR 1: Expired terminated entries are cleaned up during
    /// `register_session`, not only during `mark_terminated`.
    #[test]
    fn register_session_cleans_expired_terminated_entries() {
        let registry = InMemorySessionRegistry::new();

        // Register and terminate a session
        let session = make_session("ttl-test-1", "handle-ttl-1");
        registry.register_session(session).unwrap();
        let info = SessionTerminationInfo::new("ttl-test-1", "normal", "SUCCESS");
        registry.mark_terminated("ttl-test-1", info).unwrap();

        // Verify terminated entry exists
        assert_eq!(registry.terminated_count(), 1);

        // Manually set the entry's expires_at to the past by manipulating
        // the inner state. This simulates time passing.
        {
            let mut state = registry.state.write().expect("lock poisoned");
            if let Some(entry) = state.terminated.get_mut("ttl-test-1") {
                // Set to past by subtracting more than TTL
                entry.expires_at = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            }
        }

        // Now register a new session -- this should trigger TTL cleanup
        let session2 = make_session("new-session", "handle-new");
        registry.register_session(session2).unwrap();

        // The expired entry should have been cleaned up
        let state = registry.state.read().expect("lock poisoned");
        assert!(
            state.terminated.is_empty(),
            "Expired terminated entry should be cleaned up during register_session"
        );
    }

    // =========================================================================
    // SEC-BLOCKER: Idempotent mark_terminated with rollback on persist failure
    // =========================================================================

    /// SEC-BLOCKER regression: On persist failure the in-memory state is rolled
    /// back so the session stays ACTIVE. On retry with recovered storage the
    /// same session can be terminated successfully, and after a simulated
    /// restart no stale ACTIVE entry is resurrected.
    #[test]
    fn mark_terminated_rollback_on_persist_failure_then_retry() {
        // Phase 1: Use an impossible path so persistence fails.
        let bad_path = "/proc/nonexistent_dir/impossible_file.json";
        let registry = PersistentSessionRegistry::new(bad_path);

        // Seed a session directly into in-memory state (persistence will fail).
        let session = make_session("rollback-1", "handle-rb-1");
        registry
            .inner
            .register_session(session)
            .expect("in-memory register should succeed");

        // Attempt to terminate -- persist will fail.
        let info = SessionTerminationInfo::new("rollback-1", "crash", "FAILURE");
        let err = registry.mark_terminated("rollback-1", info);
        assert!(
            err.is_err(),
            "mark_terminated should fail when persist fails"
        );

        // The session MUST still be in the ACTIVE set (rollback).
        assert!(
            registry.get_session("rollback-1").is_some(),
            "Session must be rolled back to ACTIVE on persist failure"
        );

        // The session MUST NOT be in the terminated set.
        assert!(
            registry.get_termination_info("rollback-1").is_none(),
            "Session must not appear in terminated set after rollback"
        );

        // Phase 2: Switch to a writable path and retry the same session.
        let dir = tempfile::tempdir().unwrap();
        let good_path = dir.path().join("recovered.json");
        let registry2 = PersistentSessionRegistry::new(&good_path);
        registry2
            .inner
            .register_session(make_session("rollback-1", "handle-rb-1"))
            .expect("in-memory register should succeed");

        let info2 = SessionTerminationInfo::new("rollback-1", "crash", "FAILURE");
        assert!(
            registry2
                .mark_terminated("rollback-1", info2)
                .expect("should succeed with working storage"),
            "mark_terminated should succeed on retry"
        );

        // Phase 3: Simulate restart -- no stale ACTIVE resurrection.
        let recovered = PersistentSessionRegistry::load_from_file(&good_path).expect("should load");
        assert!(
            recovered.get_session("rollback-1").is_none(),
            "Terminated session must NOT resurrect as ACTIVE after restart"
        );
        assert!(
            recovered.get_termination_info("rollback-1").is_some(),
            "Termination info must survive restart"
        );
    }

    // =========================================================================
    // SEC-MAJOR-1: Absolute TTL expiry -- downtime does not extend lifetime
    // =========================================================================

    /// SEC-MAJOR-1: Absolute expiry is enforced on load. If the wall-clock
    /// expiry is in the past, the entry is compacted on startup even if the
    /// legacy `ttl_remaining_secs` is non-zero.
    #[test]
    fn absolute_expiry_compacted_on_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abs_expiry.json");

        let past_epoch = wall_clock_secs().saturating_sub(100);
        let state_file = PersistentStateFile {
            version: 1,
            sessions: vec![],
            terminated: vec![PersistableTerminatedEntry {
                session: PersistableSessionState {
                    session_id: "abs-exp-1".to_string(),
                    work_id: "work-abs-exp-1".to_string(),
                    role: 1,
                    ephemeral_handle: "h-ae".to_string(),
                    policy_resolved_ref: String::new(),
                    capability_manifest_hash: vec![],
                    episode_id: None,
                },
                info: SessionTerminationInfo::new("abs-exp-1", "normal", "SUCCESS"),
                issued_at_epoch_secs: past_epoch.saturating_sub(300),
                expires_at_epoch_secs: past_epoch,
                // Legacy field says 300 -- should be ignored because
                // absolute expiry takes precedence.
                ttl_remaining_secs: 300,
            }],
        };
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&path, json).unwrap();

        let recovered = PersistentSessionRegistry::load_from_file(&path).expect("should load");
        assert!(
            recovered.get_termination_info("abs-exp-1").is_none(),
            "Entry with past absolute expiry must be compacted on startup"
        );
    }

    /// SEC-MAJOR-1: Entries with valid absolute expiry are loaded correctly.
    #[test]
    fn absolute_expiry_valid_entry_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abs_valid.json");

        let future_epoch = wall_clock_secs() + 200;
        let state_file = PersistentStateFile {
            version: 1,
            sessions: vec![],
            terminated: vec![PersistableTerminatedEntry {
                session: PersistableSessionState {
                    session_id: "abs-valid-1".to_string(),
                    work_id: "work-abs-valid-1".to_string(),
                    role: 1,
                    ephemeral_handle: "h-av".to_string(),
                    policy_resolved_ref: String::new(),
                    capability_manifest_hash: vec![],
                    episode_id: None,
                },
                info: SessionTerminationInfo::new("abs-valid-1", "normal", "SUCCESS"),
                issued_at_epoch_secs: future_epoch.saturating_sub(300),
                expires_at_epoch_secs: future_epoch,
                ttl_remaining_secs: 200,
            }],
        };
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&path, json).unwrap();

        let recovered = PersistentSessionRegistry::load_from_file(&path).expect("should load");
        assert!(
            recovered.get_termination_info("abs-valid-1").is_some(),
            "Entry with future absolute expiry must be loaded"
        );
    }

    /// SEC-MAJOR-1: Legacy state files (no `expires_at_epoch_secs`) fall back
    /// to `ttl_remaining_secs`.
    #[test]
    fn legacy_ttl_fallback_when_no_absolute_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.json");

        // Manually construct JSON without expires_at_epoch_secs and
        // issued_at_epoch_secs, simulating a pre-migration state file.
        let json = r#"{
            "version": 1,
            "sessions": [],
            "terminated": [{
                "session": {
                    "session_id": "legacy-1",
                    "work_id": "work-legacy-1",
                    "role": 1,
                    "ephemeral_handle": "h-legacy",
                    "policy_resolved_ref": "",
                    "capability_manifest_hash": [],
                    "episode_id": null
                },
                "info": {
                    "session_id": "legacy-1",
                    "rationale_code": "normal",
                    "exit_classification": "SUCCESS",
                    "exit_code": null,
                    "terminated_at_ns": 0,
                    "actual_tokens_consumed": null
                },
                "ttl_remaining_secs": 200
            }]
        }"#;
        std::fs::write(&path, json).unwrap();

        let recovered = PersistentSessionRegistry::load_from_file(&path).expect("should load");
        assert!(
            recovered.get_termination_info("legacy-1").is_some(),
            "Legacy entry with ttl_remaining_secs > 0 should be loaded via fallback"
        );
    }

    // =========================================================================
    // SEC-MAJOR-2: deny_unknown_fields and collision detection
    // =========================================================================

    /// SEC-MAJOR-2: State files with unknown fields are rejected.
    #[test]
    fn deny_unknown_fields_rejects_extra_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unknown_field.json");

        let json = r#"{
            "version": 1,
            "sessions": [],
            "terminated": [],
            "evil_extra_field": true
        }"#;
        std::fs::write(&path, json).unwrap();

        let result = PersistentSessionRegistry::load_from_file(&path);
        assert!(
            result.is_err(),
            "State file with unknown fields must be rejected"
        );
    }

    /// SEC-MAJOR-2: `session_id` collision between active and terminated sets
    /// is resolved by dropping the terminated entry.
    #[test]
    fn collision_detection_active_wins_over_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("collision.json");

        let future_epoch = wall_clock_secs() + 200;
        let state_file = PersistentStateFile {
            version: 1,
            sessions: vec![PersistableSessionState {
                session_id: "collide-1".to_string(),
                work_id: "work-collide-1".to_string(),
                role: 1,
                ephemeral_handle: "h-c1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: None,
            }],
            terminated: vec![PersistableTerminatedEntry {
                session: PersistableSessionState {
                    session_id: "collide-1".to_string(),
                    work_id: "work-collide-1-term".to_string(),
                    role: 1,
                    ephemeral_handle: "h-c1-term".to_string(),
                    policy_resolved_ref: String::new(),
                    capability_manifest_hash: vec![],
                    episode_id: None,
                },
                info: SessionTerminationInfo::new("collide-1", "crash", "FAILURE"),
                issued_at_epoch_secs: future_epoch.saturating_sub(300),
                expires_at_epoch_secs: future_epoch,
                ttl_remaining_secs: 200,
            }],
        };
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&path, json).unwrap();

        let recovered = PersistentSessionRegistry::load_from_file(&path).expect("should load");

        // Active entry wins.
        assert!(
            recovered.get_session("collide-1").is_some(),
            "Active session should be preserved"
        );
        // Terminated entry with colliding ID is dropped.
        assert!(
            recovered.get_termination_info("collide-1").is_none(),
            "Terminated entry colliding with active must be dropped"
        );
    }

    // =========================================================================
    // MAJOR 1 regression: load_from_file enforces MAX_TERMINATED_SESSIONS cap
    // =========================================================================

    /// MAJOR 1 regression: `load_from_file()` enforces
    /// `MAX_TERMINATED_SESSIONS` cap. A state file with more terminated
    /// entries than the cap must be trimmed on load using the same eviction
    /// policy (oldest `expires_at` first).
    #[test]
    fn reload_enforces_terminated_session_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over_cap.json");

        let future_base = wall_clock_secs() + 200;

        // Build a state file with MAX_TERMINATED_SESSIONS + 50 entries.
        let overflow_count = MAX_TERMINATED_SESSIONS + 50;
        let terminated: Vec<PersistableTerminatedEntry> = (0..overflow_count)
            .map(|i| {
                let sid = format!("reload-cap-{i}");
                PersistableTerminatedEntry {
                    session: PersistableSessionState {
                        session_id: sid.clone(),
                        work_id: format!("work-{sid}"),
                        role: 1,
                        ephemeral_handle: format!("h-{sid}"),
                        policy_resolved_ref: String::new(),
                        capability_manifest_hash: vec![],
                        episode_id: None,
                    },
                    info: SessionTerminationInfo::new(&sid, "normal", "SUCCESS"),
                    issued_at_epoch_secs: future_base.saturating_sub(300),
                    // Stagger expiry so eviction is deterministic: earlier
                    // indices expire first.
                    #[allow(clippy::cast_possible_truncation)]
                    expires_at_epoch_secs: future_base + (i as u64),
                    ttl_remaining_secs: 200,
                }
            })
            .collect();

        let state_file = PersistentStateFile {
            version: 1,
            sessions: vec![],
            terminated,
        };
        let json = serde_json::to_string(&state_file).unwrap();
        std::fs::write(&path, json).unwrap();

        let recovered = PersistentSessionRegistry::load_from_file(&path).expect("should load");

        // The terminated count must not exceed the cap.
        let inner_state = recovered.inner.state.read().expect("lock poisoned");
        assert!(
            inner_state.terminated.len() <= MAX_TERMINATED_SESSIONS,
            "Loaded terminated count {} exceeds cap {}",
            inner_state.terminated.len(),
            MAX_TERMINATED_SESSIONS
        );

        // The oldest entries (lowest index / earliest expiry) should have been
        // evicted, and the newest entries should remain.
        let last_idx = overflow_count - 1;
        let last_key = format!("reload-cap-{last_idx}");
        assert!(
            inner_state.terminated.contains_key(&last_key),
            "Newest terminated entry should survive eviction"
        );
    }
}
