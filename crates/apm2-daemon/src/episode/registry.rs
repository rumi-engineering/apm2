//! Adapter registry for managing harness adapters.
//!
//! This module provides the [`AdapterRegistry`] for registering and looking up
//! harness adapters by type. Per AD-LAYER-001 and AD-ADAPT-001, the registry
//! acts as a factory for per-episode Holon instances.
//!
//! # Usage
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

use super::adapter::{AdapterType, HarnessAdapter};
use super::claude_code::{ClaudeCodeAdapter, ClaudeCodeHolon};
use super::raw_adapter::{RawAdapter, RawAdapterHolon};

/// Registry for harness adapters.
///
/// Provides a centralized location for registering and retrieving adapters
/// by their type. The registry owns the adapter instances and acts as a
/// factory for per-episode Holon instances.
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
}

impl AdapterRegistry {
    /// Create a new empty adapter registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new registry with default adapters registered.
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
            .finish()
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
=======
        let guard = self.sessions.read().expect("lock poisoned");
        guard.1.get(session_id).cloned()
    }

    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState> {
        let handles = self.sessions_by_handle.read().expect("lock poisoned");
        let session_id = handles.get(handle)?;
        let guard = self.sessions.read().expect("lock poisoned");
        guard.1.get(session_id).cloned()
>>>>>>> 2964356 (feat(TCK-00259): Implement ephemeral session handle generation)
    }
}
