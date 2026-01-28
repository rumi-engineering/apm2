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
    /// - [`RawAdapter`](super::raw_adapter::RawAdapter) for
    ///   [`AdapterType::Raw`]
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(super::raw_adapter::RawAdapter::new()));
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
            AdapterType::Raw => {
                // Downcast to RawAdapter to access create_holon method
                self.adapters.get(&adapter_type).and_then(|adapter| {
                    // We know this is a RawAdapter because we control registration
                    // Safe downcast via adapter type checking
                    let raw_adapter = adapter.as_any().downcast_ref::<RawAdapter>()?;
                    Some(raw_adapter.create_holon())
                })
            },
            AdapterType::ClaudeCode => {
                // ClaudeCode adapter not yet implemented
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
    use crate::episode::raw_adapter::RawAdapter;

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

        let raw = registry.get(AdapterType::Raw).unwrap();
        assert_eq!(raw.adapter_type(), AdapterType::Raw);
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
    fn test_registry_create_holon_unregistered() {
        let registry = AdapterRegistry::new();
        let holon = registry.create_holon(AdapterType::Raw);
        assert!(holon.is_none());
    }

    #[test]
    fn test_registry_create_holon_claude_code_not_implemented() {
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
}
