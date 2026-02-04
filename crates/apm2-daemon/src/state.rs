//! Shared daemon state.
//!
//! Provides thread-safe shared state for the daemon.
//!
//! # TCK-00287: Security Fixes
//!
//! Per the security review, dispatchers and registries must be shared across
//! connections to prevent state loss and authentication secret rotation issues.
//! This module provides the `DispatcherState` struct that holds:
//! - `PrivilegedDispatcher` with shared registries
//! - `SessionDispatcher` with stable `TokenMinter` secret
//! - `FailClosedManifestStore` that denies all tools by default

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use apm2_core::config::EcosystemConfig;
use apm2_core::process::ProcessId;
use apm2_core::process::runner::ProcessRunner;
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_core::supervisor::Supervisor;
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use tokio::sync::RwLock;

use crate::cas::{DurableCas, DurableCasConfig};
use crate::episode::capability::StubManifestLoader;
use crate::episode::executor::ContentAddressedStore;
use crate::episode::{
    CapabilityManifest, EpisodeRuntime, EpisodeRuntimeConfig, InMemorySessionRegistry,
    PersistentRegistryError, PersistentSessionRegistry, SharedToolBroker, ToolBrokerConfig,
    new_shared_broker_with_cas,
};
use crate::governance::GovernancePolicyResolver;
use crate::htf::{ClockConfig, HolonicClock};
use crate::ledger::{SqliteLeaseValidator, SqliteLedgerEventEmitter, SqliteWorkRegistry};
use crate::metrics::SharedMetricsRegistry;
use crate::protocol::dispatch::PrivilegedDispatcher;
use crate::protocol::messages::DecodeConfig;
use crate::protocol::resource_governance::{SharedSubscriptionRegistry, SubscriptionRegistry};
use crate::protocol::session_dispatch::{InMemoryManifestStore, ManifestStore, SessionDispatcher};
use crate::protocol::session_token::TokenMinter;
use crate::session::SessionRegistry;

// ============================================================================
// TCK-00287: Fail-Closed Manifest Store (kept for potential future use)
// ============================================================================

/// A manifest store that always returns `None`, enforcing fail-closed behavior.
///
/// Per TCK-00287 security review item 3 (Permissive Default), the
/// `SessionDispatcher` must deny all tools if no manifest is available. When
/// this store is used with `SessionDispatcher::with_manifest_store()`, any tool
/// request will be denied because `get_manifest()` returns `None`, triggering
/// the fail-closed path in `handle_request_tool()`.
///
/// # Security Invariant (INV-TCK-00260-002)
///
/// Empty or missing `tool_allowlist` denies all tools (fail-closed).
///
/// # Current Status
///
/// This struct is currently unused as the implementation now uses
/// `InMemoryManifestStore` shared between dispatchers. It is kept for potential
/// future use as a default-deny store for testing or specific security
/// scenarios.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct FailClosedManifestStore;

impl ManifestStore for FailClosedManifestStore {
    fn get_manifest(&self, _session_id: &str) -> Option<Arc<CapabilityManifest>> {
        // Always return None to trigger fail-closed behavior in SessionDispatcher.
        // The dispatcher will return SESSION_ERROR_TOOL_NOT_ALLOWED when no manifest
        // is found for a session.
        None
    }
}

// ============================================================================
// TCK-00287: Shared Dispatcher State
// ============================================================================

/// Shared dispatcher state across all connections.
///
/// Per TCK-00287 security review:
/// - Item 1 (Cross-Connection State Loss): Dispatchers must persist across
///   connections
/// - Item 2 (Authentication Secret Rotation): `TokenMinter` secret must be
///   stable
/// - Item 3 (Permissive Default): Must use fail-closed manifest store
///   initially, but allow manifests to be registered during `SpawnEpisode`
///
/// # TCK-00287 BLOCKER 1, 2, 3 Fixes
///
/// This struct now shares:
/// - `TokenMinter`: Same secret for both minting and validation
/// - `InMemoryManifestStore`: Manifests registered during spawn are visible
/// - `SessionRegistry`: Global session registry from `DaemonStateHandle`
///
/// This ensures that:
/// 1. Sessions spawned via IPC are visible to daemon's persistent state
/// 2. Clients receive HMAC-signed tokens they can use for session endpoints
/// 3. Tool requests can be validated against manifests registered during spawn
pub struct DispatcherState {
    /// Privileged endpoint dispatcher with shared registries.
    ///
    /// Contains `WorkRegistry`, `SessionRegistry`, and `LedgerEventEmitter`
    /// that persist across connections. Now also contains shared
    /// `TokenMinter` and `ManifestStore` for TCK-00287 fixes.
    privileged_dispatcher: PrivilegedDispatcher,

    /// Session endpoint dispatcher with stable token minter.
    ///
    /// The `TokenMinter` uses the same secret as `PrivilegedDispatcher`,
    /// ensuring tokens minted during spawn can be validated here.
    /// The `ManifestStore` is shared with `PrivilegedDispatcher` so manifests
    /// registered during spawn are accessible for tool validation.
    session_dispatcher: SessionDispatcher<InMemoryManifestStore>,
}

impl DispatcherState {
    /// Creates new dispatcher state with shared registries and stable secrets.
    ///
    /// # Arguments
    ///
    /// * `metrics_registry` - Optional metrics registry for observability
    ///
    /// # Security
    ///
    /// - Generates a single HMAC secret for `TokenMinter` at startup
    /// - Shares `TokenMinter` between both dispatchers for token
    ///   minting/validation
    /// - Shares `InMemoryManifestStore` so spawn manifests are visible to
    ///   session handlers
    /// - Registries persist for daemon lifetime
    ///
    /// # TCK-00287 Fixes
    ///
    /// - BLOCKER 1: Uses shared session registry (passed via
    ///   `with_session_registry`)
    /// - BLOCKER 2: Shares `TokenMinter` so spawn can mint tokens
    /// - MAJOR 3: Shares `ManifestStore` so spawn manifests are visible
    ///
    /// # Note
    ///
    /// This constructor creates an internal stub session registry. For
    /// production use with the global daemon session registry, use
    /// `with_session_registry`.
    #[must_use]
    #[allow(dead_code)] // Kept for testing and potential future use
    pub fn new(metrics_registry: Option<SharedMetricsRegistry>) -> Self {
        // TCK-00287 Item 2: Generate a single stable secret at daemon startup.
        // This secret is used for the entire daemon lifetime, ensuring tokens
        // minted on one connection are valid on other connections.
        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));

        // TCK-00287 MAJOR 3: Use shared manifest store.
        // Manifests registered during SpawnEpisode will be visible to SessionDispatcher
        // for tool request validation. If no manifest is registered for a session,
        // tool requests will be denied (fail-closed behavior in handle_request_tool).
        let manifest_store = Arc::new(InMemoryManifestStore::new());

        // TCK-00287: Create session registry (stub for now, use with_session_registry
        // for real)
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

        // TCK-00289: Create shared HolonicClock to prevent mixed clock domain hazard
        // (RSK-2503)
        let clock = Arc::new(
            HolonicClock::new(ClockConfig::default(), None)
                .expect("failed to create default clock"),
        );

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        // TCK-00287 BLOCKER 1 & 2: Create privileged dispatcher with shared state
        let privileged_dispatcher = PrivilegedDispatcher::with_shared_state(
            Arc::clone(&token_minter),
            Arc::clone(&manifest_store),
            session_registry,
            clock,
            Arc::clone(&subscription_registry),
        );

        // Add metrics if provided
        let privileged_dispatcher = if let Some(metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(metrics)
        } else {
            privileged_dispatcher
        };

        // TCK-00287: Create session dispatcher with same token minter and manifest
        // store This ensures:
        // - Tokens minted during SpawnEpisode can be validated
        // - Manifests registered during SpawnEpisode are visible for tool validation
        // TCK-00303: Share subscription registry for HEF resource governance
        let session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_subscription_registry(subscription_registry);

        Self {
            privileged_dispatcher,
            session_dispatcher,
        }
    }

    /// Creates new dispatcher state with a specific session registry.
    ///
    /// # TCK-00287 BLOCKER 1
    ///
    /// This constructor allows using the global `DaemonStateHandle` session
    /// registry instead of an internal stub, ensuring sessions spawned via
    /// IPC are visible to the daemon's persistent state.
    ///
    /// # Arguments
    ///
    /// * `session_registry` - The global session registry from
    ///   `DaemonStateHandle`
    /// * `metrics_registry` - Optional metrics registry for observability
    #[must_use]
    pub fn with_session_registry(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
    ) -> Self {
        // TCK-00287 Item 2: Generate a single stable secret at daemon startup.
        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));

        // TCK-00287 MAJOR 3: Use shared manifest store.
        let manifest_store = Arc::new(InMemoryManifestStore::new());

        // TCK-00289: Create shared HolonicClock to prevent mixed clock domain hazard
        // (RSK-2503)
        let clock = Arc::new(
            HolonicClock::new(ClockConfig::default(), None)
                .expect("failed to create default clock"),
        );

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        // TCK-00287 BLOCKER 1: Create privileged dispatcher with global session
        // registry
        let privileged_dispatcher = PrivilegedDispatcher::with_shared_state(
            Arc::clone(&token_minter),
            Arc::clone(&manifest_store),
            session_registry,
            clock,
            Arc::clone(&subscription_registry),
        );

        // Add metrics if provided
        let privileged_dispatcher = if let Some(metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(metrics)
        } else {
            privileged_dispatcher
        };

        // TCK-00287: Create session dispatcher with same token minter and manifest
        // store
        // TCK-00303: Share subscription registry for HEF resource governance
        let session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_subscription_registry(subscription_registry);

        Self {
            privileged_dispatcher,
            session_dispatcher,
        }
    }

    /// Creates new dispatcher state with persistent ledger components
    /// (TCK-00289).
    ///
    /// # Arguments
    ///
    /// * `session_registry` - Global session registry
    /// * `metrics_registry` - Optional metrics registry
    /// * `sqlite_conn` - Optional `SQLite` connection for persistent ledger. If
    ///   provided, uses durable `Sqlite*` implementations. Otherwise uses
    ///   stubs.
    #[must_use]
    pub fn with_persistence(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
        sqlite_conn: Option<Arc<Mutex<Connection>>>,
    ) -> Self {
        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));
        let manifest_store = Arc::new(InMemoryManifestStore::new());

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        let privileged_dispatcher = if let Some(conn) = sqlite_conn {
            // Use real implementations
            use rand::rngs::OsRng;
            let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);

            let policy_resolver = Arc::new(GovernancePolicyResolver::new());
            let work_registry = Arc::new(SqliteWorkRegistry::new(Arc::clone(&conn)));
            let event_emitter = Arc::new(SqliteLedgerEventEmitter::new(
                Arc::clone(&conn),
                signing_key,
            ));
            let lease_validator = Arc::new(SqliteLeaseValidator::new(Arc::clone(&conn)));
            let episode_runtime = Arc::new(EpisodeRuntime::new(EpisodeRuntimeConfig::default()));
            let clock =
                Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock failed"));

            PrivilegedDispatcher::with_dependencies(
                DecodeConfig::default(),
                policy_resolver,
                work_registry,
                event_emitter,
                episode_runtime,
                session_registry,
                lease_validator,
                clock,
                token_minter.clone(),
                manifest_store.clone(),
                Arc::clone(&subscription_registry),
            )
        } else {
            // Use stubs
            let clock = Arc::new(
                HolonicClock::new(ClockConfig::default(), None)
                    .expect("failed to create default clock"),
            );
            PrivilegedDispatcher::with_shared_state(
                token_minter.clone(),
                manifest_store.clone(),
                session_registry,
                clock,
                Arc::clone(&subscription_registry),
            )
        };

        let privileged_dispatcher = if let Some(metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(metrics)
        } else {
            privileged_dispatcher
        };

        // TCK-00303: Share subscription registry for HEF resource governance
        let session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_subscription_registry(subscription_registry);

        Self {
            privileged_dispatcher,
            session_dispatcher,
        }
    }

    /// Creates new dispatcher state with persistent ledger, CAS, and
    /// `ToolBroker` (TCK-00316).
    ///
    /// # TCK-00316: Session Dispatcher Viability
    ///
    /// This constructor properly wires ALL production dependencies:
    /// - `ledger`: For `EmitEvent` persistence
    /// - `cas`: For `PublishEvidence` artifact storage
    /// - `clock`: For HTF-compliant monotonic timestamps
    /// - `broker`: For `RequestTool` capability/policy validation and execution
    ///
    /// # Arguments
    ///
    /// * `session_registry` - Global session registry
    /// * `metrics_registry` - Optional metrics registry
    /// * `sqlite_conn` - `SQLite` connection for persistent ledger
    /// * `cas_path` - Path for durable CAS storage
    ///
    /// # Panics
    ///
    /// Panics if CAS or clock initialization fails. This is intentional:
    /// production code MUST have these dependencies configured correctly.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // Arc is intentionally moved for shared ownership
    pub fn with_persistence_and_cas(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
        sqlite_conn: Arc<Mutex<Connection>>,
        cas_path: impl AsRef<Path>,
    ) -> Self {
        use rand::rngs::OsRng;

        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));
        let manifest_store = Arc::new(InMemoryManifestStore::new());

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        // TCK-00316: Create durable CAS
        let cas_config = DurableCasConfig::new(cas_path.as_ref().to_path_buf());
        let cas: Arc<dyn ContentAddressedStore> =
            Arc::new(DurableCas::new(cas_config).expect("CAS initialization failed"));

        // TCK-00316: Create ToolBroker with CAS
        let broker: SharedToolBroker<StubManifestLoader> =
            new_shared_broker_with_cas(ToolBrokerConfig::default(), Arc::clone(&cas));

        // TCK-00289: Create shared HolonicClock
        let clock =
            Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock failed"));

        // Use real implementations
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);

        let policy_resolver = Arc::new(GovernancePolicyResolver::new());
        let work_registry = Arc::new(SqliteWorkRegistry::new(Arc::clone(&sqlite_conn)));
        let event_emitter = Arc::new(SqliteLedgerEventEmitter::new(
            Arc::clone(&sqlite_conn),
            signing_key,
        ));
        let lease_validator = Arc::new(SqliteLeaseValidator::new(Arc::clone(&sqlite_conn)));
        
        // TCK-00316: Initialize EpisodeRuntime with CAS for tool execution
        // Also wire clock for time envelope stamping (TCK-00240)
        let episode_runtime = EpisodeRuntime::with_clock(
            EpisodeRuntimeConfig::default(),
            Arc::clone(&clock)
        )
        .with_cas(Arc::clone(&cas));
        let episode_runtime = Arc::new(episode_runtime);

        let privileged_dispatcher = PrivilegedDispatcher::with_dependencies(
            DecodeConfig::default(),
            policy_resolver,
            work_registry,
            Arc::clone(&event_emitter) as Arc<dyn crate::protocol::dispatch::LedgerEventEmitter>,
            Arc::clone(&episode_runtime),
            session_registry,
            lease_validator,
            Arc::clone(&clock),
            token_minter.clone(),
            manifest_store.clone(),
            Arc::clone(&subscription_registry),
        );

        let privileged_dispatcher = if let Some(ref metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(Arc::clone(metrics))
        } else {
            privileged_dispatcher
        };

        // TCK-00316: Wire SessionDispatcher with all production dependencies
        let session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_subscription_registry(subscription_registry)
                .with_ledger(event_emitter)
                .with_cas(cas)
                .with_clock(clock)
                .with_broker(broker)
                .with_runtime(episode_runtime);

        Self {
            privileged_dispatcher,
            session_dispatcher,
        }
    }

    /// Returns a reference to the privileged dispatcher.
    #[must_use]
    pub const fn privileged_dispatcher(&self) -> &PrivilegedDispatcher {
        &self.privileged_dispatcher
    }

    /// Returns a reference to the session dispatcher.
    #[must_use]
    pub const fn session_dispatcher(&self) -> &SessionDispatcher<InMemoryManifestStore> {
        &self.session_dispatcher
    }

    /// Returns the shared subscription registry for connection lifecycle
    /// management.
    ///
    /// # TCK-00303: Connection Cleanup
    ///
    /// When a connection closes, the connection handler MUST call
    /// `unregister_connection(connection_id)` on this registry to free
    /// resources and prevent `DoS` via connection slot exhaustion.
    #[must_use]
    pub const fn subscription_registry(&self) -> &SharedSubscriptionRegistry {
        self.privileged_dispatcher.subscription_registry()
    }
}

/// Shared dispatcher state type alias.
pub type SharedDispatcherState = Arc<DispatcherState>;

/// Key for looking up process runners: (`ProcessId`, `instance_index`).
pub type RunnerKey = (ProcessId, u32);

/// Shared daemon state protected by `Arc<RwLock<...>>`.
pub type SharedState = Arc<DaemonStateHandle>;

/// Handle to daemon state with interior mutability.
pub struct DaemonStateHandle {
    /// The inner mutable state.
    inner: RwLock<DaemonState>,
    /// Shutdown flag (atomic for lock-free checking).
    shutdown: AtomicBool,
    /// Time when the daemon started.
    started_at: DateTime<Utc>,
    /// Schema registry (shared across the daemon lifetime).
    /// Used by future handlers for schema validation (TCK-00181).
    #[allow(dead_code)]
    schema_registry: InMemorySchemaRegistry,
    /// Session registry for RFC-0017 control-plane IPC (TCK-00266).
    /// This is either a persistent or in-memory registry based on
    /// configuration. Will be used when RFC-0017 protobuf IPC is fully
    /// wired up.
    #[allow(dead_code)]
    session_registry: Arc<dyn SessionRegistry>,
    /// Metrics registry for daemon health observability (TCK-00268).
    /// Used by handlers to record IPC request metrics per REQ-DCP-0012.
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    metrics_registry: Option<SharedMetricsRegistry>,
}

impl DaemonStateHandle {
    /// Create a new daemon state handle with an in-memory session registry.
    ///
    /// For production use with persistent sessions, use
    /// [`new_with_persistent_sessions`](Self::new_with_persistent_sessions)
    /// instead.
    #[must_use]
    #[allow(dead_code)] // Used in tests and for in-memory mode
    pub fn new(
        config: EcosystemConfig,
        supervisor: Supervisor,
        schema_registry: InMemorySchemaRegistry,
        metrics_registry: Option<SharedMetricsRegistry>,
    ) -> Self {
        Self {
            inner: RwLock::new(DaemonState {
                supervisor,
                runners: HashMap::new(),
                config,
            }),
            shutdown: AtomicBool::new(false),
            started_at: Utc::now(),
            schema_registry,
            session_registry: Arc::new(InMemorySessionRegistry::new()),
            metrics_registry,
        }
    }

    /// Create a new daemon state handle with a persistent session registry.
    ///
    /// # TCK-00266
    ///
    /// This constructor loads existing session state from the state file
    /// (if it exists) and persists new sessions to disk. Use this for
    /// production deployments where session state should survive daemon
    /// restarts.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file exists but cannot be parsed.
    pub fn new_with_persistent_sessions(
        config: EcosystemConfig,
        supervisor: Supervisor,
        schema_registry: InMemorySchemaRegistry,
        state_file_path: impl AsRef<Path>,
        metrics_registry: Option<SharedMetricsRegistry>,
    ) -> Result<Self, PersistentRegistryError> {
        let session_registry =
            Arc::new(PersistentSessionRegistry::load_from_file(state_file_path)?);

        Ok(Self {
            inner: RwLock::new(DaemonState {
                supervisor,
                runners: HashMap::new(),
                config,
            }),
            shutdown: AtomicBool::new(false),
            started_at: Utc::now(),
            schema_registry,
            session_registry,
            metrics_registry,
        })
    }

    /// Get a reference to the schema registry.
    /// Will be used by future handlers for schema validation (TCK-00181).
    #[must_use]
    #[allow(dead_code)]
    pub const fn schema_registry(&self) -> &InMemorySchemaRegistry {
        &self.schema_registry
    }

    /// Get a reference to the session registry.
    ///
    /// # TCK-00266
    ///
    /// Returns the session registry for RFC-0017 control-plane IPC.
    /// This may be either a persistent or in-memory registry depending
    /// on how the daemon was configured.
    #[must_use]
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    pub fn session_registry(&self) -> &Arc<dyn SessionRegistry> {
        &self.session_registry
    }

    /// Get a reference to the metrics registry.
    ///
    /// # TCK-00268
    ///
    /// Returns the metrics registry for daemon health observability.
    /// Used by handlers to record IPC request metrics per REQ-DCP-0012.
    #[must_use]
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    pub const fn metrics_registry(&self) -> Option<&SharedMetricsRegistry> {
        self.metrics_registry.as_ref()
    }

    /// Get read access to the inner state.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, DaemonState> {
        self.inner.read().await
    }

    /// Get write access to the inner state.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, DaemonState> {
        self.inner.write().await
    }

    /// Check if shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Request shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get the daemon start time.
    #[must_use]
    #[allow(dead_code)] // Part of public API for future use
    pub const fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Get daemon uptime in seconds.
    #[must_use]
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    #[allow(clippy::cast_sign_loss)] // max(0) ensures non-negative
    pub fn uptime_secs(&self) -> u64 {
        let now = Utc::now();
        (now - self.started_at).num_seconds().max(0) as u64
    }
}

/// Inner daemon state (mutable part).
pub struct DaemonState {
    /// The supervisor managing process specs and handles.
    pub supervisor: Supervisor,
    /// Active process runners keyed by (`spec_id`, instance).
    pub runners: HashMap<RunnerKey, ProcessRunner>,
    /// Current configuration.
    #[allow(dead_code)] // Part of public API for future use
    pub config: EcosystemConfig,
}

#[allow(dead_code)] // Methods are part of public API for future use
impl DaemonState {
    /// Get a reference to the supervisor.
    #[must_use]
    pub const fn supervisor(&self) -> &Supervisor {
        &self.supervisor
    }

    /// Get a mutable reference to the supervisor.
    pub const fn supervisor_mut(&mut self) -> &mut Supervisor {
        &mut self.supervisor
    }

    /// Get a runner by process name and instance.
    #[must_use]
    pub fn get_runner(&self, name: &str, instance: u32) -> Option<&ProcessRunner> {
        let spec = self.supervisor.get_spec(name)?;
        self.runners.get(&(spec.id, instance))
    }

    /// Get a mutable runner by process name and instance.
    pub fn get_runner_mut(&mut self, name: &str, instance: u32) -> Option<&mut ProcessRunner> {
        let spec = self.supervisor.get_spec(name)?;
        let key = (spec.id, instance);
        self.runners.get_mut(&key)
    }

    /// Insert a runner.
    pub fn insert_runner(&mut self, spec_id: ProcessId, instance: u32, runner: ProcessRunner) {
        self.runners.insert((spec_id, instance), runner);
    }

    /// Remove a runner.
    pub fn remove_runner(&mut self, spec_id: ProcessId, instance: u32) -> Option<ProcessRunner> {
        self.runners.remove(&(spec_id, instance))
    }

    /// Get all runners for a process name.
    pub fn get_runners(&self, name: &str) -> Vec<&ProcessRunner> {
        let Some(spec) = self.supervisor.get_spec(name) else {
            return Vec::new();
        };

        let spec_id = spec.id;
        let instances = spec.instances;

        (0..instances)
            .filter_map(|i| self.runners.get(&(spec_id, i)))
            .collect()
    }

    /// Iterate over all runners.
    pub fn runners(&self) -> impl Iterator<Item = (&RunnerKey, &ProcessRunner)> {
        self.runners.iter()
    }

    /// Iterate over all runners mutably.
    pub fn runners_mut(&mut self) -> impl Iterator<Item = (&RunnerKey, &mut ProcessRunner)> {
        self.runners.iter_mut()
    }
}
