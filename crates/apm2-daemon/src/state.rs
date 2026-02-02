//! Shared daemon state.
//!
//! Provides thread-safe shared state for the daemon.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use apm2_core::config::EcosystemConfig;
use apm2_core::process::ProcessId;
use apm2_core::process::runner::ProcessRunner;
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_core::supervisor::Supervisor;
use apm2_daemon::episode::{
    InMemorySessionRegistry, PersistentRegistryError, PersistentSessionRegistry,
};
use apm2_daemon::metrics::SharedMetricsRegistry;
use apm2_daemon::session::SessionRegistry;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

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
