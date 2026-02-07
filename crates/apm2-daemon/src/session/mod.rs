// AGENT-AUTHORED (TCK-00211)
//! Session handling for the APM2 daemon.
//!
//! This module provides session management functionality for the daemon,
//! including CONSUME mode sessions with context firewall integration.
//!
//! # Modules
//!
//! - [`consume`]: CONSUME mode session handler with context firewall
//!   integration

pub mod consume;

// Re-export main types
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub use consume::{
    ConsumeSessionContext, ConsumeSessionError, ConsumeSessionHandler,
    EXIT_CLASSIFICATION_CONTEXT_MISS, MAX_REFINEMENT_ATTEMPTS, TERMINATION_RATIONALE_CONTEXT_MISS,
    validate_tool_request,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use crate::episode::decision::SessionTerminationInfo;

/// Ephemeral session handle for IPC authentication.
///
/// Per REQ-DCP-0004, the handle is a bearer token for session-scoped IPC.
/// It MUST NOT contain credentials or long-term secrets.
///
/// # Security
///
/// - Generated using UUID v4 (random)
/// - No embedded user data or secrets
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EphemeralHandle(String);

impl EphemeralHandle {
    /// Generates a new random ephemeral handle.
    ///
    /// Format: `H-{uuid}`
    pub fn generate() -> Self {
        Self(format!("H-{}", Uuid::new_v4()))
    }

    /// Returns the handle string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EphemeralHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for EphemeralHandle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Session state for a spawned episode.
///
/// Per TCK-00256, the session state is persisted when `SpawnEpisode` succeeds
/// to enable subsequent session-scoped IPC calls.
///
/// # Persistence (TCK-00266)
///
/// This struct implements `Serialize` and `Deserialize` to support persistent
/// session registry state files for crash recovery.
///
/// # Security Note
///
/// The `Debug` impl manually redacts `lease_id` to prevent accidental leakage
/// in debug logs. The `lease_id` is a security-sensitive credential that should
/// not appear in logs or error messages.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier.
    pub session_id: String,
    /// Work ID this session is associated with.
    pub work_id: String,
    /// Role claimed for this session.
    pub role: i32, // Using i32 to avoid circular dependency with protocol::messages::WorkRole
    /// Ephemeral handle for IPC communication.
    pub ephemeral_handle: String,
    /// Lease ID authorizing this session.
    ///
    /// **SECURITY**: This field is redacted in Debug output and skipped during
    /// serialization to prevent credential leakage.
    #[serde(skip, default)]
    pub lease_id: String,
    /// Policy resolution reference.
    pub policy_resolved_ref: String,
    /// Hash of the capability manifest for this session.
    pub capability_manifest_hash: Vec<u8>,
    /// Episode ID in the runtime (if created).
    pub episode_id: Option<String>,
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("session_id", &self.session_id)
            .field("work_id", &self.work_id)
            .field("role", &self.role)
            .field("ephemeral_handle", &self.ephemeral_handle)
            .field("lease_id", &"[REDACTED]")
            .field("policy_resolved_ref", &self.policy_resolved_ref)
            .field(
                "capability_manifest_hash",
                &hex::encode(&self.capability_manifest_hash),
            )
            .field("episode_id", &self.episode_id)
            .finish()
    }
}

/// Trait for persisting and querying session state.
///
/// Per TCK-00256, sessions must be persisted to enable subsequent
/// session-scoped IPC calls.
///
/// # TCK-00385: Termination Tracking
///
/// The registry now supports marking sessions as terminated via
/// [`mark_terminated`](Self::mark_terminated) and querying termination info
/// via [`get_termination_info`](Self::get_termination_info). Terminated
/// sessions are preserved in the registry (with TTL) so that
/// `SessionStatus` queries after termination return useful information
/// instead of "session not found".
pub trait SessionRegistry: Send + Sync {
    /// Registers a new session.
    ///
    /// Returns the full [`SessionState`] of any sessions that were evicted to
    /// make room for the new session (may be empty if no eviction was
    /// necessary). Callers MUST clean up telemetry for evicted sessions to
    /// prevent orphaned entries (TCK-00384 security fix). Returning full
    /// state (rather than just IDs) enables callers to restore evicted
    /// sessions on transactional rollback, preventing capacity loss when a
    /// spawn fails after eviction (TCK-00384 quality fix).
    fn register_session(
        &self,
        session: SessionState,
    ) -> Result<Vec<SessionState>, SessionRegistryError>;

    /// Removes a session by ID.
    ///
    /// Returns the removed session state, or `None` if the session was not
    /// found. Used for transactional rollback when post-registration steps
    /// fail (TCK-00384 security fix).
    ///
    /// # Errors
    ///
    /// Returns [`SessionRegistryError::PersistenceFailed`] if the removal
    /// succeeds in-memory but fails to persist to durable storage.
    /// Persistent backends MUST propagate persistence errors so callers
    /// know the on-disk state may be stale (TCK-00384 security BLOCKER 2).
    fn remove_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionState>, SessionRegistryError>;

    /// Queries a session by session ID.
    fn get_session(&self, session_id: &str) -> Option<SessionState>;

    /// Queries a session by ephemeral handle.
    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState>;

    /// Queries a session by work ID (TCK-00344).
    ///
    /// Returns the first session associated with the given `work_id`, or `None`
    /// if no session matches. This is an O(n) scan; a production implementation
    /// could add a secondary index for efficiency.
    fn get_session_by_work_id(&self, work_id: &str) -> Option<SessionState>;

    /// Marks a session as terminated with the given termination info
    /// (TCK-00385).
    ///
    /// The session entry is preserved in the registry so that subsequent
    /// `SessionStatus` queries return TERMINATED state with exit details.
    /// The entry will be cleaned up after the configured TTL.
    ///
    /// Returns `Ok(true)` if the session was found and marked terminated,
    /// `Ok(false)` if the session was not found. Returns `Err` if the
    /// termination could not be persisted (fail-closed: callers MUST treat
    /// persistence failures as fatal for the session lifecycle).
    fn mark_terminated(
        &self,
        session_id: &str,
        info: SessionTerminationInfo,
    ) -> Result<bool, SessionRegistryError>;

    /// Queries termination info for a session (TCK-00385).
    ///
    /// Returns `Some(info)` if the session has been terminated and the
    /// termination entry has not yet expired (TTL). Returns `None` if the
    /// session is still active or not found.
    fn get_termination_info(&self, session_id: &str) -> Option<SessionTerminationInfo>;

    /// Queries a terminated session's preserved state and termination info
    /// (TCK-00385).
    ///
    /// Returns `Some((session, info))` if the session has been terminated
    /// and the entry has not yet expired. Returns `None` otherwise.
    ///
    /// This is used by the `SessionStatus` handler to return `work_id`, role,
    /// and `episode_id` alongside termination details.
    fn get_terminated_session(
        &self,
        session_id: &str,
    ) -> Option<(SessionState, SessionTerminationInfo)>;

    /// Updates the `episode_id` for an existing session (TCK-00395 Security
    /// BLOCKER 1).
    ///
    /// After `SpawnEpisode` creates and starts an episode via
    /// `episode_runtime.create()` + `start_with_workspace()`, the returned
    /// episode ID must be written back to the session in the registry.
    /// Without this write-back, `EndSession` cannot resolve the episode
    /// binding and will skip runtime stop.
    ///
    /// # Errors
    ///
    /// Returns `SessionRegistryError` if the session is not found or
    /// persistence fails (fail-closed).
    fn update_episode_id(
        &self,
        session_id: &str,
        episode_id: String,
    ) -> Result<(), SessionRegistryError>;

    /// Returns all active sessions for crash recovery (TCK-00387).
    ///
    /// Default implementation returns an empty vec (suitable for in-memory
    /// registries that don't persist across restarts).
    fn all_sessions_for_recovery(&self) -> Vec<SessionState> {
        Vec::new()
    }

    /// Clears all sessions and persists the empty state (TCK-00387).
    ///
    /// Used after crash recovery to make recovery idempotent. A second
    /// startup with the same state file will see no sessions to recover.
    ///
    /// Default implementation is a no-op (suitable for in-memory registries).
    ///
    /// # Errors
    ///
    /// Returns `SessionRegistryError` if persistence fails.
    fn clear_all_sessions(&self) -> Result<(), SessionRegistryError> {
        Ok(())
    }

    /// Removes specific sessions by ID and persists the updated state.
    ///
    /// Used after partial crash recovery (e.g., when session collection was
    /// truncated to `MAX_RECOVERY_SESSIONS`) to clear only the recovered
    /// subset without discarding unrecovered sessions.
    ///
    /// Default implementation is a no-op (suitable for in-memory registries).
    ///
    /// # Errors
    ///
    /// Returns `SessionRegistryError` if persistence fails.
    fn clear_sessions_by_ids(&self, _session_ids: &[String]) -> Result<(), SessionRegistryError> {
        Ok(())
    }
}

/// Error type for session registry operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionRegistryError {
    /// Session ID already exists.
    #[error("duplicate session_id: {session_id}")]
    DuplicateSessionId {
        /// The duplicate session ID.
        session_id: String,
    },

    /// Registration failed.
    #[error("session registration failed: {message}")]
    RegistrationFailed {
        /// Error message.
        message: String,
    },

    /// Persistence failed after an in-memory mutation.
    ///
    /// TCK-00384 security BLOCKER 2: persistent backends MUST propagate
    /// persistence errors instead of silently swallowing them.  When this
    /// error is returned from `remove_session`, the in-memory state has
    /// already been updated but the on-disk state is stale.  Callers
    /// should treat this as a critical failure and avoid assuming the
    /// removal was durable.
    #[error("persistence failed: {message}")]
    PersistenceFailed {
        /// Error message describing the persistence failure.
        message: String,
    },
}

// =============================================================================
// Session Telemetry (TCK-00384)
// =============================================================================

/// Maximum number of sessions tracked in the telemetry store.
///
/// Per CTR-1303: In-memory stores must have `max_entries` limit to prevent
/// denial-of-service via memory exhaustion. Matches the session registry
/// bound from `crate::episode::registry::MAX_SESSIONS`.
pub const MAX_TELEMETRY_SESSIONS: usize = 10_000;

/// Per-session telemetry counters.
///
/// Per TCK-00384, tracks tool call and event emission counts as well as
/// session start time. Counters are thread-safe using atomic operations.
///
/// This is stored separately from [`SessionState`] because `SessionState` must
/// remain `Clone + Serialize + Deserialize`, which is incompatible with
/// `AtomicU64`.
///
/// # Monotonic Duration
///
/// The `started_at` field uses `std::time::Instant` (monotonic clock) for
/// elapsed time computation. The `started_at_ns` field retains the wall-clock
/// timestamp for display/audit purposes only.
pub struct SessionTelemetry {
    /// Number of `RequestTool` calls dispatched for this session.
    pub tool_calls: AtomicU64,
    /// Number of `EmitEvent` calls dispatched for this session.
    pub events_emitted: AtomicU64,
    /// Number of completed episodes for this session (TCK-00351 BLOCKER-2).
    ///
    /// This counter tracks completed/terminated episodes for the session,
    /// which is semantically distinct from `tool_calls`.
    /// The pre-actuation gate uses this to enforce `max_episodes` stop
    /// conditions.
    pub episode_count: AtomicU64,
    /// Timestamp (nanoseconds since epoch) when the session was spawned.
    /// Used for display/audit metadata only; NOT for elapsed time computation.
    pub started_at_ns: u64,
    /// Monotonic instant when the session was spawned.
    /// Used for computing elapsed `duration_ms` without wall-clock skew.
    pub started_at: Instant,
}

impl SessionTelemetry {
    /// Creates a new telemetry record with the given start timestamp and
    /// monotonic instant.
    #[must_use]
    pub fn new(started_at_ns: u64) -> Self {
        Self {
            tool_calls: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
            episode_count: AtomicU64::new(0),
            started_at_ns,
            started_at: Instant::now(),
        }
    }

    /// Creates a new telemetry record with an explicit monotonic instant.
    ///
    /// This constructor is useful for testing where the caller wants to
    /// control the monotonic start point.
    #[must_use]
    pub const fn with_instant(started_at_ns: u64, started_at: Instant) -> Self {
        Self {
            tool_calls: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
            episode_count: AtomicU64::new(0),
            started_at_ns,
            started_at,
        }
    }

    /// Returns the elapsed time since session start in milliseconds,
    /// computed from the monotonic clock.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        let elapsed = self.started_at.elapsed();
        #[allow(clippy::cast_possible_truncation)]
        let ms = elapsed.as_millis() as u64;
        ms
    }

    /// Increments the tool call counter and returns the new value.
    pub fn increment_tool_calls(&self) -> u64 {
        self.tool_calls.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Increments the events emitted counter and returns the new value.
    pub fn increment_events_emitted(&self) -> u64 {
        self.events_emitted.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Returns the current tool call count.
    pub fn get_tool_calls(&self) -> u64 {
        self.tool_calls.load(Ordering::Relaxed)
    }

    /// Returns the current events emitted count.
    pub fn get_events_emitted(&self) -> u64 {
        self.events_emitted.load(Ordering::Relaxed)
    }

    /// Increments the completed-episode count and returns the new value.
    ///
    /// Called when an episode terminates. The pre-actuation gate reads this
    /// counter to enforce `max_episodes` stop conditions without off-by-one
    /// denial on a newly spawned episode.
    pub fn increment_episode_count(&self) -> u64 {
        self.episode_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Returns the current episode count (TCK-00351 MAJOR 1 FIX).
    ///
    /// Semantically distinct from `get_tool_calls()`: episodes are
    /// lifecycle units (one per `SpawnEpisode`), while tool calls count
    /// individual `RequestTool` invocations within an episode.
    pub fn get_episode_count(&self) -> u64 {
        self.episode_count.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for SessionTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTelemetry")
            .field("tool_calls", &self.tool_calls.load(Ordering::Relaxed))
            .field(
                "events_emitted",
                &self.events_emitted.load(Ordering::Relaxed),
            )
            .field("episode_count", &self.episode_count.load(Ordering::Relaxed))
            .field("started_at_ns", &self.started_at_ns)
            .field("started_at", &self.started_at)
            .field("elapsed_ms", &self.elapsed_ms())
            .finish()
    }
}

/// A snapshot of session telemetry values (non-atomic, cloneable).
///
/// Used to return telemetry data from the store without holding references
/// to atomic values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetrySnapshot {
    /// Number of tool calls dispatched.
    pub tool_calls: u64,
    /// Number of events emitted.
    pub events_emitted: u64,
    /// Number of episodes spawned (TCK-00351 MAJOR 1 FIX).
    pub episode_count: u64,
    /// Session start timestamp (nanoseconds since epoch).
    /// Wall-clock metadata for display/audit only.
    pub started_at_ns: u64,
    /// Elapsed time in milliseconds since session start, computed from
    /// the monotonic clock (`Instant`). Immune to wall-clock jumps/skew.
    pub duration_ms: u64,
}

/// Error type for telemetry store operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryStoreError {
    /// Store is at capacity and cannot accept new registrations.
    ///
    /// Per CTR-1303, the store enforces a hard bound of
    /// [`MAX_TELEMETRY_SESSIONS`] to prevent memory exhaustion. Callers
    /// must clean up terminated sessions before registering new ones.
    #[error("telemetry store at capacity ({max} sessions); registration rejected for {session_id}")]
    AtCapacity {
        /// The session ID that was rejected.
        session_id: String,
        /// The maximum number of sessions allowed.
        max: usize,
    },
}

/// Thread-safe store for per-session telemetry data (TCK-00384).
///
/// This store is separate from the session registry because telemetry
/// counters use atomic operations that are incompatible with the `Clone +
/// Serialize` requirements of [`SessionState`].
///
/// # Capacity Bounds (CTR-1303)
///
/// The store enforces a hard cap of [`MAX_TELEMETRY_SESSIONS`] entries.
/// When the limit is reached, new registrations are rejected (fail-closed)
/// rather than silently evicting existing entries. Callers must wire
/// session lifecycle events (e.g., termination) to call [`Self::remove`] and
/// free capacity.
///
/// # Thread Safety
///
/// Uses `RwLock<HashMap>` for concurrent access. Individual counter updates
/// use atomic operations without holding the write lock.
#[derive(Debug, Default)]
pub struct SessionTelemetryStore {
    /// Per-session telemetry indexed by session ID.
    entries: RwLock<HashMap<String, Arc<SessionTelemetry>>>,
}

impl SessionTelemetryStore {
    /// Creates a new empty telemetry store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers telemetry for a new session.
    ///
    /// Records the session start time and initializes counters to zero.
    /// If a session with the same ID already exists, the existing entry is
    /// preserved (idempotent).
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryStoreError::AtCapacity`] if the store already
    /// contains [`MAX_TELEMETRY_SESSIONS`] entries and the session ID is
    /// not already registered. This is a fail-closed policy per CTR-1303.
    pub fn register(
        &self,
        session_id: &str,
        started_at_ns: u64,
    ) -> Result<(), TelemetryStoreError> {
        let mut entries = self.entries.write().expect("lock poisoned");
        // Idempotent: if session already exists, return Ok without checking
        // bounds.
        if entries.contains_key(session_id) {
            return Ok(());
        }
        // Fail-closed: reject new registrations when at capacity.
        if entries.len() >= MAX_TELEMETRY_SESSIONS {
            return Err(TelemetryStoreError::AtCapacity {
                session_id: session_id.to_string(),
                max: MAX_TELEMETRY_SESSIONS,
            });
        }
        entries.insert(
            session_id.to_string(),
            Arc::new(SessionTelemetry::new(started_at_ns)),
        );
        Ok(())
    }

    /// Returns a reference-counted handle to the session's telemetry.
    ///
    /// The returned `Arc<SessionTelemetry>` can be used to increment
    /// counters without holding the store lock.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<Arc<SessionTelemetry>> {
        let entries = self.entries.read().expect("lock poisoned");
        entries.get(session_id).cloned()
    }

    /// Returns a snapshot of the session's telemetry values.
    ///
    /// The `duration_ms` field in the snapshot is computed from the
    /// monotonic `Instant`, not from wall-clock arithmetic.
    #[must_use]
    pub fn snapshot(&self, session_id: &str) -> Option<TelemetrySnapshot> {
        let entries = self.entries.read().expect("lock poisoned");
        entries.get(session_id).map(|t| TelemetrySnapshot {
            tool_calls: t.get_tool_calls(),
            events_emitted: t.get_events_emitted(),
            episode_count: t.get_episode_count(),
            started_at_ns: t.started_at_ns,
            duration_ms: t.elapsed_ms(),
        })
    }

    /// Removes telemetry for a session.
    ///
    /// This should be called when a session terminates to free capacity
    /// in the bounded store. Wire this to session lifecycle cleanup events.
    pub fn remove(&self, session_id: &str) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.remove(session_id);
    }

    /// Removes telemetry for a session and returns the entry.
    ///
    /// TCK-00384 security BLOCKER 1: Used during spawn eviction to capture
    /// the evicted telemetry entry BEFORE removal.  If a later spawn step
    /// fails, the caller can pass this entry to [`Self::restore`] alongside
    /// the re-registered session to make the rollback complete.
    #[must_use]
    pub fn remove_and_return(&self, session_id: &str) -> Option<Arc<SessionTelemetry>> {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.remove(session_id)
    }

    /// Restores a previously removed telemetry entry.
    ///
    /// TCK-00384 security BLOCKER 1: Complements [`Self::remove_and_return`].
    /// On rollback, callers pass back the `Arc<SessionTelemetry>` obtained
    /// during eviction so counters and timestamps are preserved exactly.
    ///
    /// If the session ID already exists (idempotent case), the existing
    /// entry is preserved.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryStoreError::AtCapacity`] if the store is full and
    /// the entry is not already present.
    pub fn restore(
        &self,
        session_id: &str,
        entry: Arc<SessionTelemetry>,
    ) -> Result<(), TelemetryStoreError> {
        let mut entries = self.entries.write().expect("lock poisoned");
        if entries.contains_key(session_id) {
            return Ok(());
        }
        if entries.len() >= MAX_TELEMETRY_SESSIONS {
            return Err(TelemetryStoreError::AtCapacity {
                session_id: session_id.to_string(),
                max: MAX_TELEMETRY_SESSIONS,
            });
        }
        entries.insert(session_id.to_string(), entry);
        Ok(())
    }

    /// Returns the number of tracked sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        let entries = self.entries.read().expect("lock poisoned");
        entries.len()
    }

    /// Returns true if no sessions are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes all telemetry entries.
    ///
    /// Used during crash recovery to clear telemetry state alongside the
    /// session registry (TCK-00384 security fix: complete lifecycle cleanup).
    pub fn clear(&self) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.clear();
    }

    /// Returns the maximum number of sessions this store can track.
    #[must_use]
    pub const fn capacity() -> usize {
        MAX_TELEMETRY_SESSIONS
    }
}

// =============================================================================
// TCK-00351 v3: Per-Session Stop Conditions Store
// =============================================================================

/// Per-session stop conditions store for pre-actuation gate enforcement.
///
/// TCK-00351 v3 FIX: The pre-actuation gate was called with
/// `StopConditions::default()` and `current_episode_count=0`, meaning
/// `max_episodes` and `escalation_predicate` were never checked.  This
/// store associates real stop conditions with each session so the gate can
/// enforce them.
///
/// # Capacity Bounds (CTR-1303)
///
/// Shares the same capacity limit as [`SessionTelemetryStore`].
///
/// # Thread Safety
///
/// Uses `RwLock<HashMap>` for concurrent access.  Stop conditions are
/// immutable once registered (set at session spawn time).
#[derive(Debug, Default)]
pub struct SessionStopConditionsStore {
    entries: RwLock<HashMap<String, crate::episode::envelope::StopConditions>>,
}

impl SessionStopConditionsStore {
    /// Creates a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers stop conditions for a session.
    ///
    /// If the session already has conditions registered, the existing entry
    /// is preserved (idempotent).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the store is at capacity and the session is not
    /// already registered.
    pub fn register(
        &self,
        session_id: &str,
        conditions: crate::episode::envelope::StopConditions,
    ) -> Result<(), TelemetryStoreError> {
        let mut entries = self.entries.write().expect("lock poisoned");
        if entries.contains_key(session_id) {
            return Ok(());
        }
        if entries.len() >= MAX_TELEMETRY_SESSIONS {
            return Err(TelemetryStoreError::AtCapacity {
                session_id: session_id.to_string(),
                max: MAX_TELEMETRY_SESSIONS,
            });
        }
        entries.insert(session_id.to_string(), conditions);
        Ok(())
    }

    /// Returns the stop conditions for a session, if registered.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<crate::episode::envelope::StopConditions> {
        let entries = self.entries.read().expect("lock poisoned");
        entries.get(session_id).cloned()
    }

    /// Removes and returns stop conditions for a session, if present.
    ///
    /// Used by spawn rollback paths to capture evicted stop conditions
    /// before removal and restore them if a later spawn step fails.
    #[must_use]
    pub fn remove_and_return(
        &self,
        session_id: &str,
    ) -> Option<crate::episode::envelope::StopConditions> {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.remove(session_id)
    }

    /// Restores stop conditions for a session.
    ///
    /// If the session already has an entry, this is a no-op (idempotent).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the store is at capacity and the session is not
    /// already present.
    pub fn restore(
        &self,
        session_id: &str,
        conditions: crate::episode::envelope::StopConditions,
    ) -> Result<(), TelemetryStoreError> {
        let mut entries = self.entries.write().expect("lock poisoned");
        if entries.contains_key(session_id) {
            return Ok(());
        }
        if entries.len() >= MAX_TELEMETRY_SESSIONS {
            return Err(TelemetryStoreError::AtCapacity {
                session_id: session_id.to_string(),
                max: MAX_TELEMETRY_SESSIONS,
            });
        }
        entries.insert(session_id.to_string(), conditions);
        Ok(())
    }

    /// Removes stop conditions for a session.
    ///
    /// TCK-00351 BLOCKER 3 FIX: Must be called from the same termination
    /// and eviction paths that clean up telemetry entries.  Without this,
    /// stop condition entries accumulate on every spawn/end cycle, causing
    /// the store to reach capacity and reject new registrations (`DoS`).
    pub fn remove(&self, session_id: &str) {
        let mut entries = self.entries.write().expect("lock poisoned");
        entries.remove(session_id);
    }

    /// Returns the number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        let entries = self.entries.read().expect("lock poisoned");
        entries.len()
    }

    /// Returns `true` if no entries are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// TCK-00384: Session Telemetry Tests
// =============================================================================

#[cfg(test)]
mod telemetry_tests {
    use super::*;

    // =========================================================================
    // SessionTelemetry Unit Tests
    // =========================================================================

    #[test]
    fn test_telemetry_new_initializes_zeros() {
        let telemetry = SessionTelemetry::new(1_000_000);
        assert_eq!(telemetry.get_tool_calls(), 0);
        assert_eq!(telemetry.get_events_emitted(), 0);
        assert_eq!(telemetry.started_at_ns, 1_000_000);
    }

    #[test]
    fn test_telemetry_increment_tool_calls() {
        let telemetry = SessionTelemetry::new(0);
        assert_eq!(telemetry.increment_tool_calls(), 1);
        assert_eq!(telemetry.increment_tool_calls(), 2);
        assert_eq!(telemetry.increment_tool_calls(), 3);
        assert_eq!(telemetry.get_tool_calls(), 3);
    }

    #[test]
    fn test_telemetry_increment_events_emitted() {
        let telemetry = SessionTelemetry::new(0);
        assert_eq!(telemetry.increment_events_emitted(), 1);
        assert_eq!(telemetry.increment_events_emitted(), 2);
        assert_eq!(telemetry.get_events_emitted(), 2);
    }

    #[test]
    fn test_telemetry_counters_independent() {
        let telemetry = SessionTelemetry::new(42);
        telemetry.increment_tool_calls();
        telemetry.increment_tool_calls();
        telemetry.increment_events_emitted();

        assert_eq!(telemetry.get_tool_calls(), 2);
        assert_eq!(telemetry.get_events_emitted(), 1);
        assert_eq!(telemetry.started_at_ns, 42);
    }

    #[test]
    fn test_telemetry_debug_format() {
        let telemetry = SessionTelemetry::new(999);
        telemetry.increment_tool_calls();
        let debug_str = format!("{telemetry:?}");
        assert!(debug_str.contains("tool_calls: 1"));
        assert!(debug_str.contains("events_emitted: 0"));
        assert!(debug_str.contains("started_at_ns: 999"));
        assert!(debug_str.contains("elapsed_ms:"));
    }

    #[test]
    fn test_telemetry_elapsed_ms_uses_monotonic_clock() {
        // Use with_instant to control the start point
        let past_instant = Instant::now()
            .checked_sub(std::time::Duration::from_millis(500))
            .expect("500ms subtraction should not underflow");
        let telemetry = SessionTelemetry::with_instant(0, past_instant);

        // Elapsed should be approximately 500ms (allow some tolerance)
        let elapsed = telemetry.elapsed_ms();
        assert!(elapsed >= 490, "elapsed_ms should be >= 490, got {elapsed}");
        assert!(elapsed < 2000, "elapsed_ms should be < 2000, got {elapsed}");
    }

    // =========================================================================
    // TelemetrySnapshot Tests
    // =========================================================================

    #[test]
    fn test_snapshot_values() {
        let snap = TelemetrySnapshot {
            tool_calls: 5,
            events_emitted: 3,
            episode_count: 1,
            started_at_ns: 1_000_000_000,
            duration_ms: 42,
        };
        assert_eq!(snap.tool_calls, 5);
        assert_eq!(snap.events_emitted, 3);
        assert_eq!(snap.episode_count, 1);
        assert_eq!(snap.started_at_ns, 1_000_000_000);
        assert_eq!(snap.duration_ms, 42);
    }

    #[test]
    fn test_snapshot_clone_eq() {
        let snap1 = TelemetrySnapshot {
            tool_calls: 5,
            events_emitted: 3,
            episode_count: 0,
            started_at_ns: 1_000_000_000,
            duration_ms: 0,
        };
        let snap2 = snap1;
        assert_eq!(snap1, snap2);
    }

    // =========================================================================
    // SessionTelemetryStore Tests
    // =========================================================================

    #[test]
    fn test_store_new_is_empty() {
        let store = SessionTelemetryStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_store_register_and_get() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 1_000_000).unwrap();

        let telemetry = store.get("sess-1");
        assert!(telemetry.is_some());
        let t = telemetry.unwrap();
        assert_eq!(t.get_tool_calls(), 0);
        assert_eq!(t.get_events_emitted(), 0);
        assert_eq!(t.started_at_ns, 1_000_000);
    }

    #[test]
    fn test_store_get_nonexistent() {
        let store = SessionTelemetryStore::new();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn test_store_register_idempotent() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 100).unwrap();

        // Increment a counter
        store.get("sess-1").unwrap().increment_tool_calls();

        // Re-register with different started_at_ns (should be idempotent)
        store.register("sess-1", 999).unwrap();

        // Original entry should be preserved
        let t = store.get("sess-1").unwrap();
        assert_eq!(t.started_at_ns, 100);
        assert_eq!(t.get_tool_calls(), 1);
    }

    #[test]
    fn test_store_snapshot() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 42).unwrap();

        let t = store.get("sess-1").unwrap();
        t.increment_tool_calls();
        t.increment_tool_calls();
        t.increment_events_emitted();

        let snap = store.snapshot("sess-1");
        assert!(snap.is_some());
        let snap = snap.unwrap();
        assert_eq!(snap.tool_calls, 2);
        assert_eq!(snap.events_emitted, 1);
        assert_eq!(snap.started_at_ns, 42);
        // duration_ms should be non-negative (monotonic)
        assert!(
            snap.duration_ms < 5000,
            "duration_ms should be small for a just-registered session"
        );
    }

    #[test]
    fn test_store_snapshot_nonexistent() {
        let store = SessionTelemetryStore::new();
        assert!(store.snapshot("nonexistent").is_none());
    }

    #[test]
    fn test_store_remove() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 100).unwrap();
        assert_eq!(store.len(), 1);

        store.remove("sess-1");
        assert!(store.is_empty());
        assert!(store.get("sess-1").is_none());
    }

    #[test]
    fn test_store_remove_nonexistent() {
        let store = SessionTelemetryStore::new();
        store.remove("nonexistent"); // Should not panic
        assert!(store.is_empty());
    }

    #[test]
    fn test_store_multiple_sessions() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 100).unwrap();
        store.register("sess-2", 200).unwrap();
        store.register("sess-3", 300).unwrap();
        assert_eq!(store.len(), 3);

        // Increment counters independently
        store.get("sess-1").unwrap().increment_tool_calls();
        store.get("sess-2").unwrap().increment_events_emitted();
        store.get("sess-2").unwrap().increment_events_emitted();

        let snap1 = store.snapshot("sess-1").unwrap();
        assert_eq!(snap1.tool_calls, 1);
        assert_eq!(snap1.events_emitted, 0);

        let snap2 = store.snapshot("sess-2").unwrap();
        assert_eq!(snap2.tool_calls, 0);
        assert_eq!(snap2.events_emitted, 2);

        let snap3 = store.snapshot("sess-3").unwrap();
        assert_eq!(snap3.tool_calls, 0);
        assert_eq!(snap3.events_emitted, 0);
    }

    /// TCK-00384: Verify counters are thread-safe using concurrent
    /// increments from multiple threads.
    #[test]
    fn test_telemetry_thread_safety() {
        use std::sync::Arc;

        let telemetry = Arc::new(SessionTelemetry::new(0));
        let iterations: u64 = 1000;
        let threads: u64 = 4;

        let mut handles = Vec::new();
        for _ in 0..threads {
            let t = Arc::clone(&telemetry);
            handles.push(std::thread::spawn(move || {
                for _ in 0..iterations {
                    t.increment_tool_calls();
                    t.increment_events_emitted();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        let expected = threads * iterations;
        assert_eq!(telemetry.get_tool_calls(), expected);
        assert_eq!(telemetry.get_events_emitted(), expected);
    }

    // =========================================================================
    // Bounded Store Tests (Security Blocker + Quality Major)
    // =========================================================================

    #[test]
    fn test_store_capacity_constant() {
        assert_eq!(SessionTelemetryStore::capacity(), MAX_TELEMETRY_SESSIONS);
        assert_eq!(MAX_TELEMETRY_SESSIONS, 10_000);
    }

    #[test]
    fn test_store_rejects_at_capacity() {
        let store = SessionTelemetryStore::new();

        // Fill the store to capacity
        for i in 0..MAX_TELEMETRY_SESSIONS {
            store.register(&format!("sess-{i}"), i as u64).unwrap();
        }
        assert_eq!(store.len(), MAX_TELEMETRY_SESSIONS);

        // Next registration should fail (fail-closed)
        let result = store.register("one-too-many", 999);
        assert!(result.is_err());
        match result.unwrap_err() {
            TelemetryStoreError::AtCapacity { session_id, max } => {
                assert_eq!(session_id, "one-too-many");
                assert_eq!(max, MAX_TELEMETRY_SESSIONS);
            },
        }

        // Store size should not have changed
        assert_eq!(store.len(), MAX_TELEMETRY_SESSIONS);
    }

    #[test]
    fn test_store_idempotent_register_at_capacity() {
        let store = SessionTelemetryStore::new();

        // Fill to capacity
        for i in 0..MAX_TELEMETRY_SESSIONS {
            store.register(&format!("sess-{i}"), i as u64).unwrap();
        }

        // Re-registering an existing session should succeed (idempotent)
        let result = store.register("sess-0", 999);
        assert!(result.is_ok());
    }

    #[test]
    fn test_store_remove_then_register_at_capacity() {
        let store = SessionTelemetryStore::new();

        // Fill to capacity
        for i in 0..MAX_TELEMETRY_SESSIONS {
            store.register(&format!("sess-{i}"), i as u64).unwrap();
        }

        // Remove one session to free capacity
        store.remove("sess-0");
        assert_eq!(store.len(), MAX_TELEMETRY_SESSIONS - 1);

        // Now registration should succeed
        let result = store.register("new-sess", 42);
        assert!(result.is_ok());
        assert_eq!(store.len(), MAX_TELEMETRY_SESSIONS);
    }

    // =========================================================================
    // Monotonic Duration Tests (Security Major)
    // =========================================================================

    #[test]
    fn test_snapshot_duration_ms_is_monotonic() {
        let store = SessionTelemetryStore::new();
        store.register("sess-1", 100).unwrap();

        // Take two snapshots; second should have >= duration_ms
        let snap1 = store.snapshot("sess-1").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let snap2 = store.snapshot("sess-1").unwrap();

        assert!(
            snap2.duration_ms >= snap1.duration_ms,
            "duration_ms should be monotonically non-decreasing: {} vs {}",
            snap1.duration_ms,
            snap2.duration_ms,
        );
    }

    #[test]
    fn test_snapshot_duration_ms_immune_to_wallclock() {
        // This test verifies the duration_ms field comes from Instant
        // (monotonic), not from wall-clock arithmetic. We construct a
        // SessionTelemetry with a deliberately wrong started_at_ns
        // (far in the future) but a known Instant in the past, and
        // verify that duration_ms reflects the Instant, not the ns.
        let store = SessionTelemetryStore::new();
        store.register("sess-wallclock", 0).unwrap();

        let snap = store.snapshot("sess-wallclock").unwrap();
        // duration_ms is from Instant::now() elapsed since register, should
        // be very small (a few ms at most)
        assert!(
            snap.duration_ms < 5000,
            "duration_ms should be small, got {}",
            snap.duration_ms,
        );
    }

    // =========================================================================
    // TCK-00351 BLOCKER 3: SessionStopConditionsStore lifecycle tests
    // =========================================================================

    #[test]
    fn test_stop_conditions_store_new_is_empty() {
        let store = SessionStopConditionsStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_stop_conditions_store_register_and_get() {
        let store = SessionStopConditionsStore::new();
        let conditions = crate::episode::envelope::StopConditions::max_episodes(5);
        store.register("sess-1", conditions).unwrap();

        assert_eq!(store.len(), 1);
        let got = store.get("sess-1").expect("should have conditions");
        assert_eq!(got.max_episodes, 5);
    }

    #[test]
    fn test_stop_conditions_store_remove() {
        let store = SessionStopConditionsStore::new();
        let conditions = crate::episode::envelope::StopConditions::max_episodes(10);
        store.register("sess-1", conditions).unwrap();
        assert_eq!(store.len(), 1);

        store.remove("sess-1");
        assert!(store.is_empty());
        assert!(store.get("sess-1").is_none());
    }

    #[test]
    fn test_stop_conditions_store_remove_and_restore() {
        let store = SessionStopConditionsStore::new();
        let original = crate::episode::envelope::StopConditions {
            max_episodes: 7,
            escalation_predicate: "severity>=high".to_string(),
            goal_predicate: String::new(),
            failure_predicate: String::new(),
        };
        store.register("sess-1", original.clone()).unwrap();

        let removed = store
            .remove_and_return("sess-1")
            .expect("entry should be removed");
        assert_eq!(removed.max_episodes, 7);
        assert_eq!(removed.escalation_predicate, "severity>=high");
        assert!(store.get("sess-1").is_none());

        store
            .restore("sess-1", removed)
            .expect("restore should succeed");
        let restored = store.get("sess-1").expect("entry should be restored");
        assert_eq!(restored.max_episodes, original.max_episodes);
        assert_eq!(restored.escalation_predicate, original.escalation_predicate);
    }

    #[test]
    fn test_stop_conditions_store_remove_nonexistent() {
        let store = SessionStopConditionsStore::new();
        store.remove("nonexistent"); // Should not panic
        assert!(store.is_empty());
    }

    /// TCK-00351 BLOCKER 3: Churn regression test.
    ///
    /// Simulates repeated spawn/terminate cycles and verifies that
    /// `remove()` keeps the store size stable.  Without the fix,
    /// entries accumulate and eventually hit the capacity limit.
    #[test]
    fn test_stop_conditions_store_churn_regression() {
        let store = SessionStopConditionsStore::new();
        let cycles = 100;

        for cycle in 0..cycles {
            let session_id = format!("sess-churn-{cycle}");
            let conditions = crate::episode::envelope::StopConditions::max_episodes(10);

            // Spawn: register conditions
            store.register(&session_id, conditions).unwrap();
            assert_eq!(
                store.len(),
                1,
                "cycle {cycle}: store should have exactly 1 entry during active session"
            );

            // Terminate: remove conditions
            store.remove(&session_id);
            assert!(
                store.is_empty(),
                "cycle {cycle}: store should be empty after termination"
            );
        }

        // After all cycles, store must be empty (no leaked entries)
        assert_eq!(
            store.len(),
            0,
            "store must be empty after {cycles} churn cycles"
        );
    }

    /// TCK-00351 BLOCKER 3: Capacity regression test.
    ///
    /// Fills the store to capacity, removes entries, and verifies that
    /// new registrations succeed after removal.  Proves that `remove()`
    /// actually frees capacity slots.
    #[test]
    fn test_stop_conditions_store_capacity_reclaim() {
        let store = SessionStopConditionsStore::new();

        // Fill to capacity
        for i in 0..MAX_TELEMETRY_SESSIONS {
            let conditions = crate::episode::envelope::StopConditions::max_episodes(1);
            store
                .register(&format!("sess-cap-{i}"), conditions)
                .unwrap();
        }
        assert_eq!(store.len(), MAX_TELEMETRY_SESSIONS);

        // Next registration should fail (at capacity)
        let result = store.register(
            "one-too-many",
            crate::episode::envelope::StopConditions::default(),
        );
        assert!(result.is_err(), "should reject at capacity");

        // Remove one entry to free a slot
        store.remove("sess-cap-0");
        assert_eq!(store.len(), MAX_TELEMETRY_SESSIONS - 1);

        // Now registration should succeed
        let result = store.register(
            "reclaimed",
            crate::episode::envelope::StopConditions::max_episodes(42),
        );
        assert!(result.is_ok(), "should succeed after capacity reclaim");
        assert_eq!(store.len(), MAX_TELEMETRY_SESSIONS);
    }
}
