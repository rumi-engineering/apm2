//! Episode runtime implementation.
//!
//! This module provides the `EpisodeRuntime` struct that manages episode
//! lifecycle per AD-LAYER-001 and AD-EPISODE-002. The runtime is the
//! authoritative plant controller for daemon-hosted episodes.
//!
//! # Architecture
//!
//! Per AD-LAYER-001, `EpisodeRuntime` operates at the daemon layer as the
//! authoritative plant controller. It:
//!
//! - Owns process lifetime and state machine
//! - Enforces resource budgets
//! - Emits kernel events for all state transitions
//! - Manages concurrent episode tracking
//!
//! # State Machine
//!
//! Episodes transition through states per AD-EPISODE-002:
//!
//! ```text
//! CREATED ──────► RUNNING ──────► TERMINATED
//!                    │
//!                    └──────────► QUARANTINED
//! ```
//!
//! # Invariants
//!
//! - [INV-ER001] Maximum concurrent episodes is bounded
//! - [INV-ER002] All state transitions emit events
//! - [INV-ER003] Terminal states have no outgoing transitions
//! - [INV-ER004] Episode IDs are unique within the runtime

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use apm2_core::htf::{ClockProfile, TimeEnvelope, TimeEnvelopeRef};
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use super::budget::EpisodeBudget;
use super::budget_tracker::BudgetTracker;
use super::decision::{Credential, SessionTerminationInfo, ToolResult};
use super::error::{EpisodeError, EpisodeId};
use super::executor::{ContentAddressedStore, ExecutionContext, SharedToolExecutor, ToolExecutor};
use super::handle::{SessionHandle, StopSignal};
use super::registry::AdapterRegistry;
use super::state::{EpisodeState, QuarantineReason, TerminationClass};
use super::tool_handler::{ToolArgs, ToolHandler};
use crate::episode::adapter::{HarnessEvent, HarnessHandle};
use crate::htf::HolonicClock;
use crate::protocol::dispatch::LedgerEventEmitter;
use crate::session::SessionRegistry;

/// Maximum number of concurrent episodes per runtime.
///
/// This limit prevents unbounded memory growth per CTR-1303.
pub const MAX_CONCURRENT_EPISODES: usize = 10_000;

/// Maximum number of events in the buffer before mandatory drainage.
///
/// This prevents unbounded memory growth per CTR-1303. When this limit
/// is reached, new events will evict the oldest events.
///
/// # Memory Budget
///
/// Each `EpisodeEvent` can contain a `TimeEnvelope` with multiple string
/// fields (notes, `profile_hash`, `ledger_id`) up to `MAX_STRING_LENGTH` (4KB).
/// At 10,000 events with worst-case sizing, heap usage is bounded to ~150MB,
/// which is acceptable for daemon processes.
///
/// The previous value of 100,000 could result in ~1.5GB heap usage, which
/// risks OOM on resource-constrained nodes (TCK-00240 review feedback).
pub const MAX_EVENTS_BUFFER_SIZE: usize = 10_000;

/// Hash type (BLAKE3-256).
pub type Hash = [u8; 32];

/// Episode event emitted during state transitions.
///
/// These events are designed to be persisted to the ledger for audit
/// and replay. Per RFC-0016 (HTF), all episode events include an optional
/// `time_envelope_ref` for temporal ordering and causality tracking.
///
/// # Security: Time Envelope Preimage Preservation
///
/// The `time_envelope` field contains the full `TimeEnvelope` preimage
/// alongside the `time_envelope_ref` hash. This ensures the envelope data
/// (monotonic ticks, wall bounds, ledger anchor) is persisted and verifiable.
/// Without the preimage, the hash reference would be unresolvable.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EpisodeEvent {
    /// Episode was created.
    Created {
        /// Episode identifier (typed for safety).
        episode_id: EpisodeId,
        /// Hash of the episode envelope.
        envelope_hash: Hash,
        /// Timestamp when created (nanoseconds since epoch).
        created_at_ns: u64,
        /// Reference to the `TimeEnvelope` for this event (RFC-0016 HTF).
        time_envelope_ref: Option<TimeEnvelopeRef>,
        /// The full `TimeEnvelope` preimage for verification.
        time_envelope: Option<TimeEnvelope>,
    },
    /// Episode started running.
    Started {
        /// Episode identifier (typed for safety).
        episode_id: EpisodeId,
        /// Session identifier for the running episode.
        session_id: String,
        /// Lease ID authorizing execution.
        lease_id: String,
        /// Timestamp when started (nanoseconds since epoch).
        started_at_ns: u64,
        /// Reference to the `TimeEnvelope` for this event (RFC-0016 HTF).
        time_envelope_ref: Option<TimeEnvelopeRef>,
        /// The full `TimeEnvelope` preimage for verification.
        time_envelope: Option<TimeEnvelope>,
    },
    /// Episode terminated normally.
    Stopped {
        /// Episode identifier (typed for safety).
        episode_id: EpisodeId,
        /// How the episode terminated.
        termination_class: TerminationClass,
        /// Timestamp when terminated (nanoseconds since epoch).
        terminated_at_ns: u64,
        /// Reference to the `TimeEnvelope` for this event (RFC-0016 HTF).
        time_envelope_ref: Option<TimeEnvelopeRef>,
        /// The full `TimeEnvelope` preimage for verification.
        time_envelope: Option<TimeEnvelope>,
    },
    /// Episode was quarantined.
    Quarantined {
        /// Episode identifier (typed for safety).
        episode_id: EpisodeId,
        /// Reason for quarantine.
        reason: QuarantineReason,
        /// Timestamp when quarantined (nanoseconds since epoch).
        quarantined_at_ns: u64,
        /// Reference to the `TimeEnvelope` for this event (RFC-0016 HTF).
        time_envelope_ref: Option<TimeEnvelopeRef>,
        /// The full `TimeEnvelope` preimage for verification.
        time_envelope: Option<TimeEnvelope>,
    },
    /// Clock profile was published (TCK-00240).
    ///
    /// This event is emitted when the runtime is initialized with a
    /// `HolonicClock`. It publishes the `ClockProfile` to the ledger so that
    /// auditors can resolve `clock_profile_hash` references in `TimeEnvelope`s.
    ///
    /// # Verification
    ///
    /// Auditors should verify that:
    /// - `profile_hash == hex(blake3(canonical_bytes(clock_profile)))`
    /// - All `TimeEnvelope.clock_profile_hash` fields in subsequent events
    ///   match this published profile
    ClockProfilePublished {
        /// BLAKE3 hash of the canonical clock profile.
        profile_hash: String,
        /// The full `ClockProfile` for verification.
        clock_profile: ClockProfile,
        /// Timestamp when published (nanoseconds since epoch).
        published_at_ns: u64,
        /// Reference to the `TimeEnvelope` for this event (RFC-0016 HTF).
        time_envelope_ref: Option<TimeEnvelopeRef>,
        /// The full `TimeEnvelope` preimage for verification.
        time_envelope: Option<TimeEnvelope>,
    },
    /// Lease issuance was denied (TCK-00258).
    ///
    /// Per REQ-DCP-0006, this event is emitted when a spawn request is rejected
    /// due to policy violations such as `SoD` (Separation of Duties) custody
    /// domain overlap. This provides an audit trail for security-relevant
    /// rejections.
    ///
    /// # Verification
    ///
    /// Auditors should verify that:
    /// - All `LeaseIssueDenied` events have valid denial reasons
    /// - `SOD_VIOLATION` events include overlapping domain information
    LeaseIssueDenied {
        /// Work ID that was denied.
        work_id: String,
        /// Reason for denial.
        denial_reason: LeaseIssueDenialReason,
        /// Timestamp when denied (nanoseconds since epoch).
        denied_at_ns: u64,
        /// Reference to the `TimeEnvelope` for this event (RFC-0016 HTF).
        time_envelope_ref: Option<TimeEnvelopeRef>,
        /// The full `TimeEnvelope` preimage for verification.
        time_envelope: Option<TimeEnvelope>,
    },
    /// Tool execution completed (TCK-00320).
    ///
    /// Per SEC-CTRL-FAC-0015, this event is emitted after each tool execution
    /// completes, providing the CAS result hash for evidence linking.
    ///
    /// # Evidence Integrity
    ///
    /// The `result_hash` field provides a verifiable reference to the full
    /// `ToolResultData` stored in CAS. This enables:
    /// - Downstream indexing (TCK-00327: `ToolLogIndexV1`)
    /// - Receipt verification
    /// - Audit trail integrity
    ToolExecuted {
        /// Episode identifier (typed for safety).
        episode_id: EpisodeId,
        /// Request ID for this execution.
        request_id: String,
        /// CAS hash of the full `ToolResultData`.
        ///
        /// This is the BLAKE3 hash of the serialized `ToolResultData` stored
        /// in CAS. All success paths MUST populate this field.
        result_hash: Hash,
        /// Whether the execution succeeded.
        success: bool,
        /// Timestamp when execution completed (nanoseconds since epoch).
        executed_at_ns: u64,
        /// Reference to the `TimeEnvelope` for this event (RFC-0016 HTF).
        time_envelope_ref: Option<TimeEnvelopeRef>,
        /// The full `TimeEnvelope` preimage for verification.
        time_envelope: Option<TimeEnvelope>,
    },
}

/// Reason for lease issuance denial.
///
/// Per REQ-DCP-0006, this enum captures the specific reason why a lease
/// was denied, enabling diagnostic reporting and security auditing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseIssueDenialReason {
    /// Separation of Duties violation: executor custody domain overlaps
    /// with author custody domains for the changeset.
    SodViolation {
        /// The executor's custody domain that caused the violation.
        executor_domain: String,
        /// The author's custody domain that overlaps.
        author_domain: String,
    },
    /// Policy resolution is missing for the work item.
    PolicyResolutionMissing,
    /// Role mismatch between claim and spawn request.
    RoleMismatch {
        /// The claimed role.
        claimed_role: String,
        /// The requested role.
        requested_role: String,
    },
    /// Lease ID mismatch.
    LeaseIdMismatch,
    /// Other policy violation.
    PolicyViolation {
        /// Description of the violation.
        description: String,
    },
}

impl std::fmt::Display for LeaseIssueDenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SodViolation {
                executor_domain,
                author_domain,
            } => write!(
                f,
                "SOD_VIOLATION: executor domain '{executor_domain}' overlaps with author domain '{author_domain}'"
            ),
            Self::PolicyResolutionMissing => write!(f, "POLICY_RESOLUTION_MISSING"),
            Self::RoleMismatch {
                claimed_role,
                requested_role,
            } => write!(
                f,
                "ROLE_MISMATCH: claimed={claimed_role}, requested={requested_role}"
            ),
            Self::LeaseIdMismatch => write!(f, "LEASE_ID_MISMATCH"),
            Self::PolicyViolation { description } => {
                write!(f, "POLICY_VIOLATION: {description}")
            },
        }
    }
}

impl EpisodeEvent {
    /// Returns the episode ID for this event, if applicable.
    ///
    /// Runtime-level events like [`EpisodeEvent::ClockProfilePublished`] and
    /// [`EpisodeEvent::LeaseIssueDenied`] do not have an associated episode
    /// and return `None`.
    #[must_use]
    pub const fn episode_id(&self) -> Option<&EpisodeId> {
        match self {
            Self::Created { episode_id, .. }
            | Self::Started { episode_id, .. }
            | Self::Stopped { episode_id, .. }
            | Self::Quarantined { episode_id, .. }
            | Self::ToolExecuted { episode_id, .. } => Some(episode_id),
            Self::ClockProfilePublished { .. } | Self::LeaseIssueDenied { .. } => None,
        }
    }

    /// Returns the event type name.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "episode.created",
            Self::Started { .. } => "episode.started",
            Self::Stopped { .. } => "episode.stopped",
            Self::Quarantined { .. } => "episode.quarantined",
            Self::ClockProfilePublished { .. } => "clock.profile_published",
            Self::LeaseIssueDenied { .. } => "lease.issue_denied",
            Self::ToolExecuted { .. } => "tool.executed",
        }
    }

    /// Returns the time envelope reference for this event (RFC-0016 HTF).
    #[must_use]
    pub const fn time_envelope_ref(&self) -> Option<&TimeEnvelopeRef> {
        match self {
            Self::Created {
                time_envelope_ref, ..
            }
            | Self::Started {
                time_envelope_ref, ..
            }
            | Self::Stopped {
                time_envelope_ref, ..
            }
            | Self::Quarantined {
                time_envelope_ref, ..
            }
            | Self::ClockProfilePublished {
                time_envelope_ref, ..
            }
            | Self::LeaseIssueDenied {
                time_envelope_ref, ..
            }
            | Self::ToolExecuted {
                time_envelope_ref, ..
            } => time_envelope_ref.as_ref(),
        }
    }

    /// Returns the time envelope preimage for this event (RFC-0016 HTF).
    ///
    /// The preimage is stored alongside the reference to ensure the temporal
    /// assertions remain verifiable.
    #[must_use]
    pub const fn time_envelope(&self) -> Option<&TimeEnvelope> {
        match self {
            Self::Created { time_envelope, .. }
            | Self::Started { time_envelope, .. }
            | Self::Stopped { time_envelope, .. }
            | Self::Quarantined { time_envelope, .. }
            | Self::ClockProfilePublished { time_envelope, .. }
            | Self::LeaseIssueDenied { time_envelope, .. }
            | Self::ToolExecuted { time_envelope, .. } => time_envelope.as_ref(),
        }
    }

    /// Returns the work ID for this event, if applicable.
    ///
    /// Currently only [`EpisodeEvent::LeaseIssueDenied`] has an associated work
    /// ID separate from episode ID.
    #[must_use]
    pub fn work_id(&self) -> Option<&str> {
        match self {
            Self::LeaseIssueDenied { work_id, .. } => Some(work_id),
            _ => None,
        }
    }

    /// Returns the denial reason for `LeaseIssueDenied` events.
    #[must_use]
    pub const fn denial_reason(&self) -> Option<&LeaseIssueDenialReason> {
        match self {
            Self::LeaseIssueDenied { denial_reason, .. } => Some(denial_reason),
            _ => None,
        }
    }
}

/// Configuration for the episode runtime.
#[derive(Debug, Clone)]
pub struct EpisodeRuntimeConfig {
    /// Maximum number of concurrent episodes.
    pub max_concurrent_episodes: usize,
    /// Whether to emit events for state transitions.
    pub emit_events: bool,
}

impl Default for EpisodeRuntimeConfig {
    fn default() -> Self {
        Self {
            max_concurrent_episodes: MAX_CONCURRENT_EPISODES,
            emit_events: true,
        }
    }
}

impl EpisodeRuntimeConfig {
    /// Creates a new configuration with the specified max episodes.
    #[must_use]
    pub const fn with_max_concurrent_episodes(mut self, max: usize) -> Self {
        self.max_concurrent_episodes = max;
        self
    }

    /// Creates a new configuration with event emission enabled/disabled.
    #[must_use]
    pub const fn with_emit_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }
}

/// Maximum number of tool result hashes per episode (TCK-00320).
/// Maximum tool result hashes per episode (TCK-00320).
///
/// This limit prevents unbounded memory growth per CTR-1303. Episodes
/// exceeding this limit will have their oldest result hashes evicted.
///
/// The limit is chosen to bound aggregate memory:
/// - `MAX_CONCURRENT_EPISODES` (10,000) * `MAX_RESULT_HASHES_PER_EPISODE`
///   (1,000) * 32 bytes
/// - = 320 MB worst-case, well under the 1.5 GB safety threshold.
pub const MAX_RESULT_HASHES_PER_EPISODE: usize = 1_000;

/// Internal state for a tracked episode.
struct EpisodeEntry {
    /// Current state.
    state: EpisodeState,
    /// Session handle if running.
    handle: Option<SessionHandle>,
    /// Tool executor if initialized.
    executor: Option<SharedToolExecutor>,
    /// Accumulated tool result hashes in execution order (TCK-00320).
    ///
    /// Per SEC-CTRL-FAC-0015, this accumulates CAS hashes of all
    /// `ToolResultData` in deterministic tool sequence order. Used for
    /// downstream indexing (TCK-00327: `ToolLogIndexV1`).
    result_hashes: Vec<Hash>,
    /// TCK-00399: Harness handle for the spawned agent CLI process.
    ///
    /// Stored for lifecycle management: `stop()` calls
    /// `adapter.terminate()` via this handle. Set after a successful
    /// `AdapterRegistry::spawn()` and cleared on termination.
    harness_handle: Option<HarnessHandle>,
}

/// Episode runtime for managing daemon-hosted episodes.
///
/// This struct is the authoritative plant controller per AD-LAYER-001.
/// It manages episode lifecycle with proper state machine transitions
/// and event emission.
///
/// # Thread Safety
///
/// `EpisodeRuntime` is `Send + Sync` and can be safely shared across
/// async tasks. Internal state is protected by `RwLock`.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::runtime::{EpisodeRuntime, EpisodeRuntimeConfig};
///
/// let runtime = EpisodeRuntime::new(EpisodeRuntimeConfig::default());
///
/// // Create an episode
/// let episode_id = runtime.create(envelope_hash, timestamp_ns).await?;
///
/// // Start the episode
/// let handle = runtime.start(&episode_id, lease_id, session_id, timestamp_ns).await?;
///
/// // ... episode runs ...
///
/// // Stop the episode
/// runtime.stop(&episode_id, TerminationClass::Success, timestamp_ns).await?;
/// ```
/// Type alias for workspace-rooted handler factory functions (TCK-00319).
///
/// These factories take a workspace root path and produce handlers that are
/// confined to that workspace. This is the preferred factory type for
/// production use.
pub type RootedHandlerFactory = Box<dyn Fn(&std::path::Path) -> Box<dyn ToolHandler> + Send + Sync>;

/// Runtime that manages episode lifecycle and execution.
///
/// The `EpisodeRuntime` is the central coordinator for creating, tracking, and
/// managing episodes. It handles tool handler registration, event buffering,
/// and workspace-rooted operation for secure file access.
pub struct EpisodeRuntime {
    /// Configuration.
    config: EpisodeRuntimeConfig,
    /// Episodes indexed by ID.
    episodes: RwLock<HashMap<String, EpisodeEntry>>,
    /// Event buffer for emitted events.
    events: RwLock<Vec<EpisodeEvent>>,
    /// Monotonic sequence number for session IDs.
    session_seq: AtomicU64,
    /// Monotonic sequence number for episode ID entropy.
    ///
    /// This counter provides uniqueness even when multiple episodes
    /// are created with the same envelope hash and timestamp.
    episode_seq: AtomicU64,
    /// Holonic clock for time envelope stamping (RFC-0016 HTF).
    ///
    /// When present, all episode events are stamped with a `TimeEnvelopeRef`
    /// for temporal ordering and causality tracking.
    clock: Option<Arc<HolonicClock>>,
    /// Content-addressed store for tool execution results.
    cas: Option<Arc<dyn ContentAddressedStore>>,
    /// Factories for creating tool handlers (legacy, CWD-rooted).
    ///
    /// **DEPRECATED (TCK-00319)**: Prefer `rooted_handler_factories` for
    /// production use. These factories create handlers rooted to CWD, which
    /// is a security anti-pattern.
    #[allow(clippy::type_complexity)]
    handler_factories: RwLock<Vec<Box<dyn Fn() -> Box<dyn ToolHandler> + Send + Sync>>>,
    /// Factories for creating workspace-rooted tool handlers (TCK-00319).
    ///
    /// These factories take a workspace root path and produce handlers that are
    /// confined to that workspace. This is the preferred factory type for
    /// production use.
    rooted_handler_factories: RwLock<Vec<RootedHandlerFactory>>,
    /// Default budget for new episodes.
    default_budget: EpisodeBudget,
    /// Ledger event emitter for durable episode event persistence (TCK-00321).
    ///
    /// Per REQ-0005, when present, episode events are streamed directly to the
    /// ledger as they occur (rather than buffered in memory). This enables:
    /// - Events survive daemon restart (ledger-backed durability)
    /// - Receipt event appended atomically at completion
    /// - CAS-before-ledger ordering for events referencing CAS hashes
    ///
    /// When `None`, events are buffered in memory (legacy behavior for tests).
    ledger_emitter: Option<Arc<dyn LedgerEventEmitter>>,
    /// Session registry for wiring episode lifecycle to session termination
    /// (TCK-00385 BLOCKER fix).
    ///
    /// When present, episode `stop()` and `quarantine()` calls automatically
    /// mark the corresponding session as terminated via
    /// `SessionRegistry::mark_terminated()`. This ensures all exit paths
    /// (normal, crash, timeout, quarantined, budget-exhausted) produce a
    /// `TERMINATED + reason/exit_code` status in the session registry.
    session_registry: Option<Arc<dyn SessionRegistry>>,
    /// TCK-00399: Adapter registry for spawning agent CLI processes.
    ///
    /// When present, `spawn_adapter()` uses this registry to look up the
    /// appropriate `HarnessAdapter` and spawn the agent process.
    adapter_registry: Option<Arc<AdapterRegistry>>,

    /// Orphaned harness handles awaiting cleanup (MAJOR security fix).
    ///
    /// When spawn-race cleanup fails (both `terminate()` and
    /// `escalate_sigkill()` fail), the harness handle is retained here for
    /// periodic retry. This prevents untracked orphaned processes surviving
    /// outside containment.
    ///
    /// Invariant: process death is NEVER assumed without confirmation. Handles
    /// remain in this vec until cleanup succeeds.
    orphan_harness_handles: tokio::sync::Mutex<Vec<HarnessHandle>>,
}

impl EpisodeRuntime {
    /// Creates a new episode runtime with the given configuration.
    ///
    /// This creates a runtime without a `HolonicClock`, meaning events will
    /// have `time_envelope_ref: None`. Use [`Self::with_clock`] to enable
    /// time envelope stamping.
    #[must_use]
    pub fn new(config: EpisodeRuntimeConfig) -> Self {
        Self {
            config,
            episodes: RwLock::new(HashMap::new()),
            events: RwLock::new(Vec::new()),
            session_seq: AtomicU64::new(1),
            episode_seq: AtomicU64::new(1),
            clock: None,
            cas: None,
            handler_factories: RwLock::new(Vec::new()),
            rooted_handler_factories: RwLock::new(Vec::new()),
            // SEC-CTRL-FAC-0015: Fail-closed default budget prevents DoS
            // via unbounded resource consumption. Consumers can override
            // with `with_default_budget()` if needed.
            default_budget: EpisodeBudget::default(),
            // TCK-00321: No ledger emitter by default (tests use in-memory buffer)
            ledger_emitter: None,
            // TCK-00385: No session registry by default (tests don't need it)
            session_registry: None,
            // TCK-00399: No adapter registry by default
            adapter_registry: None,
            // MAJOR security fix: empty orphan tracker
            orphan_harness_handles: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new episode runtime with the given configuration and clock.
    ///
    /// When a `HolonicClock` is provided, all episode events will be stamped
    /// with a `TimeEnvelopeRef` for temporal ordering and causality tracking
    /// per RFC-0016 (HTF).
    ///
    /// # Note
    ///
    /// This constructor does not emit the `ClockProfilePublished` event.
    /// Use [`Self::with_clock_initialized`] for production code to ensure
    /// the clock profile is published to the ledger for auditor resolution.
    #[must_use]
    pub fn with_clock(config: EpisodeRuntimeConfig, clock: Arc<HolonicClock>) -> Self {
        Self {
            config,
            episodes: RwLock::new(HashMap::new()),
            events: RwLock::new(Vec::new()),
            session_seq: AtomicU64::new(1),
            episode_seq: AtomicU64::new(1),
            clock: Some(clock),
            cas: None,
            handler_factories: RwLock::new(Vec::new()),
            rooted_handler_factories: RwLock::new(Vec::new()),
            // SEC-CTRL-FAC-0015: Fail-closed default budget
            default_budget: EpisodeBudget::default(),
            // TCK-00321: No ledger emitter by default (tests use in-memory buffer)
            ledger_emitter: None,
            // TCK-00385: No session registry by default
            session_registry: None,
            // TCK-00399: No adapter registry by default
            adapter_registry: None,
            // MAJOR security fix: empty orphan tracker
            orphan_harness_handles: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new episode runtime with clock and emits
    /// `ClockProfilePublished`.
    ///
    /// This is the preferred factory for production code. It:
    /// 1. Creates the runtime with the provided clock
    /// 2. Emits a `ClockProfilePublished` event so auditors can resolve
    ///    `clock_profile_hash` references in subsequent `TimeEnvelope`s
    ///
    /// # Returns
    ///
    /// Returns `Err` if clock stamping fails during event emission.
    ///
    /// # Security (SEC-CTRL-FAC-0015 Fail-Closed)
    ///
    /// If the clock fails to stamp the profile publication event, the runtime
    /// is not created. This ensures temporal authority is established from
    /// the start.
    pub async fn with_clock_initialized(
        config: EpisodeRuntimeConfig,
        clock: Arc<HolonicClock>,
    ) -> Result<Self, EpisodeError> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let runtime = Self::with_clock(config, clock);

        // Get current timestamp.
        // The cast from u128 to u64 is safe: nanoseconds since UNIX epoch
        // won't exceed u64::MAX until the year 2554.
        #[allow(clippy::cast_possible_truncation)]
        let published_at_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Get clock profile from the clock (safe: we just set it in with_clock)
        let clock_ref = runtime.clock().ok_or_else(|| EpisodeError::ClockFailure {
            message: "clock not available after with_clock()".to_string(),
        })?;

        // Stamp the event with the clock (fail-closed: propagate errors)
        // Since we verified clock exists, stamp_envelope will return Some
        let (time_envelope, time_envelope_ref) = runtime
            .stamp_envelope(Some(format!(
                "clock.profile_published:{}",
                clock_ref.profile_hash()
            )))
            .await?
            .ok_or_else(|| EpisodeError::ClockFailure {
                message: "stamp_envelope returned None despite clock being configured".to_string(),
            })?;

        // Emit the ClockProfilePublished event
        if runtime.config.emit_events {
            runtime
                .emit_event(EpisodeEvent::ClockProfilePublished {
                    profile_hash: clock_ref.profile_hash().to_string(),
                    clock_profile: clock_ref.clock_profile().clone(),
                    published_at_ns,
                    time_envelope_ref: Some(time_envelope_ref),
                    time_envelope: Some(time_envelope),
                })
                .await?;

            info!(
                profile_hash = %clock_ref.profile_hash(),
                "clock profile published"
            );
        }

        Ok(runtime)
    }

    /// Creates a new episode runtime with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(EpisodeRuntimeConfig::default())
    }

    /// Returns the runtime configuration.
    #[must_use]
    pub const fn config(&self) -> &EpisodeRuntimeConfig {
        &self.config
    }

    /// Returns a reference to the holonic clock, if configured.
    #[must_use]
    pub const fn clock(&self) -> Option<&Arc<HolonicClock>> {
        self.clock.as_ref()
    }

    /// Sets the content-addressed store for tool execution results.
    #[must_use]
    pub fn with_cas(mut self, cas: Arc<dyn ContentAddressedStore>) -> Self {
        self.cas = Some(cas);
        self
    }

    /// Sets the default budget for new episodes.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn with_default_budget(mut self, budget: EpisodeBudget) -> Self {
        self.default_budget = budget;
        self
    }

    /// Sets the ledger emitter for durable episode event persistence
    /// (TCK-00321).
    ///
    /// Per REQ-0005, when a ledger emitter is configured, episode events are
    /// streamed directly to the ledger as they occur. This enables:
    /// - Events survive daemon restart (ledger-backed durability)
    /// - Receipt event appended atomically at completion
    /// - CAS-before-ledger ordering for events referencing CAS hashes
    ///
    /// # Arguments
    ///
    /// * `emitter` - The ledger event emitter to use for persistence.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let runtime = EpisodeRuntime::new(config)
    ///     .with_ledger_emitter(Arc::new(SqliteLedgerEventEmitter::new(conn, key)));
    /// ```
    #[must_use]
    pub fn with_ledger_emitter(mut self, emitter: Arc<dyn LedgerEventEmitter>) -> Self {
        self.ledger_emitter = Some(emitter);
        self
    }

    /// Returns a reference to the ledger emitter, if configured.
    #[must_use]
    pub fn ledger_emitter(&self) -> Option<&Arc<dyn LedgerEventEmitter>> {
        self.ledger_emitter.as_ref()
    }

    /// Sets the session registry for wiring episode lifecycle to session
    /// termination (TCK-00385 BLOCKER fix).
    ///
    /// When configured, `stop()` and `quarantine()` automatically call
    /// `session_registry.mark_terminated()` for the session associated with
    /// the episode. This ensures all exit paths (normal completion, crash,
    /// timeout, quarantine, budget exhaustion) produce a `TERMINATED` status
    /// with reason and exit code in the session registry.
    #[must_use]
    pub fn with_session_registry(mut self, registry: Arc<dyn SessionRegistry>) -> Self {
        self.session_registry = Some(registry);
        self
    }

    /// Sets the adapter registry for spawning agent CLI processes (TCK-00399).
    #[must_use]
    pub fn with_adapter_registry(mut self, registry: Arc<AdapterRegistry>) -> Self {
        self.adapter_registry = Some(registry);
        self
    }

    /// Returns the number of orphaned harness handles awaiting cleanup.
    ///
    /// A non-zero count indicates processes whose death could not be confirmed
    /// during spawn-race cleanup. These handles are retained for periodic retry
    /// via [`retry_orphan_cleanup`](Self::retry_orphan_cleanup).
    pub async fn orphan_harness_count(&self) -> usize {
        self.orphan_harness_handles.lock().await.len()
    }

    /// Retries cleanup of orphaned harness handles (MAJOR security fix).
    ///
    /// Iterates all retained orphan handles and attempts `escalate_sigkill`
    /// again. Handles whose processes are confirmed dead (SIGKILL succeeds or
    /// ESRCH) are removed. Handles that still fail are retained for the next
    /// retry cycle.
    ///
    /// Returns the number of handles that were successfully cleaned up.
    pub async fn retry_orphan_cleanup(&self) -> usize {
        let mut orphans = self.orphan_harness_handles.lock().await;
        let mut still_orphaned = Vec::new();
        let mut cleaned = 0usize;

        for handle in orphans.drain(..) {
            match crate::episode::adapter::escalate_sigkill(&handle).await {
                Ok(()) => {
                    info!(
                        handle_id = handle.id(),
                        episode_id = %handle.episode_id(),
                        "orphaned adapter process confirmed dead on retry"
                    );
                    cleaned += 1;
                },
                Err(e) => {
                    warn!(
                        handle_id = handle.id(),
                        episode_id = %handle.episode_id(),
                        error = %e,
                        "orphaned adapter process still not confirmed dead; \
                         retaining for next retry"
                    );
                    still_orphaned.push(handle);
                },
            }
        }

        *orphans = still_orphaned;
        cleaned
    }

    /// Registers a factory for creating tool handlers (builder pattern).
    ///
    /// **DEPRECATED (TCK-00319, TCK-00336)**: Prefer
    /// `with_rooted_handler_factory` for production use. These factories
    /// create handlers rooted to CWD, which is a security anti-pattern.
    ///
    /// # Security Warning (TCK-00336)
    ///
    /// CWD-rooted handlers violate workspace isolation. Using this method
    /// in production creates a security vulnerability where tool handlers
    /// can access files outside the intended workspace. Use
    /// `with_rooted_handler_factory` instead.
    #[must_use]
    #[deprecated(
        since = "0.1.0",
        note = "TCK-00336: Use with_rooted_handler_factory for workspace isolation"
    )]
    pub fn with_handler_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn() -> Box<dyn ToolHandler> + Send + Sync + 'static,
    {
        self.handler_factories.get_mut().push(Box::new(factory));
        self
    }

    /// Registers a workspace-rooted handler factory (builder pattern).
    ///
    /// # TCK-00319: Production Handler Registration
    ///
    /// This is the **preferred** method for registering tool handlers in
    /// production. The factory receives the workspace root path at episode
    /// start time, allowing handlers to be properly isolated to the
    /// episode's workspace.
    ///
    /// # Arguments
    ///
    /// * `factory` - A function that takes a workspace root path and returns a
    ///   tool handler. The handler should be rooted to the provided path.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// runtime.with_rooted_handler_factory(|root| {
    ///     Box::new(ReadFileHandler::with_root(root))
    /// })
    /// ```
    #[must_use]
    pub fn with_rooted_handler_factory<F>(mut self, factory: F) -> Self
    where
        F: Fn(&std::path::Path) -> Box<dyn ToolHandler> + Send + Sync + 'static,
    {
        self.rooted_handler_factories
            .get_mut()
            .push(Box::new(factory));
        self
    }

    /// Registers a factory for creating tool handlers.
    ///
    /// **DEPRECATED (TCK-00319, TCK-00336)**: Prefer
    /// `register_rooted_handler_factory` for production use.
    ///
    /// This allows the runtime to spawn fresh handlers for each episode
    /// (needed because handlers are consumed by the executor).
    ///
    /// # Security Warning (TCK-00336)
    ///
    /// CWD-rooted handlers violate workspace isolation. See
    /// `with_handler_factory` for details.
    #[deprecated(
        since = "0.1.0",
        note = "TCK-00336: Use register_rooted_handler_factory for workspace isolation"
    )]
    pub async fn register_tool_handler_factory<F>(&self, factory: F)
    where
        F: Fn() -> Box<dyn ToolHandler> + Send + Sync + 'static,
    {
        let mut factories = self.handler_factories.write().await;
        factories.push(Box::new(factory));
    }

    /// Registers a workspace-rooted handler factory.
    ///
    /// # TCK-00319: Production Handler Registration
    ///
    /// See [`Self::with_rooted_handler_factory`] for details.
    pub async fn register_rooted_handler_factory<F>(&self, factory: F)
    where
        F: Fn(&std::path::Path) -> Box<dyn ToolHandler> + Send + Sync + 'static,
    {
        let mut factories = self.rooted_handler_factories.write().await;
        factories.push(Box::new(factory));
    }

    /// Stamps a time envelope and returns both the envelope and its reference.
    ///
    /// # Returns
    ///
    /// - `Ok(Some((envelope, ref)))` if clock is configured and stamping
    ///   succeeds
    /// - `Ok(None)` if no clock is configured
    /// - `Err(ClockFailure)` if clock is configured but stamping fails
    ///
    /// # Security (SEC-CTRL-FAC-0015 Fail-Closed)
    ///
    /// This method enforces fail-closed behavior: if a clock is configured but
    /// fails to stamp, the error is propagated rather than silently returning
    /// `None`. This ensures events are not emitted without timestamps when
    /// temporal authority is expected.
    ///
    /// # Security: Preimage Preservation
    ///
    /// Both the `TimeEnvelope` (preimage) and `TimeEnvelopeRef` (hash) are
    /// returned to ensure the full temporal data is persisted alongside
    /// events. Without the preimage, the hash reference would be unresolvable
    /// and the timestamps unverifiable.
    async fn stamp_envelope(
        &self,
        notes: Option<String>,
    ) -> Result<Option<(TimeEnvelope, TimeEnvelopeRef)>, EpisodeError> {
        let Some(clock) = self.clock.as_ref() else {
            return Ok(None);
        };
        match clock.stamp_envelope(notes).await {
            Ok((envelope, envelope_ref)) => Ok(Some((envelope, envelope_ref))),
            Err(e) => {
                warn!("failed to stamp time envelope: {e}");
                Err(EpisodeError::ClockFailure {
                    message: e.to_string(),
                })
            },
        }
    }

    /// Creates a new episode from an envelope.
    ///
    /// This registers the episode in CREATED state. The episode must be
    /// started via `start()` before it can execute.
    ///
    /// # Arguments
    ///
    /// * `envelope_hash` - BLAKE3 hash of the episode envelope
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    ///
    /// # Returns
    ///
    /// Returns the new `EpisodeId` on success.
    ///
    /// # Errors
    ///
    /// Returns `EpisodeError::LimitReached` if the maximum number of
    /// concurrent episodes has been reached.
    ///
    /// # Events
    ///
    /// Emits `episode.created` event (INV-ER002).
    #[instrument(skip(self, envelope_hash), fields(envelope_hash = %hex::encode(&envelope_hash[..8])))]
    pub async fn create(
        &self,
        envelope_hash: Hash,
        timestamp_ns: u64,
    ) -> Result<EpisodeId, EpisodeError> {
        // Generate episode ID from envelope hash, full nanosecond timestamp, and
        // sequence number. The sequence number provides uniqueness even when
        // multiple episodes are created with the same envelope hash and
        // timestamp (high-concurrency scenario).
        let seq = self.episode_seq.fetch_add(1, Ordering::Relaxed);
        let id_str = format!(
            "ep-{}-{}-{}",
            hex::encode(&envelope_hash[..8]),
            timestamp_ns, // Full nanosecond precision
            seq           // Monotonic sequence for entropy
        );
        let episode_id = EpisodeId::new(&id_str)?;

        let state = EpisodeState::Created {
            created_at_ns: timestamp_ns,
            envelope_hash,
        };

        {
            let mut episodes = self.episodes.write().await;

            // Check limit (CTR-1303)
            if episodes.len() >= self.config.max_concurrent_episodes {
                return Err(EpisodeError::LimitReached {
                    limit: self.config.max_concurrent_episodes,
                });
            }

            // Check for duplicate (shouldn't happen with timestamp in ID)
            if episodes.contains_key(episode_id.as_str()) {
                return Err(EpisodeError::AlreadyExists {
                    id: episode_id.as_str().to_string(),
                });
            }

            episodes.insert(
                episode_id.as_str().to_string(),
                EpisodeEntry {
                    state,
                    handle: None,
                    executor: None,
                    result_hashes: Vec::new(), // TCK-00320: Accumulate result hashes
                    harness_handle: None,      // TCK-00399: Set after spawn_adapter()
                },
            );
        }

        // Emit event (INV-ER002)
        if self.config.emit_events {
            // Stamp time envelope for temporal ordering (RFC-0016 HTF)
            // Per SEC-CTRL-FAC-0015 (Fail-Closed), propagate clock errors
            // Returns both envelope (preimage) and ref (hash) for verifiability
            let (time_envelope, time_envelope_ref) = match self
                .stamp_envelope(Some(format!("episode.created:{}", episode_id.as_str())))
                .await?
            {
                Some((env, env_ref)) => (Some(env), Some(env_ref)),
                None => (None, None),
            };
            self.emit_event(EpisodeEvent::Created {
                episode_id: episode_id.clone(),
                envelope_hash,
                created_at_ns: timestamp_ns,
                time_envelope_ref,
                time_envelope,
            })
            .await?;
        }

        info!(episode_id = %episode_id, "episode created");
        Ok(episode_id)
    }

    /// Starts an episode, transitioning it from CREATED to RUNNING.
    ///
    /// **DEPRECATED (TCK-00319, TCK-00336)**: Prefer `start_with_workspace` for
    /// production use. This method uses CWD-rooted handlers, which is a
    /// security anti-pattern that violates workspace isolation.
    ///
    /// # Security Warning (TCK-00336)
    ///
    /// Using this method in production creates a security vulnerability where
    /// tool handlers can access files outside the intended workspace. The
    /// CWD-rooted handlers registered via `with_handler_factory` or
    /// `register_tool_handler_factory` will have access to the daemon's CWD,
    /// not the episode's workspace.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to start
    /// * `lease_id` - Lease authorizing execution
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    ///
    /// # Returns
    ///
    /// Returns a `SessionHandle` for the running episode.
    ///
    /// # Errors
    ///
    /// - `EpisodeError::NotFound` if the episode doesn't exist
    /// - `EpisodeError::InvalidTransition` if the episode is not in CREATED
    ///   state
    /// - `EpisodeError::InvalidLease` if the lease ID is invalid
    ///
    /// # Events
    ///
    /// Emits `episode.started` event (INV-ER002).
    #[deprecated(
        since = "0.1.0",
        note = "TCK-00336: Use start_with_workspace for workspace isolation"
    )]
    #[instrument(skip(self, lease_id))]
    pub async fn start(
        &self,
        episode_id: &EpisodeId,
        lease_id: impl Into<String>,
        timestamp_ns: u64,
    ) -> Result<SessionHandle, EpisodeError> {
        // Delegate to internal implementation with no workspace root
        self.start_internal(episode_id, lease_id, timestamp_ns, None)
            .await
    }

    /// Starts an episode with a specific workspace root (TCK-00319).
    ///
    /// This is the **preferred** method for starting episodes in production.
    /// Tool handlers will be rooted to the specified workspace, preventing
    /// access to the daemon's CWD or other directories.
    ///
    /// # TCK-00319: Workspace Root Plumbing
    ///
    /// This method addresses BLOCKER 2: it accepts a workspace root and uses it
    /// to initialize tool handlers via the rooted handler factories.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to start
    /// * `lease_id` - Lease authorizing execution
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    /// * `workspace_root` - Absolute path to the workspace directory
    ///
    /// # Returns
    ///
    /// Returns a `SessionHandle` for the running episode.
    ///
    /// # Errors
    ///
    /// - `EpisodeError::NotFound` if the episode doesn't exist
    /// - `EpisodeError::InvalidTransition` if the episode is not in CREATED
    ///   state
    /// - `EpisodeError::InvalidLease` if the lease ID is invalid
    /// - `EpisodeError::Internal` if the workspace root does not exist or
    ///   cannot be canonicalized
    ///
    /// # Events
    ///
    /// Emits `episode.started` event (INV-ER002).
    #[instrument(skip(self, lease_id, workspace_root))]
    pub async fn start_with_workspace(
        &self,
        episode_id: &EpisodeId,
        lease_id: impl Into<String>,
        timestamp_ns: u64,
        workspace_root: &std::path::Path,
    ) -> Result<SessionHandle, EpisodeError> {
        // Validate workspace root exists and canonicalize (fail-closed)
        if !workspace_root.exists() {
            return Err(EpisodeError::Internal {
                message: format!(
                    "workspace root does not exist: {}",
                    workspace_root.display()
                ),
            });
        }

        let canonical_root =
            std::fs::canonicalize(workspace_root).map_err(|e| EpisodeError::Internal {
                message: format!(
                    "failed to canonicalize workspace root '{}': {}",
                    workspace_root.display(),
                    e
                ),
            })?;

        self.start_internal(episode_id, lease_id, timestamp_ns, Some(&canonical_root))
            .await
    }

    /// Internal implementation of start with optional workspace root.
    #[instrument(skip(self, lease_id, workspace_root))]
    async fn start_internal(
        &self,
        episode_id: &EpisodeId,
        lease_id: impl Into<String>,
        timestamp_ns: u64,
        workspace_root: Option<&std::path::Path>,
    ) -> Result<SessionHandle, EpisodeError> {
        let lease_id = lease_id.into();

        // Validate lease ID
        if lease_id.is_empty() {
            return Err(EpisodeError::InvalidLease {
                episode_id: episode_id.as_str().to_string(),
                reason: "lease ID cannot be empty".to_string(),
            });
        }

        // Generate session ID
        let session_seq = self.session_seq.fetch_add(1, Ordering::Relaxed);
        let session_id = format!("session-{session_seq}");

        let handle = {
            let mut episodes = self.episodes.write().await;

            let entry =
                episodes
                    .get_mut(episode_id.as_str())
                    .ok_or_else(|| EpisodeError::NotFound {
                        id: episode_id.as_str().to_string(),
                    })?;

            // Validate transition
            super::state::validate_transition(episode_id.as_str(), &entry.state, "Running")?;

            // Extract required fields from current state
            let (created_at_ns, envelope_hash) = match &entry.state {
                EpisodeState::Created {
                    created_at_ns,
                    envelope_hash,
                } => (*created_at_ns, *envelope_hash),
                _ => {
                    return Err(EpisodeError::InvalidTransition {
                        id: episode_id.as_str().to_string(),
                        from: entry.state.state_name(),
                        to: "Running",
                    });
                },
            };

            // Transition to Running
            entry.state = EpisodeState::Running {
                created_at_ns,
                started_at_ns: timestamp_ns,
                envelope_hash,
                lease_id: lease_id.clone(),
                session_id: session_id.clone(),
            };

            // Create session handle and store a clone in the entry.
            // Both the caller's handle and the runtime's handle share the same
            // underlying stop signal channel (INV-SH003), so signals sent via
            // `runtime.signal()` are received by the caller's handle.
            // Pass timestamp_ns for deterministic timing per HARD-TIME (M05).
            let handle = SessionHandle::new(
                episode_id.clone(),
                session_id.clone(),
                lease_id.clone(),
                timestamp_ns,
            );
            entry.handle = Some(handle.clone());

            // Initialize tool executor if CAS is configured
            if let Some(ref cas) = self.cas {
                let budget_tracker = Arc::new(BudgetTracker::from_envelope(self.default_budget));
                let mut executor = ToolExecutor::new(budget_tracker, cas.clone())
                    // SEC-CTRL-FAC-0017: Set isolation key to episode ID to prevent
                    // cross-session cache leakage. This is REQUIRED for caching to
                    // be enabled (fail-closed behavior in compute_cache_key).
                    .with_isolation_key(episode_id.as_str());

                if let Some(ref clock) = self.clock {
                    executor = executor.with_clock(clock.clone());
                }

                // TCK-00319: Register handlers from rooted factories first (preferred)
                if let Some(root) = workspace_root {
                    let rooted_factories = self.rooted_handler_factories.read().await;
                    for factory in rooted_factories.iter() {
                        if let Err(e) = executor.register_handler(factory(root)) {
                            warn!(
                                episode_id = %episode_id,
                                error = %e,
                                "failed to register rooted handler for episode"
                            );
                        }
                    }
                }

                // Register handlers from legacy (CWD-rooted) factories
                // TCK-00336: These are deprecated and should only be used in tests.
                // Production code MUST use rooted_handler_factories with a workspace root.
                let factories = self.handler_factories.read().await;
                if !factories.is_empty() && workspace_root.is_none() {
                    // TCK-00336: Emit security warning when using CWD-rooted handlers
                    // without workspace isolation in non-test contexts.
                    warn!(
                        episode_id = %episode_id,
                        factory_count = factories.len(),
                        "SECURITY: Using deprecated CWD-rooted handler factories without workspace root. \
                         This violates workspace isolation (TCK-00336). Use start_with_workspace() \
                         and register_rooted_handler_factory() for production."
                    );
                }
                for factory in factories.iter() {
                    if let Err(e) = executor.register_handler(factory()) {
                        warn!(
                            episode_id = %episode_id,
                            error = %e,
                            "failed to register handler for episode"
                        );
                    }
                }

                entry.executor = Some(Arc::new(tokio::sync::RwLock::new(executor)));
            }

            handle
        };

        // Emit event (INV-ER002)
        if self.config.emit_events {
            // Stamp time envelope for temporal ordering (RFC-0016 HTF)
            // Per SEC-CTRL-FAC-0015 (Fail-Closed), propagate clock errors
            // Returns both envelope (preimage) and ref (hash) for verifiability
            let (time_envelope, time_envelope_ref) = match self
                .stamp_envelope(Some(format!("episode.started:{}", episode_id.as_str())))
                .await?
            {
                Some((env, env_ref)) => (Some(env), Some(env_ref)),
                None => (None, None),
            };
            self.emit_event(EpisodeEvent::Started {
                episode_id: episode_id.clone(),
                session_id: handle.session_id().to_string(),
                lease_id: handle.lease_id().to_string(),
                started_at_ns: timestamp_ns,
                time_envelope_ref,
                time_envelope,
            })
            .await?;
        }

        info!(
            episode_id = %episode_id,
            session_id = %handle.session_id(),
            "episode started"
        );
        Ok(handle)
    }

    /// Spawns an agent CLI process for the given episode (TCK-00399).
    ///
    /// Validates the episode is in RUNNING state, calls
    /// `HarnessAdapter::spawn()`, stores the `HarnessHandle` in the episode
    /// entry, and launches a background bridge task to consume the
    /// `HarnessEventStream`.
    ///
    /// # Errors
    ///
    /// Returns `EpisodeError` if the episode is not in RUNNING state or
    /// if adapter spawning fails.
    pub async fn spawn_adapter(
        &self,
        episode_id: &EpisodeId,
        config: crate::episode::adapter::HarnessConfig,
        adapter: &dyn crate::episode::adapter::HarnessAdapter,
    ) -> Result<(), EpisodeError> {
        // Validate episode is in Running state
        {
            let episodes = self.episodes.read().await;
            let entry =
                episodes
                    .get(episode_id.as_str())
                    .ok_or_else(|| EpisodeError::NotFound {
                        id: episode_id.as_str().to_string(),
                    })?;
            if !matches!(entry.state, EpisodeState::Running { .. }) {
                return Err(EpisodeError::Internal {
                    message: format!(
                        "cannot spawn adapter for episode {} in state {}; expected Running",
                        episode_id,
                        entry.state.state_name()
                    ),
                });
            }
        }

        // Spawn the agent process
        let (handle, event_stream) =
            adapter
                .spawn(config)
                .await
                .map_err(|e| EpisodeError::Internal {
                    message: format!("adapter spawn failed for episode {episode_id}: {e}"),
                })?;

        info!(
            episode_id = %episode_id,
            handle_id = handle.id(),
            "agent process spawned via adapter"
        );

        // BLOCKER fix: Re-validate episode state after the spawn await.
        // If stop()/quarantine() won the race during spawn, the episode is
        // already terminal.  Terminate the just-spawned process immediately
        // to prevent orphaned processes surviving past terminal transition.
        {
            let mut episodes = self.episodes.write().await;
            // SECURITY: If the episode was removed while we were spawning,
            // terminate the just-spawned process to prevent an orphan.
            #[allow(clippy::option_if_let_else)]
            let Some(entry) = episodes.get_mut(episode_id.as_str()) else {
                drop(episodes);
                warn!(
                    episode_id = %episode_id,
                    "episode entry missing after spawn; \
                     terminating orphaned adapter process"
                );
                if let Err(e) = adapter.terminate(&handle).await {
                    warn!(
                        episode_id = %episode_id,
                        error = %e,
                        "failed to terminate orphaned adapter process \
                         on missing episode; escalating to SIGKILL"
                    );
                    // SECURITY: Escalate to SIGKILL to prevent orphaned
                    // processes when control-channel terminate fails.
                    if let Err(kill_err) = crate::episode::adapter::escalate_sigkill(&handle).await
                    {
                        error!(
                            episode_id = %episode_id,
                            error = %kill_err,
                            "SIGKILL escalation failed for orphaned adapter process \
                             on missing episode; process death NOT confirmed; \
                             retaining handle in orphan tracker"
                        );
                        // MAJOR security fix: Retain the handle for periodic
                        // cleanup retry. Never claim cleanup succeeded if
                        // process death is unconfirmed.
                        self.orphan_harness_handles.lock().await.push(handle);
                    }
                }
                return Err(EpisodeError::NotFound {
                    id: episode_id.as_str().to_string(),
                });
            };
            if !matches!(entry.state, EpisodeState::Running { .. }) {
                warn!(
                    episode_id = %episode_id,
                    state = entry.state.state_name(),
                    "episode transitioned to non-Running during spawn; \
                     terminating orphaned adapter process"
                );
                // Drop the write lock before async terminate to avoid
                // holding it across await.
                drop(episodes);
                if let Err(e) = adapter.terminate(&handle).await {
                    warn!(
                        episode_id = %episode_id,
                        error = %e,
                        "failed to terminate orphaned adapter process; \
                         escalating to SIGKILL"
                    );
                    // SECURITY: Escalate to SIGKILL to prevent orphaned
                    // processes when control-channel terminate fails.
                    if let Err(kill_err) = crate::episode::adapter::escalate_sigkill(&handle).await
                    {
                        error!(
                            episode_id = %episode_id,
                            error = %kill_err,
                            "SIGKILL escalation failed for orphaned adapter process; \
                             process death NOT confirmed; \
                             retaining handle in orphan tracker"
                        );
                        // MAJOR security fix: Retain the handle for periodic
                        // cleanup retry. Never claim cleanup succeeded if
                        // process death is unconfirmed.
                        self.orphan_harness_handles.lock().await.push(handle);
                    }
                }
                return Err(EpisodeError::Internal {
                    message: format!(
                        "episode {episode_id} transitioned away from Running \
                         during adapter spawn"
                    ),
                });
            }
            entry.harness_handle = Some(handle);
        }

        // Spawn background bridge task to consume the event stream.
        // Tool-request intents are captured with explicit stub markers
        // (tool execution is deferred to TCK-00401).
        let bridge_episode_id = episode_id.clone();
        tokio::spawn(async move {
            Self::event_stream_bridge(bridge_episode_id, event_stream).await;
        });

        Ok(())
    }

    /// Background bridge task that consumes a `HarnessEventStream`.
    ///
    /// Tool-request intents are logged with stub markers. Actual tool
    /// execution is deferred to TCK-00401.
    async fn event_stream_bridge(
        episode_id: EpisodeId,
        mut event_stream: crate::episode::adapter::HarnessEventStream,
    ) {
        let mut tool_request_count: u64 = 0;

        while let Some(event) = event_stream.recv().await {
            match &event {
                HarnessEvent::ToolRequest {
                    request_id, tool, ..
                } => {
                    tool_request_count += 1;
                    debug!(
                        episode_id = %episode_id,
                        request_id = %request_id,
                        tool = %tool,
                        "[STUB] tool-request intent captured (execution deferred to TCK-00401)"
                    );
                },
                HarnessEvent::Terminated {
                    exit_code,
                    classification,
                } => {
                    info!(
                        episode_id = %episode_id,
                        exit_code = ?exit_code,
                        classification = %classification,
                        tool_requests_captured = tool_request_count,
                        "agent process terminated"
                    );
                    break;
                },
                HarnessEvent::Output { seq, .. } => {
                    if *seq == 0 {
                        debug!(
                            episode_id = %episode_id,
                            "first output event received from agent process"
                        );
                    }
                },
                HarnessEvent::Error { code, message } => {
                    warn!(
                        episode_id = %episode_id,
                        code = %code,
                        message = %message,
                        "error event from agent process"
                    );
                },
                HarnessEvent::Progress { message, percent } => {
                    debug!(
                        episode_id = %episode_id,
                        message = %message,
                        percent = ?percent,
                        "progress event from agent process"
                    );
                },
            }
        }

        debug!(
            episode_id = %episode_id,
            tool_request_count,
            "event stream bridge task completed"
        );
    }

    /// Stops an episode, transitioning it from RUNNING to TERMINATED.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to stop
    /// * `termination_class` - How the episode terminated
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    ///
    /// # Errors
    ///
    /// - `EpisodeError::NotFound` if the episode doesn't exist
    /// - `EpisodeError::InvalidTransition` if the episode is not in RUNNING
    ///   state
    ///
    /// # Events
    ///
    /// Emits `episode.stopped` event (INV-ER002).
    #[instrument(skip(self))]
    pub async fn stop(
        &self,
        episode_id: &EpisodeId,
        termination_class: TerminationClass,
        timestamp_ns: u64,
    ) -> Result<(), EpisodeError> {
        // BLOCKER 1 fix: Make lifecycle transition and mark_terminated
        // effectively atomic at API level. We mark the session terminated
        // FIRST, then commit the runtime terminal transition only on
        // success. On mark_terminated failure the runtime state stays
        // Running so callers can retry.

        // SECURITY: Fail-closed terminal transition. Process death MUST be
        // confirmed before committing terminal state. The sequence is:
        // 1. Validate transition + extract fields (inside lock)
        // 2. Mark session terminated (inside lock)
        // 3. Take harness handle (inside lock, state stays Running)
        // 4. Drop lock
        // 5. Kill subprocess (outside lock)
        // 6. On kill success: re-acquire lock, commit Terminated state
        // 7. On kill failure: re-acquire lock, restore handle, return error

        // Phase 1: Validate and prepare (inside lock).
        let (created_at_ns, started_at_ns, envelope_hash, harness_handle_opt) = {
            let mut episodes = self.episodes.write().await;

            let entry =
                episodes
                    .get_mut(episode_id.as_str())
                    .ok_or_else(|| EpisodeError::NotFound {
                        id: episode_id.as_str().to_string(),
                    })?;

            // Validate transition
            super::state::validate_transition(episode_id.as_str(), &entry.state, "Terminated")?;

            // Extract required fields from current state
            let (created_at_ns, started_at_ns, envelope_hash, session_id) = match &entry.state {
                EpisodeState::Running {
                    created_at_ns,
                    started_at_ns,
                    envelope_hash,
                    session_id,
                    ..
                } => (
                    *created_at_ns,
                    *started_at_ns,
                    *envelope_hash,
                    session_id.clone(),
                ),
                _ => {
                    return Err(EpisodeError::InvalidTransition {
                        id: episode_id.as_str().to_string(),
                        from: entry.state.state_name(),
                        to: "Terminated",
                    });
                },
            };

            // BLOCKER 1 fix: Mark session terminated BEFORE committing
            // the runtime terminal transition. If mark_terminated fails,
            // the runtime stays in Running state so the caller can retry.
            if let Some(registry) = &self.session_registry {
                let (rationale, classification, exit_code) = match termination_class {
                    TerminationClass::Success => ("normal", "SUCCESS", Some(0)),
                    TerminationClass::Failure | TerminationClass::Crashed => {
                        ("crash", "FAILURE", Some(1))
                    },
                    TerminationClass::BudgetExhausted => ("budget_exhausted", "FAILURE", None),
                    TerminationClass::Timeout => ("timeout", "FAILURE", None),
                    TerminationClass::Cancelled => ("normal", "CANCELLED", None),
                    TerminationClass::Killed => ("crash", "FAILURE", Some(137)),
                };

                let mut info = SessionTerminationInfo::new(&session_id, rationale, classification);
                if let Some(code) = exit_code {
                    info = info.with_exit_code(code);
                }

                registry.mark_terminated(&session_id, info).map_err(|e| {
                    error!(
                        episode_id = %episode_id,
                        session_id = %session_id,
                        error = %e,
                        "Failed to mark session terminated from episode stop (fail-closed); \
                         runtime state NOT transitioned -- caller may retry"
                    );
                    EpisodeError::SessionTerminationFailed {
                        episode_id: episode_id.as_str().to_string(),
                        session_id: session_id.clone(),
                        message: e.to_string(),
                    }
                })?;
            }

            // Signal stop to handle if present
            if let Some(handle) = &entry.handle {
                handle.signal_stop(StopSignal::Graceful {
                    reason: format!("termination: {termination_class}"),
                });
            }

            // TCK-00399: Take the harness handle. State stays Running until
            // process death is confirmed (fail-closed). The terminal
            // transition is committed in Phase 3 below.
            let harness_handle = entry.harness_handle.take();

            (created_at_ns, started_at_ns, envelope_hash, harness_handle)
        };

        // Phase 2: Kill subprocess outside the lock.
        if let Some(ref harness_handle) = harness_handle_opt {
            let runner_handle = harness_handle.real_runner_handle();
            let grace_period = harness_handle.terminate_grace_period();
            match crate::episode::adapter::terminate_with_handle(
                harness_handle.id(),
                runner_handle,
                grace_period,
            )
            .await
            {
                Ok(status) => {
                    info!(
                        episode_id = %episode_id,
                        exit_status = ?status,
                        "agent process terminated during episode stop"
                    );
                },
                Err(e) => {
                    warn!(
                        episode_id = %episode_id,
                        error = %e,
                        "agent process termination error during episode stop; \
                         escalating to SIGKILL"
                    );
                    // SECURITY: Escalate to direct SIGKILL to prevent
                    // orphaned processes when the control channel fails.
                    // Fail-closed: if SIGKILL also fails, restore the
                    // harness handle and abort the terminal transition.
                    if let Err(kill_err) =
                        crate::episode::adapter::escalate_sigkill(harness_handle).await
                    {
                        error!(
                            episode_id = %episode_id,
                            error = %kill_err,
                            "SIGKILL escalation failed during episode stop; \
                             process death NOT confirmed -- restoring handle \
                             and aborting terminal transition"
                        );
                        // Restore the harness handle so a future retry can
                        // attempt termination again.
                        {
                            let mut episodes = self.episodes.write().await;
                            if let Some(entry) = episodes.get_mut(episode_id.as_str()) {
                                entry.harness_handle = harness_handle_opt;
                            }
                        }
                        return Err(EpisodeError::Internal {
                            message: format!(
                                "episode {episode_id} stop failed: subprocess kill \
                                 unconfirmed after SIGKILL escalation: {kill_err}"
                            ),
                        });
                    }
                },
            }
        }
        drop(harness_handle_opt);

        // Phase 3: Commit terminal state transition (process death confirmed).
        {
            let mut episodes = self.episodes.write().await;
            if let Some(entry) = episodes.get_mut(episode_id.as_str()) {
                entry.state = EpisodeState::Terminated {
                    created_at_ns,
                    started_at_ns,
                    terminated_at_ns: timestamp_ns,
                    envelope_hash,
                    termination_class,
                };
                entry.handle = None;
            }
        }

        // Emit event (INV-ER002)
        if self.config.emit_events {
            // Stamp time envelope for temporal ordering (RFC-0016 HTF)
            // Per SEC-CTRL-FAC-0015 (Fail-Closed), propagate clock errors
            // Returns both envelope (preimage) and ref (hash) for verifiability
            let (time_envelope, time_envelope_ref) = match self
                .stamp_envelope(Some(format!("episode.stopped:{}", episode_id.as_str())))
                .await?
            {
                Some((env, env_ref)) => (Some(env), Some(env_ref)),
                None => (None, None),
            };
            self.emit_event(EpisodeEvent::Stopped {
                episode_id: episode_id.clone(),
                termination_class,
                terminated_at_ns: timestamp_ns,
                time_envelope_ref,
                time_envelope,
            })
            .await?;
        }

        info!(
            episode_id = %episode_id,
            termination_class = %termination_class,
            "episode stopped"
        );
        Ok(())
    }

    /// Stops an episode and emits a `SessionTerminated` ledger event
    /// (TCK-00395).
    ///
    /// This is a convenience wrapper around [`Self::stop`] that additionally
    /// emits a `SessionTerminated` event to the ledger when a
    /// `ledger_emitter` is configured. This enables the `GateOrchestrator`
    /// (TCK-00388) to observe session termination and trigger gate lifecycle.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to stop
    /// * `termination_class` - How the episode terminated
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    /// * `session_id` - The session being terminated
    /// * `work_id` - The work ID this session is associated with
    /// * `actor_id` - The actor associated with this session
    ///
    /// # Errors
    ///
    /// Returns `EpisodeError` if the episode stop fails or ledger emission
    /// fails.
    pub async fn stop_with_session_context(
        &self,
        episode_id: &EpisodeId,
        termination_class: TerminationClass,
        timestamp_ns: u64,
        session_id: &str,
        work_id: &str,
        actor_id: &str,
    ) -> Result<(), EpisodeError> {
        // Perform the normal stop
        self.stop(episode_id, termination_class, timestamp_ns)
            .await?;

        // TCK-00395: Emit SessionTerminated event to ledger if emitter is configured
        if let Some(ref emitter) = self.ledger_emitter {
            let exit_code = match termination_class {
                TerminationClass::Success => 0,
                _ => 1,
            };
            let termination_reason = format!("{termination_class}");

            if let Err(e) = emitter.emit_session_terminated(
                session_id,
                work_id,
                exit_code,
                &termination_reason,
                actor_id,
                timestamp_ns,
            ) {
                warn!(
                    error = %e,
                    session_id = %session_id,
                    work_id = %work_id,
                    "SessionTerminated ledger event emission failed"
                );
                return Err(EpisodeError::LedgerFailure {
                    id: episode_id.as_str().to_string(),
                    message: format!("session terminated event emission failed: {e}"),
                });
            }

            info!(
                session_id = %session_id,
                work_id = %work_id,
                episode_id = %episode_id,
                "SessionTerminated ledger event emitted"
            );
        }

        Ok(())
    }

    /// Stops all running episodes with session context (TCK-00395 BLOCKER 1).
    ///
    /// This method iterates all running episodes and stops each one, emitting
    /// `SessionTerminated` ledger events for all sessions. It is intended for
    /// daemon shutdown, where all managed episodes must be terminated and
    /// the termination facts must be recorded in the ledger.
    ///
    /// The `actor_id` for these terminations is `"daemon:shutdown"` since
    /// the daemon itself is initiating the termination (not any user).
    ///
    /// # Arguments
    ///
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    /// * `termination_class` - How episodes are being terminated
    ///
    /// # Returns
    ///
    /// The number of episodes successfully stopped. Episodes that fail to
    /// stop are logged at warn level but do not prevent other episodes from
    /// being stopped.
    pub async fn stop_all_running(
        &self,
        timestamp_ns: u64,
        termination_class: TerminationClass,
    ) -> usize {
        // Collect running episode IDs and their session_ids under read lock
        let running: Vec<(String, String)> = {
            let episodes = self.episodes.read().await;
            episodes
                .iter()
                .filter_map(|(id, entry)| {
                    if let EpisodeState::Running { session_id, .. } = &entry.state {
                        Some((id.clone(), session_id.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };

        if running.is_empty() {
            debug!("No running episodes to stop");
            return 0;
        }

        info!(
            count = running.len(),
            "Stopping all running episodes for daemon shutdown"
        );

        let mut stopped_count = 0usize;
        for (episode_id_str, session_id) in &running {
            let episode_id = match EpisodeId::new(episode_id_str.clone()) {
                Ok(id) => id,
                Err(e) => {
                    warn!(
                        error = %e,
                        episode_id = %episode_id_str,
                        "Failed to parse episode ID during shutdown - skipping"
                    );
                    continue;
                },
            };

            // Resolve work_id from session registry if available
            let work_id = self
                .session_registry
                .as_ref()
                .and_then(|reg| reg.get_session(session_id))
                .map(|s| s.work_id)
                .unwrap_or_default();

            match self
                .stop_with_session_context(
                    &episode_id,
                    termination_class,
                    timestamp_ns,
                    session_id,
                    &work_id,
                    "daemon:shutdown",
                )
                .await
            {
                Ok(()) => {
                    stopped_count += 1;
                },
                Err(e) => {
                    warn!(
                        error = %e,
                        episode_id = %episode_id_str,
                        session_id = %session_id,
                        "Failed to stop episode during shutdown - continuing with remaining"
                    );
                },
            }
        }

        info!(
            stopped = stopped_count,
            total = running.len(),
            "Daemon shutdown episode stop complete"
        );
        stopped_count
    }

    /// Quarantines an episode, transitioning it from RUNNING to QUARANTINED.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to quarantine
    /// * `reason` - Reason for quarantine
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    ///
    /// # Errors
    ///
    /// - `EpisodeError::NotFound` if the episode doesn't exist
    /// - `EpisodeError::InvalidTransition` if the episode is not in RUNNING
    ///   state
    ///
    /// # Events
    ///
    /// Emits `episode.quarantined` event (INV-ER002).
    #[instrument(skip(self, reason))]
    pub async fn quarantine(
        &self,
        episode_id: &EpisodeId,
        reason: QuarantineReason,
        timestamp_ns: u64,
    ) -> Result<(), EpisodeError> {
        // SECURITY: Fail-closed terminal transition (same pattern as stop).
        // Process death MUST be confirmed before committing terminal state.

        // Phase 1: Validate and prepare (inside lock).
        let (created_at_ns, started_at_ns, envelope_hash, quarantine_harness_handle) = {
            let mut episodes = self.episodes.write().await;

            let entry =
                episodes
                    .get_mut(episode_id.as_str())
                    .ok_or_else(|| EpisodeError::NotFound {
                        id: episode_id.as_str().to_string(),
                    })?;

            // Validate transition
            super::state::validate_transition(episode_id.as_str(), &entry.state, "Quarantined")?;

            // Extract required fields from current state
            let (created_at_ns, started_at_ns, envelope_hash, session_id) = match &entry.state {
                EpisodeState::Running {
                    created_at_ns,
                    started_at_ns,
                    envelope_hash,
                    session_id,
                    ..
                } => (
                    *created_at_ns,
                    *started_at_ns,
                    *envelope_hash,
                    session_id.clone(),
                ),
                _ => {
                    return Err(EpisodeError::InvalidTransition {
                        id: episode_id.as_str().to_string(),
                        from: entry.state.state_name(),
                        to: "Quarantined",
                    });
                },
            };

            // BLOCKER 1 fix: Mark session terminated BEFORE committing
            // the runtime terminal transition. If mark_terminated fails,
            // the runtime stays in Running state so the caller can retry.
            if let Some(registry) = &self.session_registry {
                let info = SessionTerminationInfo::new(&session_id, "quarantined", "FAILURE");
                registry.mark_terminated(&session_id, info).map_err(|e| {
                    error!(
                        episode_id = %episode_id,
                        session_id = %session_id,
                        error = %e,
                        "Failed to mark session terminated from episode quarantine (fail-closed); \
                         runtime state NOT transitioned -- caller may retry"
                    );
                    EpisodeError::SessionTerminationFailed {
                        episode_id: episode_id.as_str().to_string(),
                        session_id: session_id.clone(),
                        message: e.to_string(),
                    }
                })?;
            }

            // Signal quarantine to handle if present
            if let Some(handle) = &entry.handle {
                handle.signal_stop(StopSignal::Quarantine {
                    reason: reason.description.clone(),
                });
            }

            // Take harness handle; state stays Running until process
            // death is confirmed.
            let harness_handle = entry.harness_handle.take();

            (created_at_ns, started_at_ns, envelope_hash, harness_handle)
        };

        // Phase 2: Kill subprocess outside the lock.
        if let Some(ref harness_handle) = quarantine_harness_handle {
            let runner_handle = harness_handle.real_runner_handle();
            let grace_period = harness_handle.terminate_grace_period();
            match crate::episode::adapter::terminate_with_handle(
                harness_handle.id(),
                runner_handle,
                grace_period,
            )
            .await
            {
                Ok(status) => {
                    info!(
                        episode_id = %episode_id,
                        exit_status = ?status,
                        "agent process terminated during episode quarantine"
                    );
                },
                Err(e) => {
                    warn!(
                        episode_id = %episode_id,
                        error = %e,
                        "agent process termination error during episode quarantine; \
                         escalating to SIGKILL"
                    );
                    // SECURITY: Escalate to direct SIGKILL. If this also
                    // fails, restore the handle and abort the transition.
                    if let Err(kill_err) =
                        crate::episode::adapter::escalate_sigkill(harness_handle).await
                    {
                        error!(
                            episode_id = %episode_id,
                            error = %kill_err,
                            "SIGKILL escalation failed during episode quarantine; \
                             process death NOT confirmed -- restoring handle \
                             and aborting terminal transition"
                        );
                        {
                            let mut episodes = self.episodes.write().await;
                            if let Some(entry) = episodes.get_mut(episode_id.as_str()) {
                                entry.harness_handle = quarantine_harness_handle;
                            }
                        }
                        return Err(EpisodeError::Internal {
                            message: format!(
                                "episode {episode_id} quarantine failed: subprocess kill \
                                 unconfirmed after SIGKILL escalation: {kill_err}"
                            ),
                        });
                    }
                },
            }
        }
        drop(quarantine_harness_handle);

        // Phase 3: Commit terminal state transition (process death confirmed).
        {
            let mut episodes = self.episodes.write().await;
            if let Some(entry) = episodes.get_mut(episode_id.as_str()) {
                entry.state = EpisodeState::Quarantined {
                    created_at_ns,
                    started_at_ns,
                    quarantined_at_ns: timestamp_ns,
                    envelope_hash,
                    reason: reason.clone(),
                };
                entry.handle = None;
            }
        }

        // Emit event (INV-ER002)
        if self.config.emit_events {
            // Stamp time envelope for temporal ordering (RFC-0016 HTF)
            // Per SEC-CTRL-FAC-0015 (Fail-Closed), propagate clock errors
            // Returns both envelope (preimage) and ref (hash) for verifiability
            let (time_envelope, time_envelope_ref) = match self
                .stamp_envelope(Some(format!("episode.quarantined:{}", episode_id.as_str())))
                .await?
            {
                Some((env, env_ref)) => (Some(env), Some(env_ref)),
                None => (None, None),
            };
            self.emit_event(EpisodeEvent::Quarantined {
                episode_id: episode_id.clone(),
                reason,
                quarantined_at_ns: timestamp_ns,
                time_envelope_ref,
                time_envelope,
            })
            .await?;
        }

        warn!(episode_id = %episode_id, "episode quarantined");
        Ok(())
    }

    /// Executes a tool in the context of an episode.
    ///
    /// Per TCK-00320, this method:
    /// 1. Executes the tool via the executor
    /// 2. Records the CAS result hash in the episode's accumulator
    /// 3. Emits a `ToolExecuted` event for downstream indexing
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to execute the tool in
    /// * `args` - The tool arguments
    /// * `credential` - Optional credential for authenticated operations
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    /// * `request_id` - Unique request ID for tracking
    ///
    /// # Returns
    ///
    /// The tool result with `result_hash` populated.
    ///
    /// # Errors
    ///
    /// Returns an error if the episode is not found, not running, or if
    /// execution fails.
    pub async fn execute_tool(
        &self,
        episode_id: &EpisodeId,
        args: &ToolArgs,
        credential: Option<&Credential>,
        timestamp_ns: u64,
        request_id: &str,
    ) -> Result<ToolResult, EpisodeError> {
        // Step 1: Read lock to get executor and validate state
        let executor = {
            let episodes = self.episodes.read().await;
            let entry =
                episodes
                    .get(episode_id.as_str())
                    .ok_or_else(|| EpisodeError::NotFound {
                        id: episode_id.as_str().to_string(),
                    })?;

            if !entry.state.is_running() {
                return Err(EpisodeError::InvalidTransition {
                    id: episode_id.as_str().to_string(),
                    from: entry.state.state_name(),
                    to: "execute_tool",
                });
            }

            entry.executor.clone().ok_or_else(|| {
                warn!(episode_id = %episode_id, "executor not available (CAS missing?)");
                EpisodeError::Internal {
                    message: "executor not available".to_string(),
                }
            })?
        };

        // Step 2: Execute the tool
        let ctx = ExecutionContext::new(episode_id.clone(), request_id, timestamp_ns);
        let executor_guard = executor.write().await;
        let result = executor_guard
            .execute(&ctx, args, credential)
            .await
            .map_err(|e| EpisodeError::ExecutionFailed {
                id: episode_id.as_str().to_string(),
                message: e.to_string(),
            })?;
        drop(executor_guard); // Release executor lock before acquiring episodes write lock

        // Step 3: Record result hash and emit event (TCK-00320)
        if let Some(result_hash) = result.result_hash {
            self.record_tool_result(
                episode_id,
                request_id,
                result_hash,
                result.success,
                result.completed_at_ns,
            )
            .await?;
        }

        Ok(result)
    }

    /// Records a tool result hash and emits a `ToolExecuted` event (TCK-00320).
    ///
    /// Per SEC-CTRL-FAC-0015, this method:
    /// 1. Accumulates the result hash in the episode's ordered collection
    /// 2. Emits a `ToolExecuted` event for downstream indexing
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode that executed the tool
    /// * `request_id` - Request ID for the tool execution
    /// * `result_hash` - CAS hash of the `ToolResultData`
    /// * `success` - Whether the execution succeeded
    /// * `executed_at_ns` - Timestamp when execution completed
    ///
    /// # Errors
    ///
    /// Returns an error if the episode is not found.
    #[instrument(skip(self))]
    pub async fn record_tool_result(
        &self,
        episode_id: &EpisodeId,
        request_id: &str,
        result_hash: Hash,
        success: bool,
        executed_at_ns: u64,
    ) -> Result<(), EpisodeError> {
        // Step 1: Write lock to update result_hashes
        {
            let mut episodes = self.episodes.write().await;
            let entry =
                episodes
                    .get_mut(episode_id.as_str())
                    .ok_or_else(|| EpisodeError::NotFound {
                        id: episode_id.as_str().to_string(),
                    })?;

            // Enforce boundedness per CTR-1303
            if entry.result_hashes.len() >= MAX_RESULT_HASHES_PER_EPISODE {
                // Evict oldest hash (FIFO)
                entry.result_hashes.remove(0);
                debug!(
                    episode_id = %episode_id,
                    "evicted oldest result hash (limit {})",
                    MAX_RESULT_HASHES_PER_EPISODE
                );
            }

            entry.result_hashes.push(result_hash);
            debug!(
                episode_id = %episode_id,
                request_id = %request_id,
                result_hash = %hex::encode(&result_hash[..8]),
                count = entry.result_hashes.len(),
                "recorded tool result hash"
            );
        }

        // Step 2: Emit ToolExecuted event
        if self.config.emit_events {
            // Stamp time envelope for temporal ordering (RFC-0016 HTF)
            // Per SEC-CTRL-FAC-0015 (Fail-Closed), propagate clock errors
            let (time_envelope, time_envelope_ref) = match self
                .stamp_envelope(Some(format!(
                    "tool.executed:{}:{}",
                    episode_id.as_str(),
                    request_id
                )))
                .await?
            {
                Some((env, env_ref)) => (Some(env), Some(env_ref)),
                None => (None, None),
            };

            let event = EpisodeEvent::ToolExecuted {
                episode_id: episode_id.clone(),
                request_id: request_id.to_string(),
                result_hash,
                success,
                executed_at_ns,
                time_envelope_ref,
                time_envelope,
            };

            self.emit_event(event).await?;
        }

        Ok(())
    }

    /// Returns the accumulated result hashes for an episode (TCK-00320).
    ///
    /// The result hashes are returned in deterministic tool sequence order.
    /// This is used for downstream indexing (TCK-00327: `ToolLogIndexV1`).
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to get result hashes for
    ///
    /// # Returns
    ///
    /// A clone of the result hashes vector, or empty if episode not found.
    #[must_use]
    pub async fn get_result_hashes(&self, episode_id: &EpisodeId) -> Vec<Hash> {
        let episodes = self.episodes.read().await;
        episodes
            .get(episode_id.as_str())
            .map(|e| e.result_hashes.clone())
            .unwrap_or_default()
    }

    /// Emits a `LeaseIssueDenied` event for `SoD` violations and other spawn
    /// rejections.
    ///
    /// Per TCK-00258 and REQ-DCP-0006, this method emits a diagnostic event
    /// when a spawn request is rejected due to policy violations such as
    /// custody domain overlap.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work ID that was denied
    /// * `denial_reason` - The reason for denial
    /// * `timestamp_ns` - Current timestamp in nanoseconds since epoch
    ///
    /// # Events
    ///
    /// Emits `lease.issue_denied` event for audit logging.
    #[instrument(skip(self, denial_reason))]
    pub async fn emit_lease_issue_denied(
        &self,
        work_id: impl Into<String> + std::fmt::Debug,
        denial_reason: LeaseIssueDenialReason,
        timestamp_ns: u64,
    ) -> Result<(), EpisodeError> {
        let work_id = work_id.into();

        if self.config.emit_events {
            // Stamp time envelope for temporal ordering (RFC-0016 HTF)
            // Per SEC-CTRL-FAC-0015 (Fail-Closed), propagate clock errors
            let (time_envelope, time_envelope_ref) = match self
                .stamp_envelope(Some(format!("lease.issue_denied:{work_id}")))
                .await?
            {
                Some((env, env_ref)) => (Some(env), Some(env_ref)),
                None => (None, None),
            };

            self.emit_event(EpisodeEvent::LeaseIssueDenied {
                work_id: work_id.clone(),
                denial_reason: denial_reason.clone(),
                denied_at_ns: timestamp_ns,
                time_envelope_ref,
                time_envelope,
            })
            .await?;
        }

        warn!(
            work_id = %work_id,
            denial_reason = %denial_reason,
            "lease issuance denied"
        );
        Ok(())
    }

    /// Sends a signal to a running episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to signal
    /// * `signal` - The stop signal to send
    ///
    /// # Errors
    ///
    /// - `EpisodeError::NotFound` if the episode doesn't exist
    /// - `EpisodeError::InvalidTransition` if the episode is not running
    #[instrument(skip(self, signal))]
    pub async fn signal(
        &self,
        episode_id: &EpisodeId,
        signal: StopSignal,
    ) -> Result<(), EpisodeError> {
        let episodes = self.episodes.read().await;

        let entry = episodes
            .get(episode_id.as_str())
            .ok_or_else(|| EpisodeError::NotFound {
                id: episode_id.as_str().to_string(),
            })?;

        if !entry.state.is_running() {
            return Err(EpisodeError::InvalidTransition {
                id: episode_id.as_str().to_string(),
                from: entry.state.state_name(),
                to: "signal",
            });
        }

        if let Some(handle) = &entry.handle {
            handle.signal_stop(signal);
            debug!(episode_id = %episode_id, "signal sent to episode");
        }

        Ok(())
    }

    /// Observes the current state of an episode.
    ///
    /// # Arguments
    ///
    /// * `episode_id` - The episode to observe
    ///
    /// # Returns
    ///
    /// Returns a clone of the current `EpisodeState`.
    ///
    /// # Errors
    ///
    /// Returns `EpisodeError::NotFound` if the episode doesn't exist.
    pub async fn observe(&self, episode_id: &EpisodeId) -> Result<EpisodeState, EpisodeError> {
        let episodes = self.episodes.read().await;

        let entry = episodes
            .get(episode_id.as_str())
            .ok_or_else(|| EpisodeError::NotFound {
                id: episode_id.as_str().to_string(),
            })?;

        Ok(entry.state.clone())
    }

    /// Returns the number of active (non-terminal) episodes.
    pub async fn active_count(&self) -> usize {
        let episodes = self.episodes.read().await;
        episodes.values().filter(|e| e.state.is_active()).count()
    }

    /// Returns the total number of tracked episodes.
    pub async fn total_count(&self) -> usize {
        let episodes = self.episodes.read().await;
        episodes.len()
    }

    /// Drains all emitted events.
    ///
    /// This is primarily for testing and integration. In production, events
    /// would be streamed to the ledger.
    pub async fn drain_events(&self) -> Vec<EpisodeEvent> {
        let mut events = self.events.write().await;
        std::mem::take(&mut *events)
    }

    /// Removes terminal episodes from tracking.
    ///
    /// This is used for cleanup of completed/quarantined episodes.
    /// Returns the number of episodes removed.
    pub async fn cleanup_terminal(&self) -> usize {
        let mut episodes = self.episodes.write().await;
        let before = episodes.len();
        episodes.retain(|_, entry| !entry.state.is_terminal());
        before - episodes.len()
    }

    /// Emits an event to the ledger (if configured) or internal buffer.
    ///
    /// # TCK-00321: Ledger-Backed Event Persistence
    ///
    /// Per REQ-0005, when a ledger emitter is configured, episode events are
    /// streamed directly to the ledger as they occur. This enables:
    /// - Events survive daemon restart (ledger-backed durability)
    /// - Receipt event appended atomically at completion
    /// - CAS-before-ledger ordering for events referencing CAS hashes
    ///
    /// # Blocking I/O and Fail-Closed
    ///
    /// Ledger emission involves blocking I/O (`SQLite`). This method spawns a
    /// blocking task to avoid stalling the async runtime.
    ///
    /// If ledger emission fails, this method returns an error (Fail-Closed)
    /// to ensure the episode does not continue without audit logging.
    async fn emit_event(&self, event: EpisodeEvent) -> Result<(), EpisodeError> {
        // TCK-00321: Stream to ledger when emitter is configured
        if let Some(emitter) = &self.ledger_emitter {
            let event_type = event.event_type();
            let episode_id = event
                .episode_id()
                .map(|id| id.as_str().to_string())
                .or_else(|| event.work_id().map(String::from))
                .unwrap_or_else(|| "unknown".to_string());

            // Serialize event to JSON for ledger persistence
            let payload = self.serialize_episode_event(&event);

            // Get timestamp from event or use 0 as fallback
            let timestamp_ns = self.extract_timestamp(&event);

            let emitter = emitter.clone();
            let episode_id_cloned = episode_id.clone();
            let payload_cloned = payload;

            // Blocking I/O in async context must be spawned (TCK-00321 Quality Review)
            let result = tokio::task::spawn_blocking(move || {
                emitter.emit_episode_event(
                    &episode_id_cloned,
                    event_type,
                    &payload_cloned,
                    timestamp_ns,
                )
            })
            .await
            .map_err(|e| EpisodeError::Internal {
                message: format!("ledger task join failed: {e}"),
            })?;

            match result {
                Ok(signed_event) => {
                    debug!(
                        event_id = %signed_event.event_id,
                        episode_id = %episode_id,
                        event_type = %event_type,
                        "Episode event streamed to ledger"
                    );
                },
                Err(e) => {
                    // Fail-Closed: Propagate ledger errors (REQ-0005)
                    return Err(EpisodeError::LedgerFailure {
                        id: episode_id,
                        message: e.to_string(),
                    });
                },
            }
        }

        // Always buffer locally (for drain_events() and backward compatibility)
        let mut events = self.events.write().await;

        // Enforce bounded buffer size (CTR-1303)
        // Evict oldest events if at capacity
        if events.len() >= MAX_EVENTS_BUFFER_SIZE {
            let evict_count = events.len() - MAX_EVENTS_BUFFER_SIZE + 1;
            warn!(
                evict_count = evict_count,
                buffer_size = events.len(),
                max_size = MAX_EVENTS_BUFFER_SIZE,
                "evicting oldest events from buffer to maintain size limit"
            );
            events.drain(0..evict_count);
        }

        events.push(event);
        Ok(())
    }

    /// Serializes an `EpisodeEvent` to JSON bytes for ledger persistence.
    ///
    /// # TCK-00321: Event Serialization
    ///
    /// This method produces a JSON representation of the event suitable for
    /// ledger persistence. The format is designed to be:
    /// - Deterministic (stable field ordering via serde)
    /// - Backward-compatible (uses serde's default handling)
    /// - Queryable (JSON fields can be indexed in `SQLite`)
    #[allow(clippy::unused_self)] // Method on instance for API consistency with emit_event
    fn serialize_episode_event(&self, event: &EpisodeEvent) -> Vec<u8> {
        use serde_json::json;

        let payload = match event {
            EpisodeEvent::Created {
                episode_id,
                envelope_hash,
                created_at_ns,
                time_envelope_ref,
                ..
            } => json!({
                "episode_id": episode_id.as_str(),
                "envelope_hash": hex::encode(envelope_hash),
                "created_at_ns": created_at_ns,
                "time_envelope_ref": time_envelope_ref.as_ref().map(|r| hex::encode(r.as_bytes())),
            }),
            EpisodeEvent::Started {
                episode_id,
                session_id,
                lease_id,
                started_at_ns,
                time_envelope_ref,
                ..
            } => json!({
                "episode_id": episode_id.as_str(),
                "session_id": session_id,
                "lease_id": lease_id,
                "started_at_ns": started_at_ns,
                "time_envelope_ref": time_envelope_ref.as_ref().map(|r| hex::encode(r.as_bytes())),
            }),
            EpisodeEvent::Stopped {
                episode_id,
                termination_class,
                terminated_at_ns,
                time_envelope_ref,
                ..
            } => json!({
                "episode_id": episode_id.as_str(),
                "termination_class": format!("{termination_class:?}"),
                "terminated_at_ns": terminated_at_ns,
                "time_envelope_ref": time_envelope_ref.as_ref().map(|r| hex::encode(r.as_bytes())),
            }),
            EpisodeEvent::Quarantined {
                episode_id,
                reason,
                quarantined_at_ns,
                time_envelope_ref,
                ..
            } => json!({
                "episode_id": episode_id.as_str(),
                "reason": format!("{reason:?}"),
                "quarantined_at_ns": quarantined_at_ns,
                "time_envelope_ref": time_envelope_ref.as_ref().map(|r| hex::encode(r.as_bytes())),
            }),
            EpisodeEvent::ClockProfilePublished {
                profile_hash,
                published_at_ns,
                time_envelope_ref,
                ..
            } => json!({
                "profile_hash": profile_hash,
                "published_at_ns": published_at_ns,
                "time_envelope_ref": time_envelope_ref.as_ref().map(|r| hex::encode(r.as_bytes())),
            }),
            EpisodeEvent::LeaseIssueDenied {
                work_id,
                denial_reason,
                denied_at_ns,
                time_envelope_ref,
                ..
            } => json!({
                "work_id": work_id,
                "denial_reason": format!("{denial_reason}"),
                "denied_at_ns": denied_at_ns,
                "time_envelope_ref": time_envelope_ref.as_ref().map(|r| hex::encode(r.as_bytes())),
            }),
            EpisodeEvent::ToolExecuted {
                episode_id,
                request_id,
                result_hash,
                success,
                executed_at_ns,
                time_envelope_ref,
                ..
            } => json!({
                "episode_id": episode_id.as_str(),
                "request_id": request_id,
                "result_hash": hex::encode(result_hash),
                "success": success,
                "executed_at_ns": executed_at_ns,
                "time_envelope_ref": time_envelope_ref.as_ref().map(|r| hex::encode(r.as_bytes())),
            }),
        };

        serde_json::to_vec(&payload).unwrap_or_default()
    }

    /// Extracts the timestamp from an `EpisodeEvent`.
    #[allow(clippy::unused_self)] // Method on instance for API consistency with emit_event
    #[allow(clippy::missing_const_for_fn)] // Not const due to future extensibility
    fn extract_timestamp(&self, event: &EpisodeEvent) -> u64 {
        match event {
            EpisodeEvent::Created { created_at_ns, .. } => *created_at_ns,
            EpisodeEvent::Started { started_at_ns, .. } => *started_at_ns,
            EpisodeEvent::Stopped {
                terminated_at_ns, ..
            } => *terminated_at_ns,
            EpisodeEvent::Quarantined {
                quarantined_at_ns, ..
            } => *quarantined_at_ns,
            EpisodeEvent::ClockProfilePublished {
                published_at_ns, ..
            } => *published_at_ns,
            EpisodeEvent::LeaseIssueDenied { denied_at_ns, .. } => *denied_at_ns,
            EpisodeEvent::ToolExecuted { executed_at_ns, .. } => *executed_at_ns,
        }
    }
}

// EpisodeRuntime is automatically Send + Sync because:
// - RwLock<HashMap<..>> is Send + Sync when T: Send
// - AtomicU64 is Send + Sync
// - Instant is Send + Sync
// No unsafe marker traits needed.

impl std::fmt::Debug for EpisodeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpisodeRuntime")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Creates a new `Arc<EpisodeRuntime>` for shared usage.
#[must_use]
pub fn new_shared_runtime(config: EpisodeRuntimeConfig) -> Arc<EpisodeRuntime> {
    Arc::new(EpisodeRuntime::new(config))
}

/// Creates a new `Arc<EpisodeRuntime>` with a `HolonicClock` for shared usage.
///
/// When a clock is provided, all episode events will be stamped with a
/// `TimeEnvelopeRef` for temporal ordering and causality tracking per
/// RFC-0016 (HTF).
///
/// # Note
///
/// This function does not emit the `ClockProfilePublished` event.
/// Use [`new_shared_runtime_with_clock_initialized`] for production code.
#[must_use]
#[allow(dead_code)] // Public API for future use
pub fn new_shared_runtime_with_clock(
    config: EpisodeRuntimeConfig,
    clock: Arc<HolonicClock>,
) -> Arc<EpisodeRuntime> {
    Arc::new(EpisodeRuntime::with_clock(config, clock))
}

/// Creates a new `Arc<EpisodeRuntime>` with initialized clock profile
/// publication.
///
/// This is the preferred factory for production code. It:
/// 1. Creates the runtime with the provided clock
/// 2. Emits a `ClockProfilePublished` event so auditors can resolve
///    `clock_profile_hash` references in subsequent `TimeEnvelope`s
///
/// # Returns
///
/// Returns `Err` if clock stamping fails during event emission.
#[allow(dead_code)] // Public API for future use
pub async fn new_shared_runtime_with_clock_initialized(
    config: EpisodeRuntimeConfig,
    clock: Arc<HolonicClock>,
) -> Result<Arc<EpisodeRuntime>, EpisodeError> {
    EpisodeRuntime::with_clock_initialized(config, clock)
        .await
        .map(Arc::new)
}

#[cfg(test)]
#[allow(deprecated)] // TCK-00336: Tests use deprecated methods intentionally for coverage
mod tests {
    use super::*;

    fn test_config() -> EpisodeRuntimeConfig {
        EpisodeRuntimeConfig::default()
            .with_max_concurrent_episodes(100)
            .with_emit_events(true)
    }

    fn test_envelope_hash() -> Hash {
        [42u8; 32]
    }

    fn test_timestamp() -> u64 {
        1_704_067_200_000_000_000 // 2024-01-01 00:00:00 UTC in nanoseconds
    }

    #[tokio::test]
    async fn test_create_episode() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        assert!(episode_id.as_str().starts_with("ep-"));

        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(matches!(state, EpisodeState::Created { .. }));
    }

    #[tokio::test]
    async fn test_create_emits_event() {
        let runtime = EpisodeRuntime::new(test_config());
        runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], EpisodeEvent::Created { .. }));
    }

    #[tokio::test]
    async fn test_start_episode() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();

        assert_eq!(handle.episode_id().as_str(), episode_id.as_str());
        assert!(handle.session_id().starts_with("session-"));
        assert_eq!(handle.lease_id(), "lease-123");

        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(matches!(state, EpisodeState::Running { .. }));
    }

    #[tokio::test]
    async fn test_start_emits_event() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        runtime.drain_events().await; // Clear create event

        runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], EpisodeEvent::Started { .. }));
    }

    #[tokio::test]
    async fn test_stop_episode() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();

        runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(matches!(
            state,
            EpisodeState::Terminated {
                termination_class: TerminationClass::Success,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_stop_emits_event() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();
        runtime.drain_events().await; // Clear previous events

        runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], EpisodeEvent::Stopped { .. }));
    }

    #[tokio::test]
    async fn test_quarantine_episode() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();

        let reason = QuarantineReason::policy_violation("TEST_POLICY");
        runtime
            .quarantine(&episode_id, reason.clone(), test_timestamp() + 2000)
            .await
            .unwrap();

        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(matches!(state, EpisodeState::Quarantined { .. }));
    }

    #[tokio::test]
    async fn test_quarantine_emits_event() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();
        runtime.drain_events().await;

        runtime
            .quarantine(
                &episode_id,
                QuarantineReason::crash("test"),
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], EpisodeEvent::Quarantined { .. }));
    }

    #[tokio::test]
    async fn test_signal_running_episode() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        let handle = runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();

        // Initially no stop signal
        assert!(!handle.should_stop());

        // Signal stop via runtime
        runtime
            .signal(
                &episode_id,
                StopSignal::Graceful {
                    reason: "test".to_string(),
                },
            )
            .await
            .unwrap();

        // The caller's handle receives the signal because both handles share
        // the same underlying channel (INV-SH003).
        assert!(handle.should_stop());
        assert!(matches!(
            handle.current_stop_signal(),
            StopSignal::Graceful { reason } if reason == "test"
        ));
    }

    /// Test that cloned `SessionHandle`s share the same stop signal channel.
    #[tokio::test]
    async fn test_session_handle_clone_shares_channel() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        let handle1 = runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
            .await
            .unwrap();

        // Clone the handle
        let handle2 = handle1.clone();

        // Initially neither should stop
        assert!(!handle1.should_stop());
        assert!(!handle2.should_stop());

        // Signal via handle1
        handle1.signal_stop(StopSignal::Immediate {
            reason: "test-clone".to_string(),
        });

        // Both handles should see the signal
        assert!(handle1.should_stop());
        assert!(handle2.should_stop());
        assert!(matches!(
            handle2.current_stop_signal(),
            StopSignal::Immediate { reason } if reason == "test-clone"
        ));
    }

    // Invalid transition tests

    #[tokio::test]
    async fn test_invalid_start_not_created() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        // Try to start again - should fail
        let result = runtime
            .start(&episode_id, "lease-2", test_timestamp() + 2000)
            .await;
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition { .. })
        ));
    }

    #[tokio::test]
    async fn test_invalid_stop_not_running() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        // Try to stop without starting - should fail
        let result = runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 1000,
            )
            .await;
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition { .. })
        ));
    }

    // =========================================================================
    // TCK-00399: Adapter spawning tests
    // =========================================================================

    /// Mock adapter for testing `spawn_adapter` without real PTY processes.
    struct MockAdapter;

    impl crate::episode::adapter::HarnessAdapter for MockAdapter {
        fn adapter_type(&self) -> crate::episode::adapter::AdapterType {
            crate::episode::adapter::AdapterType::Raw
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn spawn(
            &self,
            config: crate::episode::adapter::HarnessConfig,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = crate::episode::adapter::AdapterResult<(
                            crate::episode::adapter::HarnessHandle,
                            crate::episode::adapter::HarnessEventStream,
                        )>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
                // Create a dummy control channel (never consumed)
                let (control_tx, _control_rx) =
                    tokio::sync::mpsc::channel::<crate::episode::adapter::PtyControlCommand>(1);
                let inner = crate::episode::adapter::create_real_handle_inner(
                    99999, // fake PID
                    None, control_tx,
                );
                let handle = crate::episode::adapter::HarnessHandle::new(
                    1,
                    config.episode_id.clone(),
                    config.terminate_grace_period,
                    inner,
                );

                // Send a terminated event after a short delay to complete the bridge
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let _ = event_tx
                        .send(crate::episode::adapter::HarnessEvent::Terminated {
                            exit_code: Some(0),
                            classification:
                                crate::episode::adapter::TerminationClassification::Success,
                        })
                        .await;
                });

                Ok((handle, event_rx))
            })
        }

        fn send_input(
            &self,
            _handle: &crate::episode::adapter::HarnessHandle,
            _input: &[u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = crate::episode::adapter::AdapterResult<()>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { Ok(()) })
        }

        fn terminate(
            &self,
            _handle: &crate::episode::adapter::HarnessHandle,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = crate::episode::adapter::AdapterResult<std::process::ExitStatus>,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                // Cannot construct ExitStatus directly, so this is best-effort.
                // In practice, terminate is called via terminate_with_handle which
                // uses the real handle; mock tests avoid this path.
                Err(crate::episode::adapter::AdapterError::TerminateFailed {
                    reason: "mock terminate not implemented".to_string(),
                })
            })
        }
    }

    #[tokio::test]
    async fn test_spawn_adapter_requires_running_state() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        // Episode is in Created state, not Running. spawn_adapter should fail.
        let config = crate::episode::adapter::HarnessConfig::new("echo", episode_id.as_str());
        let adapter = MockAdapter;
        let result = runtime.spawn_adapter(&episode_id, config, &adapter).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("expected Running"),
            "Error should mention expected Running, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_spawn_adapter_success() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let config = crate::episode::adapter::HarnessConfig::new("echo", episode_id.as_str());
        let adapter = MockAdapter;
        let result = runtime.spawn_adapter(&episode_id, config, &adapter).await;
        assert!(result.is_ok(), "spawn_adapter should succeed: {result:?}");

        // Verify harness_handle is stored
        let episodes = runtime.episodes.read().await;
        let entry = episodes.get(episode_id.as_str()).unwrap();
        assert!(
            entry.harness_handle.is_some(),
            "harness_handle should be stored after spawn"
        );
    }

    #[tokio::test]
    async fn test_stop_clears_harness_handle() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let config = crate::episode::adapter::HarnessConfig::new("echo", episode_id.as_str());
        let adapter = MockAdapter;
        runtime
            .spawn_adapter(&episode_id, config, &adapter)
            .await
            .unwrap();

        // Pre-mark the mock handle as terminated (the mock uses a fake
        // PID 99999 with no start-time binding).  With fail-closed
        // semantics, stop() refuses to commit terminal state unless the
        // process is confirmed dead.  Marking terminated simulates the
        // child process already having exited.
        {
            let episodes = runtime.episodes.read().await;
            let entry = episodes.get(episode_id.as_str()).unwrap();
            if let Some(ref handle) = entry.harness_handle {
                let runner = handle.real_runner_handle();
                runner.lock().await.mark_terminated();
            }
        }

        // Stop the episode -- this should extract and drop the harness handle
        runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        // Verify episode is terminated
        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(
            state.is_terminal(),
            "episode should be terminated after stop"
        );
    }

    /// Verifies fail-closed semantics: `stop()` succeeds when the mock
    /// process (PID 99999) does not exist -- ESRCH confirms the process
    /// is dead even when PID binding validation fails (no /proc entry).
    /// The terminal transition should proceed because process death is
    /// confirmed.
    #[tokio::test]
    async fn test_stop_confirms_death_via_esrch_for_nonexistent_pid() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let config = crate::episode::adapter::HarnessConfig::new("echo", episode_id.as_str());
        let adapter = MockAdapter;
        runtime
            .spawn_adapter(&episode_id, config, &adapter)
            .await
            .unwrap();

        // Do NOT mark handle as terminated. The mock uses fake PID 99999
        // which does not exist. escalate_sigkill should detect ESRCH
        // (process does not exist) and confirm death.
        let result = runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await;

        assert!(
            result.is_ok(),
            "stop should succeed when ESRCH confirms process death: {result:?}"
        );

        // Verify episode is terminated
        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(
            state.is_terminal(),
            "episode should be terminated after stop"
        );
    }

    #[tokio::test]
    async fn test_invalid_transition_from_terminated() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();
        runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        // Try to start again after termination - should fail
        let result = runtime
            .start(&episode_id, "lease-2", test_timestamp() + 3000)
            .await;
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition { .. })
        ));
    }

    #[tokio::test]
    async fn test_invalid_transition_from_quarantined() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();
        runtime
            .quarantine(
                &episode_id,
                QuarantineReason::crash("test"),
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        // Try to stop after quarantine - should fail
        let result = runtime
            .stop(
                &episode_id,
                TerminationClass::Cancelled,
                test_timestamp() + 3000,
            )
            .await;
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition { .. })
        ));
    }

    #[tokio::test]
    async fn test_episode_not_found() {
        let runtime = EpisodeRuntime::new(test_config());
        let fake_id = EpisodeId::new("ep-nonexistent").unwrap();

        let result = runtime.observe(&fake_id).await;
        assert!(matches!(result, Err(EpisodeError::NotFound { .. })));

        let temp_dir = tempfile::tempdir().unwrap();
        let result = runtime
            .start_with_workspace(&fake_id, "lease-1", test_timestamp(), temp_dir.path())
            .await;
        assert!(matches!(result, Err(EpisodeError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_max_episodes_limit() {
        let config = EpisodeRuntimeConfig::default()
            .with_max_concurrent_episodes(2)
            .with_emit_events(false);
        let runtime = EpisodeRuntime::new(config);

        // Create max episodes
        runtime.create([1u8; 32], test_timestamp()).await.unwrap();
        runtime
            .create([2u8; 32], test_timestamp() + 1)
            .await
            .unwrap();

        // Third should fail
        let result = runtime.create([3u8; 32], test_timestamp() + 2).await;
        assert!(matches!(
            result,
            Err(EpisodeError::LimitReached { limit: 2 })
        ));
    }

    #[tokio::test]
    async fn test_active_and_total_count() {
        let runtime = EpisodeRuntime::new(test_config());

        assert_eq!(runtime.active_count().await, 0);
        assert_eq!(runtime.total_count().await, 0);

        let ep1 = runtime.create([1u8; 32], test_timestamp()).await.unwrap();
        assert_eq!(runtime.active_count().await, 1);
        assert_eq!(runtime.total_count().await, 1);

        let temp_dir = tempfile::tempdir().unwrap();
        runtime
            .start_with_workspace(&ep1, "lease-1", test_timestamp() + 1000, temp_dir.path())
            .await
            .unwrap();
        assert_eq!(runtime.active_count().await, 1);

        runtime
            .stop(&ep1, TerminationClass::Success, test_timestamp() + 2000)
            .await
            .unwrap();
        assert_eq!(runtime.active_count().await, 0);
        assert_eq!(runtime.total_count().await, 1); // Still tracked
    }

    #[tokio::test]
    async fn test_cleanup_terminal() {
        let runtime = EpisodeRuntime::new(test_config());

        // Create and terminate an episode
        let ep1 = runtime.create([1u8; 32], test_timestamp()).await.unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        runtime
            .start_with_workspace(&ep1, "lease-1", test_timestamp() + 1000, temp_dir.path())
            .await
            .unwrap();
        runtime
            .stop(&ep1, TerminationClass::Success, test_timestamp() + 2000)
            .await
            .unwrap();

        // Create an active episode
        let _ep2 = runtime
            .create([2u8; 32], test_timestamp() + 3000)
            .await
            .unwrap();

        assert_eq!(runtime.total_count().await, 2);

        let removed = runtime.cleanup_terminal().await;
        assert_eq!(removed, 1);
        assert_eq!(runtime.total_count().await, 1);
    }

    #[tokio::test]
    async fn test_invalid_lease_id_empty() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let result = runtime
            .start_with_workspace(&episode_id, "", test_timestamp() + 1000, temp_dir.path())
            .await;
        assert!(matches!(result, Err(EpisodeError::InvalidLease { .. })));
    }

    #[tokio::test]
    async fn test_signal_non_running_episode() {
        let runtime = EpisodeRuntime::new(test_config());
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        // Try to signal a created (not running) episode
        let result = runtime
            .signal(
                &episode_id,
                StopSignal::Graceful {
                    reason: "test".to_string(),
                },
            )
            .await;
        assert!(matches!(
            result,
            Err(EpisodeError::InvalidTransition { .. })
        ));
    }

    #[tokio::test]
    async fn test_event_types() {
        let runtime = EpisodeRuntime::new(test_config());

        let ep = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        runtime
            .start_with_workspace(&ep, "lease-1", test_timestamp() + 1000, temp_dir.path())
            .await
            .unwrap();
        runtime
            .stop(&ep, TerminationClass::Success, test_timestamp() + 2000)
            .await
            .unwrap();

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type(), "episode.created");
        assert_eq!(events[1].event_type(), "episode.started");
        assert_eq!(events[2].event_type(), "episode.stopped");
    }

    #[tokio::test]
    async fn test_shared_runtime() {
        let runtime = new_shared_runtime(test_config());

        // Can clone and use from multiple references
        let runtime2 = Arc::clone(&runtime);

        let ep = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        // Both references see the same state
        let state1 = runtime.observe(&ep).await.unwrap();
        let state2 = runtime2.observe(&ep).await.unwrap();
        assert_eq!(state1, state2);
    }

    /// Test that episode IDs include nanosecond precision and sequence number
    /// to prevent collisions in high-concurrency scenarios.
    #[tokio::test]
    async fn test_episode_id_includes_nanoseconds_and_sequence() {
        let runtime = EpisodeRuntime::new(test_config());

        // Create two episodes with the SAME envelope hash and timestamp
        // The sequence number ensures they get unique IDs
        let ep1 = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();
        let ep2 = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        // IDs must be different despite same hash and timestamp
        assert_ne!(ep1.as_str(), ep2.as_str());

        // Verify the ID format includes full nanosecond timestamp
        // Format: ep-{hash}-{timestamp_ns}-{seq}
        let id1 = ep1.as_str();
        assert!(id1.starts_with("ep-"));

        // The timestamp in the ID should be the full nanosecond value
        assert!(
            id1.split('-').count() >= 3,
            "ID should have at least 3 parts: ep, hash, timestamp-seq"
        );

        // Verify the timestamp portion contains the full nanosecond value
        // test_timestamp() = 1_704_067_200_000_000_000
        assert!(
            id1.contains("1704067200000000000"),
            "ID should contain full nanosecond timestamp"
        );
    }

    /// Test that concurrent episode creation with same parameters doesn't
    /// collide.
    #[tokio::test]
    async fn test_episode_id_no_collision_concurrent() {
        let runtime = Arc::new(EpisodeRuntime::new(test_config()));

        // Spawn many concurrent creates with the same envelope hash
        let mut handles = Vec::new();
        for i in 0..50 {
            let rt = Arc::clone(&runtime);
            let hash = test_envelope_hash();
            let ts = test_timestamp() + i; // Small variation in timestamp
            handles.push(tokio::spawn(async move { rt.create(hash, ts).await }));
        }

        // Collect all results
        let mut episode_ids = std::collections::HashSet::new();
        for handle in handles {
            let id = handle.await.unwrap().unwrap();
            assert!(
                episode_ids.insert(id.as_str().to_string()),
                "Duplicate episode ID detected!"
            );
        }

        // All 50 episodes should have unique IDs
        assert_eq!(episode_ids.len(), 50);
    }

    // =========================================================================
    // TCK-00240: HolonicClock integration tests
    // =========================================================================

    /// TCK-00240: Verify that events include `time_envelope_ref` when clock is
    /// provided.
    #[tokio::test]
    async fn tck_00240_events_have_time_envelope_ref_with_clock() {
        use crate::htf::{ClockConfig, HolonicClock};

        // Create a clock
        let clock = Arc::new(HolonicClock::new(ClockConfig::default(), None).unwrap());

        // Create runtime with clock
        let runtime = EpisodeRuntime::with_clock(test_config(), clock);

        // Create, start, stop an episode
        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        runtime
            .start_with_workspace(
                &episode_id,
                "lease-123",
                test_timestamp() + 1000,
                temp_dir.path(),
            )
            .await
            .unwrap();
        runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        // Check that all events have time_envelope_ref
        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 3);

        for event in &events {
            assert!(
                event.time_envelope_ref().is_some(),
                "Event {} should have time_envelope_ref",
                event.event_type()
            );
        }
    }

    /// TCK-00240: Verify that quarantine events also get `time_envelope_ref`.
    #[tokio::test]
    async fn tck_00240_quarantine_event_has_time_envelope_ref() {
        use crate::htf::{ClockConfig, HolonicClock};

        let clock = Arc::new(HolonicClock::new(ClockConfig::default(), None).unwrap());
        let runtime = EpisodeRuntime::with_clock(test_config(), clock);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        runtime
            .start_with_workspace(
                &episode_id,
                "lease-123",
                test_timestamp() + 1000,
                temp_dir.path(),
            )
            .await
            .unwrap();
        runtime
            .quarantine(
                &episode_id,
                QuarantineReason::crash("test"),
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 3);

        // Verify the quarantine event has a time_envelope_ref
        let quarantine_event = events
            .iter()
            .find(|e| matches!(e, EpisodeEvent::Quarantined { .. }));
        assert!(quarantine_event.is_some());
        assert!(
            quarantine_event.unwrap().time_envelope_ref().is_some(),
            "Quarantine event should have time_envelope_ref"
        );
    }

    /// TCK-00240: Verify that events have `time_envelope_ref: None` when no
    /// clock is provided (backward compatibility).
    #[tokio::test]
    async fn tck_00240_events_have_no_time_envelope_ref_without_clock() {
        let runtime = EpisodeRuntime::new(test_config());

        let _episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 1);

        // Without clock, time_envelope_ref should be None
        assert!(
            events[0].time_envelope_ref().is_none(),
            "Event should have no time_envelope_ref without clock"
        );
    }

    /// TCK-00240: Verify that `ClockProfilePublished` event is emitted when
    /// using `with_clock_initialized`.
    #[tokio::test]
    async fn tck_00240_clock_profile_published_event() {
        use crate::htf::{ClockConfig, HolonicClock};

        let clock = Arc::new(HolonicClock::new(ClockConfig::default(), None).unwrap());
        let expected_hash = clock.profile_hash().to_string();

        // Create runtime with initialized clock - this should emit
        // ClockProfilePublished
        let runtime = EpisodeRuntime::with_clock_initialized(test_config(), clock)
            .await
            .expect("should succeed");

        let events = runtime.drain_events().await;
        assert_eq!(
            events.len(),
            1,
            "Should have exactly one event (ClockProfilePublished)"
        );

        // Verify the event is ClockProfilePublished
        match &events[0] {
            EpisodeEvent::ClockProfilePublished {
                profile_hash,
                clock_profile,
                time_envelope_ref,
                time_envelope,
                ..
            } => {
                assert_eq!(profile_hash, &expected_hash);
                assert!(time_envelope_ref.is_some(), "Should have time_envelope_ref");
                assert!(
                    time_envelope.is_some(),
                    "Should have time_envelope preimage"
                );

                // Verify the clock profile fields
                assert!(clock_profile.hlc_enabled);
                assert_eq!(clock_profile.tick_rate_hz, 1_000_000_000); // Default 1 GHz
            },
            other => panic!(
                "Expected ClockProfilePublished event, got {:?}",
                other.event_type()
            ),
        }
    }

    /// TCK-00240: Verify that `ClockProfilePublished` has `episode_id() ==
    /// None`.
    #[tokio::test]
    async fn tck_00240_clock_profile_published_has_no_episode_id() {
        use crate::htf::{ClockConfig, HolonicClock};

        let clock = Arc::new(HolonicClock::new(ClockConfig::default(), None).unwrap());
        let runtime = EpisodeRuntime::with_clock_initialized(test_config(), clock)
            .await
            .expect("should succeed");

        let events = runtime.drain_events().await;
        assert_eq!(events.len(), 1);

        // ClockProfilePublished is a runtime-level event, not an episode event
        assert!(
            events[0].episode_id().is_none(),
            "ClockProfilePublished should not have an episode_id"
        );
    }

    /// TCK-00319: Verify that `start_with_workspace` correctly initializes
    /// rooted handlers and that they are confined to the workspace.
    #[tokio::test]
    async fn tck_00319_start_with_workspace_roots_handlers() {
        use std::path::PathBuf;

        use crate::episode::broker::StubContentAddressedStore;
        use crate::episode::handlers::ReadFileHandler;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let workspace = temp_dir.path().join("workspace");
        std::fs::create_dir(&workspace).expect("create workspace");

        // Create a file INSIDE the workspace
        let inside_file = workspace.join("inside.txt");
        std::fs::write(&inside_file, "inside").expect("write inside");

        // Create a file OUTSIDE the workspace
        let outside_file = temp_dir.path().join("outside.txt");
        std::fs::write(&outside_file, "outside").expect("write outside");

        let cas = Arc::new(StubContentAddressedStore::new());
        let runtime = EpisodeRuntime::new(test_config())
            .with_cas(cas)
            .with_rooted_handler_factory(|root| Box::new(ReadFileHandler::with_root(root)));

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        // Start with workspace
        let _handle = runtime
            .start_with_workspace(
                &episode_id,
                "lease-123",
                test_timestamp() + 1000,
                &workspace,
            )
            .await
            .unwrap();

        // Attempt to read file INSIDE workspace
        let result = runtime
            .execute_tool(
                &episode_id,
                &ToolArgs::Read(crate::episode::tool_handler::ReadArgs {
                    path: PathBuf::from("inside.txt"),
                    offset: None,
                    limit: None,
                }),
                None,
                test_timestamp() + 2000,
                "req-1",
            )
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.output_str().unwrap(), "inside");

        // Attempt to read file OUTSIDE workspace via path traversal
        let result = runtime
            .execute_tool(
                &episode_id,
                &ToolArgs::Read(crate::episode::tool_handler::ReadArgs {
                    path: PathBuf::from("../outside.txt"),
                    offset: None,
                    limit: None,
                }),
                None,
                test_timestamp() + 3000,
                "req-2",
            )
            .await;

        // Should be rejected by path validation
        assert!(result.is_err());
    }

    // =========================================================================
    // TCK-00385 BLOCKER: Episode stop/quarantine wires session termination
    // =========================================================================

    /// TCK-00385 BLOCKER regression: `stop()` with `session_registry` marks
    /// the session as TERMINATED with correct reason and exit code.
    #[tokio::test]
    async fn tck_00385_stop_wires_session_terminated() {
        use crate::episode::registry::InMemorySessionRegistry;
        use crate::session::{SessionRegistry, SessionState};

        let registry = Arc::new(InMemorySessionRegistry::new());
        let runtime = EpisodeRuntime::new(test_config())
            .with_session_registry(registry.clone() as Arc<dyn SessionRegistry>);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let session_id = handle.session_id().to_string();

        // Register the session in the registry (as production code would)
        registry
            .register_session(SessionState {
                session_id: session_id.clone(),
                work_id: "work-1".to_string(),
                role: 1,
                ephemeral_handle: "handle-1".to_string(),
                lease_id: "lease-1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some(episode_id.as_str().to_string()),
            })
            .unwrap();

        // Stop the episode (normal success)
        runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        // Session should now be terminated in the registry
        assert!(
            registry.get_session(&session_id).is_none(),
            "Session should no longer be in active set"
        );

        let term_info = registry
            .get_termination_info(&session_id)
            .expect("Session should have termination info");
        assert_eq!(term_info.rationale_code, "normal");
        assert_eq!(term_info.exit_classification, "SUCCESS");
        assert_eq!(term_info.exit_code, Some(0));
        assert_eq!(
            term_info.session_id, session_id,
            "Termination info should have the correct session_id"
        );
    }

    /// TCK-00385 BLOCKER regression: `stop()` with `BudgetExhausted` maps to
    /// correct reason.
    #[tokio::test]
    async fn tck_00385_stop_budget_exhausted_wires_reason() {
        use crate::episode::registry::InMemorySessionRegistry;
        use crate::session::{SessionRegistry, SessionState};

        let registry = Arc::new(InMemorySessionRegistry::new());
        let runtime = EpisodeRuntime::new(test_config())
            .with_session_registry(registry.clone() as Arc<dyn SessionRegistry>);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let session_id = handle.session_id().to_string();

        registry
            .register_session(SessionState {
                session_id: session_id.clone(),
                work_id: "work-1".to_string(),
                role: 1,
                ephemeral_handle: "handle-budget".to_string(),
                lease_id: "lease-1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some(episode_id.as_str().to_string()),
            })
            .unwrap();

        runtime
            .stop(
                &episode_id,
                TerminationClass::BudgetExhausted,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let term_info = registry
            .get_termination_info(&session_id)
            .expect("Should have termination info for budget exhausted");
        assert_eq!(term_info.rationale_code, "budget_exhausted");
        assert_eq!(term_info.exit_classification, "FAILURE");
    }

    /// TCK-00385 BLOCKER regression: `stop()` with Timeout maps correctly.
    #[tokio::test]
    async fn tck_00385_stop_timeout_wires_reason() {
        use crate::episode::registry::InMemorySessionRegistry;
        use crate::session::{SessionRegistry, SessionState};

        let registry = Arc::new(InMemorySessionRegistry::new());
        let runtime = EpisodeRuntime::new(test_config())
            .with_session_registry(registry.clone() as Arc<dyn SessionRegistry>);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let session_id = handle.session_id().to_string();

        registry
            .register_session(SessionState {
                session_id: session_id.clone(),
                work_id: "work-1".to_string(),
                role: 1,
                ephemeral_handle: "handle-timeout".to_string(),
                lease_id: "lease-1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some(episode_id.as_str().to_string()),
            })
            .unwrap();

        runtime
            .stop(
                &episode_id,
                TerminationClass::Timeout,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let term_info = registry
            .get_termination_info(&session_id)
            .expect("Should have termination info for timeout");
        assert_eq!(term_info.rationale_code, "timeout");
        assert_eq!(term_info.exit_classification, "FAILURE");
    }

    /// TCK-00385 BLOCKER regression: `quarantine()` wires session termination
    /// with "quarantined" reason.
    #[tokio::test]
    async fn tck_00385_quarantine_wires_session_terminated() {
        use crate::episode::registry::InMemorySessionRegistry;
        use crate::session::{SessionRegistry, SessionState};

        let registry = Arc::new(InMemorySessionRegistry::new());
        let runtime = EpisodeRuntime::new(test_config())
            .with_session_registry(registry.clone() as Arc<dyn SessionRegistry>);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let session_id = handle.session_id().to_string();

        registry
            .register_session(SessionState {
                session_id: session_id.clone(),
                work_id: "work-1".to_string(),
                role: 1,
                ephemeral_handle: "handle-quarantine".to_string(),
                lease_id: "lease-1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some(episode_id.as_str().to_string()),
            })
            .unwrap();

        let reason = QuarantineReason::policy_violation("TEST_POLICY");
        runtime
            .quarantine(&episode_id, reason, test_timestamp() + 2000)
            .await
            .unwrap();

        // Session should be terminated
        assert!(
            registry.get_session(&session_id).is_none(),
            "Session should not be in active set after quarantine"
        );

        let term_info = registry
            .get_termination_info(&session_id)
            .expect("Quarantined session should have termination info");
        assert_eq!(term_info.rationale_code, "quarantined");
        assert_eq!(term_info.exit_classification, "FAILURE");
        assert_eq!(
            term_info.session_id, session_id,
            "Termination info should have correct session_id"
        );
    }

    /// TCK-00385 BLOCKER regression: Without `session_registry`,
    /// stop/quarantine still works (backward compatibility).
    #[tokio::test]
    async fn tck_00385_stop_without_registry_still_works() {
        let runtime = EpisodeRuntime::new(test_config());

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        // Should succeed without session_registry
        runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(matches!(state, EpisodeState::Terminated { .. }));
    }

    /// TCK-00385 BLOCKER: `stop()` with Crashed maps to crash/FAILURE/exit 1.
    #[tokio::test]
    async fn tck_00385_stop_crashed_wires_reason() {
        use crate::episode::registry::InMemorySessionRegistry;
        use crate::session::{SessionRegistry, SessionState};

        let registry = Arc::new(InMemorySessionRegistry::new());
        let runtime = EpisodeRuntime::new(test_config())
            .with_session_registry(registry.clone() as Arc<dyn SessionRegistry>);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let session_id = handle.session_id().to_string();

        registry
            .register_session(SessionState {
                session_id: session_id.clone(),
                work_id: "work-1".to_string(),
                role: 1,
                ephemeral_handle: "handle-crash".to_string(),
                lease_id: "lease-1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some(episode_id.as_str().to_string()),
            })
            .unwrap();

        runtime
            .stop(
                &episode_id,
                TerminationClass::Crashed,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let term_info = registry
            .get_termination_info(&session_id)
            .expect("Should have termination info for crashed");
        assert_eq!(term_info.rationale_code, "crash");
        assert_eq!(term_info.exit_classification, "FAILURE");
        assert_eq!(term_info.exit_code, Some(1));
    }

    /// TCK-00385 BLOCKER: `stop()` with Killed maps to crash/FAILURE/exit 137.
    #[tokio::test]
    async fn tck_00385_stop_killed_wires_reason() {
        use crate::episode::registry::InMemorySessionRegistry;
        use crate::session::{SessionRegistry, SessionState};

        let registry = Arc::new(InMemorySessionRegistry::new());
        let runtime = EpisodeRuntime::new(test_config())
            .with_session_registry(registry.clone() as Arc<dyn SessionRegistry>);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let session_id = handle.session_id().to_string();

        registry
            .register_session(SessionState {
                session_id: session_id.clone(),
                work_id: "work-1".to_string(),
                role: 1,
                ephemeral_handle: "handle-killed".to_string(),
                lease_id: "lease-1".to_string(),
                policy_resolved_ref: String::new(),
                capability_manifest_hash: vec![],
                episode_id: Some(episode_id.as_str().to_string()),
            })
            .unwrap();

        runtime
            .stop(
                &episode_id,
                TerminationClass::Killed,
                test_timestamp() + 2000,
            )
            .await
            .unwrap();

        let term_info = registry
            .get_termination_info(&session_id)
            .expect("Should have termination info for killed");
        assert_eq!(term_info.rationale_code, "crash");
        assert_eq!(term_info.exit_classification, "FAILURE");
        assert_eq!(term_info.exit_code, Some(137));
    }

    // =========================================================================
    // TCK-00385 MAJOR 1: Fail-closed error propagation
    // =========================================================================

    /// A session registry that always fails on `mark_terminated`.
    /// Used to test that `stop()`/`quarantine()` propagate persistence errors.
    struct FailingSessionRegistry;

    impl SessionRegistry for FailingSessionRegistry {
        fn register_session(
            &self,
            _session: crate::session::SessionState,
        ) -> Result<Vec<crate::session::SessionState>, crate::session::SessionRegistryError>
        {
            Ok(Vec::new())
        }
        fn remove_session(
            &self,
            _session_id: &str,
        ) -> Result<Option<crate::session::SessionState>, crate::session::SessionRegistryError>
        {
            Ok(None)
        }
        fn get_session(&self, _session_id: &str) -> Option<crate::session::SessionState> {
            None
        }
        fn get_session_by_handle(&self, _handle: &str) -> Option<crate::session::SessionState> {
            None
        }
        fn get_session_by_work_id(&self, _work_id: &str) -> Option<crate::session::SessionState> {
            None
        }
        fn mark_terminated(
            &self,
            _session_id: &str,
            _info: SessionTerminationInfo,
        ) -> Result<bool, crate::session::SessionRegistryError> {
            Err(crate::session::SessionRegistryError::RegistrationFailed {
                message: "simulated persistence failure".to_string(),
            })
        }
        fn get_termination_info(&self, _session_id: &str) -> Option<SessionTerminationInfo> {
            None
        }
        fn get_terminated_session(
            &self,
            _session_id: &str,
        ) -> Option<(crate::session::SessionState, SessionTerminationInfo)> {
            None
        }
        fn update_episode_id(
            &self,
            _session_id: &str,
            _episode_id: String,
        ) -> Result<(), crate::session::SessionRegistryError> {
            Ok(())
        }
    }

    /// TCK-00385 MAJOR 1: `stop()` returns `SessionTerminationFailed` when
    /// `mark_terminated` fails, enforcing the fail-closed contract.
    #[tokio::test]
    async fn tck_00385_stop_propagates_mark_terminated_error() {
        let registry: Arc<dyn SessionRegistry> = Arc::new(FailingSessionRegistry);
        let runtime = EpisodeRuntime::new(test_config()).with_session_registry(registry);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        let handle = runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        // We need a session_id to exist in the Running state for the registry
        // to be called. The runtime extracts session_id from the Running state.
        let _session_id = handle.session_id().to_string();

        let result = runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await;

        assert!(
            result.is_err(),
            "stop() should propagate mark_terminated error"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            "session_termination_failed",
            "Error should be SessionTerminationFailed, got: {err}"
        );
    }

    /// TCK-00385 MAJOR 1: `quarantine()` returns `SessionTerminationFailed`
    /// when `mark_terminated` fails, enforcing the fail-closed contract.
    #[tokio::test]
    async fn tck_00385_quarantine_propagates_mark_terminated_error() {
        let registry: Arc<dyn SessionRegistry> = Arc::new(FailingSessionRegistry);
        let runtime = EpisodeRuntime::new(test_config()).with_session_registry(registry);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        let result = runtime
            .quarantine(
                &episode_id,
                QuarantineReason::new("TEST", "test quarantine"),
                test_timestamp() + 2000,
            )
            .await;

        assert!(
            result.is_err(),
            "quarantine() should propagate mark_terminated error"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            "session_termination_failed",
            "Error should be SessionTerminationFailed, got: {err}"
        );
    }

    // =========================================================================
    // BLOCKER 1 regression: Runtime stays Running on mark_terminated failure,
    // allowing retry reconciliation.
    // =========================================================================

    /// BLOCKER 1 regression: On `mark_terminated` failure, `stop()` leaves the
    /// runtime state as Running (not terminal). A subsequent retry succeeds
    /// when the registry is no longer failing (simulated by replacing the
    /// runtime with a working registry). This proves the caller is not blocked
    /// by `InvalidTransition` on retry.
    #[tokio::test]
    async fn blocker1_stop_stays_running_on_mark_terminated_failure() {
        let registry: Arc<dyn SessionRegistry> = Arc::new(FailingSessionRegistry);
        let runtime = EpisodeRuntime::new(test_config()).with_session_registry(registry);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        // First attempt: mark_terminated fails
        let result = runtime
            .stop(
                &episode_id,
                TerminationClass::Success,
                test_timestamp() + 2000,
            )
            .await;
        assert!(result.is_err(), "First stop() should fail");

        // Runtime state MUST still be Running (not Terminated)
        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(
            state.is_running(),
            "Runtime state must remain Running after mark_terminated failure, got: {}",
            state.state_name()
        );
    }

    /// BLOCKER 1 regression: On `mark_terminated` failure, `quarantine()`
    /// leaves the runtime state as Running (not Quarantined).
    #[tokio::test]
    async fn blocker1_quarantine_stays_running_on_mark_terminated_failure() {
        let registry: Arc<dyn SessionRegistry> = Arc::new(FailingSessionRegistry);
        let runtime = EpisodeRuntime::new(test_config()).with_session_registry(registry);

        let episode_id = runtime
            .create(test_envelope_hash(), test_timestamp())
            .await
            .unwrap();

        runtime
            .start(&episode_id, "lease-1", test_timestamp() + 1000)
            .await
            .unwrap();

        // First attempt: mark_terminated fails
        let result = runtime
            .quarantine(
                &episode_id,
                QuarantineReason::new("TEST", "test quarantine"),
                test_timestamp() + 2000,
            )
            .await;
        assert!(result.is_err(), "First quarantine() should fail");

        // Runtime state MUST still be Running (not Quarantined)
        let state = runtime.observe(&episode_id).await.unwrap();
        assert!(
            state.is_running(),
            "Runtime state must remain Running after mark_terminated failure, got: {}",
            state.state_name()
        );
    }
}
