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
use tracing::{debug, info, instrument, warn};

use super::error::{EpisodeError, EpisodeId};
use super::handle::{SessionHandle, StopSignal};
use super::state::{EpisodeState, QuarantineReason, TerminationClass};
use crate::htf::HolonicClock;

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
            | Self::Quarantined { episode_id, .. } => Some(episode_id),
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
            | Self::LeaseIssueDenied { time_envelope, .. } => time_envelope.as_ref(),
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

/// Internal state for a tracked episode.
struct EpisodeEntry {
    /// Current state.
    state: EpisodeState,
    /// Session handle if running.
    handle: Option<SessionHandle>,
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
                .await;

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
            .await;
        }

        info!(episode_id = %episode_id, "episode created");
        Ok(episode_id)
    }

    /// Starts an episode, transitioning it from CREATED to RUNNING.
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
    #[instrument(skip(self, lease_id))]
    pub async fn start(
        &self,
        episode_id: &EpisodeId,
        lease_id: impl Into<String>,
        timestamp_ns: u64,
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
            .await;
        }

        info!(
            episode_id = %episode_id,
            session_id = %handle.session_id(),
            "episode started"
        );
        Ok(handle)
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
        {
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
            let (created_at_ns, started_at_ns, envelope_hash) = match &entry.state {
                EpisodeState::Running {
                    created_at_ns,
                    started_at_ns,
                    envelope_hash,
                    ..
                } => (*created_at_ns, *started_at_ns, *envelope_hash),
                _ => {
                    return Err(EpisodeError::InvalidTransition {
                        id: episode_id.as_str().to_string(),
                        from: entry.state.state_name(),
                        to: "Terminated",
                    });
                },
            };

            // Signal stop to handle if present
            if let Some(handle) = &entry.handle {
                handle.signal_stop(StopSignal::Graceful {
                    reason: format!("termination: {termination_class}"),
                });
            }

            // Transition to Terminated
            entry.state = EpisodeState::Terminated {
                created_at_ns,
                started_at_ns,
                terminated_at_ns: timestamp_ns,
                envelope_hash,
                termination_class,
            };
            entry.handle = None;
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
            .await;
        }

        info!(
            episode_id = %episode_id,
            termination_class = %termination_class,
            "episode stopped"
        );
        Ok(())
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
        {
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
            let (created_at_ns, started_at_ns, envelope_hash) = match &entry.state {
                EpisodeState::Running {
                    created_at_ns,
                    started_at_ns,
                    envelope_hash,
                    ..
                } => (*created_at_ns, *started_at_ns, *envelope_hash),
                _ => {
                    return Err(EpisodeError::InvalidTransition {
                        id: episode_id.as_str().to_string(),
                        from: entry.state.state_name(),
                        to: "Quarantined",
                    });
                },
            };

            // Signal quarantine to handle if present
            if let Some(handle) = &entry.handle {
                handle.signal_stop(StopSignal::Quarantine {
                    reason: reason.description.clone(),
                });
            }

            // Transition to Quarantined
            entry.state = EpisodeState::Quarantined {
                created_at_ns,
                started_at_ns,
                quarantined_at_ns: timestamp_ns,
                envelope_hash,
                reason: reason.clone(),
            };
            entry.handle = None;
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
            .await;
        }

        warn!(episode_id = %episode_id, "episode quarantined");
        Ok(())
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
            .await;
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

    /// Emits an event to the internal buffer.
    ///
    /// # Bounded Buffer (CTR-1303)
    ///
    /// The events buffer is bounded by `MAX_EVENTS_BUFFER_SIZE`. When the
    /// buffer reaches capacity, the oldest events are evicted to make room
    /// for new events. This prevents unbounded memory growth.
    ///
    /// In production, events should be drained regularly via `drain_events()`
    /// to prevent eviction of important audit data.
    async fn emit_event(&self, event: EpisodeEvent) {
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

        let result = runtime.start(&fake_id, "lease-1", test_timestamp()).await;
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

        runtime
            .start(&ep1, "lease-1", test_timestamp() + 1000)
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
        runtime
            .start(&ep1, "lease-1", test_timestamp() + 1000)
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

        let result = runtime
            .start(&episode_id, "", test_timestamp() + 1000)
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
        runtime
            .start(&ep, "lease-1", test_timestamp() + 1000)
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
        runtime
            .start(&episode_id, "lease-123", test_timestamp() + 1000)
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
}
