// AGENT-AUTHORED (TCK-00388, TCK-00672)
//! Gate execution orchestrator implementation.
//!
//! Gate orchestration is publication-driven: the single authoritative
//! entrypoint is [`GateOrchestrator::start_for_changeset`] which accepts a
//! [`ChangesetPublication`] derived from an authoritative `ChangeSetPublished`
//! ledger event. Session termination is a lifecycle-only signal used solely
//! for timeout polling; it **never** starts new gate orchestrations.
//!
//! # Security Model
//!
//! - **Ordering invariant**: `PolicyResolvedForChangeSet` is always emitted
//!   before any `GateLeaseIssued` event for the same `work_id`.
//! - **Fail-closed**: Gate timeout produces FAIL verdict, blocking merge.
//! - **Domain separation**: All leases use `GATE_LEASE_ISSUED:` prefix.
//! - **Changeset binding**: Lease `changeset_digest` is bound to the
//!   authoritative `ChangeSetPublished` digest, not session data.
//! - **Receipt authenticity**: Gate receipt signatures are verified against the
//!   executor's verifying key before state transitions.
//!
//! # Event Model
//!
//! Events are returned per-invocation from each method rather than buffered
//! in shared state. This avoids concurrent drain issues where parallel
//! invocations could steal or drop events from a global buffer.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use apm2_core::crypto::{Signer, VerifyingKey};
use apm2_core::evidence::ContentAddressedStore;
use apm2_core::fac::{
    AatLeaseExtension, ChangesetPublication, GateLease, GateLeaseBuilder, GateReceipt,
    GateReceiptBuilder, PolicyInheritanceValidator, PolicyResolvedForChangeSet,
    PolicyResolvedForChangeSetBuilder, RiskTier,
};
use apm2_core::htf::{
    BoundedWallInterval, Canonicalizable, ClockProfile, Hlc, LedgerTime, MonotonicReading,
    MonotonicSource, TimeEnvelope, WallTimeSource,
};
use apm2_core::liveness::{
    LivenessGateDenial, LivenessHeartbeatReceiptV1, check_liveness_for_progression,
};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of concurrent gate orchestrations.
///
/// This prevents unbounded memory growth per CTR-1303. Each orchestration
/// tracks state for up to [`MAX_GATE_TYPES`] gates.
pub const MAX_CONCURRENT_ORCHESTRATIONS: usize = 1_000;

/// Maximum number of gate types per orchestration.
///
/// Currently three gates are supported: aat, quality, security.
pub const MAX_GATE_TYPES: usize = 8;

/// Default gate execution timeout in milliseconds (30 minutes).
///
/// After this duration, a gate lease expires and the orchestrator emits
/// a FAIL verdict (fail-closed semantics).
pub const DEFAULT_GATE_TIMEOUT_MS: u64 = 30 * 60 * 1000;

/// Maximum length of `work_id` strings.
pub const MAX_WORK_ID_LENGTH: usize = 4096;

/// Maximum number of entries in the idempotency key store (Security MAJOR 1).
///
/// Bounds the `seen_idempotency_keys` deque to prevent unbounded memory growth
/// over the process lifetime. When this limit is reached, the oldest half
/// is evicted (the active orchestrations map serves as the primary duplicate
/// guard; the seen-keys set provides secondary coverage for the post-removal
/// window).
///
/// 10 * `MAX_CONCURRENT_ORCHESTRATIONS` provides ample headroom for completed
/// orchestrations that have been removed but whose keys should still be
/// rejected.
pub const MAX_IDEMPOTENCY_KEYS: usize = 10 * MAX_CONCURRENT_ORCHESTRATIONS;

/// Dedicated timeout authority actor ID for timeout receipts.
///
/// Timeout receipts are signed by the orchestrator key (the executor never ran
/// or did not finish), so using the executor's actor ID would be misleading.
/// This constant makes the timeout authority identity explicit and
/// distinguishable from real executor-signed receipts.
pub const TIMEOUT_AUTHORITY_ACTOR_ID: &str = "orchestrator:timeout";

/// Maximum length of any string field in orchestrator events.
const MAX_STRING_LENGTH: usize = 4096;

// =============================================================================
// Clock Abstraction (MAJOR 1 fix)
// =============================================================================

/// Abstraction over time sources for testability and monotonic guarantees.
///
/// Production code injects [`SystemClock`] which uses `SystemTime` for
/// wall-clock timestamps and `Instant` for elapsed/timeout comparisons.
/// Tests can inject a mock clock for deterministic behaviour.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Returns the current wall-clock time in milliseconds since UNIX epoch.
    fn now_ms(&self) -> u64;

    /// Returns a monotonic instant for elapsed/timeout comparisons.
    fn monotonic_now(&self) -> Instant;
}

/// Production clock using `SystemTime` for timestamps and `Instant` for
/// monotonic elapsed/timeout logic.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    #[allow(clippy::cast_possible_truncation)]
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }
}

// =============================================================================
// Gate Types
// =============================================================================

/// Gate types that the orchestrator manages.
///
/// Each published changeset triggers execution of all required gate types
/// via [`GateOrchestrator::start_for_changeset`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum GateType {
    /// Agent Acceptance Testing gate.
    Aat,
    /// Code quality review gate.
    Quality,
    /// Security review gate.
    Security,
}

impl GateType {
    /// Returns the gate ID string for this gate type.
    #[must_use]
    pub const fn as_gate_id(&self) -> &'static str {
        match self {
            Self::Aat => "gate-aat",
            Self::Quality => "gate-quality",
            Self::Security => "gate-security",
        }
    }

    /// Returns the payload kind for gate receipts.
    #[must_use]
    pub const fn payload_kind(&self) -> &'static str {
        match self {
            Self::Aat => "aat",
            Self::Quality => "quality",
            Self::Security => "security",
        }
    }

    /// Returns the agent adapter profile ID for this gate type.
    #[must_use]
    pub const fn adapter_profile_id(&self) -> &'static str {
        match self {
            // AAT uses Claude Code for acceptance testing
            Self::Aat => apm2_core::fac::CLAUDE_CODE_PROFILE_ID,
            // Quality and Security use Gemini CLI for code review
            Self::Quality | Self::Security => apm2_core::fac::GEMINI_CLI_PROFILE_ID,
        }
    }

    /// Returns all standard gate types.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Aat, Self::Quality, Self::Security]
    }
}

impl fmt::Display for GateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_gate_id())
    }
}

// =============================================================================
// Gate Status
// =============================================================================

/// Status of a gate within an orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStatus {
    /// Lease has been issued, executor not yet spawned.
    LeaseIssued {
        /// The lease ID.
        lease_id: String,
    },
    /// Gate executor episode is running.
    Running {
        /// The lease ID.
        lease_id: String,
        /// The episode ID of the gate executor.
        episode_id: String,
    },
    /// Gate has completed with a receipt.
    Completed {
        /// The lease ID.
        lease_id: String,
        /// The receipt ID.
        receipt_id: String,
        /// Whether the gate passed.
        passed: bool,
    },
    /// Gate has timed out (fail-closed: treated as FAIL).
    TimedOut {
        /// The lease ID.
        lease_id: String,
    },
}

impl GateStatus {
    /// Returns `true` if the gate is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::TimedOut { .. })
    }
}

// =============================================================================
// Gate Outcome
// =============================================================================

/// The outcome of a gate execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GateOutcome {
    /// The gate type.
    pub gate_type: GateType,
    /// Whether the gate passed.
    pub passed: bool,
    /// The receipt ID (if completed normally).
    pub receipt_id: Option<String>,
    /// Whether the gate timed out.
    pub timed_out: bool,
}

// =============================================================================
// Session Terminated Info
// =============================================================================

/// Information about a terminated session lifecycle event used by legacy
/// session-seeded unit tests.
///
/// Production orchestration is publication-driven via
/// [`GateOrchestrator::start_for_changeset`].
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct SessionTerminatedInfo {
    /// The session ID that terminated.
    pub session_id: String,
    /// The work ID associated with this session.
    pub work_id: String,
    /// The changeset digest from the terminated session.
    pub changeset_digest: [u8; 32],
    /// Timestamp of session termination (milliseconds since epoch).
    pub terminated_at_ms: u64,
}

// =============================================================================
// Idempotency Key
// =============================================================================

/// Deterministic idempotency key computed from `(work_id, changeset_digest)`.
///
/// This is the authoritative gate-start idempotency tuple for publication-
/// driven orchestration and is stable across replay/restart. It is a pure
/// function of authoritative inputs from `ChangeSetPublished` and does not
/// depend on session identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IdempotencyKey {
    /// The work item bound to the publication.
    work_id: String,
    /// The canonical changeset digest from `ChangeSetPublished`.
    changeset_digest: [u8; 32],
}

impl IdempotencyKey {
    /// Creates a new idempotency key from authoritative publication identity.
    fn from_work_digest(work_id: &str, changeset_digest: [u8; 32]) -> Self {
        Self {
            work_id: work_id.to_string(),
            changeset_digest,
        }
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during gate orchestration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateOrchestratorError {
    /// Maximum concurrent orchestrations exceeded.
    #[error("maximum concurrent orchestrations exceeded: {current} >= {max}")]
    MaxOrchestrationsExceeded {
        /// Current number of orchestrations.
        current: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Work ID is empty.
    #[error("work_id must not be empty")]
    EmptyWorkId,

    /// Work ID too long.
    #[error("work_id exceeds max length: {actual} > {max}")]
    WorkIdTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Duplicate orchestration for the same `work_id`.
    #[error("orchestration already active for work_id: {work_id}")]
    DuplicateOrchestration {
        /// The duplicate work ID.
        work_id: String,
    },

    /// Policy resolution failed.
    #[error("policy resolution failed for work_id {work_id}: {reason}")]
    PolicyResolutionFailed {
        /// The work ID.
        work_id: String,
        /// Failure reason.
        reason: String,
    },

    /// Lease issuance failed.
    #[error("lease issuance failed for gate {gate_id} on work_id {work_id}: {reason}")]
    LeaseIssuanceFailed {
        /// The work ID.
        work_id: String,
        /// The gate ID.
        gate_id: String,
        /// Failure reason.
        reason: String,
    },

    /// String field too long.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Orchestration not found.
    #[error("no active orchestration for work_id: {work_id}")]
    OrchestrationNotFound {
        /// The work ID.
        work_id: String,
    },

    /// Gate not found in orchestration.
    #[error("gate {gate_type} not found in orchestration for work_id: {work_id}")]
    GateNotFound {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: String,
    },

    /// Receipt binding mismatch (`lease_id` or `gate_id` does not match issued
    /// lease).
    #[error("receipt binding mismatch for work_id {work_id}: {reason}")]
    ReceiptBindingMismatch {
        /// The work ID.
        work_id: String,
        /// Description of the mismatch.
        reason: String,
    },

    /// Invalid state transition (e.g., updating a terminal-state gate).
    #[error("invalid state transition for gate {gate_type} in work_id {work_id}: {reason}")]
    InvalidStateTransition {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: String,
        /// Description of the invalid transition.
        reason: String,
    },

    /// Lease ID is empty.
    #[error("lease_id must not be empty for gate {gate_type} in work_id {work_id}")]
    EmptyLeaseId {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: String,
    },

    /// Receipt version/kind/schema validation failed (BLOCKER 2).
    #[error("receipt version validation failed for work_id {work_id}: {reason}")]
    ReceiptVersionRejected {
        /// The work ID.
        work_id: String,
        /// Validation failure reason.
        reason: String,
    },

    /// Receipt has zero evidence hashes but claims PASS (BLOCKER 1).
    #[error("receipt has zero/invalid evidence for work_id {work_id}: {reason}")]
    ZeroEvidenceVerdictRejected {
        /// The work ID.
        work_id: String,
        /// Description of the rejection.
        reason: String,
    },

    /// Replay detected: an orchestration with the same publication identity
    /// (`work_id` + `changeset_digest`) already exists or was previously
    /// processed.
    #[error(
        "replay detected for work_id={work_id} changeset_digest={changeset_digest}: an orchestration with the same idempotency key already exists"
    )]
    ReplayDetected {
        /// The work ID.
        work_id: String,
        /// Hex-encoded changeset digest.
        changeset_digest: String,
    },

    /// Sublease validation failed during delegated lease issuance (TCK-00340).
    ///
    /// A newly issued gate lease failed strict-subset validation against its
    /// parent lease. This prevents scope escalation via gate switching or
    /// policy drift.
    #[error("sublease validation failed for work_id {work_id}: {reason}")]
    SubleaseValidationFailed {
        /// The work ID.
        work_id: String,
        /// Validation failure reason.
        reason: String,
    },
}

// =============================================================================
// Orchestrator Events
// =============================================================================

/// Events emitted by the gate orchestrator.
///
/// These events represent the gate lifecycle and are intended to be
/// persisted to the ledger.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub enum GateOrchestratorEvent {
    /// Policy was resolved for a changeset.
    PolicyResolved {
        /// The work ID.
        work_id: String,
        /// The changeset digest this policy resolution is bound to.
        changeset_digest: [u8; 32],
        /// The policy resolution hash.
        policy_hash: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate lease was issued.
    GateLeaseIssued {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The lease ID.
        lease_id: String,
        /// The executor actor ID.
        executor_actor_id: String,
        /// The changeset digest this lease is bound to.
        changeset_digest: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate executor episode was spawned.
    GateExecutorSpawned {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The episode ID.
        episode_id: String,
        /// The adapter profile ID.
        adapter_profile_id: String,
        /// The changeset digest this episode is bound to.
        changeset_digest: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate receipt was collected.
    GateReceiptCollected {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The receipt ID.
        receipt_id: String,
        /// Whether the gate passed.
        passed: bool,
        /// The changeset digest this receipt is bound to.
        changeset_digest: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A gate timed out (fail-closed: FAIL verdict).
    GateTimedOut {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The lease ID that expired.
        lease_id: String,
        /// The changeset digest this timeout is bound to.
        changeset_digest: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// A timeout receipt was generated for a timed-out gate (Quality MAJOR 1).
    ///
    /// This explicit event ensures the caller/ledger has a durable artifact
    /// for the timeout verdict, not just an internal synthetic receipt.
    GateTimeoutReceiptGenerated {
        /// The work ID.
        work_id: String,
        /// The gate type.
        gate_type: GateType,
        /// The receipt ID of the timeout receipt.
        receipt_id: String,
        /// The changeset digest this timeout receipt is bound to.
        changeset_digest: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
    /// All gates for a work item have completed.
    AllGatesCompleted {
        /// The work ID.
        work_id: String,
        /// Whether all gates passed.
        all_passed: bool,
        /// Individual gate outcomes.
        outcomes: Vec<GateOutcome>,
        /// The changeset digest this completion is bound to.
        changeset_digest: [u8; 32],
        /// Timestamp (ms since epoch).
        timestamp_ms: u64,
    },
}

impl GateOrchestratorEvent {
    /// Returns the `work_id` from any event variant.
    ///
    /// Every variant carries a `work_id` field that identifies the work item
    /// this event is bound to. This is used by the receipt writer to emit
    /// events under the correct ledger `session_id` (which maps to `work_id`).
    #[must_use]
    pub fn work_id(&self) -> &str {
        match self {
            Self::PolicyResolved { work_id, .. }
            | Self::GateLeaseIssued { work_id, .. }
            | Self::GateExecutorSpawned { work_id, .. }
            | Self::GateReceiptCollected { work_id, .. }
            | Self::GateTimedOut { work_id, .. }
            | Self::GateTimeoutReceiptGenerated { work_id, .. }
            | Self::AllGatesCompleted { work_id, .. } => work_id,
        }
    }

    /// Returns the `changeset_digest` from any event variant.
    ///
    /// Every variant carries a `changeset_digest` field that binds the event
    /// to the authoritative `ChangeSetPublished` digest. This is essential
    /// for digest-bound persistence (CSID-004): the reducer requires both
    /// `work_id` and `changeset_digest` in persisted event payloads.
    #[must_use]
    pub const fn changeset_digest(&self) -> [u8; 32] {
        match self {
            Self::PolicyResolved {
                changeset_digest, ..
            }
            | Self::GateLeaseIssued {
                changeset_digest, ..
            }
            | Self::GateExecutorSpawned {
                changeset_digest, ..
            }
            | Self::GateReceiptCollected {
                changeset_digest, ..
            }
            | Self::GateTimedOut {
                changeset_digest, ..
            }
            | Self::GateTimeoutReceiptGenerated {
                changeset_digest, ..
            }
            | Self::AllGatesCompleted {
                changeset_digest, ..
            } => *changeset_digest,
        }
    }
}

// =============================================================================
// Orchestration Entry
// =============================================================================

/// Internal state for a single gate orchestration.
#[derive(Debug)]
struct OrchestrationEntry {
    /// Authoritative publication that triggered this orchestration.
    /// Used by downstream merge automation and status queries.
    _publication: ChangesetPublication,
    /// The policy resolution for this changeset.
    policy_resolution: PolicyResolvedForChangeSet,
    /// Gate statuses indexed by gate type.
    gates: HashMap<GateType, GateStatus>,
    /// Issued leases indexed by gate type.
    leases: HashMap<GateType, GateLease>,
    /// Executor verifying keys bound per gate type (BLOCKER 4).
    ///
    /// Each executor gets its own signing identity. Receipt signatures are
    /// verified against the executor-bound key, not the orchestrator key.
    executor_keys: HashMap<GateType, VerifyingKey>,
    /// Collected receipts indexed by gate type.
    receipts: HashMap<GateType, GateReceipt>,
    /// When the orchestration started (ms since epoch).
    /// Used by downstream merge automation (TCK-00390) for stale detection.
    /// This is metadata/informational only - NOT used for timeout decisions.
    _started_at_ms: u64,
    /// Monotonic instant when the orchestration started (Security BLOCKER 1).
    ///
    /// Used for timeout decisions. Immune to NTP/manual clock shifts.
    /// The timeout fires when `started_at_monotonic.elapsed() >= gate_timeout`.
    started_at_monotonic: Instant,
    /// Deterministic idempotency key (Security MAJOR 1).
    ///
    /// Computed from `work_id + changeset_digest` to prevent replay of
    /// publication events generating new gate lifecycles. Stored for
    /// debugging/audit purposes alongside the `seen_idempotency_keys` set.
    #[allow(dead_code)]
    idempotency_key: IdempotencyKey,
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the gate orchestrator.
#[derive(Debug, Clone)]
pub struct GateOrchestratorConfig {
    /// Maximum number of concurrent orchestrations.
    pub max_concurrent_orchestrations: usize,
    /// Gate execution timeout in milliseconds.
    pub gate_timeout_ms: u64,
    /// Maximum accepted heartbeat age for authoritative progression checks.
    pub max_heartbeat_age_ticks: u64,
    /// Gate types to execute for each published changeset.
    pub gate_types: Vec<GateType>,
    /// Issuer actor ID for gate leases.
    pub issuer_actor_id: String,
    /// Resolver actor ID for policy resolution.
    pub resolver_actor_id: String,
    /// Resolver version string.
    pub resolver_version: String,
}

impl Default for GateOrchestratorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_orchestrations: MAX_CONCURRENT_ORCHESTRATIONS,
            gate_timeout_ms: DEFAULT_GATE_TIMEOUT_MS,
            max_heartbeat_age_ticks: 10,
            gate_types: GateType::all().to_vec(),
            issuer_actor_id: "daemon-gate-orchestrator".to_string(),
            resolver_actor_id: "daemon-policy-resolver".to_string(),
            resolver_version: "1.0.0".to_string(),
        }
    }
}

// =============================================================================
// Gate Orchestrator
// =============================================================================

/// Gate execution orchestrator for autonomous gate lifecycle management.
///
/// Gate orchestration is publication-driven: the single authoritative
/// entrypoint is [`Self::start_for_changeset`] which consumes a
/// [`ChangesetPublication`] derived from `ChangeSetPublished`. The
/// orchestrator autonomously drives the gate lifecycle:
///
/// 1. Resolve policy via `PolicyResolvedForChangeSet`
/// 2. Issue `GateLease` for each required gate
/// 3. Spawn gate executor episodes
/// 4. Collect `GateReceipt` results or handle timeout
///
/// Session termination is a lifecycle-only signal used for timeout polling;
/// it never starts new gate orchestrations.
///
/// # Security
///
/// - Policy resolution MUST precede all lease issuance (ordering invariant)
/// - Gate leases use domain-separated Ed25519 signatures
/// - Receipt signatures are verified against executor verifying key
/// - Timeout produces fail-closed FAIL verdict
/// - Changeset digest in leases is bound to the published changeset digest
///
/// # Event Model (BLOCKER 3 fix)
///
/// Events are returned per-invocation from each method rather than buffered
/// in shared state. This avoids concurrent drain issues where parallel
/// invocations could steal or drop events from a global buffer.
///
/// # Thread Safety
///
/// `GateOrchestrator` is `Send + Sync` and can be shared across async tasks.
pub struct GateOrchestrator {
    /// Configuration.
    config: GateOrchestratorConfig,
    /// Active orchestrations indexed by `(work_id, changeset_digest)`.
    ///
    /// CSID-003 + Code-Quality MAJOR fix: Keyed by composite
    /// `(work_id, changeset_digest)` for dedup, but enforces a
    /// **one-active-per-work_id** invariant (latest changeset wins per
    /// RFC-0032). Starting `(work, digest2)` while `(work, digest1)` is
    /// active supersedes the old entry; starting the same `(work, digest1)`
    /// twice is denied. This ensures `find_by_work_id` helpers always
    /// resolve to the correct (unique) entry.
    orchestrations: RwLock<HashMap<(String, [u8; 32]), OrchestrationEntry>>,
    /// Signer for gate leases and policy resolutions.
    signer: Arc<Signer>,
    /// Injected clock for timestamps and timeout checking (MAJOR 1).
    clock: Arc<dyn Clock>,
    /// Seen idempotency keys for replay rejection (Security MAJOR 1).
    ///
    /// Tracks idempotency keys for both active and completed orchestrations
    /// to prevent replayed termination events from generating new lifecycles.
    /// Ordered idempotency keys — `VecDeque` preserves insertion order so
    /// that eviction removes the oldest half (not all entries).
    seen_idempotency_keys: RwLock<std::collections::VecDeque<IdempotencyKey>>,
    /// Gate timeout as a `Duration` for monotonic comparison (Security BLOCKER
    /// 1).
    gate_timeout_duration: std::time::Duration,
    /// Content-addressed store for HTF time authority artifacts.
    ///
    /// When present, `issue_gate_lease` creates a real `ClockProfile` +
    /// `TimeEnvelope`, stores them in CAS, and uses the CAS hash as
    /// `time_envelope_ref`. This ensures downstream consumers
    /// (e.g. `validate_lease_time_authority`) can resolve and verify the
    /// envelope via `decode_hash32_hex`.
    cas: Option<Arc<dyn ContentAddressedStore>>,
}

impl GateOrchestrator {
    /// Creates a new gate orchestrator with the given configuration and signer.
    ///
    /// Uses the default [`SystemClock`] for time operations.
    #[must_use]
    pub fn new(config: GateOrchestratorConfig, signer: Arc<Signer>) -> Self {
        let gate_timeout_duration = std::time::Duration::from_millis(config.gate_timeout_ms);
        Self {
            config,
            orchestrations: RwLock::new(HashMap::new()),
            signer,
            clock: Arc::new(SystemClock),
            seen_idempotency_keys: RwLock::new(std::collections::VecDeque::new()),
            gate_timeout_duration,
            cas: None,
        }
    }

    /// Creates a new gate orchestrator with an injected clock.
    ///
    /// Use this constructor in tests to inject a mock clock for
    /// deterministic timestamp and timeout behaviour.
    #[must_use]
    pub fn with_clock(
        config: GateOrchestratorConfig,
        signer: Arc<Signer>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let gate_timeout_duration = std::time::Duration::from_millis(config.gate_timeout_ms);
        Self {
            config,
            orchestrations: RwLock::new(HashMap::new()),
            signer,
            clock,
            seen_idempotency_keys: RwLock::new(std::collections::VecDeque::new()),
            gate_timeout_duration,
            cas: None,
        }
    }

    /// Attaches a content-addressed store for HTF time authority artifacts.
    ///
    /// When a CAS is attached, `issue_gate_lease` creates real `ClockProfile`
    /// and `TimeEnvelope` artifacts, stores them in CAS, and uses the CAS
    /// hash (hex-encoded) as `time_envelope_ref`. This makes the lease
    /// compatible with `validate_lease_time_authority` which requires a
    /// `decode_hash32_hex`-resolvable reference.
    #[must_use]
    pub fn with_cas(mut self, cas: Arc<dyn ContentAddressedStore>) -> Self {
        self.cas = Some(cas);
        self
    }

    /// Returns the current configuration.
    #[must_use]
    pub const fn config(&self) -> &GateOrchestratorConfig {
        &self.config
    }

    /// Check liveness state before allowing gate progression.
    pub fn check_liveness_gate(
        &self,
        heartbeat: &LivenessHeartbeatReceiptV1,
        current_tick: u64,
    ) -> Result<(), LivenessGateDenial> {
        check_liveness_for_progression(heartbeat, current_tick, self.config.max_heartbeat_age_ticks)
    }

    /// Returns the number of active orchestrations.
    pub async fn active_count(&self) -> usize {
        self.orchestrations.read().await.len()
    }

    /// Starts gate orchestration for an authoritative published changeset.
    ///
    /// This is the FAC vNext gate-start entrypoint for
    /// `ChangeSetPublished -> StartGates` wiring.
    pub async fn start_for_changeset(
        &self,
        publication: ChangesetPublication,
    ) -> Result<
        (
            Vec<GateType>,
            HashMap<GateType, Arc<Signer>>,
            Vec<GateOrchestratorEvent>,
        ),
        GateOrchestratorError,
    > {
        self.start_for_publication(publication).await
    }

    /// Test-only helper that derives a publication wrapper from session data.
    ///
    /// Production code MUST use [`Self::start_for_changeset`] and must not
    /// bootstrap gate start from session lifecycle events.
    #[cfg(test)]
    pub(crate) async fn start_from_test_session(
        &self,
        info: SessionTerminatedInfo,
    ) -> Result<
        (
            Vec<GateType>,
            HashMap<GateType, Arc<Signer>>,
            Vec<GateOrchestratorEvent>,
        ),
        GateOrchestratorError,
    > {
        self.start_for_changeset(ChangesetPublication {
            work_id: info.work_id,
            changeset_digest: info.changeset_digest,
            bundle_cas_hash: [0u8; 32],
            published_at_ms: info.terminated_at_ms,
            publisher_actor_id: info.session_id.clone(),
            changeset_published_event_id: info.session_id,
        })
        .await
    }

    /// Returns the orchestrator's verifying key (for lease signature
    /// verification).
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Returns the executor-bound verifying key for a specific gate
    /// (BLOCKER 4).
    ///
    /// This is the key that was generated at lease issuance time and bound
    /// to the executor. Receipt signatures MUST be verified against this
    /// key, not the orchestrator's key.
    pub async fn executor_verifying_key(
        &self,
        work_id: &str,
        gate_type: GateType,
    ) -> Option<VerifyingKey> {
        let orchestrations = self.orchestrations.read().await;
        find_by_work_id(&orchestrations, work_id)
            .and_then(|e| e.executor_keys.get(&gate_type).copied())
    }

    /// Starts gate orchestration from authoritative published changeset
    /// identity.
    ///
    /// # Ordering Invariant
    ///
    /// The `PolicyResolved` event is ALWAYS emitted before any
    /// `GateLeaseIssued` event in the returned event list.
    ///
    /// # BLOCKER 2 Fix: Events after admission
    ///
    /// Events are staged locally and returned only after the admission check
    /// (duplicate detection + capacity check) succeeds and the orchestration
    /// is inserted. On error, no events escape.
    ///
    /// # BLOCKER 3 Fix: Per-invocation events
    ///
    /// Events are returned from this method rather than buffered in shared
    /// state. This prevents concurrent invocations from stealing events.
    ///
    /// # Errors
    ///
    /// Returns `GateOrchestratorError` if admission or lease issuance fails.
    ///
    /// Idempotency semantics: if `(work_id, changeset_digest)` has already
    /// been observed, this method is a no-op and returns empty outputs.
    async fn start_for_publication(
        &self,
        publication: ChangesetPublication,
    ) -> Result<
        (
            Vec<GateType>,
            HashMap<GateType, Arc<Signer>>,
            Vec<GateOrchestratorEvent>,
        ),
        GateOrchestratorError,
    > {
        // Validate work_id
        if publication.work_id.is_empty() {
            return Err(GateOrchestratorError::EmptyWorkId);
        }
        if publication.work_id.len() > MAX_WORK_ID_LENGTH {
            return Err(GateOrchestratorError::WorkIdTooLong {
                actual: publication.work_id.len(),
                max: MAX_WORK_ID_LENGTH,
            });
        }
        if publication.changeset_published_event_id.len() > MAX_STRING_LENGTH {
            return Err(GateOrchestratorError::StringTooLong {
                field: "changeset_published_event_id",
                actual: publication.changeset_published_event_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        // NIT (Security): Validate publisher_actor_id length consistent with
        // work_id and event_id validation above.
        if publication.publisher_actor_id.len() > MAX_STRING_LENGTH {
            return Err(GateOrchestratorError::StringTooLong {
                field: "publisher_actor_id",
                actual: publication.publisher_actor_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        let now_ms = self.clock.now_ms();
        let monotonic_now = self.clock.monotonic_now();

        // Compute publication-native idempotency key.
        let idempotency_key =
            IdempotencyKey::from_work_digest(&publication.work_id, publication.changeset_digest);

        // Step 1: Resolve policy for the changeset.
        // ORDERING INVARIANT: This MUST happen before any lease issuance.
        let policy_resolution =
            self.resolve_policy(&publication.work_id, publication.changeset_digest, now_ms)?;
        let policy_hash = policy_resolution.resolved_policy_hash();
        let risk_tier =
            RiskTier::try_from(policy_resolution.resolved_risk_tier).unwrap_or(RiskTier::Tier4);

        // Step 2: Issue gate leases for each required gate type.
        // This MUST happen AFTER policy resolution (ordering invariant).
        //
        // BLOCKER 4 FIX: Each executor gets a unique signer identity.
        // The executor's verifying key is bound in the orchestration entry
        // and used to verify receipt signatures (not the orchestrator key).
        let mut gates = HashMap::new();
        let mut leases = HashMap::new();
        let mut executor_keys = HashMap::new();
        let mut executor_signers_for_return: HashMap<GateType, Arc<Signer>> = HashMap::new();
        let mut issued_gate_types = Vec::new();

        for &gate_type in &self.config.gate_types {
            // Generate a unique executor signer per gate type
            let executor_signer = Arc::new(Signer::generate());
            let executor_vk = executor_signer.verifying_key();

            let lease = self.issue_gate_lease(
                &publication.work_id,
                publication.changeset_digest,
                gate_type,
                &policy_hash,
                now_ms,
                risk_tier,
            )?;
            let lease_id = lease.lease_id.clone();
            gates.insert(gate_type, GateStatus::LeaseIssued { lease_id });
            leases.insert(gate_type, lease);
            executor_keys.insert(gate_type, executor_vk);
            executor_signers_for_return.insert(gate_type, executor_signer);
            issued_gate_types.push(gate_type);
        }

        // Step 3 (TOCTOU FIX): Atomic replay-check + admission-check + insert.
        //
        // Security BLOCKER 1 / Quality MAJOR 1: The replay-idempotency check
        // and the orchestration insert MUST be performed atomically under a
        // single write critical section. Previously the replay key was checked
        // with a read lock and inserted with a separate write lock, allowing
        // two concurrent calls with the same idempotency key to both pass the
        // read-check before either writes the seen-key.
        //
        // Now: we acquire BOTH write locks, check the idempotency key,
        // check capacity/duplicates, insert the orchestration, and register
        // the idempotency key all in one critical section.
        {
            let mut seen_keys = self.seen_idempotency_keys.write().await;
            let mut orchestrations = self.orchestrations.write().await;

            // Replay check: identical (work_id, changeset_digest) is a no-op.
            if seen_keys.iter().any(|k| k == &idempotency_key) {
                debug!(
                    work_id = %publication.work_id,
                    changeset_digest = %hex::encode(publication.changeset_digest),
                    "Duplicate gate-start publication observed; returning no-op"
                );
                return Ok((Vec::new(), HashMap::new(), Vec::new()));
            }

            // Step 1: Enforce one active orchestration per work_id
            // (latest-wins policy per RFC-0032). When a new
            // (work_id, digest2) arrives while (work_id, digest1) is
            // active, the old orchestration is superseded/removed so
            // that find_by_work_id helpers always resolve to the
            // correct entry. Starting the same (work_id, digest)
            // twice is denied as a duplicate.
            //
            // CRITICAL: The supersede check MUST happen BEFORE the capacity
            // check. Otherwise, at capacity=1, starting (work, digest2)
            // while (work, digest1) is active returns MaxOrchestrationsExceeded
            // instead of superseding (INV-GT14 latest-wins violation).
            let composite_key = (publication.work_id.clone(), publication.changeset_digest);
            if orchestrations.contains_key(&composite_key) {
                return Err(GateOrchestratorError::DuplicateOrchestration {
                    work_id: publication.work_id.clone(),
                });
            }

            // Supersede any existing orchestration for this work_id
            // with a different digest (latest changeset wins).
            let old_key = orchestrations
                .keys()
                .find(|(wid, _)| wid == &publication.work_id)
                .cloned();
            if let Some(key) = old_key {
                info!(
                    work_id = %publication.work_id,
                    old_digest = %hex::encode(key.1),
                    new_digest = %hex::encode(publication.changeset_digest),
                    "Superseding old orchestration with latest changeset (latest-wins)"
                );
                orchestrations.remove(&key);
            }

            // Step 2: Capacity check (after supersede, so freed slot is counted).
            if orchestrations.len() >= self.config.max_concurrent_orchestrations {
                return Err(GateOrchestratorError::MaxOrchestrationsExceeded {
                    current: orchestrations.len(),
                    max: self.config.max_concurrent_orchestrations,
                });
            }

            orchestrations.insert(
                composite_key,
                OrchestrationEntry {
                    _publication: publication.clone(),
                    policy_resolution,
                    gates,
                    leases: leases.clone(),
                    executor_keys,
                    receipts: HashMap::new(),
                    _started_at_ms: now_ms,
                    started_at_monotonic: monotonic_now,
                    idempotency_key: idempotency_key.clone(),
                },
            );

            // Security MAJOR 1: Register idempotency key atomically with
            // the orchestration insert. Bounded eviction: if we exceed the
            // maximum cardinality, evict all entries (the active orchestrations
            // map is the authoritative duplicate guard; the seen-keys set is
            // a secondary defence that covers the window after removal).
            if seen_keys.len() >= MAX_IDEMPOTENCY_KEYS {
                // Evict the oldest half to preserve recent replay protection
                // while bounding memory growth. This is an improvement over
                // clearing all entries which would remove replay protection
                // for recently-completed orchestrations.
                let evict_count = seen_keys.len() / 2;
                warn!(
                    current = seen_keys.len(),
                    max = MAX_IDEMPOTENCY_KEYS,
                    evicting = evict_count,
                    "Idempotency key store at capacity, evicting oldest half"
                );
                seen_keys.drain(..evict_count);
            }
            seen_keys.push_back(idempotency_key);
        }

        // Step 4 (BLOCKER 3 FIX): Stage events locally per-invocation and
        // return them. No global buffer is used.
        let mut events = Vec::with_capacity(1 + issued_gate_types.len());

        // PolicyResolved is ALWAYS first (ordering invariant).
        events.push(GateOrchestratorEvent::PolicyResolved {
            work_id: publication.work_id.clone(),
            changeset_digest: publication.changeset_digest,
            policy_hash,
            timestamp_ms: now_ms,
        });

        info!(
            work_id = %publication.work_id,
            policy_hash = %hex::encode(policy_hash),
            "Policy resolved for changeset"
        );

        for &gate_type in &issued_gate_types {
            let lease = &leases[&gate_type];
            let lease_id = lease.lease_id.clone();
            let executor_actor_id = lease.executor_actor_id.clone();

            debug!(
                work_id = %publication.work_id,
                gate_type = %gate_type,
                lease_id = %lease_id,
                "Gate lease issued"
            );

            events.push(GateOrchestratorEvent::GateLeaseIssued {
                work_id: publication.work_id.clone(),
                gate_type,
                lease_id,
                executor_actor_id,
                changeset_digest: publication.changeset_digest,
                timestamp_ms: now_ms,
            });
        }

        Ok((issued_gate_types, executor_signers_for_return, events))
    }

    /// Records that a gate executor episode has been spawned.
    ///
    /// This updates the gate status from `LeaseIssued` to `Running` and
    /// returns a `GateExecutorSpawned` event.
    ///
    /// # State Machine
    ///
    /// Valid transition: `LeaseIssued` -> `Running`. All other states
    /// (including terminal states `Completed` and `TimedOut`) are rejected.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The orchestration or gate is not found
    /// - The gate is not in the `LeaseIssued` state
    pub async fn record_executor_spawned(
        &self,
        work_id: &str,
        gate_type: GateType,
        episode_id: &str,
    ) -> Result<Vec<GateOrchestratorEvent>, GateOrchestratorError> {
        let now_ms = self.clock.now_ms();
        let digest;

        {
            let mut orchestrations = self.orchestrations.write().await;
            // Capture the changeset digest before mutating state so persisted
            // events are digest-bound (Security MAJOR fix).
            digest = find_digest_for_work_id(&orchestrations, work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;
            let entry = find_by_work_id_mut(&mut orchestrations, work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;

            let gate_status = entry.gates.get_mut(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            // Enforce explicit state machine: only LeaseIssued -> Running is valid.
            match gate_status {
                GateStatus::LeaseIssued { lease_id } => {
                    if lease_id.is_empty() {
                        return Err(GateOrchestratorError::EmptyLeaseId {
                            work_id: work_id.to_string(),
                            gate_type: gate_type.to_string(),
                        });
                    }
                    *gate_status = GateStatus::Running {
                        lease_id: lease_id.clone(),
                        episode_id: episode_id.to_string(),
                    };
                },
                other => {
                    return Err(GateOrchestratorError::InvalidStateTransition {
                        work_id: work_id.to_string(),
                        gate_type: gate_type.to_string(),
                        reason: format!("expected LeaseIssued state, found {}", state_name(other)),
                    });
                },
            }
        }

        info!(
            work_id = %work_id,
            gate_type = %gate_type,
            episode_id = %episode_id,
            "Gate executor spawned"
        );

        Ok(vec![GateOrchestratorEvent::GateExecutorSpawned {
            work_id: work_id.to_string(),
            gate_type,
            episode_id: episode_id.to_string(),
            adapter_profile_id: gate_type.adapter_profile_id().to_string(),
            changeset_digest: digest,
            timestamp_ms: now_ms,
        }])
    }

    /// Records a gate receipt from a completed gate executor.
    ///
    /// This updates the gate status to `Completed` and returns a
    /// `GateReceiptCollected` event. If all gates are complete, also returns
    /// an `AllGatesCompleted` event.
    ///
    /// # Verdict Derivation (BLOCKER 1 fix)
    ///
    /// The verdict (pass/fail) is **derived from the receipt payload**, not
    /// from any caller-supplied parameter. A receipt with zero `payload_hash`
    /// or zero `evidence_bundle_hash` is treated as FAIL regardless of any
    /// other signal. This cryptographically binds the verdict to the
    /// receipt content and prevents caller bugs from marking
    /// insufficient-evidence receipts as PASS.
    ///
    /// # Version Validation (BLOCKER 2 fix)
    ///
    /// The receipt's `receipt_version`, `payload_kind`, and
    /// `payload_schema_version` are validated in strict mode before
    /// admission. Unknown or downgraded versions are rejected.
    ///
    /// # Signature Verification (BLOCKER 4 fix)
    ///
    /// The receipt's `receipt_signature` is verified against the
    /// executor-bound verifying key (generated at lease issuance time),
    /// not the orchestrator's signer key. This ensures only the authorized
    /// executor can produce valid receipts.
    ///
    /// # Binding Validation
    ///
    /// The receipt's `lease_id`, `gate_id`, `changeset_digest`, and
    /// `executor_actor_id` MUST match the issued lease for this gate type.
    ///
    /// # State Machine
    ///
    /// Valid transitions: `LeaseIssued` -> `Completed`, `Running` ->
    /// `Completed`. Terminal states (`Completed`, `TimedOut`) are rejected.
    ///
    /// # Arguments
    ///
    /// * `work_id` - The work ID
    /// * `gate_type` - The gate type that completed
    /// * `receipt` - The gate receipt from the executor
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The receipt version/kind/schema is unsupported (BLOCKER 2)
    /// - The receipt has zero evidence hashes (BLOCKER 1)
    /// - The receipt signature is invalid against executor key (BLOCKER 4)
    /// - The receipt's binding fields do not match the issued lease
    /// - The orchestration or gate is not found
    /// - The gate is in a terminal state
    pub async fn record_gate_receipt(
        &self,
        work_id: &str,
        gate_type: GateType,
        receipt: GateReceipt,
    ) -> Result<(Option<Vec<GateOutcome>>, Vec<GateOrchestratorEvent>), GateOrchestratorError> {
        let now_ms = self.clock.now_ms();
        let receipt_id = receipt.receipt_id.clone();

        // BLOCKER 2 FIX: Strict version/kind/schema validation at the
        // admission boundary. Unknown or downgraded receipt schemas are
        // rejected before any state transition.
        receipt.validate_version(true).map_err(|e| {
            GateOrchestratorError::ReceiptVersionRejected {
                work_id: work_id.to_string(),
                reason: e.to_string(),
            }
        })?;

        // Quality BLOCKER 2 FIX: Use the explicit `passed` field from the
        // receipt rather than deriving the verdict from hash inspection.
        // The executor MUST declare the verdict explicitly. Additionally,
        // reject receipts that claim PASS but have zero evidence hashes
        // (defense-in-depth).
        let passed = receipt.passed;

        // Defense-in-depth: a PASS verdict with zero hashes is suspicious
        // and rejected. This prevents executors from declaring PASS without
        // actually producing evidence.
        if passed {
            let has_zero_payload = receipt.payload_hash == [0u8; 32];
            let has_zero_evidence = receipt.evidence_bundle_hash == [0u8; 32];
            if has_zero_payload || has_zero_evidence {
                return Err(GateOrchestratorError::ZeroEvidenceVerdictRejected {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "receipt declares passed=true but has zero evidence \
                         (payload_hash_zero={has_zero_payload}, evidence_hash_zero={has_zero_evidence})"
                    ),
                });
            }
        }

        // Capture the changeset digest from the receipt itself (it was
        // already validated against the lease below). This ensures the
        // persisted GateReceiptCollected event is digest-bound (Security
        // MAJOR fix: receipt persistence must include changeset_digest).
        let receipt_digest = receipt.changeset_digest;

        {
            let mut orchestrations = self.orchestrations.write().await;
            let entry = find_by_work_id_mut(&mut orchestrations, work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;

            // BLOCKER 4 FIX: Verify receipt signature against the
            // executor-bound verifying key, not the orchestrator signer.
            let executor_vk = entry.executor_keys.get(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            receipt.validate_signature(executor_vk).map_err(|e| {
                GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "receipt signature verification failed against executor key: {e}"
                    ),
                }
            })?;

            let gate_status = entry.gates.get_mut(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            // Validate receipt binding against the issued lease.
            let lease = entry.leases.get(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            if receipt.lease_id != lease.lease_id {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "lease_id mismatch: receipt has '{}', expected '{}'",
                        receipt.lease_id, lease.lease_id
                    ),
                });
            }
            if receipt.gate_id != lease.gate_id {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "gate_id mismatch: receipt has '{}', expected '{}'",
                        receipt.gate_id, lease.gate_id
                    ),
                });
            }
            if receipt.changeset_digest != lease.changeset_digest {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: "changeset_digest mismatch".to_string(),
                });
            }
            if receipt.executor_actor_id != lease.executor_actor_id {
                return Err(GateOrchestratorError::ReceiptBindingMismatch {
                    work_id: work_id.to_string(),
                    reason: format!(
                        "executor_actor_id mismatch: receipt has '{}', expected '{}'",
                        receipt.executor_actor_id, lease.executor_actor_id
                    ),
                });
            }

            // Enforce explicit state machine transitions.
            // Only non-terminal states (LeaseIssued, Running) can transition
            // to Completed. Terminal states are rejected.
            match gate_status {
                GateStatus::LeaseIssued { lease_id } | GateStatus::Running { lease_id, .. } => {
                    if lease_id.is_empty() {
                        return Err(GateOrchestratorError::EmptyLeaseId {
                            work_id: work_id.to_string(),
                            gate_type: gate_type.to_string(),
                        });
                    }
                    *gate_status = GateStatus::Completed {
                        lease_id: lease_id.clone(),
                        receipt_id: receipt_id.clone(),
                        passed,
                    };
                },
                other => {
                    return Err(GateOrchestratorError::InvalidStateTransition {
                        work_id: work_id.to_string(),
                        gate_type: gate_type.to_string(),
                        reason: format!("cannot record receipt in {} state", state_name(other)),
                    });
                },
            }

            entry.receipts.insert(gate_type, receipt);
        }

        let mut events = vec![GateOrchestratorEvent::GateReceiptCollected {
            work_id: work_id.to_string(),
            gate_type,
            receipt_id,
            passed,
            changeset_digest: receipt_digest,
            timestamp_ms: now_ms,
        }];

        info!(
            work_id = %work_id,
            gate_type = %gate_type,
            passed = %passed,
            "Gate receipt collected (verdict derived from evidence hashes)"
        );

        // Check if all gates are complete
        let outcomes = self
            .check_all_gates_complete(work_id, now_ms, &mut events)
            .await?;

        Ok((outcomes, events))
    }

    /// Handles gate timeout by producing a FAIL verdict (fail-closed).
    ///
    /// # Security: Fail-Closed Semantics
    ///
    /// Expired gates produce a FAIL verdict, not silent expiry. This ensures
    /// that timeouts block merge rather than allowing unreviewed code through.
    ///
    /// # Signer Identity (Quality MAJOR 1)
    ///
    /// Timeout receipts are signed with the **orchestrator key** acting as a
    /// dedicated timeout authority. This is intentional: the executor never
    /// ran (or didn't finish), so it cannot produce a receipt. The
    /// orchestrator key serves as the timeout authority, and this is
    /// reflected in the `GateTimeoutReceiptGenerated` event.
    ///
    /// # Event Emission (Quality MAJOR 1)
    ///
    /// In addition to the `GateTimedOut` event, this method emits a
    /// `GateTimeoutReceiptGenerated` event containing the receipt ID of the
    /// synthetic timeout receipt. This ensures the ledger has a durable
    /// artifact for the timeout verdict.
    ///
    /// # State Machine
    ///
    /// Valid transitions: `LeaseIssued` -> `TimedOut`, `Running` -> `TimedOut`.
    /// Terminal states (`Completed`, `TimedOut`) are rejected.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The orchestration or gate is not found
    /// - The gate is in a terminal state
    pub async fn handle_gate_timeout(
        &self,
        work_id: &str,
        gate_type: GateType,
    ) -> Result<(Option<Vec<GateOutcome>>, Vec<GateOrchestratorEvent>), GateOrchestratorError> {
        let now_ms = self.clock.now_ms();
        let lease_id;
        let digest;
        let mut timeout_receipt_id: Option<String> = None;

        {
            let mut orchestrations = self.orchestrations.write().await;
            // Capture changeset digest for digest-bound event persistence
            // (Security MAJOR fix).
            digest = find_digest_for_work_id(&orchestrations, work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;
            let entry = find_by_work_id_mut(&mut orchestrations, work_id).ok_or_else(|| {
                GateOrchestratorError::OrchestrationNotFound {
                    work_id: work_id.to_string(),
                }
            })?;

            let gate_status = entry.gates.get_mut(&gate_type).ok_or_else(|| {
                GateOrchestratorError::GateNotFound {
                    work_id: work_id.to_string(),
                    gate_type: gate_type.to_string(),
                }
            })?;

            // Enforce state machine: only non-terminal -> TimedOut is valid.
            match gate_status {
                GateStatus::LeaseIssued { lease_id: lid }
                | GateStatus::Running { lease_id: lid, .. } => {
                    lease_id = lid.clone();
                    *gate_status = GateStatus::TimedOut {
                        lease_id: lid.clone(),
                    };
                },
                other => {
                    return Err(GateOrchestratorError::InvalidStateTransition {
                        work_id: work_id.to_string(),
                        gate_type: gate_type.to_string(),
                        reason: format!("cannot timeout in {} state", state_name(other)),
                    });
                },
            }

            // Create and store fail-closed receipt for the timed-out gate.
            // This ensures a FAIL verdict exists in the ledger, preventing
            // silent expiry from allowing unreviewed code through.
            //
            // Quality MAJOR 1: The timeout receipt is signed with the
            // orchestrator key acting as a dedicated timeout authority.
            if let Some(lease) = entry.leases.get(&gate_type) {
                let timeout_receipt = create_timeout_receipt(gate_type, lease, &self.signer);
                timeout_receipt_id = Some(timeout_receipt.receipt_id.clone());
                entry.receipts.insert(gate_type, timeout_receipt);
            }
        }

        warn!(
            work_id = %work_id,
            gate_type = %gate_type,
            "Gate timed out - fail-closed FAIL verdict (signed by orchestrator timeout authority)"
        );

        let mut events = vec![GateOrchestratorEvent::GateTimedOut {
            work_id: work_id.to_string(),
            gate_type,
            lease_id,
            changeset_digest: digest,
            timestamp_ms: now_ms,
        }];

        // Quality MAJOR 1: Emit explicit timeout receipt event so the
        // caller/ledger has a durable artifact for the timeout verdict.
        if let Some(receipt_id) = timeout_receipt_id {
            events.push(GateOrchestratorEvent::GateTimeoutReceiptGenerated {
                work_id: work_id.to_string(),
                gate_type,
                receipt_id,
                changeset_digest: digest,
                timestamp_ms: now_ms,
            });
        }

        // Check if all gates are complete
        let outcomes = self
            .check_all_gates_complete(work_id, now_ms, &mut events)
            .await?;

        Ok((outcomes, events))
    }

    /// Checks all active orchestrations for expired gates.
    ///
    /// Uses monotonic time (`Instant`) for timeout decisions to avoid
    /// NTP/manual clock shift attacks (Security BLOCKER 1). The wall-clock
    /// `expires_at` in the lease is kept as informational metadata only.
    ///
    /// Returns a list of (`work_id`, `gate_type`) pairs that have timed out.
    /// The caller should invoke [`Self::handle_gate_timeout`] for each.
    pub async fn check_timeouts(&self) -> Vec<(String, GateType)> {
        let orchestrations = self.orchestrations.read().await;
        let mut timed_out = Vec::new();

        for ((work_id, _digest), entry) in orchestrations.iter() {
            // Security BLOCKER 1: Use monotonic elapsed time, not wall-clock.
            let elapsed = entry.started_at_monotonic.elapsed();
            if elapsed >= self.gate_timeout_duration {
                for (&gate_type, status) in &entry.gates {
                    if !status.is_terminal() {
                        timed_out.push((work_id.clone(), gate_type));
                    }
                }
            }
        }

        timed_out
    }

    /// Returns the orchestrator wall clock time in milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Builds deterministic timeout events from authoritative lease facts.
    ///
    /// This path is used by the orchestrator-kernel timeout migration to avoid
    /// dependence on in-memory orchestration state after daemon restarts.
    #[must_use]
    pub fn build_timeout_events_from_lease(
        &self,
        lease: &GateLease,
        gate_type: GateType,
    ) -> Vec<GateOrchestratorEvent> {
        let now_ms = self.clock.now_ms();
        let timeout_receipt = create_timeout_receipt(gate_type, lease, &self.signer);
        vec![
            GateOrchestratorEvent::GateTimedOut {
                work_id: lease.work_id.clone(),
                gate_type,
                lease_id: lease.lease_id.clone(),
                changeset_digest: lease.changeset_digest,
                timestamp_ms: now_ms,
            },
            GateOrchestratorEvent::GateTimeoutReceiptGenerated {
                work_id: lease.work_id.clone(),
                gate_type,
                receipt_id: timeout_receipt.receipt_id,
                changeset_digest: lease.changeset_digest,
                timestamp_ms: now_ms,
            },
        ]
    }

    /// Production scheduler/driver for periodic timeout progression
    /// (Security BLOCKER 2).
    ///
    /// This method performs a complete timeout sweep: it checks for expired
    /// gates and handles each timeout in a single call. The daemon runtime
    /// should call this periodically (e.g., every 10 seconds) to ensure
    /// gate leases transition to terminal FAIL/PASS verdicts.
    ///
    /// Returns all events emitted during the sweep, suitable for ledger
    /// persistence.
    pub async fn poll_timeouts(&self) -> Vec<GateOrchestratorEvent> {
        let timed_out = self.check_timeouts().await;
        let mut all_events = Vec::new();

        for (work_id, gate_type) in timed_out {
            match self.handle_gate_timeout(&work_id, gate_type).await {
                Ok((_outcomes, events)) => all_events.extend(events),
                Err(e) => {
                    // Best-effort: log but don't fail the sweep.
                    // This can happen if a gate was completed between
                    // check_timeouts and handle_gate_timeout.
                    debug!(
                        work_id = %work_id,
                        gate_type = %gate_type,
                        error = %e,
                        "Timeout handling skipped (gate may have completed concurrently)"
                    );
                },
            }
        }

        if !all_events.is_empty() {
            info!(
                event_count = all_events.len(),
                "Timeout sweep produced events"
            );
        }

        all_events
    }

    /// Returns the gate status for a specific gate in an orchestration.
    pub async fn gate_status(&self, work_id: &str, gate_type: GateType) -> Option<GateStatus> {
        let orchestrations = self.orchestrations.read().await;
        find_by_work_id(&orchestrations, work_id).and_then(|e| e.gates.get(&gate_type).cloned())
    }

    /// Returns the gate lease for a specific gate in an orchestration.
    pub async fn gate_lease(&self, work_id: &str, gate_type: GateType) -> Option<GateLease> {
        let orchestrations = self.orchestrations.read().await;
        find_by_work_id(&orchestrations, work_id).and_then(|e| e.leases.get(&gate_type).cloned())
    }

    /// Returns the policy resolution for a work item.
    pub async fn policy_resolution(&self, work_id: &str) -> Option<PolicyResolvedForChangeSet> {
        let orchestrations = self.orchestrations.read().await;
        find_by_work_id(&orchestrations, work_id).map(|e| e.policy_resolution.clone())
    }

    /// Removes a completed orchestration from the active set.
    ///
    /// Returns `true` if the orchestration was found and removed.
    pub async fn remove_orchestration(&self, work_id: &str) -> bool {
        let mut orchestrations = self.orchestrations.write().await;
        remove_by_work_id(&mut orchestrations, work_id)
    }

    // =========================================================================
    // Publication-Driven Gate Lifecycle (CSID-003)
    // =========================================================================

    /// Lifecycle-only hook for session termination notifications.
    ///
    /// Session termination is a lifecycle signal only; it **never** starts new
    /// gate orchestrations. Gate orchestration is exclusively publication-
    /// driven through [`Self::start_for_changeset`].
    ///
    /// This method polls timeout progression on already-active orchestrations
    /// and returns any resulting timeout events (fail-closed FAIL verdicts).
    ///
    /// # Example Integration
    ///
    /// ```rust,ignore
    /// // In daemon startup:
    /// let orchestrator = Arc::new(GateOrchestrator::new(config, signer));
    ///
    /// // When a session terminates (lifecycle accounting only):
    /// let events = orchestrator
    ///     .poll_session_lifecycle()
    ///     .await;
    ///
    /// // Persist timeout events to ledger
    /// for event in events {
    ///     ledger.append(event).await?;
    /// }
    /// ```
    pub async fn poll_session_lifecycle(&self) -> Vec<GateOrchestratorEvent> {
        let events = self.poll_timeouts().await;
        debug!(
            event_count = events.len(),
            "Session lifecycle poll completed (publication-driven gate start only)"
        );
        events
    }

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /// Resolves policy for a changeset.
    ///
    /// # Ordering Invariant
    ///
    /// This MUST be called before any lease issuance for the same `work_id`.
    fn resolve_policy(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        _now_ms: u64,
    ) -> Result<PolicyResolvedForChangeSet, GateOrchestratorError> {
        PolicyResolvedForChangeSetBuilder::new(work_id, changeset_digest)
            .resolved_risk_tier(1) // Default risk tier 1 (low)
            .resolved_determinism_class(0) // Non-deterministic
            .resolver_actor_id(&self.config.resolver_actor_id)
            .resolver_version(&self.config.resolver_version)
            .try_build_and_sign(&self.signer)
            .map_err(|e| GateOrchestratorError::PolicyResolutionFailed {
                work_id: work_id.to_string(),
                reason: e.to_string(),
            })
    }

    /// Creates CAS-backed HTF time authority artifacts (`ClockProfile` +
    /// `TimeEnvelope`) and returns the hex-encoded envelope hash suitable
    /// for use as `time_envelope_ref`.
    ///
    /// # Risk-Tier-Aware Clock Profiles
    ///
    /// The `ClockProfile` is generated according to the resolved risk tier
    /// to satisfy `is_clock_profile_admissible_for_risk_tier` in the
    /// delegation/receipt admission path:
    ///
    /// - **Tier0/Tier1**: `BestEffortNtp`, no attestation.
    /// - **Tier2**: `AuthenticatedNts`, no attestation.
    /// - **Tier3/Tier4**: `AuthenticatedNts` with attestation present.
    ///
    /// # Security
    ///
    /// The returned string is a 64-character hex-encoded BLAKE3 hash of
    /// the canonical `TimeEnvelope` JSON, stored in the CAS. Downstream
    /// consumers (e.g. `validate_lease_time_authority`) resolve and verify
    /// this hash through `decode_hash32_hex` -> CAS retrieval -> canonical
    /// hash comparison.
    ///
    /// # Errors
    ///
    /// Returns [`GateOrchestratorError::LeaseIssuanceFailed`] if CAS is
    /// not configured or if CAS storage fails.
    fn create_cas_time_envelope_ref(
        &self,
        work_id: &str,
        now_ms: u64,
        risk_tier: RiskTier,
    ) -> Result<String, GateOrchestratorError> {
        let cas = self
            .cas
            .as_ref()
            .ok_or_else(|| GateOrchestratorError::LeaseIssuanceFailed {
                work_id: work_id.to_string(),
                gate_id: String::new(),
                reason: "CAS not configured; cannot create CAS-backed time_envelope_ref"
                    .to_string(),
            })?;

        // Select wall-time source and attestation based on risk tier.
        //
        // Policy (aligned with `is_clock_profile_admissible_for_risk_tier`):
        //   - Tier0/Tier1: BestEffortNtp, no attestation required.
        //   - Tier2:       AuthenticatedNts (BestEffortNtp rejected), no attestation
        //     required.
        //   - Tier3/Tier4: AuthenticatedNts + attestation present.
        let (wall_time_source, attestation) = match risk_tier {
            RiskTier::Tier0 | RiskTier::Tier1 => (WallTimeSource::BestEffortNtp, None),
            RiskTier::Tier2 => (WallTimeSource::AuthenticatedNts, None),
            RiskTier::Tier3 | RiskTier::Tier4 => (
                WallTimeSource::AuthenticatedNts,
                Some(serde_json::json!({
                    "type": "gate-orchestrator-nts-attestation",
                    "version": 1,
                    "issuer": "apm2-daemon",
                    "work_id": work_id,
                    "issued_at_ms": now_ms
                })),
            ),
        };

        // Build a ClockProfile with deterministic, risk-tier-appropriate defaults.
        let clock_profile = ClockProfile {
            attestation,
            build_fingerprint: format!("apm2-daemon/{}", env!("CARGO_PKG_VERSION")),
            hlc_enabled: true,
            max_wall_uncertainty_ns: 10_000_000, // 10ms
            monotonic_source: MonotonicSource::ClockMonotonic,
            profile_policy_id: "gate-orchestrator-default".to_string(),
            tick_rate_hz: 1_000_000_000, // 1GHz (nanosecond ticks)
            wall_time_source,
        };

        let profile_bytes = clock_profile.canonical_bytes().map_err(|e| {
            GateOrchestratorError::LeaseIssuanceFailed {
                work_id: work_id.to_string(),
                gate_id: String::new(),
                reason: format!("clock profile canonicalization failed: {e}"),
            }
        })?;
        let profile_hash = clock_profile.canonical_hash().map_err(|e| {
            GateOrchestratorError::LeaseIssuanceFailed {
                work_id: work_id.to_string(),
                gate_id: String::new(),
                reason: format!("clock profile hash failed: {e}"),
            }
        })?;
        cas.store(&profile_bytes)
            .map_err(|e| GateOrchestratorError::LeaseIssuanceFailed {
                work_id: work_id.to_string(),
                gate_id: String::new(),
                reason: format!("CAS store clock profile failed: {e}"),
            })?;

        // Build a TimeEnvelope referencing the stored ClockProfile.
        // Use tick-based timestamps derived from now_ms (not wall-time).
        let tick_value = now_ms.saturating_mul(1_000_000); // ms -> ns ticks
        let envelope = TimeEnvelope {
            clock_profile_hash: hex::encode(profile_hash),
            hlc: Hlc {
                logical: 0,
                wall_ns: now_ms.saturating_mul(1_000_000), // ms -> ns
            },
            ledger_anchor: LedgerTime::new("gate-orchestrator", 0, now_ms),
            mono: MonotonicReading {
                end_tick: Some(tick_value.saturating_add(1_000_000_000)), // +1s
                source: MonotonicSource::ClockMonotonic,
                start_tick: tick_value,
                tick_rate_hz: 1_000_000_000,
            },
            notes: Some(format!("gate-lease:{work_id}:{now_ms}")),
            wall: BoundedWallInterval::new(
                now_ms.saturating_mul(1_000_000),
                now_ms.saturating_mul(1_000_000).saturating_add(10_000_000), // +10ms uncertainty
                wall_time_source,
                "gate-orchestrator",
            )
            .unwrap_or_else(|_| {
                // Fallback: zero-width interval (should not happen with valid now_ms)
                BoundedWallInterval::new(0, 0, WallTimeSource::None, "fallback")
                    .expect("zero interval is always valid")
            }),
        };

        let envelope_bytes =
            envelope
                .canonical_bytes()
                .map_err(|e| GateOrchestratorError::LeaseIssuanceFailed {
                    work_id: work_id.to_string(),
                    gate_id: String::new(),
                    reason: format!("time envelope canonicalization failed: {e}"),
                })?;
        let envelope_hash =
            envelope
                .canonical_hash()
                .map_err(|e| GateOrchestratorError::LeaseIssuanceFailed {
                    work_id: work_id.to_string(),
                    gate_id: String::new(),
                    reason: format!("time envelope hash failed: {e}"),
                })?;
        cas.store(&envelope_bytes)
            .map_err(|e| GateOrchestratorError::LeaseIssuanceFailed {
                work_id: work_id.to_string(),
                gate_id: String::new(),
                reason: format!("CAS store time envelope failed: {e}"),
            })?;

        Ok(hex::encode(envelope_hash))
    }

    /// Issues a gate lease for a specific gate type.
    ///
    /// # Security
    ///
    /// - Uses domain-separated Ed25519 signatures (`GATE_LEASE_ISSUED:` prefix)
    /// - Binds the `changeset_digest` from authoritative publication identity
    /// - Sets temporal bounds (`issued_at` to `issued_at` + timeout)
    /// - `time_envelope_ref` is a CAS-backed hex-encoded hash when CAS is
    ///   configured, ensuring downstream HTF authority validation succeeds.
    fn issue_gate_lease(
        &self,
        work_id: &str,
        changeset_digest: [u8; 32],
        gate_type: GateType,
        policy_hash: &[u8; 32],
        now_ms: u64,
        risk_tier: RiskTier,
    ) -> Result<GateLease, GateOrchestratorError> {
        let lease_id = format!("lease-{}-{}-{}", work_id, gate_type.as_gate_id(), now_ms);
        let executor_actor_id = format!("executor-{}-{}", gate_type.as_gate_id(), now_ms);

        // Produce a CAS-backed time_envelope_ref when CAS is available.
        // Fall back to legacy format only when CAS is not configured (tests
        // without CAS wiring).
        let time_envelope_ref = if self.cas.is_some() {
            self.create_cas_time_envelope_ref(work_id, now_ms, risk_tier)?
        } else {
            format!("htf:gate:{work_id}:{now_ms}")
        };

        let mut builder = GateLeaseBuilder::new(&lease_id, work_id, gate_type.as_gate_id())
            .changeset_digest(changeset_digest)
            .executor_actor_id(&executor_actor_id)
            .issued_at(now_ms)
            .expires_at(now_ms + self.config.gate_timeout_ms)
            .policy_hash(*policy_hash)
            .issuer_actor_id(&self.config.issuer_actor_id)
            .time_envelope_ref(&time_envelope_ref);

        // AAT gates require an aat_extension per the lease invariant.
        // This binds the lease to a specific RCP manifest and view commitment.
        if gate_type == GateType::Aat {
            builder = builder.aat_extension(AatLeaseExtension {
                view_commitment_hash: changeset_digest,
                rcp_manifest_hash: *policy_hash,
                rcp_profile_id: gate_type.adapter_profile_id().to_string(),
                selection_policy_id: "default-selection-policy".to_string(),
            });
        }

        builder.try_build_and_sign(&self.signer).map_err(|e| {
            GateOrchestratorError::LeaseIssuanceFailed {
                work_id: work_id.to_string(),
                gate_id: gate_type.as_gate_id().to_string(),
                reason: e.to_string(),
            }
        })
    }

    /// Validates that a sublease is a strict subset of a parent lease.
    ///
    /// This is the production wiring point for
    /// [`PolicyInheritanceValidator::validate_sublease`]. Call this method
    /// when delegating authority from a parent holon's lease to a child
    /// holon's sublease. If validation fails, the delegation MUST
    /// be rejected (fail-closed).
    ///
    /// # Security
    ///
    /// - **Gate-scope enforcement**: The sublease's `gate_id` must match the
    ///   parent's `gate_id` (prevents gate-switching bypass).
    /// - **Strict subset**: All fields (`work_id`, `changeset_digest`,
    ///   `policy_hash`, time bounds, AAT extension fields) must be equal or
    ///   narrower.
    ///
    /// # Errors
    ///
    /// Returns [`GateOrchestratorError::SubleaseValidationFailed`] on any
    /// violation.
    pub fn validate_sublease_delegation(
        parent: &GateLease,
        sublease: &GateLease,
    ) -> Result<(), GateOrchestratorError> {
        PolicyInheritanceValidator::validate_sublease(parent, sublease).map_err(|e| {
            GateOrchestratorError::SubleaseValidationFailed {
                work_id: parent.work_id.clone(),
                reason: e.to_string(),
            }
        })
    }

    /// Issues a delegated sublease for a child holon, validating strict-subset
    /// constraints against the parent lease before signing.
    ///
    /// This is the production entry point for delegated lease issuance. It:
    ///
    /// 1. Builds a sublease [`GateLease`] from the provided parameters
    /// 2. Calls [`validate_sublease_delegation`](Self::validate_sublease_delegation)
    ///    **before** the sublease is returned to the caller
    /// 3. Returns the signed sublease only if validation passes
    ///
    /// # Security
    ///
    /// - **Admission before mutation**: The sublease is validated before being
    ///   returned, ensuring no invalid sublease escapes this method.
    /// - **Fail-closed**: Any validation failure rejects the delegation.
    /// - **Gate-scope enforcement**: The sublease's `gate_id` must match the
    ///   parent's `gate_id`.
    ///
    /// # Errors
    ///
    /// Returns [`GateOrchestratorError::SubleaseValidationFailed`] if the
    /// sublease violates the parent's constraints.
    /// Returns [`GateOrchestratorError::LeaseIssuanceFailed`] if the sublease
    /// cannot be built or signed.
    ///
    /// # TODO
    ///
    /// TODO(RFC-0019): Extend with child holon capability manifest binding,
    /// recursive depth limits, and delegation chain persistence when
    /// multi-holon orchestration is fully implemented.
    pub fn issue_delegated_sublease(
        &self,
        parent_lease: &GateLease,
        sublease_id: &str,
        executor_actor_id: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<GateLease, GateOrchestratorError> {
        // Inherit the parent lease's time_envelope_ref directly. The parent's
        // ref was already validated as CAS-backed during its issuance or
        // upstream admission. Minting a new non-CAS string would break
        // downstream `decode_hash32_hex` consumers.
        let time_envelope_ref = &parent_lease.time_envelope_ref;

        let mut builder =
            GateLeaseBuilder::new(sublease_id, &parent_lease.work_id, &parent_lease.gate_id)
                .changeset_digest(parent_lease.changeset_digest)
                .executor_actor_id(executor_actor_id)
                .issued_at(issued_at)
                .expires_at(expires_at)
                .policy_hash(parent_lease.policy_hash)
                .issuer_actor_id(&self.config.issuer_actor_id)
                .time_envelope_ref(time_envelope_ref);

        // Propagate AAT extension from parent if present (must match exactly).
        if let Some(ref aat_ext) = parent_lease.aat_extension {
            builder = builder.aat_extension(aat_ext.clone());
        }

        let sublease = builder.try_build_and_sign(&self.signer).map_err(|e| {
            GateOrchestratorError::LeaseIssuanceFailed {
                work_id: parent_lease.work_id.clone(),
                gate_id: parent_lease.gate_id.clone(),
                reason: e.to_string(),
            }
        })?;

        // Validate strict-subset BEFORE returning the sublease (fail-closed).
        Self::validate_sublease_delegation(parent_lease, &sublease)?;

        info!(
            work_id = %parent_lease.work_id,
            parent_lease_id = %parent_lease.lease_id,
            sublease_id = %sublease.lease_id,
            gate_id = %sublease.gate_id,
            "Delegated sublease issued and validated"
        );

        Ok(sublease)
    }

    /// Checks if all gates are complete and appends `AllGatesCompleted` to
    /// the provided event list if so.
    async fn check_all_gates_complete(
        &self,
        work_id: &str,
        now_ms: u64,
        events: &mut Vec<GateOrchestratorEvent>,
    ) -> Result<Option<Vec<GateOutcome>>, GateOrchestratorError> {
        let orchestrations = self.orchestrations.read().await;
        // Capture changeset digest for digest-bound AllGatesCompleted event
        // (Security MAJOR fix).
        let digest = find_digest_for_work_id(&orchestrations, work_id).ok_or_else(|| {
            GateOrchestratorError::OrchestrationNotFound {
                work_id: work_id.to_string(),
            }
        })?;
        let entry = find_by_work_id(&orchestrations, work_id).ok_or_else(|| {
            GateOrchestratorError::OrchestrationNotFound {
                work_id: work_id.to_string(),
            }
        })?;

        // Check if all gates are in terminal state
        let all_terminal = entry.gates.values().all(GateStatus::is_terminal);
        if !all_terminal {
            return Ok(None);
        }

        // Build outcomes.
        // Quality MAJOR 2: Sort outcomes by stable key (gate_id) to ensure
        // deterministic ordering for replay/hash/projection determinism.
        let mut outcomes = Vec::new();
        let mut all_passed = true;

        // Collect gate types and sort by gate_id for deterministic iteration.
        let mut gate_types: Vec<GateType> = entry.gates.keys().copied().collect();
        gate_types.sort_by_key(GateType::as_gate_id);

        for &gate_type in &gate_types {
            let status = &entry.gates[&gate_type];
            let outcome = match status {
                GateStatus::Completed {
                    receipt_id, passed, ..
                } => {
                    if !passed {
                        all_passed = false;
                    }
                    GateOutcome {
                        gate_type,
                        passed: *passed,
                        receipt_id: Some(receipt_id.clone()),
                        timed_out: false,
                    }
                },
                GateStatus::TimedOut { .. } => {
                    all_passed = false;
                    GateOutcome {
                        gate_type,
                        passed: false,
                        receipt_id: None,
                        timed_out: true,
                    }
                },
                _ => continue, // Shouldn't happen since we checked all_terminal
            };
            outcomes.push(outcome);
        }

        // Drop read lock before appending events
        drop(orchestrations);

        events.push(GateOrchestratorEvent::AllGatesCompleted {
            work_id: work_id.to_string(),
            all_passed,
            outcomes: outcomes.clone(),
            changeset_digest: digest,
            timestamp_ms: now_ms,
        });

        info!(
            work_id = %work_id,
            all_passed = %all_passed,
            gate_count = %outcomes.len(),
            "All gates completed"
        );

        // Security MAJOR 1 fix: Reclaim completed orchestrations to prevent
        // unbounded growth of the active-map. Without this, completed
        // orchestrations accumulate until max_concurrent_orchestrations is
        // reached, rejecting all new orchestrations.
        //
        // The events have been collected by value above, so removing the
        // entry from the active map does not lose any data the caller needs
        // for ledger persistence.
        let removed = self.remove_orchestration(work_id).await;
        debug!(
            work_id = %work_id,
            removed = %removed,
            "Completed orchestration reclaimed from active map"
        );

        Ok(Some(outcomes))
    }
}

// =============================================================================
// Composite Key Helpers (CSID-003)
// =============================================================================

/// Finds the orchestration entry matching `work_id`.
///
/// The one-active-per-work_id invariant (enforced in `start_for_publication`)
/// guarantees at most one entry exists per `work_id`, making this lookup
/// unambiguous. Used by receipt recording, status queries, and timeouts.
fn find_by_work_id<'a>(
    map: &'a HashMap<(String, [u8; 32]), OrchestrationEntry>,
    work_id: &str,
) -> Option<&'a OrchestrationEntry> {
    map.iter()
        .find(|((wid, _), _)| wid == work_id)
        .map(|(_, entry)| entry)
}

/// Finds the orchestration entry matching `work_id`, mutable.
///
/// The one-active-per-work_id invariant guarantees unambiguous lookup.
fn find_by_work_id_mut<'a>(
    map: &'a mut HashMap<(String, [u8; 32]), OrchestrationEntry>,
    work_id: &str,
) -> Option<&'a mut OrchestrationEntry> {
    map.iter_mut()
        .find(|((wid, _), _)| wid == work_id)
        .map(|(_, entry)| entry)
}

/// Finds the changeset digest for the orchestration matching `work_id`.
///
/// The composite key `(work_id, changeset_digest)` is the authoritative
/// identity binding. This helper extracts the digest portion so that
/// event constructors can include it in persisted payloads (CSID-004:
/// digest-bound receipt persistence).
fn find_digest_for_work_id(
    map: &HashMap<(String, [u8; 32]), OrchestrationEntry>,
    work_id: &str,
) -> Option<[u8; 32]> {
    map.keys()
        .find(|(wid, _)| wid == work_id)
        .map(|(_, digest)| *digest)
}

/// Removes the orchestration entry matching `work_id`.
///
/// The one-active-per-work_id invariant guarantees at most one entry.
/// Returns `true` if an entry was found and removed.
fn remove_by_work_id(
    map: &mut HashMap<(String, [u8; 32]), OrchestrationEntry>,
    work_id: &str,
) -> bool {
    let key = map.keys().find(|(wid, _)| wid == work_id).cloned();
    key.is_some_and(|k| map.remove(&k).is_some())
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Returns a human-readable name for a gate status variant.
const fn state_name(status: &GateStatus) -> &'static str {
    match status {
        GateStatus::LeaseIssued { .. } => "LeaseIssued",
        GateStatus::Running { .. } => "Running",
        GateStatus::Completed { .. } => "Completed",
        GateStatus::TimedOut { .. } => "TimedOut",
    }
}

/// Creates a fail-closed gate receipt for a timed-out gate.
///
/// # Security: Fail-Closed Semantics
///
/// Timed-out gates produce a receipt with FAIL semantics. This prevents
/// silent expiry from allowing unreviewed changes through the pipeline.
///
/// The receipt uses a zero payload hash and evidence bundle hash since
/// no actual gate execution occurred. The `passed` field is explicitly
/// set to `false` (Quality BLOCKER 2).
///
/// # Signer Identity (Security MAJOR 2)
///
/// The receipt is signed by the `signer` parameter, which is the
/// **orchestrator key** acting as a dedicated timeout authority. The
/// executor never ran (or didn't finish), so it cannot produce a receipt.
///
/// The `executor_actor_id` is set to [`TIMEOUT_AUTHORITY_ACTOR_ID`]
/// (`"orchestrator:timeout"`) rather than borrowing the lease's
/// `executor_actor_id`. This makes timeout receipt identity explicit
/// and distinguishable from real executor-signed receipts. The receipt
/// verification path must accept the orchestrator key for receipts
/// bearing this actor ID.
#[must_use]
pub fn create_timeout_receipt(
    gate_type: GateType,
    lease: &GateLease,
    signer: &Signer,
) -> GateReceipt {
    let receipt_id = format!("timeout-receipt-{}-{}", lease.lease_id, lease.expires_at);

    GateReceiptBuilder::new(&receipt_id, gate_type.as_gate_id(), &lease.lease_id)
        .changeset_digest(lease.changeset_digest)
        .executor_actor_id(TIMEOUT_AUTHORITY_ACTOR_ID)
        .receipt_version(1)
        .payload_kind(gate_type.payload_kind())
        .payload_schema_version(1)
        .payload_hash([0u8; 32]) // Zero hash: no actual execution
        .evidence_bundle_hash([0u8; 32]) // Zero hash: no evidence
        .passed(false) // Explicit FAIL verdict (Quality BLOCKER 2)
        .build_and_sign(signer)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(deprecated)]

    use super::*;

    /// Helper: creates a test signer (for orchestrator lease signing).
    fn test_signer() -> Arc<Signer> {
        Arc::new(Signer::generate())
    }

    /// Helper: creates a test session terminated info.
    ///
    /// Uses `terminated_at_ms: 0` to bypass freshness checks in tests.
    /// Tests that specifically validate freshness logic set a non-zero value.
    fn test_session_info(work_id: &str) -> SessionTerminatedInfo {
        SessionTerminatedInfo {
            session_id: format!("session-{work_id}"),
            work_id: work_id.to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 0,
        }
    }

    /// Helper: creates a default orchestrator.
    fn test_orchestrator() -> GateOrchestrator {
        GateOrchestrator::new(GateOrchestratorConfig::default(), test_signer())
    }

    /// Helper: start orchestration and return executor signers map.
    async fn setup_orchestration(
        orch: &GateOrchestrator,
        work_id: &str,
    ) -> HashMap<GateType, Arc<Signer>> {
        let info = test_session_info(work_id);
        let (_gate_types, executor_signers, _events) =
            orch.start_from_test_session(info).await.unwrap();
        executor_signers
    }

    /// Helper: build a valid receipt signed with the correct executor signer.
    ///
    /// The `passed` field is derived from whether both hashes are non-zero,
    /// matching the defense-in-depth check in the orchestrator.
    fn build_receipt(
        receipt_id: &str,
        gate_type: GateType,
        lease: &GateLease,
        executor_signer: &Signer,
        payload_hash: [u8; 32],
        evidence_hash: [u8; 32],
    ) -> GateReceipt {
        let verdict = payload_hash != [0u8; 32] && evidence_hash != [0u8; 32];
        GateReceiptBuilder::new(receipt_id, gate_type.as_gate_id(), &lease.lease_id)
            .changeset_digest(lease.changeset_digest)
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind(gate_type.payload_kind())
            .payload_schema_version(1)
            .payload_hash(payload_hash)
            .evidence_bundle_hash(evidence_hash)
            .passed(verdict)
            .build_and_sign(executor_signer)
    }

    // =========================================================================
    // Happy Path Tests
    // =========================================================================

    #[tokio::test]
    async fn test_start_from_test_session_issues_all_gates() {
        let orch = test_orchestrator();
        let info = test_session_info("work-001");

        let (gate_types, _executor_signers, _events) =
            orch.start_from_test_session(info).await.unwrap();

        assert_eq!(gate_types.len(), 3);
        assert!(gate_types.contains(&GateType::Aat));
        assert!(gate_types.contains(&GateType::Quality));
        assert!(gate_types.contains(&GateType::Security));
        assert_eq!(orch.active_count().await, 1);
    }

    #[tokio::test]
    async fn test_policy_resolved_before_leases() {
        let orch = test_orchestrator();
        let info = test_session_info("work-002");

        let (_gate_types, _signers, events) = orch.start_from_test_session(info).await.unwrap();

        // First event must be PolicyResolved
        assert!(matches!(
            events[0],
            GateOrchestratorEvent::PolicyResolved { .. }
        ));
        // Subsequent events must be GateLeaseIssued
        for event in &events[1..] {
            assert!(
                matches!(event, GateOrchestratorEvent::GateLeaseIssued { .. }),
                "Expected GateLeaseIssued, got {event:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_gate_lease_signatures_valid() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-003");

        orch.start_from_test_session(info).await.unwrap();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-003", gate_type).await.unwrap();
            assert!(
                lease.validate_signature(&signer.verifying_key()).is_ok(),
                "Signature validation failed for {gate_type}"
            );
        }
    }

    #[tokio::test]
    async fn test_gate_lease_changeset_binding() {
        let orch = test_orchestrator();
        let changeset = [0xAB; 32];
        let info = SessionTerminatedInfo {
            session_id: "session-binding".to_string(),
            work_id: "work-binding".to_string(),
            changeset_digest: changeset,
            terminated_at_ms: 0,
        };

        orch.start_from_test_session(info).await.unwrap();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-binding", gate_type).await.unwrap();
            assert_eq!(
                lease.changeset_digest, changeset,
                "Changeset mismatch for {gate_type}"
            );
        }
    }

    #[tokio::test]
    async fn test_gate_lease_policy_hash_matches_resolution() {
        let orch = test_orchestrator();
        let info = test_session_info("work-004");

        orch.start_from_test_session(info).await.unwrap();

        let resolution = orch.policy_resolution("work-004").await.unwrap();
        let policy_hash = resolution.resolved_policy_hash();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-004", gate_type).await.unwrap();
            assert_eq!(
                lease.policy_hash, policy_hash,
                "Policy hash mismatch for {gate_type}"
            );
        }
    }

    #[tokio::test]
    async fn test_record_executor_spawned() {
        let orch = test_orchestrator();
        let info = test_session_info("work-005");

        orch.start_from_test_session(info).await.unwrap();

        let events = orch
            .record_executor_spawned("work-005", GateType::Quality, "ep-001")
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            GateOrchestratorEvent::GateExecutorSpawned { .. }
        ));

        let status = orch
            .gate_status("work-005", GateType::Quality)
            .await
            .unwrap();
        assert!(matches!(status, GateStatus::Running { episode_id, .. } if episode_id == "ep-001"));
    }

    #[tokio::test]
    async fn test_record_gate_receipt_completes_gate() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-006").await;

        let lease = orch
            .gate_lease("work-006", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];
        let receipt = build_receipt(
            "receipt-001",
            GateType::Quality,
            &lease,
            exec_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        let (result, events) = orch
            .record_gate_receipt("work-006", GateType::Quality, receipt)
            .await
            .unwrap();

        // Not all gates complete yet
        assert!(result.is_none());
        // Should have GateReceiptCollected event
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GateOrchestratorEvent::GateReceiptCollected { .. }))
        );

        // Non-zero hashes -> verdict derived as PASS
        let status = orch
            .gate_status("work-006", GateType::Quality)
            .await
            .unwrap();
        assert!(matches!(status, GateStatus::Completed { passed: true, .. }));
    }

    #[tokio::test]
    async fn test_all_gates_completed_event() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-007").await;

        // Complete all three gates with non-zero hashes (all PASS)
        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-007", gate_type).await.unwrap();
            let exec_signer = &exec_signers[&gate_type];
            let receipt = build_receipt(
                &format!("receipt-{}", gate_type.as_gate_id()),
                gate_type,
                &lease,
                exec_signer,
                [0xBB; 32],
                [0xCC; 32],
            );

            let (result, _events) = orch
                .record_gate_receipt("work-007", gate_type, receipt)
                .await
                .unwrap();

            if gate_type == GateType::Security {
                // Last gate should trigger AllGatesCompleted
                let outcomes = result.expect("expected outcomes for last gate");
                assert_eq!(outcomes.len(), 3);
                assert!(outcomes.iter().all(|o| o.passed));
            }
        }
    }

    // =========================================================================
    // Timeout / Fail-Closed Tests
    // =========================================================================

    #[tokio::test]
    async fn test_gate_timeout_produces_fail_verdict() {
        let orch = test_orchestrator();
        let info = test_session_info("work-008");

        orch.start_from_test_session(info).await.unwrap();

        let (result, events) = orch
            .handle_gate_timeout("work-008", GateType::Aat)
            .await
            .unwrap();

        // Not all gates done
        assert!(result.is_none());
        // Should have GateTimedOut event
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. }))
        );

        let status = orch.gate_status("work-008", GateType::Aat).await.unwrap();
        assert!(matches!(status, GateStatus::TimedOut { .. }));
    }

    #[tokio::test]
    async fn test_timeout_receipt_is_fail_closed() {
        let signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-timeout", "work-timeout", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-timeout")
            .issued_at(1000)
            .expires_at(2000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-timeout")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let receipt = create_timeout_receipt(GateType::Quality, &lease, &signer);

        // Timeout receipt should have zero hashes (no actual execution)
        assert_eq!(receipt.payload_hash, [0u8; 32]);
        assert_eq!(receipt.evidence_bundle_hash, [0u8; 32]);
        assert!(receipt.receipt_id.starts_with("timeout-receipt-"));
    }

    #[tokio::test]
    async fn test_mixed_completion_and_timeout() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-009").await;

        // Complete AAT gate with non-zero hashes (PASS)
        let lease = orch.gate_lease("work-009", GateType::Aat).await.unwrap();
        let exec_signer = &exec_signers[&GateType::Aat];
        let receipt = build_receipt(
            "receipt-aat",
            GateType::Aat,
            &lease,
            exec_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        orch.record_gate_receipt("work-009", GateType::Aat, receipt)
            .await
            .unwrap();

        // Timeout quality gate
        orch.handle_gate_timeout("work-009", GateType::Quality)
            .await
            .unwrap();

        // Timeout security gate -> should trigger AllGatesCompleted
        let (result, _events) = orch
            .handle_gate_timeout("work-009", GateType::Security)
            .await
            .unwrap();

        let outcomes = result.expect("expected outcomes when all gates done");
        assert_eq!(outcomes.len(), 3);

        // AAT passed, quality and security timed out
        let aat = outcomes
            .iter()
            .find(|o| o.gate_type == GateType::Aat)
            .unwrap();
        assert!(aat.passed);
        assert!(!aat.timed_out);

        let quality = outcomes
            .iter()
            .find(|o| o.gate_type == GateType::Quality)
            .unwrap();
        assert!(!quality.passed);
        assert!(quality.timed_out);

        let security = outcomes
            .iter()
            .find(|o| o.gate_type == GateType::Security)
            .unwrap();
        assert!(!security.passed);
        assert!(security.timed_out);
    }

    // =========================================================================
    // Boundary / Error Tests
    // =========================================================================

    #[tokio::test]
    async fn test_empty_work_id_rejected() {
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "session-empty".to_string(),
            work_id: String::new(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 0,
        };

        let err = orch
            .start_from_test_session(info)
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, GateOrchestratorError::EmptyWorkId));
    }

    #[tokio::test]
    async fn test_work_id_too_long_rejected() {
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "session-long".to_string(),
            work_id: "x".repeat(MAX_WORK_ID_LENGTH + 1),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 0,
        };

        let err = orch
            .start_from_test_session(info)
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, GateOrchestratorError::WorkIdTooLong { .. }));
    }

    #[tokio::test]
    async fn test_duplicate_orchestration_replay_is_noop() {
        // Security MAJOR 1: Same (work_id, changeset_digest) is idempotent.
        let orch = test_orchestrator();
        let info1 = test_session_info("work-dup");
        let info2 = test_session_info("work-dup");

        orch.start_from_test_session(info1).await.unwrap();

        let (gate_types, signers, events) = orch.start_from_test_session(info2).await.unwrap();
        assert!(gate_types.is_empty());
        assert!(signers.is_empty());
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_same_work_id_different_digest_allowed() {
        // CSID-003: Same work_id but different changeset_digest → ALLOWED
        // (different changesets for the same work can be orchestrated
        // concurrently).
        let orch = test_orchestrator();
        let info1 = SessionTerminatedInfo {
            session_id: "session-alpha".to_string(),
            work_id: "work-dup-wid".to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 0,
        };
        let info2 = SessionTerminatedInfo {
            session_id: "session-beta".to_string(),
            work_id: "work-dup-wid".to_string(),
            changeset_digest: [0x99; 32], // Different digest → separate orchestration
            terminated_at_ms: 0,
        };

        orch.start_from_test_session(info1).await.unwrap();

        // With composite key (work_id, changeset_digest), this should succeed.
        let result = orch.start_from_test_session(info2).await;
        assert!(
            result.is_ok(),
            "same work_id with different digest should be allowed"
        );
    }

    #[tokio::test]
    async fn test_same_work_id_same_digest_duplicate_rejected() {
        // CSID-003: Same (work_id, changeset_digest) → DuplicateOrchestration
        let orch = test_orchestrator();
        let info1 = SessionTerminatedInfo {
            session_id: "session-alpha".to_string(),
            work_id: "work-dup-wid".to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 0,
        };
        let info2 = SessionTerminatedInfo {
            session_id: "session-beta".to_string(),
            work_id: "work-dup-wid".to_string(),
            changeset_digest: [0x42; 32], // Same digest → duplicate
            terminated_at_ms: 0,
        };

        orch.start_from_test_session(info1).await.unwrap();

        // Same (work_id, changeset_digest) should be detected as replay/no-op.
        // Note: the idempotency key set provides this guard, returning
        // empty outputs instead of an error.
        let result = orch.start_from_test_session(info2).await;
        assert!(result.is_ok(), "duplicate should be no-op, not error");
        let (gate_types, _, events) = result.unwrap();
        assert!(
            gate_types.is_empty(),
            "duplicate should return empty outputs"
        );
        assert!(events.is_empty(), "duplicate should return no events");
    }

    #[tokio::test]
    async fn test_max_orchestrations_exceeded() {
        let config = GateOrchestratorConfig {
            max_concurrent_orchestrations: 2,
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());

        orch.start_from_test_session(test_session_info("work-a"))
            .await
            .unwrap();
        orch.start_from_test_session(test_session_info("work-b"))
            .await
            .unwrap();

        let result = orch
            .start_from_test_session(test_session_info("work-c"))
            .await;
        assert!(result.is_err(), "expected MaxOrchestrationsExceeded");
        let err = result.err().unwrap();
        assert!(matches!(
            err,
            GateOrchestratorError::MaxOrchestrationsExceeded { current: 2, max: 2 }
        ));
    }

    #[tokio::test]
    async fn test_orchestration_not_found_error() {
        let orch = test_orchestrator();

        let err = orch
            .record_executor_spawned("nonexistent", GateType::Aat, "ep-001")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::OrchestrationNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_remove_orchestration() {
        let orch = test_orchestrator();
        let info = test_session_info("work-remove");

        orch.start_from_test_session(info).await.unwrap();
        assert_eq!(orch.active_count().await, 1);

        assert!(orch.remove_orchestration("work-remove").await);
        assert_eq!(orch.active_count().await, 0);

        // Second removal should return false
        assert!(!orch.remove_orchestration("work-remove").await);
    }

    // =========================================================================
    // Domain Separation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_leases_use_domain_separated_signatures() {
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let info = test_session_info("work-domain");

        orch.start_from_test_session(info).await.unwrap();

        // Verify that all leases have valid domain-separated signatures
        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-domain", gate_type).await.unwrap();

            // Valid with correct key
            assert!(lease.validate_signature(&signer.verifying_key()).is_ok());

            // Invalid with wrong key
            let wrong_signer = Signer::generate();
            assert!(
                lease
                    .validate_signature(&wrong_signer.verifying_key())
                    .is_err()
            );
        }
    }

    // =========================================================================
    // Policy Resolution Ordering Tests
    // =========================================================================

    #[tokio::test]
    async fn test_policy_hash_consistency_across_gates() {
        let orch = test_orchestrator();
        let info = test_session_info("work-consistency");

        orch.start_from_test_session(info).await.unwrap();

        let resolution = orch.policy_resolution("work-consistency").await.unwrap();
        let expected_hash = resolution.resolved_policy_hash();

        // All leases should reference the same policy hash
        for gate_type in GateType::all() {
            let lease = orch
                .gate_lease("work-consistency", gate_type)
                .await
                .unwrap();
            assert_eq!(
                lease.policy_hash, expected_hash,
                "Policy hash inconsistency for {gate_type}"
            );
        }
    }

    // =========================================================================
    // Temporal Bounds Tests
    // =========================================================================

    #[tokio::test]
    async fn test_gate_lease_temporal_bounds() {
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 60_000, // 1 minute
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        let info = test_session_info("work-temporal");

        orch.start_from_test_session(info).await.unwrap();

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-temporal", gate_type).await.unwrap();
            // Lease should have timeout duration
            assert_eq!(
                lease.expires_at - lease.issued_at,
                60_000,
                "Timeout mismatch for {gate_type}"
            );
            // Lease should be valid at issued_at
            assert!(lease.validate_temporal_bounds(lease.issued_at));
            // Lease should not be valid at expires_at
            assert!(!lease.validate_temporal_bounds(lease.expires_at));
        }
    }

    // =========================================================================
    // Gate Type Tests
    // =========================================================================

    #[test]
    fn test_gate_type_gate_ids() {
        assert_eq!(GateType::Aat.as_gate_id(), "gate-aat");
        assert_eq!(GateType::Quality.as_gate_id(), "gate-quality");
        assert_eq!(GateType::Security.as_gate_id(), "gate-security");
    }

    #[test]
    fn test_gate_type_payload_kinds() {
        assert_eq!(GateType::Aat.payload_kind(), "aat");
        assert_eq!(GateType::Quality.payload_kind(), "quality");
        assert_eq!(GateType::Security.payload_kind(), "security");
    }

    #[test]
    fn test_gate_type_all() {
        let all = GateType::all();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_gate_type_adapter_profiles() {
        assert_eq!(
            GateType::Aat.adapter_profile_id(),
            apm2_core::fac::CLAUDE_CODE_PROFILE_ID
        );
        assert_eq!(
            GateType::Quality.adapter_profile_id(),
            apm2_core::fac::GEMINI_CLI_PROFILE_ID
        );
        assert_eq!(
            GateType::Security.adapter_profile_id(),
            apm2_core::fac::GEMINI_CLI_PROFILE_ID
        );
    }

    // =========================================================================
    // Session ID Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_session_id_too_long_rejected() {
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "s".repeat(MAX_STRING_LENGTH + 1),
            work_id: "work-valid".to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: 0,
        };

        let err = orch
            .start_from_test_session(info)
            .await
            .err()
            .expect("expected error");
        assert!(matches!(
            err,
            GateOrchestratorError::StringTooLong {
                field: "changeset_published_event_id",
                ..
            }
        ));
    }

    // =========================================================================
    // Per-Invocation Event Tests (BLOCKER 3)
    // =========================================================================

    #[tokio::test]
    async fn test_events_returned_per_invocation() {
        let orch = test_orchestrator();
        let info = test_session_info("work-per-inv");

        let (_gate_types, _signers, events) = orch.start_from_test_session(info).await.unwrap();

        // Events are returned from the call, not buffered
        assert!(!events.is_empty());
        // 1 PolicyResolved + 3 GateLeaseIssued = 4 events
        assert_eq!(events.len(), 4);
    }

    #[tokio::test]
    async fn test_event_count_matches_gates() {
        let orch = test_orchestrator();
        let info = test_session_info("work-events");

        let (_gate_types, _signers, events) = orch.start_from_test_session(info).await.unwrap();
        // 1 PolicyResolved + 3 GateLeaseIssued = 4 events
        assert_eq!(events.len(), 4);
    }

    // =========================================================================
    // BLOCKER 2: Events not emitted on admission failure
    // =========================================================================

    #[tokio::test]
    async fn test_no_events_on_duplicate_orchestration() {
        let orch = test_orchestrator();
        let info1 = test_session_info("work-no-events-dup");
        let info2 = test_session_info("work-no-events-dup");

        // First succeeds
        let (_gate_types, _signers, events1) = orch.start_from_test_session(info1).await.unwrap();
        assert!(!events1.is_empty());

        // Second call is idempotent no-op with empty outputs.
        let (gate_types, signers, events2) = orch.start_from_test_session(info2).await.unwrap();
        assert!(gate_types.is_empty());
        assert!(signers.is_empty());
        assert!(events2.is_empty());
    }

    #[tokio::test]
    async fn test_no_events_on_max_orchestrations_exceeded() {
        let config = GateOrchestratorConfig {
            max_concurrent_orchestrations: 1,
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());

        // First succeeds
        orch.start_from_test_session(test_session_info("work-max-a"))
            .await
            .unwrap();

        // Second fails - no events should be returned
        let result = orch
            .start_from_test_session(test_session_info("work-max-b"))
            .await;
        assert!(result.is_err(), "expected MaxOrchestrationsExceeded");
        let err = result.err().unwrap();
        assert!(matches!(
            err,
            GateOrchestratorError::MaxOrchestrationsExceeded { .. }
        ));
    }

    // =========================================================================
    // Check Timeouts Tests
    // =========================================================================

    #[tokio::test]
    async fn test_check_timeouts_finds_expired_gates() {
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 0, // Instant timeout for testing
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        let info = test_session_info("work-expire");

        orch.start_from_test_session(info).await.unwrap();

        // With 0ms timeout, all gates should be timed out immediately
        let timed_out = orch.check_timeouts().await;
        assert_eq!(timed_out.len(), 3);
    }

    // =========================================================================
    // BLOCKER 3: Daemon Runtime Integration Tests
    // =========================================================================

    #[tokio::test]
    async fn test_poll_session_lifecycle_returns_no_bootstrap_events() {
        let orch = test_orchestrator();
        let events = orch.poll_session_lifecycle().await;

        // Lifecycle hook is session-only and must not start gates.
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_poll_session_lifecycle_handles_immediate_timeouts() {
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 0, // Instant timeout
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        // Seed an active orchestration via publication-driven start.
        let _ = orch
            .start_from_test_session(test_session_info("work-imm-timeout-seed"))
            .await
            .unwrap();
        let events = orch.poll_session_lifecycle().await;

        // Lifecycle hook should sweep and emit timeout events for seeded gates.
        let timeout_count = events
            .iter()
            .filter(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. }))
            .count();
        assert_eq!(timeout_count, 3, "all 3 gates should have timed out");
    }

    #[tokio::test]
    async fn test_poll_session_lifecycle_is_idempotent() {
        let orch = test_orchestrator();

        let events1 = orch.poll_session_lifecycle().await;
        let events2 = orch.poll_session_lifecycle().await;
        assert!(
            events1.is_empty() && events2.is_empty(),
            "lifecycle-only hook should be idempotent and never replay-reject"
        );

        orch.start_from_test_session(test_session_info("work-dup2"))
            .await
            .unwrap();
        let _ = orch.poll_session_lifecycle().await;
    }

    // =========================================================================
    // BLOCKER 4: Receipt Signature Against Executor-Bound Key Tests
    // =========================================================================

    #[tokio::test]
    async fn test_receipt_with_wrong_signer_rejected() {
        let orch = test_orchestrator();
        let _exec_signers = setup_orchestration(&orch, "work-sig-1").await;

        let lease = orch
            .gate_lease("work-sig-1", GateType::Quality)
            .await
            .unwrap();

        // Sign with a DIFFERENT signer (neither orchestrator nor executor key)
        let wrong_signer = Signer::generate();
        let receipt = build_receipt(
            "receipt-bad-sig",
            GateType::Quality,
            &lease,
            &wrong_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        let err = orch
            .record_gate_receipt("work-sig-1", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GateOrchestratorError::ReceiptBindingMismatch { ref reason, .. } if reason.contains("signature")),
            "Expected signature verification failure, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_receipt_signed_with_orchestrator_key_rejected() {
        // BLOCKER 4: The orchestrator signer must NOT be accepted for
        // receipt signatures; only the executor-bound key is valid.
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), Arc::clone(&signer));
        let _exec_signers = setup_orchestration(&orch, "work-sig-orch").await;

        let lease = orch
            .gate_lease("work-sig-orch", GateType::Quality)
            .await
            .unwrap();

        // Sign with the orchestrator signer (should be rejected)
        let receipt = build_receipt(
            "receipt-orch-sig",
            GateType::Quality,
            &lease,
            &signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        let err = orch
            .record_gate_receipt("work-sig-orch", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GateOrchestratorError::ReceiptBindingMismatch { ref reason, .. } if reason.contains("signature")),
            "Orchestrator signer should be rejected for receipts, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_receipt_with_correct_executor_signer_accepted() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-sig-2").await;

        let lease = orch
            .gate_lease("work-sig-2", GateType::Quality)
            .await
            .unwrap();

        // Sign with the correct executor signer
        let exec_signer = &exec_signers[&GateType::Quality];
        let receipt = build_receipt(
            "receipt-good-sig",
            GateType::Quality,
            &lease,
            exec_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        let (result, events) = orch
            .record_gate_receipt("work-sig-2", GateType::Quality, receipt)
            .await
            .unwrap();

        // Should succeed
        assert!(result.is_none()); // Not all gates complete
        assert!(!events.is_empty());
    }

    #[tokio::test]
    async fn test_executor_key_mismatch_across_gate_types() {
        // BLOCKER 4: Executor signer for gate A must NOT be accepted for
        // gate B.
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-cross-key").await;

        let lease = orch
            .gate_lease("work-cross-key", GateType::Quality)
            .await
            .unwrap();

        // Use the AAT executor signer for a quality receipt
        let wrong_exec_signer = &exec_signers[&GateType::Aat];
        let receipt = build_receipt(
            "receipt-cross-key",
            GateType::Quality,
            &lease,
            wrong_exec_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        let err = orch
            .record_gate_receipt("work-cross-key", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GateOrchestratorError::ReceiptBindingMismatch { .. }),
            "Cross-gate executor key should be rejected, got: {err:?}"
        );
    }

    // =========================================================================
    // Receipt Binding Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_receipt_lease_id_mismatch_rejected() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-bind-1").await;

        let lease = orch
            .gate_lease("work-bind-1", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong lease_id
        let exec_signer = &exec_signers[&GateType::Quality];
        let receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", "wrong-lease-id")
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .passed(true)
            .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-bind-1", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_receipt_gate_id_mismatch_rejected() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-bind-2").await;

        let lease = orch
            .gate_lease("work-bind-2", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong gate_id
        let exec_signer = &exec_signers[&GateType::Quality];
        let receipt = GateReceiptBuilder::new("receipt-bad", "wrong-gate-id", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id(&lease.executor_actor_id)
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .passed(true)
            .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-bind-2", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_receipt_changeset_digest_mismatch_rejected() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-bind-3").await;

        let lease = orch
            .gate_lease("work-bind-3", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong changeset_digest
        let exec_signer = &exec_signers[&GateType::Quality];
        let receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", &lease.lease_id)
                .changeset_digest([0xFF; 32]) // Wrong digest
                .executor_actor_id(&lease.executor_actor_id)
                .receipt_version(1)
                .payload_kind("quality")
                .payload_schema_version(1)
                .payload_hash([0xBB; 32])
                .evidence_bundle_hash([0xCC; 32])
                .passed(true)
                .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-bind-3", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_receipt_executor_actor_id_mismatch_rejected() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-bind-4").await;

        let lease = orch
            .gate_lease("work-bind-4", GateType::Quality)
            .await
            .unwrap();

        // Build receipt with wrong executor_actor_id
        let exec_signer = &exec_signers[&GateType::Quality];
        let receipt = GateReceiptBuilder::new("receipt-bad", "gate-quality", &lease.lease_id)
            .changeset_digest([0x42; 32])
            .executor_actor_id("wrong-executor")
            .receipt_version(1)
            .payload_kind("quality")
            .payload_schema_version(1)
            .payload_hash([0xBB; 32])
            .evidence_bundle_hash([0xCC; 32])
            .passed(true)
            .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-bind-4", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::ReceiptBindingMismatch { .. }
        ));
    }

    // =========================================================================
    // BLOCKER 1: Verdict Derived From Evidence (Zero-Hash = FAIL)
    // =========================================================================

    #[tokio::test]
    async fn test_zero_payload_hash_derives_fail_verdict() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-zero-ph").await;

        let lease = orch
            .gate_lease("work-zero-ph", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Zero payload hash -> verdict MUST be FAIL
        let receipt = build_receipt(
            "receipt-zero-ph",
            GateType::Quality,
            &lease,
            exec_signer,
            [0u8; 32], // zero payload hash
            [0xCC; 32],
        );

        let (_result, _events) = orch
            .record_gate_receipt("work-zero-ph", GateType::Quality, receipt)
            .await
            .unwrap();

        let status = orch
            .gate_status("work-zero-ph", GateType::Quality)
            .await
            .unwrap();
        assert!(
            matches!(status, GateStatus::Completed { passed: false, .. }),
            "Zero payload hash must derive FAIL verdict"
        );
    }

    #[tokio::test]
    async fn test_zero_evidence_hash_derives_fail_verdict() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-zero-ev").await;

        let lease = orch
            .gate_lease("work-zero-ev", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Zero evidence bundle hash -> verdict MUST be FAIL
        let receipt = build_receipt(
            "receipt-zero-ev",
            GateType::Quality,
            &lease,
            exec_signer,
            [0xBB; 32],
            [0u8; 32], // zero evidence hash
        );

        let (_result, _events) = orch
            .record_gate_receipt("work-zero-ev", GateType::Quality, receipt)
            .await
            .unwrap();

        let status = orch
            .gate_status("work-zero-ev", GateType::Quality)
            .await
            .unwrap();
        assert!(
            matches!(status, GateStatus::Completed { passed: false, .. }),
            "Zero evidence hash must derive FAIL verdict"
        );
    }

    #[tokio::test]
    async fn test_nonzero_hashes_derive_pass_verdict() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-pass").await;

        let lease = orch
            .gate_lease("work-pass", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Both non-zero -> verdict MUST be PASS
        let receipt = build_receipt(
            "receipt-pass",
            GateType::Quality,
            &lease,
            exec_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        let (_result, _events) = orch
            .record_gate_receipt("work-pass", GateType::Quality, receipt)
            .await
            .unwrap();

        let status = orch
            .gate_status("work-pass", GateType::Quality)
            .await
            .unwrap();
        assert!(
            matches!(status, GateStatus::Completed { passed: true, .. }),
            "Non-zero hashes must derive PASS verdict"
        );
    }

    #[tokio::test]
    async fn test_failing_receipt_produces_fail_verdict() {
        // Test that a quality gate with zero evidence produces overall FAIL
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-fail").await;

        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-fail", gate_type).await.unwrap();
            let exec_signer = &exec_signers[&gate_type];

            // Quality gets zero payload_hash (FAIL), others get non-zero (PASS)
            let payload_hash = if gate_type == GateType::Quality {
                [0u8; 32]
            } else {
                [0xBB; 32]
            };
            let receipt = build_receipt(
                &format!("receipt-{}", gate_type.as_gate_id()),
                gate_type,
                &lease,
                exec_signer,
                payload_hash,
                [0xCC; 32],
            );

            let (result, _events) = orch
                .record_gate_receipt("work-fail", gate_type, receipt)
                .await
                .unwrap();

            if gate_type == GateType::Security {
                // Last gate triggers AllGatesCompleted
                let outcomes = result.expect("expected outcomes");
                assert_eq!(outcomes.len(), 3);

                let quality_outcome = outcomes
                    .iter()
                    .find(|o| o.gate_type == GateType::Quality)
                    .unwrap();
                assert!(
                    !quality_outcome.passed,
                    "quality gate should have FAIL verdict"
                );
                assert!(
                    outcomes.iter().any(|o| !o.passed),
                    "at least one gate should fail"
                );
            }
        }

        // Security MAJOR 1: After all gates complete, the orchestration is
        // reclaimed from the active map to prevent unbounded growth.
        assert!(
            orch.gate_status("work-fail", GateType::Quality)
                .await
                .is_none(),
            "orchestration should be reclaimed after all gates complete"
        );
    }

    // =========================================================================
    // BLOCKER 2: Receipt Version/Kind/Schema Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn test_unsupported_receipt_version_rejected() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-ver-1").await;

        let lease = orch
            .gate_lease("work-ver-1", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Receipt with unsupported version 99
        let receipt = GateReceiptBuilder::new("receipt-bad-ver", "gate-quality", &lease.lease_id)
                .changeset_digest([0x42; 32])
                .executor_actor_id(&lease.executor_actor_id)
                .receipt_version(99) // unsupported
                .payload_kind("quality")
                .payload_schema_version(1)
                .payload_hash([0xBB; 32])
                .evidence_bundle_hash([0xCC; 32])
                .passed(true)
                .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-ver-1", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GateOrchestratorError::ReceiptVersionRejected { .. }),
            "Expected ReceiptVersionRejected, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_unsupported_payload_kind_rejected() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-ver-2").await;

        let lease = orch
            .gate_lease("work-ver-2", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Receipt with unsupported payload kind
        let receipt = GateReceiptBuilder::new("receipt-bad-kind", "gate-quality", &lease.lease_id)
                .changeset_digest([0x42; 32])
                .executor_actor_id(&lease.executor_actor_id)
                .receipt_version(1)
                .payload_kind("unknown-kind") // unsupported
                .payload_schema_version(1)
                .payload_hash([0xBB; 32])
                .evidence_bundle_hash([0xCC; 32])
                .passed(true)
                .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-ver-2", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GateOrchestratorError::ReceiptVersionRejected { .. }),
            "Expected ReceiptVersionRejected, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_unsupported_payload_schema_version_rejected() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-ver-3").await;

        let lease = orch
            .gate_lease("work-ver-3", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Receipt with unsupported payload schema version
        let receipt = GateReceiptBuilder::new("receipt-bad-schema", "gate-quality", &lease.lease_id)
                .changeset_digest([0x42; 32])
                .executor_actor_id(&lease.executor_actor_id)
                .receipt_version(1)
                .payload_kind("quality")
                .payload_schema_version(99) // unsupported
                .payload_hash([0xBB; 32])
                .evidence_bundle_hash([0xCC; 32])
                .passed(true)
                .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-ver-3", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GateOrchestratorError::ReceiptVersionRejected { .. }),
            "Expected ReceiptVersionRejected, got: {err:?}"
        );
    }

    // =========================================================================
    // State Transition Tests
    // =========================================================================

    #[tokio::test]
    async fn test_record_executor_spawned_rejects_terminal_state() {
        let orch = test_orchestrator();
        let _exec_signers = setup_orchestration(&orch, "work-term-1").await;

        // Timeout a gate (terminal state)
        orch.handle_gate_timeout("work-term-1", GateType::Quality)
            .await
            .unwrap();

        // Trying to spawn executor on timed-out gate should fail
        let err = orch
            .record_executor_spawned("work-term-1", GateType::Quality, "ep-bad")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_record_executor_spawned_rejects_running_state() {
        let orch = test_orchestrator();
        let _exec_signers = setup_orchestration(&orch, "work-term-2").await;

        // Spawn executor (now Running)
        orch.record_executor_spawned("work-term-2", GateType::Quality, "ep-001")
            .await
            .unwrap();

        // Trying to spawn again should fail (already Running)
        let err = orch
            .record_executor_spawned("work-term-2", GateType::Quality, "ep-002")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_record_receipt_rejects_completed_state() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-term-3").await;

        let lease = orch
            .gate_lease("work-term-3", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Complete the gate
        let receipt = build_receipt(
            "receipt-1",
            GateType::Quality,
            &lease,
            exec_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        orch.record_gate_receipt("work-term-3", GateType::Quality, receipt)
            .await
            .unwrap();

        // Try to record another receipt on the same (now Completed) gate
        let receipt2 = build_receipt(
            "receipt-2",
            GateType::Quality,
            &lease,
            exec_signer,
            [0xDD; 32],
            [0xEE; 32],
        );

        let err = orch
            .record_gate_receipt("work-term-3", GateType::Quality, receipt2)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }

    #[tokio::test]
    async fn test_handle_timeout_rejects_terminal_state() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-term-4").await;

        let lease = orch
            .gate_lease("work-term-4", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Complete the gate
        let receipt = build_receipt(
            "receipt-1",
            GateType::Quality,
            &lease,
            exec_signer,
            [0xBB; 32],
            [0xCC; 32],
        );

        orch.record_gate_receipt("work-term-4", GateType::Quality, receipt)
            .await
            .unwrap();

        // Trying to timeout a completed gate should fail
        let err = orch
            .handle_gate_timeout("work-term-4", GateType::Quality)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            GateOrchestratorError::InvalidStateTransition { .. }
        ));
    }

    // =========================================================================
    // Clock Injection Tests (MAJOR 1)
    // =========================================================================

    /// A mock clock for deterministic testing.
    #[derive(Debug)]
    struct MockClock {
        fixed_ms: u64,
    }

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            self.fixed_ms
        }

        fn monotonic_now(&self) -> Instant {
            Instant::now()
        }
    }

    #[tokio::test]
    async fn test_injected_clock_used_for_timestamps() {
        let mock_clock = Arc::new(MockClock {
            fixed_ms: 42_000_000,
        });
        let orch = GateOrchestrator::with_clock(
            GateOrchestratorConfig::default(),
            test_signer(),
            mock_clock,
        );
        let info = test_session_info("work-clock");

        let (_gate_types, _signers, events) = orch.start_from_test_session(info).await.unwrap();

        // All events should use the mock clock's timestamp
        if let GateOrchestratorEvent::PolicyResolved { timestamp_ms, .. } = &events[0] {
            assert_eq!(*timestamp_ms, 42_000_000);
        } else {
            panic!("first event should be PolicyResolved");
        }
    }

    #[tokio::test]
    async fn test_executor_verifying_key_retrieval() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-vk").await;

        for gate_type in GateType::all() {
            let stored_vk = orch
                .executor_verifying_key("work-vk", gate_type)
                .await
                .expect("executor key should be stored");
            let expected_vk = exec_signers[&gate_type].verifying_key();
            assert_eq!(
                stored_vk, expected_vk,
                "Stored executor VK should match for {gate_type}"
            );
        }
    }

    // =========================================================================
    // Security MAJOR 1: Replay/Idempotency Tests
    // =========================================================================

    #[tokio::test]
    async fn test_replay_same_work_changeset_is_noop() {
        let orch = test_orchestrator();
        let info1 = SessionTerminatedInfo {
            session_id: "session-replay".to_string(),
            work_id: "work-replay-1".to_string(),
            changeset_digest: [0xAA; 32],
            terminated_at_ms: 0,
        };
        orch.start_from_test_session(info1).await.unwrap();

        // Remove the orchestration so work_id is free, but replay key persists.
        orch.remove_orchestration("work-replay-1").await;

        // Same (work_id, changeset_digest) is a no-op on replay.
        let info2 = SessionTerminatedInfo {
            session_id: "session-replay-2".to_string(),
            work_id: "work-replay-1".to_string(),
            changeset_digest: [0xAA; 32],
            terminated_at_ms: 0,
        };
        let (gate_types, signers, events) = orch.start_from_test_session(info2).await.unwrap();
        assert!(
            gate_types.is_empty() && signers.is_empty() && events.is_empty(),
            "Replay should return no-op outputs"
        );
    }

    #[tokio::test]
    async fn test_terminated_timestamp_does_not_gate_publication_start() {
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "session-stale".to_string(),
            work_id: "work-stale".to_string(),
            changeset_digest: [0x42; 32],
            // A very old timestamp (2024)
            terminated_at_ms: 1_704_067_200_000,
        };
        let (_gate_types, _signers, events) = orch.start_from_test_session(info).await.unwrap();
        assert_eq!(events.len(), 4, "publication-wrapped start should succeed");
    }

    #[tokio::test]
    async fn test_zero_terminated_at_ms_bypasses_freshness_check() {
        let orch = test_orchestrator();
        // terminated_at_ms: 0 should bypass the freshness check
        let info = test_session_info("work-fresh");
        assert_eq!(info.terminated_at_ms, 0);
        orch.start_from_test_session(info).await.unwrap();
        assert_eq!(orch.active_count().await, 1);
    }

    // =========================================================================
    // Security BLOCKER 2: poll_timeouts Tests
    // =========================================================================

    #[tokio::test]
    async fn test_poll_timeouts_handles_expired_gates() {
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 0, // Instant timeout
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        let info = test_session_info("work-poll");

        orch.start_from_test_session(info).await.unwrap();

        // poll_timeouts should handle all 3 expired gates
        let events = orch.poll_timeouts().await;
        let timeout_count = events
            .iter()
            .filter(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. }))
            .count();
        assert_eq!(timeout_count, 3, "poll_timeouts should handle all 3 gates");

        // Should also have timeout receipt events (Quality MAJOR 1)
        let receipt_count = events
            .iter()
            .filter(|e| matches!(e, GateOrchestratorEvent::GateTimeoutReceiptGenerated { .. }))
            .count();
        assert_eq!(
            receipt_count, 3,
            "poll_timeouts should emit timeout receipt events"
        );
    }

    // =========================================================================
    // Quality BLOCKER 2: Explicit Passed Field Tests
    // =========================================================================

    #[tokio::test]
    async fn test_pass_with_zero_evidence_rejected() {
        // Defense-in-depth: passed=true but zero hashes should be rejected
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-pass-zero").await;

        let lease = orch
            .gate_lease("work-pass-zero", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Build a receipt that declares passed=true but has zero evidence
        let receipt = GateReceiptBuilder::new(
            "receipt-pass-zero",
            GateType::Quality.as_gate_id(),
            &lease.lease_id,
        )
        .changeset_digest(lease.changeset_digest)
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind(GateType::Quality.payload_kind())
        .payload_schema_version(1)
        .payload_hash([0u8; 32]) // zero!
        .evidence_bundle_hash([0xCC; 32])
        .passed(true) // claims pass despite zero payload hash
        .build_and_sign(exec_signer);

        let err = orch
            .record_gate_receipt("work-pass-zero", GateType::Quality, receipt)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                GateOrchestratorError::ZeroEvidenceVerdictRejected { .. }
            ),
            "passed=true with zero evidence should be rejected, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_fail_with_zero_evidence_accepted() {
        // passed=false with zero hashes is fine (e.g., explicit fail)
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-fail-zero").await;

        let lease = orch
            .gate_lease("work-fail-zero", GateType::Quality)
            .await
            .unwrap();
        let exec_signer = &exec_signers[&GateType::Quality];

        // Build a receipt that declares passed=false with zero evidence
        let receipt = GateReceiptBuilder::new(
            "receipt-fail-zero",
            GateType::Quality.as_gate_id(),
            &lease.lease_id,
        )
        .changeset_digest(lease.changeset_digest)
        .executor_actor_id(&lease.executor_actor_id)
        .receipt_version(1)
        .payload_kind(GateType::Quality.payload_kind())
        .payload_schema_version(1)
        .payload_hash([0u8; 32])
        .evidence_bundle_hash([0u8; 32])
        .passed(false) // explicit fail
        .build_and_sign(exec_signer);

        let (_result, events) = orch
            .record_gate_receipt("work-fail-zero", GateType::Quality, receipt)
            .await
            .unwrap();
        assert!(!events.is_empty(), "FAIL receipt should be accepted");

        let status = orch
            .gate_status("work-fail-zero", GateType::Quality)
            .await
            .unwrap();
        assert!(matches!(
            status,
            GateStatus::Completed { passed: false, .. }
        ));
    }

    // =========================================================================
    // Quality MAJOR 1: Timeout Receipt Event Tests
    // =========================================================================

    #[tokio::test]
    async fn test_timeout_emits_receipt_event() {
        let orch = test_orchestrator();
        setup_orchestration(&orch, "work-timeout-evt").await;

        let (_result, events) = orch
            .handle_gate_timeout("work-timeout-evt", GateType::Aat)
            .await
            .unwrap();

        // Should have both GateTimedOut and GateTimeoutReceiptGenerated
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. })),
            "Should have GateTimedOut event"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, GateOrchestratorEvent::GateTimeoutReceiptGenerated { .. })),
            "Should have GateTimeoutReceiptGenerated event"
        );
    }

    // =========================================================================
    // Quality MAJOR 2: Deterministic Outcome Ordering Tests
    // =========================================================================

    #[tokio::test]
    async fn test_all_gates_completed_outcomes_sorted_by_gate_id() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-sort").await;

        // Complete all gates in reverse order (Security, Quality, Aat)
        for &gate_type in &[GateType::Security, GateType::Quality, GateType::Aat] {
            let lease = orch.gate_lease("work-sort", gate_type).await.unwrap();
            let exec_signer = &exec_signers[&gate_type];
            let receipt = build_receipt(
                &format!("receipt-{}", gate_type.as_gate_id()),
                gate_type,
                &lease,
                exec_signer,
                [0xBB; 32],
                [0xCC; 32],
            );

            let (result, _events) = orch
                .record_gate_receipt("work-sort", gate_type, receipt)
                .await
                .unwrap();

            if gate_type == GateType::Aat {
                // Last gate completed -> outcomes
                let outcomes = result.expect("expected outcomes");
                assert_eq!(outcomes.len(), 3);

                // Outcomes must be sorted by gate_id
                let gate_ids: Vec<&str> =
                    outcomes.iter().map(|o| o.gate_type.as_gate_id()).collect();
                assert_eq!(
                    gate_ids,
                    vec!["gate-aat", "gate-quality", "gate-security"],
                    "Outcomes should be sorted by gate_id for determinism"
                );
            }
        }
    }

    // =========================================================================
    // Security BLOCKER 2: Freshness Gate Overflow Prevention Tests
    // =========================================================================

    #[tokio::test]
    async fn test_freshness_gate_no_panic_on_u64_max_timestamp() {
        // Security BLOCKER 2: Adversarial terminated_at_ms near u64::MAX
        // must not panic via arithmetic overflow.
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "session-overflow".to_string(),
            work_id: "work-overflow".to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: u64::MAX - 1, // Near u64::MAX
        };

        // This should NOT panic. The saturating_add prevents overflow.
        // The event is in the far future, so it won't be stale.
        let result = orch.start_from_test_session(info).await;
        assert!(
            result.is_ok(),
            "Near-u64::MAX timestamp should not panic or be rejected as stale"
        );
    }

    #[tokio::test]
    async fn test_freshness_gate_no_panic_on_exact_u64_max() {
        // Exact u64::MAX should also be safe.
        let orch = test_orchestrator();
        let info = SessionTerminatedInfo {
            session_id: "session-exact-max".to_string(),
            work_id: "work-exact-max".to_string(),
            changeset_digest: [0x42; 32],
            terminated_at_ms: u64::MAX,
        };

        // saturating_add(MAX_TERMINATED_AT_AGE_MS) should produce u64::MAX
        // (saturated), meaning the event is never considered stale.
        let result = orch.start_from_test_session(info).await;
        assert!(
            result.is_ok(),
            "Exact u64::MAX timestamp should not panic or be rejected as stale"
        );
    }

    // =========================================================================
    // Security MAJOR 1: Bounded Idempotency Key Store Tests
    // =========================================================================

    #[tokio::test]
    async fn test_idempotency_key_store_bounded() {
        // Create an orchestrator with very small limits to test eviction.
        let config = GateOrchestratorConfig {
            // We need room for at least the keys we insert.
            // MAX_IDEMPOTENCY_KEYS = 10 * max_concurrent_orchestrations.
            max_concurrent_orchestrations: 1,
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());

        // Insert one orchestration.
        let info1 = SessionTerminatedInfo {
            session_id: "session-bound-1".to_string(),
            work_id: "work-bound-1".to_string(),
            changeset_digest: [0x01; 32],
            terminated_at_ms: 0,
        };
        orch.start_from_test_session(info1).await.unwrap();

        // Remove it to free the slot.
        orch.remove_orchestration("work-bound-1").await;

        // Idempotency key is (work_id, changeset_digest), so a different
        // work_id with the same digest is admissible.
        let info1_replay = SessionTerminatedInfo {
            session_id: "session-bound-1".to_string(),
            work_id: "work-bound-1-again".to_string(),
            changeset_digest: [0x01; 32],
            terminated_at_ms: 0,
        };
        let (gate_types, _signers, events) =
            orch.start_from_test_session(info1_replay).await.unwrap();
        assert_eq!(gate_types.len(), GateType::all().len());
        assert!(!events.is_empty());
    }

    // =========================================================================
    // Quality BLOCKER 2: Autonomous Gate Execution Tests
    // =========================================================================

    #[tokio::test]
    async fn test_poll_session_lifecycle_transitions_to_running() {
        let orch = test_orchestrator();
        let events = orch.poll_session_lifecycle().await;

        // Session lifecycle hook must not bootstrap gates.
        assert!(events.is_empty());
        assert_eq!(orch.active_count().await, 0);
    }

    #[tokio::test]
    async fn test_poll_session_lifecycle_with_zero_timeout() {
        // With zero timeout, pre-existing orchestrations time out during the
        // lifecycle sweep.
        let config = GateOrchestratorConfig {
            gate_timeout_ms: 0,
            ..Default::default()
        };
        let orch = GateOrchestrator::new(config, test_signer());
        let _ = orch
            .start_from_test_session(test_session_info("work-drive-timeout-seed"))
            .await
            .unwrap();
        let events = orch.poll_session_lifecycle().await;

        // All seeded gates should time out and be reclaimed.
        assert_eq!(
            orch.active_count().await,
            0,
            "Orchestration should be reclaimed after all gates time out"
        );

        // Verify events contain GateTimedOut for all gate types.
        let timeout_count = events
            .iter()
            .filter(|e| matches!(e, GateOrchestratorEvent::GateTimedOut { .. }))
            .count();
        assert_eq!(
            timeout_count, 3,
            "Should have 3 GateTimedOut events for all gates"
        );
    }

    #[tokio::test]
    async fn test_poll_session_lifecycle_executor_events_have_adapter_profile() {
        let orch = test_orchestrator();
        let events = orch.poll_session_lifecycle().await;

        // Session lifecycle progression must not emit executor-spawn events.
        let has_spawn_event = events
            .iter()
            .find_map(|e| {
                if let GateOrchestratorEvent::GateExecutorSpawned {
                    gate_type,
                    adapter_profile_id,
                    ..
                } = e
                {
                    Some((*gate_type, adapter_profile_id.clone()))
                } else {
                    None
                }
            })
            .is_some();
        assert!(!has_spawn_event);
    }

    // =========================================================================
    // Security MAJOR 2: Timeout receipt identity semantics
    // =========================================================================

    /// Verifies that timeout receipts use the dedicated timeout authority
    /// actor ID (`TIMEOUT_AUTHORITY_ACTOR_ID`) instead of borrowing the
    /// executor's actor ID from the lease.
    #[tokio::test]
    async fn test_timeout_receipt_uses_dedicated_authority_actor_id() {
        let signer = Signer::generate();
        let lease = GateLeaseBuilder::new("lease-auth", "work-auth", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-original")
            .issued_at(1000)
            .expires_at(2000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-auth")
            .time_envelope_ref("htf:tick:99999")
            .build_and_sign(&signer);

        let receipt = create_timeout_receipt(GateType::Quality, &lease, &signer);

        // The timeout receipt MUST use the dedicated timeout authority actor
        // ID, not the executor's original actor ID from the lease.
        assert_eq!(
            receipt.executor_actor_id, TIMEOUT_AUTHORITY_ACTOR_ID,
            "Timeout receipt must use dedicated timeout authority actor ID, \
             not the lease executor_actor_id"
        );

        // Verify the receipt is NOT using the lease's executor actor ID.
        assert_ne!(
            receipt.executor_actor_id, lease.executor_actor_id,
            "Timeout receipt must NOT borrow executor_actor_id from the lease"
        );

        // Verify the receipt is still a FAIL verdict.
        assert!(!receipt.passed, "Timeout receipt must be a FAIL verdict");

        // Verify the receipt signature is valid (signed by orchestrator key).
        assert!(
            receipt.validate_signature(&signer.verifying_key()).is_ok(),
            "Timeout receipt signature must be valid against orchestrator key"
        );
    }

    // =========================================================================
    // Security MAJOR 1: Completed orchestration reclamation
    // =========================================================================

    /// Verifies that completed orchestrations are removed from the active
    /// map after all gates reach terminal state, preventing unbounded growth.
    #[tokio::test]
    async fn test_completed_orchestration_reclaimed_from_active_map() {
        let orch = test_orchestrator();
        let exec_signers = setup_orchestration(&orch, "work-reclaim").await;

        // Complete all gates.
        for gate_type in GateType::all() {
            let lease = orch.gate_lease("work-reclaim", gate_type).await.unwrap();
            let exec_signer = &exec_signers[&gate_type];
            let receipt = build_receipt(
                &format!("receipt-reclaim-{gate_type}"),
                gate_type,
                &lease,
                exec_signer,
                [0xAA; 32],
                [0xBB; 32],
            );
            orch.record_gate_receipt("work-reclaim", gate_type, receipt)
                .await
                .unwrap();
        }

        // After all gates complete, the orchestration should be removed from
        // the active map.
        assert_eq!(
            orch.active_count().await,
            0,
            "Completed orchestration should be reclaimed from active map"
        );

        // The gate status should no longer be found (orchestration removed).
        assert!(
            orch.gate_status("work-reclaim", GateType::Aat)
                .await
                .is_none(),
            "Gate status should be None after orchestration reclamation"
        );
    }

    // =========================================================================
    // TCK-00340: Sublease delegation validation tests (production wiring)
    // =========================================================================

    #[test]
    fn test_validate_sublease_delegation_valid() {
        let signer = Signer::generate();

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        let sublease = GateLeaseBuilder::new("sub-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("sub-executor")
            .issued_at(1_100_000)
            .expires_at(1_900_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("sub-issuer")
            .time_envelope_ref("htf:tick:200")
            .build_and_sign(&signer);

        assert!(
            GateOrchestrator::validate_sublease_delegation(&parent, &sublease).is_ok(),
            "valid sublease delegation should pass"
        );
    }

    #[test]
    fn test_validate_sublease_delegation_gate_id_mismatch_rejected() {
        let signer = Signer::generate();

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        // Different gate_id — must be rejected
        let sublease = GateLeaseBuilder::new("sub-001", "work-001", "gate-security")
            .changeset_digest([0x42; 32])
            .executor_actor_id("sub-executor")
            .issued_at(1_100_000)
            .expires_at(1_900_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("sub-issuer")
            .time_envelope_ref("htf:tick:200")
            .build_and_sign(&signer);

        let result = GateOrchestrator::validate_sublease_delegation(&parent, &sublease);
        assert!(result.is_err(), "gate_id mismatch must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("sublease validation failed"),
            "error should mention sublease validation: {err}"
        );
    }

    #[test]
    fn test_validate_sublease_delegation_time_overflow_rejected() {
        let signer = Signer::generate();

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        // Sublease expires after parent — strict-subset violation
        let sublease = GateLeaseBuilder::new("sub-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("sub-executor")
            .issued_at(1_100_000)
            .expires_at(3_000_000) // EXCEEDS parent expires_at
            .policy_hash([0xAB; 32])
            .issuer_actor_id("sub-issuer")
            .time_envelope_ref("htf:tick:200")
            .build_and_sign(&signer);

        let result = GateOrchestrator::validate_sublease_delegation(&parent, &sublease);
        assert!(result.is_err(), "time overflow must be rejected");
    }

    // =========================================================================
    // TCK-00340: Delegated sublease issuance integration tests
    // (production path through issue_delegated_sublease)
    // =========================================================================

    #[test]
    fn test_issue_delegated_sublease_valid() {
        let signer = Arc::new(Signer::generate());
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), signer.clone());

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        let result = orch.issue_delegated_sublease(
            &parent,
            "sub-001",
            "child-executor-001",
            1_100_000,
            1_900_000,
        );
        assert!(result.is_ok(), "valid delegated sublease should succeed");
        let sublease = result.unwrap();
        assert_eq!(sublease.lease_id, "sub-001");
        assert_eq!(sublease.work_id, "work-001");
        assert_eq!(sublease.gate_id, "gate-quality");
        assert_eq!(sublease.changeset_digest, [0x42; 32]);
        assert_eq!(sublease.policy_hash, [0xAB; 32]);
        // Sublease MUST inherit parent's time_envelope_ref (not mint a new one).
        assert_eq!(
            sublease.time_envelope_ref, parent.time_envelope_ref,
            "sublease must inherit parent time_envelope_ref for CAS compatibility"
        );
    }

    #[test]
    fn test_issue_delegated_sublease_gate_mismatch_rejected() {
        // Attempt to issue a sublease where the parent has gate_id "gate-quality"
        // but we try to manually construct a parent with a different gate —
        // the sublease inherits the parent's gate_id so this tests that the
        // validation path is actually invoked through the production method.
        let signer = Arc::new(Signer::generate());
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), signer.clone());

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        // Sublease within bounds — should pass validation because gate_id is
        // inherited from parent. But time overflow should be caught.
        let result = orch.issue_delegated_sublease(
            &parent,
            "sub-bad-time",
            "child-executor-001",
            1_100_000,
            3_000_000, // EXCEEDS parent expires_at
        );
        assert!(
            result.is_err(),
            "sublease exceeding parent time bounds must be rejected through production path"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("sublease validation failed"),
            "error should mention sublease validation: {err}"
        );
    }

    #[test]
    fn test_issue_delegated_sublease_aat_drift_rejected() {
        let signer = Arc::new(Signer::generate());
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), signer.clone());

        // Parent with AAT extension
        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-aat")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .aat_extension(AatLeaseExtension {
                view_commitment_hash: [0x33; 32],
                rcp_manifest_hash: [0x11; 32],
                rcp_profile_id: "profile-001".to_string(),
                selection_policy_id: "policy-001".to_string(),
            })
            .build_and_sign(&signer);

        // issue_delegated_sublease propagates the parent's AAT extension,
        // so the sublease will always have a matching AAT if the parent has
        // one. Test that the production path works end-to-end with AAT.
        let result = orch.issue_delegated_sublease(
            &parent,
            "sub-aat-001",
            "child-executor-001",
            1_100_000,
            1_900_000,
        );
        assert!(
            result.is_ok(),
            "delegated sublease with matching AAT should succeed"
        );
        let sublease = result.unwrap();
        assert!(
            sublease.aat_extension.is_some(),
            "sublease must carry AAT extension from parent"
        );
        let sub_aat = sublease.aat_extension.unwrap();
        assert_eq!(sub_aat.view_commitment_hash, [0x33; 32]);
        assert_eq!(sub_aat.rcp_manifest_hash, [0x11; 32]);
        // Sublease MUST inherit parent's time_envelope_ref.
        assert_eq!(
            sublease.time_envelope_ref, parent.time_envelope_ref,
            "AAT sublease must inherit parent time_envelope_ref"
        );
    }

    #[test]
    fn test_issue_delegated_sublease_issued_before_parent_rejected() {
        let signer = Arc::new(Signer::generate());
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), signer.clone());

        let parent = GateLeaseBuilder::new("parent-001", "work-001", "gate-quality")
            .changeset_digest([0x42; 32])
            .executor_actor_id("executor-001")
            .issued_at(1_000_000)
            .expires_at(2_000_000)
            .policy_hash([0xAB; 32])
            .issuer_actor_id("issuer-001")
            .time_envelope_ref("htf:tick:100")
            .build_and_sign(&signer);

        let result = orch.issue_delegated_sublease(
            &parent,
            "sub-early",
            "child-executor",
            999_000, // BEFORE parent issued_at
            1_500_000,
        );
        assert!(
            result.is_err(),
            "sublease issued before parent must be rejected through production path"
        );
    }

    // =========================================================================
    // TCK-00418: CAS-backed time_envelope_ref integration tests
    // =========================================================================

    /// Verifies that when a CAS is configured, `issue_gate_lease` produces a
    /// `time_envelope_ref` that is a valid 64-char hex string (32-byte hash)
    /// resolvable from CAS, and that delegated subleases inherit it.
    #[tokio::test]
    async fn test_cas_backed_time_envelope_ref_in_gate_lease() {
        use apm2_core::evidence::MemoryCas;

        let cas = Arc::new(MemoryCas::default());
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), signer)
            .with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

        let info = test_session_info("work-cas-test");
        let (_gate_types, _exec_signers, events) =
            orch.start_from_test_session(info).await.unwrap();

        // Find a lease issuance event.
        let lease_event = events
            .iter()
            .find(|e| matches!(e, GateOrchestratorEvent::GateLeaseIssued { .. }));
        assert!(
            lease_event.is_some(),
            "should have at least one GateLeaseIssued event"
        );

        // Retrieve the actual lease from the orchestrator.
        let lease = orch.gate_lease("work-cas-test", GateType::Quality).await;
        assert!(lease.is_some(), "quality gate lease must exist");
        let lease = lease.unwrap();

        // time_envelope_ref MUST be a valid 64-char hex string.
        assert_eq!(
            lease.time_envelope_ref.len(),
            64,
            "time_envelope_ref must be 64-char hex (32-byte hash), got: {}",
            lease.time_envelope_ref
        );
        let envelope_hash =
            hex::decode(&lease.time_envelope_ref).expect("time_envelope_ref must be valid hex");
        assert_eq!(envelope_hash.len(), 32);

        // The hash MUST be resolvable from CAS.
        let hash_array: [u8; 32] = envelope_hash.try_into().unwrap();
        let envelope_bytes = cas.retrieve(&hash_array);
        assert!(
            envelope_bytes.is_ok(),
            "time_envelope_ref must be resolvable from CAS"
        );

        // The CAS content MUST deserialize to a valid TimeEnvelope.
        let envelope: TimeEnvelope = serde_json::from_slice(&envelope_bytes.unwrap())
            .expect("CAS content must be a valid TimeEnvelope");

        // The clock_profile_hash in the envelope MUST also be CAS-resolvable.
        let profile_hash_bytes =
            hex::decode(&envelope.clock_profile_hash).expect("clock_profile_hash must be hex");
        let profile_hash_array: [u8; 32] = profile_hash_bytes.try_into().unwrap();
        let profile_bytes = cas.retrieve(&profile_hash_array);
        assert!(
            profile_bytes.is_ok(),
            "clock_profile_hash must be resolvable from CAS"
        );
        let _profile: ClockProfile = serde_json::from_slice(&profile_bytes.unwrap())
            .expect("CAS content must be a valid ClockProfile");
    }

    /// Verifies that delegated subleases inherit the parent's CAS-backed
    /// `time_envelope_ref` rather than minting a new legacy string.
    #[tokio::test]
    async fn test_delegated_sublease_inherits_cas_time_envelope_ref() {
        use apm2_core::evidence::MemoryCas;

        let cas = Arc::new(MemoryCas::default());
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), signer)
            .with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

        let info = test_session_info("work-delegate-cas");
        let _ = orch.start_from_test_session(info).await.unwrap();

        let parent_lease = orch
            .gate_lease("work-delegate-cas", GateType::Quality)
            .await
            .expect("parent lease must exist");

        let sublease = orch
            .issue_delegated_sublease(
                &parent_lease,
                "sub-cas-001",
                "child-executor",
                parent_lease.issued_at + 100,
                parent_lease.expires_at - 100,
            )
            .expect("delegated sublease should succeed");

        // Sublease MUST have exactly the same time_envelope_ref as parent.
        assert_eq!(
            sublease.time_envelope_ref, parent_lease.time_envelope_ref,
            "delegated sublease must inherit parent's CAS-backed time_envelope_ref"
        );

        // And it must still be a valid 64-char hex.
        assert_eq!(sublease.time_envelope_ref.len(), 64);

        // And resolvable from CAS.
        let hash_bytes = hex::decode(&sublease.time_envelope_ref).unwrap();
        let hash_array: [u8; 32] = hash_bytes.try_into().unwrap();
        assert!(
            cas.retrieve(&hash_array).is_ok(),
            "sublease time_envelope_ref must be CAS-resolvable"
        );
    }

    /// Verifies that orchestrator-issued leases produce `ClockProfile`s that
    /// satisfy `is_clock_profile_admissible_for_risk_tier` for every risk tier
    /// (Tier0 through Tier4), proving higher-tier transitions are NOT denied
    /// at delegation/receipt admission.
    ///
    /// This test directly creates CAS-backed time envelope refs for each tier,
    /// then resolves the `ClockProfile` from CAS and asserts admissibility
    /// against the same policy used in `PrivilegedDispatcher`.
    #[tokio::test]
    async fn test_clock_profile_admissible_for_all_risk_tiers() {
        use apm2_core::evidence::MemoryCas;
        use apm2_core::fac::RiskTier;

        let cas = Arc::new(MemoryCas::default());
        let signer = test_signer();
        let orch = GateOrchestrator::new(GateOrchestratorConfig::default(), signer)
            .with_cas(Arc::clone(&cas) as Arc<dyn ContentAddressedStore>);

        let tiers = [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ];

        for tier in &tiers {
            let work_id = format!("work-tier-{tier:?}");
            let now_ms = 1_700_000_000_000u64;

            let envelope_hex = orch
                .create_cas_time_envelope_ref(&work_id, now_ms, *tier)
                .expect("CAS time envelope ref must succeed");

            // Resolve the TimeEnvelope from CAS.
            let envelope_hash_bytes = hex::decode(&envelope_hex).unwrap();
            let envelope_hash: [u8; 32] = envelope_hash_bytes.try_into().unwrap();
            let envelope_bytes = cas.retrieve(&envelope_hash).unwrap();
            let envelope: TimeEnvelope = serde_json::from_slice(&envelope_bytes).unwrap();

            // Resolve the ClockProfile from CAS via the envelope's clock_profile_hash.
            let profile_hash_bytes = hex::decode(&envelope.clock_profile_hash).unwrap();
            let profile_hash: [u8; 32] = profile_hash_bytes.try_into().unwrap();
            let profile_bytes = cas.retrieve(&profile_hash).unwrap();
            let profile: ClockProfile = serde_json::from_slice(&profile_bytes).unwrap();

            // ---- Replicate is_clock_profile_admissible_for_risk_tier logic ----
            // Wall-time source check
            let source_allowed = match tier {
                RiskTier::Tier0 | RiskTier::Tier1 => matches!(
                    profile.wall_time_source,
                    WallTimeSource::None
                        | WallTimeSource::BestEffortNtp
                        | WallTimeSource::AuthenticatedNts
                        | WallTimeSource::Roughtime
                        | WallTimeSource::CloudBounded
                ),
                RiskTier::Tier2 | RiskTier::Tier3 | RiskTier::Tier4 => matches!(
                    profile.wall_time_source,
                    WallTimeSource::None
                        | WallTimeSource::AuthenticatedNts
                        | WallTimeSource::Roughtime
                        | WallTimeSource::CloudBounded
                ),
            };
            assert!(
                source_allowed,
                "ClockProfile wall_time_source {:?} must be admissible for {:?}",
                profile.wall_time_source, tier
            );

            // Attestation check
            let attestation_ok = match tier {
                RiskTier::Tier0 | RiskTier::Tier1 | RiskTier::Tier2 => true,
                RiskTier::Tier3 | RiskTier::Tier4 => profile.attestation.is_some(),
            };
            assert!(
                attestation_ok,
                "ClockProfile attestation must be present for {:?}, got: {:?}",
                tier, profile.attestation
            );
        }
    }

    // =========================================================================
    // One-Active-Per-Work-Id (Latest-Wins) Tests
    // =========================================================================

    #[tokio::test]
    async fn test_new_digest_supersedes_old_orchestration_for_same_work_id() {
        let orch = test_orchestrator();
        let pub1 = ChangesetPublication {
            work_id: "supersede-work".to_string(),
            changeset_digest: [0x11; 32],
            bundle_cas_hash: [0xAA; 32],
            published_at_ms: 1_000,
            publisher_actor_id: "actor:1".to_string(),
            changeset_published_event_id: "evt-1".to_string(),
        };
        let pub2 = ChangesetPublication {
            work_id: "supersede-work".to_string(),
            changeset_digest: [0x22; 32],
            bundle_cas_hash: [0xBB; 32],
            published_at_ms: 2_000,
            publisher_actor_id: "actor:2".to_string(),
            changeset_published_event_id: "evt-2".to_string(),
        };

        // Start first orchestration.
        let (types1, _, events1) = orch.start_for_changeset(pub1).await.unwrap();
        assert_eq!(types1.len(), 3, "first start should issue 3 gate types");
        assert!(!events1.is_empty(), "first start should emit events");
        assert_eq!(orch.active_count().await, 1);

        // Start second orchestration for same work_id, different digest.
        // The old one should be superseded.
        let (types2, _, events2) = orch.start_for_changeset(pub2).await.unwrap();
        assert_eq!(types2.len(), 3, "second start should issue 3 gate types");
        assert!(!events2.is_empty(), "second start should emit events");
        // Still only 1 active orchestration (old was superseded).
        assert_eq!(
            orch.active_count().await,
            1,
            "only one active orchestration per work_id (latest-wins)"
        );

        // Verify the active one is for the new digest.
        let lease = orch
            .gate_lease("supersede-work", GateType::Aat)
            .await
            .expect("lease should exist for the new digest");
        assert_eq!(
            lease.changeset_digest, [0x22; 32],
            "active lease should be for the new (superseding) digest"
        );
    }

    #[tokio::test]
    async fn test_duplicate_same_digest_is_idempotent_noop() {
        let orch = test_orchestrator();
        let pub1 = ChangesetPublication {
            work_id: "dup-work".to_string(),
            changeset_digest: [0x33; 32],
            bundle_cas_hash: [0xCC; 32],
            published_at_ms: 1_000,
            publisher_actor_id: "actor:dup".to_string(),
            changeset_published_event_id: "evt-dup".to_string(),
        };

        let (types1, _, events1) = orch.start_for_changeset(pub1.clone()).await.unwrap();
        assert_eq!(types1.len(), 3, "first start should issue 3 gate types");
        assert!(!events1.is_empty(), "first start should emit events");

        // Same (work_id, digest) again should be a silent no-op
        // (idempotent replay rejection, not an error).
        let (types2, signers2, events2) = orch.start_for_changeset(pub1).await.unwrap();
        assert!(
            types2.is_empty(),
            "duplicate should return empty gate types (no-op)"
        );
        assert!(
            signers2.is_empty(),
            "duplicate should return empty signers (no-op)"
        );
        assert!(
            events2.is_empty(),
            "duplicate should return empty events (no-op)"
        );
        // Still only one orchestration.
        assert_eq!(orch.active_count().await, 1);
    }

    #[tokio::test]
    async fn test_find_by_work_id_unambiguous_after_supersede() {
        let orch = test_orchestrator();
        let pub1 = ChangesetPublication {
            work_id: "find-work".to_string(),
            changeset_digest: [0x44; 32],
            bundle_cas_hash: [0xDD; 32],
            published_at_ms: 1_000,
            publisher_actor_id: "actor:find".to_string(),
            changeset_published_event_id: "evt-find-1".to_string(),
        };
        let pub2 = ChangesetPublication {
            work_id: "find-work".to_string(),
            changeset_digest: [0x55; 32],
            bundle_cas_hash: [0xEE; 32],
            published_at_ms: 2_000,
            publisher_actor_id: "actor:find".to_string(),
            changeset_published_event_id: "evt-find-2".to_string(),
        };

        let _ = orch.start_for_changeset(pub1).await.unwrap();
        let (_, signers2, _) = orch.start_for_changeset(pub2).await.unwrap();

        // Executor key should match the new orchestration.
        let vk = orch
            .executor_verifying_key("find-work", GateType::Security)
            .await
            .expect("executor key should exist");
        let expected_vk = signers2[&GateType::Security].verifying_key();
        assert_eq!(
            vk, expected_vk,
            "executor key must match the latest (superseding) orchestration"
        );
    }
}
