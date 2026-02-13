// AGENT-AUTHORED
//! Effect execution journal for crash-safe effect tracking
//! (RFC-0019 REQ-0029, TCK-00501).
//!
//! # Design
//!
//! The [`EffectJournal`] trait abstracts durable effect execution state
//! tracking keyed by `RequestId`. Each request transitions through:
//!
//! ```text
//! NotStarted -> Started -> Completed
//!                 |
//!                 v (crash / ambiguous)
//!              Unknown
//! ```
//!
//! The primary implementation, [`FileBackedEffectJournal`], uses an
//! append-only file with fsync to guarantee crash-safe state transitions.
//!
//! # Crash Window Classification
//!
//! On restart, the journal classifies each `RequestId` deterministically:
//!
//! - **`NotStarted`**: No `Started` record found. The effect was never
//!   dispatched. Safe to re-execute.
//! - **Completed**: Both `Started` and `Completed` records found. The effect
//!   finished and was acknowledged. No action needed.
//! - **Unknown**: A `Started` record exists without a matching `Completed`
//!   record. The crash occurred during or after effect dispatch but before the
//!   completion record was fsynced. The effect may or may not have executed
//!   externally.
//!
//! # Fail-Closed In-Doubt Handling
//!
//! For fail-closed tiers, `Unknown` state triggers:
//! - No output release (including streaming)
//! - Containment/quarantine per policy
//! - Deny re-execution unless the effect is declared idempotent AND the
//!   boundary confirms not executed
//!
//! # Idempotency Key Propagation
//!
//! The [`IdempotencyKeyV1`] type derives a deterministic idempotency key
//! from the `RequestId` for propagation into tool/broker adapter calls.
//! External systems that support idempotency keys can use this to
//! deduplicate effect execution.
//!
//! # Binding Data
//!
//! Each journal entry persists sufficient binding data to resume
//! deterministically after restart:
//! - Request digest
//! - `as_of` ledger anchor
//! - Policy root digest + epoch
//! - Witness seed hashes (derivation binding)
//! - Boundary profile + enforcement tier
//! - AJC ID + join selectors

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read as _, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use apm2_core::crypto::Hash;
use serde::{Deserialize, Serialize};

use super::prerequisites::LedgerAnchorV1;
use super::types::EnforcementTier;

// =============================================================================
// Resource limits
// =============================================================================

/// Maximum number of active in-flight entries held in the in-memory index.
///
/// Active entries are requests in `Started` or `Unknown` state. Terminal
/// entries (`Completed`/`NotStarted`) are retained for replay/audit but do
/// not consume admission slots.
const MAX_JOURNAL_ENTRIES: usize = 100_000;

/// Maximum number of terminal entries (`Completed`/`NotStarted`) retained
/// in the in-memory index before automatic compaction.
///
/// Terminal entries are not required for crash-window classification — only
/// active entries (`Started`/`Unknown`) matter for correctness. Retaining
/// a bounded set of terminal entries supports audit lookups, but allowing
/// unbounded growth creates a memory exhaustion vector during replay and an
/// O(n) scan cost for any index operations.
///
/// When terminal entries exceed this threshold, `prune_terminal_entries()`
/// removes the oldest terminal entries to bring the count under the limit.
const MAX_TERMINAL_ENTRIES: usize = 100_000;

/// Maximum length for the boundary profile field in journal entries.
const MAX_BOUNDARY_PROFILE_LENGTH: usize = 128;

/// Maximum length for the tool class field in journal entries.
const MAX_TOOL_CLASS_LENGTH: usize = 128;

/// Maximum length for the session ID field in journal entries.
const MAX_SESSION_ID_LENGTH: usize = 256;

/// Maximum length for a single journal line during replay (denial-of-service
/// prevention).
///
/// A well-formed `Started` line is: `S <64-hex> <JSON binding>`. The JSON
/// binding contains bounded fields (`MAX_BOUNDARY_PROFILE_LENGTH`=128,
/// `MAX_SESSION_ID_LENGTH`=256, `MAX_TOOL_CLASS_LENGTH`=128) plus fixed-size
/// hex hashes. 64 KiB is generous for any legitimate entry while still
/// preventing memory exhaustion from a malicious/corrupted journal file
/// containing an extremely long line.
const MAX_JOURNAL_LINE_LEN: usize = 64_000;

// =============================================================================
// EffectExecutionState
// =============================================================================

/// State machine for effect execution tracking (REQ-0029).
///
/// Each `RequestId` progresses through these states:
///
/// ```text
/// NotStarted -> Started -> Completed
///                 |
///                 v (crash)
///              Unknown
/// ```
///
/// `Unknown` is assigned during restart recovery when a `Started` record
/// exists without a matching `Completed` record. It is NEVER assigned
/// during normal operation.
///
/// # Fail-Closed Semantics
///
/// `Unknown` is the most restrictive state. For fail-closed tiers, it
/// triggers containment and denies all output release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectExecutionState {
    /// Effect has not been dispatched. Safe to execute.
    NotStarted,
    /// Effect dispatch has been initiated. The pre-effect record was
    /// fsynced before the external call.
    Started,
    /// Effect completed successfully. Post-effect record was fsynced.
    Completed,
    /// Crash recovery state: `Started` without `Completed`. The effect
    /// may or may not have executed externally.
    Unknown,
}

impl std::fmt::Display for EffectExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted => write!(f, "not_started"),
            Self::Started => write!(f, "started"),
            Self::Completed => write!(f, "completed"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// =============================================================================
// EffectJournalError
// =============================================================================

/// Errors from effect journal operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EffectJournalError {
    /// I/O error during durable write or fsync.
    #[error("effect journal I/O error ({kind:?}): {reason}")]
    IoError {
        /// The I/O error kind for programmatic matching.
        kind: std::io::ErrorKind,
        /// Description of the I/O error.
        reason: String,
    },

    /// Invalid state transition attempted.
    #[error(
        "invalid effect journal transition for {}: {} -> {}",
        hex::encode(.request_id),
        .current,
        .target
    )]
    InvalidTransition {
        /// The `RequestId` involved.
        request_id: Hash,
        /// Current state.
        current: EffectExecutionState,
        /// Attempted target state.
        target: EffectExecutionState,
    },

    /// Journal capacity exhausted (fail-closed).
    #[error("effect journal capacity exhausted ({count}/{max})")]
    CapacityExhausted {
        /// Current number of active entries (`Started`/`Unknown`).
        count: usize,
        /// Maximum allowed active entries.
        max: usize,
    },

    /// Corrupt journal entry detected during replay.
    #[error("corrupt effect journal entry at line {line}: {reason}")]
    CorruptEntry {
        /// Line number where corruption was detected.
        line: usize,
        /// Description of the corruption.
        reason: String,
    },

    /// Re-execution denied for Unknown state (fail-closed).
    #[error(
        "re-execution denied for {} (tier={enforcement_tier}, idempotent={declared_idempotent}): {reason}",
        hex::encode(.request_id)
    )]
    ReExecutionDenied {
        /// The `RequestId` in Unknown state.
        request_id: Hash,
        /// The enforcement tier.
        enforcement_tier: EnforcementTier,
        /// Whether the effect is declared idempotent.
        declared_idempotent: bool,
        /// Reason for denial.
        reason: String,
    },

    /// Output release denied for Unknown state (fail-closed).
    #[error("output release denied for {}: {reason}", hex::encode(.request_id))]
    OutputReleaseDenied {
        /// The `RequestId` in Unknown state.
        request_id: Hash,
        /// Reason for denial.
        reason: String,
    },

    /// Journal entry validation failed.
    #[error("effect journal validation error: {reason}")]
    ValidationError {
        /// Description of the validation failure.
        reason: String,
    },
}

impl From<std::io::Error> for EffectJournalError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError {
            kind: e.kind(),
            reason: e.to_string(),
        }
    }
}

// =============================================================================
// EffectJournalBindingV1
// =============================================================================

/// Pre-effect binding data persisted with the journal entry (REQ-0029).
///
/// Captures sufficient context to resume deterministically after restart:
/// request digest, `as_of` anchor, policy root, witness seed hashes,
/// boundary profile + enforcement tier, and AJC join selectors.
///
/// # Digest Domain Separation
///
/// Content hash: `b"apm2-effect-journal-binding-v1" || request_id ||
/// request_digest || ledger_anchor fields || policy_root_digest ||
/// policy_root_epoch || leakage_witness_seed_hash ||
/// timing_witness_seed_hash || boundary_profile_id_len ||
/// boundary_profile_id || enforcement_tier || ajc_id ||
/// authority_join_hash || session_id_len || session_id ||
/// tool_class_len || tool_class || declared_idempotent`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectJournalBindingV1 {
    /// Stable request identifier (journal key).
    pub request_id: Hash,
    /// Canonical request digest at plan time.
    pub request_digest: Hash,
    /// Ledger anchor at plan/execute time.
    pub as_of_ledger_anchor: LedgerAnchorV1,
    /// Policy root digest at plan/execute time.
    pub policy_root_digest: Hash,
    /// Policy root epoch at plan/execute time.
    pub policy_root_epoch: u64,
    /// Leakage witness seed hash (derivation binding).
    pub leakage_witness_seed_hash: Hash,
    /// Timing witness seed hash (derivation binding).
    pub timing_witness_seed_hash: Hash,
    /// Boundary profile identifier.
    pub boundary_profile_id: String,
    /// Policy-derived enforcement tier.
    pub enforcement_tier: EnforcementTier,
    /// AJC ID from the join phase.
    pub ajc_id: Hash,
    /// Authority join hash (join selector digest).
    pub authority_join_hash: Hash,
    /// Session identifier.
    pub session_id: String,
    /// Tool class identifier.
    pub tool_class: String,
    /// Whether the effect is declared idempotent.
    pub declared_idempotent: bool,
}

impl EffectJournalBindingV1 {
    /// Validate boundary constraints on this binding.
    ///
    /// # Errors
    ///
    /// Returns `EffectJournalError::ValidationError` for the first
    /// violation found (fail-closed).
    pub fn validate(&self) -> Result<(), EffectJournalError> {
        const ZERO: Hash = [0u8; 32];

        if self.request_id == ZERO {
            return Err(EffectJournalError::ValidationError {
                reason: "request_id is zero".into(),
            });
        }
        if self.request_digest == ZERO {
            return Err(EffectJournalError::ValidationError {
                reason: "request_digest is zero".into(),
            });
        }
        if self.policy_root_digest == ZERO {
            return Err(EffectJournalError::ValidationError {
                reason: "policy_root_digest is zero".into(),
            });
        }
        if self.ajc_id == ZERO {
            return Err(EffectJournalError::ValidationError {
                reason: "ajc_id is zero".into(),
            });
        }
        if self.authority_join_hash == ZERO {
            return Err(EffectJournalError::ValidationError {
                reason: "authority_join_hash is zero".into(),
            });
        }
        if self.leakage_witness_seed_hash == ZERO {
            return Err(EffectJournalError::ValidationError {
                reason: "leakage_witness_seed_hash is zero".into(),
            });
        }
        if self.timing_witness_seed_hash == ZERO {
            return Err(EffectJournalError::ValidationError {
                reason: "timing_witness_seed_hash is zero".into(),
            });
        }
        if self.boundary_profile_id.is_empty()
            || self.boundary_profile_id.len() > MAX_BOUNDARY_PROFILE_LENGTH
        {
            return Err(EffectJournalError::ValidationError {
                reason: "boundary_profile_id empty or exceeds maximum length".into(),
            });
        }
        if self.session_id.is_empty() || self.session_id.len() > MAX_SESSION_ID_LENGTH {
            return Err(EffectJournalError::ValidationError {
                reason: "session_id empty or exceeds maximum length".into(),
            });
        }
        if self.tool_class.is_empty() || self.tool_class.len() > MAX_TOOL_CLASS_LENGTH {
            return Err(EffectJournalError::ValidationError {
                reason: "tool_class empty or exceeds maximum length".into(),
            });
        }
        Ok(())
    }

    /// Compute a deterministic content hash for this binding.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String fields bounded by MAX_* (<=256), safe for u32.
    pub fn content_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-effect-journal-binding-v1");
        hasher.update(&self.request_id);
        hasher.update(&self.request_digest);
        // Ledger anchor fields (inline, deterministic)
        hasher.update(&self.as_of_ledger_anchor.ledger_id);
        hasher.update(&self.as_of_ledger_anchor.event_hash);
        hasher.update(&self.as_of_ledger_anchor.height.to_le_bytes());
        hasher.update(&self.as_of_ledger_anchor.he_time.to_le_bytes());
        hasher.update(&self.policy_root_digest);
        hasher.update(&self.policy_root_epoch.to_le_bytes());
        hasher.update(&self.leakage_witness_seed_hash);
        hasher.update(&self.timing_witness_seed_hash);
        hasher.update(self.boundary_profile_id.as_bytes());
        hasher.update(&(self.boundary_profile_id.len() as u32).to_le_bytes());
        hasher.update(match self.enforcement_tier {
            EnforcementTier::FailClosed => &[0x01],
            EnforcementTier::Monitor => &[0x02],
        });
        hasher.update(&self.ajc_id);
        hasher.update(&self.authority_join_hash);
        hasher.update(self.session_id.as_bytes());
        hasher.update(&(self.session_id.len() as u32).to_le_bytes());
        hasher.update(self.tool_class.as_bytes());
        hasher.update(&(self.tool_class.len() as u32).to_le_bytes());
        hasher.update(&[u8::from(self.declared_idempotent)]);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// IdempotencyKeyV1
// =============================================================================

/// Idempotency key derived from stable client-supplied identifiers
/// for propagation into tool/broker adapter calls (REQ-0029, INV-F-06).
///
/// The key MUST be deterministic for the same client intent so that
/// retries produce the same idempotency key, allowing external systems
/// to deduplicate effect execution. Using a random per-request UUID
/// as the sole input would defeat retry safety because a new UUID is
/// generated on each retry attempt.
///
/// # Derivation
///
/// `BLAKE3("apm2-idempotency-key-v1" || dedupe_key || request_id || ajc_id)`
///
/// - `dedupe_key`: Stable client-supplied deduplication key that persists
///   across retries of the same intent.
/// - `request_id`: Per-request identifier (provides uniqueness within a single
///   admission cycle).
/// - `ajc_id`: Admission join cycle ID (prevents cross-admission key reuse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyKeyV1 {
    /// The derived idempotency key hash.
    pub key: Hash,
    /// Source `RequestId` for audit traceability.
    pub request_id: Hash,
    /// Source AJC ID for audit traceability.
    pub ajc_id: Hash,
}

impl IdempotencyKeyV1 {
    /// Derive an idempotency key from a stable `dedupe_key`, the
    /// per-request `request_id`, and the AJC ID.
    ///
    /// The `dedupe_key` is the primary retry-stable identifier
    /// (INV-F-06). When empty, the derivation falls back to
    /// `request_id` + `ajc_id` only, which is retry-safe only if
    /// the caller ensures `request_id` is stable across retries.
    #[must_use]
    pub fn derive(request_id: Hash, ajc_id: Hash) -> Self {
        Self::derive_with_dedupe_key(request_id, ajc_id, &[])
    }

    /// Derive an idempotency key with an explicit stable `dedupe_key`
    /// (INV-F-06: retry-safe deduplication).
    ///
    /// The `dedupe_key` bytes are included in the BLAKE3 derivation
    /// before the `request_id` and `ajc_id`, ensuring that retries
    /// of the same client intent produce the same key regardless of
    /// whether a new `request_id` UUID was generated.
    #[must_use]
    pub fn derive_with_dedupe_key(request_id: Hash, ajc_id: Hash, dedupe_key: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-idempotency-key-v1");
        hasher.update(dedupe_key);
        hasher.update(&request_id);
        hasher.update(&ajc_id);
        Self {
            key: *hasher.finalize().as_bytes(),
            request_id,
            ajc_id,
        }
    }

    /// Returns the idempotency key as a hex string suitable for
    /// propagation into HTTP headers or API parameters.
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex::encode(self.key)
    }
}

// =============================================================================
// InDoubtResolutionV1
// =============================================================================

/// Resolution decision for an in-doubt (Unknown) effect (REQ-0029).
///
/// For fail-closed tiers, the default resolution is `Deny`. A request
/// may be re-executed only if:
/// 1. The effect is declared idempotent (`declared_idempotent = true`)
/// 2. The boundary confirms the effect was not executed
///
/// Both conditions must be satisfied for `AllowReExecution`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InDoubtResolutionV1 {
    /// Deny: no output release, containment/quarantine per policy.
    Deny {
        /// Reason for denial.
        reason: String,
    },
    /// Allow re-execution: the effect is idempotent and boundary
    /// confirms it was not executed.
    AllowReExecution {
        /// The idempotency key for the re-execution.
        idempotency_key: IdempotencyKeyV1,
    },
}

// =============================================================================
// EffectJournal trait
// =============================================================================

/// Abstraction for durable effect execution journal tracking (REQ-0029).
///
/// Implementations must guarantee that state transitions are fsynced
/// to durable storage before returning `Ok(())`.
///
/// # State Machine
///
/// Valid transitions:
/// - `None`/`NotStarted` -> `Started` (via `record_started`)
/// - `Started` -> `Completed` (via `record_completed`)
/// - `Started` -> `Unknown` (via restart recovery only; not a direct API)
///
/// Invalid transitions (return `Err`):
/// - Any state -> `NotStarted` (cannot revert to not-started)
/// - `Completed` -> any (terminal state)
/// - `Unknown` -> any except via `resolve_in_doubt`
///
/// # Synchronization Protocol
///
/// The journal's in-memory `HashMap<Hash, JournalRecord>` is protected
/// by a `Mutex`. The lock ordering is:
/// 1. Acquire `entries` lock
/// 2. Check state machine transition validity
/// 3. Write to file (holding lock to prevent concurrent mutation)
/// 4. Fsync
/// 5. Update in-memory state
/// 6. Release lock
///
/// This ensures that the on-disk state is always equal to or ahead of
/// the in-memory state, and concurrent writers cannot create invalid
/// state machine transitions via TOCTOU.
pub trait EffectJournal: Send + Sync {
    /// Record that effect execution has started for a `RequestId`.
    ///
    /// The binding data is persisted atomically with the state transition.
    /// Returns `Ok(())` only after the record is durably committed (fsync).
    ///
    /// # Errors
    ///
    /// - `InvalidTransition` if the request already has a `Started`,
    ///   `Completed`, or `Unknown` entry (but NOT `NotStarted`, which permits
    ///   re-execution after `resolve_in_doubt`).
    /// - `CapacityExhausted` if active in-flight entries are at capacity.
    /// - `IoError` if the durable write fails.
    fn record_started(&self, binding: &EffectJournalBindingV1) -> Result<(), EffectJournalError>;

    /// Record that effect execution has completed for a `RequestId`.
    ///
    /// Returns `Ok(())` only after the record is durably committed (fsync).
    ///
    /// # Errors
    ///
    /// - `InvalidTransition` if the request is not in `Started` state.
    /// - `IoError` if the durable write fails.
    fn record_completed(&self, request_id: &Hash) -> Result<(), EffectJournalError>;

    /// Query the current execution state for a `RequestId`.
    ///
    /// Returns `NotStarted` if no journal entry exists.
    fn query_state(&self, request_id: &Hash) -> EffectExecutionState;

    /// Query the binding data for a `RequestId`.
    ///
    /// Returns `None` if no journal entry exists.
    fn query_binding(&self, request_id: &Hash) -> Option<EffectJournalBindingV1>;

    /// Resolve an in-doubt (Unknown) effect for fail-closed tiers.
    ///
    /// This is the fail-closed gate for Unknown state. It checks:
    /// 1. The effect must be declared idempotent
    /// 2. The boundary must confirm the effect was not executed (via
    ///    `boundary_confirms_not_executed`)
    ///
    /// If both conditions are met, the entry transitions to `NotStarted`
    /// (allowing re-execution with the same idempotency key).
    ///
    /// If either condition fails, returns `Deny` with containment action.
    ///
    /// # Errors
    ///
    /// - `ReExecutionDenied` if conditions for re-execution are not met.
    fn resolve_in_doubt(
        &self,
        request_id: &Hash,
        boundary_confirms_not_executed: bool,
    ) -> Result<InDoubtResolutionV1, EffectJournalError>;

    /// Returns the number of journal entries.
    fn len(&self) -> usize;

    /// Returns true if the journal has no entries.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// JournalRecord — in-memory state
// =============================================================================

/// In-memory journal record tracking state and binding data.
#[derive(Debug, Clone)]
struct JournalRecord {
    state: EffectExecutionState,
    binding: EffectJournalBindingV1,
}

#[inline]
const fn state_counts_toward_capacity(state: EffectExecutionState) -> bool {
    matches!(
        state,
        EffectExecutionState::Started | EffectExecutionState::Unknown
    )
}

#[inline]
const fn state_is_terminal(state: EffectExecutionState) -> bool {
    matches!(
        state,
        EffectExecutionState::Completed | EffectExecutionState::NotStarted
    )
}

/// Inner state co-located under a single `Mutex` to keep the active count
/// and terminal count in sync with the entry map without additional locks.
///
/// # Synchronization Protocol
///
/// All fields are protected by the outer `Mutex` in
/// `FileBackedEffectJournal::inner`. Writers hold this lock for the full
/// check-mutate-fsync-update cycle. `active_count` and `terminal_count` are
/// maintained as O(1) counters instead of scanning the full map on every
/// operation.
struct JournalInner {
    entries: HashMap<Hash, JournalRecord>,
    /// O(1) count of active entries (`Started`/`Unknown`).
    /// Updated on every state transition.
    active_count: usize,
    /// O(1) count of terminal entries (`Completed`/`NotStarted`).
    /// Updated on every state transition.
    terminal_count: usize,
    /// FIFO eviction order for terminal entries. When entries transition
    /// to a terminal state (`Completed`/`NotStarted`), the key is pushed
    /// to the back. `prune_terminal_entries_if_needed` pops from the
    /// front for O(1) eviction instead of O(N) `HashMap` scanning.
    terminal_order: VecDeque<Hash>,
}

impl JournalInner {
    /// Prune terminal entries from the in-memory index if `terminal_count`
    /// exceeds `MAX_TERMINAL_ENTRIES`.
    ///
    /// This is called after any operation that increments `terminal_count`
    /// (`record_completed`, `resolve_in_doubt`, and during replay) to prevent
    /// unbounded memory growth from accumulated terminal entries.
    ///
    /// Returns the number of entries pruned.
    fn prune_terminal_entries_if_needed(&mut self) -> usize {
        if self.terminal_count <= MAX_TERMINAL_ENTRIES {
            return 0;
        }
        let excess = self.terminal_count - MAX_TERMINAL_ENTRIES;
        let mut pruned = 0usize;
        // O(1) per eviction: pop oldest terminal keys from the front of
        // the VecDeque. Keys may reference entries that have since been
        // overwritten (e.g., re-executed after resolve_in_doubt), so we
        // skip stale/missing keys.
        while pruned < excess {
            let Some(key) = self.terminal_order.pop_front() else {
                break;
            };
            // Only remove if the entry still exists AND is still terminal.
            // A key may have been re-inserted as active (Started) after
            // resolve_in_doubt + record_started, in which case we must
            // not evict it.
            if self
                .entries
                .get(&key)
                .is_some_and(|r| state_is_terminal(r.state))
            {
                self.entries.remove(&key);
                pruned += 1;
            }
        }
        self.terminal_count = self.terminal_count.saturating_sub(pruned);
        if pruned > 0 {
            tracing::debug!(
                pruned_count = pruned,
                remaining_terminal = self.terminal_count,
                active_count = self.active_count,
                "effect journal: pruned terminal entries"
            );
        }
        pruned
    }
}

// =============================================================================
// Journal line format
// =============================================================================

/// Journal line: `<state_tag> <request_id_hex> [<binding_json>]`
///
/// State tags: S = Started, C = Completed, R = Resolved (Unknown ->
/// `NotStarted`)
///
/// Binding JSON is only present for `Started` entries.
const TAG_STARTED: char = 'S';
const TAG_COMPLETED: char = 'C';
/// Tag for resolved in-doubt entries. Written by `resolve_in_doubt` when
/// both conditions (idempotent + boundary confirms not executed) are met.
/// On replay, an 'R' record transitions the entry from `Unknown` back to
/// `NotStarted`, allowing re-execution.
const TAG_RESOLVED: char = 'R';

// =============================================================================
// FileBackedEffectJournal
// =============================================================================

/// Append-only file-backed effect execution journal (REQ-0029).
///
/// Each state transition is written as a tagged line:
/// - `S <request_id_hex> <binding_json>` for Started
/// - `C <request_id_hex>` for Completed
///
/// On open, the file is replayed to rebuild the in-memory index and
/// classify crash windows:
/// - `S` without matching `C` -> `Unknown` (in-doubt)
/// - `S` with matching `C` -> `Completed`
/// - Only `C` without `S` -> ignored (corrupt, treated as torn tail)
///
/// # Single-Writer Exclusivity
///
/// An exclusive file lock (`flock(LOCK_EX)`) is held for the lifetime
/// of this struct. This prevents concurrent daemon instances from
/// corrupting the journal.
///
/// # Synchronization Protocol
///
/// The `entries` Mutex protects the in-memory `HashMap<Hash, JournalRecord>`.
/// The `file` Mutex protects the append-only file handle.
/// Lock ordering: `entries` first, then `file` (if both needed).
/// This is consistent within all methods and prevents deadlock.
pub struct FileBackedEffectJournal {
    /// Path to the append-only journal file.
    path: PathBuf,
    /// Maximum allowed active entries (`Started`/`Unknown`).
    max_active_entries: usize,
    /// In-memory entry index and O(1) counters.
    ///
    /// Protected by Mutex. Lock ordering: acquire `inner` before `file`.
    /// Happens-before: all mutations to the index are preceded by a
    /// successful fsync to disk, ensuring crash consistency.
    inner: Mutex<JournalInner>,
    /// Append-only file handle (holds exclusive file lock).
    ///
    /// Protected by Mutex. Lock ordering: acquire `inner` before `file`.
    /// Writers hold both locks during state transitions to prevent TOCTOU.
    file: Mutex<File>,
}

impl std::fmt::Debug for FileBackedEffectJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("inner lock poisoned");
        f.debug_struct("FileBackedEffectJournal")
            .field("path", &self.path)
            .field("max_active_entries", &self.max_active_entries)
            .field("entry_count", &inner.entries.len())
            .field("active_count", &inner.active_count)
            .field("terminal_count", &inner.terminal_count)
            .finish_non_exhaustive()
    }
}

impl FileBackedEffectJournal {
    /// Open or create the effect journal at `path`, replaying any
    /// existing entries to classify crash windows.
    ///
    /// On replay:
    /// - `S` entries without matching `C` are classified as `Unknown`
    /// - `S` entries with matching `C` are classified as `Completed`
    /// - Torn tail (corrupt last line) is truncated and recovered
    /// - Mid-file corruption fails closed with `CorruptEntry`
    ///
    /// # Errors
    ///
    /// - `IoError` if the file cannot be opened or locked.
    /// - `CorruptEntry` if mid-file corruption is detected.
    /// - `CapacityExhausted` if replayed active entries exceed the limit.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EffectJournalError> {
        Self::open_with_capacity(path, MAX_JOURNAL_ENTRIES)
    }

    #[cfg(test)]
    fn open_with_max_active_entries(
        path: impl AsRef<Path>,
        max_active_entries: usize,
    ) -> Result<Self, EffectJournalError> {
        Self::open_with_capacity(path, max_active_entries)
    }

    fn open_with_capacity(
        path: impl AsRef<Path>,
        max_active_entries: usize,
    ) -> Result<Self, EffectJournalError> {
        /// Maximum journal file size (256 MiB). Files exceeding this
        /// limit are rejected before reading to prevent unbounded
        /// allocation from a malicious or corrupted file. The limit
        /// is sized to accommodate the maximum legitimate journal:
        /// `MAX_JOURNAL_ENTRIES` + `MAX_TERMINAL_ENTRIES` entries at
        /// `MAX_JOURNAL_LINE_LEN` bytes each.
        const MAX_JOURNAL_FILE_SIZE: u64 = 256 * 1024 * 1024;

        if max_active_entries == 0 {
            return Err(EffectJournalError::ValidationError {
                reason: "max_active_entries must be > 0".to_string(),
            });
        }
        let path = path.as_ref().to_path_buf();
        let mut entries: HashMap<Hash, JournalRecord> = HashMap::new();
        let mut active_entries = 0usize;
        let mut terminal_entries = 0usize;
        let mut terminal_order: VecDeque<Hash> = VecDeque::new();

        // MINOR FIX: Pre-allocation file size check. Reject journal files
        // exceeding MAX_JOURNAL_FILE_SIZE before reading them into memory.
        if path.exists() {
            let metadata = std::fs::metadata(&path)?;
            if metadata.len() > MAX_JOURNAL_FILE_SIZE {
                return Err(EffectJournalError::ValidationError {
                    reason: format!(
                        "journal file exceeds maximum size ({} > {MAX_JOURNAL_FILE_SIZE})",
                        metadata.len()
                    ),
                });
            }
        }

        // Acquire exclusive lock for single-writer inter-process exclusivity.
        let mut open_opts = OpenOptions::new();
        open_opts
            .create(true)
            .read(true)
            .truncate(false)
            .append(true);
        // Owner-only read/write: prevent world-readable journal files
        // that leak request IDs, session IDs, policy root digests, and
        // AJC IDs (sensitive operational metadata).
        #[cfg(unix)]
        open_opts.mode(0o600);
        let file = open_opts.open(&path)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "effect journal is locked by another process ({}): {e}",
                    path.display()
                ),
            )
        })?;

        // Remediate permissions on pre-existing files.
        // OpenOptions::mode(0o600) only applies on file creation; a
        // pre-existing file with broader permissions (e.g., 0o644 from
        // a previous version or manual creation) would remain world-readable.
        // Enforce 0o600 unconditionally after open+lock to close this gap.
        #[cfg(unix)]
        enforce_journal_permissions(&path)?;

        // Replay existing entries in streaming fashion.
        // SECURITY: Use bounded read_line instead of unbounded
        // reader.lines() to prevent memory exhaustion from a
        // malicious/corrupted journal file with an extremely long line
        // (DoS: RSK-1601, CTR-1603).
        let mut needs_truncate_to: Option<u64> = None;
        {
            let mut replay = file.try_clone()?;
            replay.seek(SeekFrom::Start(0))?;
            let mut reader = BufReader::new(&mut replay);

            let mut byte_offset: u64 = 0;
            let mut line_idx: usize = 0;
            let mut pending_error: Option<(usize, u64, String)> = None;

            loop {
                // BLOCKER FIX (TCK-00501): Bounded read to prevent
                // memory exhaustion from oversized journal lines.
                //
                // BufRead::read_line() allocates the FULL line before any
                // length check — a single 4 GiB line would OOM before the
                // post-read check. Instead, use Read::take() + read_until()
                // with Vec<u8> to cap the read at MAX_JOURNAL_LINE_LEN + 1
                // bytes, then detect oversized lines BEFORE conversion.
                let mut buf: Vec<u8> = Vec::new();
                let bytes_read = (&mut reader)
                    .take((MAX_JOURNAL_LINE_LEN as u64) + 1)
                    .read_until(b'\n', &mut buf)?;
                if bytes_read == 0 {
                    break; // EOF
                }
                // Detect oversized lines: strictly enforce MAX_JOURNAL_LINE_LEN.
                // If the buffer exceeds the limit, reject regardless of whether
                // a newline was found (off-by-one fix).
                if buf.len() > MAX_JOURNAL_LINE_LEN {
                    return Err(EffectJournalError::CorruptEntry {
                        line: line_idx + 1,
                        reason: format!(
                            "journal line exceeds maximum length ({} > {MAX_JOURNAL_LINE_LEN})",
                            buf.len()
                        ),
                    });
                }
                // Convert to UTF-8 String (fail-closed on invalid UTF-8).
                let line =
                    String::from_utf8(buf).map_err(|e| EffectJournalError::CorruptEntry {
                        line: line_idx + 1,
                        reason: format!("journal line is not valid UTF-8: {e}"),
                    })?;

                // Strip trailing newline for consistent trimming.
                let content = if line.ends_with('\n') {
                    &line[..line.len() - 1]
                } else {
                    &line
                };

                // Mid-file corruption detection: if a previous line had a
                // parse error and we have more lines after it, fail closed.
                if let Some((err_line, _err_offset, err_reason)) = pending_error.take() {
                    return Err(EffectJournalError::CorruptEntry {
                        line: err_line,
                        reason: err_reason,
                    });
                }

                let trimmed = content.trim();
                let line_byte_len = line.len() as u64;

                if trimmed.is_empty() {
                    byte_offset += line_byte_len;
                    line_idx += 1;
                    continue;
                }

                match parse_journal_line(trimmed) {
                    Ok((tag, request_id, binding_opt)) => {
                        match tag {
                            TAG_STARTED => {
                                if let Some(binding) = binding_opt {
                                    let prior_state = entries.get(&request_id).map(|r| r.state);
                                    let prior_active =
                                        prior_state.is_some_and(state_counts_toward_capacity);
                                    let prior_terminal = prior_state.is_some_and(state_is_terminal);
                                    if !prior_active && active_entries >= max_active_entries {
                                        return Err(EffectJournalError::CapacityExhausted {
                                            count: active_entries,
                                            max: max_active_entries,
                                        });
                                    }

                                    // On replay, Started without Completed
                                    // will become Unknown after replay finishes.
                                    entries.insert(
                                        request_id,
                                        JournalRecord {
                                            state: EffectExecutionState::Started,
                                            binding,
                                        },
                                    );
                                    if !prior_active {
                                        active_entries += 1;
                                    }
                                    if prior_terminal {
                                        terminal_entries = terminal_entries.saturating_sub(1);
                                    }
                                } else {
                                    pending_error = Some((
                                        line_idx + 1,
                                        byte_offset,
                                        "Started entry missing binding data".into(),
                                    ));
                                }
                            },
                            TAG_COMPLETED => {
                                if let Some(record) = entries.get_mut(&request_id) {
                                    if record.state == EffectExecutionState::Started {
                                        record.state = EffectExecutionState::Completed;
                                        active_entries = active_entries.saturating_sub(1);
                                        terminal_entries += 1;
                                        terminal_order.push_back(request_id);
                                        // BLOCKER FIX: Inline terminal compaction during
                                        // replay using O(1) VecDeque eviction to prevent
                                        // unbounded memory growth.
                                        if terminal_entries > MAX_TERMINAL_ENTRIES {
                                            let excess = terminal_entries - MAX_TERMINAL_ENTRIES;
                                            let mut pruned = 0usize;
                                            while pruned < excess {
                                                let Some(key) = terminal_order.pop_front() else {
                                                    break;
                                                };
                                                if entries
                                                    .get(&key)
                                                    .is_some_and(|r| state_is_terminal(r.state))
                                                {
                                                    entries.remove(&key);
                                                    pruned += 1;
                                                }
                                            }
                                            terminal_entries =
                                                terminal_entries.saturating_sub(pruned);
                                        }
                                    }
                                    // If already Completed, ignore duplicate.
                                }
                                // If no Started entry exists, ignore orphan
                                // Completed
                                // (could be from a previous run where Started
                                // was in
                                // a different log segment after rotation).
                            },
                            TAG_RESOLVED => {
                                // An 'R' record after 'S' without 'C' means
                                // the in-doubt resolution was approved and
                                // the entry should transition to NotStarted,
                                // allowing re-execution on this or future
                                // restarts.
                                if let Some(record) = entries.get_mut(&request_id) {
                                    if record.state == EffectExecutionState::Started {
                                        // During replay, Started entries will
                                        // later be classified as Unknown if
                                        // no C or R follows. Since we see R,
                                        // transition to NotStarted directly.
                                        record.state = EffectExecutionState::NotStarted;
                                        active_entries = active_entries.saturating_sub(1);
                                        terminal_entries += 1;
                                        terminal_order.push_back(request_id);
                                        // BLOCKER FIX: Same inline compaction for Resolved
                                        // entries during replay using O(1) VecDeque eviction.
                                        if terminal_entries > MAX_TERMINAL_ENTRIES {
                                            let excess = terminal_entries - MAX_TERMINAL_ENTRIES;
                                            let mut pruned = 0usize;
                                            while pruned < excess {
                                                let Some(key) = terminal_order.pop_front() else {
                                                    break;
                                                };
                                                if entries
                                                    .get(&key)
                                                    .is_some_and(|r| state_is_terminal(r.state))
                                                {
                                                    entries.remove(&key);
                                                    pruned += 1;
                                                }
                                            }
                                            terminal_entries =
                                                terminal_entries.saturating_sub(pruned);
                                        }
                                    }
                                }
                                // Orphan R without S is ignored (same as C).
                            },
                            _ => {
                                pending_error = Some((
                                    line_idx + 1,
                                    byte_offset,
                                    format!("unknown journal tag: {tag}"),
                                ));
                            },
                        }
                    },
                    Err(reason) => {
                        pending_error = Some((line_idx + 1, byte_offset, reason));
                    },
                }

                byte_offset += line_byte_len;
                line_idx += 1;
            }

            // If the last line had an error, treat as torn tail.
            if let Some((err_line, err_offset, reason)) = pending_error {
                tracing::warn!(
                    line = err_line,
                    reason = %reason,
                    path = %path.display(),
                    "truncating torn tail from effect journal"
                );
                needs_truncate_to = Some(err_offset);
            }
        }

        // Truncate torn tail if needed.
        if let Some(truncate_pos) = needs_truncate_to {
            let mut truncate_opts = OpenOptions::new();
            truncate_opts.write(true);
            #[cfg(unix)]
            truncate_opts.mode(0o600);
            let truncate_file = truncate_opts.open(&path)?;
            // Remediate permissions on truncation reopen
            // (same rationale as the primary open path above).
            #[cfg(unix)]
            enforce_journal_permissions(&path)?;
            truncate_file.set_len(truncate_pos)?;
            truncate_file.sync_all()?;
        }

        // Post-replay: transition all `Started` entries to `Unknown`.
        // This is the crash window classification step.
        for record in entries.values_mut() {
            if record.state == EffectExecutionState::Started {
                record.state = EffectExecutionState::Unknown;
                tracing::warn!(
                    request_id = %hex::encode(record.binding.request_id),
                    enforcement_tier = %record.binding.enforcement_tier,
                    declared_idempotent = record.binding.declared_idempotent,
                    "effect journal: classifying in-doubt request as Unknown \
                     (Started without Completed)"
                );
            }
        }

        // Post-replay safety-net compaction: the inline compaction above
        // handles streaming pruning during replay, but a final pass ensures
        // no edge case leaves terminal entries above the limit (e.g., the
        // Unknown→Started reclassification above may not have triggered
        // inline compaction for pre-existing terminal entries).
        {
            let mut inner = JournalInner {
                entries,
                active_count: active_entries,
                terminal_count: terminal_entries,
                terminal_order,
            };
            inner.prune_terminal_entries_if_needed();
            entries = inner.entries;
            active_entries = inner.active_count;
            terminal_entries = inner.terminal_count;
            terminal_order = inner.terminal_order;
        }

        Ok(Self {
            path,
            max_active_entries,
            inner: Mutex::new(JournalInner {
                entries,
                active_count: active_entries,
                terminal_count: terminal_entries,
                terminal_order,
            }),
            file: Mutex::new(file),
        })
    }

    /// Returns the file path for this journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Prune terminal entries (`Completed`/`NotStarted`) from the in-memory
    /// index, retaining only active entries.
    ///
    /// This is an in-memory-only operation. The on-disk journal retains all
    /// records for forensic recovery; only the in-memory index is compacted.
    ///
    /// Returns the number of entries pruned.
    pub fn prune_terminal_entries(&self) -> usize {
        let mut inner = self.inner.lock().expect("inner lock poisoned");
        let before = inner.entries.len();
        inner
            .entries
            .retain(|_, record| !state_is_terminal(record.state));
        let pruned = before - inner.entries.len();
        inner.terminal_count = inner.terminal_count.saturating_sub(pruned);
        // Clear the terminal order queue since all terminal entries were removed.
        inner.terminal_order.clear();
        pruned
    }

    /// Returns the current active entry count (O(1)).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.inner.lock().expect("inner lock poisoned").active_count
    }

    /// Returns the current terminal entry count (O(1)).
    #[must_use]
    pub fn terminal_count(&self) -> usize {
        self.inner
            .lock()
            .expect("inner lock poisoned")
            .terminal_count
    }
}

impl EffectJournal for FileBackedEffectJournal {
    fn record_started(&self, binding: &EffectJournalBindingV1) -> Result<(), EffectJournalError> {
        // Validate binding data before persisting.
        binding.validate()?;

        let request_id = binding.request_id;

        // Lock ordering: inner first, then file.
        let mut inner = self.inner.lock().expect("inner lock poisoned");

        // Check for existing entry (state machine enforcement).
        // NotStarted (from resolve_in_doubt) is permitted — remove the stale
        // entry so the new binding can be inserted below. The old 'S' + 'R'
        // records remain in the journal file; the new 'S' record appended
        // below takes precedence on replay.
        if let Some(existing) = inner.entries.get(&request_id) {
            if existing.state != EffectExecutionState::NotStarted {
                return Err(EffectJournalError::InvalidTransition {
                    request_id,
                    current: existing.state,
                    target: EffectExecutionState::Started,
                });
            }
            // Removing a terminal (NotStarted) entry.
            inner.terminal_count = inner.terminal_count.saturating_sub(1);
            inner.entries.remove(&request_id);
        }

        // Enforce active-entry capacity BEFORE any state mutation (O(1)).
        if inner.active_count >= self.max_active_entries {
            return Err(EffectJournalError::CapacityExhausted {
                count: inner.active_count,
                max: self.max_active_entries,
            });
        }

        // Serialize binding to JSON for journal line.
        let binding_json =
            serde_json::to_string(binding).map_err(|e| EffectJournalError::IoError {
                kind: std::io::ErrorKind::InvalidData,
                reason: format!("binding serialization failed: {e}"),
            })?;

        // Write to durable storage BEFORE updating in-memory state.
        {
            let mut file = self.file.lock().expect("file lock poisoned");
            writeln!(
                file,
                "{} {} {}",
                TAG_STARTED,
                hex::encode(request_id),
                binding_json
            )?;
            file.sync_all()?;
        }

        // Update in-memory state after successful fsync.
        inner.entries.insert(
            request_id,
            JournalRecord {
                state: EffectExecutionState::Started,
                binding: binding.clone(),
            },
        );
        inner.active_count += 1;

        Ok(())
    }

    fn record_completed(&self, request_id: &Hash) -> Result<(), EffectJournalError> {
        // Lock ordering: inner first, then file.
        let mut inner = self.inner.lock().expect("inner lock poisoned");

        // Check state machine: must be in Started state.
        match inner.entries.get(request_id) {
            Some(record) => {
                if record.state != EffectExecutionState::Started {
                    return Err(EffectJournalError::InvalidTransition {
                        request_id: *request_id,
                        current: record.state,
                        target: EffectExecutionState::Completed,
                    });
                }
            },
            None => {
                return Err(EffectJournalError::InvalidTransition {
                    request_id: *request_id,
                    current: EffectExecutionState::NotStarted,
                    target: EffectExecutionState::Completed,
                });
            },
        }

        // Write to durable storage BEFORE updating in-memory state.
        {
            let mut file = self.file.lock().expect("file lock poisoned");
            writeln!(file, "{} {}", TAG_COMPLETED, hex::encode(request_id))?;
            file.sync_all()?;
        }

        // Update in-memory state after successful fsync.
        if let Some(record) = inner.entries.get_mut(request_id) {
            record.state = EffectExecutionState::Completed;
        }
        inner.active_count = inner.active_count.saturating_sub(1);
        inner.terminal_count += 1;
        inner.terminal_order.push_back(*request_id);

        // BLOCKER FIX: Prune terminal entries at runtime to prevent
        // unbounded in-memory growth during long-running daemon sessions.
        // Without this, a daemon that processes millions of requests will
        // accumulate terminal entries indefinitely, leading to OOM.
        inner.prune_terminal_entries_if_needed();

        Ok(())
    }

    fn query_state(&self, request_id: &Hash) -> EffectExecutionState {
        let inner = self.inner.lock().expect("inner lock poisoned");
        inner
            .entries
            .get(request_id)
            .map_or(EffectExecutionState::NotStarted, |r| r.state)
    }

    fn query_binding(&self, request_id: &Hash) -> Option<EffectJournalBindingV1> {
        let inner = self.inner.lock().expect("inner lock poisoned");
        inner.entries.get(request_id).map(|r| r.binding.clone())
    }

    fn resolve_in_doubt(
        &self,
        request_id: &Hash,
        boundary_confirms_not_executed: bool,
    ) -> Result<InDoubtResolutionV1, EffectJournalError> {
        // Lock ordering: inner first, then file (if both needed).
        let mut inner = self.inner.lock().expect("inner lock poisoned");

        let Some(record) = inner.entries.get(request_id) else {
            return Err(EffectJournalError::ReExecutionDenied {
                request_id: *request_id,
                enforcement_tier: EnforcementTier::FailClosed,
                declared_idempotent: false,
                reason: "no journal entry for request_id".into(),
            });
        };

        if record.state != EffectExecutionState::Unknown {
            return Err(EffectJournalError::ReExecutionDenied {
                request_id: *request_id,
                enforcement_tier: record.binding.enforcement_tier,
                declared_idempotent: record.binding.declared_idempotent,
                reason: format!(
                    "resolve_in_doubt only applies to Unknown state, current: {}",
                    record.state
                ),
            });
        }

        // Fail-closed gate: both conditions must be met.
        if !record.binding.declared_idempotent {
            return Ok(InDoubtResolutionV1::Deny {
                reason: format!(
                    "effect is not declared idempotent (request_id={}); \
                     Unknown state requires containment/quarantine",
                    hex::encode(request_id)
                ),
            });
        }

        if !boundary_confirms_not_executed {
            return Ok(InDoubtResolutionV1::Deny {
                reason: format!(
                    "boundary does not confirm effect was not executed \
                     (request_id={}); Unknown state requires containment/quarantine",
                    hex::encode(request_id)
                ),
            });
        }

        // Both conditions met: persist resolution BEFORE updating
        // in-memory state. This ensures crash consistency — if the
        // daemon crashes after the fsync but before the in-memory
        // update, the replay will correctly classify the entry as
        // NotStarted (via the 'R' record).
        let idempotency_key =
            IdempotencyKeyV1::derive(record.binding.request_id, record.binding.ajc_id);
        {
            let mut file = self.file.lock().expect("file lock poisoned");
            writeln!(file, "{} {}", TAG_RESOLVED, hex::encode(request_id))?;
            file.sync_all()?;
        }

        // Update in-memory state after successful fsync.
        // Transition Unknown -> NotStarted to allow re-execution.
        if let Some(record) = inner.entries.get_mut(request_id) {
            record.state = EffectExecutionState::NotStarted;
        }
        // Unknown is active; NotStarted is terminal.
        inner.active_count = inner.active_count.saturating_sub(1);
        inner.terminal_count += 1;
        inner.terminal_order.push_back(*request_id);

        // BLOCKER FIX: Prune terminal entries at runtime to prevent
        // unbounded in-memory growth (same rationale as record_completed).
        inner.prune_terminal_entries_if_needed();

        Ok(InDoubtResolutionV1::AllowReExecution { idempotency_key })
    }

    fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("inner lock poisoned")
            .entries
            .len()
    }
}

// =============================================================================
// Fail-closed output gating for Unknown state
// =============================================================================

/// Check whether output release is permitted for a given request state.
///
/// For fail-closed tiers, `Unknown` state denies output release
/// (including streaming). This is the boundary mediation gate that
/// prevents leakage of potentially-duplicate or partially-executed
/// effect outputs.
///
/// # Arguments
///
/// * `state` - Current effect execution state.
/// * `enforcement_tier` - The enforcement tier for this request.
///
/// # Errors
///
/// Returns `EffectJournalError::OutputReleaseDenied` if output
/// cannot be released.
pub fn check_output_release_permitted(
    state: EffectExecutionState,
    enforcement_tier: EnforcementTier,
    request_id: &Hash,
) -> Result<(), EffectJournalError> {
    match (state, enforcement_tier) {
        (EffectExecutionState::Unknown, EnforcementTier::FailClosed) => {
            Err(EffectJournalError::OutputReleaseDenied {
                request_id: *request_id,
                reason: "effect state is Unknown for fail-closed tier; \
                         no output release permitted (containment required)"
                    .into(),
            })
        },
        (EffectExecutionState::Started, EnforcementTier::FailClosed) => {
            // During normal operation, Started means the effect is in
            // progress. Output is held until Completed.
            Err(EffectJournalError::OutputReleaseDenied {
                request_id: *request_id,
                reason: "effect state is Started for fail-closed tier; \
                         output held until Completed"
                    .into(),
            })
        },
        _ => Ok(()),
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Parse a journal line into (tag, `request_id`, `optional_binding`).
fn parse_journal_line(line: &str) -> Result<(char, Hash, Option<EffectJournalBindingV1>), String> {
    let tag = line
        .chars()
        .next()
        .ok_or_else(|| "empty journal line".to_string())?;

    let rest = line
        .get(2..)
        .ok_or_else(|| format!("journal line too short: expected 'T <hex> [json]', got: {line}"))?;

    match tag {
        TAG_STARTED => {
            // Format: S <64-char hex> <json>
            if rest.len() < 65 {
                // At least 64 hex chars + 1 space
                return Err(format!(
                    "Started entry too short: expected 64 hex + space + json, got {} chars",
                    rest.len()
                ));
            }
            let hex_part = &rest[..64];
            let request_id = hex_to_hash(hex_part)?;

            // Rest after hex + space is JSON.
            let json_part = rest.get(65..).ok_or_else(|| {
                "Started entry missing binding JSON after request_id hex".to_string()
            })?;

            let binding: EffectJournalBindingV1 = serde_json::from_str(json_part)
                .map_err(|e| format!("failed to parse binding JSON: {e}"))?;

            // TCK-00501 MINOR: Validate replayed binding to prevent
            // loading invalid/oversized entries into the in-memory index.
            // Without this, a corrupted journal file could inject entries
            // with zero hashes, empty strings, or oversized fields.
            binding
                .validate()
                .map_err(|e| format!("binding validation failed: {e}"))?;

            // MAJOR-2 fix: Verify line-key request_id matches the binding's
            // request_id. A mismatch indicates corruption or tampering — the
            // line key determines lookup but the binding carries the
            // authoritative identity, so they must agree.
            if request_id != binding.request_id {
                return Err(format!(
                    "S record key/binding mismatch: line key={}, binding.request_id={}",
                    hex::encode(request_id),
                    hex::encode(binding.request_id),
                ));
            }

            Ok((TAG_STARTED, request_id, Some(binding)))
        },
        TAG_COMPLETED => {
            // Format: C <64-char hex>
            // Exact-length enforcement: reject trailing garbage that could
            // mask corruption or adversarial tampering (MAJOR-1 fix).
            if rest.len() != 64 {
                return Err(format!(
                    "Completed entry has wrong length: expected exactly 64 hex chars, got {} chars",
                    rest.len()
                ));
            }
            let request_id = hex_to_hash(rest)?;
            Ok((TAG_COMPLETED, request_id, None))
        },
        TAG_RESOLVED => {
            // Format: R <64-char hex>
            // Exact-length enforcement: reject trailing garbage that could
            // mask corruption or adversarial tampering (MAJOR-1 fix).
            if rest.len() != 64 {
                return Err(format!(
                    "Resolved entry has wrong length: expected exactly 64 hex chars, got {} chars",
                    rest.len()
                ));
            }
            let request_id = hex_to_hash(rest)?;
            Ok((TAG_RESOLVED, request_id, None))
        },
        other => Err(format!("unknown journal tag: {other}")),
    }
}

/// Enforce restrictive permissions on the journal file (Unix only).
///
/// `OpenOptions::mode(0o600)` only applies on creation; pre-existing
/// files retain their original permissions. This function unconditionally
/// enforces 0o600 to prevent world-readable journal files that leak
/// request IDs, session IDs, policy root digests, and AJC IDs.
#[cfg(unix)]
fn enforce_journal_permissions(path: &Path) -> Result<(), EffectJournalError> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

/// Parse a 64-character hex string into a 32-byte hash.
fn hex_to_hash(s: &str) -> Result<Hash, String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn test_hash(byte: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = byte;
        h[31] = byte;
        h
    }

    fn test_hash_u16(value: u16) -> Hash {
        let mut h = [0u8; 32];
        h[0..2].copy_from_slice(&value.to_le_bytes());
        h[30..32].copy_from_slice(&value.to_be_bytes());
        h
    }

    fn test_binding(request_id: Hash, declared_idempotent: bool) -> EffectJournalBindingV1 {
        EffectJournalBindingV1 {
            request_id,
            request_digest: test_hash(0x10),
            as_of_ledger_anchor: LedgerAnchorV1 {
                ledger_id: test_hash(0x20),
                event_hash: test_hash(0x21),
                height: 100,
                he_time: 1000,
            },
            policy_root_digest: test_hash(0x30),
            policy_root_epoch: 5,
            leakage_witness_seed_hash: test_hash(0x40),
            timing_witness_seed_hash: test_hash(0x41),
            boundary_profile_id: "boundary-001".to_string(),
            enforcement_tier: EnforcementTier::FailClosed,
            ajc_id: test_hash(0x50),
            authority_join_hash: test_hash(0x51),
            session_id: "session-001".to_string(),
            tool_class: "filesystem.write".to_string(),
            declared_idempotent,
        }
    }

    // =========================================================================
    // Basic state machine tests
    // =========================================================================

    #[test]
    fn record_started_and_query() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        let request_id = test_hash(0x01);
        let binding = test_binding(request_id, false);

        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::NotStarted
        );
        journal.record_started(&binding).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Started
        );
        assert_eq!(journal.len(), 1);
    }

    #[test]
    fn record_completed_after_started() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        let request_id = test_hash(0x02);
        let binding = test_binding(request_id, false);

        journal.record_started(&binding).unwrap();
        journal.record_completed(&request_id).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Completed
        );
    }

    #[test]
    fn duplicate_started_denied() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        let request_id = test_hash(0x03);
        let binding = test_binding(request_id, false);

        journal.record_started(&binding).unwrap();
        let err = journal.record_started(&binding).unwrap_err();
        assert!(
            matches!(err, EffectJournalError::InvalidTransition { .. }),
            "duplicate Started must be denied; got: {err:?}"
        );
    }

    #[test]
    fn completed_without_started_denied() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        let request_id = test_hash(0x04);
        let err = journal.record_completed(&request_id).unwrap_err();
        assert!(
            matches!(err, EffectJournalError::InvalidTransition { .. }),
            "Completed without Started must be denied; got: {err:?}"
        );
    }

    #[test]
    fn double_completed_denied() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        let request_id = test_hash(0x05);
        let binding = test_binding(request_id, false);

        journal.record_started(&binding).unwrap();
        journal.record_completed(&request_id).unwrap();

        let err = journal.record_completed(&request_id).unwrap_err();
        assert!(
            matches!(err, EffectJournalError::InvalidTransition { .. }),
            "double Completed must be denied; got: {err:?}"
        );
    }

    // =========================================================================
    // Crash window classification tests
    // =========================================================================

    #[test]
    fn crash_after_consume_before_effect_classifies_not_started() {
        // Scenario: crash after PCAC consume but before effect journal
        // records Started. On restart, the request has no journal entry.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        // First session: no journal entries written (crash before Started).
        {
            let _journal = FileBackedEffectJournal::open(&path).unwrap();
            // Simulate crash before record_started is called.
        }

        // Second session: request should be NotStarted.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        let request_id = test_hash(0x10);
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::NotStarted,
            "crash before effect journal Started -> NotStarted"
        );
    }

    #[test]
    fn crash_during_effect_classifies_unknown() {
        // Scenario: Started is fsynced, then crash during effect execution
        // (before Completed is written).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x11);
        let binding = test_binding(request_id, false);

        // First session: record Started, then crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
            // Simulate crash after Started but before Completed.
        }

        // Second session: request should be Unknown.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Unknown,
            "crash after Started but before Completed -> Unknown"
        );
    }

    #[test]
    fn crash_after_effect_before_receipts_classifies_completed_or_unknown() {
        // Scenario: Started is fsynced, effect executes, Completed is
        // fsynced, then crash before receipts are emitted. The journal
        // correctly reflects Completed.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x12);
        let binding = test_binding(request_id, false);

        // First session: record Started + Completed, then crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
            journal.record_completed(&request_id).unwrap();
            // Simulate crash after Completed but before receipt emission.
        }

        // Second session: request should be Completed.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Completed,
            "crash after Completed -> Completed (idempotent receipt \
             emission can retry safely)"
        );
    }

    #[test]
    fn crash_after_effect_without_completed_fsync_classifies_unknown() {
        // Scenario: Started is fsynced, effect executes, but crash before
        // Completed fsync. This is the critical in-doubt window.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x13);
        let binding = test_binding(request_id, false);

        // First session: write Started only.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
            // Completed not written (crash before or during Completed write).
        }

        // Second session: in-doubt.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Unknown,
            "crash after effect execution without Completed -> Unknown"
        );
    }

    // =========================================================================
    // Fail-closed in-doubt handling tests
    // =========================================================================

    #[test]
    fn unknown_non_idempotent_denies_re_execution() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x20);
        let binding = test_binding(request_id, false); // NOT idempotent

        // First session: Started, crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Second session: resolve in-doubt.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Unknown
        );

        let resolution = journal.resolve_in_doubt(&request_id, true).unwrap();
        assert!(
            matches!(resolution, InDoubtResolutionV1::Deny { .. }),
            "non-idempotent Unknown must be denied; got: {resolution:?}"
        );
    }

    #[test]
    fn unknown_idempotent_boundary_not_confirmed_denies() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x21);
        let binding = test_binding(request_id, true); // idempotent

        // First session: Started, crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Second session: boundary does NOT confirm not-executed.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        let resolution = journal.resolve_in_doubt(&request_id, false).unwrap();
        assert!(
            matches!(resolution, InDoubtResolutionV1::Deny { .. }),
            "idempotent Unknown without boundary confirmation must be denied; got: {resolution:?}"
        );
    }

    #[test]
    fn unknown_idempotent_boundary_confirmed_allows_re_execution() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x22);
        let binding = test_binding(request_id, true); // idempotent

        // First session: Started, crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Second session: boundary confirms not-executed.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        let resolution = journal.resolve_in_doubt(&request_id, true).unwrap();
        match resolution {
            InDoubtResolutionV1::AllowReExecution { idempotency_key } => {
                assert_eq!(
                    idempotency_key.request_id, request_id,
                    "idempotency key must bind to original request_id"
                );
                assert_eq!(
                    idempotency_key.ajc_id,
                    test_hash(0x50),
                    "idempotency key must bind to original ajc_id"
                );
                // Verify key is deterministic.
                let expected = IdempotencyKeyV1::derive(request_id, test_hash(0x50));
                assert_eq!(
                    idempotency_key.key, expected.key,
                    "idempotency key must be deterministically derived"
                );
            },
            InDoubtResolutionV1::Deny { reason } => {
                panic!("expected AllowReExecution; got: Deny {{ reason: {reason} }}")
            },
        }

        // Verify in-memory state transitioned to NotStarted (MAJOR 3 fix).
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::NotStarted,
            "resolve_in_doubt AllowReExecution must transition Unknown -> NotStarted"
        );
    }

    // =========================================================================
    // Output release gating tests
    // =========================================================================

    #[test]
    fn fail_closed_unknown_denies_output_release() {
        let request_id = test_hash(0x30);
        let result = check_output_release_permitted(
            EffectExecutionState::Unknown,
            EnforcementTier::FailClosed,
            &request_id,
        );
        assert!(
            result.is_err(),
            "Unknown at fail-closed must deny output release"
        );
    }

    #[test]
    fn fail_closed_started_denies_output_release() {
        let request_id = test_hash(0x31);
        let result = check_output_release_permitted(
            EffectExecutionState::Started,
            EnforcementTier::FailClosed,
            &request_id,
        );
        assert!(result.is_err(), "Started at fail-closed must hold output");
    }

    #[test]
    fn fail_closed_completed_allows_output_release() {
        let request_id = test_hash(0x32);
        let result = check_output_release_permitted(
            EffectExecutionState::Completed,
            EnforcementTier::FailClosed,
            &request_id,
        );
        assert!(
            result.is_ok(),
            "Completed at fail-closed must allow output release"
        );
    }

    #[test]
    fn monitor_unknown_allows_output_release() {
        let request_id = test_hash(0x33);
        let result = check_output_release_permitted(
            EffectExecutionState::Unknown,
            EnforcementTier::Monitor,
            &request_id,
        );
        assert!(
            result.is_ok(),
            "Monitor tier does not block on Unknown state"
        );
    }

    #[test]
    fn not_started_allows_output_release() {
        let request_id = test_hash(0x34);
        let result = check_output_release_permitted(
            EffectExecutionState::NotStarted,
            EnforcementTier::FailClosed,
            &request_id,
        );
        assert!(
            result.is_ok(),
            "NotStarted allows output release (no effect dispatched)"
        );
    }

    // =========================================================================
    // Idempotency key tests
    // =========================================================================

    #[test]
    fn idempotency_key_deterministic() {
        let request_id = test_hash(0x40);
        let ajc_id = test_hash(0x41);

        let key1 = IdempotencyKeyV1::derive(request_id, ajc_id);
        let key2 = IdempotencyKeyV1::derive(request_id, ajc_id);
        assert_eq!(key1.key, key2.key, "idempotency key must be deterministic");
        assert_eq!(key1.as_hex(), key2.as_hex());
    }

    #[test]
    fn idempotency_key_different_for_different_requests() {
        let key1 = IdempotencyKeyV1::derive(test_hash(0x40), test_hash(0x41));
        let key2 = IdempotencyKeyV1::derive(test_hash(0x42), test_hash(0x41));
        assert_ne!(
            key1.key, key2.key,
            "different request_ids must produce different keys"
        );
    }

    #[test]
    fn idempotency_key_different_for_different_ajc_ids() {
        let key1 = IdempotencyKeyV1::derive(test_hash(0x40), test_hash(0x41));
        let key2 = IdempotencyKeyV1::derive(test_hash(0x40), test_hash(0x43));
        assert_ne!(
            key1.key, key2.key,
            "different ajc_ids must produce different keys"
        );
    }

    #[test]
    fn idempotency_key_with_dedupe_key_deterministic() {
        let request_id = test_hash(0x40);
        let ajc_id = test_hash(0x41);
        let dedupe_key = b"stable-client-intent-key";

        let key1 = IdempotencyKeyV1::derive_with_dedupe_key(request_id, ajc_id, dedupe_key);
        let key2 = IdempotencyKeyV1::derive_with_dedupe_key(request_id, ajc_id, dedupe_key);
        assert_eq!(
            key1.key, key2.key,
            "derive_with_dedupe_key must be deterministic for same inputs"
        );
    }

    #[test]
    fn idempotency_key_with_dedupe_key_differs_from_without() {
        let request_id = test_hash(0x40);
        let ajc_id = test_hash(0x41);
        let dedupe_key = b"stable-client-intent-key";

        let key_without = IdempotencyKeyV1::derive(request_id, ajc_id);
        let key_with = IdempotencyKeyV1::derive_with_dedupe_key(request_id, ajc_id, dedupe_key);
        assert_ne!(
            key_without.key, key_with.key,
            "derive_with_dedupe_key must differ from derive when dedupe_key is non-empty"
        );
    }

    #[test]
    fn idempotency_key_different_dedupe_keys_produce_different_keys() {
        let request_id = test_hash(0x40);
        let ajc_id = test_hash(0x41);

        let key1 = IdempotencyKeyV1::derive_with_dedupe_key(request_id, ajc_id, b"intent-A");
        let key2 = IdempotencyKeyV1::derive_with_dedupe_key(request_id, ajc_id, b"intent-B");
        assert_ne!(
            key1.key, key2.key,
            "different dedupe_keys must produce different idempotency keys"
        );
    }

    // =========================================================================
    // Binding validation tests
    // =========================================================================

    #[test]
    fn binding_with_zero_request_id_rejected() {
        let mut binding = test_binding(test_hash(0x50), false);
        binding.request_id = [0u8; 32];
        let err = binding.validate().unwrap_err();
        assert!(
            matches!(err, EffectJournalError::ValidationError { .. }),
            "zero request_id must fail validation; got: {err:?}"
        );
    }

    #[test]
    fn binding_with_empty_boundary_profile_rejected() {
        let mut binding = test_binding(test_hash(0x51), false);
        binding.boundary_profile_id = String::new();
        let err = binding.validate().unwrap_err();
        assert!(
            matches!(err, EffectJournalError::ValidationError { .. }),
            "empty boundary_profile_id must fail validation; got: {err:?}"
        );
    }

    #[test]
    fn binding_with_oversized_tool_class_rejected() {
        let mut binding = test_binding(test_hash(0x52), false);
        binding.tool_class = "x".repeat(MAX_TOOL_CLASS_LENGTH + 1);
        let err = binding.validate().unwrap_err();
        assert!(
            matches!(err, EffectJournalError::ValidationError { .. }),
            "oversized tool_class must fail validation; got: {err:?}"
        );
    }

    #[test]
    fn binding_content_hash_deterministic() {
        let binding = test_binding(test_hash(0x53), false);
        let hash1 = binding.content_hash();
        let hash2 = binding.content_hash();
        assert_eq!(hash1, hash2, "content_hash must be deterministic");
    }

    // =========================================================================
    // Crash replay tests
    // =========================================================================

    #[test]
    fn crash_replay_preserves_completed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x60);
        let binding = test_binding(request_id, false);

        // First session: Started + Completed.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
            journal.record_completed(&request_id).unwrap();
        }

        // Second session: Completed preserved.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Completed
        );
    }

    #[test]
    fn crash_replay_classifies_in_doubt_correctly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let r1 = test_hash(0x61);
        let r2 = test_hash(0x62);
        let r3 = test_hash(0x63);

        let b1 = test_binding(r1, false);
        let b2 = test_binding(r2, true);
        let b3 = test_binding(r3, false);

        // First session: r1 Started+Completed, r2 Started only, r3 Started only.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&b1).unwrap();
            journal.record_completed(&r1).unwrap();
            journal.record_started(&b2).unwrap();
            journal.record_started(&b3).unwrap();
        }

        // Second session: classification.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(journal.query_state(&r1), EffectExecutionState::Completed);
        assert_eq!(journal.query_state(&r2), EffectExecutionState::Unknown);
        assert_eq!(journal.query_state(&r3), EffectExecutionState::Unknown);
        assert_eq!(journal.len(), 3);
    }

    #[test]
    fn query_binding_returns_persisted_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x64);
        let binding = test_binding(request_id, true);

        // First session.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Second session: binding data preserved through crash.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        let recovered = journal.query_binding(&request_id).unwrap();
        assert_eq!(recovered.request_id, binding.request_id);
        assert_eq!(recovered.request_digest, binding.request_digest);
        assert_eq!(recovered.policy_root_digest, binding.policy_root_digest);
        assert_eq!(recovered.policy_root_epoch, binding.policy_root_epoch);
        assert_eq!(recovered.ajc_id, binding.ajc_id);
        assert_eq!(recovered.declared_idempotent, binding.declared_idempotent);
        assert_eq!(recovered.enforcement_tier, binding.enforcement_tier);
    }

    // =========================================================================
    // Torn tail recovery tests
    // =========================================================================

    #[test]
    fn torn_tail_recovered_on_open() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x70);
        let binding = test_binding(request_id, false);

        // First session: write a Started entry, then simulate a torn tail
        // for the next entry.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Manually append a torn line.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "C deadbeef_incomplete").unwrap();
        drop(file);

        // Second session: should recover, torn tail removed.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Unknown
        );
        assert_eq!(journal.len(), 1);
    }

    // =========================================================================
    // Exclusive lock test
    // =========================================================================

    #[test]
    fn second_open_denied_while_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let _journal = FileBackedEffectJournal::open(&path).unwrap();
        let err = FileBackedEffectJournal::open(&path).unwrap_err();
        assert!(
            matches!(err, EffectJournalError::IoError { .. }),
            "second opener must fail while lock is held; got: {err:?}"
        );
    }

    // =========================================================================
    // Empty journal test
    // =========================================================================

    #[test]
    fn empty_journal_opens_cleanly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert!(journal.is_empty());
        assert_eq!(journal.len(), 0);
    }

    // =========================================================================
    // Active-entry capacity accounting tests (SECURITY MAJOR-2 fix)
    // =========================================================================

    #[test]
    fn completed_entries_do_not_consume_active_capacity_slots() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-capacity.journal");
        let journal = FileBackedEffectJournal::open_with_max_active_entries(&path, 1).unwrap();

        let first_request = test_hash(0x90);
        journal
            .record_started(&test_binding(first_request, false))
            .expect("first active request should be admitted");
        journal
            .record_completed(&first_request)
            .expect("first request should complete");

        let second_request = test_hash(0x91);
        journal
            .record_started(&test_binding(second_request, false))
            .expect("completed entries must not block new active admission");
    }

    #[test]
    fn many_completed_entries_still_allow_new_admission() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-many-completed.journal");
        let journal = FileBackedEffectJournal::open_with_max_active_entries(&path, 2).unwrap();

        for i in 0..128u16 {
            let request_id = test_hash_u16(0xA000u16 + i);
            let binding = test_binding(request_id, false);
            journal
                .record_started(&binding)
                .expect("admission should succeed");
            journal
                .record_completed(&request_id)
                .expect("completion should succeed");
        }

        let fresh_request = test_hash_u16(0xB001);
        journal
            .record_started(&test_binding(fresh_request, false))
            .expect("new request must still be admitted after many completions");
    }

    #[test]
    fn replay_capacity_limits_active_entries_not_completed_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-replay-capacity.journal");

        // Build replay state: one fully completed request + one in-flight
        // request. With max_active_entries=1, replay must succeed because only
        // one request is active after replay.
        let completed_id = test_hash(0x92);
        let active_id = test_hash(0x93);
        let completed_binding = test_binding(completed_id, false);
        let active_binding = test_binding(active_id, false);
        let completed_json = serde_json::to_string(&completed_binding).unwrap();
        let active_json = serde_json::to_string(&active_binding).unwrap();
        let completed_hex = hex::encode(completed_id);
        let active_hex = hex::encode(active_id);
        let content = format!(
            "S {completed_hex} {completed_json}\nC {completed_hex}\nS {active_hex} {active_json}\n"
        );
        std::fs::write(&path, content).unwrap();

        let journal = FileBackedEffectJournal::open_with_max_active_entries(&path, 1)
            .expect("replay should count only active entries toward capacity");
        assert_eq!(
            journal.query_state(&active_id),
            EffectExecutionState::Unknown,
            "in-flight replayed entry should classify as Unknown"
        );
    }

    // =========================================================================
    // resolve_in_doubt persistence tests (MAJOR 3 fix)
    // =========================================================================

    #[test]
    fn resolve_in_doubt_persists_resolution_and_transitions_to_not_started() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x80);
        let binding = test_binding(request_id, true); // idempotent

        // First session: Started, crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Second session: resolve in-doubt -> should transition to NotStarted.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::Unknown
            );

            let resolution = journal.resolve_in_doubt(&request_id, true).unwrap();
            assert!(
                matches!(resolution, InDoubtResolutionV1::AllowReExecution { .. }),
                "idempotent + boundary confirmed -> AllowReExecution; got: {resolution:?}"
            );

            // In-memory state must be NotStarted after resolution.
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::NotStarted,
                "resolve_in_doubt must transition Unknown -> NotStarted"
            );
        }

        // Third session: the 'R' record must be replayed, so the entry
        // should be NotStarted (not Unknown).
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::NotStarted,
            "replay after resolve_in_doubt must classify as NotStarted (via 'R' record)"
        );
    }

    #[test]
    fn resolve_in_doubt_deny_does_not_mutate_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x81);
        let binding = test_binding(request_id, false); // NOT idempotent

        // First session: Started, crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Second session: resolve in-doubt -> should deny (not idempotent).
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            let resolution = journal.resolve_in_doubt(&request_id, true).unwrap();
            assert!(
                matches!(resolution, InDoubtResolutionV1::Deny { .. }),
                "non-idempotent -> Deny; got: {resolution:?}"
            );

            // State must remain Unknown after denial.
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::Unknown,
                "resolve_in_doubt Deny must NOT mutate state"
            );
        }

        // Third session: still Unknown (no 'R' record written).
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Unknown,
            "replay after deny must still be Unknown"
        );
    }

    #[test]
    fn resolve_in_doubt_allows_re_execution_after_restart() {
        // End-to-end: Started -> crash -> resolve_in_doubt(allow) ->
        // record_started (same request_id) -> record_completed.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0x82);
        let binding = test_binding(request_id, true); // idempotent

        // Session 1: Started, then simulate crash (drop journal).
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::Started
            );
        }

        // Session 2: replay classifies as Unknown, resolve allows re-execution.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::Unknown,
                "after crash, Started without Completed must replay as Unknown"
            );

            let resolution = journal.resolve_in_doubt(&request_id, true).unwrap();
            match &resolution {
                InDoubtResolutionV1::AllowReExecution { idempotency_key } => {
                    assert!(
                        !idempotency_key.as_hex().is_empty(),
                        "idempotency key must be non-empty"
                    );
                },
                InDoubtResolutionV1::Deny { reason } => {
                    panic!("expected AllowReExecution, got Deny: {reason}");
                },
            }
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::NotStarted,
                "resolve_in_doubt must transition Unknown -> NotStarted"
            );

            // Re-execute: record_started for the SAME request_id succeeds
            // because the state is NotStarted (from resolve_in_doubt).
            journal
                .record_started(&binding)
                .expect("record_started must succeed for NotStarted entry (re-execution)");
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::Started,
                "after re-execution record_started, state must be Started"
            );

            // Complete the re-execution.
            journal
                .record_completed(&request_id)
                .expect("record_completed must succeed after re-execution");
            assert_eq!(
                journal.query_state(&request_id),
                EffectExecutionState::Completed,
                "after record_completed, state must be Completed"
            );
        }

        // Session 3: replay after full re-execution cycle shows Completed.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Completed,
            "replay after re-execution cycle must show Completed"
        );
        assert_eq!(journal.len(), 1, "only one logical entry for request_id");
    }

    // =========================================================================
    // Secure file mode test (MINOR 1 fix)
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn journal_file_has_restrictive_permissions() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");
        let _journal = FileBackedEffectJournal::open(&path).unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "journal file must be created with mode 0o600 (owner-only); got: {mode:o}"
        );
    }

    // =========================================================================
    // TCK-00501: Bounded journal line read (DoS prevention)
    // =========================================================================

    /// A journal file containing a line exceeding `MAX_JOURNAL_LINE_LEN`
    /// must be rejected with `CorruptEntry` during replay, preventing
    /// memory exhaustion from a malicious/corrupted journal.
    #[test]
    fn replay_rejects_oversized_line() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        // Write a line that exceeds MAX_JOURNAL_LINE_LEN.
        // Use a valid-looking prefix so the rejection is from length,
        // not from parsing.
        let oversized_line = format!("S {}\n", "a".repeat(MAX_JOURNAL_LINE_LEN + 10));
        std::fs::write(&path, oversized_line).unwrap();

        let err = FileBackedEffectJournal::open(&path).unwrap_err();
        match err {
            EffectJournalError::CorruptEntry { line, reason } => {
                assert_eq!(line, 1, "error must reference the oversized line");
                assert!(
                    reason.contains("exceeds maximum length"),
                    "error must mention max length: {reason}"
                );
            },
            other => panic!("expected CorruptEntry for oversized line, got: {other:?}"),
        }
    }

    /// A journal file with lines within `MAX_JOURNAL_LINE_LEN` must
    /// replay successfully (regression: bounded reads must not reject
    /// legitimate entries).
    #[test]
    fn replay_accepts_normal_length_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        // Write a valid Started + Completed pair.
        let request_id = test_hash(0xAA);
        let binding = test_binding(request_id, false);
        let hex_id = hex::encode(request_id);
        let json = serde_json::to_string(&binding).unwrap();

        // Verify the line is under the limit.
        let started_line = format!("S {hex_id} {json}\n");
        assert!(
            started_line.len() < MAX_JOURNAL_LINE_LEN,
            "test line must be under limit"
        );

        let completed_line = format!("C {hex_id}\n");
        let content = format!("{started_line}{completed_line}");
        std::fs::write(&path, content).unwrap();

        let journal = FileBackedEffectJournal::open(&path)
            .expect("normal-length lines must replay successfully");
        assert_eq!(
            journal.query_state(&request_id),
            EffectExecutionState::Completed,
            "replayed entry must be Completed"
        );
    }

    // =========================================================================
    // TCK-00501: Binding validation on replay (MINOR fix)
    // =========================================================================

    /// A journal file containing a Started entry with an invalid binding
    /// (e.g., zero `request_digest`) must be rejected during replay.
    ///
    /// Note: A single invalid line as the only/last line is treated as
    /// a torn tail (truncated, not an error). To trigger mid-file
    /// corruption detection, a second valid line must follow.
    #[test]
    fn replay_rejects_invalid_binding() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0xBB);
        let mut binding = test_binding(request_id, false);
        // Corrupt the binding: set request_digest to zero.
        binding.request_digest = [0u8; 32];
        let hex_id = hex::encode(request_id);
        let json = serde_json::to_string(&binding).unwrap();

        // A second valid line after the invalid one triggers mid-file
        // corruption detection (single-line errors are treated as torn
        // tail and truncated).
        let valid_id = test_hash(0xCC);
        let valid_binding = test_binding(valid_id, false);
        let valid_hex_id = hex::encode(valid_id);
        let valid_json = serde_json::to_string(&valid_binding).unwrap();

        let content = format!("S {hex_id} {json}\nS {valid_hex_id} {valid_json}\n");
        std::fs::write(&path, content).unwrap();

        let err = FileBackedEffectJournal::open(&path).unwrap_err();
        match err {
            EffectJournalError::CorruptEntry { reason, .. } => {
                assert!(
                    reason.contains("binding validation failed"),
                    "error must mention binding validation: {reason}"
                );
            },
            other => panic!("expected CorruptEntry for invalid binding, got: {other:?}"),
        }
    }

    // =========================================================================
    // TCK-00501: Witness seed hash zero-check (NIT fix)
    // =========================================================================

    /// A binding with a zero `leakage_witness_seed_hash` must fail
    /// validation.
    #[test]
    fn validate_rejects_zero_leakage_witness_seed_hash() {
        let request_id = test_hash(0xCC);
        let mut binding = test_binding(request_id, false);
        binding.leakage_witness_seed_hash = [0u8; 32];

        let err = binding.validate().unwrap_err();
        match err {
            EffectJournalError::ValidationError { reason } => {
                assert!(
                    reason.contains("leakage_witness_seed_hash"),
                    "error must identify the zero field: {reason}"
                );
            },
            other => panic!("expected ValidationError, got: {other:?}"),
        }
    }

    /// A binding with a zero `timing_witness_seed_hash` must fail
    /// validation.
    #[test]
    fn validate_rejects_zero_timing_witness_seed_hash() {
        let request_id = test_hash(0xDD);
        let mut binding = test_binding(request_id, false);
        binding.timing_witness_seed_hash = [0u8; 32];

        let err = binding.validate().unwrap_err();
        match err {
            EffectJournalError::ValidationError { reason } => {
                assert!(
                    reason.contains("timing_witness_seed_hash"),
                    "error must identify the zero field: {reason}"
                );
            },
            other => panic!("expected ValidationError, got: {other:?}"),
        }
    }

    // =========================================================================
    // MAJOR-1: Trailing garbage in C/R records rejected
    // =========================================================================

    /// A Completed record with trailing garbage after the 64 hex chars
    /// must be rejected with `CorruptEntry` during replay (MAJOR-1 fix).
    ///
    /// The journal format for C records is exactly `C <64-hex>\n`.
    /// Any extra bytes after the 64 hex characters indicate corruption
    /// or adversarial tampering and must not be silently discarded.
    #[test]
    fn replay_rejects_completed_with_trailing_garbage() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0xE0);
        let binding = test_binding(request_id, false);
        let hex_id = hex::encode(request_id);
        let json = serde_json::to_string(&binding).unwrap();

        // Write a valid Started line, then a Completed line with trailing
        // garbage, then a second valid Started to trigger mid-file
        // corruption detection (single trailing errors are treated as
        // torn tail).
        let valid_id2 = test_hash(0xE1);
        let binding2 = test_binding(valid_id2, false);
        let hex_id2 = hex::encode(valid_id2);
        let json2 = serde_json::to_string(&binding2).unwrap();

        let content = format!("S {hex_id} {json}\nC {hex_id}EXTRA\nS {hex_id2} {json2}\n");
        std::fs::write(&path, content).unwrap();

        let err = FileBackedEffectJournal::open(&path).unwrap_err();
        match err {
            EffectJournalError::CorruptEntry { reason, .. } => {
                assert!(
                    reason.contains("wrong length")
                        || reason.contains("expected exactly 64 hex chars"),
                    "error must indicate wrong length: {reason}"
                );
            },
            other => {
                panic!("expected CorruptEntry for Completed with trailing garbage, got: {other:?}")
            },
        }
    }

    /// A Resolved record with trailing garbage after the 64 hex chars
    /// must be rejected with `CorruptEntry` during replay (MAJOR-1 fix).
    #[test]
    fn replay_rejects_resolved_with_trailing_garbage() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        let request_id = test_hash(0xE2);
        let binding = test_binding(request_id, false);
        let hex_id = hex::encode(request_id);
        let json = serde_json::to_string(&binding).unwrap();

        // Write S, then R with trailing garbage, then a second valid S
        // to trigger mid-file corruption detection.
        let valid_id2 = test_hash(0xE3);
        let binding2 = test_binding(valid_id2, false);
        let hex_id2 = hex::encode(valid_id2);
        let json2 = serde_json::to_string(&binding2).unwrap();

        let content = format!("S {hex_id} {json}\nR {hex_id}EXTRA\nS {hex_id2} {json2}\n");
        std::fs::write(&path, content).unwrap();

        let err = FileBackedEffectJournal::open(&path).unwrap_err();
        match err {
            EffectJournalError::CorruptEntry { reason, .. } => {
                assert!(
                    reason.contains("wrong length")
                        || reason.contains("expected exactly 64 hex chars"),
                    "error must indicate wrong length: {reason}"
                );
            },
            other => {
                panic!("expected CorruptEntry for Resolved with trailing garbage, got: {other:?}")
            },
        }
    }

    // =========================================================================
    // MAJOR-2: S record key/binding request_id mismatch rejected
    // =========================================================================

    /// A Started record where the line-key hex differs from the binding's
    /// `request_id` must be rejected with `CorruptEntry` during replay
    /// (MAJOR-2 fix).
    ///
    /// The line-key determines in-memory lookup, but the binding carries
    /// the authoritative identity. A mismatch means the journal was
    /// tampered with or suffered bit-level corruption.
    #[test]
    fn replay_rejects_started_with_mismatched_request_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        // Create a binding for request_id A, but write the hex key as B.
        let real_id = test_hash(0xE4);
        let fake_key = test_hash(0xE5);
        let binding = test_binding(real_id, false);
        let fake_hex = hex::encode(fake_key);
        let json = serde_json::to_string(&binding).unwrap();

        // Write mismatched S line + a second valid S to trigger mid-file
        // corruption detection.
        let valid_id = test_hash(0xE6);
        let valid_binding = test_binding(valid_id, false);
        let valid_hex = hex::encode(valid_id);
        let valid_json = serde_json::to_string(&valid_binding).unwrap();

        let content = format!("S {fake_hex} {json}\nS {valid_hex} {valid_json}\n");
        std::fs::write(&path, content).unwrap();

        let err = FileBackedEffectJournal::open(&path).unwrap_err();
        match err {
            EffectJournalError::CorruptEntry { reason, .. } => {
                assert!(
                    reason.contains("key/binding mismatch"),
                    "error must mention key/binding mismatch: {reason}"
                );
            },
            other => panic!("expected CorruptEntry for mismatched request_id, got: {other:?}"),
        }
    }

    // =========================================================================
    // MINOR-1: Permission remediation for pre-existing files
    // =========================================================================

    /// A pre-existing journal file with permissive permissions (e.g.,
    /// 0o644) must be remediated to 0o600 when opened (MINOR-1 fix).
    ///
    /// `OpenOptions::mode` only applies on file creation. This test verifies
    /// that the unconditional `set_permissions` call in the open path
    /// closes the gap for files created by older versions or manual
    /// operations.
    #[cfg(unix)]
    #[test]
    fn journal_remediates_permissive_existing_file() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect.journal");

        // Create the file with overly permissive mode 0o644.
        {
            let file = std::fs::File::create(&path).unwrap();
            file.set_permissions(std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }

        // Verify the file actually has 0o644 before the open.
        let meta_before = std::fs::metadata(&path).unwrap();
        assert_eq!(
            meta_before.mode() & 0o777,
            0o644,
            "pre-condition: file must start with mode 0o644"
        );

        // Open via FileBackedEffectJournal — this should remediate.
        let _journal = FileBackedEffectJournal::open(&path).unwrap();

        let meta_after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            meta_after.mode() & 0o777,
            0o600,
            "journal must remediate pre-existing permissive file to 0o600"
        );
    }

    // =========================================================================
    // TCK-00501 SEC-BLOCKER: O(1) active count tracking
    // =========================================================================

    /// Verify that `active_count()` returns the correct O(1) count after
    /// various state transitions: Started increments, Completed decrements,
    /// and terminal entries do not contribute.
    #[test]
    fn active_count_tracks_state_transitions_o1() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-active-count.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        assert_eq!(journal.active_count(), 0, "empty journal -> 0 active");
        assert_eq!(journal.terminal_count(), 0, "empty journal -> 0 terminal");

        // Record Started for 3 entries.
        let r1 = test_hash(0xF0);
        let r2 = test_hash(0xF1);
        let r3 = test_hash(0xF2);
        journal.record_started(&test_binding(r1, false)).unwrap();
        journal.record_started(&test_binding(r2, false)).unwrap();
        journal.record_started(&test_binding(r3, false)).unwrap();
        assert_eq!(journal.active_count(), 3, "3 Started -> 3 active");
        assert_eq!(journal.terminal_count(), 0, "no completions yet");

        // Complete r1 and r2.
        journal.record_completed(&r1).unwrap();
        assert_eq!(journal.active_count(), 2, "1 Completed -> 2 active");
        assert_eq!(journal.terminal_count(), 1, "1 Completed -> 1 terminal");

        journal.record_completed(&r2).unwrap();
        assert_eq!(journal.active_count(), 1, "2 Completed -> 1 active");
        assert_eq!(journal.terminal_count(), 2, "2 Completed -> 2 terminal");

        // Complete r3.
        journal.record_completed(&r3).unwrap();
        assert_eq!(journal.active_count(), 0, "all Completed -> 0 active");
        assert_eq!(journal.terminal_count(), 3, "3 Completed -> 3 terminal");

        // Total entries = 3 (all terminal).
        assert_eq!(journal.len(), 3);
    }

    /// Verify that `active_count` is correct after replay, including
    /// crash-recovery Unknown classification.
    #[test]
    fn active_count_correct_after_replay() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-active-count-replay.journal");

        // Session 1: 2 Started, 1 Completed. Crash with 1 in-flight.
        let r1 = test_hash(0xF3);
        let r2 = test_hash(0xF4);
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&test_binding(r1, false)).unwrap();
            journal.record_completed(&r1).unwrap();
            journal.record_started(&test_binding(r2, false)).unwrap();
            // r2 remains Started; simulate crash.
        }

        // Session 2: replay. r1 is Completed (terminal), r2 is Unknown (active).
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.active_count(),
            1,
            "replay: 1 Unknown (r2) -> 1 active"
        );
        assert_eq!(
            journal.terminal_count(),
            1,
            "replay: 1 Completed (r1) -> 1 terminal"
        );
        assert_eq!(
            journal.query_state(&r2),
            EffectExecutionState::Unknown,
            "r2 must be Unknown after crash"
        );
    }

    // =========================================================================
    // TCK-00501 SEC-MAJOR-2: Terminal entry compaction
    // =========================================================================

    /// Verify that `prune_terminal_entries()` removes all terminal entries
    /// from the in-memory index while preserving active entries.
    #[test]
    fn prune_terminal_entries_removes_completed_preserves_active() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-prune.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        // Create 5 Started + Completed (terminal) entries.
        for i in 0..5u8 {
            let rid = test_hash(0xD0 + i);
            journal.record_started(&test_binding(rid, false)).unwrap();
            journal.record_completed(&rid).unwrap();
        }

        // Create 2 Started (active) entries.
        let active1 = test_hash(0xE0);
        let active2 = test_hash(0xE1);
        journal
            .record_started(&test_binding(active1, false))
            .unwrap();
        journal
            .record_started(&test_binding(active2, false))
            .unwrap();

        assert_eq!(journal.len(), 7, "5 terminal + 2 active = 7 total");
        assert_eq!(journal.active_count(), 2, "2 active entries");
        assert_eq!(journal.terminal_count(), 5, "5 terminal entries");

        // Prune terminal entries.
        let pruned = journal.prune_terminal_entries();
        assert_eq!(pruned, 5, "5 terminal entries pruned");
        assert_eq!(journal.len(), 2, "only 2 active entries remain");
        assert_eq!(journal.active_count(), 2, "active count unchanged");
        assert_eq!(journal.terminal_count(), 0, "terminal count zeroed");

        // Active entries still queryable.
        assert_eq!(journal.query_state(&active1), EffectExecutionState::Started);
        assert_eq!(journal.query_state(&active2), EffectExecutionState::Started);

        // Pruned terminal entries return NotStarted (not in index).
        assert_eq!(
            journal.query_state(&test_hash(0xD0)),
            EffectExecutionState::NotStarted
        );
    }

    /// Verify that `prune_terminal_entries()` is idempotent: calling it
    /// twice does not affect active entries or crash state.
    #[test]
    fn prune_terminal_entries_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-prune-idempotent.journal");
        let journal = FileBackedEffectJournal::open(&path).unwrap();

        // Create 3 Completed (terminal) and 1 Started (active).
        for i in 1..=3u8 {
            let rid = test_hash(0xC0 + i);
            journal.record_started(&test_binding(rid, false)).unwrap();
            journal.record_completed(&rid).unwrap();
        }
        let active = test_hash(0xCA);
        journal
            .record_started(&test_binding(active, false))
            .unwrap();

        // First prune: removes 3 terminal entries.
        let pruned1 = journal.prune_terminal_entries();
        assert_eq!(pruned1, 3);
        assert_eq!(journal.len(), 1);
        assert_eq!(journal.active_count(), 1);
        assert_eq!(journal.terminal_count(), 0);

        // Second prune: nothing to prune.
        let pruned2 = journal.prune_terminal_entries();
        assert_eq!(pruned2, 0);
        assert_eq!(journal.len(), 1);
        assert_eq!(journal.active_count(), 1);

        // Active entry still queryable.
        assert_eq!(journal.query_state(&active), EffectExecutionState::Started);
    }

    /// Verify that the `MAX_TERMINAL_ENTRIES` constant is reasonable and
    /// that replay compaction fires for small excess counts.
    #[test]
    fn replay_compaction_fires_on_excess_terminal_entries() {
        use std::fmt::Write as _;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-replay-compact.journal");

        // Write a journal file with MAX_TERMINAL_ENTRIES + 5 Completed entries
        // plus 1 active (Started without Completed).
        // Note: This test verifies the compaction code path fires; it uses
        // the real MAX_TERMINAL_ENTRIES constant.
        let mut content = String::new();
        let terminal_count = MAX_TERMINAL_ENTRIES + 5;
        for i in 1..=terminal_count {
            // Use blake3 to generate unique hashes for large index ranges
            // (test_hash_u16 only supports u16 range).
            let mut h = [0u8; 32];
            let hash_bytes = blake3::hash(&i.to_le_bytes());
            h.copy_from_slice(hash_bytes.as_bytes());
            // Ensure non-zero (blake3 output is never all-zero for any input).
            let rid = h;
            let binding = test_binding(rid, false);
            let hex_id = hex::encode(rid);
            let json = serde_json::to_string(&binding).unwrap();
            let _ = writeln!(content, "S {hex_id} {json}");
            let _ = writeln!(content, "C {hex_id}");
        }
        // One active entry.
        let active_rid = test_hash(0xFF);
        let active_binding = test_binding(active_rid, false);
        let active_hex = hex::encode(active_rid);
        let active_json = serde_json::to_string(&active_binding).unwrap();
        let _ = writeln!(content, "S {active_hex} {active_json}");

        std::fs::write(&path, content).unwrap();

        // Replay should compact terminal entries to MAX_TERMINAL_ENTRIES.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.active_count(),
            1,
            "active entry (Unknown after replay) must be preserved"
        );
        assert!(
            journal.terminal_count() <= MAX_TERMINAL_ENTRIES,
            "terminal entries must be at or below MAX_TERMINAL_ENTRIES after compaction: got {}",
            journal.terminal_count()
        );
        // Active entry is still present and classified as Unknown (crash).
        assert_eq!(
            journal.query_state(&active_rid),
            EffectExecutionState::Unknown,
            "active entry must remain as Unknown after compaction"
        );
    }

    /// Verify that `resolve_in_doubt` correctly updates active and terminal
    /// counters (Unknown -> `NotStarted` transitions active to terminal).
    #[test]
    fn resolve_in_doubt_updates_active_and_terminal_counts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-resolve-counts.journal");

        let request_id = test_hash(0xFA);
        let binding = test_binding(request_id, true); // idempotent

        // Session 1: Started, crash.
        {
            let journal = FileBackedEffectJournal::open(&path).unwrap();
            journal.record_started(&binding).unwrap();
        }

        // Session 2: Unknown -> resolve -> NotStarted.
        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(journal.active_count(), 1, "Unknown is active");
        assert_eq!(journal.terminal_count(), 0);

        let resolution = journal.resolve_in_doubt(&request_id, true).unwrap();
        assert!(matches!(
            resolution,
            InDoubtResolutionV1::AllowReExecution { .. }
        ));

        assert_eq!(
            journal.active_count(),
            0,
            "after resolve: Unknown->NotStarted, active decremented"
        );
        assert_eq!(
            journal.terminal_count(),
            1,
            "after resolve: Unknown->NotStarted, terminal incremented"
        );
    }

    // =========================================================================
    // BLOCKER FIX: Runtime terminal pruning in record_completed
    // =========================================================================

    /// Verify that `record_completed` triggers automatic terminal entry
    /// pruning when terminal entries exceed `MAX_TERMINAL_ENTRIES`. This
    /// prevents unbounded in-memory growth during long-running daemon
    /// sessions that process many requests.
    #[test]
    fn record_completed_triggers_terminal_pruning() {
        use std::fmt::Write as _;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-runtime-pruning.journal");

        // Pre-populate journal file with MAX_TERMINAL_ENTRIES completed
        // entries, then open and complete one more to trigger pruning.
        let mut content = String::new();
        for i in 1..=MAX_TERMINAL_ENTRIES {
            let mut h = [0u8; 32];
            let hash_bytes = blake3::hash(&i.to_le_bytes());
            h.copy_from_slice(hash_bytes.as_bytes());
            let rid = h;
            let binding = test_binding(rid, false);
            let hex_id = hex::encode(rid);
            let json = serde_json::to_string(&binding).unwrap();
            let _ = writeln!(content, "S {hex_id} {json}");
            let _ = writeln!(content, "C {hex_id}");
        }
        // Add one active entry that we'll complete at runtime.
        let active_rid = test_hash(0xFB);
        let active_binding = test_binding(active_rid, false);
        let active_hex = hex::encode(active_rid);
        let active_json = serde_json::to_string(&active_binding).unwrap();
        let _ = writeln!(content, "S {active_hex} {active_json}");

        std::fs::write(&path, content).unwrap();

        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert_eq!(
            journal.active_count(),
            1,
            "one active entry (Unknown after replay)"
        );
        // Terminal entries may be at or below MAX_TERMINAL_ENTRIES after
        // replay compaction.
        assert!(
            journal.terminal_count() <= MAX_TERMINAL_ENTRIES,
            "replay should have compacted terminal entries"
        );

        // Complete the active entry, pushing terminal_count over the limit.
        // Note: The entry is in Unknown state after replay, but we need it
        // in Started state to complete it. Let's resolve it first and then
        // re-start and complete it.
        // Actually, for simplicity let's just create a fresh journal with
        // a known number of terminal entries already at the limit.
        drop(journal);

        // Simpler approach: open a fresh journal, add entries to just below
        // the limit, then complete one more to trigger pruning.
        let dir2 = TempDir::new().unwrap();
        let path2 = dir2.path().join("effect-runtime-pruning2.journal");
        let journal2 = FileBackedEffectJournal::open(&path2).unwrap();

        // Fill up terminal entries to exactly MAX_TERMINAL_ENTRIES.
        for i in 1..=MAX_TERMINAL_ENTRIES {
            let mut h = [0u8; 32];
            let hash_bytes = blake3::hash(&i.to_le_bytes());
            h.copy_from_slice(hash_bytes.as_bytes());
            let rid = h;
            journal2.record_started(&test_binding(rid, false)).unwrap();
            journal2.record_completed(&rid).unwrap();
        }
        assert_eq!(
            journal2.terminal_count(),
            MAX_TERMINAL_ENTRIES,
            "terminal count should be at MAX_TERMINAL_ENTRIES"
        );

        // Start and complete one more — this should trigger pruning.
        let trigger_rid = test_hash(0xFC);
        journal2
            .record_started(&test_binding(trigger_rid, false))
            .unwrap();
        journal2.record_completed(&trigger_rid).unwrap();

        // Terminal count should be at or below MAX_TERMINAL_ENTRIES after
        // automatic pruning.
        assert!(
            journal2.terminal_count() <= MAX_TERMINAL_ENTRIES,
            "record_completed must trigger pruning when terminal entries exceed limit: got {}",
            journal2.terminal_count()
        );
        assert_eq!(journal2.active_count(), 0, "no active entries remain");
    }

    // =========================================================================
    // BLOCKER FIX: Inline replay compaction prevents OOM
    // =========================================================================

    /// Verify that inline compaction during replay keeps the in-memory
    /// entry count bounded. Without inline compaction, replaying a journal
    /// with millions of terminal entries would accumulate them all in the
    /// `HashMap` before the post-replay compaction pass, causing OOM.
    #[test]
    fn replay_inline_compaction_bounds_memory() {
        use std::fmt::Write as _;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("effect-inline-compact.journal");

        // Write a journal with 2x MAX_TERMINAL_ENTRIES completed entries.
        // With inline compaction, the in-memory map should never grow
        // beyond MAX_TERMINAL_ENTRIES + a small delta.
        let count = MAX_TERMINAL_ENTRIES * 2;
        let mut content = String::new();
        for i in 1..=count {
            let mut h = [0u8; 32];
            let hash_bytes = blake3::hash(&i.to_le_bytes());
            h.copy_from_slice(hash_bytes.as_bytes());
            let rid = h;
            let binding = test_binding(rid, false);
            let hex_id = hex::encode(rid);
            let json = serde_json::to_string(&binding).unwrap();
            let _ = writeln!(content, "S {hex_id} {json}");
            let _ = writeln!(content, "C {hex_id}");
        }

        std::fs::write(&path, content).unwrap();

        let journal = FileBackedEffectJournal::open(&path).unwrap();
        assert!(
            journal.terminal_count() <= MAX_TERMINAL_ENTRIES,
            "after replay with inline compaction, terminal entries must be bounded: got {}",
            journal.terminal_count()
        );
        assert_eq!(
            journal.active_count(),
            0,
            "no active entries in all-completed journal"
        );
    }
}
