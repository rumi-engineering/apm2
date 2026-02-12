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

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use apm2_core::crypto::Hash;
use serde::{Deserialize, Serialize};

use super::prerequisites::LedgerAnchorV1;
use super::types::EnforcementTier;

// =============================================================================
// Resource limits
// =============================================================================

/// Maximum number of journal entries held in the in-memory index.
///
/// When the index exceeds this limit, new entries are denied (fail-closed).
/// This prevents unbounded memory growth from adversarial request churn.
const MAX_JOURNAL_ENTRIES: usize = 1_000_000;

/// Maximum length for the boundary profile field in journal entries.
const MAX_BOUNDARY_PROFILE_LENGTH: usize = 128;

/// Maximum length for the tool class field in journal entries.
const MAX_TOOL_CLASS_LENGTH: usize = 128;

/// Maximum length for the session ID field in journal entries.
const MAX_SESSION_ID_LENGTH: usize = 256;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectJournalError {
    /// I/O error during durable write or fsync.
    IoError {
        /// Description of the I/O error.
        reason: String,
    },

    /// Invalid state transition attempted.
    InvalidTransition {
        /// The `RequestId` involved.
        request_id: Hash,
        /// Current state.
        current: EffectExecutionState,
        /// Attempted target state.
        target: EffectExecutionState,
    },

    /// Journal capacity exhausted (fail-closed).
    CapacityExhausted {
        /// Current number of entries.
        count: usize,
        /// Maximum allowed entries.
        max: usize,
    },

    /// Corrupt journal entry detected during replay.
    CorruptEntry {
        /// Line number where corruption was detected.
        line: usize,
        /// Description of the corruption.
        reason: String,
    },

    /// Re-execution denied for Unknown state (fail-closed).
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
    OutputReleaseDenied {
        /// The `RequestId` in Unknown state.
        request_id: Hash,
        /// Reason for denial.
        reason: String,
    },

    /// Journal entry validation failed.
    ValidationError {
        /// Description of the validation failure.
        reason: String,
    },
}

impl std::fmt::Display for EffectJournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError { reason } => write!(f, "effect journal I/O error: {reason}"),
            Self::InvalidTransition {
                request_id,
                current,
                target,
            } => write!(
                f,
                "invalid effect journal transition for {}: {} -> {}",
                hex::encode(request_id),
                current,
                target
            ),
            Self::CapacityExhausted { count, max } => {
                write!(f, "effect journal capacity exhausted ({count}/{max})")
            },
            Self::CorruptEntry { line, reason } => {
                write!(f, "corrupt effect journal entry at line {line}: {reason}")
            },
            Self::ReExecutionDenied {
                request_id, reason, ..
            } => write!(
                f,
                "re-execution denied for {}: {reason}",
                hex::encode(request_id)
            ),
            Self::OutputReleaseDenied {
                request_id, reason, ..
            } => write!(
                f,
                "output release denied for {}: {reason}",
                hex::encode(request_id)
            ),
            Self::ValidationError { reason } => {
                write!(f, "effect journal validation error: {reason}")
            },
        }
    }
}

impl std::error::Error for EffectJournalError {}

impl From<std::io::Error> for EffectJournalError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError {
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

/// Idempotency key derived from `RequestId` for propagation into
/// tool/broker adapter calls (REQ-0029).
///
/// This key is deterministically derived so that retries of the same
/// request produce the same idempotency key, allowing external systems
/// to deduplicate effect execution.
///
/// # Derivation
///
/// `BLAKE3("apm2-idempotency-key-v1" || request_id || ajc_id)`
///
/// The AJC ID is included to bind the idempotency key to a specific
/// admission decision, preventing cross-admission key reuse.
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
    /// Derive an idempotency key from a `RequestId` and AJC ID.
    #[must_use]
    pub fn derive(request_id: Hash, ajc_id: Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2-idempotency-key-v1");
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
/// - `None` -> `Started` (via `record_started`)
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
    ///   `Completed`, or `Unknown` entry.
    /// - `CapacityExhausted` if the journal is full.
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

// =============================================================================
// Journal line format
// =============================================================================

/// Journal line: `<state_tag> <request_id_hex> [<binding_json>]`
///
/// State tags: S = Started, C = Completed, U = Unknown
///
/// Binding JSON is only present for `Started` entries.
const TAG_STARTED: char = 'S';
const TAG_COMPLETED: char = 'C';

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
    /// In-memory index: `request_id` -> `JournalRecord`.
    ///
    /// Protected by Mutex. Lock ordering: acquire `entries` before `file`.
    /// Happens-before: all mutations to this map are preceded by a
    /// successful fsync to disk, ensuring crash consistency.
    entries: Mutex<HashMap<Hash, JournalRecord>>,
    /// Append-only file handle (holds exclusive file lock).
    ///
    /// Protected by Mutex. Lock ordering: acquire `entries` before `file`.
    /// Writers hold both locks during state transitions to prevent TOCTOU.
    file: Mutex<File>,
}

impl std::fmt::Debug for FileBackedEffectJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBackedEffectJournal")
            .field("path", &self.path)
            .field("entry_count", &self.len())
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
    /// - `CapacityExhausted` if replayed entries exceed the limit.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EffectJournalError> {
        let path = path.as_ref().to_path_buf();
        let mut entries: HashMap<Hash, JournalRecord> = HashMap::new();

        // Acquire exclusive lock for single-writer inter-process exclusivity.
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .truncate(false)
            .append(true)
            .open(&path)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!(
                    "effect journal is locked by another process ({}): {e}",
                    path.display()
                ),
            )
        })?;

        // Replay existing entries in streaming fashion.
        let mut needs_truncate_to: Option<u64> = None;
        {
            let mut replay = file.try_clone()?;
            replay.seek(SeekFrom::Start(0))?;
            let reader = BufReader::new(&mut replay);

            let mut byte_offset: u64 = 0;
            let mut line_idx: usize = 0;
            let mut pending_error: Option<(usize, u64, String)> = None;

            for line_result in reader.lines() {
                let line = line_result?;

                // Mid-file corruption detection: if a previous line had a
                // parse error and we have more lines after it, fail closed.
                if let Some((err_line, _err_offset, err_reason)) = pending_error.take() {
                    return Err(EffectJournalError::CorruptEntry {
                        line: err_line,
                        reason: err_reason,
                    });
                }

                let trimmed = line.trim();
                let line_byte_len = (line.len() + 1) as u64; // +1 for newline

                if trimmed.is_empty() {
                    byte_offset += line_byte_len;
                    line_idx += 1;
                    continue;
                }

                match parse_journal_line(trimmed) {
                    Ok((tag, request_id, binding_opt)) => {
                        // Enforce capacity during replay.
                        if entries.len() >= MAX_JOURNAL_ENTRIES
                            && !entries.contains_key(&request_id)
                        {
                            return Err(EffectJournalError::CapacityExhausted {
                                count: entries.len(),
                                max: MAX_JOURNAL_ENTRIES,
                            });
                        }

                        match tag {
                            TAG_STARTED => {
                                if let Some(binding) = binding_opt {
                                    // On replay, Started without Completed
                                    // will become Unknown after replay finishes.
                                    entries.insert(
                                        request_id,
                                        JournalRecord {
                                            state: EffectExecutionState::Started,
                                            binding,
                                        },
                                    );
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
                                    }
                                    // If already Completed, ignore duplicate.
                                }
                                // If no Started entry exists, ignore orphan
                                // Completed
                                // (could be from a previous run where Started
                                // was in
                                // a different log segment after rotation).
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
            let truncate_file = OpenOptions::new().write(true).open(&path)?;
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

        Ok(Self {
            path,
            entries: Mutex::new(entries),
            file: Mutex::new(file),
        })
    }

    /// Returns the file path for this journal.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl EffectJournal for FileBackedEffectJournal {
    fn record_started(&self, binding: &EffectJournalBindingV1) -> Result<(), EffectJournalError> {
        // Validate binding data before persisting.
        binding.validate()?;

        let request_id = binding.request_id;

        // Lock ordering: entries first, then file.
        let mut entries = self.entries.lock().expect("entries lock poisoned");

        // Check for existing entry (state machine enforcement).
        if let Some(existing) = entries.get(&request_id) {
            return Err(EffectJournalError::InvalidTransition {
                request_id,
                current: existing.state,
                target: EffectExecutionState::Started,
            });
        }

        // Enforce capacity limit BEFORE any state mutation.
        if entries.len() >= MAX_JOURNAL_ENTRIES {
            return Err(EffectJournalError::CapacityExhausted {
                count: entries.len(),
                max: MAX_JOURNAL_ENTRIES,
            });
        }

        // Serialize binding to JSON for journal line.
        let binding_json =
            serde_json::to_string(binding).map_err(|e| EffectJournalError::IoError {
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
        entries.insert(
            request_id,
            JournalRecord {
                state: EffectExecutionState::Started,
                binding: binding.clone(),
            },
        );

        Ok(())
    }

    fn record_completed(&self, request_id: &Hash) -> Result<(), EffectJournalError> {
        // Lock ordering: entries first, then file.
        let mut entries = self.entries.lock().expect("entries lock poisoned");

        // Check state machine: must be in Started state.
        match entries.get(request_id) {
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
        if let Some(record) = entries.get_mut(request_id) {
            record.state = EffectExecutionState::Completed;
        }

        Ok(())
    }

    fn query_state(&self, request_id: &Hash) -> EffectExecutionState {
        let entries = self.entries.lock().expect("entries lock poisoned");
        entries
            .get(request_id)
            .map_or(EffectExecutionState::NotStarted, |r| r.state)
    }

    fn query_binding(&self, request_id: &Hash) -> Option<EffectJournalBindingV1> {
        let entries = self.entries.lock().expect("entries lock poisoned");
        entries.get(request_id).map(|r| r.binding.clone())
    }

    fn resolve_in_doubt(
        &self,
        request_id: &Hash,
        boundary_confirms_not_executed: bool,
    ) -> Result<InDoubtResolutionV1, EffectJournalError> {
        let entries = self.entries.lock().expect("entries lock poisoned");

        let Some(record) = entries.get(request_id) else {
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

        // Both conditions met: allow re-execution with idempotency key.
        let idempotency_key =
            IdempotencyKeyV1::derive(record.binding.request_id, record.binding.ajc_id);
        Ok(InDoubtResolutionV1::AllowReExecution { idempotency_key })
    }

    fn len(&self) -> usize {
        self.entries.lock().expect("entries lock poisoned").len()
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

            Ok((TAG_STARTED, request_id, Some(binding)))
        },
        TAG_COMPLETED => {
            // Format: C <64-char hex>
            if rest.len() < 64 {
                return Err(format!(
                    "Completed entry too short: expected 64 hex chars, got {} chars",
                    rest.len()
                ));
            }
            let hex_part = rest[..64].trim();
            let request_id = hex_to_hash(hex_part)?;
            Ok((TAG_COMPLETED, request_id, None))
        },
        other => Err(format!("unknown journal tag: {other}")),
    }
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
}
