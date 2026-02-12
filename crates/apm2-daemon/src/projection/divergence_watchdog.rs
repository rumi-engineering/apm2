// AGENT-AUTHORED (TCK-00213)
//! Divergence watchdog for the FAC (Forge Admission Cycle).
//!
//! The watchdog is wired into the daemon runtime via `main.rs`, where a
//! background task periodically calls `check_divergence` and emits defects.
//!
//! This module implements the [`DivergenceWatchdog`] which monitors for
//! divergence between the ledger's merge receipts and the external trunk HEAD.
//! When divergence is detected, it emits an [`InterventionFreeze`] to halt
//! all new admissions until adjudication.
//!
//! # Security Model
//!
//! - **Divergence detection is critical**: Any external modification of the
//!   trunk triggers an immediate freeze to prevent inconsistent state
//! - **Freeze enforcement is strict**: Frozen repos reject all new admissions
//!   with `REPO_FROZEN` error
//! - **Unfreeze requires adjudication**: Cannot bypass the freeze mechanism
//! - **Signed events**: All freeze/unfreeze events are cryptographically signed
//!   for non-repudiation
//!
//! # RFC-0015: FAC Divergence Watchdog
//!
//! Per RFC-0015, the divergence watchdog:
//!
//! 1. Polls the external trunk HEAD at configurable intervals
//! 2. Compares against the latest `MergeReceipt` in the ledger
//! 3. On divergence: emits `DefectRecord(PROJECTION_DIVERGENCE)`
//! 4. Emits `InterventionFreeze` to halt admissions
//! 5. Requires adjudication-based unfreeze
//!
//! # Freeze Scopes
//!
//! - `Repository`: Freeze applies to a specific repository
//! - `Work`: Freeze applies to a specific work item
//! - `Namespace`: Freeze applies to all repositories in a namespace
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_core::crypto::Signer;
//! use apm2_daemon::projection::divergence_watchdog::{
//!     DivergenceWatchdog, DivergenceWatchdogConfig, FreezeScope,
//! };
//!
//! let signer = Signer::generate();
//! let config = DivergenceWatchdogConfig::new("my-repo")
//!     .with_poll_interval(Duration::from_secs(30));
//! let watchdog = DivergenceWatchdog::new(signer, config);
//!
//! // Check for divergence
//! let merge_receipt_head = [0x42; 32];
//! let external_head = [0x99; 32];
//!
//! if let Some(freeze) = watchdog.check_divergence(merge_receipt_head, external_head)? {
//!     // Divergence detected - freeze event emitted
//!     println!("Freeze ID: {}", freeze.freeze_id());
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apm2_core::crypto::{Hash, Signature, Signer, VerifyingKey, parse_verifying_key};
use apm2_core::events::{
    DefectRecorded, DefectSource, InterventionFreeze as ProtoInterventionFreeze,
    InterventionResolutionType as ProtoResolutionType, InterventionScope as ProtoScope,
    InterventionUnfreeze as ProtoInterventionUnfreeze, TimeEnvelopeRef,
};
use apm2_core::fac::{
    AuthorityKeyBindingV1, ChannelIdentitySnapshotV1, INTERVENTION_FREEZE_PREFIX,
    INTERVENTION_UNFREEZE_PREFIX, ProjectionChannel, ProjectionCompromiseSignalV1,
    ProjectionReplayReceiptV1, ProjectionSurfaceType, ReconstructedProjectionState,
    ReplaySequenceBoundsV1, SourceTrustSnapshotV1, detect_projection_divergence,
    quarantine_channel, reconstruct_projection_state, sign_with_domain, verify_with_domain,
};
use apm2_holon::defect::{DefectContext, DefectRecord, DefectSeverity, DefectSignal, SignalType};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for string fields to prevent denial-of-service attacks.
pub const MAX_STRING_LENGTH: usize = 1024;

/// Maximum length for freeze IDs (CTR-2602 compliance).
pub const MAX_FREEZE_ID_LENGTH: usize = 256;

/// Maximum length for defect IDs (CTR-2602 compliance).
pub const MAX_DEFECT_ID_LENGTH: usize = 256;

/// Maximum length for actor IDs (CTR-2602 compliance).
pub const MAX_ACTOR_ID_LENGTH: usize = 256;

/// Domain separator for signed temporal authority envelopes.
const TIME_AUTHORITY_ENVELOPE_PREFIX: &[u8] = b"TIME_AUTHORITY_ENVELOPE:";

/// Signed temporal envelope lifetime for compromise/quarantine decisions.
const DEFAULT_TIME_AUTHORITY_TTL: Duration = Duration::from_secs(300);

/// Maximum supported endpoint canonical identifier length.
const MAX_ENDPOINT_CANONICAL_ID_LENGTH: usize = 1024;

/// Maximum supported endpoint fingerprint length.
const MAX_ENDPOINT_FINGERPRINT_LENGTH: usize = 512;

/// Maximum supported temporal envelope reference length.
const MAX_TIME_ENVELOPE_REF_LENGTH: usize = 1024;

/// Maximum supported trusted authority bindings in watchdog config.
const MAX_TRUSTED_AUTHORITY_BINDINGS: usize = 64;

/// Prefix reserved for fail-closed precautionary freezes.
const PRECAUTIONARY_FREEZE_ID_PREFIX: &str = "precautionary-";

// =============================================================================
// Type-Safe Identifiers (CTR-2602)
// =============================================================================

/// A type-safe wrapper for freeze identifiers.
///
/// Per CTR-2602 (Type-Safe Identifiers): Critical domain identifiers should
/// use newtypes rather than raw `String`s to prevent accidental misuse and
/// enable compile-time type checking.
///
/// # Validation
///
/// - Must not be empty
/// - Must not exceed [`MAX_FREEZE_ID_LENGTH`] bytes
/// - Must contain only ASCII printable characters (0x20-0x7E)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FreezeId(String);

impl FreezeId {
    /// Creates a new `FreezeId` after validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is empty, too long, or contains invalid
    /// characters.
    pub fn new(id: impl Into<String>) -> Result<Self, DivergenceError> {
        let id = id.into();
        Self::validate(&id)?;
        Ok(Self(id))
    }

    /// Returns the ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates the ID format.
    fn validate(id: &str) -> Result<(), DivergenceError> {
        if id.is_empty() {
            return Err(DivergenceError::InvalidConfiguration(
                "freeze_id cannot be empty".to_string(),
            ));
        }
        if id.len() > MAX_FREEZE_ID_LENGTH {
            return Err(DivergenceError::StringTooLong {
                field: "freeze_id",
                actual: id.len(),
                max: MAX_FREEZE_ID_LENGTH,
            });
        }
        if !id.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(DivergenceError::InvalidConfiguration(
                "freeze_id contains invalid characters".to_string(),
            ));
        }
        Ok(())
    }
}

impl TryFrom<String> for FreezeId {
    type Error = DivergenceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<FreezeId> for String {
    fn from(id: FreezeId) -> Self {
        id.0
    }
}

impl std::fmt::Display for FreezeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for FreezeId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A type-safe wrapper for defect identifiers.
///
/// Per CTR-2602 (Type-Safe Identifiers): Critical domain identifiers should
/// use newtypes rather than raw `String`s to prevent accidental misuse.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DefectId(String);

impl DefectId {
    /// Creates a new `DefectId` after validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is empty, too long, or contains invalid
    /// characters.
    pub fn new(id: impl Into<String>) -> Result<Self, DivergenceError> {
        let id = id.into();
        Self::validate(&id)?;
        Ok(Self(id))
    }

    /// Returns the ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates the ID format.
    fn validate(id: &str) -> Result<(), DivergenceError> {
        if id.is_empty() {
            return Err(DivergenceError::InvalidConfiguration(
                "defect_id cannot be empty".to_string(),
            ));
        }
        if id.len() > MAX_DEFECT_ID_LENGTH {
            return Err(DivergenceError::StringTooLong {
                field: "defect_id",
                actual: id.len(),
                max: MAX_DEFECT_ID_LENGTH,
            });
        }
        if !id.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(DivergenceError::InvalidConfiguration(
                "defect_id contains invalid characters".to_string(),
            ));
        }
        Ok(())
    }
}

impl TryFrom<String> for DefectId {
    type Error = DivergenceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DefectId> for String {
    fn from(id: DefectId) -> Self {
        id.0
    }
}

impl std::fmt::Display for DefectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for DefectId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A type-safe wrapper for actor identifiers.
///
/// Per CTR-2602 (Type-Safe Identifiers): Critical domain identifiers should
/// use newtypes rather than raw `String`s to prevent accidental misuse.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ActorId(String);

impl ActorId {
    /// Creates a new `ActorId` after validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the ID is empty, too long, or contains invalid
    /// characters.
    pub fn new(id: impl Into<String>) -> Result<Self, DivergenceError> {
        let id = id.into();
        Self::validate(&id)?;
        Ok(Self(id))
    }

    /// Returns the ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates the ID format.
    fn validate(id: &str) -> Result<(), DivergenceError> {
        if id.is_empty() {
            return Err(DivergenceError::InvalidConfiguration(
                "actor_id cannot be empty".to_string(),
            ));
        }
        if id.len() > MAX_ACTOR_ID_LENGTH {
            return Err(DivergenceError::StringTooLong {
                field: "actor_id",
                actual: id.len(),
                max: MAX_ACTOR_ID_LENGTH,
            });
        }
        if !id.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(DivergenceError::InvalidConfiguration(
                "actor_id contains invalid characters".to_string(),
            ));
        }
        Ok(())
    }
}

impl TryFrom<String> for ActorId {
    type Error = DivergenceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ActorId> for String {
    fn from(id: ActorId) -> Self {
        id.0
    }
}

impl std::fmt::Display for ActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ActorId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// DivergenceResult
// =============================================================================

/// Result of a divergence detection operation.
///
/// Contains both the `InterventionFreeze` event and the associated
/// `DefectRecord(PROJECTION_DIVERGENCE)` for emission to the ledger.
#[derive(Debug, Clone)]
pub struct DivergenceResult {
    /// The freeze event to emit.
    pub freeze: InterventionFreeze,
    /// The defect record to emit.
    pub defect: DefectRecord,
    /// The defect event to emit to the ledger.
    pub defect_event: DefectRecorded,
    /// Signed compromise signal bound to source/sink snapshots.
    pub compromise_signal: ProjectionCompromiseSignalV1,
    /// Source trust snapshot (CAS+ledger rooted expectation).
    pub source_trust_snapshot: SourceTrustSnapshotV1,
    /// Sink identity snapshot (observed projection identity).
    pub sink_identity_snapshot: ChannelIdentitySnapshotV1,
    /// Durable replay receipt for reconstruction checks.
    pub replay_receipt: ProjectionReplayReceiptV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedTemporalAuthority {
    envelope: TimeAuthorityEnvelopeV1,
    time_authority_ref: Hash,
}

/// Concrete sink endpoint evidence bound into compromise snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkEndpointEvidenceV1 {
    /// Canonical sink endpoint identifier (URL or hostname form).
    pub endpoint_canonical_id: String,
    /// Endpoint key fingerprint. When `endpoint_identity_verified` is true,
    /// this is derived from remote endpoint identity (TLS SPKI/SSH host key).
    /// When false, this is derived from local signer key material as a
    /// placeholder binding.
    pub endpoint_key_fingerprint: String,
    /// Key epoch for endpoint key rotation continuity.
    pub key_epoch: u64,
    /// Whether the endpoint key fingerprint was verified against remote
    /// endpoint identity material. When `false`, the fingerprint is derived
    /// from local signer key material as a placeholder binding.
    pub endpoint_identity_verified: bool,
}

/// Signed temporal authority envelope for compromise and recovery decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeAuthorityEnvelopeV1 {
    /// HTF envelope reference.
    pub time_envelope_ref: String,
    /// Declared HTF decision window reference.
    #[serde(with = "serde_bytes")]
    pub window_ref: Hash,
    /// Issuance time for this temporal authority assertion.
    pub issued_at_ns: u64,
    /// Expiration time for this temporal authority assertion.
    pub expires_at_ns: u64,
    /// Signer actor identity.
    pub signer_actor_id: String,
    /// Signer public key bytes.
    #[serde(with = "serde_bytes")]
    pub signer_key: [u8; 32],
    /// Signature over canonical bytes.
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl TimeAuthorityEnvelopeV1 {
    #[allow(clippy::too_many_arguments)]
    fn create_signed(
        time_envelope_ref: impl Into<String>,
        window_ref: Hash,
        issued_at_ns: u64,
        expires_at_ns: u64,
        signer_actor_id: impl Into<String>,
        signer: &Signer,
    ) -> Result<Self, DivergenceError> {
        let time_envelope_ref = time_envelope_ref.into();
        let signer_actor_id = signer_actor_id.into();

        if time_envelope_ref.trim().is_empty() {
            return Err(DivergenceError::MissingTemporalAuthority(
                "time_envelope_ref".to_string(),
            ));
        }
        if time_envelope_ref.len() > MAX_TIME_ENVELOPE_REF_LENGTH {
            return Err(DivergenceError::StringTooLong {
                field: "time_envelope_ref",
                actual: time_envelope_ref.len(),
                max: MAX_TIME_ENVELOPE_REF_LENGTH,
            });
        }
        if signer_actor_id.trim().is_empty() {
            return Err(DivergenceError::MissingField(
                "time_authority_signer_actor_id",
            ));
        }
        if signer_actor_id.len() > MAX_ACTOR_ID_LENGTH {
            return Err(DivergenceError::StringTooLong {
                field: "time_authority_signer_actor_id",
                actual: signer_actor_id.len(),
                max: MAX_ACTOR_ID_LENGTH,
            });
        }
        if window_ref.iter().all(|byte| *byte == 0) {
            return Err(DivergenceError::MissingTemporalAuthority(
                "window_ref".to_string(),
            ));
        }
        if expires_at_ns <= issued_at_ns {
            return Err(DivergenceError::InvalidTemporalAuthority(
                "expires_at_ns must be greater than issued_at_ns".to_string(),
            ));
        }

        let mut envelope = Self {
            time_envelope_ref,
            window_ref,
            issued_at_ns,
            expires_at_ns,
            signer_actor_id,
            signer_key: signer.public_key_bytes(),
            signature: [0u8; 64],
        };
        let signature = sign_with_domain(
            signer,
            TIME_AUTHORITY_ENVELOPE_PREFIX,
            &envelope.canonical_bytes(),
        );
        envelope.signature = signature.to_bytes();
        Ok(envelope)
    }

    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.time_envelope_ref.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.time_envelope_ref.as_bytes());
        bytes.extend_from_slice(&self.window_ref);
        bytes.extend_from_slice(&self.issued_at_ns.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_ns.to_be_bytes());
        bytes.extend_from_slice(&(self.signer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.signer_actor_id.as_bytes());
        bytes.extend_from_slice(&self.signer_key);
        bytes
    }

    fn validate_signature(
        &self,
        trusted_time_authority_bindings: &[AuthorityKeyBindingV1],
    ) -> Result<(), DivergenceError> {
        if trusted_time_authority_bindings.is_empty() {
            return Err(DivergenceError::MissingTemporalAuthority(
                "trusted_time_authority_bindings".to_string(),
            ));
        }

        let actor_bindings = trusted_time_authority_bindings
            .iter()
            .filter(|binding| binding.actor_id == self.signer_actor_id)
            .collect::<Vec<_>>();
        if actor_bindings.is_empty() {
            return Err(DivergenceError::InvalidTemporalAuthority(format!(
                "unknown time authority actor {}",
                self.signer_actor_id
            )));
        }
        if !actor_bindings
            .iter()
            .any(|binding| bool::from(binding.verifying_key.ct_eq(&self.signer_key)))
        {
            return Err(DivergenceError::InvalidTemporalAuthority(format!(
                "untrusted key for time authority actor {}",
                self.signer_actor_id
            )));
        }

        let key = parse_verifying_key(&self.signer_key)
            .map_err(|error| DivergenceError::InvalidTemporalAuthority(error.to_string()))?;
        let signature = Signature::from_bytes(&self.signature);
        verify_with_domain(
            &key,
            TIME_AUTHORITY_ENVELOPE_PREFIX,
            &self.canonical_bytes(),
            &signature,
        )
        .map_err(|error| DivergenceError::InvalidTemporalAuthority(error.to_string()))
    }

    fn validate_freshness(&self, now_ns: u64) -> Result<(), DivergenceError> {
        if self.expires_at_ns <= self.issued_at_ns {
            return Err(DivergenceError::InvalidTemporalAuthority(
                "expires_at_ns must be greater than issued_at_ns".to_string(),
            ));
        }
        if now_ns < self.issued_at_ns {
            return Err(DivergenceError::InvalidTemporalAuthority(format!(
                "time authority envelope issued in the future: now={now_ns}, issued_at={}",
                self.issued_at_ns
            )));
        }
        if now_ns > self.expires_at_ns {
            return Err(DivergenceError::StaleTemporalAuthority {
                now_ns,
                expires_at_ns: self.expires_at_ns,
            });
        }
        Ok(())
    }

    #[must_use]
    fn derive_time_authority_ref(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.time_authority_envelope_ref.v1");
        hasher.update(&self.canonical_bytes());
        hasher.update(&self.signature);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug, Clone)]
struct ProjectionRecoveryState {
    channel_id: String,
    source_snapshot: SourceTrustSnapshotV1,
    sink_snapshot: ChannelIdentitySnapshotV1,
    receipts: Vec<ProjectionReplayReceiptV1>,
    replay_sequence_bounds: ReplaySequenceBoundsV1,
    time_authority_envelope: TimeAuthorityEnvelopeV1,
    has_durable_provenance: bool,
    durable_evidence_digest: Option<Hash>,
}

/// Default poll interval for divergence checks (30 seconds).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum poll interval to prevent excessive resource usage.
pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Maximum poll interval to ensure timely detection.
pub const MAX_POLL_INTERVAL: Duration = Duration::from_secs(3600);

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during divergence watchdog operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DivergenceError {
    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Projection compromise validation failed.
    #[error("projection compromise validation failed: {0}")]
    ProjectionCompromiseValidationFailed(String),

    /// The freeze signature is invalid.
    #[error("invalid freeze signature: {0}")]
    InvalidFreezeSignature(String),

    /// The unfreeze signature is invalid.
    #[error("invalid unfreeze signature: {0}")]
    InvalidUnfreezeSignature(String),

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// String field exceeds maximum length.
    #[error("string field {field} exceeds max length: {actual} > {max}")]
    StringTooLong {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual length of the string.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Repository is frozen.
    #[error("repository is frozen: {freeze_id}")]
    RepoFrozen {
        /// The freeze ID.
        freeze_id: String,
    },

    /// Freeze not found.
    #[error("freeze not found: {freeze_id}")]
    FreezeNotFound {
        /// The freeze ID that was not found.
        freeze_id: String,
    },

    /// Invalid resolution type.
    #[error("invalid resolution type for unfreeze")]
    InvalidResolutionType,

    /// Adjudication required but not provided.
    #[error("adjudication ID required for resolution type")]
    AdjudicationRequired,

    /// Scope is already frozen.
    #[error("scope already frozen: {scope_value} (freeze_id: {existing_freeze_id})")]
    ScopeAlreadyFrozen {
        /// The scope value that is already frozen.
        scope_value: String,
        /// The existing freeze ID for this scope.
        existing_freeze_id: String,
    },

    /// Replay recovery failed during post-containment unfreeze checks.
    #[error("projection replay recovery failed: {0}")]
    ProjectionRecoveryFailed(String),

    /// Replay recovery state exists but has no durable provenance proof.
    #[error(
        "recovery state exists but lacks durable provenance — unfreeze requires CAS/ledger-backed replay evidence (freeze_id: {freeze_id})"
    )]
    ProjectionRecoveryNotDurable {
        /// Freeze identifier requiring durable recovery provenance.
        freeze_id: String,
    },

    /// Temporal authority envelope is missing for a compromise/recovery
    /// decision.
    #[error("temporal authority envelope missing: {0}")]
    MissingTemporalAuthority(String),

    /// Temporal authority envelope verification failed.
    #[error("temporal authority envelope invalid: {0}")]
    InvalidTemporalAuthority(String),

    /// Temporal authority envelope is stale for the decision window.
    #[error("temporal authority envelope stale: now={now_ns}, expires_at={expires_at_ns}")]
    StaleTemporalAuthority {
        /// Current decision timestamp.
        now_ns: u64,
        /// Envelope expiration timestamp.
        expires_at_ns: u64,
    },
}

// =============================================================================
// FreezeScope
// =============================================================================

/// Scope of an intervention freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FreezeScope {
    /// Freeze applies to a specific repository.
    Repository,
    /// Freeze applies to a specific work item.
    Work,
    /// Freeze applies to all repositories in a namespace.
    Namespace,
}

impl FreezeScope {
    /// Returns the scope as a canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Repository => b"REPOSITORY",
            Self::Work => b"WORK",
            Self::Namespace => b"NAMESPACE",
        }
    }

    /// Returns the scope as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Repository => "REPOSITORY",
            Self::Work => "WORK",
            Self::Namespace => "NAMESPACE",
        }
    }
}

// =============================================================================
// ResolutionType
// =============================================================================

/// Resolution type for intervention unfreeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ResolutionType {
    /// Resolved through adjudication process.
    Adjudication,
    /// Resolved by manual operator intervention.
    Manual,
    /// Resolved by rollback to last known good state.
    Rollback,
    /// Resolved by accepting the divergent state as new baseline.
    AcceptDivergence,
}

impl ResolutionType {
    /// Returns the resolution type as a canonical byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Adjudication => b"ADJUDICATION",
            Self::Manual => b"MANUAL",
            Self::Rollback => b"ROLLBACK",
            Self::AcceptDivergence => b"ACCEPT_DIVERGENCE",
        }
    }

    /// Returns the resolution type as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Adjudication => "ADJUDICATION",
            Self::Manual => "MANUAL",
            Self::Rollback => "ROLLBACK",
            Self::AcceptDivergence => "ACCEPT_DIVERGENCE",
        }
    }

    /// Returns whether this resolution type requires an adjudication ID.
    ///
    /// # Unfreeze Policy: Manual and Rollback Resolution Types
    ///
    /// The `Manual` and `Rollback` resolution types intentionally bypass the
    /// adjudication ID requirement. This is a deliberate design decision for
    /// operator emergencies:
    ///
    /// - **`Manual`**: Used when an operator needs to immediately unfreeze a
    ///   repository to restore operations. This should only be used in
    ///   emergency situations where waiting for formal adjudication would cause
    ///   unacceptable operational impact. Manual unfreezes create an audit
    ///   trail but do not require a prior adjudication decision.
    ///
    /// - **`Rollback`**: Used when the divergence is resolved by rolling back
    ///   the external trunk to match the ledger's expected state. Since the
    ///   rollback itself is the resolution action (rather than accepting either
    ///   the ledger or external state), no adjudication decision is needed.
    ///
    /// Both resolution types still require:
    /// - A valid signature from an authorized gate actor
    /// - The freeze to exist in the registry
    /// - A time envelope reference for temporal authority
    ///
    /// All unfreeze events (including Manual and Rollback) are recorded in the
    /// ledger for audit purposes.
    #[must_use]
    pub const fn requires_adjudication(&self) -> bool {
        matches!(self, Self::Adjudication | Self::AcceptDivergence)
    }
}

// =============================================================================
// Proto Conversion Traits
// =============================================================================
//
// These conversions enable seamless translation between the rich domain types
// (defined in this module) and the wire format types (Protocol Buffer generated
// in apm2-core). The manual types provide ergonomic Rust APIs while the proto
// types are used for serialization/transmission.

impl From<FreezeScope> for ProtoScope {
    fn from(scope: FreezeScope) -> Self {
        match scope {
            FreezeScope::Repository => Self::Repository,
            FreezeScope::Work => Self::Work,
            FreezeScope::Namespace => Self::Namespace,
        }
    }
}

impl TryFrom<ProtoScope> for FreezeScope {
    type Error = DivergenceError;

    fn try_from(scope: ProtoScope) -> Result<Self, Self::Error> {
        match scope {
            ProtoScope::Repository => Ok(Self::Repository),
            ProtoScope::Work => Ok(Self::Work),
            ProtoScope::Namespace => Ok(Self::Namespace),
            ProtoScope::Unspecified => Err(DivergenceError::InvalidConfiguration(
                "unspecified intervention scope".to_string(),
            )),
        }
    }
}

impl From<FreezeScope> for i32 {
    fn from(scope: FreezeScope) -> Self {
        ProtoScope::from(scope) as Self
    }
}

impl TryFrom<i32> for FreezeScope {
    type Error = DivergenceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let proto_scope = ProtoScope::try_from(value).map_err(|_| {
            DivergenceError::InvalidConfiguration(format!("invalid scope value: {value}"))
        })?;
        Self::try_from(proto_scope)
    }
}

impl From<ResolutionType> for ProtoResolutionType {
    fn from(resolution: ResolutionType) -> Self {
        match resolution {
            ResolutionType::Adjudication => Self::InterventionResolutionAdjudication,
            ResolutionType::Manual => Self::InterventionResolutionManual,
            ResolutionType::Rollback => Self::InterventionResolutionRollback,
            ResolutionType::AcceptDivergence => Self::InterventionResolutionAcceptDivergence,
        }
    }
}

impl TryFrom<ProtoResolutionType> for ResolutionType {
    type Error = DivergenceError;

    fn try_from(resolution: ProtoResolutionType) -> Result<Self, Self::Error> {
        match resolution {
            ProtoResolutionType::InterventionResolutionAdjudication => Ok(Self::Adjudication),
            ProtoResolutionType::InterventionResolutionManual => Ok(Self::Manual),
            ProtoResolutionType::InterventionResolutionRollback => Ok(Self::Rollback),
            ProtoResolutionType::InterventionResolutionAcceptDivergence => {
                Ok(Self::AcceptDivergence)
            },
            ProtoResolutionType::InterventionResolutionUnspecified => {
                Err(DivergenceError::InvalidResolutionType)
            },
        }
    }
}

impl From<ResolutionType> for i32 {
    fn from(resolution: ResolutionType) -> Self {
        ProtoResolutionType::from(resolution) as Self
    }
}

impl TryFrom<i32> for ResolutionType {
    type Error = DivergenceError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let proto_resolution = ProtoResolutionType::try_from(value).map_err(|_| {
            DivergenceError::InvalidConfiguration(format!("invalid resolution type value: {value}"))
        })?;
        Self::try_from(proto_resolution)
    }
}

impl From<&InterventionFreeze> for ProtoInterventionFreeze {
    fn from(freeze: &InterventionFreeze) -> Self {
        // Convert domain time_envelope_ref (String) to proto TimeEnvelopeRef.
        // Empty string maps to None; non-empty string stores raw UTF-8 bytes
        // in the proto `hash` field for lossless roundtrip.
        //
        // TCK-00469 FIX: Store original string as UTF-8 bytes (lossless).
        // Previous implementation hashed non-hex strings (e.g. "htf:tick:*"),
        // breaking canonical bytes and signature verification after roundtrip.
        let time_envelope_ref = if freeze.time_envelope_ref.is_empty() {
            None
        } else {
            Some(TimeEnvelopeRef {
                hash: freeze.time_envelope_ref.as_bytes().to_vec(),
            })
        };

        Self {
            freeze_id: freeze.freeze_id.clone(),
            scope: i32::from(freeze.scope),
            scope_value: freeze.scope_value.clone(),
            trigger_defect_id: freeze.trigger_defect_id.clone(),
            frozen_at: freeze.frozen_at,
            expected_trunk_head: freeze.expected_trunk_head.to_vec(),
            actual_trunk_head: freeze.actual_trunk_head.to_vec(),
            gate_actor_id: freeze.gate_actor_id.clone(),
            gate_signature: freeze.gate_signature.to_vec(),
            time_envelope_ref,
        }
    }
}

impl From<InterventionFreeze> for ProtoInterventionFreeze {
    fn from(freeze: InterventionFreeze) -> Self {
        Self::from(&freeze)
    }
}

impl TryFrom<&ProtoInterventionFreeze> for InterventionFreeze {
    type Error = DivergenceError;

    fn try_from(proto: &ProtoInterventionFreeze) -> Result<Self, Self::Error> {
        let scope = FreezeScope::try_from(proto.scope)?;

        let expected_trunk_head: [u8; 32] = proto
            .expected_trunk_head
            .as_slice()
            .try_into()
            .map_err(|_| {
                DivergenceError::InvalidConfiguration(format!(
                    "expected_trunk_head must be 32 bytes, got {}",
                    proto.expected_trunk_head.len()
                ))
            })?;

        let actual_trunk_head: [u8; 32] =
            proto.actual_trunk_head.as_slice().try_into().map_err(|_| {
                DivergenceError::InvalidConfiguration(format!(
                    "actual_trunk_head must be 32 bytes, got {}",
                    proto.actual_trunk_head.len()
                ))
            })?;

        let gate_signature: [u8; 64] =
            proto.gate_signature.as_slice().try_into().map_err(|_| {
                DivergenceError::InvalidConfiguration(format!(
                    "gate_signature must be 64 bytes, got {}",
                    proto.gate_signature.len()
                ))
            })?;

        // Convert proto time_envelope_ref (Option<TimeEnvelopeRef>) to domain
        // String. None maps to empty string; Some(TimeEnvelopeRef) recovers
        // the original UTF-8 string from the proto `hash` bytes (lossless).
        //
        // TCK-00469 FIX: Recover original UTF-8 string instead of hex-encoding.
        let time_envelope_ref = proto
            .time_envelope_ref
            .as_ref()
            .map(|ter| {
                String::from_utf8(ter.hash.clone()).map_err(|_| {
                    DivergenceError::InvalidConfiguration(
                        "time_envelope_ref contains invalid UTF-8".to_string(),
                    )
                })
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            freeze_id: proto.freeze_id.clone(),
            scope,
            scope_value: proto.scope_value.clone(),
            trigger_defect_id: proto.trigger_defect_id.clone(),
            frozen_at: proto.frozen_at,
            expected_trunk_head,
            actual_trunk_head,
            gate_actor_id: proto.gate_actor_id.clone(),
            gate_signature,
            time_envelope_ref,
        })
    }
}

impl TryFrom<ProtoInterventionFreeze> for InterventionFreeze {
    type Error = DivergenceError;

    fn try_from(proto: ProtoInterventionFreeze) -> Result<Self, Self::Error> {
        Self::try_from(&proto)
    }
}

impl From<&InterventionUnfreeze> for ProtoInterventionUnfreeze {
    fn from(unfreeze: &InterventionUnfreeze) -> Self {
        // Convert domain time_envelope_ref (String) to proto TimeEnvelopeRef.
        // Empty string maps to None; non-empty string stores raw UTF-8 bytes
        // in the proto `hash` field for lossless roundtrip.
        //
        // TCK-00469 FIX: Store original string as UTF-8 bytes (lossless).
        // Previous implementation hashed non-hex strings (e.g. "htf:tick:*"),
        // breaking canonical bytes and signature verification after roundtrip.
        let time_envelope_ref = if unfreeze.time_envelope_ref.is_empty() {
            None
        } else {
            Some(TimeEnvelopeRef {
                hash: unfreeze.time_envelope_ref.as_bytes().to_vec(),
            })
        };

        Self {
            freeze_id: unfreeze.freeze_id.clone(),
            resolution_type: i32::from(unfreeze.resolution_type),
            // Proto uses empty string for None (tagged encoding ensures distinct canonical bytes)
            adjudication_id: unfreeze.adjudication_id.clone().unwrap_or_default(),
            unfrozen_at: unfreeze.unfrozen_at,
            gate_actor_id: unfreeze.gate_actor_id.clone(),
            gate_signature: unfreeze.gate_signature.to_vec(),
            time_envelope_ref,
        }
    }
}

impl From<InterventionUnfreeze> for ProtoInterventionUnfreeze {
    fn from(unfreeze: InterventionUnfreeze) -> Self {
        Self::from(&unfreeze)
    }
}

impl TryFrom<&ProtoInterventionUnfreeze> for InterventionUnfreeze {
    type Error = DivergenceError;

    fn try_from(proto: &ProtoInterventionUnfreeze) -> Result<Self, Self::Error> {
        let resolution_type = ResolutionType::try_from(proto.resolution_type)?;

        let gate_signature: [u8; 64] =
            proto.gate_signature.as_slice().try_into().map_err(|_| {
                DivergenceError::InvalidConfiguration(format!(
                    "gate_signature must be 64 bytes, got {}",
                    proto.gate_signature.len()
                ))
            })?;

        // Convert empty string to None for adjudication_id
        let adjudication_id = if proto.adjudication_id.is_empty() {
            None
        } else {
            Some(proto.adjudication_id.clone())
        };

        // Convert proto time_envelope_ref (Option<TimeEnvelopeRef>) to domain
        // String. None maps to empty string; Some(TimeEnvelopeRef) recovers
        // the original UTF-8 string from the proto `hash` bytes (lossless).
        //
        // TCK-00469 FIX: Recover original UTF-8 string instead of hex-encoding.
        let time_envelope_ref = proto
            .time_envelope_ref
            .as_ref()
            .map(|ter| {
                String::from_utf8(ter.hash.clone()).map_err(|_| {
                    DivergenceError::InvalidConfiguration(
                        "time_envelope_ref contains invalid UTF-8".to_string(),
                    )
                })
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            freeze_id: proto.freeze_id.clone(),
            resolution_type,
            adjudication_id,
            unfrozen_at: proto.unfrozen_at,
            gate_actor_id: proto.gate_actor_id.clone(),
            gate_signature,
            time_envelope_ref,
        })
    }
}

impl TryFrom<ProtoInterventionUnfreeze> for InterventionUnfreeze {
    type Error = DivergenceError;

    fn try_from(proto: ProtoInterventionUnfreeze) -> Result<Self, Self::Error> {
        Self::try_from(&proto)
    }
}

// =============================================================================
// InterventionFreeze
// =============================================================================

/// An intervention freeze event emitted when divergence is detected.
///
/// This event is cryptographically signed and halts all new admissions
/// for the specified scope until adjudication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionFreeze {
    /// Unique identifier for this freeze event.
    pub freeze_id: String,
    /// Scope of the freeze.
    pub scope: FreezeScope,
    /// Value identifying the frozen scope.
    pub scope_value: String,
    /// ID of the `DefectRecord` that triggered this freeze.
    pub trigger_defect_id: String,
    /// Timestamp when the freeze was applied (Unix nanoseconds).
    pub frozen_at: u64,
    /// Expected trunk HEAD from the latest `MergeReceipt`.
    #[serde(with = "serde_bytes")]
    pub expected_trunk_head: [u8; 32],
    /// Actual trunk HEAD observed externally.
    #[serde(with = "serde_bytes")]
    pub actual_trunk_head: [u8; 32],
    /// Actor who detected the divergence and issued the freeze.
    pub gate_actor_id: String,
    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub gate_signature: [u8; 64],
    /// Reference to the time envelope for temporal authority.
    pub time_envelope_ref: String,
}

impl InterventionFreeze {
    /// Returns the freeze ID.
    #[must_use]
    pub fn freeze_id(&self) -> &str {
        &self.freeze_id
    }

    /// Returns the canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let capacity = 4 + self.freeze_id.len()
            + 16  // scope (max)
            + 4 + self.scope_value.len()
            + 4 + self.trigger_defect_id.len()
            + 8   // frozen_at
            + 32  // expected_trunk_head
            + 32  // actual_trunk_head
            + 4 + self.gate_actor_id.len()
            + 4 + self.time_envelope_ref.len();

        let mut bytes = Vec::with_capacity(capacity);

        // 1. freeze_id (length-prefixed)
        bytes.extend_from_slice(&(self.freeze_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.freeze_id.as_bytes());

        // 2. scope (length-prefixed)
        let scope_bytes = self.scope.as_bytes();
        bytes.extend_from_slice(&(scope_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(scope_bytes);

        // 3. scope_value (length-prefixed)
        bytes.extend_from_slice(&(self.scope_value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.scope_value.as_bytes());

        // 4. trigger_defect_id (length-prefixed)
        bytes.extend_from_slice(&(self.trigger_defect_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.trigger_defect_id.as_bytes());

        // 5. frozen_at (big-endian)
        bytes.extend_from_slice(&self.frozen_at.to_be_bytes());

        // 6. expected_trunk_head
        bytes.extend_from_slice(&self.expected_trunk_head);

        // 7. actual_trunk_head
        bytes.extend_from_slice(&self.actual_trunk_head);

        // 8. gate_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.gate_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.gate_actor_id.as_bytes());

        // 9. time_envelope_ref (length-prefixed)
        bytes.extend_from_slice(&(self.time_envelope_ref.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.time_envelope_ref.as_bytes());

        bytes
    }

    /// Validates the freeze signature using domain separation.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidFreezeSignature`] if verification
    /// fails.
    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<(), DivergenceError> {
        let signature = apm2_core::crypto::Signature::from_bytes(&self.gate_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(
            verifying_key,
            INTERVENTION_FREEZE_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| DivergenceError::InvalidFreezeSignature(e.to_string()))
    }
}

// =============================================================================
// InterventionUnfreeze
// =============================================================================

/// An intervention unfreeze event emitted when a freeze is resolved.
///
/// This event is cryptographically signed and must reference a valid
/// adjudication decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionUnfreeze {
    /// ID of the `InterventionFreeze` being lifted.
    pub freeze_id: String,
    /// How the freeze was resolved.
    pub resolution_type: ResolutionType,
    /// ID of the adjudication that resolved the freeze.
    pub adjudication_id: Option<String>,
    /// Timestamp when the unfreeze was applied (Unix nanoseconds).
    pub unfrozen_at: u64,
    /// Actor who issued the unfreeze.
    pub gate_actor_id: String,
    /// Ed25519 signature over canonical bytes with domain separation.
    #[serde(with = "serde_bytes")]
    pub gate_signature: [u8; 64],
    /// Reference to the time envelope for temporal authority.
    pub time_envelope_ref: String,
}

/// Tag byte indicating Option<String> is None.
/// Per CTR-1605/CTR-2610: Using tagged encoding ensures None and Some("")
/// produce distinct canonical bytes, preventing signature collision.
const OPTION_TAG_NONE: u8 = 0x00;

/// Tag byte indicating Option<String> is Some.
const OPTION_TAG_SOME: u8 = 0x01;

impl InterventionUnfreeze {
    /// Returns the canonical bytes for signing/verification.
    ///
    /// # Canonicalization Format
    ///
    /// The canonical encoding uses tagged Option encoding to distinguish
    /// between `None` and `Some("")` (empty string), preventing signature
    /// collision attacks.
    ///
    /// For `Option<String>` fields:
    /// - `None`: Write tag byte `0x00`
    /// - `Some(s)`: Write tag byte `0x01`, then length-prefixed string
    ///
    /// This follows CTR-1605 (Deterministic Canonicalization) and CTR-2610
    /// (Canonical Representation at Boundaries) which require rejecting
    /// multiple semantic encodings for critical values.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let adjudication_id_len = self.adjudication_id.as_ref().map_or(0, String::len);
        let capacity = 4 + self.freeze_id.len()
            + 20  // resolution_type (max)
            + 1 + 4 + adjudication_id_len  // tag + optional length-prefix + string
            + 8   // unfrozen_at
            + 4 + self.gate_actor_id.len()
            + 4 + self.time_envelope_ref.len();

        let mut bytes = Vec::with_capacity(capacity);

        // 1. freeze_id (length-prefixed)
        bytes.extend_from_slice(&(self.freeze_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.freeze_id.as_bytes());

        // 2. resolution_type (length-prefixed)
        let resolution_bytes = self.resolution_type.as_bytes();
        bytes.extend_from_slice(&(resolution_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(resolution_bytes);

        // 3. adjudication_id (tagged encoding for Option<String>)
        // Per CTR-1605/CTR-2610: None and Some("") must produce distinct bytes
        // - None: 0x00 tag byte only
        // - Some(s): 0x01 tag byte + length-prefixed string
        if let Some(ref adj_id) = self.adjudication_id {
            bytes.push(OPTION_TAG_SOME);
            bytes.extend_from_slice(&(adj_id.len() as u32).to_be_bytes());
            bytes.extend_from_slice(adj_id.as_bytes());
        } else {
            bytes.push(OPTION_TAG_NONE);
        }

        // 4. unfrozen_at (big-endian)
        bytes.extend_from_slice(&self.unfrozen_at.to_be_bytes());

        // 5. gate_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.gate_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.gate_actor_id.as_bytes());

        // 6. time_envelope_ref (length-prefixed)
        bytes.extend_from_slice(&(self.time_envelope_ref.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.time_envelope_ref.as_bytes());

        bytes
    }

    /// Validates the unfreeze signature using domain separation.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidUnfreezeSignature`] if verification
    /// fails.
    pub fn validate_signature(&self, verifying_key: &VerifyingKey) -> Result<(), DivergenceError> {
        let signature = apm2_core::crypto::Signature::from_bytes(&self.gate_signature);
        let canonical = self.canonical_bytes();

        verify_with_domain(
            verifying_key,
            INTERVENTION_UNFREEZE_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|e| DivergenceError::InvalidUnfreezeSignature(e.to_string()))
    }
}

// =============================================================================
// Builders
// =============================================================================

/// Builder for constructing [`InterventionFreeze`] instances.
#[derive(Debug, Default)]
pub struct InterventionFreezeBuilder {
    freeze_id: String,
    scope: Option<FreezeScope>,
    scope_value: Option<String>,
    trigger_defect_id: Option<String>,
    frozen_at: Option<u64>,
    expected_trunk_head: Option<[u8; 32]>,
    actual_trunk_head: Option<[u8; 32]>,
    gate_actor_id: Option<String>,
    time_envelope_ref: Option<String>,
}

impl InterventionFreezeBuilder {
    /// Creates a new builder with the freeze ID.
    #[must_use]
    pub fn new(freeze_id: impl Into<String>) -> Self {
        Self {
            freeze_id: freeze_id.into(),
            ..Default::default()
        }
    }

    /// Sets the freeze scope.
    #[must_use]
    pub const fn scope(mut self, scope: FreezeScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Sets the scope value.
    #[must_use]
    pub fn scope_value(mut self, value: impl Into<String>) -> Self {
        self.scope_value = Some(value.into());
        self
    }

    /// Sets the trigger defect ID.
    #[must_use]
    pub fn trigger_defect_id(mut self, id: impl Into<String>) -> Self {
        self.trigger_defect_id = Some(id.into());
        self
    }

    /// Sets the frozen timestamp.
    #[must_use]
    pub const fn frozen_at(mut self, timestamp: u64) -> Self {
        self.frozen_at = Some(timestamp);
        self
    }

    /// Sets the expected trunk HEAD.
    #[must_use]
    pub const fn expected_trunk_head(mut self, head: [u8; 32]) -> Self {
        self.expected_trunk_head = Some(head);
        self
    }

    /// Sets the actual trunk HEAD.
    #[must_use]
    pub const fn actual_trunk_head(mut self, head: [u8; 32]) -> Self {
        self.actual_trunk_head = Some(head);
        self
    }

    /// Sets the gate actor ID.
    #[must_use]
    pub fn gate_actor_id(mut self, id: impl Into<String>) -> Self {
        self.gate_actor_id = Some(id.into());
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, ref_: impl Into<String>) -> Self {
        self.time_envelope_ref = Some(ref_.into());
        self
    }

    /// Builds and signs the freeze event.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &Signer) -> InterventionFreeze {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the freeze event.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::MissingField`] if any required field is not
    /// set. Returns [`DivergenceError::StringTooLong`] if any string field
    /// exceeds the maximum length.
    pub fn try_build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<InterventionFreeze, DivergenceError> {
        let scope = self.scope.ok_or(DivergenceError::MissingField("scope"))?;
        let scope_value = self
            .scope_value
            .ok_or(DivergenceError::MissingField("scope_value"))?;
        let trigger_defect_id = self
            .trigger_defect_id
            .ok_or(DivergenceError::MissingField("trigger_defect_id"))?;
        let expected_trunk_head = self
            .expected_trunk_head
            .ok_or(DivergenceError::MissingField("expected_trunk_head"))?;
        let actual_trunk_head = self
            .actual_trunk_head
            .ok_or(DivergenceError::MissingField("actual_trunk_head"))?;
        let gate_actor_id = self
            .gate_actor_id
            .ok_or(DivergenceError::MissingField("gate_actor_id"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(DivergenceError::MissingField("time_envelope_ref"))?;

        // Use current time if not specified
        let frozen_at = self.frozen_at.unwrap_or_else(current_timestamp_ns);

        // Validate string lengths
        validate_string_length("freeze_id", &self.freeze_id)?;
        validate_string_length("scope_value", &scope_value)?;
        validate_string_length("trigger_defect_id", &trigger_defect_id)?;
        validate_string_length("gate_actor_id", &gate_actor_id)?;
        validate_string_length("time_envelope_ref", &time_envelope_ref)?;

        // Create freeze with placeholder signature
        let mut freeze = InterventionFreeze {
            freeze_id: self.freeze_id,
            scope,
            scope_value,
            trigger_defect_id,
            frozen_at,
            expected_trunk_head,
            actual_trunk_head,
            gate_actor_id,
            gate_signature: [0u8; 64],
            time_envelope_ref,
        };

        // Sign the canonical bytes
        let canonical = freeze.canonical_bytes();
        let signature = sign_with_domain(signer, INTERVENTION_FREEZE_PREFIX, &canonical);
        freeze.gate_signature = signature.to_bytes();

        Ok(freeze)
    }
}

/// Builder for constructing [`InterventionUnfreeze`] instances.
#[derive(Debug, Default)]
pub struct InterventionUnfreezeBuilder {
    freeze_id: String,
    resolution_type: Option<ResolutionType>,
    adjudication_id: Option<String>,
    unfrozen_at: Option<u64>,
    gate_actor_id: Option<String>,
    time_envelope_ref: Option<String>,
}

impl InterventionUnfreezeBuilder {
    /// Creates a new builder with the freeze ID to unfreeze.
    #[must_use]
    pub fn new(freeze_id: impl Into<String>) -> Self {
        Self {
            freeze_id: freeze_id.into(),
            ..Default::default()
        }
    }

    /// Sets the resolution type.
    #[must_use]
    pub const fn resolution_type(mut self, resolution_type: ResolutionType) -> Self {
        self.resolution_type = Some(resolution_type);
        self
    }

    /// Sets the adjudication ID.
    #[must_use]
    pub fn adjudication_id(mut self, id: impl Into<String>) -> Self {
        self.adjudication_id = Some(id.into());
        self
    }

    /// Sets the unfrozen timestamp.
    #[must_use]
    pub const fn unfrozen_at(mut self, timestamp: u64) -> Self {
        self.unfrozen_at = Some(timestamp);
        self
    }

    /// Sets the gate actor ID.
    #[must_use]
    pub fn gate_actor_id(mut self, id: impl Into<String>) -> Self {
        self.gate_actor_id = Some(id.into());
        self
    }

    /// Sets the time envelope reference.
    #[must_use]
    pub fn time_envelope_ref(mut self, ref_: impl Into<String>) -> Self {
        self.time_envelope_ref = Some(ref_.into());
        self
    }

    /// Builds and signs the unfreeze event.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing.
    #[must_use]
    pub fn build_and_sign(self, signer: &Signer) -> InterventionUnfreeze {
        self.try_build_and_sign(signer)
            .expect("missing required field")
    }

    /// Attempts to build and sign the unfreeze event.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::MissingField`] if any required field is not
    /// set. Returns [`DivergenceError::StringTooLong`] if any string field
    /// exceeds the maximum length.
    /// Returns [`DivergenceError::AdjudicationRequired`] if the resolution type
    /// requires an adjudication ID but none is provided.
    pub fn try_build_and_sign(
        self,
        signer: &Signer,
    ) -> Result<InterventionUnfreeze, DivergenceError> {
        let resolution_type = self
            .resolution_type
            .ok_or(DivergenceError::MissingField("resolution_type"))?;
        let gate_actor_id = self
            .gate_actor_id
            .ok_or(DivergenceError::MissingField("gate_actor_id"))?;
        let time_envelope_ref = self
            .time_envelope_ref
            .ok_or(DivergenceError::MissingField("time_envelope_ref"))?;

        // Validate adjudication requirement
        if resolution_type.requires_adjudication() && self.adjudication_id.is_none() {
            return Err(DivergenceError::AdjudicationRequired);
        }

        // Use current time if not specified
        let unfrozen_at = self.unfrozen_at.unwrap_or_else(current_timestamp_ns);

        // Validate string lengths
        validate_string_length("freeze_id", &self.freeze_id)?;
        validate_string_length("gate_actor_id", &gate_actor_id)?;
        validate_string_length("time_envelope_ref", &time_envelope_ref)?;
        if let Some(ref adj_id) = self.adjudication_id {
            validate_string_length("adjudication_id", adj_id)?;
        }

        // Create unfreeze with placeholder signature
        let mut unfreeze = InterventionUnfreeze {
            freeze_id: self.freeze_id,
            resolution_type,
            adjudication_id: self.adjudication_id,
            unfrozen_at,
            gate_actor_id,
            gate_signature: [0u8; 64],
            time_envelope_ref,
        };

        // Sign the canonical bytes
        let canonical = unfreeze.canonical_bytes();
        let signature = sign_with_domain(signer, INTERVENTION_UNFREEZE_PREFIX, &canonical);
        unfreeze.gate_signature = signature.to_bytes();

        Ok(unfreeze)
    }
}

// =============================================================================
// DivergenceWatchdogConfig
// =============================================================================

/// Configuration for the divergence watchdog.
#[derive(Debug, Clone)]
pub struct DivergenceWatchdogConfig {
    /// Repository identifier for scope value.
    pub repo_id: String,
    /// Poll interval for divergence checks.
    pub poll_interval: Duration,
    /// Actor ID for the watchdog.
    pub actor_id: String,
    /// Time envelope reference pattern.
    pub time_envelope_pattern: String,
    /// External trusted time authority key bindings (CAC/HTF root).
    pub trusted_time_authority_bindings: Vec<AuthorityKeyBindingV1>,
}

impl DivergenceWatchdogConfig {
    /// Creates a new configuration with the repository ID.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidConfiguration`] if the `repo_id` is
    /// empty or exceeds the maximum length.
    pub fn new(repo_id: impl Into<String>) -> Result<Self, DivergenceError> {
        let repo_id = repo_id.into();
        if repo_id.is_empty() {
            return Err(DivergenceError::InvalidConfiguration(
                "repo_id cannot be empty".to_string(),
            ));
        }
        validate_string_length("repo_id", &repo_id)?;

        Ok(Self {
            repo_id,
            poll_interval: DEFAULT_POLL_INTERVAL,
            actor_id: "divergence-watchdog".to_string(),
            time_envelope_pattern: "htf:tick:{}".to_string(),
            trusted_time_authority_bindings: Vec::new(),
        })
    }

    /// Sets the poll interval.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidConfiguration`] if the interval is
    /// outside the allowed range.
    pub fn with_poll_interval(mut self, interval: Duration) -> Result<Self, DivergenceError> {
        if interval < MIN_POLL_INTERVAL {
            return Err(DivergenceError::InvalidConfiguration(format!(
                "poll_interval too short: {interval:?} < {MIN_POLL_INTERVAL:?}"
            )));
        }
        if interval > MAX_POLL_INTERVAL {
            return Err(DivergenceError::InvalidConfiguration(format!(
                "poll_interval too long: {interval:?} > {MAX_POLL_INTERVAL:?}"
            )));
        }
        self.poll_interval = interval;
        Ok(self)
    }

    /// Sets the actor ID.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::StringTooLong`] if the `actor_id` exceeds the
    /// maximum length.
    pub fn with_actor_id(mut self, actor_id: impl Into<String>) -> Result<Self, DivergenceError> {
        let actor_id = actor_id.into();
        validate_string_length("actor_id", &actor_id)?;
        self.actor_id = actor_id;
        Ok(self)
    }

    /// Sets externally trusted time authority bindings.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidConfiguration`] if the binding count
    /// exceeds `MAX_TRUSTED_AUTHORITY_BINDINGS` or any verifying key fails to
    /// parse.
    pub fn with_trusted_time_authority_bindings(
        mut self,
        bindings: Vec<AuthorityKeyBindingV1>,
    ) -> Result<Self, DivergenceError> {
        if bindings.len() > MAX_TRUSTED_AUTHORITY_BINDINGS {
            return Err(DivergenceError::InvalidConfiguration(format!(
                "trusted authority bindings exceed limit: {} > {MAX_TRUSTED_AUTHORITY_BINDINGS}",
                bindings.len()
            )));
        }

        for binding in &bindings {
            if binding.actor_id.trim().is_empty() {
                return Err(DivergenceError::MissingField(
                    "trusted_time_authority_bindings.actor_id",
                ));
            }
            validate_string_length(
                "trusted_time_authority_bindings.actor_id",
                &binding.actor_id,
            )?;
            parse_verifying_key(&binding.verifying_key)
                .map_err(|error| DivergenceError::InvalidConfiguration(error.to_string()))?;
        }

        self.trusted_time_authority_bindings = bindings;
        Ok(self)
    }
}

// =============================================================================
// FreezeRegistry
// =============================================================================

/// Thread-safe registry of active freezes.
///
/// This registry tracks which repositories/scopes are currently frozen
/// and is used for admission checking.
///
/// # Fail-Closed Security Model
///
/// The registry supports two operational modes:
///
/// 1. **Un-hydrated (Fail-Closed)**: When created via `new()` or
///    `new_fail_closed()`, the registry blocks ALL admissions until explicitly
///    hydrated. This prevents a daemon restart from clearing freeze state and
///    allowing work on compromised repositories.
///
/// 2. **Hydrated (Normal Operation)**: After calling `mark_hydrated()`, the
///    registry only blocks admissions for explicitly frozen scopes.
///
/// # Rehydration Strategy
///
/// On daemon startup, the caller MUST:
/// 1. Create the registry with `new_fail_closed()`
/// 2. Replay ledger events to restore freeze state via `replay_freeze`
/// 3. Call `mark_hydrated()` to transition to normal operation
///
/// ```rust,ignore
/// // Example rehydration flow
/// let registry = FreezeRegistry::new_fail_closed();
///
/// // Replay freeze events from ledger
/// for event in ledger.iter_intervention_freezes() {
///     registry.replay_freeze(&event, &watchdog_key)?;
/// }
/// for event in ledger.iter_intervention_unfreezes() {
///     registry.replay_unfreeze(&event, &watchdog_key)?;
/// }
///
/// // Mark hydrated to allow normal operation
/// registry.mark_hydrated();
/// ```
#[derive(Debug)]
pub struct FreezeRegistry {
    /// Set of active freeze IDs.
    active_freezes: RwLock<HashSet<String>>,
    /// Map of `scope_value` -> `freeze_id` for quick lookup.
    scope_map: RwLock<std::collections::HashMap<String, String>>,
    /// Whether the registry has been hydrated from ledger state.
    /// When `false`, ALL admissions are blocked (fail-closed).
    hydrated: std::sync::atomic::AtomicBool,
}

impl Default for FreezeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FreezeRegistry {
    /// Creates a new freeze registry in fail-closed mode (default).
    ///
    /// Per CTR-2617 (Fail-Closed Default): The registry blocks ALL admissions
    /// until [`Self::mark_hydrated`] is called. This ensures that a daemon
    /// restart cannot clear freeze state and allow work on compromised repos.
    ///
    /// # Production Usage
    ///
    /// ```rust,ignore
    /// let registry = FreezeRegistry::new_hydrated_for_testing();
    ///
    /// // Replay freeze events from ledger
    /// for event in ledger.iter_intervention_freezes() {
    ///     registry.replay_freeze(&event, &watchdog_key)?;
    /// }
    ///
    /// // Mark hydrated to allow normal operation
    /// registry.mark_hydrated();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_freezes: RwLock::default(),
            scope_map: RwLock::default(),
            hydrated: std::sync::atomic::AtomicBool::new(false), // CTR-2617: fail-closed by default
        }
    }

    /// Creates a new freeze registry in fail-closed mode.
    ///
    /// This is an alias for [`Self::new`] for explicit intent.
    #[must_use]
    pub fn new_fail_closed() -> Self {
        Self::new()
    }

    /// Creates a new freeze registry in hydrated mode (for testing only).
    ///
    /// # Safety
    ///
    /// This constructor bypasses the fail-closed security model and should
    /// ONLY be used in tests. Using this in production code violates CTR-2617.
    #[cfg(test)]
    #[must_use]
    pub fn new_hydrated_for_testing() -> Self {
        Self {
            active_freezes: RwLock::default(),
            scope_map: RwLock::default(),
            hydrated: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Marks the registry as hydrated, enabling normal admission checks.
    ///
    /// Call this after replaying all freeze/unfreeze events from the ledger.
    /// Before calling this, ALL admissions will be blocked.
    pub fn mark_hydrated(&self) {
        self.hydrated
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns whether the registry has been hydrated.
    #[must_use]
    pub fn is_hydrated(&self) -> bool {
        self.hydrated.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn is_precautionary_freeze_id(freeze_id: &str) -> bool {
        freeze_id.starts_with(PRECAUTIONARY_FREEZE_ID_PREFIX)
    }

    /// Registers a fail-closed precautionary freeze for a scope.
    ///
    /// This path is used when divergence checks fail internally and the daemon
    /// must block admissions until a successful follow-up check confirms state.
    ///
    /// Returns `true` only when a new freeze is inserted.
    pub fn register_precautionary_freeze(&self, scope_value: &str, freeze_id: String) -> bool {
        if !Self::is_precautionary_freeze_id(&freeze_id) {
            return false;
        }

        let Ok(mut active) = self.active_freezes.write() else {
            return false;
        };
        let Ok(mut scope) = self.scope_map.write() else {
            return false;
        };

        if scope.contains_key(scope_value) {
            return false;
        }

        active.insert(freeze_id.clone());
        scope.insert(scope_value.to_string(), freeze_id);
        true
    }

    /// Removes a fail-closed precautionary freeze for a scope if IDs match.
    ///
    /// Returns `true` only when the mapped freeze exactly matches
    /// `freeze_id` and follows the precautionary ID prefix contract.
    pub fn remove_precautionary_freeze(&self, scope_value: &str, freeze_id: &str) -> bool {
        if !Self::is_precautionary_freeze_id(freeze_id) {
            return false;
        }

        let Ok(mut active) = self.active_freezes.write() else {
            return false;
        };
        let Ok(mut scope) = self.scope_map.write() else {
            return false;
        };

        let should_remove = scope
            .get(scope_value)
            .is_some_and(|existing| existing == freeze_id)
            && Self::is_precautionary_freeze_id(freeze_id);

        if !should_remove {
            return false;
        }

        scope.remove(scope_value);
        active.remove(freeze_id);
        true
    }

    /// Replays a freeze event from ledger during rehydration.
    ///
    /// This method registers a freeze in the registry after verifying its
    /// signature. It should be used during ledger replay to restore freeze
    /// state on startup.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails.
    pub fn replay_freeze(
        &self,
        freeze: &InterventionFreeze,
        verifying_key: &VerifyingKey,
    ) -> Result<(), DivergenceError> {
        self.register(freeze, verifying_key)
    }

    /// Replays an unfreeze event from ledger during rehydration.
    ///
    /// This method removes a freeze from the registry after verifying the
    /// unfreeze signature. It should be used during ledger replay to restore
    /// freeze state on startup.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails or if the freeze
    /// doesn't exist (which may indicate out-of-order replay).
    pub fn replay_unfreeze(
        &self,
        unfreeze: &InterventionUnfreeze,
        verifying_key: &VerifyingKey,
    ) -> Result<(), DivergenceError> {
        self.unregister(unfreeze, verifying_key)
    }

    /// Registers a freeze in the registry after verifying its signature.
    ///
    /// Per CTR-2703 (Cryptographically Bound ActorID): Signatures must be
    /// validated before accepting state mutations. This prevents
    /// unauthenticated callers from bypassing the watchdog to register
    /// fraudulent freezes.
    ///
    /// # Arguments
    ///
    /// * `freeze` - The freeze event to register
    /// * `verifying_key` - The key to verify the freeze signature against
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidFreezeSignature`] if signature
    /// verification fails.
    /// Returns [`DivergenceError::ScopeAlreadyFrozen`] if the scope is already
    /// frozen (idempotency protection).
    /// Returns an error if the lock is poisoned.
    pub(crate) fn register(
        &self,
        freeze: &InterventionFreeze,
        verifying_key: &VerifyingKey,
    ) -> Result<(), DivergenceError> {
        // Per CTR-2703: Validate signature before accepting state mutation
        freeze.validate_signature(verifying_key)?;

        let mut active = self
            .active_freezes
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;
        let mut scope = self
            .scope_map
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;

        // Prevent duplicate registrations for the same scope.
        // This prevents unbounded memory growth in active_freezes if multiple
        // freeze events are registered for the same scope without unfreeze.
        if let Some(existing_freeze_id) = scope.get(&freeze.scope_value).cloned() {
            if Self::is_precautionary_freeze_id(&existing_freeze_id) {
                active.remove(&existing_freeze_id);
            } else {
                return Err(DivergenceError::ScopeAlreadyFrozen {
                    scope_value: freeze.scope_value.clone(),
                    existing_freeze_id,
                });
            }
        }

        active.insert(freeze.freeze_id.clone());
        scope.insert(freeze.scope_value.clone(), freeze.freeze_id.clone());

        Ok(())
    }

    /// Unregisters a freeze from the registry after verifying the unfreeze
    /// signature and adjudication requirements.
    ///
    /// Per CTR-2703 (Cryptographically Bound ActorID): Signatures must be
    /// validated before accepting state mutations. This prevents
    /// unauthenticated callers from bypassing the watchdog to unfreeze
    /// repositories without proper authorization.
    ///
    /// # Security Rationale
    ///
    /// The unfreeze path is as security-critical as the freeze path. Without
    /// signature verification, any component with access to the registry could
    /// lift a freeze without cryptographic proof of adjudication or manual
    /// override authority. This would violate the fail-closed principle for
    /// SCP state mutations.
    ///
    /// # Adjudication Enforcement
    ///
    /// If the `resolution_type` is `Adjudication`, the `adjudication_id` field
    /// MUST be present. This ensures all non-emergency unfreezes have a
    /// traceable adjudication reference for audit purposes.
    ///
    /// # Arguments
    ///
    /// * `unfreeze` - The signed unfreeze event
    /// * `verifying_key` - The key to verify the unfreeze signature against
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidUnfreezeSignature`] if signature
    /// verification fails.
    /// Returns [`DivergenceError::AdjudicationRequired`] if `resolution_type`
    /// is Adjudication but `adjudication_id` is missing.
    /// Returns [`DivergenceError::FreezeNotFound`] if the freeze is not in the
    /// registry.
    pub(crate) fn unregister(
        &self,
        unfreeze: &InterventionUnfreeze,
        verifying_key: &VerifyingKey,
    ) -> Result<(), DivergenceError> {
        // Per CTR-2703: Validate signature before accepting state mutation
        unfreeze.validate_signature(verifying_key)?;

        // Enforce adjudication_id requirement for Adjudication resolution type
        if unfreeze.resolution_type.requires_adjudication() && unfreeze.adjudication_id.is_none() {
            return Err(DivergenceError::AdjudicationRequired);
        }

        let mut active = self
            .active_freezes
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;
        let mut scope = self
            .scope_map
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;

        if !active.remove(&unfreeze.freeze_id) {
            return Err(DivergenceError::FreezeNotFound {
                freeze_id: unfreeze.freeze_id.clone(),
            });
        }

        // Remove from scope map (find and remove)
        scope.retain(|_, v| v != &unfreeze.freeze_id);

        Ok(())
    }

    /// Checks if a scope is frozen, including hierarchical parent scopes.
    ///
    /// # Hierarchical Freeze Enforcement
    ///
    /// Freeze checks are hierarchical: if a parent namespace is frozen, all
    /// child scopes are also considered frozen. This enforces the following
    /// invariants:
    ///
    /// - A frozen namespace (e.g., `org`) blocks all repositories under it
    ///   (e.g., `org/repo1`, `org/repo2`)
    /// - A frozen repository scope (e.g., `org/repo`) blocks all artifacts
    ///   under it
    ///
    /// # Format Support
    ///
    /// - Slash-separated: `org/repo` - checks `org/repo`, then `org`
    /// - Colon-separated: `org:kind` - checks `org:kind`, then `org`
    ///
    /// # Unfreeze Independence
    ///
    /// **Important:** While freeze checks are hierarchical (parent freezes
    /// affect children), unfreezes are NOT hierarchical. Each freeze must be
    /// explicitly unfrozen by its own `freeze_id`. Unfreezing a parent scope
    /// does NOT automatically lift freezes on child scopes.
    ///
    /// This is intentional - it enforces a "most-restrictive" security posture
    /// where explicit unfreezes are required for each frozen entity.
    ///
    /// # Returns
    ///
    /// `Some(freeze_id)` if the scope or any parent scope is frozen,
    /// `None` otherwise.
    pub fn is_frozen(&self, scope_value: &str) -> Option<String> {
        let scope = self.scope_map.read().ok()?;

        // Check exact match first
        if let Some(freeze_id) = scope.get(scope_value) {
            return Some(freeze_id.clone());
        }

        // Check hierarchical parents for slash-separated format (org/repo)
        if scope_value.contains('/') {
            for parent in Self::hierarchical_parents_slash(scope_value) {
                if let Some(freeze_id) = scope.get(parent) {
                    return Some(freeze_id.clone());
                }
            }
        }

        // Check hierarchical parents for colon-separated format (org:kind)
        if scope_value.contains(':') {
            for parent in Self::hierarchical_parents_colon(scope_value) {
                if let Some(freeze_id) = scope.get(parent) {
                    return Some(freeze_id.clone());
                }
            }
        }

        None
    }

    /// Returns an iterator over hierarchical parent scopes for slash-separated
    /// values.
    ///
    /// For `org/repo/artifact`, yields `org/repo`, then `org`.
    fn hierarchical_parents_slash(scope_value: &str) -> impl Iterator<Item = &str> {
        let mut current = scope_value;
        std::iter::from_fn(move || {
            let pos = current.rfind('/')?;
            current = &current[..pos];
            Some(current)
        })
    }

    /// Returns an iterator over hierarchical parent scopes for colon-separated
    /// values.
    ///
    /// For `org:kind:id`, yields `org:kind`, then `org`.
    fn hierarchical_parents_colon(scope_value: &str) -> impl Iterator<Item = &str> {
        let mut current = scope_value;
        std::iter::from_fn(move || {
            let pos = current.rfind(':')?;
            current = &current[..pos];
            Some(current)
        })
    }

    /// Checks admission and returns an error if the scope is frozen or if
    /// the registry has not been hydrated yet.
    ///
    /// This method performs hierarchical freeze checking: if any parent
    /// scope is frozen, the admission is rejected.
    ///
    /// # Fail-Closed Behavior
    ///
    /// If the registry has not been hydrated (via [`Self::mark_hydrated`]),
    /// ALL admissions are blocked. This prevents a daemon restart from clearing
    /// freeze state and allowing work on compromised repositories.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::RepoFrozen`] if:
    /// - The scope or any parent scope is frozen, OR
    /// - The registry has not been hydrated yet (fail-closed)
    pub fn check_admission(&self, scope_value: &str) -> Result<(), DivergenceError> {
        // Fail-closed: block all admissions until hydrated
        if !self.is_hydrated() {
            return Err(DivergenceError::RepoFrozen {
                freeze_id: "__REGISTRY_NOT_HYDRATED__".to_string(),
            });
        }

        if let Some(freeze_id) = self.is_frozen(scope_value) {
            return Err(DivergenceError::RepoFrozen { freeze_id });
        }
        Ok(())
    }

    /// Returns the number of active freezes.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_freezes.read().map(|f| f.len()).unwrap_or(0)
    }
}

// =============================================================================
// FreezeCheck Trait Implementation
// =============================================================================

// Re-export the FreezeCheck trait from apm2-core for use in this module.
// This enables AdmissionGate in apm2-core to use FreezeRegistry from
// apm2-daemon.
pub use apm2_core::cac::freeze_check::{FreezeCheck, FreezeCheckError};

impl FreezeCheck for FreezeRegistry {
    fn check_admission(&self, scope_value: &str) -> Result<(), FreezeCheckError> {
        // Delegate to the existing method and convert the error
        Self::check_admission(self, scope_value).map_err(|e| match e {
            DivergenceError::RepoFrozen { freeze_id } => {
                FreezeCheckError::frozen_with_reason(freeze_id, "divergence detected")
            },
            other => FreezeCheckError::internal(other.to_string()),
        })
    }

    fn is_frozen(&self, scope_value: &str) -> bool {
        Self::is_frozen(self, scope_value).is_some()
    }
}

// =============================================================================
// TimeSource Trait
// =============================================================================

/// Trait for obtaining the current time.
///
/// This trait abstracts time access, enabling deterministic testing by
/// allowing injection of mock time sources.
///
/// # Production Requirements
///
/// **WARNING**: For production deployments, an HTF (Holon Time Fabric) backed
/// implementation MUST be used. See [`SystemTimeSource`] documentation for the
/// required integration path.
///
/// The poll interval for the divergence watchdog should ideally be bound to
/// HTF ticks rather than wall-clock `Duration` to ensure deterministic
/// behavior across distributed nodes.
///
/// # Security
///
/// Time sources are used for:
/// - Freeze/unfreeze event timestamps
/// - Time envelope references
/// - Defect record timestamps
///
/// Implementations must return monotonically increasing values to prevent
/// time-based attacks.
pub trait TimeSource: Send + Sync {
    /// Returns the current time in nanoseconds since Unix epoch.
    fn now_nanos(&self) -> u64;

    /// Returns a time envelope reference for the current time.
    ///
    /// The format is typically `htf:tick:{timestamp}`.
    fn time_envelope_ref(&self, pattern: &str) -> String {
        pattern.replace("{}", &self.now_nanos().to_string())
    }
}

/// System time source using the real system clock.
///
/// This is the **default implementation** for development and testing. In
/// production deployments, consider using an HTF (Holon Time Fabric) backed
/// time source for:
///
/// - **Distributed consistency**: HTF provides globally-ordered timestamps
///   across nodes, preventing clock skew issues
/// - **Audit compliance**: HTF timestamps are cryptographically witnessed,
///   supporting regulatory requirements
/// - **Replay protection**: HTF-backed timestamps prevent replay attacks across
///   temporal boundaries
///
/// # Production Time Source Requirements
///
/// For production use, implement the [`TimeSource`] trait with an HTF-backed
/// provider:
///
/// ```rust,ignore
/// use apm2_daemon::projection::{TimeSource, DivergenceWatchdog};
///
/// struct HtfTimeSource {
///     htf_client: HtfClient,
/// }
///
/// impl TimeSource for HtfTimeSource {
///     fn now_nanos(&self) -> u64 {
///         self.htf_client.current_tick_nanos()
///     }
///
///     fn time_envelope_ref(&self, _pattern: &str) -> String {
///         // Use actual HTF tick reference instead of pattern
///         format!("htf:tick:{}", self.htf_client.current_tick_id())
///     }
/// }
///
/// // Create watchdog with HTF time source
/// let htf_source = HtfTimeSource::new(htf_client);
/// let watchdog = DivergenceWatchdog::with_time_source(signer, config, htf_source);
/// ```
///
/// # Security Note
///
/// Using `SystemTimeSource` in production may result in:
/// - Clock skew between nodes causing inconsistent freeze timestamps
/// - Potential time-based attacks if system clock is manipulated
/// - Non-auditable timestamps that cannot be cryptographically verified
///
/// These limitations are acceptable for development and testing but should
/// be addressed for production deployments by integrating with HTF.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now_nanos(&self) -> u64 {
        current_timestamp_ns()
    }
}

// =============================================================================
// DivergenceWatchdog
// =============================================================================

/// The divergence watchdog that monitors for ledger/trunk divergence.
///
/// This watchdog periodically checks whether the external trunk HEAD matches
/// the ledger's latest merge receipt. On divergence, it emits a freeze event.
///
/// # Time Source Injection
///
/// The watchdog accepts a [`TimeSource`] for testability. In production, use
/// [`SystemTimeSource`]. For testing, inject a mock time source to control
/// timestamps deterministically.
pub struct DivergenceWatchdog<T: TimeSource = SystemTimeSource> {
    /// Signer for freeze events.
    signer: Signer,
    /// Configuration.
    config: DivergenceWatchdogConfig,
    /// Freeze registry for tracking active freezes.
    registry: Arc<FreezeRegistry>,
    /// Counter for generating freeze IDs.
    freeze_counter: std::sync::atomic::AtomicU64,
    /// Counter for generating defect IDs.
    defect_counter: std::sync::atomic::AtomicU64,
    /// Time source for obtaining current time.
    time_source: T,
    /// Per-freeze replay recovery state used for post-containment
    /// reconstruction checks before unfreeze.
    projection_recovery_state: std::sync::Mutex<HashMap<String, ProjectionRecoveryState>>,
    /// Pending externally provided temporal authority envelope.
    pending_time_authority_envelope: std::sync::Mutex<Option<TimeAuthorityEnvelopeV1>>,
}

impl DivergenceWatchdog<SystemTimeSource> {
    /// Creates a new divergence watchdog with the system time source.
    #[must_use]
    pub fn new(signer: Signer, config: DivergenceWatchdogConfig) -> Self {
        Self {
            signer,
            config,
            registry: Arc::new(FreezeRegistry::new()),
            freeze_counter: std::sync::atomic::AtomicU64::new(0),
            defect_counter: std::sync::atomic::AtomicU64::new(0),
            time_source: SystemTimeSource,
            projection_recovery_state: std::sync::Mutex::new(HashMap::new()),
            pending_time_authority_envelope: std::sync::Mutex::new(None),
        }
    }

    /// Creates a new divergence watchdog with a shared freeze registry.
    #[must_use]
    pub fn with_registry(
        signer: Signer,
        config: DivergenceWatchdogConfig,
        registry: Arc<FreezeRegistry>,
    ) -> Self {
        Self {
            signer,
            config,
            registry,
            freeze_counter: std::sync::atomic::AtomicU64::new(0),
            defect_counter: std::sync::atomic::AtomicU64::new(0),
            time_source: SystemTimeSource,
            projection_recovery_state: std::sync::Mutex::new(HashMap::new()),
            pending_time_authority_envelope: std::sync::Mutex::new(None),
        }
    }
}

impl<T: TimeSource> DivergenceWatchdog<T> {
    /// Creates a new divergence watchdog with a custom time source.
    ///
    /// This constructor is primarily for testing, allowing injection of
    /// mock time sources for deterministic behavior.
    #[must_use]
    pub fn with_time_source(
        signer: Signer,
        config: DivergenceWatchdogConfig,
        time_source: T,
    ) -> Self {
        Self {
            signer,
            config,
            registry: Arc::new(FreezeRegistry::new()),
            freeze_counter: std::sync::atomic::AtomicU64::new(0),
            defect_counter: std::sync::atomic::AtomicU64::new(0),
            time_source,
            projection_recovery_state: std::sync::Mutex::new(HashMap::new()),
            pending_time_authority_envelope: std::sync::Mutex::new(None),
        }
    }

    /// Creates a new divergence watchdog with a shared registry and custom time
    /// source.
    #[must_use]
    pub fn with_registry_and_time_source(
        signer: Signer,
        config: DivergenceWatchdogConfig,
        registry: Arc<FreezeRegistry>,
        time_source: T,
    ) -> Self {
        Self {
            signer,
            config,
            registry,
            freeze_counter: std::sync::atomic::AtomicU64::new(0),
            defect_counter: std::sync::atomic::AtomicU64::new(0),
            time_source,
            projection_recovery_state: std::sync::Mutex::new(HashMap::new()),
            pending_time_authority_envelope: std::sync::Mutex::new(None),
        }
    }

    /// Returns the freeze registry.
    #[must_use]
    pub fn registry(&self) -> Arc<FreezeRegistry> {
        Arc::clone(&self.registry)
    }

    /// Returns the poll interval.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        self.config.poll_interval
    }

    /// Returns the verifying key for the watchdog's signer.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Generates a unique freeze ID.
    fn generate_freeze_id(&self) -> String {
        let count = self
            .freeze_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = self.time_source.now_nanos();
        format!("freeze-{timestamp}-{count}")
    }

    /// Generates a unique defect ID.
    fn generate_defect_id(&self) -> String {
        let count = self
            .defect_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = self.time_source.now_nanos();
        format!("defect-divergence-{timestamp}-{count}")
    }

    /// Generates a time envelope reference.
    fn generate_time_envelope_ref(&self) -> String {
        self.time_source
            .time_envelope_ref(&self.config.time_envelope_pattern)
    }

    fn trusted_authority_bindings(&self) -> Result<Vec<AuthorityKeyBindingV1>, DivergenceError> {
        let bindings = if self.config.trusted_time_authority_bindings.is_empty() {
            if self.config.actor_id.trim().is_empty() {
                return Err(DivergenceError::MissingField("actor_id"));
            }
            if self.config.actor_id.len() > MAX_ACTOR_ID_LENGTH {
                return Err(DivergenceError::StringTooLong {
                    field: "actor_id",
                    actual: self.config.actor_id.len(),
                    max: MAX_ACTOR_ID_LENGTH,
                });
            }
            vec![AuthorityKeyBindingV1 {
                actor_id: self.config.actor_id.clone(),
                verifying_key: self.signer.public_key_bytes(),
            }]
        } else {
            self.config.trusted_time_authority_bindings.clone()
        };

        if bindings.len() > MAX_TRUSTED_AUTHORITY_BINDINGS {
            return Err(DivergenceError::InvalidConfiguration(format!(
                "trusted authority bindings exceed limit: {} > {MAX_TRUSTED_AUTHORITY_BINDINGS}",
                bindings.len()
            )));
        }

        for binding in &bindings {
            if binding.actor_id.trim().is_empty() {
                return Err(DivergenceError::MissingField(
                    "trusted_time_authority_bindings.actor_id",
                ));
            }
            if binding.actor_id.len() > MAX_ACTOR_ID_LENGTH {
                return Err(DivergenceError::StringTooLong {
                    field: "trusted_time_authority_bindings.actor_id",
                    actual: binding.actor_id.len(),
                    max: MAX_ACTOR_ID_LENGTH,
                });
            }
            parse_verifying_key(&binding.verifying_key)
                .map_err(|error| DivergenceError::InvalidConfiguration(error.to_string()))?;
        }

        Ok(bindings)
    }

    fn verify_temporal_authority_envelope(
        envelope: TimeAuthorityEnvelopeV1,
        trusted_authority_bindings: &[AuthorityKeyBindingV1],
        now_ns: u64,
    ) -> Result<VerifiedTemporalAuthority, DivergenceError> {
        envelope.validate_signature(trusted_authority_bindings)?;
        envelope.validate_freshness(now_ns)?;
        Ok(VerifiedTemporalAuthority {
            time_authority_ref: envelope.derive_time_authority_ref(),
            envelope,
        })
    }

    fn resolve_temporal_authority(
        &self,
        now_ns: u64,
        trusted_authority_bindings: &[AuthorityKeyBindingV1],
    ) -> Result<VerifiedTemporalAuthority, DivergenceError> {
        let pending_envelope = self
            .pending_time_authority_envelope
            .lock()
            .map_err(|error| {
                DivergenceError::InvalidConfiguration(format!("lock poisoned: {error}"))
            })?
            .take();
        if let Some(envelope) = pending_envelope {
            return Self::verify_temporal_authority_envelope(
                envelope,
                trusted_authority_bindings,
                now_ns,
            );
        }

        let time_envelope_ref = self.generate_time_envelope_ref();
        let window_ref = self.derive_window_ref(now_ns);
        let ttl_ns = u64::try_from(DEFAULT_TIME_AUTHORITY_TTL.as_nanos()).map_err(|_| {
            DivergenceError::InvalidConfiguration("time authority ttl exceeds u64".to_string())
        })?;
        let expires_at_ns = now_ns.checked_add(ttl_ns).ok_or_else(|| {
            DivergenceError::InvalidConfiguration("time authority expiry overflow".to_string())
        })?;
        let envelope = TimeAuthorityEnvelopeV1::create_signed(
            time_envelope_ref,
            window_ref,
            now_ns,
            expires_at_ns,
            self.config.actor_id.clone(),
            &self.signer,
        )?;
        Self::verify_temporal_authority_envelope(envelope, trusted_authority_bindings, now_ns)
    }

    /// Provides an externally signed temporal authority envelope for the next
    /// divergence decision.
    ///
    /// The envelope is validated before it is accepted and stored.
    pub fn provide_time_authority_envelope(
        &self,
        envelope: TimeAuthorityEnvelopeV1,
    ) -> Result<(), DivergenceError> {
        let trusted_authority_bindings = self.trusted_authority_bindings()?;
        let now_ns = self.time_source.now_nanos();
        let _verified = Self::verify_temporal_authority_envelope(
            envelope.clone(),
            &trusted_authority_bindings,
            now_ns,
        )?;
        let mut pending = self
            .pending_time_authority_envelope
            .lock()
            .map_err(|error| {
                DivergenceError::InvalidConfiguration(format!("lock poisoned: {error}"))
            })?;
        *pending = Some(envelope);
        Ok(())
    }

    /// Derives HTF window reference hash for compromise decisions.
    fn derive_window_ref(&self, timestamp_ns: u64) -> Hash {
        // 5-minute windows match active quarantine TTL granularity in the daemon.
        const WINDOW_NS: u64 = 300 * 1_000_000_000;
        let window_start = timestamp_ns - (timestamp_ns % WINDOW_NS);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.projection_compromise.window_ref.v1");
        hasher.update(self.config.repo_id.as_bytes());
        hasher.update(&window_start.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Constructs sink-side endpoint evidence for projection-compromise
    /// detection.
    ///
    /// # Trust Boundary
    ///
    /// When `remote_fingerprint` is `None`, the returned evidence uses a
    /// fingerprint derived from the **local** daemon signer key. This is a
    /// self-attested identity claim and MUST NOT be trusted for remote
    /// endpoint verification. The `endpoint_identity_verified` field will be
    /// `false` and a warning is emitted to the `tracing` subsystem.
    fn sink_endpoint_evidence(&self, remote_fingerprint: Option<&str>) -> SinkEndpointEvidenceV1 {
        remote_fingerprint.map_or_else(
            || {
                tracing::warn!(
                    repo_id = %self.config.repo_id,
                    "sink_endpoint_evidence: using local-signer fallback fingerprint \
                     (unverified mode) — endpoint identity is self-attested"
                );
                let mut hasher = blake3::Hasher::new();
                hasher
                    .update(b"apm2.projection_compromise.endpoint_key_fingerprint.local_signer.v1");
                hasher.update(&self.signer.public_key_bytes());
                SinkEndpointEvidenceV1 {
                    endpoint_canonical_id: format!("github://{}", self.config.repo_id),
                    endpoint_key_fingerprint: hex::encode(hasher.finalize().as_bytes()),
                    key_epoch: 0,
                    endpoint_identity_verified: false,
                }
            },
            |fingerprint| SinkEndpointEvidenceV1 {
                endpoint_canonical_id: format!("github://{}", self.config.repo_id),
                endpoint_key_fingerprint: fingerprint.to_string(),
                key_epoch: 0,
                endpoint_identity_verified: true,
            },
        )
    }

    fn validate_sink_endpoint_evidence(
        endpoint_evidence: &SinkEndpointEvidenceV1,
    ) -> Result<(), DivergenceError> {
        if endpoint_evidence.endpoint_canonical_id.trim().is_empty() {
            return Err(DivergenceError::MissingField("endpoint_canonical_id"));
        }
        if endpoint_evidence.endpoint_key_fingerprint.trim().is_empty() {
            return Err(DivergenceError::MissingField("endpoint_key_fingerprint"));
        }
        if endpoint_evidence.endpoint_canonical_id.len() > MAX_ENDPOINT_CANONICAL_ID_LENGTH {
            return Err(DivergenceError::StringTooLong {
                field: "endpoint_canonical_id",
                actual: endpoint_evidence.endpoint_canonical_id.len(),
                max: MAX_ENDPOINT_CANONICAL_ID_LENGTH,
            });
        }
        if endpoint_evidence.endpoint_key_fingerprint.len() > MAX_ENDPOINT_FINGERPRINT_LENGTH {
            return Err(DivergenceError::StringTooLong {
                field: "endpoint_key_fingerprint",
                actual: endpoint_evidence.endpoint_key_fingerprint.len(),
                max: MAX_ENDPOINT_FINGERPRINT_LENGTH,
            });
        }
        Ok(())
    }

    /// Derives a digest binding sink identity to concrete endpoint evidence.
    fn derive_sink_identity_digest(
        &self,
        endpoint_evidence: &SinkEndpointEvidenceV1,
    ) -> Result<Hash, DivergenceError> {
        Self::validate_sink_endpoint_evidence(endpoint_evidence)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.projection_compromise.sink_identity.v1");
        hasher.update(self.config.repo_id.as_bytes());
        hasher.update(self.config.actor_id.as_bytes());
        hasher.update(endpoint_evidence.endpoint_canonical_id.as_bytes());
        hasher.update(endpoint_evidence.endpoint_key_fingerprint.as_bytes());
        hasher.update(&endpoint_evidence.key_epoch.to_be_bytes());
        hasher.update(&[u8::from(endpoint_evidence.endpoint_identity_verified)]);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Derives endpoint binding digest independently from sink identity digest.
    fn derive_endpoint_binding_digest(
        endpoint_evidence: &SinkEndpointEvidenceV1,
    ) -> Result<Hash, DivergenceError> {
        Self::validate_sink_endpoint_evidence(endpoint_evidence)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.projection_compromise.endpoint_binding.v1");
        hasher.update(endpoint_evidence.endpoint_canonical_id.as_bytes());
        hasher.update(endpoint_evidence.endpoint_key_fingerprint.as_bytes());
        hasher.update(&endpoint_evidence.key_epoch.to_be_bytes());
        hasher.update(&[u8::from(endpoint_evidence.endpoint_identity_verified)]);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Checks for divergence between the merge receipt HEAD and external trunk
    /// HEAD.
    ///
    /// If divergence is detected AND the repository is not already frozen,
    /// emits an [`InterventionFreeze`] and a [`DefectRecord`] with signal type
    /// `PROJECTION_DIVERGENCE`, and registers the freeze.
    ///
    /// # Idempotency
    ///
    /// If the repository is already frozen (from a prior divergence detection),
    /// this method returns `None` without creating a new freeze event. This
    /// prevents unbounded memory growth in the `FreezeRegistry` from repeated
    /// polls during an adjudication window.
    ///
    /// # Arguments
    ///
    /// * `merge_receipt_head` - The expected trunk HEAD from the latest
    ///   `MergeReceipt`
    /// * `external_trunk_head` - The actual trunk HEAD observed externally
    ///
    /// # Returns
    ///
    /// `Some(DivergenceResult)` if divergence is detected AND a new freeze was
    /// created. `None` if no divergence OR if already frozen.
    ///
    /// # Errors
    ///
    /// Returns an error if freeze creation or registration fails.
    pub fn check_divergence(
        &self,
        merge_receipt_head: [u8; 32],
        external_trunk_head: [u8; 32],
    ) -> Result<Option<DivergenceResult>, DivergenceError> {
        // No divergence if heads match
        if bool::from(merge_receipt_head.ct_eq(&external_trunk_head)) {
            return Ok(None);
        }

        // Check if already frozen to prevent unbounded memory growth.
        // If the repository is already frozen (from a prior divergence), we don't
        // need to create another freeze event. This makes the operation idempotent
        // and prevents DoS via accumulated freeze IDs in the registry.
        if let Some(freeze_id) = self.registry.is_frozen(&self.config.repo_id)
            && !FreezeRegistry::is_precautionary_freeze_id(&freeze_id)
        {
            return Ok(None);
        }

        // Divergence detected and not already frozen - emit freeze and defect record
        let result = self.on_divergence(merge_receipt_head, external_trunk_head)?;

        Ok(Some(result))
    }

    /// Called when divergence is detected. Creates and registers a freeze
    /// event, and emits a `DefectRecord(PROJECTION_DIVERGENCE)`.
    ///
    /// This method:
    /// 1. Creates a `DefectRecord(PROJECTION_DIVERGENCE)`
    /// 2. Creates an `InterventionFreeze` event referencing the defect
    /// 3. Registers the freeze in the registry
    ///
    /// # Arguments
    ///
    /// * `expected_head` - The expected trunk HEAD from the latest
    ///   `MergeReceipt`
    /// * `actual_head` - The actual trunk HEAD observed externally
    ///
    /// # Returns
    ///
    /// A [`DivergenceResult`] containing both the freeze and defect record.
    ///
    /// # Errors
    ///
    /// Returns an error if freeze creation, defect record creation, or
    /// registration fails.
    pub fn on_divergence(
        &self,
        expected_head: [u8; 32],
        actual_head: [u8; 32],
    ) -> Result<DivergenceResult, DivergenceError> {
        let freeze_id = self.generate_freeze_id();
        let defect_id = self.generate_defect_id();
        let timestamp = self.time_source.now_nanos();
        let trusted_authority_bindings = self.trusted_authority_bindings()?;
        let VerifiedTemporalAuthority {
            envelope: time_authority_envelope,
            time_authority_ref,
        } = self.resolve_temporal_authority(timestamp, &trusted_authority_bindings)?;
        let time_envelope_ref = time_authority_envelope.time_envelope_ref.clone();
        let window_ref = time_authority_envelope.window_ref;
        let sink_endpoint_evidence = self.sink_endpoint_evidence(None);
        let sink_identity_digest = self.derive_sink_identity_digest(&sink_endpoint_evidence)?;
        let endpoint_binding_digest =
            Self::derive_endpoint_binding_digest(&sink_endpoint_evidence)?;

        let mut channel = ProjectionChannel::new(
            self.config.repo_id.clone(),
            ProjectionSurfaceType::GitRepository,
            expected_head,
        )
        .map_err(|error| {
            DivergenceError::ProjectionCompromiseValidationFailed(error.to_string())
        })?;

        let divergence = detect_projection_divergence(
            &channel,
            actual_head,
            expected_head,
            expected_head,
            time_authority_ref,
            window_ref,
        )
        .map_err(|error| DivergenceError::ProjectionCompromiseValidationFailed(error.to_string()))?
        .ok_or_else(|| {
            DivergenceError::ProjectionCompromiseValidationFailed(
                "mismatched heads did not produce divergence".to_string(),
            )
        })?;

        let source_trust_snapshot = SourceTrustSnapshotV1 {
            channel_id: self.config.repo_id.clone(),
            cas_state_digest: expected_head,
            ledger_state_digest: expected_head,
            expected_projection_digest: expected_head,
            time_authority_ref,
            window_ref,
        };
        let sink_identity_snapshot = ChannelIdentitySnapshotV1 {
            channel_id: self.config.repo_id.clone(),
            sink_identity_digest,
            observed_projection_digest: actual_head,
            endpoint_binding_digest,
            time_authority_ref,
            window_ref,
        };

        let compromise_signal = quarantine_channel(
            &mut channel,
            &divergence,
            &source_trust_snapshot,
            &sink_identity_snapshot,
            format!("projection-compromise-{freeze_id}"),
            self.config.actor_id.clone(),
            &self.signer,
            timestamp,
        )
        .map_err(|error| {
            DivergenceError::ProjectionCompromiseValidationFailed(error.to_string())
        })?;

        let replay_receipt = ProjectionReplayReceiptV1::create_signed(
            format!("projection-replay-{freeze_id}-0"),
            self.config.repo_id.clone(),
            0,
            expected_head,
            time_authority_ref,
            window_ref,
            source_trust_snapshot.snapshot_digest(),
            sink_identity_snapshot.snapshot_digest(),
            self.config.actor_id.clone(),
            &self.signer,
        )
        .map_err(|error| {
            DivergenceError::ProjectionCompromiseValidationFailed(error.to_string())
        })?;

        {
            let mut recovery_state = self.projection_recovery_state.lock().map_err(|e| {
                DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}"))
            })?;
            recovery_state.insert(
                freeze_id.clone(),
                ProjectionRecoveryState {
                    channel_id: self.config.repo_id.clone(),
                    source_snapshot: source_trust_snapshot.clone(),
                    sink_snapshot: sink_identity_snapshot.clone(),
                    receipts: vec![replay_receipt.clone()],
                    replay_sequence_bounds: ReplaySequenceBoundsV1 {
                        required_start_sequence: 0,
                        required_end_sequence: 0,
                    },
                    time_authority_envelope,
                    has_durable_provenance: false,
                    durable_evidence_digest: None,
                },
            );
        }

        let defect_details = serde_json::json!({
            "channel_id": divergence.channel_id,
            "expected_digest": hex::encode(divergence.expected_digest),
            "observed_digest": hex::encode(divergence.observed_digest),
            "divergence_evidence_digest": hex::encode(divergence.evidence_digest()),
            "source_trust_snapshot_digest": hex::encode(source_trust_snapshot.snapshot_digest()),
            "sink_identity_snapshot_digest": hex::encode(sink_identity_snapshot.snapshot_digest()),
            "time_authority_ref": hex::encode(time_authority_ref),
            "window_ref": hex::encode(window_ref),
            "time_envelope_ref": time_envelope_ref,
            "sink_endpoint_canonical_id": sink_endpoint_evidence.endpoint_canonical_id,
            "sink_endpoint_key_fingerprint": sink_endpoint_evidence.endpoint_key_fingerprint,
            "sink_endpoint_key_epoch": sink_endpoint_evidence.key_epoch,
            "sink_endpoint_identity_verified": sink_endpoint_evidence.endpoint_identity_verified,
        });

        let defect = DefectRecord::builder(&defect_id, "PROJECTION_DIVERGENCE")
            .severity(DefectSeverity::S0)
            .work_id(&self.config.repo_id)
            .detected_at(timestamp)
            .signal(DefectSignal::new(
                SignalType::ProjectionDivergence,
                defect_details.to_string(),
            ))
            .context(
                DefectContext::new()
                    .with_actor_id(self.config.actor_id.clone())
                    .with_requested_stable_id(self.config.repo_id.clone()),
            )
            .add_evidence(divergence.evidence_digest())
            .add_evidence(source_trust_snapshot.snapshot_digest())
            .add_evidence(sink_identity_snapshot.snapshot_digest())
            .add_remediation("quarantine compromised projection channel")
            .add_remediation("continue FAC authority using CAS+ledger trust roots")
            .add_remediation("reconstruct projection state from durable receipts before unfreeze")
            .build()
            .map_err(|e| {
                DivergenceError::InvalidConfiguration(format!("defect record error: {e}"))
            })?;

        // Create the freeze event referencing the defect
        let freeze = InterventionFreezeBuilder::new(&freeze_id)
            .scope(FreezeScope::Repository)
            .scope_value(&self.config.repo_id)
            .trigger_defect_id(&defect_id)
            .frozen_at(timestamp)
            .expected_trunk_head(expected_head)
            .actual_trunk_head(actual_head)
            .gate_actor_id(&self.config.actor_id)
            .time_envelope_ref(&time_envelope_ref)
            .try_build_and_sign(&self.signer)?;

        // Register the freeze (with signature verification per CTR-2703)
        self.registry
            .register(&freeze, &self.signer.verifying_key())?;

        // TCK-00307: Create DefectRecorded event
        // We compute the CAS hash by hashing the serialized DefectRecord.
        // In a real system, this would happen after storing in CAS, but for
        // divergence detection, we are the producer.
        let defect_bytes = serde_json::to_vec(&defect).map_err(|e| {
            DivergenceError::InvalidConfiguration(format!("serialization error: {e}"))
        })?;
        // Use BLAKE3 for CAS hash (RFC-0018)
        let cas_hash = blake3::hash(&defect_bytes).as_bytes().to_vec();

        let defect_event = DefectRecorded {
            defect_id,
            defect_type: defect.defect_class().to_string(),
            cas_hash,
            source: DefectSource::DivergenceWatchdog as i32,
            work_id: self.config.repo_id.clone(),
            severity: defect.severity().as_str().to_string(),
            detected_at: timestamp,
            time_envelope_ref: Some(TimeEnvelopeRef {
                hash: time_authority_ref.to_vec(),
            }),
        };

        Ok(DivergenceResult {
            freeze,
            defect,
            defect_event,
            compromise_signal,
            source_trust_snapshot,
            sink_identity_snapshot,
            replay_receipt,
        })
    }

    fn verify_projection_recovery_state(
        &self,
        freeze_id: &str,
    ) -> Result<ReconstructedProjectionState, DivergenceError> {
        let trusted_authority_bindings = self.trusted_authority_bindings()?;
        let now_ns = self.time_source.now_nanos();
        let recovery_state = self
            .projection_recovery_state
            .lock()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;
        let state = recovery_state
            .get(freeze_id)
            .ok_or_else(|| {
                DivergenceError::ProjectionRecoveryFailed(format!(
                    "missing recovery state for freeze_id={freeze_id}"
                ))
            })?
            .clone();
        drop(recovery_state);

        if !state.has_durable_provenance {
            return Err(DivergenceError::ProjectionRecoveryNotDurable {
                freeze_id: freeze_id.to_string(),
            });
        }
        match state.durable_evidence_digest {
            Some(digest) if !is_zero_hash(&digest) => {},
            Some(_) => {
                return Err(DivergenceError::ProjectionRecoveryFailed(
                    "durable evidence digest must be non-zero".to_string(),
                ));
            },
            None => {
                return Err(DivergenceError::ProjectionRecoveryFailed(
                    "durable evidence digest missing".to_string(),
                ));
            },
        }

        let verified_temporal_authority = Self::verify_temporal_authority_envelope(
            state.time_authority_envelope.clone(),
            &trusted_authority_bindings,
            now_ns,
        )?;
        if !bool::from(
            verified_temporal_authority
                .time_authority_ref
                .ct_eq(&state.source_snapshot.time_authority_ref),
        ) || !bool::from(
            verified_temporal_authority
                .time_authority_ref
                .ct_eq(&state.sink_snapshot.time_authority_ref),
        ) {
            return Err(DivergenceError::ProjectionRecoveryFailed(
                "temporal authority reference mismatch in recovery state".to_string(),
            ));
        }
        if !bool::from(
            verified_temporal_authority
                .envelope
                .window_ref
                .ct_eq(&state.source_snapshot.window_ref),
        ) || !bool::from(
            verified_temporal_authority
                .envelope
                .window_ref
                .ct_eq(&state.sink_snapshot.window_ref),
        ) {
            return Err(DivergenceError::ProjectionRecoveryFailed(
                "temporal window reference mismatch in recovery state".to_string(),
            ));
        }

        reconstruct_projection_state(
            &state.channel_id,
            &state.receipts,
            &state.source_snapshot,
            &state.sink_snapshot,
            &trusted_authority_bindings,
            state.replay_sequence_bounds,
        )
        .map_err(|error| DivergenceError::ProjectionRecoveryFailed(error.to_string()))
    }

    /// Registers durable post-compromise replay evidence for a freeze.
    ///
    /// This upgrades the recovery state from synthetic/in-memory evidence to
    /// durable provenance that can satisfy unfreeze gating.
    pub fn register_durable_recovery_evidence(
        &self,
        freeze_id: &str,
        receipts: Vec<ProjectionReplayReceiptV1>,
        durable_evidence_digest: Hash,
        sequence_bounds: ReplaySequenceBoundsV1,
    ) -> Result<(), DivergenceError> {
        let active =
            self.registry.active_freezes.read().map_err(|e| {
                DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}"))
            })?;
        if !active.contains(freeze_id) {
            return Err(DivergenceError::FreezeNotFound {
                freeze_id: freeze_id.to_string(),
            });
        }
        drop(active);

        if is_zero_hash(&durable_evidence_digest) {
            return Err(DivergenceError::ProjectionRecoveryFailed(
                "durable evidence digest must be non-zero".to_string(),
            ));
        }

        let trusted_authority_bindings = self.trusted_authority_bindings()?;
        let now_ns = self.time_source.now_nanos();
        let state = {
            let recovery_state = self.projection_recovery_state.lock().map_err(|e| {
                DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}"))
            })?;
            recovery_state
                .get(freeze_id)
                .ok_or_else(|| {
                    DivergenceError::ProjectionRecoveryFailed(format!(
                        "missing recovery state for freeze_id={freeze_id}"
                    ))
                })?
                .clone()
        };

        let verified_temporal_authority = Self::verify_temporal_authority_envelope(
            state.time_authority_envelope.clone(),
            &trusted_authority_bindings,
            now_ns,
        )?;
        if !bool::from(
            verified_temporal_authority
                .time_authority_ref
                .ct_eq(&state.source_snapshot.time_authority_ref),
        ) || !bool::from(
            verified_temporal_authority
                .time_authority_ref
                .ct_eq(&state.sink_snapshot.time_authority_ref),
        ) {
            return Err(DivergenceError::ProjectionRecoveryFailed(
                "temporal authority reference mismatch in recovery state".to_string(),
            ));
        }
        if !bool::from(
            verified_temporal_authority
                .envelope
                .window_ref
                .ct_eq(&state.source_snapshot.window_ref),
        ) || !bool::from(
            verified_temporal_authority
                .envelope
                .window_ref
                .ct_eq(&state.sink_snapshot.window_ref),
        ) {
            return Err(DivergenceError::ProjectionRecoveryFailed(
                "temporal window reference mismatch in recovery state".to_string(),
            ));
        }

        reconstruct_projection_state(
            &state.channel_id,
            &receipts,
            &state.source_snapshot,
            &state.sink_snapshot,
            &trusted_authority_bindings,
            sequence_bounds,
        )
        .map_err(|error| DivergenceError::ProjectionRecoveryFailed(error.to_string()))?;

        let mut recovery_state = self
            .projection_recovery_state
            .lock()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;
        let entry = recovery_state.get_mut(freeze_id).ok_or_else(|| {
            DivergenceError::ProjectionRecoveryFailed(format!(
                "missing recovery state for freeze_id={freeze_id}"
            ))
        })?;
        entry.receipts = receipts;
        entry.replay_sequence_bounds = sequence_bounds;
        entry.has_durable_provenance = true;
        entry.durable_evidence_digest = Some(durable_evidence_digest);
        Ok(())
    }

    /// Creates an unfreeze event for a given freeze ID.
    ///
    /// **IMPORTANT**: This method does NOT mutate the registry. The caller must
    /// persist the unfreeze event to the ledger first, then call
    /// [`Self::apply_unfreeze`] to update the local registry. This ensures
    /// local state and ledger state remain consistent even if the caller
    /// crashes between operations.
    ///
    /// # Correct Usage Pattern
    ///
    /// ```rust,ignore
    /// // 1. Create the unfreeze event (no local state change)
    /// let unfreeze = watchdog.create_unfreeze(freeze_id, resolution_type, adj_id)?;
    ///
    /// // 2. Persist to ledger (may fail)
    /// ledger.persist(&unfreeze).await?;
    ///
    /// // 3. Apply to local registry AFTER successful persistence (signature verified)
    /// watchdog.apply_unfreeze(&unfreeze)?;
    /// ```
    ///
    /// # Arguments
    ///
    /// * `freeze_id` - The ID of the freeze to lift
    /// * `resolution_type` - How the freeze was resolved
    /// * `adjudication_id` - The adjudication ID (required for some resolution
    ///   types)
    ///
    /// # Returns
    ///
    /// The created [`InterventionUnfreeze`] event. The event is signed but the
    /// registry is NOT modified.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::FreezeNotFound`] if the freeze is not active.
    /// Returns [`DivergenceError::AdjudicationRequired`] if adjudication is
    /// required but not provided.
    pub fn create_unfreeze(
        &self,
        freeze_id: &str,
        resolution_type: ResolutionType,
        adjudication_id: Option<&str>,
    ) -> Result<InterventionUnfreeze, DivergenceError> {
        // Verify the freeze exists
        let active =
            self.registry.active_freezes.read().map_err(|e| {
                DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}"))
            })?;

        if !active.contains(freeze_id) {
            return Err(DivergenceError::FreezeNotFound {
                freeze_id: freeze_id.to_string(),
            });
        }
        drop(active);

        // RFC-0028 REQ-0009: Post-containment projection replay must be
        // reconstructable from durable receipts before unfreeze.
        // Temporal ambiguity or receipt invalidity fails closed.
        let _reconstructed = self.verify_projection_recovery_state(freeze_id)?;

        let time_envelope_ref = self.generate_time_envelope_ref();

        let mut builder = InterventionUnfreezeBuilder::new(freeze_id)
            .resolution_type(resolution_type)
            .gate_actor_id(&self.config.actor_id)
            .time_envelope_ref(&time_envelope_ref);

        if let Some(adj_id) = adjudication_id {
            builder = builder.adjudication_id(adj_id);
        }

        let unfreeze = builder.try_build_and_sign(&self.signer)?;

        // NOTE: We intentionally do NOT unregister the freeze here.
        // The caller must persist the event to the ledger first, then call
        // apply_unfreeze() to update local state. This prevents inconsistency
        // if the caller crashes between local mutation and ledger persistence.

        Ok(unfreeze)
    }

    /// Applies an unfreeze to the local registry after ledger persistence.
    ///
    /// This method should be called AFTER the [`InterventionUnfreeze`] event
    /// has been successfully persisted to the ledger. This ordering ensures
    /// that the local registry state matches the ledger state even if the
    /// process crashes.
    ///
    /// # Security
    ///
    /// Per CTR-2703 (Cryptographically Bound ActorID): The unfreeze event's
    /// signature is verified before accepting the state mutation. This ensures
    /// that only properly authorized unfreeze events can lift a freeze,
    /// maintaining the security boundary integrity.
    ///
    /// # Arguments
    ///
    /// * `unfreeze` - The signed unfreeze event (signature will be verified)
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::InvalidUnfreezeSignature`] if signature
    /// verification fails.
    /// Returns [`DivergenceError::FreezeNotFound`] if the freeze is not in the
    /// registry.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Create unfreeze event
    /// let unfreeze = watchdog.create_unfreeze(freeze_id, ResolutionType::Adjudication, Some("adj-001"))?;
    ///
    /// // Persist to ledger first
    /// ledger.persist_unfreeze(&unfreeze).await?;
    ///
    /// // Then apply to local registry (signature verified)
    /// watchdog.apply_unfreeze(&unfreeze)?;
    /// ```
    pub fn apply_unfreeze(&self, unfreeze: &InterventionUnfreeze) -> Result<(), DivergenceError> {
        self.registry
            .unregister(unfreeze, &self.signer.verifying_key())?;
        let mut recovery_state = self
            .projection_recovery_state
            .lock()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;
        recovery_state.remove(&unfreeze.freeze_id);
        Ok(())
    }

    /// Checks if admission is allowed for the configured repository.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::RepoFrozen`] if the repository is frozen.
    pub fn check_admission(&self) -> Result<(), DivergenceError> {
        self.registry.check_admission(&self.config.repo_id)
    }
}

impl<T: TimeSource> std::fmt::Debug for DivergenceWatchdog<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DivergenceWatchdog")
            .field("config", &self.config)
            .field("active_freezes", &self.registry.active_count())
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Returns the current timestamp in nanoseconds since epoch.
fn current_timestamp_ns() -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn is_zero_hash(hash: &Hash) -> bool {
    hash.iter().all(|byte| *byte == 0)
}

/// Validates that a string field does not exceed the maximum length.
const fn validate_string_length(field: &'static str, value: &str) -> Result<(), DivergenceError> {
    if value.len() > MAX_STRING_LENGTH {
        return Err(DivergenceError::StringTooLong {
            field,
            actual: value.len(),
            max: MAX_STRING_LENGTH,
        });
    }
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
pub mod tests {
    use super::*;

    fn create_test_config() -> DivergenceWatchdogConfig {
        DivergenceWatchdogConfig::new("test-repo").expect("config should be valid")
    }

    fn create_test_watchdog() -> DivergenceWatchdog {
        let signer = Signer::generate();
        let config = create_test_config();
        // Use a hydrated registry for tests to bypass fail-closed checks
        let registry = Arc::new(FreezeRegistry::new_hydrated_for_testing());
        DivergenceWatchdog::with_registry(signer, config, registry)
    }

    fn derive_test_durable_digest(freeze_id: &str, receipts: &[ProjectionReplayReceiptV1]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.test.projection_durable_evidence_digest.v1");
        hasher.update(freeze_id.as_bytes());
        for receipt in receipts {
            hasher.update(&receipt.canonical_bytes());
            hasher.update(&receipt.signature);
        }
        *hasher.finalize().as_bytes()
    }

    fn register_test_durable_recovery(
        watchdog: &DivergenceWatchdog,
        freeze_id: &str,
        replay_receipt: &ProjectionReplayReceiptV1,
    ) {
        let receipts = vec![replay_receipt.clone()];
        let digest = derive_test_durable_digest(freeze_id, &receipts);
        watchdog
            .register_durable_recovery_evidence(
                freeze_id,
                receipts,
                digest,
                ReplaySequenceBoundsV1 {
                    required_start_sequence: 0,
                    required_end_sequence: 0,
                },
            )
            .expect("durable recovery evidence should register");
    }

    // =========================================================================
    // Type-Safe Identifier Tests (CTR-2602)
    // =========================================================================

    #[test]
    fn test_freeze_id_valid() {
        let id = FreezeId::new("freeze-001").unwrap();
        assert_eq!(id.as_str(), "freeze-001");
        assert_eq!(id.to_string(), "freeze-001");
    }

    #[test]
    fn test_freeze_id_empty_rejected() {
        let result = FreezeId::new("");
        assert!(matches!(
            result,
            Err(DivergenceError::InvalidConfiguration(msg)) if msg.contains("empty")
        ));
    }

    #[test]
    fn test_freeze_id_too_long_rejected() {
        let long_id = "x".repeat(MAX_FREEZE_ID_LENGTH + 1);
        let result = FreezeId::new(long_id);
        assert!(matches!(
            result,
            Err(DivergenceError::StringTooLong {
                field: "freeze_id",
                ..
            })
        ));
    }

    #[test]
    fn test_freeze_id_invalid_chars_rejected() {
        // Control character (tab)
        let result = FreezeId::new("freeze\t001");
        assert!(matches!(
            result,
            Err(DivergenceError::InvalidConfiguration(msg)) if msg.contains("invalid characters")
        ));
    }

    #[test]
    fn test_defect_id_valid() {
        let id = DefectId::new("defect-001").unwrap();
        assert_eq!(id.as_str(), "defect-001");
    }

    #[test]
    fn test_defect_id_empty_rejected() {
        let result = DefectId::new("");
        assert!(matches!(
            result,
            Err(DivergenceError::InvalidConfiguration(msg)) if msg.contains("empty")
        ));
    }

    #[test]
    fn test_actor_id_valid() {
        let id = ActorId::new("watchdog-001").unwrap();
        assert_eq!(id.as_str(), "watchdog-001");
    }

    #[test]
    fn test_actor_id_empty_rejected() {
        let result = ActorId::new("");
        assert!(matches!(
            result,
            Err(DivergenceError::InvalidConfiguration(msg)) if msg.contains("empty")
        ));
    }

    #[test]
    fn test_type_safe_ids_serde_roundtrip() {
        let freeze_id = FreezeId::new("freeze-001").unwrap();
        let json = serde_json::to_string(&freeze_id).unwrap();
        let parsed: FreezeId = serde_json::from_str(&json).unwrap();
        assert_eq!(freeze_id, parsed);
    }

    #[test]
    fn test_type_safe_ids_serde_deserialize_invalid() {
        // Empty string should fail deserialization
        let result: Result<FreezeId, _> = serde_json::from_str("\"\"");
        assert!(result.is_err());
    }

    // =========================================================================
    // FreezeScope Tests
    // =========================================================================

    #[test]
    fn test_freeze_scope_as_str() {
        assert_eq!(FreezeScope::Repository.as_str(), "REPOSITORY");
        assert_eq!(FreezeScope::Work.as_str(), "WORK");
        assert_eq!(FreezeScope::Namespace.as_str(), "NAMESPACE");
    }

    #[test]
    fn test_freeze_scope_as_bytes() {
        assert_eq!(FreezeScope::Repository.as_bytes(), b"REPOSITORY");
        assert_eq!(FreezeScope::Work.as_bytes(), b"WORK");
        assert_eq!(FreezeScope::Namespace.as_bytes(), b"NAMESPACE");
    }

    // =========================================================================
    // ResolutionType Tests
    // =========================================================================

    #[test]
    fn test_resolution_type_as_str() {
        assert_eq!(ResolutionType::Adjudication.as_str(), "ADJUDICATION");
        assert_eq!(ResolutionType::Manual.as_str(), "MANUAL");
        assert_eq!(ResolutionType::Rollback.as_str(), "ROLLBACK");
        assert_eq!(
            ResolutionType::AcceptDivergence.as_str(),
            "ACCEPT_DIVERGENCE"
        );
    }

    #[test]
    fn test_resolution_type_requires_adjudication() {
        assert!(ResolutionType::Adjudication.requires_adjudication());
        assert!(!ResolutionType::Manual.requires_adjudication());
        assert!(!ResolutionType::Rollback.requires_adjudication());
        assert!(ResolutionType::AcceptDivergence.requires_adjudication());
    }

    // =========================================================================
    // Proto Conversion Tests
    // =========================================================================

    #[test]
    fn test_freeze_scope_proto_conversion() {
        // Manual -> Proto -> Manual roundtrip
        assert_eq!(
            FreezeScope::try_from(ProtoScope::from(FreezeScope::Repository)).unwrap(),
            FreezeScope::Repository
        );
        assert_eq!(
            FreezeScope::try_from(ProtoScope::from(FreezeScope::Work)).unwrap(),
            FreezeScope::Work
        );
        assert_eq!(
            FreezeScope::try_from(ProtoScope::from(FreezeScope::Namespace)).unwrap(),
            FreezeScope::Namespace
        );

        // Unspecified should fail
        assert!(FreezeScope::try_from(ProtoScope::Unspecified).is_err());
    }

    #[test]
    fn test_freeze_scope_i32_conversion() {
        // Manual -> i32 -> Manual roundtrip
        assert_eq!(
            FreezeScope::try_from(i32::from(FreezeScope::Repository)).unwrap(),
            FreezeScope::Repository
        );
        assert_eq!(
            FreezeScope::try_from(i32::from(FreezeScope::Work)).unwrap(),
            FreezeScope::Work
        );
        assert_eq!(
            FreezeScope::try_from(i32::from(FreezeScope::Namespace)).unwrap(),
            FreezeScope::Namespace
        );

        // Invalid i32 should fail
        assert!(FreezeScope::try_from(99i32).is_err());
    }

    #[test]
    fn test_resolution_type_proto_conversion() {
        // Manual -> Proto -> Manual roundtrip
        assert_eq!(
            ResolutionType::try_from(ProtoResolutionType::from(ResolutionType::Adjudication))
                .unwrap(),
            ResolutionType::Adjudication
        );
        assert_eq!(
            ResolutionType::try_from(ProtoResolutionType::from(ResolutionType::Manual)).unwrap(),
            ResolutionType::Manual
        );
        assert_eq!(
            ResolutionType::try_from(ProtoResolutionType::from(ResolutionType::Rollback)).unwrap(),
            ResolutionType::Rollback
        );
        assert_eq!(
            ResolutionType::try_from(ProtoResolutionType::from(ResolutionType::AcceptDivergence))
                .unwrap(),
            ResolutionType::AcceptDivergence
        );

        // Unspecified should fail
        assert!(
            ResolutionType::try_from(ProtoResolutionType::InterventionResolutionUnspecified)
                .is_err()
        );
    }

    #[test]
    fn test_intervention_freeze_proto_conversion() {
        let signer = Signer::generate();
        // TCK-00469: Use runtime htf:tick format to prove lossless roundtrip.
        let time_envelope_ref_str = "htf:tick:1707123456789000000";
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .frozen_at(1_000_000_000)
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref(time_envelope_ref_str)
            .build_and_sign(&signer);

        // Manual -> Proto
        let proto: ProtoInterventionFreeze = freeze.clone().into();
        assert_eq!(proto.freeze_id, freeze.freeze_id);
        assert_eq!(proto.scope, i32::from(freeze.scope));
        assert_eq!(proto.scope_value, freeze.scope_value);
        assert_eq!(proto.trigger_defect_id, freeze.trigger_defect_id);
        assert_eq!(proto.frozen_at, freeze.frozen_at);
        assert_eq!(
            proto.expected_trunk_head,
            freeze.expected_trunk_head.to_vec()
        );
        assert_eq!(proto.actual_trunk_head, freeze.actual_trunk_head.to_vec());
        assert_eq!(proto.gate_actor_id, freeze.gate_actor_id);
        assert_eq!(proto.gate_signature, freeze.gate_signature.to_vec());
        // TCK-00469: proto hash field stores raw UTF-8 bytes of the original string.
        let proto_time_envelope_ref = proto
            .time_envelope_ref
            .as_ref()
            .map(|ter| String::from_utf8(ter.hash.clone()).unwrap())
            .unwrap_or_default();
        assert_eq!(proto_time_envelope_ref, freeze.time_envelope_ref);

        // Proto -> Manual roundtrip
        let recovered = InterventionFreeze::try_from(proto).unwrap();
        assert_eq!(recovered, freeze);
    }

    /// TCK-00469: Verify that freeze with htf:tick format survives proto
    /// roundtrip and signature verification still passes.
    #[test]
    fn test_intervention_freeze_proto_roundtrip_htf_tick_signature() {
        use ed25519_dalek::Verifier;

        let signer = Signer::generate();
        let time_envelope_ref_str = "htf:tick:1707123456789000000";
        let freeze = InterventionFreezeBuilder::new("freeze-sig-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-sig-001")
            .frozen_at(1_000_000_000)
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref(time_envelope_ref_str)
            .try_build_and_sign(&signer)
            .unwrap();

        // Roundtrip through proto
        let proto: ProtoInterventionFreeze = freeze.clone().into();
        let recovered = InterventionFreeze::try_from(proto).unwrap();

        // Canonical bytes must match (lossless roundtrip)
        assert_eq!(
            freeze.canonical_bytes(),
            recovered.canonical_bytes(),
            "canonical bytes must survive proto roundtrip for htf:tick format"
        );

        // Signature must still verify on the recovered struct
        let verifying_key = signer.verifying_key();
        let signature = ed25519_dalek::Signature::from_bytes(&recovered.gate_signature);
        let domain_sep = b"INTERVENTION_FREEZE:";
        let canonical = recovered.canonical_bytes();
        let mut msg = Vec::with_capacity(domain_sep.len() + canonical.len());
        msg.extend_from_slice(domain_sep);
        msg.extend_from_slice(&canonical);
        assert!(
            verifying_key.verify(&msg, &signature).is_ok(),
            "signature must verify after proto roundtrip with htf:tick format"
        );
    }

    #[test]
    fn test_intervention_unfreeze_proto_conversion() {
        let signer = Signer::generate();
        // TCK-00469: Use runtime htf:tick format to prove lossless roundtrip.
        let time_envelope_ref_str = "htf:tick:1707123456789000000";
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Adjudication)
            .adjudication_id("adj-001")
            .unfrozen_at(2_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref(time_envelope_ref_str)
            .build_and_sign(&signer);

        // Manual -> Proto
        let proto: ProtoInterventionUnfreeze = unfreeze.clone().into();
        assert_eq!(proto.freeze_id, unfreeze.freeze_id);
        assert_eq!(proto.resolution_type, i32::from(unfreeze.resolution_type));
        assert_eq!(proto.adjudication_id, "adj-001"); // Some -> string
        assert_eq!(proto.unfrozen_at, unfreeze.unfrozen_at);
        assert_eq!(proto.gate_actor_id, unfreeze.gate_actor_id);
        assert_eq!(proto.gate_signature, unfreeze.gate_signature.to_vec());
        // TCK-00469: proto hash field stores raw UTF-8 bytes of the original string.
        let proto_time_envelope_ref = proto
            .time_envelope_ref
            .as_ref()
            .map(|ter| String::from_utf8(ter.hash.clone()).unwrap())
            .unwrap_or_default();
        assert_eq!(proto_time_envelope_ref, unfreeze.time_envelope_ref);

        // Proto -> Manual roundtrip
        let recovered = InterventionUnfreeze::try_from(proto).unwrap();
        assert_eq!(recovered, unfreeze);
    }

    /// TCK-00469: Verify that unfreeze with htf:tick format survives proto
    /// roundtrip and signature verification still passes.
    #[test]
    fn test_intervention_unfreeze_proto_roundtrip_htf_tick_signature() {
        use ed25519_dalek::Verifier;

        let signer = Signer::generate();
        let time_envelope_ref_str = "htf:tick:1707123456789000000";
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-sig-002")
            .resolution_type(ResolutionType::Adjudication)
            .adjudication_id("adj-sig-002")
            .unfrozen_at(2_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref(time_envelope_ref_str)
            .try_build_and_sign(&signer)
            .unwrap();

        // Roundtrip through proto
        let proto: ProtoInterventionUnfreeze = unfreeze.clone().into();
        let recovered = InterventionUnfreeze::try_from(proto).unwrap();

        // Canonical bytes must match (lossless roundtrip)
        assert_eq!(
            unfreeze.canonical_bytes(),
            recovered.canonical_bytes(),
            "canonical bytes must survive proto roundtrip for htf:tick format"
        );

        // Signature must still verify on the recovered struct
        let verifying_key = signer.verifying_key();
        let signature = ed25519_dalek::Signature::from_bytes(&recovered.gate_signature);
        let domain_sep = b"INTERVENTION_UNFREEZE:";
        let canonical = recovered.canonical_bytes();
        let mut msg = Vec::with_capacity(domain_sep.len() + canonical.len());
        msg.extend_from_slice(domain_sep);
        msg.extend_from_slice(&canonical);
        assert!(
            verifying_key.verify(&msg, &signature).is_ok(),
            "signature must verify after proto roundtrip with htf:tick format"
        );
    }

    #[test]
    fn test_intervention_unfreeze_proto_conversion_none_adjudication() {
        let signer = Signer::generate();
        // TCK-00469: Use runtime htf:tick format to prove lossless roundtrip.
        let time_envelope_ref_str = "htf:tick:1707123456789000000";
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .unfrozen_at(2_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref(time_envelope_ref_str)
            .build_and_sign(&signer);

        // Manual -> Proto (None -> empty string)
        let proto: ProtoInterventionUnfreeze = unfreeze.clone().into();
        assert!(proto.adjudication_id.is_empty());

        // Proto -> Manual (empty string -> None)
        let recovered = InterventionUnfreeze::try_from(proto).unwrap();
        assert_eq!(recovered.adjudication_id, None);
        assert_eq!(recovered, unfreeze);
    }

    // =========================================================================
    // Canonical Bytes Tagged Encoding Tests
    // =========================================================================

    #[test]
    fn test_canonical_bytes_none_vs_empty_string_distinct() {
        let signer = Signer::generate();

        // Create unfreeze with adjudication_id = None
        let unfreeze_none = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .unfrozen_at(1_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Create unfreeze with adjudication_id = Some("")
        let unfreeze_empty = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .adjudication_id("")
            .unfrozen_at(1_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Per CTR-1605/CTR-2610: None and Some("") must produce DISTINCT canonical
        // bytes This prevents signature collision attacks
        assert_ne!(
            unfreeze_none.canonical_bytes(),
            unfreeze_empty.canonical_bytes(),
            "None and Some(\"\") must produce distinct canonical bytes"
        );
    }

    #[test]
    fn test_canonical_bytes_tagged_encoding_format() {
        let signer = Signer::generate();

        // Create unfreeze with adjudication_id = None
        let unfreeze_none = InterventionUnfreezeBuilder::new("f")
            .resolution_type(ResolutionType::Manual)
            .unfrozen_at(0)
            .gate_actor_id("a")
            .time_envelope_ref("t")
            .build_and_sign(&signer);

        let bytes_none = unfreeze_none.canonical_bytes();

        // Find the position of the adjudication_id tag
        // Format: freeze_id (4 + len) + resolution_type (4 + len) + tag
        let freeze_id_len = 1; // "f"
        let resolution_type_len = 6; // "MANUAL"
        let expected_tag_pos = 4 + freeze_id_len + 4 + resolution_type_len;

        // Verify tag byte is 0x00 for None
        assert_eq!(
            bytes_none[expected_tag_pos], OPTION_TAG_NONE,
            "None should use tag byte 0x00"
        );

        // Create unfreeze with adjudication_id = Some("x")
        let unfreeze_some = InterventionUnfreezeBuilder::new("f")
            .resolution_type(ResolutionType::Manual)
            .adjudication_id("x")
            .unfrozen_at(0)
            .gate_actor_id("a")
            .time_envelope_ref("t")
            .build_and_sign(&signer);

        let bytes_some = unfreeze_some.canonical_bytes();

        // Verify tag byte is 0x01 for Some
        assert_eq!(
            bytes_some[expected_tag_pos], OPTION_TAG_SOME,
            "Some should use tag byte 0x01"
        );

        // Verify length prefix follows the tag for Some
        let length_prefix = u32::from_be_bytes([
            bytes_some[expected_tag_pos + 1],
            bytes_some[expected_tag_pos + 2],
            bytes_some[expected_tag_pos + 3],
            bytes_some[expected_tag_pos + 4],
        ]);
        assert_eq!(length_prefix, 1, "Length prefix should be 1 for \"x\"");
    }

    // =========================================================================
    // InterventionFreeze Tests
    // =========================================================================

    #[test]
    fn test_freeze_builder() {
        let signer = Signer::generate();
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        assert_eq!(freeze.freeze_id, "freeze-001");
        assert_eq!(freeze.scope, FreezeScope::Repository);
        assert_eq!(freeze.scope_value, "test-repo");
        assert_eq!(freeze.trigger_defect_id, "defect-001");
        assert_eq!(freeze.expected_trunk_head, [0x42; 32]);
        assert_eq!(freeze.actual_trunk_head, [0x99; 32]);
        assert_eq!(freeze.gate_actor_id, "watchdog-001");
        assert_eq!(freeze.time_envelope_ref, "htf:tick:12345");
    }

    #[test]
    fn test_freeze_signature_valid() {
        let signer = Signer::generate();
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        assert!(freeze.validate_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_freeze_signature_invalid_with_other_key() {
        let signer = Signer::generate();
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let other_signer = Signer::generate();
        assert!(
            freeze
                .validate_signature(&other_signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_freeze_canonical_bytes_deterministic() {
        let signer = Signer::generate();
        let freeze1 = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .frozen_at(1_000_000_000)
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let freeze2 = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .frozen_at(1_000_000_000)
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        assert_eq!(freeze1.canonical_bytes(), freeze2.canonical_bytes());
    }

    #[test]
    fn test_freeze_missing_field() {
        let signer = Signer::generate();
        let result = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            // Missing scope_value
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(DivergenceError::MissingField("scope_value"))
        ));
    }

    #[test]
    fn test_freeze_string_too_long() {
        let signer = Signer::generate();
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let result = InterventionFreezeBuilder::new(long_string)
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(
            result,
            Err(DivergenceError::StringTooLong {
                field: "freeze_id",
                ..
            })
        ));
    }

    // =========================================================================
    // InterventionUnfreeze Tests
    // =========================================================================

    #[test]
    fn test_unfreeze_builder() {
        let signer = Signer::generate();
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Adjudication)
            .adjudication_id("adj-001")
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        assert_eq!(unfreeze.freeze_id, "freeze-001");
        assert_eq!(unfreeze.resolution_type, ResolutionType::Adjudication);
        assert_eq!(unfreeze.adjudication_id, Some("adj-001".to_string()));
        assert_eq!(unfreeze.gate_actor_id, "operator-001");
        assert_eq!(unfreeze.time_envelope_ref, "htf:tick:12345");
    }

    #[test]
    fn test_unfreeze_signature_valid() {
        let signer = Signer::generate();
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        assert!(unfreeze.validate_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_unfreeze_adjudication_required() {
        let signer = Signer::generate();
        let result = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Adjudication)
            // Missing adjudication_id
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(matches!(result, Err(DivergenceError::AdjudicationRequired)));
    }

    #[test]
    fn test_unfreeze_manual_no_adjudication_required() {
        let signer = Signer::generate();
        let result = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            // No adjudication_id needed
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .try_build_and_sign(&signer);

        assert!(result.is_ok());
    }

    // =========================================================================
    // FreezeRegistry Tests
    // =========================================================================

    #[test]
    fn test_registry_register_and_check() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();

        assert_eq!(registry.active_count(), 1);
        assert!(registry.is_frozen("test-repo").is_some());
        assert!(registry.is_frozen("other-repo").is_none());
    }

    #[test]
    fn test_registry_register_rejects_invalid_signature() {
        let signer = Signer::generate();
        let other_signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Try to register with wrong verifying key - should fail
        let result = registry.register(&freeze, &other_signer.verifying_key());
        assert!(matches!(
            result,
            Err(DivergenceError::InvalidFreezeSignature(_))
        ));
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_registry_unregister() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();
        assert_eq!(registry.active_count(), 1);

        // Create a signed unfreeze event
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12346")
            .build_and_sign(&signer);

        registry
            .unregister(&unfreeze, &signer.verifying_key())
            .unwrap();
        assert_eq!(registry.active_count(), 0);
        assert!(registry.is_frozen("test-repo").is_none());
    }

    #[test]
    fn test_registry_unregister_not_found() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        // Create a signed unfreeze event for a non-existent freeze
        let unfreeze = InterventionUnfreezeBuilder::new("nonexistent")
            .resolution_type(ResolutionType::Manual)
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let result = registry.unregister(&unfreeze, &signer.verifying_key());
        assert!(matches!(
            result,
            Err(DivergenceError::FreezeNotFound { .. })
        ));
    }

    #[test]
    fn test_registry_unregister_rejects_invalid_signature() {
        let signer = Signer::generate();
        let other_signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();
        assert_eq!(registry.active_count(), 1);

        // Create a signed unfreeze event with correct signer
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12346")
            .build_and_sign(&signer);

        // Try to unregister with wrong verifying key - should fail
        let result = registry.unregister(&unfreeze, &other_signer.verifying_key());
        assert!(matches!(
            result,
            Err(DivergenceError::InvalidUnfreezeSignature(_))
        ));
        // Freeze should still be active
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_registry_rejects_duplicate_scope_freeze() {
        // Security fix: Prevent unbounded memory growth by rejecting duplicate
        // scope registrations
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        let freeze1 = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // First registration should succeed
        registry
            .register(&freeze1, &signer.verifying_key())
            .unwrap();
        assert_eq!(registry.active_count(), 1);

        // Second freeze for the same scope should be rejected
        let freeze2 = InterventionFreezeBuilder::new("freeze-002")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo") // Same scope as freeze1
            .trigger_defect_id("defect-002")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x88; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12346")
            .build_and_sign(&signer);

        let result = registry.register(&freeze2, &signer.verifying_key());
        assert!(matches!(
            result,
            Err(DivergenceError::ScopeAlreadyFrozen { .. })
        ));

        // Still only one freeze registered
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_register_precautionary_freeze_registers_scope_and_exposes_freeze_id() {
        let registry = FreezeRegistry::new_hydrated_for_testing();
        let freeze_id = "precautionary-test-repo".to_string();

        assert!(registry.register_precautionary_freeze("test-repo", freeze_id.clone()));
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.is_frozen("test-repo"), Some(freeze_id));

        // Duplicate scope should not create an additional freeze.
        assert!(
            !registry.register_precautionary_freeze(
                "test-repo",
                "precautionary-test-repo-2".to_string()
            )
        );
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_remove_precautionary_freeze_only_removes_matching_precautionary_id() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();
        let precautionary_id = "precautionary-test-repo".to_string();
        assert!(registry.register_precautionary_freeze("test-repo", precautionary_id.clone()));

        // Wrong pattern must not remove.
        assert!(!registry.remove_precautionary_freeze("test-repo", "freeze-001"));
        assert_eq!(
            registry.is_frozen("test-repo"),
            Some(precautionary_id.clone())
        );

        // Mismatched precautionary ID must not remove.
        assert!(!registry.remove_precautionary_freeze("test-repo", "precautionary-other"));
        assert_eq!(
            registry.is_frozen("test-repo"),
            Some(precautionary_id.clone())
        );

        // Exact precautionary ID removes successfully.
        assert!(registry.remove_precautionary_freeze("test-repo", &precautionary_id));
        assert!(registry.is_frozen("test-repo").is_none());

        // Non-precautionary freeze IDs must not be removable through this API.
        let signed_freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("signed-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);
        registry
            .register(&signed_freeze, &signer.verifying_key())
            .unwrap();

        assert!(!registry.remove_precautionary_freeze("signed-repo", &signed_freeze.freeze_id));
        assert_eq!(
            registry.is_frozen("signed-repo"),
            Some(signed_freeze.freeze_id)
        );
    }

    #[test]
    fn test_registry_unregister_with_adjudication_succeeds() {
        // Verify that unfreeze with Adjudication type + adjudication_id works
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();
        assert_eq!(registry.active_count(), 1);

        // Unfreeze with Adjudication type requires adjudication_id
        // Note: The builder enforces this at build time
        // (test_unfreeze_adjudication_required) The registry also enforces this
        // as defense-in-depth
        let unfreeze_with_adj = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Adjudication)
            .adjudication_id("adj-001") // Required for Adjudication type
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12347")
            .build_and_sign(&signer);

        registry
            .unregister(&unfreeze_with_adj, &signer.verifying_key())
            .unwrap();
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_registry_check_admission() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        // Should allow admission when not frozen
        assert!(registry.check_admission("test-repo").is_ok());

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();

        // Should reject admission when frozen
        let result = registry.check_admission("test-repo");
        assert!(matches!(result, Err(DivergenceError::RepoFrozen { .. })));

        // Other repos should still be allowed
        assert!(registry.check_admission("other-repo").is_ok());
    }

    // =========================================================================
    // Hierarchical Freeze Tests
    // =========================================================================

    #[test]
    fn test_hierarchical_freeze_namespace_blocks_repos_slash() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        // Freeze the namespace "myorg"
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Namespace)
            .scope_value("myorg")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();

        // Direct match should be frozen
        assert!(registry.is_frozen("myorg").is_some());

        // Child scopes under the namespace should also be frozen (hierarchical)
        assert!(registry.is_frozen("myorg/repo1").is_some());
        assert!(registry.is_frozen("myorg/repo2").is_some());
        assert!(registry.is_frozen("myorg/repo/artifact/id").is_some());

        // Other namespaces should not be frozen
        assert!(registry.is_frozen("otherorg").is_none());
        assert!(registry.is_frozen("otherorg/repo").is_none());
    }

    #[test]
    fn test_hierarchical_freeze_namespace_blocks_repos_colon() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        // Freeze the namespace "myorg"
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Namespace)
            .scope_value("myorg")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();

        // Direct match should be frozen
        assert!(registry.is_frozen("myorg").is_some());

        // Child scopes under the namespace should also be frozen (hierarchical)
        assert!(registry.is_frozen("myorg:ticket").is_some());
        assert!(registry.is_frozen("myorg:rfc").is_some());
        assert!(registry.is_frozen("myorg:ticket:TCK-00213").is_some());

        // Other namespaces should not be frozen
        assert!(registry.is_frozen("otherorg").is_none());
        assert!(registry.is_frozen("otherorg:ticket").is_none());
    }

    #[test]
    fn test_hierarchical_freeze_repo_blocks_artifacts() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        // Freeze the repository "myorg/myrepo"
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("myorg/myrepo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();

        // Direct match should be frozen
        assert!(registry.is_frozen("myorg/myrepo").is_some());

        // Child paths under the repo should be frozen
        assert!(
            registry
                .is_frozen("myorg/myrepo/ticket/TCK-00213")
                .is_some()
        );
        assert!(registry.is_frozen("myorg/myrepo/artifact/id").is_some());

        // Parent namespace should NOT be frozen (freeze is repo-level only)
        assert!(registry.is_frozen("myorg").is_none());

        // Other repos in same org should not be frozen
        assert!(registry.is_frozen("myorg/otherrepo").is_none());
    }

    #[test]
    fn test_hierarchical_check_admission_blocks_children() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new_hydrated_for_testing();

        // Freeze the namespace
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Namespace)
            .scope_value("frozenorg")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze, &signer.verifying_key()).unwrap();

        // check_admission should block all children
        assert!(registry.check_admission("frozenorg").is_err());
        assert!(registry.check_admission("frozenorg/repo").is_err());
        assert!(registry.check_admission("frozenorg/repo/artifact").is_err());
        assert!(
            registry
                .check_admission("frozenorg:ticket:TCK-001")
                .is_err()
        );

        // Other orgs should pass
        assert!(registry.check_admission("allowedorg").is_ok());
        assert!(registry.check_admission("allowedorg/repo").is_ok());
    }

    #[test]
    fn test_hierarchical_parents_slash_iterator() {
        let parents: Vec<&str> = FreezeRegistry::hierarchical_parents_slash("a/b/c/d").collect();
        assert_eq!(parents, vec!["a/b/c", "a/b", "a"]);
    }

    #[test]
    fn test_hierarchical_parents_colon_iterator() {
        let parents: Vec<&str> = FreezeRegistry::hierarchical_parents_colon("a:b:c:d").collect();
        assert_eq!(parents, vec!["a:b:c", "a:b", "a"]);
    }

    #[test]
    fn test_hierarchical_parents_no_separator() {
        assert!(
            FreezeRegistry::hierarchical_parents_slash("single")
                .next()
                .is_none()
        );
        assert!(
            FreezeRegistry::hierarchical_parents_colon("single")
                .next()
                .is_none()
        );
    }

    // =========================================================================
    // DivergenceWatchdog Tests
    // =========================================================================

    #[test]
    fn test_watchdog_creation() {
        let watchdog = create_test_watchdog();
        assert_eq!(watchdog.poll_interval(), DEFAULT_POLL_INTERVAL);
        assert_eq!(watchdog.registry().active_count(), 0);
    }

    #[test]
    fn test_watchdog_no_divergence() {
        let watchdog = create_test_watchdog();

        let head = [0x42; 32];
        let result = watchdog.check_divergence(head, head).unwrap();

        assert!(result.is_none());
        assert_eq!(watchdog.registry().active_count(), 0);
    }

    #[test]
    fn test_watchdog_divergence_detected() {
        let watchdog = create_test_watchdog();

        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];
        let result = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap();

        assert!(result.is_some());
        let divergence_result = result.unwrap();
        let freeze = &divergence_result.freeze;

        assert_eq!(freeze.scope, FreezeScope::Repository);
        assert_eq!(freeze.scope_value, "test-repo");
        assert_eq!(freeze.expected_trunk_head, expected_head);
        assert_eq!(freeze.actual_trunk_head, actual_head);
        assert_eq!(watchdog.registry().active_count(), 1);

        // Verify defect record was also created
        assert_eq!(
            divergence_result.defect.defect_class(),
            "PROJECTION_DIVERGENCE"
        );
    }

    #[test]
    fn test_watchdog_divergence_idempotent_when_frozen() {
        // F-001 fix: check_divergence should be idempotent when already frozen
        let watchdog = create_test_watchdog();

        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];

        // First divergence should create a freeze
        let result1 = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap();
        assert!(result1.is_some());
        assert_eq!(watchdog.registry().active_count(), 1);

        // Second divergence should NOT create another freeze (idempotent)
        let result2 = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap();
        assert!(result2.is_none()); // No new freeze because already frozen
        assert_eq!(watchdog.registry().active_count(), 1); // Still only 1 freeze

        // Even with different heads, should NOT create another freeze
        let result3 = watchdog.check_divergence([0x11; 32], [0x22; 32]).unwrap();
        assert!(result3.is_none()); // Still idempotent
        assert_eq!(watchdog.registry().active_count(), 1);
    }

    #[test]
    fn test_watchdog_replaces_precautionary_freeze_with_divergence_freeze() {
        let watchdog = create_test_watchdog();
        let precautionary_id = "precautionary-test-repo".to_string();
        assert!(
            watchdog
                .registry()
                .register_precautionary_freeze("test-repo", precautionary_id.clone())
        );
        assert_eq!(
            watchdog.registry().is_frozen("test-repo"),
            Some(precautionary_id.clone())
        );

        let result = watchdog
            .check_divergence([0x42; 32], [0x99; 32])
            .expect("divergence check should succeed")
            .expect("divergence should replace precautionary freeze");

        assert_ne!(result.freeze.freeze_id, precautionary_id);
        assert_eq!(
            watchdog.registry().is_frozen("test-repo"),
            Some(result.freeze.freeze_id)
        );
    }

    #[test]
    fn test_registry_fail_closed_when_not_hydrated() {
        // F-002 fix: Registry should block all admissions when not hydrated
        let registry = FreezeRegistry::new_fail_closed();

        // Should block ALL admissions before hydration
        let result = registry.check_admission("any-repo");
        assert!(matches!(result, Err(DivergenceError::RepoFrozen { .. })));

        // is_frozen returns None (no specific freeze exists)
        assert!(registry.is_frozen("any-repo").is_none());

        // After hydration, normal operation resumes
        registry.mark_hydrated();
        assert!(registry.check_admission("any-repo").is_ok());
    }

    #[test]
    fn test_registry_hydration_state() {
        let registry = FreezeRegistry::new_fail_closed();
        assert!(!registry.is_hydrated());

        registry.mark_hydrated();
        assert!(registry.is_hydrated());
    }

    #[test]
    fn test_registry_new_is_fail_closed_by_default() {
        // CTR-2617: new() should be fail-closed by default
        let registry = FreezeRegistry::new();
        assert!(!registry.is_hydrated());

        // Should block all admissions before hydration
        let result = registry.check_admission("any-repo");
        assert!(matches!(result, Err(DivergenceError::RepoFrozen { .. })));

        // After hydration, normal operation resumes
        registry.mark_hydrated();
        assert!(registry.is_hydrated());
        assert!(registry.check_admission("any-repo").is_ok());
    }

    #[test]
    fn test_registry_hydrated_for_testing() {
        // Test helper should be hydrated for test convenience
        let registry = FreezeRegistry::new_hydrated_for_testing();
        assert!(registry.is_hydrated());
        assert!(registry.check_admission("any-repo").is_ok());
    }

    #[test]
    fn test_watchdog_freeze_signature_valid() {
        let watchdog = create_test_watchdog();

        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];
        let divergence_result = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap()
            .unwrap();

        assert!(
            divergence_result
                .freeze
                .validate_signature(&watchdog.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_watchdog_check_admission_before_divergence() {
        let watchdog = create_test_watchdog();

        // Should allow admission when no freeze
        assert!(watchdog.check_admission().is_ok());
    }

    #[test]
    fn test_watchdog_check_admission_after_divergence() {
        let watchdog = create_test_watchdog();

        // Trigger divergence
        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];
        watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap();

        // Should reject admission when frozen
        let result = watchdog.check_admission();
        assert!(matches!(result, Err(DivergenceError::RepoFrozen { .. })));
    }

    #[test]
    fn test_watchdog_create_unfreeze() {
        let watchdog = create_test_watchdog();

        // Trigger divergence first
        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];
        let divergence_result = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap()
            .unwrap();
        let freeze = &divergence_result.freeze;
        register_test_durable_recovery(
            &watchdog,
            &freeze.freeze_id,
            &divergence_result.replay_receipt,
        );

        assert!(watchdog.check_admission().is_err());

        // Create unfreeze (does NOT mutate registry - just creates the event)
        let unfreeze = watchdog
            .create_unfreeze(
                &freeze.freeze_id,
                ResolutionType::Adjudication,
                Some("adj-001"),
            )
            .unwrap();

        assert_eq!(unfreeze.freeze_id, freeze.freeze_id);
        assert_eq!(unfreeze.resolution_type, ResolutionType::Adjudication);
        assert_eq!(unfreeze.adjudication_id, Some("adj-001".to_string()));

        // Unfreeze signature should be valid
        assert!(
            unfreeze
                .validate_signature(&watchdog.verifying_key())
                .is_ok()
        );

        // Admission is STILL blocked because we haven't applied the unfreeze yet
        // This simulates the case where the ledger persistence hasn't happened
        assert!(watchdog.check_admission().is_err());

        // Now apply the unfreeze (simulating successful ledger persistence)
        // The signature is verified during apply_unfreeze
        watchdog.apply_unfreeze(&unfreeze).unwrap();
        {
            let recovery_state = watchdog
                .projection_recovery_state
                .lock()
                .expect("projection recovery lock should not be poisoned");
            assert!(
                !recovery_state.contains_key(&freeze.freeze_id),
                "projection recovery state should be removed after unfreeze apply",
            );
        }

        // Should allow admission after applying unfreeze
        assert!(watchdog.check_admission().is_ok());
    }

    #[test]
    fn test_unfreeze_fails_without_durable_provenance() {
        let watchdog = create_test_watchdog();
        let divergence = watchdog
            .check_divergence([0x42; 32], [0x99; 32])
            .expect("divergence check should succeed")
            .expect("divergence should create freeze");

        let error = watchdog
            .create_unfreeze(
                &divergence.freeze.freeze_id,
                ResolutionType::Adjudication,
                Some("adj-001"),
            )
            .expect_err("unfreeze should fail without durable provenance");
        assert!(
            matches!(
                error,
                DivergenceError::ProjectionRecoveryNotDurable { ref freeze_id }
                if freeze_id == &divergence.freeze.freeze_id
            ),
            "expected ProjectionRecoveryNotDurable, got {error:?}"
        );
    }

    #[test]
    fn test_watchdog_apply_unfreeze_not_found() {
        let watchdog = create_test_watchdog();

        // Create a fake unfreeze for a non-existent freeze
        let fake_unfreeze = InterventionUnfreezeBuilder::new("nonexistent")
            .resolution_type(ResolutionType::Manual)
            .gate_actor_id("test-actor")
            .time_envelope_ref("htf:tick:0")
            .build_and_sign(&watchdog.signer);

        // Try to apply unfreeze for non-existent freeze
        let result = watchdog.apply_unfreeze(&fake_unfreeze);
        assert!(matches!(
            result,
            Err(DivergenceError::FreezeNotFound { .. })
        ));
    }

    #[test]
    fn test_watchdog_unfreeze_not_found() {
        let watchdog = create_test_watchdog();

        let result = watchdog.create_unfreeze("nonexistent", ResolutionType::Manual, None);

        assert!(matches!(
            result,
            Err(DivergenceError::FreezeNotFound { .. })
        ));
    }

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn test_config_creation() {
        let config = DivergenceWatchdogConfig::new("test-repo").unwrap();
        assert_eq!(config.repo_id, "test-repo");
        assert_eq!(config.poll_interval, DEFAULT_POLL_INTERVAL);
    }

    #[test]
    fn test_config_empty_repo_id() {
        let result = DivergenceWatchdogConfig::new("");
        assert!(matches!(
            result,
            Err(DivergenceError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn test_config_poll_interval_valid() {
        let config = DivergenceWatchdogConfig::new("test-repo")
            .unwrap()
            .with_poll_interval(Duration::from_secs(60))
            .unwrap();

        assert_eq!(config.poll_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_config_poll_interval_too_short() {
        let config = DivergenceWatchdogConfig::new("test-repo").unwrap();
        let result = config.with_poll_interval(Duration::from_millis(100));

        assert!(matches!(
            result,
            Err(DivergenceError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn test_config_poll_interval_too_long() {
        let config = DivergenceWatchdogConfig::new("test-repo").unwrap();
        let result = config.with_poll_interval(Duration::from_secs(7200));

        assert!(matches!(
            result,
            Err(DivergenceError::InvalidConfiguration(_))
        ));
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_freeze_serde_roundtrip() {
        let signer = Signer::generate();
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .frozen_at(1_000_000_000)
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let json = serde_json::to_string(&freeze).unwrap();
        let recovered: InterventionFreeze = serde_json::from_str(&json).unwrap();

        assert_eq!(freeze.freeze_id, recovered.freeze_id);
        assert_eq!(freeze.scope, recovered.scope);
        assert_eq!(freeze.scope_value, recovered.scope_value);
        assert_eq!(freeze.trigger_defect_id, recovered.trigger_defect_id);
        assert_eq!(freeze.frozen_at, recovered.frozen_at);
        assert_eq!(freeze.expected_trunk_head, recovered.expected_trunk_head);
        assert_eq!(freeze.actual_trunk_head, recovered.actual_trunk_head);
        assert_eq!(freeze.gate_actor_id, recovered.gate_actor_id);
        assert_eq!(freeze.gate_signature, recovered.gate_signature);
        assert_eq!(freeze.time_envelope_ref, recovered.time_envelope_ref);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_unfreeze_serde_roundtrip() {
        let signer = Signer::generate();
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Adjudication)
            .adjudication_id("adj-001")
            .unfrozen_at(2_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        let json = serde_json::to_string(&unfreeze).unwrap();
        let recovered: InterventionUnfreeze = serde_json::from_str(&json).unwrap();

        assert_eq!(unfreeze.freeze_id, recovered.freeze_id);
        assert_eq!(unfreeze.resolution_type, recovered.resolution_type);
        assert_eq!(unfreeze.adjudication_id, recovered.adjudication_id);
        assert_eq!(unfreeze.unfrozen_at, recovered.unfrozen_at);
        assert_eq!(unfreeze.gate_actor_id, recovered.gate_actor_id);
        assert_eq!(unfreeze.gate_signature, recovered.gate_signature);
        assert_eq!(unfreeze.time_envelope_ref, recovered.time_envelope_ref);

        // Signature should still be valid
        assert!(
            recovered
                .validate_signature(&signer.verifying_key())
                .is_ok()
        );
    }

    // =========================================================================
    // Domain Separation Tests
    // =========================================================================

    #[test]
    fn test_freeze_domain_separator_prevents_replay() {
        let signer = Signer::generate();
        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Create a signature without domain prefix
        let canonical = freeze.canonical_bytes();
        let wrong_signature = signer.sign(&canonical); // No domain prefix!

        // Manually create a freeze with the wrong signature
        let mut bad_freeze = freeze;
        bad_freeze.gate_signature = wrong_signature.to_bytes();

        // Verification should fail
        assert!(
            bad_freeze
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    #[test]
    fn test_unfreeze_domain_separator_prevents_replay() {
        let signer = Signer::generate();
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Create a signature without domain prefix
        let canonical = unfreeze.canonical_bytes();
        let wrong_signature = signer.sign(&canonical); // No domain prefix!

        // Manually create an unfreeze with the wrong signature
        let mut bad_unfreeze = unfreeze;
        bad_unfreeze.gate_signature = wrong_signature.to_bytes();

        // Verification should fail
        assert!(
            bad_unfreeze
                .validate_signature(&signer.verifying_key())
                .is_err()
        );
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_full_freeze_unfreeze_cycle() {
        let watchdog = create_test_watchdog();

        // 1. Initially, admission is allowed
        assert!(watchdog.check_admission().is_ok());

        // 2. Divergence is detected
        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];
        let divergence_result = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap()
            .unwrap();
        let freeze = &divergence_result.freeze;
        register_test_durable_recovery(
            &watchdog,
            &freeze.freeze_id,
            &divergence_result.replay_receipt,
        );

        // 3. Admission is now blocked
        let err = watchdog.check_admission().unwrap_err();
        assert!(matches!(err, DivergenceError::RepoFrozen { .. }));

        // 4. Verify freeze signature
        assert!(freeze.validate_signature(&watchdog.verifying_key()).is_ok());

        // 5. Create unfreeze with adjudication (does NOT mutate registry)
        let unfreeze = watchdog
            .create_unfreeze(
                &freeze.freeze_id,
                ResolutionType::Adjudication,
                Some("adj-001"),
            )
            .unwrap();

        // 6. Verify unfreeze signature
        assert!(
            unfreeze
                .validate_signature(&watchdog.verifying_key())
                .is_ok()
        );

        // 7. Admission is still blocked (unfreeze not yet applied)
        assert!(watchdog.check_admission().is_err());

        // 8. Simulate: persist unfreeze to ledger (no-op in test)
        // In production: ledger.persist(&unfreeze).await?;

        // 9. Apply unfreeze to registry after successful persistence
        // The signature is verified during apply_unfreeze
        watchdog.apply_unfreeze(&unfreeze).unwrap();
        {
            let recovery_state = watchdog
                .projection_recovery_state
                .lock()
                .expect("projection recovery lock should not be poisoned");
            assert!(
                !recovery_state.contains_key(&freeze.freeze_id),
                "projection recovery state should be removed after unfreeze apply",
            );
        }

        // 10. Admission is allowed again
        assert!(watchdog.check_admission().is_ok());
    }

    #[test]
    fn test_multiple_divergences_idempotent() {
        // F-001 fix: Multiple divergences should NOT create multiple freezes.
        // Once a repository is frozen, subsequent divergences return None
        // to prevent DoS via unbounded memory growth in the FreezeRegistry.
        let watchdog = create_test_watchdog();

        // Trigger first divergence - should create a freeze
        let result1 = watchdog
            .check_divergence([0x11; 32], [0x22; 32])
            .unwrap()
            .unwrap();

        // Second divergence on the same (already frozen) repo should return None
        // This is the idempotent behavior that prevents DoS
        let result2 = watchdog.check_divergence([0x22; 32], [0x33; 32]).unwrap();

        assert!(result2.is_none()); // No new freeze because repo is already frozen
        assert_eq!(watchdog.registry().active_count(), 1); // Still only 1 freeze

        // The original freeze ID is still the only one (test-repo is from
        // create_test_config)
        assert!(watchdog.registry().is_frozen("test-repo").is_some());
        assert_eq!(
            watchdog.registry().is_frozen("test-repo"),
            Some(result1.freeze.freeze_id)
        );
    }

    #[test]
    fn test_divergence_result_contains_defect_record() {
        let watchdog = create_test_watchdog();

        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];
        let result = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap()
            .unwrap();

        // Verify the defect record is properly created
        assert_eq!(result.defect.defect_class(), "PROJECTION_DIVERGENCE");
        assert_eq!(
            result.defect.signal().signal_type(),
            apm2_holon::defect::SignalType::ProjectionDivergence
        );
        let details: serde_json::Value =
            serde_json::from_str(result.defect.signal().details()).expect("details must be JSON");
        let expected_hex = hex::encode(expected_head);
        let actual_hex = hex::encode(actual_head);
        assert_eq!(details["channel_id"].as_str(), Some("test-repo"));
        assert_eq!(
            details["expected_digest"].as_str(),
            Some(expected_hex.as_str())
        );
        assert_eq!(
            details["observed_digest"].as_str(),
            Some(actual_hex.as_str())
        );
        assert!(
            details["time_authority_ref"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "time_authority_ref must be present"
        );
        assert!(
            details["window_ref"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "window_ref must be present"
        );

        // Verify the freeze references the defect
        assert_eq!(result.freeze.trigger_defect_id, result.defect.defect_id());

        // TCK-00307: Verify DefectRecorded event is created
        assert_eq!(result.defect_event.defect_id, result.defect.defect_id());
        assert_eq!(result.defect_event.defect_type, "PROJECTION_DIVERGENCE");
        assert_eq!(
            result.defect_event.source,
            DefectSource::DivergenceWatchdog as i32
        );
        assert_eq!(result.defect_event.work_id, "test-repo");
        assert_eq!(result.defect_event.severity, "S0");
        assert!(!result.defect_event.cas_hash.is_empty()); // Hash should be present
        result
            .compromise_signal
            .verify_signature(&watchdog.verifying_key())
            .expect("compromise signal must verify");
        assert_eq!(result.source_trust_snapshot.channel_id, "test-repo");
        assert_eq!(result.sink_identity_snapshot.channel_id, "test-repo");
        let trusted_authority_bindings = watchdog
            .trusted_authority_bindings()
            .expect("trusted authority bindings must be valid");
        result
            .replay_receipt
            .verify_signature(&trusted_authority_bindings)
            .expect("replay receipt must verify");
    }

    #[test]
    fn test_sink_endpoint_evidence_local_placeholder_is_unverified() {
        let watchdog = create_test_watchdog();
        let evidence = watchdog.sink_endpoint_evidence(None);

        assert!(!evidence.endpoint_identity_verified);
        assert_eq!(evidence.endpoint_canonical_id, "github://test-repo");
        assert!(!evidence.endpoint_key_fingerprint.is_empty());
    }

    #[test]
    fn test_sink_endpoint_evidence_remote_fingerprint_is_verified() {
        let watchdog = create_test_watchdog();
        let evidence = watchdog.sink_endpoint_evidence(Some("remote-fingerprint"));

        assert!(evidence.endpoint_identity_verified);
        assert_eq!(evidence.endpoint_canonical_id, "github://test-repo");
        assert_eq!(evidence.endpoint_key_fingerprint, "remote-fingerprint");
    }

    #[test]
    fn test_endpoint_identity_verified_flag_domain_separates_digests() {
        let watchdog = create_test_watchdog();
        let unverified = SinkEndpointEvidenceV1 {
            endpoint_canonical_id: "github://test-repo".to_string(),
            endpoint_key_fingerprint: "fingerprint".to_string(),
            key_epoch: 0,
            endpoint_identity_verified: false,
        };
        let verified = SinkEndpointEvidenceV1 {
            endpoint_identity_verified: true,
            ..unverified.clone()
        };

        let unverified_sink_digest = watchdog
            .derive_sink_identity_digest(&unverified)
            .expect("unverified sink identity digest should derive");
        let verified_sink_digest = watchdog
            .derive_sink_identity_digest(&verified)
            .expect("verified sink identity digest should derive");
        assert_ne!(unverified_sink_digest, verified_sink_digest);

        let unverified_binding_digest =
            DivergenceWatchdog::<SystemTimeSource>::derive_endpoint_binding_digest(&unverified)
                .expect("unverified endpoint binding digest should derive");
        let verified_binding_digest =
            DivergenceWatchdog::<SystemTimeSource>::derive_endpoint_binding_digest(&verified)
                .expect("verified endpoint binding digest should derive");
        assert_ne!(unverified_binding_digest, verified_binding_digest);
    }

    #[test]
    fn test_temporal_authority_rejects_self_issued_when_external_configured() {
        let watchdog_signer = Signer::generate();
        let external_signer = Signer::generate();
        let config = create_test_config()
            .with_trusted_time_authority_bindings(vec![AuthorityKeyBindingV1 {
                actor_id: "external-time-authority".to_string(),
                verifying_key: external_signer.public_key_bytes(),
            }])
            .expect("external authority bindings should be valid");
        let registry = Arc::new(FreezeRegistry::new_hydrated_for_testing());
        let watchdog = DivergenceWatchdog::with_registry(watchdog_signer, config, registry);

        let error = watchdog
            .check_divergence([0x42; 32], [0x99; 32])
            .expect_err("self-issued temporal authority must be rejected");
        assert!(
            matches!(error, DivergenceError::InvalidTemporalAuthority(ref message) if message.contains("unknown time authority actor")),
            "expected InvalidTemporalAuthority unknown actor, got {error:?}"
        );
    }

    #[test]
    fn test_temporal_authority_accepts_external_envelope() {
        let watchdog_signer = Signer::generate();
        let external_signer = Signer::generate();
        let external_actor_id = "external-time-authority";
        let config = create_test_config()
            .with_trusted_time_authority_bindings(vec![AuthorityKeyBindingV1 {
                actor_id: external_actor_id.to_string(),
                verifying_key: external_signer.public_key_bytes(),
            }])
            .expect("external authority bindings should be valid");
        let registry = Arc::new(FreezeRegistry::new_hydrated_for_testing());
        let watchdog = DivergenceWatchdog::with_registry(watchdog_signer, config, registry);

        let issued_at_ns = current_timestamp_ns();
        let ttl_ns =
            u64::try_from(DEFAULT_TIME_AUTHORITY_TTL.as_nanos()).expect("ttl must fit in u64");
        let expires_at_ns = issued_at_ns
            .checked_add(ttl_ns)
            .expect("time authority expiry should not overflow");
        let envelope = TimeAuthorityEnvelopeV1::create_signed(
            "htf:tick:external-1",
            watchdog.derive_window_ref(issued_at_ns),
            issued_at_ns,
            expires_at_ns,
            external_actor_id,
            &external_signer,
        )
        .expect("external envelope should be signable");
        let expected_time_authority_ref = envelope.derive_time_authority_ref();
        watchdog
            .provide_time_authority_envelope(envelope)
            .expect("external envelope should be accepted");

        let divergence = watchdog
            .check_divergence([0x12; 32], [0x34; 32])
            .expect("divergence check should succeed")
            .expect("divergence should create freeze");
        assert_eq!(
            divergence.source_trust_snapshot.time_authority_ref,
            expected_time_authority_ref
        );
    }

    #[test]
    fn test_create_unfreeze_fails_closed_when_recovery_state_missing() {
        let watchdog = create_test_watchdog();

        let result = watchdog
            .check_divergence([0x42; 32], [0x99; 32])
            .expect("divergence check should succeed")
            .expect("divergence should create freeze");
        let freeze_id = result.freeze.freeze_id;
        {
            let mut recovery_state = watchdog
                .projection_recovery_state
                .lock()
                .expect("projection recovery lock should not be poisoned");
            recovery_state.remove(&freeze_id);
        }

        let error = watchdog
            .create_unfreeze(&freeze_id, ResolutionType::Adjudication, Some("adj-001"))
            .expect_err("missing recovery state must fail closed");
        assert!(
            matches!(error, DivergenceError::ProjectionRecoveryFailed(ref message) if message.contains("missing recovery state")),
            "expected projection recovery failure, got {error:?}"
        );
    }
}
