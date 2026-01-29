//! Evidence artifact types per AD-EVID-002.
//!
//! This module defines the `EvidenceArtifact` type representing
//! content-addressed evidence with TTL-based retention policies and pinning
//! support for incident binding.
//!
//! # Architecture
//!
//! ```text
//! EvidenceArtifact
//!     |
//!     +-- artifact_id: ArtifactId (unique identifier)
//!     +-- content_hash: Hash (CAS reference)
//!     +-- class: EvidenceClass (Ephemeral | Standard | Archival)
//!     +-- ttl: Duration (time-to-live)
//!     +-- pin_state: PinState (Unpinned | Pinned)
//!     +-- created_at: Timestamp (creation time)
//!     +-- episode_id: EpisodeId (owning episode)
//! ```
//!
//! # TTL Classes
//!
//! Per AD-EVID-002, evidence is classified by retention requirements:
//!
//! | Class     | Default TTL | Use Case                     |
//! |-----------|-------------|------------------------------|
//! | Ephemeral | 1 hour      | Debug logs, transient state  |
//! | Standard  | 7 days      | Normal operational evidence  |
//! | Archival  | 90 days     | Compliance, incident records |
//!
//! # Security Model
//!
//! - Pinned artifacts are protected from TTL expiration
//! - Pins require explicit reason and optional expiration
//! - Artifact IDs are validated to prevent injection
//! - All operations are fail-closed
//!
//! # Invariants
//!
//! - [INV-ART001] Artifact IDs are non-empty and bounded
//! - [INV-ART002] TTL is always positive
//! - [INV-ART003] Pinned artifacts include reason
//! - [INV-ART004] Created timestamp is non-zero
//!
//! # Contract References
//!
//! - AD-EVID-002: Evidence retention and TTL
//! - AD-CAC-001: Defect record binding
//! - CTR-1303: Bounded collections
//! - CTR-1604: `deny_unknown_fields` on ledger types

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::episode::EpisodeId;
use crate::evidence::receipt::Hash;

// =============================================================================
// Constants (CTR-1303)
// =============================================================================

/// Maximum length for artifact identifiers.
pub const MAX_ARTIFACT_ID_LEN: usize = 256;

/// Maximum length for pin reason.
pub const MAX_PIN_REASON_LEN: usize = 1024;

/// Maximum length for defect record ID.
pub const MAX_DEFECT_RECORD_ID_LEN: usize = 128;

/// Maximum length for actor ID in pins.
pub const MAX_PIN_ACTOR_LEN: usize = 256;

// =============================================================================
// TTL Defaults (AD-EVID-002)
// =============================================================================

/// Default TTL for ephemeral evidence (1 hour).
pub const EPHEMERAL_TTL_SECS: u64 = 3600;

/// Default TTL for standard evidence (7 days).
pub const STANDARD_TTL_SECS: u64 = 7 * 24 * 3600;

/// Default TTL for archival evidence (90 days).
pub const ARCHIVAL_TTL_SECS: u64 = 90 * 24 * 3600;

// =============================================================================
// ArtifactId
// =============================================================================

/// Unique identifier for an evidence artifact.
///
/// Format: `art-{content_hash_prefix}-{timestamp_ns}` where:
/// - `content_hash_prefix`: First 8 bytes of BLAKE3 hash (hex-encoded)
/// - `timestamp_ns`: Creation timestamp in nanoseconds
///
/// Maximum length: 256 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// Creates a new artifact ID with validation.
    ///
    /// # Errors
    ///
    /// Returns `ArtifactError::InvalidId` if the ID is empty, too long,
    /// or contains forbidden characters.
    pub fn new(id: impl Into<String>) -> Result<Self, ArtifactError> {
        let id = id.into();
        Self::validate(&id)?;
        Ok(Self(id))
    }

    /// Generates an artifact ID from a content hash and timestamp.
    ///
    /// This produces a deterministic ID suitable for CAS-backed artifacts.
    #[must_use]
    pub fn from_hash_and_timestamp(hash: &Hash, timestamp_ns: u64) -> Self {
        let prefix = hex::encode(&hash[..8]);
        let id = format!("art-{prefix}-{timestamp_ns}");
        // SAFETY: Generated format is always valid
        Self(id)
    }

    /// Returns the inner string reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates an artifact ID string.
    fn validate(id: &str) -> Result<(), ArtifactError> {
        // INV-ART001: Non-empty and bounded
        if id.is_empty() {
            return Err(ArtifactError::InvalidId {
                id: id.to_string(),
                reason: "artifact ID cannot be empty".to_string(),
            });
        }
        if id.len() > MAX_ARTIFACT_ID_LEN {
            return Err(ArtifactError::InvalidId {
                id: id.chars().take(32).collect::<String>() + "...",
                reason: format!(
                    "artifact ID exceeds maximum length of {MAX_ARTIFACT_ID_LEN} characters"
                ),
            });
        }
        // No null bytes or path separators
        if id.contains('\0') {
            return Err(ArtifactError::InvalidId {
                id: id.replace('\0', "\\0"),
                reason: "artifact ID cannot contain null bytes".to_string(),
            });
        }
        if id.contains('/') || id.contains('\\') {
            return Err(ArtifactError::InvalidId {
                id: id.to_string(),
                reason: "artifact ID cannot contain path separators".to_string(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ArtifactId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// EvidenceClass
// =============================================================================

/// Classification determining evidence retention policy.
///
/// Per AD-EVID-002, evidence is classified into retention tiers based on
/// compliance and operational requirements.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum EvidenceClass {
    /// Short-lived evidence for debugging.
    ///
    /// TTL: 1 hour. Auto-deleted on expiration.
    /// Use: Debug logs, transient state, development artifacts.
    Ephemeral,

    /// Standard operational evidence.
    ///
    /// TTL: 7 days. Normal retention for operational review.
    /// Use: Tool receipts, telemetry, episode bundles.
    #[default]
    Standard,

    /// Long-term evidence for compliance and incidents.
    ///
    /// TTL: 90 days. Extended retention for audits.
    /// Use: Security incidents, compliance records, defect evidence.
    Archival,
}

impl EvidenceClass {
    /// Returns the default TTL duration for this class.
    #[must_use]
    pub const fn default_ttl(&self) -> Duration {
        match self {
            Self::Ephemeral => Duration::from_secs(EPHEMERAL_TTL_SECS),
            Self::Standard => Duration::from_secs(STANDARD_TTL_SECS),
            Self::Archival => Duration::from_secs(ARCHIVAL_TTL_SECS),
        }
    }

    /// Returns the class name as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Standard => "standard",
            Self::Archival => "archival",
        }
    }

    /// Returns the default TTL in seconds.
    #[must_use]
    pub const fn default_ttl_secs(&self) -> u64 {
        match self {
            Self::Ephemeral => EPHEMERAL_TTL_SECS,
            Self::Standard => STANDARD_TTL_SECS,
            Self::Archival => ARCHIVAL_TTL_SECS,
        }
    }
}

impl fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// PinReason
// =============================================================================

/// Reason for pinning evidence to prevent expiration.
///
/// Pins are used to preserve evidence for incidents, investigations,
/// or compliance holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum PinReason {
    /// Evidence pinned due to active defect record.
    DefectBinding {
        /// Defect record ID that requires this evidence.
        defect_record_id: String,
    },

    /// Evidence pinned for incident investigation.
    IncidentInvestigation {
        /// Incident ID being investigated.
        incident_id: String,
        /// Brief description of the investigation.
        description: String,
    },

    /// Evidence pinned for compliance hold.
    ComplianceHold {
        /// Compliance requirement identifier.
        requirement_id: String,
        /// Regulatory body or standard.
        standard: String,
    },

    /// Evidence pinned by explicit operator request.
    ManualHold {
        /// Actor who requested the pin.
        actor: String,
        /// Reason for the manual pin.
        reason: String,
    },

    /// Evidence pinned during quarantine.
    QuarantineEvidence {
        /// Episode ID that was quarantined.
        quarantine_episode_id: String,
    },
}

impl PinReason {
    /// Creates a defect binding pin reason.
    #[must_use]
    pub fn defect_binding(defect_record_id: &str) -> Self {
        Self::DefectBinding {
            defect_record_id: truncate_string(
                defect_record_id.to_string(),
                MAX_DEFECT_RECORD_ID_LEN,
            ),
        }
    }

    /// Creates an incident investigation pin reason.
    #[must_use]
    pub fn incident_investigation(incident_id: &str, description: &str) -> Self {
        Self::IncidentInvestigation {
            incident_id: truncate_string(incident_id.to_string(), MAX_DEFECT_RECORD_ID_LEN),
            description: truncate_string(description.to_string(), MAX_PIN_REASON_LEN),
        }
    }

    /// Creates a compliance hold pin reason.
    #[must_use]
    pub fn compliance_hold(requirement_id: &str, standard: &str) -> Self {
        Self::ComplianceHold {
            requirement_id: truncate_string(requirement_id.to_string(), MAX_DEFECT_RECORD_ID_LEN),
            standard: truncate_string(standard.to_string(), MAX_DEFECT_RECORD_ID_LEN),
        }
    }

    /// Creates a manual hold pin reason.
    #[must_use]
    pub fn manual_hold(actor: &str, reason: &str) -> Self {
        Self::ManualHold {
            actor: truncate_string(actor.to_string(), MAX_PIN_ACTOR_LEN),
            reason: truncate_string(reason.to_string(), MAX_PIN_REASON_LEN),
        }
    }

    /// Creates a quarantine evidence pin reason.
    #[must_use]
    pub fn quarantine_evidence(episode_id: &EpisodeId) -> Self {
        Self::QuarantineEvidence {
            quarantine_episode_id: episode_id.as_str().to_string(),
        }
    }

    /// Returns the reason type as a string identifier.
    #[must_use]
    pub const fn reason_type(&self) -> &'static str {
        match self {
            Self::DefectBinding { .. } => "defect_binding",
            Self::IncidentInvestigation { .. } => "incident_investigation",
            Self::ComplianceHold { .. } => "compliance_hold",
            Self::ManualHold { .. } => "manual_hold",
            Self::QuarantineEvidence { .. } => "quarantine_evidence",
        }
    }

    /// Returns a human-readable summary of the pin reason.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::DefectBinding { defect_record_id } => {
                format!("Bound to defect record: {defect_record_id}")
            },
            Self::IncidentInvestigation {
                incident_id,
                description,
            } => {
                format!("Incident investigation {incident_id}: {description}")
            },
            Self::ComplianceHold {
                requirement_id,
                standard,
            } => {
                format!("Compliance hold ({standard}): {requirement_id}")
            },
            Self::ManualHold { actor, reason } => {
                format!("Manual hold by {actor}: {reason}")
            },
            Self::QuarantineEvidence {
                quarantine_episode_id,
            } => {
                format!("Quarantine evidence for episode: {quarantine_episode_id}")
            },
        }
    }
}

// =============================================================================
// PinState
// =============================================================================

/// Pin state for an evidence artifact.
///
/// Pinned artifacts are protected from TTL-based eviction until the pin
/// expires or is explicitly removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinState {
    /// Artifact is not pinned and subject to TTL eviction.
    #[default]
    Unpinned,

    /// Artifact is pinned and protected from TTL eviction.
    Pinned {
        /// Reason for the pin.
        reason: PinReason,
        /// Optional expiration timestamp (nanoseconds since epoch).
        /// If `None`, pin is indefinite until manual removal.
        expires_at: Option<u64>,
        /// Timestamp when pin was created (nanoseconds since epoch).
        pinned_at: u64,
    },
}

impl PinState {
    /// Creates a new unpinned state.
    #[must_use]
    pub const fn unpinned() -> Self {
        Self::Unpinned
    }

    /// Creates a new pinned state.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // PinReason is not Copy
    pub fn pinned(reason: PinReason, expires_at: Option<u64>, pinned_at: u64) -> Self {
        Self::Pinned {
            reason,
            expires_at,
            pinned_at,
        }
    }

    /// Returns `true` if the artifact is pinned.
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        matches!(self, Self::Pinned { .. })
    }

    /// Returns `true` if the artifact is unpinned.
    #[must_use]
    pub const fn is_unpinned(&self) -> bool {
        matches!(self, Self::Unpinned)
    }

    /// Returns the pin reason if pinned.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't return &PinReason in const fn
    pub fn reason(&self) -> Option<&PinReason> {
        match self {
            Self::Pinned { reason, .. } => Some(reason),
            Self::Unpinned => None,
        }
    }

    /// Returns the pin expiration if pinned with an expiration.
    #[must_use]
    pub const fn expires_at(&self) -> Option<u64> {
        match self {
            Self::Pinned { expires_at, .. } => *expires_at,
            Self::Unpinned => None,
        }
    }

    /// Checks if the pin has expired at the given timestamp.
    ///
    /// Returns `true` if the pin has expired, `false` if still active
    /// or if the artifact is unpinned.
    #[must_use]
    pub const fn is_expired_at(&self, now_ns: u64) -> bool {
        match self {
            Self::Pinned {
                expires_at: Some(exp),
                ..
            } => now_ns >= *exp,
            Self::Pinned {
                expires_at: None, ..
            }
            | Self::Unpinned => false,
        }
    }
}

// =============================================================================
// Timestamp
// =============================================================================

/// Timestamp in nanoseconds since Unix epoch.
///
/// This is a convenience type alias for clarity in artifact timestamps.
pub type Timestamp = u64;

// =============================================================================
// EvidenceArtifact
// =============================================================================

/// An evidence artifact stored in the content-addressed store.
///
/// Artifacts represent content-addressed evidence with TTL-based retention
/// and pinning support per AD-EVID-002.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::artifact::{EvidenceArtifact, EvidenceClass};
///
/// let artifact = EvidenceArtifact::try_new(
///     "art-abc123-1234567890",
///     [0u8; 32],
///     EvidenceClass::Standard,
///     "ep-test-001",
///     1_000_000_000,
/// )?;
///
/// assert!(!artifact.is_expired(2_000_000_000));
/// assert!(artifact.pin_state().is_unpinned());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    /// Unique artifact identifier.
    artifact_id: ArtifactId,

    /// BLAKE3 hash of artifact content (CAS reference).
    #[serde(with = "serde_hash")]
    content_hash: Hash,

    /// Evidence classification determining base TTL.
    class: EvidenceClass,

    /// Time-to-live in seconds from creation.
    ttl_secs: u64,

    /// Pin state (protected from TTL eviction if pinned).
    pin_state: PinState,

    /// Creation timestamp (nanoseconds since epoch).
    created_at: Timestamp,

    /// Owning episode identifier.
    episode_id: EpisodeId,
}

impl EvidenceArtifact {
    /// Creates a new evidence artifact with validation.
    ///
    /// Uses the default TTL for the specified evidence class.
    ///
    /// # Errors
    ///
    /// Returns `ArtifactError` if validation fails.
    pub fn try_new(
        artifact_id: &str,
        content_hash: Hash,
        class: EvidenceClass,
        episode_id: &str,
        created_at: Timestamp,
    ) -> Result<Self, ArtifactError> {
        Self::try_new_with_ttl(
            artifact_id,
            content_hash,
            class,
            class.default_ttl(),
            episode_id,
            created_at,
        )
    }

    /// Creates a new evidence artifact with custom TTL.
    ///
    /// # Errors
    ///
    /// Returns `ArtifactError` if validation fails.
    pub fn try_new_with_ttl(
        artifact_id: &str,
        content_hash: Hash,
        class: EvidenceClass,
        ttl: Duration,
        episode_id: &str,
        created_at: Timestamp,
    ) -> Result<Self, ArtifactError> {
        let artifact_id = ArtifactId::new(artifact_id)?;
        let episode_id =
            EpisodeId::new(episode_id).map_err(|e| ArtifactError::InvalidEpisodeId {
                reason: e.to_string(),
            })?;

        // INV-ART002: TTL must be positive
        if ttl.is_zero() {
            return Err(ArtifactError::InvalidTtl {
                ttl_secs: 0,
                reason: "TTL must be positive".to_string(),
            });
        }

        // INV-ART004: Created timestamp must be non-zero
        if created_at == 0 {
            return Err(ArtifactError::InvalidTimestamp {
                timestamp: 0,
                reason: "creation timestamp cannot be zero".to_string(),
            });
        }

        Ok(Self {
            artifact_id,
            content_hash,
            class,
            ttl_secs: ttl.as_secs(),
            pin_state: PinState::Unpinned,
            created_at,
            episode_id,
        })
    }

    /// Creates a new artifact from a content hash, generating the ID
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns `ArtifactError` if validation fails.
    pub fn from_content(
        content_hash: Hash,
        class: EvidenceClass,
        episode_id: &str,
        created_at: Timestamp,
    ) -> Result<Self, ArtifactError> {
        let artifact_id = ArtifactId::from_hash_and_timestamp(&content_hash, created_at);
        let episode_id =
            EpisodeId::new(episode_id).map_err(|e| ArtifactError::InvalidEpisodeId {
                reason: e.to_string(),
            })?;

        // INV-ART004: Created timestamp must be non-zero
        if created_at == 0 {
            return Err(ArtifactError::InvalidTimestamp {
                timestamp: 0,
                reason: "creation timestamp cannot be zero".to_string(),
            });
        }

        Ok(Self {
            artifact_id,
            content_hash,
            class,
            ttl_secs: class.default_ttl_secs(),
            pin_state: PinState::Unpinned,
            created_at,
            episode_id,
        })
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Returns the artifact ID.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns the content hash.
    #[must_use]
    pub const fn content_hash(&self) -> &Hash {
        &self.content_hash
    }

    /// Returns the evidence class.
    #[must_use]
    pub const fn class(&self) -> EvidenceClass {
        self.class
    }

    /// Returns the TTL in seconds.
    #[must_use]
    pub const fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Returns the TTL as a Duration.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_secs)
    }

    /// Returns the pin state.
    #[must_use]
    pub const fn pin_state(&self) -> &PinState {
        &self.pin_state
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Returns the owning episode ID.
    #[must_use]
    pub const fn episode_id(&self) -> &EpisodeId {
        &self.episode_id
    }

    // =========================================================================
    // TTL and Expiration
    // =========================================================================

    /// Returns the expiration timestamp (nanoseconds since epoch).
    ///
    /// This is calculated as `created_at + ttl_secs * 1_000_000_000`.
    #[must_use]
    pub const fn expires_at_ns(&self) -> u64 {
        self.created_at
            .saturating_add(self.ttl_secs.saturating_mul(1_000_000_000))
    }

    /// Checks if the artifact has expired at the given timestamp.
    ///
    /// Pinned artifacts never expire through TTL.
    #[must_use]
    pub const fn is_expired(&self, now_ns: u64) -> bool {
        // Pinned artifacts don't expire through TTL
        if self.pin_state.is_pinned() {
            return false;
        }
        now_ns >= self.expires_at_ns()
    }

    /// Returns the remaining TTL in seconds at the given timestamp.
    ///
    /// Returns 0 if already expired, or `u64::MAX` if pinned.
    #[must_use]
    pub const fn remaining_ttl_secs(&self, now_ns: u64) -> u64 {
        if self.pin_state.is_pinned() {
            return u64::MAX;
        }
        let expires_at = self.expires_at_ns();
        if now_ns >= expires_at {
            return 0;
        }
        (expires_at - now_ns) / 1_000_000_000
    }

    // =========================================================================
    // Pin Operations
    // =========================================================================

    /// Returns `true` if the artifact is pinned.
    #[must_use]
    pub const fn is_pinned(&self) -> bool {
        self.pin_state.is_pinned()
    }

    /// Pins the artifact with the given reason.
    ///
    /// # Arguments
    ///
    /// * `reason` - Why the artifact is being pinned
    /// * `expires_at` - Optional expiration for the pin (nanoseconds)
    /// * `now_ns` - Current timestamp (nanoseconds)
    pub fn pin(&mut self, reason: PinReason, expires_at: Option<u64>, now_ns: u64) {
        self.pin_state = PinState::pinned(reason, expires_at, now_ns);
    }

    /// Unpins the artifact, making it subject to TTL eviction again.
    pub fn unpin(&mut self) {
        self.pin_state = PinState::Unpinned;
    }

    /// Checks if a pinned artifact's pin has expired.
    ///
    /// Returns `true` if the artifact is pinned and the pin has expired.
    #[must_use]
    pub const fn is_pin_expired(&self, now_ns: u64) -> bool {
        self.pin_state.is_expired_at(now_ns)
    }

    /// Returns `true` if the artifact should be evicted at the given timestamp.
    ///
    /// An artifact should be evicted if:
    /// 1. It's unpinned and TTL has expired, OR
    /// 2. It's pinned but the pin has expired and TTL has expired
    #[must_use]
    pub const fn should_evict(&self, now_ns: u64) -> bool {
        match &self.pin_state {
            PinState::Unpinned => now_ns >= self.expires_at_ns(),
            PinState::Pinned { expires_at, .. } => {
                // Pin must be expired for eviction
                if let Some(pin_exp) = expires_at {
                    if now_ns < *pin_exp {
                        return false;
                    }
                } else {
                    // Indefinite pin - never evict
                    return false;
                }
                // Pin expired, check TTL
                now_ns >= self.expires_at_ns()
            },
        }
    }
}

// =============================================================================
// ArtifactError
// =============================================================================

/// Errors for artifact operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ArtifactError {
    /// Invalid artifact ID.
    #[error("invalid artifact ID '{id}': {reason}")]
    InvalidId {
        /// The invalid ID (truncated if too long).
        id: String,
        /// Reason for rejection.
        reason: String,
    },

    /// Invalid episode ID.
    #[error("invalid episode ID: {reason}")]
    InvalidEpisodeId {
        /// Reason for rejection.
        reason: String,
    },

    /// Invalid TTL.
    #[error("invalid TTL {ttl_secs}s: {reason}")]
    InvalidTtl {
        /// The invalid TTL value.
        ttl_secs: u64,
        /// Reason for rejection.
        reason: String,
    },

    /// Invalid timestamp.
    #[error("invalid timestamp {timestamp}: {reason}")]
    InvalidTimestamp {
        /// The invalid timestamp.
        timestamp: u64,
        /// Reason for rejection.
        reason: String,
    },

    /// Artifact not found.
    #[error("artifact not found: {id}")]
    NotFound {
        /// The artifact ID that was not found.
        id: String,
    },
}

impl ArtifactError {
    /// Returns the error kind as a string identifier.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::InvalidId { .. } => "invalid_id",
            Self::InvalidEpisodeId { .. } => "invalid_episode_id",
            Self::InvalidTtl { .. } => "invalid_ttl",
            Self::InvalidTimestamp { .. } => "invalid_timestamp",
            Self::NotFound { .. } => "not_found",
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Truncates a string to the maximum length, preserving valid UTF-8.
fn truncate_string(s: String, max_len: usize) -> String {
    if s.len() <= max_len {
        return s;
    }

    // Find a valid UTF-8 boundary
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    s[..end].to_string()
}

/// Serde helpers for Hash type.
mod serde_hash {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(hash: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(hash))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // UT-00171-03: Evidence class TTLs
    // =========================================================================

    #[test]
    fn test_evidence_class_ephemeral_ttl() {
        let class = EvidenceClass::Ephemeral;
        assert_eq!(class.default_ttl_secs(), EPHEMERAL_TTL_SECS);
        assert_eq!(class.default_ttl(), Duration::from_secs(3600));
    }

    #[test]
    fn test_evidence_class_standard_ttl() {
        let class = EvidenceClass::Standard;
        assert_eq!(class.default_ttl_secs(), STANDARD_TTL_SECS);
        assert_eq!(class.default_ttl(), Duration::from_secs(7 * 24 * 3600));
    }

    #[test]
    fn test_evidence_class_archival_ttl() {
        let class = EvidenceClass::Archival;
        assert_eq!(class.default_ttl_secs(), ARCHIVAL_TTL_SECS);
        assert_eq!(class.default_ttl(), Duration::from_secs(90 * 24 * 3600));
    }

    #[test]
    fn test_evidence_class_default() {
        assert_eq!(EvidenceClass::default(), EvidenceClass::Standard);
    }

    #[test]
    fn test_evidence_class_display() {
        assert_eq!(EvidenceClass::Ephemeral.to_string(), "ephemeral");
        assert_eq!(EvidenceClass::Standard.to_string(), "standard");
        assert_eq!(EvidenceClass::Archival.to_string(), "archival");
    }

    // =========================================================================
    // ArtifactId tests
    // =========================================================================

    #[test]
    fn test_artifact_id_valid() {
        let id = ArtifactId::new("art-abc123-1234567890").unwrap();
        assert_eq!(id.as_str(), "art-abc123-1234567890");
    }

    #[test]
    fn test_artifact_id_from_hash() {
        let hash = [0xab; 32];
        let id = ArtifactId::from_hash_and_timestamp(&hash, 1_000_000_000);
        assert!(id.as_str().starts_with("art-"));
        assert!(id.as_str().contains("abababab"));
    }

    #[test]
    fn test_artifact_id_empty_rejected() {
        let result = ArtifactId::new("");
        assert!(matches!(
            result,
            Err(ArtifactError::InvalidId { reason, .. }) if reason.contains("empty")
        ));
    }

    #[test]
    fn test_artifact_id_too_long_rejected() {
        let long_id = "x".repeat(MAX_ARTIFACT_ID_LEN + 1);
        let result = ArtifactId::new(long_id);
        assert!(matches!(
            result,
            Err(ArtifactError::InvalidId { reason, .. }) if reason.contains("maximum length")
        ));
    }

    #[test]
    fn test_artifact_id_null_rejected() {
        let result = ArtifactId::new("art\x00123");
        assert!(matches!(
            result,
            Err(ArtifactError::InvalidId { reason, .. }) if reason.contains("null")
        ));
    }

    #[test]
    fn test_artifact_id_path_separator_rejected() {
        assert!(ArtifactId::new("art/123").is_err());
        assert!(ArtifactId::new("art\\123").is_err());
    }

    // =========================================================================
    // PinState tests
    // =========================================================================

    #[test]
    fn test_pin_state_unpinned() {
        let state = PinState::unpinned();
        assert!(state.is_unpinned());
        assert!(!state.is_pinned());
        assert!(state.reason().is_none());
        assert!(state.expires_at().is_none());
    }

    #[test]
    fn test_pin_state_pinned() {
        let reason = PinReason::defect_binding("DEF-001");
        let state = PinState::pinned(reason, Some(2_000_000_000), 1_000_000_000);

        assert!(state.is_pinned());
        assert!(!state.is_unpinned());
        assert_eq!(state.reason().unwrap().reason_type(), "defect_binding");
        assert_eq!(state.expires_at(), Some(2_000_000_000));
    }

    #[test]
    fn test_pin_state_expiration() {
        let reason = PinReason::manual_hold("user", "testing");
        let state = PinState::pinned(reason, Some(2_000_000_000), 1_000_000_000);

        assert!(!state.is_expired_at(1_500_000_000));
        assert!(state.is_expired_at(2_000_000_000));
        assert!(state.is_expired_at(3_000_000_000));
    }

    #[test]
    fn test_pin_state_indefinite_never_expires() {
        let reason = PinReason::compliance_hold("SOC2", "Audit");
        let state = PinState::pinned(reason, None, 1_000_000_000);

        assert!(!state.is_expired_at(u64::MAX));
    }

    // =========================================================================
    // PinReason tests
    // =========================================================================

    #[test]
    fn test_pin_reason_defect_binding() {
        let reason = PinReason::defect_binding("DEF-001");
        assert_eq!(reason.reason_type(), "defect_binding");
        assert!(reason.summary().contains("DEF-001"));
    }

    #[test]
    fn test_pin_reason_incident_investigation() {
        let reason = PinReason::incident_investigation("INC-123", "Investigating memory leak");
        assert_eq!(reason.reason_type(), "incident_investigation");
        assert!(reason.summary().contains("INC-123"));
    }

    #[test]
    fn test_pin_reason_compliance_hold() {
        let reason = PinReason::compliance_hold("REQ-001", "SOC2");
        assert_eq!(reason.reason_type(), "compliance_hold");
        assert!(reason.summary().contains("SOC2"));
    }

    #[test]
    fn test_pin_reason_manual_hold() {
        let reason = PinReason::manual_hold("admin@example.com", "Testing retention");
        assert_eq!(reason.reason_type(), "manual_hold");
        assert!(reason.summary().contains("admin@example.com"));
    }

    // =========================================================================
    // EvidenceArtifact tests
    // =========================================================================

    #[test]
    fn test_artifact_creation() {
        let artifact = EvidenceArtifact::try_new(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Standard,
            "ep-test-001",
            1_000_000_000,
        )
        .unwrap();

        assert_eq!(artifact.artifact_id().as_str(), "art-test-001");
        assert_eq!(artifact.class(), EvidenceClass::Standard);
        assert_eq!(artifact.ttl_secs(), STANDARD_TTL_SECS);
        assert!(artifact.pin_state().is_unpinned());
    }

    #[test]
    fn test_artifact_from_content() {
        let hash = [0xab; 32];
        let artifact = EvidenceArtifact::from_content(
            hash,
            EvidenceClass::Ephemeral,
            "ep-test-001",
            1_000_000_000,
        )
        .unwrap();

        assert!(artifact.artifact_id().as_str().starts_with("art-"));
        assert_eq!(artifact.class(), EvidenceClass::Ephemeral);
        assert_eq!(artifact.ttl_secs(), EPHEMERAL_TTL_SECS);
    }

    #[test]
    fn test_artifact_zero_ttl_rejected() {
        let result = EvidenceArtifact::try_new_with_ttl(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Standard,
            Duration::ZERO,
            "ep-test-001",
            1_000_000_000,
        );
        assert!(matches!(result, Err(ArtifactError::InvalidTtl { .. })));
    }

    #[test]
    fn test_artifact_zero_timestamp_rejected() {
        let result = EvidenceArtifact::try_new(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Standard,
            "ep-test-001",
            0, // zero timestamp
        );
        assert!(matches!(
            result,
            Err(ArtifactError::InvalidTimestamp { .. })
        ));
    }

    // =========================================================================
    // UT-00171-01: TTL expiration
    // =========================================================================

    #[test]
    fn test_ttl_expiration() {
        let artifact = EvidenceArtifact::try_new(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Ephemeral,
            "ep-test-001",
            1_000_000_000, // created at 1 second
        )
        .unwrap();

        // TTL is 1 hour = 3600 seconds
        let expires_at = artifact.expires_at_ns();
        let expected = 1_000_000_000 + (EPHEMERAL_TTL_SECS * 1_000_000_000);
        assert_eq!(expires_at, expected);

        // Not expired before TTL
        assert!(!artifact.is_expired(1_000_000_000));
        assert!(!artifact.is_expired(expires_at - 1));

        // Expired at and after TTL
        assert!(artifact.is_expired(expires_at));
        assert!(artifact.is_expired(expires_at + 1_000_000_000));
    }

    #[test]
    fn test_remaining_ttl() {
        let artifact = EvidenceArtifact::try_new(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Standard,
            "ep-test-001",
            1_000_000_000,
        )
        .unwrap();

        // At creation time
        assert_eq!(
            artifact.remaining_ttl_secs(1_000_000_000),
            STANDARD_TTL_SECS
        );

        // After some time
        let later = 1_000_000_000 + (1_000_000_000 * 3600); // 1 hour later
        assert_eq!(artifact.remaining_ttl_secs(later), STANDARD_TTL_SECS - 3600);

        // After expiration
        let after_expiry = artifact.expires_at_ns() + 1;
        assert_eq!(artifact.remaining_ttl_secs(after_expiry), 0);
    }

    // =========================================================================
    // UT-00171-02: Pin prevents deletion
    // =========================================================================

    #[test]
    fn test_pin_retention() {
        let mut artifact = EvidenceArtifact::try_new(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Ephemeral,
            "ep-test-001",
            1_000_000_000,
        )
        .unwrap();

        // Should expire normally
        let after_ttl = artifact.expires_at_ns() + 1;
        assert!(artifact.should_evict(after_ttl));

        // Pin it
        artifact.pin(
            PinReason::defect_binding("DEF-001"),
            None, // indefinite
            1_000_000_000,
        );

        // Now should NOT expire even after TTL
        assert!(!artifact.is_expired(after_ttl));
        assert!(!artifact.should_evict(after_ttl));
        assert!(artifact.is_pinned());

        // Remaining TTL should be MAX for pinned
        assert_eq!(artifact.remaining_ttl_secs(after_ttl), u64::MAX);
    }

    #[test]
    fn test_pin_with_expiration() {
        let mut artifact = EvidenceArtifact::try_new(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Ephemeral,
            "ep-test-001",
            1_000_000_000,
        )
        .unwrap();

        // Pin with expiration before TTL expires
        let pin_expires = 2_000_000_000;
        artifact.pin(
            PinReason::manual_hold("user", "testing"),
            Some(pin_expires),
            1_000_000_000,
        );

        // Before pin expires - should not evict
        assert!(!artifact.should_evict(1_500_000_000));

        // After pin expires but before TTL - still not evict (pin expired but TTL
        // hasn't)
        assert!(!artifact.is_pin_expired(1_500_000_000));
        assert!(artifact.is_pin_expired(2_000_000_000));
    }

    #[test]
    fn test_unpin() {
        let mut artifact = EvidenceArtifact::try_new(
            "art-test-001",
            [0u8; 32],
            EvidenceClass::Ephemeral,
            "ep-test-001",
            1_000_000_000,
        )
        .unwrap();

        artifact.pin(PinReason::defect_binding("DEF-001"), None, 1_000_000_000);
        assert!(artifact.is_pinned());

        artifact.unpin();
        assert!(!artifact.is_pinned());
        assert!(artifact.pin_state().is_unpinned());
    }

    // =========================================================================
    // Serialization tests
    // =========================================================================

    #[test]
    fn test_artifact_serialization() {
        let artifact = EvidenceArtifact::try_new(
            "art-test-001",
            [0xab; 32],
            EvidenceClass::Standard,
            "ep-test-001",
            1_000_000_000,
        )
        .unwrap();

        let json = serde_json::to_string(&artifact).unwrap();
        let deserialized: EvidenceArtifact = serde_json::from_str(&json).unwrap();

        assert_eq!(artifact, deserialized);
    }

    #[test]
    fn test_evidence_class_serialization() {
        let class = EvidenceClass::Archival;
        let json = serde_json::to_string(&class).unwrap();
        assert_eq!(json, "\"archival\"");

        let deserialized: EvidenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, EvidenceClass::Archival);
    }

    #[test]
    fn test_pin_state_serialization() {
        let reason = PinReason::defect_binding("DEF-001");
        let state = PinState::pinned(reason, Some(2_000_000_000), 1_000_000_000);

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: PinState = serde_json::from_str(&json).unwrap();

        assert_eq!(state, deserialized);
    }

    /// SECURITY: Verify unknown fields are rejected.
    #[test]
    fn test_evidence_class_rejects_unknown_fields() {
        // Evidence class is a simple enum, test via artifact
        let json = r#"{
            "artifact_id": "art-test",
            "content_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "class": "standard",
            "ttl_secs": 604800,
            "pin_state": {"state": "unpinned"},
            "created_at": 1000000000,
            "episode_id": "ep-test",
            "malicious": "attack"
        }"#;

        let result: Result<EvidenceArtifact, _> = serde_json::from_str(json);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn test_artifact_error_kinds() {
        let err = ArtifactError::InvalidId {
            id: "x".to_string(),
            reason: "test".to_string(),
        };
        assert_eq!(err.kind(), "invalid_id");

        let err = ArtifactError::NotFound {
            id: "x".to_string(),
        };
        assert_eq!(err.kind(), "not_found");
    }
}
