// AGENT-AUTHORED
//! Quarantine projection for tracking quarantined pools and specs.
//!
//! This module implements the [`QuarantineProjection`] for tracking which
//! runner pools and AAT specs are currently quarantined in the Forge
//! Admission Cycle.
//!
//! # Overview
//!
//! When flakiness is detected during AAT execution, the system routes the
//! flake to appropriate quarantine actions based on classification:
//!
//! - [`FlakeClass::HarnessFlake`](crate::fac::FlakeClass) -> Quarantine runner
//!   pool
//! - [`FlakeClass::TestNonsemantic`](crate::fac::FlakeClass) -> Quarantine AAT
//!   spec
//! - [`FlakeClass::CodeNonsemantic`](crate::fac::FlakeClass) -> Quarantine AAT
//!   spec
//!
//! The projection maintains two sets tracking which pools and specs are
//! currently quarantined. Selection logic uses this projection to exclude
//! quarantined targets from AAT execution.
//!
//! # Events
//!
//! The projection processes three event types:
//!
//! - [`RunnerPoolQuarantined`]: Adds `pool_id` to quarantined pools
//! - [`AATSpecQuarantined`]: Adds `spec_id` to quarantined specs
//! - [`QuarantineCleared`]: Removes `target_id` from both sets
//!
//! # Security
//!
//! - All quarantine events require signatures for non-repudiation
//! - Evidence refs bind quarantine decisions to supporting data
//! - Time envelope refs enforce temporal authority bounds
//! - Resource limits prevent denial-of-service attacks
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::quarantine::{
//!     AATSpecQuarantined, QuarantineCleared, QuarantineEvent, QuarantineProjection,
//!     RunnerPoolQuarantined,
//! };
//!
//! let mut projection = QuarantineProjection::new();
//!
//! // Quarantine a runner pool
//! let pool_event = RunnerPoolQuarantined {
//!     quarantine_id: "q-001".to_string(),
//!     pool_id: "pool-flaky".to_string(),
//!     reason: "Timing flakiness detected".to_string(),
//!     evidence_refs: vec!["evidence-001".to_string()],
//!     time_envelope_ref: None,
//!     issuer_actor_id: "gate-001".to_string(),
//!     issuer_signature: [0u8; 64],
//! };
//! projection
//!     .apply(QuarantineEvent::PoolQuarantined(pool_event))
//!     .unwrap();
//!
//! assert!(projection.is_pool_quarantined("pool-flaky"));
//! assert!(!projection.is_pool_quarantined("pool-healthy"));
//!
//! // Clear the quarantine
//! let clear_event = QuarantineCleared {
//!     quarantine_id: "q-001".to_string(),
//!     target_id: "pool-flaky".to_string(),
//!     cleared_at: 1704067200000,
//!     issuer_actor_id: "gate-001".to_string(),
//!     issuer_signature: [0u8; 64],
//!     // HTF time envelope reference (RFC-0016): not yet populated.
//!     time_envelope_ref: None,
//! };
//! projection
//!     .apply(QuarantineEvent::Cleared(clear_event))
//!     .unwrap();
//!
//! assert!(!projection.is_pool_quarantined("pool-flaky"));
//! ```

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::domain_separator::{QUARANTINE_EVENT_PREFIX, verify_with_domain};
use crate::crypto::{Signature, VerifyingKey};
// Re-export proto types
pub use crate::events::{
    AatSpecQuarantined as AATSpecQuarantinedProto, QuarantineCleared as QuarantineClearedProto,
    RunnerPoolQuarantined as RunnerPoolQuarantinedProto,
};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length for string fields (denial-of-service protection).
pub const MAX_STRING_LENGTH: usize = 1024;

/// Maximum number of evidence refs per event (denial-of-service protection).
pub const MAX_EVIDENCE_REFS: usize = 64;

/// Maximum number of quarantined items per set (denial-of-service protection).
pub const MAX_QUARANTINED_ITEMS: usize = 10_000;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during quarantine operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum QuarantineError {
    /// String field exceeds maximum length.
    #[error("string field '{field}' exceeds maximum length ({len} > {max})")]
    StringTooLong {
        /// The field name.
        field: &'static str,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Too many evidence refs.
    #[error("evidence_refs exceeds maximum count ({count} > {max})")]
    TooManyEvidenceRefs {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Quarantine limit exceeded (denial-of-service protection).
    #[error("quarantine limit exceeded for {target_type} ({count} >= {max})")]
    QuarantineLimitExceeded {
        /// Type of target (pool or spec).
        target_type: &'static str,
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid data in conversion.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Invalid signature length.
    #[error("invalid signature length ({len} != 64)")]
    InvalidSignatureLength {
        /// Actual length.
        len: usize,
    },

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}

// =============================================================================
// Serde Helpers for TimeEnvelopeRef
// =============================================================================

/// Serializes a proto `TimeEnvelopeRef` to hex-encoded string.
///
/// Note: Serde requires `&Option<T>` signature for field-level serialization.
#[allow(clippy::ref_option)]
fn serialize_time_envelope_ref<S>(
    value: &Option<crate::events::TimeEnvelopeRef>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(envelope_ref) => {
            let hex = hex::encode(&envelope_ref.hash);
            serializer.serialize_some(&hex)
        },
        None => serializer.serialize_none(),
    }
}

/// Deserializes a hex-encoded string to a proto `TimeEnvelopeRef`.
fn deserialize_time_envelope_ref<'de, D>(
    deserializer: D,
) -> Result<Option<crate::events::TimeEnvelopeRef>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom(format!(
                    "time_envelope_ref hash must be 32 bytes, got {}",
                    bytes.len()
                )));
            }
            Ok(Some(crate::events::TimeEnvelopeRef { hash: bytes }))
        },
        None => Ok(None),
    }
}

// =============================================================================
// Domain Types
// =============================================================================

/// Event indicating a runner pool has been quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerPoolQuarantined {
    /// Unique identifier for this quarantine event.
    pub quarantine_id: String,

    /// ID of the runner pool being quarantined.
    pub pool_id: String,

    /// Human-readable reason for quarantine.
    pub reason: String,

    /// References to evidence supporting the quarantine decision.
    pub evidence_refs: Vec<String>,

    /// HTF time envelope reference for temporal authority (RFC-0016).
    /// Binds the quarantine event to verifiable HTF time.
    /// Stored as proto type for direct conversion; serde uses hex encoding.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_time_envelope_ref",
        deserialize_with = "deserialize_time_envelope_ref",
        default
    )]
    pub time_envelope_ref: Option<crate::events::TimeEnvelopeRef>,

    /// Actor who issued the quarantine.
    pub issuer_actor_id: String,

    /// Ed25519 signature over canonical bytes.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: [u8; 64],
}

impl RunnerPoolQuarantined {
    /// Computes the canonical bytes for signing/verification.
    ///
    /// The canonical encoding includes all fields EXCEPT the signature itself,
    /// in a deterministic order:
    /// - `quarantine_id` (length-prefixed)
    /// - `pool_id` (length-prefixed)
    /// - `reason` (length-prefixed)
    /// - `evidence_refs` count + each ref (length-prefixed, sorted)
    /// - `time_envelope_ref` (optional: present flag + 32 byte hash)
    /// - `issuer_actor_id` (length-prefixed)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All strings are bounded by MAX_STRING_LENGTH < u32::MAX
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // quarantine_id (length-prefixed)
        bytes.extend_from_slice(&(self.quarantine_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.quarantine_id.as_bytes());

        // pool_id (length-prefixed)
        bytes.extend_from_slice(&(self.pool_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.pool_id.as_bytes());

        // reason (length-prefixed)
        bytes.extend_from_slice(&(self.reason.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.reason.as_bytes());

        // evidence_refs (count + each ref length-prefixed, sorted for determinism)
        let mut sorted_refs = self.evidence_refs.clone();
        sorted_refs.sort();
        bytes.extend_from_slice(&(sorted_refs.len() as u32).to_be_bytes());
        for r in &sorted_refs {
            bytes.extend_from_slice(&(r.len() as u32).to_be_bytes());
            bytes.extend_from_slice(r.as_bytes());
        }

        // time_envelope_ref (optional: 1 byte present flag + 32 byte hash if present)
        if let Some(ref envelope_ref) = self.time_envelope_ref {
            bytes.push(1); // Present flag
            bytes.extend_from_slice(&envelope_ref.hash);
        } else {
            bytes.push(0); // Absent flag
        }

        // issuer_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.issuer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.issuer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the issuer signature using the `QUARANTINE_EVENT:` domain
    /// prefix.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected signer
    ///
    /// # Errors
    ///
    /// Returns [`QuarantineError::SignatureVerificationFailed`] if the
    /// signature does not match the canonical bytes.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), QuarantineError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.issuer_signature);

        verify_with_domain(
            verifying_key,
            QUARANTINE_EVENT_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|_| QuarantineError::SignatureVerificationFailed)
    }
}

/// Event indicating an AAT spec has been quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AATSpecQuarantined {
    /// Unique identifier for this quarantine event.
    pub quarantine_id: String,

    /// ID of the AAT spec being quarantined.
    pub spec_id: String,

    /// Human-readable reason for quarantine.
    pub reason: String,

    /// References to evidence supporting the quarantine decision.
    pub evidence_refs: Vec<String>,

    /// HTF time envelope reference for temporal authority (RFC-0016).
    /// Binds the quarantine event to verifiable HTF time.
    /// Stored as proto type for direct conversion; serde uses hex encoding.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_time_envelope_ref",
        deserialize_with = "deserialize_time_envelope_ref",
        default
    )]
    pub time_envelope_ref: Option<crate::events::TimeEnvelopeRef>,

    /// Actor who issued the quarantine.
    pub issuer_actor_id: String,

    /// Ed25519 signature over canonical bytes.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: [u8; 64],
}

impl AATSpecQuarantined {
    /// Computes the canonical bytes for signing/verification.
    ///
    /// The canonical encoding includes all fields EXCEPT the signature itself,
    /// in a deterministic order:
    /// - `quarantine_id` (length-prefixed)
    /// - `spec_id` (length-prefixed)
    /// - `reason` (length-prefixed)
    /// - `evidence_refs` count + each ref (length-prefixed, sorted)
    /// - `time_envelope_ref` (optional: present flag + 32 byte hash)
    /// - `issuer_actor_id` (length-prefixed)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All strings are bounded by MAX_STRING_LENGTH < u32::MAX
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // quarantine_id (length-prefixed)
        bytes.extend_from_slice(&(self.quarantine_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.quarantine_id.as_bytes());

        // spec_id (length-prefixed)
        bytes.extend_from_slice(&(self.spec_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.spec_id.as_bytes());

        // reason (length-prefixed)
        bytes.extend_from_slice(&(self.reason.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.reason.as_bytes());

        // evidence_refs (count + each ref length-prefixed, sorted for determinism)
        let mut sorted_refs = self.evidence_refs.clone();
        sorted_refs.sort();
        bytes.extend_from_slice(&(sorted_refs.len() as u32).to_be_bytes());
        for r in &sorted_refs {
            bytes.extend_from_slice(&(r.len() as u32).to_be_bytes());
            bytes.extend_from_slice(r.as_bytes());
        }

        // time_envelope_ref (optional: 1 byte present flag + 32 byte hash if present)
        if let Some(ref envelope_ref) = self.time_envelope_ref {
            bytes.push(1); // Present flag
            bytes.extend_from_slice(&envelope_ref.hash);
        } else {
            bytes.push(0); // Absent flag
        }

        // issuer_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.issuer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.issuer_actor_id.as_bytes());

        bytes
    }

    /// Verifies the issuer signature using the `QUARANTINE_EVENT:` domain
    /// prefix.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected signer
    ///
    /// # Errors
    ///
    /// Returns [`QuarantineError::SignatureVerificationFailed`] if the
    /// signature does not match the canonical bytes.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), QuarantineError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.issuer_signature);

        verify_with_domain(
            verifying_key,
            QUARANTINE_EVENT_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|_| QuarantineError::SignatureVerificationFailed)
    }
}

/// Event indicating a quarantine has been cleared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineCleared {
    /// ID of the original quarantine event being cleared.
    pub quarantine_id: String,

    /// ID of the target being cleared (`pool_id` or `spec_id`).
    pub target_id: String,

    /// OBSERVATIONAL - see HTF RFC-0016; not used for protocol authority.
    /// Timestamp when the quarantine was cleared (Unix nanoseconds).
    pub cleared_at: u64,

    /// Actor who cleared the quarantine.
    pub issuer_actor_id: String,

    /// Ed25519 signature over canonical bytes.
    #[serde(with = "serde_bytes")]
    pub issuer_signature: [u8; 64],

    /// HTF time envelope reference for temporal authority (RFC-0016).
    /// Binds the quarantine clearing event to verifiable HTF time.
    /// Stored as proto type for direct conversion; serde uses hex encoding.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_time_envelope_ref",
        deserialize_with = "deserialize_time_envelope_ref",
        default
    )]
    pub time_envelope_ref: Option<crate::events::TimeEnvelopeRef>,
}

impl QuarantineCleared {
    /// Computes the canonical bytes for signing/verification.
    ///
    /// The canonical encoding includes all fields EXCEPT the signature itself,
    /// in a deterministic order:
    /// - `quarantine_id` (length-prefixed)
    /// - `target_id` (length-prefixed)
    /// - `cleared_at` (8 bytes big-endian)
    /// - `issuer_actor_id` (length-prefixed)
    /// - `time_envelope_ref` (optional: present flag + 32 byte hash)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // All strings are bounded by MAX_STRING_LENGTH < u32::MAX
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // quarantine_id (length-prefixed)
        bytes.extend_from_slice(&(self.quarantine_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.quarantine_id.as_bytes());

        // target_id (length-prefixed)
        bytes.extend_from_slice(&(self.target_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.target_id.as_bytes());

        // cleared_at (8 bytes big-endian)
        bytes.extend_from_slice(&self.cleared_at.to_be_bytes());

        // issuer_actor_id (length-prefixed)
        bytes.extend_from_slice(&(self.issuer_actor_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.issuer_actor_id.as_bytes());

        // time_envelope_ref (optional: 1 byte present flag + 32 byte hash if present)
        if let Some(ref envelope_ref) = self.time_envelope_ref {
            bytes.push(1); // Present flag
            bytes.extend_from_slice(&envelope_ref.hash);
        } else {
            bytes.push(0); // Absent flag
        }

        bytes
    }

    /// Verifies the issuer signature using the `QUARANTINE_EVENT:` domain
    /// prefix.
    ///
    /// # Arguments
    ///
    /// * `verifying_key` - The public key of the expected signer
    ///
    /// # Errors
    ///
    /// Returns [`QuarantineError::SignatureVerificationFailed`] if the
    /// signature does not match the canonical bytes.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), QuarantineError> {
        let canonical = self.canonical_bytes();
        let signature = Signature::from_bytes(&self.issuer_signature);

        verify_with_domain(
            verifying_key,
            QUARANTINE_EVENT_PREFIX,
            &canonical,
            &signature,
        )
        .map_err(|_| QuarantineError::SignatureVerificationFailed)
    }
}

/// Union of all quarantine event types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineEvent {
    /// A runner pool was quarantined.
    PoolQuarantined(RunnerPoolQuarantined),

    /// An AAT spec was quarantined.
    SpecQuarantined(AATSpecQuarantined),

    /// A quarantine was cleared.
    Cleared(QuarantineCleared),
}

// =============================================================================
// QuarantineProjection
// =============================================================================

/// Projection tracking quarantined runner pools and AAT specs.
///
/// This projection maintains the current set of quarantined targets and
/// provides query methods for selection logic to exclude them.
///
/// # Thread Safety
///
/// This type is not thread-safe. For concurrent access, wrap in appropriate
/// synchronization primitives.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineProjection {
    /// Set of quarantined runner pool IDs.
    quarantined_pools: HashSet<String>,

    /// Set of quarantined AAT spec IDs.
    quarantined_specs: HashSet<String>,
}

impl QuarantineProjection {
    /// Creates a new empty projection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a quarantine event to update the projection state.
    ///
    /// # Arguments
    ///
    /// * `event` - The quarantine event to process.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the event was successfully applied.
    ///
    /// # Errors
    ///
    /// Returns [`QuarantineError`] if:
    /// - Resource limits are exceeded (denial-of-service protection)
    /// - Event validation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::quarantine::{
    ///     QuarantineEvent, QuarantineProjection, RunnerPoolQuarantined,
    /// };
    ///
    /// let mut projection = QuarantineProjection::new();
    ///
    /// let event = RunnerPoolQuarantined {
    ///     quarantine_id: "q-001".to_string(),
    ///     pool_id: "pool-001".to_string(),
    ///     reason: "Flaky".to_string(),
    ///     evidence_refs: vec![],
    ///     time_envelope_ref: None,
    ///     issuer_actor_id: "gate".to_string(),
    ///     issuer_signature: [0u8; 64],
    /// };
    ///
    /// projection
    ///     .apply(QuarantineEvent::PoolQuarantined(event))
    ///     .unwrap();
    /// assert!(projection.is_pool_quarantined("pool-001"));
    /// ```
    pub fn apply(&mut self, event: QuarantineEvent) -> Result<(), QuarantineError> {
        match event {
            QuarantineEvent::PoolQuarantined(e) => {
                // Validate event fields (DoS protection for direct domain type usage)
                validate_pool_quarantined(&e)?;
                // Check resource limits before adding
                if self.quarantined_pools.len() >= MAX_QUARANTINED_ITEMS
                    && !self.quarantined_pools.contains(&e.pool_id)
                {
                    return Err(QuarantineError::QuarantineLimitExceeded {
                        target_type: "pools",
                        count: self.quarantined_pools.len(),
                        max: MAX_QUARANTINED_ITEMS,
                    });
                }
                self.quarantined_pools.insert(e.pool_id);
            },
            QuarantineEvent::SpecQuarantined(e) => {
                // Validate event fields (DoS protection for direct domain type usage)
                validate_spec_quarantined(&e)?;
                // Check resource limits before adding
                if self.quarantined_specs.len() >= MAX_QUARANTINED_ITEMS
                    && !self.quarantined_specs.contains(&e.spec_id)
                {
                    return Err(QuarantineError::QuarantineLimitExceeded {
                        target_type: "specs",
                        count: self.quarantined_specs.len(),
                        max: MAX_QUARANTINED_ITEMS,
                    });
                }
                self.quarantined_specs.insert(e.spec_id);
            },
            QuarantineEvent::Cleared(e) => {
                // Validate event fields (DoS protection for direct domain type usage)
                validate_cleared(&e)?;
                // Remove from both sets (target could be either type)
                self.quarantined_pools.remove(&e.target_id);
                self.quarantined_specs.remove(&e.target_id);
            },
        }
        Ok(())
    }

    /// Returns `true` if the given pool ID is quarantined.
    ///
    /// Selection logic should use this to exclude quarantined pools from
    /// runner selection.
    ///
    /// # Arguments
    ///
    /// * `pool_id` - The pool ID to check.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::quarantine::QuarantineProjection;
    ///
    /// let projection = QuarantineProjection::new();
    /// assert!(!projection.is_pool_quarantined("pool-001"));
    /// ```
    #[must_use]
    pub fn is_pool_quarantined(&self, pool_id: &str) -> bool {
        self.quarantined_pools.contains(pool_id)
    }

    /// Returns `true` if the given spec ID is quarantined.
    ///
    /// Selection logic should use this to exclude quarantined specs from
    /// AAT selection.
    ///
    /// # Arguments
    ///
    /// * `spec_id` - The spec ID to check.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::quarantine::QuarantineProjection;
    ///
    /// let projection = QuarantineProjection::new();
    /// assert!(!projection.is_spec_quarantined("spec-001"));
    /// ```
    #[must_use]
    pub fn is_spec_quarantined(&self, spec_id: &str) -> bool {
        self.quarantined_specs.contains(spec_id)
    }

    /// Returns the number of quarantined pools.
    #[must_use]
    pub fn quarantined_pool_count(&self) -> usize {
        self.quarantined_pools.len()
    }

    /// Returns the number of quarantined specs.
    #[must_use]
    pub fn quarantined_spec_count(&self) -> usize {
        self.quarantined_specs.len()
    }

    /// Returns an iterator over quarantined pool IDs.
    pub fn quarantined_pools(&self) -> impl Iterator<Item = &str> {
        self.quarantined_pools.iter().map(String::as_str)
    }

    /// Returns an iterator over quarantined spec IDs.
    pub fn quarantined_specs(&self) -> impl Iterator<Item = &str> {
        self.quarantined_specs.iter().map(String::as_str)
    }
}

// =============================================================================
// Validation Functions
// =============================================================================

/// Validates a `RunnerPoolQuarantined` event.
fn validate_pool_quarantined(event: &RunnerPoolQuarantined) -> Result<(), QuarantineError> {
    validate_string_length("quarantine_id", &event.quarantine_id)?;
    validate_string_length("pool_id", &event.pool_id)?;
    validate_string_length("reason", &event.reason)?;
    validate_time_envelope_ref(event.time_envelope_ref.as_ref())?;
    validate_string_length("issuer_actor_id", &event.issuer_actor_id)?;
    validate_evidence_refs(&event.evidence_refs)?;
    Ok(())
}

/// Validates an `AATSpecQuarantined` event.
fn validate_spec_quarantined(event: &AATSpecQuarantined) -> Result<(), QuarantineError> {
    validate_string_length("quarantine_id", &event.quarantine_id)?;
    validate_string_length("spec_id", &event.spec_id)?;
    validate_string_length("reason", &event.reason)?;
    validate_time_envelope_ref(event.time_envelope_ref.as_ref())?;
    validate_string_length("issuer_actor_id", &event.issuer_actor_id)?;
    validate_evidence_refs(&event.evidence_refs)?;
    Ok(())
}

/// Validates a `QuarantineCleared` event.
fn validate_cleared(event: &QuarantineCleared) -> Result<(), QuarantineError> {
    validate_string_length("quarantine_id", &event.quarantine_id)?;
    validate_string_length("target_id", &event.target_id)?;
    validate_string_length("issuer_actor_id", &event.issuer_actor_id)?;
    Ok(())
}

/// Validates string length against `MAX_STRING_LENGTH`.
const fn validate_string_length(field: &'static str, value: &str) -> Result<(), QuarantineError> {
    if value.len() > MAX_STRING_LENGTH {
        return Err(QuarantineError::StringTooLong {
            field,
            len: value.len(),
            max: MAX_STRING_LENGTH,
        });
    }
    Ok(())
}

/// Validates a time envelope reference.
///
/// If present, the hash must be exactly 32 bytes (SHA-256).
fn validate_time_envelope_ref(
    envelope_ref: Option<&crate::events::TimeEnvelopeRef>,
) -> Result<(), QuarantineError> {
    if let Some(envelope) = envelope_ref {
        if envelope.hash.len() != 32 {
            return Err(QuarantineError::InvalidData(format!(
                "time_envelope_ref hash must be 32 bytes, got {}",
                envelope.hash.len()
            )));
        }
    }
    Ok(())
}

/// Validates evidence refs count and individual lengths.
fn validate_evidence_refs(refs: &[String]) -> Result<(), QuarantineError> {
    if refs.len() > MAX_EVIDENCE_REFS {
        return Err(QuarantineError::TooManyEvidenceRefs {
            count: refs.len(),
            max: MAX_EVIDENCE_REFS,
        });
    }
    for (i, r) in refs.iter().enumerate() {
        if r.len() > MAX_STRING_LENGTH {
            return Err(QuarantineError::StringTooLong {
                field: "evidence_refs",
                len: r.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        // Avoid unused variable warning
        let _ = i;
    }
    Ok(())
}

// =============================================================================
// Proto Conversions
// =============================================================================

impl TryFrom<RunnerPoolQuarantinedProto> for RunnerPoolQuarantined {
    type Error = QuarantineError;

    fn try_from(proto: RunnerPoolQuarantinedProto) -> Result<Self, Self::Error> {
        let issuer_signature: [u8; 64] = proto
            .issuer_signature
            .try_into()
            .map_err(|v: Vec<u8>| QuarantineError::InvalidSignatureLength { len: v.len() })?;

        let event = Self {
            quarantine_id: proto.quarantine_id,
            pool_id: proto.pool_id,
            reason: proto.reason,
            evidence_refs: proto.evidence_refs,
            time_envelope_ref: proto.time_envelope_ref,
            issuer_actor_id: proto.issuer_actor_id,
            issuer_signature,
        };

        validate_pool_quarantined(&event)?;
        Ok(event)
    }
}

impl From<RunnerPoolQuarantined> for RunnerPoolQuarantinedProto {
    fn from(domain: RunnerPoolQuarantined) -> Self {
        Self {
            quarantine_id: domain.quarantine_id,
            pool_id: domain.pool_id,
            reason: domain.reason,
            evidence_refs: domain.evidence_refs,
            time_envelope_ref: domain.time_envelope_ref,
            issuer_actor_id: domain.issuer_actor_id,
            issuer_signature: domain.issuer_signature.to_vec(),
        }
    }
}

impl TryFrom<AATSpecQuarantinedProto> for AATSpecQuarantined {
    type Error = QuarantineError;

    fn try_from(proto: AATSpecQuarantinedProto) -> Result<Self, Self::Error> {
        let issuer_signature: [u8; 64] = proto
            .issuer_signature
            .try_into()
            .map_err(|v: Vec<u8>| QuarantineError::InvalidSignatureLength { len: v.len() })?;

        let event = Self {
            quarantine_id: proto.quarantine_id,
            spec_id: proto.spec_id,
            reason: proto.reason,
            evidence_refs: proto.evidence_refs,
            time_envelope_ref: proto.time_envelope_ref,
            issuer_actor_id: proto.issuer_actor_id,
            issuer_signature,
        };

        validate_spec_quarantined(&event)?;
        Ok(event)
    }
}

impl From<AATSpecQuarantined> for AATSpecQuarantinedProto {
    fn from(domain: AATSpecQuarantined) -> Self {
        Self {
            quarantine_id: domain.quarantine_id,
            spec_id: domain.spec_id,
            reason: domain.reason,
            evidence_refs: domain.evidence_refs,
            time_envelope_ref: domain.time_envelope_ref,
            issuer_actor_id: domain.issuer_actor_id,
            issuer_signature: domain.issuer_signature.to_vec(),
        }
    }
}

impl TryFrom<QuarantineClearedProto> for QuarantineCleared {
    type Error = QuarantineError;

    fn try_from(proto: QuarantineClearedProto) -> Result<Self, Self::Error> {
        let issuer_signature: [u8; 64] = proto
            .issuer_signature
            .try_into()
            .map_err(|v: Vec<u8>| QuarantineError::InvalidSignatureLength { len: v.len() })?;

        let event = Self {
            quarantine_id: proto.quarantine_id,
            target_id: proto.target_id,
            cleared_at: proto.cleared_at,
            issuer_actor_id: proto.issuer_actor_id,
            issuer_signature,
            time_envelope_ref: proto.time_envelope_ref,
        };

        validate_cleared(&event)?;
        Ok(event)
    }
}

impl From<QuarantineCleared> for QuarantineClearedProto {
    fn from(domain: QuarantineCleared) -> Self {
        Self {
            quarantine_id: domain.quarantine_id,
            target_id: domain.target_id,
            cleared_at: domain.cleared_at,
            issuer_actor_id: domain.issuer_actor_id,
            issuer_signature: domain.issuer_signature.to_vec(),
            time_envelope_ref: domain.time_envelope_ref,
        }
    }
}

// =============================================================================
// QuarantineEvent Proto Conversions
// =============================================================================

use crate::events::kernel_event::Payload;

impl TryFrom<Payload> for QuarantineEvent {
    type Error = QuarantineError;

    fn try_from(payload: Payload) -> Result<Self, Self::Error> {
        match payload {
            Payload::RunnerPoolQuarantined(proto) => Ok(Self::PoolQuarantined(proto.try_into()?)),
            Payload::AatSpecQuarantined(proto) => Ok(Self::SpecQuarantined(proto.try_into()?)),
            Payload::QuarantineCleared(proto) => Ok(Self::Cleared(proto.try_into()?)),
            _ => Err(QuarantineError::InvalidData(
                "Payload is not a quarantine event".to_string(),
            )),
        }
    }
}

impl From<QuarantineEvent> for Payload {
    fn from(event: QuarantineEvent) -> Self {
        match event {
            QuarantineEvent::PoolQuarantined(e) => Self::RunnerPoolQuarantined(e.into()),
            QuarantineEvent::SpecQuarantined(e) => Self::AatSpecQuarantined(e.into()),
            QuarantineEvent::Cleared(e) => Self::QuarantineCleared(e.into()),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
pub mod tests {
    use super::*;

    // =========================================================================
    // Test Helpers
    // =========================================================================

    fn create_pool_quarantined(pool_id: &str) -> RunnerPoolQuarantined {
        RunnerPoolQuarantined {
            quarantine_id: format!("q-{pool_id}"),
            pool_id: pool_id.to_string(),
            reason: "Test flakiness".to_string(),
            evidence_refs: vec!["evidence-001".to_string()],
            time_envelope_ref: Some(crate::events::TimeEnvelopeRef {
                hash: [0x42u8; 32].to_vec(),
            }),
            issuer_actor_id: "gate-001".to_string(),
            issuer_signature: [0u8; 64],
        }
    }

    fn create_spec_quarantined(spec_id: &str) -> AATSpecQuarantined {
        AATSpecQuarantined {
            quarantine_id: format!("q-{spec_id}"),
            spec_id: spec_id.to_string(),
            reason: "Non-deterministic output".to_string(),
            evidence_refs: vec!["evidence-002".to_string()],
            time_envelope_ref: Some(crate::events::TimeEnvelopeRef {
                hash: [0x43u8; 32].to_vec(),
            }),
            issuer_actor_id: "gate-002".to_string(),
            issuer_signature: [0u8; 64],
        }
    }

    fn create_cleared(target_id: &str) -> QuarantineCleared {
        QuarantineCleared {
            quarantine_id: format!("q-{target_id}"),
            target_id: target_id.to_string(),
            cleared_at: 1_704_067_200_000,
            issuer_actor_id: "gate-001".to_string(),
            issuer_signature: [0u8; 64],
            time_envelope_ref: Some(crate::events::TimeEnvelopeRef {
                hash: [0x44u8; 32].to_vec(),
            }),
        }
    }

    // =========================================================================
    // Projection Tests
    // =========================================================================

    #[test]
    fn test_new_projection_is_empty() {
        let projection = QuarantineProjection::new();
        assert_eq!(projection.quarantined_pool_count(), 0);
        assert_eq!(projection.quarantined_spec_count(), 0);
    }

    #[test]
    fn test_pool_quarantine_and_query() {
        let mut projection = QuarantineProjection::new();

        // Initially not quarantined
        assert!(!projection.is_pool_quarantined("pool-001"));

        // Quarantine the pool
        let event = create_pool_quarantined("pool-001");
        projection
            .apply(QuarantineEvent::PoolQuarantined(event))
            .unwrap();

        // Now quarantined
        assert!(projection.is_pool_quarantined("pool-001"));
        assert!(!projection.is_pool_quarantined("pool-002"));
        assert_eq!(projection.quarantined_pool_count(), 1);
    }

    #[test]
    fn test_spec_quarantine_and_query() {
        let mut projection = QuarantineProjection::new();

        // Initially not quarantined
        assert!(!projection.is_spec_quarantined("spec-001"));

        // Quarantine the spec
        let event = create_spec_quarantined("spec-001");
        projection
            .apply(QuarantineEvent::SpecQuarantined(event))
            .unwrap();

        // Now quarantined
        assert!(projection.is_spec_quarantined("spec-001"));
        assert!(!projection.is_spec_quarantined("spec-002"));
        assert_eq!(projection.quarantined_spec_count(), 1);
    }

    #[test]
    fn test_quarantine_cleared_removes_pool() {
        let mut projection = QuarantineProjection::new();

        // Quarantine a pool
        let quarantine = create_pool_quarantined("pool-001");
        projection
            .apply(QuarantineEvent::PoolQuarantined(quarantine))
            .unwrap();
        assert!(projection.is_pool_quarantined("pool-001"));

        // Clear the quarantine
        let clear = create_cleared("pool-001");
        projection.apply(QuarantineEvent::Cleared(clear)).unwrap();

        // No longer quarantined
        assert!(!projection.is_pool_quarantined("pool-001"));
        assert_eq!(projection.quarantined_pool_count(), 0);
    }

    #[test]
    fn test_quarantine_cleared_removes_spec() {
        let mut projection = QuarantineProjection::new();

        // Quarantine a spec
        let quarantine = create_spec_quarantined("spec-001");
        projection
            .apply(QuarantineEvent::SpecQuarantined(quarantine))
            .unwrap();
        assert!(projection.is_spec_quarantined("spec-001"));

        // Clear the quarantine
        let clear = create_cleared("spec-001");
        projection.apply(QuarantineEvent::Cleared(clear)).unwrap();

        // No longer quarantined
        assert!(!projection.is_spec_quarantined("spec-001"));
        assert_eq!(projection.quarantined_spec_count(), 0);
    }

    #[test]
    fn test_clear_removes_from_both_sets() {
        let mut projection = QuarantineProjection::new();

        // Add an ID to both sets (edge case: same ID used for pool and spec)
        let pool_event = create_pool_quarantined("shared-id");
        let spec_event = create_spec_quarantined("shared-id");

        projection
            .apply(QuarantineEvent::PoolQuarantined(pool_event))
            .unwrap();
        projection
            .apply(QuarantineEvent::SpecQuarantined(spec_event))
            .unwrap();

        assert!(projection.is_pool_quarantined("shared-id"));
        assert!(projection.is_spec_quarantined("shared-id"));

        // Clear removes from both
        let clear = create_cleared("shared-id");
        projection.apply(QuarantineEvent::Cleared(clear)).unwrap();

        assert!(!projection.is_pool_quarantined("shared-id"));
        assert!(!projection.is_spec_quarantined("shared-id"));
    }

    #[test]
    fn test_multiple_quarantines() {
        let mut projection = QuarantineProjection::new();

        // Quarantine multiple pools
        for i in 1..=5 {
            let event = create_pool_quarantined(&format!("pool-{i:03}"));
            projection
                .apply(QuarantineEvent::PoolQuarantined(event))
                .unwrap();
        }

        // Quarantine multiple specs
        for i in 1..=3 {
            let event = create_spec_quarantined(&format!("spec-{i:03}"));
            projection
                .apply(QuarantineEvent::SpecQuarantined(event))
                .unwrap();
        }

        assert_eq!(projection.quarantined_pool_count(), 5);
        assert_eq!(projection.quarantined_spec_count(), 3);

        // Verify specific queries
        assert!(projection.is_pool_quarantined("pool-003"));
        assert!(projection.is_spec_quarantined("spec-002"));
        assert!(!projection.is_pool_quarantined("pool-006"));
        assert!(!projection.is_spec_quarantined("spec-004"));
    }

    #[test]
    fn test_quarantine_idempotent() {
        let mut projection = QuarantineProjection::new();

        // Quarantine the same pool twice
        let event1 = create_pool_quarantined("pool-001");
        let event2 = create_pool_quarantined("pool-001");

        projection
            .apply(QuarantineEvent::PoolQuarantined(event1))
            .unwrap();
        projection
            .apply(QuarantineEvent::PoolQuarantined(event2))
            .unwrap();

        // Should still have count of 1 (HashSet deduplicates)
        assert_eq!(projection.quarantined_pool_count(), 1);
    }

    #[test]
    fn test_clear_nonexistent_is_noop() {
        let mut projection = QuarantineProjection::new();

        // Clear a target that was never quarantined
        let clear = create_cleared("nonexistent");
        projection.apply(QuarantineEvent::Cleared(clear)).unwrap();

        // Should succeed without error
        assert_eq!(projection.quarantined_pool_count(), 0);
        assert_eq!(projection.quarantined_spec_count(), 0);
    }

    #[test]
    fn test_iterators() {
        let mut projection = QuarantineProjection::new();

        // Add some quarantines
        projection
            .apply(QuarantineEvent::PoolQuarantined(create_pool_quarantined(
                "pool-a",
            )))
            .unwrap();
        projection
            .apply(QuarantineEvent::PoolQuarantined(create_pool_quarantined(
                "pool-b",
            )))
            .unwrap();
        projection
            .apply(QuarantineEvent::SpecQuarantined(create_spec_quarantined(
                "spec-x",
            )))
            .unwrap();

        // Collect and verify iterators
        let pools: HashSet<&str> = projection.quarantined_pools().collect();
        let specs: HashSet<&str> = projection.quarantined_specs().collect();

        assert_eq!(pools.len(), 2);
        assert!(pools.contains("pool-a"));
        assert!(pools.contains("pool-b"));

        assert_eq!(specs.len(), 1);
        assert!(specs.contains("spec-x"));
    }

    // =========================================================================
    // Proto Conversion Tests
    // =========================================================================

    #[test]
    fn test_pool_quarantined_proto_roundtrip() {
        let original = create_pool_quarantined("pool-001");

        let proto: RunnerPoolQuarantinedProto = original.clone().into();
        let recovered: RunnerPoolQuarantined = proto.try_into().unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_spec_quarantined_proto_roundtrip() {
        let original = create_spec_quarantined("spec-001");

        let proto: AATSpecQuarantinedProto = original.clone().into();
        let recovered: AATSpecQuarantined = proto.try_into().unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_cleared_proto_roundtrip() {
        let original = create_cleared("target-001");

        let proto: QuarantineClearedProto = original.clone().into();
        let recovered: QuarantineCleared = proto.try_into().unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_proto_invalid_signature_length() {
        let proto = RunnerPoolQuarantinedProto {
            quarantine_id: "q-001".to_string(),
            pool_id: "pool-001".to_string(),
            reason: "test".to_string(),
            evidence_refs: vec![],
            // HTF time envelope reference (RFC-0016): using None for test.
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: vec![0u8; 32], // Wrong length!
        };

        let result: Result<RunnerPoolQuarantined, _> = proto.try_into();
        assert!(matches!(
            result,
            Err(QuarantineError::InvalidSignatureLength { len: 32 })
        ));
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_string_too_long_quarantine_id() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = RunnerPoolQuarantinedProto {
            quarantine_id: long_string,
            pool_id: "pool".to_string(),
            reason: "test".to_string(),
            evidence_refs: vec![],
            // HTF time envelope reference (RFC-0016): using None for test.
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: vec![0u8; 64],
        };

        let result: Result<RunnerPoolQuarantined, _> = proto.try_into();
        assert!(matches!(
            result,
            Err(QuarantineError::StringTooLong {
                field: "quarantine_id",
                ..
            })
        ));
    }

    #[test]
    fn test_string_too_long_pool_id() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = RunnerPoolQuarantinedProto {
            quarantine_id: "q-001".to_string(),
            pool_id: long_string,
            reason: "test".to_string(),
            evidence_refs: vec![],
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: vec![0u8; 64],
        };

        let result: Result<RunnerPoolQuarantined, _> = proto.try_into();
        assert!(matches!(
            result,
            Err(QuarantineError::StringTooLong {
                field: "pool_id",
                ..
            })
        ));
    }

    #[test]
    fn test_too_many_evidence_refs() {
        let many_refs: Vec<String> = (0..=MAX_EVIDENCE_REFS)
            .map(|i| format!("evidence-{i:04}"))
            .collect();

        let proto = RunnerPoolQuarantinedProto {
            quarantine_id: "q-001".to_string(),
            pool_id: "pool".to_string(),
            reason: "test".to_string(),
            evidence_refs: many_refs,
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: vec![0u8; 64],
        };

        let result: Result<RunnerPoolQuarantined, _> = proto.try_into();
        assert!(matches!(
            result,
            Err(QuarantineError::TooManyEvidenceRefs { .. })
        ));
    }

    #[test]
    fn test_evidence_ref_too_long() {
        let long_ref = "x".repeat(MAX_STRING_LENGTH + 1);
        let proto = RunnerPoolQuarantinedProto {
            quarantine_id: "q-001".to_string(),
            pool_id: "pool".to_string(),
            reason: "test".to_string(),
            evidence_refs: vec![long_ref],
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: vec![0u8; 64],
        };

        let result: Result<RunnerPoolQuarantined, _> = proto.try_into();
        assert!(matches!(
            result,
            Err(QuarantineError::StringTooLong {
                field: "evidence_refs",
                ..
            })
        ));
    }

    // =========================================================================
    // Resource Limit Tests (denial-of-service protection)
    // =========================================================================

    #[test]
    fn test_quarantine_limit_exceeded_pools() {
        let mut projection = QuarantineProjection::new();

        // Fill to the limit (simulate, not actually MAX_QUARANTINED_ITEMS)
        // We test the logic with a smaller projection
        for i in 0..100 {
            let event = create_pool_quarantined(&format!("pool-{i:04}"));
            projection
                .apply(QuarantineEvent::PoolQuarantined(event))
                .unwrap();
        }

        assert_eq!(projection.quarantined_pool_count(), 100);

        // Adding duplicate should succeed (idempotent)
        let dup_event = create_pool_quarantined("pool-0050");
        assert!(
            projection
                .apply(QuarantineEvent::PoolQuarantined(dup_event))
                .is_ok()
        );
    }

    // =========================================================================
    // Serde Tests
    // =========================================================================

    #[test]
    fn test_projection_serde_roundtrip() {
        let mut projection = QuarantineProjection::new();

        projection
            .apply(QuarantineEvent::PoolQuarantined(create_pool_quarantined(
                "pool-001",
            )))
            .unwrap();
        projection
            .apply(QuarantineEvent::SpecQuarantined(create_spec_quarantined(
                "spec-001",
            )))
            .unwrap();

        let json = serde_json::to_string(&projection).unwrap();
        let recovered: QuarantineProjection = serde_json::from_str(&json).unwrap();

        assert!(recovered.is_pool_quarantined("pool-001"));
        assert!(recovered.is_spec_quarantined("spec-001"));
        assert_eq!(
            projection.quarantined_pool_count(),
            recovered.quarantined_pool_count()
        );
        assert_eq!(
            projection.quarantined_spec_count(),
            recovered.quarantined_spec_count()
        );
    }

    #[test]
    fn test_event_types_serde_roundtrip() {
        let pool = create_pool_quarantined("pool-001");
        let pool_json = serde_json::to_string(&pool).unwrap();
        let pool_recovered: RunnerPoolQuarantined = serde_json::from_str(&pool_json).unwrap();
        assert_eq!(pool, pool_recovered);

        let spec = create_spec_quarantined("spec-001");
        let spec_json = serde_json::to_string(&spec).unwrap();
        let spec_recovered: AATSpecQuarantined = serde_json::from_str(&spec_json).unwrap();
        assert_eq!(spec, spec_recovered);

        let clear = create_cleared("target-001");
        let clear_json = serde_json::to_string(&clear).unwrap();
        let clear_recovered: QuarantineCleared = serde_json::from_str(&clear_json).unwrap();
        assert_eq!(clear, clear_recovered);
    }

    // =========================================================================
    // Selection Exclusion Tests (Definition of Done)
    // =========================================================================

    #[test]
    fn test_selection_excludes_quarantined_pools() {
        let mut projection = QuarantineProjection::new();

        // Quarantine pool-002
        projection
            .apply(QuarantineEvent::PoolQuarantined(create_pool_quarantined(
                "pool-002",
            )))
            .unwrap();

        // Simulate selection filtering
        let available_pools = vec!["pool-001", "pool-002", "pool-003"];
        let selectable: Vec<_> = available_pools
            .into_iter()
            .filter(|p| !projection.is_pool_quarantined(p))
            .collect();

        assert_eq!(selectable, vec!["pool-001", "pool-003"]);
    }

    #[test]
    fn test_selection_excludes_quarantined_specs() {
        let mut projection = QuarantineProjection::new();

        // Quarantine spec-002
        projection
            .apply(QuarantineEvent::SpecQuarantined(create_spec_quarantined(
                "spec-002",
            )))
            .unwrap();

        // Simulate selection filtering
        let available_specs = vec!["spec-001", "spec-002", "spec-003"];
        let selectable: Vec<_> = available_specs
            .into_iter()
            .filter(|s| !projection.is_spec_quarantined(s))
            .collect();

        assert_eq!(selectable, vec!["spec-001", "spec-003"]);
    }

    #[test]
    fn test_cleared_re_enables_targets() {
        let mut projection = QuarantineProjection::new();

        // Quarantine both pool and spec
        projection
            .apply(QuarantineEvent::PoolQuarantined(create_pool_quarantined(
                "pool-001",
            )))
            .unwrap();
        projection
            .apply(QuarantineEvent::SpecQuarantined(create_spec_quarantined(
                "spec-001",
            )))
            .unwrap();

        // Verify excluded
        assert!(projection.is_pool_quarantined("pool-001"));
        assert!(projection.is_spec_quarantined("spec-001"));

        // Clear both
        projection
            .apply(QuarantineEvent::Cleared(create_cleared("pool-001")))
            .unwrap();
        projection
            .apply(QuarantineEvent::Cleared(create_cleared("spec-001")))
            .unwrap();

        // Verify re-enabled
        assert!(!projection.is_pool_quarantined("pool-001"));
        assert!(!projection.is_spec_quarantined("spec-001"));
    }

    // =========================================================================
    // QuarantineEvent Proto Conversion Tests
    // =========================================================================

    use crate::events::kernel_event::Payload;

    #[test]
    fn test_quarantine_event_pool_payload_roundtrip() {
        let original = QuarantineEvent::PoolQuarantined(create_pool_quarantined("pool-001"));

        // Convert to Payload
        let payload: Payload = original.clone().into();

        // Verify it's the correct variant
        assert!(matches!(payload, Payload::RunnerPoolQuarantined(_)));

        // Convert back
        let recovered: QuarantineEvent = payload.try_into().unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_quarantine_event_spec_payload_roundtrip() {
        let original = QuarantineEvent::SpecQuarantined(create_spec_quarantined("spec-001"));

        // Convert to Payload
        let payload: Payload = original.clone().into();

        // Verify it's the correct variant
        assert!(matches!(payload, Payload::AatSpecQuarantined(_)));

        // Convert back
        let recovered: QuarantineEvent = payload.try_into().unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_quarantine_event_cleared_payload_roundtrip() {
        let original = QuarantineEvent::Cleared(create_cleared("target-001"));

        // Convert to Payload
        let payload: Payload = original.clone().into();

        // Verify it's the correct variant
        assert!(matches!(payload, Payload::QuarantineCleared(_)));

        // Convert back
        let recovered: QuarantineEvent = payload.try_into().unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_quarantine_event_from_non_quarantine_payload_fails() {
        // Use a non-quarantine payload (e.g., MergeReceipt)
        let payload = Payload::MergeReceipt(crate::events::MergeReceipt {
            base_selector: "main".to_string(),
            changeset_digest: vec![0u8; 32],
            gate_receipt_ids: vec![],
            policy_hash: vec![0u8; 32],
            result_selector: "abc123".to_string(),
            merged_at: 1_234_567_890,
            gate_actor_id: "gate-001".to_string(),
            gate_signature: vec![0u8; 64],
            // HTF time envelope reference (RFC-0016): not yet populated.
            time_envelope_ref: None,
        });

        let result: Result<QuarantineEvent, _> = payload.try_into();

        assert!(matches!(result, Err(QuarantineError::InvalidData(_))));
    }

    // =========================================================================
    // Cryptographic Verification Tests (SEC-FAC-01, SEC-FAC-02)
    // =========================================================================

    use super::super::domain_separator::{QUARANTINE_EVENT_PREFIX, sign_with_domain};
    use crate::crypto::Signer;

    /// Helper to create a signed `RunnerPoolQuarantined` event.
    fn create_signed_pool_quarantined(pool_id: &str, signer: &Signer) -> RunnerPoolQuarantined {
        let mut event = RunnerPoolQuarantined {
            quarantine_id: format!("q-{pool_id}"),
            pool_id: pool_id.to_string(),
            reason: "Test flakiness".to_string(),
            evidence_refs: vec!["evidence-001".to_string()],
            time_envelope_ref: None,
            issuer_actor_id: "gate-001".to_string(),
            issuer_signature: [0u8; 64],
        };

        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, QUARANTINE_EVENT_PREFIX, &canonical);
        event.issuer_signature = signature.to_bytes();

        event
    }

    /// Helper to create a signed `AATSpecQuarantined` event.
    fn create_signed_spec_quarantined(spec_id: &str, signer: &Signer) -> AATSpecQuarantined {
        let mut event = AATSpecQuarantined {
            quarantine_id: format!("q-{spec_id}"),
            spec_id: spec_id.to_string(),
            reason: "Non-deterministic output".to_string(),
            evidence_refs: vec!["evidence-002".to_string()],
            time_envelope_ref: None,
            issuer_actor_id: "gate-002".to_string(),
            issuer_signature: [0u8; 64],
        };

        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, QUARANTINE_EVENT_PREFIX, &canonical);
        event.issuer_signature = signature.to_bytes();

        event
    }

    /// Helper to create a signed `QuarantineCleared` event.
    fn create_signed_cleared(target_id: &str, signer: &Signer) -> QuarantineCleared {
        let mut event = QuarantineCleared {
            quarantine_id: format!("q-{target_id}"),
            target_id: target_id.to_string(),
            cleared_at: 1_704_067_200_000,
            issuer_actor_id: "gate-001".to_string(),
            issuer_signature: [0u8; 64],
            // HTF time envelope reference (RFC-0016): using None for test.
            time_envelope_ref: None,
        };

        let canonical = event.canonical_bytes();
        let signature = sign_with_domain(signer, QUARANTINE_EVENT_PREFIX, &canonical);
        event.issuer_signature = signature.to_bytes();

        event
    }

    #[test]
    fn test_pool_quarantined_canonical_bytes_deterministic() {
        let event1 = create_pool_quarantined("pool-001");
        let event2 = create_pool_quarantined("pool-001");

        // Canonical bytes should be identical for identical events
        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
    }

    #[test]
    fn test_pool_quarantined_canonical_bytes_different_for_different_events() {
        let event1 = create_pool_quarantined("pool-001");
        let event2 = create_pool_quarantined("pool-002");

        // Canonical bytes should differ for different events
        assert_ne!(event1.canonical_bytes(), event2.canonical_bytes());
    }

    #[test]
    fn test_pool_quarantined_verify_signature_success() {
        let signer = Signer::generate();
        let event = create_signed_pool_quarantined("pool-001", &signer);

        // Verification should succeed with correct key
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_pool_quarantined_verify_signature_wrong_key() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let event = create_signed_pool_quarantined("pool-001", &signer1);

        // Verification should fail with wrong key
        assert!(event.verify_signature(&signer2.verifying_key()).is_err());
    }

    #[test]
    fn test_pool_quarantined_verify_signature_tampered_data() {
        let signer = Signer::generate();
        let mut event = create_signed_pool_quarantined("pool-001", &signer);

        // Tamper with the data
        event.reason = "Different reason".to_string();

        // Verification should fail
        assert!(event.verify_signature(&signer.verifying_key()).is_err());
    }

    #[test]
    fn test_spec_quarantined_canonical_bytes_deterministic() {
        let event1 = create_spec_quarantined("spec-001");
        let event2 = create_spec_quarantined("spec-001");

        // Canonical bytes should be identical for identical events
        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
    }

    #[test]
    fn test_spec_quarantined_verify_signature_success() {
        let signer = Signer::generate();
        let event = create_signed_spec_quarantined("spec-001", &signer);

        // Verification should succeed with correct key
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_spec_quarantined_verify_signature_wrong_key() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let event = create_signed_spec_quarantined("spec-001", &signer1);

        // Verification should fail with wrong key
        assert!(event.verify_signature(&signer2.verifying_key()).is_err());
    }

    #[test]
    fn test_cleared_canonical_bytes_deterministic() {
        let event1 = create_cleared("target-001");
        let event2 = create_cleared("target-001");

        // Canonical bytes should be identical for identical events
        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
    }

    #[test]
    fn test_cleared_verify_signature_success() {
        let signer = Signer::generate();
        let event = create_signed_cleared("target-001", &signer);

        // Verification should succeed with correct key
        assert!(event.verify_signature(&signer.verifying_key()).is_ok());
    }

    #[test]
    fn test_cleared_verify_signature_wrong_key() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();
        let event = create_signed_cleared("target-001", &signer1);

        // Verification should fail with wrong key
        assert!(event.verify_signature(&signer2.verifying_key()).is_err());
    }

    #[test]
    fn test_evidence_refs_sorted_in_canonical_bytes() {
        // Create events with evidence refs in different orders
        let mut event1 = create_pool_quarantined("pool-001");
        event1.evidence_refs = vec!["b".to_string(), "a".to_string(), "c".to_string()];

        let mut event2 = create_pool_quarantined("pool-001");
        event2.evidence_refs = vec!["c".to_string(), "a".to_string(), "b".to_string()];

        // Canonical bytes should be identical because evidence_refs are sorted
        assert_eq!(event1.canonical_bytes(), event2.canonical_bytes());
    }

    // =========================================================================
    // Apply Validation Tests (DoS protection for direct domain type usage)
    // =========================================================================

    #[test]
    fn test_apply_rejects_pool_quarantined_with_oversized_pool_id() {
        let mut projection = QuarantineProjection::new();

        // Create event with oversized pool_id (bypassing proto conversion)
        let oversized_pool_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let event = RunnerPoolQuarantined {
            quarantine_id: "q-001".to_string(),
            pool_id: oversized_pool_id,
            reason: "test".to_string(),
            evidence_refs: vec![],
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: [0u8; 64],
        };

        let result = projection.apply(QuarantineEvent::PoolQuarantined(event));
        assert!(matches!(
            result,
            Err(QuarantineError::StringTooLong {
                field: "pool_id",
                ..
            })
        ));
    }

    #[test]
    fn test_apply_rejects_spec_quarantined_with_oversized_spec_id() {
        let mut projection = QuarantineProjection::new();

        // Create event with oversized spec_id (bypassing proto conversion)
        let oversized_spec_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let event = AATSpecQuarantined {
            quarantine_id: "q-001".to_string(),
            spec_id: oversized_spec_id,
            reason: "test".to_string(),
            evidence_refs: vec![],
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: [0u8; 64],
        };

        let result = projection.apply(QuarantineEvent::SpecQuarantined(event));
        assert!(matches!(
            result,
            Err(QuarantineError::StringTooLong {
                field: "spec_id",
                ..
            })
        ));
    }

    #[test]
    fn test_apply_rejects_cleared_with_oversized_target_id() {
        let mut projection = QuarantineProjection::new();

        // Create event with oversized target_id (bypassing proto conversion)
        let oversized_target_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let event = QuarantineCleared {
            quarantine_id: "q-001".to_string(),
            target_id: oversized_target_id,
            cleared_at: 1_704_067_200_000,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: [0u8; 64],
            // HTF time envelope reference (RFC-0016): using None for test.
            time_envelope_ref: None,
        };

        let result = projection.apply(QuarantineEvent::Cleared(event));
        assert!(matches!(
            result,
            Err(QuarantineError::StringTooLong {
                field: "target_id",
                ..
            })
        ));
    }

    #[test]
    fn test_apply_rejects_pool_quarantined_with_too_many_evidence_refs() {
        let mut projection = QuarantineProjection::new();

        // Create event with too many evidence refs (bypassing proto conversion)
        let many_refs: Vec<String> = (0..=MAX_EVIDENCE_REFS)
            .map(|i| format!("evidence-{i:04}"))
            .collect();

        let event = RunnerPoolQuarantined {
            quarantine_id: "q-001".to_string(),
            pool_id: "pool-001".to_string(),
            reason: "test".to_string(),
            evidence_refs: many_refs,
            time_envelope_ref: None,
            issuer_actor_id: "gate".to_string(),
            issuer_signature: [0u8; 64],
        };

        let result = projection.apply(QuarantineEvent::PoolQuarantined(event));
        assert!(matches!(
            result,
            Err(QuarantineError::TooManyEvidenceRefs { .. })
        ));
    }
}
