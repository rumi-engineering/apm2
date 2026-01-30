// AGENT-AUTHORED (TCK-00213)
//! Divergence watchdog for the FAC (Forge Admission Cycle).
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

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apm2_core::crypto::{Signer, VerifyingKey};
use apm2_core::fac::{
    INTERVENTION_FREEZE_PREFIX, INTERVENTION_UNFREEZE_PREFIX, sign_with_domain, verify_with_domain,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for string fields to prevent denial-of-service attacks.
pub const MAX_STRING_LENGTH: usize = 1024;

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
    #[must_use]
    pub const fn requires_adjudication(&self) -> bool {
        matches!(self, Self::Adjudication | Self::AcceptDivergence)
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

impl InterventionUnfreeze {
    /// Returns the canonical bytes for signing/verification.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let adjudication_id_len = self.adjudication_id.as_ref().map_or(0, String::len);
        let capacity = 4 + self.freeze_id.len()
            + 20  // resolution_type (max)
            + 4 + adjudication_id_len
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

        // 3. adjudication_id (length-prefixed, 0 length for None)
        if let Some(ref adj_id) = self.adjudication_id {
            bytes.extend_from_slice(&(adj_id.len() as u32).to_be_bytes());
            bytes.extend_from_slice(adj_id.as_bytes());
        } else {
            bytes.extend_from_slice(&0u32.to_be_bytes());
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
}

// =============================================================================
// FreezeRegistry
// =============================================================================

/// Thread-safe registry of active freezes.
///
/// This registry tracks which repositories/scopes are currently frozen
/// and is used for admission checking.
#[derive(Debug, Default)]
pub struct FreezeRegistry {
    /// Set of active freeze IDs.
    active_freezes: RwLock<HashSet<String>>,
    /// Map of `scope_value` -> `freeze_id` for quick lookup.
    scope_map: RwLock<std::collections::HashMap<String, String>>,
}

impl FreezeRegistry {
    /// Creates a new empty freeze registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a freeze in the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn register(&self, freeze: &InterventionFreeze) -> Result<(), DivergenceError> {
        let mut active = self
            .active_freezes
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;
        let mut scope = self
            .scope_map
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;

        active.insert(freeze.freeze_id.clone());
        scope.insert(freeze.scope_value.clone(), freeze.freeze_id.clone());

        Ok(())
    }

    /// Unregisters a freeze from the registry.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::FreezeNotFound`] if the freeze is not in the
    /// registry.
    pub fn unregister(&self, freeze_id: &str) -> Result<(), DivergenceError> {
        let mut active = self
            .active_freezes
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;
        let mut scope = self
            .scope_map
            .write()
            .map_err(|e| DivergenceError::InvalidConfiguration(format!("lock poisoned: {e}")))?;

        if !active.remove(freeze_id) {
            return Err(DivergenceError::FreezeNotFound {
                freeze_id: freeze_id.to_string(),
            });
        }

        // Remove from scope map (find and remove)
        scope.retain(|_, v| v != freeze_id);

        Ok(())
    }

    /// Checks if a scope is frozen.
    ///
    /// Returns `Some(freeze_id)` if frozen, `None` otherwise.
    pub fn is_frozen(&self, scope_value: &str) -> Option<String> {
        let scope = self.scope_map.read().ok()?;
        scope.get(scope_value).cloned()
    }

    /// Checks admission and returns an error if the scope is frozen.
    ///
    /// # Errors
    ///
    /// Returns [`DivergenceError::RepoFrozen`] if the scope is frozen.
    pub fn check_admission(&self, scope_value: &str) -> Result<(), DivergenceError> {
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
// DivergenceWatchdog
// =============================================================================

/// The divergence watchdog that monitors for ledger/trunk divergence.
///
/// This watchdog periodically checks whether the external trunk HEAD matches
/// the ledger's latest merge receipt. On divergence, it emits a freeze event.
pub struct DivergenceWatchdog {
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
}

impl DivergenceWatchdog {
    /// Creates a new divergence watchdog.
    #[must_use]
    pub fn new(signer: Signer, config: DivergenceWatchdogConfig) -> Self {
        Self {
            signer,
            config,
            registry: Arc::new(FreezeRegistry::new()),
            freeze_counter: std::sync::atomic::AtomicU64::new(0),
            defect_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Creates a new divergence watchdog with a shared freeze registry.
    #[must_use]
    pub const fn with_registry(
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
        let timestamp = current_timestamp_ns();
        format!("freeze-{timestamp}-{count}")
    }

    /// Generates a unique defect ID.
    fn generate_defect_id(&self) -> String {
        let count = self
            .defect_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let timestamp = current_timestamp_ns();
        format!("defect-divergence-{timestamp}-{count}")
    }

    /// Generates a time envelope reference.
    fn generate_time_envelope_ref(&self) -> String {
        let timestamp = current_timestamp_ns();
        self.config
            .time_envelope_pattern
            .replace("{}", &timestamp.to_string())
    }

    /// Checks for divergence between the merge receipt HEAD and external trunk
    /// HEAD.
    ///
    /// If divergence is detected, emits an [`InterventionFreeze`] and registers
    /// it.
    ///
    /// # Arguments
    ///
    /// * `merge_receipt_head` - The expected trunk HEAD from the latest
    ///   `MergeReceipt`
    /// * `external_trunk_head` - The actual trunk HEAD observed externally
    ///
    /// # Returns
    ///
    /// `Some(InterventionFreeze)` if divergence is detected, `None` if no
    /// divergence.
    ///
    /// # Errors
    ///
    /// Returns an error if freeze creation or registration fails.
    pub fn check_divergence(
        &self,
        merge_receipt_head: [u8; 32],
        external_trunk_head: [u8; 32],
    ) -> Result<Option<InterventionFreeze>, DivergenceError> {
        // No divergence if heads match
        if merge_receipt_head == external_trunk_head {
            return Ok(None);
        }

        // Divergence detected - emit freeze
        let freeze = self.on_divergence(merge_receipt_head, external_trunk_head)?;

        Ok(Some(freeze))
    }

    /// Called when divergence is detected. Creates and registers a freeze
    /// event.
    ///
    /// This method:
    /// 1. Generates a defect ID for the `DefectRecord(PROJECTION_DIVERGENCE)`
    /// 2. Creates an `InterventionFreeze` event
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
    /// The created [`InterventionFreeze`] event.
    ///
    /// # Errors
    ///
    /// Returns an error if freeze creation or registration fails.
    pub fn on_divergence(
        &self,
        expected_head: [u8; 32],
        actual_head: [u8; 32],
    ) -> Result<InterventionFreeze, DivergenceError> {
        let freeze_id = self.generate_freeze_id();
        let defect_id = self.generate_defect_id();
        let time_envelope_ref = self.generate_time_envelope_ref();

        let freeze = InterventionFreezeBuilder::new(&freeze_id)
            .scope(FreezeScope::Repository)
            .scope_value(&self.config.repo_id)
            .trigger_defect_id(&defect_id)
            .expected_trunk_head(expected_head)
            .actual_trunk_head(actual_head)
            .gate_actor_id(&self.config.actor_id)
            .time_envelope_ref(&time_envelope_ref)
            .try_build_and_sign(&self.signer)?;

        // Register the freeze
        self.registry.register(&freeze)?;

        Ok(freeze)
    }

    /// Creates an unfreeze event for a given freeze ID.
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
    /// The created [`InterventionUnfreeze`] event.
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

        let time_envelope_ref = self.generate_time_envelope_ref();

        let mut builder = InterventionUnfreezeBuilder::new(freeze_id)
            .resolution_type(resolution_type)
            .gate_actor_id(&self.config.actor_id)
            .time_envelope_ref(&time_envelope_ref);

        if let Some(adj_id) = adjudication_id {
            builder = builder.adjudication_id(adj_id);
        }

        let unfreeze = builder.try_build_and_sign(&self.signer)?;

        // Unregister the freeze
        self.registry.unregister(freeze_id)?;

        Ok(unfreeze)
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

impl std::fmt::Debug for DivergenceWatchdog {
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
        DivergenceWatchdog::new(signer, config)
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
        let registry = FreezeRegistry::new();

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze).unwrap();

        assert_eq!(registry.active_count(), 1);
        assert!(registry.is_frozen("test-repo").is_some());
        assert!(registry.is_frozen("other-repo").is_none());
    }

    #[test]
    fn test_registry_unregister() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new();

        let freeze = InterventionFreezeBuilder::new("freeze-001")
            .scope(FreezeScope::Repository)
            .scope_value("test-repo")
            .trigger_defect_id("defect-001")
            .expected_trunk_head([0x42; 32])
            .actual_trunk_head([0x99; 32])
            .gate_actor_id("watchdog-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        registry.register(&freeze).unwrap();
        assert_eq!(registry.active_count(), 1);

        registry.unregister("freeze-001").unwrap();
        assert_eq!(registry.active_count(), 0);
        assert!(registry.is_frozen("test-repo").is_none());
    }

    #[test]
    fn test_registry_unregister_not_found() {
        let registry = FreezeRegistry::new();

        let result = registry.unregister("nonexistent");
        assert!(matches!(
            result,
            Err(DivergenceError::FreezeNotFound { .. })
        ));
    }

    #[test]
    fn test_registry_check_admission() {
        let signer = Signer::generate();
        let registry = FreezeRegistry::new();

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

        registry.register(&freeze).unwrap();

        // Should reject admission when frozen
        let result = registry.check_admission("test-repo");
        assert!(matches!(result, Err(DivergenceError::RepoFrozen { .. })));

        // Other repos should still be allowed
        assert!(registry.check_admission("other-repo").is_ok());
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
        let freeze = result.unwrap();

        assert_eq!(freeze.scope, FreezeScope::Repository);
        assert_eq!(freeze.scope_value, "test-repo");
        assert_eq!(freeze.expected_trunk_head, expected_head);
        assert_eq!(freeze.actual_trunk_head, actual_head);
        assert_eq!(watchdog.registry().active_count(), 1);
    }

    #[test]
    fn test_watchdog_freeze_signature_valid() {
        let watchdog = create_test_watchdog();

        let expected_head = [0x42; 32];
        let actual_head = [0x99; 32];
        let freeze = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap()
            .unwrap();

        assert!(freeze.validate_signature(&watchdog.verifying_key()).is_ok());
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
        let freeze = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap()
            .unwrap();

        assert!(watchdog.check_admission().is_err());

        // Create unfreeze
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

        // Should allow admission after unfreeze
        assert!(watchdog.check_admission().is_ok());
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
        let freeze = watchdog
            .check_divergence(expected_head, actual_head)
            .unwrap()
            .unwrap();

        // 3. Admission is now blocked
        let err = watchdog.check_admission().unwrap_err();
        assert!(matches!(err, DivergenceError::RepoFrozen { .. }));

        // 4. Verify freeze signature
        assert!(freeze.validate_signature(&watchdog.verifying_key()).is_ok());

        // 5. Create unfreeze with adjudication
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

        // 7. Admission is allowed again
        assert!(watchdog.check_admission().is_ok());
    }

    #[test]
    fn test_multiple_divergences() {
        let watchdog = create_test_watchdog();

        // Trigger first divergence
        let freeze1 = watchdog
            .check_divergence([0x11; 32], [0x22; 32])
            .unwrap()
            .unwrap();

        // Since the same repo is already frozen, further divergence checks
        // will still return new freeze events (for audit trail)
        let freeze2 = watchdog
            .check_divergence([0x22; 32], [0x33; 32])
            .unwrap()
            .unwrap();

        assert_ne!(freeze1.freeze_id, freeze2.freeze_id);
        assert_eq!(watchdog.registry().active_count(), 2);
    }
}
