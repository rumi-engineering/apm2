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
use apm2_core::events::{
    InterventionFreeze as ProtoInterventionFreeze,
    InterventionResolutionType as ProtoResolutionType, InterventionScope as ProtoScope,
    InterventionUnfreeze as ProtoInterventionUnfreeze,
};
use apm2_core::fac::{
    INTERVENTION_FREEZE_PREFIX, INTERVENTION_UNFREEZE_PREFIX, sign_with_domain, verify_with_domain,
};
use apm2_holon::defect::DefectRecord;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for string fields to prevent denial-of-service attacks.
pub const MAX_STRING_LENGTH: usize = 1024;

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
            time_envelope_ref: freeze.time_envelope_ref.clone(),
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
            time_envelope_ref: proto.time_envelope_ref.clone(),
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
        Self {
            freeze_id: unfreeze.freeze_id.clone(),
            resolution_type: i32::from(unfreeze.resolution_type),
            // Proto uses empty string for None (tagged encoding ensures distinct canonical bytes)
            adjudication_id: unfreeze.adjudication_id.clone().unwrap_or_default(),
            unfrozen_at: unfreeze.unfrozen_at,
            gate_actor_id: unfreeze.gate_actor_id.clone(),
            gate_signature: unfreeze.gate_signature.to_vec(),
            time_envelope_ref: unfreeze.time_envelope_ref.clone(),
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

        Ok(Self {
            freeze_id: proto.freeze_id.clone(),
            resolution_type,
            adjudication_id,
            unfrozen_at: proto.unfrozen_at,
            gate_actor_id: proto.gate_actor_id.clone(),
            gate_signature,
            time_envelope_ref: proto.time_envelope_ref.clone(),
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
    /// verification fails. Returns an error if the lock is poisoned.
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
/// allowing injection of mock time sources. Production code should use
/// [`SystemTimeSource`], while tests can use custom implementations.
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
            time_source: SystemTimeSource,
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
        }
    }

    /// Creates a new divergence watchdog with a shared registry and custom time
    /// source.
    #[must_use]
    pub const fn with_registry_and_time_source(
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

    /// Checks for divergence between the merge receipt HEAD and external trunk
    /// HEAD.
    ///
    /// If divergence is detected, emits an [`InterventionFreeze`] and a
    /// [`DefectRecord`] with signal type `PROJECTION_DIVERGENCE`, and
    /// registers the freeze.
    ///
    /// # Arguments
    ///
    /// * `merge_receipt_head` - The expected trunk HEAD from the latest
    ///   `MergeReceipt`
    /// * `external_trunk_head` - The actual trunk HEAD observed externally
    ///
    /// # Returns
    ///
    /// `Some(DivergenceResult)` if divergence is detected, `None` if no
    /// divergence.
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
        if merge_receipt_head == external_trunk_head {
            return Ok(None);
        }

        // Divergence detected - emit freeze and defect record
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
        let time_envelope_ref = self.generate_time_envelope_ref();
        let timestamp = self.time_source.now_nanos();

        // Create the DefectRecord(PROJECTION_DIVERGENCE) first
        let defect = DefectRecord::projection_divergence(
            &defect_id,
            &self.config.repo_id,
            expected_head,
            actual_head,
            timestamp,
        )
        .map_err(|e| DivergenceError::InvalidConfiguration(format!("defect record error: {e}")))?;

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

        Ok(DivergenceResult { freeze, defect })
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
    /// // 3. Apply to local registry AFTER successful persistence
    /// watchdog.apply_unfreeze(&unfreeze.freeze_id)?;
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
    /// # Arguments
    ///
    /// * `freeze_id` - The ID of the freeze to unregister
    ///
    /// # Errors
    ///
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
    /// // Then apply to local registry
    /// watchdog.apply_unfreeze(&unfreeze.freeze_id)?;
    /// ```
    pub fn apply_unfreeze(&self, freeze_id: &str) -> Result<(), DivergenceError> {
        self.registry.unregister(freeze_id)
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
        assert_eq!(proto.time_envelope_ref, freeze.time_envelope_ref);

        // Proto -> Manual roundtrip
        let recovered = InterventionFreeze::try_from(proto).unwrap();
        assert_eq!(recovered, freeze);
    }

    #[test]
    fn test_intervention_unfreeze_proto_conversion() {
        let signer = Signer::generate();
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Adjudication)
            .adjudication_id("adj-001")
            .unfrozen_at(2_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
            .build_and_sign(&signer);

        // Manual -> Proto
        let proto: ProtoInterventionUnfreeze = unfreeze.clone().into();
        assert_eq!(proto.freeze_id, unfreeze.freeze_id);
        assert_eq!(proto.resolution_type, i32::from(unfreeze.resolution_type));
        assert_eq!(proto.adjudication_id, "adj-001"); // Some -> string
        assert_eq!(proto.unfrozen_at, unfreeze.unfrozen_at);
        assert_eq!(proto.gate_actor_id, unfreeze.gate_actor_id);
        assert_eq!(proto.gate_signature, unfreeze.gate_signature.to_vec());
        assert_eq!(proto.time_envelope_ref, unfreeze.time_envelope_ref);

        // Proto -> Manual roundtrip
        let recovered = InterventionUnfreeze::try_from(proto).unwrap();
        assert_eq!(recovered, unfreeze);
    }

    #[test]
    fn test_intervention_unfreeze_proto_conversion_none_adjudication() {
        let signer = Signer::generate();
        let unfreeze = InterventionUnfreezeBuilder::new("freeze-001")
            .resolution_type(ResolutionType::Manual)
            .unfrozen_at(2_000_000_000)
            .gate_actor_id("operator-001")
            .time_envelope_ref("htf:tick:12345")
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

        registry.register(&freeze, &signer.verifying_key()).unwrap();

        assert_eq!(registry.active_count(), 1);
        assert!(registry.is_frozen("test-repo").is_some());
        assert!(registry.is_frozen("other-repo").is_none());
    }

    #[test]
    fn test_registry_register_rejects_invalid_signature() {
        let signer = Signer::generate();
        let other_signer = Signer::generate();
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

        registry.register(&freeze, &signer.verifying_key()).unwrap();
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

        registry.register(&freeze, &signer.verifying_key()).unwrap();

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
        watchdog.apply_unfreeze(&unfreeze.freeze_id).unwrap();

        // Should allow admission after applying unfreeze
        assert!(watchdog.check_admission().is_ok());
    }

    #[test]
    fn test_watchdog_apply_unfreeze_not_found() {
        let watchdog = create_test_watchdog();

        // Try to apply unfreeze for non-existent freeze
        let result = watchdog.apply_unfreeze("nonexistent");
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
        watchdog.apply_unfreeze(&unfreeze.freeze_id).unwrap();

        // 10. Admission is allowed again
        assert!(watchdog.check_admission().is_ok());
    }

    #[test]
    fn test_multiple_divergences() {
        let watchdog = create_test_watchdog();

        // Trigger first divergence
        let result1 = watchdog
            .check_divergence([0x11; 32], [0x22; 32])
            .unwrap()
            .unwrap();

        // Since the same repo is already frozen, further divergence checks
        // will still return new freeze events (for audit trail)
        let result2 = watchdog
            .check_divergence([0x22; 32], [0x33; 32])
            .unwrap()
            .unwrap();

        assert_ne!(result1.freeze.freeze_id, result2.freeze.freeze_id);
        assert_eq!(watchdog.registry().active_count(), 2);
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
        assert!(
            result
                .defect
                .signal()
                .details()
                .contains("divergence detected")
        );

        // Verify the freeze references the defect
        assert_eq!(result.freeze.trigger_defect_id, result.defect.defect_id());
    }
}
