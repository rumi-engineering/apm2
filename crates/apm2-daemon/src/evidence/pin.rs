//! Pin API for evidence artifact retention per AD-EVID-002.
//!
//! This module provides the `PinManager` API for pinning evidence artifacts
//! to prevent TTL-based eviction. Pins are used to preserve evidence for
//! incident investigation, compliance holds, and defect binding.
//!
//! # Architecture
//!
//! ```text
//! PinManager
//!     |
//!     +-- pin(artifact_id, reason, expires_at) -> Result<PinReceipt>
//!     +-- unpin(artifact_id) -> Result<()>
//!     +-- is_pinned(artifact_id) -> bool
//!     +-- pin_for_defect(artifact_id, defect_record_id, grace_period)
//!     +-- unpin_for_defect_closure(defect_record_id)
//! ```
//!
//! # Defect Integration (AD-CAC-001)
//!
//! Per AD-CAC-001, defect records trigger automatic pins:
//! - On defect creation: Pin related evidence artifacts
//! - Pin expiration: Defect resolution + grace period
//! - On defect closure: Unpin associated artifacts
//!
//! # Security Model
//!
//! - All pin operations are auditable via events
//! - Pins include actor identity for accountability
//! - Grace periods ensure evidence survives brief closures
//! - Pin receipts provide proof of retention
//!
//! # Invariants
//!
//! - [INV-PIN001] Pins always include a reason
//! - [INV-PIN002] Pin events are emitted for all operations
//! - [INV-PIN003] Defect pins use standard grace periods
//!
//! # Contract References
//!
//! - AD-EVID-002: Evidence retention and pinning
//! - AD-CAC-001: Defect record binding

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use super::artifact::{EvidenceArtifact, PinReason, PinState};
use super::ttl::TtlEnforcer;

// =============================================================================
// Constants
// =============================================================================

/// Default grace period after defect closure (24 hours).
pub const DEFAULT_DEFECT_GRACE_PERIOD_SECS: u64 = 24 * 3600;

/// Maximum grace period (30 days).
pub const MAX_GRACE_PERIOD_SECS: u64 = 30 * 24 * 3600;

/// Maximum active pins per artifact (prevents pin accumulation).
pub const MAX_PINS_PER_ARTIFACT: usize = 10;

// =============================================================================
// PinReceipt
// =============================================================================

/// Receipt confirming a pin operation.
///
/// Pin receipts provide proof that evidence was pinned at a specific time
/// and can be used for audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinReceipt {
    /// ID of the pinned artifact.
    pub artifact_id: String,

    /// Reason for the pin.
    pub reason: PinReason,

    /// When the pin was created (nanoseconds).
    pub pinned_at: u64,

    /// When the pin expires (if any).
    pub expires_at: Option<u64>,

    /// Actor who created the pin.
    pub actor: String,
}

impl PinReceipt {
    /// Returns `true` if the pin has expired.
    #[must_use]
    pub const fn is_expired(&self, now_ns: u64) -> bool {
        match self.expires_at {
            Some(exp) => now_ns >= exp,
            None => false,
        }
    }
}

// =============================================================================
// PinEvent
// =============================================================================

/// Event emitted for pin operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinEvent {
    /// Artifact was pinned.
    Pinned {
        /// Artifact ID.
        artifact_id: String,
        /// Episode owning the artifact.
        episode_id: String,
        /// Reason for the pin.
        reason: PinReason,
        /// When the pin was created.
        pinned_at: u64,
        /// When the pin expires (if any).
        expires_at: Option<u64>,
    },

    /// Artifact was unpinned.
    Unpinned {
        /// Artifact ID.
        artifact_id: String,
        /// Episode owning the artifact.
        episode_id: String,
        /// When the unpin occurred.
        unpinned_at: u64,
        /// Reason for the original pin.
        original_reason: Option<PinReason>,
    },

    /// Pin was extended.
    Extended {
        /// Artifact ID.
        artifact_id: String,
        /// Previous expiration.
        old_expires_at: Option<u64>,
        /// New expiration.
        new_expires_at: Option<u64>,
        /// When the extension occurred.
        extended_at: u64,
    },

    /// Defect-triggered pin.
    DefectPinned {
        /// Artifact ID.
        artifact_id: String,
        /// Defect record ID.
        defect_record_id: String,
        /// When the pin was created.
        pinned_at: u64,
    },

    /// Defect closure triggered unpin.
    DefectUnpinned {
        /// Artifact ID.
        artifact_id: String,
        /// Defect record ID.
        defect_record_id: String,
        /// When the unpin occurred.
        unpinned_at: u64,
    },
}

impl PinEvent {
    /// Returns the event type as a string.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::Pinned { .. } => "pinned",
            Self::Unpinned { .. } => "unpinned",
            Self::Extended { .. } => "extended",
            Self::DefectPinned { .. } => "defect_pinned",
            Self::DefectUnpinned { .. } => "defect_unpinned",
        }
    }

    /// Returns the artifact ID.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        match self {
            Self::Pinned { artifact_id, .. }
            | Self::Unpinned { artifact_id, .. }
            | Self::Extended { artifact_id, .. }
            | Self::DefectPinned { artifact_id, .. }
            | Self::DefectUnpinned { artifact_id, .. } => artifact_id,
        }
    }
}

// =============================================================================
// PinError
// =============================================================================

/// Errors for pin operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// Artifact not found.
    ArtifactNotFound {
        /// The artifact ID that was not found.
        artifact_id: String,
    },

    /// Artifact is already pinned.
    AlreadyPinned {
        /// The artifact ID that is already pinned.
        artifact_id: String,
    },

    /// Artifact is not pinned.
    NotPinned {
        /// The artifact ID that is not pinned.
        artifact_id: String,
    },

    /// Invalid grace period.
    InvalidGracePeriod {
        /// Reason for the invalid grace period.
        reason: String,
    },

    /// Internal error.
    Internal {
        /// Error message.
        message: String,
    },
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArtifactNotFound { artifact_id } => {
                write!(f, "artifact not found: {artifact_id}")
            },
            Self::AlreadyPinned { artifact_id } => {
                write!(f, "artifact already pinned: {artifact_id}")
            },
            Self::NotPinned { artifact_id } => {
                write!(f, "artifact not pinned: {artifact_id}")
            },
            Self::InvalidGracePeriod { reason } => {
                write!(f, "invalid grace period: {reason}")
            },
            Self::Internal { message } => {
                write!(f, "internal pin error: {message}")
            },
        }
    }
}

impl std::error::Error for PinError {}

// =============================================================================
// DefectBinding
// =============================================================================

/// Tracks artifacts pinned for a defect record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefectBinding {
    /// Defect record ID.
    pub defect_record_id: String,

    /// Artifact IDs bound to this defect.
    pub artifact_ids: Vec<String>,

    /// When the binding was created.
    pub created_at: u64,

    /// Grace period in seconds after defect closure.
    pub grace_period_secs: u64,
}

// =============================================================================
// PinManager
// =============================================================================

/// Manager for evidence artifact pins.
///
/// The `PinManager` provides a high-level API for pinning and unpinning
/// evidence artifacts, with special support for defect record binding.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::pin::PinManager;
/// use apm2_daemon::evidence::artifact::PinReason;
///
/// let mut manager = PinManager::new();
///
/// // Pin an artifact
/// let receipt = manager.pin(
///     &mut enforcer,
///     "art-001",
///     PinReason::manual_hold("admin", "investigating"),
///     None,
///     "admin@example.com",
///     now_ns,
/// )?;
///
/// // Check if pinned
/// assert!(manager.is_pinned(&enforcer, "art-001"));
///
/// // Unpin
/// manager.unpin(&mut enforcer, "art-001", now_ns)?;
/// ```
pub struct PinManager {
    /// Defect bindings by defect record ID.
    defect_bindings: HashMap<String, DefectBinding>,

    /// Collected pin events (cleared on drain).
    events: Vec<PinEvent>,
}

impl PinManager {
    /// Creates a new pin manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            defect_bindings: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Returns the number of active defect bindings.
    #[must_use]
    pub fn defect_binding_count(&self) -> usize {
        self.defect_bindings.len()
    }

    /// Drains and returns all collected events.
    pub fn drain_events(&mut self) -> Vec<PinEvent> {
        std::mem::take(&mut self.events)
    }

    // =========================================================================
    // Pin Operations
    // =========================================================================

    /// Pins an artifact.
    ///
    /// # Arguments
    ///
    /// * `enforcer` - The TTL enforcer managing artifacts
    /// * `artifact_id` - ID of the artifact to pin
    /// * `reason` - Reason for the pin
    /// * `expires_at` - Optional expiration timestamp (nanoseconds)
    /// * `actor` - Identity of the actor creating the pin
    /// * `now_ns` - Current timestamp (nanoseconds)
    ///
    /// # Returns
    ///
    /// A `PinReceipt` confirming the pin operation.
    ///
    /// # Errors
    ///
    /// Returns `PinError::ArtifactNotFound` if the artifact doesn't exist.
    #[instrument(skip(self, enforcer, actor), fields(artifact_id = %artifact_id))]
    pub fn pin(
        &mut self,
        enforcer: &mut TtlEnforcer,
        artifact_id: &str,
        reason: PinReason,
        expires_at: Option<u64>,
        actor: impl Into<String>,
        now_ns: u64,
    ) -> Result<PinReceipt, PinError> {
        let actor = actor.into();

        let artifact =
            enforcer
                .get_artifact_mut(artifact_id)
                .ok_or_else(|| PinError::ArtifactNotFound {
                    artifact_id: artifact_id.to_string(),
                })?;

        let episode_id = artifact.episode_id().as_str().to_string();

        // Apply pin
        artifact.pin(reason.clone(), expires_at, now_ns);

        debug!(
            artifact_id = %artifact_id,
            actor = %actor,
            reason_type = %reason.reason_type(),
            "artifact pinned"
        );

        // Emit event
        self.events.push(PinEvent::Pinned {
            artifact_id: artifact_id.to_string(),
            episode_id,
            reason: reason.clone(),
            pinned_at: now_ns,
            expires_at,
        });

        Ok(PinReceipt {
            artifact_id: artifact_id.to_string(),
            reason,
            pinned_at: now_ns,
            expires_at,
            actor,
        })
    }

    /// Unpins an artifact.
    ///
    /// # Arguments
    ///
    /// * `enforcer` - The TTL enforcer managing artifacts
    /// * `artifact_id` - ID of the artifact to unpin
    /// * `now_ns` - Current timestamp (nanoseconds)
    ///
    /// # Errors
    ///
    /// Returns `PinError::ArtifactNotFound` if the artifact doesn't exist.
    /// Returns `PinError::NotPinned` if the artifact is not pinned.
    #[instrument(skip(self, enforcer), fields(artifact_id = %artifact_id))]
    pub fn unpin(
        &mut self,
        enforcer: &mut TtlEnforcer,
        artifact_id: &str,
        now_ns: u64,
    ) -> Result<(), PinError> {
        let artifact =
            enforcer
                .get_artifact_mut(artifact_id)
                .ok_or_else(|| PinError::ArtifactNotFound {
                    artifact_id: artifact_id.to_string(),
                })?;

        if !artifact.is_pinned() {
            return Err(PinError::NotPinned {
                artifact_id: artifact_id.to_string(),
            });
        }

        let original_reason = artifact.pin_state().reason().cloned();
        let episode_id = artifact.episode_id().as_str().to_string();

        artifact.unpin();

        debug!(artifact_id = %artifact_id, "artifact unpinned");

        self.events.push(PinEvent::Unpinned {
            artifact_id: artifact_id.to_string(),
            episode_id,
            unpinned_at: now_ns,
            original_reason,
        });

        Ok(())
    }

    /// Checks if an artifact is pinned.
    #[must_use]
    pub fn is_pinned(&self, enforcer: &TtlEnforcer, artifact_id: &str) -> bool {
        enforcer
            .get_artifact(artifact_id)
            .is_some_and(EvidenceArtifact::is_pinned)
    }

    /// Extends a pin's expiration.
    ///
    /// # Arguments
    ///
    /// * `enforcer` - The TTL enforcer managing artifacts
    /// * `artifact_id` - ID of the artifact
    /// * `new_expires_at` - New expiration timestamp (nanoseconds), or None for
    ///   indefinite
    /// * `now_ns` - Current timestamp (nanoseconds)
    ///
    /// # Errors
    ///
    /// Returns `PinError::ArtifactNotFound` if the artifact doesn't exist.
    /// Returns `PinError::NotPinned` if the artifact is not pinned.
    pub fn extend_pin(
        &mut self,
        enforcer: &mut TtlEnforcer,
        artifact_id: &str,
        new_expires_at: Option<u64>,
        now_ns: u64,
    ) -> Result<(), PinError> {
        let artifact =
            enforcer
                .get_artifact_mut(artifact_id)
                .ok_or_else(|| PinError::ArtifactNotFound {
                    artifact_id: artifact_id.to_string(),
                })?;

        let old_expires_at = match artifact.pin_state() {
            PinState::Pinned {
                expires_at, reason, ..
            } => {
                let old_exp = *expires_at;
                // Re-pin with same reason but new expiration
                artifact.pin(reason.clone(), new_expires_at, now_ns);
                old_exp
            },
            PinState::Unpinned => {
                return Err(PinError::NotPinned {
                    artifact_id: artifact_id.to_string(),
                });
            },
        };

        debug!(
            artifact_id = %artifact_id,
            old_expires = ?old_expires_at,
            new_expires = ?new_expires_at,
            "pin extended"
        );

        self.events.push(PinEvent::Extended {
            artifact_id: artifact_id.to_string(),
            old_expires_at,
            new_expires_at,
            extended_at: now_ns,
        });

        Ok(())
    }

    // =========================================================================
    // Defect Integration (AD-CAC-001)
    // =========================================================================

    /// Pins artifacts for a defect record.
    ///
    /// Per AD-CAC-001, defect records trigger automatic evidence pins
    /// to ensure related evidence is preserved during investigation.
    ///
    /// # Arguments
    ///
    /// * `enforcer` - The TTL enforcer managing artifacts
    /// * `defect_record_id` - ID of the defect record
    /// * `artifact_ids` - IDs of artifacts to pin
    /// * `grace_period` - Duration to preserve after potential closure
    /// * `now_ns` - Current timestamp (nanoseconds)
    ///
    /// # Returns
    ///
    /// Number of artifacts successfully pinned.
    ///
    /// # Errors
    ///
    /// Returns `PinError::InvalidGracePeriod` if grace period exceeds maximum.
    #[instrument(skip(self, enforcer, artifact_ids), fields(defect_record_id = %defect_record_id))]
    pub fn pin_for_defect(
        &mut self,
        enforcer: &mut TtlEnforcer,
        defect_record_id: &str,
        artifact_ids: &[&str],
        grace_period: Duration,
        now_ns: u64,
    ) -> Result<usize, PinError> {
        let defect_record_id = defect_record_id.to_string();
        let grace_secs = grace_period.as_secs();

        if grace_secs > MAX_GRACE_PERIOD_SECS {
            return Err(PinError::InvalidGracePeriod {
                reason: format!(
                    "grace period {grace_secs}s exceeds maximum {MAX_GRACE_PERIOD_SECS}s"
                ),
            });
        }

        let mut pinned_ids = Vec::with_capacity(artifact_ids.len());
        let reason = PinReason::defect_binding(&defect_record_id);

        for artifact_id in artifact_ids {
            if let Some(artifact) = enforcer.get_artifact_mut(artifact_id) {
                artifact.pin(reason.clone(), None, now_ns);
                pinned_ids.push((*artifact_id).to_string());

                self.events.push(PinEvent::DefectPinned {
                    artifact_id: (*artifact_id).to_string(),
                    defect_record_id: defect_record_id.clone(),
                    pinned_at: now_ns,
                });
            } else {
                warn!(
                    artifact_id = %artifact_id,
                    defect_record_id = %defect_record_id,
                    "artifact not found for defect binding"
                );
            }
        }

        let count = pinned_ids.len();

        // Track binding
        self.defect_bindings.insert(
            defect_record_id.clone(),
            DefectBinding {
                defect_record_id,
                artifact_ids: pinned_ids,
                created_at: now_ns,
                grace_period_secs: grace_secs,
            },
        );

        info!(count = count, "artifacts pinned for defect");

        Ok(count)
    }

    /// Unpins artifacts when a defect record is closed.
    ///
    /// Per AD-CAC-001, when a defect is closed, the associated evidence
    /// pins are converted to time-limited pins with a grace period.
    ///
    /// # Arguments
    ///
    /// * `enforcer` - The TTL enforcer managing artifacts
    /// * `defect_record_id` - ID of the closed defect record
    /// * `now_ns` - Current timestamp (nanoseconds)
    ///
    /// # Returns
    ///
    /// Number of artifacts whose pins were updated.
    #[instrument(skip(self, enforcer), fields(defect_record_id = %defect_record_id))]
    pub fn unpin_for_defect_closure(
        &mut self,
        enforcer: &mut TtlEnforcer,
        defect_record_id: &str,
        now_ns: u64,
    ) -> usize {
        let Some(binding) = self.defect_bindings.remove(defect_record_id) else {
            warn!(
                defect_record_id = %defect_record_id,
                "no defect binding found"
            );
            return 0;
        };

        // Calculate expiration: now + grace period
        let expires_at = now_ns.saturating_add(binding.grace_period_secs * 1_000_000_000);

        let mut count = 0;
        for artifact_id in &binding.artifact_ids {
            if let Some(artifact) = enforcer.get_artifact_mut(artifact_id) {
                // Check if still pinned for this defect
                if let PinState::Pinned { reason, .. } = artifact.pin_state() {
                    if matches!(reason, PinReason::DefectBinding { .. }) {
                        // Convert to time-limited pin
                        artifact.pin(reason.clone(), Some(expires_at), now_ns);
                        count += 1;

                        self.events.push(PinEvent::DefectUnpinned {
                            artifact_id: artifact_id.clone(),
                            defect_record_id: defect_record_id.to_string(),
                            unpinned_at: now_ns,
                        });
                    }
                }
            }
        }

        info!(
            count = count,
            grace_period_secs = binding.grace_period_secs,
            "defect pins converted to time-limited"
        );

        count
    }

    /// Returns artifacts bound to a defect record.
    #[must_use]
    pub fn get_defect_artifacts(&self, defect_record_id: &str) -> Option<&[String]> {
        self.defect_bindings
            .get(defect_record_id)
            .map(|b| b.artifact_ids.as_slice())
    }

    // =========================================================================
    // Bulk Operations
    // =========================================================================

    /// Pins multiple artifacts with the same reason.
    ///
    /// # Returns
    ///
    /// A vector of (`artifact_id`, result) pairs.
    pub fn pin_batch(
        &mut self,
        enforcer: &mut TtlEnforcer,
        artifact_ids: &[&str],
        reason: &PinReason,
        expires_at: Option<u64>,
        actor: impl Into<String>,
        now_ns: u64,
    ) -> Vec<(String, Result<PinReceipt, PinError>)> {
        let actor = actor.into();
        let mut results = Vec::with_capacity(artifact_ids.len());

        for artifact_id in artifact_ids {
            let result = self.pin(
                enforcer,
                artifact_id,
                reason.clone(),
                expires_at,
                actor.clone(),
                now_ns,
            );
            results.push(((*artifact_id).to_string(), result));
        }

        results
    }

    /// Unpins multiple artifacts.
    ///
    /// # Returns
    ///
    /// A vector of (`artifact_id`, result) pairs.
    pub fn unpin_batch(
        &mut self,
        enforcer: &mut TtlEnforcer,
        artifact_ids: &[&str],
        now_ns: u64,
    ) -> Vec<(String, Result<(), PinError>)> {
        let mut results = Vec::with_capacity(artifact_ids.len());

        for artifact_id in artifact_ids {
            let result = self.unpin(enforcer, artifact_id, now_ns);
            results.push(((*artifact_id).to_string(), result));
        }

        results
    }

    /// Returns all currently active pins.
    pub fn active_pins<'a>(&self, enforcer: &'a TtlEnforcer) -> Vec<&'a EvidenceArtifact> {
        enforcer.artifacts().filter(|a| a.is_pinned()).collect()
    }

    /// Returns pins expiring within the given duration.
    #[allow(clippy::cast_possible_truncation)] // Duration in practice is < u64::MAX nanos
    pub fn pins_expiring_within<'a>(
        &self,
        enforcer: &'a TtlEnforcer,
        duration: Duration,
        now_ns: u64,
    ) -> Vec<&'a EvidenceArtifact> {
        let duration_ns = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
        let threshold = now_ns.saturating_add(duration_ns);

        enforcer
            .artifacts()
            .filter(|a| {
                if let PinState::Pinned {
                    expires_at: Some(exp),
                    ..
                } = a.pin_state()
                {
                    *exp <= threshold
                } else {
                    false
                }
            })
            .collect()
    }
}

impl Default for PinManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PinManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinManager")
            .field("defect_bindings", &self.defect_bindings.len())
            .field("pending_events", &self.events.len())
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::artifact::EvidenceClass;
    use crate::evidence::ttl::TtlEnforcerConfig;

    fn make_enforcer() -> TtlEnforcer {
        let config = TtlEnforcerConfig::default();
        TtlEnforcer::new(config)
    }

    fn make_artifact(id: &str, class: EvidenceClass, created_at: u64) -> EvidenceArtifact {
        EvidenceArtifact::try_new(id, [0u8; 32], class, "ep-test-001", created_at).unwrap()
    }

    // =========================================================================
    // Basic pin/unpin tests
    // =========================================================================

    #[test]
    fn test_pin_artifact() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        let receipt = manager
            .pin(
                &mut enforcer,
                "art-001",
                PinReason::manual_hold("admin", "testing"),
                None,
                "admin@test.com",
                1_000_000_000,
            )
            .unwrap();

        assert_eq!(receipt.artifact_id, "art-001");
        assert_eq!(receipt.actor, "admin@test.com");
        assert!(manager.is_pinned(&enforcer, "art-001"));
    }

    #[test]
    fn test_unpin_artifact() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        manager
            .pin(
                &mut enforcer,
                "art-001",
                PinReason::manual_hold("admin", "testing"),
                None,
                "admin",
                1_000_000_000,
            )
            .unwrap();

        assert!(manager.is_pinned(&enforcer, "art-001"));

        manager
            .unpin(&mut enforcer, "art-001", 2_000_000_000)
            .unwrap();

        assert!(!manager.is_pinned(&enforcer, "art-001"));
    }

    #[test]
    fn test_pin_not_found() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let result = manager.pin(
            &mut enforcer,
            "nonexistent",
            PinReason::manual_hold("admin", "testing"),
            None,
            "admin",
            1_000_000_000,
        );

        assert!(matches!(result, Err(PinError::ArtifactNotFound { .. })));
    }

    #[test]
    fn test_unpin_not_pinned() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        let result = manager.unpin(&mut enforcer, "art-001", 1_000_000_000);

        assert!(matches!(result, Err(PinError::NotPinned { .. })));
    }

    // =========================================================================
    // Pin expiration tests
    // =========================================================================

    #[test]
    fn test_pin_with_expiration() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        let expires_at = 5_000_000_000;
        let receipt = manager
            .pin(
                &mut enforcer,
                "art-001",
                PinReason::manual_hold("admin", "testing"),
                Some(expires_at),
                "admin",
                1_000_000_000,
            )
            .unwrap();

        assert_eq!(receipt.expires_at, Some(expires_at));
        assert!(!receipt.is_expired(2_000_000_000));
        assert!(receipt.is_expired(5_000_000_000));
    }

    #[test]
    fn test_extend_pin() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        // Pin with expiration
        manager
            .pin(
                &mut enforcer,
                "art-001",
                PinReason::manual_hold("admin", "testing"),
                Some(2_000_000_000),
                "admin",
                1_000_000_000,
            )
            .unwrap();

        // Extend
        manager
            .extend_pin(&mut enforcer, "art-001", Some(5_000_000_000), 1_500_000_000)
            .unwrap();

        let artifact = enforcer.get_artifact("art-001").unwrap();
        assert_eq!(artifact.pin_state().expires_at(), Some(5_000_000_000));
    }

    // =========================================================================
    // Defect integration tests
    // =========================================================================

    #[test]
    fn test_pin_for_defect() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let a1 = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        let a2 = make_artifact("art-002", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(a1).unwrap();
        enforcer.add_artifact(a2).unwrap();

        let count = manager
            .pin_for_defect(
                &mut enforcer,
                "DEF-001",
                &["art-001", "art-002"],
                Duration::from_secs(DEFAULT_DEFECT_GRACE_PERIOD_SECS),
                1_000_000_000,
            )
            .unwrap();

        assert_eq!(count, 2);
        assert!(manager.is_pinned(&enforcer, "art-001"));
        assert!(manager.is_pinned(&enforcer, "art-002"));

        let artifacts = manager.get_defect_artifacts("DEF-001").unwrap();
        assert_eq!(artifacts.len(), 2);
    }

    #[test]
    fn test_unpin_for_defect_closure() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let a1 = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(a1).unwrap();

        let grace_secs = 3600; // 1 hour grace
        manager
            .pin_for_defect(
                &mut enforcer,
                "DEF-001",
                &["art-001"],
                Duration::from_secs(grace_secs),
                1_000_000_000,
            )
            .unwrap();

        // Close defect
        let count = manager.unpin_for_defect_closure(&mut enforcer, "DEF-001", 2_000_000_000);

        assert_eq!(count, 1);

        // Pin should now have expiration
        let artifact = enforcer.get_artifact("art-001").unwrap();
        let expected_expiration = 2_000_000_000 + (grace_secs * 1_000_000_000);
        assert_eq!(artifact.pin_state().expires_at(), Some(expected_expiration));
    }

    #[test]
    fn test_defect_grace_period_limit() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        // Grace period too long
        let result = manager.pin_for_defect(
            &mut enforcer,
            "DEF-001",
            &["art-001"],
            Duration::from_secs(MAX_GRACE_PERIOD_SECS + 1),
            1_000_000_000,
        );

        assert!(matches!(result, Err(PinError::InvalidGracePeriod { .. })));
    }

    // =========================================================================
    // Event tests
    // =========================================================================

    #[test]
    fn test_pin_events() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        manager
            .pin(
                &mut enforcer,
                "art-001",
                PinReason::manual_hold("admin", "testing"),
                None,
                "admin",
                1_000_000_000,
            )
            .unwrap();

        manager
            .unpin(&mut enforcer, "art-001", 2_000_000_000)
            .unwrap();

        let events = manager.drain_events();
        assert_eq!(events.len(), 2);

        assert!(
            matches!(&events[0], PinEvent::Pinned { artifact_id, .. } if artifact_id == "art-001")
        );
        assert!(
            matches!(&events[1], PinEvent::Unpinned { artifact_id, .. } if artifact_id == "art-001")
        );
    }

    #[test]
    fn test_defect_events() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        manager
            .pin_for_defect(
                &mut enforcer,
                "DEF-001",
                &["art-001"],
                Duration::from_secs(3600),
                1_000_000_000,
            )
            .unwrap();

        manager.unpin_for_defect_closure(&mut enforcer, "DEF-001", 2_000_000_000);

        let events = manager.drain_events();
        assert_eq!(events.len(), 2);

        assert!(
            matches!(&events[0], PinEvent::DefectPinned { defect_record_id, .. } if defect_record_id == "DEF-001")
        );
        assert!(
            matches!(&events[1], PinEvent::DefectUnpinned { defect_record_id, .. } if defect_record_id == "DEF-001")
        );
    }

    // =========================================================================
    // Batch operations tests
    // =========================================================================

    #[test]
    fn test_pin_batch() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        for i in 0..3 {
            let artifact = make_artifact(
                &format!("art-{i:03}"),
                EvidenceClass::Standard,
                1_000_000_000,
            );
            enforcer.add_artifact(artifact).unwrap();
        }

        let results = manager.pin_batch(
            &mut enforcer,
            &["art-000", "art-001", "art-002", "nonexistent"],
            &PinReason::manual_hold("admin", "batch test"),
            None,
            "admin",
            1_000_000_000,
        );

        assert_eq!(results.len(), 4);
        assert!(results[0].1.is_ok());
        assert!(results[1].1.is_ok());
        assert!(results[2].1.is_ok());
        assert!(results[3].1.is_err());
    }

    #[test]
    fn test_unpin_batch() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        for i in 0..2 {
            let artifact = make_artifact(
                &format!("art-{i:03}"),
                EvidenceClass::Standard,
                1_000_000_000,
            );
            enforcer.add_artifact(artifact).unwrap();
        }

        // Pin them
        manager.pin_batch(
            &mut enforcer,
            &["art-000", "art-001"],
            &PinReason::manual_hold("admin", "testing"),
            None,
            "admin",
            1_000_000_000,
        );

        // Unpin batch
        let results = manager.unpin_batch(&mut enforcer, &["art-000", "art-001"], 2_000_000_000);

        assert_eq!(results.len(), 2);
        assert!(results[0].1.is_ok());
        assert!(results[1].1.is_ok());
    }

    // =========================================================================
    // Query tests
    // =========================================================================

    #[test]
    fn test_active_pins() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        for i in 0..3 {
            let artifact = make_artifact(
                &format!("art-{i:03}"),
                EvidenceClass::Standard,
                1_000_000_000,
            );
            enforcer.add_artifact(artifact).unwrap();
        }

        // Pin only first two
        manager.pin_batch(
            &mut enforcer,
            &["art-000", "art-001"],
            &PinReason::manual_hold("admin", "testing"),
            None,
            "admin",
            1_000_000_000,
        );

        let active = manager.active_pins(&enforcer);
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_pins_expiring_within() {
        let mut enforcer = make_enforcer();
        let mut manager = PinManager::new();

        let a1 = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        let a2 = make_artifact("art-002", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(a1).unwrap();
        enforcer.add_artifact(a2).unwrap();

        // Pin with different expirations
        manager
            .pin(
                &mut enforcer,
                "art-001",
                PinReason::manual_hold("admin", "short"),
                Some(2_000_000_000), // expires soon
                "admin",
                1_000_000_000,
            )
            .unwrap();

        manager
            .pin(
                &mut enforcer,
                "art-002",
                PinReason::manual_hold("admin", "long"),
                Some(10_000_000_000), // expires later
                "admin",
                1_000_000_000,
            )
            .unwrap();

        let expiring = manager.pins_expiring_within(
            &enforcer,
            Duration::from_secs(5), // within 5 seconds
            1_000_000_000,
        );

        // Only art-001 expires within 5 seconds from now
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].artifact_id().as_str(), "art-001");
    }

    // =========================================================================
    // Serialization tests
    // =========================================================================

    #[test]
    fn test_pin_receipt_serialization() {
        let receipt = PinReceipt {
            artifact_id: "art-001".to_string(),
            reason: PinReason::manual_hold("admin", "testing"),
            pinned_at: 1_000_000_000,
            expires_at: Some(2_000_000_000),
            actor: "admin@test.com".to_string(),
        };

        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: PinReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt, deserialized);
    }

    #[test]
    fn test_pin_event_serialization() {
        let event = PinEvent::Pinned {
            artifact_id: "art-001".to_string(),
            episode_id: "ep-001".to_string(),
            reason: PinReason::defect_binding("DEF-001"),
            pinned_at: 1_000_000_000,
            expires_at: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PinEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event, deserialized);
    }
}
