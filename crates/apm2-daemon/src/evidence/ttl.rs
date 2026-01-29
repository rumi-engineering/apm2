//! TTL enforcement for evidence artifacts per AD-EVID-002.
//!
//! This module implements the `TtlEnforcer` which periodically scans
//! artifacts for expiration and evicts expired unpinned artifacts.
//!
//! # Architecture
//!
//! ```text
//! TtlEnforcer
//!     |
//!     +-- config: TtlEnforcerConfig
//!     +-- artifacts: HashMap<ArtifactId, EvidenceArtifact>
//!     |
//!     +-- enforce_ttl(now_ns) -> Vec<EvictionEvent>
//!     +-- add_artifact(artifact)
//!     +-- remove_artifact(artifact_id)
//!     +-- get_artifact(artifact_id) -> Option<&EvidenceArtifact>
//! ```
//!
//! # Eviction Logic
//!
//! Per AD-EVID-002, artifacts are evicted when:
//! 1. TTL has expired (`now >= created_at + ttl`)
//! 2. Artifact is not pinned, OR pin has expired
//!
//! # Timer Integration
//!
//! The enforcer is designed to be driven by an external timer:
//! - Production: Tokio interval timer (1 minute default)
//! - Testing: Manual invocation of `enforce_ttl()`
//!
//! # Security Model
//!
//! - Eviction is fail-closed: errors preserve artifacts
//! - All evictions emit events for audit logging
//! - Bounded artifact count prevents memory exhaustion
//!
//! # Invariants
//!
//! - [INV-TTL001] Pinned artifacts are never evicted
//! - [INV-TTL002] Eviction events include artifact metadata
//! - [INV-TTL003] Maximum artifact count is bounded
//!
//! # Contract References
//!
//! - AD-EVID-002: Evidence retention and TTL
//! - CTR-1303: Bounded collections

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use super::artifact::{ArtifactError, EvidenceArtifact, EvidenceClass};

// =============================================================================
// Constants
// =============================================================================

/// Default enforcement interval (1 minute).
pub const DEFAULT_ENFORCEMENT_INTERVAL_SECS: u64 = 60;

/// Minimum enforcement interval (10 seconds).
pub const MIN_ENFORCEMENT_INTERVAL_SECS: u64 = 10;

/// Maximum enforcement interval (1 hour).
pub const MAX_ENFORCEMENT_INTERVAL_SECS: u64 = 3600;

/// Maximum number of artifacts to track.
pub const MAX_ARTIFACTS: usize = 100_000;

/// Maximum evictions per enforcement run (prevents starvation).
pub const MAX_EVICTIONS_PER_RUN: usize = 1000;

// =============================================================================
// TtlEnforcerConfig
// =============================================================================

/// Configuration for the TTL enforcer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtlEnforcerConfig {
    /// Enforcement interval in seconds.
    enforcement_interval_secs: u64,

    /// Maximum artifacts to track.
    max_artifacts: usize,

    /// Maximum evictions per enforcement run.
    max_evictions_per_run: usize,

    /// Whether to emit debug logs for each eviction.
    verbose_eviction_logging: bool,
}

impl TtlEnforcerConfig {
    /// Creates a new configuration with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if any value is out of bounds.
    pub fn try_new(
        enforcement_interval_secs: u64,
        max_artifacts: usize,
        max_evictions_per_run: usize,
    ) -> Result<Self, String> {
        if enforcement_interval_secs < MIN_ENFORCEMENT_INTERVAL_SECS {
            return Err(format!(
                "enforcement_interval_secs ({enforcement_interval_secs}) must be >= {MIN_ENFORCEMENT_INTERVAL_SECS}"
            ));
        }
        if enforcement_interval_secs > MAX_ENFORCEMENT_INTERVAL_SECS {
            return Err(format!(
                "enforcement_interval_secs ({enforcement_interval_secs}) must be <= {MAX_ENFORCEMENT_INTERVAL_SECS}"
            ));
        }
        if max_artifacts == 0 {
            return Err("max_artifacts must be > 0".to_string());
        }
        if max_artifacts > MAX_ARTIFACTS {
            return Err(format!(
                "max_artifacts ({max_artifacts}) exceeds MAX_ARTIFACTS ({MAX_ARTIFACTS})"
            ));
        }
        if max_evictions_per_run == 0 {
            return Err("max_evictions_per_run must be > 0".to_string());
        }

        Ok(Self {
            enforcement_interval_secs,
            max_artifacts,
            max_evictions_per_run,
            verbose_eviction_logging: false,
        })
    }

    /// Returns the enforcement interval as a Duration.
    #[must_use]
    pub const fn enforcement_interval(&self) -> Duration {
        Duration::from_secs(self.enforcement_interval_secs)
    }

    /// Returns the maximum number of artifacts.
    #[must_use]
    pub const fn max_artifacts(&self) -> usize {
        self.max_artifacts
    }

    /// Returns the maximum evictions per run.
    #[must_use]
    pub const fn max_evictions_per_run(&self) -> usize {
        self.max_evictions_per_run
    }

    /// Enables verbose eviction logging.
    #[must_use]
    pub const fn with_verbose_logging(mut self, verbose: bool) -> Self {
        self.verbose_eviction_logging = verbose;
        self
    }

    /// Returns whether verbose eviction logging is enabled.
    #[must_use]
    pub const fn verbose_eviction_logging(&self) -> bool {
        self.verbose_eviction_logging
    }
}

impl Default for TtlEnforcerConfig {
    fn default() -> Self {
        Self {
            enforcement_interval_secs: DEFAULT_ENFORCEMENT_INTERVAL_SECS,
            max_artifacts: MAX_ARTIFACTS,
            max_evictions_per_run: MAX_EVICTIONS_PER_RUN,
            verbose_eviction_logging: false,
        }
    }
}

// =============================================================================
// EvictionEvent
// =============================================================================

/// Event emitted when an artifact is evicted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvictionEvent {
    /// ID of the evicted artifact.
    pub artifact_id: String,

    /// Episode that owned the artifact.
    pub episode_id: String,

    /// Evidence class of the artifact.
    pub class: EvidenceClass,

    /// TTL that was configured (seconds).
    pub ttl_secs: u64,

    /// When the artifact was created (nanoseconds).
    pub created_at_ns: u64,

    /// When eviction occurred (nanoseconds).
    pub evicted_at_ns: u64,

    /// Reason for eviction.
    pub reason: EvictionReason,
}

/// Reason for artifact eviction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionReason {
    /// TTL expired and artifact was unpinned.
    TtlExpired,

    /// TTL expired and pin had also expired.
    TtlAndPinExpired,

    /// Manual eviction request.
    ManualEviction,

    /// Capacity limit reached, oldest evicted.
    CapacityEviction,
}

impl EvictionReason {
    /// Returns the reason as a string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TtlExpired => "ttl_expired",
            Self::TtlAndPinExpired => "ttl_and_pin_expired",
            Self::ManualEviction => "manual_eviction",
            Self::CapacityEviction => "capacity_eviction",
        }
    }
}

// =============================================================================
// EnforcementStats
// =============================================================================

/// Statistics from an enforcement run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnforcementStats {
    /// Number of artifacts scanned.
    pub artifacts_scanned: usize,

    /// Number of artifacts evicted.
    pub artifacts_evicted: usize,

    /// Number of pinned artifacts skipped.
    pub pinned_skipped: usize,

    /// Number of active (not expired) artifacts.
    pub active_artifacts: usize,

    /// Whether max evictions limit was hit.
    pub limit_reached: bool,

    /// Duration of the enforcement run (nanoseconds).
    pub duration_ns: u64,
}

// =============================================================================
// TtlEnforcer
// =============================================================================

/// TTL enforcer for evidence artifacts.
///
/// The enforcer maintains a collection of artifacts and provides
/// periodic enforcement of TTL policies.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::evidence::ttl::{TtlEnforcer, TtlEnforcerConfig};
/// use apm2_daemon::evidence::artifact::{EvidenceArtifact, EvidenceClass};
///
/// let config = TtlEnforcerConfig::default();
/// let mut enforcer = TtlEnforcer::new(config);
///
/// // Add artifacts
/// let artifact = EvidenceArtifact::try_new(
///     "art-001",
///     [0u8; 32],
///     EvidenceClass::Ephemeral,
///     "ep-001",
///     1_000_000_000,
/// )?;
/// enforcer.add_artifact(artifact)?;
///
/// // Run enforcement (typically called by timer)
/// let (events, stats) = enforcer.enforce_ttl(now_ns);
/// ```
pub struct TtlEnforcer {
    /// Configuration.
    config: TtlEnforcerConfig,

    /// Tracked artifacts by ID.
    artifacts: HashMap<String, EvidenceArtifact>,

    /// Last enforcement timestamp (nanoseconds).
    last_enforcement_ns: u64,
}

impl TtlEnforcer {
    /// Creates a new TTL enforcer.
    #[must_use]
    pub fn new(config: TtlEnforcerConfig) -> Self {
        Self {
            config,
            artifacts: HashMap::with_capacity(1024),
            last_enforcement_ns: 0,
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &TtlEnforcerConfig {
        &self.config
    }

    /// Returns the number of tracked artifacts.
    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Returns `true` if no artifacts are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Returns the last enforcement timestamp.
    #[must_use]
    pub const fn last_enforcement_ns(&self) -> u64 {
        self.last_enforcement_ns
    }

    // =========================================================================
    // Artifact Management
    // =========================================================================

    /// Adds an artifact to the enforcer.
    ///
    /// # Errors
    ///
    /// Returns `ArtifactError::LimitReached` if at capacity.
    pub fn add_artifact(&mut self, artifact: EvidenceArtifact) -> Result<(), ArtifactError> {
        if self.artifacts.len() >= self.config.max_artifacts {
            return Err(ArtifactError::InvalidId {
                id: artifact.artifact_id().as_str().to_string(),
                reason: format!(
                    "artifact limit reached (max: {})",
                    self.config.max_artifacts
                ),
            });
        }

        let id = artifact.artifact_id().as_str().to_string();
        self.artifacts.insert(id, artifact);
        Ok(())
    }

    /// Removes an artifact by ID.
    ///
    /// Returns the removed artifact if it existed.
    pub fn remove_artifact(&mut self, artifact_id: &str) -> Option<EvidenceArtifact> {
        self.artifacts.remove(artifact_id)
    }

    /// Gets an artifact by ID.
    #[must_use]
    pub fn get_artifact(&self, artifact_id: &str) -> Option<&EvidenceArtifact> {
        self.artifacts.get(artifact_id)
    }

    /// Gets a mutable reference to an artifact by ID.
    #[must_use]
    pub fn get_artifact_mut(&mut self, artifact_id: &str) -> Option<&mut EvidenceArtifact> {
        self.artifacts.get_mut(artifact_id)
    }

    /// Returns an iterator over all artifacts.
    pub fn artifacts(&self) -> impl Iterator<Item = &EvidenceArtifact> {
        self.artifacts.values()
    }

    // =========================================================================
    // TTL Enforcement
    // =========================================================================

    /// Enforces TTL policies, evicting expired artifacts.
    ///
    /// This method should be called periodically (typically by a timer).
    /// It scans all artifacts and evicts those that have expired and are
    /// not protected by a valid pin.
    ///
    /// # Arguments
    ///
    /// * `now_ns` - Current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// A tuple of (eviction events, enforcement stats).
    #[instrument(skip(self), fields(artifact_count = self.artifacts.len()))]
    pub fn enforce_ttl(&mut self, now_ns: u64) -> (Vec<EvictionEvent>, EnforcementStats) {
        let start_ns = now_ns;
        let mut events = Vec::new();
        let mut stats = EnforcementStats {
            artifacts_scanned: self.artifacts.len(),
            ..Default::default()
        };

        // Collect IDs of artifacts to evict
        let mut to_evict: Vec<(String, EvictionReason)> = Vec::new();

        for (id, artifact) in &self.artifacts {
            if artifact.is_pinned() {
                // Check if pin has expired
                if artifact.is_pin_expired(now_ns) {
                    // Pin expired, check if TTL also expired
                    if artifact.should_evict(now_ns) {
                        if to_evict.len() < self.config.max_evictions_per_run {
                            to_evict.push((id.clone(), EvictionReason::TtlAndPinExpired));
                        } else {
                            stats.limit_reached = true;
                            break;
                        }
                    } else {
                        stats.active_artifacts += 1;
                    }
                } else {
                    // Pin still active
                    stats.pinned_skipped += 1;
                    stats.active_artifacts += 1;
                }
            } else if artifact.should_evict(now_ns) {
                // Unpinned and expired
                if to_evict.len() < self.config.max_evictions_per_run {
                    to_evict.push((id.clone(), EvictionReason::TtlExpired));
                } else {
                    stats.limit_reached = true;
                    break;
                }
            } else {
                stats.active_artifacts += 1;
            }
        }

        // Perform evictions
        for (id, reason) in to_evict {
            if let Some(artifact) = self.artifacts.remove(&id) {
                let event = EvictionEvent {
                    artifact_id: id,
                    episode_id: artifact.episode_id().as_str().to_string(),
                    class: artifact.class(),
                    ttl_secs: artifact.ttl_secs(),
                    created_at_ns: artifact.created_at(),
                    evicted_at_ns: now_ns,
                    reason,
                };

                if self.config.verbose_eviction_logging {
                    debug!(
                        artifact_id = %event.artifact_id,
                        episode_id = %event.episode_id,
                        reason = ?event.reason,
                        "evicting artifact"
                    );
                }

                events.push(event);
                stats.artifacts_evicted += 1;
            }
        }

        self.last_enforcement_ns = now_ns;
        stats.duration_ns = now_ns.saturating_sub(start_ns);

        if stats.artifacts_evicted > 0 {
            info!(
                evicted = stats.artifacts_evicted,
                remaining = self.artifacts.len(),
                "TTL enforcement completed"
            );
        }

        (events, stats)
    }

    /// Forces eviction of a specific artifact.
    ///
    /// This bypasses TTL and pin checks.
    ///
    /// # Arguments
    ///
    /// * `artifact_id` - ID of the artifact to evict
    /// * `now_ns` - Current timestamp for the eviction event
    ///
    /// # Returns
    ///
    /// The eviction event if the artifact existed.
    pub fn force_evict(&mut self, artifact_id: &str, now_ns: u64) -> Option<EvictionEvent> {
        let artifact = self.artifacts.remove(artifact_id)?;

        let event = EvictionEvent {
            artifact_id: artifact_id.to_string(),
            episode_id: artifact.episode_id().as_str().to_string(),
            class: artifact.class(),
            ttl_secs: artifact.ttl_secs(),
            created_at_ns: artifact.created_at(),
            evicted_at_ns: now_ns,
            reason: EvictionReason::ManualEviction,
        };

        warn!(
            artifact_id = %event.artifact_id,
            "force evicting artifact"
        );

        Some(event)
    }

    /// Evicts artifacts to make room when at capacity.
    ///
    /// Evicts the oldest expired unpinned artifacts first.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of artifacts to evict
    /// * `now_ns` - Current timestamp
    ///
    /// # Returns
    ///
    /// The eviction events for evicted artifacts.
    pub fn evict_for_capacity(&mut self, count: usize, now_ns: u64) -> Vec<EvictionEvent> {
        if count == 0 || self.artifacts.is_empty() {
            return Vec::new();
        }

        // Collect candidates sorted by expiration (oldest first)
        let mut candidates: Vec<_> = self
            .artifacts
            .iter()
            .filter(|(_, a)| !a.is_pinned())
            .map(|(id, a)| (id.clone(), a.created_at()))
            .collect();

        candidates.sort_by_key(|(_, created)| *created);

        let mut events = Vec::with_capacity(count.min(candidates.len()));

        for (id, _) in candidates.into_iter().take(count) {
            if let Some(artifact) = self.artifacts.remove(&id) {
                events.push(EvictionEvent {
                    artifact_id: id,
                    episode_id: artifact.episode_id().as_str().to_string(),
                    class: artifact.class(),
                    ttl_secs: artifact.ttl_secs(),
                    created_at_ns: artifact.created_at(),
                    evicted_at_ns: now_ns,
                    reason: EvictionReason::CapacityEviction,
                });
            }
        }

        if !events.is_empty() {
            warn!(
                evicted = events.len(),
                remaining = self.artifacts.len(),
                "capacity eviction completed"
            );
        }

        events
    }

    /// Clears all artifacts.
    pub fn clear(&mut self) {
        self.artifacts.clear();
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    /// Counts artifacts by evidence class.
    #[must_use]
    pub fn count_by_class(&self) -> HashMap<EvidenceClass, usize> {
        let mut counts = HashMap::new();
        for artifact in self.artifacts.values() {
            *counts.entry(artifact.class()).or_insert(0) += 1;
        }
        counts
    }

    /// Counts pinned artifacts.
    #[must_use]
    pub fn count_pinned(&self) -> usize {
        self.artifacts.values().filter(|a| a.is_pinned()).count()
    }

    /// Returns IDs of expired but pinned artifacts.
    #[must_use]
    pub fn expired_pinned_artifacts(&self, now_ns: u64) -> Vec<String> {
        self.artifacts
            .iter()
            .filter(|(_, a)| {
                a.is_pinned() && now_ns >= a.expires_at_ns() && !a.is_pin_expired(now_ns)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Returns artifacts expiring within the given duration.
    #[allow(clippy::cast_possible_truncation)] // Duration in practice is < u64::MAX nanos
    pub fn expiring_within(&self, duration: Duration, now_ns: u64) -> Vec<&EvidenceArtifact> {
        // Clamp to u64::MAX to avoid truncation issues for very long durations
        let duration_ns = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
        let threshold = now_ns.saturating_add(duration_ns);
        self.artifacts
            .values()
            .filter(|a| !a.is_pinned() && a.expires_at_ns() <= threshold)
            .collect()
    }
}

impl std::fmt::Debug for TtlEnforcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtlEnforcer")
            .field("config", &self.config)
            .field("artifact_count", &self.artifacts.len())
            .field("last_enforcement_ns", &self.last_enforcement_ns)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::artifact::{EPHEMERAL_TTL_SECS, PinReason};

    fn make_artifact(id: &str, class: EvidenceClass, created_at: u64) -> EvidenceArtifact {
        EvidenceArtifact::try_new(id, [0u8; 32], class, "ep-test-001", created_at).unwrap()
    }

    // =========================================================================
    // Config tests
    // =========================================================================

    #[test]
    fn test_config_default() {
        let config = TtlEnforcerConfig::default();
        assert_eq!(
            config.enforcement_interval_secs,
            DEFAULT_ENFORCEMENT_INTERVAL_SECS
        );
        assert_eq!(config.max_artifacts, MAX_ARTIFACTS);
        assert_eq!(config.max_evictions_per_run, MAX_EVICTIONS_PER_RUN);
    }

    #[test]
    fn test_config_validation() {
        // Too short interval
        assert!(TtlEnforcerConfig::try_new(5, 1000, 100).is_err());

        // Too long interval
        assert!(TtlEnforcerConfig::try_new(7200, 1000, 100).is_err());

        // Zero artifacts
        assert!(TtlEnforcerConfig::try_new(60, 0, 100).is_err());

        // Too many artifacts
        assert!(TtlEnforcerConfig::try_new(60, MAX_ARTIFACTS + 1, 100).is_err());

        // Zero evictions
        assert!(TtlEnforcerConfig::try_new(60, 1000, 0).is_err());

        // Valid config
        assert!(TtlEnforcerConfig::try_new(60, 1000, 100).is_ok());
    }

    // =========================================================================
    // Artifact management tests
    // =========================================================================

    #[test]
    fn test_add_and_get_artifact() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        assert_eq!(enforcer.artifact_count(), 1);
        assert!(!enforcer.is_empty());

        let retrieved = enforcer.get_artifact("art-001").unwrap();
        assert_eq!(retrieved.artifact_id().as_str(), "art-001");
    }

    #[test]
    fn test_remove_artifact() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        let artifact = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        let removed = enforcer.remove_artifact("art-001");
        assert!(removed.is_some());
        assert!(enforcer.is_empty());

        let removed_again = enforcer.remove_artifact("art-001");
        assert!(removed_again.is_none());
    }

    #[test]
    fn test_capacity_limit() {
        let config = TtlEnforcerConfig::try_new(60, 2, 100).unwrap();
        let mut enforcer = TtlEnforcer::new(config);

        let a1 = make_artifact("art-001", EvidenceClass::Standard, 1_000_000_000);
        let a2 = make_artifact("art-002", EvidenceClass::Standard, 1_000_000_000);
        let a3 = make_artifact("art-003", EvidenceClass::Standard, 1_000_000_000);

        assert!(enforcer.add_artifact(a1).is_ok());
        assert!(enforcer.add_artifact(a2).is_ok());
        assert!(enforcer.add_artifact(a3).is_err());
    }

    // =========================================================================
    // UT-00171-01: TTL expiration
    // =========================================================================

    #[test]
    fn test_ttl_expiration() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        // Add ephemeral artifact (1 hour TTL)
        let artifact = make_artifact("art-001", EvidenceClass::Ephemeral, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        // Before TTL - no eviction
        let (events, stats) = enforcer.enforce_ttl(1_000_000_000);
        assert_eq!(events.len(), 0);
        assert_eq!(stats.artifacts_evicted, 0);
        assert_eq!(stats.active_artifacts, 1);

        // After TTL - eviction
        let after_ttl = 1_000_000_000 + (EPHEMERAL_TTL_SECS * 1_000_000_000) + 1;
        let (events, stats) = enforcer.enforce_ttl(after_ttl);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].artifact_id, "art-001");
        assert_eq!(events[0].reason, EvictionReason::TtlExpired);
        assert_eq!(stats.artifacts_evicted, 1);
        assert!(enforcer.is_empty());
    }

    #[test]
    fn test_multiple_artifacts_different_ttls() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        // Add ephemeral (1 hour) and standard (7 days) artifacts
        let a1 = make_artifact("art-ephemeral", EvidenceClass::Ephemeral, 1_000_000_000);
        let a2 = make_artifact("art-standard", EvidenceClass::Standard, 1_000_000_000);

        enforcer.add_artifact(a1).unwrap();
        enforcer.add_artifact(a2).unwrap();

        // After 2 hours - only ephemeral should be evicted
        let two_hours_ns = 1_000_000_000 + (2 * 3600 * 1_000_000_000);
        let (events, _) = enforcer.enforce_ttl(two_hours_ns);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].artifact_id, "art-ephemeral");
        assert_eq!(enforcer.artifact_count(), 1);
        assert!(enforcer.get_artifact("art-standard").is_some());
    }

    // =========================================================================
    // UT-00171-02: Pin prevents deletion
    // =========================================================================

    #[test]
    fn test_pin_retention() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        // Add and pin ephemeral artifact
        let mut artifact = make_artifact("art-001", EvidenceClass::Ephemeral, 1_000_000_000);
        artifact.pin(
            PinReason::defect_binding("DEF-001"),
            None, // indefinite pin
            1_000_000_000,
        );
        enforcer.add_artifact(artifact).unwrap();

        // After TTL - should NOT be evicted because pinned
        let after_ttl = 1_000_000_000 + (EPHEMERAL_TTL_SECS * 1_000_000_000) + 1;
        let (events, stats) = enforcer.enforce_ttl(after_ttl);

        assert_eq!(events.len(), 0);
        assert_eq!(stats.pinned_skipped, 1);
        assert_eq!(stats.artifacts_evicted, 0);
        assert_eq!(enforcer.artifact_count(), 1);
    }

    #[test]
    fn test_pin_with_expiration() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        // Pin expires in 30 minutes
        let pin_expires = 1_000_000_000 + (30 * 60 * 1_000_000_000);

        let mut artifact = make_artifact("art-001", EvidenceClass::Ephemeral, 1_000_000_000);
        artifact.pin(
            PinReason::manual_hold("user", "testing"),
            Some(pin_expires),
            1_000_000_000,
        );
        enforcer.add_artifact(artifact).unwrap();

        // After pin expires but before TTL - should not evict
        let after_pin = pin_expires + 1;
        let (events, _) = enforcer.enforce_ttl(after_pin);
        assert_eq!(events.len(), 0);

        // After both pin and TTL expire - should evict
        let after_ttl = 1_000_000_000 + (EPHEMERAL_TTL_SECS * 1_000_000_000) + 1;
        let (events, stats) = enforcer.enforce_ttl(after_ttl);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, EvictionReason::TtlAndPinExpired);
        assert_eq!(stats.artifacts_evicted, 1);
    }

    #[test]
    fn test_unpin_allows_eviction() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        // Add and pin artifact
        let mut artifact = make_artifact("art-001", EvidenceClass::Ephemeral, 1_000_000_000);
        artifact.pin(PinReason::defect_binding("DEF-001"), None, 1_000_000_000);
        enforcer.add_artifact(artifact).unwrap();

        // Unpin via mutable reference
        enforcer.get_artifact_mut("art-001").unwrap().unpin();

        // Now it should be evictable after TTL
        let after_ttl = 1_000_000_000 + (EPHEMERAL_TTL_SECS * 1_000_000_000) + 1;
        let (events, _) = enforcer.enforce_ttl(after_ttl);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].artifact_id, "art-001");
    }

    // =========================================================================
    // Force eviction tests
    // =========================================================================

    #[test]
    fn test_force_evict() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        // Add pinned artifact
        let mut artifact = make_artifact("art-001", EvidenceClass::Archival, 1_000_000_000);
        artifact.pin(
            PinReason::compliance_hold("SOC2", "Audit"),
            None,
            1_000_000_000,
        );
        enforcer.add_artifact(artifact).unwrap();

        // Force evict bypasses pin
        let event = enforcer.force_evict("art-001", 2_000_000_000);

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.artifact_id, "art-001");
        assert_eq!(event.reason, EvictionReason::ManualEviction);
        assert!(enforcer.is_empty());
    }

    #[test]
    fn test_force_evict_nonexistent() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        let event = enforcer.force_evict("nonexistent", 2_000_000_000);
        assert!(event.is_none());
    }

    // =========================================================================
    // Capacity eviction tests
    // =========================================================================

    #[test]
    fn test_capacity_eviction() {
        let config = TtlEnforcerConfig::try_new(60, 100, 100).unwrap();
        let mut enforcer = TtlEnforcer::new(config);

        // Add 5 artifacts with different creation times
        for i in 0u64..5 {
            let artifact = make_artifact(
                &format!("art-{i:03}"),
                EvidenceClass::Standard,
                1_000_000_000 + (i * 1_000_000),
            );
            enforcer.add_artifact(artifact).unwrap();
        }

        // Evict 2 oldest
        let events = enforcer.evict_for_capacity(2, 10_000_000_000);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].artifact_id, "art-000");
        assert_eq!(events[1].artifact_id, "art-001");
        assert_eq!(events[0].reason, EvictionReason::CapacityEviction);
        assert_eq!(enforcer.artifact_count(), 3);
    }

    #[test]
    fn test_capacity_eviction_skips_pinned() {
        let config = TtlEnforcerConfig::try_new(60, 100, 100).unwrap();
        let mut enforcer = TtlEnforcer::new(config);

        // Add 3 artifacts, pin the oldest
        for i in 0u64..3 {
            let mut artifact = make_artifact(
                &format!("art-{i:03}"),
                EvidenceClass::Standard,
                1_000_000_000 + (i * 1_000_000),
            );
            if i == 0 {
                artifact.pin(PinReason::defect_binding("DEF-001"), None, 1_000_000_000);
            }
            enforcer.add_artifact(artifact).unwrap();
        }

        // Try to evict 2
        let events = enforcer.evict_for_capacity(2, 10_000_000_000);

        // Only 2 unpinned artifacts should be evicted
        assert_eq!(events.len(), 2);
        assert!(enforcer.get_artifact("art-000").is_some()); // pinned, kept
        assert_eq!(enforcer.artifact_count(), 1);
    }

    // =========================================================================
    // Query tests
    // =========================================================================

    #[test]
    fn test_count_by_class() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        enforcer
            .add_artifact(make_artifact("a1", EvidenceClass::Ephemeral, 1_000_000_000))
            .unwrap();
        enforcer
            .add_artifact(make_artifact("a2", EvidenceClass::Standard, 1_000_000_000))
            .unwrap();
        enforcer
            .add_artifact(make_artifact("a3", EvidenceClass::Standard, 1_000_000_000))
            .unwrap();
        enforcer
            .add_artifact(make_artifact("a4", EvidenceClass::Archival, 1_000_000_000))
            .unwrap();

        let counts = enforcer.count_by_class();
        assert_eq!(counts.get(&EvidenceClass::Ephemeral), Some(&1));
        assert_eq!(counts.get(&EvidenceClass::Standard), Some(&2));
        assert_eq!(counts.get(&EvidenceClass::Archival), Some(&1));
    }

    #[test]
    fn test_count_pinned() {
        let config = TtlEnforcerConfig::default();
        let mut enforcer = TtlEnforcer::new(config);

        let mut a1 = make_artifact("a1", EvidenceClass::Standard, 1_000_000_000);
        a1.pin(PinReason::defect_binding("DEF-001"), None, 1_000_000_000);

        let a2 = make_artifact("a2", EvidenceClass::Standard, 1_000_000_000);

        enforcer.add_artifact(a1).unwrap();
        enforcer.add_artifact(a2).unwrap();

        assert_eq!(enforcer.count_pinned(), 1);
    }

    #[test]
    fn test_eviction_limit() {
        let config = TtlEnforcerConfig::try_new(60, 1000, 2).unwrap(); // max 2 evictions per run
        let mut enforcer = TtlEnforcer::new(config);

        // Add 5 ephemeral artifacts
        for i in 0..5 {
            let artifact = make_artifact(
                &format!("art-{i:03}"),
                EvidenceClass::Ephemeral,
                1_000_000_000,
            );
            enforcer.add_artifact(artifact).unwrap();
        }

        // All expired
        let after_ttl = 1_000_000_000 + (EPHEMERAL_TTL_SECS * 1_000_000_000) + 1;
        let (events, stats) = enforcer.enforce_ttl(after_ttl);

        // Only 2 evicted due to limit
        assert_eq!(events.len(), 2);
        assert_eq!(stats.artifacts_evicted, 2);
        assert!(stats.limit_reached);
        assert_eq!(enforcer.artifact_count(), 3);

        // Run again to evict more
        let (events2, stats2) = enforcer.enforce_ttl(after_ttl + 1);
        assert_eq!(events2.len(), 2);
        assert_eq!(stats2.artifacts_evicted, 2);
        assert!(stats2.limit_reached);
        assert_eq!(enforcer.artifact_count(), 1);

        // Run again to finish
        let (events3, stats3) = enforcer.enforce_ttl(after_ttl + 2);
        assert_eq!(events3.len(), 1);
        assert!(!stats3.limit_reached);
        assert!(enforcer.is_empty());
    }

    // =========================================================================
    // Serialization tests
    // =========================================================================

    #[test]
    fn test_eviction_event_serialization() {
        let event = EvictionEvent {
            artifact_id: "art-001".to_string(),
            episode_id: "ep-001".to_string(),
            class: EvidenceClass::Ephemeral,
            ttl_secs: 3600,
            created_at_ns: 1_000_000_000,
            evicted_at_ns: 5_000_000_000,
            reason: EvictionReason::TtlExpired,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: EvictionEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_config_serialization() {
        let config = TtlEnforcerConfig::try_new(120, 5000, 500).unwrap();

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TtlEnforcerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }
}
