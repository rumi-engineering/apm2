// AGENT-AUTHORED
//! `FreshnessPolicyV1`: HTF authority integration for risk-tier-specific
//! staleness enforcement (TCK-00364).
//!
//! This module implements freshness evaluation that uses only
//! ledger-anchor lag and local HTF ticks as the authority source.
//! Wall-clock deltas are explicitly forbidden in authorization decisions.
//!
//! # Design
//!
//! [`FreshnessPolicyV1`] maps each risk tier (Tier0..Tier4) to a maximum
//! head age in ticks and a staleness action ([`StalenessAction`]). The
//! [`FreshnessPolicyEvaluator`] computes the lag between the current HTF
//! tick and the head epoch tick, then applies the configured action.
//!
//! # Security Model
//!
//! - **Fail-closed**: Tier2+ stale heads deny authoritative actions.
//! - **No wall-clock**: Freshness uses only ledger-anchor lag or local HTF
//!   tick. Remote wall-clock deltas are never consulted.
//! - **Deterministic**: Given the same inputs, the evaluator always produces
//!   the same [`StalenessVerdict`] and [`FreshnessAuditEvent`].
//!
//! # Authority Model
//!
//! The freshness authority is the difference between the current HTF tick
//! and the head epoch tick. This is a node-local computation that does not
//! depend on any remote clock.
//!
//! ```text
//! head_age = current_tick - head_epoch_tick
//! ```
//!
//! If `head_age > max_head_age_ticks` for the tier, the configured
//! [`StalenessAction`] is applied.

use serde::{Deserialize, Serialize};

use crate::fac::RiskTier;

// =============================================================================
// Constants
// =============================================================================

/// Number of risk tiers supported (Tier0..Tier4).
const NUM_TIERS: usize = 5;

/// Default maximum head age in ticks for Tier0 (discovery-only). 0 = no limit.
pub const DEFAULT_TIER0_MAX_HEAD_AGE_TICKS: u64 = 0;

/// Default maximum head age in ticks for Tier1 (local development).
pub const DEFAULT_TIER1_MAX_HEAD_AGE_TICKS: u64 = 1_000_000;

/// Default maximum head age in ticks for Tier2 (production-adjacent).
pub const DEFAULT_TIER2_MAX_HEAD_AGE_TICKS: u64 = 100_000;

/// Default maximum head age in ticks for Tier3 (production with external
/// effects).
pub const DEFAULT_TIER3_MAX_HEAD_AGE_TICKS: u64 = 10_000;

/// Default maximum head age in ticks for Tier4 (critical operations).
pub const DEFAULT_TIER4_MAX_HEAD_AGE_TICKS: u64 = 1_000;

/// Maximum number of audit events retained per evaluator call
/// (denial-of-service bound).
pub const MAX_AUDIT_EVENTS: usize = 16;

/// Domain separator for freshness audit event hashing.
const FRESHNESS_AUDIT_DOMAIN: &[u8] = b"apm2:freshness_policy_v1:audit:v1\0";

// =============================================================================
// StalenessAction
// =============================================================================

/// Action to take when a head is stale for a given risk tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum StalenessAction {
    /// Allow the action to proceed despite staleness.
    Allow = 0,
    /// Warn about staleness but allow the action to proceed.
    Warn  = 1,
    /// Deny the action due to staleness.
    Deny  = 2,
}

impl std::fmt::Display for StalenessAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Warn => write!(f, "warn"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

// =============================================================================
// TierFreshnessConfig
// =============================================================================

/// Per-tier freshness configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierFreshnessConfig {
    /// Maximum head age in ticks before the action fires.
    /// A value of `0` means no staleness enforcement for this tier.
    pub max_head_age_ticks: u64,

    /// Action to take when the head exceeds `max_head_age_ticks`.
    pub staleness_action: StalenessAction,
}

// =============================================================================
// FreshnessPolicyV1
// =============================================================================

/// Risk-tier-specific freshness policy for HTF authority integration.
///
/// Each tier maps to a [`TierFreshnessConfig`] specifying the maximum
/// allowed head age (in ticks) and the action to take when stale.
///
/// # Invariants
///
/// - Tier2+ MUST use [`StalenessAction::Deny`] in the default policy.
/// - Thresholds decrease as tier increases (higher tiers are stricter).
/// - A threshold of `0` disables staleness enforcement for that tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessPolicyV1 {
    /// Per-tier configuration, indexed by tier ordinal (0 = Tier0, ..., 4 =
    /// Tier4).
    tiers: [TierFreshnessConfig; NUM_TIERS],
}

impl Default for FreshnessPolicyV1 {
    fn default() -> Self {
        Self {
            tiers: [
                // Tier0: discovery-only, no enforcement
                TierFreshnessConfig {
                    max_head_age_ticks: DEFAULT_TIER0_MAX_HEAD_AGE_TICKS,
                    staleness_action: StalenessAction::Allow,
                },
                // Tier1: local development, warn on stale
                TierFreshnessConfig {
                    max_head_age_ticks: DEFAULT_TIER1_MAX_HEAD_AGE_TICKS,
                    staleness_action: StalenessAction::Warn,
                },
                // Tier2: production-adjacent, deny on stale
                TierFreshnessConfig {
                    max_head_age_ticks: DEFAULT_TIER2_MAX_HEAD_AGE_TICKS,
                    staleness_action: StalenessAction::Deny,
                },
                // Tier3: production w/ external effects, deny on stale
                TierFreshnessConfig {
                    max_head_age_ticks: DEFAULT_TIER3_MAX_HEAD_AGE_TICKS,
                    staleness_action: StalenessAction::Deny,
                },
                // Tier4: critical operations, deny on stale
                TierFreshnessConfig {
                    max_head_age_ticks: DEFAULT_TIER4_MAX_HEAD_AGE_TICKS,
                    staleness_action: StalenessAction::Deny,
                },
            ],
        }
    }
}

impl FreshnessPolicyV1 {
    /// Creates a new freshness policy with explicit per-tier configurations.
    #[must_use]
    pub const fn new(tiers: [TierFreshnessConfig; NUM_TIERS]) -> Self {
        Self { tiers }
    }

    /// Returns the configuration for the given risk tier.
    #[must_use]
    pub const fn tier_config(&self, tier: RiskTier) -> &TierFreshnessConfig {
        &self.tiers[tier as usize]
    }

    /// Returns the maximum head age in ticks for the given risk tier.
    #[must_use]
    pub const fn max_head_age_ticks(&self, tier: RiskTier) -> u64 {
        self.tiers[tier as usize].max_head_age_ticks
    }

    /// Returns the staleness action for the given risk tier.
    #[must_use]
    pub const fn staleness_action(&self, tier: RiskTier) -> StalenessAction {
        self.tiers[tier as usize].staleness_action
    }

    /// Returns true if the given risk tier is considered authoritative
    /// (Tier2+), meaning staleness enforcement is mandatory.
    #[must_use]
    pub const fn is_authoritative_tier(tier: RiskTier) -> bool {
        (tier as u8) >= 2
    }
}

// =============================================================================
// StalenessVerdict
// =============================================================================

/// Outcome of freshness evaluation for a single head against a risk tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalenessVerdict {
    /// The action applied.
    pub action: StalenessAction,

    /// Risk tier evaluated.
    pub risk_tier: RiskTier,

    /// Computed head age in ticks (`None` on tick reversal or missing head).
    pub head_age_ticks: Option<u64>,

    /// Configured maximum head age for this tier.
    pub max_head_age_ticks: u64,

    /// Whether the head was stale (age exceeded threshold).
    pub is_stale: bool,

    /// Audit event for deterministic logging.
    pub audit_event: FreshnessAuditEvent,
}

// =============================================================================
// FreshnessAuditEvent
// =============================================================================

/// Deterministic audit event emitted for every freshness evaluation.
///
/// These events form a CAS-addressable audit trail. Given the same
/// inputs, the same event (and hash) is produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FreshnessAuditEvent {
    /// Head is fresh; action is allowed.
    Fresh {
        /// Risk tier evaluated.
        risk_tier: RiskTier,
        /// Computed head age in ticks.
        head_age_ticks: u64,
        /// Configured threshold for the tier.
        max_head_age_ticks: u64,
    },

    /// Head is stale; action is allowed (Tier0/Tier1 under permissive policy).
    StaleAllowed {
        /// Risk tier evaluated.
        risk_tier: RiskTier,
        /// Computed head age in ticks.
        head_age_ticks: u64,
        /// Configured threshold for the tier.
        max_head_age_ticks: u64,
    },

    /// Head is stale; warning emitted but action proceeds.
    StaleWarned {
        /// Risk tier evaluated.
        risk_tier: RiskTier,
        /// Computed head age in ticks.
        head_age_ticks: u64,
        /// Configured threshold for the tier.
        max_head_age_ticks: u64,
    },

    /// Head is stale; action denied.
    StaleDenied {
        /// Risk tier evaluated.
        risk_tier: RiskTier,
        /// Computed head age in ticks.
        head_age_ticks: u64,
        /// Configured threshold for the tier.
        max_head_age_ticks: u64,
    },

    /// Tick reversal detected: current tick predates head epoch tick.
    TickReversal {
        /// Risk tier evaluated.
        risk_tier: RiskTier,
        /// Current tick at evaluation time.
        current_tick: u64,
        /// Head epoch tick.
        head_epoch_tick: u64,
    },

    /// Staleness enforcement is disabled for this tier (threshold == 0).
    EnforcementDisabled {
        /// Risk tier evaluated.
        risk_tier: RiskTier,
    },
}

impl FreshnessAuditEvent {
    /// Returns a static event kind label for structured logging.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Fresh { .. } => "freshness.fresh",
            Self::StaleAllowed { .. } => "freshness.stale_allowed",
            Self::StaleWarned { .. } => "freshness.stale_warned",
            Self::StaleDenied { .. } => "freshness.stale_denied",
            Self::TickReversal { .. } => "freshness.tick_reversal",
            Self::EnforcementDisabled { .. } => "freshness.enforcement_disabled",
        }
    }

    /// Returns the risk tier associated with this event.
    #[must_use]
    pub const fn risk_tier(&self) -> RiskTier {
        match self {
            Self::Fresh { risk_tier, .. }
            | Self::StaleAllowed { risk_tier, .. }
            | Self::StaleWarned { risk_tier, .. }
            | Self::StaleDenied { risk_tier, .. }
            | Self::TickReversal { risk_tier, .. }
            | Self::EnforcementDisabled { risk_tier, .. } => *risk_tier,
        }
    }

    /// Computes a deterministic BLAKE3 hash of this audit event for
    /// CAS-addressable storage.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(FRESHNESS_AUDIT_DOMAIN);
        hasher.update(self.kind().as_bytes());
        hasher.update(&[self.risk_tier() as u8]);
        match self {
            Self::Fresh {
                head_age_ticks,
                max_head_age_ticks,
                ..
            }
            | Self::StaleAllowed {
                head_age_ticks,
                max_head_age_ticks,
                ..
            }
            | Self::StaleWarned {
                head_age_ticks,
                max_head_age_ticks,
                ..
            }
            | Self::StaleDenied {
                head_age_ticks,
                max_head_age_ticks,
                ..
            } => {
                hasher.update(&head_age_ticks.to_le_bytes());
                hasher.update(&max_head_age_ticks.to_le_bytes());
            },
            Self::TickReversal {
                current_tick,
                head_epoch_tick,
                ..
            } => {
                hasher.update(&current_tick.to_le_bytes());
                hasher.update(&head_epoch_tick.to_le_bytes());
            },
            Self::EnforcementDisabled { .. } => {
                // No additional data beyond kind + tier.
            },
        }
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// FreshnessEvaluationError
// =============================================================================

/// Errors during freshness policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FreshnessEvaluationError {
    /// Current tick predates head epoch tick (time reversal).
    #[error(
        "tick reversal: current_tick {current_tick} < head_epoch_tick {head_epoch_tick} for {risk_tier:?}"
    )]
    TickReversal {
        /// Current tick at evaluation time.
        current_tick: u64,
        /// Head epoch tick.
        head_epoch_tick: u64,
        /// Risk tier being evaluated.
        risk_tier: RiskTier,
    },

    /// Head is stale and the policy action is Deny.
    #[error(
        "stale head denied: age_ticks {head_age_ticks} > max_head_age_ticks {max_head_age_ticks} for {risk_tier:?}"
    )]
    StaleDenied {
        /// Computed head age in ticks.
        head_age_ticks: u64,
        /// Configured threshold.
        max_head_age_ticks: u64,
        /// Risk tier that triggered the denial.
        risk_tier: RiskTier,
    },
}

// =============================================================================
// FreshnessPolicyEvaluator
// =============================================================================

/// Evaluates head freshness against a [`FreshnessPolicyV1`].
///
/// The evaluator is deterministic and side-effect-free. It computes the
/// head age as `current_tick - head_epoch_tick` using only HTF-compatible
/// tick authority. Wall-clock time is never consulted.
#[derive(Debug, Clone)]
pub struct FreshnessPolicyEvaluator {
    policy: FreshnessPolicyV1,
}

impl FreshnessPolicyEvaluator {
    /// Creates a new evaluator with the given policy.
    #[must_use]
    pub const fn new(policy: FreshnessPolicyV1) -> Self {
        Self { policy }
    }

    /// Returns a reference to the configured policy.
    #[must_use]
    pub const fn policy(&self) -> &FreshnessPolicyV1 {
        &self.policy
    }

    /// Evaluates freshness for a head at the given risk tier.
    ///
    /// # Arguments
    ///
    /// * `risk_tier` - The risk tier of the operation being authorized.
    /// * `current_tick` - The current authoritative HTF tick (ledger-anchor lag
    ///   or local tick).
    /// * `head_epoch_tick` - The tick at which the head was last updated.
    ///
    /// # Returns
    ///
    /// A [`StalenessVerdict`] describing the outcome and audit event.
    /// This is always returned regardless of whether the head is fresh
    /// or stale, to ensure every evaluation is auditable.
    #[must_use]
    pub const fn evaluate(
        &self,
        risk_tier: RiskTier,
        current_tick: u64,
        head_epoch_tick: u64,
    ) -> StalenessVerdict {
        let config = self.policy.tier_config(risk_tier);
        let max_age = config.max_head_age_ticks;

        // Case 1: Enforcement disabled for this tier (threshold == 0).
        if max_age == 0 {
            return StalenessVerdict {
                action: StalenessAction::Allow,
                risk_tier,
                head_age_ticks: current_tick.checked_sub(head_epoch_tick),
                max_head_age_ticks: 0,
                is_stale: false,
                audit_event: FreshnessAuditEvent::EnforcementDisabled { risk_tier },
            };
        }

        // Case 2: Tick reversal.
        if current_tick < head_epoch_tick {
            // Fail-closed: tick reversal always denies.
            return StalenessVerdict {
                action: StalenessAction::Deny,
                risk_tier,
                head_age_ticks: None,
                max_head_age_ticks: max_age,
                is_stale: true,
                audit_event: FreshnessAuditEvent::TickReversal {
                    risk_tier,
                    current_tick,
                    head_epoch_tick,
                },
            };
        }

        let head_age = current_tick - head_epoch_tick;

        // Case 3: Head is fresh (age <= threshold).
        if head_age <= max_age {
            return StalenessVerdict {
                action: StalenessAction::Allow,
                risk_tier,
                head_age_ticks: Some(head_age),
                max_head_age_ticks: max_age,
                is_stale: false,
                audit_event: FreshnessAuditEvent::Fresh {
                    risk_tier,
                    head_age_ticks: head_age,
                    max_head_age_ticks: max_age,
                },
            };
        }

        // Case 4: Head is stale -- apply the configured action.
        let action = config.staleness_action;
        let audit_event = match action {
            StalenessAction::Allow => FreshnessAuditEvent::StaleAllowed {
                risk_tier,
                head_age_ticks: head_age,
                max_head_age_ticks: max_age,
            },
            StalenessAction::Warn => FreshnessAuditEvent::StaleWarned {
                risk_tier,
                head_age_ticks: head_age,
                max_head_age_ticks: max_age,
            },
            StalenessAction::Deny => FreshnessAuditEvent::StaleDenied {
                risk_tier,
                head_age_ticks: head_age,
                max_head_age_ticks: max_age,
            },
        };

        StalenessVerdict {
            action,
            risk_tier,
            head_age_ticks: Some(head_age),
            max_head_age_ticks: max_age,
            is_stale: true,
            audit_event,
        }
    }

    /// Convenience method that evaluates and returns `Ok(verdict)` for
    /// Allow/Warn, or `Err(FreshnessEvaluationError)` for Deny.
    ///
    /// This is the primary entry point for authorization decisions.
    ///
    /// # Errors
    ///
    /// Returns [`FreshnessEvaluationError::TickReversal`] on tick reversal.
    /// Returns [`FreshnessEvaluationError::StaleDenied`] when the head is
    /// stale and the policy action is Deny.
    pub fn evaluate_or_deny(
        &self,
        risk_tier: RiskTier,
        current_tick: u64,
        head_epoch_tick: u64,
    ) -> Result<StalenessVerdict, FreshnessEvaluationError> {
        let verdict = self.evaluate(risk_tier, current_tick, head_epoch_tick);
        match verdict.action {
            StalenessAction::Allow | StalenessAction::Warn => Ok(verdict),
            StalenessAction::Deny => {
                if let FreshnessAuditEvent::TickReversal {
                    current_tick,
                    head_epoch_tick,
                    risk_tier,
                    ..
                } = verdict.audit_event
                {
                    Err(FreshnessEvaluationError::TickReversal {
                        current_tick,
                        head_epoch_tick,
                        risk_tier,
                    })
                } else {
                    Err(FreshnessEvaluationError::StaleDenied {
                        head_age_ticks: verdict.head_age_ticks.unwrap_or(0),
                        max_head_age_ticks: verdict.max_head_age_ticks,
                        risk_tier: verdict.risk_tier,
                    })
                }
            },
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_evaluator() -> FreshnessPolicyEvaluator {
        FreshnessPolicyEvaluator::new(FreshnessPolicyV1::default())
    }

    // =========================================================================
    // FreshnessPolicyV1 Construction Tests
    // =========================================================================

    #[test]
    fn default_policy_has_expected_thresholds() {
        let policy = FreshnessPolicyV1::default();
        assert_eq!(
            policy.max_head_age_ticks(RiskTier::Tier0),
            DEFAULT_TIER0_MAX_HEAD_AGE_TICKS
        );
        assert_eq!(
            policy.max_head_age_ticks(RiskTier::Tier1),
            DEFAULT_TIER1_MAX_HEAD_AGE_TICKS
        );
        assert_eq!(
            policy.max_head_age_ticks(RiskTier::Tier2),
            DEFAULT_TIER2_MAX_HEAD_AGE_TICKS
        );
        assert_eq!(
            policy.max_head_age_ticks(RiskTier::Tier3),
            DEFAULT_TIER3_MAX_HEAD_AGE_TICKS
        );
        assert_eq!(
            policy.max_head_age_ticks(RiskTier::Tier4),
            DEFAULT_TIER4_MAX_HEAD_AGE_TICKS
        );
    }

    #[test]
    fn default_policy_staleness_actions() {
        let policy = FreshnessPolicyV1::default();
        assert_eq!(
            policy.staleness_action(RiskTier::Tier0),
            StalenessAction::Allow
        );
        assert_eq!(
            policy.staleness_action(RiskTier::Tier1),
            StalenessAction::Warn
        );
        assert_eq!(
            policy.staleness_action(RiskTier::Tier2),
            StalenessAction::Deny
        );
        assert_eq!(
            policy.staleness_action(RiskTier::Tier3),
            StalenessAction::Deny
        );
        assert_eq!(
            policy.staleness_action(RiskTier::Tier4),
            StalenessAction::Deny
        );
    }

    #[test]
    fn is_authoritative_tier() {
        assert!(!FreshnessPolicyV1::is_authoritative_tier(RiskTier::Tier0));
        assert!(!FreshnessPolicyV1::is_authoritative_tier(RiskTier::Tier1));
        assert!(FreshnessPolicyV1::is_authoritative_tier(RiskTier::Tier2));
        assert!(FreshnessPolicyV1::is_authoritative_tier(RiskTier::Tier3));
        assert!(FreshnessPolicyV1::is_authoritative_tier(RiskTier::Tier4));
    }

    #[test]
    fn custom_policy_construction() {
        let policy = FreshnessPolicyV1::new([
            TierFreshnessConfig {
                max_head_age_ticks: 0,
                staleness_action: StalenessAction::Allow,
            },
            TierFreshnessConfig {
                max_head_age_ticks: 500,
                staleness_action: StalenessAction::Allow,
            },
            TierFreshnessConfig {
                max_head_age_ticks: 200,
                staleness_action: StalenessAction::Deny,
            },
            TierFreshnessConfig {
                max_head_age_ticks: 100,
                staleness_action: StalenessAction::Deny,
            },
            TierFreshnessConfig {
                max_head_age_ticks: 50,
                staleness_action: StalenessAction::Deny,
            },
        ]);
        assert_eq!(policy.max_head_age_ticks(RiskTier::Tier1), 500);
        assert_eq!(policy.max_head_age_ticks(RiskTier::Tier4), 50);
    }

    // =========================================================================
    // Tier0 Tests (discovery-only, no enforcement by default)
    // =========================================================================

    #[test]
    fn tier0_enforcement_disabled() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier0, 1_000_000, 0);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
        assert!(matches!(
            verdict.audit_event,
            FreshnessAuditEvent::EnforcementDisabled {
                risk_tier: RiskTier::Tier0
            }
        ));
    }

    #[test]
    fn tier0_enforcement_disabled_even_with_large_lag() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier0, u64::MAX, 0);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
    }

    // =========================================================================
    // Tier1 Tests (warn on stale by default)
    // =========================================================================

    #[test]
    fn tier1_fresh_head_allowed() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier1, 500, 100);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
        assert_eq!(verdict.head_age_ticks, Some(400));
        assert!(matches!(
            verdict.audit_event,
            FreshnessAuditEvent::Fresh { .. }
        ));
    }

    #[test]
    fn tier1_stale_head_warned() {
        let eval = default_evaluator();
        // Age = 2_000_000 > threshold 1_000_000
        let verdict = eval.evaluate(RiskTier::Tier1, 2_000_000, 0);
        assert_eq!(verdict.action, StalenessAction::Warn);
        assert!(verdict.is_stale);
        assert_eq!(verdict.head_age_ticks, Some(2_000_000));
        assert!(matches!(
            verdict.audit_event,
            FreshnessAuditEvent::StaleWarned { .. }
        ));
    }

    #[test]
    fn tier1_boundary_exactly_at_threshold_fresh() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier1, DEFAULT_TIER1_MAX_HEAD_AGE_TICKS, 0);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
    }

    #[test]
    fn tier1_boundary_one_past_threshold_warned() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier1, DEFAULT_TIER1_MAX_HEAD_AGE_TICKS + 1, 0);
        assert_eq!(verdict.action, StalenessAction::Warn);
        assert!(verdict.is_stale);
    }

    // =========================================================================
    // Tier2 Tests (deny on stale by default)
    // =========================================================================

    #[test]
    fn tier2_fresh_head_allowed() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier2, 200, 100);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
        assert_eq!(verdict.head_age_ticks, Some(100));
    }

    #[test]
    fn tier2_stale_head_denied() {
        let eval = default_evaluator();
        // Age = 200_000 > threshold 100_000
        let verdict = eval.evaluate(RiskTier::Tier2, 200_000, 0);
        assert_eq!(verdict.action, StalenessAction::Deny);
        assert!(verdict.is_stale);
        assert!(matches!(
            verdict.audit_event,
            FreshnessAuditEvent::StaleDenied {
                risk_tier: RiskTier::Tier2,
                ..
            }
        ));
    }

    #[test]
    fn tier2_boundary_exactly_at_threshold_fresh() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier2, DEFAULT_TIER2_MAX_HEAD_AGE_TICKS, 0);
        assert!(!verdict.is_stale);
        assert_eq!(verdict.action, StalenessAction::Allow);
    }

    #[test]
    fn tier2_boundary_one_past_threshold_denied() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier2, DEFAULT_TIER2_MAX_HEAD_AGE_TICKS + 1, 0);
        assert!(verdict.is_stale);
        assert_eq!(verdict.action, StalenessAction::Deny);
    }

    // =========================================================================
    // Tier3 Tests (deny on stale by default)
    // =========================================================================

    #[test]
    fn tier3_fresh_head_allowed() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier3, 200, 100);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
    }

    #[test]
    fn tier3_stale_head_denied() {
        let eval = default_evaluator();
        // Age = 20_000 > threshold 10_000
        let verdict = eval.evaluate(RiskTier::Tier3, 20_000, 0);
        assert_eq!(verdict.action, StalenessAction::Deny);
        assert!(verdict.is_stale);
    }

    #[test]
    fn tier3_boundary_exactly_at_threshold_fresh() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier3, DEFAULT_TIER3_MAX_HEAD_AGE_TICKS, 0);
        assert!(!verdict.is_stale);
    }

    #[test]
    fn tier3_boundary_one_past_threshold_denied() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier3, DEFAULT_TIER3_MAX_HEAD_AGE_TICKS + 1, 0);
        assert!(verdict.is_stale);
        assert_eq!(verdict.action, StalenessAction::Deny);
    }

    // =========================================================================
    // Tier4 Tests (deny on stale by default, strictest)
    // =========================================================================

    #[test]
    fn tier4_fresh_head_allowed() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier4, 200, 100);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
    }

    #[test]
    fn tier4_stale_head_denied() {
        let eval = default_evaluator();
        // Age = 2_000 > threshold 1_000
        let verdict = eval.evaluate(RiskTier::Tier4, 2_000, 0);
        assert_eq!(verdict.action, StalenessAction::Deny);
        assert!(verdict.is_stale);
    }

    #[test]
    fn tier4_boundary_exactly_at_threshold_fresh() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier4, DEFAULT_TIER4_MAX_HEAD_AGE_TICKS, 0);
        assert!(!verdict.is_stale);
    }

    #[test]
    fn tier4_boundary_one_past_threshold_denied() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier4, DEFAULT_TIER4_MAX_HEAD_AGE_TICKS + 1, 0);
        assert!(verdict.is_stale);
        assert_eq!(verdict.action, StalenessAction::Deny);
    }

    // =========================================================================
    // Tick Reversal Tests
    // =========================================================================

    #[test]
    fn tick_reversal_denied_all_tiers() {
        let eval = default_evaluator();
        for tier in [
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ] {
            let verdict = eval.evaluate(tier, 100, 500);
            assert_eq!(
                verdict.action,
                StalenessAction::Deny,
                "tick reversal should deny for {tier:?}"
            );
            assert!(verdict.is_stale);
            assert_eq!(verdict.head_age_ticks, None);
            assert!(
                matches!(
                    verdict.audit_event,
                    FreshnessAuditEvent::TickReversal { .. }
                ),
                "should emit tick reversal for {tier:?}"
            );
        }
    }

    #[test]
    fn tick_reversal_tier0_enforcement_disabled_skips_reversal() {
        // Tier0 has threshold == 0, so enforcement is disabled entirely.
        // Even a tick reversal is not flagged for Tier0 because enforcement
        // is bypassed.
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier0, 100, 500);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(!verdict.is_stale);
    }

    // =========================================================================
    // evaluate_or_deny Tests
    // =========================================================================

    #[test]
    fn evaluate_or_deny_fresh_ok() {
        let eval = default_evaluator();
        let result = eval.evaluate_or_deny(RiskTier::Tier2, 200, 100);
        assert!(result.is_ok());
        let verdict = result.unwrap();
        assert_eq!(verdict.action, StalenessAction::Allow);
    }

    #[test]
    fn evaluate_or_deny_stale_tier2_err() {
        let eval = default_evaluator();
        let result = eval.evaluate_or_deny(RiskTier::Tier2, 200_000, 0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FreshnessEvaluationError::StaleDenied {
                risk_tier: RiskTier::Tier2,
                ..
            }
        ));
    }

    #[test]
    fn evaluate_or_deny_stale_tier1_warn_ok() {
        let eval = default_evaluator();
        let result = eval.evaluate_or_deny(RiskTier::Tier1, 2_000_000, 0);
        assert!(result.is_ok());
        let verdict = result.unwrap();
        assert_eq!(verdict.action, StalenessAction::Warn);
    }

    #[test]
    fn evaluate_or_deny_tick_reversal_err() {
        let eval = default_evaluator();
        let result = eval.evaluate_or_deny(RiskTier::Tier3, 100, 500);
        assert!(matches!(
            result.unwrap_err(),
            FreshnessEvaluationError::TickReversal { .. }
        ));
    }

    // =========================================================================
    // Determinism Tests
    // =========================================================================

    #[test]
    fn verdict_is_deterministic() {
        let eval = default_evaluator();
        let v1 = eval.evaluate(RiskTier::Tier2, 50_000, 0);
        let v2 = eval.evaluate(RiskTier::Tier2, 50_000, 0);
        assert_eq!(v1, v2);
    }

    #[test]
    fn audit_event_hash_is_deterministic() {
        let eval = default_evaluator();
        let v1 = eval.evaluate(RiskTier::Tier3, 20_000, 0);
        let v2 = eval.evaluate(RiskTier::Tier3, 20_000, 0);
        assert_eq!(
            v1.audit_event.canonical_hash(),
            v2.audit_event.canonical_hash()
        );
    }

    #[test]
    fn audit_event_hash_differs_on_different_inputs() {
        let eval = default_evaluator();
        let v1 = eval.evaluate(RiskTier::Tier2, 200_000, 0);
        let v2 = eval.evaluate(RiskTier::Tier3, 200_000, 0);
        assert_ne!(
            v1.audit_event.canonical_hash(),
            v2.audit_event.canonical_hash()
        );
    }

    #[test]
    fn audit_event_hash_differs_on_stale_vs_fresh() {
        let eval = default_evaluator();
        let fresh = eval.evaluate(RiskTier::Tier2, 50_000, 0);
        let stale = eval.evaluate(RiskTier::Tier2, 200_000, 0);
        assert_ne!(
            fresh.audit_event.canonical_hash(),
            stale.audit_event.canonical_hash()
        );
    }

    // =========================================================================
    // Audit Event Kind Labels
    // =========================================================================

    #[test]
    fn audit_event_kind_labels() {
        assert_eq!(
            FreshnessAuditEvent::Fresh {
                risk_tier: RiskTier::Tier2,
                head_age_ticks: 100,
                max_head_age_ticks: 100_000,
            }
            .kind(),
            "freshness.fresh"
        );
        assert_eq!(
            FreshnessAuditEvent::StaleAllowed {
                risk_tier: RiskTier::Tier0,
                head_age_ticks: 100,
                max_head_age_ticks: 50,
            }
            .kind(),
            "freshness.stale_allowed"
        );
        assert_eq!(
            FreshnessAuditEvent::StaleWarned {
                risk_tier: RiskTier::Tier1,
                head_age_ticks: 100,
                max_head_age_ticks: 50,
            }
            .kind(),
            "freshness.stale_warned"
        );
        assert_eq!(
            FreshnessAuditEvent::StaleDenied {
                risk_tier: RiskTier::Tier2,
                head_age_ticks: 100,
                max_head_age_ticks: 50,
            }
            .kind(),
            "freshness.stale_denied"
        );
        assert_eq!(
            FreshnessAuditEvent::TickReversal {
                risk_tier: RiskTier::Tier3,
                current_tick: 10,
                head_epoch_tick: 20,
            }
            .kind(),
            "freshness.tick_reversal"
        );
        assert_eq!(
            FreshnessAuditEvent::EnforcementDisabled {
                risk_tier: RiskTier::Tier0,
            }
            .kind(),
            "freshness.enforcement_disabled"
        );
    }

    // =========================================================================
    // Audit Event risk_tier Accessor
    // =========================================================================

    #[test]
    fn audit_event_risk_tier_accessor() {
        let event = FreshnessAuditEvent::StaleDenied {
            risk_tier: RiskTier::Tier4,
            head_age_ticks: 5000,
            max_head_age_ticks: 1000,
        };
        assert_eq!(event.risk_tier(), RiskTier::Tier4);
    }

    // =========================================================================
    // StalenessAction Display
    // =========================================================================

    #[test]
    fn staleness_action_display() {
        assert_eq!(StalenessAction::Allow.to_string(), "allow");
        assert_eq!(StalenessAction::Warn.to_string(), "warn");
        assert_eq!(StalenessAction::Deny.to_string(), "deny");
    }

    // =========================================================================
    // Serde Roundtrip Tests
    // =========================================================================

    #[test]
    fn staleness_action_serde_roundtrip() {
        for action in [
            StalenessAction::Allow,
            StalenessAction::Warn,
            StalenessAction::Deny,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let deserialized: StalenessAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, deserialized);
        }
    }

    #[test]
    fn freshness_policy_v1_serde_roundtrip() {
        let policy = FreshnessPolicyV1::default();
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: FreshnessPolicyV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    // =========================================================================
    // Wall-Clock Prohibition Test
    // =========================================================================

    #[test]
    fn evaluator_uses_only_tick_authority() {
        // This test documents the invariant that the evaluator accepts only
        // tick values and never wall-clock times. The API signature enforces
        // this at compile time (current_tick: u64, head_epoch_tick: u64),
        // but we assert the behavior explicitly.
        let eval = default_evaluator();
        // These are tick values, NOT timestamps.
        let verdict = eval.evaluate(RiskTier::Tier2, 50_000, 0);
        assert_eq!(verdict.head_age_ticks, Some(50_000));
        assert!(!verdict.is_stale);
    }

    // =========================================================================
    // Custom Policy with Allow-on-Stale for Tier2 (non-default)
    // =========================================================================

    #[test]
    fn custom_policy_allow_on_stale_tier2() {
        let policy = FreshnessPolicyV1::new([
            TierFreshnessConfig {
                max_head_age_ticks: 0,
                staleness_action: StalenessAction::Allow,
            },
            TierFreshnessConfig {
                max_head_age_ticks: 1_000_000,
                staleness_action: StalenessAction::Warn,
            },
            TierFreshnessConfig {
                max_head_age_ticks: 100_000,
                staleness_action: StalenessAction::Allow, // non-default
            },
            TierFreshnessConfig {
                max_head_age_ticks: 10_000,
                staleness_action: StalenessAction::Deny,
            },
            TierFreshnessConfig {
                max_head_age_ticks: 1_000,
                staleness_action: StalenessAction::Deny,
            },
        ]);

        let eval = FreshnessPolicyEvaluator::new(policy);
        let verdict = eval.evaluate(RiskTier::Tier2, 200_000, 0);
        assert!(verdict.is_stale);
        assert_eq!(verdict.action, StalenessAction::Allow);
        assert!(matches!(
            verdict.audit_event,
            FreshnessAuditEvent::StaleAllowed { .. }
        ));
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn evaluation_error_display() {
        let err = FreshnessEvaluationError::TickReversal {
            current_tick: 100,
            head_epoch_tick: 500,
            risk_tier: RiskTier::Tier3,
        };
        let msg = err.to_string();
        assert!(msg.contains("tick reversal"));
        assert!(msg.contains("100"));
        assert!(msg.contains("500"));

        let err = FreshnessEvaluationError::StaleDenied {
            head_age_ticks: 200_000,
            max_head_age_ticks: 100_000,
            risk_tier: RiskTier::Tier2,
        };
        let msg = err.to_string();
        assert!(msg.contains("stale head denied"));
        assert!(msg.contains("200000"));
        assert!(msg.contains("100000"));
    }

    // =========================================================================
    // Head Age == 0 (same tick) Tests
    // =========================================================================

    #[test]
    fn zero_age_is_fresh() {
        let eval = default_evaluator();
        let verdict = eval.evaluate(RiskTier::Tier4, 1000, 1000);
        assert!(!verdict.is_stale);
        assert_eq!(verdict.head_age_ticks, Some(0));
        assert_eq!(verdict.action, StalenessAction::Allow);
    }
}
