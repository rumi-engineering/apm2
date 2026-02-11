//! Business continuity types and enforcers for RFC-0020 Section 11.
//!
//! This module provides:
//! - [`DrillReceiptV1`] for chaos/partition drill evidence binding.
//! - [`StopPathSloEnforcer`] for stop-path SLO tracking and fail-safe gating.
//! - [`RpoRtoEnforcer`] for RPO/RTO objective tracking and violation reporting.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize, de};
use thiserror::Error;

use crate::crypto::Hash;

/// Schema identifier for [`DrillReceiptV1`].
pub const DRILL_RECEIPT_V1_SCHEMA: &str = "apm2.drill_receipt.v1";

/// Maximum length for drill scenario identifiers.
pub const MAX_DRILL_SCENARIO_ID_LEN: usize = 128;
/// Maximum length for drill scenario versions.
pub const MAX_DRILL_SCENARIO_VERSION_LEN: usize = 64;
/// Maximum number of observed failure modes in a drill receipt.
pub const MAX_DRILL_FAILURE_MODES: usize = 64;
/// Maximum length for a single failure mode string.
pub const MAX_DRILL_FAILURE_MODE_LEN: usize = 256;
/// Maximum number of evidence references in a drill receipt.
pub const MAX_DRILL_EVIDENCE_REFS: usize = 256;

/// Maximum stop-order identifier length.
pub const MAX_STOP_ORDER_ID_LEN: usize = 128;
/// Maximum tracked pending stop orders.
pub const MAX_PENDING_STOP_ORDERS: usize = 10_000;
/// Maximum retained stop propagation samples.
pub const MAX_STOP_PROPAGATION_SAMPLES: usize = 20_000;
/// Maximum retained stop-path SLO defects.
pub const MAX_STOP_PATH_DEFECTS: usize = 4_096;

/// Maximum retained RPO/RTO defects.
pub const MAX_RPO_RTO_DEFECTS: usize = 4_096;

/// Baseline stop propagation SLO threshold (p99).
pub const STOP_PROPAGATION_P99_TARGET_MS: u64 = 2_000;
/// Baseline stop uncertainty deny deadline for Tier3+ episodes.
pub const STOP_UNCERTAINTY_DENY_TARGET_MS: u64 = 250;

/// Baseline ledger RPO target.
pub const LEDGER_RPO_TARGET_MS: u64 = 5 * 60 * 1_000;
/// Baseline ledger RTO target.
pub const LEDGER_RTO_TARGET_MS: u64 = 30 * 60 * 1_000;
/// Baseline CAS RPO target.
pub const CAS_RPO_TARGET_MS: u64 = 15 * 60 * 1_000;
/// Baseline CAS RTO target.
pub const CAS_RTO_TARGET_MS: u64 = 60 * 60 * 1_000;

/// Errors produced by continuity enforcement and receipt validation.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContinuityError {
    /// A required field is empty.
    #[error("field '{field}' must be non-empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// A string field exceeded its configured bound.
    #[error("field '{field}' exceeds max length: {actual} > {max}")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A bounded collection exceeded its cap.
    #[error("field '{field}' contains too many entries: {actual} > {max}")]
    TooManyEntries {
        /// Field name.
        field: &'static str,
        /// Actual count.
        actual: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Tier3+ drill receipts cannot report stop-order failures.
    #[error("tier3+ drill receipts require stop_order_failure_count == 0, got {count}")]
    Tier3StopOrderFailures {
        /// Reported stop-order failure count.
        count: u64,
    },
    /// A stop termination was reported for an unknown order.
    #[error("unknown stop order id '{order_id}'")]
    UnknownStopOrder {
        /// Unknown stop-order identifier.
        order_id: String,
    },
    /// Invalid SLO configuration.
    #[error("invalid SLO config: {reason}")]
    InvalidSloConfig {
        /// Validation reason.
        reason: String,
    },
    /// Invalid RPO/RTO configuration.
    #[error("invalid RPO/RTO config: {reason}")]
    InvalidRpoRtoConfig {
        /// Validation reason.
        reason: String,
    },
}

/// Drill receipt for chaos/partition exercises.
///
/// This receipt binds scenario identity, observed failure modes, recovery
/// timing, stop-order failure counts, and evidence references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DrillReceiptV1 {
    /// Drill scenario identifier.
    pub scenario_id: String,
    /// Drill scenario version.
    pub scenario_version: String,
    /// Observed failure mode identifiers.
    pub observed_failure_modes: Vec<String>,
    /// End-to-end recovery time in milliseconds.
    pub recovery_time_ms: u64,
    /// Number of stop-order failures observed in this drill.
    pub stop_order_failure_count: u64,
    /// CAS evidence references supporting this drill.
    pub evidence_references: Vec<Hash>,
}

impl<'de> Deserialize<'de> for DrillReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawDrillReceiptV1 {
            scenario_id: String,
            scenario_version: String,
            observed_failure_modes: Vec<String>,
            recovery_time_ms: u64,
            stop_order_failure_count: u64,
            evidence_references: Vec<Hash>,
        }

        let raw = RawDrillReceiptV1::deserialize(deserializer)?;
        let receipt = Self {
            scenario_id: raw.scenario_id,
            scenario_version: raw.scenario_version,
            observed_failure_modes: raw.observed_failure_modes,
            recovery_time_ms: raw.recovery_time_ms,
            stop_order_failure_count: raw.stop_order_failure_count,
            evidence_references: raw.evidence_references,
        };
        receipt.validate().map_err(de::Error::custom)?;
        Ok(receipt)
    }
}

impl DrillReceiptV1 {
    /// Returns the schema identifier for this receipt type.
    #[must_use]
    pub const fn schema() -> &'static str {
        DRILL_RECEIPT_V1_SCHEMA
    }

    /// Validates bounded-resource and structural constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError`] when any field violates a hard bound.
    pub fn validate(&self) -> Result<(), ContinuityError> {
        if self.scenario_id.is_empty() {
            return Err(ContinuityError::EmptyField {
                field: "scenario_id",
            });
        }
        if self.scenario_id.len() > MAX_DRILL_SCENARIO_ID_LEN {
            return Err(ContinuityError::FieldTooLong {
                field: "scenario_id",
                actual: self.scenario_id.len(),
                max: MAX_DRILL_SCENARIO_ID_LEN,
            });
        }

        if self.scenario_version.is_empty() {
            return Err(ContinuityError::EmptyField {
                field: "scenario_version",
            });
        }
        if self.scenario_version.len() > MAX_DRILL_SCENARIO_VERSION_LEN {
            return Err(ContinuityError::FieldTooLong {
                field: "scenario_version",
                actual: self.scenario_version.len(),
                max: MAX_DRILL_SCENARIO_VERSION_LEN,
            });
        }

        if self.observed_failure_modes.len() > MAX_DRILL_FAILURE_MODES {
            return Err(ContinuityError::TooManyEntries {
                field: "observed_failure_modes",
                actual: self.observed_failure_modes.len(),
                max: MAX_DRILL_FAILURE_MODES,
            });
        }
        for mode in &self.observed_failure_modes {
            if mode.is_empty() {
                return Err(ContinuityError::EmptyField {
                    field: "observed_failure_modes[]",
                });
            }
            if mode.len() > MAX_DRILL_FAILURE_MODE_LEN {
                return Err(ContinuityError::FieldTooLong {
                    field: "observed_failure_modes[]",
                    actual: mode.len(),
                    max: MAX_DRILL_FAILURE_MODE_LEN,
                });
            }
        }

        if self.evidence_references.len() > MAX_DRILL_EVIDENCE_REFS {
            return Err(ContinuityError::TooManyEntries {
                field: "evidence_references",
                actual: self.evidence_references.len(),
                max: MAX_DRILL_EVIDENCE_REFS,
            });
        }

        Ok(())
    }

    /// Validates Tier3+ posture requirements.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError::Tier3StopOrderFailures`] when
    /// `stop_order_failure_count` is non-zero.
    pub fn validate_for_tier3_plus(&self) -> Result<(), ContinuityError> {
        self.validate()?;
        if self.stop_order_failure_count != 0 {
            return Err(ContinuityError::Tier3StopOrderFailures {
                count: self.stop_order_failure_count,
            });
        }
        Ok(())
    }
}

/// SLO configuration for stop-path enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopPathSloConfig {
    /// Target p99 stop propagation latency in milliseconds.
    pub stop_propagation_p99_ms: u64,
    /// Target stop uncertainty deny latency in milliseconds (Tier3+).
    pub stop_uncertainty_deny_ms: u64,
    /// Maximum pending stop orders retained in memory.
    pub max_pending_orders: usize,
    /// Maximum propagation samples retained in memory.
    pub max_samples: usize,
    /// Maximum stored defects retained in memory.
    pub max_defects: usize,
}

impl Default for StopPathSloConfig {
    fn default() -> Self {
        Self {
            stop_propagation_p99_ms: STOP_PROPAGATION_P99_TARGET_MS,
            stop_uncertainty_deny_ms: STOP_UNCERTAINTY_DENY_TARGET_MS,
            max_pending_orders: MAX_PENDING_STOP_ORDERS,
            max_samples: MAX_STOP_PROPAGATION_SAMPLES,
            max_defects: MAX_STOP_PATH_DEFECTS,
        }
    }
}

impl StopPathSloConfig {
    /// Validates configuration bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError::InvalidSloConfig`] when a bound is invalid.
    pub fn validate(&self) -> Result<(), ContinuityError> {
        if self.stop_propagation_p99_ms == 0 {
            return Err(ContinuityError::InvalidSloConfig {
                reason: "stop_propagation_p99_ms must be > 0".to_string(),
            });
        }
        if self.stop_uncertainty_deny_ms == 0 {
            return Err(ContinuityError::InvalidSloConfig {
                reason: "stop_uncertainty_deny_ms must be > 0".to_string(),
            });
        }
        if self.max_pending_orders == 0 {
            return Err(ContinuityError::InvalidSloConfig {
                reason: "max_pending_orders must be > 0".to_string(),
            });
        }
        if self.max_samples == 0 {
            return Err(ContinuityError::InvalidSloConfig {
                reason: "max_samples must be > 0".to_string(),
            });
        }
        if self.max_defects == 0 {
            return Err(ContinuityError::InvalidSloConfig {
                reason: "max_defects must be > 0".to_string(),
            });
        }
        Ok(())
    }
}

/// Stop-path SLO defect classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopPathSloDefectKind {
    /// p99 stop propagation exceeded target.
    StopPropagationP99Exceeded,
    /// Stop uncertainty deny latency exceeded target.
    StopUncertaintyDenyExceeded,
    /// Capsule termination was reported for an unknown stop order.
    UnknownStopOrder,
}

/// Structured stop-path SLO defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopPathSloDefect {
    /// Defect kind.
    pub kind: StopPathSloDefectKind,
    /// Optional stop order identifier.
    pub order_id: Option<String>,
    /// Observed latency in milliseconds.
    pub observed_ms: u64,
    /// Target threshold in milliseconds.
    pub threshold_ms: u64,
    /// Human-readable detail.
    pub detail: String,
}

/// Stop-path SLO enforcer with bounded state and fail-safe gating semantics.
#[derive(Debug, Clone)]
pub struct StopPathSloEnforcer {
    config: StopPathSloConfig,
    pending_orders: BTreeMap<String, u64>,
    propagation_samples_ms: VecDeque<u64>,
    defects: VecDeque<StopPathSloDefect>,
}

impl StopPathSloEnforcer {
    /// Creates a new stop-path SLO enforcer.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError::InvalidSloConfig`] for invalid bounds.
    pub fn new(config: StopPathSloConfig) -> Result<Self, ContinuityError> {
        config.validate()?;
        Ok(Self {
            config,
            pending_orders: BTreeMap::new(),
            propagation_samples_ms: VecDeque::new(),
            defects: VecDeque::new(),
        })
    }

    /// Records a stop order issuance timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError`] for invalid identifiers or capacity
    /// saturation.
    pub fn record_stop_order_issued(
        &mut self,
        order_id: &str,
        issued_at_ms: u64,
    ) -> Result<(), ContinuityError> {
        if order_id.is_empty() {
            return Err(ContinuityError::EmptyField { field: "order_id" });
        }
        if order_id.len() > MAX_STOP_ORDER_ID_LEN {
            return Err(ContinuityError::FieldTooLong {
                field: "order_id",
                actual: order_id.len(),
                max: MAX_STOP_ORDER_ID_LEN,
            });
        }
        if !self.pending_orders.contains_key(order_id)
            && self.pending_orders.len() >= self.config.max_pending_orders
        {
            return Err(ContinuityError::TooManyEntries {
                field: "pending_orders",
                actual: self.pending_orders.len() + 1,
                max: self.config.max_pending_orders,
            });
        }
        self.pending_orders
            .insert(order_id.to_string(), issued_at_ms);
        Ok(())
    }

    /// Records capsule termination confirmation for a stop order.
    ///
    /// Returns the computed stop propagation latency in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError::UnknownStopOrder`] when the order was not
    /// previously issued.
    pub fn record_capsule_terminated(
        &mut self,
        order_id: &str,
        terminated_at_ms: u64,
    ) -> Result<u64, ContinuityError> {
        let Some(issued_at_ms) = self.pending_orders.remove(order_id) else {
            self.push_defect(StopPathSloDefect {
                kind: StopPathSloDefectKind::UnknownStopOrder,
                order_id: Some(order_id.to_string()),
                observed_ms: 0,
                threshold_ms: 0,
                detail: "capsule termination reported without a known stop order".to_string(),
            });
            return Err(ContinuityError::UnknownStopOrder {
                order_id: order_id.to_string(),
            });
        };

        let propagation_ms = terminated_at_ms.saturating_sub(issued_at_ms);
        self.propagation_samples_ms.push_back(propagation_ms);
        while self.propagation_samples_ms.len() > self.config.max_samples {
            let _ = self.propagation_samples_ms.pop_front();
        }

        if let Some(p99_ms) = self.stop_propagation_p99_ms() {
            if p99_ms > self.config.stop_propagation_p99_ms {
                self.push_defect(StopPathSloDefect {
                    kind: StopPathSloDefectKind::StopPropagationP99Exceeded,
                    order_id: Some(order_id.to_string()),
                    observed_ms: p99_ms,
                    threshold_ms: self.config.stop_propagation_p99_ms,
                    detail: format!(
                        "stop propagation p99 {}ms exceeded target {}ms",
                        p99_ms, self.config.stop_propagation_p99_ms
                    ),
                });
            }
        }

        Ok(propagation_ms)
    }

    /// Records observed stop-uncertainty deny latency.
    ///
    /// Tier3+ episodes must deny actuation within the configured deadline.
    pub fn record_uncertainty_deny_latency(&mut self, observed_ms: u64, tier3_plus: bool) {
        if tier3_plus && observed_ms > self.config.stop_uncertainty_deny_ms {
            self.push_defect(StopPathSloDefect {
                kind: StopPathSloDefectKind::StopUncertaintyDenyExceeded,
                order_id: None,
                observed_ms,
                threshold_ms: self.config.stop_uncertainty_deny_ms,
                detail: format!(
                    "stop uncertainty deny latency {}ms exceeded target {}ms",
                    observed_ms, self.config.stop_uncertainty_deny_ms
                ),
            });
        }
    }

    /// Returns the computed p99 stop propagation latency.
    #[must_use]
    pub fn stop_propagation_p99_ms(&self) -> Option<u64> {
        percentile_99(self.propagation_samples_ms.as_slices())
    }

    /// Returns all retained blocking defects.
    #[must_use]
    pub fn blocking_defects(&self) -> Vec<StopPathSloDefect> {
        self.defects.iter().cloned().collect()
    }

    /// Returns `true` when promotion can proceed.
    ///
    /// Any tracked SLO defect blocks promotion of tighter ratchet stages.
    #[must_use]
    pub fn promotion_allowed(&self) -> bool {
        self.defects.is_empty()
    }

    fn push_defect(&mut self, defect: StopPathSloDefect) {
        self.defects.push_back(defect);
        while self.defects.len() > self.config.max_defects {
            let _ = self.defects.pop_front();
        }
    }
}

/// Storage class used by RPO/RTO enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityStore {
    /// Event ledger durability/recovery objective.
    Ledger,
    /// Content-addressed storage durability/recovery objective.
    Cas,
}

/// Objective metric class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityMetric {
    /// Recovery point objective (data-loss window).
    Rpo,
    /// Recovery time objective (service restoration window).
    Rto,
}

/// Structured RPO/RTO violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpoRtoDefect {
    /// Storage class with violated objective.
    pub store: ContinuityStore,
    /// Metric type (`RPO` or `RTO`).
    pub metric: ContinuityMetric,
    /// Observed value in milliseconds.
    pub observed_ms: u64,
    /// Maximum allowed value in milliseconds.
    pub threshold_ms: u64,
    /// Observation timestamp in milliseconds.
    pub observed_at_ms: u64,
    /// Human-readable detail.
    pub detail: String,
}

/// RPO/RTO enforcement configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpoRtoConfig {
    /// Ledger RPO target in milliseconds.
    pub ledger_rpo_ms: u64,
    /// Ledger RTO target in milliseconds.
    pub ledger_rto_ms: u64,
    /// CAS RPO target in milliseconds.
    pub cas_rpo_ms: u64,
    /// CAS RTO target in milliseconds.
    pub cas_rto_ms: u64,
    /// Maximum retained defects.
    pub max_defects: usize,
}

impl Default for RpoRtoConfig {
    fn default() -> Self {
        Self {
            ledger_rpo_ms: LEDGER_RPO_TARGET_MS,
            ledger_rto_ms: LEDGER_RTO_TARGET_MS,
            cas_rpo_ms: CAS_RPO_TARGET_MS,
            cas_rto_ms: CAS_RTO_TARGET_MS,
            max_defects: MAX_RPO_RTO_DEFECTS,
        }
    }
}

impl RpoRtoConfig {
    /// Validates objective configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError::InvalidRpoRtoConfig`] for invalid values.
    pub fn validate(&self) -> Result<(), ContinuityError> {
        if self.ledger_rpo_ms == 0
            || self.ledger_rto_ms == 0
            || self.cas_rpo_ms == 0
            || self.cas_rto_ms == 0
        {
            return Err(ContinuityError::InvalidRpoRtoConfig {
                reason: "RPO/RTO targets must be > 0".to_string(),
            });
        }
        if self.max_defects == 0 {
            return Err(ContinuityError::InvalidRpoRtoConfig {
                reason: "max_defects must be > 0".to_string(),
            });
        }
        Ok(())
    }
}

/// RPO/RTO enforcer with bounded defect retention.
#[derive(Debug, Clone)]
pub struct RpoRtoEnforcer {
    config: RpoRtoConfig,
    defects: VecDeque<RpoRtoDefect>,
}

impl RpoRtoEnforcer {
    /// Creates a new enforcer instance.
    ///
    /// # Errors
    ///
    /// Returns [`ContinuityError::InvalidRpoRtoConfig`] for invalid config.
    pub fn new(config: RpoRtoConfig) -> Result<Self, ContinuityError> {
        config.validate()?;
        Ok(Self {
            config,
            defects: VecDeque::new(),
        })
    }

    /// Records checkpoint lag (RPO observation).
    ///
    /// Returns `true` when the observation satisfies target objectives.
    pub fn record_checkpoint_lag(
        &mut self,
        store: ContinuityStore,
        lag_ms: u64,
        observed_at_ms: u64,
    ) -> bool {
        self.record_observation(store, ContinuityMetric::Rpo, lag_ms, observed_at_ms)
    }

    /// Records recovery duration (RTO observation).
    ///
    /// Returns `true` when the observation satisfies target objectives.
    pub fn record_recovery_time(
        &mut self,
        store: ContinuityStore,
        recovery_ms: u64,
        observed_at_ms: u64,
    ) -> bool {
        self.record_observation(store, ContinuityMetric::Rto, recovery_ms, observed_at_ms)
    }

    /// Returns all retained RPO/RTO defects.
    #[must_use]
    pub fn defects(&self) -> Vec<RpoRtoDefect> {
        self.defects.iter().cloned().collect()
    }

    /// Returns `true` when all tracked observations are within configured
    /// targets.
    #[must_use]
    pub fn within_targets(&self) -> bool {
        self.defects.is_empty()
    }

    fn record_observation(
        &mut self,
        store: ContinuityStore,
        metric: ContinuityMetric,
        observed_ms: u64,
        observed_at_ms: u64,
    ) -> bool {
        let threshold_ms = self.threshold(store, metric);
        if observed_ms <= threshold_ms {
            return true;
        }

        self.defects.push_back(RpoRtoDefect {
            store,
            metric,
            observed_ms,
            threshold_ms,
            observed_at_ms,
            detail: format!(
                "{store:?} {metric:?} observation {observed_ms}ms exceeded target {threshold_ms}ms"
            ),
        });
        while self.defects.len() > self.config.max_defects {
            let _ = self.defects.pop_front();
        }
        false
    }

    const fn threshold(&self, store: ContinuityStore, metric: ContinuityMetric) -> u64 {
        match (store, metric) {
            (ContinuityStore::Ledger, ContinuityMetric::Rpo) => self.config.ledger_rpo_ms,
            (ContinuityStore::Ledger, ContinuityMetric::Rto) => self.config.ledger_rto_ms,
            (ContinuityStore::Cas, ContinuityMetric::Rpo) => self.config.cas_rpo_ms,
            (ContinuityStore::Cas, ContinuityMetric::Rto) => self.config.cas_rto_ms,
        }
    }
}

fn percentile_99(slices: (&[u64], &[u64])) -> Option<u64> {
    let total_len = slices.0.len() + slices.1.len();
    if total_len == 0 {
        return None;
    }

    let mut samples = Vec::with_capacity(total_len);
    samples.extend_from_slice(slices.0);
    samples.extend_from_slice(slices.1);
    samples.sort_unstable();

    let rank = ((total_len.saturating_mul(99))
        .saturating_add(99)
        .saturating_sub(1))
        / 100;
    let index = rank.saturating_sub(1).min(samples.len().saturating_sub(1));
    samples.get(index).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn drill_receipt_rejects_oversized_failure_modes() {
        let receipt = DrillReceiptV1 {
            scenario_id: "scenario".to_string(),
            scenario_version: "v1".to_string(),
            observed_failure_modes: (0..=MAX_DRILL_FAILURE_MODES)
                .map(|_| "mode".to_string())
                .collect(),
            recovery_time_ms: 42,
            stop_order_failure_count: 0,
            evidence_references: vec![test_hash(1)],
        };
        let err = receipt
            .validate()
            .expect_err("must reject oversized mode list");
        assert!(matches!(err, ContinuityError::TooManyEntries { .. }));
    }

    #[test]
    fn tier3_drill_receipt_requires_zero_stop_failures() {
        let receipt = DrillReceiptV1 {
            scenario_id: "scenario".to_string(),
            scenario_version: "v1".to_string(),
            observed_failure_modes: vec!["partition".to_string()],
            recovery_time_ms: 100,
            stop_order_failure_count: 1,
            evidence_references: vec![test_hash(2)],
        };
        let err = receipt
            .validate_for_tier3_plus()
            .expect_err("tier3+ should reject non-zero stop failures");
        assert!(matches!(
            err,
            ContinuityError::Tier3StopOrderFailures { .. }
        ));
    }

    #[test]
    fn stop_path_enforcer_detects_propagation_slo_violations() {
        let mut enforcer =
            StopPathSloEnforcer::new(StopPathSloConfig::default()).expect("config should be valid");
        enforcer
            .record_stop_order_issued("order-1", 0)
            .expect("order should register");
        let latency = enforcer
            .record_capsule_terminated("order-1", 2_500)
            .expect("termination should be recorded");
        assert_eq!(latency, 2_500);
        assert_eq!(enforcer.blocking_defects().len(), 1);
        assert!(!enforcer.promotion_allowed());
    }

    #[test]
    fn rpo_rto_enforcer_records_both_ledger_and_cas_violations() {
        let mut enforcer =
            RpoRtoEnforcer::new(RpoRtoConfig::default()).expect("config should be valid");
        let ledger_ok =
            enforcer.record_checkpoint_lag(ContinuityStore::Ledger, LEDGER_RPO_TARGET_MS + 1, 100);
        let cas_ok =
            enforcer.record_recovery_time(ContinuityStore::Cas, CAS_RTO_TARGET_MS + 1, 200);
        assert!(!ledger_ok);
        assert!(!cas_ok);
        assert_eq!(enforcer.defects().len(), 2);
        assert!(!enforcer.within_targets());
    }
}
