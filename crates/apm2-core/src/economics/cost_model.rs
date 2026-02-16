//! RFC-0029 cost model: per-job-kind cost estimation and post-run calibration.
//!
//! This module provides:
//! - [`CostModelV1`]: per-job-kind cost estimates for queue admission.
//! - [`JobCostEstimate`]: deterministic cost estimate for a single job kind.
//! - [`ObservedJobCost`]: observed runtime cost metrics recorded in receipts.
//! - [`calibrate`]: bounded, monotone-safe calibration from receipt
//!   observations.
//!
//! # Invariants
//!
//! - [INV-CM01] Every known job kind has a deterministic cost estimate.
//! - [INV-CM02] Calibration never increases cost estimates beyond their initial
//!   conservative defaults (monotone-safe: estimates can only decrease or
//!   stay).
//! - [INV-CM03] Calibration never makes the system less safe (never increases
//!   concurrency budgets or admission windows).
//! - [INV-CM04] Cost model is bounded: maximum of [`MAX_JOB_KINDS`] entries.
//! - [INV-CM05] Unknown job kinds receive the most conservative (largest)
//!   estimate.
//! - [INV-CM06] All arithmetic uses checked/saturating operations.
//! - [INV-CM07] Calibration sample count is bounded by
//!   [`MAX_CALIBRATION_SAMPLES`].
//! - [INV-CM08] `ObservedJobCost` fields are all bounded by `u64::MAX` (no
//!   panic).
//!
//! # Contracts
//!
//! - [CTR-CM01] `estimate()` always returns a valid `JobCostEstimate` for any
//!   input string (fail-closed to conservative default for unknown kinds).
//! - [CTR-CM02] `calibrate()` only adjusts estimates downward within floor
//!   bounds.
//! - [CTR-CM03] `CostModelV1` round-trips through serde deterministically.
//! - [CTR-CM04] `canonical_bytes()` produces deterministic output for hashing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::determinism::canonicalize_json;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of distinct job kinds in the cost model.
pub const MAX_JOB_KINDS: usize = 16;

/// Maximum calibration samples retained per job kind.
pub const MAX_CALIBRATION_SAMPLES: usize = 1024;

/// Exponential weighted moving average decay factor (permille).
/// 200 permille = 0.20 weight on new observation.
/// This is deliberately conservative: new observations have low influence.
const EWMA_ALPHA_PERMILLE: u64 = 200;

/// Minimum floor for estimated ticks (never calibrate below this).
const MIN_ESTIMATED_TICKS: u64 = 1;

/// Minimum floor for estimated wall time in milliseconds.
const MIN_ESTIMATED_WALL_MS: u64 = 1_000; // 1 second

/// Minimum floor for estimated I/O bytes (zero: no floor applied).
#[allow(dead_code)]
const MIN_ESTIMATED_IO_BYTES: u64 = 0;

/// Schema identifier for serialized cost model.
pub const COST_MODEL_SCHEMA: &str = "apm2.economics.cost_model.v1";

/// Domain separator for cost model content hashing.
const COST_MODEL_HASH_DOMAIN: &[u8] = b"apm2.economics.cost_model.v1";

/// Maximum length for a job kind string.
pub const MAX_JOB_KIND_LENGTH: usize = 64;

// ---------------------------------------------------------------------------
// Conservative defaults per job kind
// ---------------------------------------------------------------------------

/// Returns the conservative default cost estimate for a known job kind.
///
/// These values are intentionally high (pessimistic) to ensure the system
/// starts in a safe state. Calibration can only lower them toward observed
/// reality, never raise them above these defaults.
#[must_use]
fn default_estimate(kind: &str) -> JobCostEstimate {
    match kind {
        // Gate jobs: full CI pipeline (~10 min, moderate I/O)
        "gates" => JobCostEstimate {
            estimated_ticks: 600,
            estimated_wall_ms: 600_000,
            estimated_io_bytes: 500_000_000,
        },
        // Warm jobs: dependency cache warming (~5 min, high I/O)
        "warm" => JobCostEstimate {
            estimated_ticks: 300,
            estimated_wall_ms: 300_000,
            estimated_io_bytes: 1_000_000_000,
        },
        // Control jobs: fast administrative actions (~30 sec, low I/O)
        "control" => JobCostEstimate {
            estimated_ticks: 30,
            estimated_wall_ms: 30_000,
            estimated_io_bytes: 10_000_000,
        },
        // Stop/revoke jobs: immediate cancellation (~10 sec, minimal I/O)
        "stop_revoke" => JobCostEstimate {
            estimated_ticks: 10,
            estimated_wall_ms: 10_000,
            estimated_io_bytes: 1_000_000,
        },
        // Bulk jobs and all unknown kinds: most conservative estimate (~15 min, high I/O)
        _ => JobCostEstimate {
            estimated_ticks: 900,
            estimated_wall_ms: 900_000,
            estimated_io_bytes: 2_000_000_000,
        },
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from cost model operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CostModelError {
    /// Too many job kinds in the cost model.
    #[error("cost model has too many job kinds: {count} > {max}")]
    TooManyKinds {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Job kind string exceeds maximum length.
    #[error("job kind too long: {len} > {max}")]
    KindTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Serialization failure.
    #[error("serialization error: {detail}")]
    Serialization {
        /// Detail about the failure.
        detail: String,
    },

    /// Schema mismatch during deserialization.
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        /// Expected schema.
        expected: String,
        /// Actual schema.
        actual: String,
    },

    /// Too many calibration samples.
    #[error("calibration sample count {count} exceeds max {max}")]
    TooManySamples {
        /// Actual count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Deterministic cost estimate for a single job kind.
///
/// All fields represent upper-bound estimates used for queue admission
/// capacity planning. Calibration can only decrease these values toward
/// observed reality (monotone-safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobCostEstimate {
    /// Expected execution duration in scheduler ticks.
    pub estimated_ticks: u64,
    /// Expected wall-clock time in milliseconds.
    pub estimated_wall_ms: u64,
    /// Expected I/O bytes written.
    pub estimated_io_bytes: u64,
}

/// Observed runtime cost metrics from a completed job.
///
/// Recorded in receipts for post-run calibration. All fields are
/// best-effort: workers report what they can measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedJobCost {
    /// Actual wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Actual CPU time in milliseconds (best-effort; 0 if unavailable).
    pub cpu_time_ms: u64,
    /// Actual bytes written (best-effort; 0 if unavailable).
    pub bytes_written: u64,
}

/// Per-kind calibration state tracking EWMA estimates and sample counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationState {
    /// EWMA estimate of wall-clock duration in milliseconds.
    pub ewma_wall_ms: u64,
    /// EWMA estimate of I/O bytes.
    pub ewma_io_bytes: u64,
    /// Number of calibration samples incorporated.
    pub sample_count: u64,
}

/// Per-job-kind cost model for queue admission.
///
/// Contains conservative cost estimates for each known job kind. Estimates
/// start at high defaults and can only be calibrated downward based on
/// observed receipt data.
///
/// The model is persisted as part of the scheduler state for continuity
/// across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostModelV1 {
    /// Schema identifier.
    pub schema: String,
    /// Per-kind cost estimates. Key = job kind string.
    /// Uses `BTreeMap` for deterministic serialization order.
    pub estimates: BTreeMap<String, JobCostEstimate>,
    /// Per-kind calibration state.
    /// Uses `BTreeMap` for deterministic serialization order.
    pub calibration: BTreeMap<String, CalibrationState>,
    /// BLAKE3 content hash for integrity verification.
    pub content_hash: String,
}

impl CostModelV1 {
    /// Creates a new cost model with conservative defaults for all known
    /// job kinds.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut estimates = BTreeMap::new();
        for kind in &["gates", "warm", "bulk", "control", "stop_revoke"] {
            estimates.insert((*kind).to_string(), default_estimate(kind));
        }
        Self {
            schema: COST_MODEL_SCHEMA.to_string(),
            estimates,
            calibration: BTreeMap::new(),
            content_hash: String::new(),
        }
    }

    /// Returns the cost estimate for a given job kind.
    ///
    /// For known kinds, returns the (possibly calibrated) estimate.
    /// For unknown kinds, returns the most conservative default (INV-CM05).
    #[must_use]
    pub fn estimate(&self, kind: &str) -> JobCostEstimate {
        self.estimates
            .get(kind)
            .copied()
            .unwrap_or_else(|| default_estimate(kind))
    }

    /// Returns the queue admission cost (in abstract ticks) for a given job
    /// kind.
    ///
    /// This is the primary integration point between the cost model and queue
    /// admission. The returned value should be used as the `cost` field in
    /// `QueueAdmissionRequest`.
    #[must_use]
    pub fn queue_cost(&self, kind: &str) -> u64 {
        self.estimate(kind).estimated_ticks
    }

    /// Validates the cost model structure.
    ///
    /// # Errors
    ///
    /// Returns `CostModelError` if the model exceeds bounds.
    pub fn validate(&self) -> Result<(), CostModelError> {
        if self.schema != COST_MODEL_SCHEMA {
            return Err(CostModelError::SchemaMismatch {
                expected: COST_MODEL_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }
        if self.estimates.len() > MAX_JOB_KINDS {
            return Err(CostModelError::TooManyKinds {
                count: self.estimates.len(),
                max: MAX_JOB_KINDS,
            });
        }
        for kind in self.estimates.keys() {
            if kind.len() > MAX_JOB_KIND_LENGTH {
                return Err(CostModelError::KindTooLong {
                    len: kind.len(),
                    max: MAX_JOB_KIND_LENGTH,
                });
            }
        }
        if self.calibration.len() > MAX_JOB_KINDS {
            return Err(CostModelError::TooManyKinds {
                count: self.calibration.len(),
                max: MAX_JOB_KINDS,
            });
        }
        for (kind, cal) in &self.calibration {
            if kind.len() > MAX_JOB_KIND_LENGTH {
                return Err(CostModelError::KindTooLong {
                    len: kind.len(),
                    max: MAX_JOB_KIND_LENGTH,
                });
            }
            if cal.sample_count > MAX_CALIBRATION_SAMPLES as u64 {
                return Err(CostModelError::TooManySamples {
                    count: usize::try_from(cal.sample_count).unwrap_or(usize::MAX),
                    max: MAX_CALIBRATION_SAMPLES,
                });
            }
        }
        Ok(())
    }

    /// Returns deterministic CAC-JSON canonical bytes for hashing.
    ///
    /// Uses the project-standard `canonicalize_json()` helper (SP-INV-004)
    /// instead of raw `serde_json::to_vec` to ensure JCS-compliant key
    /// ordering and deterministic formatting across platforms.
    ///
    /// # Errors
    ///
    /// Returns `CostModelError::Serialization` if serialization or
    /// canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CostModelError> {
        let mut normalized = self.clone();
        normalized.content_hash = String::new();
        let json_str =
            serde_json::to_string(&normalized).map_err(|e| CostModelError::Serialization {
                detail: e.to_string(),
            })?;
        let canonical =
            canonicalize_json(&json_str).map_err(|e| CostModelError::Serialization {
                detail: format!("canonicalization failed: {e}"),
            })?;
        Ok(canonical.into_bytes())
    }

    /// Computes the content hash for integrity verification.
    ///
    /// # Errors
    ///
    /// Returns `CostModelError::Serialization` if canonical bytes fail.
    pub fn compute_content_hash(&self) -> Result<String, CostModelError> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(COST_MODEL_HASH_DOMAIN);
        hasher.update(&canonical);
        Ok(format!("b3-256:{}", hasher.finalize().to_hex()))
    }

    /// Incorporates an observed job cost into the calibration state.
    ///
    /// Calibration is monotone-safe: estimates can only decrease toward
    /// observed values, never increase above the initial conservative
    /// defaults (INV-CM02, INV-CM03).
    ///
    /// Uses bounded EWMA with floor constraints:
    /// - `new_estimate` = max(floor, ewma(old, observed))
    /// - If observed > current estimate, the observation is recorded but the
    ///   estimate is not raised (monotone-safe).
    ///
    /// # Errors
    ///
    /// Returns `CostModelError` if the kind string exceeds length bounds
    /// or calibration samples exceed the maximum.
    pub fn calibrate(
        &mut self,
        kind: &str,
        observed: &ObservedJobCost,
    ) -> Result<(), CostModelError> {
        if kind.len() > MAX_JOB_KIND_LENGTH {
            return Err(CostModelError::KindTooLong {
                len: kind.len(),
                max: MAX_JOB_KIND_LENGTH,
            });
        }

        // Check that adding this kind would not exceed MAX_JOB_KINDS for the
        // TOTAL set of unique keys across both estimates and calibration maps.
        // This prevents the persistent-DoS scenario where calibrate() pushes
        // the combined key count past the validate() limit, making the model
        // invalid on disk (INV-CM04).
        let is_new_kind =
            !self.estimates.contains_key(kind) && !self.calibration.contains_key(kind);
        if is_new_kind {
            let mut total_kinds = self.estimates.len();
            for key in self.calibration.keys() {
                if !self.estimates.contains_key(key.as_str()) {
                    total_kinds = total_kinds.saturating_add(1);
                }
            }
            // +1 for the new kind about to be inserted
            if total_kinds.saturating_add(1) > MAX_JOB_KINDS {
                return Err(CostModelError::TooManyKinds {
                    count: total_kinds.saturating_add(1),
                    max: MAX_JOB_KINDS,
                });
            }
        }

        // Pre-compute the current estimate before mutable borrow of calibration map.
        let current = self.estimate(kind);

        let cal = self
            .calibration
            .entry(kind.to_string())
            .or_insert(CalibrationState {
                ewma_wall_ms: current.estimated_wall_ms,
                ewma_io_bytes: current.estimated_io_bytes,
                sample_count: 0,
            });

        if cal.sample_count >= MAX_CALIBRATION_SAMPLES as u64 {
            return Err(CostModelError::TooManySamples {
                count: usize::try_from(cal.sample_count).unwrap_or(usize::MAX),
                max: MAX_CALIBRATION_SAMPLES,
            });
        }

        // EWMA update: new = (alpha * observed) + ((1 - alpha) * old)
        // Using permille to avoid floating point.
        cal.ewma_wall_ms = ewma_permille(cal.ewma_wall_ms, observed.duration_ms);
        cal.ewma_io_bytes = ewma_permille(cal.ewma_io_bytes, observed.bytes_written);
        cal.sample_count = cal.sample_count.saturating_add(1);

        // Copy EWMA values out before releasing the mutable borrow on calibration.
        let ewma_wall_ms = cal.ewma_wall_ms;
        let ewma_io_bytes = cal.ewma_io_bytes;

        // Now apply the calibrated EWMA back to the estimate, but only
        // if it would DECREASE the estimate (monotone-safe: never increase).
        let default = default_estimate(kind);

        // Wall time: use min of current and EWMA, but never below floor
        // and never above the initial default.
        let new_wall_ms = ewma_wall_ms
            .min(current.estimated_wall_ms)
            .max(MIN_ESTIMATED_WALL_MS)
            .min(default.estimated_wall_ms);

        // I/O bytes: same logic (no floor needed since MIN_ESTIMATED_IO_BYTES is 0)
        let new_io_bytes = ewma_io_bytes
            .min(current.estimated_io_bytes)
            .min(default.estimated_io_bytes);

        // Ticks: derive from wall time ratio vs default
        // ticks = default_ticks * (new_wall_ms / default_wall_ms), floored
        let new_ticks = if default.estimated_wall_ms > 0 {
            default
                .estimated_ticks
                .saturating_mul(new_wall_ms)
                .checked_div(default.estimated_wall_ms)
                .unwrap_or(default.estimated_ticks)
                .max(MIN_ESTIMATED_TICKS)
                .min(default.estimated_ticks)
        } else {
            default.estimated_ticks
        };

        self.estimates.insert(
            kind.to_string(),
            JobCostEstimate {
                estimated_ticks: new_ticks,
                estimated_wall_ms: new_wall_ms,
                estimated_io_bytes: new_io_bytes,
            },
        );

        Ok(())
    }

    /// Resets the cost model to conservative defaults, discarding all
    /// calibration data.
    pub fn reset_to_defaults(&mut self) {
        *self = Self::with_defaults();
    }
}

/// EWMA update using permille (integer arithmetic, no floats).
///
/// `result = (alpha * observed + (1000 - alpha) * old) / 1000`
///
/// Uses saturating arithmetic to prevent overflow (INV-CM06).
fn ewma_permille(old: u64, observed: u64) -> u64 {
    let alpha = EWMA_ALPHA_PERMILLE;
    let complement = 1000u64.saturating_sub(alpha);
    // Use u128 intermediates to prevent overflow in multiplication.
    let weighted_observed = u128::from(observed).saturating_mul(u128::from(alpha));
    let weighted_old = u128::from(old).saturating_mul(u128::from(complement));
    let sum = weighted_observed.saturating_add(weighted_old);
    // Divide by 1000 to get permille average.
    let result = sum / 1000;
    // Clamp to u64 range — result is bounded by the input range so truncation
    // cannot occur in practice, but we guard defensively.
    #[allow(clippy::cast_possible_truncation)]
    let clamped = result.min(u128::from(u64::MAX)) as u64;
    clamped
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_model_has_all_known_kinds() {
        let model = CostModelV1::with_defaults();
        assert_eq!(model.estimates.len(), 5);
        for kind in &["gates", "warm", "bulk", "control", "stop_revoke"] {
            assert!(
                model.estimates.contains_key(*kind),
                "missing default for kind: {kind}"
            );
        }
    }

    #[test]
    fn unknown_kind_returns_conservative_default() {
        let model = CostModelV1::with_defaults();
        let estimate = model.estimate("nonexistent_kind");
        // Unknown kinds get bulk-equivalent (most conservative)
        assert_eq!(estimate.estimated_ticks, 900);
        assert_eq!(estimate.estimated_wall_ms, 900_000);
        assert_eq!(estimate.estimated_io_bytes, 2_000_000_000);
    }

    #[test]
    fn estimate_returns_per_kind_values() {
        let model = CostModelV1::with_defaults();
        let gates = model.estimate("gates");
        assert_eq!(gates.estimated_ticks, 600);
        assert_eq!(gates.estimated_wall_ms, 600_000);

        let stop = model.estimate("stop_revoke");
        assert_eq!(stop.estimated_ticks, 10);
        assert_eq!(stop.estimated_wall_ms, 10_000);
    }

    #[test]
    fn calibration_decreases_estimate_toward_observed() {
        let mut model = CostModelV1::with_defaults();
        let initial = model.estimate("gates");

        // Observed value much lower than default
        let observed = ObservedJobCost {
            duration_ms: 120_000, // 2 minutes vs 10 min default
            cpu_time_ms: 100_000,
            bytes_written: 100_000_000, // 100MB vs 500MB default
        };

        model.calibrate("gates", &observed).expect("calibrate ok");

        let after = model.estimate("gates");
        // Estimate should have decreased (EWMA pulls toward observed)
        assert!(
            after.estimated_wall_ms < initial.estimated_wall_ms,
            "wall_ms should decrease: {} < {}",
            after.estimated_wall_ms,
            initial.estimated_wall_ms
        );
        assert!(
            after.estimated_io_bytes < initial.estimated_io_bytes,
            "io_bytes should decrease: {} < {}",
            after.estimated_io_bytes,
            initial.estimated_io_bytes
        );
    }

    #[test]
    fn calibration_never_increases_above_default() {
        let mut model = CostModelV1::with_defaults();
        let initial_default = default_estimate("gates");

        // Observed value much HIGHER than default (adversarial)
        let observed = ObservedJobCost {
            duration_ms: 99_999_999,
            cpu_time_ms: 99_999_999,
            bytes_written: 99_999_999_999,
        };

        model.calibrate("gates", &observed).expect("calibrate ok");

        let after = model.estimate("gates");
        // Monotone-safe: estimate must not exceed default
        assert!(
            after.estimated_wall_ms <= initial_default.estimated_wall_ms,
            "wall_ms should not exceed default: {} <= {}",
            after.estimated_wall_ms,
            initial_default.estimated_wall_ms
        );
        assert!(
            after.estimated_io_bytes <= initial_default.estimated_io_bytes,
            "io_bytes should not exceed default: {} <= {}",
            after.estimated_io_bytes,
            initial_default.estimated_io_bytes
        );
        assert!(
            after.estimated_ticks <= initial_default.estimated_ticks,
            "ticks should not exceed default: {} <= {}",
            after.estimated_ticks,
            initial_default.estimated_ticks
        );
    }

    #[test]
    fn calibration_respects_floor() {
        let mut model = CostModelV1::with_defaults();

        // Observed value of zero (pathological)
        let observed = ObservedJobCost {
            duration_ms: 0,
            cpu_time_ms: 0,
            bytes_written: 0,
        };

        // Calibrate many times to drive EWMA toward zero
        for _ in 0..20 {
            // Reset sample count by re-creating calibration entry
            model.calibration.remove("gates");
            model.calibrate("gates", &observed).expect("calibrate ok");
        }

        let after = model.estimate("gates");
        // Floor constraints must hold
        assert!(
            after.estimated_ticks >= MIN_ESTIMATED_TICKS,
            "ticks must be >= floor: {} >= {}",
            after.estimated_ticks,
            MIN_ESTIMATED_TICKS
        );
        assert!(
            after.estimated_wall_ms >= MIN_ESTIMATED_WALL_MS,
            "wall_ms must be >= floor: {} >= {}",
            after.estimated_wall_ms,
            MIN_ESTIMATED_WALL_MS
        );
    }

    #[test]
    fn calibration_sample_count_is_bounded() {
        let mut model = CostModelV1::with_defaults();
        let observed = ObservedJobCost {
            duration_ms: 300_000,
            cpu_time_ms: 200_000,
            bytes_written: 200_000_000,
        };

        // Fill up to the maximum samples
        for _ in 0..MAX_CALIBRATION_SAMPLES {
            model.calibrate("gates", &observed).expect("calibrate ok");
        }

        // Next calibration should fail
        let result = model.calibrate("gates", &observed);
        assert!(
            matches!(result, Err(CostModelError::TooManySamples { .. })),
            "expected TooManySamples, got: {result:?}"
        );
    }

    #[test]
    fn calibration_rejects_oversized_kind() {
        let mut model = CostModelV1::with_defaults();
        let long_kind = "x".repeat(MAX_JOB_KIND_LENGTH + 1);
        let observed = ObservedJobCost {
            duration_ms: 100,
            cpu_time_ms: 50,
            bytes_written: 1000,
        };

        let result = model.calibrate(&long_kind, &observed);
        assert!(
            matches!(result, Err(CostModelError::KindTooLong { .. })),
            "expected KindTooLong, got: {result:?}"
        );
    }

    #[test]
    fn too_many_kinds_rejected() {
        let mut model = CostModelV1::with_defaults();
        let observed = ObservedJobCost {
            duration_ms: 100,
            cpu_time_ms: 50,
            bytes_written: 1000,
        };

        // Fill calibration map to MAX_JOB_KINDS
        for i in 0..MAX_JOB_KINDS {
            let kind = format!("kind_{i}");
            model.calibration.insert(
                kind,
                CalibrationState {
                    ewma_wall_ms: 100,
                    ewma_io_bytes: 1000,
                    sample_count: 1,
                },
            );
        }

        // Next new kind should fail
        let result = model.calibrate("new_kind_overflow", &observed);
        assert!(
            matches!(result, Err(CostModelError::TooManyKinds { .. })),
            "expected TooManyKinds, got: {result:?}"
        );
    }

    #[test]
    fn validate_rejects_bad_schema() {
        let mut model = CostModelV1::with_defaults();
        model.schema = "wrong.schema".to_string();
        assert!(matches!(
            model.validate(),
            Err(CostModelError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let model = CostModelV1::with_defaults();
        let bytes1 = model.canonical_bytes().expect("canonical bytes");
        let bytes2 = model.canonical_bytes().expect("canonical bytes");
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn content_hash_is_deterministic() {
        let model = CostModelV1::with_defaults();
        let hash1 = model.compute_content_hash().expect("hash");
        let hash2 = model.compute_content_hash().expect("hash");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn content_hash_changes_on_mutation() {
        let model1 = CostModelV1::with_defaults();
        let mut model2 = CostModelV1::with_defaults();
        model2
            .estimates
            .get_mut("gates")
            .expect("gates exists")
            .estimated_ticks = 999;

        let hash1 = model1.compute_content_hash().expect("hash");
        let hash2 = model2.compute_content_hash().expect("hash");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn serde_round_trip() {
        let model = CostModelV1::with_defaults();
        let bytes = serde_json::to_vec(&model).expect("serialize");
        let restored: CostModelV1 = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(model, restored);
    }

    #[test]
    fn reset_to_defaults_clears_calibration() {
        let mut model = CostModelV1::with_defaults();
        let observed = ObservedJobCost {
            duration_ms: 100_000,
            cpu_time_ms: 80_000,
            bytes_written: 50_000_000,
        };
        model.calibrate("gates", &observed).expect("calibrate ok");
        assert!(!model.calibration.is_empty());

        model.reset_to_defaults();
        assert!(model.calibration.is_empty());
        assert_eq!(model.estimates.len(), 5);
    }

    #[test]
    fn ewma_permille_basic() {
        // old=1000, observed=0, alpha=200 => result = 800
        assert_eq!(ewma_permille(1000, 0), 800);
        // old=1000, observed=1000, alpha=200 => result = 1000
        assert_eq!(ewma_permille(1000, 1000), 1000);
        // old=0, observed=1000, alpha=200 => result = 200
        assert_eq!(ewma_permille(0, 1000), 200);
    }

    #[test]
    fn ewma_permille_no_overflow() {
        // Large values should not overflow
        let result = ewma_permille(u64::MAX, u64::MAX);
        assert!(result > 0);
        // Should be close to u64::MAX
        assert!(result >= u64::MAX - 1);
    }

    #[test]
    fn multiple_calibrations_converge() {
        let mut model = CostModelV1::with_defaults();
        let observed = ObservedJobCost {
            duration_ms: 120_000,
            cpu_time_ms: 100_000,
            bytes_written: 100_000_000,
        };

        let mut prev_wall = model.estimate("gates").estimated_wall_ms;
        for i in 0..10 {
            // Reset sample counter for repeated calibration
            if let Some(cal) = model.calibration.get_mut("gates") {
                if cal.sample_count >= MAX_CALIBRATION_SAMPLES as u64 {
                    break;
                }
            }
            model.calibrate("gates", &observed).expect("calibrate ok");
            let current_wall = model.estimate("gates").estimated_wall_ms;
            assert!(
                current_wall <= prev_wall,
                "iteration {i}: estimate should monotonically decrease: {current_wall} <= {prev_wall}"
            );
            prev_wall = current_wall;
        }

        // After multiple calibrations, estimate should be closer to observed
        let final_est = model.estimate("gates");
        assert!(final_est.estimated_wall_ms < 600_000);
    }

    #[test]
    fn observed_job_cost_serde_round_trip() {
        let cost = ObservedJobCost {
            duration_ms: 123_456,
            cpu_time_ms: 100_000,
            bytes_written: 999_888_777,
        };
        let bytes = serde_json::to_vec(&cost).expect("serialize");
        let restored: ObservedJobCost = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(cost, restored);
    }
}
