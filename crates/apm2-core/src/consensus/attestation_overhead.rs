// AGENT-AUTHORED
//! Attestation overhead accounting contract and scale projection helpers
//! (RFC-0020 §9.5.7, TCK-00372).
//!
//! This module defines deterministic types for:
//! - recording measured CPU/network p99 envelopes at a concrete effect scale,
//! - enforcing the `<1%` overhead gate for batched attestation paths, and
//! - projecting from measured `10^6` + `10^8` points to `10^12`.
//!
//! The projection model uses log-log linear extrapolation (power-law fit)
//! between the measured scales.

use thiserror::Error;

/// Required measurement scale: `10^6` effects.
pub const SCALE_EFFECTS_10E6: u64 = 1_000_000;
/// Required measurement scale: `10^8` effects.
pub const SCALE_EFFECTS_10E8: u64 = 100_000_000;
/// Projection target scale: `10^12` effects.
pub const SCALE_EFFECTS_10E12: u64 = 1_000_000_000_000;

const SCALE_EFFECTS_10E6_F64: f64 = 1_000_000.0;
const SCALE_EFFECTS_10E8_F64: f64 = 100_000_000.0;
const SCALE_EFFECTS_10E12_F64: f64 = 1_000_000_000_000.0;

/// Default maximum p99 overhead ratio (`1%`).
pub const DEFAULT_MAX_P99_OVERHEAD_RATIO: f64 = 0.01;

/// Errors for attestation overhead accounting and projection.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum AttestationOverheadError {
    /// Effect count must be non-zero.
    #[error("effects must be > 0")]
    InvalidEffects,
    /// Baseline CPU p99 must be positive.
    #[error("baseline_cpu_p99_us must be > 0")]
    InvalidBaselineCpuP99,
    /// Batched CPU p99 must be positive.
    #[error("batched_cpu_p99_us must be > 0")]
    InvalidBatchedCpuP99,
    /// Baseline network p99 must be positive.
    #[error("baseline_network_p99_bytes must be > 0")]
    InvalidBaselineNetworkP99,
    /// Batched network p99 must be positive.
    #[error("batched_network_p99_bytes must be > 0")]
    InvalidBatchedNetworkP99,
    /// Overhead gate was exceeded.
    #[error(
        "attestation overhead gate exceeded: cpu_overhead_ratio={cpu_overhead_ratio:.6}, \
         network_overhead_ratio={network_overhead_ratio:.6}, \
         max_cpu_overhead_ratio={max_cpu_overhead_ratio:.6}, \
         max_network_overhead_ratio={max_network_overhead_ratio:.6}"
    )]
    OverheadGateExceeded {
        /// Observed CPU overhead ratio (`(batched - baseline) / baseline`).
        cpu_overhead_ratio: f64,
        /// Observed network overhead ratio (`(batched - baseline) / baseline`).
        network_overhead_ratio: f64,
        /// Configured maximum CPU overhead ratio.
        max_cpu_overhead_ratio: f64,
        /// Configured maximum network overhead ratio.
        max_network_overhead_ratio: f64,
    },
    /// Projection model requires ordered `10^6` and `10^8` measurements.
    #[error(
        "projection model requires measurements at 10^6 and 10^8 effects \
         (got lhs={lhs_effects}, rhs={rhs_effects})"
    )]
    InvalidProjectionScales {
        /// Left-hand measurement effects.
        lhs_effects: u64,
        /// Right-hand measurement effects.
        rhs_effects: u64,
    },
}

/// Measured p99 accounting snapshot for one effect scale.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttestationScaleMeasurement {
    /// Number of effects represented by this measurement point.
    pub effects: u64,
    /// Baseline path CPU p99 envelope in microseconds.
    pub baseline_cpu_p99_us: f64,
    /// Batched path CPU p99 envelope in microseconds.
    pub batched_cpu_p99_us: f64,
    /// Baseline path network p99 envelope in bytes.
    pub baseline_network_p99_bytes: f64,
    /// Batched path network p99 envelope in bytes.
    pub batched_network_p99_bytes: f64,
}

impl AttestationScaleMeasurement {
    /// Creates a validated scale measurement.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationOverheadError`] when any required positive field
    /// is zero or negative.
    pub fn new(
        effects: u64,
        baseline_cpu_p99_us: f64,
        batched_cpu_p99_us: f64,
        baseline_network_p99_bytes: f64,
        batched_network_p99_bytes: f64,
    ) -> Result<Self, AttestationOverheadError> {
        if effects == 0 {
            return Err(AttestationOverheadError::InvalidEffects);
        }
        if baseline_cpu_p99_us <= 0.0 {
            return Err(AttestationOverheadError::InvalidBaselineCpuP99);
        }
        if batched_cpu_p99_us <= 0.0 {
            return Err(AttestationOverheadError::InvalidBatchedCpuP99);
        }
        if baseline_network_p99_bytes <= 0.0 {
            return Err(AttestationOverheadError::InvalidBaselineNetworkP99);
        }
        if batched_network_p99_bytes <= 0.0 {
            return Err(AttestationOverheadError::InvalidBatchedNetworkP99);
        }

        Ok(Self {
            effects,
            baseline_cpu_p99_us,
            batched_cpu_p99_us,
            baseline_network_p99_bytes,
            batched_network_p99_bytes,
        })
    }

    /// Returns the CPU overhead ratio (`(batched - baseline) / baseline`).
    #[must_use]
    pub fn cpu_overhead_ratio(&self) -> f64 {
        (self.batched_cpu_p99_us - self.baseline_cpu_p99_us) / self.baseline_cpu_p99_us
    }

    /// Returns the network overhead ratio (`(batched - baseline) / baseline`).
    #[must_use]
    pub fn network_overhead_ratio(&self) -> f64 {
        (self.batched_network_p99_bytes - self.baseline_network_p99_bytes)
            / self.baseline_network_p99_bytes
    }
}

/// `<1%` overhead gate contract for batched attestation paths.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttestationOverheadGate {
    /// Maximum CPU overhead ratio.
    pub max_cpu_overhead_ratio: f64,
    /// Maximum network overhead ratio.
    pub max_network_overhead_ratio: f64,
}

impl Default for AttestationOverheadGate {
    fn default() -> Self {
        Self {
            max_cpu_overhead_ratio: DEFAULT_MAX_P99_OVERHEAD_RATIO,
            max_network_overhead_ratio: DEFAULT_MAX_P99_OVERHEAD_RATIO,
        }
    }
}

impl AttestationOverheadGate {
    /// Creates a gate with explicit CPU/network overhead limits.
    #[must_use]
    pub const fn new(max_cpu_overhead_ratio: f64, max_network_overhead_ratio: f64) -> Self {
        Self {
            max_cpu_overhead_ratio,
            max_network_overhead_ratio,
        }
    }

    /// Enforces the overhead gate on a measurement snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationOverheadError::OverheadGateExceeded`] if either
    /// CPU or network overhead exceeds the configured limit.
    pub fn enforce(
        &self,
        measurement: &AttestationScaleMeasurement,
    ) -> Result<(), AttestationOverheadError> {
        let cpu_overhead_ratio = measurement.cpu_overhead_ratio();
        let network_overhead_ratio = measurement.network_overhead_ratio();

        if cpu_overhead_ratio <= self.max_cpu_overhead_ratio
            && network_overhead_ratio <= self.max_network_overhead_ratio
        {
            return Ok(());
        }

        Err(AttestationOverheadError::OverheadGateExceeded {
            cpu_overhead_ratio,
            network_overhead_ratio,
            max_cpu_overhead_ratio: self.max_cpu_overhead_ratio,
            max_network_overhead_ratio: self.max_network_overhead_ratio,
        })
    }
}

/// Two-point projection model for `10^6` + `10^8` measured scales.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttestationProjectionModel {
    measured_10e6: AttestationScaleMeasurement,
    measured_10e8: AttestationScaleMeasurement,
}

impl AttestationProjectionModel {
    /// Constructs a validated projection model from required measured points.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationOverheadError::InvalidProjectionScales`] if the
    /// measurement scales are not exactly `10^6` and `10^8`.
    pub const fn new(
        measured_10e6: AttestationScaleMeasurement,
        measured_10e8: AttestationScaleMeasurement,
    ) -> Result<Self, AttestationOverheadError> {
        if measured_10e6.effects != SCALE_EFFECTS_10E6
            || measured_10e8.effects != SCALE_EFFECTS_10E8
        {
            return Err(AttestationOverheadError::InvalidProjectionScales {
                lhs_effects: measured_10e6.effects,
                rhs_effects: measured_10e8.effects,
            });
        }
        Ok(Self {
            measured_10e6,
            measured_10e8,
        })
    }

    /// Returns the measured `10^6` snapshot.
    #[must_use]
    pub const fn measured_10e6(&self) -> &AttestationScaleMeasurement {
        &self.measured_10e6
    }

    /// Returns the measured `10^8` snapshot.
    #[must_use]
    pub const fn measured_10e8(&self) -> &AttestationScaleMeasurement {
        &self.measured_10e8
    }

    /// Projects p99 CPU/network envelopes to `10^12` effects.
    #[must_use]
    pub fn project_10e12(&self) -> AttestationScaleMeasurement {
        AttestationScaleMeasurement {
            effects: SCALE_EFFECTS_10E12,
            baseline_cpu_p99_us: project_power_law(
                SCALE_EFFECTS_10E6_F64,
                self.measured_10e6.baseline_cpu_p99_us,
                SCALE_EFFECTS_10E8_F64,
                self.measured_10e8.baseline_cpu_p99_us,
                SCALE_EFFECTS_10E12_F64,
            ),
            batched_cpu_p99_us: project_power_law(
                SCALE_EFFECTS_10E6_F64,
                self.measured_10e6.batched_cpu_p99_us,
                SCALE_EFFECTS_10E8_F64,
                self.measured_10e8.batched_cpu_p99_us,
                SCALE_EFFECTS_10E12_F64,
            ),
            baseline_network_p99_bytes: project_power_law(
                SCALE_EFFECTS_10E6_F64,
                self.measured_10e6.baseline_network_p99_bytes,
                SCALE_EFFECTS_10E8_F64,
                self.measured_10e8.baseline_network_p99_bytes,
                SCALE_EFFECTS_10E12_F64,
            ),
            batched_network_p99_bytes: project_power_law(
                SCALE_EFFECTS_10E6_F64,
                self.measured_10e6.batched_network_p99_bytes,
                SCALE_EFFECTS_10E8_F64,
                self.measured_10e8.batched_network_p99_bytes,
                SCALE_EFFECTS_10E12_F64,
            ),
        }
    }
}

/// Power-law projection between two measured points on a log-log plane.
#[must_use]
fn project_power_law(x1: f64, y1: f64, x2: f64, y2: f64, target_x: f64) -> f64 {
    let lx1 = x1.ln();
    let lx2 = x2.ln();
    let ly1 = y1.ln();
    let ly2 = y2.ln();

    let slope = (ly2 - ly1) / (lx2 - lx1);
    let intercept = slope.mul_add(-lx1, ly1);
    slope.mul_add(target_x.ln(), intercept).exp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        effects: u64,
        baseline_cpu_p99_us: f64,
        batched_cpu_p99_us: f64,
        baseline_network_p99_bytes: f64,
        batched_network_p99_bytes: f64,
    ) -> AttestationScaleMeasurement {
        AttestationScaleMeasurement::new(
            effects,
            baseline_cpu_p99_us,
            batched_cpu_p99_us,
            baseline_network_p99_bytes,
            batched_network_p99_bytes,
        )
        .expect("sample must be valid")
    }

    #[test]
    fn measurement_rejects_zero_or_negative_inputs() {
        assert!(matches!(
            AttestationScaleMeasurement::new(0, 1.0, 1.0, 1.0, 1.0),
            Err(AttestationOverheadError::InvalidEffects)
        ));
        assert!(matches!(
            AttestationScaleMeasurement::new(1, 0.0, 1.0, 1.0, 1.0),
            Err(AttestationOverheadError::InvalidBaselineCpuP99)
        ));
        assert!(matches!(
            AttestationScaleMeasurement::new(1, 1.0, 0.0, 1.0, 1.0),
            Err(AttestationOverheadError::InvalidBatchedCpuP99)
        ));
        assert!(matches!(
            AttestationScaleMeasurement::new(1, 1.0, 1.0, 0.0, 1.0),
            Err(AttestationOverheadError::InvalidBaselineNetworkP99)
        ));
        assert!(matches!(
            AttestationScaleMeasurement::new(1, 1.0, 1.0, 1.0, 0.0),
            Err(AttestationOverheadError::InvalidBatchedNetworkP99)
        ));
    }

    #[test]
    fn overhead_ratios_compute_expected_values() {
        let measurement = sample(10, 100.0, 101.0, 1000.0, 995.0);
        assert!((measurement.cpu_overhead_ratio() - 0.01).abs() < 1e-12);
        assert!((measurement.network_overhead_ratio() - (-0.005)).abs() < 1e-12);
    }

    #[test]
    fn gate_allows_within_one_percent() {
        let gate = AttestationOverheadGate::default();
        let measurement = sample(10, 100.0, 101.0, 1000.0, 1009.0);
        assert!(gate.enforce(&measurement).is_ok());
    }

    #[test]
    fn gate_rejects_cpu_or_network_overflow() {
        let gate = AttestationOverheadGate::default();
        let cpu_fail = sample(10, 100.0, 102.0, 1000.0, 1000.0);
        let network_fail = sample(10, 100.0, 100.0, 1000.0, 1015.0);

        assert!(matches!(
            gate.enforce(&cpu_fail),
            Err(AttestationOverheadError::OverheadGateExceeded { .. })
        ));
        assert!(matches!(
            gate.enforce(&network_fail),
            Err(AttestationOverheadError::OverheadGateExceeded { .. })
        ));
    }

    #[test]
    fn projection_model_requires_required_scales() {
        let lhs = sample(10, 1.0, 1.0, 1.0, 1.0);
        let rhs = sample(20, 1.0, 1.0, 1.0, 1.0);
        let err = AttestationProjectionModel::new(lhs, rhs).expect_err("scales must fail");
        assert!(matches!(
            err,
            AttestationOverheadError::InvalidProjectionScales {
                lhs_effects: 10,
                rhs_effects: 20,
            }
        ));
    }

    #[test]
    fn projection_to_10e12_is_deterministic() {
        let measured_10e6 = sample(SCALE_EFFECTS_10E6, 1_000.0, 1_005.0, 5_000.0, 5_002.0);
        let measured_10e8 = sample(
            SCALE_EFFECTS_10E8,
            110_000.0,
            110_550.0,
            500_000.0,
            500_200.0,
        );
        let model = AttestationProjectionModel::new(measured_10e6, measured_10e8)
            .expect("projection model must be valid");

        let p1 = model.project_10e12();
        let p2 = model.project_10e12();
        assert_eq!(p1.effects, SCALE_EFFECTS_10E12);
        assert!((p1.baseline_cpu_p99_us - p2.baseline_cpu_p99_us).abs() < 1e-9);
        assert!((p1.batched_cpu_p99_us - p2.batched_cpu_p99_us).abs() < 1e-9);
        assert!((p1.baseline_network_p99_bytes - p2.baseline_network_p99_bytes).abs() < 1e-9);
        assert!((p1.batched_network_p99_bytes - p2.batched_network_p99_bytes).abs() < 1e-9);
    }
}
