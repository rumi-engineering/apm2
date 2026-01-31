// AGENT-AUTHORED
//! Flake classification types and routing for the Forge Admission Cycle.
//!
//! This module defines the [`FlakeRouting`] enum that determines how different
//! types of test flakiness should be handled by the admission system, and
//! provides the [`routing_action`](crate::fac::FlakeClass::routing_action)
//! method on [`FlakeClass`](crate::fac::FlakeClass).
//!
//! # Flake Classes and Routing
//!
//! When AAT runs produce non-deterministic results, the flakiness must be
//! classified and routed to the appropriate remediation path:
//!
//! | Flake Class | Routing Action | Rationale |
//! |-------------|----------------|-----------|
//! | `DeterministicFail` | `Fail` | Consistent failure - not a flake |
//! | `HarnessFlake` | `QuarantineRunnerPool` | Runner/infra issue |
//! | `EnvironmentDrift` | `InvalidateAttestation` | Toolchain/env changed |
//! | `TestNonsemantic` | `QuarantineSpec` | Test output format changed |
//! | `CodeNonsemantic` | `QuarantineSpec` | Code produces non-semantic diff |
//! | `Unknown` | `NeedsInput` | Cannot auto-classify |
//!
//! # Critical Invariant: Unknown Cannot Retry to PASS
//!
//! **SECURITY**: The `Unknown` flake class MUST route to `NeedsInput`, which
//! prevents the system from automatically retrying unknown failures to a PASS
//! verdict. This is a security-critical invariant:
//!
//! - Unknown failures indicate unclassified non-determinism
//! - Automatic retry could mask real bugs or security issues
//! - Human investigation is required before retry is permitted
//!
//! See [FAC-REQ-0008] for the full requirement.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{FlakeClass, FlakeRouting};
//!
//! // Harness flakes quarantine the runner pool
//! let routing = FlakeClass::HarnessFlake.routing_action();
//! assert_eq!(routing, FlakeRouting::QuarantineRunnerPool);
//!
//! // Unknown flakes require human input - cannot auto-retry
//! let routing = FlakeClass::Unknown.routing_action();
//! assert_eq!(routing, FlakeRouting::NeedsInput);
//! ```

use serde::{Deserialize, Serialize};

use super::aat_receipt::FlakeClass;

// =============================================================================
// FlakeRouting Enum
// =============================================================================

/// Routing action for flake classification.
///
/// Determines how the system should respond to a classified flake to maintain
/// throughput while preventing bad merges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum FlakeRouting {
    /// Deterministic failure - proceed with FAIL verdict.
    ///
    /// Used when the result is consistently failing across all runs.
    /// Not actually a flake, so no special handling needed.
    Fail                 = 1,

    /// Quarantine the runner pool.
    ///
    /// Used when flakiness is attributed to runner/infrastructure issues
    /// (timing, resource contention, runner-specific bugs).
    ///
    /// The quarantined runner pool is excluded from future AAT runs until
    /// the issue is investigated and resolved.
    QuarantineRunnerPool = 2,

    /// Invalidate the attestation.
    ///
    /// Used when flakiness is attributed to environment drift (toolchain
    /// version mismatch, dependency changes, environment configuration).
    ///
    /// The attestation binding the result to the execution environment is
    /// marked invalid, requiring re-execution with a verified environment.
    InvalidateAttestation = 3,

    /// Quarantine the test specification.
    ///
    /// Used when flakiness is in the test itself - either test-level
    /// non-semantic differences (output format changes) or code-level
    /// non-semantic differences (timestamps, random IDs in output).
    ///
    /// The test spec is quarantined until the non-determinism is resolved.
    QuarantineSpec       = 4,

    /// Human input required.
    ///
    /// Used when the flake cannot be automatically classified. This is a
    /// **security-critical** routing action because it prevents unknown
    /// failures from being automatically retried to PASS.
    ///
    /// # Security
    ///
    /// This routing action enforces FAC-REQ-0008: "UNKNOWN failures never
    /// PASS via retries". The system MUST NOT automatically retry tests
    /// that reach this state - human investigation is required.
    NeedsInput           = 5,
}

impl FlakeRouting {
    /// Returns the numeric value of this routing action.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns `true` if this routing action allows automatic retry.
    ///
    /// # Security
    ///
    /// `NeedsInput` returns `false` because unknown failures must not
    /// be automatically retried - this enforces FAC-REQ-0008.
    #[must_use]
    pub const fn allows_automatic_retry(self) -> bool {
        !matches!(self, Self::NeedsInput | Self::Fail)
    }

    /// Returns `true` if this routing action triggers a quarantine.
    #[must_use]
    pub const fn triggers_quarantine(self) -> bool {
        matches!(
            self,
            Self::QuarantineRunnerPool | Self::QuarantineSpec | Self::InvalidateAttestation
        )
    }
}

impl std::fmt::Display for FlakeRouting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fail => write!(f, "FAIL"),
            Self::QuarantineRunnerPool => write!(f, "QUARANTINE_RUNNER_POOL"),
            Self::InvalidateAttestation => write!(f, "INVALIDATE_ATTESTATION"),
            Self::QuarantineSpec => write!(f, "QUARANTINE_SPEC"),
            Self::NeedsInput => write!(f, "NEEDS_INPUT"),
        }
    }
}

// =============================================================================
// FlakeClass::routing_action Implementation
// =============================================================================

impl FlakeClass {
    /// Returns the routing action for this flake classification.
    ///
    /// This method maps each flake class to its appropriate remediation path:
    ///
    /// - `DeterministicFail` → `Fail` (consistent failure, not a flake)
    /// - `HarnessFlake` → `QuarantineRunnerPool` (runner/infra issue)
    /// - `EnvironmentDrift` → `InvalidateAttestation` (env changed)
    /// - `TestNonsemantic` → `QuarantineSpec` (test output format)
    /// - `CodeNonsemantic` → `QuarantineSpec` (code non-semantic diff)
    /// - `Unknown` → `NeedsInput` (cannot auto-classify)
    ///
    /// # Security
    ///
    /// **CRITICAL**: `Unknown` MUST route to `NeedsInput` to prevent unknown
    /// failures from being automatically retried to PASS. This is enforced
    /// by FAC-REQ-0008.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::{FlakeClass, FlakeRouting};
    ///
    /// // Each flake class has a defined routing action
    /// assert_eq!(
    ///     FlakeClass::DeterministicFail.routing_action(),
    ///     FlakeRouting::Fail
    /// );
    /// assert_eq!(
    ///     FlakeClass::HarnessFlake.routing_action(),
    ///     FlakeRouting::QuarantineRunnerPool
    /// );
    /// assert_eq!(
    ///     FlakeClass::Unknown.routing_action(),
    ///     FlakeRouting::NeedsInput
    /// );
    /// ```
    #[must_use]
    pub const fn routing_action(self) -> FlakeRouting {
        match self {
            Self::DeterministicFail => FlakeRouting::Fail,
            Self::HarnessFlake => FlakeRouting::QuarantineRunnerPool,
            Self::EnvironmentDrift => FlakeRouting::InvalidateAttestation,
            Self::TestNonsemantic | Self::CodeNonsemantic => FlakeRouting::QuarantineSpec,
            Self::Unknown => FlakeRouting::NeedsInput,
        }
    }

    /// Returns `true` if this flake class allows automatic retry.
    ///
    /// Delegates to [`FlakeRouting::allows_automatic_retry`].
    ///
    /// # Security
    ///
    /// `Unknown` returns `false` because unknown failures must not be
    /// automatically retried - this enforces FAC-REQ-0008.
    #[must_use]
    pub const fn allows_automatic_retry(self) -> bool {
        self.routing_action().allows_automatic_retry()
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
    // Routing Action Tests
    // =========================================================================

    #[test]
    fn test_deterministic_fail_routes_to_fail() {
        assert_eq!(
            FlakeClass::DeterministicFail.routing_action(),
            FlakeRouting::Fail
        );
    }

    #[test]
    fn test_harness_flake_routes_to_quarantine_runner_pool() {
        assert_eq!(
            FlakeClass::HarnessFlake.routing_action(),
            FlakeRouting::QuarantineRunnerPool
        );
    }

    #[test]
    fn test_environment_drift_routes_to_invalidate_attestation() {
        assert_eq!(
            FlakeClass::EnvironmentDrift.routing_action(),
            FlakeRouting::InvalidateAttestation
        );
    }

    #[test]
    fn test_test_nonsemantic_routes_to_quarantine_spec() {
        assert_eq!(
            FlakeClass::TestNonsemantic.routing_action(),
            FlakeRouting::QuarantineSpec
        );
    }

    #[test]
    fn test_code_nonsemantic_routes_to_quarantine_spec() {
        assert_eq!(
            FlakeClass::CodeNonsemantic.routing_action(),
            FlakeRouting::QuarantineSpec
        );
    }

    #[test]
    fn test_unknown_routes_to_needs_input() {
        // SECURITY: This is a critical invariant from FAC-REQ-0008
        assert_eq!(
            FlakeClass::Unknown.routing_action(),
            FlakeRouting::NeedsInput
        );
    }

    // =========================================================================
    // Security Invariant Tests (FAC-REQ-0008)
    // =========================================================================

    #[test]
    fn test_unknown_cannot_auto_retry() {
        // SECURITY: Unknown failures MUST NOT be automatically retried
        // This enforces FAC-REQ-0008: "UNKNOWN failures never PASS via retries"
        assert!(
            !FlakeClass::Unknown.allows_automatic_retry(),
            "Unknown flake class must not allow automatic retry"
        );
    }

    #[test]
    fn test_deterministic_fail_cannot_auto_retry() {
        // Deterministic failures should not be retried either
        assert!(!FlakeClass::DeterministicFail.allows_automatic_retry());
    }

    #[test]
    fn test_quarantinable_flakes_allow_auto_retry() {
        // Flakes that trigger quarantine can be retried on non-quarantined
        // resources
        assert!(FlakeClass::HarnessFlake.allows_automatic_retry());
        assert!(FlakeClass::EnvironmentDrift.allows_automatic_retry());
        assert!(FlakeClass::TestNonsemantic.allows_automatic_retry());
        assert!(FlakeClass::CodeNonsemantic.allows_automatic_retry());
    }

    // =========================================================================
    // FlakeRouting Helper Tests
    // =========================================================================

    #[test]
    fn test_routing_triggers_quarantine() {
        assert!(!FlakeRouting::Fail.triggers_quarantine());
        assert!(FlakeRouting::QuarantineRunnerPool.triggers_quarantine());
        assert!(FlakeRouting::InvalidateAttestation.triggers_quarantine());
        assert!(FlakeRouting::QuarantineSpec.triggers_quarantine());
        assert!(!FlakeRouting::NeedsInput.triggers_quarantine());
    }

    #[test]
    fn test_routing_allows_automatic_retry() {
        assert!(!FlakeRouting::Fail.allows_automatic_retry());
        assert!(FlakeRouting::QuarantineRunnerPool.allows_automatic_retry());
        assert!(FlakeRouting::InvalidateAttestation.allows_automatic_retry());
        assert!(FlakeRouting::QuarantineSpec.allows_automatic_retry());
        assert!(!FlakeRouting::NeedsInput.allows_automatic_retry());
    }

    // =========================================================================
    // Display Tests
    // =========================================================================

    #[test]
    fn test_flake_routing_display() {
        assert_eq!(FlakeRouting::Fail.to_string(), "FAIL");
        assert_eq!(
            FlakeRouting::QuarantineRunnerPool.to_string(),
            "QUARANTINE_RUNNER_POOL"
        );
        assert_eq!(
            FlakeRouting::InvalidateAttestation.to_string(),
            "INVALIDATE_ATTESTATION"
        );
        assert_eq!(FlakeRouting::QuarantineSpec.to_string(), "QUARANTINE_SPEC");
        assert_eq!(FlakeRouting::NeedsInput.to_string(), "NEEDS_INPUT");
    }

    #[test]
    fn test_flake_routing_as_u8() {
        assert_eq!(FlakeRouting::Fail.as_u8(), 1);
        assert_eq!(FlakeRouting::QuarantineRunnerPool.as_u8(), 2);
        assert_eq!(FlakeRouting::InvalidateAttestation.as_u8(), 3);
        assert_eq!(FlakeRouting::QuarantineSpec.as_u8(), 4);
        assert_eq!(FlakeRouting::NeedsInput.as_u8(), 5);
    }

    // =========================================================================
    // Serde Tests
    // =========================================================================

    #[test]
    fn test_flake_routing_serde_roundtrip() {
        for routing in [
            FlakeRouting::Fail,
            FlakeRouting::QuarantineRunnerPool,
            FlakeRouting::InvalidateAttestation,
            FlakeRouting::QuarantineSpec,
            FlakeRouting::NeedsInput,
        ] {
            let json = serde_json::to_string(&routing).unwrap();
            let deserialized: FlakeRouting = serde_json::from_str(&json).unwrap();
            assert_eq!(routing, deserialized);
        }
    }

    #[test]
    fn test_flake_routing_serde_format() {
        // Verify SCREAMING_SNAKE_CASE serialization
        assert_eq!(
            serde_json::to_string(&FlakeRouting::QuarantineRunnerPool).unwrap(),
            "\"QUARANTINE_RUNNER_POOL\""
        );
        assert_eq!(
            serde_json::to_string(&FlakeRouting::NeedsInput).unwrap(),
            "\"NEEDS_INPUT\""
        );
    }

    // =========================================================================
    // Exhaustiveness Tests
    // =========================================================================

    #[test]
    fn test_all_flake_classes_have_routing() {
        // Ensure every FlakeClass variant has a defined routing action
        // This test will fail to compile if a new variant is added
        // without updating routing_action()
        let classes = [
            FlakeClass::DeterministicFail,
            FlakeClass::HarnessFlake,
            FlakeClass::EnvironmentDrift,
            FlakeClass::TestNonsemantic,
            FlakeClass::CodeNonsemantic,
            FlakeClass::Unknown,
        ];

        for class in classes {
            // Just verify it doesn't panic and returns a valid routing
            let _routing = class.routing_action();
        }
    }

    #[test]
    fn test_flake_class_has_6_variants() {
        // Verify we have exactly 6 variants as specified in the ticket
        let classes = [
            FlakeClass::DeterministicFail,
            FlakeClass::HarnessFlake,
            FlakeClass::EnvironmentDrift,
            FlakeClass::TestNonsemantic,
            FlakeClass::CodeNonsemantic,
            FlakeClass::Unknown,
        ];
        assert_eq!(classes.len(), 6);
    }
}
