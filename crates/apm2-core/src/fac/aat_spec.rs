// AGENT-AUTHORED
//! AAT specification types with invariant-first validation.
//!
//! This module implements DD-FAC-0012 (Invariant-First AAT Specifications)
//! which ensures that AAT (Agent Acceptance Testing) specifications are
//! structured for machine-checkable verification.
//!
//! # Invariant-First Design
//!
//! AAT specs MUST declare invariants as the primary acceptance criteria.
//! Procedural steps are observational only - they cannot affect the pass/fail
//! determination. This design:
//!
//! - Ensures testable acceptance criteria with machine-checkable outcomes
//! - Prevents step-only specs that lack verifiable invariants
//! - Supports Goodhart drift prevention by anchoring to ground truth
//!
//! # Security Model
//!
//! - Step-only specs (no invariants) are rejected at validation
//! - Invariants without machine predicates are rejected
//! - Non-observational steps are rejected to enforce determinism
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{
//!     AatSpec, AatSpecBuilder, AatStep, Invariant, Predicate, PredicateOp, VerifierKind,
//! };
//!
//! // Create an invariant with machine predicate
//! let invariant = Invariant::builder("inv-001")
//!     .statement("Build must exit with code 0")
//!     .verifier_kind(VerifierKind::ExitCode)
//!     .machine_predicate(Predicate::compare(
//!         Predicate::variable("exit_code"),
//!         PredicateOp::Eq,
//!         Predicate::literal(0),
//!     ))
//!     .build()
//!     .expect("valid invariant");
//!
//! // Create an observational step
//! let step = AatStep::builder("step-001")
//!     .action("Run cargo build")
//!     .observational(true)
//!     .build()
//!     .expect("valid step");
//!
//! // Build the spec with at least one invariant
//! let spec = AatSpecBuilder::new("spec-001")
//!     .scenario_type("build")
//!     .add_invariant(invariant)
//!     .add_step(step)
//!     .build()
//!     .expect("valid spec");
//!
//! // Validate returns Ok(()) for well-formed specs
//! assert!(spec.validate().is_ok());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::policy_resolution::MAX_STRING_LENGTH;
use super::terminal_verifier::{Predicate, VerifierKind};

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of invariants allowed in an AAT spec.
pub const MAX_INVARIANTS: usize = 256;

/// Maximum number of steps allowed in an AAT spec.
pub const MAX_STEPS: usize = 256;

/// Maximum length of an invariant statement.
pub const MAX_STATEMENT_LENGTH: usize = 4096;

/// Maximum length of an action description.
pub const MAX_ACTION_LENGTH: usize = 4096;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during AAT spec operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AatSpecError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid spec data.
    #[error("invalid spec data: {0}")]
    InvalidData(String),

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

    /// Collection size exceeds resource limit.
    #[error("collection size exceeds limit: {field} has {actual} items, max is {max}")]
    CollectionTooLarge {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual size of the collection.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Spec has no invariants (step-only spec rejected).
    #[error("AAT spec must have at least one invariant (step-only specs are rejected)")]
    NoInvariants,

    /// Invariant is missing machine predicate.
    #[error("invariant {invariant_id} is missing machine_predicate")]
    MissingMachinePredicate {
        /// The invariant ID that is missing a predicate.
        invariant_id: String,
    },

    /// Step is not observational.
    #[error("step {step_id} must be observational (observational=true required)")]
    StepNotObservational {
        /// The step ID that is not observational.
        step_id: String,
    },

    /// Duplicate invariant ID.
    #[error("duplicate invariant_id: {invariant_id}")]
    DuplicateInvariantId {
        /// The duplicate invariant ID.
        invariant_id: String,
    },

    /// Duplicate step ID.
    #[error("duplicate step_id: {step_id}")]
    DuplicateStepId {
        /// The duplicate step ID.
        step_id: String,
    },

    /// Predicate validation failed.
    #[error("predicate validation failed for invariant {invariant_id}: {reason}")]
    PredicateValidationFailed {
        /// The invariant ID with the invalid predicate.
        invariant_id: String,
        /// The reason for validation failure.
        reason: String,
    },
}

// =============================================================================
// Invariant
// =============================================================================

/// An invariant that must be satisfied for the AAT to pass.
///
/// Invariants are the primary acceptance criteria for AAT specs. Each invariant
/// MUST have a machine-checkable predicate that can be evaluated against
/// terminal verifier outputs.
///
/// # Fields
///
/// - `invariant_id`: Unique identifier for this invariant
/// - `statement`: Human-readable description of the invariant
/// - `verifier_kind`: The type of terminal verifier that evaluates this
///   invariant
/// - `machine_predicate`: Machine-checkable predicate expression (REQUIRED)
///
/// # Security
///
/// The `machine_predicate` field is required to ensure all invariants have
/// machine-checkable outcomes. Invariants without predicates cannot be
/// automatically verified and are rejected during spec validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Invariant {
    /// Unique identifier for this invariant.
    invariant_id: String,

    /// Human-readable description of what this invariant checks.
    statement: String,

    /// The type of terminal verifier that evaluates this invariant.
    verifier_kind: VerifierKind,

    /// Machine-checkable predicate that MUST be satisfied.
    ///
    /// This is REQUIRED - invariants without machine predicates are rejected
    /// during spec validation.
    machine_predicate: Predicate,
}

impl Invariant {
    /// Creates a new builder for `Invariant`.
    #[must_use]
    pub fn builder(invariant_id: impl Into<String>) -> InvariantBuilder {
        InvariantBuilder::new(invariant_id)
    }

    /// Returns the invariant ID.
    #[must_use]
    pub fn invariant_id(&self) -> &str {
        &self.invariant_id
    }

    /// Returns the statement.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    /// Returns the verifier kind.
    #[must_use]
    pub const fn verifier_kind(&self) -> VerifierKind {
        self.verifier_kind
    }

    /// Returns the machine predicate.
    #[must_use]
    pub const fn machine_predicate(&self) -> &Predicate {
        &self.machine_predicate
    }

    /// Validates the invariant.
    ///
    /// # Errors
    ///
    /// Returns [`AatSpecError::PredicateValidationFailed`] if the predicate
    /// is invalid.
    pub fn validate(&self) -> Result<(), AatSpecError> {
        // Validate the predicate (depth, node count, string lengths)
        self.machine_predicate
            .validate()
            .map_err(|e| AatSpecError::PredicateValidationFailed {
                invariant_id: self.invariant_id.clone(),
                reason: e.to_string(),
            })
    }

    /// Validates resource limits for defense against deserialization bypass.
    ///
    /// This method enforces string length limits that are normally checked
    /// during construction via the builder. When deserializing untrusted
    /// input, call this to prevent denial-of-service attacks.
    ///
    /// # Errors
    ///
    /// Returns [`AatSpecError::StringTooLong`] if string fields exceed limits.
    pub fn validate_resource_limits(&self) -> Result<(), AatSpecError> {
        if self.invariant_id.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "invariant_id",
                actual: self.invariant_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.statement.len() > MAX_STATEMENT_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "statement",
                actual: self.statement.len(),
                max: MAX_STATEMENT_LENGTH,
            });
        }
        Ok(())
    }
}

// =============================================================================
// InvariantBuilder
// =============================================================================

/// Builder for constructing [`Invariant`] instances.
#[derive(Debug, Default)]
pub struct InvariantBuilder {
    invariant_id: String,
    statement: Option<String>,
    verifier_kind: Option<VerifierKind>,
    machine_predicate: Option<Predicate>,
}

impl InvariantBuilder {
    /// Creates a new builder with the given invariant ID.
    #[must_use]
    pub fn new(invariant_id: impl Into<String>) -> Self {
        Self {
            invariant_id: invariant_id.into(),
            ..Default::default()
        }
    }

    /// Sets the statement.
    #[must_use]
    pub fn statement(mut self, statement: impl Into<String>) -> Self {
        self.statement = Some(statement.into());
        self
    }

    /// Sets the verifier kind.
    #[must_use]
    pub const fn verifier_kind(mut self, kind: VerifierKind) -> Self {
        self.verifier_kind = Some(kind);
        self
    }

    /// Sets the machine predicate.
    #[must_use]
    pub fn machine_predicate(mut self, predicate: Predicate) -> Self {
        self.machine_predicate = Some(predicate);
        self
    }

    /// Builds the invariant.
    ///
    /// # Errors
    ///
    /// Returns [`AatSpecError::MissingField`] if required fields are missing.
    /// Returns [`AatSpecError::StringTooLong`] if string fields exceed limits.
    /// Returns [`AatSpecError::PredicateValidationFailed`] if the predicate is
    /// invalid.
    pub fn build(self) -> Result<Invariant, AatSpecError> {
        let statement = self
            .statement
            .ok_or(AatSpecError::MissingField("statement"))?;
        let verifier_kind = self
            .verifier_kind
            .ok_or(AatSpecError::MissingField("verifier_kind"))?;
        let machine_predicate = self
            .machine_predicate
            .ok_or(AatSpecError::MissingField("machine_predicate"))?;

        // Validate string lengths
        if self.invariant_id.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "invariant_id",
                actual: self.invariant_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if statement.len() > MAX_STATEMENT_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "statement",
                actual: statement.len(),
                max: MAX_STATEMENT_LENGTH,
            });
        }

        // Validate predicate
        machine_predicate
            .validate()
            .map_err(|e| AatSpecError::PredicateValidationFailed {
                invariant_id: self.invariant_id.clone(),
                reason: e.to_string(),
            })?;

        Ok(Invariant {
            invariant_id: self.invariant_id,
            statement,
            verifier_kind,
            machine_predicate,
        })
    }
}

// =============================================================================
// AatStep
// =============================================================================

/// A step in an AAT specification.
///
/// Steps are observational only - they describe actions to be performed but
/// do not affect the pass/fail determination. Only invariants determine
/// whether an AAT passes.
///
/// # Observational-Only Constraint
///
/// The `observational` field MUST be `true`. Non-observational steps are
/// rejected during spec validation because:
///
/// 1. Pass/fail must be determined solely by invariants
/// 2. Steps should not have side effects that affect verification
/// 3. Determinism requires that steps are pure observations
///
/// # Fields
///
/// - `step_id`: Unique identifier for this step
/// - `action`: Description of the action to perform
/// - `observational`: Must be `true` (non-observational steps are rejected)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatStep {
    /// Unique identifier for this step.
    step_id: String,

    /// Description of the action to perform.
    action: String,

    /// Whether this step is observational only.
    ///
    /// MUST be `true` - non-observational steps are rejected during spec
    /// validation.
    observational: bool,
}

impl AatStep {
    /// Creates a new builder for `AatStep`.
    #[must_use]
    pub fn builder(step_id: impl Into<String>) -> AatStepBuilder {
        AatStepBuilder::new(step_id)
    }

    /// Returns the step ID.
    #[must_use]
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    /// Returns the action description.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Returns whether this step is observational.
    #[must_use]
    pub const fn observational(&self) -> bool {
        self.observational
    }

    /// Validates resource limits for defense against deserialization bypass.
    ///
    /// This method enforces string length limits that are normally checked
    /// during construction via the builder. When deserializing untrusted
    /// input, call this to prevent denial-of-service attacks.
    ///
    /// # Errors
    ///
    /// Returns [`AatSpecError::StringTooLong`] if string fields exceed limits.
    pub fn validate_resource_limits(&self) -> Result<(), AatSpecError> {
        if self.step_id.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "step_id",
                actual: self.step_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.action.len() > MAX_ACTION_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "action",
                actual: self.action.len(),
                max: MAX_ACTION_LENGTH,
            });
        }
        Ok(())
    }
}

// =============================================================================
// AatStepBuilder
// =============================================================================

/// Builder for constructing [`AatStep`] instances.
#[derive(Debug, Default)]
pub struct AatStepBuilder {
    step_id: String,
    action: Option<String>,
    observational: Option<bool>,
}

impl AatStepBuilder {
    /// Creates a new builder with the given step ID.
    #[must_use]
    pub fn new(step_id: impl Into<String>) -> Self {
        Self {
            step_id: step_id.into(),
            ..Default::default()
        }
    }

    /// Sets the action description.
    #[must_use]
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Sets whether this step is observational.
    #[must_use]
    pub const fn observational(mut self, observational: bool) -> Self {
        self.observational = Some(observational);
        self
    }

    /// Builds the step.
    ///
    /// # Errors
    ///
    /// Returns [`AatSpecError::MissingField`] if required fields are missing.
    /// Returns [`AatSpecError::StringTooLong`] if string fields exceed limits.
    pub fn build(self) -> Result<AatStep, AatSpecError> {
        let action = self.action.ok_or(AatSpecError::MissingField("action"))?;
        let observational = self
            .observational
            .ok_or(AatSpecError::MissingField("observational"))?;

        // Validate string lengths
        if self.step_id.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "step_id",
                actual: self.step_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if action.len() > MAX_ACTION_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "action",
                actual: action.len(),
                max: MAX_ACTION_LENGTH,
            });
        }

        Ok(AatStep {
            step_id: self.step_id,
            action,
            observational,
        })
    }
}

// =============================================================================
// AatSpec
// =============================================================================

/// An AAT (Agent Acceptance Testing) specification.
///
/// AAT specs define acceptance criteria for changes through invariants and
/// observational steps. The invariant-first design ensures that:
///
/// - At least one invariant must be declared
/// - All invariants must have machine-checkable predicates
/// - All steps must be observational only
///
/// # Validation
///
/// Call [`AatSpec::validate()`] to check all invariants:
///
/// 1. At least one invariant exists (no step-only specs)
/// 2. All invariants have machine predicates
/// 3. All steps are observational
/// 4. No duplicate invariant or step IDs
///
/// # Fields
///
/// - `spec_id`: Unique identifier for this specification
/// - `scenario_type`: Type of scenario (e.g., "build", "test", "security")
/// - `invariants`: List of invariants (required, at least one)
/// - `steps`: List of observational steps (optional)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AatSpec {
    /// Unique identifier for this specification.
    spec_id: String,

    /// Type of scenario this spec covers.
    scenario_type: String,

    /// List of invariants that must be satisfied.
    ///
    /// MUST contain at least one invariant. Step-only specs are rejected.
    invariants: Vec<Invariant>,

    /// List of observational steps.
    ///
    /// All steps MUST have `observational=true`.
    steps: Vec<AatStep>,
}

impl AatSpec {
    /// Creates a new builder for `AatSpec`.
    #[must_use]
    pub fn builder(spec_id: impl Into<String>) -> AatSpecBuilder {
        AatSpecBuilder::new(spec_id)
    }

    /// Returns the spec ID.
    #[must_use]
    pub fn spec_id(&self) -> &str {
        &self.spec_id
    }

    /// Returns the scenario type.
    #[must_use]
    pub fn scenario_type(&self) -> &str {
        &self.scenario_type
    }

    /// Returns the invariants.
    #[must_use]
    pub fn invariants(&self) -> &[Invariant] {
        &self.invariants
    }

    /// Returns the steps.
    #[must_use]
    pub fn steps(&self) -> &[AatStep] {
        &self.steps
    }

    /// Validates the AAT spec against all invariants.
    ///
    /// # Validation Rules
    ///
    /// 1. **At least one invariant required**: Step-only specs are rejected
    ///    because they lack machine-checkable acceptance criteria.
    ///
    /// 2. **All invariants have machine predicates**: Each invariant's
    ///    predicate is validated for depth, node count, and string lengths.
    ///
    /// 3. **All steps are observational**: Non-observational steps are rejected
    ///    because pass/fail must be determined solely by invariants.
    ///
    /// 4. **No duplicate IDs**: Invariant IDs and step IDs must be unique.
    ///
    /// # Errors
    ///
    /// Returns appropriate [`AatSpecError`] variants for validation failures.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::{
    ///     AatSpec, AatSpecBuilder, Invariant, Predicate, PredicateOp, VerifierKind,
    /// };
    ///
    /// let invariant = Invariant::builder("inv-001")
    ///     .statement("Exit code must be 0")
    ///     .verifier_kind(VerifierKind::ExitCode)
    ///     .machine_predicate(Predicate::compare(
    ///         Predicate::variable("exit_code"),
    ///         PredicateOp::Eq,
    ///         Predicate::literal(0),
    ///     ))
    ///     .build()
    ///     .expect("valid invariant");
    ///
    /// let spec = AatSpecBuilder::new("spec-001")
    ///     .scenario_type("build")
    ///     .add_invariant(invariant)
    ///     .build()
    ///     .expect("valid spec");
    ///
    /// assert!(spec.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), AatSpecError> {
        // 0. Check resource limits (defense against deserialization bypass)
        // These checks prevent DoS attacks via unbounded collections or strings
        if self.invariants.len() > MAX_INVARIANTS {
            return Err(AatSpecError::CollectionTooLarge {
                field: "invariants",
                actual: self.invariants.len(),
                max: MAX_INVARIANTS,
            });
        }
        if self.steps.len() > MAX_STEPS {
            return Err(AatSpecError::CollectionTooLarge {
                field: "steps",
                actual: self.steps.len(),
                max: MAX_STEPS,
            });
        }
        if self.spec_id.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "spec_id",
                actual: self.spec_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if self.scenario_type.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "scenario_type",
                actual: self.scenario_type.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // 1. Check at least one invariant exists
        if self.invariants.is_empty() {
            return Err(AatSpecError::NoInvariants);
        }

        // 2. Check for duplicate invariant IDs and validate each invariant
        for (i, invariant) in self.invariants.iter().enumerate() {
            // Validate invariant string lengths (defense against deserialization bypass)
            invariant.validate_resource_limits()?;

            // Check for duplicates
            for (j, other) in self.invariants.iter().enumerate() {
                if i != j && invariant.invariant_id() == other.invariant_id() {
                    return Err(AatSpecError::DuplicateInvariantId {
                        invariant_id: invariant.invariant_id().to_string(),
                    });
                }
            }

            // Validate the invariant's predicate
            invariant.validate()?;
        }

        // 3. Check all steps are observational and check for duplicates
        for (i, step) in self.steps.iter().enumerate() {
            // Validate step string lengths (defense against deserialization bypass)
            step.validate_resource_limits()?;

            // Check for duplicates
            for (j, other) in self.steps.iter().enumerate() {
                if i != j && step.step_id() == other.step_id() {
                    return Err(AatSpecError::DuplicateStepId {
                        step_id: step.step_id().to_string(),
                    });
                }
            }

            // Check step is observational
            if !step.observational() {
                return Err(AatSpecError::StepNotObservational {
                    step_id: step.step_id().to_string(),
                });
            }
        }

        Ok(())
    }
}

// =============================================================================
// AatSpecBuilder
// =============================================================================

/// Builder for constructing [`AatSpec`] instances.
#[derive(Debug, Default)]
pub struct AatSpecBuilder {
    spec_id: String,
    scenario_type: Option<String>,
    invariants: Vec<Invariant>,
    steps: Vec<AatStep>,
}

impl AatSpecBuilder {
    /// Creates a new builder with the given spec ID.
    #[must_use]
    pub fn new(spec_id: impl Into<String>) -> Self {
        Self {
            spec_id: spec_id.into(),
            ..Default::default()
        }
    }

    /// Sets the scenario type.
    #[must_use]
    pub fn scenario_type(mut self, scenario_type: impl Into<String>) -> Self {
        self.scenario_type = Some(scenario_type.into());
        self
    }

    /// Adds an invariant.
    #[must_use]
    pub fn add_invariant(mut self, invariant: Invariant) -> Self {
        self.invariants.push(invariant);
        self
    }

    /// Sets all invariants.
    #[must_use]
    pub fn invariants(mut self, invariants: Vec<Invariant>) -> Self {
        self.invariants = invariants;
        self
    }

    /// Adds a step.
    #[must_use]
    pub fn add_step(mut self, step: AatStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Sets all steps.
    #[must_use]
    pub fn steps(mut self, steps: Vec<AatStep>) -> Self {
        self.steps = steps;
        self
    }

    /// Builds the AAT spec.
    ///
    /// # Errors
    ///
    /// Returns [`AatSpecError::MissingField`] if required fields are missing.
    /// Returns [`AatSpecError::StringTooLong`] if string fields exceed limits.
    /// Returns [`AatSpecError::CollectionTooLarge`] if collections exceed
    /// limits. Returns [`AatSpecError::NoInvariants`] if no invariants are
    /// provided.
    pub fn build(self) -> Result<AatSpec, AatSpecError> {
        let scenario_type = self
            .scenario_type
            .ok_or(AatSpecError::MissingField("scenario_type"))?;

        // Validate string lengths
        if self.spec_id.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "spec_id",
                actual: self.spec_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if scenario_type.len() > MAX_STRING_LENGTH {
            return Err(AatSpecError::StringTooLong {
                field: "scenario_type",
                actual: scenario_type.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate collection sizes
        if self.invariants.len() > MAX_INVARIANTS {
            return Err(AatSpecError::CollectionTooLarge {
                field: "invariants",
                actual: self.invariants.len(),
                max: MAX_INVARIANTS,
            });
        }
        if self.steps.len() > MAX_STEPS {
            return Err(AatSpecError::CollectionTooLarge {
                field: "steps",
                actual: self.steps.len(),
                max: MAX_STEPS,
            });
        }

        let spec = AatSpec {
            spec_id: self.spec_id,
            scenario_type,
            invariants: self.invariants,
            steps: self.steps,
        };

        // Validate the spec (this will check no invariants and observational
        // steps)
        spec.validate()?;

        Ok(spec)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::fac::terminal_verifier::PredicateOp;

    // =========================================================================
    // Helper Functions
    // =========================================================================

    fn create_test_invariant(id: &str) -> Invariant {
        Invariant::builder(id)
            .statement("Test invariant")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid invariant")
    }

    fn create_test_step(id: &str) -> AatStep {
        AatStep::builder(id)
            .action("Test action")
            .observational(true)
            .build()
            .expect("valid step")
    }

    // =========================================================================
    // Invariant Tests
    // =========================================================================

    #[test]
    fn test_invariant_builder_success() {
        let invariant = Invariant::builder("inv-001")
            .statement("Exit code must be 0")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid invariant");

        assert_eq!(invariant.invariant_id(), "inv-001");
        assert_eq!(invariant.statement(), "Exit code must be 0");
        assert_eq!(invariant.verifier_kind(), VerifierKind::ExitCode);
    }

    #[test]
    fn test_invariant_missing_statement() {
        let result = Invariant::builder("inv-001")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1))
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::MissingField("statement"))
        ));
    }

    #[test]
    fn test_invariant_missing_verifier_kind() {
        let result = Invariant::builder("inv-001")
            .statement("Test")
            .machine_predicate(Predicate::literal(1))
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::MissingField("verifier_kind"))
        ));
    }

    #[test]
    fn test_invariant_missing_machine_predicate() {
        let result = Invariant::builder("inv-001")
            .statement("Test")
            .verifier_kind(VerifierKind::ExitCode)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::MissingField("machine_predicate"))
        ));
    }

    #[test]
    fn test_invariant_statement_too_long() {
        let long_statement = "x".repeat(MAX_STATEMENT_LENGTH + 1);
        let result = Invariant::builder("inv-001")
            .statement(long_statement)
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1))
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "statement",
                ..
            })
        ));
    }

    #[test]
    fn test_invariant_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let result = Invariant::builder(long_id)
            .statement("Test")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1))
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "invariant_id",
                ..
            })
        ));
    }

    #[test]
    fn test_invariant_serde_roundtrip() {
        let invariant = create_test_invariant("inv-001");
        let json = serde_json::to_string(&invariant).expect("serialize");
        let deserialized: Invariant = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(invariant, deserialized);
    }

    // =========================================================================
    // AatStep Tests
    // =========================================================================

    #[test]
    fn test_step_builder_success() {
        let step = AatStep::builder("step-001")
            .action("Run cargo build")
            .observational(true)
            .build()
            .expect("valid step");

        assert_eq!(step.step_id(), "step-001");
        assert_eq!(step.action(), "Run cargo build");
        assert!(step.observational());
    }

    #[test]
    fn test_step_missing_action() {
        let result = AatStep::builder("step-001").observational(true).build();

        assert!(matches!(result, Err(AatSpecError::MissingField("action"))));
    }

    #[test]
    fn test_step_missing_observational() {
        let result = AatStep::builder("step-001").action("Test").build();

        assert!(matches!(
            result,
            Err(AatSpecError::MissingField("observational"))
        ));
    }

    #[test]
    fn test_step_action_too_long() {
        let long_action = "x".repeat(MAX_ACTION_LENGTH + 1);
        let result = AatStep::builder("step-001")
            .action(long_action)
            .observational(true)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "action",
                ..
            })
        ));
    }

    #[test]
    fn test_step_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let result = AatStep::builder(long_id)
            .action("Test")
            .observational(true)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "step_id",
                ..
            })
        ));
    }

    #[test]
    fn test_step_serde_roundtrip() {
        let step = create_test_step("step-001");
        let json = serde_json::to_string(&step).expect("serialize");
        let deserialized: AatStep = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(step, deserialized);
    }

    // =========================================================================
    // AatSpec Tests
    // =========================================================================

    #[test]
    fn test_spec_builder_success() {
        let invariant = create_test_invariant("inv-001");
        let step = create_test_step("step-001");

        let spec = AatSpecBuilder::new("spec-001")
            .scenario_type("build")
            .add_invariant(invariant)
            .add_step(step)
            .build()
            .expect("valid spec");

        assert_eq!(spec.spec_id(), "spec-001");
        assert_eq!(spec.scenario_type(), "build");
        assert_eq!(spec.invariants().len(), 1);
        assert_eq!(spec.steps().len(), 1);
    }

    #[test]
    fn test_spec_with_only_invariants() {
        let invariant = create_test_invariant("inv-001");

        let spec = AatSpecBuilder::new("spec-001")
            .scenario_type("build")
            .add_invariant(invariant)
            .build()
            .expect("valid spec");

        assert!(spec.validate().is_ok());
        assert_eq!(spec.invariants().len(), 1);
        assert!(spec.steps().is_empty());
    }

    #[test]
    fn test_spec_missing_scenario_type() {
        let invariant = create_test_invariant("inv-001");

        let result = AatSpecBuilder::new("spec-001")
            .add_invariant(invariant)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::MissingField("scenario_type"))
        ));
    }

    #[test]
    fn test_spec_no_invariants_rejected() {
        // Step-only spec should be rejected
        let step = create_test_step("step-001");

        let result = AatSpecBuilder::new("spec-001")
            .scenario_type("build")
            .add_step(step)
            .build();

        assert!(matches!(result, Err(AatSpecError::NoInvariants)));
    }

    #[test]
    fn test_spec_validate_no_invariants() {
        // Create spec with no invariants (bypassing builder validation)
        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants: vec![],
            steps: vec![],
        };

        let result = spec.validate();
        assert!(matches!(result, Err(AatSpecError::NoInvariants)));
    }

    #[test]
    fn test_spec_non_observational_step_rejected() {
        let invariant = create_test_invariant("inv-001");

        // Create a non-observational step
        let non_obs_step = AatStep {
            step_id: "step-001".to_string(),
            action: "Test".to_string(),
            observational: false,
        };

        // Create spec bypassing builder to test validate()
        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants: vec![invariant],
            steps: vec![non_obs_step],
        };

        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::StepNotObservational { step_id }) if step_id == "step-001"
        ));
    }

    #[test]
    fn test_spec_duplicate_invariant_id_rejected() {
        let inv1 = create_test_invariant("inv-001");
        let inv2 = create_test_invariant("inv-001"); // Duplicate ID

        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants: vec![inv1, inv2],
            steps: vec![],
        };

        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::DuplicateInvariantId { invariant_id }) if invariant_id == "inv-001"
        ));
    }

    #[test]
    fn test_spec_duplicate_step_id_rejected() {
        let invariant = create_test_invariant("inv-001");
        let step1 = create_test_step("step-001");
        let step2 = create_test_step("step-001"); // Duplicate ID

        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants: vec![invariant],
            steps: vec![step1, step2],
        };

        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::DuplicateStepId { step_id }) if step_id == "step-001"
        ));
    }

    #[test]
    fn test_spec_too_many_invariants() {
        let invariants: Vec<Invariant> = (0..=MAX_INVARIANTS)
            .map(|i| create_test_invariant(&format!("inv-{i:04}")))
            .collect();

        let result = AatSpecBuilder::new("spec-001")
            .scenario_type("build")
            .invariants(invariants)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::CollectionTooLarge {
                field: "invariants",
                ..
            })
        ));
    }

    #[test]
    fn test_spec_too_many_steps() {
        let invariant = create_test_invariant("inv-001");
        let steps: Vec<AatStep> = (0..=MAX_STEPS)
            .map(|i| create_test_step(&format!("step-{i:04}")))
            .collect();

        let result = AatSpecBuilder::new("spec-001")
            .scenario_type("build")
            .add_invariant(invariant)
            .steps(steps)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::CollectionTooLarge { field: "steps", .. })
        ));
    }

    #[test]
    fn test_spec_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);
        let invariant = create_test_invariant("inv-001");

        let result = AatSpecBuilder::new(long_id)
            .scenario_type("build")
            .add_invariant(invariant)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "spec_id",
                ..
            })
        ));
    }

    #[test]
    fn test_spec_scenario_type_too_long() {
        let long_type = "x".repeat(MAX_STRING_LENGTH + 1);
        let invariant = create_test_invariant("inv-001");

        let result = AatSpecBuilder::new("spec-001")
            .scenario_type(long_type)
            .add_invariant(invariant)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "scenario_type",
                ..
            })
        ));
    }

    #[test]
    fn test_spec_serde_roundtrip() {
        let invariant = create_test_invariant("inv-001");
        let step = create_test_step("step-001");

        let spec = AatSpecBuilder::new("spec-001")
            .scenario_type("build")
            .add_invariant(invariant)
            .add_step(step)
            .build()
            .expect("valid spec");

        let json = serde_json::to_string(&spec).expect("serialize");
        let deserialized: AatSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, deserialized);
    }

    // =========================================================================
    // Verifier Kind Integration Tests
    // =========================================================================

    #[test]
    fn test_invariant_exit_code_verifier() {
        let invariant = Invariant::builder("build-success")
            .statement("Build must exit with code 0")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid invariant");

        assert_eq!(invariant.verifier_kind(), VerifierKind::ExitCode);
        assert!(invariant.validate().is_ok());
    }

    #[test]
    fn test_invariant_structured_test_report_verifier() {
        let invariant = Invariant::builder("no-test-failures")
            .statement("No test failures allowed")
            .verifier_kind(VerifierKind::StructuredTestReport)
            .machine_predicate(Predicate::compare(
                Predicate::variable("failed_count"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid invariant");

        assert_eq!(
            invariant.verifier_kind(),
            VerifierKind::StructuredTestReport
        );
        assert!(invariant.validate().is_ok());
    }

    #[test]
    fn test_invariant_snapshot_diff_verifier() {
        let invariant = Invariant::builder("no-snapshot-changes")
            .statement("No snapshot changes or diff approved")
            .verifier_kind(VerifierKind::SnapshotDiff)
            .machine_predicate(Predicate::or(
                Predicate::compare(
                    Predicate::variable("changed_files_count"),
                    PredicateOp::Eq,
                    Predicate::literal(0),
                ),
                Predicate::variable("diff_approved"),
            ))
            .build()
            .expect("valid invariant");

        assert_eq!(invariant.verifier_kind(), VerifierKind::SnapshotDiff);
        assert!(invariant.validate().is_ok());
    }

    #[test]
    fn test_invariant_check_verifier() {
        use crate::fac::CheckResult;

        let invariant = Invariant::builder("invariant-satisfied")
            .statement("Invariant check must be satisfied")
            .verifier_kind(VerifierKind::InvariantCheck)
            .machine_predicate(Predicate::compare(
                Predicate::variable("check_result"),
                PredicateOp::Eq,
                Predicate::literal(CheckResult::Satisfied.as_i64()),
            ))
            .build()
            .expect("valid invariant");

        assert_eq!(invariant.verifier_kind(), VerifierKind::InvariantCheck);
        assert!(invariant.validate().is_ok());
    }

    // =========================================================================
    // Complex Predicate Tests
    // =========================================================================

    #[test]
    fn test_invariant_complex_predicate() {
        // (exit_code == 0) AND (failed_count == 0) AND NOT has_warnings
        let predicate = Predicate::and(
            Predicate::and(
                Predicate::compare(
                    Predicate::variable("exit_code"),
                    PredicateOp::Eq,
                    Predicate::literal(0),
                ),
                Predicate::compare(
                    Predicate::variable("failed_count"),
                    PredicateOp::Eq,
                    Predicate::literal(0),
                ),
            ),
            Predicate::negate(Predicate::variable("has_warnings")),
        );

        let invariant = Invariant::builder("clean-build")
            .statement("Clean build with no warnings or failures")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(predicate)
            .build()
            .expect("valid invariant");

        assert!(invariant.validate().is_ok());
    }

    #[test]
    fn test_invariant_predicate_validation_depth_exceeded() {
        // Build a deep predicate tree that exceeds MAX_PREDICATE_DEPTH
        fn build_deep(depth: usize) -> Predicate {
            if depth == 0 {
                Predicate::literal(1)
            } else {
                Predicate::negate(build_deep(depth - 1))
            }
        }

        // MAX_PREDICATE_DEPTH is 32, so 33 should fail
        let deep_predicate = build_deep(33);

        let result = Invariant::builder("deep-inv")
            .statement("Deep predicate")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(deep_predicate)
            .build();

        assert!(matches!(
            result,
            Err(AatSpecError::PredicateValidationFailed { .. })
        ));
    }

    // =========================================================================
    // Multiple Invariants and Steps
    // =========================================================================

    #[test]
    fn test_spec_multiple_invariants() {
        let inv1 = Invariant::builder("build-success")
            .statement("Build must succeed")
            .verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid invariant");

        let inv2 = Invariant::builder("no-test-failures")
            .statement("No test failures")
            .verifier_kind(VerifierKind::StructuredTestReport)
            .machine_predicate(Predicate::compare(
                Predicate::variable("failed_count"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid invariant");

        let spec = AatSpecBuilder::new("spec-001")
            .scenario_type("ci")
            .add_invariant(inv1)
            .add_invariant(inv2)
            .build()
            .expect("valid spec");

        assert_eq!(spec.invariants().len(), 2);
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_spec_multiple_steps() {
        let invariant = create_test_invariant("inv-001");

        let step1 = AatStep::builder("step-001")
            .action("Run cargo build")
            .observational(true)
            .build()
            .expect("valid step");

        let step2 = AatStep::builder("step-002")
            .action("Run cargo test")
            .observational(true)
            .build()
            .expect("valid step");

        let step3 = AatStep::builder("step-003")
            .action("Run cargo clippy")
            .observational(true)
            .build()
            .expect("valid step");

        let spec = AatSpecBuilder::new("spec-001")
            .scenario_type("ci")
            .add_invariant(invariant)
            .add_step(step1)
            .add_step(step2)
            .add_step(step3)
            .build()
            .expect("valid spec");

        assert_eq!(spec.steps().len(), 3);
        assert!(spec.validate().is_ok());
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = AatSpecError::NoInvariants;
        assert!(err.to_string().contains("at least one invariant"));

        let err = AatSpecError::MissingMachinePredicate {
            invariant_id: "inv-001".to_string(),
        };
        assert!(err.to_string().contains("inv-001"));
        assert!(err.to_string().contains("machine_predicate"));

        let err = AatSpecError::StepNotObservational {
            step_id: "step-001".to_string(),
        };
        assert!(err.to_string().contains("step-001"));
        assert!(err.to_string().contains("observational"));

        let err = AatSpecError::DuplicateInvariantId {
            invariant_id: "inv-001".to_string(),
        };
        assert!(err.to_string().contains("duplicate"));
        assert!(err.to_string().contains("inv-001"));
    }

    // =========================================================================
    // Deserialization Bypass Defense Tests
    // =========================================================================

    /// Test that `validate()` catches resource limit violations on deserialized
    /// data. This defends against attackers bypassing builder validation
    /// via direct JSON/YAML deserialization.
    #[test]
    fn test_validate_catches_deserialized_too_many_invariants() {
        // Create a spec with too many invariants via deserialization (simulated)
        let invariants: Vec<Invariant> = (0..=MAX_INVARIANTS)
            .map(|i| create_test_invariant(&format!("inv-{i:04}")))
            .collect();

        // Construct the spec directly (as if deserialized), bypassing the builder
        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants,
            steps: vec![],
        };

        // validate() must catch the resource limit violation
        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::CollectionTooLarge {
                field: "invariants",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_catches_deserialized_too_many_steps() {
        let invariants = vec![create_test_invariant("inv-001")];
        let steps: Vec<AatStep> = (0..=MAX_STEPS)
            .map(|i| create_test_step(&format!("step-{i:04}")))
            .collect();

        // Construct the spec directly (as if deserialized), bypassing the builder
        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants,
            steps,
        };

        // validate() must catch the resource limit violation
        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::CollectionTooLarge { field: "steps", .. })
        ));
    }

    #[test]
    fn test_validate_catches_deserialized_long_spec_id() {
        let invariants = vec![create_test_invariant("inv-001")];

        // Construct the spec directly with overly long spec_id
        let spec = AatSpec {
            spec_id: "x".repeat(MAX_STRING_LENGTH + 1),
            scenario_type: "build".to_string(),
            invariants,
            steps: vec![],
        };

        // validate() must catch the string length violation
        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "spec_id",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_catches_deserialized_long_invariant_id() {
        // Construct an invariant directly with overly long ID
        let long_id_invariant = Invariant {
            invariant_id: "x".repeat(MAX_STRING_LENGTH + 1),
            statement: "Test".to_string(),
            verifier_kind: VerifierKind::ExitCode,
            machine_predicate: Predicate::literal(0),
        };

        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants: vec![long_id_invariant],
            steps: vec![],
        };

        // validate() must catch the string length violation
        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "invariant_id",
                ..
            })
        ));
    }

    #[test]
    fn test_validate_catches_deserialized_long_step_action() {
        let invariants = vec![create_test_invariant("inv-001")];

        // Construct a step directly with overly long action
        let long_action_step = AatStep {
            step_id: "step-001".to_string(),
            action: "x".repeat(MAX_ACTION_LENGTH + 1),
            observational: true,
        };

        let spec = AatSpec {
            spec_id: "spec-001".to_string(),
            scenario_type: "build".to_string(),
            invariants,
            steps: vec![long_action_step],
        };

        // validate() must catch the string length violation
        let result = spec.validate();
        assert!(matches!(
            result,
            Err(AatSpecError::StringTooLong {
                field: "action",
                ..
            })
        ));
    }
}
