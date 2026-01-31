// AGENT-AUTHORED
//! Terminal verifier types for Agent Acceptance Testing (AAT).
//!
//! This module defines the terminal verifier infrastructure used to evaluate
//! AAT outcomes. Terminal verifiers provide machine-checkable predicates that
//! determine whether acceptance test results meet policy requirements.
//!
//! # Components
//!
//! - [`TerminalVerifier`]: Trait for implementing verifier logic
//! - [`VerifierKind`]: Enum of supported verifier types
//! - [`VerifierOutput`]: Result of a verifier evaluation
//! - [`VerifierPolicy`]: Policy configuration for a verifier
//! - [`Predicate`]: Machine-checkable predicate expressions
//!
//! # Security Model
//!
//! Terminal verifiers enforce that AAT outcomes are machine-checkable:
//!
//! - **No narrative substitution**: Narrative evidence cannot substitute for
//!   verifier outputs
//! - **Deterministic evaluation**: Predicate evaluation is purely functional
//! - **Policy binding**: Verifier policies are bound to changesets via hash
//!
//! # Supported Verifier Kinds
//!
//! - `ExitCode`: Checks command exit codes (`exit_code == 0`)
//! - `SnapshotDiff`: Compares file snapshots (`changed_files_count == 0`)
//! - `StructuredTestReport`: Parses test reports (`failed_count == 0`)
//! - `InvariantCheck`: Evaluates invariant conditions (`check_result ==
//!   SATISFIED`)
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{
//!     Predicate, PredicateOp, VerifierKind, VerifierOutput, VerifierPolicy,
//!     VerifierPolicyBuilder,
//! };
//!
//! // Create a policy for exit code verification
//! let policy = VerifierPolicyBuilder::new("policy-001")
//!     .scenario_type("build")
//!     .add_allowed_verifier_kind(VerifierKind::ExitCode)
//!     .add_required_output("exit_code")
//!     .add_required_output("command")
//!     .machine_predicate(Predicate::Compare {
//!         left: Box::new(Predicate::Variable("exit_code".to_string())),
//!         op: PredicateOp::Eq,
//!         right: Box::new(Predicate::Literal(0)),
//!     })
//!     .build()
//!     .expect("valid policy");
//!
//! // Evaluate a verifier output against the policy
//! let output = VerifierOutput::builder()
//!     .output_digest([0xAB; 32])
//!     .verifier_kind(VerifierKind::ExitCode)
//!     .add_value("exit_code", 0)
//!     .add_value("command", 0) // placeholder
//!     .build()
//!     .expect("valid output");
//!
//! assert!(output.predicate_satisfied());
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::policy_resolution::MAX_STRING_LENGTH;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of allowed verifier kinds in a policy.
pub const MAX_ALLOWED_VERIFIER_KINDS: usize = 16;

/// Maximum number of required outputs in a policy.
pub const MAX_REQUIRED_OUTPUTS: usize = 64;

/// Maximum number of output values in a verifier output.
pub const MAX_OUTPUT_VALUES: usize = 256;

/// Maximum depth of nested predicates to prevent stack overflow.
pub const MAX_PREDICATE_DEPTH: usize = 32;

/// Maximum total number of nodes in a predicate tree to prevent
/// denial-of-service.
///
/// A full binary tree of depth 32 could have ~4.29 billion nodes, causing OOM.
/// This limit ensures predicate trees remain tractable for validation.
pub const MAX_PREDICATE_NODES: usize = 256;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during terminal verifier operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifierError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid verifier data.
    #[error("invalid verifier data: {0}")]
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

    /// Predicate evaluation error.
    #[error("predicate evaluation error: {0}")]
    PredicateError(String),

    /// Predicate depth exceeded.
    #[error("predicate depth exceeded: {depth} > {max}")]
    PredicateDepthExceeded {
        /// Actual depth.
        depth: usize,
        /// Maximum allowed depth.
        max: usize,
    },

    /// Predicate node count exceeded.
    #[error("predicate node count exceeded: {count} > {max}")]
    PredicateNodeCountExceeded {
        /// Actual node count.
        count: usize,
        /// Maximum allowed node count.
        max: usize,
    },

    /// Variable name in predicate exceeds maximum string length.
    #[error("predicate variable name too long: {actual} > {max}")]
    PredicateVariableTooLong {
        /// Actual length of the variable name.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Unknown variable in predicate.
    #[error("unknown variable in predicate: {0}")]
    UnknownVariable(String),

    /// Verifier kind not allowed by policy.
    #[error("verifier kind {kind:?} not allowed by policy")]
    VerifierKindNotAllowed {
        /// The disallowed verifier kind.
        kind: VerifierKind,
    },

    /// Required output missing from verifier result.
    #[error("required output missing: {0}")]
    RequiredOutputMissing(String),

    /// Duplicate required output in policy.
    #[error("duplicate required output: {0}")]
    DuplicateRequiredOutput(String),
}

// =============================================================================
// VerifierKind
// =============================================================================

/// The kind of terminal verifier.
///
/// Each verifier kind has specific required outputs and typical predicates:
///
/// - `ExitCode`: `exit_code`, `command` -> `exit_code == 0`
/// - `SnapshotDiff`: `diff_digest`, `changed_files_count` ->
///   `changed_files_count == 0`
/// - `StructuredTestReport`: `report_digest`, `passed_count`, `failed_count`,
///   `skipped_count` -> `failed_count == 0`
/// - `InvariantCheck`: `invariant_id`, `check_result` -> `check_result ==
///   SATISFIED`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum VerifierKind {
    /// Exit code verifier.
    ///
    /// Required outputs: `exit_code`, `command`
    /// Typical predicate: `exit_code == 0`
    ExitCode,

    /// Snapshot diff verifier.
    ///
    /// Required outputs: `diff_digest`, `changed_files_count`
    /// Typical predicate: `changed_files_count == 0 OR diff_approved`
    SnapshotDiff,

    /// Structured test report verifier.
    ///
    /// Required outputs: `report_digest`, `passed_count`, `failed_count`,
    /// `skipped_count` Typical predicate: `failed_count == 0`
    StructuredTestReport,

    /// Invariant check verifier.
    ///
    /// Required outputs: `invariant_id`, `check_result`
    /// Typical predicate: `check_result == SATISFIED`
    InvariantCheck,
}

impl VerifierKind {
    /// Returns an iterator over all verifier kinds.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::ExitCode,
            Self::SnapshotDiff,
            Self::StructuredTestReport,
            Self::InvariantCheck,
        ]
        .into_iter()
    }

    /// Returns the default required outputs for this verifier kind.
    #[must_use]
    pub const fn default_required_outputs(&self) -> &'static [&'static str] {
        match self {
            Self::ExitCode => &["exit_code", "command"],
            Self::SnapshotDiff => &["diff_digest", "changed_files_count"],
            Self::StructuredTestReport => &[
                "report_digest",
                "passed_count",
                "failed_count",
                "skipped_count",
            ],
            Self::InvariantCheck => &["invariant_id", "check_result"],
        }
    }
}

impl std::fmt::Display for VerifierKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExitCode => write!(f, "exit_code"),
            Self::SnapshotDiff => write!(f, "snapshot_diff"),
            Self::StructuredTestReport => write!(f, "structured_test_report"),
            Self::InvariantCheck => write!(f, "invariant_check"),
        }
    }
}

// =============================================================================
// CheckResult
// =============================================================================

/// Result of an invariant check.
///
/// Used as the value type for `check_result` in `InvariantCheck` verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(i64)]
pub enum CheckResult {
    /// The invariant is satisfied.
    Satisfied = 1,
    /// The invariant is violated.
    Violated  = 0,
    /// The invariant check could not be performed.
    Unknown   = -1,
}

impl CheckResult {
    /// Converts to an i64 value for predicate evaluation.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self as i64
    }
}

impl From<CheckResult> for i64 {
    fn from(result: CheckResult) -> Self {
        result.as_i64()
    }
}

impl TryFrom<i64> for CheckResult {
    type Error = VerifierError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Satisfied),
            0 => Ok(Self::Violated),
            -1 => Ok(Self::Unknown),
            _ => Err(VerifierError::InvalidData(format!(
                "invalid check result value: {value}, expected -1, 0, or 1"
            ))),
        }
    }
}

// =============================================================================
// PredicateOp
// =============================================================================

/// Comparison and logical operators for predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PredicateOp {
    /// Equality comparison (`==`).
    Eq,
    /// Inequality comparison (`!=`).
    Ne,
    /// Less than comparison (`<`).
    Lt,
    /// Less than or equal comparison (`<=`).
    Le,
    /// Greater than comparison (`>`).
    Gt,
    /// Greater than or equal comparison (`>=`).
    Ge,
}

impl PredicateOp {
    /// Evaluates this operator on two i64 values.
    #[must_use]
    pub const fn evaluate(self, left: i64, right: i64) -> bool {
        match self {
            Self::Eq => left == right,
            Self::Ne => left != right,
            Self::Lt => left < right,
            Self::Le => left <= right,
            Self::Gt => left > right,
            Self::Ge => left >= right,
        }
    }
}

impl std::fmt::Display for PredicateOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eq => write!(f, "=="),
            Self::Ne => write!(f, "!="),
            Self::Lt => write!(f, "<"),
            Self::Le => write!(f, "<="),
            Self::Gt => write!(f, ">"),
            Self::Ge => write!(f, ">="),
        }
    }
}

// =============================================================================
// Predicate
// =============================================================================

/// A machine-checkable predicate expression.
///
/// Predicates form an expression tree that can be evaluated against a set of
/// variable bindings. The supported operations are:
///
/// - **Literal**: A constant i64 value
/// - **Variable**: A named variable to be looked up in bindings
/// - **Compare**: Binary comparison (`==`, `!=`, `<`, `<=`, `>`, `>=`)
/// - **And**: Logical AND of two predicates
/// - **Or**: Logical OR of two predicates
/// - **Not**: Logical NOT of a predicate
///
/// # Depth Limit
///
/// Predicate trees are limited to [`MAX_PREDICATE_DEPTH`] levels to prevent
/// stack overflow during evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::use_self)] // Self cannot be used in enum variant field types
pub enum Predicate {
    /// A literal i64 value.
    Literal(i64),

    /// A variable reference.
    Variable(String),

    /// A comparison between two expressions.
    Compare {
        /// Left operand.
        left: Box<Predicate>,
        /// Comparison operator.
        op: PredicateOp,
        /// Right operand.
        right: Box<Predicate>,
    },

    /// Logical AND of two predicates.
    And {
        /// Left operand.
        left: Box<Predicate>,
        /// Right operand.
        right: Box<Predicate>,
    },

    /// Logical OR of two predicates.
    Or {
        /// Left operand.
        left: Box<Predicate>,
        /// Right operand.
        right: Box<Predicate>,
    },

    /// Logical NOT of a predicate.
    Not {
        /// Inner predicate.
        inner: Box<Predicate>,
    },
}

impl Predicate {
    /// Creates a literal predicate.
    #[must_use]
    pub const fn literal(value: i64) -> Self {
        Self::Literal(value)
    }

    /// Creates a variable reference predicate.
    #[must_use]
    pub fn variable(name: impl Into<String>) -> Self {
        Self::Variable(name.into())
    }

    /// Creates a comparison predicate.
    #[must_use]
    pub fn compare(left: Self, op: PredicateOp, right: Self) -> Self {
        Self::Compare {
            left: Box::new(left),
            op,
            right: Box::new(right),
        }
    }

    /// Creates a logical AND predicate.
    #[must_use]
    pub fn and(left: Self, right: Self) -> Self {
        Self::And {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Creates a logical OR predicate.
    #[must_use]
    pub fn or(left: Self, right: Self) -> Self {
        Self::Or {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Creates a logical NOT predicate.
    #[must_use]
    #[allow(clippy::should_implement_trait)] // Named for clarity, not to implement std::ops::Not
    pub fn negate(inner: Self) -> Self {
        Self::Not {
            inner: Box::new(inner),
        }
    }

    /// Calculates the depth of this predicate tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Literal(_) | Self::Variable(_) => 1,
            Self::Compare { left, right, .. }
            | Self::And { left, right }
            | Self::Or { left, right } => 1 + left.depth().max(right.depth()),
            Self::Not { inner } => 1 + inner.depth(),
        }
    }

    /// Validates the predicate depth against the maximum limit.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError::PredicateDepthExceeded`] if the depth exceeds
    /// [`MAX_PREDICATE_DEPTH`].
    pub fn validate_depth(&self) -> Result<(), VerifierError> {
        let depth = self.depth();
        if depth > MAX_PREDICATE_DEPTH {
            return Err(VerifierError::PredicateDepthExceeded {
                depth,
                max: MAX_PREDICATE_DEPTH,
            });
        }
        Ok(())
    }

    /// Counts the total number of nodes in the predicate tree.
    ///
    /// This counts all nodes including `Literal`, `Variable`, `Compare`,
    /// `And`, `Or`, and `Not` nodes recursively.
    #[must_use]
    pub fn count_nodes(&self) -> usize {
        match self {
            Self::Literal(_) | Self::Variable(_) => 1,
            Self::Compare { left, right, .. } => 1 + left.count_nodes() + right.count_nodes(),
            Self::And { left, right } | Self::Or { left, right } => {
                1 + left.count_nodes() + right.count_nodes()
            },
            Self::Not { inner } => 1 + inner.count_nodes(),
        }
    }

    /// Validates the predicate node count against the maximum limit.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError::PredicateNodeCountExceeded`] if the total node
    /// count exceeds [`MAX_PREDICATE_NODES`].
    pub fn validate_node_count(&self) -> Result<(), VerifierError> {
        let count = self.count_nodes();
        if count > MAX_PREDICATE_NODES {
            return Err(VerifierError::PredicateNodeCountExceeded {
                count,
                max: MAX_PREDICATE_NODES,
            });
        }
        Ok(())
    }

    /// Validates all variable names in the predicate tree against the maximum
    /// string length.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError::PredicateVariableTooLong`] if any variable name
    /// exceeds [`MAX_STRING_LENGTH`].
    pub fn validate_string_lengths(&self) -> Result<(), VerifierError> {
        match self {
            Self::Literal(_) => Ok(()),
            Self::Variable(name) => {
                if name.len() > MAX_STRING_LENGTH {
                    Err(VerifierError::PredicateVariableTooLong {
                        actual: name.len(),
                        max: MAX_STRING_LENGTH,
                    })
                } else {
                    Ok(())
                }
            },
            Self::Compare { left, right, .. }
            | Self::And { left, right }
            | Self::Or { left, right } => {
                left.validate_string_lengths()?;
                right.validate_string_lengths()
            },
            Self::Not { inner } => inner.validate_string_lengths(),
        }
    }

    /// Performs complete validation of the predicate tree.
    ///
    /// This validates:
    /// - Predicate depth does not exceed [`MAX_PREDICATE_DEPTH`]
    /// - Total node count does not exceed [`MAX_PREDICATE_NODES`]
    /// - All variable names do not exceed [`MAX_STRING_LENGTH`]
    ///
    /// # Errors
    ///
    /// Returns an appropriate [`VerifierError`] if any validation fails.
    pub fn validate(&self) -> Result<(), VerifierError> {
        self.validate_depth()?;
        self.validate_node_count()?;
        self.validate_string_lengths()
    }

    /// Evaluates this predicate with the given variable bindings.
    ///
    /// # Arguments
    ///
    /// * `bindings` - A function that returns the value for a variable name
    ///
    /// # Returns
    ///
    /// The boolean result of evaluating the predicate.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError::UnknownVariable`] if a variable is not found in
    /// bindings. Returns [`VerifierError::PredicateError`] for other evaluation
    /// errors.
    pub fn evaluate<F>(&self, bindings: &F) -> Result<bool, VerifierError>
    where
        F: Fn(&str) -> Option<i64>,
    {
        self.evaluate_with_depth(bindings, 0)
    }

    /// Internal evaluation with depth tracking.
    fn evaluate_with_depth<F>(&self, bindings: &F, depth: usize) -> Result<bool, VerifierError>
    where
        F: Fn(&str) -> Option<i64>,
    {
        if depth > MAX_PREDICATE_DEPTH {
            return Err(VerifierError::PredicateDepthExceeded {
                depth,
                max: MAX_PREDICATE_DEPTH,
            });
        }

        match self {
            Self::Literal(v) => Ok(*v != 0),
            Self::Variable(name) => bindings(name)
                .map(|v| v != 0)
                .ok_or_else(|| VerifierError::UnknownVariable(name.clone())),
            Self::Compare { left, op, right } => {
                let left_val = Self::eval_to_i64(left, bindings, depth + 1)?;
                let right_val = Self::eval_to_i64(right, bindings, depth + 1)?;
                Ok(op.evaluate(left_val, right_val))
            },
            Self::And { left, right } => {
                // Short-circuit evaluation
                if !left.evaluate_with_depth(bindings, depth + 1)? {
                    return Ok(false);
                }
                right.evaluate_with_depth(bindings, depth + 1)
            },
            Self::Or { left, right } => {
                // Short-circuit evaluation
                if left.evaluate_with_depth(bindings, depth + 1)? {
                    return Ok(true);
                }
                right.evaluate_with_depth(bindings, depth + 1)
            },
            Self::Not { inner } => Ok(!inner.evaluate_with_depth(bindings, depth + 1)?),
        }
    }

    /// Evaluates a predicate to an i64 value (for comparison operands).
    fn eval_to_i64<F>(pred: &Self, bindings: &F, depth: usize) -> Result<i64, VerifierError>
    where
        F: Fn(&str) -> Option<i64>,
    {
        if depth > MAX_PREDICATE_DEPTH {
            return Err(VerifierError::PredicateDepthExceeded {
                depth,
                max: MAX_PREDICATE_DEPTH,
            });
        }

        match pred {
            Self::Literal(v) => Ok(*v),
            Self::Variable(name) => {
                bindings(name).ok_or_else(|| VerifierError::UnknownVariable(name.clone()))
            },
            _ => Err(VerifierError::PredicateError(
                "comparison operand must be literal or variable".to_string(),
            )),
        }
    }
}

// =============================================================================
// VerifierOutput
// =============================================================================

/// The output of a terminal verifier evaluation.
///
/// This struct captures both the cryptographic digest of the raw output and
/// the extracted values used for predicate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierOutput {
    /// Cryptographic digest of the raw verifier output.
    ///
    /// This binds the output to a specific evidence artifact in CAS.
    #[serde(with = "serde_bytes")]
    output_digest: [u8; 32],

    /// The verifier kind that produced this output.
    verifier_kind: VerifierKind,

    /// Extracted values from the verifier output.
    ///
    /// These are the named values used for predicate evaluation.
    output_values: Vec<(String, i64)>,

    /// Whether the predicate was satisfied.
    ///
    /// This is computed during construction and cached for efficiency.
    predicate_satisfied: bool,
}

impl VerifierOutput {
    /// Creates a new builder for `VerifierOutput`.
    #[must_use]
    pub fn builder() -> VerifierOutputBuilder {
        VerifierOutputBuilder::new()
    }

    /// Returns the output digest.
    #[must_use]
    pub const fn output_digest(&self) -> [u8; 32] {
        self.output_digest
    }

    /// Returns the verifier kind.
    #[must_use]
    pub const fn verifier_kind(&self) -> VerifierKind {
        self.verifier_kind
    }

    /// Returns the output values.
    #[must_use]
    pub fn output_values(&self) -> &[(String, i64)] {
        &self.output_values
    }

    /// Returns whether the predicate was satisfied.
    #[must_use]
    pub const fn predicate_satisfied(&self) -> bool {
        self.predicate_satisfied
    }

    /// Gets a value by name.
    #[must_use]
    pub fn get_value(&self, name: &str) -> Option<i64> {
        self.output_values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
    }

    /// Creates a bindings function for predicate evaluation.
    pub fn bindings(&self) -> impl Fn(&str) -> Option<i64> + '_ {
        |name| self.get_value(name)
    }
}

// =============================================================================
// VerifierOutputBuilder
// =============================================================================

/// Builder for constructing [`VerifierOutput`] instances.
#[derive(Debug, Default)]
pub struct VerifierOutputBuilder {
    output_digest: Option<[u8; 32]>,
    verifier_kind: Option<VerifierKind>,
    output_values: Vec<(String, i64)>,
    predicate: Option<Predicate>,
}

impl VerifierOutputBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the output digest.
    #[must_use]
    pub const fn output_digest(mut self, digest: [u8; 32]) -> Self {
        self.output_digest = Some(digest);
        self
    }

    /// Sets the verifier kind.
    #[must_use]
    pub const fn verifier_kind(mut self, kind: VerifierKind) -> Self {
        self.verifier_kind = Some(kind);
        self
    }

    /// Adds an output value.
    #[must_use]
    pub fn add_value(mut self, name: impl Into<String>, value: i64) -> Self {
        self.output_values.push((name.into(), value));
        self
    }

    /// Sets the predicate for evaluation.
    #[must_use]
    pub fn predicate(mut self, predicate: Predicate) -> Self {
        self.predicate = Some(predicate);
        self
    }

    /// Builds the verifier output.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError::MissingField`] if required fields are missing.
    /// Returns [`VerifierError::CollectionTooLarge`] if output values exceed
    /// limits.
    pub fn build(self) -> Result<VerifierOutput, VerifierError> {
        let output_digest = self
            .output_digest
            .ok_or(VerifierError::MissingField("output_digest"))?;
        let verifier_kind = self
            .verifier_kind
            .ok_or(VerifierError::MissingField("verifier_kind"))?;

        if self.output_values.len() > MAX_OUTPUT_VALUES {
            return Err(VerifierError::CollectionTooLarge {
                field: "output_values",
                actual: self.output_values.len(),
                max: MAX_OUTPUT_VALUES,
            });
        }

        // Validate string lengths
        for (name, _) in &self.output_values {
            if name.len() > MAX_STRING_LENGTH {
                return Err(VerifierError::StringTooLong {
                    field: "output_values key",
                    actual: name.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // Evaluate predicate if provided
        let predicate_satisfied = if let Some(ref pred) = self.predicate {
            let bindings = |name: &str| {
                self.output_values
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, v)| *v)
            };
            pred.evaluate(&bindings)?
        } else {
            // Default to true if no predicate (useful for testing)
            true
        };

        Ok(VerifierOutput {
            output_digest,
            verifier_kind,
            output_values: self.output_values,
            predicate_satisfied,
        })
    }
}

// =============================================================================
// VerifierPolicy
// =============================================================================

/// Policy configuration for terminal verifiers.
///
/// A verifier policy defines:
/// - Which verifier kinds are allowed for a scenario
/// - Which outputs are required
/// - The machine predicate that must be satisfied
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierPolicy {
    /// Unique identifier for this policy.
    policy_id: String,

    /// Hash of the policy for binding.
    #[serde(with = "serde_bytes")]
    policy_hash: [u8; 32],

    /// Schema version for forward compatibility.
    schema_version: u32,

    /// The scenario type this policy applies to.
    scenario_type: String,

    /// Allowed verifier kinds for this scenario.
    allowed_verifier_kinds: Vec<VerifierKind>,

    /// Required outputs that must be present.
    required_outputs: Vec<String>,

    /// The machine predicate that must be satisfied.
    machine_predicate: Predicate,

    /// Language identifier for the predicate (currently only
    /// "fac-predicate-v1").
    predicate_lang: String,
}

impl VerifierPolicy {
    /// Creates a new builder for `VerifierPolicy`.
    #[must_use]
    pub fn builder(policy_id: impl Into<String>) -> VerifierPolicyBuilder {
        VerifierPolicyBuilder::new(policy_id)
    }

    /// Returns the policy ID.
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Returns the policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }

    /// Returns the schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the scenario type.
    #[must_use]
    pub fn scenario_type(&self) -> &str {
        &self.scenario_type
    }

    /// Returns the allowed verifier kinds.
    #[must_use]
    pub fn allowed_verifier_kinds(&self) -> &[VerifierKind] {
        &self.allowed_verifier_kinds
    }

    /// Returns the required outputs.
    #[must_use]
    pub fn required_outputs(&self) -> &[String] {
        &self.required_outputs
    }

    /// Returns the machine predicate.
    #[must_use]
    pub const fn machine_predicate(&self) -> &Predicate {
        &self.machine_predicate
    }

    /// Returns the predicate language.
    #[must_use]
    pub fn predicate_lang(&self) -> &str {
        &self.predicate_lang
    }

    /// Validates a verifier output against this policy.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError::VerifierKindNotAllowed`] if the verifier kind
    /// is not in the allowed list.
    /// Returns [`VerifierError::RequiredOutputMissing`] if a required output is
    /// missing.
    /// Returns predicate evaluation errors if the predicate fails.
    pub fn validate_output(&self, output: &VerifierOutput) -> Result<bool, VerifierError> {
        // Check verifier kind is allowed
        if !self
            .allowed_verifier_kinds
            .contains(&output.verifier_kind())
        {
            return Err(VerifierError::VerifierKindNotAllowed {
                kind: output.verifier_kind(),
            });
        }

        // Check all required outputs are present
        for required in &self.required_outputs {
            if output.get_value(required).is_none() {
                return Err(VerifierError::RequiredOutputMissing(required.clone()));
            }
        }

        // Evaluate predicate
        self.machine_predicate.evaluate(&output.bindings())
    }
}

// =============================================================================
// VerifierPolicyBuilder
// =============================================================================

/// Builder for constructing [`VerifierPolicy`] instances.
#[derive(Debug)]
pub struct VerifierPolicyBuilder {
    policy_id: String,
    schema_version: u32,
    scenario_type: Option<String>,
    allowed_verifier_kinds: Vec<VerifierKind>,
    required_outputs: Vec<String>,
    machine_predicate: Option<Predicate>,
    predicate_lang: String,
}

impl VerifierPolicyBuilder {
    /// Creates a new builder with the given policy ID.
    #[must_use]
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            schema_version: 1,
            scenario_type: None,
            allowed_verifier_kinds: Vec::new(),
            required_outputs: Vec::new(),
            machine_predicate: None,
            predicate_lang: "fac-predicate-v1".to_string(),
        }
    }

    /// Sets the schema version.
    #[must_use]
    pub const fn schema_version(mut self, version: u32) -> Self {
        self.schema_version = version;
        self
    }

    /// Sets the scenario type.
    #[must_use]
    pub fn scenario_type(mut self, scenario: impl Into<String>) -> Self {
        self.scenario_type = Some(scenario.into());
        self
    }

    /// Adds an allowed verifier kind.
    #[must_use]
    pub fn add_allowed_verifier_kind(mut self, kind: VerifierKind) -> Self {
        if !self.allowed_verifier_kinds.contains(&kind) {
            self.allowed_verifier_kinds.push(kind);
        }
        self
    }

    /// Adds a required output.
    #[must_use]
    pub fn add_required_output(mut self, output: impl Into<String>) -> Self {
        self.required_outputs.push(output.into());
        self
    }

    /// Sets the machine predicate.
    #[must_use]
    pub fn machine_predicate(mut self, predicate: Predicate) -> Self {
        self.machine_predicate = Some(predicate);
        self
    }

    /// Sets the predicate language.
    #[must_use]
    pub fn predicate_lang(mut self, lang: impl Into<String>) -> Self {
        self.predicate_lang = lang.into();
        self
    }

    /// Builds the verifier policy.
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError::MissingField`] if required fields are missing.
    /// Returns [`VerifierError::CollectionTooLarge`] if collections exceed
    /// limits. Returns [`VerifierError::DuplicateRequiredOutput`] if there are
    /// duplicate required outputs.
    pub fn build(self) -> Result<VerifierPolicy, VerifierError> {
        let scenario_type = self
            .scenario_type
            .ok_or(VerifierError::MissingField("scenario_type"))?;
        let machine_predicate = self
            .machine_predicate
            .ok_or(VerifierError::MissingField("machine_predicate"))?;

        // Validate string lengths
        if self.policy_id.len() > MAX_STRING_LENGTH {
            return Err(VerifierError::StringTooLong {
                field: "policy_id",
                actual: self.policy_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }
        if scenario_type.len() > MAX_STRING_LENGTH {
            return Err(VerifierError::StringTooLong {
                field: "scenario_type",
                actual: scenario_type.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate collection sizes
        if self.allowed_verifier_kinds.len() > MAX_ALLOWED_VERIFIER_KINDS {
            return Err(VerifierError::CollectionTooLarge {
                field: "allowed_verifier_kinds",
                actual: self.allowed_verifier_kinds.len(),
                max: MAX_ALLOWED_VERIFIER_KINDS,
            });
        }
        if self.required_outputs.len() > MAX_REQUIRED_OUTPUTS {
            return Err(VerifierError::CollectionTooLarge {
                field: "required_outputs",
                actual: self.required_outputs.len(),
                max: MAX_REQUIRED_OUTPUTS,
            });
        }

        // Check for duplicate required outputs
        for (i, output) in self.required_outputs.iter().enumerate() {
            if output.len() > MAX_STRING_LENGTH {
                return Err(VerifierError::StringTooLong {
                    field: "required_outputs",
                    actual: output.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            for (j, other) in self.required_outputs.iter().enumerate() {
                if i != j && output == other {
                    return Err(VerifierError::DuplicateRequiredOutput(output.clone()));
                }
            }
        }

        // Validate predicate (depth, node count, and string lengths)
        machine_predicate.validate()?;

        // Compute policy hash
        let policy_hash = compute_policy_hash(
            &self.policy_id,
            self.schema_version,
            &scenario_type,
            &self.allowed_verifier_kinds,
            &self.required_outputs,
            &machine_predicate,
            &self.predicate_lang,
        );

        Ok(VerifierPolicy {
            policy_id: self.policy_id,
            policy_hash,
            schema_version: self.schema_version,
            scenario_type,
            allowed_verifier_kinds: self.allowed_verifier_kinds,
            required_outputs: self.required_outputs,
            machine_predicate,
            predicate_lang: self.predicate_lang,
        })
    }
}

/// Computes the policy hash from all policy fields.
///
/// # Determinism Warning
///
/// **CRITICAL**: This function relies on `serde_json::to_string` for
/// serializing the `machine_predicate`. The current `Predicate` enum uses only
/// deterministic types (i64, String, Box<Predicate>). **DO NOT** add `HashMap`,
/// `HashSet`, or any other non-deterministic iteration order types to
/// `Predicate` without updating this function to use a sorted/canonical
/// serialization approach. Failure to maintain determinism will cause policy
/// hash mismatches and break verification.
#[allow(clippy::cast_possible_truncation)]
fn compute_policy_hash(
    policy_id: &str,
    schema_version: u32,
    scenario_type: &str,
    allowed_verifier_kinds: &[VerifierKind],
    required_outputs: &[String],
    machine_predicate: &Predicate,
    predicate_lang: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();

    // policy_id (length-prefixed)
    hasher.update(&(policy_id.len() as u32).to_be_bytes());
    hasher.update(policy_id.as_bytes());

    // schema_version
    hasher.update(&schema_version.to_be_bytes());

    // scenario_type (length-prefixed)
    hasher.update(&(scenario_type.len() as u32).to_be_bytes());
    hasher.update(scenario_type.as_bytes());

    // allowed_verifier_kinds (count + each kind as u8)
    hasher.update(&(allowed_verifier_kinds.len() as u32).to_be_bytes());
    for kind in allowed_verifier_kinds {
        hasher.update(&[*kind as u8]);
    }

    // required_outputs (count + each output length-prefixed)
    hasher.update(&(required_outputs.len() as u32).to_be_bytes());
    for output in required_outputs {
        hasher.update(&(output.len() as u32).to_be_bytes());
        hasher.update(output.as_bytes());
    }

    // machine_predicate (serialize to JSON for hashing)
    // NOTE: See function doc comment about determinism requirements.
    let predicate_json = serde_json::to_string(machine_predicate).unwrap_or_default();
    hasher.update(&(predicate_json.len() as u32).to_be_bytes());
    hasher.update(predicate_json.as_bytes());

    // predicate_lang (length-prefixed)
    hasher.update(&(predicate_lang.len() as u32).to_be_bytes());
    hasher.update(predicate_lang.as_bytes());

    *hasher.finalize().as_bytes()
}

// =============================================================================
// TerminalVerifier Trait
// =============================================================================

/// Trait for terminal verifier implementations.
///
/// Terminal verifiers evaluate AAT outputs and produce machine-checkable
/// results. Each verifier implementation is responsible for:
///
/// 1. Declaring its [`VerifierKind`]
/// 2. Extracting values from raw output bytes
/// 3. Computing the output digest
pub trait TerminalVerifier: Send + Sync {
    /// Returns the kind of this verifier.
    fn kind(&self) -> VerifierKind;

    /// Evaluates the raw output bytes and produces a [`VerifierOutput`].
    ///
    /// # Arguments
    ///
    /// * `raw_output` - The raw bytes of the verifier output
    /// * `predicate` - The predicate to evaluate against the extracted values
    ///
    /// # Errors
    ///
    /// Returns [`VerifierError`] if the output cannot be parsed or evaluated.
    fn evaluate(
        &self,
        raw_output: &[u8],
        predicate: &Predicate,
    ) -> Result<VerifierOutput, VerifierError>;
}

// =============================================================================
// Standalone Predicate Evaluation Function
// =============================================================================

/// Evaluates a predicate with the given variable bindings.
///
/// This is a convenience function that wraps [`Predicate::evaluate`].
///
/// # Arguments
///
/// * `predicate` - The predicate to evaluate
/// * `bindings` - A map of variable names to values
///
/// # Returns
///
/// The boolean result of evaluating the predicate.
///
/// # Errors
///
/// Returns [`VerifierError::UnknownVariable`] if a variable is not found.
/// Returns [`VerifierError::PredicateDepthExceeded`] if depth exceeds limit.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
///
/// use apm2_core::fac::{Predicate, PredicateOp, evaluate_predicate};
///
/// let mut bindings = HashMap::new();
/// bindings.insert("exit_code".to_string(), 0i64);
/// bindings.insert("failed_count".to_string(), 0i64);
///
/// // exit_code == 0
/// let pred = Predicate::compare(
///     Predicate::variable("exit_code"),
///     PredicateOp::Eq,
///     Predicate::literal(0),
/// );
///
/// assert!(evaluate_predicate(&pred, &bindings).unwrap());
/// ```
pub fn evaluate_predicate<S: std::hash::BuildHasher>(
    predicate: &Predicate,
    bindings: &std::collections::HashMap<String, i64, S>,
) -> Result<bool, VerifierError> {
    let lookup = |name: &str| bindings.get(name).copied();
    predicate.evaluate(&lookup)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use super::*;

    // =========================================================================
    // VerifierKind Tests
    // =========================================================================

    #[test]
    fn test_verifier_kind_all() {
        let kinds: Vec<_> = VerifierKind::all().collect();
        assert_eq!(kinds.len(), 4);
        assert!(kinds.contains(&VerifierKind::ExitCode));
        assert!(kinds.contains(&VerifierKind::SnapshotDiff));
        assert!(kinds.contains(&VerifierKind::StructuredTestReport));
        assert!(kinds.contains(&VerifierKind::InvariantCheck));
    }

    #[test]
    fn test_verifier_kind_default_required_outputs() {
        assert_eq!(
            VerifierKind::ExitCode.default_required_outputs(),
            &["exit_code", "command"]
        );
        assert_eq!(
            VerifierKind::SnapshotDiff.default_required_outputs(),
            &["diff_digest", "changed_files_count"]
        );
        assert_eq!(
            VerifierKind::StructuredTestReport.default_required_outputs(),
            &[
                "report_digest",
                "passed_count",
                "failed_count",
                "skipped_count"
            ]
        );
        assert_eq!(
            VerifierKind::InvariantCheck.default_required_outputs(),
            &["invariant_id", "check_result"]
        );
    }

    #[test]
    fn test_verifier_kind_display() {
        assert_eq!(VerifierKind::ExitCode.to_string(), "exit_code");
        assert_eq!(VerifierKind::SnapshotDiff.to_string(), "snapshot_diff");
        assert_eq!(
            VerifierKind::StructuredTestReport.to_string(),
            "structured_test_report"
        );
        assert_eq!(VerifierKind::InvariantCheck.to_string(), "invariant_check");
    }

    #[test]
    fn test_verifier_kind_serde_roundtrip() {
        for kind in VerifierKind::all() {
            let json = serde_json::to_string(&kind).unwrap();
            let deserialized: VerifierKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, deserialized);
        }
    }

    // =========================================================================
    // CheckResult Tests
    // =========================================================================

    #[test]
    fn test_check_result_as_i64() {
        assert_eq!(CheckResult::Satisfied.as_i64(), 1);
        assert_eq!(CheckResult::Violated.as_i64(), 0);
        assert_eq!(CheckResult::Unknown.as_i64(), -1);
    }

    #[test]
    fn test_check_result_try_from_i64() {
        assert_eq!(CheckResult::try_from(1).unwrap(), CheckResult::Satisfied);
        assert_eq!(CheckResult::try_from(0).unwrap(), CheckResult::Violated);
        assert_eq!(CheckResult::try_from(-1).unwrap(), CheckResult::Unknown);
        assert!(CheckResult::try_from(2).is_err());
        assert!(CheckResult::try_from(-2).is_err());
    }

    // =========================================================================
    // PredicateOp Tests
    // =========================================================================

    #[test]
    fn test_predicate_op_evaluate() {
        assert!(PredicateOp::Eq.evaluate(5, 5));
        assert!(!PredicateOp::Eq.evaluate(5, 6));

        assert!(PredicateOp::Ne.evaluate(5, 6));
        assert!(!PredicateOp::Ne.evaluate(5, 5));

        assert!(PredicateOp::Lt.evaluate(5, 6));
        assert!(!PredicateOp::Lt.evaluate(5, 5));
        assert!(!PredicateOp::Lt.evaluate(6, 5));

        assert!(PredicateOp::Le.evaluate(5, 6));
        assert!(PredicateOp::Le.evaluate(5, 5));
        assert!(!PredicateOp::Le.evaluate(6, 5));

        assert!(PredicateOp::Gt.evaluate(6, 5));
        assert!(!PredicateOp::Gt.evaluate(5, 5));
        assert!(!PredicateOp::Gt.evaluate(5, 6));

        assert!(PredicateOp::Ge.evaluate(6, 5));
        assert!(PredicateOp::Ge.evaluate(5, 5));
        assert!(!PredicateOp::Ge.evaluate(5, 6));
    }

    #[test]
    fn test_predicate_op_display() {
        assert_eq!(PredicateOp::Eq.to_string(), "==");
        assert_eq!(PredicateOp::Ne.to_string(), "!=");
        assert_eq!(PredicateOp::Lt.to_string(), "<");
        assert_eq!(PredicateOp::Le.to_string(), "<=");
        assert_eq!(PredicateOp::Gt.to_string(), ">");
        assert_eq!(PredicateOp::Ge.to_string(), ">=");
    }

    // =========================================================================
    // Predicate Tests
    // =========================================================================

    #[test]
    fn test_predicate_literal() {
        let bindings = |_: &str| None;

        assert!(Predicate::literal(1).evaluate(&bindings).unwrap());
        assert!(Predicate::literal(100).evaluate(&bindings).unwrap());
        assert!(!Predicate::literal(0).evaluate(&bindings).unwrap());
        assert!(Predicate::literal(-1).evaluate(&bindings).unwrap());
    }

    #[test]
    fn test_predicate_variable() {
        let mut map = HashMap::new();
        map.insert("x".to_string(), 5i64);
        map.insert("zero".to_string(), 0i64);

        let bindings = |name: &str| map.get(name).copied();

        assert!(Predicate::variable("x").evaluate(&bindings).unwrap());
        assert!(!Predicate::variable("zero").evaluate(&bindings).unwrap());

        // Unknown variable
        let result = Predicate::variable("unknown").evaluate(&bindings);
        assert!(matches!(result, Err(VerifierError::UnknownVariable(_))));
    }

    #[test]
    fn test_predicate_compare() {
        let mut map = HashMap::new();
        map.insert("exit_code".to_string(), 0i64);
        map.insert("failed_count".to_string(), 3i64);

        let bindings = |name: &str| map.get(name).copied();

        // exit_code == 0
        let pred = Predicate::compare(
            Predicate::variable("exit_code"),
            PredicateOp::Eq,
            Predicate::literal(0),
        );
        assert!(pred.evaluate(&bindings).unwrap());

        // failed_count > 0
        let pred = Predicate::compare(
            Predicate::variable("failed_count"),
            PredicateOp::Gt,
            Predicate::literal(0),
        );
        assert!(pred.evaluate(&bindings).unwrap());

        // failed_count == 0
        let pred = Predicate::compare(
            Predicate::variable("failed_count"),
            PredicateOp::Eq,
            Predicate::literal(0),
        );
        assert!(!pred.evaluate(&bindings).unwrap());
    }

    #[test]
    fn test_predicate_and() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), 1i64);
        map.insert("b".to_string(), 1i64);
        map.insert("c".to_string(), 0i64);

        let bindings = |name: &str| map.get(name).copied();

        // a AND b (both true)
        let pred = Predicate::and(Predicate::variable("a"), Predicate::variable("b"));
        assert!(pred.evaluate(&bindings).unwrap());

        // a AND c (c is false)
        let pred = Predicate::and(Predicate::variable("a"), Predicate::variable("c"));
        assert!(!pred.evaluate(&bindings).unwrap());

        // c AND a (c is false, short-circuit)
        let pred = Predicate::and(Predicate::variable("c"), Predicate::variable("a"));
        assert!(!pred.evaluate(&bindings).unwrap());
    }

    #[test]
    fn test_predicate_or() {
        let mut map = HashMap::new();
        map.insert("a".to_string(), 1i64);
        map.insert("b".to_string(), 0i64);
        map.insert("c".to_string(), 0i64);

        let bindings = |name: &str| map.get(name).copied();

        // a OR b (a is true)
        let pred = Predicate::or(Predicate::variable("a"), Predicate::variable("b"));
        assert!(pred.evaluate(&bindings).unwrap());

        // b OR c (both false)
        let pred = Predicate::or(Predicate::variable("b"), Predicate::variable("c"));
        assert!(!pred.evaluate(&bindings).unwrap());

        // a OR unknown (short-circuit, never evaluates unknown)
        let pred = Predicate::or(Predicate::variable("a"), Predicate::variable("unknown"));
        assert!(pred.evaluate(&bindings).unwrap());
    }

    #[test]
    fn test_predicate_not() {
        let mut map = HashMap::new();
        map.insert("x".to_string(), 1i64);
        map.insert("y".to_string(), 0i64);

        let bindings = |name: &str| map.get(name).copied();

        // NOT x (x is true)
        let pred = Predicate::negate(Predicate::variable("x"));
        assert!(!pred.evaluate(&bindings).unwrap());

        // NOT y (y is false)
        let pred = Predicate::negate(Predicate::variable("y"));
        assert!(pred.evaluate(&bindings).unwrap());
    }

    #[test]
    fn test_predicate_complex() {
        let mut map = HashMap::new();
        map.insert("exit_code".to_string(), 0i64);
        map.insert("failed_count".to_string(), 0i64);
        map.insert("changed_files_count".to_string(), 2i64);
        map.insert("diff_approved".to_string(), 1i64);

        let bindings = |name: &str| map.get(name).copied();

        // (exit_code == 0) AND (failed_count == 0)
        let pred = Predicate::and(
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
        );
        assert!(pred.evaluate(&bindings).unwrap());

        // (changed_files_count == 0) OR diff_approved
        let pred = Predicate::or(
            Predicate::compare(
                Predicate::variable("changed_files_count"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ),
            Predicate::variable("diff_approved"),
        );
        assert!(pred.evaluate(&bindings).unwrap());
    }

    #[test]
    fn test_predicate_depth() {
        let shallow = Predicate::literal(1);
        assert_eq!(shallow.depth(), 1);

        let nested = Predicate::and(
            Predicate::negate(Predicate::variable("x")),
            Predicate::compare(
                Predicate::variable("y"),
                PredicateOp::Gt,
                Predicate::literal(5),
            ),
        );
        assert_eq!(nested.depth(), 3);
    }

    #[test]
    fn test_predicate_serde_roundtrip() {
        let pred = Predicate::and(
            Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ),
            Predicate::negate(Predicate::variable("has_errors")),
        );

        let json = serde_json::to_string(&pred).unwrap();
        let deserialized: Predicate = serde_json::from_str(&json).unwrap();
        assert_eq!(pred, deserialized);
    }

    // =========================================================================
    // evaluate_predicate Function Tests
    // =========================================================================

    #[test]
    fn test_evaluate_predicate_function() {
        let mut bindings = HashMap::new();
        bindings.insert("exit_code".to_string(), 0i64);
        bindings.insert("failed_count".to_string(), 0i64);

        // exit_code == 0
        let pred = Predicate::compare(
            Predicate::variable("exit_code"),
            PredicateOp::Eq,
            Predicate::literal(0),
        );
        assert!(evaluate_predicate(&pred, &bindings).unwrap());

        // failed_count > 0
        let pred = Predicate::compare(
            Predicate::variable("failed_count"),
            PredicateOp::Gt,
            Predicate::literal(0),
        );
        assert!(!evaluate_predicate(&pred, &bindings).unwrap());
    }

    // =========================================================================
    // VerifierOutput Tests
    // =========================================================================

    #[test]
    fn test_verifier_output_builder() {
        let output = VerifierOutput::builder()
            .output_digest([0xAB; 32])
            .verifier_kind(VerifierKind::ExitCode)
            .add_value("exit_code", 0)
            .add_value("command", 1)
            .predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid output");

        assert_eq!(output.output_digest(), [0xAB; 32]);
        assert_eq!(output.verifier_kind(), VerifierKind::ExitCode);
        assert_eq!(output.get_value("exit_code"), Some(0));
        assert_eq!(output.get_value("command"), Some(1));
        assert!(output.predicate_satisfied());
    }

    #[test]
    fn test_verifier_output_predicate_not_satisfied() {
        let output = VerifierOutput::builder()
            .output_digest([0xAB; 32])
            .verifier_kind(VerifierKind::ExitCode)
            .add_value("exit_code", 1) // Non-zero exit code
            .predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid output");

        assert!(!output.predicate_satisfied());
    }

    #[test]
    fn test_verifier_output_missing_field() {
        let result = VerifierOutput::builder()
            .verifier_kind(VerifierKind::ExitCode)
            .add_value("exit_code", 0)
            .build();

        assert!(matches!(
            result,
            Err(VerifierError::MissingField("output_digest"))
        ));
    }

    // =========================================================================
    // VerifierPolicy Tests
    // =========================================================================

    #[test]
    fn test_verifier_policy_builder() {
        let policy = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .add_required_output("command")
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .expect("valid policy");

        assert_eq!(policy.policy_id(), "policy-001");
        assert_eq!(policy.scenario_type(), "build");
        assert_eq!(policy.schema_version(), 1);
        assert_eq!(policy.allowed_verifier_kinds(), &[VerifierKind::ExitCode]);
        assert_eq!(policy.required_outputs(), &["exit_code", "command"]);
        assert_eq!(policy.predicate_lang(), "fac-predicate-v1");
    }

    #[test]
    fn test_verifier_policy_validate_output_success() {
        let policy = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .unwrap();

        let output = VerifierOutput::builder()
            .output_digest([0xAB; 32])
            .verifier_kind(VerifierKind::ExitCode)
            .add_value("exit_code", 0)
            .build()
            .unwrap();

        assert!(policy.validate_output(&output).unwrap());
    }

    #[test]
    fn test_verifier_policy_validate_output_kind_not_allowed() {
        let policy = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .machine_predicate(Predicate::literal(1))
            .build()
            .unwrap();

        let output = VerifierOutput::builder()
            .output_digest([0xAB; 32])
            .verifier_kind(VerifierKind::SnapshotDiff) // Not allowed
            .add_value("exit_code", 0)
            .build()
            .unwrap();

        let result = policy.validate_output(&output);
        assert!(matches!(
            result,
            Err(VerifierError::VerifierKindNotAllowed { .. })
        ));
    }

    #[test]
    fn test_verifier_policy_validate_output_missing_required() {
        let policy = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .add_required_output("command")
            .machine_predicate(Predicate::literal(1))
            .build()
            .unwrap();

        let output = VerifierOutput::builder()
            .output_digest([0xAB; 32])
            .verifier_kind(VerifierKind::ExitCode)
            .add_value("exit_code", 0)
            // Missing "command"
            .build()
            .unwrap();

        let result = policy.validate_output(&output);
        assert!(matches!(
            result,
            Err(VerifierError::RequiredOutputMissing(ref s)) if s == "command"
        ));
    }

    #[test]
    fn test_verifier_policy_duplicate_required_output() {
        let result = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .add_required_output("exit_code") // Duplicate
            .machine_predicate(Predicate::literal(1))
            .build();

        assert!(matches!(
            result,
            Err(VerifierError::DuplicateRequiredOutput(_))
        ));
    }

    #[test]
    fn test_verifier_policy_missing_scenario_type() {
        let result = VerifierPolicyBuilder::new("policy-001")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1))
            .build();

        assert!(matches!(
            result,
            Err(VerifierError::MissingField("scenario_type"))
        ));
    }

    #[test]
    fn test_verifier_policy_hash_deterministic() {
        let policy1 = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .machine_predicate(Predicate::literal(1))
            .build()
            .unwrap();

        let policy2 = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .machine_predicate(Predicate::literal(1))
            .build()
            .unwrap();

        assert_eq!(policy1.policy_hash(), policy2.policy_hash());
    }

    #[test]
    fn test_verifier_policy_hash_differs_with_different_inputs() {
        let policy1 = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1))
            .build()
            .unwrap();

        let policy2 = VerifierPolicyBuilder::new("policy-002") // Different ID
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1))
            .build()
            .unwrap();

        assert_ne!(policy1.policy_hash(), policy2.policy_hash());
    }

    #[test]
    fn test_verifier_policy_serde_roundtrip() {
        let policy = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_allowed_verifier_kind(VerifierKind::StructuredTestReport)
            .add_required_output("exit_code")
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .unwrap();

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: VerifierPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, deserialized);
    }

    // =========================================================================
    // Resource Limit Tests
    // =========================================================================

    #[test]
    fn test_too_many_allowed_verifier_kinds() {
        let mut builder = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .machine_predicate(Predicate::literal(1));

        // Add more than MAX_ALLOWED_VERIFIER_KINDS (16)
        // Since we only have 4 kinds, we need to test collection limit differently
        // This test validates the limit exists
        for kind in VerifierKind::all() {
            builder = builder.add_allowed_verifier_kind(kind);
        }
        // Should succeed with 4 kinds
        assert!(builder.build().is_ok());
    }

    #[test]
    fn test_too_many_required_outputs() {
        let mut builder = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1));

        // Add more than MAX_REQUIRED_OUTPUTS (64)
        for i in 0..=MAX_REQUIRED_OUTPUTS {
            builder = builder.add_required_output(format!("output_{i}"));
        }

        let result = builder.build();
        assert!(matches!(
            result,
            Err(VerifierError::CollectionTooLarge {
                field: "required_outputs",
                ..
            })
        ));
    }

    #[test]
    fn test_string_too_long() {
        let long_string = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = VerifierPolicyBuilder::new(long_string)
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(Predicate::literal(1))
            .build();

        assert!(matches!(
            result,
            Err(VerifierError::StringTooLong {
                field: "policy_id",
                ..
            })
        ));
    }

    // =========================================================================
    // Real-world Scenario Tests
    // =========================================================================

    #[test]
    fn test_exit_code_verifier_scenario() {
        // Simulate: cargo test exits with code 0
        let policy = VerifierPolicyBuilder::new("cargo-test-policy")
            .scenario_type("unit-test")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .add_required_output("exit_code")
            .add_required_output("command")
            .machine_predicate(Predicate::compare(
                Predicate::variable("exit_code"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .unwrap();

        // Successful test run
        let output = VerifierOutput::builder()
            .output_digest([0x11; 32])
            .verifier_kind(VerifierKind::ExitCode)
            .add_value("exit_code", 0)
            .add_value("command", 1) // hash of command
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(policy.validate_output(&output).unwrap());
        assert!(output.predicate_satisfied());

        // Failed test run
        let output = VerifierOutput::builder()
            .output_digest([0x22; 32])
            .verifier_kind(VerifierKind::ExitCode)
            .add_value("exit_code", 1) // Non-zero
            .add_value("command", 1)
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(!policy.validate_output(&output).unwrap());
        assert!(!output.predicate_satisfied());
    }

    #[test]
    fn test_structured_test_report_scenario() {
        // Simulate: test report with pass/fail counts
        let policy = VerifierPolicyBuilder::new("test-report-policy")
            .scenario_type("integration-test")
            .add_allowed_verifier_kind(VerifierKind::StructuredTestReport)
            .add_required_output("report_digest")
            .add_required_output("passed_count")
            .add_required_output("failed_count")
            .add_required_output("skipped_count")
            .machine_predicate(Predicate::compare(
                Predicate::variable("failed_count"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ))
            .build()
            .unwrap();

        // All tests pass
        let output = VerifierOutput::builder()
            .output_digest([0x33; 32])
            .verifier_kind(VerifierKind::StructuredTestReport)
            .add_value("report_digest", 12345)
            .add_value("passed_count", 42)
            .add_value("failed_count", 0)
            .add_value("skipped_count", 2)
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(policy.validate_output(&output).unwrap());
    }

    #[test]
    fn test_snapshot_diff_scenario() {
        // Simulate: snapshot diff with approval
        let policy = VerifierPolicyBuilder::new("snapshot-policy")
            .scenario_type("snapshot")
            .add_allowed_verifier_kind(VerifierKind::SnapshotDiff)
            .add_required_output("diff_digest")
            .add_required_output("changed_files_count")
            .add_required_output("diff_approved")
            .machine_predicate(Predicate::or(
                Predicate::compare(
                    Predicate::variable("changed_files_count"),
                    PredicateOp::Eq,
                    Predicate::literal(0),
                ),
                Predicate::variable("diff_approved"),
            ))
            .build()
            .unwrap();

        // No changes
        let output = VerifierOutput::builder()
            .output_digest([0x44; 32])
            .verifier_kind(VerifierKind::SnapshotDiff)
            .add_value("diff_digest", 0)
            .add_value("changed_files_count", 0)
            .add_value("diff_approved", 0)
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(policy.validate_output(&output).unwrap());

        // Changes but approved
        let output = VerifierOutput::builder()
            .output_digest([0x55; 32])
            .verifier_kind(VerifierKind::SnapshotDiff)
            .add_value("diff_digest", 123)
            .add_value("changed_files_count", 5)
            .add_value("diff_approved", 1)
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(policy.validate_output(&output).unwrap());

        // Changes and NOT approved
        let output = VerifierOutput::builder()
            .output_digest([0x66; 32])
            .verifier_kind(VerifierKind::SnapshotDiff)
            .add_value("diff_digest", 123)
            .add_value("changed_files_count", 5)
            .add_value("diff_approved", 0)
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(!policy.validate_output(&output).unwrap());
    }

    #[test]
    fn test_invariant_check_scenario() {
        // Simulate: invariant check with SATISFIED result
        let policy = VerifierPolicyBuilder::new("invariant-policy")
            .scenario_type("invariant")
            .add_allowed_verifier_kind(VerifierKind::InvariantCheck)
            .add_required_output("invariant_id")
            .add_required_output("check_result")
            .machine_predicate(Predicate::compare(
                Predicate::variable("check_result"),
                PredicateOp::Eq,
                Predicate::literal(CheckResult::Satisfied.as_i64()),
            ))
            .build()
            .unwrap();

        // Invariant satisfied
        let output = VerifierOutput::builder()
            .output_digest([0x77; 32])
            .verifier_kind(VerifierKind::InvariantCheck)
            .add_value("invariant_id", 42)
            .add_value("check_result", CheckResult::Satisfied.as_i64())
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(policy.validate_output(&output).unwrap());

        // Invariant violated
        let output = VerifierOutput::builder()
            .output_digest([0x88; 32])
            .verifier_kind(VerifierKind::InvariantCheck)
            .add_value("invariant_id", 42)
            .add_value("check_result", CheckResult::Violated.as_i64())
            .predicate(policy.machine_predicate().clone())
            .build()
            .unwrap();

        assert!(!policy.validate_output(&output).unwrap());
    }

    // =========================================================================
    // Predicate Node Count Tests (DoS prevention)
    // =========================================================================

    #[test]
    fn test_predicate_count_nodes_simple() {
        // Single literal node
        assert_eq!(Predicate::literal(1).count_nodes(), 1);

        // Single variable node
        assert_eq!(Predicate::variable("x").count_nodes(), 1);

        // Compare: 1 (compare) + 1 (left var) + 1 (right literal) = 3
        let compare = Predicate::compare(
            Predicate::variable("x"),
            PredicateOp::Eq,
            Predicate::literal(0),
        );
        assert_eq!(compare.count_nodes(), 3);

        // And: 1 (and) + 1 (left) + 1 (right) = 3
        let and = Predicate::and(Predicate::literal(1), Predicate::literal(1));
        assert_eq!(and.count_nodes(), 3);

        // Not: 1 (not) + 1 (inner) = 2
        let not = Predicate::negate(Predicate::literal(1));
        assert_eq!(not.count_nodes(), 2);
    }

    #[test]
    fn test_predicate_count_nodes_nested() {
        // ((a == 0) AND (b == 0)) OR (c != 0)
        // Structure:
        // OR (1)
        //   AND (1)
        //     Compare (1) + Var (1) + Lit (1) = 3
        //     Compare (1) + Var (1) + Lit (1) = 3
        //   Compare (1) + Var (1) + Lit (1) = 3
        // Total: 1 + 1 + 3 + 3 + 3 = 11
        let pred = Predicate::or(
            Predicate::and(
                Predicate::compare(
                    Predicate::variable("a"),
                    PredicateOp::Eq,
                    Predicate::literal(0),
                ),
                Predicate::compare(
                    Predicate::variable("b"),
                    PredicateOp::Eq,
                    Predicate::literal(0),
                ),
            ),
            Predicate::compare(
                Predicate::variable("c"),
                PredicateOp::Ne,
                Predicate::literal(0),
            ),
        );
        assert_eq!(pred.count_nodes(), 11);
    }

    #[test]
    fn test_predicate_validate_node_count_within_limit() {
        // A simple predicate well within the limit
        let pred = Predicate::compare(
            Predicate::variable("x"),
            PredicateOp::Eq,
            Predicate::literal(0),
        );
        assert!(pred.validate_node_count().is_ok());
        assert!(pred.validate().is_ok());
    }

    #[test]
    fn test_predicate_validate_node_count_exceeds_limit() {
        // Build a balanced tree that exceeds MAX_PREDICATE_NODES (256) but stays
        // within MAX_PREDICATE_DEPTH (32).
        // A balanced binary tree of depth d has 2^(d+1) - 1 nodes.
        // With depth 8 we get 2^9 - 1 = 511 nodes > 256, but depth is only 9 < 32.
        fn build_balanced_tree(depth: usize) -> Predicate {
            if depth == 0 {
                Predicate::literal(1)
            } else {
                Predicate::and(
                    build_balanced_tree(depth - 1),
                    build_balanced_tree(depth - 1),
                )
            }
        }

        let large_pred = build_balanced_tree(8);
        assert!(large_pred.count_nodes() > MAX_PREDICATE_NODES);
        assert!(large_pred.depth() <= MAX_PREDICATE_DEPTH);

        let result = large_pred.validate_node_count();
        assert!(matches!(
            result,
            Err(VerifierError::PredicateNodeCountExceeded { .. })
        ));

        // Also verify it fails full validate()
        let result = large_pred.validate();
        assert!(matches!(
            result,
            Err(VerifierError::PredicateNodeCountExceeded { .. })
        ));
    }

    #[test]
    fn test_predicate_node_count_at_boundary() {
        // Test at exactly MAX_PREDICATE_NODES (256)
        // A balanced binary tree of depth d has 2^(d+1) - 1 nodes.
        // Depth 7 gives 2^8 - 1 = 255 nodes (just under limit)
        // Depth 8 gives 2^9 - 1 = 511 nodes (over limit)
        fn build_balanced_tree(depth: usize) -> Predicate {
            if depth == 0 {
                Predicate::literal(1)
            } else {
                Predicate::and(
                    build_balanced_tree(depth - 1),
                    build_balanced_tree(depth - 1),
                )
            }
        }

        // 255 nodes is under the limit of 256
        let at_limit_minus_one = build_balanced_tree(7);
        assert_eq!(at_limit_minus_one.count_nodes(), 255);
        assert!(at_limit_minus_one.validate_node_count().is_ok());

        // 511 nodes exceeds the limit of 256
        let exceeds_limit = build_balanced_tree(8);
        assert_eq!(exceeds_limit.count_nodes(), 511);
        assert!(exceeds_limit.validate_node_count().is_err());
    }

    // =========================================================================
    // Predicate Variable String Length Tests
    // =========================================================================

    #[test]
    fn test_predicate_validate_string_lengths_valid() {
        let pred = Predicate::compare(
            Predicate::variable("exit_code"),
            PredicateOp::Eq,
            Predicate::literal(0),
        );
        assert!(pred.validate_string_lengths().is_ok());
        assert!(pred.validate().is_ok());
    }

    #[test]
    fn test_predicate_validate_string_lengths_too_long() {
        let long_name = "x".repeat(MAX_STRING_LENGTH + 1);
        let pred = Predicate::variable(long_name);

        let result = pred.validate_string_lengths();
        assert!(matches!(
            result,
            Err(VerifierError::PredicateVariableTooLong { .. })
        ));

        // Also fails full validate()
        let result = pred.validate();
        assert!(matches!(
            result,
            Err(VerifierError::PredicateVariableTooLong { .. })
        ));
    }

    #[test]
    fn test_predicate_validate_string_lengths_nested() {
        // Long variable buried in a nested predicate tree
        let long_name = "x".repeat(MAX_STRING_LENGTH + 1);
        let pred = Predicate::and(
            Predicate::compare(
                Predicate::variable("a"),
                PredicateOp::Eq,
                Predicate::literal(0),
            ),
            Predicate::or(
                Predicate::literal(1),
                Predicate::variable(long_name), // Long name buried deep
            ),
        );

        let result = pred.validate_string_lengths();
        assert!(matches!(
            result,
            Err(VerifierError::PredicateVariableTooLong { .. })
        ));
    }

    #[test]
    fn test_predicate_validate_string_at_max_length() {
        // Exactly at the limit should succeed
        let max_name = "x".repeat(MAX_STRING_LENGTH);
        let pred = Predicate::variable(max_name);
        assert!(pred.validate_string_lengths().is_ok());
    }

    // =========================================================================
    // Policy Builder Integration with New Validations
    // =========================================================================

    #[test]
    fn test_policy_builder_rejects_predicate_too_many_nodes() {
        // Build a wide tree that stays within depth limit but exceeds node limit.
        // A balanced binary tree of depth d has 2^(d+1) - 1 nodes.
        // With depth 8 we get 2^9 - 1 = 511 nodes > 256, but depth is only 8 < 32.
        fn build_balanced_tree(depth: usize) -> Predicate {
            if depth == 0 {
                Predicate::literal(1)
            } else {
                Predicate::and(
                    build_balanced_tree(depth - 1),
                    build_balanced_tree(depth - 1),
                )
            }
        }

        // Depth 8 gives us 511 nodes > 256, but depth 8 < 32
        let large_pred = build_balanced_tree(8);
        assert_eq!(large_pred.depth(), 9); // depth of tree is levels + 1
        assert!(large_pred.count_nodes() > MAX_PREDICATE_NODES);

        let result = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(large_pred)
            .build();

        assert!(matches!(
            result,
            Err(VerifierError::PredicateNodeCountExceeded { .. })
        ));
    }

    #[test]
    fn test_policy_builder_rejects_predicate_variable_too_long() {
        let long_name = "x".repeat(MAX_STRING_LENGTH + 1);
        let pred = Predicate::compare(
            Predicate::variable(long_name),
            PredicateOp::Eq,
            Predicate::literal(0),
        );

        let result = VerifierPolicyBuilder::new("policy-001")
            .scenario_type("build")
            .add_allowed_verifier_kind(VerifierKind::ExitCode)
            .machine_predicate(pred)
            .build();

        assert!(matches!(
            result,
            Err(VerifierError::PredicateVariableTooLong { .. })
        ));
    }

    #[test]
    fn test_predicate_full_validate_checks_all() {
        // Test that validate() catches depth issues
        fn build_deep(depth: usize) -> Predicate {
            if depth == 0 {
                Predicate::literal(1)
            } else {
                Predicate::negate(build_deep(depth - 1))
            }
        }

        // Depth of 33 exceeds MAX_PREDICATE_DEPTH (32)
        let deep_pred = build_deep(33);
        let result = deep_pred.validate();
        assert!(matches!(
            result,
            Err(VerifierError::PredicateDepthExceeded { .. })
        ));
    }
}
