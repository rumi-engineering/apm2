//! `ContextPack` specification types.
//!
//! This module provides Rust types for the `ContextPack` specification schema,
//! which defines the artifacts and budget constraints for hermetic consumption.
//!
//! # Design Principles
//!
//! - **Typed Quantities**: All quantities use explicit units to prevent unit
//!   mismatch errors (per DD-0007, "Mars Climate Orbiter" prevention)
//! - **Strict Serde**: All types use `#[serde(deny_unknown_fields)]` to reject
//!   unknown fields (CTR-1604)
//! - **Overflow Protection**: Arithmetic operations use checked arithmetic and
//!   return errors on overflow
//!
//! # Example
//!
//! ```rust
//! use apm2_core::cac::pack_spec::{
//!     BudgetConstraint, ContextPackSpec, QuantityUnit, TypedQuantity,
//! };
//!
//! // Create budget constraints with typed quantities
//! let budget = BudgetConstraint::builder()
//!     .max_tokens(TypedQuantity::tokens(100_000))
//!     .max_bytes(TypedQuantity::bytes(1_048_576))
//!     .max_artifacts(TypedQuantity::artifacts(50))
//!     .max_time_ms(TypedQuantity::ms(30_000))
//!     .build();
//!
//! // Create a ContextPackSpec
//! let spec = ContextPackSpec::builder()
//!     .spec_id("pack-001")
//!     .root("org:doc:readme")
//!     .root("org:doc:agents")
//!     .budget(budget)
//!     .target_profile("org:profile:claude-code")
//!     .build()
//!     .unwrap();
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for spec IDs.
pub const MAX_SPEC_ID_LENGTH: usize = 256;

/// Maximum length for stable IDs in roots and dependencies.
pub const MAX_STABLE_ID_LENGTH: usize = 1024;

/// Maximum number of root artifacts in a pack spec.
pub const MAX_ROOTS: usize = 1024;

/// Maximum number of dependency reviews.
pub const MAX_DEPENDENCY_REVIEWS: usize = 10_000;

/// Maximum length for author strings.
pub const MAX_AUTHOR_LENGTH: usize = 256;

/// Maximum length for description strings.
pub const MAX_DESCRIPTION_LENGTH: usize = 4096;

/// Maximum number of labels.
pub const MAX_LABELS: usize = 64;

/// Maximum length for label strings.
pub const MAX_LABEL_LENGTH: usize = 128;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during `ContextPackSpec` operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackSpecError {
    /// A required field is missing.
    #[error("missing required field: {field}")]
    MissingField {
        /// The name of the missing field.
        field: String,
    },

    /// A field value exceeds its maximum length.
    #[error("{field} exceeds maximum length of {max_length} (got {actual_length})")]
    FieldTooLong {
        /// The name of the field.
        field: String,
        /// Maximum allowed length.
        max_length: usize,
        /// Actual length provided.
        actual_length: usize,
    },

    /// A collection exceeds its maximum size.
    #[error("{field} exceeds maximum count of {max_count} (got {actual_count})")]
    TooManyItems {
        /// The name of the field.
        field: String,
        /// Maximum allowed count.
        max_count: usize,
        /// Actual count provided.
        actual_count: usize,
    },

    /// Unit mismatch in a typed quantity operation.
    #[error("unit mismatch: expected {expected}, got {actual}")]
    UnitMismatch {
        /// Expected unit.
        expected: QuantityUnit,
        /// Actual unit provided.
        actual: QuantityUnit,
    },

    /// Arithmetic overflow in quantity operation.
    #[error("arithmetic overflow in {operation}")]
    ArithmeticOverflow {
        /// Description of the operation that overflowed.
        operation: String,
    },

    /// Invalid quantity value (e.g., negative).
    #[error("invalid quantity value: {message}")]
    InvalidQuantity {
        /// Description of the invalid value.
        message: String,
    },

    /// Invalid spec ID format.
    #[error("invalid spec_id format: {message}")]
    InvalidSpecId {
        /// Description of the format violation.
        message: String,
    },

    /// Empty roots list.
    #[error("roots list cannot be empty")]
    EmptyRoots,
}

// ============================================================================
// QuantityUnit
// ============================================================================

/// Unit for typed quantities.
///
/// Using explicit units prevents unit mismatch errors that could cause
/// silent failures in budget enforcement (per DD-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum QuantityUnit {
    /// Token count (inference tokens).
    Tokens,
    /// Byte count.
    Bytes,
    /// Artifact count.
    Artifacts,
    /// Milliseconds.
    Ms,
    /// Generic count.
    Count,
}

impl QuantityUnit {
    /// Returns the string representation of the unit.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tokens => "tokens",
            Self::Bytes => "bytes",
            Self::Artifacts => "artifacts",
            Self::Ms => "ms",
            Self::Count => "count",
        }
    }
}

impl std::fmt::Display for QuantityUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// TypedQuantity
// ============================================================================

/// A quantity with explicit unit for type-safe arithmetic.
///
/// # Design
///
/// - **Unit Safety**: Operations between quantities with different units are
///   rejected at runtime with [`PackSpecError::UnitMismatch`]
/// - **Overflow Protection**: All arithmetic operations use checked arithmetic
///   and return errors on overflow
/// - **Integer-Only**: Values are integers per CAC-JSON constraints (no floats)
///
/// # Example
///
/// ```rust
/// use apm2_core::cac::pack_spec::{QuantityUnit, TypedQuantity};
///
/// // Create typed quantities
/// let tokens = TypedQuantity::tokens(1000);
/// let more_tokens = TypedQuantity::tokens(500);
///
/// // Safe arithmetic
/// let total = tokens.checked_add(&more_tokens).unwrap();
/// assert_eq!(total.value(), 1500);
/// assert_eq!(total.unit(), QuantityUnit::Tokens);
///
/// // Unit mismatch is an error
/// let bytes = TypedQuantity::bytes(1024);
/// assert!(tokens.checked_add(&bytes).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedQuantity {
    /// The quantity value (non-negative integer).
    value: u64,
    /// The unit of measurement.
    unit: QuantityUnit,
}

impl TypedQuantity {
    /// Creates a new typed quantity.
    ///
    /// # Panics
    ///
    /// This function does not panic. Use this for programmatic construction.
    #[must_use]
    pub const fn new(value: u64, unit: QuantityUnit) -> Self {
        Self { value, unit }
    }

    /// Creates a token quantity.
    #[must_use]
    pub const fn tokens(value: u64) -> Self {
        Self::new(value, QuantityUnit::Tokens)
    }

    /// Creates a byte quantity.
    #[must_use]
    pub const fn bytes(value: u64) -> Self {
        Self::new(value, QuantityUnit::Bytes)
    }

    /// Creates an artifact count quantity.
    #[must_use]
    pub const fn artifacts(value: u64) -> Self {
        Self::new(value, QuantityUnit::Artifacts)
    }

    /// Creates a millisecond quantity.
    #[must_use]
    pub const fn ms(value: u64) -> Self {
        Self::new(value, QuantityUnit::Ms)
    }

    /// Creates a generic count quantity.
    #[must_use]
    pub const fn count(value: u64) -> Self {
        Self::new(value, QuantityUnit::Count)
    }

    /// Returns the value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Returns the unit.
    #[must_use]
    pub const fn unit(&self) -> QuantityUnit {
        self.unit
    }

    /// Returns true if the quantity is zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.value == 0
    }

    /// Checked addition with unit validation.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::UnitMismatch`] if units differ
    /// - [`PackSpecError::ArithmeticOverflow`] if the result overflows
    pub fn checked_add(&self, other: &Self) -> Result<Self, PackSpecError> {
        if self.unit != other.unit {
            return Err(PackSpecError::UnitMismatch {
                expected: self.unit,
                actual: other.unit,
            });
        }
        let value = self.value.checked_add(other.value).ok_or_else(|| {
            PackSpecError::ArithmeticOverflow {
                operation: format!("{} + {} ({})", self.value, other.value, self.unit),
            }
        })?;
        Ok(Self::new(value, self.unit))
    }

    /// Checked subtraction with unit validation.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::UnitMismatch`] if units differ
    /// - [`PackSpecError::ArithmeticOverflow`] if the result underflows
    pub fn checked_sub(&self, other: &Self) -> Result<Self, PackSpecError> {
        if self.unit != other.unit {
            return Err(PackSpecError::UnitMismatch {
                expected: self.unit,
                actual: other.unit,
            });
        }
        let value = self.value.checked_sub(other.value).ok_or_else(|| {
            PackSpecError::ArithmeticOverflow {
                operation: format!("{} - {} ({})", self.value, other.value, self.unit),
            }
        })?;
        Ok(Self::new(value, self.unit))
    }

    /// Checked multiplication by a scalar.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::ArithmeticOverflow`] if the result overflows
    pub fn checked_mul(&self, scalar: u64) -> Result<Self, PackSpecError> {
        let value =
            self.value
                .checked_mul(scalar)
                .ok_or_else(|| PackSpecError::ArithmeticOverflow {
                    operation: format!("{} * {} ({})", self.value, scalar, self.unit),
                })?;
        Ok(Self::new(value, self.unit))
    }

    /// Checked division by a scalar.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::ArithmeticOverflow`] if dividing by zero
    pub fn checked_div(&self, scalar: u64) -> Result<Self, PackSpecError> {
        let value =
            self.value
                .checked_div(scalar)
                .ok_or_else(|| PackSpecError::ArithmeticOverflow {
                    operation: format!("{} / {} ({})", self.value, scalar, self.unit),
                })?;
        Ok(Self::new(value, self.unit))
    }

    /// Saturating addition with unit validation.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::UnitMismatch`] if units differ
    pub fn saturating_add(&self, other: &Self) -> Result<Self, PackSpecError> {
        if self.unit != other.unit {
            return Err(PackSpecError::UnitMismatch {
                expected: self.unit,
                actual: other.unit,
            });
        }
        Ok(Self::new(self.value.saturating_add(other.value), self.unit))
    }

    /// Saturating subtraction with unit validation.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::UnitMismatch`] if units differ
    pub fn saturating_sub(&self, other: &Self) -> Result<Self, PackSpecError> {
        if self.unit != other.unit {
            return Err(PackSpecError::UnitMismatch {
                expected: self.unit,
                actual: other.unit,
            });
        }
        Ok(Self::new(self.value.saturating_sub(other.value), self.unit))
    }

    /// Validates that this quantity uses the expected unit.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::UnitMismatch`] if units differ
    pub fn validate_unit(&self, expected: QuantityUnit) -> Result<(), PackSpecError> {
        if self.unit != expected {
            return Err(PackSpecError::UnitMismatch {
                expected,
                actual: self.unit,
            });
        }
        Ok(())
    }
}

impl std::fmt::Display for TypedQuantity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.value, self.unit)
    }
}

// ============================================================================
// BudgetConstraint
// ============================================================================

/// Budget constraints for `ContextPack` consumption.
///
/// All constraints are optional. When present, they define limits on
/// resource consumption during pack compilation and execution.
///
/// # Example
///
/// ```rust
/// use apm2_core::cac::pack_spec::{BudgetConstraint, TypedQuantity};
///
/// let budget = BudgetConstraint::builder()
///     .max_tokens(TypedQuantity::tokens(100_000))
///     .max_bytes(TypedQuantity::bytes(10_485_760)) // 10 MiB
///     .max_artifacts(TypedQuantity::artifacts(100))
///     .max_time_ms(TypedQuantity::ms(60_000)) // 1 minute
///     .build();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConstraint {
    /// Maximum tokens allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<TypedQuantity>,

    /// Maximum bytes allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<TypedQuantity>,

    /// Maximum artifact count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_artifacts: Option<TypedQuantity>,

    /// Maximum time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time_ms: Option<TypedQuantity>,
}

impl BudgetConstraint {
    /// Creates a new builder for `BudgetConstraint`.
    #[must_use]
    pub const fn builder() -> BudgetConstraintBuilder {
        BudgetConstraintBuilder::new()
    }

    /// Creates an empty budget constraint (no limits).
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_tokens: None,
            max_bytes: None,
            max_artifacts: None,
            max_time_ms: None,
        }
    }

    /// Validates that all constraints use correct units.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::UnitMismatch`] if any constraint has wrong unit
    pub fn validate(&self) -> Result<(), PackSpecError> {
        if let Some(ref q) = self.max_tokens {
            q.validate_unit(QuantityUnit::Tokens)?;
        }
        if let Some(ref q) = self.max_bytes {
            q.validate_unit(QuantityUnit::Bytes)?;
        }
        if let Some(ref q) = self.max_artifacts {
            q.validate_unit(QuantityUnit::Artifacts)?;
        }
        if let Some(ref q) = self.max_time_ms {
            q.validate_unit(QuantityUnit::Ms)?;
        }
        Ok(())
    }

    /// Returns `true` if all constraints are unlimited (no limits set).
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.max_tokens.is_none()
            && self.max_bytes.is_none()
            && self.max_artifacts.is_none()
            && self.max_time_ms.is_none()
    }
}

/// Builder for [`BudgetConstraint`].
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_field_names)]
pub struct BudgetConstraintBuilder {
    max_tokens: Option<TypedQuantity>,
    max_bytes: Option<TypedQuantity>,
    max_artifacts: Option<TypedQuantity>,
    max_time_ms: Option<TypedQuantity>,
}

impl BudgetConstraintBuilder {
    /// Creates a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_tokens: None,
            max_bytes: None,
            max_artifacts: None,
            max_time_ms: None,
        }
    }

    /// Sets the maximum tokens constraint.
    #[must_use]
    pub const fn max_tokens(mut self, quantity: TypedQuantity) -> Self {
        self.max_tokens = Some(quantity);
        self
    }

    /// Sets the maximum bytes constraint.
    #[must_use]
    pub const fn max_bytes(mut self, quantity: TypedQuantity) -> Self {
        self.max_bytes = Some(quantity);
        self
    }

    /// Sets the maximum artifacts constraint.
    #[must_use]
    pub const fn max_artifacts(mut self, quantity: TypedQuantity) -> Self {
        self.max_artifacts = Some(quantity);
        self
    }

    /// Sets the maximum time constraint (milliseconds).
    #[must_use]
    pub const fn max_time_ms(mut self, quantity: TypedQuantity) -> Self {
        self.max_time_ms = Some(quantity);
        self
    }

    /// Builds the `BudgetConstraint`.
    #[must_use]
    pub const fn build(self) -> BudgetConstraint {
        BudgetConstraint {
            max_tokens: self.max_tokens,
            max_bytes: self.max_bytes,
            max_artifacts: self.max_artifacts,
            max_time_ms: self.max_time_ms,
        }
    }
}

// ============================================================================
// DependencyReview
// ============================================================================

/// Review hash for reproducibility tracking.
///
/// Records the content hash of a dependency at the time it was reviewed,
/// enabling verification that dependencies haven't changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyReview {
    /// The stable ID of the reviewed dependency.
    pub stable_id: String,

    /// BLAKE3-256 hash at review time (64 hex characters).
    pub content_hash: String,

    /// ISO 8601 timestamp when dependency was reviewed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<DateTime<Utc>>,
}

impl DependencyReview {
    /// Creates a new dependency review.
    #[must_use]
    pub fn new(stable_id: impl Into<String>, content_hash: impl Into<String>) -> Self {
        Self {
            stable_id: stable_id.into(),
            content_hash: content_hash.into(),
            reviewed_at: None,
        }
    }

    /// Creates a dependency review with a timestamp.
    #[must_use]
    pub fn with_timestamp(
        stable_id: impl Into<String>,
        content_hash: impl Into<String>,
        reviewed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            stable_id: stable_id.into(),
            content_hash: content_hash.into(),
            reviewed_at: Some(reviewed_at),
        }
    }

    /// Validates the dependency review.
    ///
    /// # Errors
    ///
    /// - [`PackSpecError::FieldTooLong`] if `stable_id` exceeds max length
    /// - [`PackSpecError::InvalidQuantity`] if `content_hash` is not 64 hex
    ///   chars
    pub fn validate(&self) -> Result<(), PackSpecError> {
        if self.stable_id.len() > MAX_STABLE_ID_LENGTH {
            return Err(PackSpecError::FieldTooLong {
                field: "dependency_review.stable_id".to_string(),
                max_length: MAX_STABLE_ID_LENGTH,
                actual_length: self.stable_id.len(),
            });
        }
        if self.content_hash.len() != 64
            || !self.content_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(PackSpecError::InvalidQuantity {
                message: format!(
                    "content_hash must be 64 hex characters, got {} chars",
                    self.content_hash.len()
                ),
            });
        }
        Ok(())
    }
}

// ============================================================================
// PackMetadata
// ============================================================================

/// Metadata for the `ContextPack` specification.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    /// Author or owner of this pack spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// ISO 8601 timestamp when spec was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,

    /// Human-readable description of the pack's purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Labels for categorization and filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
}

impl PackMetadata {
    /// Creates a new builder for `PackMetadata`.
    #[must_use]
    pub fn builder() -> PackMetadataBuilder {
        PackMetadataBuilder::default()
    }

    /// Validates the metadata.
    ///
    /// # Errors
    ///
    /// Returns validation errors for field constraints.
    pub fn validate(&self) -> Result<(), PackSpecError> {
        if let Some(ref author) = self.author {
            if author.len() > MAX_AUTHOR_LENGTH {
                return Err(PackSpecError::FieldTooLong {
                    field: "metadata.author".to_string(),
                    max_length: MAX_AUTHOR_LENGTH,
                    actual_length: author.len(),
                });
            }
        }
        if let Some(ref description) = self.description {
            if description.len() > MAX_DESCRIPTION_LENGTH {
                return Err(PackSpecError::FieldTooLong {
                    field: "metadata.description".to_string(),
                    max_length: MAX_DESCRIPTION_LENGTH,
                    actual_length: description.len(),
                });
            }
        }
        if self.labels.len() > MAX_LABELS {
            return Err(PackSpecError::TooManyItems {
                field: "metadata.labels".to_string(),
                max_count: MAX_LABELS,
                actual_count: self.labels.len(),
            });
        }
        for (i, label) in self.labels.iter().enumerate() {
            if label.len() > MAX_LABEL_LENGTH {
                return Err(PackSpecError::FieldTooLong {
                    field: format!("metadata.labels[{i}]"),
                    max_length: MAX_LABEL_LENGTH,
                    actual_length: label.len(),
                });
            }
        }
        Ok(())
    }
}

/// Builder for [`PackMetadata`].
#[derive(Debug, Clone, Default)]
pub struct PackMetadataBuilder {
    author: Option<String>,
    created_at: Option<DateTime<Utc>>,
    description: Option<String>,
    labels: Vec<String>,
}

impl PackMetadataBuilder {
    /// Sets the author.
    #[must_use]
    pub fn author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Sets the creation timestamp.
    #[must_use]
    pub const fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Adds a label.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Builds the `PackMetadata`.
    #[must_use]
    pub fn build(self) -> PackMetadata {
        PackMetadata {
            author: self.author,
            created_at: self.created_at,
            description: self.description,
            labels: self.labels,
        }
    }
}

// ============================================================================
// ContextPackSpec
// ============================================================================

/// Schema identifier for `ContextPackSpec` v1.
pub const CONTEXT_PACK_SPEC_SCHEMA: &str = "bootstrap:context_pack_spec.v1";

/// Schema version for `ContextPackSpec` v1.
pub const CONTEXT_PACK_SPEC_VERSION: &str = "v1";

/// Specification for a `ContextPack` that defines artifacts and budget
/// constraints.
///
/// A `ContextPackSpec` is the input to the pack compiler (DD-0003). It
/// specifies:
/// - Root artifacts to include (ordered for dependency resolution)
/// - Budget constraints for resource limits
/// - Target profile for compilation
/// - Dependency reviews for reproducibility
///
/// # Example
///
/// ```rust
/// use apm2_core::cac::pack_spec::{BudgetConstraint, ContextPackSpec, TypedQuantity};
///
/// let spec = ContextPackSpec::builder()
///     .spec_id("my-pack-001")
///     .root("org:doc:readme")
///     .root("org:doc:agents")
///     .budget(
///         BudgetConstraint::builder()
///             .max_tokens(TypedQuantity::tokens(50_000))
///             .build(),
///     )
///     .target_profile("org:profile:claude-code")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPackSpec {
    /// Schema identifier (constant).
    pub schema: String,

    /// Schema version (constant).
    pub schema_version: String,

    /// Unique identifier for this `ContextPack` specification.
    pub spec_id: String,

    /// Ordered list of root stable IDs (entry points for dependency
    /// resolution).
    pub roots: Vec<String>,

    /// Budget constraints for pack consumption.
    pub budget: BudgetConstraint,

    /// Reference to the target profile (`stable_id`) for compilation.
    pub target_profile: String,

    /// Review hashes for reproducibility verification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_reviews: Vec<DependencyReview>,

    /// Optional pack metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PackMetadata>,
}

impl ContextPackSpec {
    /// Creates a new builder for `ContextPackSpec`.
    #[must_use]
    pub fn builder() -> ContextPackSpecBuilder {
        ContextPackSpecBuilder::default()
    }

    /// Validates the entire specification.
    ///
    /// # Errors
    ///
    /// Returns validation errors for any constraint violations.
    pub fn validate(&self) -> Result<(), PackSpecError> {
        // Validate spec_id
        if self.spec_id.is_empty() {
            return Err(PackSpecError::MissingField {
                field: "spec_id".to_string(),
            });
        }
        if self.spec_id.len() > MAX_SPEC_ID_LENGTH {
            return Err(PackSpecError::FieldTooLong {
                field: "spec_id".to_string(),
                max_length: MAX_SPEC_ID_LENGTH,
                actual_length: self.spec_id.len(),
            });
        }
        // Validate spec_id format: [A-Za-z0-9_.:-]+
        if !self
            .spec_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '-')
        {
            return Err(PackSpecError::InvalidSpecId {
                message: "spec_id must contain only alphanumeric characters, underscores, dots, colons, and hyphens".to_string(),
            });
        }

        // Validate roots
        if self.roots.is_empty() {
            return Err(PackSpecError::EmptyRoots);
        }
        if self.roots.len() > MAX_ROOTS {
            return Err(PackSpecError::TooManyItems {
                field: "roots".to_string(),
                max_count: MAX_ROOTS,
                actual_count: self.roots.len(),
            });
        }
        for (i, root) in self.roots.iter().enumerate() {
            if root.is_empty() {
                return Err(PackSpecError::MissingField {
                    field: format!("roots[{i}]"),
                });
            }
            if root.len() > MAX_STABLE_ID_LENGTH {
                return Err(PackSpecError::FieldTooLong {
                    field: format!("roots[{i}]"),
                    max_length: MAX_STABLE_ID_LENGTH,
                    actual_length: root.len(),
                });
            }
        }

        // Validate target_profile
        if self.target_profile.is_empty() {
            return Err(PackSpecError::MissingField {
                field: "target_profile".to_string(),
            });
        }
        if self.target_profile.len() > MAX_STABLE_ID_LENGTH {
            return Err(PackSpecError::FieldTooLong {
                field: "target_profile".to_string(),
                max_length: MAX_STABLE_ID_LENGTH,
                actual_length: self.target_profile.len(),
            });
        }

        // Validate budget
        self.budget.validate()?;

        // Validate dependency reviews
        if self.dependency_reviews.len() > MAX_DEPENDENCY_REVIEWS {
            return Err(PackSpecError::TooManyItems {
                field: "dependency_reviews".to_string(),
                max_count: MAX_DEPENDENCY_REVIEWS,
                actual_count: self.dependency_reviews.len(),
            });
        }
        for review in &self.dependency_reviews {
            review.validate()?;
        }

        // Validate metadata
        if let Some(ref metadata) = self.metadata {
            metadata.validate()?;
        }

        Ok(())
    }
}

/// Builder for [`ContextPackSpec`].
#[derive(Debug, Clone, Default)]
pub struct ContextPackSpecBuilder {
    spec_id: Option<String>,
    roots: Vec<String>,
    budget: Option<BudgetConstraint>,
    target_profile: Option<String>,
    dependency_reviews: Vec<DependencyReview>,
    metadata: Option<PackMetadata>,
}

impl ContextPackSpecBuilder {
    /// Sets the spec ID.
    #[must_use]
    pub fn spec_id(mut self, spec_id: impl Into<String>) -> Self {
        self.spec_id = Some(spec_id.into());
        self
    }

    /// Adds a root stable ID.
    #[must_use]
    pub fn root(mut self, stable_id: impl Into<String>) -> Self {
        self.roots.push(stable_id.into());
        self
    }

    /// Sets all roots at once (replaces existing).
    #[must_use]
    pub fn roots(mut self, roots: Vec<String>) -> Self {
        self.roots = roots;
        self
    }

    /// Sets the budget constraint.
    #[must_use]
    pub const fn budget(mut self, budget: BudgetConstraint) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Sets the target profile.
    #[must_use]
    pub fn target_profile(mut self, target_profile: impl Into<String>) -> Self {
        self.target_profile = Some(target_profile.into());
        self
    }

    /// Adds a dependency review.
    #[must_use]
    pub fn dependency_review(mut self, review: DependencyReview) -> Self {
        self.dependency_reviews.push(review);
        self
    }

    /// Sets the metadata.
    #[must_use]
    pub fn metadata(mut self, metadata: PackMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Builds the `ContextPackSpec`.
    ///
    /// # Errors
    ///
    /// Returns [`PackSpecError`] if required fields are missing or validation
    /// fails.
    pub fn build(self) -> Result<ContextPackSpec, PackSpecError> {
        let spec = ContextPackSpec {
            schema: CONTEXT_PACK_SPEC_SCHEMA.to_string(),
            schema_version: CONTEXT_PACK_SPEC_VERSION.to_string(),
            spec_id: self.spec_id.ok_or_else(|| PackSpecError::MissingField {
                field: "spec_id".to_string(),
            })?,
            roots: self.roots,
            budget: self.budget.unwrap_or_default(),
            target_profile: self
                .target_profile
                .ok_or_else(|| PackSpecError::MissingField {
                    field: "target_profile".to_string(),
                })?,
            dependency_reviews: self.dependency_reviews,
            metadata: self.metadata,
        };
        spec.validate()?;
        Ok(spec)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    // =========================================================================
    // TypedQuantity Tests
    // =========================================================================

    #[test]
    fn test_typed_quantity_creation() {
        let tokens = TypedQuantity::tokens(1000);
        assert_eq!(tokens.value(), 1000);
        assert_eq!(tokens.unit(), QuantityUnit::Tokens);

        let bytes = TypedQuantity::bytes(1024);
        assert_eq!(bytes.value(), 1024);
        assert_eq!(bytes.unit(), QuantityUnit::Bytes);

        let artifacts = TypedQuantity::artifacts(50);
        assert_eq!(artifacts.value(), 50);
        assert_eq!(artifacts.unit(), QuantityUnit::Artifacts);

        let ms = TypedQuantity::ms(5000);
        assert_eq!(ms.value(), 5000);
        assert_eq!(ms.unit(), QuantityUnit::Ms);

        let count = TypedQuantity::count(10);
        assert_eq!(count.value(), 10);
        assert_eq!(count.unit(), QuantityUnit::Count);
    }

    #[test]
    fn test_typed_quantity_checked_add_same_unit() {
        let a = TypedQuantity::tokens(1000);
        let b = TypedQuantity::tokens(500);
        let result = a.checked_add(&b).unwrap();
        assert_eq!(result.value(), 1500);
        assert_eq!(result.unit(), QuantityUnit::Tokens);
    }

    #[test]
    fn test_typed_quantity_checked_add_unit_mismatch() {
        let tokens = TypedQuantity::tokens(1000);
        let bytes = TypedQuantity::bytes(1024);
        let result = tokens.checked_add(&bytes);
        assert!(matches!(result, Err(PackSpecError::UnitMismatch { .. })));
    }

    #[test]
    fn test_typed_quantity_checked_add_overflow() {
        let a = TypedQuantity::tokens(u64::MAX);
        let b = TypedQuantity::tokens(1);
        let result = a.checked_add(&b);
        assert!(matches!(
            result,
            Err(PackSpecError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn test_typed_quantity_checked_sub() {
        let a = TypedQuantity::tokens(1000);
        let b = TypedQuantity::tokens(300);
        let result = a.checked_sub(&b).unwrap();
        assert_eq!(result.value(), 700);
    }

    #[test]
    fn test_typed_quantity_checked_sub_underflow() {
        let a = TypedQuantity::tokens(100);
        let b = TypedQuantity::tokens(200);
        let result = a.checked_sub(&b);
        assert!(matches!(
            result,
            Err(PackSpecError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn test_typed_quantity_checked_mul() {
        let a = TypedQuantity::tokens(100);
        let result = a.checked_mul(5).unwrap();
        assert_eq!(result.value(), 500);
    }

    #[test]
    fn test_typed_quantity_checked_mul_overflow() {
        let a = TypedQuantity::tokens(u64::MAX);
        let result = a.checked_mul(2);
        assert!(matches!(
            result,
            Err(PackSpecError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn test_typed_quantity_checked_div() {
        let a = TypedQuantity::tokens(100);
        let result = a.checked_div(5).unwrap();
        assert_eq!(result.value(), 20);
    }

    #[test]
    fn test_typed_quantity_checked_div_by_zero() {
        let a = TypedQuantity::tokens(100);
        let result = a.checked_div(0);
        assert!(matches!(
            result,
            Err(PackSpecError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn test_typed_quantity_saturating_add() {
        let a = TypedQuantity::tokens(u64::MAX - 10);
        let b = TypedQuantity::tokens(100);
        let result = a.saturating_add(&b).unwrap();
        assert_eq!(result.value(), u64::MAX);
    }

    #[test]
    fn test_typed_quantity_saturating_sub() {
        let a = TypedQuantity::tokens(100);
        let b = TypedQuantity::tokens(200);
        let result = a.saturating_sub(&b).unwrap();
        assert_eq!(result.value(), 0);
    }

    #[test]
    fn test_typed_quantity_serialization() {
        let q = TypedQuantity::tokens(1000);
        let json = serde_json::to_string(&q).unwrap();
        assert!(json.contains("\"value\":1000"));
        assert!(json.contains("\"unit\":\"tokens\""));

        let deserialized: TypedQuantity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, q);
    }

    #[test]
    fn test_typed_quantity_deny_unknown_fields() {
        let json = r#"{"value": 1000, "unit": "tokens", "extra": "field"}"#;
        let result: Result<TypedQuantity, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_typed_quantity_display() {
        let q = TypedQuantity::tokens(1000);
        assert_eq!(format!("{q}"), "1000 tokens");
    }

    // =========================================================================
    // BudgetConstraint Tests
    // =========================================================================

    #[test]
    fn test_budget_constraint_builder() {
        let budget = BudgetConstraint::builder()
            .max_tokens(TypedQuantity::tokens(100_000))
            .max_bytes(TypedQuantity::bytes(1_048_576))
            .max_artifacts(TypedQuantity::artifacts(50))
            .max_time_ms(TypedQuantity::ms(30_000))
            .build();

        assert_eq!(budget.max_tokens.unwrap().value(), 100_000);
        assert_eq!(budget.max_bytes.unwrap().value(), 1_048_576);
        assert_eq!(budget.max_artifacts.unwrap().value(), 50);
        assert_eq!(budget.max_time_ms.unwrap().value(), 30_000);
    }

    #[test]
    fn test_budget_constraint_unlimited() {
        let budget = BudgetConstraint::unlimited();
        assert!(budget.is_unlimited());
        assert!(budget.max_tokens.is_none());
        assert!(budget.max_bytes.is_none());
        assert!(budget.max_artifacts.is_none());
        assert!(budget.max_time_ms.is_none());
    }

    #[test]
    fn test_budget_constraint_validate_success() {
        let budget = BudgetConstraint::builder()
            .max_tokens(TypedQuantity::tokens(100_000))
            .max_bytes(TypedQuantity::bytes(1024))
            .build();

        assert!(budget.validate().is_ok());
    }

    #[test]
    fn test_budget_constraint_validate_wrong_unit() {
        let budget = BudgetConstraint {
            max_tokens: Some(TypedQuantity::bytes(100)), // Wrong unit!
            max_bytes: None,
            max_artifacts: None,
            max_time_ms: None,
        };

        let result = budget.validate();
        assert!(matches!(result, Err(PackSpecError::UnitMismatch { .. })));
    }

    #[test]
    fn test_budget_constraint_serialization() {
        let budget = BudgetConstraint::builder()
            .max_tokens(TypedQuantity::tokens(1000))
            .build();

        let json = serde_json::to_string(&budget).unwrap();
        let deserialized: BudgetConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_tokens.unwrap().value(), 1000);
    }

    // =========================================================================
    // DependencyReview Tests
    // =========================================================================

    #[test]
    fn test_dependency_review_creation() {
        let review = DependencyReview::new("org:doc:readme", "a".repeat(64));
        assert_eq!(review.stable_id, "org:doc:readme");
        assert_eq!(review.content_hash.len(), 64);
        assert!(review.reviewed_at.is_none());
    }

    #[test]
    fn test_dependency_review_with_timestamp() {
        let fixed_time = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let review = DependencyReview::with_timestamp("org:doc:readme", "a".repeat(64), fixed_time);
        assert_eq!(review.reviewed_at, Some(fixed_time));
    }

    #[test]
    fn test_dependency_review_validate_success() {
        let review = DependencyReview::new("org:doc:readme", "a".repeat(64));
        assert!(review.validate().is_ok());
    }

    #[test]
    fn test_dependency_review_validate_invalid_hash() {
        let review = DependencyReview::new("org:doc:readme", "tooshort");
        let result = review.validate();
        assert!(matches!(result, Err(PackSpecError::InvalidQuantity { .. })));
    }

    #[test]
    fn test_dependency_review_validate_long_stable_id() {
        let review = DependencyReview::new("x".repeat(MAX_STABLE_ID_LENGTH + 1), "a".repeat(64));
        let result = review.validate();
        assert!(matches!(result, Err(PackSpecError::FieldTooLong { .. })));
    }

    // =========================================================================
    // PackMetadata Tests
    // =========================================================================

    #[test]
    fn test_pack_metadata_builder() {
        let metadata = PackMetadata::builder()
            .author("test-author")
            .description("A test pack")
            .label("category:test")
            .label("priority:high")
            .build();

        assert_eq!(metadata.author.as_deref(), Some("test-author"));
        assert_eq!(metadata.description.as_deref(), Some("A test pack"));
        assert_eq!(metadata.labels.len(), 2);
    }

    #[test]
    fn test_pack_metadata_validate_long_author() {
        let metadata = PackMetadata {
            author: Some("x".repeat(MAX_AUTHOR_LENGTH + 1)),
            ..Default::default()
        };
        let result = metadata.validate();
        assert!(matches!(result, Err(PackSpecError::FieldTooLong { .. })));
    }

    #[test]
    fn test_pack_metadata_validate_too_many_labels() {
        let labels: Vec<String> = (0..=MAX_LABELS).map(|i| format!("label-{i}")).collect();
        let metadata = PackMetadata {
            labels,
            ..Default::default()
        };
        let result = metadata.validate();
        assert!(matches!(result, Err(PackSpecError::TooManyItems { .. })));
    }

    // =========================================================================
    // ContextPackSpec Tests
    // =========================================================================

    #[test]
    fn test_context_pack_spec_builder_success() {
        let spec = ContextPackSpec::builder()
            .spec_id("pack-001")
            .root("org:doc:readme")
            .root("org:doc:agents")
            .budget(
                BudgetConstraint::builder()
                    .max_tokens(TypedQuantity::tokens(100_000))
                    .build(),
            )
            .target_profile("org:profile:claude-code")
            .build()
            .unwrap();

        assert_eq!(spec.schema, CONTEXT_PACK_SPEC_SCHEMA);
        assert_eq!(spec.schema_version, CONTEXT_PACK_SPEC_VERSION);
        assert_eq!(spec.spec_id, "pack-001");
        assert_eq!(spec.roots.len(), 2);
        assert_eq!(spec.target_profile, "org:profile:claude-code");
    }

    #[test]
    fn test_context_pack_spec_builder_missing_spec_id() {
        let result = ContextPackSpec::builder()
            .root("org:doc:readme")
            .budget(BudgetConstraint::unlimited())
            .target_profile("org:profile:test")
            .build();

        assert!(matches!(result, Err(PackSpecError::MissingField { field }) if field == "spec_id"));
    }

    #[test]
    fn test_context_pack_spec_builder_missing_target_profile() {
        let result = ContextPackSpec::builder()
            .spec_id("pack-001")
            .root("org:doc:readme")
            .budget(BudgetConstraint::unlimited())
            .build();

        assert!(matches!(
            result,
            Err(PackSpecError::MissingField { field }) if field == "target_profile"
        ));
    }

    #[test]
    fn test_context_pack_spec_builder_empty_roots() {
        let result = ContextPackSpec::builder()
            .spec_id("pack-001")
            .budget(BudgetConstraint::unlimited())
            .target_profile("org:profile:test")
            .build();

        assert!(matches!(result, Err(PackSpecError::EmptyRoots)));
    }

    #[test]
    fn test_context_pack_spec_validate_invalid_spec_id() {
        let result = ContextPackSpec::builder()
            .spec_id("invalid spec id!") // Contains space and !
            .root("org:doc:readme")
            .budget(BudgetConstraint::unlimited())
            .target_profile("org:profile:test")
            .build();

        assert!(matches!(result, Err(PackSpecError::InvalidSpecId { .. })));
    }

    #[test]
    fn test_context_pack_spec_serialization() {
        let spec = ContextPackSpec::builder()
            .spec_id("pack-001")
            .root("org:doc:readme")
            .budget(
                BudgetConstraint::builder()
                    .max_tokens(TypedQuantity::tokens(1000))
                    .build(),
            )
            .target_profile("org:profile:test")
            .build()
            .unwrap();

        let json = serde_json::to_string(&spec).unwrap();
        let deserialized: ContextPackSpec = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.spec_id, spec.spec_id);
        assert_eq!(deserialized.roots, spec.roots);
    }

    #[test]
    fn test_context_pack_spec_deny_unknown_fields() {
        let json = r#"{
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "spec_id": "pack-001",
            "roots": ["org:doc:readme"],
            "budget": {},
            "target_profile": "org:profile:test",
            "extra_field": "not allowed"
        }"#;

        let result: Result<ContextPackSpec, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_context_pack_spec_with_dependency_reviews() {
        let spec = ContextPackSpec::builder()
            .spec_id("pack-001")
            .root("org:doc:readme")
            .budget(BudgetConstraint::unlimited())
            .target_profile("org:profile:test")
            .dependency_review(DependencyReview::new("org:lib:utils", "a".repeat(64)))
            .dependency_review(DependencyReview::new("org:lib:core", "b".repeat(64)))
            .build()
            .unwrap();

        assert_eq!(spec.dependency_reviews.len(), 2);
    }

    #[test]
    fn test_context_pack_spec_with_metadata() {
        let spec = ContextPackSpec::builder()
            .spec_id("pack-001")
            .root("org:doc:readme")
            .budget(BudgetConstraint::unlimited())
            .target_profile("org:profile:test")
            .metadata(
                PackMetadata::builder()
                    .author("test-author")
                    .description("A test pack")
                    .build(),
            )
            .build()
            .unwrap();

        assert!(spec.metadata.is_some());
        assert_eq!(
            spec.metadata.as_ref().unwrap().author.as_deref(),
            Some("test-author")
        );
    }

    // =========================================================================
    // Property Tests for Overflow Protection
    // =========================================================================

    #[test]
    fn test_property_add_commutative() {
        let a = TypedQuantity::tokens(100);
        let b = TypedQuantity::tokens(200);

        let ab = a.checked_add(&b).unwrap();
        let ba = b.checked_add(&a).unwrap();

        assert_eq!(ab.value(), ba.value());
    }

    #[test]
    fn test_property_add_identity() {
        let a = TypedQuantity::tokens(100);
        let zero = TypedQuantity::tokens(0);

        let result = a.checked_add(&zero).unwrap();
        assert_eq!(result.value(), a.value());
    }

    #[test]
    fn test_property_mul_identity() {
        let a = TypedQuantity::tokens(100);

        let result = a.checked_mul(1).unwrap();
        assert_eq!(result.value(), a.value());
    }

    #[test]
    fn test_property_mul_zero() {
        let a = TypedQuantity::tokens(100);

        let result = a.checked_mul(0).unwrap();
        assert_eq!(result.value(), 0);
    }

    #[test]
    fn test_property_sub_self_is_zero() {
        let a = TypedQuantity::tokens(100);

        let result = a.checked_sub(&a).unwrap();
        assert_eq!(result.value(), 0);
    }

    #[test]
    fn test_property_overflow_near_max() {
        // Test values near u64::MAX
        let near_max = TypedQuantity::tokens(u64::MAX - 1);
        let one = TypedQuantity::tokens(1);
        let two = TypedQuantity::tokens(2);

        // Should succeed: (MAX-1) + 1 = MAX
        let result = near_max.checked_add(&one);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value(), u64::MAX);

        // Should fail: (MAX-1) + 2 overflows
        let result = near_max.checked_add(&two);
        assert!(matches!(
            result,
            Err(PackSpecError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn test_property_saturating_never_overflows() {
        let max = TypedQuantity::tokens(u64::MAX);
        let big = TypedQuantity::tokens(u64::MAX);

        // Saturating add should not fail, even with overflow
        let result = max.saturating_add(&big).unwrap();
        assert_eq!(result.value(), u64::MAX);
    }

    #[test]
    fn test_property_saturating_sub_never_underflows() {
        let small = TypedQuantity::tokens(10);
        let big = TypedQuantity::tokens(1000);

        // Saturating sub should not fail, even with underflow
        let result = small.saturating_sub(&big).unwrap();
        assert_eq!(result.value(), 0);
    }

    // =========================================================================
    // Validation Tests for Schema Compliance
    // =========================================================================

    #[test]
    fn test_validation_rejects_float_values() {
        // JSON with float value should not parse into TypedQuantity (which uses u64)
        let json = r#"{"value": 1.5, "unit": "tokens"}"#;
        let result: Result<TypedQuantity, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_rejects_negative_values() {
        // JSON with negative value should not parse (u64 is unsigned)
        let json = r#"{"value": -100, "unit": "tokens"}"#;
        let result: Result<TypedQuantity, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_rejects_invalid_unit() {
        let json = r#"{"value": 100, "unit": "invalid"}"#;
        let result: Result<TypedQuantity, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let error = PackSpecError::UnitMismatch {
            expected: QuantityUnit::Tokens,
            actual: QuantityUnit::Bytes,
        };
        let msg = error.to_string();
        assert!(msg.contains("tokens"));
        assert!(msg.contains("bytes"));

        let error = PackSpecError::ArithmeticOverflow {
            operation: "test operation".to_string(),
        };
        let msg = error.to_string();
        assert!(msg.contains("overflow"));
        assert!(msg.contains("test operation"));
    }

    // =========================================================================
    // CAC Validator Integration Tests
    // =========================================================================

    #[test]
    fn test_cac_validation_with_bootstrap_schema() {
        use crate::bootstrap::get_bootstrap_schema;
        use crate::cac::CacValidator;

        // Get the bootstrap schema
        let schema_entry = get_bootstrap_schema(CONTEXT_PACK_SPEC_SCHEMA)
            .expect("ContextPackSpec schema should exist in bootstrap bundle");
        let schema_json = schema_entry
            .parse_json()
            .expect("Schema should be valid JSON");

        // Create validator
        let validator = CacValidator::new(&schema_json).expect("Schema should be valid");

        // Create a valid spec and validate
        let spec = ContextPackSpec::builder()
            .spec_id("pack-001")
            .root("org:doc:readme")
            .budget(
                BudgetConstraint::builder()
                    .max_tokens(TypedQuantity::tokens(100_000))
                    .build(),
            )
            .target_profile("org:profile:claude-code")
            .build()
            .unwrap();

        let spec_json: serde_json::Value = serde_json::to_value(&spec).unwrap();
        let result = validator.validate(&spec_json);
        assert!(
            result.is_ok(),
            "Valid spec should pass CAC validation: {result:?}"
        );
    }

    #[test]
    fn test_cac_validation_rejects_unknown_fields() {
        use serde_json::json;

        use crate::bootstrap::get_bootstrap_schema;
        use crate::cac::CacValidator;

        // Get the bootstrap schema
        let schema_entry = get_bootstrap_schema(CONTEXT_PACK_SPEC_SCHEMA)
            .expect("ContextPackSpec schema should exist in bootstrap bundle");
        let schema_json = schema_entry
            .parse_json()
            .expect("Schema should be valid JSON");

        // Create validator
        let validator = CacValidator::new(&schema_json).expect("Schema should be valid");

        // Create spec with unknown field
        let spec_with_extra = json!({
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "spec_id": "pack-001",
            "roots": ["org:doc:readme"],
            "budget": {},
            "target_profile": "org:profile:test",
            "unknown_field": "should be rejected"
        });

        let result = validator.validate(&spec_with_extra);
        assert!(result.is_err(), "Unknown field should be rejected");
    }

    #[test]
    fn test_cac_validation_rejects_missing_required() {
        use serde_json::json;

        use crate::bootstrap::get_bootstrap_schema;
        use crate::cac::CacValidator;

        // Get the bootstrap schema
        let schema_entry = get_bootstrap_schema(CONTEXT_PACK_SPEC_SCHEMA)
            .expect("ContextPackSpec schema should exist in bootstrap bundle");
        let schema_json = schema_entry
            .parse_json()
            .expect("Schema should be valid JSON");

        // Create validator
        let validator = CacValidator::new(&schema_json).expect("Schema should be valid");

        // Missing spec_id
        let spec_missing_field = json!({
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "roots": ["org:doc:readme"],
            "budget": {},
            "target_profile": "org:profile:test"
        });

        let result = validator.validate(&spec_missing_field);
        assert!(result.is_err(), "Missing required field should be rejected");
    }

    #[test]
    fn test_cac_validation_typed_quantity_unit_mismatch() {
        use serde_json::json;

        use crate::bootstrap::get_bootstrap_schema;
        use crate::cac::CacValidator;

        // Get the bootstrap schema
        let schema_entry = get_bootstrap_schema(CONTEXT_PACK_SPEC_SCHEMA)
            .expect("ContextPackSpec schema should exist in bootstrap bundle");
        let schema_json = schema_entry
            .parse_json()
            .expect("Schema should be valid JSON");

        // Create validator
        let validator = CacValidator::new(&schema_json).expect("Schema should be valid");

        // Invalid unit for max_tokens (should be "tokens", not "bytes")
        let spec_wrong_unit = json!({
            "schema": "bootstrap:context_pack_spec.v1",
            "schema_version": "v1",
            "spec_id": "pack-001",
            "roots": ["org:doc:readme"],
            "budget": {
                "max_tokens": {
                    "value": 1000,
                    "unit": "invalid_unit"
                }
            },
            "target_profile": "org:profile:test"
        });

        let result = validator.validate(&spec_wrong_unit);
        assert!(result.is_err(), "Invalid unit should be rejected by schema");
    }

    #[test]
    fn test_cac_validation_with_all_fields() {
        use crate::bootstrap::get_bootstrap_schema;
        use crate::cac::CacValidator;

        // Get the bootstrap schema
        let schema_entry = get_bootstrap_schema(CONTEXT_PACK_SPEC_SCHEMA)
            .expect("ContextPackSpec schema should exist in bootstrap bundle");
        let schema_json = schema_entry
            .parse_json()
            .expect("Schema should be valid JSON");

        // Create validator
        let validator = CacValidator::new(&schema_json).expect("Schema should be valid");

        // Create a fully-populated spec
        let spec = ContextPackSpec::builder()
            .spec_id("pack-full-001")
            .root("org:doc:readme")
            .root("org:doc:agents")
            .root("org:doc:security")
            .budget(
                BudgetConstraint::builder()
                    .max_tokens(TypedQuantity::tokens(100_000))
                    .max_bytes(TypedQuantity::bytes(10_485_760))
                    .max_artifacts(TypedQuantity::artifacts(100))
                    .max_time_ms(TypedQuantity::ms(60_000))
                    .build(),
            )
            .target_profile("org:profile:claude-code")
            .dependency_review(DependencyReview::new("org:lib:utils", "a".repeat(64)))
            .dependency_review(DependencyReview::new("org:lib:core", "b".repeat(64)))
            .metadata(
                PackMetadata::builder()
                    .author("test-author")
                    .description("A comprehensive test pack")
                    .label("category:test")
                    .label("priority:high")
                    .build(),
            )
            .build()
            .unwrap();

        let spec_json: serde_json::Value = serde_json::to_value(&spec).unwrap();
        let result = validator.validate(&spec_json);
        assert!(
            result.is_ok(),
            "Fully-populated spec should pass CAC validation: {result:?}"
        );
    }

    #[test]
    fn test_bootstrap_schema_exists() {
        use crate::bootstrap::get_bootstrap_schema;

        // Verify the schema exists in the bootstrap bundle
        let result = get_bootstrap_schema(CONTEXT_PACK_SPEC_SCHEMA);
        assert!(
            result.is_ok(),
            "ContextPackSpec schema should be in bootstrap bundle: {result:?}"
        );

        let schema = result.unwrap();
        assert_eq!(schema.stable_id, CONTEXT_PACK_SPEC_SCHEMA);
        assert!(!schema.content.is_empty());
    }

    #[test]
    fn test_bootstrap_schema_parses_as_json() {
        use crate::bootstrap::get_bootstrap_schema;

        let schema = get_bootstrap_schema(CONTEXT_PACK_SPEC_SCHEMA).expect("Schema should exist");
        let json = schema.parse_json().expect("Schema should be valid JSON");

        // Verify key schema properties
        assert_eq!(
            json.get("$id").and_then(|v| v.as_str()),
            Some("bootstrap:context_pack_spec.v1")
        );
        assert_eq!(
            json.get("$schema").and_then(|v| v.as_str()),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert!(json.get("$defs").is_some(), "Schema should have $defs");
        assert!(
            json.get("properties").is_some(),
            "Schema should have properties"
        );
    }
}
