//! Target Profile schema for CAC export pipeline.
//!
//! This module provides Rust types for the `TargetProfile` schema, which
//! decouples CAC-JSON from vendor-specific layouts and configures how
//! artifacts are rendered, budgeted, and delivered to consumer agents.
//!
//! # Design Principles
//!
//! - **Stage Taxonomy**: Profiles define rendering policies per stage
//!   (plan/implement/review/ops) following DD-0005
//! - **Typed Quantities**: Budget limits use explicit units to prevent "Mars
//!   Climate Orbiter" errors (per DD-0007)
//! - **Strict Serde**: All types use `#[serde(deny_unknown_fields)]` to reject
//!   unknown fields (CTR-1604)
//! - **Forward Compatibility**: Enums use `#[non_exhaustive]` for safe
//!   extension
//!
//! # Example
//!
//! ```rust
//! use apm2_core::cac::target_profile::{
//!     BudgetPolicy, DeliveryConstraints, OutputFormat, ProvenanceEmbed, RenderingPolicy,
//!     RetrievalPolicy, Stage, TargetProfile, TypedQuantity,
//! };
//!
//! let profile = TargetProfile::builder()
//!     .profile_id("claude-code-default")
//!     .version("2026-01-27")
//!     .description("Default profile for Claude Code agent consumption")
//!     .rendering_policy(
//!         RenderingPolicy::builder()
//!             .stage(Stage::Implement)
//!             .max_context_tokens(TypedQuantity::tokens(100_000))
//!             .include_provenance(true)
//!             .build()
//!             .unwrap(),
//!     )
//!     .budget_policy(
//!         BudgetPolicy::builder()
//!             .max_tokens(TypedQuantity::tokens(100_000))
//!             .max_artifacts(TypedQuantity::artifacts(50))
//!             .max_bytes(TypedQuantity::bytes(10_485_760))
//!             .build(),
//!     )
//!     .retrieval_policy(
//!         RetrievalPolicy::builder()
//!             .max_fetch_bytes(TypedQuantity::bytes(52_428_800))
//!             .inline_threshold(TypedQuantity::bytes(4096))
//!             .build(),
//!     )
//!     .delivery_constraints(
//!         DeliveryConstraints::builder()
//!             .output_format(OutputFormat::Markdown)
//!             .provenance_embed(ProvenanceEmbed::Inline)
//!             .build(),
//!     )
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(profile.profile_id, "claude-code-default");
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::pack_spec::QuantityUnit;

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for profile IDs.
pub const MAX_PROFILE_ID_LENGTH: usize = 256;

/// Maximum length for version strings.
pub const MAX_VERSION_LENGTH: usize = 64;

/// Maximum length for description strings.
pub const MAX_DESCRIPTION_LENGTH: usize = 4096;

/// Maximum length for format hint strings.
pub const MAX_FORMAT_HINT_LENGTH: usize = 256;

/// Default inline threshold in bytes (4 KiB).
pub const DEFAULT_INLINE_THRESHOLD_BYTES: u64 = 4096;

/// Default max fetch bytes (50 MiB).
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 52_428_800;

/// Default max context tokens.
pub const DEFAULT_MAX_CONTEXT_TOKENS: u64 = 100_000;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during `TargetProfile` operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetProfileError {
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

    /// Invalid profile ID format.
    #[error("invalid profile_id format: {message}")]
    InvalidProfileId {
        /// Description of the format violation.
        message: String,
    },

    /// Unit mismatch in a typed quantity.
    #[error("unit mismatch for {field}: expected {expected}, got {actual}")]
    UnitMismatch {
        /// The field name.
        field: String,
        /// Expected unit.
        expected: QuantityUnit,
        /// Actual unit provided.
        actual: QuantityUnit,
    },

    /// Invalid quantity value (e.g., zero when not allowed).
    #[error("invalid quantity for {field}: {message}")]
    InvalidQuantity {
        /// The field name.
        field: String,
        /// Description of the invalid value.
        message: String,
    },

    /// Validation error for constraints.
    #[error("validation error: {message}")]
    ValidationError {
        /// Description of the validation failure.
        message: String,
    },
}

// ============================================================================
// TypedQuantity (re-export from pack_spec for convenience)
// ============================================================================

/// A quantity with explicit unit for type-safe arithmetic.
///
/// Re-exports from `pack_spec` module for convenience. See
/// [`super::pack_spec::TypedQuantity`] for full documentation.
pub use super::pack_spec::TypedQuantity;

// ============================================================================
// Stage Enum
// ============================================================================

/// Pipeline stage taxonomy for rendering policies.
///
/// Stages represent the different phases of agent work where context
/// requirements differ. Per DD-0005, profiles can specify different
/// rendering policies per stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Stage {
    /// Planning stage - high-level task decomposition.
    Plan,
    /// Implementation stage - code writing and modification.
    Implement,
    /// Review stage - code review and validation.
    Review,
    /// Operations stage - deployment and monitoring.
    Ops,
}

impl Stage {
    /// Returns the string representation of the stage.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Implement => "implement",
            Self::Review => "review",
            Self::Ops => "ops",
        }
    }

    /// Parses a stage from a string.
    ///
    /// # Errors
    ///
    /// Returns [`TargetProfileError::ValidationError`] if the string is not
    /// a recognized stage.
    pub fn parse(s: &str) -> Result<Self, TargetProfileError> {
        match s.to_lowercase().as_str() {
            "plan" => Ok(Self::Plan),
            "implement" => Ok(Self::Implement),
            "review" => Ok(Self::Review),
            "ops" => Ok(Self::Ops),
            _ => Err(TargetProfileError::ValidationError {
                message: format!("unknown stage: {s}"),
            }),
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// OutputFormat Enum
// ============================================================================

/// Output format for rendered context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputFormat {
    /// Markdown format (default).
    #[default]
    Markdown,
    /// Plain text format.
    PlainText,
    /// JSON format.
    Json,
    /// XML format.
    Xml,
}

impl OutputFormat {
    /// Returns the string representation of the format.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::PlainText => "plain_text",
            Self::Json => "json",
            Self::Xml => "xml",
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// ProvenanceEmbed Enum
// ============================================================================

/// How provenance information is embedded in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProvenanceEmbed {
    /// Embed provenance inline with content (default).
    #[default]
    Inline,
    /// Embed provenance in a separate footer section.
    Footer,
    /// Embed provenance as structured metadata.
    Metadata,
    /// Do not embed provenance.
    None,
}

impl ProvenanceEmbed {
    /// Returns the string representation of the embed mode.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Footer => "footer",
            Self::Metadata => "metadata",
            Self::None => "none",
        }
    }
}

impl std::fmt::Display for ProvenanceEmbed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// RenderingPolicy
// ============================================================================

/// Rendering policy for a specific pipeline stage.
///
/// Defines how artifacts are formatted and what context limits apply
/// for a given stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderingPolicy {
    /// The stage this policy applies to.
    pub stage: Stage,

    /// Maximum context tokens for this stage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_context_tokens: Option<TypedQuantity>,

    /// Whether to include provenance information.
    #[serde(default = "default_include_provenance")]
    pub include_provenance: bool,

    /// Optional format hint for rendering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_hint: Option<String>,
}

const fn default_include_provenance() -> bool {
    true
}

impl RenderingPolicy {
    /// Creates a new builder for `RenderingPolicy`.
    #[must_use]
    pub fn builder() -> RenderingPolicyBuilder {
        RenderingPolicyBuilder::default()
    }

    /// Validates the rendering policy.
    ///
    /// # Errors
    ///
    /// Returns validation errors for constraint violations.
    pub fn validate(&self) -> Result<(), TargetProfileError> {
        // Validate max_context_tokens unit
        if let Some(ref tokens) = self.max_context_tokens {
            if tokens.unit() != QuantityUnit::Tokens {
                return Err(TargetProfileError::UnitMismatch {
                    field: "max_context_tokens".to_string(),
                    expected: QuantityUnit::Tokens,
                    actual: tokens.unit(),
                });
            }
        }

        // Validate format_hint length
        if let Some(ref hint) = self.format_hint {
            if hint.len() > MAX_FORMAT_HINT_LENGTH {
                return Err(TargetProfileError::FieldTooLong {
                    field: "format_hint".to_string(),
                    max_length: MAX_FORMAT_HINT_LENGTH,
                    actual_length: hint.len(),
                });
            }
        }

        Ok(())
    }
}

/// Builder for [`RenderingPolicy`].
#[derive(Debug, Clone, Default)]
pub struct RenderingPolicyBuilder {
    stage: Option<Stage>,
    max_context_tokens: Option<TypedQuantity>,
    include_provenance: bool,
    format_hint: Option<String>,
}

impl RenderingPolicyBuilder {
    /// Sets the stage.
    #[must_use]
    pub const fn stage(mut self, stage: Stage) -> Self {
        self.stage = Some(stage);
        self
    }

    /// Sets the maximum context tokens.
    #[must_use]
    pub const fn max_context_tokens(mut self, tokens: TypedQuantity) -> Self {
        self.max_context_tokens = Some(tokens);
        self
    }

    /// Sets whether to include provenance.
    #[must_use]
    pub const fn include_provenance(mut self, include: bool) -> Self {
        self.include_provenance = include;
        self
    }

    /// Sets the format hint.
    #[must_use]
    pub fn format_hint(mut self, hint: impl Into<String>) -> Self {
        self.format_hint = Some(hint.into());
        self
    }

    /// Builds the `RenderingPolicy`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetProfileError`] if required fields are missing or
    /// validation fails.
    pub fn build(self) -> Result<RenderingPolicy, TargetProfileError> {
        let policy = RenderingPolicy {
            stage: self.stage.ok_or_else(|| TargetProfileError::MissingField {
                field: "stage".to_string(),
            })?,
            max_context_tokens: self.max_context_tokens,
            include_provenance: self.include_provenance,
            format_hint: self.format_hint,
        };
        policy.validate()?;
        Ok(policy)
    }
}

// ============================================================================
// BudgetPolicy
// ============================================================================

/// Budget policy defining resource limits for context consumption.
///
/// All limits use typed quantities to prevent unit mismatch errors.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetPolicy {
    /// Maximum tokens allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<TypedQuantity>,

    /// Maximum artifact count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_artifacts: Option<TypedQuantity>,

    /// Maximum bytes allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<TypedQuantity>,
}

impl BudgetPolicy {
    /// Creates a new builder for `BudgetPolicy`.
    #[must_use]
    pub const fn builder() -> BudgetPolicyBuilder {
        BudgetPolicyBuilder::new()
    }

    /// Creates an unlimited budget policy.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_tokens: None,
            max_artifacts: None,
            max_bytes: None,
        }
    }

    /// Returns true if all constraints are unlimited.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.max_tokens.is_none() && self.max_artifacts.is_none() && self.max_bytes.is_none()
    }

    /// Validates the budget policy.
    ///
    /// # Errors
    ///
    /// Returns validation errors for unit mismatches.
    pub fn validate(&self) -> Result<(), TargetProfileError> {
        if let Some(ref tokens) = self.max_tokens {
            if tokens.unit() != QuantityUnit::Tokens {
                return Err(TargetProfileError::UnitMismatch {
                    field: "max_tokens".to_string(),
                    expected: QuantityUnit::Tokens,
                    actual: tokens.unit(),
                });
            }
        }
        if let Some(ref artifacts) = self.max_artifacts {
            if artifacts.unit() != QuantityUnit::Artifacts {
                return Err(TargetProfileError::UnitMismatch {
                    field: "max_artifacts".to_string(),
                    expected: QuantityUnit::Artifacts,
                    actual: artifacts.unit(),
                });
            }
        }
        if let Some(ref bytes) = self.max_bytes {
            if bytes.unit() != QuantityUnit::Bytes {
                return Err(TargetProfileError::UnitMismatch {
                    field: "max_bytes".to_string(),
                    expected: QuantityUnit::Bytes,
                    actual: bytes.unit(),
                });
            }
        }
        Ok(())
    }
}

/// Builder for [`BudgetPolicy`].
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_field_names)]
pub struct BudgetPolicyBuilder {
    max_tokens: Option<TypedQuantity>,
    max_artifacts: Option<TypedQuantity>,
    max_bytes: Option<TypedQuantity>,
}

impl BudgetPolicyBuilder {
    /// Creates a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_tokens: None,
            max_artifacts: None,
            max_bytes: None,
        }
    }

    /// Sets the maximum tokens.
    #[must_use]
    pub const fn max_tokens(mut self, tokens: TypedQuantity) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    /// Sets the maximum artifacts.
    #[must_use]
    pub const fn max_artifacts(mut self, artifacts: TypedQuantity) -> Self {
        self.max_artifacts = Some(artifacts);
        self
    }

    /// Sets the maximum bytes.
    #[must_use]
    pub const fn max_bytes(mut self, bytes: TypedQuantity) -> Self {
        self.max_bytes = Some(bytes);
        self
    }

    /// Builds the `BudgetPolicy`.
    #[must_use]
    pub const fn build(self) -> BudgetPolicy {
        BudgetPolicy {
            max_tokens: self.max_tokens,
            max_artifacts: self.max_artifacts,
            max_bytes: self.max_bytes,
        }
    }
}

// ============================================================================
// RetrievalPolicy
// ============================================================================

/// Retrieval policy for fetching external artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPolicy {
    /// Maximum bytes to fetch from external sources.
    #[serde(default = "default_max_fetch_bytes")]
    pub max_fetch_bytes: TypedQuantity,

    /// Threshold below which content is inlined instead of referenced.
    #[serde(default = "default_inline_threshold")]
    pub inline_threshold: TypedQuantity,
}

const fn default_max_fetch_bytes() -> TypedQuantity {
    TypedQuantity::bytes(DEFAULT_MAX_FETCH_BYTES)
}

const fn default_inline_threshold() -> TypedQuantity {
    TypedQuantity::bytes(DEFAULT_INLINE_THRESHOLD_BYTES)
}

impl Default for RetrievalPolicy {
    fn default() -> Self {
        Self {
            max_fetch_bytes: default_max_fetch_bytes(),
            inline_threshold: default_inline_threshold(),
        }
    }
}

impl RetrievalPolicy {
    /// Creates a new builder for `RetrievalPolicy`.
    #[must_use]
    pub fn builder() -> RetrievalPolicyBuilder {
        RetrievalPolicyBuilder::default()
    }

    /// Validates the retrieval policy.
    ///
    /// # Errors
    ///
    /// Returns validation errors for unit mismatches or invalid values.
    pub fn validate(&self) -> Result<(), TargetProfileError> {
        if self.max_fetch_bytes.unit() != QuantityUnit::Bytes {
            return Err(TargetProfileError::UnitMismatch {
                field: "max_fetch_bytes".to_string(),
                expected: QuantityUnit::Bytes,
                actual: self.max_fetch_bytes.unit(),
            });
        }
        if self.inline_threshold.unit() != QuantityUnit::Bytes {
            return Err(TargetProfileError::UnitMismatch {
                field: "inline_threshold".to_string(),
                expected: QuantityUnit::Bytes,
                actual: self.inline_threshold.unit(),
            });
        }
        // Inline threshold should not exceed max fetch bytes
        if self.inline_threshold.value() > self.max_fetch_bytes.value() {
            return Err(TargetProfileError::ValidationError {
                message: format!(
                    "inline_threshold ({}) cannot exceed max_fetch_bytes ({})",
                    self.inline_threshold.value(),
                    self.max_fetch_bytes.value()
                ),
            });
        }
        Ok(())
    }
}

/// Builder for [`RetrievalPolicy`].
#[derive(Debug, Clone, Default)]
pub struct RetrievalPolicyBuilder {
    max_fetch_bytes: Option<TypedQuantity>,
    inline_threshold: Option<TypedQuantity>,
}

impl RetrievalPolicyBuilder {
    /// Sets the maximum fetch bytes.
    #[must_use]
    pub const fn max_fetch_bytes(mut self, bytes: TypedQuantity) -> Self {
        self.max_fetch_bytes = Some(bytes);
        self
    }

    /// Sets the inline threshold.
    #[must_use]
    pub const fn inline_threshold(mut self, bytes: TypedQuantity) -> Self {
        self.inline_threshold = Some(bytes);
        self
    }

    /// Builds the `RetrievalPolicy`.
    #[must_use]
    pub fn build(self) -> RetrievalPolicy {
        RetrievalPolicy {
            max_fetch_bytes: self.max_fetch_bytes.unwrap_or_else(default_max_fetch_bytes),
            inline_threshold: self
                .inline_threshold
                .unwrap_or_else(default_inline_threshold),
        }
    }
}

// ============================================================================
// DeliveryConstraints
// ============================================================================

/// Delivery constraints for vendor-specific output requirements.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryConstraints {
    /// Output format for rendered content.
    #[serde(default)]
    pub output_format: OutputFormat,

    /// How provenance is embedded in output.
    #[serde(default)]
    pub provenance_embed: ProvenanceEmbed,
}

impl DeliveryConstraints {
    /// Creates a new builder for `DeliveryConstraints`.
    #[must_use]
    pub fn builder() -> DeliveryConstraintsBuilder {
        DeliveryConstraintsBuilder::default()
    }
}

/// Builder for [`DeliveryConstraints`].
#[derive(Debug, Clone, Default)]
pub struct DeliveryConstraintsBuilder {
    output_format: Option<OutputFormat>,
    provenance_embed: Option<ProvenanceEmbed>,
}

impl DeliveryConstraintsBuilder {
    /// Sets the output format.
    #[must_use]
    pub const fn output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = Some(format);
        self
    }

    /// Sets the provenance embed mode.
    #[must_use]
    pub const fn provenance_embed(mut self, embed: ProvenanceEmbed) -> Self {
        self.provenance_embed = Some(embed);
        self
    }

    /// Builds the `DeliveryConstraints`.
    #[must_use]
    pub fn build(self) -> DeliveryConstraints {
        DeliveryConstraints {
            output_format: self.output_format.unwrap_or_default(),
            provenance_embed: self.provenance_embed.unwrap_or_default(),
        }
    }
}

// ============================================================================
// TargetProfile
// ============================================================================

/// Target profile defining how CAC artifacts are rendered and delivered.
///
/// A `TargetProfile` decouples the internal CAC-JSON representation from
/// vendor-specific layouts and consumption patterns. It specifies:
///
/// - **Rendering Policy**: Stage-specific context limits and formatting
/// - **Budget Policy**: Resource limits for consumption
/// - **Retrieval Policy**: External fetch limits and inline thresholds
/// - **Delivery Constraints**: Output format and provenance embedding
///
/// # Example
///
/// ```rust
/// use apm2_core::cac::target_profile::{
///     BudgetPolicy, DeliveryConstraints, RenderingPolicy, RetrievalPolicy, Stage, TargetProfile,
///     TypedQuantity,
/// };
///
/// let profile = TargetProfile::builder()
///     .profile_id("claude-code-default")
///     .version("2026-01-27")
///     .description("Profile for Claude Code consumption")
///     .rendering_policy(
///         RenderingPolicy::builder()
///             .stage(Stage::Implement)
///             .max_context_tokens(TypedQuantity::tokens(100_000))
///             .build()
///             .unwrap(),
///     )
///     .budget_policy(
///         BudgetPolicy::builder()
///             .max_tokens(TypedQuantity::tokens(100_000))
///             .build(),
///     )
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfile {
    /// Unique identifier for this profile.
    pub profile_id: String,

    /// Profile version (ISO date format recommended).
    pub version: String,

    /// Human-readable description of the profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Rendering policy for context formatting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendering_policy: Option<RenderingPolicy>,

    /// Budget policy for resource limits.
    #[serde(default)]
    pub budget_policy: BudgetPolicy,

    /// Retrieval policy for external fetches.
    #[serde(default)]
    pub retrieval_policy: RetrievalPolicy,

    /// Delivery constraints for output format.
    #[serde(default)]
    pub delivery_constraints: DeliveryConstraints,
}

impl TargetProfile {
    /// Creates a new builder for `TargetProfile`.
    #[must_use]
    pub fn builder() -> TargetProfileBuilder {
        TargetProfileBuilder::default()
    }

    /// Validates the entire profile.
    ///
    /// # Errors
    ///
    /// Returns validation errors for any constraint violations.
    pub fn validate(&self) -> Result<(), TargetProfileError> {
        // Validate profile_id
        if self.profile_id.is_empty() {
            return Err(TargetProfileError::MissingField {
                field: "profile_id".to_string(),
            });
        }
        if self.profile_id.len() > MAX_PROFILE_ID_LENGTH {
            return Err(TargetProfileError::FieldTooLong {
                field: "profile_id".to_string(),
                max_length: MAX_PROFILE_ID_LENGTH,
                actual_length: self.profile_id.len(),
            });
        }
        // Validate profile_id format: must start with lowercase letter,
        // contain only lowercase alphanumeric, underscore, hyphen
        if !is_valid_profile_id(&self.profile_id) {
            return Err(TargetProfileError::InvalidProfileId {
                message: "must start with lowercase letter and contain only \
                          lowercase alphanumeric, underscore, or hyphen"
                    .to_string(),
            });
        }

        // Validate version
        if self.version.is_empty() {
            return Err(TargetProfileError::MissingField {
                field: "version".to_string(),
            });
        }
        if self.version.len() > MAX_VERSION_LENGTH {
            return Err(TargetProfileError::FieldTooLong {
                field: "version".to_string(),
                max_length: MAX_VERSION_LENGTH,
                actual_length: self.version.len(),
            });
        }

        // Validate description length
        if let Some(ref desc) = self.description {
            if desc.len() > MAX_DESCRIPTION_LENGTH {
                return Err(TargetProfileError::FieldTooLong {
                    field: "description".to_string(),
                    max_length: MAX_DESCRIPTION_LENGTH,
                    actual_length: desc.len(),
                });
            }
        }

        // Validate rendering policy
        if let Some(ref policy) = self.rendering_policy {
            policy.validate()?;
        }

        // Validate budget policy
        self.budget_policy.validate()?;

        // Validate retrieval policy
        self.retrieval_policy.validate()?;

        Ok(())
    }
}

/// Validates that a profile ID matches the expected format.
fn is_valid_profile_id(id: &str) -> bool {
    if id.is_empty() || id.len() > MAX_PROFILE_ID_LENGTH {
        return false;
    }

    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {},
        _ => return false,
    }

    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Builder for [`TargetProfile`].
#[derive(Debug, Clone, Default)]
pub struct TargetProfileBuilder {
    profile_id: Option<String>,
    version: Option<String>,
    description: Option<String>,
    rendering_policy: Option<RenderingPolicy>,
    budget_policy: Option<BudgetPolicy>,
    retrieval_policy: Option<RetrievalPolicy>,
    delivery_constraints: Option<DeliveryConstraints>,
}

impl TargetProfileBuilder {
    /// Sets the profile ID.
    #[must_use]
    pub fn profile_id(mut self, id: impl Into<String>) -> Self {
        self.profile_id = Some(id.into());
        self
    }

    /// Sets the version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the rendering policy.
    #[must_use]
    pub fn rendering_policy(mut self, policy: RenderingPolicy) -> Self {
        self.rendering_policy = Some(policy);
        self
    }

    /// Sets the budget policy.
    #[must_use]
    pub const fn budget_policy(mut self, policy: BudgetPolicy) -> Self {
        self.budget_policy = Some(policy);
        self
    }

    /// Sets the retrieval policy.
    #[must_use]
    pub const fn retrieval_policy(mut self, policy: RetrievalPolicy) -> Self {
        self.retrieval_policy = Some(policy);
        self
    }

    /// Sets the delivery constraints.
    #[must_use]
    pub const fn delivery_constraints(mut self, constraints: DeliveryConstraints) -> Self {
        self.delivery_constraints = Some(constraints);
        self
    }

    /// Builds the `TargetProfile`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetProfileError`] if required fields are missing or
    /// validation fails.
    pub fn build(self) -> Result<TargetProfile, TargetProfileError> {
        let profile = TargetProfile {
            profile_id: self
                .profile_id
                .ok_or_else(|| TargetProfileError::MissingField {
                    field: "profile_id".to_string(),
                })?,
            version: self
                .version
                .ok_or_else(|| TargetProfileError::MissingField {
                    field: "version".to_string(),
                })?,
            description: self.description,
            rendering_policy: self.rendering_policy,
            budget_policy: self.budget_policy.unwrap_or_default(),
            retrieval_policy: self.retrieval_policy.unwrap_or_default(),
            delivery_constraints: self.delivery_constraints.unwrap_or_default(),
        };
        profile.validate()?;
        Ok(profile)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Stage Tests
    // =========================================================================

    #[test]
    fn test_stage_as_str() {
        assert_eq!(Stage::Plan.as_str(), "plan");
        assert_eq!(Stage::Implement.as_str(), "implement");
        assert_eq!(Stage::Review.as_str(), "review");
        assert_eq!(Stage::Ops.as_str(), "ops");
    }

    #[test]
    fn test_stage_parse() {
        assert_eq!(Stage::parse("plan").unwrap(), Stage::Plan);
        assert_eq!(Stage::parse("IMPLEMENT").unwrap(), Stage::Implement);
        assert_eq!(Stage::parse("Review").unwrap(), Stage::Review);
        assert_eq!(Stage::parse("ops").unwrap(), Stage::Ops);
    }

    #[test]
    fn test_stage_parse_invalid() {
        let result = Stage::parse("unknown");
        assert!(matches!(
            result,
            Err(TargetProfileError::ValidationError { .. })
        ));
    }

    #[test]
    fn test_stage_serialization() {
        let stage = Stage::Implement;
        let json = serde_json::to_string(&stage).unwrap();
        assert_eq!(json, "\"implement\"");

        let deserialized: Stage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, stage);
    }

    // =========================================================================
    // OutputFormat Tests
    // =========================================================================

    #[test]
    fn test_output_format_default() {
        assert_eq!(OutputFormat::default(), OutputFormat::Markdown);
    }

    #[test]
    fn test_output_format_as_str() {
        assert_eq!(OutputFormat::Markdown.as_str(), "markdown");
        assert_eq!(OutputFormat::PlainText.as_str(), "plain_text");
        assert_eq!(OutputFormat::Json.as_str(), "json");
        assert_eq!(OutputFormat::Xml.as_str(), "xml");
    }

    // =========================================================================
    // ProvenanceEmbed Tests
    // =========================================================================

    #[test]
    fn test_provenance_embed_default() {
        assert_eq!(ProvenanceEmbed::default(), ProvenanceEmbed::Inline);
    }

    #[test]
    fn test_provenance_embed_as_str() {
        assert_eq!(ProvenanceEmbed::Inline.as_str(), "inline");
        assert_eq!(ProvenanceEmbed::Footer.as_str(), "footer");
        assert_eq!(ProvenanceEmbed::Metadata.as_str(), "metadata");
        assert_eq!(ProvenanceEmbed::None.as_str(), "none");
    }

    // =========================================================================
    // RenderingPolicy Tests
    // =========================================================================

    #[test]
    fn test_rendering_policy_builder() {
        let policy = RenderingPolicy::builder()
            .stage(Stage::Implement)
            .max_context_tokens(TypedQuantity::tokens(100_000))
            .include_provenance(true)
            .format_hint("code-focused")
            .build()
            .unwrap();

        assert_eq!(policy.stage, Stage::Implement);
        assert_eq!(policy.max_context_tokens.unwrap().value(), 100_000);
        assert!(policy.include_provenance);
        assert_eq!(policy.format_hint.as_deref(), Some("code-focused"));
    }

    #[test]
    fn test_rendering_policy_missing_stage() {
        let result = RenderingPolicy::builder()
            .max_context_tokens(TypedQuantity::tokens(100_000))
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::MissingField { field }) if field == "stage"
        ));
    }

    #[test]
    fn test_rendering_policy_wrong_unit() {
        let result = RenderingPolicy::builder()
            .stage(Stage::Plan)
            .max_context_tokens(TypedQuantity::bytes(1000)) // Wrong unit!
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::UnitMismatch { .. })
        ));
    }

    #[test]
    fn test_rendering_policy_format_hint_too_long() {
        let result = RenderingPolicy::builder()
            .stage(Stage::Plan)
            .format_hint("x".repeat(MAX_FORMAT_HINT_LENGTH + 1))
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn test_rendering_policy_serialization() {
        let policy = RenderingPolicy::builder()
            .stage(Stage::Review)
            .include_provenance(false)
            .build()
            .unwrap();

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: RenderingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.stage, policy.stage);
        assert_eq!(deserialized.include_provenance, policy.include_provenance);
    }

    #[test]
    fn test_rendering_policy_deny_unknown_fields() {
        let json = r#"{"stage": "plan", "include_provenance": true, "unknown": "field"}"#;
        let result: Result<RenderingPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // BudgetPolicy Tests
    // =========================================================================

    #[test]
    fn test_budget_policy_builder() {
        let policy = BudgetPolicy::builder()
            .max_tokens(TypedQuantity::tokens(100_000))
            .max_artifacts(TypedQuantity::artifacts(50))
            .max_bytes(TypedQuantity::bytes(10_485_760))
            .build();

        assert_eq!(policy.max_tokens.unwrap().value(), 100_000);
        assert_eq!(policy.max_artifacts.unwrap().value(), 50);
        assert_eq!(policy.max_bytes.unwrap().value(), 10_485_760);
    }

    #[test]
    fn test_budget_policy_unlimited() {
        let policy = BudgetPolicy::unlimited();
        assert!(policy.is_unlimited());
    }

    #[test]
    fn test_budget_policy_validate_wrong_units() {
        let policy = BudgetPolicy {
            max_tokens: Some(TypedQuantity::bytes(100)), // Wrong!
            max_artifacts: None,
            max_bytes: None,
        };
        let result = policy.validate();
        assert!(matches!(
            result,
            Err(TargetProfileError::UnitMismatch { .. })
        ));
    }

    #[test]
    fn test_budget_policy_serialization() {
        let policy = BudgetPolicy::builder()
            .max_tokens(TypedQuantity::tokens(1000))
            .build();

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: BudgetPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.max_tokens.unwrap().value(),
            policy.max_tokens.unwrap().value()
        );
    }

    // =========================================================================
    // RetrievalPolicy Tests
    // =========================================================================

    #[test]
    fn test_retrieval_policy_default() {
        let policy = RetrievalPolicy::default();
        assert_eq!(policy.max_fetch_bytes.value(), DEFAULT_MAX_FETCH_BYTES);
        assert_eq!(
            policy.inline_threshold.value(),
            DEFAULT_INLINE_THRESHOLD_BYTES
        );
    }

    #[test]
    fn test_retrieval_policy_builder() {
        let policy = RetrievalPolicy::builder()
            .max_fetch_bytes(TypedQuantity::bytes(100_000_000))
            .inline_threshold(TypedQuantity::bytes(8192))
            .build();

        assert_eq!(policy.max_fetch_bytes.value(), 100_000_000);
        assert_eq!(policy.inline_threshold.value(), 8192);
    }

    #[test]
    fn test_retrieval_policy_validate_wrong_unit() {
        let policy = RetrievalPolicy {
            max_fetch_bytes: TypedQuantity::tokens(1000), // Wrong!
            inline_threshold: TypedQuantity::bytes(4096),
        };
        let result = policy.validate();
        assert!(matches!(
            result,
            Err(TargetProfileError::UnitMismatch { .. })
        ));
    }

    #[test]
    fn test_retrieval_policy_validate_threshold_exceeds_max() {
        let policy = RetrievalPolicy {
            max_fetch_bytes: TypedQuantity::bytes(1000),
            inline_threshold: TypedQuantity::bytes(2000), // Exceeds max!
        };
        let result = policy.validate();
        assert!(matches!(
            result,
            Err(TargetProfileError::ValidationError { .. })
        ));
    }

    // =========================================================================
    // DeliveryConstraints Tests
    // =========================================================================

    #[test]
    fn test_delivery_constraints_default() {
        let constraints = DeliveryConstraints::default();
        assert_eq!(constraints.output_format, OutputFormat::Markdown);
        assert_eq!(constraints.provenance_embed, ProvenanceEmbed::Inline);
    }

    #[test]
    fn test_delivery_constraints_builder() {
        let constraints = DeliveryConstraints::builder()
            .output_format(OutputFormat::Json)
            .provenance_embed(ProvenanceEmbed::Metadata)
            .build();

        assert_eq!(constraints.output_format, OutputFormat::Json);
        assert_eq!(constraints.provenance_embed, ProvenanceEmbed::Metadata);
    }

    #[test]
    fn test_delivery_constraints_serialization() {
        let constraints = DeliveryConstraints::builder()
            .output_format(OutputFormat::PlainText)
            .provenance_embed(ProvenanceEmbed::Footer)
            .build();

        let json = serde_json::to_string(&constraints).unwrap();
        let deserialized: DeliveryConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.output_format, constraints.output_format);
        assert_eq!(deserialized.provenance_embed, constraints.provenance_embed);
    }

    // =========================================================================
    // TargetProfile Tests
    // =========================================================================

    #[test]
    fn test_target_profile_builder_minimal() {
        let profile = TargetProfile::builder()
            .profile_id("test-profile")
            .version("2026-01-27")
            .build()
            .unwrap();

        assert_eq!(profile.profile_id, "test-profile");
        assert_eq!(profile.version, "2026-01-27");
        assert!(profile.description.is_none());
        assert!(profile.rendering_policy.is_none());
        assert!(profile.budget_policy.is_unlimited());
    }

    #[test]
    fn test_target_profile_builder_full() {
        let profile = TargetProfile::builder()
            .profile_id("claude-code-default")
            .version("2026-01-27")
            .description("Default profile for Claude Code")
            .rendering_policy(
                RenderingPolicy::builder()
                    .stage(Stage::Implement)
                    .max_context_tokens(TypedQuantity::tokens(100_000))
                    .include_provenance(true)
                    .build()
                    .unwrap(),
            )
            .budget_policy(
                BudgetPolicy::builder()
                    .max_tokens(TypedQuantity::tokens(100_000))
                    .max_artifacts(TypedQuantity::artifacts(50))
                    .max_bytes(TypedQuantity::bytes(10_485_760))
                    .build(),
            )
            .retrieval_policy(
                RetrievalPolicy::builder()
                    .max_fetch_bytes(TypedQuantity::bytes(52_428_800))
                    .inline_threshold(TypedQuantity::bytes(4096))
                    .build(),
            )
            .delivery_constraints(
                DeliveryConstraints::builder()
                    .output_format(OutputFormat::Markdown)
                    .provenance_embed(ProvenanceEmbed::Inline)
                    .build(),
            )
            .build()
            .unwrap();

        assert_eq!(profile.profile_id, "claude-code-default");
        assert!(profile.rendering_policy.is_some());
        assert!(!profile.budget_policy.is_unlimited());
    }

    #[test]
    fn test_target_profile_missing_profile_id() {
        let result = TargetProfile::builder().version("2026-01-27").build();

        assert!(matches!(
            result,
            Err(TargetProfileError::MissingField { field }) if field == "profile_id"
        ));
    }

    #[test]
    fn test_target_profile_missing_version() {
        let result = TargetProfile::builder().profile_id("test").build();

        assert!(matches!(
            result,
            Err(TargetProfileError::MissingField { field }) if field == "version"
        ));
    }

    #[test]
    fn test_target_profile_invalid_profile_id_uppercase() {
        let result = TargetProfile::builder()
            .profile_id("InvalidId") // Uppercase not allowed
            .version("2026-01-27")
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::InvalidProfileId { .. })
        ));
    }

    #[test]
    fn test_target_profile_invalid_profile_id_starts_with_number() {
        let result = TargetProfile::builder()
            .profile_id("123-profile")
            .version("2026-01-27")
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::InvalidProfileId { .. })
        ));
    }

    #[test]
    fn test_target_profile_profile_id_too_long() {
        let result = TargetProfile::builder()
            .profile_id("x".repeat(MAX_PROFILE_ID_LENGTH + 1))
            .version("2026-01-27")
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::FieldTooLong { field, .. }) if field == "profile_id"
        ));
    }

    #[test]
    fn test_target_profile_version_too_long() {
        let result = TargetProfile::builder()
            .profile_id("test")
            .version("x".repeat(MAX_VERSION_LENGTH + 1))
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::FieldTooLong { field, .. }) if field == "version"
        ));
    }

    #[test]
    fn test_target_profile_description_too_long() {
        let result = TargetProfile::builder()
            .profile_id("test")
            .version("2026-01-27")
            .description("x".repeat(MAX_DESCRIPTION_LENGTH + 1))
            .build();

        assert!(matches!(
            result,
            Err(TargetProfileError::FieldTooLong { field, .. }) if field == "description"
        ));
    }

    #[test]
    fn test_target_profile_serialization() {
        let profile = TargetProfile::builder()
            .profile_id("test-profile")
            .version("2026-01-27")
            .description("A test profile")
            .build()
            .unwrap();

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: TargetProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.profile_id, profile.profile_id);
        assert_eq!(deserialized.version, profile.version);
    }

    #[test]
    fn test_target_profile_deny_unknown_fields() {
        let json = r#"{
            "profile_id": "test",
            "version": "2026-01-27",
            "budget_policy": {},
            "retrieval_policy": {},
            "delivery_constraints": {},
            "unknown_field": "not allowed"
        }"#;

        let result: Result<TargetProfile, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Valid Profile ID Format Tests
    // =========================================================================

    #[test]
    fn test_valid_profile_ids() {
        assert!(is_valid_profile_id("local"));
        assert!(is_valid_profile_id("local-dev"));
        assert!(is_valid_profile_id("local_dev"));
        assert!(is_valid_profile_id("local123"));
        assert!(is_valid_profile_id("a"));
        assert!(is_valid_profile_id("claude-code-default"));
    }

    #[test]
    fn test_invalid_profile_ids() {
        assert!(!is_valid_profile_id("")); // empty
        assert!(!is_valid_profile_id("Local")); // uppercase
        assert!(!is_valid_profile_id("123local")); // starts with number
        assert!(!is_valid_profile_id("-local")); // starts with hyphen
        assert!(!is_valid_profile_id("local.dev")); // contains dot
        assert!(!is_valid_profile_id("local dev")); // contains space
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let error = TargetProfileError::MissingField {
            field: "profile_id".to_string(),
        };
        assert!(error.to_string().contains("profile_id"));

        let error = TargetProfileError::UnitMismatch {
            field: "max_tokens".to_string(),
            expected: QuantityUnit::Tokens,
            actual: QuantityUnit::Bytes,
        };
        let msg = error.to_string();
        assert!(msg.contains("max_tokens"));
        assert!(msg.contains("tokens"));
        assert!(msg.contains("bytes"));
    }
}
