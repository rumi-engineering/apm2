//! Capability Manifest generator for CAC v1.
//!
//! This module provides the `CapabilityManifest` type and generation logic
//! for enumerating binary capabilities and binding them to binary version.
//!
//! # Design Principles
//!
//! - **Binary Hash Binding**: The manifest is cryptographically bound to the
//!   binary version via `binary_hash` computed from version + target + profile
//!   (per DD-0006)
//! - **Deterministic Serialization**: Uses `BTreeMap` for sorted keys to ensure
//!   stable output (CTR-2612)
//! - **CLI Integration**: Commands can be populated from CLI introspection at
//!   the application level (e.g., via clap's `Command::get_subcommands()`)
//! - **Strict Serde**: All types use `#[serde(deny_unknown_fields)]` to reject
//!   unknown fields (CTR-1604)
//!
//! # Security
//!
//! Binary hash binding prevents manifest replay across versions (DD-0006).
//! Deterministic generation ensures agents can verify manifest integrity.
//!
//! # Example
//!
//! ```rust
//! use apm2_core::cac::manifest::{
//!     Capability, CapabilityManifest, Command, ManifestConfig, VerificationMethod,
//! };
//!
//! // Create a manifest configuration
//! let config = ManifestConfig::builder()
//!     .version("0.3.0")
//!     .target("x86_64-unknown-linux-gnu")
//!     .profile("release")
//!     .build()
//!     .unwrap();
//!
//! // Generate the manifest
//! let manifest = CapabilityManifest::generate(&config);
//!
//! // The manifest has a binary hash binding
//! assert!(!manifest.binary_hash.is_empty());
//!
//! // Serialization is deterministic (sorted keys)
//! let json1 = serde_json::to_string(&manifest).unwrap();
//! let json2 = serde_json::to_string(&manifest).unwrap();
//! assert_eq!(json1, json2);
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for command names.
pub const MAX_COMMAND_NAME_LENGTH: usize = 128;

/// Maximum length for command descriptions.
pub const MAX_COMMAND_DESCRIPTION_LENGTH: usize = 4096;

/// Maximum length for schema reference strings.
pub const MAX_SCHEMA_REF_LENGTH: usize = 1024;

/// Maximum length for capability IDs.
pub const MAX_CAPABILITY_ID_LENGTH: usize = 256;

/// Maximum length for capability descriptions.
pub const MAX_CAPABILITY_DESCRIPTION_LENGTH: usize = 4096;

/// Maximum length for selftest IDs.
pub const MAX_SELFTEST_ID_LENGTH: usize = 256;

/// Maximum length for version strings.
pub const MAX_VERSION_LENGTH: usize = 64;

/// Maximum length for target strings (e.g., "x86_64-unknown-linux-gnu").
pub const MAX_TARGET_LENGTH: usize = 128;

/// Maximum length for profile strings (e.g., "release", "debug").
pub const MAX_PROFILE_LENGTH: usize = 64;

/// Maximum number of commands in a manifest.
pub const MAX_COMMANDS: usize = 1024;

/// Maximum number of capabilities in a manifest.
pub const MAX_CAPABILITIES: usize = 1024;

/// Maximum number of selftest references.
pub const MAX_SELFTEST_REFS: usize = 10_000;

/// Current schema version for capability manifests.
pub const CAPABILITY_MANIFEST_VERSION: &str = "2026-01-27";

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during manifest operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
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

    /// Invalid capability ID format.
    #[error("invalid capability_id format: {message}")]
    InvalidCapabilityId {
        /// Description of the format violation.
        message: String,
    },

    /// Invalid selftest ID format.
    #[error("invalid selftest_id format: {message}")]
    InvalidSelftestId {
        /// Description of the format violation.
        message: String,
    },

    /// Duplicate entry found.
    #[error("duplicate {item_type}: {id}")]
    Duplicate {
        /// Type of the duplicate item.
        item_type: String,
        /// ID of the duplicate item.
        id: String,
    },

    /// A field contains control characters (including null bytes).
    ///
    /// Control characters in hash input fields can enable collision attacks
    /// where different logical inputs produce the same hash.
    #[error("{field} contains control characters (including null bytes) which are not allowed")]
    ControlCharactersNotAllowed {
        /// The name of the field containing control characters.
        field: String,
    },
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Returns `true` if the string contains any control characters (ASCII 0-31 or
/// 127).
///
/// Control characters in hash input fields can enable collision attacks where
/// the delimiter (null byte) is embedded in field values, causing different
/// logical inputs to produce identical hash outputs.
///
/// # Example Attack Vector (prevented by this check)
///
/// Without this validation:
/// - `version="1.0\0"` + `target="x86"` would hash as `1.0\0\0x86`
/// - `version="1.0"` + `target="\0x86"` would also hash as `1.0\0\0x86`
///
/// Both produce the same hash, allowing manifest replay attacks.
#[must_use]
fn contains_control_characters(s: &str) -> bool {
    s.bytes().any(|b| b < 32 || b == 127)
}

// ============================================================================
// VerificationMethod
// ============================================================================

/// Method used to verify a capability.
///
/// Per DD-0006, capabilities are verified through selftests (AAT) that prove
/// the binary can perform the claimed operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationMethod {
    /// Capability is verified by an automated selftest.
    Selftest,
    /// Capability is verified by static analysis of code paths.
    StaticAnalysis,
    /// Capability is declared but not automatically verified.
    #[default]
    Declared,
}

impl VerificationMethod {
    /// Returns the string representation of the verification method.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Selftest => "selftest",
            Self::StaticAnalysis => "static_analysis",
            Self::Declared => "declared",
        }
    }
}

// ============================================================================
// Command
// ============================================================================

/// A CLI command exposed by the binary.
///
/// Commands are enumerated via clap introspection and include references
/// to their input/output schemas for type-safe interaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    /// Command name (e.g., "start", "cac apply-patch").
    pub name: String,

    /// Human-readable description of what the command does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Reference to the input schema (JSON Schema stable ID or path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema_ref: Option<String>,

    /// Reference to the output schema (JSON Schema stable ID or path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema_ref: Option<String>,

    /// Subcommands of this command.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subcommands: Vec<Self>,
}

impl Command {
    /// Creates a new command with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            input_schema_ref: None,
            output_schema_ref: None,
            subcommands: Vec::new(),
        }
    }

    /// Creates a command builder.
    #[must_use]
    pub fn builder() -> CommandBuilder {
        CommandBuilder::default()
    }

    /// Validates the command fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // Validate name length
        if self.name.len() > MAX_COMMAND_NAME_LENGTH {
            return Err(ManifestError::FieldTooLong {
                field: "name".to_string(),
                max_length: MAX_COMMAND_NAME_LENGTH,
                actual_length: self.name.len(),
            });
        }

        // Validate name is not empty
        if self.name.is_empty() {
            return Err(ManifestError::MissingField {
                field: "name".to_string(),
            });
        }

        // Validate description length
        if let Some(ref desc) = self.description {
            if desc.len() > MAX_COMMAND_DESCRIPTION_LENGTH {
                return Err(ManifestError::FieldTooLong {
                    field: "description".to_string(),
                    max_length: MAX_COMMAND_DESCRIPTION_LENGTH,
                    actual_length: desc.len(),
                });
            }
        }

        // Validate input_schema_ref length
        if let Some(ref schema_ref) = self.input_schema_ref {
            if schema_ref.len() > MAX_SCHEMA_REF_LENGTH {
                return Err(ManifestError::FieldTooLong {
                    field: "input_schema_ref".to_string(),
                    max_length: MAX_SCHEMA_REF_LENGTH,
                    actual_length: schema_ref.len(),
                });
            }
        }

        // Validate output_schema_ref length
        if let Some(ref schema_ref) = self.output_schema_ref {
            if schema_ref.len() > MAX_SCHEMA_REF_LENGTH {
                return Err(ManifestError::FieldTooLong {
                    field: "output_schema_ref".to_string(),
                    max_length: MAX_SCHEMA_REF_LENGTH,
                    actual_length: schema_ref.len(),
                });
            }
        }

        // Check for duplicate subcommand names at this level
        let mut seen_subcommands = std::collections::HashSet::new();
        for subcmd in &self.subcommands {
            if !seen_subcommands.insert(&subcmd.name) {
                return Err(ManifestError::Duplicate {
                    item_type: "subcommand".to_string(),
                    id: subcmd.name.clone(),
                });
            }
        }

        // Validate subcommands recursively (this will also check their nested
        // duplicates)
        for subcmd in &self.subcommands {
            subcmd.validate()?;
        }

        Ok(())
    }
}

/// Builder for [`Command`].
#[derive(Debug, Default, Clone)]
pub struct CommandBuilder {
    name: Option<String>,
    description: Option<String>,
    input_schema_ref: Option<String>,
    output_schema_ref: Option<String>,
    subcommands: Vec<Command>,
}

impl CommandBuilder {
    /// Sets the command name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the command description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the input schema reference.
    #[must_use]
    pub fn input_schema_ref(mut self, schema_ref: impl Into<String>) -> Self {
        self.input_schema_ref = Some(schema_ref.into());
        self
    }

    /// Sets the output schema reference.
    #[must_use]
    pub fn output_schema_ref(mut self, schema_ref: impl Into<String>) -> Self {
        self.output_schema_ref = Some(schema_ref.into());
        self
    }

    /// Adds a subcommand.
    #[must_use]
    pub fn subcommand(mut self, subcommand: Command) -> Self {
        self.subcommands.push(subcommand);
        self
    }

    /// Adds multiple subcommands.
    #[must_use]
    pub fn subcommands(mut self, subcommands: impl IntoIterator<Item = Command>) -> Self {
        self.subcommands.extend(subcommands);
        self
    }

    /// Builds the command, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    pub fn build(self) -> Result<Command, ManifestError> {
        let name = self.name.ok_or_else(|| ManifestError::MissingField {
            field: "name".to_string(),
        })?;

        let command = Command {
            name,
            description: self.description,
            input_schema_ref: self.input_schema_ref,
            output_schema_ref: self.output_schema_ref,
            subcommands: self.subcommands,
        };

        command.validate()?;
        Ok(command)
    }
}

// ============================================================================
// Clap Introspection
// ============================================================================

/// Extracts CLI commands from a clap `Command` structure.
///
/// This function recursively traverses the clap command tree and converts
/// it to the manifest's `Command` representation for capability enumeration.
///
/// # Feature Flag
///
/// This functionality requires the `clap-introspection` feature:
///
/// ```toml
/// [dependencies]
/// apm2-core = { version = "0.3", features = ["clap-introspection"] }
/// ```
///
/// # Example
///
/// ```ignore
/// use apm2_core::cac::manifest::{Command, extract_commands_from_clap};
/// use clap::Command as ClapCommand;
///
/// let app = ClapCommand::new("myapp")
///     .about("My application")
///     .subcommand(ClapCommand::new("start").about("Start the app"))
///     .subcommand(ClapCommand::new("stop").about("Stop the app"));
///
/// let commands = extract_commands_from_clap(&app);
/// ```
#[cfg(feature = "clap-introspection")]
#[must_use]
pub fn extract_commands_from_clap(clap_cmd: &clap::Command) -> Vec<Command> {
    clap_cmd
        .get_subcommands()
        .map(convert_clap_command)
        .collect()
}

/// Recursively converts a clap `Command` to a manifest `Command`.
#[cfg(feature = "clap-introspection")]
fn convert_clap_command(clap_cmd: &clap::Command) -> Command {
    let subcommands: Vec<Command> = clap_cmd
        .get_subcommands()
        .map(convert_clap_command)
        .collect();

    Command {
        name: clap_cmd.get_name().to_string(),
        description: clap_cmd.get_about().map(ToString::to_string),
        input_schema_ref: None,  // Schema refs must be set manually
        output_schema_ref: None, // Schema refs must be set manually
        subcommands,
    }
}

/// Populates manifest commands from a clap `Command` structure.
///
/// This is a convenience method that combines manifest generation with
/// clap command extraction.
///
/// # Feature Flag
///
/// Requires the `clap-introspection` feature.
///
/// # Example
///
/// ```ignore
/// use apm2_core::cac::manifest::{CapabilityManifest, ManifestConfig};
/// use clap::Command as ClapCommand;
///
/// let config = ManifestConfig::builder()
///     .version("0.3.0")
///     .target("x86_64-unknown-linux-gnu")
///     .profile("release")
///     .build()
///     .unwrap();
///
/// let app = ClapCommand::new("apm2")
///     .subcommand(ClapCommand::new("start"))
///     .subcommand(ClapCommand::new("stop"));
///
/// let manifest = CapabilityManifest::generate_with_clap(&config, &app);
/// ```
#[cfg(feature = "clap-introspection")]
impl CapabilityManifest {
    /// Generates a manifest with commands extracted from clap introspection.
    #[must_use]
    pub fn generate_with_clap(config: &ManifestConfig, clap_cmd: &clap::Command) -> Self {
        let mut manifest = Self::generate(config);
        manifest.commands = extract_commands_from_clap(clap_cmd);
        manifest
    }
}

// ============================================================================
// Capability
// ============================================================================

/// A capability claimed by the binary.
///
/// Capabilities are verified through selftests (AAT) per DD-0006. Each
/// capability has a verification method and optional selftest reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// Unique identifier for the capability.
    pub id: String,

    /// Human-readable description of the capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// How this capability is verified.
    pub verification_method: VerificationMethod,

    /// Reference to the selftest that verifies this capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selftest_id: Option<String>,
}

impl Capability {
    /// Creates a new capability with the given ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: None,
            verification_method: VerificationMethod::default(),
            selftest_id: None,
        }
    }

    /// Creates a capability builder.
    #[must_use]
    pub fn builder() -> CapabilityBuilder {
        CapabilityBuilder::default()
    }

    /// Validates the capability fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // Validate id length
        if self.id.len() > MAX_CAPABILITY_ID_LENGTH {
            return Err(ManifestError::FieldTooLong {
                field: "id".to_string(),
                max_length: MAX_CAPABILITY_ID_LENGTH,
                actual_length: self.id.len(),
            });
        }

        // Validate id is not empty
        if self.id.is_empty() {
            return Err(ManifestError::MissingField {
                field: "id".to_string(),
            });
        }

        // Validate capability ID format (alphanumeric, hyphens, underscores, colons)
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':')
        {
            return Err(ManifestError::InvalidCapabilityId {
                message: "capability ID must contain only alphanumeric characters, hyphens, \
                          underscores, and colons"
                    .to_string(),
            });
        }

        // Validate description length
        if let Some(ref desc) = self.description {
            if desc.len() > MAX_CAPABILITY_DESCRIPTION_LENGTH {
                return Err(ManifestError::FieldTooLong {
                    field: "description".to_string(),
                    max_length: MAX_CAPABILITY_DESCRIPTION_LENGTH,
                    actual_length: desc.len(),
                });
            }
        }

        // Validate selftest_id length and format
        if let Some(ref selftest_id) = self.selftest_id {
            if selftest_id.len() > MAX_SELFTEST_ID_LENGTH {
                return Err(ManifestError::FieldTooLong {
                    field: "selftest_id".to_string(),
                    max_length: MAX_SELFTEST_ID_LENGTH,
                    actual_length: selftest_id.len(),
                });
            }

            if !selftest_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':')
            {
                return Err(ManifestError::InvalidSelftestId {
                    message: "selftest ID must contain only alphanumeric characters, hyphens, \
                              underscores, and colons"
                        .to_string(),
                });
            }
        }

        // Validate that selftest method has a selftest_id
        if self.verification_method == VerificationMethod::Selftest && self.selftest_id.is_none() {
            return Err(ManifestError::MissingField {
                field: "selftest_id (required when verification_method is selftest)".to_string(),
            });
        }

        Ok(())
    }
}

/// Builder for [`Capability`].
#[derive(Debug, Default, Clone)]
pub struct CapabilityBuilder {
    id: Option<String>,
    description: Option<String>,
    verification_method: Option<VerificationMethod>,
    selftest_id: Option<String>,
}

impl CapabilityBuilder {
    /// Sets the capability ID.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the capability description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the verification method.
    #[must_use]
    pub const fn verification_method(mut self, method: VerificationMethod) -> Self {
        self.verification_method = Some(method);
        self
    }

    /// Sets the selftest ID.
    #[must_use]
    pub fn selftest_id(mut self, selftest_id: impl Into<String>) -> Self {
        self.selftest_id = Some(selftest_id.into());
        self
    }

    /// Builds the capability, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    pub fn build(self) -> Result<Capability, ManifestError> {
        let id = self.id.ok_or_else(|| ManifestError::MissingField {
            field: "id".to_string(),
        })?;

        let capability = Capability {
            id,
            description: self.description,
            verification_method: self.verification_method.unwrap_or_default(),
            selftest_id: self.selftest_id,
        };

        capability.validate()?;
        Ok(capability)
    }
}

// ============================================================================
// SelftestRef
// ============================================================================

/// A reference mapping a selftest to a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelftestRef {
    /// The selftest ID (test function name or unique identifier).
    pub selftest_id: String,

    /// The capability ID this selftest verifies.
    pub capability_id: String,
}

impl SelftestRef {
    /// Creates a new selftest reference.
    #[must_use]
    pub fn new(selftest_id: impl Into<String>, capability_id: impl Into<String>) -> Self {
        Self {
            selftest_id: selftest_id.into(),
            capability_id: capability_id.into(),
        }
    }
}

// ============================================================================
// ManifestConfig
// ============================================================================

/// Configuration for generating a capability manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestConfig {
    /// Binary version (from `CARGO_PKG_VERSION`).
    pub version: String,

    /// Target triple (e.g., "x86_64-unknown-linux-gnu").
    pub target: String,

    /// Build profile ("debug" or "release").
    pub profile: String,
}

impl ManifestConfig {
    /// Creates a new manifest config.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        target: impl Into<String>,
        profile: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            target: target.into(),
            profile: profile.into(),
        }
    }

    /// Creates a config builder.
    #[must_use]
    pub fn builder() -> ManifestConfigBuilder {
        ManifestConfigBuilder::default()
    }

    /// Creates a config from environment variables and compile-time constants.
    ///
    /// Uses:
    /// - `CARGO_PKG_VERSION` for version
    /// - `TARGET` environment variable or a default for target
    /// - `cfg!(debug_assertions)` for profile
    #[must_use]
    pub fn from_env() -> Self {
        let version = env!("CARGO_PKG_VERSION").to_string();

        // Target is typically set by cargo during cross-compilation.
        // We use a compile-time constant if available, otherwise fall back to a runtime
        // check.
        let target = option_env!("TARGET").map(String::from).unwrap_or_else(|| {
            // Fallback: construct from current platform
            #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
            {
                "x86_64-unknown-linux-gnu".to_string()
            }
            #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
            {
                "aarch64-unknown-linux-gnu".to_string()
            }
            #[cfg(not(any(
                all(target_arch = "x86_64", target_os = "linux"),
                all(target_arch = "aarch64", target_os = "linux")
            )))]
            {
                "unknown-unknown-unknown".to_string()
            }
        });

        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .to_string();

        Self {
            version,
            target,
            profile,
        }
    }

    /// Validates the config fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    ///
    /// # Security
    ///
    /// This method rejects control characters (including null bytes) in all
    /// fields to prevent binary hash collision attacks. The
    /// `compute_binary_hash` function uses null bytes as field delimiters,
    /// so allowing null bytes in field values would enable attackers to
    /// craft different inputs that produce identical hashes.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // SECURITY: Reject control characters to prevent hash collision attacks.
        // The binary hash uses null bytes as delimiters, so embedded nulls could
        // cause `version="1.0\0" + target="x86"` to collide with
        // `version="1.0" + target="\0x86"`.
        if contains_control_characters(&self.version) {
            return Err(ManifestError::ControlCharactersNotAllowed {
                field: "version".to_string(),
            });
        }

        if contains_control_characters(&self.target) {
            return Err(ManifestError::ControlCharactersNotAllowed {
                field: "target".to_string(),
            });
        }

        if contains_control_characters(&self.profile) {
            return Err(ManifestError::ControlCharactersNotAllowed {
                field: "profile".to_string(),
            });
        }

        if self.version.len() > MAX_VERSION_LENGTH {
            return Err(ManifestError::FieldTooLong {
                field: "version".to_string(),
                max_length: MAX_VERSION_LENGTH,
                actual_length: self.version.len(),
            });
        }

        if self.version.is_empty() {
            return Err(ManifestError::MissingField {
                field: "version".to_string(),
            });
        }

        if self.target.len() > MAX_TARGET_LENGTH {
            return Err(ManifestError::FieldTooLong {
                field: "target".to_string(),
                max_length: MAX_TARGET_LENGTH,
                actual_length: self.target.len(),
            });
        }

        if self.target.is_empty() {
            return Err(ManifestError::MissingField {
                field: "target".to_string(),
            });
        }

        if self.profile.len() > MAX_PROFILE_LENGTH {
            return Err(ManifestError::FieldTooLong {
                field: "profile".to_string(),
                max_length: MAX_PROFILE_LENGTH,
                actual_length: self.profile.len(),
            });
        }

        if self.profile.is_empty() {
            return Err(ManifestError::MissingField {
                field: "profile".to_string(),
            });
        }

        Ok(())
    }
}

/// Builder for [`ManifestConfig`].
#[derive(Debug, Default, Clone)]
pub struct ManifestConfigBuilder {
    version: Option<String>,
    target: Option<String>,
    profile: Option<String>,
}

impl ManifestConfigBuilder {
    /// Sets the version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the target triple.
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Sets the build profile.
    #[must_use]
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Builds the config, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    pub fn build(self) -> Result<ManifestConfig, ManifestError> {
        let version = self.version.ok_or_else(|| ManifestError::MissingField {
            field: "version".to_string(),
        })?;

        let target = self.target.ok_or_else(|| ManifestError::MissingField {
            field: "target".to_string(),
        })?;

        let profile = self.profile.ok_or_else(|| ManifestError::MissingField {
            field: "profile".to_string(),
        })?;

        let config = ManifestConfig {
            version,
            target,
            profile,
        };

        config.validate()?;
        Ok(config)
    }
}

// ============================================================================
// CapabilityManifest
// ============================================================================

/// Capability manifest for a binary.
///
/// The manifest enumerates all commands and capabilities exposed by the binary,
/// with a cryptographic hash binding to the specific binary version.
///
/// # Deterministic Serialization
///
/// The manifest uses `BTreeMap` for `selftest_refs` to ensure deterministic
/// key ordering during serialization (CTR-2612). This is critical for:
/// - Consistent hash computation
/// - Verifiable integrity
/// - Reproducible builds
///
/// # Binary Hash Binding
///
/// Per DD-0006, the `binary_hash` field cryptographically binds the manifest
/// to a specific binary version. It is computed as:
///
/// ```text
/// BLAKE3(version || "\0" || target || "\0" || profile)
/// ```
///
/// This prevents manifest replay across different binary versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    /// Schema version for the manifest format.
    pub schema_version: String,

    /// BLAKE3 hash binding the manifest to a specific binary.
    pub binary_hash: String,

    /// Binary version (from `CARGO_PKG_VERSION`).
    pub version: String,

    /// Target triple (e.g., "x86_64-unknown-linux-gnu").
    pub target: String,

    /// Build profile ("debug" or "release").
    pub profile: String,

    /// Commands exposed by the binary.
    pub commands: Vec<Command>,

    /// Capabilities claimed by the binary.
    pub capabilities: Vec<Capability>,

    /// Mapping from selftest IDs to capability IDs.
    /// Uses `BTreeMap` for deterministic ordering (CTR-2612).
    pub selftest_refs: BTreeMap<String, String>,
}

impl CapabilityManifest {
    /// Generates a capability manifest from the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Build configuration (version, target, profile)
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::cac::manifest::{CapabilityManifest, ManifestConfig};
    ///
    /// let config = ManifestConfig::builder()
    ///     .version("0.3.0")
    ///     .target("x86_64-unknown-linux-gnu")
    ///     .profile("release")
    ///     .build()
    ///     .unwrap();
    ///
    /// let manifest = CapabilityManifest::generate(&config);
    /// assert!(!manifest.binary_hash.is_empty());
    /// ```
    #[must_use]
    pub fn generate(config: &ManifestConfig) -> Self {
        let binary_hash = Self::compute_binary_hash(config);

        Self {
            schema_version: CAPABILITY_MANIFEST_VERSION.to_string(),
            binary_hash,
            version: config.version.clone(),
            target: config.target.clone(),
            profile: config.profile.clone(),
            commands: Vec::new(),
            capabilities: Vec::new(),
            selftest_refs: BTreeMap::new(),
        }
    }

    /// Computes the binary hash from the configuration.
    ///
    /// Uses BLAKE3 with null-separated fields:
    /// `BLAKE3(version || "\0" || target || "\0" || profile)`
    #[must_use]
    pub fn compute_binary_hash(config: &ManifestConfig) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(config.version.as_bytes());
        hasher.update(b"\0");
        hasher.update(config.target.as_bytes());
        hasher.update(b"\0");
        hasher.update(config.profile.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Creates a manifest builder for more control over generation.
    #[must_use]
    pub fn builder() -> CapabilityManifestBuilder {
        CapabilityManifestBuilder::default()
    }

    /// Adds a command to the manifest.
    pub fn add_command(&mut self, command: Command) {
        self.commands.push(command);
    }

    /// Adds a capability to the manifest.
    pub fn add_capability(&mut self, capability: Capability) {
        self.capabilities.push(capability);
    }

    /// Adds a selftest reference mapping.
    pub fn add_selftest_ref(
        &mut self,
        selftest_id: impl Into<String>,
        capability_id: impl Into<String>,
    ) {
        self.selftest_refs
            .insert(selftest_id.into(), capability_id.into());
    }

    /// Validates the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    pub fn validate(&self) -> Result<(), ManifestError> {
        // Validate commands count
        if self.commands.len() > MAX_COMMANDS {
            return Err(ManifestError::TooManyItems {
                field: "commands".to_string(),
                max_count: MAX_COMMANDS,
                actual_count: self.commands.len(),
            });
        }

        // Validate each command
        for cmd in &self.commands {
            cmd.validate()?;
        }

        // Validate capabilities count
        if self.capabilities.len() > MAX_CAPABILITIES {
            return Err(ManifestError::TooManyItems {
                field: "capabilities".to_string(),
                max_count: MAX_CAPABILITIES,
                actual_count: self.capabilities.len(),
            });
        }

        // Validate each capability
        for cap in &self.capabilities {
            cap.validate()?;
        }

        // Validate selftest_refs count
        if self.selftest_refs.len() > MAX_SELFTEST_REFS {
            return Err(ManifestError::TooManyItems {
                field: "selftest_refs".to_string(),
                max_count: MAX_SELFTEST_REFS,
                actual_count: self.selftest_refs.len(),
            });
        }

        // Check for duplicate command names (at top level)
        let mut seen_commands = std::collections::HashSet::new();
        for cmd in &self.commands {
            if !seen_commands.insert(&cmd.name) {
                return Err(ManifestError::Duplicate {
                    item_type: "command".to_string(),
                    id: cmd.name.clone(),
                });
            }
        }

        // Check for duplicate capability IDs
        let mut seen_capabilities = std::collections::HashSet::new();
        for cap in &self.capabilities {
            if !seen_capabilities.insert(&cap.id) {
                return Err(ManifestError::Duplicate {
                    item_type: "capability".to_string(),
                    id: cap.id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Serializes the manifest to canonical JSON with sorted keys.
    ///
    /// This method ensures deterministic output by sorting:
    /// - Commands (and their subcommands, recursively) by name
    /// - Capabilities by ID
    /// - Selftest refs (already sorted via `BTreeMap`)
    ///
    /// # Errors
    ///
    /// Returns serialization error if the manifest cannot be serialized.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        // Create a sorted copy for deterministic serialization
        let sorted = self.to_sorted();
        serde_json::to_string_pretty(&sorted)
    }

    /// Returns a copy of the manifest with all collections sorted for
    /// determinism.
    ///
    /// This ensures stable output regardless of insertion order:
    /// - Commands sorted by name (recursively for subcommands)
    /// - Capabilities sorted by ID
    /// - Selftest refs already sorted (`BTreeMap`)
    #[must_use]
    pub fn to_sorted(&self) -> Self {
        let mut sorted = self.clone();

        // Sort commands by name, recursively
        sort_commands(&mut sorted.commands);

        // Sort capabilities by ID
        sorted.capabilities.sort_by(|a, b| a.id.cmp(&b.id));

        sorted
    }
}

/// Recursively sorts commands and their subcommands by name.
fn sort_commands(commands: &mut [Command]) {
    commands.sort_by(|a, b| a.name.cmp(&b.name));
    for cmd in commands.iter_mut() {
        sort_commands(&mut cmd.subcommands);
    }
}

/// Builder for [`CapabilityManifest`].
#[derive(Debug, Default, Clone)]
pub struct CapabilityManifestBuilder {
    config: Option<ManifestConfig>,
    commands: Vec<Command>,
    capabilities: Vec<Capability>,
    selftest_refs: BTreeMap<String, String>,
}

impl CapabilityManifestBuilder {
    /// Sets the manifest configuration.
    #[must_use]
    pub fn config(mut self, config: ManifestConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Adds a command.
    #[must_use]
    pub fn command(mut self, command: Command) -> Self {
        self.commands.push(command);
        self
    }

    /// Adds multiple commands.
    #[must_use]
    pub fn commands(mut self, commands: impl IntoIterator<Item = Command>) -> Self {
        self.commands.extend(commands);
        self
    }

    /// Adds a capability.
    #[must_use]
    pub fn capability(mut self, capability: Capability) -> Self {
        self.capabilities.push(capability);
        self
    }

    /// Adds multiple capabilities.
    #[must_use]
    pub fn capabilities(mut self, capabilities: impl IntoIterator<Item = Capability>) -> Self {
        self.capabilities.extend(capabilities);
        self
    }

    /// Adds a selftest reference.
    #[must_use]
    pub fn selftest_ref(
        mut self,
        selftest_id: impl Into<String>,
        capability_id: impl Into<String>,
    ) -> Self {
        self.selftest_refs
            .insert(selftest_id.into(), capability_id.into());
        self
    }

    /// Builds the manifest, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] if validation fails.
    pub fn build(self) -> Result<CapabilityManifest, ManifestError> {
        let config = self.config.ok_or_else(|| ManifestError::MissingField {
            field: "config".to_string(),
        })?;

        config.validate()?;

        let binary_hash = CapabilityManifest::compute_binary_hash(&config);

        let manifest = CapabilityManifest {
            schema_version: CAPABILITY_MANIFEST_VERSION.to_string(),
            binary_hash,
            version: config.version,
            target: config.target,
            profile: config.profile,
            commands: self.commands,
            capabilities: self.capabilities,
            selftest_refs: self.selftest_refs,
        };

        manifest.validate()?;
        Ok(manifest)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Command Tests
    // =========================================================================

    #[test]
    fn test_command_new() {
        let cmd = Command::new("start");
        assert_eq!(cmd.name, "start");
        assert!(cmd.description.is_none());
        assert!(cmd.subcommands.is_empty());
    }

    #[test]
    fn test_command_builder() {
        let cmd = Command::builder()
            .name("cac")
            .description("Context-as-Code commands")
            .subcommand(Command::new("apply-patch"))
            .build()
            .unwrap();

        assert_eq!(cmd.name, "cac");
        assert_eq!(
            cmd.description,
            Some("Context-as-Code commands".to_string())
        );
        assert_eq!(cmd.subcommands.len(), 1);
        assert_eq!(cmd.subcommands[0].name, "apply-patch");
    }

    #[test]
    fn test_command_validation_empty_name() {
        let result = Command::builder().name("").build();
        assert!(matches!(result, Err(ManifestError::MissingField { .. })));
    }

    #[test]
    fn test_command_validation_name_too_long() {
        let long_name = "x".repeat(MAX_COMMAND_NAME_LENGTH + 1);
        let result = Command::builder().name(long_name).build();
        assert!(matches!(result, Err(ManifestError::FieldTooLong { .. })));
    }

    #[test]
    fn test_command_validation_duplicate_subcommands() {
        // Duplicate subcommands at the same level should be rejected
        let result = Command::builder()
            .name("parent")
            .subcommand(Command::new("child"))
            .subcommand(Command::new("child")) // Duplicate!
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::Duplicate { item_type, id }) if item_type == "subcommand" && id == "child"
        ));
    }

    #[test]
    fn test_command_validation_duplicate_nested_subcommands() {
        // Duplicate subcommands in nested commands should also be rejected
        let nested = Command::builder()
            .name("nested")
            .subcommand(Command::new("dup"))
            .subcommand(Command::new("dup")) // Duplicate!
            .build();

        assert!(matches!(nested, Err(ManifestError::Duplicate { .. })));
    }

    #[test]
    fn test_command_same_name_different_levels_ok() {
        // The same name at different nesting levels is OK
        // e.g., "apm2 start" and "apm2 cac start" can coexist
        let result = Command::builder()
            .name("root")
            .subcommand(Command::new("start"))
            .subcommand(
                Command::builder()
                    .name("cac")
                    .subcommand(Command::new("start")) // Same name, different parent - OK
                    .build()
                    .unwrap(),
            )
            .build();
        assert!(result.is_ok());
    }

    // =========================================================================
    // Capability Tests
    // =========================================================================

    #[test]
    fn test_capability_new() {
        let cap = Capability::new("cac:patch:apply");
        assert_eq!(cap.id, "cac:patch:apply");
        assert!(cap.description.is_none());
        assert_eq!(cap.verification_method, VerificationMethod::Declared);
    }

    #[test]
    fn test_capability_builder() {
        let cap = Capability::builder()
            .id("cac:patch:apply")
            .description("Apply JSON patches to CAC artifacts")
            .verification_method(VerificationMethod::Selftest)
            .selftest_id("test_patch_apply")
            .build()
            .unwrap();

        assert_eq!(cap.id, "cac:patch:apply");
        assert_eq!(cap.verification_method, VerificationMethod::Selftest);
        assert_eq!(cap.selftest_id, Some("test_patch_apply".to_string()));
    }

    #[test]
    fn test_capability_validation_empty_id() {
        let result = Capability::builder().id("").build();
        assert!(matches!(result, Err(ManifestError::MissingField { .. })));
    }

    #[test]
    fn test_capability_validation_invalid_id_format() {
        let result = Capability::builder().id("invalid id!").build();
        assert!(matches!(
            result,
            Err(ManifestError::InvalidCapabilityId { .. })
        ));
    }

    #[test]
    fn test_capability_validation_selftest_requires_id() {
        let result = Capability::builder()
            .id("test-cap")
            .verification_method(VerificationMethod::Selftest)
            .build();
        assert!(matches!(result, Err(ManifestError::MissingField { .. })));
    }

    // =========================================================================
    // ManifestConfig Tests
    // =========================================================================

    #[test]
    fn test_manifest_config_builder() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        assert_eq!(config.version, "0.3.0");
        assert_eq!(config.target, "x86_64-unknown-linux-gnu");
        assert_eq!(config.profile, "release");
    }

    #[test]
    fn test_manifest_config_from_env() {
        let config = ManifestConfig::from_env();
        assert!(!config.version.is_empty());
        assert!(!config.target.is_empty());
        assert!(!config.profile.is_empty());
    }

    // =========================================================================
    // Security: Control Character Rejection Tests
    // =========================================================================

    #[test]
    fn test_manifest_config_rejects_null_in_version() {
        // SECURITY: This test verifies we prevent hash collision attacks.
        // Without this check, "1.0\0" + "x86" would hash the same as "1.0" + "\0x86"
        let result = ManifestConfig::builder()
            .version("1.0\0sneaky")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::ControlCharactersNotAllowed { field }) if field == "version"
        ));
    }

    #[test]
    fn test_manifest_config_rejects_null_in_target() {
        let result = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64\0attack")
            .profile("release")
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::ControlCharactersNotAllowed { field }) if field == "target"
        ));
    }

    #[test]
    fn test_manifest_config_rejects_null_in_profile() {
        let result = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release\0")
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::ControlCharactersNotAllowed { field }) if field == "profile"
        ));
    }

    #[test]
    fn test_manifest_config_rejects_other_control_characters() {
        // Tab character (ASCII 9)
        let result = ManifestConfig::builder()
            .version("0.3.0\t")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::ControlCharactersNotAllowed { .. })
        ));

        // Newline character (ASCII 10)
        let result = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64\n")
            .profile("release")
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::ControlCharactersNotAllowed { .. })
        ));

        // Carriage return (ASCII 13)
        let result = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release\r")
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::ControlCharactersNotAllowed { .. })
        ));

        // DEL character (ASCII 127)
        let result = ManifestConfig::builder()
            .version("0.3.0\x7F")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build();
        assert!(matches!(
            result,
            Err(ManifestError::ControlCharactersNotAllowed { .. })
        ));
    }

    #[test]
    fn test_contains_control_characters_helper() {
        // Valid strings
        assert!(!contains_control_characters("hello"));
        assert!(!contains_control_characters("0.3.0"));
        assert!(!contains_control_characters("x86_64-unknown-linux-gnu"));
        assert!(!contains_control_characters("release"));
        assert!(!contains_control_characters("test with spaces"));
        assert!(!contains_control_characters("symbols!@#$%^&*()"));

        // Invalid strings with control characters
        assert!(contains_control_characters("with\0null"));
        assert!(contains_control_characters("\0leading"));
        assert!(contains_control_characters("trailing\0"));
        assert!(contains_control_characters("with\ttab"));
        assert!(contains_control_characters("with\nnewline"));
        assert!(contains_control_characters("with\rcarriage"));
        assert!(contains_control_characters("with\x7Fdel"));
        assert!(contains_control_characters("\x01bell"));
    }

    // =========================================================================
    // CapabilityManifest Tests
    // =========================================================================

    #[test]
    fn test_manifest_generate() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let manifest = CapabilityManifest::generate(&config);

        assert_eq!(manifest.schema_version, CAPABILITY_MANIFEST_VERSION);
        assert_eq!(manifest.version, "0.3.0");
        assert_eq!(manifest.target, "x86_64-unknown-linux-gnu");
        assert_eq!(manifest.profile, "release");
        assert!(!manifest.binary_hash.is_empty());
    }

    #[test]
    fn test_manifest_binary_hash_deterministic() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let hash1 = CapabilityManifest::compute_binary_hash(&config);
        let hash2 = CapabilityManifest::compute_binary_hash(&config);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_manifest_binary_hash_changes_with_version() {
        let config1 = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let config2 = ManifestConfig::builder()
            .version("0.4.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let hash1 = CapabilityManifest::compute_binary_hash(&config1);
        let hash2 = CapabilityManifest::compute_binary_hash(&config2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_manifest_binary_hash_changes_with_profile() {
        let config1 = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let config2 = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("debug")
            .build()
            .unwrap();

        let hash1 = CapabilityManifest::compute_binary_hash(&config1);
        let hash2 = CapabilityManifest::compute_binary_hash(&config2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_manifest_builder() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let manifest = CapabilityManifest::builder()
            .config(config)
            .command(Command::new("start"))
            .capability(
                Capability::builder()
                    .id("process:start")
                    .verification_method(VerificationMethod::Declared)
                    .build()
                    .unwrap(),
            )
            .selftest_ref("test_start", "process:start")
            .build()
            .unwrap();

        assert_eq!(manifest.commands.len(), 1);
        assert_eq!(manifest.capabilities.len(), 1);
        assert_eq!(manifest.selftest_refs.len(), 1);
    }

    #[test]
    fn test_manifest_validation_duplicate_commands() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let result = CapabilityManifest::builder()
            .config(config)
            .command(Command::new("start"))
            .command(Command::new("start"))
            .build();

        assert!(matches!(result, Err(ManifestError::Duplicate { .. })));
    }

    #[test]
    fn test_manifest_validation_duplicate_capabilities() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let result = CapabilityManifest::builder()
            .config(config)
            .capability(
                Capability::builder()
                    .id("test-cap")
                    .verification_method(VerificationMethod::Declared)
                    .build()
                    .unwrap(),
            )
            .capability(
                Capability::builder()
                    .id("test-cap")
                    .verification_method(VerificationMethod::Declared)
                    .build()
                    .unwrap(),
            )
            .build();

        assert!(matches!(result, Err(ManifestError::Duplicate { .. })));
    }

    #[test]
    fn test_manifest_serialization_deterministic() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let manifest = CapabilityManifest::builder()
            .config(config)
            .selftest_ref("zebra_test", "cap:zebra")
            .selftest_ref("alpha_test", "cap:alpha")
            .build()
            .unwrap();

        let json1 = manifest.to_canonical_json().unwrap();
        let json2 = manifest.to_canonical_json().unwrap();

        assert_eq!(json1, json2);

        // Verify BTreeMap sorted order in output
        let alpha_pos = json1.find("alpha_test").unwrap();
        let zebra_pos = json1.find("zebra_test").unwrap();
        assert!(
            alpha_pos < zebra_pos,
            "selftest_refs should be sorted alphabetically"
        );
    }

    #[test]
    fn test_manifest_sorts_commands_and_capabilities() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        // Add commands and capabilities in non-alphabetical order
        let manifest = CapabilityManifest::builder()
            .config(config)
            // Commands in reverse order
            .command(Command::new("zebra"))
            .command(
                Command::builder()
                    .name("alpha")
                    .subcommand(Command::new("zed"))
                    .subcommand(Command::new("ace"))
                    .build()
                    .unwrap(),
            )
            // Capabilities in reverse order
            .capability(
                Capability::builder()
                    .id("zzz-cap")
                    .verification_method(VerificationMethod::Declared)
                    .build()
                    .unwrap(),
            )
            .capability(
                Capability::builder()
                    .id("aaa-cap")
                    .verification_method(VerificationMethod::Declared)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        // Get sorted version
        let sorted = manifest.to_sorted();

        // Commands should be sorted
        assert_eq!(sorted.commands[0].name, "alpha");
        assert_eq!(sorted.commands[1].name, "zebra");

        // Subcommands should also be sorted
        assert_eq!(sorted.commands[0].subcommands[0].name, "ace");
        assert_eq!(sorted.commands[0].subcommands[1].name, "zed");

        // Capabilities should be sorted
        assert_eq!(sorted.capabilities[0].id, "aaa-cap");
        assert_eq!(sorted.capabilities[1].id, "zzz-cap");

        // to_canonical_json should use sorted order
        let json = manifest.to_canonical_json().unwrap();
        let alpha_pos = json.find("\"alpha\"").unwrap();
        let zebra_pos = json.find("\"zebra\"").unwrap();
        assert!(alpha_pos < zebra_pos, "commands should be sorted in JSON");

        let aaa_pos = json.find("aaa-cap").unwrap();
        let zzz_pos = json.find("zzz-cap").unwrap();
        assert!(aaa_pos < zzz_pos, "capabilities should be sorted in JSON");
    }

    #[test]
    fn test_verification_method_as_str() {
        assert_eq!(VerificationMethod::Selftest.as_str(), "selftest");
        assert_eq!(
            VerificationMethod::StaticAnalysis.as_str(),
            "static_analysis"
        );
        assert_eq!(VerificationMethod::Declared.as_str(), "declared");
    }

    #[test]
    fn test_selftest_ref_new() {
        let ref_ = SelftestRef::new("test_patch", "cac:patch:apply");
        assert_eq!(ref_.selftest_id, "test_patch");
        assert_eq!(ref_.capability_id, "cac:patch:apply");
    }

    // =========================================================================
    // Nested Command Tests
    // =========================================================================

    #[test]
    fn test_nested_commands_via_builder() {
        let config_cmd = Command::builder()
            .name("config")
            .description("Configuration commands")
            .subcommand(
                Command::builder()
                    .name("get")
                    .description("Get a config value")
                    .build()
                    .unwrap(),
            )
            .subcommand(
                Command::builder()
                    .name("set")
                    .description("Set a config value")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let root_cmd = Command::builder()
            .name("test-cli")
            .description("A test CLI application")
            .subcommand(
                Command::builder()
                    .name("start")
                    .description("Start something")
                    .build()
                    .unwrap(),
            )
            .subcommand(config_cmd)
            .build()
            .unwrap();

        assert_eq!(root_cmd.name, "test-cli");
        assert_eq!(
            root_cmd.description,
            Some("A test CLI application".to_string())
        );
        assert_eq!(root_cmd.subcommands.len(), 2);

        // Find the 'config' subcommand
        let found_config_cmd = root_cmd
            .subcommands
            .iter()
            .find(|c| c.name == "config")
            .unwrap();
        assert_eq!(found_config_cmd.subcommands.len(), 2);
    }

    #[test]
    fn test_manifest_with_commands_via_builder() {
        let config = ManifestConfig::builder()
            .version("0.3.0")
            .target("x86_64-unknown-linux-gnu")
            .profile("release")
            .build()
            .unwrap();

        let apm2_cmd = Command::builder()
            .name("apm2")
            .description("AI Process Manager")
            .subcommand(
                Command::builder()
                    .name("start")
                    .description("Start a process")
                    .build()
                    .unwrap(),
            )
            .subcommand(
                Command::builder()
                    .name("stop")
                    .description("Stop a process")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let manifest = CapabilityManifest::builder()
            .config(config)
            .command(apm2_cmd)
            .build()
            .unwrap();

        assert_eq!(manifest.commands.len(), 1);
        assert_eq!(manifest.commands[0].name, "apm2");
        assert_eq!(manifest.commands[0].subcommands.len(), 2);
    }

    // =========================================================================
    // Schema Reference Tests
    // =========================================================================

    #[test]
    fn test_command_with_schema_refs() {
        let cmd = Command::builder()
            .name("apply-patch")
            .description("Apply a JSON patch")
            .input_schema_ref("schemas/cac/patch_request.schema.json")
            .output_schema_ref("schemas/cac/admission_receipt.schema.json")
            .build()
            .unwrap();

        assert_eq!(
            cmd.input_schema_ref,
            Some("schemas/cac/patch_request.schema.json".to_string())
        );
        assert_eq!(
            cmd.output_schema_ref,
            Some("schemas/cac/admission_receipt.schema.json".to_string())
        );
    }
}
