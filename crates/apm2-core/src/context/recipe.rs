//! Deterministic `ContextPack` recipe compilation and drift fingerprinting.
//!
//! This module compiles hash-pinned selector inputs into deterministic
//! [`ContextPackRecipe`] artifacts, emits comparable [`DriftFingerprint`]s, and
//! reconstructs recipes from receipt-bound CAS hashes without ambient
//! filesystem fallback.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::determinism::canonicalize_json;
use crate::events::Canonicalize;
use crate::evidence::{CasError, ContentAddressedStore};

/// Schema identifier for `ContextPackRecipe`.
pub const CONTEXT_PACK_RECIPE_SCHEMA: &str = "apm2.context_pack_recipe.v1";

/// Schema version for `ContextPackRecipe`.
pub const CONTEXT_PACK_RECIPE_VERSION: &str = "1.0.0";

/// Maximum length for schema fields.
pub const MAX_SCHEMA_FIELD_LENGTH: usize = 128;

/// Maximum length for schema version fields.
pub const MAX_SCHEMA_VERSION_LENGTH: usize = 32;

/// Maximum number of required read paths.
pub const MAX_REQUIRED_READ_PATHS: usize = 10_000;

/// Maximum length of a required read path.
pub const MAX_REQUIRED_READ_PATH_LENGTH: usize = 4_096;

/// Maximum number of path components in a required read path.
pub const MAX_REQUIRED_READ_PATH_COMPONENTS: usize = 256;

/// Maximum number of hash-pinned required-read digests.
pub const MAX_REQUIRED_READ_DIGESTS: usize = MAX_REQUIRED_READ_PATHS;

/// Maximum allowed length of the workspace root path.
pub const MAX_WORKSPACE_ROOT_LENGTH: usize = 4_096;

/// Hash-pinned selector input for deterministic recipe compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackSelectorInput {
    /// Hash of `RoleSpec v2` contract.
    pub role_spec_hash: [u8; 32],
    /// Deterministic set of files required for context reads.
    pub required_read_paths: BTreeSet<String>,
    /// Hash-pinned digest set for required reads.
    ///
    /// Keys are normalized workspace-relative paths. Values are BLAKE3 digests
    /// of the corresponding read artifact bytes.
    pub required_read_digests: BTreeMap<String, [u8; 32]>,
    /// Hash of the `ContextPackManifest`.
    pub context_manifest_hash: [u8; 32],
    /// Hash of the budget profile.
    pub budget_profile_hash: [u8; 32],
}

/// Result of recipe compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledContextPackRecipe {
    /// Deterministic compiled recipe.
    pub recipe: ContextPackRecipe,
    /// Drift fingerprint emitted for run-to-run comparison.
    pub fingerprint: DriftFingerprint,
}

/// Machine-readable reason codes for recipe compiler failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecipeCompilerReasonCode {
    /// Workspace root is not absolute.
    WorkspaceRootNotAbsolute,
    /// Workspace root path exceeds allowed length.
    WorkspaceRootTooLong,
    /// Workspace root canonicalization failed.
    WorkspaceRootCanonicalizationFailed,
    /// Selector contains no required read paths.
    EmptyRequiredReadPaths,
    /// Selector contains too many required read paths.
    TooManyRequiredReadPaths,
    /// Required path is empty.
    RequiredReadPathEmpty,
    /// Required path exceeds maximum length.
    RequiredReadPathTooLong,
    /// Required path contains an embedded null byte.
    RequiredReadPathContainsNull,
    /// Required path uses an absolute path.
    RequiredReadPathAbsolute,
    /// Required path contains traversal (`..`) components.
    RequiredReadPathTraversal,
    /// Required path has too many components.
    RequiredReadPathTooManyComponents,
    /// Required path resolves outside workspace boundaries.
    RequiredReadPathOutsideWorkspace,
    /// Required path resolves through a symlink component.
    RequiredReadPathSymlink,
    /// Required path or one of its components does not exist.
    RequiredReadPathNotFound,
    /// Failed to inspect path metadata during closure validation.
    RequiredReadPathMetadataReadFailed,
    /// Two required paths normalize to the same value.
    DuplicateNormalizedRequiredReadPath,
    /// Recipe schema field is invalid.
    InvalidRecipeSchema,
    /// Recipe schema version field is invalid.
    InvalidRecipeVersion,
    /// Required read paths are not sorted canonically.
    UnsortedRequiredReadPaths,
    /// Required read paths contain duplicates.
    DuplicateRequiredReadPath,
    /// Selector contains too many required-read digest entries.
    TooManyRequiredReadDigests,
    /// A required read path is not hash-pinned in the digest set.
    MissingRequiredReadDigest,
    /// The selector contains digest entries that are not required reads.
    UnexpectedRequiredReadDigest,
    /// Required-read digest set hash does not match required digests.
    RequiredReadDigestMismatch,
    /// Observed filesystem dependency is not hash-pinned by selector digests.
    AmbientReadNotHashPinned,
    /// Missing role hash artifact in CAS.
    MissingCasRoleHash,
    /// Missing required-read digest artifact in CAS.
    MissingCasRequiredReadDigest,
    /// Missing context manifest hash artifact in CAS.
    MissingCasContextManifestHash,
    /// Missing budget profile hash artifact in CAS.
    MissingCasBudgetProfileHash,
    /// Missing recipe artifact in CAS.
    MissingCasRecipeHash,
    /// CAS operation failed.
    CasOperationFailed,
    /// Serialization or canonicalization failed.
    SerializationFailed,
    /// Deserialization failed.
    DeserializationFailed,
    /// Recipe hash verification failed.
    RecipeHashMismatch,
    /// Fingerprint binding verification failed.
    FingerprintMismatch,
    /// Integer conversion overflowed.
    IntegerOverflow,
}

impl std::fmt::Display for RecipeCompilerReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::WorkspaceRootNotAbsolute => "workspace_root_not_absolute",
            Self::WorkspaceRootTooLong => "workspace_root_too_long",
            Self::WorkspaceRootCanonicalizationFailed => "workspace_root_canonicalization_failed",
            Self::EmptyRequiredReadPaths => "empty_required_read_paths",
            Self::TooManyRequiredReadPaths => "too_many_required_read_paths",
            Self::RequiredReadPathEmpty => "required_read_path_empty",
            Self::RequiredReadPathTooLong => "required_read_path_too_long",
            Self::RequiredReadPathContainsNull => "required_read_path_contains_null",
            Self::RequiredReadPathAbsolute => "required_read_path_absolute",
            Self::RequiredReadPathTraversal => "required_read_path_traversal",
            Self::RequiredReadPathTooManyComponents => "required_read_path_too_many_components",
            Self::RequiredReadPathOutsideWorkspace => "required_read_path_outside_workspace",
            Self::RequiredReadPathSymlink => "required_read_path_symlink",
            Self::RequiredReadPathNotFound => "required_read_path_not_found",
            Self::RequiredReadPathMetadataReadFailed => "required_read_path_metadata_read_failed",
            Self::DuplicateNormalizedRequiredReadPath => "duplicate_normalized_required_read_path",
            Self::InvalidRecipeSchema => "invalid_recipe_schema",
            Self::InvalidRecipeVersion => "invalid_recipe_version",
            Self::UnsortedRequiredReadPaths => "unsorted_required_read_paths",
            Self::DuplicateRequiredReadPath => "duplicate_required_read_path",
            Self::TooManyRequiredReadDigests => "too_many_required_read_digests",
            Self::MissingRequiredReadDigest => "missing_required_read_digest",
            Self::UnexpectedRequiredReadDigest => "unexpected_required_read_digest",
            Self::RequiredReadDigestMismatch => "required_read_digest_mismatch",
            Self::AmbientReadNotHashPinned => "ambient_read_not_hash_pinned",
            Self::MissingCasRoleHash => "missing_cas_role_hash",
            Self::MissingCasRequiredReadDigest => "missing_cas_required_read_digest",
            Self::MissingCasContextManifestHash => "missing_cas_context_manifest_hash",
            Self::MissingCasBudgetProfileHash => "missing_cas_budget_profile_hash",
            Self::MissingCasRecipeHash => "missing_cas_recipe_hash",
            Self::CasOperationFailed => "cas_operation_failed",
            Self::SerializationFailed => "serialization_failed",
            Self::DeserializationFailed => "deserialization_failed",
            Self::RecipeHashMismatch => "recipe_hash_mismatch",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::IntegerOverflow => "integer_overflow",
        };
        write!(f, "{value}")
    }
}

/// Errors that can occur while compiling or reconstructing context recipes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecipeCompilerError {
    /// Selector closure validation failed.
    #[error("selector closure violation ({code}): {message}")]
    SelectorClosure {
        /// Machine-readable reason code.
        code: RecipeCompilerReasonCode,
        /// Human-readable detail.
        message: String,
        /// Offending path when available.
        path: Option<String>,
    },

    /// Recipe structure or field validation failed.
    #[error("recipe validation failed ({code}): {message}")]
    RecipeValidation {
        /// Machine-readable reason code.
        code: RecipeCompilerReasonCode,
        /// Human-readable detail.
        message: String,
    },

    /// Serialization or canonicalization failed.
    #[error("serialization failed ({code}): {message}")]
    Serialization {
        /// Machine-readable reason code.
        code: RecipeCompilerReasonCode,
        /// Human-readable detail.
        message: String,
    },

    /// CAS operation failed or required hash is missing.
    #[error("cas operation failed ({code}) for hash {hash_hex}: {message}")]
    Cas {
        /// Machine-readable reason code.
        code: RecipeCompilerReasonCode,
        /// Hex-encoded hash context.
        hash_hex: String,
        /// Human-readable detail.
        message: String,
    },

    /// Hash binding verification failed.
    #[error("hash mismatch ({code}): expected {expected_hex}, actual {actual_hex}; {message}")]
    HashMismatch {
        /// Machine-readable reason code.
        code: RecipeCompilerReasonCode,
        /// Expected hash (hex).
        expected_hex: String,
        /// Actual hash (hex).
        actual_hex: String,
        /// Human-readable detail.
        message: String,
    },
}

impl RecipeCompilerError {
    /// Returns the machine-readable reason code for this error.
    #[must_use]
    pub const fn reason_code(&self) -> RecipeCompilerReasonCode {
        match self {
            Self::SelectorClosure { code, .. }
            | Self::RecipeValidation { code, .. }
            | Self::Serialization { code, .. }
            | Self::Cas { code, .. }
            | Self::HashMismatch { code, .. } => *code,
        }
    }
}

/// Deterministic compiler for `ContextPackRecipe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextPackRecipeCompiler {
    workspace_root: PathBuf,
    default_compiled_at_tick: u64,
}

impl ContextPackRecipeCompiler {
    /// Creates a compiler rooted at `workspace_root`.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if `workspace_root` is invalid.
    pub fn new(workspace_root: impl Into<PathBuf>) -> Result<Self, RecipeCompilerError> {
        let workspace_root = workspace_root.into();
        if !workspace_root.is_absolute() {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::WorkspaceRootNotAbsolute,
                message: "workspace root must be an absolute path".to_string(),
                path: Some(workspace_root.to_string_lossy().to_string()),
            });
        }

        let root_len = workspace_root.to_string_lossy().len();
        if root_len > MAX_WORKSPACE_ROOT_LENGTH {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::WorkspaceRootTooLong,
                message: format!(
                    "workspace root exceeds maximum length ({root_len} > \
                     {MAX_WORKSPACE_ROOT_LENGTH})"
                ),
                path: Some(workspace_root.to_string_lossy().to_string()),
            });
        }

        let canonical_root = fs::canonicalize(&workspace_root).map_err(|error| {
            RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::WorkspaceRootCanonicalizationFailed,
                message: format!("failed to canonicalize workspace root: {error}"),
                path: Some(workspace_root.to_string_lossy().to_string()),
            }
        })?;

        Ok(Self {
            workspace_root: canonical_root,
            default_compiled_at_tick: 0,
        })
    }

    /// Returns the canonical workspace root boundary used by this compiler.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Sets the default `compiled_at_tick` used by [`Self::compile`].
    #[must_use]
    pub const fn with_default_compiled_at_tick(mut self, tick: u64) -> Self {
        self.default_compiled_at_tick = tick;
        self
    }

    /// Compiles selector input into a deterministic recipe and drift
    /// fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] on selector closure, canonicalization,
    /// or validation failure.
    pub fn compile(
        &self,
        selector: &ContextPackSelectorInput,
    ) -> Result<CompiledContextPackRecipe, RecipeCompilerError> {
        self.compile_at_tick(selector, self.default_compiled_at_tick)
    }

    /// Compiles selector input at an explicit `compiled_at_tick`.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] on selector closure, canonicalization,
    /// or validation failure.
    pub fn compile_at_tick(
        &self,
        selector: &ContextPackSelectorInput,
        compiled_at_tick: u64,
    ) -> Result<CompiledContextPackRecipe, RecipeCompilerError> {
        self.compile_with_observed_reads(selector, &BTreeSet::new(), compiled_at_tick)
    }

    /// Compiles selector input with explicit observed filesystem dependencies.
    ///
    /// Any `observed_read_paths` entry not hash-pinned in
    /// `selector.required_read_digests` fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] when closure validation or
    /// ambient-read validation fails.
    pub fn compile_with_observed_reads(
        &self,
        selector: &ContextPackSelectorInput,
        observed_read_paths: &BTreeSet<String>,
        compiled_at_tick: u64,
    ) -> Result<CompiledContextPackRecipe, RecipeCompilerError> {
        let normalized_paths = self.validate_selector_closure(
            &selector.required_read_paths,
            &selector.required_read_digests,
        )?;
        let required_read_digest_set_hash =
            compute_required_read_digest_set_hash(&selector.required_read_digests)?;

        let recipe = ContextPackRecipe::new(
            selector.role_spec_hash,
            normalized_paths,
            selector.required_read_digests.clone(),
            required_read_digest_set_hash,
            selector.context_manifest_hash,
            selector.budget_profile_hash,
        )?;
        self.enforce_observed_dependencies_hash_pinned(observed_read_paths, &recipe)?;
        let recipe_hash = recipe.recipe_hash()?;

        let fingerprint = DriftFingerprint {
            role_hash: selector.role_spec_hash,
            required_read_digest_set_hash,
            context_manifest_hash: selector.context_manifest_hash,
            budget_profile_hash: selector.budget_profile_hash,
            recipe_hash,
            compiled_at_tick,
        };

        Ok(CompiledContextPackRecipe {
            recipe,
            fingerprint,
        })
    }

    fn validate_selector_closure(
        &self,
        required_read_paths: &BTreeSet<String>,
        required_read_digests: &BTreeMap<String, [u8; 32]>,
    ) -> Result<Vec<String>, RecipeCompilerError> {
        if required_read_paths.is_empty() {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::EmptyRequiredReadPaths,
                message: "required_read_paths must not be empty".to_string(),
                path: None,
            });
        }
        if required_read_paths.len() > MAX_REQUIRED_READ_PATHS {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::TooManyRequiredReadPaths,
                message: format!(
                    "required_read_paths exceeds maximum size ({} > {})",
                    required_read_paths.len(),
                    MAX_REQUIRED_READ_PATHS
                ),
                path: None,
            });
        }
        if required_read_digests.len() > MAX_REQUIRED_READ_DIGESTS {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::TooManyRequiredReadDigests,
                message: format!(
                    "required_read_digests exceeds maximum size ({} > {})",
                    required_read_digests.len(),
                    MAX_REQUIRED_READ_DIGESTS
                ),
                path: None,
            });
        }

        let mut normalized = Vec::with_capacity(required_read_paths.len());
        let mut dedupe = BTreeSet::new();

        for raw_path in required_read_paths {
            let normalized_path = self.validate_required_read_path(raw_path)?;
            if !dedupe.insert(normalized_path.clone()) {
                return Err(RecipeCompilerError::SelectorClosure {
                    code: RecipeCompilerReasonCode::DuplicateNormalizedRequiredReadPath,
                    message: "required read paths collapse to duplicate normalized value"
                        .to_string(),
                    path: Some(normalized_path),
                });
            }
            normalized.push(normalized_path);
        }

        let mut normalized_digest_map: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        for (raw_path, digest) in required_read_digests {
            let normalized_path = self.validate_required_read_path(raw_path)?;
            if normalized_digest_map
                .insert(normalized_path.clone(), *digest)
                .is_some()
            {
                return Err(RecipeCompilerError::SelectorClosure {
                    code: RecipeCompilerReasonCode::DuplicateNormalizedRequiredReadPath,
                    message: "required read digests collapse to duplicate normalized path"
                        .to_string(),
                    path: Some(normalized_path),
                });
            }
        }

        for path in &normalized {
            if !normalized_digest_map.contains_key(path) {
                return Err(RecipeCompilerError::SelectorClosure {
                    code: RecipeCompilerReasonCode::MissingRequiredReadDigest,
                    message: "required read path is not hash-pinned in required_read_digests"
                        .to_string(),
                    path: Some(path.clone()),
                });
            }
        }
        for digest_path in normalized_digest_map.keys() {
            if !dedupe.contains(digest_path) {
                return Err(RecipeCompilerError::SelectorClosure {
                    code: RecipeCompilerReasonCode::UnexpectedRequiredReadDigest,
                    message: "required_read_digests contains a path not in required_read_paths"
                        .to_string(),
                    path: Some(digest_path.clone()),
                });
            }
        }

        normalized.sort_unstable();
        Ok(normalized)
    }

    fn enforce_observed_dependencies_hash_pinned(
        &self,
        observed_read_paths: &BTreeSet<String>,
        recipe: &ContextPackRecipe,
    ) -> Result<(), RecipeCompilerError> {
        for observed in observed_read_paths {
            let normalized_observed = self.validate_required_read_path(observed)?;
            if !recipe
                .required_read_digests
                .contains_key(&normalized_observed)
            {
                return Err(RecipeCompilerError::SelectorClosure {
                    code: RecipeCompilerReasonCode::AmbientReadNotHashPinned,
                    message:
                        "observed filesystem dependency is not hash-pinned by selector digest set"
                            .to_string(),
                    path: Some(observed.clone()),
                });
            }
        }
        Ok(())
    }

    fn validate_required_read_path(&self, raw_path: &str) -> Result<String, RecipeCompilerError> {
        if raw_path.is_empty() {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::RequiredReadPathEmpty,
                message: "required read path must not be empty".to_string(),
                path: Some(raw_path.to_string()),
            });
        }
        if raw_path.len() > MAX_REQUIRED_READ_PATH_LENGTH {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::RequiredReadPathTooLong,
                message: format!(
                    "required read path exceeds maximum length ({} > {})",
                    raw_path.len(),
                    MAX_REQUIRED_READ_PATH_LENGTH
                ),
                path: Some(raw_path.to_string()),
            });
        }
        if raw_path.contains('\0') {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::RequiredReadPathContainsNull,
                message: "required read path contains embedded null byte".to_string(),
                path: Some(raw_path.to_string()),
            });
        }

        let normalized_relative = normalize_required_read_path(raw_path)?;
        let candidate = self.workspace_root.join(&normalized_relative);

        if !candidate.starts_with(&self.workspace_root) {
            return Err(RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::RequiredReadPathOutsideWorkspace,
                message: "required read path resolves outside workspace boundaries".to_string(),
                path: Some(raw_path.to_string()),
            });
        }

        self.ensure_no_symlink_components(&candidate, raw_path)?;

        Ok(path_to_forward_slashes(&normalized_relative))
    }

    fn ensure_no_symlink_components(
        &self,
        absolute_candidate: &Path,
        raw_path: &str,
    ) -> Result<(), RecipeCompilerError> {
        let relative = absolute_candidate
            .strip_prefix(&self.workspace_root)
            .map_err(|_| RecipeCompilerError::SelectorClosure {
                code: RecipeCompilerReasonCode::RequiredReadPathOutsideWorkspace,
                message: "required read path failed workspace boundary check".to_string(),
                path: Some(raw_path.to_string()),
            })?;

        let mut current = self.workspace_root.clone();
        for component in relative.components() {
            if let Component::Normal(part) = component {
                current.push(part);
                let metadata =
                    fs::symlink_metadata(&current).map_err(|error| match error.kind() {
                        std::io::ErrorKind::NotFound => RecipeCompilerError::SelectorClosure {
                            code: RecipeCompilerReasonCode::RequiredReadPathNotFound,
                            message: "required read path does not exist".to_string(),
                            path: Some(raw_path.to_string()),
                        },
                        _ => RecipeCompilerError::SelectorClosure {
                            code: RecipeCompilerReasonCode::RequiredReadPathMetadataReadFailed,
                            message: format!(
                                "failed to inspect required read path metadata: {error}"
                            ),
                            path: Some(raw_path.to_string()),
                        },
                    })?;
                if metadata.file_type().is_symlink() {
                    return Err(RecipeCompilerError::SelectorClosure {
                        code: RecipeCompilerReasonCode::RequiredReadPathSymlink,
                        message: "required read path resolves through symlink component"
                            .to_string(),
                        path: Some(raw_path.to_string()),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Deterministic compiled recipe for hash-pinned context selectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPackRecipe {
    /// Recipe schema identifier.
    #[serde(deserialize_with = "deserialize_schema_field")]
    pub schema: String,
    /// Recipe schema version.
    #[serde(deserialize_with = "deserialize_schema_version_field")]
    pub schema_version: String,
    /// Hash of the `RoleSpec v2` contract.
    pub role_spec_hash: [u8; 32],
    /// Canonically sorted required read paths.
    #[serde(deserialize_with = "deserialize_required_read_paths")]
    pub required_read_paths: Vec<String>,
    /// Hash-pinned digest entries for required reads.
    #[serde(deserialize_with = "deserialize_required_read_digests")]
    pub required_read_digests: BTreeMap<String, [u8; 32]>,
    /// Digest of canonical required-read digest set.
    #[serde(alias = "required_read_digest")]
    pub required_read_digest_set_hash: [u8; 32],
    /// Hash of the `ContextPackManifest`.
    pub context_manifest_hash: [u8; 32],
    /// Hash of the budget profile.
    pub budget_profile_hash: [u8; 32],
}

impl Canonicalize for ContextPackRecipe {
    fn canonicalize(&mut self) {
        self.required_read_paths.sort_unstable();
    }
}

impl ContextPackRecipe {
    /// Creates and validates a recipe.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] when the recipe is invalid.
    pub fn new(
        role_spec_hash: [u8; 32],
        required_read_paths: Vec<String>,
        required_read_digests: BTreeMap<String, [u8; 32]>,
        required_read_digest_set_hash: [u8; 32],
        context_manifest_hash: [u8; 32],
        budget_profile_hash: [u8; 32],
    ) -> Result<Self, RecipeCompilerError> {
        let recipe = Self {
            schema: CONTEXT_PACK_RECIPE_SCHEMA.to_string(),
            schema_version: CONTEXT_PACK_RECIPE_VERSION.to_string(),
            role_spec_hash,
            required_read_paths,
            required_read_digests,
            required_read_digest_set_hash,
            context_manifest_hash,
            budget_profile_hash,
        };
        recipe.validate()?;
        Ok(recipe)
    }

    /// Validates recipe invariants.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] when any invariant is violated.
    pub fn validate(&self) -> Result<(), RecipeCompilerError> {
        if self.schema != CONTEXT_PACK_RECIPE_SCHEMA {
            return Err(RecipeCompilerError::RecipeValidation {
                code: RecipeCompilerReasonCode::InvalidRecipeSchema,
                message: format!(
                    "invalid recipe schema: expected {CONTEXT_PACK_RECIPE_SCHEMA}, got {}",
                    self.schema
                ),
            });
        }
        if self.schema_version != CONTEXT_PACK_RECIPE_VERSION {
            return Err(RecipeCompilerError::RecipeValidation {
                code: RecipeCompilerReasonCode::InvalidRecipeVersion,
                message: format!(
                    "invalid recipe schema_version: expected {CONTEXT_PACK_RECIPE_VERSION}, got {}",
                    self.schema_version
                ),
            });
        }
        if self.required_read_paths.is_empty() {
            return Err(RecipeCompilerError::RecipeValidation {
                code: RecipeCompilerReasonCode::EmptyRequiredReadPaths,
                message: "required_read_paths must not be empty".to_string(),
            });
        }
        if self.required_read_paths.len() > MAX_REQUIRED_READ_PATHS {
            return Err(RecipeCompilerError::RecipeValidation {
                code: RecipeCompilerReasonCode::TooManyRequiredReadPaths,
                message: format!(
                    "required_read_paths exceeds maximum size ({} > {})",
                    self.required_read_paths.len(),
                    MAX_REQUIRED_READ_PATHS
                ),
            });
        }

        for path in &self.required_read_paths {
            validate_required_read_path_shape(path)?;
        }
        if self.required_read_digests.len() > MAX_REQUIRED_READ_DIGESTS {
            return Err(RecipeCompilerError::RecipeValidation {
                code: RecipeCompilerReasonCode::TooManyRequiredReadDigests,
                message: format!(
                    "required_read_digests exceeds maximum size ({} > {})",
                    self.required_read_digests.len(),
                    MAX_REQUIRED_READ_DIGESTS
                ),
            });
        }

        for pair in self.required_read_paths.windows(2) {
            match pair[0].cmp(&pair[1]) {
                Ordering::Greater => {
                    return Err(RecipeCompilerError::RecipeValidation {
                        code: RecipeCompilerReasonCode::UnsortedRequiredReadPaths,
                        message: "required_read_paths must be sorted lexicographically".to_string(),
                    });
                },
                Ordering::Equal => {
                    return Err(RecipeCompilerError::RecipeValidation {
                        code: RecipeCompilerReasonCode::DuplicateRequiredReadPath,
                        message: format!("duplicate required read path: {}", pair[0]),
                    });
                },
                Ordering::Less => {},
            }
        }

        for digest_path in self.required_read_digests.keys() {
            validate_required_read_path_shape(digest_path)?;
        }
        for path in &self.required_read_paths {
            if !self.required_read_digests.contains_key(path) {
                return Err(RecipeCompilerError::RecipeValidation {
                    code: RecipeCompilerReasonCode::MissingRequiredReadDigest,
                    message: format!("required read path '{path}' is not hash-pinned"),
                });
            }
        }
        for digest_path in self.required_read_digests.keys() {
            if self.required_read_paths.binary_search(digest_path).is_err() {
                return Err(RecipeCompilerError::RecipeValidation {
                    code: RecipeCompilerReasonCode::UnexpectedRequiredReadDigest,
                    message: format!(
                        "required_read_digests path '{digest_path}' is not in required_read_paths"
                    ),
                });
            }
        }

        let computed_digest_set_hash =
            compute_required_read_digest_set_hash(&self.required_read_digests)?;
        if computed_digest_set_hash != self.required_read_digest_set_hash {
            return Err(RecipeCompilerError::HashMismatch {
                code: RecipeCompilerReasonCode::RequiredReadDigestMismatch,
                expected_hex: hex::encode(self.required_read_digest_set_hash),
                actual_hex: hex::encode(computed_digest_set_hash),
                message: "required_read_digest_set_hash does not match required_read_digests"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Returns canonical JSON bytes for deterministic hashing/CAS storage.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecipeCompilerError> {
        let mut canonical = self.clone();
        canonical.canonicalize();
        let json = serde_json::to_string(&canonical).map_err(|error| {
            RecipeCompilerError::Serialization {
                code: RecipeCompilerReasonCode::SerializationFailed,
                message: error.to_string(),
            }
        })?;
        let canonical_json =
            canonicalize_json(&json).map_err(|error| RecipeCompilerError::Serialization {
                code: RecipeCompilerReasonCode::SerializationFailed,
                message: error.to_string(),
            })?;
        Ok(canonical_json.into_bytes())
    }

    /// Computes the deterministic hash of this recipe.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if canonicalization fails.
    pub fn recipe_hash(&self) -> Result<[u8; 32], RecipeCompilerError> {
        let bytes = self.canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Returns the canonical payload used to compute
    /// `required_read_digest_set_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if payload encoding fails.
    pub fn required_read_digest_set_payload(&self) -> Result<Vec<u8>, RecipeCompilerError> {
        build_required_read_digest_set_payload(&self.required_read_digests)
    }

    /// Backward-compatible alias for
    /// [`required_read_digest_set_payload`](Self::required_read_digest_set_payload).
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if payload encoding fails.
    pub fn required_read_digest_payload(&self) -> Result<Vec<u8>, RecipeCompilerError> {
        self.required_read_digest_set_payload()
    }
}

/// Compact fingerprint emitted on every recipe compilation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftFingerprint {
    /// `RoleSpec` hash binding.
    pub role_hash: [u8; 32],
    /// Digest of canonical required-read digest set.
    #[serde(alias = "required_read_digest")]
    pub required_read_digest_set_hash: [u8; 32],
    /// Context manifest hash binding.
    pub context_manifest_hash: [u8; 32],
    /// Budget profile hash binding.
    pub budget_profile_hash: [u8; 32],
    /// Compiled recipe hash binding.
    pub recipe_hash: [u8; 32],
    /// HTF tick at which compilation occurred.
    #[serde(default)]
    pub compiled_at_tick: u64,
}

impl Canonicalize for DriftFingerprint {
    fn canonicalize(&mut self) {}
}

impl DriftFingerprint {
    /// Returns canonical JSON bytes for deterministic hashing/CAS storage.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if canonicalization fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecipeCompilerError> {
        let json =
            serde_json::to_string(self).map_err(|error| RecipeCompilerError::Serialization {
                code: RecipeCompilerReasonCode::SerializationFailed,
                message: error.to_string(),
            })?;
        let canonical_json =
            canonicalize_json(&json).map_err(|error| RecipeCompilerError::Serialization {
                code: RecipeCompilerReasonCode::SerializationFailed,
                message: error.to_string(),
            })?;
        Ok(canonical_json.into_bytes())
    }

    /// Computes the deterministic hash of this fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if canonicalization fails.
    pub fn compute_fingerprint(&self) -> Result<[u8; 32], RecipeCompilerError> {
        let bytes = self.canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Backward-compatible alias for
    /// [`compute_fingerprint`](Self::compute_fingerprint).
    ///
    /// # Errors
    ///
    /// Returns [`RecipeCompilerError`] if canonicalization fails.
    pub fn fingerprint_hash(&self) -> Result<[u8; 32], RecipeCompilerError> {
        self.compute_fingerprint()
    }
}

/// Reconstructs a recipe from receipt-bound hashes in CAS.
///
/// This function is fail-closed:
/// - every hash in `fingerprint` must exist in CAS,
/// - recipe bytes are loaded from CAS only,
/// - no ambient filesystem reads are attempted.
///
/// # Errors
///
/// Returns [`RecipeCompilerError`] on missing CAS entries, deserialization
/// failure, or hash mismatch.
pub fn reconstruct_from_receipts(
    cas: &dyn ContentAddressedStore,
    fingerprint: &DriftFingerprint,
) -> Result<ContextPackRecipe, RecipeCompilerError> {
    ensure_hash_exists(
        cas,
        &fingerprint.role_hash,
        RecipeCompilerReasonCode::MissingCasRoleHash,
    )?;
    ensure_hash_exists(
        cas,
        &fingerprint.required_read_digest_set_hash,
        RecipeCompilerReasonCode::MissingCasRequiredReadDigest,
    )?;
    ensure_hash_exists(
        cas,
        &fingerprint.context_manifest_hash,
        RecipeCompilerReasonCode::MissingCasContextManifestHash,
    )?;
    ensure_hash_exists(
        cas,
        &fingerprint.budget_profile_hash,
        RecipeCompilerReasonCode::MissingCasBudgetProfileHash,
    )?;
    ensure_hash_exists(
        cas,
        &fingerprint.recipe_hash,
        RecipeCompilerReasonCode::MissingCasRecipeHash,
    )?;

    let recipe_bytes = cas.retrieve(&fingerprint.recipe_hash).map_err(|error| {
        cas_error(
            RecipeCompilerReasonCode::CasOperationFailed,
            &fingerprint.recipe_hash,
            &error,
        )
    })?;

    let recipe: ContextPackRecipe = serde_json::from_slice(&recipe_bytes).map_err(|error| {
        RecipeCompilerError::Serialization {
            code: RecipeCompilerReasonCode::DeserializationFailed,
            message: error.to_string(),
        }
    })?;
    recipe.validate()?;

    let computed_hash = recipe.recipe_hash()?;
    if computed_hash != fingerprint.recipe_hash {
        return Err(RecipeCompilerError::HashMismatch {
            code: RecipeCompilerReasonCode::RecipeHashMismatch,
            expected_hex: hex::encode(fingerprint.recipe_hash),
            actual_hex: hex::encode(computed_hash),
            message: "reconstructed recipe hash does not match fingerprint".to_string(),
        });
    }

    let recipe_bindings = (
        recipe.role_spec_hash,
        recipe.required_read_digest_set_hash,
        recipe.context_manifest_hash,
        recipe.budget_profile_hash,
    );
    let fingerprint_bindings = (
        fingerprint.role_hash,
        fingerprint.required_read_digest_set_hash,
        fingerprint.context_manifest_hash,
        fingerprint.budget_profile_hash,
    );
    if recipe_bindings != fingerprint_bindings {
        return Err(RecipeCompilerError::RecipeValidation {
            code: RecipeCompilerReasonCode::FingerprintMismatch,
            message: "reconstructed recipe fields do not match drift fingerprint".to_string(),
        });
    }

    Ok(recipe)
}

fn ensure_hash_exists(
    cas: &dyn ContentAddressedStore,
    hash: &[u8; 32],
    missing_code: RecipeCompilerReasonCode,
) -> Result<(), RecipeCompilerError> {
    match cas.exists(hash) {
        Ok(true) => Ok(()),
        Ok(false) => Err(RecipeCompilerError::Cas {
            code: missing_code,
            hash_hex: hex::encode(hash),
            message: "required hash missing from CAS".to_string(),
        }),
        Err(error) => Err(cas_error(
            RecipeCompilerReasonCode::CasOperationFailed,
            hash,
            &error,
        )),
    }
}

fn cas_error(
    code: RecipeCompilerReasonCode,
    hash: &[u8; 32],
    error: &CasError,
) -> RecipeCompilerError {
    RecipeCompilerError::Cas {
        code,
        hash_hex: hex::encode(hash),
        message: error.to_string(),
    }
}

fn validate_required_read_path_shape(path: &str) -> Result<(), RecipeCompilerError> {
    if path.is_empty() {
        return Err(RecipeCompilerError::RecipeValidation {
            code: RecipeCompilerReasonCode::RequiredReadPathEmpty,
            message: "required read path must not be empty".to_string(),
        });
    }
    if path.len() > MAX_REQUIRED_READ_PATH_LENGTH {
        return Err(RecipeCompilerError::RecipeValidation {
            code: RecipeCompilerReasonCode::RequiredReadPathTooLong,
            message: format!(
                "required read path exceeds maximum length ({} > {})",
                path.len(),
                MAX_REQUIRED_READ_PATH_LENGTH
            ),
        });
    }
    if path.contains('\0') {
        return Err(RecipeCompilerError::RecipeValidation {
            code: RecipeCompilerReasonCode::RequiredReadPathContainsNull,
            message: "required read path contains embedded null byte".to_string(),
        });
    }
    let _ = normalize_required_read_path(path)?;
    Ok(())
}

fn normalize_required_read_path(path: &str) -> Result<PathBuf, RecipeCompilerError> {
    let mut normalized = PathBuf::new();
    let mut component_count = 0usize;

    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => {
                component_count = component_count.saturating_add(1);
                if component_count > MAX_REQUIRED_READ_PATH_COMPONENTS {
                    return Err(RecipeCompilerError::SelectorClosure {
                        code: RecipeCompilerReasonCode::RequiredReadPathTooManyComponents,
                        message: format!(
                            "required read path exceeds maximum component count \
                             ({component_count} > {MAX_REQUIRED_READ_PATH_COMPONENTS})"
                        ),
                        path: Some(path.to_string()),
                    });
                }
                normalized.push(part);
            },
            Component::CurDir => {},
            Component::ParentDir => {
                return Err(RecipeCompilerError::SelectorClosure {
                    code: RecipeCompilerReasonCode::RequiredReadPathTraversal,
                    message: "required read path contains path traversal component".to_string(),
                    path: Some(path.to_string()),
                });
            },
            Component::RootDir | Component::Prefix(_) => {
                return Err(RecipeCompilerError::SelectorClosure {
                    code: RecipeCompilerReasonCode::RequiredReadPathAbsolute,
                    message: "required read path must be workspace-relative".to_string(),
                    path: Some(path.to_string()),
                });
            },
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(RecipeCompilerError::SelectorClosure {
            code: RecipeCompilerReasonCode::RequiredReadPathEmpty,
            message: "required read path resolves to empty path".to_string(),
            path: Some(path.to_string()),
        });
    }

    Ok(normalized)
}

fn path_to_forward_slashes(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn build_required_read_digest_set_payload(
    required_read_digests: &BTreeMap<String, [u8; 32]>,
) -> Result<Vec<u8>, RecipeCompilerError> {
    let mut payload = Vec::new();
    for (path, digest) in required_read_digests {
        let length = u32::try_from(path.len()).map_err(|_| RecipeCompilerError::Serialization {
            code: RecipeCompilerReasonCode::IntegerOverflow,
            message: "required read path length exceeds u32 range".to_string(),
        })?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(path.as_bytes());
        payload.extend_from_slice(digest);
    }
    Ok(payload)
}

fn compute_required_read_digest_set_hash(
    required_read_digests: &BTreeMap<String, [u8; 32]>,
) -> Result<[u8; 32], RecipeCompilerError> {
    let payload = build_required_read_digest_set_payload(required_read_digests)?;
    Ok(*blake3::hash(&payload).as_bytes())
}

fn deserialize_bounded_string<'de, D>(
    deserializer: D,
    max_len: usize,
    field_name: &str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > max_len {
        return Err(de::Error::custom(format!(
            "{field_name} exceeds maximum length ({} > {max_len})",
            value.len()
        )));
    }
    Ok(value)
}

fn deserialize_schema_field<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_SCHEMA_FIELD_LENGTH, "schema")
}

fn deserialize_schema_version_field<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string(deserializer, MAX_SCHEMA_VERSION_LENGTH, "schema_version")
}

fn deserialize_required_read_paths<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RequiredReadPathsVisitor;

    impl<'de> Visitor<'de> for RequiredReadPathsVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a sequence of at most {MAX_REQUIRED_READ_PATHS} required read paths"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values =
                Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_REQUIRED_READ_PATHS));
            while let Some(value) = seq.next_element::<String>()? {
                if value.len() > MAX_REQUIRED_READ_PATH_LENGTH {
                    return Err(de::Error::custom(format!(
                        "required read path exceeds maximum length ({} > {})",
                        value.len(),
                        MAX_REQUIRED_READ_PATH_LENGTH
                    )));
                }
                if values.len() >= MAX_REQUIRED_READ_PATHS {
                    return Err(de::Error::custom(format!(
                        "required_read_paths exceeds maximum size ({MAX_REQUIRED_READ_PATHS})"
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(RequiredReadPathsVisitor)
}

fn deserialize_required_read_digests<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, [u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RequiredReadDigestsVisitor;

    impl<'de> Visitor<'de> for RequiredReadDigestsVisitor {
        type Value = BTreeMap<String, [u8; 32]>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a map of at most {MAX_REQUIRED_READ_DIGESTS} required-read digests"
            )
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((path, digest)) = map.next_entry::<String, [u8; 32]>()? {
                if path.len() > MAX_REQUIRED_READ_PATH_LENGTH {
                    return Err(de::Error::custom(format!(
                        "required read path exceeds maximum length ({} > {})",
                        path.len(),
                        MAX_REQUIRED_READ_PATH_LENGTH
                    )));
                }
                if values.len() >= MAX_REQUIRED_READ_DIGESTS {
                    return Err(de::Error::custom(format!(
                        "required_read_digests exceeds maximum size ({MAX_REQUIRED_READ_DIGESTS})"
                    )));
                }
                if values.insert(path, digest).is_some() {
                    return Err(de::Error::custom(
                        "duplicate required_read_digests key encountered",
                    ));
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(RequiredReadDigestsVisitor)
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;
    use crate::evidence::{ContentAddressedStore, MemoryCas};

    fn setup_workspace() -> TempDir {
        let workspace = tempfile::tempdir().expect("tempdir should be created");
        fs::create_dir_all(workspace.path().join("src")).expect("src dir should be created");
        fs::create_dir_all(workspace.path().join("docs")).expect("docs dir should be created");
        fs::write(
            workspace.path().join("src/lib.rs"),
            b"pub fn deterministic_recipe() -> bool { true }\n",
        )
        .expect("src/lib.rs should be created");
        fs::write(workspace.path().join("README.md"), b"# recipe test\n")
            .expect("README.md should be created");
        fs::write(workspace.path().join("docs/spec.md"), b"spec\n")
            .expect("docs/spec.md should be created");
        fs::write(workspace.path().join("src/ambient.rs"), b"ambient\n")
            .expect("src/ambient.rs should be created");
        workspace
    }

    fn selector_with_paths(
        role_spec_hash: [u8; 32],
        context_manifest_hash: [u8; 32],
        budget_profile_hash: [u8; 32],
        paths: &[&str],
    ) -> ContextPackSelectorInput {
        let mut required_read_paths = BTreeSet::new();
        let mut required_read_digests = BTreeMap::new();
        for path in paths {
            let owned = (*path).to_string();
            required_read_paths.insert(owned.clone());
            required_read_digests.insert(owned.clone(), *blake3::hash(owned.as_bytes()).as_bytes());
        }

        ContextPackSelectorInput {
            role_spec_hash,
            required_read_paths,
            required_read_digests,
            context_manifest_hash,
            budget_profile_hash,
        }
    }

    #[test]
    fn compile_is_deterministic_for_identical_inputs() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");

        let role_hash = [0x11; 32];
        let context_hash = [0x22; 32];
        let budget_hash = [0x33; 32];
        let selector = selector_with_paths(
            role_hash,
            context_hash,
            budget_hash,
            &["README.md", "src/lib.rs"],
        );

        let first = compiler
            .compile(&selector)
            .expect("first compile should pass");
        let second = compiler
            .compile(&selector)
            .expect("second compile should pass");

        assert_eq!(
            first
                .recipe
                .recipe_hash()
                .expect("recipe hash should compute"),
            second
                .recipe
                .recipe_hash()
                .expect("recipe hash should compute")
        );
        assert_eq!(
            first
                .recipe
                .canonical_bytes()
                .expect("canonical bytes should compute"),
            second
                .recipe
                .canonical_bytes()
                .expect("canonical bytes should compute")
        );
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.fingerprint.role_hash, [0x11; 32]);
        assert_eq!(first.fingerprint.context_manifest_hash, [0x22; 32]);
        assert_eq!(first.fingerprint.budget_profile_hash, [0x33; 32]);
        assert_eq!(first.fingerprint.compiled_at_tick, 0);
        assert_eq!(
            first
                .fingerprint
                .compute_fingerprint()
                .expect("fingerprint hash should compute"),
            second
                .fingerprint
                .compute_fingerprint()
                .expect("fingerprint hash should compute")
        );
    }

    #[test]
    fn selector_closure_rejects_path_traversal() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");
        let selector = selector_with_paths([0x01; 32], [0x02; 32], [0x03; 32], &["../outside.txt"]);

        let error = compiler
            .compile(&selector)
            .expect_err("path traversal should be rejected");
        assert_eq!(
            error.reason_code(),
            RecipeCompilerReasonCode::RequiredReadPathTraversal
        );
    }

    #[cfg(unix)]
    #[test]
    fn selector_closure_rejects_symlink_path() {
        let workspace = setup_workspace();
        let outside = tempfile::tempdir().expect("outside tempdir should be created");
        fs::write(outside.path().join("leak.txt"), b"leak").expect("outside file should exist");
        symlink(
            outside.path().join("leak.txt"),
            workspace.path().join("src/leak_link"),
        )
        .expect("symlink should be created");

        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");
        let selector = selector_with_paths([0x01; 32], [0x02; 32], [0x03; 32], &["src/leak_link"]);

        let error = compiler
            .compile(&selector)
            .expect_err("symlink should be rejected");
        assert_eq!(
            error.reason_code(),
            RecipeCompilerReasonCode::RequiredReadPathSymlink
        );
    }

    #[test]
    fn selector_closure_rejects_empty_required_paths() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");
        let selector = selector_with_paths([0x01; 32], [0x02; 32], [0x03; 32], &[]);

        let error = compiler
            .compile(&selector)
            .expect_err("empty required paths should be rejected");
        assert_eq!(
            error.reason_code(),
            RecipeCompilerReasonCode::EmptyRequiredReadPaths
        );
    }

    #[test]
    fn selector_closure_rejects_missing_required_digest() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");
        let mut selector = selector_with_paths(
            [0x01; 32],
            [0x02; 32],
            [0x03; 32],
            &["README.md", "src/lib.rs"],
        );
        selector.required_read_digests.remove("src/lib.rs");

        let error = compiler
            .compile(&selector)
            .expect_err("missing required digest should fail selector closure");
        assert_eq!(
            error.reason_code(),
            RecipeCompilerReasonCode::MissingRequiredReadDigest
        );
    }

    #[test]
    fn ambient_read_denial_rejects_unpinned_observed_dependency() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");
        let selector = selector_with_paths([0x11; 32], [0x22; 32], [0x33; 32], &["README.md"]);

        let mut observed = BTreeSet::new();
        observed.insert("src/ambient.rs".to_string());
        let error = compiler
            .compile_with_observed_reads(&selector, &observed, 42)
            .expect_err("unhash-pinned observed dependency must be rejected");
        assert_eq!(
            error.reason_code(),
            RecipeCompilerReasonCode::AmbientReadNotHashPinned
        );
    }

    #[test]
    fn drift_fingerprint_changes_when_selector_changes() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");

        let base_selector = selector_with_paths([0xA1; 32], [0xB2; 32], [0xC3; 32], &["README.md"]);
        let same_selector = selector_with_paths([0xA1; 32], [0xB2; 32], [0xC3; 32], &["README.md"]);
        let changed_selector =
            selector_with_paths([0xA1; 32], [0xB2; 32], [0xC3; 32], &["docs/spec.md"]);

        let first = compiler
            .compile(&base_selector)
            .expect("base compile should pass");
        let second = compiler
            .compile(&same_selector)
            .expect("same compile should pass");
        let changed = compiler
            .compile(&changed_selector)
            .expect("changed compile should pass");

        assert_eq!(first.fingerprint, second.fingerprint);
        assert_ne!(first.fingerprint, changed.fingerprint);
        assert_ne!(
            first.fingerprint.required_read_digest_set_hash,
            changed.fingerprint.required_read_digest_set_hash
        );
        assert_ne!(
            first
                .fingerprint
                .compute_fingerprint()
                .expect("fingerprint hash should compute"),
            changed
                .fingerprint
                .compute_fingerprint()
                .expect("fingerprint hash should compute")
        );
    }

    #[test]
    fn reconstruct_round_trip_from_cas_succeeds() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");
        let cas = MemoryCas::new();

        let role_hash = cas
            .store(b"role-spec-v2")
            .expect("role hash should store")
            .hash;
        let context_manifest_hash = cas
            .store(b"context-manifest")
            .expect("manifest hash should store")
            .hash;
        let budget_profile_hash = cas
            .store(b"budget-profile")
            .expect("budget hash should store")
            .hash;

        let selector = selector_with_paths(
            role_hash,
            context_manifest_hash,
            budget_profile_hash,
            &["README.md", "src/lib.rs"],
        );
        let compilation = compiler.compile(&selector).expect("compile should pass");

        let required_digest_payload = compilation
            .recipe
            .required_read_digest_payload()
            .expect("required-read payload should encode");
        let required_store = cas
            .store(&required_digest_payload)
            .expect("required digest payload should store");
        assert_eq!(
            required_store.hash,
            compilation.fingerprint.required_read_digest_set_hash
        );

        let recipe_bytes = compilation
            .recipe
            .canonical_bytes()
            .expect("recipe canonical bytes should serialize");
        let recipe_store = cas.store(&recipe_bytes).expect("recipe should store");
        assert_eq!(recipe_store.hash, compilation.fingerprint.recipe_hash);

        let reconstructed = reconstruct_from_receipts(&cas, &compilation.fingerprint)
            .expect("reconstruction should succeed");

        assert_eq!(reconstructed.role_spec_hash, role_hash);
        assert_eq!(reconstructed.context_manifest_hash, context_manifest_hash);
        assert_eq!(reconstructed.budget_profile_hash, budget_profile_hash);
        assert_eq!(
            reconstructed.required_read_paths,
            vec!["README.md".to_string(), "src/lib.rs".to_string()]
        );
    }

    #[test]
    fn reconstruct_fails_when_required_cas_entry_is_missing() {
        let workspace = setup_workspace();
        let compiler =
            ContextPackRecipeCompiler::new(workspace.path()).expect("compiler should initialize");
        let cas = MemoryCas::new();

        let role_hash = cas.store(b"role").expect("role hash should store").hash;
        let context_manifest_hash = cas
            .store(b"context")
            .expect("context hash should store")
            .hash;
        let budget_profile_hash = cas.store(b"budget").expect("budget hash should store").hash;

        let selector = selector_with_paths(
            role_hash,
            context_manifest_hash,
            budget_profile_hash,
            &["README.md"],
        );
        let compilation = compiler.compile(&selector).expect("compile should pass");

        let recipe_bytes = compilation
            .recipe
            .canonical_bytes()
            .expect("recipe canonical bytes should serialize");
        cas.store(&recipe_bytes).expect("recipe should store");
        // Intentionally skip storing required_read_digest_set payload.

        let error = reconstruct_from_receipts(&cas, &compilation.fingerprint)
            .expect_err("missing CAS digest entry must fail closed");
        assert_eq!(
            error.reason_code(),
            RecipeCompilerReasonCode::MissingCasRequiredReadDigest
        );
    }
}
