//! CAC JSON Schema validator.
//!
//! This module provides JSON Schema validation for CAC (Context-as-Code)
//! artifacts with strict enforcement of the CAC profile constraints.
//!
//! # CAC Validation Profile
//!
//! The validator enforces:
//!
//! - **Strict schema validation**: Uses `unevaluatedProperties=false` to reject
//!   unknown fields (fail-closed)
//! - **Size limits**: Pre-validation checks before schema validation to prevent
//!   denial-of-service
//!   - Maximum array members: 100,000
//!   - Maximum object properties: 100,000
//!   - Maximum nesting depth: 128 levels
//! - **Error location reporting**: All errors include JSON path to the
//!   violation
//!
//! # Security
//!
//! Pre-validating size limits before schema validation prevents
//! denial-of-service attacks that could exploit expensive schema operations on
//! maliciously large inputs.
//!
//! # Example
//!
//! ```ignore
//! use apm2_core::cac::{CacValidator, ValidationError};
//! use serde_json::json;
//!
//! let schema = json!({
//!     "$schema": "https://json-schema.org/draft/2020-12/schema",
//!     "type": "object",
//!     "properties": {
//!         "name": { "type": "string" }
//!     },
//!     "unevaluatedProperties": false
//! });
//!
//! let validator = CacValidator::new(&schema).unwrap();
//!
//! // Valid artifact
//! let valid = json!({"name": "test"});
//! assert!(validator.validate(&valid).is_ok());
//!
//! // Unknown field rejected
//! let invalid = json!({"name": "test", "extra": "field"});
//! assert!(matches!(
//!     validator.validate(&invalid).unwrap_err(),
//!     ValidationError::UnknownField { .. }
//! ));
//! ```

use jsonschema::error::ValidationErrorKind;
use serde_json::Value;
use thiserror::Error;

/// Maximum number of members allowed in a JSON array.
///
/// Arrays with more than 100,000 members are rejected with
/// [`ValidationError::ArrayTooLarge`].
///
/// # Rationale
///
/// This limit is specified by RFC-0011 (Context-as-Code v1) to accommodate
/// large CAC artifacts such as batch ticket lists or comprehensive audit logs.
/// DoS attacks are mitigated by performing this size check **before** schema
/// validation, ensuring expensive schema operations never run on oversized
/// inputs.
pub const MAX_ARRAY_MEMBERS: usize = 100_000;

/// Maximum number of properties allowed in a JSON object.
///
/// Objects with more than 100,000 properties are rejected with
/// [`ValidationError::ObjectTooLarge`].
///
/// # Rationale
///
/// This limit is specified by RFC-0011 (Context-as-Code v1) to accommodate
/// large CAC artifacts such as property-heavy configuration objects.
/// DoS attacks are mitigated by performing this size check **before** schema
/// validation, ensuring expensive schema operations never run on oversized
/// inputs.
pub const MAX_OBJECT_PROPERTIES: usize = 100_000;

/// Maximum nesting depth allowed in JSON structures.
///
/// Structures nested deeper than 128 levels are rejected with
/// [`ValidationError::MaxDepthExceeded`].
pub const MAX_DEPTH: usize = 128;

/// Errors that can occur during CAC validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// An unknown field was found in the JSON object.
    ///
    /// CAC validation uses strict schema mode (`unevaluatedProperties=false`)
    /// to reject any fields not explicitly defined in the schema.
    #[error("unknown field '{field}' at path '{path}'")]
    UnknownField {
        /// The name of the unknown field.
        field: String,
        /// JSON path to the object containing the unknown field.
        path: String,
    },

    /// An array exceeds the maximum allowed number of members.
    #[error("array at path '{path}' has {count} members, exceeds limit of {limit}")]
    ArrayTooLarge {
        /// JSON path to the array.
        path: String,
        /// Actual number of members in the array.
        count: usize,
        /// Maximum allowed members.
        limit: usize,
    },

    /// An object exceeds the maximum allowed number of properties.
    #[error("object at path '{path}' has {count} properties, exceeds limit of {limit}")]
    ObjectTooLarge {
        /// JSON path to the object.
        path: String,
        /// Actual number of properties in the object.
        count: usize,
        /// Maximum allowed properties.
        limit: usize,
    },

    /// The JSON structure exceeds the maximum allowed nesting depth.
    #[error("maximum depth of {max_depth} exceeded at path '{path}'")]
    MaxDepthExceeded {
        /// JSON path where the depth limit was exceeded.
        path: String,
        /// The maximum allowed depth.
        max_depth: usize,
    },

    /// Schema validation failed with a specific error message.
    #[error("schema validation failed at path '{path}': {message}")]
    SchemaValidation {
        /// JSON path to the validation failure.
        path: String,
        /// Description of the validation error.
        message: String,
    },

    /// The JSON Schema itself is invalid.
    #[error("invalid JSON schema: {message}")]
    InvalidSchema {
        /// Description of the schema error.
        message: String,
    },
}

/// CAC JSON Schema validator.
///
/// Wraps the `jsonschema` crate's `Validator` with CAC-specific configuration
/// and size limit pre-validation.
///
/// # Construction
///
/// Create a validator from a JSON Schema value:
///
/// ```ignore
/// use apm2_core::cac::CacValidator;
/// use serde_json::json;
///
/// let schema = json!({
///     "$schema": "https://json-schema.org/draft/2020-12/schema",
///     "type": "object"
/// });
///
/// let validator = CacValidator::new(&schema)?;
/// ```
///
/// # Validation
///
/// The validator performs two-phase validation:
/// 1. **Size limit pre-validation**: Check array sizes, object sizes, and depth
/// 2. **Schema validation**: Validate against the JSON Schema with strict mode
///
/// Both phases report errors with JSON path locations.
#[derive(Debug)]
pub struct CacValidator {
    validator: jsonschema::Validator,
}

impl CacValidator {
    /// Creates a new CAC validator from a JSON Schema.
    ///
    /// The schema should use draft 2020-12 and include `unevaluatedProperties:
    /// false` for strict validation. The validator is configured with:
    ///
    /// - Draft 2020-12 compliance
    /// - Strict mode for format validation
    ///
    /// # Arguments
    ///
    /// * `schema` - A JSON Schema value (must be a valid JSON Schema)
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidSchema`] if the schema is not a valid
    /// JSON Schema.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use apm2_core::cac::CacValidator;
    /// use serde_json::json;
    ///
    /// let schema = json!({
    ///     "$schema": "https://json-schema.org/draft/2020-12/schema",
    ///     "type": "object",
    ///     "properties": {
    ///         "id": { "type": "string" }
    ///     },
    ///     "unevaluatedProperties": false
    /// });
    ///
    /// let validator = CacValidator::new(&schema)?;
    /// ```
    pub fn new(schema: &Value) -> Result<Self, ValidationError> {
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .build(schema)
            .map_err(|e| ValidationError::InvalidSchema {
                message: e.to_string(),
            })?;

        Ok(Self { validator })
    }

    /// Validates a JSON value against the schema with CAC constraints.
    ///
    /// This method performs two-phase validation:
    ///
    /// 1. **Size limit pre-validation**: Checks for oversized arrays, objects,
    ///    and excessive nesting depth. This prevents denial-of-service attacks
    ///    that could exploit expensive schema operations.
    ///
    /// 2. **Schema validation**: Validates the value against the JSON Schema.
    ///    Unknown fields are rejected if the schema uses
    ///    `unevaluatedProperties: false`.
    ///
    /// # Arguments
    ///
    /// * `value` - The JSON value to validate
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] if validation fails:
    ///
    /// - [`ValidationError::ArrayTooLarge`] - Array exceeds 100,000 members
    /// - [`ValidationError::ObjectTooLarge`] - Object exceeds 100,000
    ///   properties
    /// - [`ValidationError::MaxDepthExceeded`] - Nesting exceeds 128 levels
    /// - [`ValidationError::UnknownField`] - Unknown field in strict mode
    /// - [`ValidationError::SchemaValidation`] - Other schema validation
    ///   failures
    ///
    /// # Example
    ///
    /// ```ignore
    /// use apm2_core::cac::CacValidator;
    /// use serde_json::json;
    ///
    /// let schema = json!({
    ///     "$schema": "https://json-schema.org/draft/2020-12/schema",
    ///     "type": "object",
    ///     "properties": {
    ///         "name": { "type": "string" }
    ///     },
    ///     "unevaluatedProperties": false
    /// });
    ///
    /// let validator = CacValidator::new(&schema)?;
    ///
    /// // Valid value
    /// let valid = json!({"name": "test"});
    /// validator.validate(&valid)?;
    ///
    /// // Invalid: unknown field
    /// let invalid = json!({"name": "test", "extra": "field"});
    /// assert!(validator.validate(&invalid).is_err());
    /// ```
    pub fn validate(&self, value: &Value) -> Result<(), ValidationError> {
        // Phase 1: Size limit pre-validation
        validate_size_limits(value, "", 0)?;

        // Phase 2: Schema validation
        self.validate_schema(value)
    }

    /// Validates a JSON value against the schema only (no size limit checks).
    ///
    /// This is useful when size limits have already been checked or when
    /// validating values known to be within limits.
    fn validate_schema(&self, value: &Value) -> Result<(), ValidationError> {
        self.validator.validate(value).map_err(|error| {
            let path = error.instance_path().to_string();
            let formatted_path = if path.is_empty() {
                "$".to_string()
            } else {
                format!("${path}")
            };

            // Check if this is an unevaluatedProperties or additionalProperties error
            // by inspecting the error kind enum directly (more robust than string parsing)
            match error.kind() {
                ValidationErrorKind::UnevaluatedProperties { unexpected }
                | ValidationErrorKind::AdditionalProperties { unexpected } => {
                    // Get the first unexpected field name, or "unknown" if empty
                    let field = unexpected
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());

                    ValidationError::UnknownField {
                        field,
                        path: formatted_path,
                    }
                },
                _ => ValidationError::SchemaValidation {
                    path: formatted_path,
                    message: error.to_string(),
                },
            }
        })
    }
}

/// Validates size limits on a JSON value recursively.
///
/// Checks for:
/// - Arrays with more than `MAX_ARRAY_MEMBERS` members
/// - Objects with more than `MAX_OBJECT_PROPERTIES` properties
/// - Nesting deeper than `MAX_DEPTH` levels
fn validate_size_limits(value: &Value, path: &str, depth: usize) -> Result<(), ValidationError> {
    // Check depth limit
    if depth > MAX_DEPTH {
        return Err(ValidationError::MaxDepthExceeded {
            path: format_path(path),
            max_depth: MAX_DEPTH,
        });
    }

    match value {
        Value::Array(arr) => {
            // Check array size
            if arr.len() > MAX_ARRAY_MEMBERS {
                return Err(ValidationError::ArrayTooLarge {
                    path: format_path(path),
                    count: arr.len(),
                    limit: MAX_ARRAY_MEMBERS,
                });
            }

            // Recursively check array elements
            for (i, item) in arr.iter().enumerate() {
                let item_path = format!("{path}[{i}]");
                validate_size_limits(item, &item_path, depth + 1)?;
            }
        },
        Value::Object(obj) => {
            // Check object size
            if obj.len() > MAX_OBJECT_PROPERTIES {
                return Err(ValidationError::ObjectTooLarge {
                    path: format_path(path),
                    count: obj.len(),
                    limit: MAX_OBJECT_PROPERTIES,
                });
            }

            // Recursively check object values
            for (key, val) in obj {
                let val_path = if path.is_empty() {
                    format!(".{key}")
                } else {
                    format!("{path}.{key}")
                };
                validate_size_limits(val, &val_path, depth + 1)?;
            }
        },
        // Primitives have no size/depth concerns
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {},
    }

    Ok(())
}

/// Formats a JSON path for error messages.
///
/// Converts internal path format to JSON Pointer style with `$` prefix.
fn format_path(path: &str) -> String {
    if path.is_empty() {
        "$".to_string()
    } else {
        format!("${path}")
    }
}

/// Validates a CAC artifact through the admission pipeline.
///
/// This function is the primary entry point for validating CAC artifacts
/// in the admission pipeline. It creates a temporary validator and validates
/// the artifact against the provided schema.
///
/// For repeated validations against the same schema, prefer creating a
/// [`CacValidator`] once and reusing it.
///
/// # Arguments
///
/// * `schema` - The JSON Schema to validate against
/// * `artifact` - The JSON artifact to validate
///
/// # Errors
///
/// Returns a [`ValidationError`] if validation fails.
///
/// # Example
///
/// ```ignore
/// use apm2_core::cac::validate_cac_artifact;
/// use serde_json::json;
///
/// let schema = json!({
///     "$schema": "https://json-schema.org/draft/2020-12/schema",
///     "type": "object",
///     "properties": {
///         "id": { "type": "string" }
///     },
///     "unevaluatedProperties": false
/// });
///
/// let artifact = json!({"id": "CAC-001"});
/// validate_cac_artifact(&schema, &artifact)?;
/// ```
pub fn validate_cac_artifact(schema: &Value, artifact: &Value) -> Result<(), ValidationError> {
    let validator = CacValidator::new(schema)?;
    validator.validate(artifact)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // =========================================================================
    // Schema Construction Tests
    // =========================================================================

    #[test]
    fn test_valid_schema_construction() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "id": { "type": "string" }
            }
        });

        let result = CacValidator::new(&schema);
        assert!(result.is_ok(), "Valid schema should construct successfully");
    }

    #[test]
    fn test_invalid_schema_construction() {
        // Invalid: $ref to non-existent schema
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "file:///nonexistent/schema.json"
        });

        let result = CacValidator::new(&schema);
        assert!(
            matches!(result, Err(ValidationError::InvalidSchema { .. })),
            "Invalid schema should fail construction"
        );
    }

    // =========================================================================
    // Unknown Field Rejection Tests
    // =========================================================================

    #[test]
    fn test_reject_unknown_field_with_unevaluated_properties() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "name": { "type": "string" }
            },
            "unevaluatedProperties": false
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Valid: only known property
        let valid = json!({"name": "test"});
        assert!(validator.validate(&valid).is_ok());

        // Invalid: unknown property
        let invalid = json!({"name": "test", "extra": "field"});
        let result = validator.validate(&invalid);
        assert!(
            matches!(result, Err(ValidationError::UnknownField { .. })),
            "Expected UnknownField error, got: {result:?}"
        );
    }

    #[test]
    fn test_reject_unknown_field_nested_object() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "outer": {
                    "type": "object",
                    "properties": {
                        "inner": { "type": "string" }
                    },
                    "unevaluatedProperties": false
                }
            },
            "unevaluatedProperties": false
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Valid nested object
        let valid = json!({"outer": {"inner": "value"}});
        assert!(validator.validate(&valid).is_ok());

        // Unknown field in nested object
        let invalid = json!({"outer": {"inner": "value", "unknown": "x"}});
        let result = validator.validate(&invalid);
        assert!(
            matches!(result, Err(ValidationError::UnknownField { .. })),
            "Expected UnknownField for nested object, got: {result:?}"
        );
    }

    #[test]
    fn test_error_includes_path() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "level1": {
                    "type": "object",
                    "properties": {
                        "level2": { "type": "string" }
                    },
                    "unevaluatedProperties": false
                }
            }
        });

        let validator = CacValidator::new(&schema).unwrap();
        let invalid = json!({"level1": {"level2": "ok", "bad": "field"}});
        let result = validator.validate(&invalid);

        match result {
            Err(ValidationError::UnknownField { path, field }) => {
                assert!(
                    path.contains("level1"),
                    "Path should contain 'level1', got: {path}"
                );
                assert_eq!(field, "bad", "Field should be 'bad'");
            },
            other => panic!("Expected UnknownField error, got: {other:?}"),
        }
    }

    // =========================================================================
    // Array Size Limit Tests
    // =========================================================================

    #[test]
    fn test_reject_array_too_large() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "array",
            "items": { "type": "integer" }
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Array at limit should pass
        let at_limit_json = Value::Array((0..MAX_ARRAY_MEMBERS).map(|i| json!(i)).collect());
        assert!(
            validator.validate(&at_limit_json).is_ok(),
            "Array at limit should pass"
        );

        // Array over limit should fail
        let over_limit_json = Value::Array((0..=MAX_ARRAY_MEMBERS).map(|i| json!(i)).collect());
        let result = validator.validate(&over_limit_json);
        assert!(
            matches!(
                result,
                Err(ValidationError::ArrayTooLarge {
                    count,
                    limit,
                    ..
                }) if count == MAX_ARRAY_MEMBERS + 1 && limit == MAX_ARRAY_MEMBERS
            ),
            "Array over limit should fail with ArrayTooLarge, got: {result:?}"
        );
    }

    #[test]
    fn test_reject_nested_array_too_large() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": { "type": "integer" }
                }
            }
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Nested array over limit
        let over_limit_array: Vec<Value> = (0..=MAX_ARRAY_MEMBERS).map(|i| json!(i)).collect();
        let invalid = json!({
            "items": over_limit_array
        });

        let result = validator.validate(&invalid);
        match result {
            Err(ValidationError::ArrayTooLarge { path, count, limit }) => {
                assert!(path.contains("items"), "Path should contain 'items'");
                assert_eq!(count, MAX_ARRAY_MEMBERS + 1);
                assert_eq!(limit, MAX_ARRAY_MEMBERS);
            },
            other => panic!("Expected ArrayTooLarge, got: {other:?}"),
        }
    }

    // =========================================================================
    // Object Size Limit Tests
    // =========================================================================

    #[test]
    fn test_reject_object_too_large() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object"
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Object at limit should pass
        let mut at_limit = serde_json::Map::new();
        for i in 0..MAX_OBJECT_PROPERTIES {
            at_limit.insert(format!("key_{i}"), json!(i));
        }
        let at_limit_json = Value::Object(at_limit);
        assert!(
            validator.validate(&at_limit_json).is_ok(),
            "Object at limit should pass"
        );

        // Object over limit should fail
        let mut over_limit = serde_json::Map::new();
        for i in 0..=MAX_OBJECT_PROPERTIES {
            over_limit.insert(format!("key_{i}"), json!(i));
        }
        let over_limit_json = Value::Object(over_limit);
        let result = validator.validate(&over_limit_json);
        assert!(
            matches!(
                result,
                Err(ValidationError::ObjectTooLarge {
                    count,
                    limit,
                    ..
                }) if count == MAX_OBJECT_PROPERTIES + 1 && limit == MAX_OBJECT_PROPERTIES
            ),
            "Object over limit should fail with ObjectTooLarge, got: {result:?}"
        );
    }

    // =========================================================================
    // Depth Limit Tests
    // =========================================================================

    #[test]
    fn test_reject_excessive_depth() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema"
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Build deeply nested structure (> MAX_DEPTH levels)
        let mut nested = json!(0);
        for _ in 0..(MAX_DEPTH + 2) {
            nested = json!({"nested": nested});
        }

        let result = validator.validate(&nested);
        assert!(
            matches!(
                result,
                Err(ValidationError::MaxDepthExceeded { max_depth, .. }) if max_depth == MAX_DEPTH
            ),
            "Excessive depth should fail with MaxDepthExceeded, got: {result:?}"
        );
    }

    #[test]
    fn test_accept_depth_at_limit() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema"
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Build structure at exactly MAX_DEPTH levels
        let mut nested = json!(0);
        for _ in 0..MAX_DEPTH {
            nested = json!({"nested": nested});
        }

        let result = validator.validate(&nested);
        assert!(result.is_ok(), "Structure at MAX_DEPTH should pass");
    }

    #[test]
    fn test_reject_excessive_array_depth() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema"
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Build deeply nested array structure
        let mut nested = json!(0);
        for _ in 0..(MAX_DEPTH + 2) {
            nested = json!([nested]);
        }

        let result = validator.validate(&nested);
        assert!(
            matches!(result, Err(ValidationError::MaxDepthExceeded { .. })),
            "Excessive array depth should fail, got: {result:?}"
        );
    }

    // =========================================================================
    // Schema Validation Error Tests
    // =========================================================================

    #[test]
    fn test_type_mismatch_error() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "count": { "type": "integer" }
            }
        });

        let validator = CacValidator::new(&schema).unwrap();
        let invalid = json!({"count": "not-a-number"});
        let result = validator.validate(&invalid);

        assert!(
            matches!(result, Err(ValidationError::SchemaValidation { .. })),
            "Type mismatch should return SchemaValidation error, got: {result:?}"
        );
    }

    #[test]
    fn test_required_field_error() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "id": { "type": "string" }
            },
            "required": ["id"]
        });

        let validator = CacValidator::new(&schema).unwrap();
        let invalid = json!({});
        let result = validator.validate(&invalid);

        assert!(
            matches!(result, Err(ValidationError::SchemaValidation { .. })),
            "Missing required field should return SchemaValidation error, got: {result:?}"
        );
    }

    // =========================================================================
    // Integration Tests
    // =========================================================================

    #[test]
    fn test_validate_cac_artifact_function() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "version": { "type": "string" }
            },
            "required": ["id", "version"],
            "unevaluatedProperties": false
        });

        // Valid artifact
        let valid = json!({
            "id": "CAC-001",
            "version": "1.0.0"
        });
        assert!(validate_cac_artifact(&schema, &valid).is_ok());

        // Invalid: missing required field
        let missing = json!({"id": "CAC-001"});
        assert!(validate_cac_artifact(&schema, &missing).is_err());

        // Invalid: unknown field
        let extra = json!({
            "id": "CAC-001",
            "version": "1.0.0",
            "unknown": "field"
        });
        assert!(matches!(
            validate_cac_artifact(&schema, &extra),
            Err(ValidationError::UnknownField { .. })
        ));
    }

    #[test]
    fn test_complex_schema_validation() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "ticket_meta": {
                    "type": "object",
                    "properties": {
                        "ticket": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string", "pattern": "^TCK-\\d{5}$" },
                                "title": { "type": "string" }
                            },
                            "required": ["id", "title"],
                            "unevaluatedProperties": false
                        }
                    },
                    "required": ["ticket"],
                    "unevaluatedProperties": false
                }
            },
            "required": ["ticket_meta"],
            "unevaluatedProperties": false
        });

        let validator = CacValidator::new(&schema).unwrap();

        // Valid ticket
        let valid = json!({
            "ticket_meta": {
                "ticket": {
                    "id": "TCK-00128",
                    "title": "Implement CAC JSON Schema validator"
                }
            }
        });
        assert!(validator.validate(&valid).is_ok());

        // Invalid: id doesn't match pattern
        let invalid_id = json!({
            "ticket_meta": {
                "ticket": {
                    "id": "INVALID",
                    "title": "Test"
                }
            }
        });
        assert!(matches!(
            validator.validate(&invalid_id),
            Err(ValidationError::SchemaValidation { .. })
        ));

        // Invalid: unknown field in ticket
        let unknown_field = json!({
            "ticket_meta": {
                "ticket": {
                    "id": "TCK-00128",
                    "title": "Test",
                    "assignee": "unknown"
                }
            }
        });
        assert!(matches!(
            validator.validate(&unknown_field),
            Err(ValidationError::UnknownField { .. })
        ));
    }

    // =========================================================================
    // Error Message Tests
    // =========================================================================

    #[test]
    fn test_error_display_unknown_field() {
        let err = ValidationError::UnknownField {
            field: "extra".to_string(),
            path: "$.data".to_string(),
        };
        assert_eq!(err.to_string(), "unknown field 'extra' at path '$.data'");
    }

    #[test]
    fn test_error_display_array_too_large() {
        let err = ValidationError::ArrayTooLarge {
            path: "$.items".to_string(),
            count: 100_001,
            limit: 100_000,
        };
        assert_eq!(
            err.to_string(),
            "array at path '$.items' has 100001 members, exceeds limit of 100000"
        );
    }

    #[test]
    fn test_error_display_object_too_large() {
        let err = ValidationError::ObjectTooLarge {
            path: "$.data".to_string(),
            count: 100_001,
            limit: 100_000,
        };
        assert_eq!(
            err.to_string(),
            "object at path '$.data' has 100001 properties, exceeds limit of 100000"
        );
    }

    #[test]
    fn test_error_display_max_depth_exceeded() {
        let err = ValidationError::MaxDepthExceeded {
            path: "$.a.b.c".to_string(),
            max_depth: 128,
        };
        assert_eq!(
            err.to_string(),
            "maximum depth of 128 exceeded at path '$.a.b.c'"
        );
    }

    // =========================================================================
    // Constants Tests
    // =========================================================================

    #[test]
    fn test_constants() {
        assert_eq!(MAX_ARRAY_MEMBERS, 100_000);
        assert_eq!(MAX_OBJECT_PROPERTIES, 100_000);
        assert_eq!(MAX_DEPTH, 128);
    }
}
