//! Skill frontmatter parsing and holon configuration.
//!
//! This module provides types for parsing skill YAML frontmatter and
//! extracting holon configuration. Skills are markdown files with YAML
//! frontmatter that define agent capabilities and behaviors.
//!
//! # Frontmatter Format
//!
//! Skill frontmatter is YAML content between `---` delimiters at the start
//! of a markdown file:
//!
//! ```yaml
//! ---
//! name: my-skill
//! description: A skill that does something useful
//! user-invocable: true
//! holon:
//!   contract:
//!     input_type: TaskRequest
//!     output_type: TaskResult
//!   stop_conditions:
//!     max_episodes: 10
//!     timeout_ms: 300000
//!     budget:
//!       tokens: 100000
//!   tools:
//!     - read_file
//!     - write_file
//! ---
//!
//! # Skill Content
//! ...
//! ```
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::skill::{HolonConfig, SkillFrontmatter};
//!
//! let yaml = r#"
//! name: example-skill
//! description: An example skill
//! holon:
//!   contract:
//!     input_type: String
//!     output_type: String
//!   stop_conditions:
//!     max_episodes: 5
//! "#;
//!
//! let frontmatter: SkillFrontmatter = serde_yaml::from_str(yaml).unwrap();
//! assert_eq!(frontmatter.name, "example-skill");
//! assert!(frontmatter.holon.is_some());
//!
//! let holon_config = frontmatter.holon.unwrap();
//! assert_eq!(holon_config.stop_conditions.max_episodes, Some(5));
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during skill parsing.
#[derive(Debug, Error)]
pub enum SkillParseError {
    /// The file could not be read.
    #[error("failed to read skill file: {0}")]
    IoError(#[from] std::io::Error),

    /// The frontmatter delimiters are missing or malformed.
    #[error("invalid frontmatter: {0}")]
    InvalidFrontmatter(String),

    /// The YAML content is invalid.
    #[error("invalid YAML: {0}")]
    YamlError(#[from] serde_yaml::Error),

    /// The holon configuration is invalid.
    #[error("invalid holon config: {0}")]
    InvalidHolonConfig(String),
}

/// Skill frontmatter parsed from a SKILL.md file.
///
/// This represents the YAML content between `---` delimiters at the
/// start of a skill markdown file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillFrontmatter {
    /// The skill's unique name.
    pub name: String,

    /// A brief description of what the skill does.
    pub description: String,

    /// Whether users can directly invoke this skill.
    ///
    /// Defaults to `true` if not specified.
    #[serde(rename = "user-invocable", default = "default_user_invocable")]
    pub user_invocable: bool,

    /// Holon configuration for this skill.
    ///
    /// If present, the skill can be executed as a holon with bounded
    /// episodes, stop conditions, and tool restrictions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holon: Option<HolonConfig>,
}

const fn default_user_invocable() -> bool {
    true
}

/// Configuration for a skill operating as a holon.
///
/// This defines the contract surface, execution boundaries, and
/// tool permissions for a holon-based skill.
///
/// # Security
///
/// This struct uses `deny_unknown_fields` to prevent fail-open behavior
/// from typos (e.g., `time_out_ms` vs `timeout_ms` would silently use
/// default values if unknown fields were allowed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolonConfig {
    /// The contract defining input/output types.
    pub contract: HolonContract,

    /// Conditions under which the holon should stop.
    ///
    /// At least one stop condition must be configured to prevent
    /// unbounded execution.
    pub stop_conditions: StopConditionsConfig,

    /// Tools this holon is allowed to use.
    ///
    /// # Security
    ///
    /// This field uses fail-close semantics:
    /// - `None` (omitted): No tools are permitted (maximum restriction)
    /// - `Some([])` (empty list): No tools are permitted
    /// - `Some([...])`: Only the listed tools are permitted
    ///
    /// This prevents fail-open behavior where omitting the field would
    /// accidentally grant access to all tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
}

impl HolonConfig {
    /// Validates the holon configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn validate(&self) -> Result<(), SkillParseError> {
        // Validate contract
        self.contract.validate()?;

        // Validate stop conditions - at least one must be configured
        // to prevent unbounded execution
        self.stop_conditions.validate()?;
        if !self.stop_conditions.is_configured() {
            return Err(SkillParseError::InvalidHolonConfig(
                "at least one stop condition must be configured to prevent unbounded execution"
                    .to_string(),
            ));
        }

        // Validate tools (no duplicates, no empty names)
        if let Some(ref tools) = self.tools {
            let mut seen = std::collections::HashSet::new();
            for tool in tools {
                if tool.is_empty() {
                    return Err(SkillParseError::InvalidHolonConfig(
                        "tool name cannot be empty".to_string(),
                    ));
                }
                if !seen.insert(tool) {
                    return Err(SkillParseError::InvalidHolonConfig(format!(
                        "duplicate tool: {tool}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Returns the list of allowed tools.
    ///
    /// If `None`, no tools are permitted (fail-close default).
    /// If `Some`, only the listed tools are allowed (may be empty).
    #[must_use]
    pub fn allowed_tools(&self) -> Option<&[String]> {
        self.tools.as_deref()
    }
}

/// The contract surface for a holon.
///
/// Defines the types that the holon accepts and produces.
///
/// # Security
///
/// Uses `deny_unknown_fields` to catch typos in field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolonContract {
    /// The type of input this holon accepts.
    ///
    /// This is a type identifier string (e.g., `TaskRequest`, `String`).
    pub input_type: String,

    /// The type of output this holon produces.
    ///
    /// This is a type identifier string (e.g., `TaskResult`, `String`).
    pub output_type: String,

    /// Optional type for the holon's internal state.
    ///
    /// If not specified, the holon is considered stateless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_type: Option<String>,
}

impl HolonContract {
    /// Validates the contract configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the contract is invalid.
    pub fn validate(&self) -> Result<(), SkillParseError> {
        if self.input_type.is_empty() {
            return Err(SkillParseError::InvalidHolonConfig(
                "input_type cannot be empty".to_string(),
            ));
        }
        if self.output_type.is_empty() {
            return Err(SkillParseError::InvalidHolonConfig(
                "output_type cannot be empty".to_string(),
            ));
        }
        if let Some(ref state) = self.state_type {
            if state.is_empty() {
                return Err(SkillParseError::InvalidHolonConfig(
                    "state_type cannot be empty when specified".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Configuration for holon stop conditions.
///
/// These define when the holon should terminate its episode loop.
///
/// # Security
///
/// Uses `deny_unknown_fields` to prevent fail-open behavior from typos.
/// For example, `time_out_ms` instead of `timeout_ms` would result in
/// no timeout if unknown fields were silently ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopConditionsConfig {
    /// Maximum number of episodes before forced termination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_episodes: Option<u64>,

    /// Timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    /// Budget limits for various resources.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub budget: HashMap<String, u64>,

    /// Maximum number of stall episodes before escalation.
    ///
    /// A "stall" is when no observable progress is made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stall_episodes: Option<u64>,
}

impl StopConditionsConfig {
    /// Validates the stop conditions configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn validate(&self) -> Result<(), SkillParseError> {
        if let Some(max_episodes) = self.max_episodes {
            if max_episodes == 0 {
                return Err(SkillParseError::InvalidHolonConfig(
                    "max_episodes must be greater than 0".to_string(),
                ));
            }
        }
        if let Some(timeout_ms) = self.timeout_ms {
            if timeout_ms == 0 {
                return Err(SkillParseError::InvalidHolonConfig(
                    "timeout_ms must be greater than 0".to_string(),
                ));
            }
        }
        for (resource, &amount) in &self.budget {
            if resource.is_empty() {
                return Err(SkillParseError::InvalidHolonConfig(
                    "budget resource name cannot be empty".to_string(),
                ));
            }
            if amount == 0 {
                return Err(SkillParseError::InvalidHolonConfig(format!(
                    "budget for '{resource}' must be greater than 0"
                )));
            }
        }
        if let Some(max_stall) = self.max_stall_episodes {
            if max_stall == 0 {
                return Err(SkillParseError::InvalidHolonConfig(
                    "max_stall_episodes must be greater than 0".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Returns `true` if any stop conditions are configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.max_episodes.is_some()
            || self.timeout_ms.is_some()
            || !self.budget.is_empty()
            || self.max_stall_episodes.is_some()
    }
}

/// Parses skill frontmatter from a markdown file.
///
/// The frontmatter must be YAML content between `---` delimiters
/// at the very start of the file.
///
/// # Arguments
///
/// * `content` - The full content of the markdown file
///
/// # Returns
///
/// The parsed frontmatter and the remaining markdown content.
///
/// # Errors
///
/// Returns an error if the frontmatter is missing, malformed, or
/// contains invalid YAML.
///
/// # Example
///
/// ```rust
/// use apm2_holon::skill::parse_frontmatter;
///
/// let content = "---\nname: my-skill\ndescription: A useful skill\n---\n\n# Skill Documentation\n";
///
/// let (frontmatter, body) = parse_frontmatter(content).unwrap();
/// assert_eq!(frontmatter.name, "my-skill");
/// assert!(body.contains("# Skill Documentation"));
/// ```
pub fn parse_frontmatter(content: &str) -> Result<(SkillFrontmatter, &str), SkillParseError> {
    // Must start with ---
    let content = content.trim_start();
    if !content.starts_with("---") {
        return Err(SkillParseError::InvalidFrontmatter(
            "file must start with '---'".to_string(),
        ));
    }

    // Find the closing ---
    let after_first = &content[3..];
    let closing_pos = after_first.find("\n---").ok_or_else(|| {
        SkillParseError::InvalidFrontmatter("missing closing '---' delimiter".to_string())
    })?;

    // Extract YAML content (skip the leading newline if present)
    let yaml_content = after_first[..closing_pos].trim();

    // Parse YAML
    let frontmatter: SkillFrontmatter = serde_yaml::from_str(yaml_content)?;

    // Validate holon config if present
    if let Some(ref holon) = frontmatter.holon {
        holon.validate()?;
    }

    // Return frontmatter and remaining content
    let body_start = 3 + closing_pos + 4; // "---" + yaml + "\n---"
    let body = if body_start < content.len() {
        &content[body_start..]
    } else {
        ""
    };

    Ok((frontmatter, body))
}

/// Parses skill frontmatter from a file path.
///
/// This is a convenience function that reads the file and parses
/// its frontmatter.
///
/// # Arguments
///
/// * `path` - Path to the SKILL.md file
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn parse_skill_file(path: &Path) -> Result<(SkillFrontmatter, String), SkillParseError> {
    let content = std::fs::read_to_string(path)?;
    let (frontmatter, body) = parse_frontmatter(&content)?;
    Ok((frontmatter, body.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_frontmatter() {
        let content = "---\nname: test-skill\ndescription: A test skill\n---\n\n# Test Skill\n\nThis is the body.\n";

        let (fm, body) = parse_frontmatter(content).unwrap();
        assert_eq!(fm.name, "test-skill");
        assert_eq!(fm.description, "A test skill");
        assert!(fm.user_invocable); // default
        assert!(fm.holon.is_none());
        assert!(body.contains("# Test Skill"));
    }

    #[test]
    fn test_parse_frontmatter_with_user_invocable() {
        let content = "---\nname: internal-skill\ndescription: An internal skill\nuser-invocable: false\n---\n";

        let (fm, _) = parse_frontmatter(content).unwrap();
        assert!(!fm.user_invocable);
    }

    #[test]
    fn test_parse_frontmatter_with_holon_config() {
        let content = "---\nname: holon-skill\ndescription: A skill with holon config\nholon:\n  contract:\n    input_type: TaskRequest\n    output_type: TaskResult\n  stop_conditions:\n    max_episodes: 10\n    timeout_ms: 300000\n    budget:\n      tokens: 100000\n  tools:\n    - read_file\n    - write_file\n---\n";

        let (fm, _) = parse_frontmatter(content).unwrap();
        assert!(fm.holon.is_some());

        let holon = fm.holon.unwrap();
        assert_eq!(holon.contract.input_type, "TaskRequest");
        assert_eq!(holon.contract.output_type, "TaskResult");
        assert_eq!(holon.stop_conditions.max_episodes, Some(10));
        assert_eq!(holon.stop_conditions.timeout_ms, Some(300_000));
        assert_eq!(holon.stop_conditions.budget.get("tokens"), Some(&100_000));
        assert_eq!(
            holon.tools,
            Some(vec!["read_file".to_string(), "write_file".to_string()])
        );
        assert_eq!(
            holon.allowed_tools(),
            Some(&["read_file".to_string(), "write_file".to_string()][..])
        );
    }

    #[test]
    fn test_holon_config_requires_stop_conditions() {
        // Config with no stop conditions should fail validation
        let content = "---\nname: minimal-holon\ndescription: Minimal holon config\nholon:\n  contract:\n    input_type: String\n    output_type: String\n---\n";

        let result = parse_frontmatter(content);
        assert!(
            result.is_err(),
            "config without stop conditions should be rejected"
        );
    }

    #[test]
    fn test_omitted_tools_means_no_access() {
        // Omitting tools field means no tools are permitted (fail-close)
        let content = "---\nname: restricted-skill\ndescription: Skill with no tools\nholon:\n  contract:\n    input_type: String\n    output_type: String\n  stop_conditions:\n    max_episodes: 10\n---\n";

        let (fm, _) = parse_frontmatter(content).unwrap();
        let holon = fm.holon.unwrap();
        assert!(holon.tools.is_none(), "omitted tools should be None");
        assert!(
            holon.allowed_tools().is_none(),
            "no tools should be permitted"
        );
    }

    #[test]
    fn test_parse_frontmatter_missing_delimiter() {
        let content = "name: test\ndescription: test";
        let result = parse_frontmatter(content);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SkillParseError::InvalidFrontmatter(_)
        ));
    }

    #[test]
    fn test_parse_frontmatter_missing_closing_delimiter() {
        let content = "---\nname: test\ndescription: test";
        let result = parse_frontmatter(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_config_validation_empty_input_type() {
        let content = "---\nname: bad-skill\ndescription: Bad skill\nholon:\n  contract:\n    input_type: \"\"\n    output_type: Result\n  stop_conditions:\n    max_episodes: 10\n---\n";

        let result = parse_frontmatter(content);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SkillParseError::InvalidHolonConfig(_)));
    }

    #[test]
    fn test_holon_config_validation_zero_max_episodes() {
        let content = "---\nname: bad-skill\ndescription: Bad skill\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n  stop_conditions:\n    max_episodes: 0\n---\n";

        let result = parse_frontmatter(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_config_validation_zero_budget() {
        let content = "---\nname: bad-skill\ndescription: Bad skill\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n  stop_conditions:\n    budget:\n      tokens: 0\n---\n";

        let result = parse_frontmatter(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_config_validation_duplicate_tool() {
        let content = "---\nname: bad-skill\ndescription: Bad skill\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n  stop_conditions:\n    max_episodes: 10\n  tools:\n    - read_file\n    - read_file\n---\n";

        let result = parse_frontmatter(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_holon_config_validation_empty_tool() {
        let content = "---\nname: bad-skill\ndescription: Bad skill\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n  stop_conditions:\n    max_episodes: 10\n  tools:\n    - read_file\n    - \"\"\n---\n";

        let result = parse_frontmatter(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_stop_conditions_is_configured() {
        let empty = StopConditionsConfig::default();
        assert!(!empty.is_configured());

        let with_max = StopConditionsConfig {
            max_episodes: Some(10),
            ..Default::default()
        };
        assert!(with_max.is_configured());

        let mut budget = HashMap::new();
        budget.insert("tokens".to_string(), 1000);
        let with_budget = StopConditionsConfig {
            budget,
            ..Default::default()
        };
        assert!(with_budget.is_configured());
    }

    #[test]
    fn test_frontmatter_serialization_roundtrip() {
        let fm = SkillFrontmatter {
            name: "test-skill".to_string(),
            description: "A test".to_string(),
            user_invocable: true,
            holon: Some(HolonConfig {
                contract: HolonContract {
                    input_type: "String".to_string(),
                    output_type: "String".to_string(),
                    state_type: None,
                },
                stop_conditions: StopConditionsConfig {
                    max_episodes: Some(5),
                    timeout_ms: Some(60000),
                    budget: HashMap::new(),
                    max_stall_episodes: None,
                },
                tools: Some(vec!["read".to_string(), "write".to_string()]),
            }),
        };

        let yaml = serde_yaml::to_string(&fm).unwrap();
        let parsed: SkillFrontmatter = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(fm, parsed);
    }

    #[test]
    fn test_existing_skills_without_holon_work() {
        // Simulating an existing skill format without holon field
        let content = "---\nname: legacy-skill\ndescription: An old skill without holon config\nuser-invocable: true\n---\n\n# Legacy Skill\n\nThis skill predates holon support.\n";

        let (fm, body) = parse_frontmatter(content).unwrap();
        assert_eq!(fm.name, "legacy-skill");
        assert!(fm.holon.is_none());
        assert!(body.contains("# Legacy Skill"));
    }

    #[test]
    fn test_contract_with_state_type() {
        let content = "---\nname: stateful-skill\ndescription: A stateful skill\nholon:\n  contract:\n    input_type: Request\n    output_type: Response\n    state_type: SessionState\n  stop_conditions:\n    max_episodes: 10\n---\n";

        let (fm, _) = parse_frontmatter(content).unwrap();
        let holon = fm.holon.unwrap();
        assert_eq!(holon.contract.state_type, Some("SessionState".to_string()));
    }

    #[test]
    fn test_contract_validation_empty_state_type() {
        let content = "---\nname: bad-skill\ndescription: Bad skill\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n    state_type: \"\"\n  stop_conditions:\n    max_episodes: 10\n---\n";

        let result = parse_frontmatter(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_stall_episodes() {
        let content = "---\nname: stall-aware\ndescription: Detects stalls\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n  stop_conditions:\n    max_stall_episodes: 3\n---\n";

        let (fm, _) = parse_frontmatter(content).unwrap();
        let holon = fm.holon.unwrap();
        assert_eq!(holon.stop_conditions.max_stall_episodes, Some(3));
    }

    #[test]
    fn test_holon_config_validate_success() {
        let mut budget = HashMap::new();
        budget.insert("tokens".to_string(), 1000);

        let config = HolonConfig {
            contract: HolonContract {
                input_type: "Input".to_string(),
                output_type: "Output".to_string(),
                state_type: None,
            },
            stop_conditions: StopConditionsConfig {
                max_episodes: Some(10),
                timeout_ms: Some(60000),
                budget,
                max_stall_episodes: Some(2),
            },
            tools: Some(vec!["read_file".to_string(), "write_file".to_string()]),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_holon_requires_at_least_one_stop_condition() {
        // Config without any stop condition should fail validation
        let config = HolonConfig {
            contract: HolonContract {
                input_type: "Input".to_string(),
                output_type: "Output".to_string(),
                state_type: None,
            },
            stop_conditions: StopConditionsConfig::default(),
            tools: None,
        };

        let result = config.validate();
        assert!(
            result.is_err(),
            "should require at least one stop condition"
        );
    }

    #[test]
    fn test_unknown_field_in_holon_config_rejected() {
        // Unknown field in HolonConfig should be rejected to prevent fail-open security
        // issues
        let content = "---\nname: typo-skill\ndescription: Has typo\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n  stop_conditions:\n    max_episodes: 10\n  unknown_field: true\n---\n";

        let result = parse_frontmatter(content);
        assert!(result.is_err(), "unknown field should be rejected");
    }

    #[test]
    fn test_unknown_field_in_contract_rejected() {
        // Unknown field in contract should be rejected
        let content = "---\nname: typo-skill\ndescription: Has typo\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n    extra_field: value\n---\n";

        let result = parse_frontmatter(content);
        assert!(
            result.is_err(),
            "unknown field in contract should be rejected"
        );
    }

    #[test]
    fn test_typo_in_stop_conditions_rejected() {
        // Typo: "time_out_ms" instead of "timeout_ms" should be rejected
        let content = "---\nname: typo-skill\ndescription: Has typo\nholon:\n  contract:\n    input_type: Input\n    output_type: Output\n  stop_conditions:\n    time_out_ms: 60000\n---\n";

        let result = parse_frontmatter(content);
        assert!(
            result.is_err(),
            "typo in stop_conditions should be rejected"
        );
    }
}
