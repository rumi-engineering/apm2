// AGENT-AUTHORED
//! Key policy types for the Forge Admission Cycle.
//!
//! This module defines [`KeyPolicy`] which represents the custody domain and
//! conflict of interest (COI) rules for key management. `KeyPolicy` enforces
//! separation of concerns by ensuring executors cannot be in the same COI group
//! as changeset authors, preventing self-review attacks.
//!
//! # Security Model
//!
//! `KeyPolicy` enforces conflict of interest separation:
//!
//! - **Custody Domains**: Keys are grouped into custody domains with associated
//!   COI groups
//! - **COI Rules**: Define enforcement levels for conflict of interest
//!   violations
//! - **Validation**: `validate_coi()` checks if an executor can review a
//!   changeset
//!
//! # Self-Review Prevention
//!
//! The primary security goal is preventing self-review attacks where an author
//! could approve their own changeset. This is achieved by:
//!
//! 1. Assigning keys to custody domains with COI group IDs
//! 2. Checking that executor's COI group differs from author's COI group
//! 3. Rejecting lease issuance when COI violation is detected
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::{
//!     CoiEnforcementLevel, CoiRule, CustodyDomain, KeyBinding, KeyPolicy,
//!     KeyPolicyBuilder,
//! };
//!
//! // Create a key policy with two custody domains
//! let policy = KeyPolicyBuilder::new("policy-001")
//!     .schema_version(1)
//!     .add_custody_domain(CustodyDomain {
//!         domain_id: "dev-team-a".to_string(),
//!         coi_group_id: "coi-group-alpha".to_string(),
//!         key_bindings: vec![KeyBinding {
//!             key_id: "key-alice".to_string(),
//!             actor_id: "alice".to_string(),
//!         }],
//!     })
//!     .add_custody_domain(CustodyDomain {
//!         domain_id: "dev-team-b".to_string(),
//!         coi_group_id: "coi-group-beta".to_string(),
//!         key_bindings: vec![KeyBinding {
//!             key_id: "key-bob".to_string(),
//!             actor_id: "bob".to_string(),
//!         }],
//!     })
//!     .add_coi_rule(CoiRule {
//!         rule_id: "no-self-review".to_string(),
//!         description: "Prevent self-review attacks".to_string(),
//!         enforcement_level: CoiEnforcementLevel::Reject,
//!     })
//!     .build();
//!
//! // Validate COI: bob can review alice's changeset (different COI groups)
//! assert!(policy.validate_coi("key-bob", "alice").is_ok());
//!
//! // Validate COI: alice cannot review her own changeset (same COI group)
//! assert!(policy.validate_coi("key-alice", "alice").is_err());
//! ```

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::policy_resolution::MAX_STRING_LENGTH;

// =============================================================================
// Resource Limits (DoS Protection)
// =============================================================================

/// Maximum number of custody domains allowed in a key policy.
/// This prevents denial-of-service attacks via oversized repeated fields.
pub const MAX_CUSTODY_DOMAINS: usize = 256;

/// Maximum number of COI rules allowed in a key policy.
pub const MAX_COI_RULES: usize = 256;

/// Maximum number of delegation rules allowed in a key policy.
pub const MAX_DELEGATION_RULES: usize = 256;

/// Maximum number of key bindings per custody domain.
pub const MAX_KEY_BINDINGS: usize = 1024;

/// Supported schema versions for key policy.
pub const SUPPORTED_SCHEMA_VERSIONS: &[u32] = &[1];

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during key policy operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyPolicyError {
    /// Conflict of interest violation detected.
    #[error(
        "COI violation: executor key '{executor_key_id}' is in same COI group '{coi_group_id}' as author '{author_actor_id}'"
    )]
    CoiViolation {
        /// The executor's key ID.
        executor_key_id: String,
        /// The author's actor ID.
        author_actor_id: String,
        /// The conflicting COI group ID.
        coi_group_id: String,
    },

    /// Policy hash mismatch during lease issuance.
    #[error("policy hash mismatch: expected={expected}, actual={actual}")]
    PolicyHashMismatch {
        /// Expected policy hash.
        expected: String,
        /// Actual policy hash.
        actual: String,
    },

    /// Key not found in any custody domain.
    #[error("key '{key_id}' not found in any custody domain")]
    KeyNotFound {
        /// The key ID that was not found.
        key_id: String,
    },

    /// Actor not found in any custody domain.
    #[error("actor '{actor_id}' not found in any custody domain")]
    ActorNotFound {
        /// The actor ID that was not found.
        actor_id: String,
    },

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

    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid key policy data.
    #[error("invalid key policy data: {0}")]
    InvalidData(String),

    /// Unsupported schema version.
    #[error("unsupported schema version: {version}, supported: {supported:?}")]
    UnsupportedSchemaVersion {
        /// The unsupported version.
        version: u32,
        /// List of supported versions.
        supported: Vec<u32>,
    },

    /// Duplicate key ID found.
    #[error("duplicate key_id: {key_id}")]
    DuplicateKeyId {
        /// The duplicate key ID.
        key_id: String,
    },

    /// Duplicate domain ID found.
    #[error("duplicate domain_id: {domain_id}")]
    DuplicateDomainId {
        /// The duplicate domain ID.
        domain_id: String,
    },

    /// Duplicate rule ID found.
    #[error("duplicate rule_id: {rule_id}")]
    DuplicateRuleId {
        /// The duplicate rule ID.
        rule_id: String,
    },

    /// Policy hash self-consistency check failed.
    #[error("policy hash self-consistency check failed: computed={computed}, stored={stored}")]
    SelfConsistencyCheckFailed {
        /// The computed policy hash.
        computed: String,
        /// The stored policy hash.
        stored: String,
    },
}

// =============================================================================
// CoiEnforcementLevel
// =============================================================================

/// Enforcement level for COI rule violations.
///
/// Determines what action to take when a conflict of interest is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CoiEnforcementLevel {
    /// Log the violation but allow the action to proceed.
    Warn           = 0,
    /// Reject the action with an error.
    Reject         = 1,
    /// Reject and audit log the violation for security review.
    RejectAndAudit = 2,
}

impl TryFrom<u8> for CoiEnforcementLevel {
    type Error = KeyPolicyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Warn),
            1 => Ok(Self::Reject),
            2 => Ok(Self::RejectAndAudit),
            _ => Err(KeyPolicyError::InvalidData(format!(
                "invalid COI enforcement level {value}, must be 0-2"
            ))),
        }
    }
}

impl From<CoiEnforcementLevel> for u8 {
    fn from(level: CoiEnforcementLevel) -> Self {
        level as Self
    }
}

// =============================================================================
// KeyBinding
// =============================================================================

/// Binding between a cryptographic key and an actor identity.
///
/// Each key binding associates a key ID (typically a public key fingerprint)
/// with an actor ID (human or service identity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBinding {
    /// Unique identifier for the key (e.g., public key fingerprint).
    pub key_id: String,

    /// Actor identity associated with this key.
    pub actor_id: String,
}

// =============================================================================
// CustodyDomain
// =============================================================================

/// A custody domain groups keys with a shared COI group.
///
/// Keys within the same custody domain share a COI group identifier. When
/// validating COI, if the executor's key and the author's actor belong to
/// the same COI group, a conflict of interest is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyDomain {
    /// Unique identifier for this custody domain.
    pub domain_id: String,

    /// COI group identifier for conflict detection.
    ///
    /// Keys in domains with the same `coi_group_id` are considered to have
    /// a conflict of interest with each other.
    pub coi_group_id: String,

    /// Keys bound to this custody domain.
    pub key_bindings: Vec<KeyBinding>,
}

// =============================================================================
// CoiRule
// =============================================================================

/// A conflict of interest rule with enforcement configuration.
///
/// COI rules define how conflict of interest violations should be handled.
/// Multiple rules can be defined with different enforcement levels for
/// different scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoiRule {
    /// Unique identifier for this rule.
    pub rule_id: String,

    /// Human-readable description of the rule.
    pub description: String,

    /// What action to take when this rule is violated.
    pub enforcement_level: CoiEnforcementLevel,
}

// =============================================================================
// DelegationRule
// =============================================================================

/// A delegation rule for key authority transfer.
///
/// Delegation rules define how authority can be transferred between actors
/// or keys. This enables scenarios like vacation coverage or escalation paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRule {
    /// Unique identifier for this delegation rule.
    pub rule_id: String,

    /// Actor ID that is delegating authority.
    pub from_actor_id: String,

    /// Actor ID receiving delegated authority.
    pub to_actor_id: String,

    /// Optional scope restriction for the delegation.
    pub scope: Option<String>,

    /// Whether this delegation is currently active.
    pub active: bool,
}

// =============================================================================
// KeyPolicy
// =============================================================================

/// A key policy defining custody domains and COI rules.
///
/// The key policy is the central configuration for conflict of interest
/// enforcement. It defines which keys belong to which custody domains,
/// and what rules govern COI detection and enforcement.
///
/// # Fields
///
/// - `policy_id`: Unique identifier for this policy
/// - `policy_hash`: Hash of the policy content for integrity verification
/// - `schema_version`: Version of the policy schema
/// - `custody_domains`: List of custody domains with key bindings
/// - `coi_rules`: List of COI rules with enforcement levels
/// - `delegation_rules`: List of delegation rules for authority transfer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyPolicy {
    /// Unique identifier for this policy.
    pub policy_id: String,

    /// Hash of the policy content for integrity verification.
    #[serde(with = "serde_bytes")]
    policy_hash: [u8; 32],

    /// Schema version for forward compatibility.
    pub schema_version: u32,

    /// Custody domains defining key-to-COI-group mappings.
    pub custody_domains: Vec<CustodyDomain>,

    /// Rules for COI violation handling.
    pub coi_rules: Vec<CoiRule>,

    /// Rules for authority delegation.
    pub delegation_rules: Vec<DelegationRule>,
}

impl KeyPolicy {
    /// Returns the policy hash.
    #[must_use]
    pub const fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }

    /// Computes the policy hash from the policy fields.
    ///
    /// The hash is computed over the canonical representation of all policy
    /// fields except the hash itself.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn compute_policy_hash(
        policy_id: &str,
        schema_version: u32,
        custody_domains: &[CustodyDomain],
        coi_rules: &[CoiRule],
        delegation_rules: &[DelegationRule],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Policy ID (length-prefixed)
        hasher.update(&(policy_id.len() as u32).to_be_bytes());
        hasher.update(policy_id.as_bytes());

        // Schema version
        hasher.update(&schema_version.to_be_bytes());

        // Custody domains
        hasher.update(&(custody_domains.len() as u32).to_be_bytes());
        for domain in custody_domains {
            hasher.update(&(domain.domain_id.len() as u32).to_be_bytes());
            hasher.update(domain.domain_id.as_bytes());
            hasher.update(&(domain.coi_group_id.len() as u32).to_be_bytes());
            hasher.update(domain.coi_group_id.as_bytes());
            hasher.update(&(domain.key_bindings.len() as u32).to_be_bytes());
            for binding in &domain.key_bindings {
                hasher.update(&(binding.key_id.len() as u32).to_be_bytes());
                hasher.update(binding.key_id.as_bytes());
                hasher.update(&(binding.actor_id.len() as u32).to_be_bytes());
                hasher.update(binding.actor_id.as_bytes());
            }
        }
        hasher.update(&[0xFF]); // section separator

        // COI rules
        hasher.update(&(coi_rules.len() as u32).to_be_bytes());
        for rule in coi_rules {
            hasher.update(&(rule.rule_id.len() as u32).to_be_bytes());
            hasher.update(rule.rule_id.as_bytes());
            hasher.update(&(rule.description.len() as u32).to_be_bytes());
            hasher.update(rule.description.as_bytes());
            hasher.update(&[rule.enforcement_level as u8]);
        }
        hasher.update(&[0xFF]); // section separator

        // Delegation rules
        hasher.update(&(delegation_rules.len() as u32).to_be_bytes());
        for rule in delegation_rules {
            hasher.update(&(rule.rule_id.len() as u32).to_be_bytes());
            hasher.update(rule.rule_id.as_bytes());
            hasher.update(&(rule.from_actor_id.len() as u32).to_be_bytes());
            hasher.update(rule.from_actor_id.as_bytes());
            hasher.update(&(rule.to_actor_id.len() as u32).to_be_bytes());
            hasher.update(rule.to_actor_id.as_bytes());
            if let Some(ref scope) = rule.scope {
                hasher.update(&[1u8]); // presence flag
                hasher.update(&(scope.len() as u32).to_be_bytes());
                hasher.update(scope.as_bytes());
            } else {
                hasher.update(&[0u8]); // absence flag
            }
            hasher.update(&[u8::from(rule.active)]);
        }

        *hasher.finalize().as_bytes()
    }

    /// Finds the COI group ID for a given key ID.
    ///
    /// # Returns
    ///
    /// `Some(&str)` with the COI group ID if the key is found, `None`
    /// otherwise.
    #[must_use]
    pub fn get_coi_group_for_key(&self, key_id: &str) -> Option<&str> {
        for domain in &self.custody_domains {
            for binding in &domain.key_bindings {
                if binding.key_id == key_id {
                    return Some(&domain.coi_group_id);
                }
            }
        }
        None
    }

    /// Finds all COI group IDs for a given actor ID.
    ///
    /// An actor may belong to multiple custody domains (with different keys),
    /// and thus may be associated with multiple COI groups. This method returns
    /// all COI groups the actor belongs to.
    ///
    /// # Returns
    ///
    /// A `HashSet<String>` containing all COI group IDs the actor belongs to.
    /// Returns an empty set if the actor is not found in any custody domain.
    #[must_use]
    pub fn get_coi_groups_for_actor(&self, actor_id: &str) -> HashSet<String> {
        let mut groups = HashSet::new();
        for domain in &self.custody_domains {
            for binding in &domain.key_bindings {
                if binding.actor_id == actor_id {
                    groups.insert(domain.coi_group_id.clone());
                }
            }
        }
        groups
    }

    /// Validates that there is no conflict of interest between an executor
    /// and an author.
    ///
    /// This is the primary security check for preventing self-review attacks.
    /// The executor (identified by their key ID) must not be in the same COI
    /// group as the author (identified by their actor ID).
    ///
    /// # Security Notes
    ///
    /// - Uses constant-time comparison for COI group IDs to prevent timing
    ///   attacks
    /// - Checks ALL COI groups the author belongs to (not just the first),
    ///   preventing bypass via multiple group bindings
    ///
    /// # Arguments
    ///
    /// * `executor_key_id` - The key ID of the executor attempting to run a
    ///   gate
    /// * `author_actor_id` - The actor ID of the changeset author
    ///
    /// # Returns
    ///
    /// `Ok(())` if no COI violation is detected, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`KeyPolicyError::KeyNotFound`] if the executor key is not in
    /// any custody domain.
    ///
    /// Returns [`KeyPolicyError::ActorNotFound`] if the author actor is not in
    /// any custody domain.
    ///
    /// Returns [`KeyPolicyError::CoiViolation`] if the executor and author are
    /// in the same COI group (or share any COI group).
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::{
    ///     CustodyDomain, KeyBinding, KeyPolicy, KeyPolicyBuilder,
    /// };
    ///
    /// let policy = KeyPolicyBuilder::new("policy-001")
    ///     .schema_version(1)
    ///     .add_custody_domain(CustodyDomain {
    ///         domain_id: "team-a".to_string(),
    ///         coi_group_id: "group-alpha".to_string(),
    ///         key_bindings: vec![KeyBinding {
    ///             key_id: "key-alice".to_string(),
    ///             actor_id: "alice".to_string(),
    ///         }],
    ///     })
    ///     .add_custody_domain(CustodyDomain {
    ///         domain_id: "team-b".to_string(),
    ///         coi_group_id: "group-beta".to_string(),
    ///         key_bindings: vec![KeyBinding {
    ///             key_id: "key-bob".to_string(),
    ///             actor_id: "bob".to_string(),
    ///         }],
    ///     })
    ///     .build();
    ///
    /// // Different COI groups: OK
    /// assert!(policy.validate_coi("key-bob", "alice").is_ok());
    ///
    /// // Same COI group: REJECTED
    /// assert!(policy.validate_coi("key-alice", "alice").is_err());
    /// ```
    pub fn validate_coi(
        &self,
        executor_key_id: &str,
        author_actor_id: &str,
    ) -> Result<(), KeyPolicyError> {
        // Find executor's COI group
        let executor_coi_group = self.get_coi_group_for_key(executor_key_id).ok_or_else(|| {
            KeyPolicyError::KeyNotFound {
                key_id: executor_key_id.to_string(),
            }
        })?;

        // Find ALL of author's COI groups (CRITICAL: not just the first one)
        let author_coi_groups = self.get_coi_groups_for_actor(author_actor_id);

        if author_coi_groups.is_empty() {
            return Err(KeyPolicyError::ActorNotFound {
                actor_id: author_actor_id.to_string(),
            });
        }

        // Check for COI violation using constant-time comparison (RSK-1909)
        // The executor's group must not intersect with ANY of the author's groups
        for author_group in &author_coi_groups {
            // Use constant-time comparison to prevent timing side-channel attacks
            let executor_bytes = executor_coi_group.as_bytes();
            let author_bytes = author_group.as_bytes();

            // Constant-time comparison requires equal-length inputs; pad if necessary
            let is_equal = if executor_bytes.len() == author_bytes.len() {
                bool::from(executor_bytes.ct_eq(author_bytes))
            } else {
                // Different lengths cannot be equal
                false
            };

            if is_equal {
                return Err(KeyPolicyError::CoiViolation {
                    executor_key_id: executor_key_id.to_string(),
                    author_actor_id: author_actor_id.to_string(),
                    coi_group_id: executor_coi_group.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates the policy hash matches the expected value.
    ///
    /// This is used during lease issuance to ensure the policy configuration
    /// hasn't changed since resolution.
    ///
    /// # Arguments
    ///
    /// * `expected_hash` - The expected policy hash
    ///
    /// # Returns
    ///
    /// `Ok(())` if the hash matches, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`KeyPolicyError::PolicyHashMismatch`] if the hashes don't
    /// match.
    pub fn verify_policy_hash(&self, expected_hash: &[u8; 32]) -> Result<(), KeyPolicyError> {
        // Use constant-time comparison for security-sensitive hash comparison
        if !bool::from(self.policy_hash.ct_eq(expected_hash)) {
            return Err(KeyPolicyError::PolicyHashMismatch {
                expected: hex_encode(expected_hash),
                actual: hex_encode(&self.policy_hash),
            });
        }
        Ok(())
    }

    /// Validates the schema version is supported.
    ///
    /// # Arguments
    ///
    /// * `enforce` - If `true`, unsupported versions return an error. If
    ///   `false`, unsupported versions are silently accepted.
    ///
    /// # Returns
    ///
    /// `Ok(())` if validation passes (or permissive mode is enabled).
    ///
    /// # Errors
    ///
    /// Returns [`KeyPolicyError::UnsupportedSchemaVersion`] if `enforce` is
    /// `true` and the schema version is not supported.
    pub fn validate_version(&self, enforce: bool) -> Result<(), KeyPolicyError> {
        if !SUPPORTED_SCHEMA_VERSIONS.contains(&self.schema_version) && enforce {
            return Err(KeyPolicyError::UnsupportedSchemaVersion {
                version: self.schema_version,
                supported: SUPPORTED_SCHEMA_VERSIONS.to_vec(),
            });
        }
        Ok(())
    }

    /// Verifies self-consistency by recomputing the policy hash and comparing.
    ///
    /// This method recomputes the policy hash from the current policy fields
    /// and verifies it matches the stored `policy_hash`. This is useful after
    /// deserialization to ensure the policy has not been tampered with.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the recomputed hash matches the stored hash.
    ///
    /// # Errors
    ///
    /// Returns [`KeyPolicyError::SelfConsistencyCheckFailed`] if the computed
    /// hash does not match the stored hash.
    ///
    /// # Example
    ///
    /// ```rust
    /// use apm2_core::fac::{KeyPolicy, KeyPolicyBuilder};
    ///
    /// let policy = KeyPolicyBuilder::new("policy-001")
    ///     .schema_version(1)
    ///     .build();
    ///
    /// // After construction, self-consistency check passes
    /// assert!(policy.verify_self_consistency().is_ok());
    /// ```
    pub fn verify_self_consistency(&self) -> Result<(), KeyPolicyError> {
        let computed_hash = Self::compute_policy_hash(
            &self.policy_id,
            self.schema_version,
            &self.custody_domains,
            &self.coi_rules,
            &self.delegation_rules,
        );

        // Use constant-time comparison for security-sensitive hash comparison
        if !bool::from(computed_hash.ct_eq(&self.policy_hash)) {
            return Err(KeyPolicyError::SelfConsistencyCheckFailed {
                computed: hex_encode(&computed_hash),
                stored: hex_encode(&self.policy_hash),
            });
        }

        Ok(())
    }
}

/// Encodes bytes as a hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`KeyPolicy`] instances.
#[derive(Debug, Default)]
pub struct KeyPolicyBuilder {
    policy_id: String,
    schema_version: Option<u32>,
    custody_domains: Vec<CustodyDomain>,
    coi_rules: Vec<CoiRule>,
    delegation_rules: Vec<DelegationRule>,
}

impl KeyPolicyBuilder {
    /// Creates a new builder with the required policy ID.
    #[must_use]
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            policy_id: policy_id.into(),
            ..Default::default()
        }
    }

    /// Sets the schema version.
    #[must_use]
    pub const fn schema_version(mut self, version: u32) -> Self {
        self.schema_version = Some(version);
        self
    }

    /// Adds a custody domain.
    #[must_use]
    pub fn add_custody_domain(mut self, domain: CustodyDomain) -> Self {
        self.custody_domains.push(domain);
        self
    }

    /// Sets all custody domains.
    #[must_use]
    pub fn custody_domains(mut self, domains: Vec<CustodyDomain>) -> Self {
        self.custody_domains = domains;
        self
    }

    /// Adds a COI rule.
    #[must_use]
    pub fn add_coi_rule(mut self, rule: CoiRule) -> Self {
        self.coi_rules.push(rule);
        self
    }

    /// Sets all COI rules.
    #[must_use]
    pub fn coi_rules(mut self, rules: Vec<CoiRule>) -> Self {
        self.coi_rules = rules;
        self
    }

    /// Adds a delegation rule.
    #[must_use]
    pub fn add_delegation_rule(mut self, rule: DelegationRule) -> Self {
        self.delegation_rules.push(rule);
        self
    }

    /// Sets all delegation rules.
    #[must_use]
    pub fn delegation_rules(mut self, rules: Vec<DelegationRule>) -> Self {
        self.delegation_rules = rules;
        self
    }

    /// Builds the key policy.
    ///
    /// # Panics
    ///
    /// Panics if required fields are missing or validation fails.
    #[must_use]
    pub fn build(self) -> KeyPolicy {
        self.try_build().expect("key policy build failed")
    }

    /// Attempts to build the key policy.
    ///
    /// # Errors
    ///
    /// Returns [`KeyPolicyError::MissingField`] if `schema_version` is not set.
    /// Returns [`KeyPolicyError::StringTooLong`] if any string field exceeds
    /// the maximum length.
    /// Returns [`KeyPolicyError::CollectionTooLarge`] if any collection exceeds
    /// resource limits.
    /// Returns [`KeyPolicyError::DuplicateKeyId`] if duplicate key IDs are
    /// found.
    /// Returns [`KeyPolicyError::DuplicateDomainId`] if duplicate domain IDs
    /// are found.
    #[allow(clippy::too_many_lines)]
    pub fn try_build(self) -> Result<KeyPolicy, KeyPolicyError> {
        let schema_version = self
            .schema_version
            .ok_or(KeyPolicyError::MissingField("schema_version"))?;

        // Validate string lengths
        if self.policy_id.len() > MAX_STRING_LENGTH {
            return Err(KeyPolicyError::StringTooLong {
                field: "policy_id",
                actual: self.policy_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate collection sizes
        if self.custody_domains.len() > MAX_CUSTODY_DOMAINS {
            return Err(KeyPolicyError::CollectionTooLarge {
                field: "custody_domains",
                actual: self.custody_domains.len(),
                max: MAX_CUSTODY_DOMAINS,
            });
        }
        if self.coi_rules.len() > MAX_COI_RULES {
            return Err(KeyPolicyError::CollectionTooLarge {
                field: "coi_rules",
                actual: self.coi_rules.len(),
                max: MAX_COI_RULES,
            });
        }
        if self.delegation_rules.len() > MAX_DELEGATION_RULES {
            return Err(KeyPolicyError::CollectionTooLarge {
                field: "delegation_rules",
                actual: self.delegation_rules.len(),
                max: MAX_DELEGATION_RULES,
            });
        }

        // Track all key IDs for duplicate detection
        let mut all_key_ids: Vec<&str> = Vec::new();
        let mut domain_ids: Vec<&str> = Vec::new();

        // Validate custody domains
        for domain in &self.custody_domains {
            // Check for duplicate domain ID
            if domain_ids.contains(&domain.domain_id.as_str()) {
                return Err(KeyPolicyError::DuplicateDomainId {
                    domain_id: domain.domain_id.clone(),
                });
            }
            domain_ids.push(&domain.domain_id);

            // Validate domain string lengths
            if domain.domain_id.len() > MAX_STRING_LENGTH {
                return Err(KeyPolicyError::StringTooLong {
                    field: "custody_domain.domain_id",
                    actual: domain.domain_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if domain.coi_group_id.len() > MAX_STRING_LENGTH {
                return Err(KeyPolicyError::StringTooLong {
                    field: "custody_domain.coi_group_id",
                    actual: domain.coi_group_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }

            // Validate key bindings count
            if domain.key_bindings.len() > MAX_KEY_BINDINGS {
                return Err(KeyPolicyError::CollectionTooLarge {
                    field: "custody_domain.key_bindings",
                    actual: domain.key_bindings.len(),
                    max: MAX_KEY_BINDINGS,
                });
            }

            // Validate key bindings
            for binding in &domain.key_bindings {
                // Check for duplicate key ID
                if all_key_ids.contains(&binding.key_id.as_str()) {
                    return Err(KeyPolicyError::DuplicateKeyId {
                        key_id: binding.key_id.clone(),
                    });
                }
                all_key_ids.push(&binding.key_id);

                if binding.key_id.len() > MAX_STRING_LENGTH {
                    return Err(KeyPolicyError::StringTooLong {
                        field: "key_binding.key_id",
                        actual: binding.key_id.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
                if binding.actor_id.len() > MAX_STRING_LENGTH {
                    return Err(KeyPolicyError::StringTooLong {
                        field: "key_binding.actor_id",
                        actual: binding.actor_id.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
            }
        }

        // Validate COI rules and check for duplicates
        let mut coi_rule_ids: Vec<&str> = Vec::new();
        for rule in &self.coi_rules {
            // Check for duplicate rule ID
            if coi_rule_ids.contains(&rule.rule_id.as_str()) {
                return Err(KeyPolicyError::DuplicateRuleId {
                    rule_id: rule.rule_id.clone(),
                });
            }
            coi_rule_ids.push(&rule.rule_id);

            if rule.rule_id.len() > MAX_STRING_LENGTH {
                return Err(KeyPolicyError::StringTooLong {
                    field: "coi_rule.rule_id",
                    actual: rule.rule_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if rule.description.len() > MAX_STRING_LENGTH {
                return Err(KeyPolicyError::StringTooLong {
                    field: "coi_rule.description",
                    actual: rule.description.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
        }

        // Validate delegation rules and check for duplicates
        let mut delegation_rule_ids: Vec<&str> = Vec::new();
        for rule in &self.delegation_rules {
            // Check for duplicate rule ID
            if delegation_rule_ids.contains(&rule.rule_id.as_str()) {
                return Err(KeyPolicyError::DuplicateRuleId {
                    rule_id: rule.rule_id.clone(),
                });
            }
            delegation_rule_ids.push(&rule.rule_id);
            if rule.rule_id.len() > MAX_STRING_LENGTH {
                return Err(KeyPolicyError::StringTooLong {
                    field: "delegation_rule.rule_id",
                    actual: rule.rule_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if rule.from_actor_id.len() > MAX_STRING_LENGTH {
                return Err(KeyPolicyError::StringTooLong {
                    field: "delegation_rule.from_actor_id",
                    actual: rule.from_actor_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if rule.to_actor_id.len() > MAX_STRING_LENGTH {
                return Err(KeyPolicyError::StringTooLong {
                    field: "delegation_rule.to_actor_id",
                    actual: rule.to_actor_id.len(),
                    max: MAX_STRING_LENGTH,
                });
            }
            if let Some(ref scope) = rule.scope {
                if scope.len() > MAX_STRING_LENGTH {
                    return Err(KeyPolicyError::StringTooLong {
                        field: "delegation_rule.scope",
                        actual: scope.len(),
                        max: MAX_STRING_LENGTH,
                    });
                }
            }
        }

        // Compute policy hash
        let policy_hash = KeyPolicy::compute_policy_hash(
            &self.policy_id,
            schema_version,
            &self.custody_domains,
            &self.coi_rules,
            &self.delegation_rules,
        );

        Ok(KeyPolicy {
            policy_id: self.policy_id,
            policy_hash,
            schema_version,
            custody_domains: self.custody_domains,
            coi_rules: self.coi_rules,
            delegation_rules: self.delegation_rules,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    use super::*;

    fn create_test_policy() -> KeyPolicy {
        KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "team-alpha".to_string(),
                coi_group_id: "coi-group-a".to_string(),
                key_bindings: vec![
                    KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    },
                    KeyBinding {
                        key_id: "key-charlie".to_string(),
                        actor_id: "charlie".to_string(),
                    },
                ],
            })
            .add_custody_domain(CustodyDomain {
                domain_id: "team-beta".to_string(),
                coi_group_id: "coi-group-b".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-bob".to_string(),
                    actor_id: "bob".to_string(),
                }],
            })
            .add_coi_rule(CoiRule {
                rule_id: "no-self-review".to_string(),
                description: "Prevent self-review attacks".to_string(),
                enforcement_level: CoiEnforcementLevel::Reject,
            })
            .build()
    }

    // =========================================================================
    // Basic Construction Tests
    // =========================================================================

    #[test]
    fn test_build_key_policy() {
        let policy = create_test_policy();

        assert_eq!(policy.policy_id, "policy-001");
        assert_eq!(policy.schema_version, 1);
        assert_eq!(policy.custody_domains.len(), 2);
        assert_eq!(policy.coi_rules.len(), 1);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let policy1 = create_test_policy();
        let policy2 = create_test_policy();

        // Same policy should produce same hash
        assert_eq!(policy1.policy_hash(), policy2.policy_hash());
    }

    #[test]
    fn test_policy_hash_differs_with_different_content() {
        let policy1 = create_test_policy();

        let policy2 = KeyPolicyBuilder::new("policy-002") // Different ID
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "team-alpha".to_string(),
                coi_group_id: "coi-group-a".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-alice".to_string(),
                    actor_id: "alice".to_string(),
                }],
            })
            .build();

        assert_ne!(policy1.policy_hash(), policy2.policy_hash());
    }

    // =========================================================================
    // COI Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_coi_different_groups_ok() {
        let policy = create_test_policy();

        // Bob (group-b) reviewing Alice's (group-a) changeset: OK
        assert!(policy.validate_coi("key-bob", "alice").is_ok());
    }

    #[test]
    fn test_validate_coi_same_group_rejected() {
        let policy = create_test_policy();

        // Alice reviewing her own changeset: REJECTED (same COI group)
        let result = policy.validate_coi("key-alice", "alice");
        assert!(matches!(
            result,
            Err(KeyPolicyError::CoiViolation {
                executor_key_id,
                author_actor_id,
                coi_group_id,
            }) if executor_key_id == "key-alice"
               && author_actor_id == "alice"
               && coi_group_id == "coi-group-a"
        ));
    }

    #[test]
    fn test_validate_coi_same_group_different_actors_rejected() {
        let policy = create_test_policy();

        // Charlie reviewing Alice's changeset: REJECTED (same COI group-a)
        let result = policy.validate_coi("key-charlie", "alice");
        assert!(matches!(
            result,
            Err(KeyPolicyError::CoiViolation {
                coi_group_id,
                ..
            }) if coi_group_id == "coi-group-a"
        ));
    }

    #[test]
    fn test_validate_coi_executor_key_not_found() {
        let policy = create_test_policy();

        let result = policy.validate_coi("unknown-key", "alice");
        assert!(matches!(
            result,
            Err(KeyPolicyError::KeyNotFound { key_id }) if key_id == "unknown-key"
        ));
    }

    #[test]
    fn test_validate_coi_author_actor_not_found() {
        let policy = create_test_policy();

        let result = policy.validate_coi("key-bob", "unknown-actor");
        assert!(matches!(
            result,
            Err(KeyPolicyError::ActorNotFound { actor_id }) if actor_id == "unknown-actor"
        ));
    }

    // =========================================================================
    // Policy Hash Verification Tests
    // =========================================================================

    #[test]
    fn test_verify_policy_hash_match() {
        let policy = create_test_policy();
        let hash = policy.policy_hash();

        assert!(policy.verify_policy_hash(&hash).is_ok());
    }

    #[test]
    fn test_verify_policy_hash_mismatch() {
        let policy = create_test_policy();
        let wrong_hash = [0xAB; 32];

        let result = policy.verify_policy_hash(&wrong_hash);
        assert!(matches!(
            result,
            Err(KeyPolicyError::PolicyHashMismatch { .. })
        ));
    }

    // =========================================================================
    // Version Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_version_supported() {
        let policy = create_test_policy();

        assert!(policy.validate_version(true).is_ok());
        assert!(policy.validate_version(false).is_ok());
    }

    #[test]
    fn test_validate_version_unsupported_enforce() {
        // Create a policy and manually modify the schema version via serialization
        let json = r#"{"policy_id":"policy-001","policy_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"schema_version":999,"custody_domains":[],"coi_rules":[],"delegation_rules":[]}"#;
        let policy: KeyPolicy = serde_json::from_str(json).unwrap();

        let result = policy.validate_version(true);
        assert!(matches!(
            result,
            Err(KeyPolicyError::UnsupportedSchemaVersion { version: 999, .. })
        ));
    }

    #[test]
    fn test_validate_version_unsupported_permissive() {
        // Create a policy and manually modify the schema version via serialization
        let json = r#"{"policy_id":"policy-001","policy_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"schema_version":999,"custody_domains":[],"coi_rules":[],"delegation_rules":[]}"#;
        let policy: KeyPolicy = serde_json::from_str(json).unwrap();

        // Permissive mode: returns Ok even for unsupported versions
        assert!(policy.validate_version(false).is_ok());
    }

    // =========================================================================
    // Lookup Tests
    // =========================================================================

    #[test]
    fn test_get_coi_group_for_key() {
        let policy = create_test_policy();

        assert_eq!(
            policy.get_coi_group_for_key("key-alice"),
            Some("coi-group-a")
        );
        assert_eq!(policy.get_coi_group_for_key("key-bob"), Some("coi-group-b"));
        assert_eq!(policy.get_coi_group_for_key("unknown-key"), None);
    }

    #[test]
    fn test_get_coi_groups_for_actor() {
        let policy = create_test_policy();

        let alice_groups = policy.get_coi_groups_for_actor("alice");
        assert!(alice_groups.contains("coi-group-a"));
        assert_eq!(alice_groups.len(), 1);

        let bob_groups = policy.get_coi_groups_for_actor("bob");
        assert!(bob_groups.contains("coi-group-b"));
        assert_eq!(bob_groups.len(), 1);

        let unknown_groups = policy.get_coi_groups_for_actor("unknown-actor");
        assert!(unknown_groups.is_empty());
    }

    // =========================================================================
    // Resource Limit Tests
    // =========================================================================

    #[test]
    fn test_custody_domains_too_large() {
        let domains: Vec<CustodyDomain> = (0..=MAX_CUSTODY_DOMAINS)
            .map(|i| CustodyDomain {
                domain_id: format!("domain-{i}"),
                coi_group_id: format!("group-{i}"),
                key_bindings: vec![],
            })
            .collect();

        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .custody_domains(domains)
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::CollectionTooLarge {
                field: "custody_domains",
                actual,
                max,
            }) if actual == MAX_CUSTODY_DOMAINS + 1 && max == MAX_CUSTODY_DOMAINS
        ));
    }

    #[test]
    fn test_coi_rules_too_large() {
        let rules: Vec<CoiRule> = (0..=MAX_COI_RULES)
            .map(|i| CoiRule {
                rule_id: format!("rule-{i}"),
                description: "Test rule".to_string(),
                enforcement_level: CoiEnforcementLevel::Reject,
            })
            .collect();

        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .coi_rules(rules)
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::CollectionTooLarge {
                field: "coi_rules",
                ..
            })
        ));
    }

    #[test]
    fn test_key_bindings_too_large() {
        let bindings: Vec<KeyBinding> = (0..=MAX_KEY_BINDINGS)
            .map(|i| KeyBinding {
                key_id: format!("key-{i}"),
                actor_id: format!("actor-{i}"),
            })
            .collect();

        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "domain-001".to_string(),
                coi_group_id: "group-001".to_string(),
                key_bindings: bindings,
            })
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::CollectionTooLarge {
                field: "custody_domain.key_bindings",
                ..
            })
        ));
    }

    // =========================================================================
    // String Length Tests
    // =========================================================================

    #[test]
    fn test_policy_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = KeyPolicyBuilder::new(long_id).schema_version(1).try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::StringTooLong {
                field: "policy_id",
                ..
            })
        ));
    }

    #[test]
    fn test_domain_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: long_id,
                coi_group_id: "group-001".to_string(),
                key_bindings: vec![],
            })
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::StringTooLong {
                field: "custody_domain.domain_id",
                ..
            })
        ));
    }

    #[test]
    fn test_key_id_too_long() {
        let long_id = "x".repeat(MAX_STRING_LENGTH + 1);

        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "domain-001".to_string(),
                coi_group_id: "group-001".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: long_id,
                    actor_id: "actor-001".to_string(),
                }],
            })
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::StringTooLong {
                field: "key_binding.key_id",
                ..
            })
        ));
    }

    // =========================================================================
    // Duplicate Detection Tests
    // =========================================================================

    #[test]
    fn test_duplicate_key_id_rejected() {
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "domain-001".to_string(),
                coi_group_id: "group-001".to_string(),
                key_bindings: vec![
                    KeyBinding {
                        key_id: "key-alice".to_string(),
                        actor_id: "alice".to_string(),
                    },
                    KeyBinding {
                        key_id: "key-alice".to_string(), // Duplicate
                        actor_id: "bob".to_string(),
                    },
                ],
            })
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::DuplicateKeyId { key_id }) if key_id == "key-alice"
        ));
    }

    #[test]
    fn test_duplicate_key_id_across_domains_rejected() {
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "domain-001".to_string(),
                coi_group_id: "group-001".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-alice".to_string(),
                    actor_id: "alice".to_string(),
                }],
            })
            .add_custody_domain(CustodyDomain {
                domain_id: "domain-002".to_string(),
                coi_group_id: "group-002".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-alice".to_string(), // Duplicate across domains
                    actor_id: "bob".to_string(),
                }],
            })
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::DuplicateKeyId { key_id }) if key_id == "key-alice"
        ));
    }

    #[test]
    fn test_duplicate_domain_id_rejected() {
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "domain-001".to_string(),
                coi_group_id: "group-001".to_string(),
                key_bindings: vec![],
            })
            .add_custody_domain(CustodyDomain {
                domain_id: "domain-001".to_string(), // Duplicate
                coi_group_id: "group-002".to_string(),
                key_bindings: vec![],
            })
            .try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::DuplicateDomainId { domain_id }) if domain_id == "domain-001"
        ));
    }

    // =========================================================================
    // Missing Field Tests
    // =========================================================================

    #[test]
    fn test_missing_schema_version() {
        let result = KeyPolicyBuilder::new("policy-001").try_build();

        assert!(matches!(
            result,
            Err(KeyPolicyError::MissingField("schema_version"))
        ));
    }

    // =========================================================================
    // Serde Round-Trip Tests
    // =========================================================================

    #[test]
    fn test_serde_roundtrip() {
        let original = create_test_policy();

        // Serialize to JSON
        let json = serde_json::to_string(&original).unwrap();

        // Deserialize back
        let recovered: KeyPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(original.policy_id, recovered.policy_id);
        assert_eq!(original.policy_hash, recovered.policy_hash);
        assert_eq!(original.schema_version, recovered.schema_version);
        assert_eq!(original.custody_domains, recovered.custody_domains);
        assert_eq!(original.coi_rules, recovered.coi_rules);
    }

    #[test]
    fn test_serde_deny_unknown_fields() {
        // JSON with unknown field should fail to deserialize
        let json = r#"{"policy_id":"test","policy_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"schema_version":1,"custody_domains":[],"coi_rules":[],"delegation_rules":[],"unknown_field":"bad"}"#;

        let result: Result<KeyPolicy, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // =========================================================================
    // Enforcement Level Tests
    // =========================================================================

    #[test]
    fn test_coi_enforcement_level_try_from() {
        assert_eq!(
            CoiEnforcementLevel::try_from(0).unwrap(),
            CoiEnforcementLevel::Warn
        );
        assert_eq!(
            CoiEnforcementLevel::try_from(1).unwrap(),
            CoiEnforcementLevel::Reject
        );
        assert_eq!(
            CoiEnforcementLevel::try_from(2).unwrap(),
            CoiEnforcementLevel::RejectAndAudit
        );
        assert!(CoiEnforcementLevel::try_from(3).is_err());
    }

    #[test]
    fn test_coi_enforcement_level_to_u8() {
        assert_eq!(u8::from(CoiEnforcementLevel::Warn), 0);
        assert_eq!(u8::from(CoiEnforcementLevel::Reject), 1);
        assert_eq!(u8::from(CoiEnforcementLevel::RejectAndAudit), 2);
    }

    // =========================================================================
    // Delegation Rule Tests
    // =========================================================================

    #[test]
    fn test_delegation_rules_included_in_hash() {
        let policy_without_delegation = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .build();

        let policy_with_delegation = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_delegation_rule(DelegationRule {
                rule_id: "delegation-001".to_string(),
                from_actor_id: "alice".to_string(),
                to_actor_id: "bob".to_string(),
                scope: Some("review".to_string()),
                active: true,
            })
            .build();

        // Different delegation rules should produce different hashes
        assert_ne!(
            policy_without_delegation.policy_hash(),
            policy_with_delegation.policy_hash()
        );
    }

    #[test]
    fn test_delegation_rule_scope_optional() {
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_delegation_rule(DelegationRule {
                rule_id: "delegation-001".to_string(),
                from_actor_id: "alice".to_string(),
                to_actor_id: "bob".to_string(),
                scope: None, // No scope
                active: true,
            })
            .try_build();

        assert!(result.is_ok());
    }

    // =========================================================================
    // Empty Policy Tests
    // =========================================================================

    #[test]
    fn test_empty_policy_valid() {
        let policy = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .build();

        assert!(policy.custody_domains.is_empty());
        assert!(policy.coi_rules.is_empty());
        assert!(policy.delegation_rules.is_empty());
    }

    #[test]
    fn test_empty_policy_coi_validation_fails() {
        let policy = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .build();

        // Both key and actor not found
        let result = policy.validate_coi("any-key", "any-actor");
        assert!(matches!(result, Err(KeyPolicyError::KeyNotFound { .. })));
    }

    // =========================================================================
    // COI Bypass via Multiple Group Bindings Tests (CRITICAL Security Fix)
    // =========================================================================

    #[test]
    fn test_validate_coi_multiple_group_bindings_rejected() {
        // CRITICAL: Actor belongs to multiple COI groups {A, B}
        // Executor is in group B
        // The check MUST detect the overlap and reject
        let policy = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "team-alpha".to_string(),
                coi_group_id: "coi-group-a".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-alice-alpha".to_string(),
                    actor_id: "alice".to_string(), // Alice in group A
                }],
            })
            .add_custody_domain(CustodyDomain {
                domain_id: "team-beta".to_string(),
                coi_group_id: "coi-group-b".to_string(),
                key_bindings: vec![
                    KeyBinding {
                        key_id: "key-alice-beta".to_string(),
                        actor_id: "alice".to_string(), // Alice ALSO in group B
                    },
                    KeyBinding {
                        key_id: "key-bob".to_string(),
                        actor_id: "bob".to_string(),
                    },
                ],
            })
            .build();

        // Alice is in groups {A, B}
        let alice_groups = policy.get_coi_groups_for_actor("alice");
        assert_eq!(alice_groups.len(), 2);
        assert!(alice_groups.contains("coi-group-a"));
        assert!(alice_groups.contains("coi-group-b"));

        // Bob (group B) reviewing Alice's changeset: MUST be REJECTED
        // because Alice is ALSO in group B
        let result = policy.validate_coi("key-bob", "alice");
        assert!(
            matches!(
                &result,
                Err(KeyPolicyError::CoiViolation {
                    coi_group_id,
                    ..
                }) if coi_group_id == "coi-group-b"
            ),
            "COI bypass via multiple group bindings: expected rejection but got {result:?}"
        );
    }

    #[test]
    fn test_validate_coi_multiple_groups_no_overlap_ok() {
        // Actor in groups {A, B}, executor in group C - no overlap, should be OK
        let policy = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_custody_domain(CustodyDomain {
                domain_id: "team-alpha".to_string(),
                coi_group_id: "coi-group-a".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-alice-alpha".to_string(),
                    actor_id: "alice".to_string(),
                }],
            })
            .add_custody_domain(CustodyDomain {
                domain_id: "team-beta".to_string(),
                coi_group_id: "coi-group-b".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-alice-beta".to_string(),
                    actor_id: "alice".to_string(),
                }],
            })
            .add_custody_domain(CustodyDomain {
                domain_id: "team-gamma".to_string(),
                coi_group_id: "coi-group-c".to_string(),
                key_bindings: vec![KeyBinding {
                    key_id: "key-carol".to_string(),
                    actor_id: "carol".to_string(),
                }],
            })
            .build();

        // Carol (group C) reviewing Alice's (groups A, B) changeset: OK (no overlap)
        assert!(policy.validate_coi("key-carol", "alice").is_ok());
    }

    // =========================================================================
    // Self-Consistency Hash Verification Tests (MEDIUM Security Fix)
    // =========================================================================

    #[test]
    fn test_verify_self_consistency_passes() {
        let policy = create_test_policy();

        // Freshly created policy should pass self-consistency
        assert!(policy.verify_self_consistency().is_ok());
    }

    #[test]
    fn test_verify_self_consistency_fails_on_tampered_policy() {
        // Create a policy with a manually corrupted hash via JSON
        let json = r#"{"policy_id":"policy-001","policy_hash":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"schema_version":1,"custody_domains":[],"coi_rules":[],"delegation_rules":[]}"#;
        let policy: KeyPolicy = serde_json::from_str(json).unwrap();

        // Self-consistency check should fail because hash doesn't match content
        let result = policy.verify_self_consistency();
        assert!(
            matches!(
                result,
                Err(KeyPolicyError::SelfConsistencyCheckFailed { .. })
            ),
            "Expected SelfConsistencyCheckFailed but got {result:?}"
        );
    }

    #[test]
    fn test_verify_self_consistency_after_deserialization() {
        let original = create_test_policy();

        // Serialize and deserialize
        let json = serde_json::to_string(&original).unwrap();
        let recovered: KeyPolicy = serde_json::from_str(&json).unwrap();

        // Self-consistency should still pass
        assert!(recovered.verify_self_consistency().is_ok());
    }

    // =========================================================================
    // Duplicate Rule ID Tests (LOW Security Fix)
    // =========================================================================

    #[test]
    fn test_duplicate_coi_rule_id_rejected() {
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_coi_rule(CoiRule {
                rule_id: "rule-001".to_string(),
                description: "First rule".to_string(),
                enforcement_level: CoiEnforcementLevel::Reject,
            })
            .add_coi_rule(CoiRule {
                rule_id: "rule-001".to_string(), // Duplicate
                description: "Second rule with same ID".to_string(),
                enforcement_level: CoiEnforcementLevel::Warn,
            })
            .try_build();

        assert!(
            matches!(
                &result,
                Err(KeyPolicyError::DuplicateRuleId { rule_id }) if rule_id == "rule-001"
            ),
            "Expected DuplicateRuleId but got {result:?}"
        );
    }

    #[test]
    fn test_duplicate_delegation_rule_id_rejected() {
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_delegation_rule(DelegationRule {
                rule_id: "delegation-001".to_string(),
                from_actor_id: "alice".to_string(),
                to_actor_id: "bob".to_string(),
                scope: None,
                active: true,
            })
            .add_delegation_rule(DelegationRule {
                rule_id: "delegation-001".to_string(), // Duplicate
                from_actor_id: "carol".to_string(),
                to_actor_id: "dave".to_string(),
                scope: None,
                active: true,
            })
            .try_build();

        assert!(
            matches!(
                &result,
                Err(KeyPolicyError::DuplicateRuleId { rule_id }) if rule_id == "delegation-001"
            ),
            "Expected DuplicateRuleId but got {result:?}"
        );
    }

    #[test]
    fn test_same_rule_id_across_coi_and_delegation_allowed() {
        // Different namespaces: same rule_id in coi_rules and delegation_rules is
        // allowed
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_coi_rule(CoiRule {
                rule_id: "rule-001".to_string(),
                description: "COI rule".to_string(),
                enforcement_level: CoiEnforcementLevel::Reject,
            })
            .add_delegation_rule(DelegationRule {
                rule_id: "rule-001".to_string(), // Same ID but different collection
                from_actor_id: "alice".to_string(),
                to_actor_id: "bob".to_string(),
                scope: None,
                active: true,
            })
            .try_build();

        // Should succeed - they're in different namespaces
        assert!(result.is_ok());
    }

    #[test]
    fn test_unique_rule_ids_accepted() {
        let result = KeyPolicyBuilder::new("policy-001")
            .schema_version(1)
            .add_coi_rule(CoiRule {
                rule_id: "coi-rule-001".to_string(),
                description: "First COI rule".to_string(),
                enforcement_level: CoiEnforcementLevel::Reject,
            })
            .add_coi_rule(CoiRule {
                rule_id: "coi-rule-002".to_string(),
                description: "Second COI rule".to_string(),
                enforcement_level: CoiEnforcementLevel::Warn,
            })
            .add_delegation_rule(DelegationRule {
                rule_id: "delegation-001".to_string(),
                from_actor_id: "alice".to_string(),
                to_actor_id: "bob".to_string(),
                scope: None,
                active: true,
            })
            .add_delegation_rule(DelegationRule {
                rule_id: "delegation-002".to_string(),
                from_actor_id: "carol".to_string(),
                to_actor_id: "dave".to_string(),
                scope: None,
                active: true,
            })
            .try_build();

        assert!(result.is_ok());
    }
}
