// AGENT-AUTHORED
//! AAT harness sandboxing schema for the Forge Admission Cycle.
//!
//! This module defines the schema types for AAT harness sandboxing as specified
//! in RFC-0015 DD-FAC-0016. AAT harnesses run in strict sandbox environments
//! with deny-by-default egress control.
//!
//! # Phase 1 - Schema Only
//!
//! This ticket (TCK-00230) defines only the schema types:
//! - [`NetworkPolicyProfile`]: Network policy profile for AAT harness
//!   sandboxing
//! - [`EgressRule`]: Individual egress rule defining allowed network access
//!
//! Phase 2 (future ticket) will implement runtime enforcement.
//!
//! # Security Model
//!
//! AAT harnesses run in strict sandbox with:
//! - **Deny-by-default egress**: All outbound network access blocked unless
//!   explicitly allowed
//! - **Policy-declared access**: Only policy-declared endpoints are reachable
//! - **Receipt recording**: Actual egress is recorded in receipts for audit
//! - **Pinned snapshot mounts**: Host mounts limited to pinned snapshot
//!
//! # Network Policy Profile
//!
//! The [`NetworkPolicyProfile`] defines the allowed network access for an AAT
//! harness. Each profile:
//! - Has a unique `profile_id` for identification
//! - Contains a computed `profile_hash` for integrity verification
//! - Lists `allowed_egress` rules for permitted endpoints
//! - Uses `deny_by_default` to ensure fail-closed security
//!
//! # Egress Rules
//!
//! Each [`EgressRule`] specifies:
//! - `host`: Target hostname or IP address
//! - `port`: Target port number
//! - `protocol`: Transport protocol (TCP, UDP)
//!
//! # Attestation Binding
//!
//! The `network_policy_profile_hash` field in
//! [`AatAttestation`](super::AatAttestation) binds an AAT execution to a
//! specific network policy profile. This ensures:
//! - Receipts reference the exact policy enforced during execution
//! - Policy substitution attacks are detectable
//! - Audit trails include network policy provenance
//!
//! # Example
//!
//! ```rust
//! use apm2_core::fac::harness_sandbox::{
//!     EgressRule, NetworkPolicyProfile, NetworkPolicyProfileBuilder, Protocol,
//! };
//!
//! // Define a network policy allowing access to package registries
//! let policy = NetworkPolicyProfileBuilder::new("aat-default-policy")
//!     .add_egress_rule(EgressRule {
//!         host: "registry.npmjs.org".to_string(),
//!         port: 443,
//!         protocol: Protocol::Tcp,
//!     })
//!     .add_egress_rule(EgressRule {
//!         host: "crates.io".to_string(),
//!         port: 443,
//!         protocol: Protocol::Tcp,
//!     })
//!     .deny_by_default(true)
//!     .build()
//!     .expect("valid policy");
//!
//! // Verify deny-by-default is set
//! assert!(policy.deny_by_default);
//!
//! // Get the profile hash for attestation binding
//! let hash = policy.profile_hash;
//! assert_ne!(hash, [0u8; 32]);
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum number of egress rules allowed in a network policy profile.
/// This prevents denial-of-service attacks via oversized rule lists.
pub const MAX_EGRESS_RULES: usize = 256;

/// Maximum length of any string field in the harness sandbox schema.
pub const MAX_STRING_LENGTH: usize = 4096;

/// Maximum length of host field in egress rules.
/// Covers DNS hostnames and IPv6 addresses.
pub const MAX_HOST_LENGTH: usize = 253;

/// Maximum port number (inclusive).
pub const MAX_PORT: u16 = 65535;

/// Minimum port number (inclusive).
pub const MIN_PORT: u16 = 1;

// =============================================================================
// Protocol Enum
// =============================================================================

/// Transport protocol for egress rules.
///
/// Specifies the transport layer protocol for network access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum Protocol {
    /// Transmission Control Protocol (connection-oriented).
    #[default]
    Tcp = 1,
    /// User Datagram Protocol (connectionless).
    Udp = 2,
}

impl Protocol {
    /// Returns the numeric value of this protocol.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the protocol name as a string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

impl TryFrom<u8> for Protocol {
    type Error = HarnessSandboxError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(HarnessSandboxError::InvalidEnumValue {
                field: "protocol",
                value: i32::from(value),
            }),
        }
    }
}

impl TryFrom<i32> for Protocol {
    type Error = HarnessSandboxError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(HarnessSandboxError::InvalidEnumValue {
                field: "protocol",
                value,
            }),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during harness sandbox operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HarnessSandboxError {
    /// Missing required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid data in schema.
    #[error("invalid harness sandbox data: {0}")]
    InvalidData(String),

    /// Invalid enum value.
    #[error("invalid enum value for {field}: {value}")]
    InvalidEnumValue {
        /// Name of the field with invalid value.
        field: &'static str,
        /// The invalid value.
        value: i32,
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

    /// Collection size exceeds limit.
    #[error("collection {field} exceeds limit: {actual} > {max}")]
    CollectionTooLarge {
        /// Name of the field that exceeded the limit.
        field: &'static str,
        /// Actual size.
        actual: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Port number out of valid range.
    #[error("port {port} out of valid range [{min}, {max}]")]
    PortOutOfRange {
        /// The invalid port number.
        port: u16,
        /// Minimum valid port.
        min: u16,
        /// Maximum valid port.
        max: u16,
    },

    /// Empty host in egress rule.
    #[error("egress rule host cannot be empty")]
    EmptyHost,

    /// Deny-by-default must be true for security.
    #[error("deny_by_default must be true (fail-closed security model)")]
    DenyByDefaultRequired,
}

// =============================================================================
// EgressRule
// =============================================================================

/// An individual egress rule defining allowed network access.
///
/// Each rule specifies a single (host, port, protocol) tuple that is
/// permitted for outbound network connections.
///
/// # Security Notes
///
/// - Rules are evaluated in order; first match wins
/// - Wildcards are NOT supported (explicit hosts only)
/// - Port ranges are NOT supported (explicit ports only)
/// - CIDR notation is NOT supported for hosts
///
/// # Validation
///
/// - `host` must be non-empty and at most 253 characters
/// - `port` must be in range [1, 65535]
/// - `protocol` must be TCP or UDP
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    /// Target hostname or IP address.
    ///
    /// Must be a valid DNS hostname or IP address (v4 or v6).
    /// Wildcards are not supported for security reasons.
    pub host: String,

    /// Target port number.
    ///
    /// Must be in range [1, 65535]. Port 0 is reserved.
    pub port: u16,

    /// Transport protocol (TCP or UDP).
    pub protocol: Protocol,
}

impl EgressRule {
    /// Validates the egress rule fields.
    ///
    /// # Errors
    ///
    /// Returns [`HarnessSandboxError`] if validation fails.
    pub fn validate(&self) -> Result<(), HarnessSandboxError> {
        // Validate host
        if self.host.is_empty() {
            return Err(HarnessSandboxError::EmptyHost);
        }
        if self.host.len() > MAX_HOST_LENGTH {
            return Err(HarnessSandboxError::StringTooLong {
                field: "host",
                actual: self.host.len(),
                max: MAX_HOST_LENGTH,
            });
        }

        // Validate port
        if self.port < MIN_PORT {
            return Err(HarnessSandboxError::PortOutOfRange {
                port: self.port,
                min: MIN_PORT,
                max: MAX_PORT,
            });
        }

        Ok(())
    }

    /// Computes a hash of this egress rule for ordering and deduplication.
    ///
    /// The hash is computed over the canonical representation of the rule:
    /// `host || port (big-endian) || protocol`
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.host.as_bytes());
        hasher.update(&self.port.to_be_bytes());
        hasher.update(&[self.protocol.as_u8()]);
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// NetworkPolicyProfile
// =============================================================================

/// Network policy profile for AAT harness sandboxing.
///
/// Defines the allowed egress rules for an AAT harness execution environment.
/// The profile uses a deny-by-default model where all egress is blocked unless
/// explicitly allowed by a rule.
///
/// # Fields
///
/// - `profile_id`: Unique identifier for this policy profile
/// - `profile_hash`: BLAKE3 hash of the canonical profile representation
/// - `allowed_egress`: List of allowed egress rules (max 256)
/// - `deny_by_default`: MUST be true (fail-closed security model)
///
/// # Canonical Representation
///
/// The `profile_hash` is computed over:
/// ```text
/// profile_id || len(allowed_egress) || sorted(egress_rule_hashes) || deny_by_default
/// ```
///
/// # Security Model
///
/// - Deny-by-default MUST be true; builder enforces this
/// - Egress rules are sorted by hash for canonical encoding
/// - Profile hash provides integrity verification
/// - Profile referenced by `network_policy_profile_hash` in attestation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyProfile {
    /// Unique identifier for this policy profile.
    pub profile_id: String,

    /// BLAKE3 hash of the canonical profile representation.
    ///
    /// Computed from: `profile_id || len(allowed_egress) ||
    /// sorted(egress_hashes) || deny_by_default`
    #[serde(with = "serde_bytes")]
    pub profile_hash: [u8; 32],

    /// List of allowed egress rules.
    ///
    /// Each rule specifies a (host, port, protocol) tuple that is permitted.
    /// Maximum 256 rules to prevent denial-of-service.
    pub allowed_egress: Vec<EgressRule>,

    /// Deny-by-default flag (MUST be true).
    ///
    /// When true, all egress not matching a rule is blocked.
    /// This field MUST be true for the fail-closed security model.
    pub deny_by_default: bool,
}

impl NetworkPolicyProfile {
    /// Computes the canonical profile hash.
    ///
    /// The hash covers:
    /// - `profile_id` (length-prefixed)
    /// - Number of egress rules (u32 big-endian)
    /// - Sorted egress rule hashes
    /// - `deny_by_default` flag (1 byte)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // String lengths are validated elsewhere
    pub fn compute_profile_hash(
        profile_id: &str,
        allowed_egress: &[EgressRule],
        deny_by_default: bool,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Profile ID (length-prefixed)
        hasher.update(&(profile_id.len() as u32).to_be_bytes());
        hasher.update(profile_id.as_bytes());

        // Number of egress rules
        hasher.update(&(allowed_egress.len() as u32).to_be_bytes());

        // Sorted egress rule hashes for canonical encoding
        let mut rule_hashes: Vec<[u8; 32]> = allowed_egress
            .iter()
            .map(EgressRule::compute_hash)
            .collect();
        rule_hashes.sort_unstable();
        for hash in &rule_hashes {
            hasher.update(hash);
        }

        // Deny-by-default flag
        hasher.update(&[u8::from(deny_by_default)]);

        *hasher.finalize().as_bytes()
    }

    /// Validates the network policy profile.
    ///
    /// # Validations
    ///
    /// - `profile_id` must be non-empty and within length limits
    /// - `allowed_egress` must not exceed [`MAX_EGRESS_RULES`]
    /// - Each egress rule must be valid
    /// - `deny_by_default` must be true
    /// - `profile_hash` must match computed value
    ///
    /// # Errors
    ///
    /// Returns [`HarnessSandboxError`] if validation fails.
    pub fn validate(&self) -> Result<(), HarnessSandboxError> {
        // Validate profile_id
        if self.profile_id.is_empty() {
            return Err(HarnessSandboxError::MissingField("profile_id"));
        }
        if self.profile_id.len() > MAX_STRING_LENGTH {
            return Err(HarnessSandboxError::StringTooLong {
                field: "profile_id",
                actual: self.profile_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate egress rules count
        if self.allowed_egress.len() > MAX_EGRESS_RULES {
            return Err(HarnessSandboxError::CollectionTooLarge {
                field: "allowed_egress",
                actual: self.allowed_egress.len(),
                max: MAX_EGRESS_RULES,
            });
        }

        // Validate each egress rule
        for rule in &self.allowed_egress {
            rule.validate()?;
        }

        // Validate deny_by_default (MUST be true for fail-closed security)
        if !self.deny_by_default {
            return Err(HarnessSandboxError::DenyByDefaultRequired);
        }

        // Validate profile_hash matches computed value
        let computed_hash = Self::compute_profile_hash(
            &self.profile_id,
            &self.allowed_egress,
            self.deny_by_default,
        );
        if self.profile_hash != computed_hash {
            return Err(HarnessSandboxError::InvalidData(
                "profile_hash does not match computed value".to_string(),
            ));
        }

        Ok(())
    }

    /// Returns true if egress to the given (host, port, protocol) is allowed.
    ///
    /// This is a schema-level check only. Phase 2 will implement runtime
    /// enforcement.
    ///
    /// # Arguments
    ///
    /// * `host` - Target hostname or IP address
    /// * `port` - Target port number
    /// * `protocol` - Transport protocol
    ///
    /// # Returns
    ///
    /// `true` if a matching rule exists, `false` otherwise (deny-by-default).
    #[must_use]
    pub fn allows_egress(&self, host: &str, port: u16, protocol: Protocol) -> bool {
        // Deny-by-default: only allow if a rule matches
        self.allowed_egress
            .iter()
            .any(|rule| rule.host == host && rule.port == port && rule.protocol == protocol)
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`NetworkPolicyProfile`] instances with validation.
#[derive(Debug, Default)]
pub struct NetworkPolicyProfileBuilder {
    profile_id: Option<String>,
    allowed_egress: Vec<EgressRule>,
    deny_by_default: bool,
}

impl NetworkPolicyProfileBuilder {
    /// Creates a new builder with the given profile ID.
    ///
    /// # Arguments
    ///
    /// * `profile_id` - Unique identifier for the policy profile
    #[must_use]
    pub fn new(profile_id: impl Into<String>) -> Self {
        Self {
            profile_id: Some(profile_id.into()),
            allowed_egress: Vec::new(),
            deny_by_default: true, // Default to true for security
        }
    }

    /// Sets the profile ID.
    #[must_use]
    pub fn profile_id(mut self, id: impl Into<String>) -> Self {
        self.profile_id = Some(id.into());
        self
    }

    /// Adds an egress rule to the allowed list.
    #[must_use]
    pub fn add_egress_rule(mut self, rule: EgressRule) -> Self {
        self.allowed_egress.push(rule);
        self
    }

    /// Sets all egress rules at once.
    #[must_use]
    pub fn allowed_egress(mut self, rules: Vec<EgressRule>) -> Self {
        self.allowed_egress = rules;
        self
    }

    /// Sets the deny-by-default flag.
    ///
    /// # Note
    ///
    /// This MUST be `true` for the fail-closed security model.
    /// The builder will reject `false` during build.
    #[must_use]
    pub const fn deny_by_default(mut self, deny: bool) -> Self {
        self.deny_by_default = deny;
        self
    }

    /// Builds the network policy profile, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`HarnessSandboxError::MissingField`] if `profile_id` is not
    /// set. Returns [`HarnessSandboxError::DenyByDefaultRequired`] if
    /// `deny_by_default` is false. Returns other [`HarnessSandboxError`]
    /// variants for validation failures.
    pub fn build(self) -> Result<NetworkPolicyProfile, HarnessSandboxError> {
        let profile_id = self
            .profile_id
            .ok_or(HarnessSandboxError::MissingField("profile_id"))?;

        // Validate deny_by_default MUST be true
        if !self.deny_by_default {
            return Err(HarnessSandboxError::DenyByDefaultRequired);
        }

        // Compute profile hash
        let profile_hash = NetworkPolicyProfile::compute_profile_hash(
            &profile_id,
            &self.allowed_egress,
            self.deny_by_default,
        );

        let profile = NetworkPolicyProfile {
            profile_id,
            profile_hash,
            allowed_egress: self.allowed_egress,
            deny_by_default: self.deny_by_default,
        };

        // Validate the complete profile
        profile.validate()?;

        Ok(profile)
    }
}

// =============================================================================
// Proto Message Conversion
// =============================================================================

// Re-export proto types for wire format serialization.
pub use crate::events::{
    EgressRule as EgressRuleProto, NetworkPolicyProfile as NetworkPolicyProfileProto,
    Protocol as ProtocolProto,
};

impl TryFrom<EgressRuleProto> for EgressRule {
    type Error = HarnessSandboxError;

    fn try_from(proto: EgressRuleProto) -> Result<Self, Self::Error> {
        // Validate string length
        if proto.host.len() > MAX_HOST_LENGTH {
            return Err(HarnessSandboxError::StringTooLong {
                field: "host",
                actual: proto.host.len(),
                max: MAX_HOST_LENGTH,
            });
        }

        // Validate port range
        let port = u16::try_from(proto.port).map_err(|_| HarnessSandboxError::PortOutOfRange {
            port: 0,
            min: MIN_PORT,
            max: MAX_PORT,
        })?;

        // Convert protocol
        let protocol = Protocol::try_from(proto.protocol)?;

        let rule = Self {
            host: proto.host,
            port,
            protocol,
        };

        rule.validate()?;
        Ok(rule)
    }
}

impl From<EgressRule> for EgressRuleProto {
    fn from(rule: EgressRule) -> Self {
        Self {
            host: rule.host,
            port: u32::from(rule.port),
            protocol: i32::from(rule.protocol.as_u8()),
        }
    }
}

impl TryFrom<NetworkPolicyProfileProto> for NetworkPolicyProfile {
    type Error = HarnessSandboxError;

    fn try_from(proto: NetworkPolicyProfileProto) -> Result<Self, Self::Error> {
        // Validate string length
        if proto.profile_id.len() > MAX_STRING_LENGTH {
            return Err(HarnessSandboxError::StringTooLong {
                field: "profile_id",
                actual: proto.profile_id.len(),
                max: MAX_STRING_LENGTH,
            });
        }

        // Validate collection size
        if proto.allowed_egress.len() > MAX_EGRESS_RULES {
            return Err(HarnessSandboxError::CollectionTooLarge {
                field: "allowed_egress",
                actual: proto.allowed_egress.len(),
                max: MAX_EGRESS_RULES,
            });
        }

        // Convert profile_hash
        let profile_hash: [u8; 32] = proto.profile_hash.try_into().map_err(|_| {
            HarnessSandboxError::InvalidData("profile_hash must be 32 bytes".to_string())
        })?;

        // Convert egress rules
        let allowed_egress: Vec<EgressRule> = proto
            .allowed_egress
            .into_iter()
            .map(EgressRule::try_from)
            .collect::<Result<_, _>>()?;

        let profile = Self {
            profile_id: proto.profile_id,
            profile_hash,
            allowed_egress,
            deny_by_default: proto.deny_by_default,
        };

        profile.validate()?;
        Ok(profile)
    }
}

impl From<NetworkPolicyProfile> for NetworkPolicyProfileProto {
    fn from(profile: NetworkPolicyProfile) -> Self {
        Self {
            profile_id: profile.profile_id,
            profile_hash: profile.profile_hash.to_vec(),
            allowed_egress: profile.allowed_egress.into_iter().map(Into::into).collect(),
            deny_by_default: profile.deny_by_default,
        }
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
    // Protocol Tests
    // =========================================================================

    #[test]
    fn test_protocol_values() {
        assert_eq!(Protocol::Tcp.as_u8(), 1);
        assert_eq!(Protocol::Udp.as_u8(), 2);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
    }

    #[test]
    fn test_protocol_try_from_u8() {
        assert_eq!(Protocol::try_from(1u8).unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::try_from(2u8).unwrap(), Protocol::Udp);
        assert!(Protocol::try_from(0u8).is_err());
        assert!(Protocol::try_from(3u8).is_err());
    }

    #[test]
    fn test_protocol_try_from_i32() {
        assert_eq!(Protocol::try_from(1i32).unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::try_from(2i32).unwrap(), Protocol::Udp);
        assert!(Protocol::try_from(0i32).is_err());
        assert!(Protocol::try_from(3i32).is_err());
    }

    #[test]
    fn test_protocol_default() {
        assert_eq!(Protocol::default(), Protocol::Tcp);
    }

    #[test]
    fn test_protocol_serde_roundtrip() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let json = serde_json::to_string(&protocol).unwrap();
            let deserialized: Protocol = serde_json::from_str(&json).unwrap();
            assert_eq!(protocol, deserialized);
        }
    }

    // =========================================================================
    // EgressRule Tests
    // =========================================================================

    #[test]
    fn test_egress_rule_valid() {
        let rule = EgressRule {
            host: "registry.npmjs.org".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn test_egress_rule_empty_host() {
        let rule = EgressRule {
            host: String::new(),
            port: 443,
            protocol: Protocol::Tcp,
        };
        assert!(matches!(
            rule.validate(),
            Err(HarnessSandboxError::EmptyHost)
        ));
    }

    #[test]
    fn test_egress_rule_host_too_long() {
        let rule = EgressRule {
            host: "a".repeat(254),
            port: 443,
            protocol: Protocol::Tcp,
        };
        assert!(matches!(
            rule.validate(),
            Err(HarnessSandboxError::StringTooLong { field: "host", .. })
        ));
    }

    #[test]
    fn test_egress_rule_port_zero() {
        let rule = EgressRule {
            host: "example.com".to_string(),
            port: 0,
            protocol: Protocol::Tcp,
        };
        assert!(matches!(
            rule.validate(),
            Err(HarnessSandboxError::PortOutOfRange { .. })
        ));
    }

    #[test]
    fn test_egress_rule_compute_hash_deterministic() {
        let rule = EgressRule {
            host: "example.com".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        };
        let hash1 = rule.compute_hash();
        let hash2 = rule.compute_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_egress_rule_different_hosts_different_hashes() {
        let rule1 = EgressRule {
            host: "example.com".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        };
        let rule2 = EgressRule {
            host: "other.com".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        };
        assert_ne!(rule1.compute_hash(), rule2.compute_hash());
    }

    #[test]
    fn test_egress_rule_serde_roundtrip() {
        let rule = EgressRule {
            host: "registry.npmjs.org".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: EgressRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
    }

    // =========================================================================
    // NetworkPolicyProfile Tests
    // =========================================================================

    fn create_test_egress_rule() -> EgressRule {
        EgressRule {
            host: "registry.npmjs.org".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn test_network_policy_profile_builder_valid() {
        let profile = NetworkPolicyProfileBuilder::new("test-policy")
            .add_egress_rule(create_test_egress_rule())
            .deny_by_default(true)
            .build()
            .unwrap();

        assert_eq!(profile.profile_id, "test-policy");
        assert!(profile.deny_by_default);
        assert_eq!(profile.allowed_egress.len(), 1);
        assert_ne!(profile.profile_hash, [0u8; 32]);
    }

    #[test]
    fn test_network_policy_profile_builder_missing_profile_id() {
        let result = NetworkPolicyProfileBuilder::default()
            .add_egress_rule(create_test_egress_rule())
            .deny_by_default(true)
            .build();

        assert!(matches!(
            result,
            Err(HarnessSandboxError::MissingField("profile_id"))
        ));
    }

    #[test]
    fn test_network_policy_profile_deny_by_default_required() {
        let result = NetworkPolicyProfileBuilder::new("test-policy")
            .add_egress_rule(create_test_egress_rule())
            .deny_by_default(false)
            .build();

        assert!(matches!(
            result,
            Err(HarnessSandboxError::DenyByDefaultRequired)
        ));
    }

    #[test]
    fn test_network_policy_profile_empty_egress_valid() {
        let profile = NetworkPolicyProfileBuilder::new("test-policy")
            .deny_by_default(true)
            .build()
            .unwrap();

        assert!(profile.allowed_egress.is_empty());
        assert!(profile.deny_by_default);
    }

    #[test]
    fn test_network_policy_profile_too_many_rules() {
        let rules: Vec<EgressRule> = (0..=MAX_EGRESS_RULES)
            .map(|i| EgressRule {
                host: format!("host{i}.example.com"),
                port: 443,
                protocol: Protocol::Tcp,
            })
            .collect();

        let result = NetworkPolicyProfileBuilder::new("test-policy")
            .allowed_egress(rules)
            .deny_by_default(true)
            .build();

        assert!(matches!(
            result,
            Err(HarnessSandboxError::CollectionTooLarge {
                field: "allowed_egress",
                ..
            })
        ));
    }

    #[test]
    fn test_network_policy_profile_hash_deterministic() {
        let rules = vec![create_test_egress_rule()];

        let hash1 = NetworkPolicyProfile::compute_profile_hash("test-policy", &rules, true);
        let hash2 = NetworkPolicyProfile::compute_profile_hash("test-policy", &rules, true);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_network_policy_profile_hash_changes_with_rules() {
        let rules1 = vec![EgressRule {
            host: "a.example.com".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        }];
        let rules2 = vec![EgressRule {
            host: "b.example.com".to_string(),
            port: 443,
            protocol: Protocol::Tcp,
        }];

        let hash1 = NetworkPolicyProfile::compute_profile_hash("test-policy", &rules1, true);
        let hash2 = NetworkPolicyProfile::compute_profile_hash("test-policy", &rules2, true);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_network_policy_profile_allows_egress_matching_rule() {
        let profile = NetworkPolicyProfileBuilder::new("test-policy")
            .add_egress_rule(EgressRule {
                host: "example.com".to_string(),
                port: 443,
                protocol: Protocol::Tcp,
            })
            .deny_by_default(true)
            .build()
            .unwrap();

        assert!(profile.allows_egress("example.com", 443, Protocol::Tcp));
    }

    #[test]
    fn test_network_policy_profile_denies_egress_no_matching_rule() {
        let profile = NetworkPolicyProfileBuilder::new("test-policy")
            .add_egress_rule(EgressRule {
                host: "example.com".to_string(),
                port: 443,
                protocol: Protocol::Tcp,
            })
            .deny_by_default(true)
            .build()
            .unwrap();

        // Different host
        assert!(!profile.allows_egress("other.com", 443, Protocol::Tcp));
        // Different port
        assert!(!profile.allows_egress("example.com", 80, Protocol::Tcp));
        // Different protocol
        assert!(!profile.allows_egress("example.com", 443, Protocol::Udp));
    }

    #[test]
    fn test_network_policy_profile_denies_all_when_empty() {
        let profile = NetworkPolicyProfileBuilder::new("test-policy")
            .deny_by_default(true)
            .build()
            .unwrap();

        assert!(!profile.allows_egress("example.com", 443, Protocol::Tcp));
    }

    #[test]
    fn test_network_policy_profile_serde_roundtrip() {
        let profile = NetworkPolicyProfileBuilder::new("test-policy")
            .add_egress_rule(create_test_egress_rule())
            .deny_by_default(true)
            .build()
            .unwrap();

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: NetworkPolicyProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(profile, deserialized);
    }

    #[test]
    fn test_network_policy_profile_validation_invalid_hash() {
        let profile = NetworkPolicyProfile {
            profile_id: "test-policy".to_string(),
            profile_hash: [0u8; 32], // Invalid hash
            allowed_egress: vec![create_test_egress_rule()],
            deny_by_default: true,
        };

        assert!(matches!(
            profile.validate(),
            Err(HarnessSandboxError::InvalidData(_))
        ));
    }

    // =========================================================================
    // Error Display Tests
    // =========================================================================

    #[test]
    fn test_error_display() {
        let err = HarnessSandboxError::EmptyHost;
        assert!(err.to_string().contains("empty"));

        let err = HarnessSandboxError::DenyByDefaultRequired;
        assert!(err.to_string().contains("deny_by_default"));

        let err = HarnessSandboxError::PortOutOfRange {
            port: 0,
            min: 1,
            max: 65535,
        };
        assert!(err.to_string().contains("port"));
    }
}
