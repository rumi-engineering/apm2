//! Tool class enumeration for capability scoping.
//!
//! This module defines the `ToolClass` enum that categorizes tool types
//! for capability matching. Per AD-TOOL-002, capabilities are sealed
//! references to specific tool classes with scoped parameters.
//!
//! # Architecture
//!
//! Tool classes form a taxonomy that enables:
//! - Coarse-grained capability grants (e.g., "Read" covers all file reads)
//! - Fine-grained scope restriction (e.g., Read within `/workspace/**`)
//! - Default-deny evaluation (no capability = denied)
//!
//! # Contract References
//!
//! - AD-TOOL-002: Capability manifests as sealed references
//! - REQ-TOOL-001: Tool access control requirements

use std::fmt;

use prost::Message;
use serde::{Deserialize, Serialize};

/// Maximum string length for tool class names during parsing.
pub const MAX_TOOL_CLASS_NAME_LEN: usize = 64;

/// Tool class for capability categorization.
///
/// Per AD-TOOL-002, tool classes define the coarse-grained category of
/// operations a capability allows. Fine-grained restrictions are applied
/// via `CapabilityScope`.
///
/// # Discriminant Stability
///
/// Explicit discriminant values maintain semver compatibility. New variants
/// must use new values; existing values must not change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[non_exhaustive]
pub enum ToolClass {
    /// Read operations: file reads, directory listings, git status.
    #[default]
    Read      = 0,

    /// Write operations: file writes, file edits, file deletions.
    Write     = 1,

    /// Execute operations: shell commands, process spawning.
    Execute   = 2,

    /// Network operations: HTTP requests, socket connections.
    Network   = 3,

    /// Git operations: commits, pushes, branch operations.
    Git       = 4,

    /// Inference operations: LLM API calls.
    Inference = 5,

    /// Artifact operations: CAS publish/fetch.
    Artifact  = 6,
}

impl ToolClass {
    /// Returns the numeric value of this tool class.
    #[must_use]
    pub const fn value(&self) -> u8 {
        *self as u8
    }

    /// Parses a tool class from a u8 value.
    ///
    /// # Returns
    ///
    /// `None` if the value does not correspond to a known tool class.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Execute),
            3 => Some(Self::Network),
            4 => Some(Self::Git),
            5 => Some(Self::Inference),
            6 => Some(Self::Artifact),
            _ => None,
        }
    }

    /// Parses a tool class from a u32 value.
    ///
    /// # Security
    ///
    /// This method validates the full u32 range to prevent truncation attacks.
    /// Casting to u8 first would truncate values like 256 to 0, potentially
    /// granting unintended capabilities.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Execute),
            3 => Some(Self::Network),
            4 => Some(Self::Git),
            5 => Some(Self::Inference),
            6 => Some(Self::Artifact),
            _ => None,
        }
    }

    /// Parses a tool class from a string name.
    ///
    /// # Security
    ///
    /// Rejects names longer than `MAX_TOOL_CLASS_NAME_LEN` to prevent
    /// memory exhaustion attacks.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() > MAX_TOOL_CLASS_NAME_LEN {
            return None;
        }
        match s.to_lowercase().as_str() {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "execute" | "exec" => Some(Self::Execute),
            "network" | "net" => Some(Self::Network),
            "git" => Some(Self::Git),
            "inference" | "llm" => Some(Self::Inference),
            "artifact" | "cas" => Some(Self::Artifact),
            _ => None,
        }
    }

    /// Returns the canonical name of this tool class.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Write => "Write",
            Self::Execute => "Execute",
            Self::Network => "Network",
            Self::Git => "Git",
            Self::Inference => "Inference",
            Self::Artifact => "Artifact",
        }
    }

    /// Returns `true` if this tool class represents read-only operations.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Self::Read)
    }

    /// Returns `true` if this tool class can modify state.
    #[must_use]
    pub const fn can_mutate(&self) -> bool {
        matches!(
            self,
            Self::Write | Self::Execute | Self::Git | Self::Artifact
        )
    }

    /// Returns `true` if this tool class involves network access.
    #[must_use]
    pub const fn involves_network(&self) -> bool {
        matches!(self, Self::Network | Self::Inference)
    }

    /// Returns all known tool classes.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Read,
            Self::Write,
            Self::Execute,
            Self::Network,
            Self::Git,
            Self::Inference,
            Self::Artifact,
        ]
    }
}

impl fmt::Display for ToolClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Internal protobuf representation for `ToolClass`.
#[derive(Clone, PartialEq, Message)]
struct ToolClassProto {
    #[prost(uint32, optional, tag = "1")]
    value: Option<u32>,
}

impl ToolClass {
    /// Returns the canonical bytes for this tool class.
    ///
    /// Per AD-VERIFY-001, this provides deterministic serialization
    /// for use in digests and signatures.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let proto = ToolClassProto {
            value: Some(u32::from(self.value())),
        };
        proto.encode_to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u8() {
        assert_eq!(ToolClass::from_u8(0), Some(ToolClass::Read));
        assert_eq!(ToolClass::from_u8(1), Some(ToolClass::Write));
        assert_eq!(ToolClass::from_u8(2), Some(ToolClass::Execute));
        assert_eq!(ToolClass::from_u8(3), Some(ToolClass::Network));
        assert_eq!(ToolClass::from_u8(4), Some(ToolClass::Git));
        assert_eq!(ToolClass::from_u8(5), Some(ToolClass::Inference));
        assert_eq!(ToolClass::from_u8(6), Some(ToolClass::Artifact));
        assert_eq!(ToolClass::from_u8(7), None);
        assert_eq!(ToolClass::from_u8(255), None);
    }

    #[test]
    fn test_from_u32_truncation_prevention() {
        // Ensure values > 255 are not truncated to valid values
        assert_eq!(ToolClass::from_u32(256), None); // Would truncate to 0
        assert_eq!(ToolClass::from_u32(257), None); // Would truncate to 1
        assert_eq!(ToolClass::from_u32(u32::MAX), None);
    }

    #[test]
    fn test_parse() {
        assert_eq!(ToolClass::parse("read"), Some(ToolClass::Read));
        assert_eq!(ToolClass::parse("READ"), Some(ToolClass::Read));
        assert_eq!(ToolClass::parse("Write"), Some(ToolClass::Write));
        assert_eq!(ToolClass::parse("execute"), Some(ToolClass::Execute));
        assert_eq!(ToolClass::parse("exec"), Some(ToolClass::Execute));
        assert_eq!(ToolClass::parse("network"), Some(ToolClass::Network));
        assert_eq!(ToolClass::parse("net"), Some(ToolClass::Network));
        assert_eq!(ToolClass::parse("git"), Some(ToolClass::Git));
        assert_eq!(ToolClass::parse("inference"), Some(ToolClass::Inference));
        assert_eq!(ToolClass::parse("llm"), Some(ToolClass::Inference));
        assert_eq!(ToolClass::parse("artifact"), Some(ToolClass::Artifact));
        assert_eq!(ToolClass::parse("cas"), Some(ToolClass::Artifact));
        assert_eq!(ToolClass::parse("unknown"), None);
    }

    #[test]
    fn test_parse_length_limit() {
        let long_name = "a".repeat(MAX_TOOL_CLASS_NAME_LEN + 1);
        assert_eq!(ToolClass::parse(&long_name), None);

        let max_name = "a".repeat(MAX_TOOL_CLASS_NAME_LEN);
        // Valid length but unknown name
        assert_eq!(ToolClass::parse(&max_name), None);
    }

    #[test]
    fn test_properties() {
        assert!(ToolClass::Read.is_read_only());
        assert!(!ToolClass::Write.is_read_only());

        assert!(!ToolClass::Read.can_mutate());
        assert!(ToolClass::Write.can_mutate());
        assert!(ToolClass::Execute.can_mutate());
        assert!(ToolClass::Git.can_mutate());

        assert!(!ToolClass::Read.involves_network());
        assert!(ToolClass::Network.involves_network());
        assert!(ToolClass::Inference.involves_network());
    }

    #[test]
    fn test_canonical_bytes_determinism() {
        let class = ToolClass::Execute;
        let bytes1 = class.canonical_bytes();
        let bytes2 = class.canonical_bytes();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", ToolClass::Read), "Read");
        assert_eq!(format!("{}", ToolClass::Write), "Write");
        assert_eq!(format!("{}", ToolClass::Execute), "Execute");
    }

    #[test]
    fn test_all_classes() {
        let all = ToolClass::all();
        assert_eq!(all.len(), 7);
        assert!(all.contains(&ToolClass::Read));
        assert!(all.contains(&ToolClass::Artifact));
    }

    #[test]
    fn test_roundtrip() {
        for class in ToolClass::all() {
            let value = class.value();
            assert_eq!(ToolClass::from_u8(value), Some(*class));
            assert_eq!(ToolClass::from_u32(u32::from(value)), Some(*class));
        }
    }
}
