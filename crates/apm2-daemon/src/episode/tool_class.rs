//! Tool class enumeration for capability scoping.
//!
//! This module re-exports `ToolClass` from `apm2_core::context` to provide
//! a unified type across both crates. Per AD-TOOL-002, capabilities are sealed
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

// Re-export the canonical ToolClass and ToolClassExt from apm2-core to
// eliminate type duplication. Per Code Quality Review [MINOR]: ToolClass
// canonicalization logic was previously fragmented between crates. The
// canonical definition now lives in apm2-core (TCK-00254).
//
// Also re-export allowlist constants and helpers from apm2-core to eliminate
// duplication (Code Quality Review [MAJOR]). All MAX_*_ALLOWLIST constants
// and shell_pattern_matches are now defined in apm2-core and re-exported here.
pub use apm2_core::context::{
    MAX_SHELL_ALLOWLIST, MAX_SHELL_PATTERN_LEN, MAX_TOOL_ALLOWLIST, MAX_TOOL_CLASS_NAME_LEN,
    MAX_WRITE_ALLOWLIST, ToolClass, ToolClassExt, shell_pattern_matches,
};

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
        assert_eq!(ToolClass::from_u8(7), Some(ToolClass::ListFiles));
        assert_eq!(ToolClass::from_u8(8), Some(ToolClass::Search));
        assert_eq!(ToolClass::from_u8(9), None);
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
        assert_eq!(all.len(), 9);
        assert!(all.contains(&ToolClass::Read));
        assert!(all.contains(&ToolClass::Artifact));
        assert!(all.contains(&ToolClass::ListFiles));
        assert!(all.contains(&ToolClass::Search));
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
