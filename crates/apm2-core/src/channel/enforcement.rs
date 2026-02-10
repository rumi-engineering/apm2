//! Markov-blanket channel enforcement for RFC-0020.
//!
//! Restricts authoritative actuation to typed tool-intent channel events
//! and emits structured defects for boundary violations.

use serde::{Deserialize, Serialize};

/// Maximum string length for channel enforcement detail fields.
pub const MAX_CHANNEL_DETAIL_LENGTH: usize = 512;

/// Channel source classification for actuation boundary enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelSource {
    /// Typed tool-intent channel event (structured, broker-mediated).
    TypedToolIntent,
    /// Free-form model output (unstructured text, non-authoritative).
    FreeFormOutput,
    /// Direct manifest invocation (bypass attempt).
    DirectManifest,
    /// Unknown/missing channel metadata.
    Unknown,
}

/// Channel boundary enforcement result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct ChannelBoundaryCheck {
    /// The classified channel source.
    pub source: ChannelSource,
    /// Whether the source is authorized for actuation.
    pub authorized: bool,
    /// Whether the broker path was verified.
    pub broker_verified: bool,
    /// Whether capability enforcement was verified.
    pub capability_verified: bool,
    /// Whether context-firewall integrity was verified.
    pub context_firewall_verified: bool,
}

/// Channel boundary violation defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelBoundaryDefect {
    /// The type of violation.
    pub violation_class: ChannelViolationClass,
    /// Human-readable detail (bounded to `MAX_CHANNEL_DETAIL_LENGTH`).
    pub detail: String,
}

impl ChannelBoundaryDefect {
    /// Construct a channel boundary defect with bounded detail length.
    #[must_use]
    pub fn new(violation_class: ChannelViolationClass, detail: impl Into<String>) -> Self {
        Self {
            violation_class,
            detail: truncate_channel_detail(detail.into()),
        }
    }
}

/// Classification of channel boundary violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelViolationClass {
    /// Free-form model output attempted to drive authoritative actuation.
    UntypedChannelSource,
    /// Direct manifest invocation bypassing broker.
    BrokerBypassDetected,
    /// Capability enforcement not verified before actuation.
    CapabilityNotVerified,
    /// Context-firewall integrity not verified before actuation.
    ContextFirewallNotVerified,
    /// Channel metadata missing or malformed.
    MissingChannelMetadata,
    /// Channel source unknown or unclassifiable.
    UnknownChannelSource,
}

/// Validate that a channel boundary check satisfies actuation requirements.
///
/// Returns defects for any violations found. Empty vec = authorized.
/// Fail-closed: any missing/ambiguous check results in a defect.
#[must_use]
pub fn validate_channel_boundary(check: &ChannelBoundaryCheck) -> Vec<ChannelBoundaryDefect> {
    let mut defects = Vec::new();

    match check.source {
        ChannelSource::TypedToolIntent => {},
        ChannelSource::FreeFormOutput => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::UntypedChannelSource,
            "free-form model output cannot drive authoritative actuation",
        )),
        ChannelSource::DirectManifest => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::BrokerBypassDetected,
            "direct manifest invocation is a broker bypass",
        )),
        ChannelSource::Unknown => defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::UnknownChannelSource,
            "channel source is unknown or unclassifiable",
        )),
    }

    if !check.broker_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::BrokerBypassDetected,
            "broker path was not verified",
        ));
    }

    if !check.capability_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::CapabilityNotVerified,
            "capability enforcement was not verified",
        ));
    }

    if !check.context_firewall_verified {
        defects.push(ChannelBoundaryDefect::new(
            ChannelViolationClass::ContextFirewallNotVerified,
            "context-firewall integrity was not verified",
        ));
    }

    defects
}

fn truncate_channel_detail(mut detail: String) -> String {
    if detail.len() <= MAX_CHANNEL_DETAIL_LENGTH {
        return detail;
    }

    let mut boundary = MAX_CHANNEL_DETAIL_LENGTH;
    while !detail.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    detail.truncate(boundary);
    detail
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_check() -> ChannelBoundaryCheck {
        ChannelBoundaryCheck {
            source: ChannelSource::TypedToolIntent,
            authorized: true,
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
        }
    }

    #[test]
    fn test_typed_tool_intent_all_verified_passes() {
        let check = baseline_check();
        let defects = validate_channel_boundary(&check);
        assert!(defects.is_empty());
    }

    #[test]
    fn test_freeform_output_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::FreeFormOutput;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::UntypedChannelSource
        );
    }

    #[test]
    fn test_direct_manifest_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::DirectManifest;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::BrokerBypassDetected
        );
    }

    #[test]
    fn test_unknown_source_denied() {
        let mut check = baseline_check();
        check.source = ChannelSource::Unknown;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::UnknownChannelSource
        );
    }

    #[test]
    fn test_broker_not_verified_denied() {
        let mut check = baseline_check();
        check.broker_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::BrokerBypassDetected
        );
    }

    #[test]
    fn test_capability_not_verified_denied() {
        let mut check = baseline_check();
        check.capability_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::CapabilityNotVerified
        );
    }

    #[test]
    fn test_context_firewall_not_verified_denied() {
        let mut check = baseline_check();
        check.context_firewall_verified = false;
        let defects = validate_channel_boundary(&check);
        assert_eq!(defects.len(), 1);
        assert_eq!(
            defects[0].violation_class,
            ChannelViolationClass::ContextFirewallNotVerified
        );
    }

    #[test]
    fn test_multiple_violations_emitted() {
        let check = ChannelBoundaryCheck {
            source: ChannelSource::FreeFormOutput,
            authorized: false,
            broker_verified: false,
            capability_verified: false,
            context_firewall_verified: false,
        };

        let defects = validate_channel_boundary(&check);
        let classes: Vec<ChannelViolationClass> = defects
            .iter()
            .map(|defect| defect.violation_class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ChannelViolationClass::UntypedChannelSource,
                ChannelViolationClass::BrokerBypassDetected,
                ChannelViolationClass::CapabilityNotVerified,
                ChannelViolationClass::ContextFirewallNotVerified,
            ]
        );
    }

    #[test]
    fn test_channel_defect_serialization() {
        let detail = "a".repeat(MAX_CHANNEL_DETAIL_LENGTH + 32);
        let defect =
            ChannelBoundaryDefect::new(ChannelViolationClass::CapabilityNotVerified, detail);
        assert_eq!(defect.detail.len(), MAX_CHANNEL_DETAIL_LENGTH);

        let json = serde_json::to_string(&defect).expect("defect should serialize");
        let decoded: ChannelBoundaryDefect =
            serde_json::from_str(&json).expect("defect should deserialize");
        assert_eq!(decoded, defect);
    }
}
