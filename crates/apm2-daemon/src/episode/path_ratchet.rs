// AGENT-AUTHORED
//! No-bypass path ratchet enforcement (TCK-00376).
//!
//! This module implements the `PathRatchet` which ensures that **every** tool
//! actuation path passes through all required enforcement components before
//! execution is permitted. No manifest-only or non-broker bypass paths exist.
//!
//! # Enforcement Components
//!
//! The ratchet requires four enforcement components for a tool actuation to
//! proceed:
//!
//! 1. **Broker authorization**: The `ToolBroker` must validate the request.
//! 2. **Capability manifest**: A capability manifest must be loaded and the
//!    request validated against it.
//! 3. **Context firewall**: A `ContextPackManifest` must be loaded for firewall
//!    enforcement.
//! 4. **Capsule profile admission**: The `AdmissionGate` must admit the capsule
//!    profile (Tier3+). **Note**: Runtime capsule admission is not yet wired
//!    into the broker; it is currently reported as `Unavailable`. The
//!    `AdmissionGate` itself is validated in TCK-00374 unit tests. When runtime
//!    wiring lands, the broker will set this to `Checked`/`Unavailable` based
//!    on actual capsule presence.
//!
//! # Tier Enforcement
//!
//! - **Tier2+**: Broker, capability, and context-firewall enforcement are
//!   **mandatory**. If any of these components is unavailable or unchecked, the
//!   ratchet returns a deny-default decision. This is fail-closed behavior.
//! - **Tier3+**: Capsule containment is **mandatory** in addition to all Tier2
//!   requirements. Per REQ-0028, Tier3+ actuation must execute within admitted
//!   capsule profiles.
//! - **Tier0-1**: Enforcement components are **recommended** but not mandatory.
//!   Missing components produce warnings but do not block actuation.
//! - **Tier2 capsule**: Capsule unavailable produces a warning, not denial.
//!
//! # Security Properties
//!
//! - [INV-RATCHET-001] No actuation path bypasses broker and policy checks
//! - [INV-RATCHET-002] Unavailable enforcement dependency causes deny at Tier2+
//!   (capsule at Tier3+ per REQ-0028)
//! - [INV-RATCHET-003] Regression tests prevent bypass reintroduction
//!
//! # Contract References
//!
//! - TCK-00376: No-bypass path ratchet enforcement
//! - REQ-0030: All actuation paths must pass through enforcement gates
//! - TCK-00374: Capsule profile admission
//! - TCK-00375: Context firewall TOCTOU hash enforcement

use std::fmt;

use super::envelope::RiskTier;

// =============================================================================
// Constants
// =============================================================================

/// Maximum length for a denial reason string (`DoS` bound).
const MAX_DENIAL_REASON_LEN: usize = 1024;

/// The tier threshold at which broker, capability, and context-firewall
/// enforcement components become mandatory.
/// Tier2 (value 2) and above require these components.
const MANDATORY_ENFORCEMENT_TIER: u8 = 2;

/// The tier threshold at which capsule containment becomes mandatory.
/// Per REQ-0028, Tier3+ actuation MUST execute within admitted capsule
/// profiles. Tier2 produces a warning but does not deny.
const CAPSULE_MANDATORY_ENFORCEMENT_TIER: u8 = 3;

// =============================================================================
// EnforcementStatus
// =============================================================================

/// Status of a single enforcement component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementStatus {
    /// Component is available and has been checked.
    Checked,
    /// Component is available but not yet checked (should not reach ratchet).
    Available,
    /// Component is unavailable (not loaded or not configured).
    Unavailable,
}

impl EnforcementStatus {
    /// Returns `true` if the component has been checked.
    #[must_use]
    pub const fn is_checked(&self) -> bool {
        matches!(self, Self::Checked)
    }

    /// Returns `true` if the component is unavailable.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

impl fmt::Display for EnforcementStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checked => write!(f, "CHECKED"),
            Self::Available => write!(f, "AVAILABLE"),
            Self::Unavailable => write!(f, "UNAVAILABLE"),
        }
    }
}

// =============================================================================
// PathRatchetError
// =============================================================================

/// Errors from path ratchet enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathRatchetError {
    /// A required enforcement component is unavailable at this tier.
    ComponentUnavailable {
        /// The component that is unavailable.
        component: &'static str,
        /// The risk tier that requires this component.
        risk_tier: u8,
    },

    /// A required enforcement component was not checked before actuation.
    ComponentNotChecked {
        /// The component that was not checked.
        component: &'static str,
        /// The risk tier requiring the check.
        risk_tier: u8,
    },

    /// Broker authorization is required but not initialized.
    BrokerNotInitialized,

    /// Capability manifest is not loaded.
    CapabilityManifestMissing {
        /// The risk tier that requires the manifest.
        risk_tier: u8,
    },

    /// Context firewall manifest is not loaded.
    ContextFirewallMissing {
        /// The risk tier that requires the firewall.
        risk_tier: u8,
    },

    /// Capsule profile admission is required but no profile is present.
    CapsuleProfileMissing {
        /// The risk tier that requires admission.
        risk_tier: u8,
    },
}

impl fmt::Display for PathRatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComponentUnavailable {
                component,
                risk_tier,
            } => {
                write!(
                    f,
                    "path ratchet denied: enforcement component '{component}' \
                     unavailable at tier {risk_tier} (mandatory for tier >= {MANDATORY_ENFORCEMENT_TIER})"
                )
            },
            Self::ComponentNotChecked {
                component,
                risk_tier,
            } => {
                write!(
                    f,
                    "path ratchet denied: enforcement component '{component}' \
                     not checked before actuation at tier {risk_tier}"
                )
            },
            Self::BrokerNotInitialized => {
                write!(
                    f,
                    "path ratchet denied: broker not initialized (all tiers require broker)"
                )
            },
            Self::CapabilityManifestMissing { risk_tier } => {
                write!(
                    f,
                    "path ratchet denied: capability manifest not loaded at tier {risk_tier} \
                     (mandatory for tier >= {MANDATORY_ENFORCEMENT_TIER})"
                )
            },
            Self::ContextFirewallMissing { risk_tier } => {
                write!(
                    f,
                    "path ratchet denied: context firewall manifest not loaded at tier {risk_tier} \
                     (mandatory for tier >= {MANDATORY_ENFORCEMENT_TIER})"
                )
            },
            Self::CapsuleProfileMissing { risk_tier } => {
                write!(
                    f,
                    "path ratchet denied: capsule profile not present at tier {risk_tier} \
                     (mandatory for tier >= {CAPSULE_MANDATORY_ENFORCEMENT_TIER})"
                )
            },
        }
    }
}

impl PathRatchetError {
    /// Returns `true` if this error is a context-firewall denial
    /// (either missing manifest or unchecked status for the context
    /// firewall component).
    #[must_use]
    pub fn is_context_firewall_denial(&self) -> bool {
        match self {
            Self::ContextFirewallMissing { .. } => true,
            Self::ComponentNotChecked { component, .. } => *component == "context_firewall",
            _ => false,
        }
    }

    /// Returns the risk tier associated with this error, if applicable.
    #[must_use]
    pub const fn risk_tier(&self) -> Option<u8> {
        match self {
            Self::ComponentUnavailable { risk_tier, .. }
            | Self::ComponentNotChecked { risk_tier, .. }
            | Self::CapabilityManifestMissing { risk_tier }
            | Self::ContextFirewallMissing { risk_tier }
            | Self::CapsuleProfileMissing { risk_tier } => Some(*risk_tier),
            Self::BrokerNotInitialized => None,
        }
    }
}

impl std::error::Error for PathRatchetError {}

// =============================================================================
// PathRatchetInput
// =============================================================================

/// Input for a path ratchet check, capturing the status of each enforcement
/// component at the time of the actuation request.
///
/// This struct is populated by the broker before calling
/// [`PathRatchet::enforce`]. Each field indicates whether the corresponding
/// enforcement component is available and has been checked.
#[derive(Debug, Clone)]
pub struct PathRatchetInput {
    /// Risk tier of the current request.
    pub risk_tier: RiskTier,

    /// Whether the broker is initialized and has processed this request.
    pub broker_checked: bool,

    /// Status of the capability manifest.
    pub capability_status: EnforcementStatus,

    /// Status of the context firewall manifest.
    pub context_firewall_status: EnforcementStatus,

    /// Status of the capsule profile admission.
    pub capsule_admission_status: EnforcementStatus,
}

// =============================================================================
// PathRatchetOutcome
// =============================================================================

/// Outcome of a path ratchet enforcement check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum PathRatchetOutcome {
    /// All enforcement components passed. Actuation may proceed.
    Allowed,

    /// Actuation is allowed but with warnings about missing optional
    /// components (Tier0-1 only).
    AllowedWithWarnings {
        /// Warning messages for missing components.
        warnings: Vec<String>,
    },

    /// Actuation is denied because a required enforcement component is
    /// missing or unchecked.
    Denied {
        /// The denial error.
        error: PathRatchetError,
    },
}

impl PathRatchetOutcome {
    /// Returns `true` if actuation is allowed (with or without warnings).
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedWithWarnings { .. })
    }

    /// Returns `true` if actuation is denied.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }
}

// =============================================================================
// PathRatchet
// =============================================================================

/// No-bypass path ratchet enforcing all required checks before tool actuation.
///
/// The ratchet is a stateless checkpoint that verifies all enforcement
/// components have been satisfied before allowing tool execution to proceed.
/// It does not itself perform the checks; rather, it verifies that the checks
/// have been performed by their respective owners.
///
/// # Usage
///
/// ```rust,ignore
/// let ratchet = PathRatchet::new();
/// let input = PathRatchetInput {
///     risk_tier: RiskTier::Tier2,
///     broker_checked: true,
///     capability_status: EnforcementStatus::Checked,
///     context_firewall_status: EnforcementStatus::Checked,
///     capsule_admission_status: EnforcementStatus::Checked,
/// };
/// let outcome = ratchet.enforce(&input);
/// assert!(outcome.is_allowed());
/// ```
pub struct PathRatchet {
    _private: (),
}

impl PathRatchet {
    /// Creates a new path ratchet.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Enforces the path ratchet against the given input.
    ///
    /// Returns [`PathRatchetOutcome::Allowed`] only if all required
    /// enforcement components for the given risk tier have been satisfied.
    ///
    /// # Tier Behavior
    ///
    /// - **Tier0-1**: Missing components produce warnings but allow actuation.
    /// - **Tier2+**: Missing broker/capability/context-firewall produces deny.
    /// - **Tier3+**: Missing capsule profile also produces deny (REQ-0028).
    ///
    /// # All Tiers
    ///
    /// The broker must always be initialized. Broker authorization is required
    /// at every tier because it is the single entry point for tool mediation.
    pub fn enforce(&self, input: &PathRatchetInput) -> PathRatchetOutcome {
        let tier_value = input.risk_tier.tier();
        let is_mandatory = tier_value >= MANDATORY_ENFORCEMENT_TIER;
        let capsule_mandatory = tier_value >= CAPSULE_MANDATORY_ENFORCEMENT_TIER;

        // Broker is ALWAYS required (all tiers)
        if !input.broker_checked {
            return PathRatchetOutcome::Denied {
                error: PathRatchetError::BrokerNotInitialized,
            };
        }

        // Capability manifest check
        if input.capability_status.is_unavailable() {
            if is_mandatory {
                return PathRatchetOutcome::Denied {
                    error: PathRatchetError::CapabilityManifestMissing {
                        risk_tier: tier_value,
                    },
                };
            }
        } else if !input.capability_status.is_checked() && is_mandatory {
            return PathRatchetOutcome::Denied {
                error: PathRatchetError::ComponentNotChecked {
                    component: "capability_manifest",
                    risk_tier: tier_value,
                },
            };
        }

        // Context firewall check
        if input.context_firewall_status.is_unavailable() {
            if is_mandatory {
                return PathRatchetOutcome::Denied {
                    error: PathRatchetError::ContextFirewallMissing {
                        risk_tier: tier_value,
                    },
                };
            }
        } else if !input.context_firewall_status.is_checked() && is_mandatory {
            return PathRatchetOutcome::Denied {
                error: PathRatchetError::ComponentNotChecked {
                    component: "context_firewall",
                    risk_tier: tier_value,
                },
            };
        }

        // Capsule admission check — mandatory at Tier3+ per REQ-0028
        if input.capsule_admission_status.is_unavailable() {
            if capsule_mandatory {
                return PathRatchetOutcome::Denied {
                    error: PathRatchetError::CapsuleProfileMissing {
                        risk_tier: tier_value,
                    },
                };
            }
        } else if !input.capsule_admission_status.is_checked() && capsule_mandatory {
            return PathRatchetOutcome::Denied {
                error: PathRatchetError::ComponentNotChecked {
                    component: "capsule_admission",
                    risk_tier: tier_value,
                },
            };
        }

        // For tiers below mandatory threshold, collect warnings for unavailable
        // components. Also collect capsule warnings for Tier2 (below capsule
        // threshold but above the base mandatory threshold).
        let mut warnings = Vec::new();

        if !is_mandatory {
            if input.capability_status.is_unavailable() {
                let mut msg = format!(
                    "capability manifest unavailable at tier {tier_value}; \
                     enforcement is optional but recommended"
                );
                msg.truncate(MAX_DENIAL_REASON_LEN);
                warnings.push(msg);
            }
            if input.context_firewall_status.is_unavailable() {
                let mut msg = format!(
                    "context firewall manifest unavailable at tier {tier_value}; \
                     enforcement is optional but recommended"
                );
                msg.truncate(MAX_DENIAL_REASON_LEN);
                warnings.push(msg);
            }
        }

        // Capsule warning for tiers below capsule threshold (Tier0-2)
        if !capsule_mandatory && input.capsule_admission_status.is_unavailable() {
            let mut msg = format!(
                "capsule profile unavailable at tier {tier_value}; \
                 enforcement is optional but recommended (mandatory at tier >= {CAPSULE_MANDATORY_ENFORCEMENT_TIER})"
            );
            msg.truncate(MAX_DENIAL_REASON_LEN);
            warnings.push(msg);
        }

        if warnings.is_empty() {
            PathRatchetOutcome::Allowed
        } else {
            PathRatchetOutcome::AllowedWithWarnings { warnings }
        }
    }
}

impl Default for PathRatchet {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    fn ratchet() -> PathRatchet {
        PathRatchet::new()
    }

    fn all_checked_input(tier: RiskTier) -> PathRatchetInput {
        PathRatchetInput {
            risk_tier: tier,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        }
    }

    // =========================================================================
    // Broker Always Required
    // =========================================================================

    #[test]
    fn test_actuation_without_broker_denied_tier0() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier0,
            broker_checked: false,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied(), "broker required at all tiers");
        assert_eq!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::BrokerNotInitialized,
            }
        );
    }

    #[test]
    fn test_actuation_without_broker_denied_tier2() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier2,
            broker_checked: false,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::BrokerNotInitialized,
            }
        ));
    }

    #[test]
    fn test_actuation_without_broker_denied_tier4() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier4,
            broker_checked: false,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
    }

    // =========================================================================
    // Capability Manifest
    // =========================================================================

    #[test]
    fn test_actuation_without_capability_denied_tier2() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier2,
            broker_checked: true,
            capability_status: EnforcementStatus::Unavailable,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::CapabilityManifestMissing { risk_tier: 2 },
            }
        ));
    }

    #[test]
    fn test_actuation_without_capability_allowed_with_warning_tier0() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier0,
            broker_checked: true,
            capability_status: EnforcementStatus::Unavailable,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_allowed());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::AllowedWithWarnings { .. }
        ));
    }

    // =========================================================================
    // Context Firewall
    // =========================================================================

    #[test]
    fn test_actuation_without_context_firewall_denied_tier2() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier2,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Unavailable,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::ContextFirewallMissing { risk_tier: 2 },
            }
        ));
    }

    #[test]
    fn test_actuation_without_context_firewall_denied_tier3() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier3,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Unavailable,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::ContextFirewallMissing { risk_tier: 3 },
            }
        ));
    }

    #[test]
    fn test_actuation_without_context_firewall_allowed_with_warning_tier1() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier1,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Unavailable,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_allowed());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::AllowedWithWarnings { .. }
        ));
    }

    // =========================================================================
    // Capsule Profile Admission
    // =========================================================================

    /// Per REQ-0028, capsule is mandatory at Tier3+, not Tier2.
    /// Tier2 with capsule unavailable should be allowed with a warning.
    #[test]
    fn test_actuation_without_capsule_profile_allowed_with_warning_tier2() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier2,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Unavailable,
        };
        let outcome = r.enforce(&input);
        assert!(
            outcome.is_allowed(),
            "Tier2 capsule unavailable should be allowed with warning, got: {outcome:?}"
        );
        assert!(matches!(
            outcome,
            PathRatchetOutcome::AllowedWithWarnings { .. }
        ));
        if let PathRatchetOutcome::AllowedWithWarnings { warnings } = &outcome {
            assert!(
                warnings.iter().any(|w| w.contains("capsule")),
                "warning must mention capsule: {warnings:?}"
            );
        }
    }

    /// Per REQ-0028, capsule is mandatory at Tier3+. Tier3 with capsule
    /// unavailable must be denied (fail-closed).
    #[test]
    fn test_actuation_without_capsule_profile_denied_tier3() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier3,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Unavailable,
        };
        let outcome = r.enforce(&input);
        assert!(
            outcome.is_denied(),
            "Tier3 capsule unavailable must be denied"
        );
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::CapsuleProfileMissing { risk_tier: 3 },
            }
        ));
    }

    #[test]
    fn test_actuation_without_capsule_profile_allowed_with_warning_tier0() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier0,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Unavailable,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_allowed());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::AllowedWithWarnings { .. }
        ));
    }

    // =========================================================================
    // All Checks Pass
    // =========================================================================

    #[test]
    fn test_all_checks_pass_tier0() {
        let r = ratchet();
        let outcome = r.enforce(&all_checked_input(RiskTier::Tier0));
        assert_eq!(outcome, PathRatchetOutcome::Allowed);
    }

    #[test]
    fn test_all_checks_pass_tier2() {
        let r = ratchet();
        let outcome = r.enforce(&all_checked_input(RiskTier::Tier2));
        assert_eq!(outcome, PathRatchetOutcome::Allowed);
    }

    #[test]
    fn test_all_checks_pass_tier3() {
        let r = ratchet();
        let outcome = r.enforce(&all_checked_input(RiskTier::Tier3));
        assert_eq!(outcome, PathRatchetOutcome::Allowed);
    }

    #[test]
    fn test_all_checks_pass_tier4() {
        let r = ratchet();
        let outcome = r.enforce(&all_checked_input(RiskTier::Tier4));
        assert_eq!(outcome, PathRatchetOutcome::Allowed);
    }

    // =========================================================================
    // Enforcement Component Unavailable at Tier2 → Denied
    // =========================================================================

    #[test]
    fn test_all_components_unavailable_tier2_denied() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier2,
            broker_checked: true,
            capability_status: EnforcementStatus::Unavailable,
            context_firewall_status: EnforcementStatus::Unavailable,
            capsule_admission_status: EnforcementStatus::Unavailable,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        // First missing component is capability
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::CapabilityManifestMissing { risk_tier: 2 },
            }
        ));
    }

    // =========================================================================
    // Enforcement Component Unavailable at Tier0 → Allowed with Warnings
    // =========================================================================

    #[test]
    fn test_all_components_unavailable_tier0_allowed_with_warnings() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier0,
            broker_checked: true,
            capability_status: EnforcementStatus::Unavailable,
            context_firewall_status: EnforcementStatus::Unavailable,
            capsule_admission_status: EnforcementStatus::Unavailable,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_allowed());
        if let PathRatchetOutcome::AllowedWithWarnings { warnings } = &outcome {
            assert_eq!(
                warnings.len(),
                3,
                "should have 3 warnings for 3 missing components"
            );
            assert!(warnings[0].contains("capability manifest"));
            assert!(warnings[1].contains("context firewall"));
            assert!(warnings[2].contains("capsule profile"));
        } else {
            panic!("expected AllowedWithWarnings, got: {outcome:?}");
        }
    }

    #[test]
    fn test_all_components_unavailable_tier1_allowed_with_warnings() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier1,
            broker_checked: true,
            capability_status: EnforcementStatus::Unavailable,
            context_firewall_status: EnforcementStatus::Unavailable,
            capsule_admission_status: EnforcementStatus::Unavailable,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_allowed());
        if let PathRatchetOutcome::AllowedWithWarnings { warnings } = &outcome {
            assert_eq!(warnings.len(), 3);
        } else {
            panic!("expected AllowedWithWarnings");
        }
    }

    // =========================================================================
    // Component Not-Checked at Tier2+ → Denied
    // =========================================================================

    #[test]
    fn test_capability_available_but_not_checked_tier2_denied() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier2,
            broker_checked: true,
            capability_status: EnforcementStatus::Available,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::ComponentNotChecked {
                    component: "capability_manifest",
                    risk_tier: 2,
                },
            }
        ));
    }

    #[test]
    fn test_context_firewall_available_but_not_checked_tier3_denied() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier3,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Available,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::ComponentNotChecked {
                    component: "context_firewall",
                    risk_tier: 3,
                },
            }
        ));
    }

    #[test]
    fn test_capsule_available_but_not_checked_tier4_denied() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier4,
            broker_checked: true,
            capability_status: EnforcementStatus::Checked,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Available,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_denied());
        assert!(matches!(
            outcome,
            PathRatchetOutcome::Denied {
                error: PathRatchetError::ComponentNotChecked {
                    component: "capsule_admission",
                    risk_tier: 4,
                },
            }
        ));
    }

    // =========================================================================
    // Tier Boundary Tests
    // =========================================================================

    #[test]
    fn test_tier1_is_not_mandatory() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier1,
            broker_checked: true,
            capability_status: EnforcementStatus::Unavailable,
            context_firewall_status: EnforcementStatus::Unavailable,
            capsule_admission_status: EnforcementStatus::Unavailable,
        };
        let outcome = r.enforce(&input);
        assert!(outcome.is_allowed(), "Tier1 should allow with warnings");
    }

    #[test]
    fn test_tier2_is_mandatory() {
        let r = ratchet();
        let input = PathRatchetInput {
            risk_tier: RiskTier::Tier2,
            broker_checked: true,
            capability_status: EnforcementStatus::Unavailable,
            context_firewall_status: EnforcementStatus::Checked,
            capsule_admission_status: EnforcementStatus::Checked,
        };
        let outcome = r.enforce(&input);
        assert!(
            outcome.is_denied(),
            "Tier2 should deny when capability unavailable"
        );
    }

    // =========================================================================
    // Display / Error Formatting
    // =========================================================================

    #[test]
    fn test_error_display_formatting() {
        let err = PathRatchetError::BrokerNotInitialized;
        let msg = format!("{err}");
        assert!(msg.contains("broker not initialized"));

        let err = PathRatchetError::ContextFirewallMissing { risk_tier: 3 };
        let msg = format!("{err}");
        assert!(msg.contains("context firewall"));
        assert!(msg.contains("tier 3"));

        let err = PathRatchetError::ComponentNotChecked {
            component: "test_component",
            risk_tier: 2,
        };
        let msg = format!("{err}");
        assert!(msg.contains("test_component"));
        assert!(msg.contains("not checked"));
    }

    #[test]
    fn test_enforcement_status_display() {
        assert_eq!(format!("{}", EnforcementStatus::Checked), "CHECKED");
        assert_eq!(format!("{}", EnforcementStatus::Available), "AVAILABLE");
        assert_eq!(format!("{}", EnforcementStatus::Unavailable), "UNAVAILABLE");
    }

    // =========================================================================
    // Regression: Bypass Reintroduction Prevention
    // =========================================================================

    /// Regression test: Verify that EVERY combination of tier >= 2 with a
    /// single missing enforcement component is denied (capsule at Tier3+).
    /// This prevents future code changes from accidentally re-introducing
    /// bypass paths.
    #[test]
    fn test_regression_no_bypass_at_mandatory_tiers() {
        let r = ratchet();
        let mandatory_tiers = [RiskTier::Tier2, RiskTier::Tier3, RiskTier::Tier4];

        for tier in mandatory_tiers {
            // Missing capability — denied at Tier2+
            let input = PathRatchetInput {
                risk_tier: tier,
                broker_checked: true,
                capability_status: EnforcementStatus::Unavailable,
                context_firewall_status: EnforcementStatus::Checked,
                capsule_admission_status: EnforcementStatus::Checked,
            };
            assert!(
                r.enforce(&input).is_denied(),
                "tier {tier:?} with missing capability must be denied"
            );

            // Missing context firewall — denied at Tier2+
            let input = PathRatchetInput {
                risk_tier: tier,
                broker_checked: true,
                capability_status: EnforcementStatus::Checked,
                context_firewall_status: EnforcementStatus::Unavailable,
                capsule_admission_status: EnforcementStatus::Checked,
            };
            assert!(
                r.enforce(&input).is_denied(),
                "tier {tier:?} with missing context firewall must be denied"
            );

            // Missing capsule admission — denied at Tier3+ only (REQ-0028)
            let input = PathRatchetInput {
                risk_tier: tier,
                broker_checked: true,
                capability_status: EnforcementStatus::Checked,
                context_firewall_status: EnforcementStatus::Checked,
                capsule_admission_status: EnforcementStatus::Unavailable,
            };
            if tier.tier() >= 3 {
                assert!(
                    r.enforce(&input).is_denied(),
                    "tier {tier:?} with missing capsule admission must be denied (Tier3+)"
                );
            } else {
                assert!(
                    r.enforce(&input).is_allowed(),
                    "tier {tier:?} with missing capsule should be allowed with warning (Tier2)"
                );
            }

            // Missing broker — denied at ALL tiers
            let input = PathRatchetInput {
                risk_tier: tier,
                broker_checked: false,
                capability_status: EnforcementStatus::Checked,
                context_firewall_status: EnforcementStatus::Checked,
                capsule_admission_status: EnforcementStatus::Checked,
            };
            assert!(
                r.enforce(&input).is_denied(),
                "tier {tier:?} with missing broker must be denied"
            );
        }
    }

    /// Regression test: Verify that broker is required at EVERY tier (Tier0
    /// through Tier4). This prevents future code changes from accidentally
    /// allowing non-broker actuation paths.
    #[test]
    fn test_regression_broker_required_all_tiers() {
        let r = ratchet();
        let all_tiers = [
            RiskTier::Tier0,
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ];

        for tier in all_tiers {
            let input = PathRatchetInput {
                risk_tier: tier,
                broker_checked: false,
                capability_status: EnforcementStatus::Checked,
                context_firewall_status: EnforcementStatus::Checked,
                capsule_admission_status: EnforcementStatus::Checked,
            };
            assert!(
                r.enforce(&input).is_denied(),
                "broker must be required at tier {tier:?}"
            );
        }
    }

    /// Regression test: Verify that the mandatory enforcement tier thresholds
    /// are correct. These constants must not be changed without security
    /// review.
    #[test]
    fn test_regression_mandatory_enforcement_threshold() {
        assert_eq!(
            MANDATORY_ENFORCEMENT_TIER, 2,
            "MANDATORY_ENFORCEMENT_TIER must be 2 (Tier2+)"
        );
        assert_eq!(
            CAPSULE_MANDATORY_ENFORCEMENT_TIER, 3,
            "CAPSULE_MANDATORY_ENFORCEMENT_TIER must be 3 (Tier3+, per REQ-0028)"
        );
    }
}
