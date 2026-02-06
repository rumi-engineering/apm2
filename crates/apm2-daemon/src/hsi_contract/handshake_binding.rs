//! Handshake contract-hash binding and tiered mismatch gates (TCK-00348).
//!
//! This module implements the RFC-0020 section 3.1.2 and 3.1.3 requirements:
//!
//! - **Binding**: `cli_contract_hash` and canonicalizer metadata are exchanged
//!   during the Hello/HelloAck handshake and persisted in `SessionStarted`
//!   events.
//! - **Tiered mismatch policy**: When the client's `cli_contract_hash` differs
//!   from the daemon's active contract hash, the response depends on the
//!   session's risk tier:
//!   - Tier0/Tier1: warn and waive (session proceeds, mismatch counter emitted)
//!   - Tier2+: deny by default (handshake rejected with `HelloNack`)
//!
//! # Fail-closed Semantics
//!
//! Per RFC-0020 section 4 (fail-closed enforcement), unknown or error states
//! during mismatch evaluation MUST result in DENY. If the risk tier cannot be
//! determined, the handshake is denied.
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1.2: `cli_contract_hash` MUST be included in session
//!   handshake
//! - RFC-0020 section 3.1.3: Fail-closed mismatch behavior
//! - RFC-0020 section 11.4: `contract_mismatch_total` counter
//! - REQ-0002: Handshake contract hash and canonicalizer binding

use serde::{Deserialize, Serialize};

/// Maximum length for `cli_contract_hash` string (denial-of-service bound).
///
/// A `blake3:<64-hex>` hash is 71 characters. We allow up to 128 to
/// accommodate alternative hash formats while preventing unbounded input.
pub const MAX_CONTRACT_HASH_LEN: usize = 128;

/// Maximum length for a canonicalizer ID string.
pub const MAX_CANONICALIZER_ID_LEN: usize = 128;

/// Maximum number of canonicalizer entries in a single Hello message
/// (denial-of-service bound).
pub const MAX_CANONICALIZER_ENTRIES: usize = 32;

/// Risk tier for mismatch policy evaluation.
///
/// Per RFC-0020 section 3.1.3, the mismatch policy depends on the session's
/// risk tier:
/// - Tier0/Tier1: warn and waive
/// - Tier2+: deny by default
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    /// Tier 0: minimal risk. Mismatch is warned and waived.
    Tier0,
    /// Tier 1: low risk. Mismatch is warned and waived.
    Tier1,
    /// Tier 2: moderate risk. Mismatch is denied by default.
    Tier2,
    /// Tier 3: high risk. Mismatch is denied by default.
    Tier3,
    /// Tier 4: critical risk. Mismatch is denied by default.
    Tier4,
}

impl RiskTier {
    /// Returns a label string for metrics emission.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Tier0 => "tier0",
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
            Self::Tier3 => "tier3",
            Self::Tier4 => "tier4",
        }
    }

    /// Returns `true` if this tier allows mismatch waiver (warn-only).
    ///
    /// Per RFC-0020 section 3.1.3, Tier0 and Tier1 use warn/waive policy.
    #[must_use]
    pub const fn allows_mismatch_waiver(&self) -> bool {
        matches!(self, Self::Tier0 | Self::Tier1)
    }

    /// Returns `true` if this tier requires deny-by-default on mismatch.
    ///
    /// Per RFC-0020 section 3.1.3, Tier2+ sessions MUST deny on mismatch.
    #[must_use]
    pub const fn requires_deny_on_mismatch(&self) -> bool {
        !self.allows_mismatch_waiver()
    }
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Canonicalizer metadata exchanged during handshake.
///
/// Per RFC-0020 section 3.1.2, the client MUST declare the canonicalizer
/// it uses for deterministic serialization so the daemon can detect
/// incompatible encodings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalizerInfo {
    /// Canonicalizer identifier (e.g., `"apm2.canonical.v1"`).
    pub id: String,
    /// Canonicalizer version (e.g., `1`).
    pub version: u32,
}

/// Contract binding metadata exchanged during the Hello handshake.
///
/// Captures the client-declared contract hash and canonicalizer info
/// that are validated against the daemon's active contract during
/// [`evaluate_mismatch_policy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractBinding {
    /// The client's HSI contract manifest content hash.
    ///
    /// Format: `blake3:<64-hex>` (or equivalent hash scheme).
    pub cli_contract_hash: String,

    /// Canonicalizer metadata declared by the client.
    pub canonicalizers: Vec<CanonicalizerInfo>,
}

/// Outcome of the mismatch policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MismatchOutcome {
    /// No mismatch detected. The contract hashes and canonicalizers match.
    Match,

    /// Mismatch detected but waived (Tier0/Tier1).
    ///
    /// The session may proceed, but a warning counter is emitted.
    Waived {
        /// Risk tier that allowed the waiver.
        tier: RiskTier,
        /// Description of the mismatch(es).
        detail: String,
    },

    /// Mismatch detected and denied (Tier2+).
    ///
    /// The handshake MUST be rejected.
    Denied {
        /// Risk tier that triggered the denial.
        tier: RiskTier,
        /// Description of the mismatch(es).
        detail: String,
    },
}

impl MismatchOutcome {
    /// Returns `true` if the outcome is a denial.
    #[must_use]
    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Returns `true` if the outcome is a waiver.
    #[must_use]
    pub const fn is_waived(&self) -> bool {
        matches!(self, Self::Waived { .. })
    }

    /// Returns `true` if the contract matched exactly.
    #[must_use]
    pub const fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }

    /// Returns the risk tier label for metrics emission, if applicable.
    #[must_use]
    pub const fn tier_label(&self) -> Option<&'static str> {
        match self {
            Self::Match => None,
            Self::Waived { tier, .. } | Self::Denied { tier, .. } => Some(tier.label()),
        }
    }
}

/// Validation error for contract binding fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractBindingError {
    /// The `cli_contract_hash` exceeds the maximum length.
    ContractHashTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// A canonicalizer ID exceeds the maximum length.
    CanonicalizerIdTooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },
    /// Too many canonicalizer entries.
    TooManyCanonicalizerEntries {
        /// Actual count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
}

impl std::fmt::Display for ContractBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContractHashTooLong { len, max } => {
                write!(f, "cli_contract_hash length {len} exceeds maximum {max}")
            },
            Self::CanonicalizerIdTooLong { len, max } => {
                write!(f, "canonicalizer id length {len} exceeds maximum {max}")
            },
            Self::TooManyCanonicalizerEntries { count, max } => {
                write!(f, "canonicalizer count {count} exceeds maximum {max}")
            },
        }
    }
}

impl std::error::Error for ContractBindingError {}

/// Validates a contract binding against field-level bounds.
///
/// # Errors
///
/// Returns `ContractBindingError` if any field exceeds its bounds.
pub fn validate_contract_binding(binding: &ContractBinding) -> Result<(), ContractBindingError> {
    if binding.cli_contract_hash.len() > MAX_CONTRACT_HASH_LEN {
        return Err(ContractBindingError::ContractHashTooLong {
            len: binding.cli_contract_hash.len(),
            max: MAX_CONTRACT_HASH_LEN,
        });
    }
    if binding.canonicalizers.len() > MAX_CANONICALIZER_ENTRIES {
        return Err(ContractBindingError::TooManyCanonicalizerEntries {
            count: binding.canonicalizers.len(),
            max: MAX_CANONICALIZER_ENTRIES,
        });
    }
    for canon in &binding.canonicalizers {
        if canon.id.len() > MAX_CANONICALIZER_ID_LEN {
            return Err(ContractBindingError::CanonicalizerIdTooLong {
                len: canon.id.len(),
                max: MAX_CANONICALIZER_ID_LEN,
            });
        }
    }
    Ok(())
}

/// Evaluates the mismatch policy between client and server contract bindings.
///
/// Per RFC-0020 section 3.1.3:
/// - If `cli_contract_hash` mismatches and risk tier is Tier0/Tier1: waive
///   (warn + proceed)
/// - If `cli_contract_hash` mismatches and risk tier is Tier2+: deny
///
/// # Fail-closed
///
/// This function checks admission BEFORE producing any state change. The
/// caller MUST NOT proceed with session setup if the outcome is `Denied`.
///
/// # Arguments
///
/// * `client_hash` - The `cli_contract_hash` from the client's Hello message.
///   If empty/absent, it is treated as "unknown" and compared with the server
///   hash for compatibility.
/// * `server_hash` - The daemon's active contract hash.
/// * `client_canonicalizers` - Canonicalizer entries from the client.
/// * `server_canonicalizers` - Canonicalizer entries from the daemon.
/// * `risk_tier` - The risk tier for this session.
#[must_use]
pub fn evaluate_mismatch_policy(
    client_hash: &str,
    server_hash: &str,
    client_canonicalizers: &[CanonicalizerInfo],
    server_canonicalizers: &[CanonicalizerInfo],
    risk_tier: RiskTier,
) -> MismatchOutcome {
    let mut mismatches = Vec::new();

    // Check contract hash mismatch
    if !client_hash.is_empty() && client_hash != server_hash {
        mismatches.push(format!(
            "contract hash mismatch: client='{}' server='{}'",
            truncate_for_log(client_hash, 80),
            truncate_for_log(server_hash, 80),
        ));
    } else if client_hash.is_empty() && !server_hash.is_empty() {
        // Client did not provide a contract hash. For Tier2+, this is treated
        // as unknown (fail-closed). For Tier0/Tier1, it is acceptable.
        if risk_tier.requires_deny_on_mismatch() {
            mismatches
                .push("client did not provide cli_contract_hash (required for Tier2+)".to_string());
        }
    }

    // Check canonicalizer mismatches
    for client_canon in client_canonicalizers {
        let server_match = server_canonicalizers
            .iter()
            .find(|s| s.id == client_canon.id);
        match server_match {
            Some(server_canon) if server_canon.version != client_canon.version => {
                mismatches.push(format!(
                    "canonicalizer '{}' version mismatch: client={} server={}",
                    truncate_for_log(&client_canon.id, 64),
                    client_canon.version,
                    server_canon.version,
                ));
            },
            None => {
                mismatches.push(format!(
                    "canonicalizer '{}' (version {}) not supported by server",
                    truncate_for_log(&client_canon.id, 64),
                    client_canon.version,
                ));
            },
            Some(_) => {
                // Versions match, no mismatch.
            },
        }
    }

    if mismatches.is_empty() {
        return MismatchOutcome::Match;
    }

    let detail = mismatches.join("; ");

    // Apply tiered policy
    if risk_tier.allows_mismatch_waiver() {
        MismatchOutcome::Waived {
            tier: risk_tier,
            detail,
        }
    } else {
        MismatchOutcome::Denied {
            tier: risk_tier,
            detail,
        }
    }
}

/// Truncates a string for log output without panicking on UTF-8 boundaries.
fn truncate_for_log(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max_len)
        .last()
        .unwrap_or(0);
    &s[..end]
}

/// Metadata persisted in `SessionStarted` events for contract binding.
///
/// Per RFC-0020 section 3.1.2, this metadata MUST be persisted in session
/// start events and authoritative receipt context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContractBinding {
    /// The client's declared `cli_contract_hash`.
    pub cli_contract_hash: String,

    /// The daemon's active contract hash at session start.
    pub server_contract_hash: String,

    /// Canonicalizer metadata from the client.
    pub client_canonicalizers: Vec<CanonicalizerInfo>,

    /// Whether a contract mismatch was detected and waived.
    pub mismatch_waived: bool,

    /// Risk tier at session start.
    pub risk_tier: RiskTier,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // RiskTier tests
    // =========================================================================

    #[test]
    fn tier0_and_tier1_allow_waiver() {
        assert!(RiskTier::Tier0.allows_mismatch_waiver());
        assert!(RiskTier::Tier1.allows_mismatch_waiver());
    }

    #[test]
    fn tier2_plus_require_deny() {
        assert!(RiskTier::Tier2.requires_deny_on_mismatch());
        assert!(RiskTier::Tier3.requires_deny_on_mismatch());
        assert!(RiskTier::Tier4.requires_deny_on_mismatch());
    }

    #[test]
    fn risk_tier_label_is_deterministic() {
        assert_eq!(RiskTier::Tier0.label(), "tier0");
        assert_eq!(RiskTier::Tier1.label(), "tier1");
        assert_eq!(RiskTier::Tier2.label(), "tier2");
        assert_eq!(RiskTier::Tier3.label(), "tier3");
        assert_eq!(RiskTier::Tier4.label(), "tier4");
    }

    #[test]
    fn risk_tier_display() {
        assert_eq!(RiskTier::Tier0.to_string(), "tier0");
        assert_eq!(RiskTier::Tier4.to_string(), "tier4");
    }

    // =========================================================================
    // Validation tests
    // =========================================================================

    #[test]
    fn validate_valid_binding() {
        let binding = ContractBinding {
            cli_contract_hash:
                "blake3:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                    .to_string(),
            canonicalizers: vec![CanonicalizerInfo {
                id: "apm2.canonical.v1".to_string(),
                version: 1,
            }],
        };
        assert!(validate_contract_binding(&binding).is_ok());
    }

    #[test]
    fn validate_contract_hash_too_long() {
        let binding = ContractBinding {
            cli_contract_hash: "x".repeat(MAX_CONTRACT_HASH_LEN + 1),
            canonicalizers: Vec::new(),
        };
        match validate_contract_binding(&binding) {
            Err(ContractBindingError::ContractHashTooLong { len, max }) => {
                assert_eq!(len, MAX_CONTRACT_HASH_LEN + 1);
                assert_eq!(max, MAX_CONTRACT_HASH_LEN);
            },
            other => panic!("expected ContractHashTooLong, got: {other:?}"),
        }
    }

    #[test]
    fn validate_too_many_canonicalizers() {
        let binding = ContractBinding {
            cli_contract_hash: "blake3:abc".to_string(),
            canonicalizers: (0..=MAX_CANONICALIZER_ENTRIES)
                .map(|i| CanonicalizerInfo {
                    id: format!("canon.{i}"),
                    version: 1,
                })
                .collect(),
        };
        match validate_contract_binding(&binding) {
            Err(ContractBindingError::TooManyCanonicalizerEntries { count, max }) => {
                assert_eq!(count, MAX_CANONICALIZER_ENTRIES + 1);
                assert_eq!(max, MAX_CANONICALIZER_ENTRIES);
            },
            other => panic!("expected TooManyCanonicalizerEntries, got: {other:?}"),
        }
    }

    #[test]
    fn validate_canonicalizer_id_too_long() {
        let binding = ContractBinding {
            cli_contract_hash: "blake3:abc".to_string(),
            canonicalizers: vec![CanonicalizerInfo {
                id: "c".repeat(MAX_CANONICALIZER_ID_LEN + 1),
                version: 1,
            }],
        };
        match validate_contract_binding(&binding) {
            Err(ContractBindingError::CanonicalizerIdTooLong { len, max }) => {
                assert_eq!(len, MAX_CANONICALIZER_ID_LEN + 1);
                assert_eq!(max, MAX_CANONICALIZER_ID_LEN);
            },
            other => panic!("expected CanonicalizerIdTooLong, got: {other:?}"),
        }
    }

    // =========================================================================
    // Mismatch policy evaluation tests
    // =========================================================================

    #[test]
    fn exact_match_returns_match() {
        let outcome = evaluate_mismatch_policy(
            "blake3:aabb",
            "blake3:aabb",
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 1,
            }],
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 1,
            }],
            RiskTier::Tier2,
        );
        assert!(outcome.is_match());
        assert!(outcome.tier_label().is_none());
    }

    #[test]
    fn contract_hash_mismatch_tier0_waived() {
        let outcome = evaluate_mismatch_policy(
            "blake3:client_hash",
            "blake3:server_hash",
            &[],
            &[],
            RiskTier::Tier0,
        );
        assert!(outcome.is_waived());
        assert!(!outcome.is_denied());
        assert_eq!(outcome.tier_label(), Some("tier0"));
        if let MismatchOutcome::Waived { detail, .. } = &outcome {
            assert!(
                detail.contains("contract hash mismatch"),
                "detail should describe mismatch: {detail}"
            );
        }
    }

    #[test]
    fn contract_hash_mismatch_tier1_waived() {
        let outcome =
            evaluate_mismatch_policy("blake3:client", "blake3:server", &[], &[], RiskTier::Tier1);
        assert!(outcome.is_waived());
        assert_eq!(outcome.tier_label(), Some("tier1"));
    }

    #[test]
    fn contract_hash_mismatch_tier2_denied() {
        let outcome =
            evaluate_mismatch_policy("blake3:client", "blake3:server", &[], &[], RiskTier::Tier2);
        assert!(outcome.is_denied());
        assert!(!outcome.is_waived());
        assert_eq!(outcome.tier_label(), Some("tier2"));
        if let MismatchOutcome::Denied { detail, .. } = &outcome {
            assert!(
                detail.contains("contract hash mismatch"),
                "detail should describe mismatch: {detail}"
            );
        }
    }

    #[test]
    fn contract_hash_mismatch_tier3_denied() {
        let outcome =
            evaluate_mismatch_policy("blake3:client", "blake3:server", &[], &[], RiskTier::Tier3);
        assert!(outcome.is_denied());
        assert_eq!(outcome.tier_label(), Some("tier3"));
    }

    #[test]
    fn contract_hash_mismatch_tier4_denied() {
        let outcome =
            evaluate_mismatch_policy("blake3:client", "blake3:server", &[], &[], RiskTier::Tier4);
        assert!(outcome.is_denied());
        assert_eq!(outcome.tier_label(), Some("tier4"));
    }

    #[test]
    fn missing_client_hash_tier0_allowed() {
        let outcome = evaluate_mismatch_policy("", "blake3:server", &[], &[], RiskTier::Tier0);
        // Empty client hash at Tier0 is not a mismatch — it's acceptable
        assert!(outcome.is_match());
    }

    #[test]
    fn missing_client_hash_tier2_denied() {
        let outcome = evaluate_mismatch_policy("", "blake3:server", &[], &[], RiskTier::Tier2);
        assert!(outcome.is_denied());
        if let MismatchOutcome::Denied { detail, .. } = &outcome {
            assert!(
                detail.contains("did not provide cli_contract_hash"),
                "detail should mention missing hash: {detail}"
            );
        }
    }

    #[test]
    fn canonicalizer_version_mismatch_tier0_waived() {
        let outcome = evaluate_mismatch_policy(
            "blake3:same",
            "blake3:same",
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 2,
            }],
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 1,
            }],
            RiskTier::Tier0,
        );
        assert!(outcome.is_waived());
        if let MismatchOutcome::Waived { detail, .. } = &outcome {
            assert!(
                detail.contains("canonicalizer 'v1' version mismatch"),
                "detail should describe canonicalizer mismatch: {detail}"
            );
        }
    }

    #[test]
    fn canonicalizer_version_mismatch_tier2_denied() {
        let outcome = evaluate_mismatch_policy(
            "blake3:same",
            "blake3:same",
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 2,
            }],
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 1,
            }],
            RiskTier::Tier2,
        );
        assert!(outcome.is_denied());
        if let MismatchOutcome::Denied { detail, .. } = &outcome {
            assert!(
                detail.contains("canonicalizer 'v1' version mismatch"),
                "detail should describe canonicalizer mismatch: {detail}"
            );
        }
    }

    #[test]
    fn unknown_canonicalizer_tier2_denied() {
        let outcome = evaluate_mismatch_policy(
            "blake3:same",
            "blake3:same",
            &[CanonicalizerInfo {
                id: "unknown.canon".to_string(),
                version: 1,
            }],
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 1,
            }],
            RiskTier::Tier2,
        );
        assert!(outcome.is_denied());
        if let MismatchOutcome::Denied { detail, .. } = &outcome {
            assert!(
                detail.contains("not supported by server"),
                "detail should mention unsupported canonicalizer: {detail}"
            );
        }
    }

    #[test]
    fn combined_hash_and_canonicalizer_mismatch() {
        let outcome = evaluate_mismatch_policy(
            "blake3:client",
            "blake3:server",
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 99,
            }],
            &[CanonicalizerInfo {
                id: "v1".to_string(),
                version: 1,
            }],
            RiskTier::Tier2,
        );
        assert!(outcome.is_denied());
        if let MismatchOutcome::Denied { detail, .. } = &outcome {
            assert!(
                detail.contains("contract hash mismatch"),
                "detail should describe hash mismatch: {detail}"
            );
            assert!(
                detail.contains("canonicalizer 'v1' version mismatch"),
                "detail should describe canonicalizer mismatch: {detail}"
            );
        }
    }

    #[test]
    fn empty_canonicalizers_on_both_sides_is_match() {
        let outcome =
            evaluate_mismatch_policy("blake3:same", "blake3:same", &[], &[], RiskTier::Tier4);
        assert!(outcome.is_match());
    }

    #[test]
    fn mismatch_outcome_predicates() {
        let m = MismatchOutcome::Match;
        assert!(m.is_match());
        assert!(!m.is_waived());
        assert!(!m.is_denied());

        let w = MismatchOutcome::Waived {
            tier: RiskTier::Tier0,
            detail: "test".to_string(),
        };
        assert!(!w.is_match());
        assert!(w.is_waived());
        assert!(!w.is_denied());

        let d = MismatchOutcome::Denied {
            tier: RiskTier::Tier2,
            detail: "test".to_string(),
        };
        assert!(!d.is_match());
        assert!(!d.is_waived());
        assert!(d.is_denied());
    }

    // =========================================================================
    // Session contract binding tests
    // =========================================================================

    #[test]
    fn session_contract_binding_serialization_roundtrip() {
        let binding = SessionContractBinding {
            cli_contract_hash: "blake3:aabb".to_string(),
            server_contract_hash: "blake3:ccdd".to_string(),
            client_canonicalizers: vec![CanonicalizerInfo {
                id: "v1".to_string(),
                version: 1,
            }],
            mismatch_waived: true,
            risk_tier: RiskTier::Tier0,
        };
        let json = serde_json::to_string(&binding).expect("serialize");
        let parsed: SessionContractBinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, binding);
    }

    #[test]
    fn truncate_for_log_short_string() {
        assert_eq!(truncate_for_log("hello", 10), "hello");
    }

    #[test]
    fn truncate_for_log_exact_boundary() {
        assert_eq!(truncate_for_log("hello", 5), "hello");
    }

    #[test]
    fn truncate_for_log_long_string() {
        let long = "a".repeat(200);
        assert_eq!(truncate_for_log(&long, 10).len(), 10);
    }

    #[test]
    fn truncate_for_log_multibyte_boundary() {
        // 3 emojis = 12 bytes, truncate at 5 should give 4 bytes (1 emoji)
        let emojis = "\u{1F600}\u{1F600}\u{1F600}";
        let truncated = truncate_for_log(emojis, 5);
        assert!(truncated.len() <= 5);
        assert_eq!(truncated.len(), 4); // one full emoji
    }

    #[test]
    fn contract_binding_error_display() {
        let e = ContractBindingError::ContractHashTooLong { len: 200, max: 128 };
        assert!(e.to_string().contains("200"));
        assert!(e.to_string().contains("128"));

        let e = ContractBindingError::CanonicalizerIdTooLong { len: 200, max: 128 };
        assert!(e.to_string().contains("200"));

        let e = ContractBindingError::TooManyCanonicalizerEntries { count: 50, max: 32 };
        assert!(e.to_string().contains("50"));
        assert!(e.to_string().contains("32"));
    }
}
