// AGENT-AUTHORED
//! Boundary intent typing for RFC-0028 REQ-0001.
//!
//! Classifies boundary intents and enforces acceptance-fact separation so that
//! Observe-class payloads cannot satisfy authoritative predicates.

use serde::{Deserialize, Serialize};

/// Maximum string length for intent class metadata fields.
pub const MAX_INTENT_CLASS_DETAIL_LENGTH: usize = 512;

/// Boundary intent classification per RFC-0028 REQ-0001.
///
/// External interaction channels MUST classify boundary intents as one of these
/// classes. Lower-assurance classes (Observe) cannot be consumed as
/// authoritative acceptance facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BoundaryIntentClass {
    /// Read-only observation. Cannot satisfy authoritative predicates.
    Observe  = 0,
    /// Assertion of a fact. Requires receipt-bound acceptance.
    Assert   = 1,
    /// Delegation of authority (narrowing only).
    Delegate = 2,
    /// Actuation of external effect. Requires complete lifecycle receipts.
    Actuate  = 3,
    /// Governance/policy change. Highest restriction level.
    Govern   = 4,
}

/// Acceptance fact classification derived from intent class.
///
/// Determines whether a payload can satisfy authoritative admission
/// predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AcceptanceFactClass {
    /// Can be used in authoritative predicates
    /// (`Assert`/`Delegate`/`Actuate`/`Govern`).
    Authoritative,
    /// `Observe` class: cannot satisfy authoritative predicates.
    Observational,
}

impl BoundaryIntentClass {
    /// Stable discriminant used for deterministic comparisons/hashing.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Derive the acceptance-fact class from this intent class.
    ///
    /// `Observe` -> `Observational` (cannot satisfy authoritative predicates)
    /// all others -> `Authoritative`.
    #[must_use]
    pub const fn acceptance_fact_class(&self) -> AcceptanceFactClass {
        match self {
            Self::Observe => AcceptanceFactClass::Observational,
            Self::Assert | Self::Delegate | Self::Actuate | Self::Govern => {
                AcceptanceFactClass::Authoritative
            },
        }
    }

    /// Returns true if this intent class can satisfy authoritative predicates.
    #[must_use]
    pub const fn is_authoritative(&self) -> bool {
        matches!(
            self,
            Self::Assert | Self::Delegate | Self::Actuate | Self::Govern
        )
    }
}

impl std::fmt::Display for BoundaryIntentClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Observe => write!(f, "observe"),
            Self::Assert => write!(f, "assert"),
            Self::Delegate => write!(f, "delegate"),
            Self::Actuate => write!(f, "actuate"),
            Self::Govern => write!(f, "govern"),
        }
    }
}

impl std::fmt::Display for AcceptanceFactClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authoritative => write!(f, "authoritative"),
            Self::Observational => write!(f, "observational"),
        }
    }
}
