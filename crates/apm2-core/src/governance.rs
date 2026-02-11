//! Governance control-plane message and authorization types for RFC-0020.
//!
//! This module defines signed governance messages used for cross-cell stop,
//! rotation, and ratchet operations.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{Signer, parse_signature, verify_signature};

/// Schema identifier for [`GovernanceStopOrderV1`].
pub const GOVERNANCE_STOP_ORDER_V1_SCHEMA: &str = "apm2.governance_stop_order.v1";
/// Schema identifier for [`GovernanceRotationAnnouncementV1`].
pub const GOVERNANCE_ROTATION_ANNOUNCEMENT_V1_SCHEMA: &str =
    "apm2.governance_rotation_announcement.v1";
/// Schema identifier for [`GovernanceRatchetUpdateV1`].
pub const GOVERNANCE_RATCHET_UPDATE_V1_SCHEMA: &str = "apm2.governance_ratchet_update.v1";

/// Maximum cell identifier length for governance messages.
pub const MAX_GOVERNANCE_CELL_ID_LEN: usize = 128;
/// Maximum reason/justification length for governance messages.
pub const MAX_GOVERNANCE_REASON_LEN: usize = 1_024;
/// Maximum key identifier length for governance messages.
pub const MAX_GOVERNANCE_KEY_ID_LEN: usize = 128;
/// Maximum gate-level label length for governance ratchet messages.
pub const MAX_GOVERNANCE_GATE_LEVEL_LEN: usize = 32;
/// Required signature byte length for governance messages.
pub const GOVERNANCE_SIGNATURE_LEN: usize = 64;

/// Errors produced by governance message validation and signature checks.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum GovernanceMessageError {
    /// A required field is empty.
    #[error("field '{field}' must be non-empty")]
    EmptyField {
        /// Field name.
        field: &'static str,
    },
    /// A bounded field exceeded maximum length.
    #[error("field '{field}' exceeds max length: {actual} > {max}")]
    FieldTooLong {
        /// Field name.
        field: &'static str,
        /// Actual field length.
        actual: usize,
        /// Maximum field length.
        max: usize,
    },
    /// Overlap validity window is invalid.
    #[error(
        "overlap validity window is invalid: not_after_ms ({not_after_ms}) < not_before_ms ({not_before_ms})"
    )]
    InvalidOverlapWindow {
        /// Window start.
        not_before_ms: u64,
        /// Window end.
        not_after_ms: u64,
    },
    /// A signature is missing.
    #[error("missing message signature")]
    MissingSignature,
    /// A signature length was invalid.
    #[error("invalid signature length: {actual} (expected {expected})")]
    InvalidSignatureLength {
        /// Actual signature length.
        actual: usize,
        /// Expected signature length.
        expected: usize,
    },
    /// Signature parsing or verification failed.
    #[error("signature verification failed: {reason}")]
    SignatureVerificationFailed {
        /// Failure reason.
        reason: String,
    },
    /// The ratchet update does not change gate level.
    #[error("ratchet update requires previous_gate_level != next_gate_level")]
    NoRatchetChange,
    /// Rotation announcement reused identical key IDs.
    #[error("rotation announcement requires old_key_id != new_key_id")]
    RotationNoKeyChange,
}

/// Governance stop classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernanceStopClass {
    /// Emergency stop condition.
    EmergencyStop,
    /// Governance-defined stop condition.
    GovernanceStop,
    /// Escalation-triggered stop condition.
    EscalationTriggered,
    /// Maximum-episodes stop condition.
    MaxEpisodesReached,
}

impl fmt::Display for GovernanceStopClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmergencyStop => f.write_str("EMERGENCY_STOP"),
            Self::GovernanceStop => f.write_str("GOVERNANCE_STOP"),
            Self::EscalationTriggered => f.write_str("ESCALATION_TRIGGERED"),
            Self::MaxEpisodesReached => f.write_str("MAX_EPISODES_REACHED"),
        }
    }
}

/// Overlapping key validity window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlapValidityWindowV1 {
    /// Overlap start timestamp (milliseconds since epoch).
    pub not_before_ms: u64,
    /// Overlap end timestamp (milliseconds since epoch).
    pub not_after_ms: u64,
}

impl OverlapValidityWindowV1 {
    /// Validates overlap window ordering.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError::InvalidOverlapWindow`] when
    /// `not_after_ms < not_before_ms`.
    pub const fn validate(&self) -> Result<(), GovernanceMessageError> {
        if self.not_after_ms < self.not_before_ms {
            return Err(GovernanceMessageError::InvalidOverlapWindow {
                not_before_ms: self.not_before_ms,
                not_after_ms: self.not_after_ms,
            });
        }
        Ok(())
    }
}

/// Signed cross-cell stop order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceStopOrderV1 {
    /// Issuer cell identifier.
    pub issuer_cell_id: String,
    /// Target cell identifier.
    pub target_cell_id: String,
    /// Stop class.
    pub stop_class: GovernanceStopClass,
    /// Human-readable reason.
    pub reason: String,
    /// Issuance timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Ed25519 signature over domain-separated canonical bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl GovernanceStopOrderV1 {
    /// Returns this message schema identifier.
    #[must_use]
    pub const fn schema() -> &'static str {
        GOVERNANCE_STOP_ORDER_V1_SCHEMA
    }

    /// Validates structural and bounded-field constraints.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when validation fails.
    pub fn validate(&self) -> Result<(), GovernanceMessageError> {
        validate_non_empty_bounded(
            "issuer_cell_id",
            &self.issuer_cell_id,
            MAX_GOVERNANCE_CELL_ID_LEN,
        )?;
        validate_non_empty_bounded(
            "target_cell_id",
            &self.target_cell_id,
            MAX_GOVERNANCE_CELL_ID_LEN,
        )?;
        validate_non_empty_bounded("reason", &self.reason, MAX_GOVERNANCE_REASON_LEN)?;
        validate_signature_len(&self.signature)?;
        Ok(())
    }

    /// Produces domain-separated signable bytes (excluding signature field).
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"GOV_STOP_ORDER_V1\0");
        write_len_prefixed_string(&mut bytes, &self.issuer_cell_id);
        write_len_prefixed_string(&mut bytes, &self.target_cell_id);
        write_len_prefixed_string(&mut bytes, &self.stop_class.to_string());
        write_len_prefixed_string(&mut bytes, &self.reason);
        bytes.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        bytes
    }

    /// Signs this message in-place.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when message validation fails.
    pub fn sign(&mut self, signer: &Signer) -> Result<(), GovernanceMessageError> {
        self.validate()?;
        self.signature = signer.sign(&self.signable_bytes()).to_bytes().to_vec();
        Ok(())
    }

    /// Verifies signature authenticity.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when signature verification fails.
    pub fn verify_signature(
        &self,
        verifying_key: &crate::crypto::VerifyingKey,
    ) -> Result<(), GovernanceMessageError> {
        self.validate()?;
        if self.signature.is_empty() {
            return Err(GovernanceMessageError::MissingSignature);
        }
        let sig = parse_signature(&self.signature).map_err(|error| {
            GovernanceMessageError::SignatureVerificationFailed {
                reason: error.to_string(),
            }
        })?;
        verify_signature(verifying_key, &self.signable_bytes(), &sig).map_err(|error| {
            GovernanceMessageError::SignatureVerificationFailed {
                reason: error.to_string(),
            }
        })
    }
}

/// Signed policy-root rotation announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceRotationAnnouncementV1 {
    /// Cell identifier for the rotating policy root.
    pub cell_id: String,
    /// Previous key identifier.
    pub old_key_id: String,
    /// New key identifier.
    pub new_key_id: String,
    /// Overlapping key validity window.
    pub overlap_validity_window: OverlapValidityWindowV1,
    /// Announcement timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Ed25519 signature over domain-separated canonical bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl GovernanceRotationAnnouncementV1 {
    /// Returns this message schema identifier.
    #[must_use]
    pub const fn schema() -> &'static str {
        GOVERNANCE_ROTATION_ANNOUNCEMENT_V1_SCHEMA
    }

    /// Validates structural and bounded-field constraints.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when validation fails.
    pub fn validate(&self) -> Result<(), GovernanceMessageError> {
        validate_non_empty_bounded("cell_id", &self.cell_id, MAX_GOVERNANCE_CELL_ID_LEN)?;
        validate_non_empty_bounded("old_key_id", &self.old_key_id, MAX_GOVERNANCE_KEY_ID_LEN)?;
        validate_non_empty_bounded("new_key_id", &self.new_key_id, MAX_GOVERNANCE_KEY_ID_LEN)?;
        if self.old_key_id == self.new_key_id {
            return Err(GovernanceMessageError::RotationNoKeyChange);
        }
        self.overlap_validity_window.validate()?;
        validate_signature_len(&self.signature)?;
        Ok(())
    }

    /// Produces domain-separated signable bytes (excluding signature field).
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"GOV_ROTATION_ANNOUNCEMENT_V1\0");
        write_len_prefixed_string(&mut bytes, &self.cell_id);
        write_len_prefixed_string(&mut bytes, &self.old_key_id);
        write_len_prefixed_string(&mut bytes, &self.new_key_id);
        bytes.extend_from_slice(&self.overlap_validity_window.not_before_ms.to_be_bytes());
        bytes.extend_from_slice(&self.overlap_validity_window.not_after_ms.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        bytes
    }

    /// Signs this message in-place.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when message validation fails.
    pub fn sign(&mut self, signer: &Signer) -> Result<(), GovernanceMessageError> {
        self.validate()?;
        self.signature = signer.sign(&self.signable_bytes()).to_bytes().to_vec();
        Ok(())
    }

    /// Verifies signature authenticity.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when signature verification fails.
    pub fn verify_signature(
        &self,
        verifying_key: &crate::crypto::VerifyingKey,
    ) -> Result<(), GovernanceMessageError> {
        self.validate()?;
        if self.signature.is_empty() {
            return Err(GovernanceMessageError::MissingSignature);
        }
        let sig = parse_signature(&self.signature).map_err(|error| {
            GovernanceMessageError::SignatureVerificationFailed {
                reason: error.to_string(),
            }
        })?;
        verify_signature(verifying_key, &self.signable_bytes(), &sig).map_err(|error| {
            GovernanceMessageError::SignatureVerificationFailed {
                reason: error.to_string(),
            }
        })
    }
}

/// Signed contract-ratchet update announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceRatchetUpdateV1 {
    /// Cell identifier applying the ratchet update.
    pub cell_id: String,
    /// Previous gate level (for example `G1`).
    pub previous_gate_level: String,
    /// New gate level (for example `G2`).
    pub next_gate_level: String,
    /// Human-readable justification.
    pub justification: String,
    /// Update timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Ed25519 signature over domain-separated canonical bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl GovernanceRatchetUpdateV1 {
    /// Returns this message schema identifier.
    #[must_use]
    pub const fn schema() -> &'static str {
        GOVERNANCE_RATCHET_UPDATE_V1_SCHEMA
    }

    /// Returns `true` when this update tightens enforcement (for example
    /// `G1 -> G2`).
    #[must_use]
    pub fn tightens_enforcement(&self) -> bool {
        gate_level_rank(&self.next_gate_level) > gate_level_rank(&self.previous_gate_level)
    }

    /// Validates structural and bounded-field constraints.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when validation fails.
    pub fn validate(&self) -> Result<(), GovernanceMessageError> {
        validate_non_empty_bounded("cell_id", &self.cell_id, MAX_GOVERNANCE_CELL_ID_LEN)?;
        validate_non_empty_bounded(
            "previous_gate_level",
            &self.previous_gate_level,
            MAX_GOVERNANCE_GATE_LEVEL_LEN,
        )?;
        validate_non_empty_bounded(
            "next_gate_level",
            &self.next_gate_level,
            MAX_GOVERNANCE_GATE_LEVEL_LEN,
        )?;
        validate_non_empty_bounded(
            "justification",
            &self.justification,
            MAX_GOVERNANCE_REASON_LEN,
        )?;
        if self.previous_gate_level == self.next_gate_level {
            return Err(GovernanceMessageError::NoRatchetChange);
        }
        validate_signature_len(&self.signature)?;
        Ok(())
    }

    /// Produces domain-separated signable bytes (excluding signature field).
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"GOV_RATCHET_UPDATE_V1\0");
        write_len_prefixed_string(&mut bytes, &self.cell_id);
        write_len_prefixed_string(&mut bytes, &self.previous_gate_level);
        write_len_prefixed_string(&mut bytes, &self.next_gate_level);
        write_len_prefixed_string(&mut bytes, &self.justification);
        bytes.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        bytes
    }

    /// Signs this message in-place.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when message validation fails.
    pub fn sign(&mut self, signer: &Signer) -> Result<(), GovernanceMessageError> {
        self.validate()?;
        self.signature = signer.sign(&self.signable_bytes()).to_bytes().to_vec();
        Ok(())
    }

    /// Verifies signature authenticity.
    ///
    /// # Errors
    ///
    /// Returns [`GovernanceMessageError`] when signature verification fails.
    pub fn verify_signature(
        &self,
        verifying_key: &crate::crypto::VerifyingKey,
    ) -> Result<(), GovernanceMessageError> {
        self.validate()?;
        if self.signature.is_empty() {
            return Err(GovernanceMessageError::MissingSignature);
        }
        let sig = parse_signature(&self.signature).map_err(|error| {
            GovernanceMessageError::SignatureVerificationFailed {
                reason: error.to_string(),
            }
        })?;
        verify_signature(verifying_key, &self.signable_bytes(), &sig).map_err(|error| {
            GovernanceMessageError::SignatureVerificationFailed {
                reason: error.to_string(),
            }
        })
    }
}

const fn validate_non_empty_bounded(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), GovernanceMessageError> {
    if value.is_empty() {
        return Err(GovernanceMessageError::EmptyField { field });
    }
    if value.len() > max_len {
        return Err(GovernanceMessageError::FieldTooLong {
            field,
            actual: value.len(),
            max: max_len,
        });
    }
    Ok(())
}

const fn validate_signature_len(signature: &[u8]) -> Result<(), GovernanceMessageError> {
    if signature.is_empty() {
        return Ok(());
    }
    if signature.len() != GOVERNANCE_SIGNATURE_LEN {
        return Err(GovernanceMessageError::InvalidSignatureLength {
            actual: signature.len(),
            expected: GOVERNANCE_SIGNATURE_LEN,
        });
    }
    Ok(())
}

fn write_len_prefixed_string(buf: &mut Vec<u8>, value: &str) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn gate_level_rank(level: &str) -> i32 {
    match level.trim() {
        "G0" => 0,
        "G1" => 1,
        "G2" => 2,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governance_stop_order_sign_and_verify_roundtrip() {
        let signer = Signer::generate();
        let mut msg = GovernanceStopOrderV1 {
            issuer_cell_id: "cell-a".to_string(),
            target_cell_id: "cell-b".to_string(),
            stop_class: GovernanceStopClass::EmergencyStop,
            reason: "operator initiated stop".to_string(),
            timestamp_ms: 1_700_000_000_000,
            signature: Vec::new(),
        };
        msg.sign(&signer).expect("message should sign");
        assert_eq!(msg.signature.len(), GOVERNANCE_SIGNATURE_LEN);
        msg.verify_signature(&signer.verifying_key())
            .expect("signature should verify");
    }

    #[test]
    fn rotation_message_rejects_identical_keys() {
        let msg = GovernanceRotationAnnouncementV1 {
            cell_id: "cell-a".to_string(),
            old_key_id: "k-old".to_string(),
            new_key_id: "k-old".to_string(),
            overlap_validity_window: OverlapValidityWindowV1 {
                not_before_ms: 100,
                not_after_ms: 200,
            },
            timestamp_ms: 150,
            signature: Vec::new(),
        };
        let err = msg.validate().expect_err("identical keys must be rejected");
        assert!(matches!(err, GovernanceMessageError::RotationNoKeyChange));
    }

    #[test]
    fn ratchet_update_tightens_enforcement_for_g1_to_g2() {
        let msg = GovernanceRatchetUpdateV1 {
            cell_id: "cell-a".to_string(),
            previous_gate_level: "G1".to_string(),
            next_gate_level: "G2".to_string(),
            justification: "escape rate stabilized".to_string(),
            timestamp_ms: 42,
            signature: Vec::new(),
        };
        assert!(msg.tightens_enforcement());
    }
}
