//! Disclosure-control policy primitives for RFC-0028 REQ-0007.
//!
//! This module defines signed disclosure policy snapshots and fail-closed
//! validation rules used to gate promotion-critical effects.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{
    Hash, PUBLIC_KEY_SIZE, SIGNATURE_SIZE, Signer, parse_signature, parse_verifying_key,
    verify_signature,
};

/// Maximum accepted phase identifier length.
pub const MAX_DISCLOSURE_PHASE_ID_LEN: usize = 128;
/// Domain separator for signed disclosure snapshots.
pub const DISCLOSURE_POLICY_SNAPSHOT_DOMAIN: &[u8] = b"apm2.disclosure_policy_snapshot.v1";

/// Disclosure-control policy modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosurePolicyMode {
    /// Trade-secret-only mode: deny patent/provisional/publication channels.
    TradeSecretOnly,
    /// Selective disclosure mode (requires additional declassification
    /// controls).
    SelectiveDisclosure,
}

impl DisclosurePolicyMode {
    /// Canonical mode label used in signing preimages.
    #[must_use]
    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::TradeSecretOnly => "trade_secret_only",
            Self::SelectiveDisclosure => "selective_disclosure",
        }
    }
}

/// Disclosure channel class for policy admission checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureChannelClass {
    /// Internal-only channel.
    Internal,
    /// Patent filing channel.
    PatentFiling,
    /// Provisional patent application channel.
    ProvisionalApplication,
    /// External publication channel.
    ExternalPublication,
    /// Signed declassification-controlled channel.
    DeclassificationControlled,
}

/// Signed disclosure-control policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicySnapshot {
    /// Policy mode for this epoch.
    pub mode: DisclosurePolicyMode,
    /// Monotonic policy epoch.
    pub epoch: u64,
    /// Phase identifier this snapshot is scoped to.
    pub phase_id: String,
    /// Digest of canonical policy content.
    pub policy_digest: Hash,
    /// Signature over canonical snapshot bytes.
    pub signature: Vec<u8>,
    /// Issuer verifying key bytes.
    pub issuer_verifying_key: [u8; PUBLIC_KEY_SIZE],
    /// Issuance timestamp (ns).
    pub issued_at_ns: u64,
    /// Expiration timestamp (ns), or `0` for no explicit expiry.
    pub expires_at_ns: u64,
}

impl DisclosurePolicySnapshot {
    /// Returns canonical signable bytes for this snapshot.
    #[must_use]
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(DISCLOSURE_POLICY_SNAPSHOT_DOMAIN);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(self.mode.canonical_label().as_bytes());
        write_len_prefixed_string(&mut bytes, &self.phase_id);
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.issued_at_ns.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_ns.to_be_bytes());
        bytes
    }

    /// Signs this snapshot in place and binds the issuer public key.
    pub fn sign(&mut self, signer: &Signer) {
        self.issuer_verifying_key = signer.public_key_bytes();
        self.signature = signer.sign(&self.signable_bytes()).to_bytes().to_vec();
    }

    fn validate_shape(&self) -> Result<(), DisclosurePolicyError> {
        if self.phase_id.trim().is_empty() {
            return Err(DisclosurePolicyError::EmptyPhaseId {
                field: "snapshot.phase_id",
            });
        }
        if self.phase_id.len() > MAX_DISCLOSURE_PHASE_ID_LEN {
            return Err(DisclosurePolicyError::PhaseIdTooLong {
                field: "snapshot.phase_id",
                actual: self.phase_id.len(),
                max: MAX_DISCLOSURE_PHASE_ID_LEN,
            });
        }
        if self.policy_digest == [0u8; 32] {
            return Err(DisclosurePolicyError::ZeroPolicyDigest);
        }
        if self.signature.is_empty() {
            return Err(DisclosurePolicyError::MissingSignature);
        }
        if self.signature.len() != SIGNATURE_SIZE {
            return Err(DisclosurePolicyError::InvalidSignatureLength {
                actual: self.signature.len(),
                expected: SIGNATURE_SIZE,
            });
        }
        Ok(())
    }

    fn verify_signature(
        &self,
        trusted_issuer_verifying_key: &[u8; PUBLIC_KEY_SIZE],
    ) -> Result<(), DisclosurePolicyError> {
        let verifying_key = parse_verifying_key(trusted_issuer_verifying_key).map_err(|error| {
            DisclosurePolicyError::InvalidIssuerVerifyingKey {
                reason: error.to_string(),
            }
        })?;
        let signature = parse_signature(&self.signature).map_err(|error| {
            DisclosurePolicyError::SignatureParseFailed {
                reason: error.to_string(),
            }
        })?;
        verify_signature(&verifying_key, &self.signable_bytes(), &signature).map_err(|error| {
            DisclosurePolicyError::SignatureVerificationFailed {
                reason: error.to_string(),
            }
        })
    }
}

/// Disclosure policy validation errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DisclosurePolicyError {
    /// Required phase identifier is empty.
    #[error("field '{field}' must be non-empty")]
    EmptyPhaseId {
        /// Field name.
        field: &'static str,
    },
    /// Phase identifier exceeds max length.
    #[error("field '{field}' exceeds max length: {actual} > {max}")]
    PhaseIdTooLong {
        /// Field name.
        field: &'static str,
        /// Actual length.
        actual: usize,
        /// Max length.
        max: usize,
    },
    /// Policy digest was zeroed.
    #[error("policy digest must be non-zero")]
    ZeroPolicyDigest,
    /// Snapshot signature is missing.
    #[error("snapshot signature is missing")]
    MissingSignature,
    /// Snapshot signature length is invalid.
    #[error("invalid signature length: {actual} (expected {expected})")]
    InvalidSignatureLength {
        /// Actual signature length.
        actual: usize,
        /// Expected signature length.
        expected: usize,
    },
    /// Issuer verifying key is malformed.
    #[error("invalid issuer verifying key: {reason}")]
    InvalidIssuerVerifyingKey {
        /// Parse reason.
        reason: String,
    },
    /// Snapshot signature bytes are malformed.
    #[error("snapshot signature parse failed: {reason}")]
    SignatureParseFailed {
        /// Parse reason.
        reason: String,
    },
    /// Signature verification failed.
    #[error("snapshot signature verification failed: {reason}")]
    SignatureVerificationFailed {
        /// Verification failure detail.
        reason: String,
    },
    /// Snapshot phase does not match evaluated phase.
    #[error("phase mismatch: expected '{expected}', got '{actual}'")]
    PhaseMismatch {
        /// Expected phase ID.
        expected: String,
        /// Actual phase ID.
        actual: String,
    },
    /// Snapshot mode does not match active phase profile.
    #[error("mode mismatch for phase '{phase_id}': expected {expected:?}, got {actual:?}")]
    ModeMismatch {
        /// Phase ID under evaluation.
        phase_id: String,
        /// Expected mode.
        expected: DisclosurePolicyMode,
        /// Actual mode.
        actual: DisclosurePolicyMode,
    },
    /// Snapshot expiry is stale.
    #[error("snapshot expired: expires_at_ns={expires_at_ns}, current_time_ns={current_time_ns}")]
    Expired {
        /// Snapshot expiry timestamp.
        expires_at_ns: u64,
        /// Current evaluation time.
        current_time_ns: u64,
    },
    /// Snapshot issuance timestamp is in the future.
    #[error(
        "snapshot issued_at_ns is in the future: issued_at_ns={issued_at_ns}, current_time_ns={current_time_ns}"
    )]
    IssuedInFuture {
        /// Snapshot issue time.
        issued_at_ns: u64,
        /// Current evaluation time.
        current_time_ns: u64,
    },
    /// Epoch did not increase monotonically.
    #[error(
        "non-monotonic epoch transition: last_epoch={last_epoch}, current_epoch={current_epoch}"
    )]
    NonMonotonicEpoch {
        /// Last known epoch.
        last_epoch: u64,
        /// Current snapshot epoch.
        current_epoch: u64,
    },
}

/// Resolve the active disclosure profile for a given phase.
///
/// Current policy defaults all known phases to trade-secret-only mode.
#[must_use]
pub const fn phase_disclosure_profile(_phase_id: &str) -> DisclosurePolicyMode {
    DisclosurePolicyMode::TradeSecretOnly
}

/// Validates a disclosure policy snapshot for the current evaluation window.
///
/// # Errors
///
/// Returns [`DisclosurePolicyError`] when signature, phase, mode, freshness,
/// or epoch checks fail.
pub fn validate_disclosure_policy(
    snapshot: &DisclosurePolicySnapshot,
    trusted_issuer_verifying_key: &[u8; PUBLIC_KEY_SIZE],
    current_phase_id: &str,
    current_time_ns: u64,
    last_known_epoch: Option<u64>,
) -> Result<(), DisclosurePolicyError> {
    if current_phase_id.trim().is_empty() {
        return Err(DisclosurePolicyError::EmptyPhaseId {
            field: "current_phase_id",
        });
    }
    if current_phase_id.len() > MAX_DISCLOSURE_PHASE_ID_LEN {
        return Err(DisclosurePolicyError::PhaseIdTooLong {
            field: "current_phase_id",
            actual: current_phase_id.len(),
            max: MAX_DISCLOSURE_PHASE_ID_LEN,
        });
    }

    snapshot.validate_shape()?;
    snapshot.verify_signature(trusted_issuer_verifying_key)?;

    if snapshot.phase_id != current_phase_id {
        return Err(DisclosurePolicyError::PhaseMismatch {
            expected: current_phase_id.to_string(),
            actual: snapshot.phase_id.clone(),
        });
    }

    let expected_mode = phase_disclosure_profile(current_phase_id);
    if snapshot.mode != expected_mode {
        return Err(DisclosurePolicyError::ModeMismatch {
            phase_id: current_phase_id.to_string(),
            expected: expected_mode,
            actual: snapshot.mode,
        });
    }

    if snapshot.issued_at_ns > current_time_ns {
        return Err(DisclosurePolicyError::IssuedInFuture {
            issued_at_ns: snapshot.issued_at_ns,
            current_time_ns,
        });
    }

    if snapshot.expires_at_ns != 0 && snapshot.expires_at_ns <= current_time_ns {
        return Err(DisclosurePolicyError::Expired {
            expires_at_ns: snapshot.expires_at_ns,
            current_time_ns,
        });
    }

    if let Some(last_epoch) = last_known_epoch
        && snapshot.epoch <= last_epoch
    {
        return Err(DisclosurePolicyError::NonMonotonicEpoch {
            last_epoch,
            current_epoch: snapshot.epoch,
        });
    }

    Ok(())
}

fn write_len_prefixed_string(bytes: &mut Vec<u8>, value: &str) {
    let len =
        u32::try_from(value.len()).expect("length-prefixed disclosure strings must fit into u32");
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_snapshot(signer: &Signer, now_ns: u64) -> DisclosurePolicySnapshot {
        let mut snapshot = DisclosurePolicySnapshot {
            mode: DisclosurePolicyMode::TradeSecretOnly,
            epoch: 1,
            phase_id: "pre_federation".to_string(),
            policy_digest: [0xAB; 32],
            signature: Vec::new(),
            issuer_verifying_key: [0u8; 32],
            issued_at_ns: now_ns.saturating_sub(1_000),
            expires_at_ns: now_ns.saturating_add(1_000_000),
        };
        snapshot.sign(signer);
        snapshot
    }

    #[test]
    fn validate_accepts_valid_snapshot() {
        let signer = Signer::generate();
        let now_ns = 1_700_000_000_000_000_000;
        let snapshot = valid_snapshot(&signer, now_ns);
        let trusted_issuer_key = signer.public_key_bytes();
        let result = validate_disclosure_policy(
            &snapshot,
            &trusted_issuer_key,
            "pre_federation",
            now_ns,
            None,
        );
        assert!(result.is_ok(), "valid snapshot should pass: {result:?}");
    }

    #[test]
    fn validate_denies_expired_snapshot() {
        let signer = Signer::generate();
        let now_ns = 1_700_000_000_000_000_000;
        let mut snapshot = valid_snapshot(&signer, now_ns);
        snapshot.expires_at_ns = now_ns.saturating_sub(1);
        snapshot.sign(&signer);
        let trusted_issuer_key = signer.public_key_bytes();
        let result = validate_disclosure_policy(
            &snapshot,
            &trusted_issuer_key,
            "pre_federation",
            now_ns,
            None,
        );
        assert!(
            matches!(result, Err(DisclosurePolicyError::Expired { .. })),
            "expired snapshot must deny, got: {result:?}"
        );
    }

    #[test]
    fn validate_denies_bad_signature() {
        let signer = Signer::generate();
        let now_ns = 1_700_000_000_000_000_000;
        let mut snapshot = valid_snapshot(&signer, now_ns);
        snapshot.phase_id = "tampered-phase".to_string();
        let trusted_issuer_key = signer.public_key_bytes();
        let result = validate_disclosure_policy(
            &snapshot,
            &trusted_issuer_key,
            "pre_federation",
            now_ns,
            None,
        );
        assert!(
            matches!(
                result,
                Err(DisclosurePolicyError::SignatureVerificationFailed { .. })
            ),
            "tampered snapshot must fail signature verification, got: {result:?}"
        );
    }

    #[test]
    fn validate_denies_phase_mismatch() {
        let signer = Signer::generate();
        let now_ns = 1_700_000_000_000_000_000;
        let snapshot = valid_snapshot(&signer, now_ns);
        let trusted_issuer_key = signer.public_key_bytes();
        let result =
            validate_disclosure_policy(&snapshot, &trusted_issuer_key, "replication", now_ns, None);
        assert!(
            matches!(result, Err(DisclosurePolicyError::PhaseMismatch { .. })),
            "phase mismatch must deny, got: {result:?}"
        );
    }

    #[test]
    fn validate_denies_zero_policy_digest() {
        let signer = Signer::generate();
        let now_ns = 1_700_000_000_000_000_000;
        let mut snapshot = valid_snapshot(&signer, now_ns);
        snapshot.policy_digest = [0u8; 32];
        snapshot.sign(&signer);
        let trusted_issuer_key = signer.public_key_bytes();
        let result = validate_disclosure_policy(
            &snapshot,
            &trusted_issuer_key,
            "pre_federation",
            now_ns,
            None,
        );
        assert!(
            matches!(result, Err(DisclosurePolicyError::ZeroPolicyDigest)),
            "zero digest must deny, got: {result:?}"
        );
    }

    #[test]
    fn validate_denies_non_monotonic_epoch() {
        let signer = Signer::generate();
        let now_ns = 1_700_000_000_000_000_000;
        let snapshot = valid_snapshot(&signer, now_ns);
        let trusted_issuer_key = signer.public_key_bytes();
        let result = validate_disclosure_policy(
            &snapshot,
            &trusted_issuer_key,
            "pre_federation",
            now_ns,
            Some(1),
        );
        assert!(
            matches!(result, Err(DisclosurePolicyError::NonMonotonicEpoch { .. })),
            "non-monotonic epoch must deny, got: {result:?}"
        );
    }

    #[test]
    fn validate_denies_snapshot_signed_by_unauthorized_issuer() {
        let trusted_signer = Signer::generate();
        let rogue_signer = Signer::generate();
        let now_ns = 1_700_000_000_000_000_000;
        let snapshot = valid_snapshot(&rogue_signer, now_ns);
        let trusted_issuer_key = trusted_signer.public_key_bytes();
        let result = validate_disclosure_policy(
            &snapshot,
            &trusted_issuer_key,
            "pre_federation",
            now_ns,
            None,
        );
        assert!(
            matches!(
                result,
                Err(DisclosurePolicyError::SignatureVerificationFailed { .. })
            ),
            "snapshot signed by an unauthorized issuer must deny, got: {result:?}"
        );
    }
}
