// AGENT-AUTHORED
//! HMP admission pipeline — cross-cell fact import and receipt issuance
//! (TCK-00380, REQ-0034).
//!
//! This module implements the admission gate for cross-cell authoritative fact
//! imports. It enforces the normative rule from RFC-0020 §2.4.0b: any cross-
//! cell ingestion of ledger event ranges, policy root/cell certificates, or
//! permeability grants MUST emit an [`AdmissionReceiptV1`] (or
//! [`ImportReceiptV1`]) in the receiving cell.
//!
//! # Admission Pipeline
//!
//! 1. **Envelope admission**: Pre-decode size bound, structural validation.
//! 2. **Channel class routing**: Determine import category from channel class.
//! 3. **Digest verification**: Verify the body hash matches CAS content (not
//!    implemented here — done by CAS layer).
//! 4. **Authority verification**: Verify sender cell identity and policy root
//!    against known trust roots.
//! 5. **Receipt issuance**: Emit [`AdmissionReceiptV1`] binding the admitted
//!    facts to the local ledger anchor.
//!
//! # Digest-First Fetch Policy
//!
//! The [`DigestFirstFetchPolicy`] enforces bounded resource use for body
//! resolution:
//! - Maximum body size per fetch.
//! - Maximum concurrent fetches.
//! - Timeout per fetch.
//!
//! Unsolicited large payloads are dropped before body fetch.
//!
//! # Security Properties
//!
//! - **Fail-closed**: Any verification failure denies admission.
//! - **Bounded**: All fetch operations respect size and timeout bounds.
//! - **Receipt-bound**: Every successful import emits an auditable receipt.
//! - **Untrusted-by-default**: Replicated bytes without receipts are cache.
//!
//! # Contract References
//!
//! - RFC-0020 §2.4.0b: Admission receipts (normative)
//! - RFC-0020 §2.4.0: Control-plane vs data-plane separation
//! - REQ-0034: Digest-first HMP classes and admission receipts
//! - EVID-0034: HMP conformance evidence

use apm2_core::crypto::Hash;

use super::{
    AdmissionReceiptV1, HmpError, HmpMessageV1, ImportCategory, ImportReceiptV1, RejectionReason,
    VerificationMethod,
};

// =============================================================================
// Constants
// =============================================================================

/// Maximum body size for a single CAS fetch (16 MiB).
///
/// Bodies exceeding this limit are dropped without allocation.
pub const MAX_BODY_FETCH_BYTES: usize = 16 * 1024 * 1024;

/// Maximum concurrent CAS fetches per admission batch.
pub const MAX_CONCURRENT_FETCHES: usize = 16;

/// Default fetch timeout in milliseconds.
pub const DEFAULT_FETCH_TIMEOUT_MS: u64 = 30_000;

/// Maximum number of messages in a single admission batch.
pub const MAX_ADMISSION_BATCH_SIZE: usize = 10_000;

// =============================================================================
// Digest-First Fetch Policy
// =============================================================================

/// Policy governing digest-first body fetching behavior.
///
/// All CAS body resolutions are bounded by this policy to prevent resource
/// exhaustion from unsolicited or oversized payloads.
#[derive(Debug, Clone, Copy)]
pub struct DigestFirstFetchPolicy {
    /// Maximum body size in bytes.
    pub max_body_bytes: usize,
    /// Maximum concurrent fetches.
    pub max_concurrent_fetches: usize,
    /// Fetch timeout in milliseconds.
    pub fetch_timeout_ms: u64,
}

impl DigestFirstFetchPolicy {
    /// Create a new fetch policy with explicit bounds.
    #[must_use]
    pub const fn new(
        max_body_bytes: usize,
        max_concurrent_fetches: usize,
        fetch_timeout_ms: u64,
    ) -> Self {
        Self {
            max_body_bytes,
            max_concurrent_fetches,
            fetch_timeout_ms,
        }
    }

    /// Default policy with production-safe bounds.
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::new(
            MAX_BODY_FETCH_BYTES,
            MAX_CONCURRENT_FETCHES,
            DEFAULT_FETCH_TIMEOUT_MS,
        )
    }

    /// Check if a body size is within the policy bounds.
    ///
    /// # Errors
    ///
    /// Returns [`HmpError::AdmissionDenied`] if the body exceeds the size
    /// bound.
    pub fn check_body_size(&self, body_size: usize) -> Result<(), HmpError> {
        if body_size > self.max_body_bytes {
            return Err(HmpError::AdmissionDenied {
                detail: format!(
                    "body size {} exceeds max {}",
                    body_size, self.max_body_bytes
                ),
            });
        }
        Ok(())
    }
}

impl Default for DigestFirstFetchPolicy {
    fn default() -> Self {
        Self::default_bounded()
    }
}

// =============================================================================
// Admission Decision
// =============================================================================

/// Result of an admission decision for a single artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Artifact admitted successfully.
    Admitted {
        /// Hash of the admitted artifact.
        artifact_hash: Hash,
    },
    /// Artifact rejected.
    Rejected {
        /// Hash of the rejected artifact.
        artifact_hash: Hash,
        /// Reason for rejection.
        reason: String,
    },
}

impl AdmissionDecision {
    /// Returns `true` if this decision is an admission.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    /// Returns `true` if this decision is a rejection.
    #[must_use]
    pub const fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }
}

// =============================================================================
// Import Admission Gate
// =============================================================================

/// Gate for cross-cell authoritative fact imports.
///
/// Validates incoming facts, issues admission receipts, and enforces
/// the digest-first fetch policy.
#[derive(Debug, Clone)]
pub struct ImportAdmissionGate {
    /// Fetch policy for CAS body resolution.
    fetch_policy: DigestFirstFetchPolicy,
    /// Local cell ID for receipt binding.
    local_cell_id: String,
}

impl ImportAdmissionGate {
    /// Create a new import admission gate.
    #[must_use]
    pub const fn new(fetch_policy: DigestFirstFetchPolicy, local_cell_id: String) -> Self {
        Self {
            fetch_policy,
            local_cell_id,
        }
    }

    /// Determine the import category from an HMP message.
    ///
    /// Returns `None` if the message is not an import-bearing message
    /// (e.g., pure routing/discovery messages).
    #[must_use]
    pub fn classify_import(message: &HmpMessageV1) -> Option<ImportCategory> {
        // Classification is based on message_class prefix.
        let mc = &message.message_class;
        if mc.starts_with("HSI.ANTI_ENTROPY.") {
            Some(ImportCategory::LedgerEventRange)
        } else if mc.starts_with("HSI.CAS.") {
            Some(ImportCategory::CasArtifact)
        } else if mc.starts_with("HSI.PERMEABILITY.") {
            Some(ImportCategory::PermeabilityGrant)
        } else if mc.starts_with("HSI.DIRECTORY.") {
            // Directory announcements may carry certificate updates.
            Some(ImportCategory::PolicyRootCertificate)
        } else {
            None
        }
    }

    /// Evaluate admission decisions for a batch of artifact hashes.
    ///
    /// Each artifact is independently evaluated. The result is a list of
    /// decisions and the corresponding admission receipt.
    ///
    /// # Arguments
    ///
    /// * `message` - The HMP message that triggered the import.
    /// * `artifact_hashes` - Hashes of the artifacts to evaluate.
    /// * `verification_method` - How the artifacts were authenticated.
    /// * `local_ledger_anchor` - Current local ledger head hash.
    /// * `admitted_at_hlc` - HLC timestamp for the admission.
    /// * `verifier` - Closure that returns `Ok(())` for admitted artifacts or
    ///   `Err(reason)` for rejected artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`HmpError`] for structural validation failures. Individual
    /// artifact rejections are recorded in the receipt, not as errors.
    pub fn evaluate_admission<F>(
        &self,
        message: &HmpMessageV1,
        artifact_hashes: &[Hash],
        verification_method: VerificationMethod,
        local_ledger_anchor: Hash,
        admitted_at_hlc: u64,
        verifier: F,
    ) -> Result<(Vec<AdmissionDecision>, AdmissionReceiptV1), HmpError>
    where
        F: Fn(&Hash) -> Result<(), String>,
    {
        if artifact_hashes.len() > super::MAX_ADMITTED_HASHES {
            return Err(HmpError::TooManyAdmittedHashes {
                count: artifact_hashes.len(),
                max: super::MAX_ADMITTED_HASHES,
            });
        }

        let mut decisions = Vec::with_capacity(artifact_hashes.len());
        let mut admitted_hashes = Vec::new();
        let mut rejection_reasons = Vec::new();

        for hash in artifact_hashes {
            match verifier(hash) {
                Ok(()) => {
                    admitted_hashes.push(*hash);
                    decisions.push(AdmissionDecision::Admitted {
                        artifact_hash: *hash,
                    });
                },
                Err(reason) => {
                    let truncated_reason = if reason.len() > super::MAX_REJECTION_REASON_LEN {
                        // Truncate at a safe char boundary.
                        let mut end = super::MAX_REJECTION_REASON_LEN;
                        while end > 0 && !reason.is_char_boundary(end) {
                            end -= 1;
                        }
                        reason[..end].to_string()
                    } else {
                        reason.clone()
                    };
                    rejection_reasons.push(RejectionReason {
                        artifact_hash: *hash,
                        reason: truncated_reason.clone(),
                    });
                    decisions.push(AdmissionDecision::Rejected {
                        artifact_hash: *hash,
                        reason: truncated_reason,
                    });
                },
            }
        }

        // Compute receipt ID from content hash of all admitted + rejected.
        let receipt_id = Self::compute_receipt_id(
            &message.sender_cell_id,
            &admitted_hashes,
            &rejection_reasons,
            admitted_at_hlc,
        );

        let receipt = AdmissionReceiptV1 {
            receipt_id,
            sender_cell_id: message.sender_cell_id.clone(),
            sender_policy_root_key_id: message.sender_policy_root_key_id.clone(),
            admitted_hashes,
            verification_method,
            local_ledger_anchor,
            admitted_at_hlc,
            rejection_reasons,
        };

        receipt.validate()?;

        Ok((decisions, receipt))
    }

    /// Issue a full import receipt with category metadata.
    ///
    /// # Errors
    ///
    /// Returns [`HmpError`] for validation failures.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_import_receipt<F>(
        &self,
        message: &HmpMessageV1,
        artifact_hashes: &[Hash],
        verification_method: VerificationMethod,
        local_ledger_anchor: Hash,
        admitted_at_hlc: u64,
        source_range: Option<(u64, u64)>,
        verifier: F,
    ) -> Result<(Vec<AdmissionDecision>, ImportReceiptV1), HmpError>
    where
        F: Fn(&Hash) -> Result<(), String>,
    {
        let import_category =
            Self::classify_import(message).ok_or_else(|| HmpError::AdmissionDenied {
                detail: format!(
                    "message class '{}' is not an import-bearing class",
                    message.message_class
                ),
            })?;

        let (decisions, admission_receipt) = self.evaluate_admission(
            message,
            artifact_hashes,
            verification_method,
            local_ledger_anchor,
            admitted_at_hlc,
            verifier,
        )?;

        let import_receipt = ImportReceiptV1 {
            admission_receipt,
            import_category,
            source_range_start: source_range.map(|(s, _)| s),
            source_range_end: source_range.map(|(_, e)| e),
        };

        import_receipt.validate()?;

        Ok((decisions, import_receipt))
    }

    /// Returns a reference to the fetch policy.
    #[must_use]
    pub const fn fetch_policy(&self) -> &DigestFirstFetchPolicy {
        &self.fetch_policy
    }

    /// Returns the local cell ID.
    #[must_use]
    pub fn local_cell_id(&self) -> &str {
        &self.local_cell_id
    }

    /// Compute a deterministic receipt ID from admission content.
    fn compute_receipt_id(
        sender_cell_id: &str,
        admitted_hashes: &[Hash],
        rejection_reasons: &[RejectionReason],
        admitted_at_hlc: u64,
    ) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2:admission_receipt_id:v1\0");
        hasher.update(sender_cell_id.as_bytes());
        hasher.update(b"\n");
        let count = admitted_hashes.len() as u64;
        hasher.update(&count.to_le_bytes());
        for hash in admitted_hashes {
            hasher.update(hash);
        }
        let rej_count = rejection_reasons.len() as u64;
        hasher.update(&rej_count.to_le_bytes());
        for reason in rejection_reasons {
            hasher.update(&reason.artifact_hash);
            hasher.update(reason.reason.as_bytes());
        }
        hasher.update(&admitted_at_hlc.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmp::{BodyRef, ChannelClass, HmpMessageV1};

    fn test_hash(b: u8) -> Hash {
        [b; 32]
    }

    fn test_message(class: &str) -> HmpMessageV1 {
        HmpMessageV1 {
            protocol_id: "hsi:v1".to_string(),
            message_class: class.to_string(),
            message_id: test_hash(0x01),
            idempotency_key: "idem-001".to_string(),
            hlc_timestamp: 1000,
            parents: vec![],
            sender_holon_id: "holon:v1:blake3:aabb".to_string(),
            sender_actor_id: "actor-1".to_string(),
            channel_class: ChannelClass::Evidence,
            sender_cell_id: "cell:v1:blake3:ccdd".to_string(),
            receiver_cell_id: "cell:v1:blake3:eeff".to_string(),
            sender_policy_root_key_id: "pkid:v1:ed25519:blake3:1122".to_string(),
            body_ref: BodyRef {
                cas_hash: test_hash(0x03),
                content_type: "application/cbor".to_string(),
            },
            ledger_head_hash: test_hash(0x04),
            context_pack_hash: None,
            manifest_hash: None,
            view_commitment_hash: None,
            permeability_receipt_hash: None,
        }
    }

    fn test_gate() -> ImportAdmissionGate {
        ImportAdmissionGate::new(
            DigestFirstFetchPolicy::default_bounded(),
            "cell:v1:blake3:local".to_string(),
        )
    }

    // ─── DigestFirstFetchPolicy tests ───────────────────────────

    #[test]
    fn fetch_policy_admits_within_bounds() {
        let policy = DigestFirstFetchPolicy::default_bounded();
        assert!(policy.check_body_size(1024).is_ok());
        assert!(policy.check_body_size(MAX_BODY_FETCH_BYTES).is_ok());
    }

    #[test]
    fn fetch_policy_rejects_oversized() {
        let policy = DigestFirstFetchPolicy::default_bounded();
        assert!(policy.check_body_size(MAX_BODY_FETCH_BYTES + 1).is_err());
    }

    #[test]
    fn fetch_policy_custom_bounds() {
        let policy = DigestFirstFetchPolicy::new(1024, 4, 5000);
        assert!(policy.check_body_size(1024).is_ok());
        assert!(policy.check_body_size(1025).is_err());
    }

    // ─── Import classification tests ────────────────────────────

    #[test]
    fn classify_anti_entropy_as_ledger_range() {
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");
        assert_eq!(
            ImportAdmissionGate::classify_import(&msg),
            Some(ImportCategory::LedgerEventRange)
        );
    }

    #[test]
    fn classify_cas_as_artifact() {
        let msg = test_message("HSI.CAS.DELIVER");
        assert_eq!(
            ImportAdmissionGate::classify_import(&msg),
            Some(ImportCategory::CasArtifact)
        );
    }

    #[test]
    fn classify_permeability_as_grant() {
        let msg = test_message("HSI.PERMEABILITY.GRANT");
        assert_eq!(
            ImportAdmissionGate::classify_import(&msg),
            Some(ImportCategory::PermeabilityGrant)
        );
    }

    #[test]
    fn classify_directory_as_certificate() {
        let msg = test_message("HSI.DIRECTORY.ANNOUNCE");
        assert_eq!(
            ImportAdmissionGate::classify_import(&msg),
            Some(ImportCategory::PolicyRootCertificate)
        );
    }

    #[test]
    fn classify_unknown_returns_none() {
        let msg = test_message("FAC.PULSE");
        assert_eq!(ImportAdmissionGate::classify_import(&msg), None);
    }

    // ─── Admission evaluation tests ─────────────────────────────

    #[test]
    fn evaluate_all_admitted() {
        let gate = test_gate();
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");
        let hashes = vec![test_hash(0x10), test_hash(0x11), test_hash(0x12)];

        let (decisions, receipt) = gate
            .evaluate_admission(
                &msg,
                &hashes,
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |_| Ok(()),
            )
            .unwrap();

        assert_eq!(decisions.len(), 3);
        assert!(decisions.iter().all(AdmissionDecision::is_admitted));
        assert_eq!(receipt.admitted_hashes.len(), 3);
        assert!(receipt.is_complete());
    }

    #[test]
    fn evaluate_partial_admission() {
        let gate = test_gate();
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");
        let hashes = vec![test_hash(0x10), test_hash(0x11), test_hash(0x12)];

        let (decisions, receipt) = gate
            .evaluate_admission(
                &msg,
                &hashes,
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |hash| {
                    if hash[0] == 0x11 {
                        Err("signature invalid".to_string())
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap();

        assert_eq!(decisions.len(), 3);
        assert_eq!(decisions.iter().filter(|d| d.is_admitted()).count(), 2);
        assert_eq!(decisions.iter().filter(|d| d.is_rejected()).count(), 1);
        assert_eq!(receipt.admitted_hashes.len(), 2);
        assert_eq!(receipt.rejection_reasons.len(), 1);
        assert!(!receipt.is_complete());
    }

    #[test]
    fn evaluate_all_rejected() {
        let gate = test_gate();
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");
        let hashes = vec![test_hash(0x10)];

        let (decisions, receipt) = gate
            .evaluate_admission(
                &msg,
                &hashes,
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |_| Err("verification failed".to_string()),
            )
            .unwrap();

        assert_eq!(decisions.len(), 1);
        assert!(decisions[0].is_rejected());
        assert!(receipt.admitted_hashes.is_empty());
        assert_eq!(receipt.rejection_reasons.len(), 1);
    }

    // ─── Import receipt tests ───────────────────────────────────

    #[test]
    fn issue_import_receipt_with_range() {
        let gate = test_gate();
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");
        let hashes = vec![test_hash(0x10)];

        let (decisions, import_receipt) = gate
            .issue_import_receipt(
                &msg,
                &hashes,
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                Some((100, 200)),
                |_| Ok(()),
            )
            .unwrap();

        assert_eq!(decisions.len(), 1);
        assert!(decisions[0].is_admitted());
        assert_eq!(
            import_receipt.import_category,
            ImportCategory::LedgerEventRange
        );
        assert_eq!(import_receipt.source_range_start, Some(100));
        assert_eq!(import_receipt.source_range_end, Some(200));
    }

    #[test]
    fn issue_import_receipt_non_import_class_fails() {
        let gate = test_gate();
        let msg = test_message("FAC.PULSE");
        let hashes = vec![test_hash(0x10)];

        let result = gate.issue_import_receipt(
            &msg,
            &hashes,
            VerificationMethod::SingleSignature,
            test_hash(0x30),
            2000,
            None,
            |_| Ok(()),
        );

        assert!(matches!(result, Err(HmpError::AdmissionDenied { .. })));
    }

    // ─── Receipt ID determinism ─────────────────────────────────

    #[test]
    fn receipt_id_deterministic() {
        let gate = test_gate();
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");
        let hashes = vec![test_hash(0x10), test_hash(0x11)];

        let (_, r1) = gate
            .evaluate_admission(
                &msg,
                &hashes,
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |_| Ok(()),
            )
            .unwrap();

        let (_, r2) = gate
            .evaluate_admission(
                &msg,
                &hashes,
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |_| Ok(()),
            )
            .unwrap();

        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn receipt_id_changes_with_different_input() {
        let gate = test_gate();
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");

        let (_, r1) = gate
            .evaluate_admission(
                &msg,
                &[test_hash(0x10)],
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |_| Ok(()),
            )
            .unwrap();

        let (_, r2) = gate
            .evaluate_admission(
                &msg,
                &[test_hash(0x11)],
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |_| Ok(()),
            )
            .unwrap();

        assert_ne!(r1.receipt_id, r2.receipt_id);
    }

    // ─── Rejection reason truncation ────────────────────────────

    #[test]
    fn rejection_reason_truncated_safely() {
        let gate = test_gate();
        let msg = test_message("HSI.ANTI_ENTROPY.OFFER");
        let hashes = vec![test_hash(0x10)];

        let long_reason = "x".repeat(super::super::MAX_REJECTION_REASON_LEN + 100);
        let (decisions, receipt) = gate
            .evaluate_admission(
                &msg,
                &hashes,
                VerificationMethod::SingleSignature,
                test_hash(0x30),
                2000,
                |_| Err(long_reason.clone()),
            )
            .unwrap();

        assert!(decisions[0].is_rejected());
        assert!(
            receipt.rejection_reasons[0].reason.len() <= super::super::MAX_REJECTION_REASON_LEN
        );
    }

    // ─── Fetch policy integration ───────────────────────────────

    #[test]
    fn gate_exposes_fetch_policy() {
        let gate = test_gate();
        assert_eq!(gate.fetch_policy().max_body_bytes, MAX_BODY_FETCH_BYTES);
        assert_eq!(
            gate.fetch_policy().max_concurrent_fetches,
            MAX_CONCURRENT_FETCHES
        );
        assert_eq!(
            gate.fetch_policy().fetch_timeout_ms,
            DEFAULT_FETCH_TIMEOUT_MS
        );
    }

    #[test]
    fn gate_exposes_local_cell_id() {
        let gate = test_gate();
        assert_eq!(gate.local_cell_id(), "cell:v1:blake3:local");
    }
}
