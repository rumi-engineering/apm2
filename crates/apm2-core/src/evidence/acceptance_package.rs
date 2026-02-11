//! Portable acceptance evidence package and deterministic reverification.
//!
//! This module implements RFC-0028 REQ-0005:
//! authoritative external claims must be backed by portable, receipt-addressed
//! evidence that independent counterparties can deterministically re-verify
//! without ambient runtime state.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{
    EventHasher, Hash, Signer, parse_signature, parse_verifying_key, verify_signature,
};

const ACCEPTANCE_PACKAGE_VERSION: u32 = 1;
const ZERO_HASH: Hash = [0u8; 32];

/// Portable acceptance evidence package containing all receipt pointers
/// and verification metadata needed for deterministic third-party
/// reverification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptancePackageV1 {
    /// Package format version for forward compatibility.
    pub version: u32,
    /// Unique identifier for this acceptance package.
    pub package_id: Hash,
    /// The effect/decision this package provides evidence for.
    pub subject_effect_id: Hash,
    /// Digest of the complete receipt set.
    pub receipt_set_digest: Hash,
    /// Individual receipt pointers with their verification metadata.
    pub receipt_pointers: Vec<ReceiptPointer>,
    /// Policy snapshot hash that was active when the decision was made.
    pub policy_snapshot_hash: Hash,
    /// Timestamp envelope reference for temporal binding.
    pub time_authority_ref: Hash,
    /// The admission verdict this evidence supports.
    pub verdict: AdmissionVerdict,
    /// Signature over canonical package bytes by the issuing authority.
    pub issuer_signature: Vec<u8>,
    /// Verifying key of the issuer (for portable verification).
    pub issuer_verifying_key: [u8; 32],
}

/// Individual receipt pointer within an acceptance package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPointer {
    /// Type of receipt (delegation, consume, effect, boundary,
    /// declassification).
    pub receipt_type: ReceiptType,
    /// Content-addressed digest of the receipt.
    pub receipt_digest: Hash,
    /// CAS address where the receipt can be retrieved.
    pub cas_address: Option<String>,
    /// Ledger event ID that records this receipt.
    pub ledger_event_id: Option<String>,
}

impl ReceiptPointer {
    /// Returns `true` if this pointer carries at least one non-empty locator
    /// (CAS address or ledger event ID).
    #[must_use]
    pub fn has_any_locator(&self) -> bool {
        self.cas_address
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || self
                .ledger_event_id
                .as_deref()
                .is_some_and(|value| !value.is_empty())
    }
}

/// Receipt types that can appear in an acceptance package.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    /// Delegation receipt pointer.
    Delegation,
    /// Consumption proof receipt pointer.
    Consume,
    /// Effect witness receipt pointer.
    Effect,
    /// Boundary-flow witness receipt pointer.
    Boundary,
    /// Declassification witness receipt pointer.
    Declassification,
    /// Gate-admission witness receipt pointer.
    GateAdmission,
}

impl ReceiptType {
    const fn stable_tag(self) -> u8 {
        match self {
            Self::Delegation => 1,
            Self::Consume => 2,
            Self::Effect => 3,
            Self::Boundary => 4,
            Self::Declassification => 5,
            Self::GateAdmission => 6,
        }
    }
}

/// Admission verdict bound by the package.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionVerdict {
    /// Effect was admitted.
    Admitted,
    /// Effect was denied.
    Denied,
}

/// Error returned by package signing/canonicalization helpers.
#[derive(Debug, Error)]
pub enum AcceptancePackageError {
    /// Canonicalization/serialization failed.
    #[error("acceptance package canonicalization failed: {message}")]
    Canonicalization {
        /// Serialization detail.
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequiredReceipt {
    receipt_type: ReceiptType,
    reason: &'static str,
}

impl AcceptancePackageV1 {
    /// Returns the current package schema version.
    #[must_use]
    pub const fn current_version() -> u32 {
        ACCEPTANCE_PACKAGE_VERSION
    }

    /// Deterministically recomputes `receipt_set_digest`.
    ///
    /// The digest is order-independent and canonicalized by stable sorting.
    #[must_use]
    pub fn compute_receipt_set_digest(receipt_pointers: &[ReceiptPointer]) -> Hash {
        let mut ordered = receipt_pointers.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.receipt_type
                .stable_tag()
                .cmp(&right.receipt_type.stable_tag())
                .then_with(|| left.receipt_digest.cmp(&right.receipt_digest))
                .then_with(|| {
                    left.cas_address
                        .as_deref()
                        .unwrap_or("")
                        .cmp(right.cas_address.as_deref().unwrap_or(""))
                })
                .then_with(|| {
                    left.ledger_event_id
                        .as_deref()
                        .unwrap_or("")
                        .cmp(right.ledger_event_id.as_deref().unwrap_or(""))
                })
        });

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.acceptance_package.receipt_set_digest.v1");
        for pointer in ordered {
            hasher.update(&[pointer.receipt_type.stable_tag()]);
            hasher.update(&pointer.receipt_digest);
            hash_optional_string(&mut hasher, pointer.cas_address.as_deref());
            hash_optional_string(&mut hasher, pointer.ledger_event_id.as_deref());
        }
        *hasher.finalize().as_bytes()
    }

    /// Computes the deterministic package identifier.
    ///
    /// The package ID excludes both `package_id` and `issuer_signature`.
    ///
    /// # Errors
    /// Returns [`AcceptancePackageError::Canonicalization`] when canonical
    /// payload serialization fails.
    pub fn compute_package_id(&self) -> Result<Hash, AcceptancePackageError> {
        let payload = serde_json::to_vec(&PackageIdPayload {
            version: self.version,
            subject_effect_id: self.subject_effect_id,
            receipt_set_digest: self.receipt_set_digest,
            receipt_pointers: &self.receipt_pointers,
            policy_snapshot_hash: self.policy_snapshot_hash,
            time_authority_ref: self.time_authority_ref,
            verdict: self.verdict,
            issuer_verifying_key: self.issuer_verifying_key,
        })
        .map_err(|error| AcceptancePackageError::Canonicalization {
            message: error.to_string(),
        })?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.acceptance_package.package_id.v1");
        hasher.update(&payload);
        Ok(*hasher.finalize().as_bytes())
    }

    /// Canonical bytes that are signed/verified by issuers.
    ///
    /// `issuer_signature` is intentionally excluded.
    ///
    /// # Errors
    /// Returns [`AcceptancePackageError::Canonicalization`] when canonical
    /// payload serialization fails.
    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>, AcceptancePackageError> {
        serde_json::to_vec(&SigningPayload {
            version: self.version,
            package_id: self.package_id,
            subject_effect_id: self.subject_effect_id,
            receipt_set_digest: self.receipt_set_digest,
            receipt_pointers: &self.receipt_pointers,
            policy_snapshot_hash: self.policy_snapshot_hash,
            time_authority_ref: self.time_authority_ref,
            verdict: self.verdict,
            issuer_verifying_key: self.issuer_verifying_key,
        })
        .map_err(|error| AcceptancePackageError::Canonicalization {
            message: error.to_string(),
        })
    }

    /// Signs the package in-place using the supplied signer.
    ///
    /// This updates `issuer_verifying_key`, recomputes `package_id`, and writes
    /// `issuer_signature`.
    ///
    /// # Errors
    /// Returns [`AcceptancePackageError::Canonicalization`] when canonical
    /// payload serialization fails while deriving the signed payload.
    pub fn sign_with(&mut self, signer: &Signer) -> Result<(), AcceptancePackageError> {
        self.version = Self::current_version();
        self.issuer_verifying_key = signer.public_key_bytes();
        self.receipt_set_digest = Self::compute_receipt_set_digest(&self.receipt_pointers);
        self.package_id = self.compute_package_id()?;
        let payload = self.signing_payload_bytes()?;
        self.issuer_signature = signer.sign(&payload).to_bytes().to_vec();
        Ok(())
    }
}

#[derive(Serialize)]
struct PackageIdPayload<'a> {
    version: u32,
    subject_effect_id: Hash,
    receipt_set_digest: Hash,
    receipt_pointers: &'a [ReceiptPointer],
    policy_snapshot_hash: Hash,
    time_authority_ref: Hash,
    verdict: AdmissionVerdict,
    issuer_verifying_key: [u8; 32],
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    version: u32,
    package_id: Hash,
    subject_effect_id: Hash,
    receipt_set_digest: Hash,
    receipt_pointers: &'a [ReceiptPointer],
    policy_snapshot_hash: Hash,
    time_authority_ref: Hash,
    verdict: AdmissionVerdict,
    issuer_verifying_key: [u8; 32],
}

fn hash_optional_string(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(text) => {
            hasher.update(&[1]);
            let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
            hasher.update(&length.to_le_bytes());
            hasher.update(text.as_bytes());
        },
        None => {
            hasher.update(&[0]);
        },
    }
}

/// Verification result from deterministic reverification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// Verified package identifier.
    pub package_id: Hash,
    /// `true` when no error-severity findings were produced.
    pub verified: bool,
    /// Deterministic verifier findings.
    pub findings: Vec<VerificationFinding>,
}

/// Structured verification finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationFinding {
    /// Finding severity.
    pub severity: FindingSeverity,
    /// Stable machine-readable finding code.
    pub code: &'static str,
    /// Human-readable diagnostic detail.
    pub message: String,
}

impl VerificationFinding {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: FindingSeverity::Error,
            code,
            message: message.into(),
        }
    }
}

/// Verification finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    /// Verification-blocking finding.
    Error,
}

/// Trait for resolving receipt content from receipt pointers.
///
/// Different verifier implementations can use different backends while
/// producing identical verification results.
pub trait ReceiptProvider: Send + Sync {
    /// Resolves the raw receipt bytes for a pointer.
    ///
    /// # Errors
    /// Returns `ReceiptResolutionError` when a locator cannot be resolved,
    /// when digest validation fails, or when digest fallback lookup fails.
    fn resolve_receipt(&self, pointer: &ReceiptPointer) -> Result<Vec<u8>, ReceiptResolutionError>;
}

/// Error returned when resolving receipt bytes from a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptResolutionError {
    /// A locator was present on the pointer, but no receipt was found for it.
    LocatorNotFound {
        /// Pointer locator value.
        locator: String,
    },
    /// Resolved receipt bytes did not match the pointer digest.
    DigestMismatch {
        /// Expected digest from the pointer.
        expected: Hash,
        /// Actual digest computed over resolved bytes.
        actual: Hash,
    },
    /// The pointer carries at least one locator, but not the provider-specific
    /// one. Digest fallback is denied for locator-present pointers
    /// (fail-closed).
    LocatorRequired {
        /// Description of which locator is required.
        provider_kind: &'static str,
    },
    /// Digest-based fallback lookup failed.
    NotFound {
        /// Missing digest value.
        digest: Hash,
    },
}

/// CAS-oriented receipt provider implementation.
#[derive(Debug, Clone, Default)]
pub struct CasReceiptProvider {
    receipts_by_address: HashMap<String, Vec<u8>>,
    receipts_by_digest: HashMap<Hash, Vec<u8>>,
}

impl CasReceiptProvider {
    /// Creates an empty CAS provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a receipt under a CAS address.
    ///
    /// Returns the computed digest for convenience.
    pub fn insert_with_address(&mut self, address: impl Into<String>, receipt: Vec<u8>) -> Hash {
        let digest = EventHasher::hash_content(&receipt);
        self.receipts_by_address
            .insert(address.into(), receipt.clone());
        self.receipts_by_digest.insert(digest, receipt);
        digest
    }

    /// Inserts a digest-addressed receipt (no CAS address required).
    pub fn insert_with_digest(&mut self, digest: Hash, receipt: Vec<u8>) {
        self.receipts_by_digest.insert(digest, receipt);
    }

    /// Removes a receipt by CAS address.
    pub fn remove_by_address(&mut self, address: &str) {
        self.receipts_by_address.remove(address);
    }
}

impl ReceiptProvider for CasReceiptProvider {
    fn resolve_receipt(&self, pointer: &ReceiptPointer) -> Result<Vec<u8>, ReceiptResolutionError> {
        if let Some(address) = pointer
            .cas_address
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let receipt = self
                .receipts_by_address
                .get(address)
                .cloned()
                .ok_or_else(|| ReceiptResolutionError::LocatorNotFound {
                    locator: address.to_string(),
                })?;
            let resolved_digest = EventHasher::hash_content(&receipt);
            if resolved_digest != pointer.receipt_digest {
                return Err(ReceiptResolutionError::DigestMismatch {
                    expected: pointer.receipt_digest,
                    actual: resolved_digest,
                });
            }
            return Ok(receipt);
        }

        // Fail closed: if the pointer carries ANY locator (including ledger),
        // digest-only fallback is denied. The CAS provider MUST resolve via
        // its own locator for locator-present pointers.
        if pointer.has_any_locator() {
            return Err(ReceiptResolutionError::LocatorRequired {
                provider_kind: "cas",
            });
        }

        // Pure digest-only fallback is only allowed when no locators exist.
        self.receipts_by_digest
            .get(&pointer.receipt_digest)
            .cloned()
            .ok_or(ReceiptResolutionError::NotFound {
                digest: pointer.receipt_digest,
            })
    }
}

/// Ledger-oriented receipt provider implementation.
#[derive(Debug, Clone, Default)]
pub struct LedgerReceiptProvider {
    receipts_by_event_id: HashMap<String, Vec<u8>>,
    receipts_by_digest: HashMap<Hash, Vec<u8>>,
}

impl LedgerReceiptProvider {
    /// Creates an empty ledger provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a receipt under a ledger event identifier.
    ///
    /// Returns the computed digest for convenience.
    pub fn insert_with_event_id(
        &mut self,
        ledger_event_id: impl Into<String>,
        receipt: Vec<u8>,
    ) -> Hash {
        let digest = EventHasher::hash_content(&receipt);
        self.receipts_by_event_id
            .insert(ledger_event_id.into(), receipt.clone());
        self.receipts_by_digest.insert(digest, receipt);
        digest
    }

    /// Inserts a digest-addressed receipt (no ledger event ID required).
    pub fn insert_with_digest(&mut self, digest: Hash, receipt: Vec<u8>) {
        self.receipts_by_digest.insert(digest, receipt);
    }
}

impl ReceiptProvider for LedgerReceiptProvider {
    fn resolve_receipt(&self, pointer: &ReceiptPointer) -> Result<Vec<u8>, ReceiptResolutionError> {
        if let Some(event_id) = pointer
            .ledger_event_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            let receipt = self
                .receipts_by_event_id
                .get(event_id)
                .cloned()
                .ok_or_else(|| ReceiptResolutionError::LocatorNotFound {
                    locator: event_id.to_string(),
                })?;
            let resolved_digest = EventHasher::hash_content(&receipt);
            if resolved_digest != pointer.receipt_digest {
                return Err(ReceiptResolutionError::DigestMismatch {
                    expected: pointer.receipt_digest,
                    actual: resolved_digest,
                });
            }
            return Ok(receipt);
        }

        // Fail closed: if the pointer carries ANY locator (including CAS),
        // digest-only fallback is denied. The ledger provider MUST resolve via
        // its own locator for locator-present pointers.
        if pointer.has_any_locator() {
            return Err(ReceiptResolutionError::LocatorRequired {
                provider_kind: "ledger",
            });
        }

        // Pure digest-only fallback is only allowed when no locators exist.
        self.receipts_by_digest
            .get(&pointer.receipt_digest)
            .cloned()
            .ok_or(ReceiptResolutionError::NotFound {
                digest: pointer.receipt_digest,
            })
    }
}

/// Set of trusted issuer verifying keys for acceptance package validation.
///
/// When provided, the verifier checks that the package's
/// `issuer_verifying_key` matches one of the trusted keys, failing closed on
/// mismatch.
#[derive(Debug, Clone)]
pub struct TrustedIssuerSet {
    trusted_keys: Vec<[u8; 32]>,
}

impl TrustedIssuerSet {
    /// Creates a trust set from verifying key bytes.
    #[must_use]
    pub fn from_keys(keys: &[[u8; 32]]) -> Self {
        Self {
            trusted_keys: keys.to_vec(),
        }
    }

    /// Returns `true` if the given key is in the trusted set.
    #[must_use]
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.trusted_keys.iter().any(|trusted| trusted == key)
    }
}

/// Deterministic verifier that checks acceptance package integrity without
/// ambient runtime state.
#[must_use]
pub fn verify_acceptance_package(
    package: &AcceptancePackageV1,
    receipt_provider: &dyn ReceiptProvider,
    trusted_issuers: Option<&TrustedIssuerSet>,
) -> VerificationResult {
    let mut findings = Vec::new();

    if package.version != ACCEPTANCE_PACKAGE_VERSION {
        findings.push(VerificationFinding::error(
            "ACPT_VERSION_UNSUPPORTED",
            format!(
                "unsupported package version: expected {}, got {}",
                ACCEPTANCE_PACKAGE_VERSION, package.version
            ),
        ));
    }

    if package.subject_effect_id == ZERO_HASH {
        findings.push(VerificationFinding::error(
            "ACPT_SUBJECT_EFFECT_ZERO",
            "subject_effect_id must be non-zero",
        ));
    }

    if package.policy_snapshot_hash == ZERO_HASH {
        findings.push(VerificationFinding::error(
            "ACPT_POLICY_HASH_ZERO",
            "policy_snapshot_hash must be non-zero",
        ));
    }

    if package.time_authority_ref == ZERO_HASH {
        findings.push(VerificationFinding::error(
            "ACPT_TIME_AUTHORITY_ZERO",
            "time_authority_ref must be non-zero",
        ));
    }

    if package.receipt_pointers.is_empty() {
        findings.push(VerificationFinding::error(
            "ACPT_RECEIPT_POINTERS_EMPTY",
            "receipt_pointers must be non-empty",
        ));
    }

    let recomputed_receipt_set_digest =
        AcceptancePackageV1::compute_receipt_set_digest(&package.receipt_pointers);
    if recomputed_receipt_set_digest != package.receipt_set_digest {
        findings.push(VerificationFinding::error(
            "ACPT_RECEIPT_SET_DIGEST_MISMATCH",
            format!(
                "receipt_set_digest mismatch: expected {}, got {}",
                hex::encode(recomputed_receipt_set_digest),
                hex::encode(package.receipt_set_digest)
            ),
        ));
    }

    match package.compute_package_id() {
        Ok(recomputed_package_id) => {
            if recomputed_package_id != package.package_id {
                findings.push(VerificationFinding::error(
                    "ACPT_PACKAGE_ID_MISMATCH",
                    format!(
                        "package_id mismatch: expected {}, got {}",
                        hex::encode(recomputed_package_id),
                        hex::encode(package.package_id)
                    ),
                ));
            }
        },
        Err(error) => findings.push(VerificationFinding::error(
            "ACPT_PACKAGE_ID_RECOMPUTE_FAILED",
            error.to_string(),
        )),
    }

    verify_signature_envelope(package, &mut findings);
    if let Some(trusted) = trusted_issuers {
        if !trusted.contains(&package.issuer_verifying_key) {
            findings.push(VerificationFinding::error(
                "ACPT_ISSUER_UNTRUSTED",
                format!(
                    "issuer verifying key {} is not in the trusted issuer set",
                    hex::encode(package.issuer_verifying_key)
                ),
            ));
        }
    }
    verify_required_receipt_types(package, &mut findings);
    verify_receipts(package, receipt_provider, &mut findings);

    let verified = findings
        .iter()
        .all(|finding| finding.severity != FindingSeverity::Error);

    VerificationResult {
        package_id: package.package_id,
        verified,
        findings,
    }
}

fn verify_signature_envelope(
    package: &AcceptancePackageV1,
    findings: &mut Vec<VerificationFinding>,
) {
    let payload = match package.signing_payload_bytes() {
        Ok(payload) => payload,
        Err(error) => {
            findings.push(VerificationFinding::error(
                "ACPT_SIGNING_PAYLOAD_INVALID",
                error.to_string(),
            ));
            return;
        },
    };

    let verifying_key = match parse_verifying_key(&package.issuer_verifying_key) {
        Ok(key) => key,
        Err(error) => {
            findings.push(VerificationFinding::error(
                "ACPT_ISSUER_KEY_INVALID",
                error.to_string(),
            ));
            return;
        },
    };

    let signature = match parse_signature(&package.issuer_signature) {
        Ok(signature) => signature,
        Err(error) => {
            findings.push(VerificationFinding::error(
                "ACPT_SIGNATURE_INVALID",
                error.to_string(),
            ));
            return;
        },
    };

    if verify_signature(&verifying_key, &payload, &signature).is_err() {
        findings.push(VerificationFinding::error(
            "ACPT_SIGNATURE_VERIFY_FAILED",
            "issuer signature verification failed",
        ));
    }
}

const fn required_receipts(verdict: AdmissionVerdict) -> &'static [RequiredReceipt] {
    match verdict {
        AdmissionVerdict::Admitted => &[
            RequiredReceipt {
                receipt_type: ReceiptType::Consume,
                reason: "authoritative consume witness is mandatory for admitted effects",
            },
            RequiredReceipt {
                receipt_type: ReceiptType::Effect,
                reason: "effect witness is mandatory for admitted effects",
            },
            RequiredReceipt {
                receipt_type: ReceiptType::Boundary,
                reason: "boundary-flow witness is mandatory for admitted effects",
            },
            RequiredReceipt {
                receipt_type: ReceiptType::GateAdmission,
                reason: "gate-admission witness is mandatory for admitted effects",
            },
        ],
        AdmissionVerdict::Denied => &[RequiredReceipt {
            receipt_type: ReceiptType::GateAdmission,
            reason: "deny verdict must still include gate-admission witness",
        }],
    }
}

fn verify_required_receipt_types(
    package: &AcceptancePackageV1,
    findings: &mut Vec<VerificationFinding>,
) {
    for required in required_receipts(package.verdict) {
        let present = package
            .receipt_pointers
            .iter()
            .any(|pointer| pointer.receipt_type == required.receipt_type);
        if !present {
            findings.push(VerificationFinding::error(
                "ACPT_REQUIRED_RECEIPT_MISSING",
                format!(
                    "required receipt pointer missing for {:?}: {}",
                    required.receipt_type, required.reason
                ),
            ));
        }
    }
}

fn verify_receipts(
    package: &AcceptancePackageV1,
    receipt_provider: &dyn ReceiptProvider,
    findings: &mut Vec<VerificationFinding>,
) {
    let mut seen = std::collections::HashSet::new();

    for pointer in &package.receipt_pointers {
        if pointer.receipt_digest == ZERO_HASH {
            findings.push(VerificationFinding::error(
                "ACPT_RECEIPT_DIGEST_ZERO",
                format!("receipt digest is zero for {:?}", pointer.receipt_type),
            ));
            continue;
        }

        if !seen.insert((pointer.receipt_type, pointer.receipt_digest)) {
            findings.push(VerificationFinding::error(
                "ACPT_DUPLICATE_RECEIPT_POINTER",
                format!(
                    "duplicate receipt pointer detected for {:?} digest {}",
                    pointer.receipt_type,
                    hex::encode(pointer.receipt_digest)
                ),
            ));
        }

        match receipt_provider.resolve_receipt(pointer) {
            Ok(receipt_bytes) => {
                let resolved_digest = EventHasher::hash_content(&receipt_bytes);
                if resolved_digest != pointer.receipt_digest {
                    findings.push(VerificationFinding::error(
                        "ACPT_RECEIPT_DIGEST_MISMATCH",
                        format!(
                            "receipt digest mismatch for {:?}: expected {}, got {}",
                            pointer.receipt_type,
                            hex::encode(pointer.receipt_digest),
                            hex::encode(resolved_digest)
                        ),
                    ));
                }
            },
            Err(ReceiptResolutionError::LocatorNotFound { locator }) => {
                findings.push(VerificationFinding::error(
                    "ACPT_RECEIPT_MISSING",
                    format!(
                        "receipt bytes unavailable for {:?} via locator {}",
                        pointer.receipt_type, locator
                    ),
                ));
            },
            Err(ReceiptResolutionError::DigestMismatch { expected, actual }) => {
                findings.push(VerificationFinding::error(
                    "ACPT_RECEIPT_DIGEST_MISMATCH",
                    format!(
                        "receipt digest mismatch for {:?}: expected {}, got {}",
                        pointer.receipt_type,
                        hex::encode(expected),
                        hex::encode(actual)
                    ),
                ));
            },
            Err(ReceiptResolutionError::NotFound { digest }) => {
                findings.push(VerificationFinding::error(
                    "ACPT_RECEIPT_MISSING",
                    format!(
                        "receipt bytes unavailable for {:?} digest {}",
                        pointer.receipt_type,
                        hex::encode(digest)
                    ),
                ));
            },
            Err(ReceiptResolutionError::LocatorRequired { provider_kind }) => {
                findings.push(VerificationFinding::error(
                    "ACPT_RECEIPT_LOCATOR_REQUIRED",
                    format!(
                        "receipt pointer for {:?} carries locators but {} provider has no {}-specific locator; digest fallback denied",
                        pointer.receipt_type, provider_kind, provider_kind
                    ),
                ));
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static FIXTURE_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Clone)]
    struct ReceiptFixture {
        pointer: ReceiptPointer,
        receipt_bytes: Vec<u8>,
    }

    fn deterministic_signer() -> Signer {
        Signer::from_bytes(&[0x55; 32]).expect("deterministic signer bytes must parse")
    }

    fn fixture_receipts() -> Vec<(ReceiptType, Vec<u8>)> {
        vec![
            (
                ReceiptType::Consume,
                br#"{"kind":"consume","ajc_id":"AJC-001","tick":42}"#.to_vec(),
            ),
            (
                ReceiptType::Effect,
                br#"{"kind":"effect","request_id":"REQ-001","tool":"execute"}"#.to_vec(),
            ),
            (
                ReceiptType::Boundary,
                br#"{"kind":"boundary","taint_allow":true,"classification_allow":true}"#.to_vec(),
            ),
            (
                ReceiptType::GateAdmission,
                br#"{"kind":"gate_admission","verdict":"admitted"}"#.to_vec(),
            ),
            (
                ReceiptType::Declassification,
                br#"{"kind":"declassification","receipt_id":"RR-001"}"#.to_vec(),
            ),
        ]
    }

    fn build_fixture_package() -> (AcceptancePackageV1, Vec<ReceiptFixture>) {
        let mut pointers = Vec::new();
        let mut fixtures = Vec::new();

        for (index, (receipt_type, receipt_bytes)) in fixture_receipts().into_iter().enumerate() {
            let digest = EventHasher::hash_content(&receipt_bytes);
            let pointer = ReceiptPointer {
                receipt_type,
                receipt_digest: digest,
                cas_address: Some(format!("cas://receipt/{index}")),
                ledger_event_id: Some(format!("EVT-RECEIPT-{index:04}")),
            };
            fixtures.push(ReceiptFixture {
                pointer: pointer.clone(),
                receipt_bytes,
            });
            pointers.push(pointer);
        }

        let mut package = AcceptancePackageV1 {
            version: ACCEPTANCE_PACKAGE_VERSION,
            package_id: ZERO_HASH,
            subject_effect_id: EventHasher::hash_content(b"subject-effect-001"),
            receipt_set_digest: AcceptancePackageV1::compute_receipt_set_digest(&pointers),
            receipt_pointers: pointers,
            policy_snapshot_hash: [0xA1; 32],
            time_authority_ref: [0xB2; 32],
            verdict: AdmissionVerdict::Admitted,
            issuer_signature: Vec::new(),
            issuer_verifying_key: [0u8; 32],
        };

        package
            .sign_with(&deterministic_signer())
            .expect("fixture package signing should succeed");
        (package, fixtures)
    }

    fn build_cas_provider(fixtures: &[ReceiptFixture]) -> CasReceiptProvider {
        let mut provider = CasReceiptProvider::new();
        for fixture in fixtures {
            let address = fixture
                .pointer
                .cas_address
                .clone()
                .expect("fixture pointers always carry cas addresses");
            provider.insert_with_address(address, fixture.receipt_bytes.clone());
        }
        provider
    }

    fn build_ledger_provider(fixtures: &[ReceiptFixture]) -> LedgerReceiptProvider {
        let mut provider = LedgerReceiptProvider::new();
        for fixture in fixtures {
            let event_id = fixture
                .pointer
                .ledger_event_id
                .clone()
                .expect("fixture pointers always carry ledger event IDs");
            provider.insert_with_event_id(event_id, fixture.receipt_bytes.clone());
        }
        provider
    }

    fn build_digest_only_provider(fixtures: &[ReceiptFixture]) -> CasReceiptProvider {
        let mut provider = CasReceiptProvider::new();
        for fixture in fixtures {
            provider.insert_with_digest(
                fixture.pointer.receipt_digest,
                fixture.receipt_bytes.clone(),
            );
        }
        provider
    }

    fn build_digest_only_ledger_provider(fixtures: &[ReceiptFixture]) -> LedgerReceiptProvider {
        let mut provider = LedgerReceiptProvider::new();
        for fixture in fixtures {
            provider.insert_with_digest(
                fixture.pointer.receipt_digest,
                fixture.receipt_bytes.clone(),
            );
        }
        provider
    }

    #[test]
    fn verify_acceptance_package_valid_package_passes() {
        let (package, fixtures) = build_fixture_package();
        let cas_provider = build_cas_provider(&fixtures);

        let result = verify_acceptance_package(&package, &cas_provider, None);
        assert!(result.verified, "valid package must verify: {result:?}");
        assert_eq!(result.findings.len(), 0);
    }

    #[test]
    fn verify_acceptance_package_missing_receipt_denies() {
        let (package, fixtures) = build_fixture_package();
        let cas_provider = build_cas_provider(&fixtures[1..]);

        let result = verify_acceptance_package(&package, &cas_provider, None);
        assert!(
            !result.verified,
            "package with missing receipt must deny: {result:?}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "ACPT_RECEIPT_MISSING"),
            "missing-receipt finding must be present: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_bad_signature_denies() {
        let (mut package, fixtures) = build_fixture_package();
        let cas_provider = build_cas_provider(&fixtures);

        package.issuer_signature[0] ^= 0x80;
        let result = verify_acceptance_package(&package, &cas_provider, None);
        assert!(
            !result.verified,
            "package with invalid signature must deny: {result:?}"
        );
        assert!(
            result.findings.iter().any(|finding| {
                finding.code == "ACPT_SIGNATURE_VERIFY_FAILED"
                    || finding.code == "ACPT_SIGNATURE_INVALID"
            }),
            "signature failure finding must be present: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_locator_present_but_retrieval_fails_denies() {
        let (package, fixtures) = build_fixture_package();
        let mut cas_provider = build_cas_provider(&fixtures);
        let first_address = fixtures[0]
            .pointer
            .cas_address
            .clone()
            .expect("fixture pointer should have address");
        cas_provider.remove_by_address(&first_address);

        let result = verify_acceptance_package(&package, &cas_provider, None);
        assert!(
            !result.verified,
            "missing locator-targeted receipt must deny: {result:?}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "ACPT_RECEIPT_MISSING"),
            "missing-receipt finding must be present: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_receipt_digest_mismatch_denies() {
        let (package, fixtures) = build_fixture_package();
        let mut cas_provider = build_cas_provider(&fixtures);
        let first_address = fixtures[0]
            .pointer
            .cas_address
            .clone()
            .expect("fixture pointer should have address");
        cas_provider.insert_with_address(first_address, b"tampered-receipt".to_vec());

        let result = verify_acceptance_package(&package, &cas_provider, None);
        assert!(
            !result.verified,
            "tampered receipt content must deny: {result:?}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "ACPT_RECEIPT_DIGEST_MISMATCH"),
            "digest mismatch finding must be present: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_digest_only_lookup_without_locator_passes() {
        let (mut package, fixtures) = build_fixture_package();
        for pointer in &mut package.receipt_pointers {
            pointer.cas_address = None;
            pointer.ledger_event_id = None;
        }
        package
            .sign_with(&deterministic_signer())
            .expect("re-signing package without locators should succeed");
        let digest_provider = build_digest_only_provider(&fixtures);

        let result = verify_acceptance_package(&package, &digest_provider, None);
        assert!(
            result.verified,
            "digest-only lookup without locators must pass: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_zero_policy_hash_denies() {
        let (mut package, fixtures) = build_fixture_package();
        let cas_provider = build_cas_provider(&fixtures);
        package.policy_snapshot_hash = ZERO_HASH;

        let result = verify_acceptance_package(&package, &cas_provider, None);
        assert!(
            !result.verified,
            "zero policy snapshot hash must deny: {result:?}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "ACPT_POLICY_HASH_ZERO"),
            "policy hash finding must be present: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_cross_verifier_concordance() {
        let (package, fixtures) = build_fixture_package();
        let cas_provider = build_cas_provider(&fixtures);
        let ledger_provider = build_ledger_provider(&fixtures);

        let cas_result = verify_acceptance_package(&package, &cas_provider, None);
        let ledger_result = verify_acceptance_package(&package, &ledger_provider, None);

        assert!(
            cas_result.verified,
            "CAS verifier must pass: {cas_result:?}"
        );
        assert!(
            ledger_result.verified,
            "ledger verifier must pass: {ledger_result:?}"
        );
        assert_eq!(
            cas_result, ledger_result,
            "independent verifiers must produce identical deterministic results"
        );
    }

    #[test]
    fn verify_acceptance_package_durable_readback_concordance_matches_write_buffer() {
        let (package, fixtures) = build_fixture_package();

        let write_buffer_cas_provider = build_cas_provider(&fixtures);
        let write_buffer_ledger_provider = build_ledger_provider(&fixtures);

        let mut durable_cas = HashMap::new();
        let mut durable_ledger = HashMap::new();
        for fixture in &fixtures {
            let cas_address = fixture
                .pointer
                .cas_address
                .clone()
                .expect("fixture pointer should have CAS address");
            let ledger_event_id = fixture
                .pointer
                .ledger_event_id
                .clone()
                .expect("fixture pointer should have ledger event ID");
            durable_cas.insert(cas_address, fixture.receipt_bytes.clone());
            durable_ledger.insert(ledger_event_id, fixture.receipt_bytes.clone());
        }

        let mut readback_cas_provider = CasReceiptProvider::new();
        let mut readback_ledger_provider = LedgerReceiptProvider::new();
        for pointer in &package.receipt_pointers {
            if let Some(address) = pointer.cas_address.as_deref() {
                let receipt_bytes = durable_cas
                    .get(address)
                    .cloned()
                    .expect("durable CAS retrieval should succeed");
                assert_eq!(
                    EventHasher::hash_content(&receipt_bytes),
                    pointer.receipt_digest,
                    "durable CAS read-back digest must match pointer digest"
                );
                readback_cas_provider.insert_with_address(address.to_string(), receipt_bytes);
            }
            if let Some(event_id) = pointer.ledger_event_id.as_deref() {
                let receipt_bytes = durable_ledger
                    .get(event_id)
                    .cloned()
                    .expect("durable ledger retrieval should succeed");
                assert_eq!(
                    EventHasher::hash_content(&receipt_bytes),
                    pointer.receipt_digest,
                    "durable ledger read-back digest must match pointer digest"
                );
                readback_ledger_provider.insert_with_event_id(event_id.to_string(), receipt_bytes);
            }
        }

        let write_buffer_cas_result =
            verify_acceptance_package(&package, &write_buffer_cas_provider, None);
        let readback_cas_result = verify_acceptance_package(&package, &readback_cas_provider, None);
        assert_eq!(
            write_buffer_cas_result, readback_cas_result,
            "CAS durable read-back verifier result must match write-buffer verifier result"
        );

        let write_buffer_ledger_result =
            verify_acceptance_package(&package, &write_buffer_ledger_provider, None);
        let readback_ledger_result =
            verify_acceptance_package(&package, &readback_ledger_provider, None);
        assert_eq!(
            write_buffer_ledger_result, readback_ledger_result,
            "ledger durable read-back verifier result must match write-buffer verifier result"
        );
    }

    #[test]
    fn verify_acceptance_package_replay_fixture_roundtrip_in_clean_context() {
        let (package, fixtures) = build_fixture_package();
        let fixture_path = unique_fixture_path();

        let serialized =
            serde_json::to_vec(&package).expect("fixture package serialization should succeed");
        fs::write(&fixture_path, &serialized).expect("fixture write should succeed");

        let loaded_bytes = fs::read(&fixture_path).expect("fixture read should succeed");
        let loaded_package: AcceptancePackageV1 =
            serde_json::from_slice(&loaded_bytes).expect("fixture decode should succeed");

        let provider = build_cas_provider(&fixtures);
        let result = verify_acceptance_package(&loaded_package, &provider, None);
        assert!(
            result.verified,
            "clean-context replay verification must pass: {result:?}"
        );

        let _ = fs::remove_file(&fixture_path);
    }

    fn unique_fixture_path() -> PathBuf {
        let sequence = FIXTURE_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!(
            "apm2_acceptance_package_fixture_{pid}_{sequence}.json"
        ))
    }

    #[test]
    fn verify_acceptance_package_untrusted_issuer_with_valid_signature_denies() {
        let (package, fixtures) = build_fixture_package();
        let cas_provider = build_cas_provider(&fixtures);
        let untrusted_signer =
            Signer::from_bytes(&[0xAA; 32]).expect("untrusted signer bytes must parse");
        let trusted = TrustedIssuerSet::from_keys(&[untrusted_signer.public_key_bytes()]);

        let result = verify_acceptance_package(&package, &cas_provider, Some(&trusted));
        assert!(
            !result.verified,
            "valid signature from untrusted issuer must deny: {result:?}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "ACPT_ISSUER_UNTRUSTED"),
            "untrusted issuer finding must be present: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_trusted_issuer_with_valid_signature_passes() {
        let (package, fixtures) = build_fixture_package();
        let cas_provider = build_cas_provider(&fixtures);
        let trusted = TrustedIssuerSet::from_keys(&[deterministic_signer().public_key_bytes()]);

        let result = verify_acceptance_package(&package, &cas_provider, Some(&trusted));
        assert!(
            result.verified,
            "valid signature from trusted issuer must pass: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_locator_present_digest_fallback_denied_cas() {
        let (mut package, fixtures) = build_fixture_package();
        for pointer in &mut package.receipt_pointers {
            pointer.cas_address = None;
        }
        package
            .sign_with(&deterministic_signer())
            .expect("re-signing package after locator edits should succeed");

        let digest_provider = build_digest_only_provider(&fixtures);
        let result = verify_acceptance_package(&package, &digest_provider, None);
        assert!(
            !result.verified,
            "digest fallback must be denied when any locator is present: {result:?}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "ACPT_RECEIPT_LOCATOR_REQUIRED"),
            "locator-required finding must be present: {result:?}"
        );
    }

    #[test]
    fn verify_acceptance_package_locator_present_digest_fallback_denied_ledger() {
        let (mut package, fixtures) = build_fixture_package();
        for pointer in &mut package.receipt_pointers {
            pointer.ledger_event_id = None;
        }
        package
            .sign_with(&deterministic_signer())
            .expect("re-signing package after locator edits should succeed");

        let digest_provider = build_digest_only_ledger_provider(&fixtures);
        let result = verify_acceptance_package(&package, &digest_provider, None);
        assert!(
            !result.verified,
            "digest fallback must be denied when any locator is present: {result:?}"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "ACPT_RECEIPT_LOCATOR_REQUIRED"),
            "locator-required finding must be present: {result:?}"
        );
    }
}
