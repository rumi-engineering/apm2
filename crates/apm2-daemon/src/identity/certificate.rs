//! Cell/holon certificate types for RFC-0020 section 1.7.6.
//!
//! These types bind stable identity IDs (`CellIdV1`, `HolonIdV1`) to
//! verification material and enforce strict role separation between
//! root/genesis keys, operational keys, and delegated session keys.

use std::collections::BTreeSet;
use std::str::FromStr;

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use super::{
    AlgorithmTag, CellGenesisV1, CellIdV1, HolonGenesisV1, HolonIdV1, HolonPurpose, KeyIdError,
    PolicyRootId, PublicKeyIdV1,
};

/// Domain separator for `CellCertificateV1` canonical bytes.
const CELL_CERT_DOMAIN_SEPARATOR: &[u8] = b"apm2:cell_certificate:v1\0";
/// Domain separator for `HolonCertificateV1` canonical bytes.
const HOLON_CERT_DOMAIN_SEPARATOR: &[u8] = b"apm2:holon_certificate:v1\0";

/// Ed25519 public key size in bytes.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Maximum length for certificate trust-domain values.
const MAX_TRUST_DOMAIN_LEN: usize = 253;
/// Maximum length for revocation stream identifiers.
const MAX_REVOCATION_STREAM_LEN: usize = 256;
/// Maximum length for SPIFFE IDs.
const MAX_SPIFFE_ID_LEN: usize = 512;
/// Maximum endpoint hints allowed in a single certificate.
const MAX_ENDPOINT_HINTS: usize = 32;
/// Maximum endpoint hint length.
const MAX_ENDPOINT_HINT_LEN: usize = 512;
/// Maximum number of purpose tags allowed.
const MAX_PURPOSES: usize = 8;
/// Maximum validators carried in a cell certificate.
const MAX_VALIDATORS: usize = 256;

/// Certificate and delegation validation errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// Wrapped canonical identity error.
    #[error("identity validation failed: {0}")]
    KeyId(#[from] KeyIdError),

    /// Generic invalid field error.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Field name.
        field: &'static str,
        /// Human-readable reason.
        reason: String,
    },

    /// Ed25519 key bytes must be exactly 32 bytes.
    #[error("invalid Ed25519 key length for {field}: expected {expected}, got {got}")]
    InvalidEd25519KeyLength {
        /// Field name.
        field: &'static str,
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// Signature bytes must be exactly 64 bytes.
    #[error("invalid signature length: expected 64, got {got}")]
    InvalidSignatureLength {
        /// Actual signature length.
        got: usize,
    },

    /// `cell_id` does not match derivation from committed genesis inputs.
    #[error("cell_id binding mismatch")]
    CellIdBindingMismatch,

    /// `holon_id` does not match derivation from committed genesis inputs.
    #[error("holon_id binding mismatch")]
    HolonIdBindingMismatch,

    /// Key ID does not match provided key bytes.
    #[error("public key id mismatch for {field}")]
    PublicKeyIdMismatch {
        /// Field name.
        field: &'static str,
    },

    /// Root/operational/session role overlap is forbidden.
    #[error("key role overlap between {left} and {right}")]
    KeyRoleOverlap {
        /// Left role.
        left: &'static str,
        /// Right role.
        right: &'static str,
    },

    /// HTF validity window is invalid.
    #[error(
        "invalid validity window: expires_at_tick ({expires_at_tick}) must be greater than issued_at_envelope_ref ({issued_at_envelope_ref})"
    )]
    InvalidValidityWindow {
        /// Issued-at envelope reference.
        issued_at_envelope_ref: u64,
        /// Expiry tick.
        expires_at_tick: u64,
    },

    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Session delegation lifetime exceeds the maximum allowed ticks.
    #[error("delegation lifetime {lifetime_ticks} exceeds maximum of {max_ticks}")]
    DelegationLifetimeExceeded {
        /// Actual delegation lifetime in ticks.
        lifetime_ticks: u64,
        /// Maximum allowed lifetime in ticks.
        max_ticks: u64,
    },

    /// Unknown purpose token encountered while parsing.
    #[error("unknown purpose tag: {tag}")]
    UnknownPurposeTag {
        /// Rejected token.
        tag: String,
    },

    /// Delegation is not yet valid at the verifier's current tick.
    #[error(
        "delegation not yet valid: current_tick ({current_tick}) < issued_at_envelope_ref ({issued_at_envelope_ref})"
    )]
    DelegationNotYetValid {
        /// The verifier's current HTF tick.
        current_tick: u64,
        /// The delegation's issued-at envelope reference.
        issued_at_envelope_ref: u64,
    },

    /// Delegation has expired at the verifier's current tick.
    #[error(
        "delegation expired: current_tick ({current_tick}) >= expires_at_tick ({expires_at_tick})"
    )]
    DelegationExpired {
        /// The verifier's current HTF tick.
        current_tick: u64,
        /// The delegation's expiry tick.
        expires_at_tick: u64,
    },

    /// Ed25519 public key bytes are not a valid curve point.
    #[error("malformed Ed25519 key bytes for {field}: not a valid curve point")]
    MalformedKeyBytes {
        /// Field name.
        field: &'static str,
    },
}

/// Revocation/rotation discovery pointer for a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RevocationPointer {
    /// Pointer to a ledger stream and envelope reference.
    LedgerAnchor {
        /// Ledger stream/event family identifier.
        stream: String,
        /// Earliest relevant envelope reference.
        from_envelope_ref: u64,
    },
    /// Pointer to a CAS artifact digest.
    CasDigest([u8; 32]),
}

impl RevocationPointer {
    fn validate(&self) -> Result<(), CertificateError> {
        match self {
            Self::LedgerAnchor {
                stream,
                from_envelope_ref,
            } => {
                validate_ascii_visible(
                    "revocation_pointer.stream",
                    stream,
                    MAX_REVOCATION_STREAM_LEN,
                )?;
                if *from_envelope_ref == 0 {
                    return Err(CertificateError::InvalidField {
                        field: "revocation_pointer.from_envelope_ref",
                        reason: "must be non-zero".to_string(),
                    });
                }
            },
            Self::CasDigest(_) => {},
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CertificateError> {
        self.validate()?;
        let mut out = Vec::with_capacity(1 + 4 + MAX_REVOCATION_STREAM_LEN + 8);
        match self {
            Self::LedgerAnchor {
                stream,
                from_envelope_ref,
            } => {
                out.push(0x01);
                write_len_prefixed(&mut out, stream.as_bytes());
                out.extend_from_slice(&from_envelope_ref.to_le_bytes());
            },
            Self::CasDigest(hash) => {
                out.push(0x02);
                out.extend_from_slice(hash);
            },
        }
        Ok(out)
    }
}

/// Validate key-role separation (HSI 1.7.2b).
pub fn validate_key_roles(
    genesis_key_id: &PublicKeyIdV1,
    operational_key_id: &PublicKeyIdV1,
    session_key_id: Option<&PublicKeyIdV1>,
) -> Result<(), CertificateError> {
    if genesis_key_id == operational_key_id {
        return Err(CertificateError::KeyRoleOverlap {
            left: "genesis",
            right: "operational",
        });
    }

    if let Some(session_key_id) = session_key_id {
        if session_key_id == genesis_key_id {
            return Err(CertificateError::KeyRoleOverlap {
                left: "genesis",
                right: "session",
            });
        }
        if session_key_id == operational_key_id {
            return Err(CertificateError::KeyRoleOverlap {
                left: "operational",
                right: "session",
            });
        }
    }

    Ok(())
}

/// `CellCertificateV1` binds a stable `cell_id` to trust parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CellCertificateV1 {
    cell_id: CellIdV1,
    trust_domain: String,
    ledger_genesis_hash: [u8; 32],
    policy_root: PolicyRootId,
    revocation_pointer: RevocationPointer,
    federation_attestation: Option<[u8; 32]>,
    validators: Vec<PublicKeyIdV1>,
}

impl CellCertificateV1 {
    /// Construct and validate a `CellCertificateV1`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cell_id: CellIdV1,
        trust_domain: impl Into<String>,
        ledger_genesis_hash: [u8; 32],
        policy_root: PolicyRootId,
        revocation_pointer: RevocationPointer,
        federation_attestation: Option<[u8; 32]>,
        validators: Vec<PublicKeyIdV1>,
    ) -> Result<Self, CertificateError> {
        let cert = Self {
            cell_id,
            trust_domain: trust_domain.into(),
            ledger_genesis_hash,
            policy_root,
            revocation_pointer,
            federation_attestation,
            validators,
        };
        cert.validate()?;
        Ok(cert)
    }

    /// Validate all certificate invariants (fail-closed).
    pub fn validate(&self) -> Result<(), CertificateError> {
        validate_ascii_visible("trust_domain", &self.trust_domain, MAX_TRUST_DOMAIN_LEN)?;
        self.revocation_pointer.validate()?;

        let policy_root_bytes = self.policy_root.canonical_bytes();
        if policy_root_bytes.is_empty() {
            return Err(CertificateError::InvalidField {
                field: "policy_root",
                reason: "policy root key id must be non-empty".to_string(),
            });
        }

        if self.validators.len() > MAX_VALIDATORS {
            return Err(CertificateError::InvalidField {
                field: "validators",
                reason: format!(
                    "validator count {} exceeds maximum of {MAX_VALIDATORS}",
                    self.validators.len()
                ),
            });
        }

        if !self.validators.is_empty() && !matches!(self.policy_root, PolicyRootId::Quorum(_)) {
            return Err(CertificateError::InvalidField {
                field: "validators",
                reason: "validators are only valid when policy_root uses quorum mode".to_string(),
            });
        }

        let mut seen = BTreeSet::new();
        for validator in &self.validators {
            if !seen.insert(*validator.as_bytes()) {
                return Err(CertificateError::InvalidField {
                    field: "validators",
                    reason: "duplicate validator key id".to_string(),
                });
            }
        }

        // Rebuild cell genesis commitments and require an exact derived ID
        // match. This enforces binding between certificate data and `cell_id`.
        let genesis = CellGenesisV1::new(
            self.ledger_genesis_hash,
            self.policy_root.clone(),
            self.trust_domain.clone(),
        )?;
        let expected_cell_id = CellIdV1::from_genesis(&genesis);
        if expected_cell_id != self.cell_id {
            return Err(CertificateError::CellIdBindingMismatch);
        }

        Ok(())
    }

    /// Deterministic canonical bytes for CAS hash-addressing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CertificateError> {
        self.validate()?;

        let policy_root_bytes = self.policy_root.canonical_bytes();
        let revocation_bytes = self.revocation_pointer.canonical_bytes()?;
        let mut validators = self
            .validators
            .iter()
            .map(PublicKeyIdV1::to_binary)
            .collect::<Vec<_>>();
        validators.sort_unstable();

        let mut out = Vec::with_capacity(
            CELL_CERT_DOMAIN_SEPARATOR.len()
                + 33
                + 32
                + policy_root_bytes.len()
                + 4
                + self.trust_domain.len()
                + 4
                + revocation_bytes.len()
                + 1
                + self.federation_attestation.map_or(0, |_| 32)
                + 4
                + (validators.len() * 33),
        );

        out.extend_from_slice(CELL_CERT_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.cell_id.to_binary());
        out.extend_from_slice(&self.ledger_genesis_hash);
        out.extend_from_slice(&policy_root_bytes);
        write_len_prefixed(&mut out, self.trust_domain.as_bytes());
        write_len_prefixed(&mut out, &revocation_bytes);
        out.push(u8::from(self.federation_attestation.is_some()));
        if let Some(attestation) = self.federation_attestation {
            out.extend_from_slice(&attestation);
        }

        let validator_count =
            u32::try_from(validators.len()).expect("validators length is bounded to <= 256");
        out.extend_from_slice(&validator_count.to_le_bytes());
        for validator in validators {
            out.extend_from_slice(&validator);
        }
        Ok(out)
    }

    /// Stable `cell_id` bound by this certificate.
    pub const fn cell_id(&self) -> &CellIdV1 {
        &self.cell_id
    }

    /// Bound trust domain.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Bound ledger genesis hash.
    pub const fn ledger_genesis_hash(&self) -> &[u8; 32] {
        &self.ledger_genesis_hash
    }

    /// Bound policy root commitment.
    pub const fn policy_root(&self) -> &PolicyRootId {
        &self.policy_root
    }

    /// Revocation pointer.
    pub const fn revocation_pointer(&self) -> &RevocationPointer {
        &self.revocation_pointer
    }

    /// Optional federation attestation pointer digest.
    pub const fn federation_attestation(&self) -> Option<&[u8; 32]> {
        self.federation_attestation.as_ref()
    }

    /// Optional validator key IDs for quorum policy roots.
    pub fn validators(&self) -> &[PublicKeyIdV1] {
        &self.validators
    }
}

/// `HolonCertificateV1` binds a `holon_id` to cell and key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HolonCertificateV1 {
    holon_id: HolonIdV1,
    cell_id: CellIdV1,
    genesis_public_key_id: PublicKeyIdV1,
    genesis_public_key_bytes: [u8; 32],
    operational_public_key_id: PublicKeyIdV1,
    operational_public_key_bytes: [u8; 32],
    prev_operational_public_key_id: Option<PublicKeyIdV1>,
    spiffe_id: Option<String>,
    endpoint_hints: Vec<String>,
    purposes: Vec<HolonPurpose>,
}

impl HolonCertificateV1 {
    /// Construct and validate a `HolonCertificateV1`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        holon_id: HolonIdV1,
        cell_id: CellIdV1,
        genesis_public_key_id: PublicKeyIdV1,
        genesis_public_key_bytes: &[u8],
        operational_public_key_id: PublicKeyIdV1,
        operational_public_key_bytes: &[u8],
        prev_operational_public_key_id: Option<PublicKeyIdV1>,
        spiffe_id: Option<String>,
        endpoint_hints: Vec<String>,
        purposes: Vec<HolonPurpose>,
    ) -> Result<Self, CertificateError> {
        let cert = Self {
            holon_id,
            cell_id,
            genesis_public_key_id,
            genesis_public_key_bytes: copy_ed25519_key(
                "genesis_public_key_bytes",
                genesis_public_key_bytes,
            )?,
            operational_public_key_id,
            operational_public_key_bytes: copy_ed25519_key(
                "operational_public_key_bytes",
                operational_public_key_bytes,
            )?,
            prev_operational_public_key_id,
            spiffe_id,
            endpoint_hints,
            purposes,
        };
        cert.validate()?;
        Ok(cert)
    }

    /// Parse purpose tokens with fail-closed unknown-tag rejection.
    pub fn parse_purposes(purposes: &[&str]) -> Result<Vec<HolonPurpose>, CertificateError> {
        let mut parsed = Vec::with_capacity(purposes.len());
        for token in purposes {
            parsed.push(HolonPurpose::from_str(token).map_err(|_| {
                CertificateError::UnknownPurposeTag {
                    tag: (*token).to_string(),
                }
            })?);
        }
        Ok(parsed)
    }

    /// Validate all certificate invariants (fail-closed).
    pub fn validate(&self) -> Result<(), CertificateError> {
        let expected_genesis_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &self.genesis_public_key_bytes);
        if expected_genesis_id != self.genesis_public_key_id {
            return Err(CertificateError::PublicKeyIdMismatch {
                field: "genesis_public_key_id",
            });
        }

        let expected_operational_id = PublicKeyIdV1::from_key_bytes(
            AlgorithmTag::Ed25519,
            &self.operational_public_key_bytes,
        );
        if expected_operational_id != self.operational_public_key_id {
            return Err(CertificateError::PublicKeyIdMismatch {
                field: "operational_public_key_id",
            });
        }

        // Fail-closed: verify genesis key bytes are a valid Ed25519 curve
        // point and reject weak/small-order keys.
        let genesis_verifying_key = VerifyingKey::from_bytes(&self.genesis_public_key_bytes)
            .map_err(|_| CertificateError::MalformedKeyBytes {
                field: "genesis_public_key_bytes",
            })?;
        if genesis_verifying_key.is_weak() {
            return Err(CertificateError::InvalidField {
                field: "genesis_public_key_bytes",
                reason: "weak/small-order Ed25519 key rejected".to_string(),
            });
        }

        // Fail-closed: verify operational key bytes are a valid Ed25519 curve
        // point and reject weak/small-order keys.
        let operational_verifying_key =
            VerifyingKey::from_bytes(&self.operational_public_key_bytes).map_err(|_| {
                CertificateError::MalformedKeyBytes {
                    field: "operational_public_key_bytes",
                }
            })?;
        if operational_verifying_key.is_weak() {
            return Err(CertificateError::InvalidField {
                field: "operational_public_key_bytes",
                reason: "weak/small-order Ed25519 key rejected".to_string(),
            });
        }

        validate_key_roles(
            &self.genesis_public_key_id,
            &self.operational_public_key_id,
            None,
        )?;

        if let Some(prev_operational_key_id) = self.prev_operational_public_key_id.as_ref() {
            if prev_operational_key_id == &self.operational_public_key_id {
                return Err(CertificateError::InvalidField {
                    field: "prev_operational_public_key_id",
                    reason: "must differ from current operational key id".to_string(),
                });
            }
            if prev_operational_key_id == &self.genesis_public_key_id {
                return Err(CertificateError::InvalidField {
                    field: "prev_operational_public_key_id",
                    reason: "must differ from genesis key id".to_string(),
                });
            }
        }

        if self.purposes.is_empty() {
            return Err(CertificateError::InvalidField {
                field: "purposes",
                reason: "at least one purpose tag is required".to_string(),
            });
        }
        if self.purposes.len() > MAX_PURPOSES {
            return Err(CertificateError::InvalidField {
                field: "purposes",
                reason: format!(
                    "purpose count {} exceeds maximum of {MAX_PURPOSES}",
                    self.purposes.len()
                ),
            });
        }
        let mut seen_purpose_tokens = BTreeSet::new();
        for purpose in &self.purposes {
            if !seen_purpose_tokens.insert(purpose.as_token()) {
                return Err(CertificateError::InvalidField {
                    field: "purposes",
                    reason: "duplicate purpose tags are not allowed".to_string(),
                });
            }
        }

        if self.endpoint_hints.len() > MAX_ENDPOINT_HINTS {
            return Err(CertificateError::InvalidField {
                field: "endpoint_hints",
                reason: format!(
                    "endpoint hint count {} exceeds maximum of {MAX_ENDPOINT_HINTS}",
                    self.endpoint_hints.len()
                ),
            });
        }
        let mut seen_hints = BTreeSet::new();
        for hint in &self.endpoint_hints {
            validate_ascii_visible("endpoint_hints", hint, MAX_ENDPOINT_HINT_LEN)?;
            if !seen_hints.insert(hint) {
                return Err(CertificateError::InvalidField {
                    field: "endpoint_hints",
                    reason: "duplicate endpoint hints are not allowed".to_string(),
                });
            }
        }

        if let Some(spiffe_id) = self.spiffe_id.as_deref() {
            validate_spiffe_binding(spiffe_id, &self.cell_id, &self.holon_id)?;
        }

        // Rebuild the genesis binding to prove `holon_id` derivation is
        // bound to the immutable root key (never operational/session keys).
        let genesis = HolonGenesisV1::new(
            self.cell_id.clone(),
            self.genesis_public_key_id.clone(),
            self.genesis_public_key_bytes.to_vec(),
            None,
            None,
        )?;
        let expected_holon_id = HolonIdV1::from_genesis(&genesis);
        if expected_holon_id != self.holon_id {
            return Err(CertificateError::HolonIdBindingMismatch);
        }

        Ok(())
    }

    /// Deterministic canonical bytes for CAS hash-addressing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CertificateError> {
        self.validate()?;

        let mut sorted_endpoint_hints = self.endpoint_hints.clone();
        sorted_endpoint_hints.sort_unstable();

        let mut sorted_purpose_tokens = self
            .purposes
            .iter()
            .map(|purpose| purpose.as_token())
            .collect::<Vec<_>>();
        sorted_purpose_tokens.sort_unstable();

        let mut out = Vec::with_capacity(
            HOLON_CERT_DOMAIN_SEPARATOR.len()
                + 33
                + 33
                + 33
                + 32
                + 33
                + 32
                + 1
                + self
                    .prev_operational_public_key_id
                    .as_ref()
                    .map_or(0, |_| 33)
                + 1
                + self.spiffe_id.as_ref().map_or(0, |s| 4 + s.len())
                + 4
                + sorted_endpoint_hints
                    .iter()
                    .map(|h| 4 + h.len())
                    .sum::<usize>()
                + 4
                + sorted_purpose_tokens
                    .iter()
                    .map(|token| 4 + token.len())
                    .sum::<usize>(),
        );

        out.extend_from_slice(HOLON_CERT_DOMAIN_SEPARATOR);
        out.extend_from_slice(&self.holon_id.to_binary());
        out.extend_from_slice(&self.cell_id.to_binary());
        out.extend_from_slice(&self.genesis_public_key_id.to_binary());
        out.extend_from_slice(&self.genesis_public_key_bytes);
        out.extend_from_slice(&self.operational_public_key_id.to_binary());
        out.extend_from_slice(&self.operational_public_key_bytes);

        out.push(u8::from(self.prev_operational_public_key_id.is_some()));
        if let Some(prev_operational_public_key_id) = self.prev_operational_public_key_id.as_ref() {
            out.extend_from_slice(&prev_operational_public_key_id.to_binary());
        }

        out.push(u8::from(self.spiffe_id.is_some()));
        if let Some(spiffe_id) = self.spiffe_id.as_deref() {
            write_len_prefixed(&mut out, spiffe_id.as_bytes());
        }

        let endpoint_count = u32::try_from(sorted_endpoint_hints.len())
            .expect("endpoint hint count is bounded to <= 32");
        out.extend_from_slice(&endpoint_count.to_le_bytes());
        for endpoint_hint in sorted_endpoint_hints {
            write_len_prefixed(&mut out, endpoint_hint.as_bytes());
        }

        let purpose_count =
            u32::try_from(sorted_purpose_tokens.len()).expect("purpose count is bounded to <= 8");
        out.extend_from_slice(&purpose_count.to_le_bytes());
        for purpose_token in sorted_purpose_tokens {
            write_len_prefixed(&mut out, purpose_token.as_bytes());
        }

        Ok(out)
    }

    /// Bound `holon_id`.
    pub const fn holon_id(&self) -> &HolonIdV1 {
        &self.holon_id
    }

    /// Bound `cell_id`.
    pub const fn cell_id(&self) -> &CellIdV1 {
        &self.cell_id
    }

    /// Immutable genesis key id (root role).
    pub const fn genesis_public_key_id(&self) -> &PublicKeyIdV1 {
        &self.genesis_public_key_id
    }

    /// Immutable genesis key bytes.
    pub const fn genesis_public_key_bytes(&self) -> &[u8; 32] {
        &self.genesis_public_key_bytes
    }

    /// Active operational key id.
    pub const fn operational_public_key_id(&self) -> &PublicKeyIdV1 {
        &self.operational_public_key_id
    }

    /// Active operational key bytes.
    pub const fn operational_public_key_bytes(&self) -> &[u8; 32] {
        &self.operational_public_key_bytes
    }

    /// Optional previous operational key id.
    pub const fn prev_operational_public_key_id(&self) -> Option<&PublicKeyIdV1> {
        self.prev_operational_public_key_id.as_ref()
    }

    /// Optional SPIFFE-like mapping.
    pub fn spiffe_id(&self) -> Option<&str> {
        self.spiffe_id.as_deref()
    }

    /// Endpoint hints.
    pub fn endpoint_hints(&self) -> &[String] {
        &self.endpoint_hints
    }

    /// Purpose tags.
    pub fn purposes(&self) -> &[HolonPurpose] {
        &self.purposes
    }
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("variable-length field must fit in u32");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn copy_ed25519_key(field: &'static str, bytes: &[u8]) -> Result<[u8; 32], CertificateError> {
    if bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(CertificateError::InvalidEd25519KeyLength {
            field,
            expected: ED25519_PUBLIC_KEY_LEN,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; ED25519_PUBLIC_KEY_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn validate_ascii_visible(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), CertificateError> {
    if value.is_empty() {
        return Err(CertificateError::InvalidField {
            field,
            reason: "must be non-empty".to_string(),
        });
    }
    if value.len() > max_len {
        return Err(CertificateError::InvalidField {
            field,
            reason: format!("length {} exceeds maximum of {max_len}", value.len()),
        });
    }
    if !value.is_ascii() {
        return Err(CertificateError::InvalidField {
            field,
            reason: "must be ASCII".to_string(),
        });
    }
    if value.contains('%') {
        return Err(CertificateError::InvalidField {
            field,
            reason: "percent-encoded forms are forbidden".to_string(),
        });
    }
    if value != value.trim() {
        return Err(CertificateError::InvalidField {
            field,
            reason: "leading/trailing whitespace is forbidden".to_string(),
        });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(CertificateError::InvalidField {
            field,
            reason: "interior whitespace is forbidden".to_string(),
        });
    }
    if value.bytes().any(|b| b <= 0x1F || b == 0x7F) {
        return Err(CertificateError::InvalidField {
            field,
            reason: "ASCII control characters are forbidden".to_string(),
        });
    }
    Ok(())
}

fn validate_spiffe_binding(
    spiffe_id: &str,
    cell_id: &CellIdV1,
    holon_id: &HolonIdV1,
) -> Result<(), CertificateError> {
    validate_ascii_visible("spiffe_id", spiffe_id, MAX_SPIFFE_ID_LEN)?;

    let Some(rest) = spiffe_id.strip_prefix("spiffe://") else {
        return Err(CertificateError::InvalidField {
            field: "spiffe_id",
            reason: "must start with \"spiffe://\"".to_string(),
        });
    };

    let expected_tail = format!(
        "/apm2/cell/{}/holon/{}",
        cell_id.to_text(),
        holon_id.to_text()
    );
    let Some(trust_domain) = rest.strip_suffix(&expected_tail) else {
        return Err(CertificateError::InvalidField {
            field: "spiffe_id",
            reason: "must bind the same cell_id and holon_id".to_string(),
        });
    };

    if trust_domain.is_empty() {
        return Err(CertificateError::InvalidField {
            field: "spiffe_id",
            reason: "trust domain segment must be non-empty".to_string(),
        });
    }
    if trust_domain.contains('/') {
        return Err(CertificateError::InvalidField {
            field: "spiffe_id",
            reason: "trust domain segment must not include '/'".to_string(),
        });
    }
    validate_ascii_visible("spiffe_id.trust_domain", trust_domain, MAX_TRUST_DOMAIN_LEN)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::identity::{CellGenesisV1, SetTag};

    fn make_public_key_id(fill: u8) -> PublicKeyIdV1 {
        PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[fill; 32])
    }

    fn make_cell_id(
        ledger_genesis_hash: [u8; 32],
        policy_root: &PolicyRootId,
        trust_domain: &str,
    ) -> CellIdV1 {
        let genesis =
            CellGenesisV1::new(ledger_genesis_hash, policy_root.clone(), trust_domain).unwrap();
        CellIdV1::from_genesis(&genesis)
    }

    fn weak_ed25519_public_key_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0x01;
        key
    }

    fn make_cell_certificate() -> CellCertificateV1 {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_id = make_cell_id([0x11; 32], &policy_root, "cell.example.internal");
        CellCertificateV1::new(
            cell_id,
            "cell.example.internal",
            [0x11; 32],
            policy_root,
            RevocationPointer::LedgerAnchor {
                stream: "ledger.rotations".to_string(),
                from_envelope_ref: 7,
            },
            None,
            Vec::new(),
        )
        .unwrap()
    }

    fn make_holon_certificate() -> HolonCertificateV1 {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_id = make_cell_id([0x22; 32], &policy_root, "cell.example.internal");

        // Derive valid Ed25519 public key bytes from signing keys so they are
        // well-formed curve points.
        let genesis_key_bytes = SigningKey::from_bytes(&[0x55u8; 32])
            .verifying_key()
            .to_bytes();
        let operational_key_bytes = SigningKey::from_bytes(&[0x66u8; 32])
            .verifying_key()
            .to_bytes();
        let genesis_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &genesis_key_bytes);
        let operational_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &operational_key_bytes);

        let genesis = HolonGenesisV1::new(
            cell_id.clone(),
            genesis_key_id.clone(),
            genesis_key_bytes.to_vec(),
            None,
            None,
        )
        .unwrap();
        let holon_id = HolonIdV1::from_genesis(&genesis);

        HolonCertificateV1::new(
            holon_id.clone(),
            cell_id,
            genesis_key_id,
            &genesis_key_bytes,
            operational_key_id,
            &operational_key_bytes,
            None,
            Some(format!(
                "spiffe://cell.example.internal/apm2/cell/{}/holon/{}",
                genesis.cell_id().to_text(),
                holon_id.to_text()
            )),
            vec!["relay.cell.internal:7443".to_string()],
            vec![HolonPurpose::Relay],
        )
        .unwrap()
    }

    #[test]
    fn cell_certificate_rejects_mismatched_cell_id_binding() {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let right_cell_id = make_cell_id([0x11; 32], &policy_root, "cell.example.internal");
        let wrong_cell_id = make_cell_id([0x22; 32], &policy_root, "cell.example.internal");
        assert_ne!(right_cell_id, wrong_cell_id);

        let err = CellCertificateV1::new(
            wrong_cell_id,
            "cell.example.internal",
            [0x11; 32],
            policy_root,
            RevocationPointer::LedgerAnchor {
                stream: "ledger.rotations".to_string(),
                from_envelope_ref: 99,
            },
            None,
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(err, CertificateError::CellIdBindingMismatch);
    }

    #[test]
    fn cell_certificate_rejects_empty_trust_domain() {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_id = make_cell_id([0x11; 32], &policy_root, "cell.example.internal");

        let err = CellCertificateV1::new(
            cell_id,
            "",
            [0x11; 32],
            policy_root,
            RevocationPointer::LedgerAnchor {
                stream: "ledger.rotations".to_string(),
                from_envelope_ref: 1,
            },
            None,
            Vec::new(),
        )
        .unwrap_err();

        assert!(
            matches!(err, CertificateError::InvalidField { field, .. } if field == "trust_domain")
        );
    }

    #[test]
    fn cell_certificate_rejects_control_char_in_trust_domain() {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_id = make_cell_id([0x11; 32], &policy_root, "cell.example.internal");

        let err = CellCertificateV1::new(
            cell_id,
            "cell\x7Fexample.internal",
            [0x11; 32],
            policy_root,
            RevocationPointer::LedgerAnchor {
                stream: "ledger.rotations".to_string(),
                from_envelope_ref: 1,
            },
            None,
            Vec::new(),
        )
        .unwrap_err();

        assert!(
            matches!(err, CertificateError::InvalidField { field, .. } if field == "trust_domain")
        );
    }

    #[test]
    fn cell_certificate_rejects_malformed_revocation_pointer() {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_id = make_cell_id([0x11; 32], &policy_root, "cell.example.internal");

        let err = CellCertificateV1::new(
            cell_id,
            "cell.example.internal",
            [0x11; 32],
            policy_root,
            RevocationPointer::LedgerAnchor {
                stream: "ledger\x01rotations".to_string(),
                from_envelope_ref: 1,
            },
            None,
            Vec::new(),
        )
        .unwrap_err();

        assert!(
            matches!(err, CertificateError::InvalidField { field, .. } if field == "revocation_pointer.stream")
        );
    }

    #[test]
    fn cell_certificate_rejects_validators_in_single_key_mode() {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_id = make_cell_id([0x11; 32], &policy_root, "cell.example.internal");

        let err = CellCertificateV1::new(
            cell_id,
            "cell.example.internal",
            [0x11; 32],
            policy_root,
            RevocationPointer::CasDigest([0xAA; 32]),
            None,
            vec![make_public_key_id(0xB1)],
        )
        .unwrap_err();

        assert!(
            matches!(err, CertificateError::InvalidField { field, .. } if field == "validators")
        );
    }

    #[test]
    fn cell_certificate_allows_quorum_validators_and_is_deterministic() {
        let key_a = make_public_key_id(0xA1);
        let key_b = make_public_key_id(0xB2);
        let quorum = super::super::KeySetIdV1::from_descriptor(
            "ed25519",
            SetTag::Threshold,
            1,
            &[key_a.clone(), key_b.clone()],
            None,
        )
        .unwrap();
        let policy_root = PolicyRootId::Quorum(quorum);
        let cell_id = make_cell_id([0x42; 32], &policy_root, "cell.example.internal");

        let cert_a = CellCertificateV1::new(
            cell_id.clone(),
            "cell.example.internal",
            [0x42; 32],
            policy_root.clone(),
            RevocationPointer::CasDigest([0x55; 32]),
            Some([0x77; 32]),
            vec![key_a.clone(), key_b.clone()],
        )
        .unwrap();
        let cert_b = CellCertificateV1::new(
            cell_id,
            "cell.example.internal",
            [0x42; 32],
            policy_root,
            RevocationPointer::CasDigest([0x55; 32]),
            Some([0x77; 32]),
            vec![key_b, key_a],
        )
        .unwrap();

        let bytes_a = cert_a.canonical_bytes().unwrap();
        let bytes_b = cert_b.canonical_bytes().unwrap();
        assert_eq!(bytes_a, bytes_b, "canonical bytes must be deterministic");
    }

    #[test]
    fn holon_certificate_rejects_binding_mismatch() {
        let cert = make_holon_certificate();

        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let other_cell_id = make_cell_id([0x99; 32], &policy_root, "cell.example.internal");
        let other_genesis_key_bytes = [0x11u8; 32];
        let other_genesis_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &other_genesis_key_bytes);
        let other_holon_id = HolonIdV1::from_genesis(
            &HolonGenesisV1::new(
                other_cell_id,
                other_genesis_key_id,
                other_genesis_key_bytes.to_vec(),
                None,
                None,
            )
            .unwrap(),
        );

        let err = HolonCertificateV1::new(
            other_holon_id,
            cert.cell_id().clone(),
            cert.genesis_public_key_id().clone(),
            cert.genesis_public_key_bytes(),
            cert.operational_public_key_id().clone(),
            cert.operational_public_key_bytes(),
            None,
            None,
            cert.endpoint_hints().to_vec(),
            cert.purposes().to_vec(),
        )
        .unwrap_err();
        assert_eq!(err, CertificateError::HolonIdBindingMismatch);
    }

    #[test]
    fn holon_certificate_rejects_role_overlap() {
        let policy_root = PolicyRootId::Single(make_public_key_id(0xAB));
        let cell_id = make_cell_id([0x22; 32], &policy_root, "cell.example.internal");

        // Use a valid Ed25519 public key (derived from a signing key) so that
        // the well-formedness check passes and the role-overlap check fires.
        let root_key_bytes = SigningKey::from_bytes(&[0x33u8; 32])
            .verifying_key()
            .to_bytes();
        let root_key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &root_key_bytes);
        let holon_id = HolonIdV1::from_genesis(
            &HolonGenesisV1::new(
                cell_id.clone(),
                root_key_id.clone(),
                root_key_bytes.to_vec(),
                None,
                None,
            )
            .unwrap(),
        );

        let err = HolonCertificateV1::new(
            holon_id,
            cell_id,
            root_key_id.clone(),
            &root_key_bytes,
            root_key_id,
            &root_key_bytes,
            None,
            None,
            vec!["relay.cell.internal:7443".to_string()],
            vec![HolonPurpose::Agent],
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::KeyRoleOverlap {
                left: "genesis",
                right: "operational"
            }
        );
    }

    #[test]
    fn holon_certificate_rejects_prev_operational_overlap() {
        let cert = make_holon_certificate();
        let err = HolonCertificateV1::new(
            cert.holon_id().clone(),
            cert.cell_id().clone(),
            cert.genesis_public_key_id().clone(),
            cert.genesis_public_key_bytes(),
            cert.operational_public_key_id().clone(),
            cert.operational_public_key_bytes(),
            Some(cert.operational_public_key_id().clone()),
            cert.spiffe_id().map(ToString::to_string),
            cert.endpoint_hints().to_vec(),
            cert.purposes().to_vec(),
        )
        .unwrap_err();
        assert!(
            matches!(err, CertificateError::InvalidField { field, .. } if field == "prev_operational_public_key_id")
        );
    }

    #[test]
    fn holon_certificate_rejects_empty_purposes() {
        let cert = make_holon_certificate();
        let err = HolonCertificateV1::new(
            cert.holon_id().clone(),
            cert.cell_id().clone(),
            cert.genesis_public_key_id().clone(),
            cert.genesis_public_key_bytes(),
            cert.operational_public_key_id().clone(),
            cert.operational_public_key_bytes(),
            cert.prev_operational_public_key_id().cloned(),
            cert.spiffe_id().map(ToString::to_string),
            cert.endpoint_hints().to_vec(),
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, CertificateError::InvalidField { field, .. } if field == "purposes"));
    }

    #[test]
    fn holon_certificate_rejects_unknown_purpose_tags() {
        let err = HolonCertificateV1::parse_purposes(&["AGENT", "UNKNOWN"]).unwrap_err();
        assert_eq!(
            err,
            CertificateError::UnknownPurposeTag {
                tag: "UNKNOWN".to_string(),
            }
        );
    }

    #[test]
    fn holon_certificate_rejects_malformed_key_bytes() {
        let cert = make_holon_certificate();
        let short_key = [0x22u8; 31];
        let err = HolonCertificateV1::new(
            cert.holon_id().clone(),
            cert.cell_id().clone(),
            cert.genesis_public_key_id().clone(),
            &short_key,
            cert.operational_public_key_id().clone(),
            cert.operational_public_key_bytes(),
            cert.prev_operational_public_key_id().cloned(),
            cert.spiffe_id().map(ToString::to_string),
            cert.endpoint_hints().to_vec(),
            cert.purposes().to_vec(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CertificateError::InvalidEd25519KeyLength {
                field: "genesis_public_key_bytes",
                expected: 32,
                got: 31
            }
        ));
    }

    #[test]
    fn holon_certificate_canonical_bytes_are_deterministic() {
        let cert_a = make_holon_certificate();
        let cert_b = make_holon_certificate();
        assert_eq!(
            cert_a.canonical_bytes().unwrap(),
            cert_b.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn certificate_canonical_bytes_round_trip_in_memory_cas() {
        use apm2_core::evidence::{ContentAddressedStore, MemoryCas};

        let cas = MemoryCas::new();
        let cell_cert = make_cell_certificate();
        let holon_cert = make_holon_certificate();

        let cell_bytes = cell_cert.canonical_bytes().unwrap();
        let holon_bytes = holon_cert.canonical_bytes().unwrap();

        let cell_store = cas.store(&cell_bytes).unwrap();
        let holon_store = cas.store(&holon_bytes).unwrap();
        assert!(cell_store.is_new);
        assert!(holon_store.is_new);

        let cell_retrieved = cas.retrieve(&cell_store.hash).unwrap();
        let holon_retrieved = cas.retrieve(&holon_store.hash).unwrap();
        assert_eq!(cell_retrieved, cell_bytes);
        assert_eq!(holon_retrieved, holon_bytes);
    }

    #[test]
    fn validate_key_roles_rejects_all_overlap_cases() {
        let root = make_public_key_id(0xA1);
        let operational = make_public_key_id(0xB2);
        let session = make_public_key_id(0xC3);

        assert!(validate_key_roles(&root, &operational, Some(&session)).is_ok());

        let err = validate_key_roles(&root, &root, Some(&session)).unwrap_err();
        assert_eq!(
            err,
            CertificateError::KeyRoleOverlap {
                left: "genesis",
                right: "operational"
            }
        );

        let err = validate_key_roles(&root, &operational, Some(&operational)).unwrap_err();
        assert_eq!(
            err,
            CertificateError::KeyRoleOverlap {
                left: "operational",
                right: "session"
            }
        );

        let err = validate_key_roles(&root, &operational, Some(&root)).unwrap_err();
        assert_eq!(
            err,
            CertificateError::KeyRoleOverlap {
                left: "genesis",
                right: "session"
            }
        );
    }

    // ---- Ed25519 key-bytes well-formedness adversarial tests ----

    #[test]
    fn holon_certificate_rejects_genesis_key_not_on_curve() {
        let cert = make_holon_certificate();

        // y=2 (LE: [0x02, 0x00, ...]) is not on the Ed25519 curve — the
        // corresponding x^2 is a quadratic non-residue mod p.
        let mut bad_genesis_bytes = [0x00u8; 32];
        bad_genesis_bytes[0] = 0x02;
        let bad_genesis_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &bad_genesis_bytes);

        // Build a holon_id from this bad genesis so the key-id binding check
        // passes — the well-formedness check should fire before holon_id
        // binding.
        let holon_id = HolonIdV1::from_genesis(
            &HolonGenesisV1::new(
                cert.cell_id().clone(),
                bad_genesis_id.clone(),
                bad_genesis_bytes.to_vec(),
                None,
                None,
            )
            .unwrap(),
        );

        let err = HolonCertificateV1::new(
            holon_id,
            cert.cell_id().clone(),
            bad_genesis_id,
            &bad_genesis_bytes,
            cert.operational_public_key_id().clone(),
            cert.operational_public_key_bytes(),
            None,
            None,
            cert.endpoint_hints().to_vec(),
            cert.purposes().to_vec(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::MalformedKeyBytes {
                field: "genesis_public_key_bytes",
            }
        );
    }

    #[test]
    fn holon_certificate_rejects_operational_key_not_on_curve() {
        let cert = make_holon_certificate();

        // y=2 (LE: [0x02, 0x00, ...]) is not on the Ed25519 curve — the
        // corresponding x^2 is a quadratic non-residue mod p.
        let mut bad_operational_bytes = [0x00u8; 32];
        bad_operational_bytes[0] = 0x02;
        let bad_operational_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &bad_operational_bytes);

        let err = HolonCertificateV1::new(
            cert.holon_id().clone(),
            cert.cell_id().clone(),
            cert.genesis_public_key_id().clone(),
            cert.genesis_public_key_bytes(),
            bad_operational_id,
            &bad_operational_bytes,
            None,
            None,
            cert.endpoint_hints().to_vec(),
            cert.purposes().to_vec(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::MalformedKeyBytes {
                field: "operational_public_key_bytes",
            }
        );
    }

    #[test]
    fn holon_certificate_rejects_weak_genesis_key() {
        let cert = make_holon_certificate();
        let weak_genesis_bytes = weak_ed25519_public_key_bytes();
        let weak_genesis_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &weak_genesis_bytes);

        // Build a holon_id from the weak genesis key so key-id and holon-id
        // binding checks still align, then ensure weak-key rejection fires.
        let holon_id = HolonIdV1::from_genesis(
            &HolonGenesisV1::new(
                cert.cell_id().clone(),
                weak_genesis_id.clone(),
                weak_genesis_bytes.to_vec(),
                None,
                None,
            )
            .unwrap(),
        );

        let err = HolonCertificateV1::new(
            holon_id,
            cert.cell_id().clone(),
            weak_genesis_id,
            &weak_genesis_bytes,
            cert.operational_public_key_id().clone(),
            cert.operational_public_key_bytes(),
            None,
            None,
            cert.endpoint_hints().to_vec(),
            cert.purposes().to_vec(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::InvalidField {
                field: "genesis_public_key_bytes",
                reason: "weak/small-order Ed25519 key rejected".to_string(),
            }
        );
    }

    #[test]
    fn holon_certificate_rejects_weak_operational_key() {
        let cert = make_holon_certificate();
        let weak_operational_bytes = weak_ed25519_public_key_bytes();
        let weak_operational_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &weak_operational_bytes);

        let err = HolonCertificateV1::new(
            cert.holon_id().clone(),
            cert.cell_id().clone(),
            cert.genesis_public_key_id().clone(),
            cert.genesis_public_key_bytes(),
            weak_operational_id,
            &weak_operational_bytes,
            None,
            None,
            cert.endpoint_hints().to_vec(),
            cert.purposes().to_vec(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::InvalidField {
                field: "operational_public_key_bytes",
                reason: "weak/small-order Ed25519 key rejected".to_string(),
            }
        );
    }
}
