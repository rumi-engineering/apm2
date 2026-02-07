//! Session key delegation for hot-path authentication (RFC-0020 section 1.7.6).
//!
//! A `SessionKeyDelegationV1` binds a short-lived session key to a holon ID
//! through a signature from the holon's operational key. Validity uses HTF
//! references only (`issued_at_envelope_ref`, `expires_at_tick`) and never
//! wall-clock time.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::certificate::{CertificateError, HolonCertificateV1, validate_key_roles};
use super::{AlgorithmTag, HolonIdV1, PublicKeyIdV1};

/// Domain separator for session delegation signatures.
const SESSION_DELEGATION_DOMAIN_SEPARATOR: &[u8] = b"apm2:session_key_delegation:v1\0";

/// Ed25519 public key size.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature size.
const ED25519_SIGNATURE_LEN: usize = 64;

/// `SessionKeyDelegationV1` binds a session key to a holon via an operational
/// signing key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKeyDelegationV1 {
    session_public_key_id: PublicKeyIdV1,
    session_public_key_bytes: [u8; 32],
    holon_id: HolonIdV1,
    issuer_operational_public_key_id: PublicKeyIdV1,
    issued_at_envelope_ref: u64,
    expires_at_tick: u64,
    signature: [u8; 64],
    channel_binding: Option<[u8; 32]>,
}

impl SessionKeyDelegationV1 {
    /// Construct a session delegation from validated field values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_public_key_id: PublicKeyIdV1,
        session_public_key_bytes: &[u8],
        holon_id: HolonIdV1,
        issuer_operational_public_key_id: PublicKeyIdV1,
        issued_at_envelope_ref: u64,
        expires_at_tick: u64,
        signature: &[u8],
        channel_binding: Option<[u8; 32]>,
    ) -> Result<Self, CertificateError> {
        let delegation = Self {
            session_public_key_id,
            session_public_key_bytes: copy_ed25519_key(
                "session_public_key_bytes",
                session_public_key_bytes,
            )?,
            holon_id,
            issuer_operational_public_key_id,
            issued_at_envelope_ref,
            expires_at_tick,
            signature: copy_signature(signature)?,
            channel_binding,
        };
        Ok(delegation)
    }

    /// Return canonical unsigned bytes used for signature generation and
    /// verification.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        Self::unsigned_bytes_for(
            &self.session_public_key_id,
            &self.session_public_key_bytes,
            &self.holon_id,
            &self.issuer_operational_public_key_id,
            self.issued_at_envelope_ref,
            self.expires_at_tick,
            self.channel_binding.as_ref(),
        )
    }

    /// Return canonical unsigned bytes for provided fields.
    #[allow(clippy::too_many_arguments)]
    pub fn unsigned_bytes_for(
        session_public_key_id: &PublicKeyIdV1,
        session_public_key_bytes: &[u8; 32],
        holon_id: &HolonIdV1,
        issuer_operational_public_key_id: &PublicKeyIdV1,
        issued_at_envelope_ref: u64,
        expires_at_tick: u64,
        channel_binding: Option<&[u8; 32]>,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SESSION_DELEGATION_DOMAIN_SEPARATOR.len() + 33 + 32 + 33 + 33 + 8 + 8 + 1 + 32,
        );
        out.extend_from_slice(SESSION_DELEGATION_DOMAIN_SEPARATOR);
        out.extend_from_slice(&session_public_key_id.to_binary());
        out.extend_from_slice(session_public_key_bytes);
        out.extend_from_slice(&holon_id.to_binary());
        out.extend_from_slice(&issuer_operational_public_key_id.to_binary());
        out.extend_from_slice(&issued_at_envelope_ref.to_le_bytes());
        out.extend_from_slice(&expires_at_tick.to_le_bytes());
        out.push(u8::from(channel_binding.is_some()));
        if let Some(channel_binding) = channel_binding {
            out.extend_from_slice(channel_binding);
        }
        out
    }

    /// Validate this delegation against the issuing holon certificate.
    ///
    /// Enforced invariants:
    /// - delegation holon matches certificate holon
    /// - issuer operational key ID matches certificate operational key
    /// - session key role does not overlap genesis/operational roles
    /// - `expires_at_tick > issued_at_envelope_ref`
    /// - signature verifies under the operational public key bytes
    pub fn validate_against_holon_certificate(
        &self,
        holon_certificate: &HolonCertificateV1,
    ) -> Result<(), CertificateError> {
        if &self.holon_id != holon_certificate.holon_id() {
            return Err(CertificateError::InvalidField {
                field: "holon_id",
                reason: "must match holon certificate holon_id".to_string(),
            });
        }

        if &self.issuer_operational_public_key_id != holon_certificate.operational_public_key_id() {
            return Err(CertificateError::InvalidField {
                field: "issuer_operational_public_key_id",
                reason: "must match holon certificate operational key id".to_string(),
            });
        }

        self.validate_common(
            holon_certificate.genesis_public_key_id(),
            holon_certificate.operational_public_key_bytes(),
        )
    }

    fn validate_common(
        &self,
        genesis_public_key_id: &PublicKeyIdV1,
        issuer_operational_public_key_bytes: &[u8; 32],
    ) -> Result<(), CertificateError> {
        let expected_session_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &self.session_public_key_bytes);
        if expected_session_id != self.session_public_key_id {
            return Err(CertificateError::PublicKeyIdMismatch {
                field: "session_public_key_id",
            });
        }

        let expected_issuer_id = PublicKeyIdV1::from_key_bytes(
            AlgorithmTag::Ed25519,
            issuer_operational_public_key_bytes,
        );
        if expected_issuer_id != self.issuer_operational_public_key_id {
            return Err(CertificateError::PublicKeyIdMismatch {
                field: "issuer_operational_public_key_id",
            });
        }

        validate_key_roles(
            genesis_public_key_id,
            &self.issuer_operational_public_key_id,
            Some(&self.session_public_key_id),
        )?;

        if self.expires_at_tick <= self.issued_at_envelope_ref {
            return Err(CertificateError::InvalidValidityWindow {
                issued_at_envelope_ref: self.issued_at_envelope_ref,
                expires_at_tick: self.expires_at_tick,
            });
        }

        self.verify_signature(issuer_operational_public_key_bytes)
    }

    /// Verify signature under the provided issuer operational public key bytes.
    pub fn verify_signature(
        &self,
        issuer_operational_public_key_bytes: &[u8; 32],
    ) -> Result<(), CertificateError> {
        let verifying_key =
            VerifyingKey::from_bytes(issuer_operational_public_key_bytes).map_err(|_| {
                CertificateError::InvalidField {
                    field: "issuer_operational_public_key_bytes",
                    reason: "invalid Ed25519 public key bytes".to_string(),
                }
            })?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&self.unsigned_bytes(), &signature)
            .map_err(|_| CertificateError::SignatureVerificationFailed)
    }

    /// Session key ID.
    pub const fn session_public_key_id(&self) -> &PublicKeyIdV1 {
        &self.session_public_key_id
    }

    /// Session key bytes.
    pub const fn session_public_key_bytes(&self) -> &[u8; 32] {
        &self.session_public_key_bytes
    }

    /// Bound holon ID.
    pub const fn holon_id(&self) -> &HolonIdV1 {
        &self.holon_id
    }

    /// Issuer operational key ID.
    pub const fn issuer_operational_public_key_id(&self) -> &PublicKeyIdV1 {
        &self.issuer_operational_public_key_id
    }

    /// Issued-at HTF envelope reference.
    pub const fn issued_at_envelope_ref(&self) -> u64 {
        self.issued_at_envelope_ref
    }

    /// Expiry HTF tick.
    pub const fn expires_at_tick(&self) -> u64 {
        self.expires_at_tick
    }

    /// Signature bytes.
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Optional channel binding.
    pub const fn channel_binding(&self) -> Option<&[u8; 32]> {
        self.channel_binding.as_ref()
    }
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

fn copy_signature(bytes: &[u8]) -> Result<[u8; 64], CertificateError> {
    if bytes.len() != ED25519_SIGNATURE_LEN {
        return Err(CertificateError::InvalidSignatureLength { got: bytes.len() });
    }
    let mut out = [0u8; ED25519_SIGNATURE_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::identity::{CellGenesisV1, CellIdV1, HolonGenesisV1, HolonPurpose, PolicyRootId};

    struct Fixture {
        holon_certificate: HolonCertificateV1,
        operational_signing_key: SigningKey,
        genesis_public_key_bytes: [u8; 32],
    }

    fn make_fixture() -> Fixture {
        let cell_policy_key_id = PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0xAA; 32]);
        let cell_policy_root = PolicyRootId::Single(cell_policy_key_id);
        let cell_genesis =
            CellGenesisV1::new([0x11; 32], cell_policy_root, "cell.example.internal").unwrap();
        let cell_id = CellIdV1::from_genesis(&cell_genesis);

        let genesis_public_key_bytes = [0x22; 32];
        let genesis_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &genesis_public_key_bytes);

        let operational_signing_key = SigningKey::from_bytes(&[0x33; 32]);
        let operational_public_key_bytes = operational_signing_key.verifying_key().to_bytes();
        let operational_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &operational_public_key_bytes);

        let holon_genesis = HolonGenesisV1::new(
            cell_id.clone(),
            genesis_public_key_id.clone(),
            genesis_public_key_bytes.to_vec(),
            None,
            None,
        )
        .unwrap();
        let holon_id = HolonIdV1::from_genesis(&holon_genesis);
        let spiffe_id = format!(
            "spiffe://cell.example.internal/apm2/cell/{}/holon/{}",
            cell_id.to_text(),
            holon_id.to_text()
        );

        let holon_certificate = HolonCertificateV1::new(
            holon_id,
            cell_id,
            genesis_public_key_id,
            &genesis_public_key_bytes,
            operational_public_key_id,
            &operational_public_key_bytes,
            None,
            Some(spiffe_id),
            vec!["relay.cell.internal:7443".to_string()],
            vec![HolonPurpose::Agent],
        )
        .unwrap();

        Fixture {
            holon_certificate,
            operational_signing_key,
            genesis_public_key_bytes,
        }
    }

    fn make_signed_delegation(
        fixture: &Fixture,
        session_public_key_bytes: [u8; 32],
        issued_at_envelope_ref: u64,
        expires_at_tick: u64,
        channel_binding: Option<[u8; 32]>,
    ) -> SessionKeyDelegationV1 {
        let session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_public_key_bytes);
        let issuer_operational_public_key_id = fixture
            .holon_certificate
            .operational_public_key_id()
            .clone();

        let unsigned_bytes = SessionKeyDelegationV1::unsigned_bytes_for(
            &session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id(),
            &issuer_operational_public_key_id,
            issued_at_envelope_ref,
            expires_at_tick,
            channel_binding.as_ref(),
        );
        let signature = fixture
            .operational_signing_key
            .sign(&unsigned_bytes)
            .to_bytes();

        SessionKeyDelegationV1::new(
            session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id().clone(),
            issuer_operational_public_key_id,
            issued_at_envelope_ref,
            expires_at_tick,
            &signature,
            channel_binding,
        )
        .unwrap()
    }

    #[test]
    fn delegation_verifies_with_operational_authority() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(&fixture, [0x44; 32], 10, 100, None);

        delegation
            .validate_against_holon_certificate(&fixture.holon_certificate)
            .unwrap();
    }

    #[test]
    fn delegation_rejects_invalid_validity_window() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(&fixture, [0x44; 32], 50, 50, None);

        let err = delegation
            .validate_against_holon_certificate(&fixture.holon_certificate)
            .unwrap_err();
        assert_eq!(
            err,
            CertificateError::InvalidValidityWindow {
                issued_at_envelope_ref: 50,
                expires_at_tick: 50
            }
        );
    }

    #[test]
    fn delegation_rejects_signature_not_from_operational_key() {
        let fixture = make_fixture();
        let session_public_key_bytes = [0x44; 32];
        let session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_public_key_bytes);
        let issuer_operational_public_key_id = fixture
            .holon_certificate
            .operational_public_key_id()
            .clone();

        let unsigned_bytes = SessionKeyDelegationV1::unsigned_bytes_for(
            &session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id(),
            &issuer_operational_public_key_id,
            10,
            100,
            None,
        );
        let wrong_signing_key = SigningKey::from_bytes(&[0x99; 32]);
        let signature = wrong_signing_key.sign(&unsigned_bytes).to_bytes();

        let delegation = SessionKeyDelegationV1::new(
            session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id().clone(),
            issuer_operational_public_key_id,
            10,
            100,
            &signature,
            None,
        )
        .unwrap();

        let err = delegation
            .validate_against_holon_certificate(&fixture.holon_certificate)
            .unwrap_err();
        assert_eq!(err, CertificateError::SignatureVerificationFailed);
    }

    #[test]
    fn delegation_rejects_operational_session_overlap() {
        let fixture = make_fixture();
        let overlapping_session_key_bytes =
            *fixture.holon_certificate.operational_public_key_bytes();
        let delegation =
            make_signed_delegation(&fixture, overlapping_session_key_bytes, 10, 100, None);

        let err = delegation
            .validate_against_holon_certificate(&fixture.holon_certificate)
            .unwrap_err();
        assert_eq!(
            err,
            CertificateError::KeyRoleOverlap {
                left: "operational",
                right: "session"
            }
        );
    }

    #[test]
    fn delegation_rejects_genesis_session_overlap() {
        let fixture = make_fixture();
        let delegation =
            make_signed_delegation(&fixture, fixture.genesis_public_key_bytes, 10, 100, None);

        let err = delegation
            .validate_against_holon_certificate(&fixture.holon_certificate)
            .unwrap_err();
        assert_eq!(
            err,
            CertificateError::KeyRoleOverlap {
                left: "genesis",
                right: "session"
            }
        );
    }

    #[test]
    fn delegation_rejects_holon_mismatch() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(&fixture, [0x44; 32], 10, 100, None);

        let other_holon_id = HolonIdV1::from_genesis(
            &HolonGenesisV1::new(
                fixture.holon_certificate.cell_id().clone(),
                PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x77; 32]),
                vec![0x77; 32],
                None,
                None,
            )
            .unwrap(),
        );

        let forged = SessionKeyDelegationV1::new(
            delegation.session_public_key_id().clone(),
            delegation.session_public_key_bytes(),
            other_holon_id,
            delegation.issuer_operational_public_key_id().clone(),
            delegation.issued_at_envelope_ref(),
            delegation.expires_at_tick(),
            delegation.signature(),
            delegation.channel_binding().copied(),
        )
        .unwrap();

        let err = forged
            .validate_against_holon_certificate(&fixture.holon_certificate)
            .unwrap_err();
        assert!(matches!(err, CertificateError::InvalidField { field, .. } if field == "holon_id"));
    }

    #[test]
    fn delegation_rejects_signature_length_mismatch() {
        let fixture = make_fixture();
        let err = SessionKeyDelegationV1::new(
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &[0x44; 32]),
            &[0x44; 32],
            fixture.holon_certificate.holon_id().clone(),
            fixture
                .holon_certificate
                .operational_public_key_id()
                .clone(),
            10,
            100,
            &[0x01; 63],
            None,
        )
        .unwrap_err();

        assert_eq!(err, CertificateError::InvalidSignatureLength { got: 63 });
    }

    #[test]
    fn delegation_unsigned_bytes_are_deterministic() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(&fixture, [0x44; 32], 10, 100, Some([0xAA; 32]));
        assert_eq!(delegation.unsigned_bytes(), delegation.unsigned_bytes());
    }
}
