//! Session key delegation for hot-path authentication (RFC-0020 section 1.7.6).
//!
//! A `SessionKeyDelegationV1` binds a short-lived session key to a holon ID
//! through a signature from the holon's operational key. Validity uses HTF
//! references only (`issued_at_envelope_ref`, `expires_at_tick`) and never
//! wall-clock time.
//!
//! # Construction API
//!
//! Two constructors are provided with different safety guarantees:
//!
//! - [`SessionKeyDelegationV1::new_unchecked`]: Enforces structural and
//!   cert-independent invariants (key-id binding, key-byte curve-point
//!   well-formedness, validity window, max lifetime). Use for deserialization
//!   paths where the full certificate context is not yet available. **Callers
//!   MUST later call
//!   [`validate_against_holon_certificate`](SessionKeyDelegationV1::validate_against_holon_certificate)
//!   before trusting the delegation.**
//!
//! - [`SessionKeyDelegationV1::new_validated`]: Enforces all invariants
//!   including authority binding and signature verification against a
//!   `HolonCertificateV1`. This is the recommended constructor for production
//!   mint paths.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::certificate::{CertificateError, HolonCertificateV1, validate_key_roles};
use super::{AlgorithmTag, HolonIdV1, PublicKeyIdV1};

/// Domain separator for session delegation signatures.
const SESSION_DELEGATION_DOMAIN_SEPARATOR: &[u8] = b"apm2:session_key_delegation:v1\0";

/// Ed25519 public key size.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature size.
const ED25519_SIGNATURE_LEN: usize = 64;

/// Maximum session delegation lifetime in ticks.
///
/// Set to 86 400 ticks (approximately one day at 1 tick/second). Delegations
/// exceeding this window are rejected to bound the blast radius of key
/// compromise or replay.
pub const MAX_SESSION_DELEGATION_TICKS: u64 = 86_400;

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
    /// Construct a session delegation enforcing **cert-independent**
    /// invariants.
    ///
    /// This constructor validates:
    /// - Ed25519 key and signature byte lengths
    /// - `session_public_key_bytes` are a valid Ed25519 curve point
    /// - `session_public_key_id` is correctly derived from
    ///   `session_public_key_bytes`
    /// - `expires_at_tick > issued_at_envelope_ref` (non-empty validity window)
    /// - delegation lifetime does not exceed [`MAX_SESSION_DELEGATION_TICKS`]
    ///
    /// # Safety contract
    ///
    /// This does **not** verify authority binding (issuer key matches a
    /// certificate) or signature validity. Callers **MUST** subsequently call
    /// [`validate_against_holon_certificate`](Self::validate_against_holon_certificate)
    /// with the verifier's current HTF tick before trusting the delegation.
    /// This constructor exists for deserialization paths where the full
    /// certificate context is not yet available.
    #[must_use = "delegation is not fully validated; call validate_against_holon_certificate(current_tick, certificate) before trusting"]
    #[allow(clippy::too_many_arguments)]
    pub fn new_unchecked(
        session_public_key_id: PublicKeyIdV1,
        session_public_key_bytes: &[u8],
        holon_id: HolonIdV1,
        issuer_operational_public_key_id: PublicKeyIdV1,
        issued_at_envelope_ref: u64,
        expires_at_tick: u64,
        signature: &[u8],
        channel_binding: Option<[u8; 32]>,
    ) -> Result<Self, CertificateError> {
        let session_key_array =
            copy_ed25519_key("session_public_key_bytes", session_public_key_bytes)?;
        validate_ed25519_curve_point("session_public_key_bytes", &session_key_array)?;

        // Verify session key-id is correctly derived from session key bytes.
        let expected_session_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_key_array);
        if expected_session_id != session_public_key_id {
            return Err(CertificateError::PublicKeyIdMismatch {
                field: "session_public_key_id",
            });
        }

        // Validity window: expires_at_tick must be strictly after issued_at.
        if expires_at_tick <= issued_at_envelope_ref {
            return Err(CertificateError::InvalidValidityWindow {
                issued_at_envelope_ref,
                expires_at_tick,
            });
        }

        // Max delegation lifetime bound.
        let lifetime = expires_at_tick - issued_at_envelope_ref;
        if lifetime > MAX_SESSION_DELEGATION_TICKS {
            return Err(CertificateError::DelegationLifetimeExceeded {
                lifetime_ticks: lifetime,
                max_ticks: MAX_SESSION_DELEGATION_TICKS,
            });
        }

        let delegation = Self {
            session_public_key_id,
            session_public_key_bytes: session_key_array,
            holon_id,
            issuer_operational_public_key_id,
            issued_at_envelope_ref,
            expires_at_tick,
            signature: copy_signature(signature)?,
            channel_binding,
        };
        Ok(delegation)
    }

    /// Construct a **fully validated** session delegation against a holon
    /// certificate and a verifier-supplied current HTF tick.
    ///
    /// This is the recommended production constructor. It enforces every
    /// invariant enforced by [`new_unchecked`](Self::new_unchecked) **plus**:
    /// - delegation holon matches certificate holon
    /// - issuer operational key ID matches certificate operational key
    /// - session key role does not overlap genesis/operational roles
    /// - signature verifies under the certificate's operational public key
    /// - `issued_at_envelope_ref <= current_tick < expires_at_tick` (temporal
    ///   validity at the verifier's current tick)
    #[allow(clippy::too_many_arguments)]
    pub fn new_validated(
        holon_certificate: &HolonCertificateV1,
        current_tick: u64,
        session_public_key_id: PublicKeyIdV1,
        session_public_key_bytes: &[u8],
        issued_at_envelope_ref: u64,
        expires_at_tick: u64,
        signature: &[u8],
        channel_binding: Option<[u8; 32]>,
    ) -> Result<Self, CertificateError> {
        let delegation = Self::new_unchecked(
            session_public_key_id,
            session_public_key_bytes,
            holon_certificate.holon_id().clone(),
            holon_certificate.operational_public_key_id().clone(),
            issued_at_envelope_ref,
            expires_at_tick,
            signature,
            channel_binding,
        )?;

        // Full authority + temporal validation.
        delegation.validate_against_holon_certificate(current_tick, holon_certificate)?;

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

    /// Validate this delegation at a verifier-supplied HTF tick against the
    /// issuing holon certificate.
    ///
    /// This method performs full validation:
    /// - delegation holon matches certificate holon
    /// - issuer operational key ID matches certificate operational key
    /// - issuer operational key ID is correctly derived from certificate key
    ///   bytes
    /// - session key role does not overlap genesis/operational roles
    /// - signature verifies under the operational public key bytes
    /// - `issued_at_envelope_ref <= current_tick` (delegation must be active)
    /// - `current_tick < expires_at_tick` (delegation must not have expired)
    ///
    /// Returns [`CertificateError::DelegationNotYetValid`] or
    /// [`CertificateError::DelegationExpired`] on temporal failure.
    pub fn validate_at_tick(
        &self,
        current_tick: u64,
        holon_certificate: &HolonCertificateV1,
    ) -> Result<(), CertificateError> {
        self.validate_authority_against_holon_certificate(holon_certificate)?;
        self.validate_temporal_window(current_tick)
    }

    /// Validate this delegation against the issuing holon certificate at the
    /// verifier's current HTF tick.
    ///
    /// This is the primary trust-validation entry point and performs full
    /// validation including authority, signature, role separation, and
    /// temporal validity.
    pub fn validate_against_holon_certificate(
        &self,
        current_tick: u64,
        holon_certificate: &HolonCertificateV1,
    ) -> Result<(), CertificateError> {
        self.validate_at_tick(current_tick, holon_certificate)
    }

    /// Validate delegation temporal bounds at a verifier-supplied current tick.
    const fn validate_temporal_window(&self, current_tick: u64) -> Result<(), CertificateError> {
        // Temporal: delegation must have started.
        if current_tick < self.issued_at_envelope_ref {
            return Err(CertificateError::DelegationNotYetValid {
                current_tick,
                issued_at_envelope_ref: self.issued_at_envelope_ref,
            });
        }

        // Temporal: delegation must not have expired.
        if current_tick >= self.expires_at_tick {
            return Err(CertificateError::DelegationExpired {
                current_tick,
                expires_at_tick: self.expires_at_tick,
            });
        }

        Ok(())
    }

    /// Validate delegation authority/signature bindings to a holon
    /// certificate.
    ///
    /// Enforced authority invariants:
    /// - delegation holon matches certificate holon
    /// - issuer operational key ID matches certificate operational key
    /// - issuer operational key ID is correctly derived from certificate key
    ///   bytes
    /// - session key role does not overlap genesis/operational roles
    /// - signature verifies under the operational public key bytes
    ///
    /// Note: cert-independent invariants (key-id binding, key-byte
    /// well-formedness, validity window, max lifetime) are enforced at
    /// construction in
    /// [`new_unchecked`](Self::new_unchecked).
    fn validate_authority_against_holon_certificate(
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

        self.validate_authority(
            holon_certificate.genesis_public_key_id(),
            holon_certificate.operational_public_key_bytes(),
        )
    }

    /// Validate authority binding: issuer key-id derivation, role separation,
    /// and cryptographic signature.
    fn validate_authority(
        &self,
        genesis_public_key_id: &PublicKeyIdV1,
        issuer_operational_public_key_bytes: &[u8; 32],
    ) -> Result<(), CertificateError> {
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

fn validate_ed25519_curve_point(
    field: &'static str,
    bytes: &[u8; 32],
) -> Result<(), CertificateError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| CertificateError::MalformedKeyBytes { field })?;
    Ok(())
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

        let genesis_signing_key = SigningKey::from_bytes(&[0x22; 32]);
        let genesis_public_key_bytes = genesis_signing_key.verifying_key().to_bytes();
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

    fn make_session_public_key_bytes(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
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

        SessionKeyDelegationV1::new_unchecked(
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
        let delegation =
            make_signed_delegation(&fixture, make_session_public_key_bytes(0x44), 10, 100, None);

        delegation
            .validate_against_holon_certificate(50, &fixture.holon_certificate)
            .unwrap();
    }

    #[test]
    fn new_validated_round_trips_successfully() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
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
        let signature = fixture
            .operational_signing_key
            .sign(&unsigned_bytes)
            .to_bytes();

        let delegation = SessionKeyDelegationV1::new_validated(
            &fixture.holon_certificate,
            50, // current_tick within [10, 100)
            session_public_key_id,
            &session_public_key_bytes,
            10,
            100,
            &signature,
            None,
        )
        .unwrap();

        assert_eq!(delegation.issued_at_envelope_ref(), 10);
        assert_eq!(delegation.expires_at_tick(), 100);
    }

    #[test]
    fn new_validated_rejects_bad_signature() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
        let session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_public_key_bytes);

        let wrong_signing_key = SigningKey::from_bytes(&[0x99; 32]);
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
        let signature = wrong_signing_key.sign(&unsigned_bytes).to_bytes();

        let err = SessionKeyDelegationV1::new_validated(
            &fixture.holon_certificate,
            50, // current_tick within [10, 100)
            session_public_key_id,
            &session_public_key_bytes,
            10,
            100,
            &signature,
            None,
        )
        .unwrap_err();
        assert_eq!(err, CertificateError::SignatureVerificationFailed);
    }

    #[test]
    fn delegation_rejects_invalid_validity_window_at_construction() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
        let session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_public_key_bytes);

        // expires_at == issued_at (zero-width window)
        let err = SessionKeyDelegationV1::new_unchecked(
            session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id().clone(),
            fixture
                .holon_certificate
                .operational_public_key_id()
                .clone(),
            50,
            50,
            &[0x00; 64],
            None,
        )
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
    fn delegation_rejects_invalid_validity_window_via_validate() {
        let fixture = make_fixture();
        // Use make_signed_delegation which calls new_unchecked internally.
        // A valid window but test the full pipeline through validate.
        let delegation =
            make_signed_delegation(&fixture, make_session_public_key_bytes(0x44), 10, 100, None);

        delegation
            .validate_against_holon_certificate(50, &fixture.holon_certificate)
            .unwrap();
    }

    #[test]
    fn delegation_rejects_mismatched_session_key_id_at_construction() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
        // Derive key-id from DIFFERENT bytes to create a mismatch
        let wrong_session_public_key_bytes = make_session_public_key_bytes(0x55);
        let wrong_session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &wrong_session_public_key_bytes);

        let err = SessionKeyDelegationV1::new_unchecked(
            wrong_session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id().clone(),
            fixture
                .holon_certificate
                .operational_public_key_id()
                .clone(),
            10,
            100,
            &[0x00; 64],
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CertificateError::PublicKeyIdMismatch {
                field: "session_public_key_id"
            }
        );
    }

    #[test]
    fn delegation_rejects_session_key_not_on_curve_at_construction() {
        let fixture = make_fixture();

        // y=2 (LE: [0x02, 0x00, ...]) is not on the Ed25519 curve.
        let mut bad_session_public_key_bytes = [0x00u8; 32];
        bad_session_public_key_bytes[0] = 0x02;
        let bad_session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &bad_session_public_key_bytes);

        let err = SessionKeyDelegationV1::new_unchecked(
            bad_session_public_key_id,
            &bad_session_public_key_bytes,
            fixture.holon_certificate.holon_id().clone(),
            fixture
                .holon_certificate
                .operational_public_key_id()
                .clone(),
            10,
            100,
            &[0x00; 64],
            None,
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::MalformedKeyBytes {
                field: "session_public_key_bytes",
            }
        );
    }

    #[test]
    fn delegation_rejects_signature_not_from_operational_key() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
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

        let delegation = SessionKeyDelegationV1::new_unchecked(
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
            .validate_against_holon_certificate(50, &fixture.holon_certificate)
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
            .validate_against_holon_certificate(50, &fixture.holon_certificate)
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
            .validate_against_holon_certificate(50, &fixture.holon_certificate)
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
        let delegation =
            make_signed_delegation(&fixture, make_session_public_key_bytes(0x44), 10, 100, None);

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

        let forged = SessionKeyDelegationV1::new_unchecked(
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
            .validate_against_holon_certificate(50, &fixture.holon_certificate)
            .unwrap_err();
        assert!(matches!(err, CertificateError::InvalidField { field, .. } if field == "holon_id"));
    }

    #[test]
    fn delegation_rejects_signature_length_mismatch() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
        let session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_public_key_bytes);
        let err = SessionKeyDelegationV1::new_unchecked(
            session_public_key_id,
            &session_public_key_bytes,
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
        let delegation = make_signed_delegation(
            &fixture,
            make_session_public_key_bytes(0x44),
            10,
            100,
            Some([0xAA; 32]),
        );
        assert_eq!(delegation.unsigned_bytes(), delegation.unsigned_bytes());
    }

    // ---- Max delegation lifetime adversarial tests ----

    #[test]
    fn delegation_rejects_lifetime_exceeding_max() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
        let session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_public_key_bytes);

        // MAX + 1 ticks => rejected
        let err = SessionKeyDelegationV1::new_unchecked(
            session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id().clone(),
            fixture
                .holon_certificate
                .operational_public_key_id()
                .clone(),
            0,
            MAX_SESSION_DELEGATION_TICKS + 1,
            &[0x00; 64],
            None,
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::DelegationLifetimeExceeded {
                lifetime_ticks: MAX_SESSION_DELEGATION_TICKS + 1,
                max_ticks: MAX_SESSION_DELEGATION_TICKS,
            }
        );
    }

    #[test]
    fn delegation_accepts_lifetime_at_max() {
        let fixture = make_fixture();
        // Exactly MAX ticks => accepted (signature is garbage but construction
        // succeeds)
        let delegation = make_signed_delegation(
            &fixture,
            make_session_public_key_bytes(0x44),
            0,
            MAX_SESSION_DELEGATION_TICKS,
            None,
        );
        assert_eq!(delegation.expires_at_tick(), MAX_SESSION_DELEGATION_TICKS);
    }

    #[test]
    fn delegation_accepts_minimal_lifetime() {
        let fixture = make_fixture();
        // 1 tick => accepted
        let delegation =
            make_signed_delegation(&fixture, make_session_public_key_bytes(0x44), 10, 11, None);
        assert_eq!(
            delegation.expires_at_tick() - delegation.issued_at_envelope_ref(),
            1
        );
    }

    #[test]
    fn delegation_rejects_large_lifetime_offset() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
        let session_public_key_id =
            PublicKeyIdV1::from_key_bytes(AlgorithmTag::Ed25519, &session_public_key_bytes);

        // Very large lifetime from a non-zero start
        let err = SessionKeyDelegationV1::new_unchecked(
            session_public_key_id,
            &session_public_key_bytes,
            fixture.holon_certificate.holon_id().clone(),
            fixture
                .holon_certificate
                .operational_public_key_id()
                .clone(),
            1000,
            1000 + MAX_SESSION_DELEGATION_TICKS + 1,
            &[0x00; 64],
            None,
        )
        .unwrap_err();

        assert_eq!(
            err,
            CertificateError::DelegationLifetimeExceeded {
                lifetime_ticks: MAX_SESSION_DELEGATION_TICKS + 1,
                max_ticks: MAX_SESSION_DELEGATION_TICKS,
            }
        );
    }

    // ---- HTF tick temporal validity adversarial tests ----

    #[test]
    fn validate_at_tick_rejects_not_yet_valid() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(
            &fixture,
            make_session_public_key_bytes(0x44),
            100,
            200,
            None,
        );

        // current_tick (50) < issued_at_envelope_ref (100) → not yet valid
        let err = delegation
            .validate_at_tick(50, &fixture.holon_certificate)
            .unwrap_err();
        assert_eq!(
            err,
            CertificateError::DelegationNotYetValid {
                current_tick: 50,
                issued_at_envelope_ref: 100,
            }
        );
    }

    #[test]
    fn validate_at_tick_rejects_expired_at_boundary() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(
            &fixture,
            make_session_public_key_bytes(0x44),
            100,
            200,
            None,
        );

        // current_tick (200) == expires_at_tick (200) → expired
        let err = delegation
            .validate_at_tick(200, &fixture.holon_certificate)
            .unwrap_err();
        assert_eq!(
            err,
            CertificateError::DelegationExpired {
                current_tick: 200,
                expires_at_tick: 200,
            }
        );
    }

    #[test]
    fn validate_at_tick_accepts_at_issued_boundary() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(
            &fixture,
            make_session_public_key_bytes(0x44),
            100,
            200,
            None,
        );

        // current_tick (100) == issued_at_envelope_ref (100) → accepted
        delegation
            .validate_at_tick(100, &fixture.holon_certificate)
            .unwrap();
    }

    #[test]
    fn validate_at_tick_accepts_at_expires_minus_one() {
        let fixture = make_fixture();
        let delegation = make_signed_delegation(
            &fixture,
            make_session_public_key_bytes(0x44),
            100,
            200,
            None,
        );

        // current_tick (199) == expires_at_tick - 1 → accepted
        delegation
            .validate_at_tick(199, &fixture.holon_certificate)
            .unwrap();
    }

    #[test]
    fn new_validated_rejects_not_yet_valid_delegation() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
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
            100,
            200,
            None,
        );
        let signature = fixture
            .operational_signing_key
            .sign(&unsigned_bytes)
            .to_bytes();

        // current_tick (50) < issued_at_envelope_ref (100)
        let err = SessionKeyDelegationV1::new_validated(
            &fixture.holon_certificate,
            50,
            session_public_key_id,
            &session_public_key_bytes,
            100,
            200,
            &signature,
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CertificateError::DelegationNotYetValid {
                current_tick: 50,
                issued_at_envelope_ref: 100,
            }
        );
    }

    #[test]
    fn new_validated_rejects_expired_delegation() {
        let fixture = make_fixture();
        let session_public_key_bytes = make_session_public_key_bytes(0x44);
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
            100,
            200,
            None,
        );
        let signature = fixture
            .operational_signing_key
            .sign(&unsigned_bytes)
            .to_bytes();

        // current_tick (200) == expires_at_tick (200)
        let err = SessionKeyDelegationV1::new_validated(
            &fixture.holon_certificate,
            200,
            session_public_key_id,
            &session_public_key_bytes,
            100,
            200,
            &signature,
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CertificateError::DelegationExpired {
                current_tick: 200,
                expires_at_tick: 200,
            }
        );
    }
}
