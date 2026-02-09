// AGENT-AUTHORED
//! Tier2+ sovereignty composition checks (RFC-0027 §6.6, TCK-00427).
//!
//! [`SovereigntyChecker`] validates sovereignty inputs for Tier2+ authority
//! operations. It is invoked during `revalidate` and `consume` to enforce:
//!
//! - **Epoch freshness**: sovereignty epoch must not be stale relative to the
//!   current tick.
//! - **Revocation head**: principal revocation head must be known and
//!   unambiguous.
//! - **Autonomy ceiling**: requested risk tier must not exceed the ceiling.
//! - **Freeze detection**: active freeze conditions deny all operations.
//! - **Sovereignty uncertainty**: triggers the configured freeze action.
//!
//! Tier0/1 operations bypass all sovereignty checks.

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityDenyClass, AuthorityDenyV1, AuthorityJoinCertificateV1, AutonomyCeiling, FreezeAction,
    RiskTier, SovereigntyEpoch,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const ZERO_HASH: Hash = [0u8; 32];
const ZERO_SIGNATURE: [u8; 64] = [0u8; 64];
const EPOCH_DOMAIN_SEPARATOR: &[u8] = b"apm2-sovereignty-epoch-v1";

/// Maximum allowed tick drift before a sovereignty epoch is considered stale.
const DEFAULT_EPOCH_STALENESS_THRESHOLD: u64 = 100;

/// Sovereignty state for a principal scope.
///
/// Captures the current sovereignty inputs needed for Tier2+ validation.
/// Callers populate this from their authority store before calling
/// `SovereigntyChecker` methods.
#[derive(Debug, Clone)]
pub struct SovereigntyState {
    /// Current sovereignty epoch, if known.
    pub epoch: Option<SovereigntyEpoch>,

    /// Principal ID for revocation head checks.
    pub principal_id: String,

    /// Whether the principal's revocation head is known.
    pub revocation_head_known: bool,

    /// Autonomy ceiling for this principal scope.
    pub autonomy_ceiling: Option<AutonomyCeiling>,

    /// Active freeze action, if any.
    pub active_freeze: FreezeAction,
}

/// Validates sovereignty inputs for Tier2+ authority operations.
///
/// All checks are fail-closed: missing or ambiguous state produces a denial.
/// Tier0/1 operations (identified by `cert.risk_tier`) bypass all checks.
pub struct SovereigntyChecker {
    /// Staleness threshold for epoch freshness checks.
    epoch_staleness_threshold: u64,
}

impl SovereigntyChecker {
    /// Creates a new sovereignty checker with default thresholds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            epoch_staleness_threshold: DEFAULT_EPOCH_STALENESS_THRESHOLD,
        }
    }

    /// Creates a new sovereignty checker with a custom staleness threshold.
    #[must_use]
    pub const fn with_staleness_threshold(threshold: u64) -> Self {
        Self {
            epoch_staleness_threshold: threshold,
        }
    }

    /// Returns `true` if the certificate's risk tier requires sovereignty
    /// checks.
    const fn requires_sovereignty_check(cert: &AuthorityJoinCertificateV1) -> bool {
        matches!(cert.risk_tier, RiskTier::Tier2Plus)
    }

    /// Validates sovereignty state during revalidation.
    ///
    /// Checks epoch freshness and revocation head state. Called as part
    /// of the revalidate lifecycle stage.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityDenyV1` on:
    /// - Stale or missing sovereignty epoch
    /// - Unknown principal revocation head
    /// - Active freeze condition
    /// - Sovereignty uncertainty
    pub fn check_revalidate(
        &self,
        cert: &AuthorityJoinCertificateV1,
        state: &SovereigntyState,
        current_tick: u64,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        if !Self::requires_sovereignty_check(cert) {
            return Ok(());
        }

        Self::check_active_freeze(
            cert,
            state,
            current_tick,
            current_time_envelope_ref,
            current_ledger_anchor,
        )?;
        self.check_epoch_freshness(
            cert,
            state,
            current_tick,
            current_time_envelope_ref,
            current_ledger_anchor,
        )?;
        Self::check_revocation_head(
            cert,
            state,
            current_tick,
            current_time_envelope_ref,
            current_ledger_anchor,
        )?;

        Ok(())
    }

    /// Validates sovereignty state during consumption.
    ///
    /// Checks all sovereignty conditions: epoch freshness, revocation head,
    /// autonomy ceiling, and freeze state. Called as part of the consume
    /// lifecycle stage.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityDenyV1` on any sovereignty check failure.
    pub fn check_consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        state: &SovereigntyState,
        current_tick: u64,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        if !Self::requires_sovereignty_check(cert) {
            return Ok(());
        }

        Self::check_active_freeze(
            cert,
            state,
            current_tick,
            current_time_envelope_ref,
            current_ledger_anchor,
        )?;
        self.check_epoch_freshness(
            cert,
            state,
            current_tick,
            current_time_envelope_ref,
            current_ledger_anchor,
        )?;
        Self::check_revocation_head(
            cert,
            state,
            current_tick,
            current_time_envelope_ref,
            current_ledger_anchor,
        )?;
        Self::check_autonomy_ceiling(
            cert,
            state,
            current_tick,
            current_time_envelope_ref,
            current_ledger_anchor,
        )?;

        Ok(())
    }

    /// Checks whether an active freeze condition exists.
    fn check_active_freeze(
        cert: &AuthorityJoinCertificateV1,
        state: &SovereigntyState,
        current_tick: u64,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        match state.active_freeze {
            FreezeAction::NoAction => Ok(()),
            freeze_action => Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::ActiveSovereignFreeze { freeze_action },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(freeze_action),
            })),
        }
    }

    /// Builds the domain-separated signing payload for sovereignty epochs.
    #[must_use]
    pub fn epoch_signing_message(epoch_id: &str, freshness_tick: u64) -> Vec<u8> {
        let mut message = Vec::with_capacity(
            EPOCH_DOMAIN_SEPARATOR.len() + epoch_id.len() + std::mem::size_of::<u64>(),
        );
        message.extend_from_slice(EPOCH_DOMAIN_SEPARATOR);
        message.extend_from_slice(epoch_id.as_bytes());
        message.extend_from_slice(&freshness_tick.to_le_bytes());
        message
    }

    /// Signs a sovereignty epoch with Ed25519 and domain separation.
    #[must_use]
    pub fn sign_epoch(signing_key: &SigningKey, epoch_id: &str, freshness_tick: u64) -> [u8; 64] {
        signing_key
            .sign(&Self::epoch_signing_message(epoch_id, freshness_tick))
            .to_bytes()
    }

    /// Checks sovereignty epoch freshness and cryptographic signature.
    fn check_epoch_freshness(
        &self,
        cert: &AuthorityJoinCertificateV1,
        state: &SovereigntyState,
        current_tick: u64,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        let Some(epoch) = &state.epoch else {
            // Missing epoch is sovereignty uncertainty -> trigger freeze.
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: "no sovereignty epoch available".to_string(),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        };

        // Zero signature is treated as unsigned/invalid.
        if epoch.signature == ZERO_SIGNATURE {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: "sovereignty epoch has zero signature".to_string(),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        }

        // Zero signer public key is treated as missing signer.
        if epoch.signer_public_key == ZERO_HASH {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: "sovereignty epoch has zero signer public key".to_string(),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        }

        // Verify Ed25519 signature over domain-separated message.
        let Ok(verifying_key) = VerifyingKey::from_bytes(&epoch.signer_public_key) else {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: "sovereignty epoch signer public key is invalid".to_string(),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        };

        let signature = Signature::from_bytes(&epoch.signature);
        let signing_message = Self::epoch_signing_message(&epoch.epoch_id, epoch.freshness_tick);

        if verifying_key
            .verify_strict(&signing_message, &signature)
            .is_err()
        {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: "sovereignty epoch signature verification failed".to_string(),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        }

        // Staleness check: epoch freshness tick must be within threshold.
        if current_tick > epoch.freshness_tick
            && (current_tick - epoch.freshness_tick) > self.epoch_staleness_threshold
        {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::StaleSovereigntyEpoch {
                    epoch_id: epoch.epoch_id.clone(),
                    last_known_tick: epoch.freshness_tick,
                    current_tick,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        }

        Ok(())
    }

    /// Checks that the principal's revocation head is known.
    fn check_revocation_head(
        cert: &AuthorityJoinCertificateV1,
        state: &SovereigntyState,
        current_tick: u64,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        if !state.revocation_head_known {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::UnknownRevocationHead {
                    principal_id: state.principal_id.clone(),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::SoftFreeze),
            }));
        }
        Ok(())
    }

    /// Checks autonomy ceiling compatibility.
    fn check_autonomy_ceiling(
        cert: &AuthorityJoinCertificateV1,
        state: &SovereigntyState,
        current_tick: u64,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        let Some(ceiling) = &state.autonomy_ceiling else {
            // Missing ceiling at Tier2+ is sovereignty uncertainty.
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: "no autonomy ceiling defined for scope".to_string(),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(Self::evaluate_uncertainty_freeze(state)),
            }));
        };

        // Check that the requested tier does not exceed the ceiling.
        if !tier_within_ceiling(cert.risk_tier, ceiling.max_risk_tier) {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::IncompatibleAutonomyCeiling {
                    required: ceiling.max_risk_tier,
                    actual: cert.risk_tier,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::SoftFreeze),
            }));
        }

        Ok(())
    }

    /// Evaluates sovereignty uncertainty and returns the freeze action that
    /// should be emitted (if any).
    ///
    /// This is called by policy layers to determine what freeze action to
    /// take when sovereignty state is uncertain.
    #[must_use]
    pub const fn evaluate_uncertainty_freeze(state: &SovereigntyState) -> FreezeAction {
        // If epoch is missing entirely, hard freeze.
        if state.epoch.is_none() {
            return FreezeAction::HardFreeze;
        }

        // If revocation head is unknown, soft freeze.
        if !state.revocation_head_known {
            return FreezeAction::SoftFreeze;
        }

        // If autonomy ceiling is missing, soft freeze.
        if state.autonomy_ceiling.is_none() {
            return FreezeAction::SoftFreeze;
        }

        FreezeAction::NoAction
    }
}

impl Default for SovereigntyChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` if `requested` does not exceed `ceiling`.
///
/// Tier ordering: `Tier0` < `Tier1` < `Tier2Plus`.
const fn tier_within_ceiling(requested: RiskTier, ceiling: RiskTier) -> bool {
    tier_ordinal(requested) <= tier_ordinal(ceiling)
}

/// Maps risk tier to a numeric ordinal for comparison.
const fn tier_ordinal(tier: RiskTier) -> u8 {
    match tier {
        RiskTier::Tier0 => 0,
        RiskTier::Tier1 => 1,
        RiskTier::Tier2Plus => 2,
        // Fail-closed: unknown tiers get maximum ordinal.
        _ => u8::MAX,
    }
}

#[cfg(test)]
mod tests {
    use apm2_core::pcac::IdentityEvidenceLevel;

    use super::*;

    fn test_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn tier2_cert() -> AuthorityJoinCertificateV1 {
        AuthorityJoinCertificateV1 {
            ajc_id: test_hash(0xAA),
            authority_join_hash: test_hash(0xBB),
            intent_digest: test_hash(0x01),
            risk_tier: RiskTier::Tier2Plus,
            issued_time_envelope_ref: test_hash(0x07),
            as_of_ledger_anchor: test_hash(0x08),
            expires_at_tick: 500,
            revocation_head_hash: test_hash(0x04),
            identity_evidence_level: IdentityEvidenceLevel::Verified,
            admission_capacity_token: None,
        }
    }

    fn tier1_cert() -> AuthorityJoinCertificateV1 {
        let mut cert = tier2_cert();
        cert.risk_tier = RiskTier::Tier1;
        cert
    }

    /// Builds a `SovereigntyEpoch` with a valid Ed25519 signature.
    fn signed_epoch(epoch_id: &str, freshness_tick: u64, key_seed: u8) -> SovereigntyEpoch {
        let signing_key = signing_key(key_seed);
        SovereigntyEpoch {
            epoch_id: epoch_id.to_string(),
            freshness_tick,
            signer_public_key: signing_key.verifying_key().to_bytes(),
            signature: SovereigntyChecker::sign_epoch(&signing_key, epoch_id, freshness_tick),
        }
    }

    fn valid_sovereignty_state() -> SovereigntyState {
        SovereigntyState {
            epoch: Some(signed_epoch("epoch-001", 100, 0xCC)),
            principal_id: "principal-001".to_string(),
            revocation_head_known: true,
            autonomy_ceiling: Some(AutonomyCeiling {
                max_risk_tier: RiskTier::Tier2Plus,
                policy_binding_hash: test_hash(0xDD),
            }),
            active_freeze: FreezeAction::NoAction,
        }
    }

    // =========================================================================
    // Tier1 bypass tests
    // =========================================================================

    #[test]
    fn tier1_bypasses_revalidate_sovereignty_checks() {
        let checker = SovereigntyChecker::new();
        let cert = tier1_cert();
        // Even with completely invalid sovereignty state, Tier1 passes.
        let state = SovereigntyState {
            epoch: None,
            principal_id: String::new(),
            revocation_head_known: false,
            autonomy_ceiling: None,
            active_freeze: FreezeAction::HardFreeze,
        };

        let result = checker.check_revalidate(&cert, &state, 200, test_hash(0x07), test_hash(0x08));
        assert!(result.is_ok(), "Tier1 should bypass sovereignty checks");
    }

    #[test]
    fn tier1_bypasses_consume_sovereignty_checks() {
        let checker = SovereigntyChecker::new();
        let cert = tier1_cert();
        let state = SovereigntyState {
            epoch: None,
            principal_id: String::new(),
            revocation_head_known: false,
            autonomy_ceiling: None,
            active_freeze: FreezeAction::HardFreeze,
        };

        let result = checker.check_consume(&cert, &state, 200, test_hash(0x07), test_hash(0x08));
        assert!(result.is_ok(), "Tier1 should bypass sovereignty checks");
    }

    // =========================================================================
    // Stale sovereignty epoch tests
    // =========================================================================

    #[test]
    fn stale_sovereignty_epoch_denied_on_revalidate() {
        let checker = SovereigntyChecker::with_staleness_threshold(50);
        let cert = tier2_cert();
        let state = valid_sovereignty_state();

        // Current tick is 251, epoch freshness is 100, drift = 151 > 50.
        let err = checker
            .check_revalidate(&cert, &state, 251, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::StaleSovereigntyEpoch {
                    ref epoch_id,
                    last_known_tick: 100,
                    current_tick: 251,
                } if epoch_id == "epoch-001"
            ),
            "expected StaleSovereigntyEpoch, got: {:?}",
            err.deny_class
        );
    }

    #[test]
    fn stale_sovereignty_epoch_denied_on_consume() {
        let checker = SovereigntyChecker::with_staleness_threshold(50);
        let cert = tier2_cert();
        let state = valid_sovereignty_state();

        let err = checker
            .check_consume(&cert, &state, 251, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::StaleSovereigntyEpoch { .. }
        ));
    }

    #[test]
    fn fresh_epoch_passes() {
        let checker = SovereigntyChecker::with_staleness_threshold(100);
        let cert = tier2_cert();
        let state = valid_sovereignty_state();

        // Current tick 150, epoch freshness 100, drift = 50 <= 100. Passes.
        let result = checker.check_revalidate(&cert, &state, 150, test_hash(0x07), test_hash(0x08));
        assert!(result.is_ok());
    }

    // =========================================================================
    // Unknown revocation head tests
    // =========================================================================

    #[test]
    fn unknown_revocation_head_denied_on_revalidate() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.revocation_head_known = false;

        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::UnknownRevocationHead { ref principal_id }
                    if principal_id == "principal-001"
            ),
            "expected UnknownRevocationHead, got: {:?}",
            err.deny_class
        );
        assert_eq!(
            err.containment_action,
            Some(FreezeAction::SoftFreeze),
            "unknown revocation head must carry containment signal"
        );
    }

    #[test]
    fn unknown_revocation_head_denied_on_consume() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.revocation_head_known = false;

        let err = checker
            .check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::UnknownRevocationHead { .. }
        ));
    }

    // =========================================================================
    // Incompatible autonomy ceiling tests
    // =========================================================================

    #[test]
    fn incompatible_autonomy_ceiling_denied_on_consume() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert(); // requests Tier2Plus
        let mut state = valid_sovereignty_state();
        // Set ceiling to Tier1 -- Tier2Plus > Tier1, so denied.
        state.autonomy_ceiling = Some(AutonomyCeiling {
            max_risk_tier: RiskTier::Tier1,
            policy_binding_hash: test_hash(0xDD),
        });

        let err = checker
            .check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::IncompatibleAutonomyCeiling {
                    required: RiskTier::Tier1,
                    actual: RiskTier::Tier2Plus,
                }
            ),
            "expected IncompatibleAutonomyCeiling, got: {:?}",
            err.deny_class
        );
    }

    #[test]
    fn compatible_autonomy_ceiling_passes() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert(); // Tier2Plus
        let state = valid_sovereignty_state(); // ceiling is Tier2Plus

        let result = checker.check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08));
        assert!(result.is_ok());
    }

    #[test]
    fn missing_autonomy_ceiling_denied_on_consume() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.autonomy_ceiling = None;

        let err = checker
            .check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::SovereigntyUncertainty { .. }
        ));
    }

    // =========================================================================
    // Active freeze condition tests
    // =========================================================================

    #[test]
    fn active_soft_freeze_denied() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.active_freeze = FreezeAction::SoftFreeze;

        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::ActiveSovereignFreeze {
                freeze_action: FreezeAction::SoftFreeze,
            }
        ));
    }

    #[test]
    fn active_hard_freeze_denied() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.active_freeze = FreezeAction::HardFreeze;

        let err = checker
            .check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::ActiveSovereignFreeze {
                freeze_action: FreezeAction::HardFreeze,
            }
        ));
    }

    #[test]
    fn no_freeze_passes() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let state = valid_sovereignty_state(); // NoAction

        let result = checker.check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08));
        assert!(result.is_ok());
    }

    // =========================================================================
    // Sovereignty uncertainty triggers freeze action
    // =========================================================================

    #[test]
    fn missing_epoch_triggers_hard_freeze() {
        let state = SovereigntyState {
            epoch: None,
            principal_id: "principal-001".to_string(),
            revocation_head_known: true,
            autonomy_ceiling: Some(AutonomyCeiling {
                max_risk_tier: RiskTier::Tier2Plus,
                policy_binding_hash: test_hash(0xDD),
            }),
            active_freeze: FreezeAction::NoAction,
        };

        assert_eq!(
            SovereigntyChecker::evaluate_uncertainty_freeze(&state),
            FreezeAction::HardFreeze
        );
    }

    #[test]
    fn unknown_revocation_triggers_soft_freeze() {
        let mut state = valid_sovereignty_state();
        state.revocation_head_known = false;

        assert_eq!(
            SovereigntyChecker::evaluate_uncertainty_freeze(&state),
            FreezeAction::SoftFreeze
        );
    }

    #[test]
    fn missing_ceiling_triggers_soft_freeze() {
        let mut state = valid_sovereignty_state();
        state.autonomy_ceiling = None;

        assert_eq!(
            SovereigntyChecker::evaluate_uncertainty_freeze(&state),
            FreezeAction::SoftFreeze
        );
    }

    #[test]
    fn valid_state_triggers_no_freeze() {
        let state = valid_sovereignty_state();
        assert_eq!(
            SovereigntyChecker::evaluate_uncertainty_freeze(&state),
            FreezeAction::NoAction
        );
    }

    // =========================================================================
    // Sovereignty uncertainty denial tests
    // =========================================================================

    #[test]
    fn missing_epoch_denied_as_uncertainty() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.epoch = None;

        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("no sovereignty epoch")
            ),
            "expected SovereigntyUncertainty, got: {:?}",
            err.deny_class
        );
        assert_eq!(
            err.containment_action,
            Some(FreezeAction::HardFreeze),
            "missing epoch uncertainty must carry hard-freeze containment signal"
        );
    }

    #[test]
    fn zero_signature_epoch_denied_as_uncertainty() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.epoch = Some(SovereigntyEpoch {
            epoch_id: "epoch-bad".to_string(),
            freshness_tick: 100,
            signer_public_key: test_hash(0xCC),
            signature: ZERO_SIGNATURE,
        });

        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(matches!(
            err.deny_class,
            AuthorityDenyClass::SovereigntyUncertainty { .. }
        ));
    }

    // =========================================================================
    // Full lifecycle integration
    // =========================================================================

    #[test]
    fn valid_tier2_passes_all_checks() {
        let checker = SovereigntyChecker::new();
        let cert = tier2_cert();
        let state = valid_sovereignty_state();

        assert!(
            checker
                .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
                .is_ok()
        );
        assert!(
            checker
                .check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
                .is_ok()
        );
    }

    #[test]
    fn tier0_bypasses_all_checks() {
        let checker = SovereigntyChecker::new();
        let mut cert = tier2_cert();
        cert.risk_tier = RiskTier::Tier0;
        let state = SovereigntyState {
            epoch: None,
            principal_id: String::new(),
            revocation_head_known: false,
            autonomy_ceiling: None,
            active_freeze: FreezeAction::HardFreeze,
        };

        assert!(
            checker
                .check_revalidate(&cert, &state, 200, test_hash(0x07), test_hash(0x08))
                .is_ok()
        );
        assert!(
            checker
                .check_consume(&cert, &state, 200, test_hash(0x07), test_hash(0x08))
                .is_ok()
        );
    }
}
