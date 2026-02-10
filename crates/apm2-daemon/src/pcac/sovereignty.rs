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
use subtle::ConstantTimeEq;

const ZERO_HASH: Hash = [0u8; 32];
const ZERO_SIGNATURE: [u8; 64] = [0u8; 64];
const EPOCH_DOMAIN_SEPARATOR: &[u8] = b"apm2-sovereignty-epoch-v1";

/// Maximum allowed tick drift before a sovereignty epoch is considered stale.
const DEFAULT_EPOCH_STALENESS_THRESHOLD: u64 = 100;

/// Maximum allowed future skew in ticks before a sovereignty epoch is rejected.
///
/// An epoch with `freshness_tick > current_tick + max_future_skew_ticks` is
/// treated as sovereignty uncertainty (potential clock manipulation or relay
/// attack) and triggers a hard freeze.
const DEFAULT_MAX_FUTURE_SKEW_TICKS: u64 = 300;

/// Sovereignty state for a principal scope.
///
/// Captures the current sovereignty inputs needed for Tier2+ validation.
/// Callers populate this from their authority store before calling
/// `SovereigntyChecker` methods.
///
/// Current limitation: this state is currently treated as a snapshot. Without
/// runtime epoch refresh wiring, Tier2+ checks will eventually deny on stale
/// epoch evidence as freshness thresholds elapse.
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

impl SovereigntyState {
    /// Refreshes the sovereignty epoch snapshot.
    ///
    /// TODO(TCK-00427): Wire this through a runtime IPC/projection update path.
    /// For now this stub exists so daemon construction sites can track the
    /// missing liveness plumbing explicitly.
    pub fn refresh_epoch(&mut self, next_epoch: SovereigntyEpoch) {
        self.epoch = Some(next_epoch);
    }
}

/// Validates sovereignty inputs for Tier2+ authority operations.
///
/// All checks are fail-closed: missing or ambiguous state produces a denial.
/// Tier0/1 operations (identified by `cert.risk_tier`) bypass all checks.
pub struct SovereigntyChecker {
    /// Trusted sovereignty authority signer public key (Ed25519).
    trusted_signer_key: [u8; 32],
    /// Staleness threshold for epoch freshness checks.
    epoch_staleness_threshold: u64,
    /// Maximum future skew in ticks before a sovereignty epoch is rejected.
    ///
    /// An epoch with `freshness_tick > current_tick + max_future_skew_ticks`
    /// is treated as sovereignty uncertainty and triggers a hard freeze.
    max_future_skew_ticks: u64,
}

impl SovereigntyChecker {
    /// Creates a new sovereignty checker with a trusted signer key and
    /// default thresholds.
    #[must_use]
    pub const fn new(trusted_signer_key: [u8; 32]) -> Self {
        Self {
            trusted_signer_key,
            epoch_staleness_threshold: DEFAULT_EPOCH_STALENESS_THRESHOLD,
            max_future_skew_ticks: DEFAULT_MAX_FUTURE_SKEW_TICKS,
        }
    }

    /// Creates a new sovereignty checker with a trusted signer key and custom
    /// staleness threshold.
    #[must_use]
    pub const fn with_staleness_threshold(trusted_signer_key: [u8; 32], threshold: u64) -> Self {
        Self {
            trusted_signer_key,
            epoch_staleness_threshold: threshold,
            max_future_skew_ticks: DEFAULT_MAX_FUTURE_SKEW_TICKS,
        }
    }

    /// Creates a new sovereignty checker with custom staleness threshold and
    /// future skew limit.
    #[must_use]
    pub const fn with_thresholds(
        trusted_signer_key: [u8; 32],
        staleness_threshold: u64,
        max_future_skew_ticks: u64,
    ) -> Self {
        Self {
            trusted_signer_key,
            epoch_staleness_threshold: staleness_threshold,
            max_future_skew_ticks,
        }
    }

    /// Returns the trusted sovereignty signer public key.
    #[must_use]
    pub const fn trusted_signer_key(&self) -> [u8; 32] {
        self.trusted_signer_key
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

    /// Computes the BLAKE3 digest of a principal ID for scope binding.
    #[must_use]
    pub fn principal_scope_hash(principal_id: &str) -> Hash {
        *blake3::hash(principal_id.as_bytes()).as_bytes()
    }

    /// Builds the domain-separated signing payload for sovereignty epochs.
    ///
    /// The payload includes the principal scope hash to cryptographically
    /// bind the epoch to a specific principal, preventing cross-principal
    /// replay attacks.
    #[must_use]
    pub fn epoch_signing_message(
        principal_scope_hash: &Hash,
        epoch_id: &str,
        freshness_tick: u64,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(
            EPOCH_DOMAIN_SEPARATOR.len()
                + 32 // principal_scope_hash
                + epoch_id.len()
                + std::mem::size_of::<u64>(),
        );
        message.extend_from_slice(EPOCH_DOMAIN_SEPARATOR);
        message.extend_from_slice(principal_scope_hash);
        message.extend_from_slice(epoch_id.as_bytes());
        message.extend_from_slice(&freshness_tick.to_le_bytes());
        message
    }

    /// Signs a sovereignty epoch with Ed25519 and domain separation.
    ///
    /// The signature commits to the `principal_scope_hash`, preventing
    /// cross-principal replay of signed epochs.
    #[must_use]
    pub fn sign_epoch(
        signing_key: &SigningKey,
        principal_id: &str,
        epoch_id: &str,
        freshness_tick: u64,
    ) -> [u8; 64] {
        let scope_hash = Self::principal_scope_hash(principal_id);
        signing_key
            .sign(&Self::epoch_signing_message(
                &scope_hash,
                epoch_id,
                freshness_tick,
            ))
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

        // Validate epoch field boundaries (fail-closed on oversized fields).
        if let Err(validation_err) = epoch.validate() {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: format!(
                        "sovereignty epoch boundary validation failed: {validation_err}"
                    ),
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        }

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

        // Fail-closed: signer key embedded in the epoch MUST match the trusted
        // sovereignty authority key configured for this checker.
        if epoch
            .signer_public_key
            .ct_eq(&self.trusted_signer_key)
            .unwrap_u8()
            == 0
        {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::UntrustedSovereigntySigner {
                    expected_signer_key: self.trusted_signer_key,
                    actual_signer_key: epoch.signer_public_key,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: current_tick,
                containment_action: Some(FreezeAction::HardFreeze),
            }));
        }

        // Verify principal scope binding: the epoch's principal_scope_hash
        // MUST match the runtime principal_id. This prevents cross-principal
        // replay attacks where an epoch signed for principal A is presented
        // as evidence for principal B.
        let expected_scope_hash = Self::principal_scope_hash(&state.principal_id);
        if epoch.principal_scope_hash != expected_scope_hash {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: format!(
                        "sovereignty epoch principal_scope_hash mismatch: \
                         epoch bound to different principal scope than runtime state '{}'",
                        state.principal_id,
                    ),
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
        let signing_message = Self::epoch_signing_message(
            &epoch.principal_scope_hash,
            &epoch.epoch_id,
            epoch.freshness_tick,
        );

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

        // Future-skew check: epoch freshness tick must not be too far in the
        // future. A future-dated epoch indicates clock manipulation, replay
        // of a pre-signed epoch, or relay attack. Treat as sovereignty
        // uncertainty with hard freeze (fail-closed).
        if epoch.freshness_tick > current_tick.saturating_add(self.max_future_skew_ticks) {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: AuthorityDenyClass::SovereigntyUncertainty {
                    reason: format!(
                        "sovereignty epoch freshness_tick {} exceeds current_tick {} + max_future_skew {}",
                        epoch.freshness_tick, current_tick, self.max_future_skew_ticks,
                    ),
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
        Self::new(ZERO_HASH)
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

    const TRUSTED_SIGNER_SEED: u8 = 0xCC;

    fn trusted_signer_key() -> [u8; 32] {
        signing_key(TRUSTED_SIGNER_SEED).verifying_key().to_bytes()
    }

    fn checker() -> SovereigntyChecker {
        SovereigntyChecker::new(trusted_signer_key())
    }

    fn checker_with_staleness_threshold(threshold: u64) -> SovereigntyChecker {
        SovereigntyChecker::with_staleness_threshold(trusted_signer_key(), threshold)
    }

    fn tier2_cert() -> AuthorityJoinCertificateV1 {
        AuthorityJoinCertificateV1 {
            ajc_id: test_hash(0xAA),
            authority_join_hash: test_hash(0xBB),
            intent_digest: test_hash(0x01),
            boundary_intent_class: apm2_core::pcac::BoundaryIntentClass::Assert,
            risk_tier: RiskTier::Tier2Plus,
            issued_time_envelope_ref: test_hash(0x07),
            as_of_ledger_anchor: test_hash(0x08),
            expires_at_tick: 500,
            issued_at_tick: 100,
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

    /// Builds a `SovereigntyEpoch` with a valid Ed25519 signature bound to
    /// a principal scope.
    fn signed_epoch(
        epoch_id: &str,
        freshness_tick: u64,
        key_seed: u8,
        principal_id: &str,
    ) -> SovereigntyEpoch {
        let signing_key = signing_key(key_seed);
        SovereigntyEpoch {
            epoch_id: epoch_id.to_string(),
            freshness_tick,
            principal_scope_hash: SovereigntyChecker::principal_scope_hash(principal_id),
            signer_public_key: signing_key.verifying_key().to_bytes(),
            signature: SovereigntyChecker::sign_epoch(
                &signing_key,
                principal_id,
                epoch_id,
                freshness_tick,
            ),
        }
    }

    const TEST_PRINCIPAL_ID: &str = "principal-001";

    fn valid_sovereignty_state() -> SovereigntyState {
        SovereigntyState {
            epoch: Some(signed_epoch(
                "epoch-001",
                100,
                TRUSTED_SIGNER_SEED,
                TEST_PRINCIPAL_ID,
            )),
            principal_id: TEST_PRINCIPAL_ID.to_string(),
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
        let checker = checker();
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
        let checker = checker();
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
        let checker = checker_with_staleness_threshold(50);
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
        let checker = checker_with_staleness_threshold(50);
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
        let checker = checker_with_staleness_threshold(100);
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
        let checker = checker();
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
        let checker = checker();
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
        let checker = checker();
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
        let checker = checker();
        let cert = tier2_cert(); // Tier2Plus
        let state = valid_sovereignty_state(); // ceiling is Tier2Plus

        let result = checker.check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08));
        assert!(result.is_ok());
    }

    #[test]
    fn missing_autonomy_ceiling_denied_on_consume() {
        let checker = checker();
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
        let checker = checker();
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
        let checker = checker();
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
        let checker = checker();
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
        let checker = checker();
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
        let checker = checker();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.epoch = Some(SovereigntyEpoch {
            epoch_id: "epoch-bad".to_string(),
            freshness_tick: 100,
            principal_scope_hash: SovereigntyChecker::principal_scope_hash(TEST_PRINCIPAL_ID),
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

    #[test]
    fn untrusted_signer_epoch_denied() {
        let checker = checker();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        let untrusted_key = signing_key(0xDD).verifying_key().to_bytes();
        state.epoch = Some(signed_epoch(
            "epoch-untrusted",
            100,
            0xDD,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::UntrustedSovereigntySigner {
                    expected_signer_key,
                    actual_signer_key,
                } if expected_signer_key == trusted_signer_key()
                    && actual_signer_key == untrusted_key
            ),
            "expected UntrustedSovereigntySigner, got: {:?}",
            err.deny_class
        );
    }

    // =========================================================================
    // Future-dated epoch skew tests (MAJOR 1 fix)
    // =========================================================================

    #[test]
    fn future_dated_epoch_denied_on_revalidate() {
        // Use a checker with future skew limit of 300 ticks.
        let checker = SovereigntyChecker::with_thresholds(trusted_signer_key(), 100, 300);
        let cert = tier2_cert();
        // Epoch freshness_tick is 1000, current_tick is 100. Skew = 900 > 300.
        let mut state = valid_sovereignty_state();
        state.epoch = Some(signed_epoch(
            "epoch-future",
            1000,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_revalidate(&cert, &state, 100, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("future_skew")
            ),
            "expected SovereigntyUncertainty with future_skew, got: {:?}",
            err.deny_class
        );
        assert_eq!(
            err.containment_action,
            Some(FreezeAction::HardFreeze),
            "future-dated epoch must carry hard-freeze containment signal"
        );
    }

    #[test]
    fn future_dated_epoch_denied_on_consume() {
        let checker = SovereigntyChecker::with_thresholds(trusted_signer_key(), 100, 300);
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        // freshness_tick=500, current_tick=100, skew=400 > 300
        state.epoch = Some(signed_epoch(
            "epoch-future-2",
            500,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_consume(&cert, &state, 100, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("future_skew")
            ),
            "expected SovereigntyUncertainty for future-dated epoch, got: {:?}",
            err.deny_class
        );
    }

    #[test]
    fn epoch_within_future_skew_passes() {
        let checker = SovereigntyChecker::with_thresholds(trusted_signer_key(), 100, 300);
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        // freshness_tick=350, current_tick=100, skew=250 <= 300. Should pass.
        state.epoch = Some(signed_epoch(
            "epoch-slight-future",
            350,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let result = checker.check_revalidate(&cert, &state, 100, test_hash(0x07), test_hash(0x08));
        assert!(
            result.is_ok(),
            "epoch within future skew tolerance should pass"
        );
    }

    #[test]
    fn epoch_at_exact_future_skew_boundary_passes() {
        let checker = SovereigntyChecker::with_thresholds(trusted_signer_key(), 100, 300);
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        // freshness_tick=400, current_tick=100, skew=300 == max_future_skew.
        // At the boundary, should pass (boundary is exclusive: > not >=).
        state.epoch = Some(signed_epoch(
            "epoch-boundary",
            400,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let result = checker.check_revalidate(&cert, &state, 100, test_hash(0x07), test_hash(0x08));
        assert!(
            result.is_ok(),
            "epoch at exact future skew boundary should pass"
        );
    }

    #[test]
    fn epoch_one_past_future_skew_boundary_denied() {
        let checker = SovereigntyChecker::with_thresholds(trusted_signer_key(), 100, 300);
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        // freshness_tick=401, current_tick=100, skew=301 > 300. Should deny.
        state.epoch = Some(signed_epoch(
            "epoch-past-boundary",
            401,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_revalidate(&cert, &state, 100, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { .. }
            ),
            "epoch one past future skew boundary should be denied"
        );
    }

    #[test]
    fn far_future_epoch_adversarial_denied() {
        // Adversarial test: attacker sets freshness_tick to u64::MAX - 1
        let checker = checker();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.epoch = Some(signed_epoch(
            "epoch-adversarial",
            u64::MAX - 1,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_revalidate(&cert, &state, 100, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("future_skew")
            ),
            "far-future adversarial epoch should be denied as uncertainty"
        );
        assert_eq!(
            err.containment_action,
            Some(FreezeAction::HardFreeze),
            "adversarial future epoch must trigger hard freeze"
        );
    }

    #[test]
    fn tier1_bypasses_future_skew_check() {
        let checker = SovereigntyChecker::with_thresholds(trusted_signer_key(), 100, 300);
        let cert = tier1_cert();
        let mut state = valid_sovereignty_state();
        state.epoch = Some(signed_epoch(
            "epoch-future-tier1",
            99999,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let result = checker.check_revalidate(&cert, &state, 100, test_hash(0x07), test_hash(0x08));
        assert!(result.is_ok(), "Tier1 should bypass future skew check");
    }

    // =========================================================================
    // Full lifecycle integration
    // =========================================================================

    #[test]
    fn valid_tier2_passes_all_checks() {
        let checker = checker();
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

    // =========================================================================
    // Cross-principal replay adversarial test (Security BLOCKER fix)
    // =========================================================================

    /// Proves that a sovereignty epoch signed for principal A is rejected
    /// when presented for principal B. This prevents cross-principal replay
    /// attacks where an attacker reuses epoch evidence across scopes.
    #[test]
    fn cross_principal_replay_denied() {
        let checker = checker();
        let cert = tier2_cert();

        // Sign an epoch for principal-A.
        let epoch_for_a = signed_epoch("epoch-001", 100, TRUSTED_SIGNER_SEED, "principal-A");

        // Present it as sovereignty evidence for principal-B.
        let state = SovereigntyState {
            epoch: Some(epoch_for_a),
            principal_id: "principal-B".to_string(),
            revocation_head_known: true,
            autonomy_ceiling: Some(AutonomyCeiling {
                max_risk_tier: RiskTier::Tier2Plus,
                policy_binding_hash: test_hash(0xDD),
            }),
            active_freeze: FreezeAction::NoAction,
        };

        // Must be denied: epoch is bound to principal-A, runtime says
        // principal-B.
        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("principal_scope_hash mismatch")
            ),
            "cross-principal replay must be denied with scope mismatch, got: {:?}",
            err.deny_class
        );
        assert_eq!(
            err.containment_action,
            Some(FreezeAction::HardFreeze),
            "cross-principal replay must carry hard-freeze containment"
        );
    }

    /// Proves that cross-principal replay is also denied in the consume path.
    #[test]
    fn cross_principal_replay_denied_on_consume() {
        let checker = checker();
        let cert = tier2_cert();

        let epoch_for_a = signed_epoch("epoch-001", 100, TRUSTED_SIGNER_SEED, "principal-A");

        let state = SovereigntyState {
            epoch: Some(epoch_for_a),
            principal_id: "principal-B".to_string(),
            revocation_head_known: true,
            autonomy_ceiling: Some(AutonomyCeiling {
                max_risk_tier: RiskTier::Tier2Plus,
                policy_binding_hash: test_hash(0xDD),
            }),
            active_freeze: FreezeAction::NoAction,
        };

        let err = checker
            .check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("principal_scope_hash mismatch")
            ),
            "cross-principal replay on consume must be denied, got: {:?}",
            err.deny_class
        );
    }

    // =========================================================================
    // SovereigntyEpoch boundary validation tests (Security BLOCKER fix)
    // =========================================================================

    #[test]
    fn oversized_epoch_id_denied_on_revalidate() {
        let checker = checker();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        // Create an epoch with an epoch_id that exceeds MAX_STRING_LENGTH.
        let oversized_id = "x".repeat(apm2_core::pcac::MAX_STRING_LENGTH + 1);
        state.epoch = Some(signed_epoch(
            &oversized_id,
            100,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("boundary validation failed")
            ),
            "oversized epoch_id must be denied as sovereignty uncertainty, got: {:?}",
            err.deny_class
        );
        assert_eq!(
            err.containment_action,
            Some(FreezeAction::HardFreeze),
            "oversized epoch_id must carry hard-freeze containment"
        );
    }

    #[test]
    fn oversized_epoch_id_denied_on_consume() {
        let checker = checker();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        let oversized_id = "x".repeat(apm2_core::pcac::MAX_STRING_LENGTH + 1);
        state.epoch = Some(signed_epoch(
            &oversized_id,
            100,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_consume(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("boundary validation failed")
            ),
            "oversized epoch_id must be denied on consume path, got: {:?}",
            err.deny_class
        );
    }

    #[test]
    fn empty_epoch_id_denied_on_revalidate() {
        let checker = checker();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        state.epoch = Some(signed_epoch(
            "",
            100,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let err = checker
            .check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08))
            .unwrap_err();
        assert!(
            matches!(
                err.deny_class,
                AuthorityDenyClass::SovereigntyUncertainty { ref reason }
                    if reason.contains("boundary validation failed")
            ),
            "empty epoch_id must be denied, got: {:?}",
            err.deny_class
        );
    }

    #[test]
    fn epoch_id_at_max_length_passes() {
        let checker = checker();
        let cert = tier2_cert();
        let mut state = valid_sovereignty_state();
        // epoch_id at exactly MAX_STRING_LENGTH should pass validation.
        let max_id = "x".repeat(apm2_core::pcac::MAX_STRING_LENGTH);
        state.epoch = Some(signed_epoch(
            &max_id,
            100,
            TRUSTED_SIGNER_SEED,
            TEST_PRINCIPAL_ID,
        ));

        let result = checker.check_revalidate(&cert, &state, 110, test_hash(0x07), test_hash(0x08));
        assert!(
            result.is_ok(),
            "epoch_id at exactly MAX_STRING_LENGTH should pass validation"
        );
    }

    #[test]
    fn tier0_bypasses_all_checks() {
        let checker = checker();
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
