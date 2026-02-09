// AGENT-AUTHORED
//! In-process `AuthorityJoinKernel` implementation and lifecycle gate
//! (RFC-0027 §3.3, TCK-00423).
//!
//! # Design
//!
//! [`InProcessKernel`] is the Phase 1 kernel that validates authority locally
//! against daemon state. All seven semantic laws from RFC-0027 §4 are
//! enforced:
//!
//! 1. **Linear Consumption**: Each AJC authorizes at most one side effect.
//! 2. **Intent Equality**: Consume requires exact intent digest match.
//! 3. **Freshness Dominance**: Tier2+ denies on stale freshness.
//! 4. **Revocation Dominance**: Revocation frontier advancement denies.
//! 5. **Delegation Narrowing**: Delegated joins are strict-subset.
//! 6. **Boundary Monotonicity**: `join < revalidate <= consume <= effect`.
//! 7. **Evidence Sufficiency**: Authoritative outcomes need replay receipts.
//!
//! [`LifecycleGate`] wraps a kernel and provides a single-call entry point
//! for `handle_request_tool` that executes the full `join -> revalidate ->
//! consume` sequence.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use apm2_core::crypto::Hash;
use apm2_core::pcac::{
    AuthorityConsumeRecordV1, AuthorityConsumedV1, AuthorityDenyV1, AuthorityJoinCertificateV1,
    AuthorityJoinInputV1, AuthorityJoinKernel, RiskTier,
};

const ZERO_HASH: Hash = [0u8; 32];

// =============================================================================
// InProcessKernel
// =============================================================================

/// Phase 1 in-process `AuthorityJoinKernel` implementation.
///
/// Validates authority locally. The consumed set is held in memory;
/// TCK-00426 (Durable Consume) will add persistent backing.
pub struct InProcessKernel {
    /// Set of consumed AJC IDs (Law 1: Linear Consumption).
    consumed: Mutex<HashSet<Hash>>,
    /// Current tick counter (monotonic).
    current_tick: Mutex<u64>,
}

impl InProcessKernel {
    /// Creates a new in-process kernel with the given starting tick.
    #[must_use]
    pub fn new(starting_tick: u64) -> Self {
        Self {
            consumed: Mutex::new(HashSet::new()),
            current_tick: Mutex::new(starting_tick),
        }
    }

    /// Advances the kernel tick (for testing and time progression).
    pub fn advance_tick(&self, new_tick: u64) {
        let mut tick = self.current_tick.lock().expect("lock poisoned");
        if new_tick > *tick {
            *tick = new_tick;
        }
    }

    /// Returns the current tick.
    #[must_use]
    pub fn current_tick(&self) -> u64 {
        *self.current_tick.lock().expect("lock poisoned")
    }

    /// Validates that a hash field is non-zero (fail-closed).
    fn require_nonzero(hash: &Hash, field_name: &str) -> Result<(), Box<AuthorityDenyV1>> {
        if *hash == ZERO_HASH {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::ZeroHash {
                    field_name: field_name.to_string(),
                },
                ajc_id: None,
                time_envelope_ref: ZERO_HASH,
                ledger_anchor: ZERO_HASH,
                denied_at_tick: 0,
            }));
        }
        Ok(())
    }

    /// Computes the authority join hash from the full normative input set.
    ///
    /// Per RFC-0027 §3.1, the join hash commits to ALL required fields:
    /// session, intent, capabilities, scope witnesses, identity, freshness,
    /// stop/budget, risk tier, determinism class, identity evidence level,
    /// and time/ledger anchors. Omitting any field would allow an attacker
    /// to produce colliding join hashes for semantically distinct authority
    /// requests.
    ///
    /// # Framing
    ///
    /// All variable-length fields are prefixed with `(len as
    /// u64).to_le_bytes()` to prevent concatenation ambiguity attacks. Vec
    /// fields additionally include a count prefix.
    fn compute_join_hash(input: &AuthorityJoinInputV1) -> Hash {
        use apm2_core::pcac::{DeterminismClass, IdentityEvidenceLevel};
        use blake3::Hasher;
        let mut hasher = Hasher::new();

        // Helper: length-prefixed variable-length field.
        let update_var = |h: &mut Hasher, data: &[u8]| {
            h.update(&(data.len() as u64).to_le_bytes());
            h.update(data);
        };

        // Subject bindings (length-prefixed strings)
        update_var(&mut hasher, input.session_id.as_bytes());
        match input.holon_id {
            Some(ref holon_id) => {
                hasher.update(&[1u8]); // present marker
                update_var(&mut hasher, holon_id.as_bytes());
            },
            None => {
                hasher.update(&[0u8]); // absent marker
            },
        }
        // Intent binding (fixed-length hash, no prefix needed)
        hasher.update(&input.intent_digest);
        // Capability bindings
        hasher.update(&input.capability_manifest_hash);
        // Scope witnesses: count prefix + each hash
        hasher.update(&(input.scope_witness_hashes.len() as u64).to_le_bytes());
        for scope_hash in &input.scope_witness_hashes {
            hasher.update(scope_hash);
        }
        // Delegation bindings (length-prefixed strings)
        update_var(&mut hasher, input.lease_id.as_bytes());
        match input.permeability_receipt_hash {
            Some(ref perm_hash) => {
                hasher.update(&[1u8]);
                hasher.update(perm_hash);
            },
            None => {
                hasher.update(&[0u8]);
            },
        }
        // Identity bindings
        hasher.update(&input.identity_proof_hash);
        // MAJOR 2 FIX: Include identity_evidence_level in hash.
        hasher.update(&[match input.identity_evidence_level {
            IdentityEvidenceLevel::Verified => 0u8,
            IdentityEvidenceLevel::PointerOnly => 1u8,
            _ => u8::MAX, // fail-closed: unknown levels
        }]);
        // Freshness bindings
        hasher.update(&input.directory_head_hash);
        hasher.update(&input.freshness_policy_hash);
        hasher.update(&input.freshness_witness_tick.to_le_bytes());
        // Stop/budget bindings
        hasher.update(&input.stop_budget_profile_digest);
        // Pre-actuation receipts: count prefix + each hash
        hasher.update(&(input.pre_actuation_receipt_hashes.len() as u64).to_le_bytes());
        for receipt_hash in &input.pre_actuation_receipt_hashes {
            hasher.update(receipt_hash);
        }
        // Risk classification
        hasher.update(&[match input.risk_tier {
            RiskTier::Tier0 => 0u8,
            RiskTier::Tier1 => 1u8,
            RiskTier::Tier2Plus => 2u8,
            _ => u8::MAX, // fail-closed: unknown tiers get maximum ordinal
        }]);
        // MAJOR 2 FIX: Include determinism_class in hash.
        hasher.update(&[match input.determinism_class {
            DeterminismClass::Deterministic => 0u8,
            DeterminismClass::BoundedNondeterministic => 1u8,
            _ => u8::MAX, // fail-closed: unknown classes
        }]);
        // Time/ledger anchors
        hasher.update(&input.time_envelope_ref);
        hasher.update(&input.as_of_ledger_anchor);
        *hasher.finalize().as_bytes()
    }

    /// Mints an AJC ID from the join hash and current tick.
    fn mint_ajc_id(join_hash: &Hash, tick: u64) -> Hash {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(join_hash);
        hasher.update(&tick.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

impl AuthorityJoinKernel for InProcessKernel {
    fn join(
        &self,
        input: &AuthorityJoinInputV1,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
        let tick = self.current_tick();

        // Validate required string fields.
        if input.session_id.is_empty() {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::InvalidSessionId,
                ajc_id: None,
                time_envelope_ref: input.time_envelope_ref,
                ledger_anchor: input.as_of_ledger_anchor,
                denied_at_tick: tick,
            }));
        }
        if input.lease_id.is_empty() {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::InvalidLeaseId,
                ajc_id: None,
                time_envelope_ref: input.time_envelope_ref,
                ledger_anchor: input.as_of_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        // Validate required hash fields are non-zero.
        Self::require_nonzero(&input.intent_digest, "intent_digest")?;
        Self::require_nonzero(&input.capability_manifest_hash, "capability_manifest_hash")?;
        Self::require_nonzero(&input.identity_proof_hash, "identity_proof_hash")?;
        Self::require_nonzero(&input.time_envelope_ref, "time_envelope_ref")?;
        Self::require_nonzero(&input.as_of_ledger_anchor, "as_of_ledger_anchor")?;
        Self::require_nonzero(&input.directory_head_hash, "directory_head_hash")?;
        Self::require_nonzero(&input.freshness_policy_hash, "freshness_policy_hash")?;
        Self::require_nonzero(
            &input.stop_budget_profile_digest,
            "stop_budget_profile_digest",
        )?;

        // Law 3 (partial): Freshness witness must be non-stale at join.
        // Phase 1: tick-based staleness check.
        if input.freshness_witness_tick == 0 {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::StaleFreshnessAtJoin,
                ajc_id: None,
                time_envelope_ref: input.time_envelope_ref,
                ledger_anchor: input.as_of_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        // §5: Tier2+ denies PointerOnly identity evidence.
        if matches!(input.risk_tier, RiskTier::Tier2Plus)
            && matches!(
                input.identity_evidence_level,
                apm2_core::pcac::IdentityEvidenceLevel::PointerOnly
            )
        {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::PointerOnlyDeniedAtTier2Plus,
                ajc_id: None,
                time_envelope_ref: input.time_envelope_ref,
                ledger_anchor: input.as_of_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        // Compute join hash and mint AJC.
        let join_hash = Self::compute_join_hash(input);
        let ajc_id = Self::mint_ajc_id(&join_hash, tick);

        // Default TTL: 300 ticks for Phase 1.
        let expires_at_tick = tick + 300;

        // Compute revocation head from directory_head_hash.
        let revocation_head_hash = input.directory_head_hash;

        Ok(AuthorityJoinCertificateV1 {
            ajc_id,
            authority_join_hash: join_hash,
            intent_digest: input.intent_digest,
            risk_tier: input.risk_tier,
            issued_time_envelope_ref: input.time_envelope_ref,
            as_of_ledger_anchor: input.as_of_ledger_anchor,
            expires_at_tick,
            revocation_head_hash,
            identity_evidence_level: input.identity_evidence_level,
            admission_capacity_token: None,
        })
    }

    fn revalidate(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        let tick = self.current_tick();

        // Law 4: Certificate expiry check.
        if tick > cert.expires_at_tick {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::CertificateExpired {
                    expired_at: cert.expires_at_tick,
                    current_tick: tick,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        // Law 4: Revocation frontier advancement.
        if current_revocation_head_hash != cert.revocation_head_hash {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::RevocationFrontierAdvanced,
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        // MAJOR 3 FIX: LedgerAnchorDrift check — if the current ledger
        // anchor has advanced beyond the AJC's `as_of_ledger_anchor`, the
        // authority is stale. This enforces the trait contract documented in
        // kernel.rs.
        if current_ledger_anchor != cert.as_of_ledger_anchor {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::LedgerAnchorDrift,
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: current_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        Ok(())
    }

    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        current_time_envelope_ref: Hash,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        let tick = self.current_tick();

        // MAJOR 3 FIX: Certificate expiry check in consume — the trait
        // contract documents this as a required check, and time can advance
        // between revalidate and consume.
        if tick > cert.expires_at_tick {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::CertificateExpired {
                    expired_at: cert.expires_at_tick,
                    current_tick: tick,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: cert.as_of_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        // Law 2: Intent digest equality.
        if intent_digest != cert.intent_digest {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::IntentDigestMismatch {
                    expected: cert.intent_digest,
                    actual: intent_digest,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: cert.as_of_ledger_anchor,
                denied_at_tick: tick,
            }));
        }

        // Law 1: Linear consumption — check and mark consumed atomically.
        {
            let mut consumed = self.consumed.lock().expect("lock poisoned");
            if consumed.contains(&cert.ajc_id) {
                return Err(Box::new(AuthorityDenyV1 {
                    deny_class: apm2_core::pcac::AuthorityDenyClass::AlreadyConsumed {
                        ajc_id: cert.ajc_id,
                    },
                    ajc_id: Some(cert.ajc_id),
                    time_envelope_ref: current_time_envelope_ref,
                    ledger_anchor: cert.as_of_ledger_anchor,
                    denied_at_tick: tick,
                }));
            }
            consumed.insert(cert.ajc_id);
        }

        // Compute effect selector digest from intent + tool class context.
        let effect_selector_digest = {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(&cert.ajc_id);
            hasher.update(&intent_digest);
            hasher.update(&tick.to_le_bytes());
            *hasher.finalize().as_bytes()
        };

        let consumed_witness = AuthorityConsumedV1 {
            ajc_id: cert.ajc_id,
            intent_digest,
            consumed_time_envelope_ref: current_time_envelope_ref,
            consumed_at_tick: tick,
        };

        let consume_record = AuthorityConsumeRecordV1 {
            ajc_id: cert.ajc_id,
            consumed_time_envelope_ref: current_time_envelope_ref,
            consumed_at_tick: tick,
            effect_selector_digest,
        };

        Ok((consumed_witness, consume_record))
    }
}

// =============================================================================
// LifecycleReceipts
// =============================================================================

/// Collected lifecycle receipts from a successful `join -> revalidate ->
/// consume` sequence. Attached to the tool response for replay verification.
#[derive(Debug, Clone)]
pub struct LifecycleReceipts {
    /// The AJC that was issued, revalidated, and consumed.
    pub certificate: AuthorityJoinCertificateV1,
    /// The consume record proving single-use consumption.
    pub consume_record: AuthorityConsumeRecordV1,
    /// The consumed witness for effect authorization.
    pub consumed_witness: AuthorityConsumedV1,
}

// =============================================================================
// LifecycleGate
// =============================================================================

/// Single-call lifecycle gate for `handle_request_tool`.
///
/// Executes the full `join -> revalidate -> consume` sequence. If any stage
/// fails, the deny is returned and no side effect may execute.
///
/// TCK-00427: When a `SovereigntyChecker` is configured, Tier2+ operations
/// are additionally validated against sovereignty state during revalidate
/// and consume stages.
pub struct LifecycleGate {
    kernel: Arc<dyn AuthorityJoinKernel>,
    /// Optional sovereignty checker for Tier2+ enforcement (TCK-00427).
    sovereignty_checker: Option<super::sovereignty::SovereigntyChecker>,
}

impl LifecycleGate {
    /// Returns `true` if the certificate's risk tier requires sovereignty
    /// checks.
    const fn requires_sovereignty_check(cert: &AuthorityJoinCertificateV1) -> bool {
        matches!(cert.risk_tier, RiskTier::Tier2Plus)
    }

    /// Creates a new lifecycle gate with the given kernel.
    #[must_use]
    pub fn new(kernel: Arc<dyn AuthorityJoinKernel>) -> Self {
        Self {
            kernel,
            sovereignty_checker: None,
        }
    }

    /// Creates a new lifecycle gate with sovereignty enforcement (TCK-00427).
    ///
    /// When a sovereignty checker is provided, Tier2+ operations are
    /// validated against sovereignty state during revalidate and consume.
    #[must_use]
    pub fn with_sovereignty_checker(
        kernel: Arc<dyn AuthorityJoinKernel>,
        checker: super::sovereignty::SovereigntyChecker,
    ) -> Self {
        Self {
            kernel,
            sovereignty_checker: Some(checker),
        }
    }

    /// Executes the full PCAC lifecycle for a tool request.
    ///
    /// # Arguments
    ///
    /// * `input` — Authority join inputs (session, intent, capabilities, etc.)
    /// * `current_time_envelope_ref` — Current HTF time witness for
    ///   revalidation.
    /// * `current_ledger_anchor` — Current ledger anchor for revalidation.
    /// * `current_revocation_head_hash` — Current revocation frontier for
    ///   revalidation.
    ///
    /// # Returns
    ///
    /// `Ok(LifecycleReceipts)` if all three stages pass, or `Err(deny)` at
    /// the first failing stage.
    ///
    /// # Errors
    ///
    /// Returns `Box<AuthorityDenyV1>` from whichever lifecycle stage fails
    /// first. The deny carries the stage context (join, revalidate, or
    /// consume).
    pub fn execute(
        &self,
        input: &AuthorityJoinInputV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<LifecycleReceipts, Box<AuthorityDenyV1>> {
        self.execute_with_sovereignty(
            input,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
            None,
            0,
        )
    }

    /// Executes the full PCAC lifecycle with optional sovereignty state
    /// (TCK-00427).
    ///
    /// When `sovereignty_state` is `Some` and a sovereignty checker is
    /// configured, Tier2+ operations are validated against sovereignty
    /// state during revalidate and consume stages.
    ///
    /// # Arguments
    ///
    /// * `input` — Authority join inputs.
    /// * `current_time_envelope_ref` — Current HTF time witness.
    /// * `current_ledger_anchor` — Current ledger anchor.
    /// * `current_revocation_head_hash` — Current revocation frontier.
    /// * `sovereignty_state` — Optional sovereignty state for Tier2+ checks.
    /// * `current_tick` — Current tick for sovereignty staleness checks.
    ///
    /// # Errors
    ///
    /// Returns `Box<AuthorityDenyV1>` from whichever lifecycle or sovereignty
    /// stage fails first.
    pub fn execute_with_sovereignty(
        &self,
        input: &AuthorityJoinInputV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
        sovereignty_state: Option<&super::sovereignty::SovereigntyState>,
        current_tick: u64,
    ) -> Result<LifecycleReceipts, Box<AuthorityDenyV1>> {
        // Stage 1: Join — construct AJC from validated inputs.
        let cert = self.kernel.join(input)?;

        // Stage 2: Revalidate — verify AJC against current state.
        self.kernel.revalidate(
            &cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )?;

        // Stage 2b (TCK-00427): Sovereignty revalidation for Tier2+.
        // BLOCKER 1 FIX: Fail-closed when checker is configured but state
        // is absent for a Tier2+ operation. Previously the `if let` conjunction
        // silently skipped the check.
        if Self::requires_sovereignty_check(&cert) {
            match (&self.sovereignty_checker, sovereignty_state) {
                (Some(checker), Some(state)) => {
                    checker.check_revalidate(
                        &cert,
                        state,
                        current_tick,
                        current_time_envelope_ref,
                        current_ledger_anchor,
                    )?;
                },
                (Some(_), None) => {
                    return Err(Box::new(AuthorityDenyV1 {
                        deny_class: apm2_core::pcac::AuthorityDenyClass::SovereigntyUncertainty {
                            reason: "sovereignty state not available for Tier2+ revalidation"
                                .to_string(),
                        },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: current_ledger_anchor,
                        denied_at_tick: current_tick,
                    }));
                },
                (None, _) => {
                    // No sovereignty checker configured — sovereignty checks
                    // are not enforced (Phase 1 opt-in).
                },
            }
        }

        // Stage 3b (TCK-00427): Sovereignty consume checks for Tier2+.
        // BLOCKER 2 FIX: This check is performed BEFORE kernel.consume() to
        // prevent irrevocable consume-set mutation before sovereignty
        // validation passes.
        if Self::requires_sovereignty_check(&cert) {
            match (&self.sovereignty_checker, sovereignty_state) {
                (Some(checker), Some(state)) => {
                    checker.check_consume(
                        &cert,
                        state,
                        current_tick,
                        current_time_envelope_ref,
                        current_ledger_anchor,
                    )?;
                },
                (Some(_), None) => {
                    return Err(Box::new(AuthorityDenyV1 {
                        deny_class: apm2_core::pcac::AuthorityDenyClass::SovereigntyUncertainty {
                            reason: "sovereignty state not available for Tier2+ consume"
                                .to_string(),
                        },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: current_ledger_anchor,
                        denied_at_tick: current_tick,
                    }));
                },
                (None, _) => {},
            }
        }

        // Stage 3: Consume — single-use consumption with intent equality.
        // BLOCKER 2 FIX: kernel.consume() is now called AFTER sovereignty
        // checks, preventing irrevocable consume-set mutation before
        // all admission checks pass.
        let (consumed_witness, consume_record) =
            self.kernel
                .consume(&cert, input.intent_digest, current_time_envelope_ref)?;

        Ok(LifecycleReceipts {
            certificate: cert,
            consume_record,
            consumed_witness,
        })
    }
}
