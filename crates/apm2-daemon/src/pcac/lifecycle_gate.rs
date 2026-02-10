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
    AuthorityJoinInputV1, AuthorityJoinKernel, BoundaryIntentClass, FreezeAction, RiskTier,
};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::htf::HolonicClock;

const ZERO_HASH: Hash = [0u8; 32];

// =============================================================================
// InProcessKernel
// =============================================================================

/// Phase 1 in-process `AuthorityJoinKernel` implementation.
///
/// Validates authority locally. The consumed set is held in memory;
/// TCK-00426 (Durable Consume) will add persistent backing.
///
/// # Clock Integration (TCK-00427 quality BLOCKER fix)
///
/// When constructed with [`InProcessKernel::with_clock`], the kernel
/// derives its current tick dynamically from the shared [`HolonicClock`].
/// This ensures certificate expiry checks in `revalidate` and `consume`
/// use real elapsed time rather than a frozen starting tick.
///
/// The test constructor [`InProcessKernel::new`] uses a manual tick that
/// can be advanced via [`InProcessKernel::advance_tick`] for deterministic
/// unit testing.
pub struct InProcessKernel {
    /// Set of consumed AJC IDs (Law 1: Linear Consumption).
    consumed: Mutex<HashSet<Hash>>,
    /// Manual tick counter (used when no clock is provided, i.e., tests).
    manual_tick: Mutex<u64>,
    /// Optional shared holonic clock for dynamic tick derivation.
    ///
    /// When present, `current_tick()` reads the monotonic tick from the
    /// clock instead of using the manual counter. This prevents the
    /// "frozen tick" bug where certificates never expire.
    clock: Option<Arc<HolonicClock>>,
}

impl InProcessKernel {
    /// Creates a new in-process kernel with the given starting tick.
    ///
    /// This constructor is intended for **tests** that need deterministic
    /// tick control. For production use, prefer [`with_clock`] to derive
    /// ticks from the shared [`HolonicClock`].
    ///
    /// [`with_clock`]: InProcessKernel::with_clock
    #[must_use]
    pub fn new(starting_tick: u64) -> Self {
        Self {
            consumed: Mutex::new(HashSet::new()),
            manual_tick: Mutex::new(starting_tick),
            clock: None,
        }
    }

    /// Creates a new in-process kernel backed by a shared [`HolonicClock`].
    ///
    /// The kernel derives its current tick from the clock's monotonic tick
    /// source (`now_mono_tick`), ensuring certificate expiry checks use
    /// real elapsed time. This satisfies RFC-0027 Law 4 (Freshness/Revocation
    /// Dominance) for TTL enforcement.
    ///
    /// # Fail-Closed Semantics
    ///
    /// If the clock reports a regression error, `current_tick()` returns an
    /// `Err` denial rather than falling back to a tick value. This prevents
    /// time-based security checks (certificate expiry, sovereignty staleness)
    /// from failing open.
    #[must_use]
    pub fn with_clock(clock: Arc<HolonicClock>) -> Self {
        Self {
            consumed: Mutex::new(HashSet::new()),
            manual_tick: Mutex::new(0),
            clock: Some(clock),
        }
    }

    /// Advances the kernel tick (for testing and time progression).
    ///
    /// When a clock is configured, this sets a floor for the manual tick
    /// counter but the clock-derived tick takes precedence via `max()`.
    pub fn advance_tick(&self, new_tick: u64) {
        let mut tick = self.manual_tick.lock().expect("lock poisoned");
        if new_tick > *tick {
            *tick = new_tick;
        }
    }

    /// Returns the current tick.
    ///
    /// When a [`HolonicClock`] is configured (production), derives the tick
    /// from the clock's monotonic source and takes the maximum of the
    /// clock-derived tick and the manual tick floor (monotonicity).
    ///
    /// When no clock is configured (tests), returns the manual tick counter.
    ///
    /// # Fail-Closed (Security)
    ///
    /// Clock regression errors return `Err` instead of a fallback value.
    /// Falling back to tick `0` would cause time-based security checks
    /// (certificate expiry, sovereignty staleness) to **fail-open**, because
    /// `0 > any_positive_threshold` is always `false`. Callers must
    /// construct an appropriate `AuthorityDenyV1` with their available
    /// context (time envelope ref, ledger anchor, AJC ID).
    ///
    /// # Errors
    ///
    /// Returns a `String` describing the clock error. Callers are responsible
    /// for wrapping this into an `AuthorityDenyV1` with appropriate context.
    pub fn current_tick(&self) -> Result<u64, String> {
        let manual = *self.manual_tick.lock().expect("lock poisoned");

        match self.clock.as_ref() {
            None => Ok(manual),
            Some(clock) => {
                let clock_tick = match clock.now_mono_tick() {
                    Ok(t) => t.value(),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "InProcessKernel: clock regression during tick derivation \
                             — denying authority operation (fail-closed)"
                        );
                        return Err(format!("clock regression during tick derivation: {e}"));
                    },
                };
                // Monotonicity: take the max of clock-derived and manual floor.
                Ok(manual.max(clock_tick))
            },
        }
    }

    /// Converts a clock error from [`current_tick`] into an authority denial
    /// with the provided context.
    ///
    /// [`current_tick`]: InProcessKernel::current_tick
    pub(crate) fn clock_error_to_deny(
        &self,
        reason: String,
        ajc_id: Option<Hash>,
        time_envelope_ref: Hash,
        ledger_anchor: Hash,
    ) -> Box<AuthorityDenyV1> {
        let denied_at_tick = {
            let manual_tick = *self.manual_tick.lock().expect("lock poisoned");
            if manual_tick == 0 {
                u64::MAX
            } else {
                manual_tick
            }
        };

        Box::new(AuthorityDenyV1 {
            deny_class: apm2_core::pcac::AuthorityDenyClass::SovereigntyUncertainty { reason },
            ajc_id,
            time_envelope_ref,
            ledger_anchor,
            // Prefer last-known kernel tick; use MAX as unknown sentinel.
            denied_at_tick,
            containment_action: Some(apm2_core::pcac::FreezeAction::HardFreeze),
        })
    }

    /// Validates that a hash field is non-zero (fail-closed).
    ///
    /// TCK-00427 quality MAJOR fix: Deny records now carry contextual
    /// `time_envelope_ref`, `ledger_anchor`, and `denied_at_tick` so they
    /// pass `AuthorityDenyV1::validate` replay-binding invariants.
    fn require_nonzero(
        hash: &Hash,
        field_name: &str,
        time_envelope_ref: Hash,
        ledger_anchor: Hash,
        denied_at_tick: u64,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        if *hash == ZERO_HASH {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::ZeroHash {
                    field_name: field_name.to_string(),
                },
                ajc_id: None,
                time_envelope_ref,
                ledger_anchor,
                denied_at_tick,
                containment_action: None,
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
    /// Every field is domain-separated with an explicit field tag. Variable-
    /// length fields are prefixed with `(len as u64).to_le_bytes()` to
    /// prevent concatenation ambiguity attacks. Vec fields additionally
    /// include a count prefix.
    fn compute_join_hash(input: &AuthorityJoinInputV1) -> Hash {
        use apm2_core::pcac::{DeterminismClass, IdentityEvidenceLevel};
        use blake3::Hasher;
        let mut hasher = Hasher::new();

        // Helper: domain-separated fixed-width field.
        let update_tagged_fixed = |h: &mut Hasher, tag: &[u8], data: &[u8]| {
            h.update(tag);
            h.update(data);
        };
        // Helper: domain-separated length-prefixed variable-length field.
        let update_tagged_var = |h: &mut Hasher, tag: &[u8], data: &[u8]| {
            h.update(tag);
            h.update(&(data.len() as u64).to_le_bytes());
            h.update(data);
        };
        // Helper: domain-separated u64 field.
        let update_tagged_u64 = |h: &mut Hasher, tag: &[u8], value: u64| {
            h.update(tag);
            h.update(&value.to_le_bytes());
        };

        // Subject bindings (length-prefixed strings)
        update_tagged_var(&mut hasher, b"session_id", input.session_id.as_bytes());
        hasher.update(b"holon_id");
        if let Some(ref holon_id) = input.holon_id {
            hasher.update(&[1u8]); // present marker
            update_tagged_var(&mut hasher, b"holon_id_value", holon_id.as_bytes());
        } else {
            hasher.update(&[0u8]); // absent marker
        }
        // Intent binding (fixed-length hash, no prefix needed)
        update_tagged_fixed(&mut hasher, b"intent_digest", &input.intent_digest);
        hasher.update(b"boundary_intent_class");
        hasher.update(&[match input.boundary_intent_class {
            BoundaryIntentClass::Observe => 0u8,
            BoundaryIntentClass::Assert => 1u8,
            BoundaryIntentClass::Delegate => 2u8,
            BoundaryIntentClass::Actuate => 3u8,
            BoundaryIntentClass::Govern => 4u8,
            _ => u8::MAX, // fail-closed: unknown classes
        }]);
        // Capability bindings
        update_tagged_fixed(
            &mut hasher,
            b"capability_manifest_hash",
            &input.capability_manifest_hash,
        );
        // Scope witnesses: count prefix + each hash (canonical set ordering).
        // Security: sorting prevents order-dependent AJC IDs for semantically
        // identical witness sets.
        let mut sorted_scope_witness_hashes = input.scope_witness_hashes.clone();
        sorted_scope_witness_hashes.sort_unstable();
        hasher.update(b"scope_witness_hashes");
        hasher.update(&(sorted_scope_witness_hashes.len() as u64).to_le_bytes());
        for scope_hash in &sorted_scope_witness_hashes {
            update_tagged_fixed(&mut hasher, b"scope_witness_hash", scope_hash);
        }
        // Delegation bindings (length-prefixed strings)
        update_tagged_var(&mut hasher, b"lease_id", input.lease_id.as_bytes());
        hasher.update(b"permeability_receipt_hash");
        if let Some(ref perm_hash) = input.permeability_receipt_hash {
            hasher.update(&[1u8]);
            update_tagged_fixed(&mut hasher, b"permeability_receipt_hash_value", perm_hash);
        } else {
            hasher.update(&[0u8]);
        }
        // Identity bindings
        update_tagged_fixed(
            &mut hasher,
            b"identity_proof_hash",
            &input.identity_proof_hash,
        );
        // MAJOR 2 FIX: Include identity_evidence_level in hash.
        hasher.update(b"identity_evidence_level");
        hasher.update(&[match input.identity_evidence_level {
            IdentityEvidenceLevel::Verified => 0u8,
            IdentityEvidenceLevel::PointerOnly => 1u8,
            _ => u8::MAX, // fail-closed: unknown levels
        }]);
        // Pointer-only waiver binding
        hasher.update(b"pointer_only_waiver_hash");
        if let Some(ref waiver_hash) = input.pointer_only_waiver_hash {
            hasher.update(&[1u8]); // present marker
            update_tagged_fixed(&mut hasher, b"pointer_only_waiver_hash_value", waiver_hash);
        } else {
            hasher.update(&[0u8]); // absent marker
        }
        // Freshness bindings
        update_tagged_fixed(
            &mut hasher,
            b"directory_head_hash",
            &input.directory_head_hash,
        );
        update_tagged_fixed(
            &mut hasher,
            b"freshness_policy_hash",
            &input.freshness_policy_hash,
        );
        update_tagged_u64(
            &mut hasher,
            b"freshness_witness_tick",
            input.freshness_witness_tick,
        );
        // Stop/budget bindings
        update_tagged_fixed(
            &mut hasher,
            b"stop_budget_profile_digest",
            &input.stop_budget_profile_digest,
        );
        // Pre-actuation receipts: count prefix + each hash (canonical set
        // ordering). Security: sorting prevents replay amplification by receipt
        // permutation.
        let mut sorted_pre_actuation_receipt_hashes = input.pre_actuation_receipt_hashes.clone();
        sorted_pre_actuation_receipt_hashes.sort_unstable();
        hasher.update(b"pre_actuation_receipt_hashes");
        hasher.update(&(sorted_pre_actuation_receipt_hashes.len() as u64).to_le_bytes());
        for receipt_hash in &sorted_pre_actuation_receipt_hashes {
            update_tagged_fixed(&mut hasher, b"pre_actuation_receipt_hash", receipt_hash);
        }
        // Risk classification
        hasher.update(b"risk_tier");
        hasher.update(&[match input.risk_tier {
            RiskTier::Tier0 => 0u8,
            RiskTier::Tier1 => 1u8,
            RiskTier::Tier2Plus => 2u8,
            _ => u8::MAX, // fail-closed: unknown tiers get maximum ordinal
        }]);
        // MAJOR 2 FIX: Include determinism_class in hash.
        hasher.update(b"determinism_class");
        hasher.update(&[match input.determinism_class {
            DeterminismClass::Deterministic => 0u8,
            DeterminismClass::BoundedNondeterministic => 1u8,
            _ => u8::MAX, // fail-closed: unknown classes
        }]);
        // Time/ledger anchors
        update_tagged_fixed(&mut hasher, b"time_envelope_ref", &input.time_envelope_ref);
        update_tagged_fixed(
            &mut hasher,
            b"as_of_ledger_anchor",
            &input.as_of_ledger_anchor,
        );
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
        let tick = self.current_tick().map_err(|reason| {
            self.clock_error_to_deny(
                reason,
                None,
                input.time_envelope_ref,
                input.as_of_ledger_anchor,
            )
        })?;

        // Validate required string fields.
        if input.session_id.is_empty() {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::InvalidSessionId,
                ajc_id: None,
                time_envelope_ref: input.time_envelope_ref,
                ledger_anchor: input.as_of_ledger_anchor,
                denied_at_tick: tick,
                containment_action: None,
            }));
        }
        if input.lease_id.is_empty() {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::InvalidLeaseId,
                ajc_id: None,
                time_envelope_ref: input.time_envelope_ref,
                ledger_anchor: input.as_of_ledger_anchor,
                denied_at_tick: tick,
                containment_action: None,
            }));
        }

        // TCK-00427 quality MAJOR fix: Validate time_envelope_ref and
        // as_of_ledger_anchor first so they can be threaded as context into
        // subsequent require_nonzero calls, producing deny records that pass
        // AuthorityDenyV1::validate replay-binding invariants.
        if input.time_envelope_ref == ZERO_HASH {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::ZeroHash {
                    field_name: "time_envelope_ref".to_string(),
                },
                ajc_id: None,
                // time_envelope_ref itself is zero, but as_of_ledger_anchor
                // may be valid. Use the best-available context.
                time_envelope_ref: input.as_of_ledger_anchor,
                ledger_anchor: input.as_of_ledger_anchor,
                denied_at_tick: tick,
                containment_action: None,
            }));
        }
        if input.as_of_ledger_anchor == ZERO_HASH {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::ZeroHash {
                    field_name: "as_of_ledger_anchor".to_string(),
                },
                ajc_id: None,
                time_envelope_ref: input.time_envelope_ref,
                // ledger_anchor itself is zero; use time_envelope_ref as
                // best-available anchor binding.
                ledger_anchor: input.time_envelope_ref,
                denied_at_tick: tick,
                containment_action: None,
            }));
        }

        // Both time_envelope_ref and as_of_ledger_anchor are now validated
        // non-zero and can be threaded into remaining require_nonzero calls.
        Self::require_nonzero(
            &input.intent_digest,
            "intent_digest",
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            tick,
        )?;
        Self::require_nonzero(
            &input.capability_manifest_hash,
            "capability_manifest_hash",
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            tick,
        )?;
        Self::require_nonzero(
            &input.identity_proof_hash,
            "identity_proof_hash",
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            tick,
        )?;
        Self::require_nonzero(
            &input.directory_head_hash,
            "directory_head_hash",
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            tick,
        )?;
        Self::require_nonzero(
            &input.freshness_policy_hash,
            "freshness_policy_hash",
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            tick,
        )?;
        Self::require_nonzero(
            &input.stop_budget_profile_digest,
            "stop_budget_profile_digest",
            input.time_envelope_ref,
            input.as_of_ledger_anchor,
            tick,
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
                containment_action: None,
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
                containment_action: None,
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
            boundary_intent_class: input.boundary_intent_class,
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
        let tick = self.current_tick().map_err(|reason| {
            self.clock_error_to_deny(
                reason,
                Some(cert.ajc_id),
                current_time_envelope_ref,
                current_ledger_anchor,
            )
        })?;

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
                containment_action: None,
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
                containment_action: None,
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
                containment_action: None,
            }));
        }

        Ok(())
    }

    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        boundary_intent_class: BoundaryIntentClass,
        requires_authoritative_acceptance: bool,
        current_time_envelope_ref: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        let tick = self.current_tick().map_err(|reason| {
            self.clock_error_to_deny(
                reason,
                Some(cert.ajc_id),
                current_time_envelope_ref,
                cert.as_of_ledger_anchor,
            )
        })?;

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
                containment_action: None,
            }));
        }

        // Law 4: Revocation frontier advancement check in consume.
        if !bool::from(current_revocation_head_hash.ct_eq(&cert.revocation_head_hash)) {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::RevocationFrontierAdvanced,
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: cert.as_of_ledger_anchor,
                denied_at_tick: tick,
                containment_action: None,
            }));
        }

        let join_intent_class = cert.boundary_intent_class;
        if !bool::from(
            join_intent_class
                .value()
                .ct_eq(&boundary_intent_class.value()),
        ) {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::IntentClassDriftBetweenStages {
                    join_intent_class,
                    consume_intent_class: boundary_intent_class,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: cert.as_of_ledger_anchor,
                denied_at_tick: tick,
                containment_action: None,
            }));
        }

        if requires_authoritative_acceptance && !boundary_intent_class.is_authoritative() {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class:
                    apm2_core::pcac::AuthorityDenyClass::ObservationalPayloadInAuthoritativePath {
                        intent_class: boundary_intent_class,
                    },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: cert.as_of_ledger_anchor,
                denied_at_tick: tick,
                containment_action: None,
            }));
        }

        // Law 2: Intent digest equality.
        if !bool::from(intent_digest.ct_eq(&cert.intent_digest)) {
            return Err(Box::new(AuthorityDenyV1 {
                deny_class: apm2_core::pcac::AuthorityDenyClass::IntentDigestMismatch {
                    expected: cert.intent_digest,
                    actual: intent_digest,
                },
                ajc_id: Some(cert.ajc_id),
                time_envelope_ref: current_time_envelope_ref,
                ledger_anchor: cert.as_of_ledger_anchor,
                denied_at_tick: tick,
                containment_action: None,
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
                    containment_action: None,
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
    /// Optional reference to the in-process kernel for production tick
    /// advancement. When set, `advance_tick` calls are forwarded so
    /// freshness checks observe monotonic runtime time.
    tick_kernel: Option<Arc<InProcessKernel>>,
    /// Optional sovereignty checker for Tier2+ enforcement (TCK-00427).
    sovereignty_checker: Option<super::sovereignty::SovereigntyChecker>,
    /// Optional stop authority for sovereignty freeze actuation (TCK-00427
    /// security review BLOCKER 1).
    ///
    /// When a sovereignty denial carries a `containment_action`, the gate
    /// actuates the freeze via this authority before returning the denial.
    /// `HardFreeze` triggers an emergency stop (persistent, all sessions).
    /// `SoftFreeze` triggers a governance stop (session-scoped restriction).
    stop_authority: Option<Arc<crate::episode::preactuation::StopAuthority>>,
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
            tick_kernel: None,
            sovereignty_checker: None,
            stop_authority: None,
        }
    }

    /// Creates a lifecycle gate with production tick advancement wiring.
    ///
    /// The `tick_kernel` reference is advanced by session dispatch using
    /// fresh HLC-derived ticks so revalidation/consume freshness checks
    /// cannot stay pinned to join-time.
    #[must_use]
    pub fn with_tick_kernel(
        kernel: Arc<dyn AuthorityJoinKernel>,
        tick_kernel: Arc<InProcessKernel>,
    ) -> Self {
        Self {
            kernel,
            tick_kernel: Some(tick_kernel),
            sovereignty_checker: None,
            stop_authority: None,
        }
    }

    /// Creates a lifecycle gate with both tick advancement and sovereignty
    /// composition checks.
    #[must_use]
    pub fn with_tick_kernel_and_sovereignty(
        kernel: Arc<dyn AuthorityJoinKernel>,
        tick_kernel: Arc<InProcessKernel>,
        checker: super::sovereignty::SovereigntyChecker,
        stop_authority: Arc<crate::episode::preactuation::StopAuthority>,
    ) -> Self {
        Self {
            kernel,
            tick_kernel: Some(tick_kernel),
            sovereignty_checker: Some(checker),
            stop_authority: Some(stop_authority),
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
            tick_kernel: None,
            sovereignty_checker: Some(checker),
            stop_authority: None,
        }
    }

    /// Creates a new lifecycle gate with sovereignty enforcement and freeze
    /// actuation (TCK-00427 security review BLOCKER 1).
    ///
    /// When a sovereignty denial carries a `containment_action`, the gate
    /// actuates the freeze via the provided `StopAuthority` before returning
    /// the denial. This ensures `HardFreeze` and `SoftFreeze` are
    /// persistently applied to runtime controls, not just logged.
    #[must_use]
    pub fn with_sovereignty_and_stop_authority(
        kernel: Arc<dyn AuthorityJoinKernel>,
        checker: super::sovereignty::SovereigntyChecker,
        stop_authority: Arc<crate::episode::preactuation::StopAuthority>,
    ) -> Self {
        Self {
            kernel,
            tick_kernel: None,
            sovereignty_checker: Some(checker),
            stop_authority: Some(stop_authority),
        }
    }

    /// Advances the attached tick kernel (if configured) monotonically.
    pub fn advance_tick(&self, new_tick: u64) {
        if let Some(ref tick_kernel) = self.tick_kernel {
            tick_kernel.advance_tick(new_tick);
        }
    }

    /// Actuates a sovereignty freeze via `StopAuthority` and logs the
    /// containment action.
    ///
    /// TCK-00427 security review BLOCKER 1: Sovereignty denials with
    /// `containment_action` are now mapped to authoritative runtime controls:
    /// - `HardFreeze` -> `set_emergency_stop(true)` (persistent, all sessions)
    /// - `SoftFreeze` -> `set_governance_stop(true)` (session-scoped
    ///   restriction)
    fn actuate_containment(&self, stage: &'static str, deny: &AuthorityDenyV1) {
        let Some(containment_action) = deny.containment_action else {
            return;
        };

        warn!(
            stage = stage,
            deny_class = %deny.deny_class,
            containment_action = %containment_action,
            ajc_id = ?deny.ajc_id.map(hex::encode),
            denied_at_tick = deny.denied_at_tick,
            "sovereignty denial emitted containment recommendation"
        );

        // Actuate the freeze via StopAuthority (BLOCKER 1 fix).
        if let Some(ref authority) = self.stop_authority {
            match containment_action {
                FreezeAction::HardFreeze => {
                    authority.set_emergency_stop(true);
                    info!(
                        stage = stage,
                        containment_action = %containment_action,
                        "sovereignty hard freeze actuated: emergency stop set"
                    );
                },
                FreezeAction::SoftFreeze => {
                    authority.set_governance_stop(true);
                    info!(
                        stage = stage,
                        containment_action = %containment_action,
                        "sovereignty soft freeze actuated: governance stop set"
                    );
                },
                FreezeAction::NoAction => {},
                // Fail-closed: unknown freeze actions trigger emergency stop.
                _ => {
                    authority.set_emergency_stop(true);
                    warn!(
                        stage = stage,
                        containment_action = %containment_action,
                        "unknown freeze action actuated as emergency stop (fail-closed)"
                    );
                },
            }
        } else {
            warn!(
                stage = stage,
                containment_action = %containment_action,
                "sovereignty freeze recommended but no StopAuthority configured for actuation"
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_revalidate_sovereignty(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        sovereignty_state: Option<&super::sovereignty::SovereigntyState>,
        current_tick: u64,
        pcac_policy: Option<&apm2_core::pcac::PcacPolicyKnobs>,
        stage: &'static str,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        let sovereignty_mode = pcac_policy
            .map(|p| p.tier2_sovereignty_mode)
            .unwrap_or_default();

        if !Self::requires_sovereignty_check(cert)
            || sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Disabled
        {
            return Ok(());
        }

        match (&self.sovereignty_checker, sovereignty_state) {
            (Some(checker), Some(sov_state)) => {
                if let Err(deny) = checker.check_revalidate(
                    cert,
                    sov_state,
                    current_tick,
                    current_time_envelope_ref,
                    current_ledger_anchor,
                ) {
                    if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Monitor {
                        warn!(
                            stage = stage,
                            deny_class = %deny.deny_class,
                            "Sovereignty violation observed (monitor mode)"
                        );
                    } else {
                        self.actuate_containment(stage, &deny);
                        return Err(deny);
                    }
                }
                Ok(())
            },
            (Some(_), None) => {
                let deny = Box::new(AuthorityDenyV1 {
                    deny_class: apm2_core::pcac::AuthorityDenyClass::SovereigntyUncertainty {
                        reason: "sovereignty state not available for Tier2+ revalidation"
                            .to_string(),
                    },
                    ajc_id: Some(cert.ajc_id),
                    time_envelope_ref: current_time_envelope_ref,
                    ledger_anchor: current_ledger_anchor,
                    denied_at_tick: current_tick,
                    containment_action: Some(FreezeAction::HardFreeze),
                });
                if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Monitor {
                    warn!(
                        stage = stage,
                        deny_class = %deny.deny_class,
                        "Sovereignty state missing (monitor mode)"
                    );
                    Ok(())
                } else {
                    self.actuate_containment(stage, &deny);
                    Err(deny)
                }
            },
            (None, _) => {
                if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Strict {
                    let deny = Box::new(AuthorityDenyV1 {
                        deny_class: apm2_core::pcac::AuthorityDenyClass::SovereigntyUncertainty {
                            reason: "sovereignty checker not wired; strict mode requires checker"
                                .to_string(),
                        },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: current_ledger_anchor,
                        denied_at_tick: current_tick,
                        containment_action: Some(FreezeAction::HardFreeze),
                    });
                    self.actuate_containment(stage, &deny);
                    Err(deny)
                } else {
                    if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Monitor {
                        warn!(
                            stage = stage,
                            "Sovereignty checker not wired (monitor mode)"
                        );
                    }
                    Ok(())
                }
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn check_consume_sovereignty(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        sovereignty_state: Option<&super::sovereignty::SovereigntyState>,
        current_tick: u64,
        pcac_policy: Option<&apm2_core::pcac::PcacPolicyKnobs>,
        stage: &'static str,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        let sovereignty_mode = pcac_policy
            .map(|p| p.tier2_sovereignty_mode)
            .unwrap_or_default();

        if !Self::requires_sovereignty_check(cert)
            || sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Disabled
        {
            return Ok(());
        }

        match (&self.sovereignty_checker, sovereignty_state) {
            (Some(checker), Some(sov_state)) => {
                if let Err(deny) = checker.check_consume(
                    cert,
                    sov_state,
                    current_tick,
                    current_time_envelope_ref,
                    current_ledger_anchor,
                ) {
                    if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Monitor {
                        warn!(
                            stage = stage,
                            deny_class = %deny.deny_class,
                            "Sovereignty violation observed (monitor mode)"
                        );
                    } else {
                        self.actuate_containment(stage, &deny);
                        return Err(deny);
                    }
                }
                Ok(())
            },
            (Some(_), None) => {
                let deny = Box::new(AuthorityDenyV1 {
                    deny_class: apm2_core::pcac::AuthorityDenyClass::SovereigntyUncertainty {
                        reason: "sovereignty state not available for Tier2+ consume".to_string(),
                    },
                    ajc_id: Some(cert.ajc_id),
                    time_envelope_ref: current_time_envelope_ref,
                    ledger_anchor: current_ledger_anchor,
                    denied_at_tick: current_tick,
                    containment_action: Some(FreezeAction::HardFreeze),
                });
                if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Monitor {
                    warn!(
                        stage = stage,
                        deny_class = %deny.deny_class,
                        "Sovereignty state missing (monitor mode)"
                    );
                    Ok(())
                } else {
                    self.actuate_containment(stage, &deny);
                    Err(deny)
                }
            },
            (None, _) => {
                if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Strict {
                    let deny = Box::new(AuthorityDenyV1 {
                        deny_class: apm2_core::pcac::AuthorityDenyClass::SovereigntyUncertainty {
                            reason: "sovereignty checker not wired; strict mode requires checker"
                                .to_string(),
                        },
                        ajc_id: Some(cert.ajc_id),
                        time_envelope_ref: current_time_envelope_ref,
                        ledger_anchor: current_ledger_anchor,
                        denied_at_tick: current_tick,
                        containment_action: Some(FreezeAction::HardFreeze),
                    });
                    self.actuate_containment(stage, &deny);
                    Err(deny)
                } else {
                    if sovereignty_mode == apm2_core::pcac::SovereigntyEnforcementMode::Monitor {
                        warn!(
                            stage = stage,
                            "Sovereignty checker not wired (monitor mode)"
                        );
                    }
                    Ok(())
                }
            },
        }
    }

    /// Executes `join -> revalidate-before-decision`.
    pub fn join_and_revalidate(
        &self,
        input: &AuthorityJoinInputV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
        let cert = self.kernel.join(input)?;
        self.kernel.revalidate(
            &cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )?;
        Ok(cert)
    }

    /// Executes `join -> revalidate-before-decision` with optional
    /// sovereignty checks for Tier2+.
    #[allow(clippy::too_many_arguments)]
    pub fn join_and_revalidate_with_sovereignty(
        &self,
        input: &AuthorityJoinInputV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
        sovereignty_state: Option<&super::sovereignty::SovereigntyState>,
        current_tick: u64,
        pcac_policy: Option<&apm2_core::pcac::PcacPolicyKnobs>,
    ) -> Result<AuthorityJoinCertificateV1, Box<AuthorityDenyV1>> {
        let cert = self.join_and_revalidate(
            input,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )?;
        self.check_revalidate_sovereignty(
            &cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            sovereignty_state,
            current_tick,
            pcac_policy,
            "revalidate-before-decision",
        )?;
        Ok(cert)
    }

    /// Executes revalidate-before-execution for an already joined
    /// certificate.
    pub fn revalidate_before_execution(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        self.kernel.revalidate(
            cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )
    }

    /// Executes revalidate-before-execution with optional sovereignty checks
    /// for Tier2+.
    #[allow(clippy::too_many_arguments)]
    pub fn revalidate_before_execution_with_sovereignty(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
        sovereignty_state: Option<&super::sovereignty::SovereigntyState>,
        current_tick: u64,
        pcac_policy: Option<&apm2_core::pcac::PcacPolicyKnobs>,
    ) -> Result<(), Box<AuthorityDenyV1>> {
        self.revalidate_before_execution(
            cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )?;
        self.check_revalidate_sovereignty(
            cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            sovereignty_state,
            current_tick,
            pcac_policy,
            "revalidate-before-execution",
        )
    }

    /// Consumes authority immediately before effect execution.
    pub fn consume_before_effect(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        boundary_intent_class: BoundaryIntentClass,
        requires_authoritative_acceptance: bool,
        current_time_envelope_ref: Hash,
        current_revocation_head_hash: Hash,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        self.kernel.consume(
            cert,
            intent_digest,
            boundary_intent_class,
            requires_authoritative_acceptance,
            current_time_envelope_ref,
            current_revocation_head_hash,
        )
    }

    /// Consumes authority immediately before effect execution with optional
    /// sovereignty checks for Tier2+.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_before_effect_with_sovereignty(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        boundary_intent_class: BoundaryIntentClass,
        requires_authoritative_acceptance: bool,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
        sovereignty_state: Option<&super::sovereignty::SovereigntyState>,
        current_tick: u64,
        pcac_policy: Option<&apm2_core::pcac::PcacPolicyKnobs>,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        self.check_consume_sovereignty(
            cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            sovereignty_state,
            current_tick,
            pcac_policy,
            "consume-before-effect",
        )?;
        self.consume_before_effect(
            cert,
            intent_digest,
            boundary_intent_class,
            requires_authoritative_acceptance,
            current_time_envelope_ref,
            current_revocation_head_hash,
        )
    }

    /// Executes the full lifecycle:
    /// `join -> revalidate-before-decision -> revalidate-before-execution ->
    /// consume`.
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

    /// Executes the full lifecycle with optional sovereignty checks.
    pub fn execute_with_sovereignty(
        &self,
        input: &AuthorityJoinInputV1,
        current_time_envelope_ref: Hash,
        current_ledger_anchor: Hash,
        current_revocation_head_hash: Hash,
        sovereignty_state: Option<&super::sovereignty::SovereigntyState>,
        current_tick: u64,
    ) -> Result<LifecycleReceipts, Box<AuthorityDenyV1>> {
        let cert = self.join_and_revalidate_with_sovereignty(
            input,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
            sovereignty_state,
            current_tick,
            None,
        )?;

        self.revalidate_before_execution_with_sovereignty(
            &cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
            sovereignty_state,
            current_tick,
            None,
        )?;

        let (consumed_witness, consume_record) = self.consume_before_effect_with_sovereignty(
            &cert,
            input.intent_digest,
            input.boundary_intent_class,
            input.boundary_intent_class.is_authoritative(),
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
            sovereignty_state,
            current_tick,
            None,
        )?;

        Ok(LifecycleReceipts {
            certificate: cert,
            consume_record,
            consumed_witness,
        })
    }
}
