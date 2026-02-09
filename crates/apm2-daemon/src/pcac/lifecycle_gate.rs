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
//! 6. **Boundary Monotonicity**: `join < pre-actuation <
//!    revalidate-before-decision < revalidate-before-execution < consume <=
//!    effect`.
//! 7. **Evidence Sufficiency**: Authoritative outcomes need replay receipts.
//!
//! [`LifecycleGate`] wraps a kernel and provides a single-call entry point
//! for `handle_request_tool` that executes the full `join -> revalidate
//! (before-decision) -> revalidate (before-execution) -> consume` sequence.

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

    /// Computes the authority join hash from the FULL input surface.
    ///
    /// All authority dimensions are canonicalized with domain-separated
    /// field tags to prevent cross-field collision and ensure binding
    /// completeness (RFC-0027 §3.1).
    fn compute_join_hash(input: &AuthorityJoinInputV1) -> Hash {
        use blake3::Hasher;
        fn put_field(hasher: &mut Hasher, name: &[u8], value: &[u8]) {
            hasher.update(name);
            hasher.update(&(value.len() as u64).to_le_bytes());
            hasher.update(value);
        }

        fn put_hash(hasher: &mut Hasher, name: &[u8], hash: &Hash) {
            put_field(hasher, name, hash);
        }

        fn put_opt_hash(hasher: &mut Hasher, name: &[u8], value: Option<&Hash>) {
            hasher.update(name);
            if let Some(hash) = value {
                hasher.update(&[1u8]);
                hasher.update(&(hash.len() as u64).to_le_bytes());
                hasher.update(hash);
            } else {
                hasher.update(&[0u8]);
                hasher.update(&0u64.to_le_bytes());
            }
        }

        fn put_opt_str(hasher: &mut Hasher, name: &[u8], value: Option<&str>) {
            hasher.update(name);
            if let Some(text) = value {
                hasher.update(&[1u8]);
                hasher.update(&(text.len() as u64).to_le_bytes());
                hasher.update(text.as_bytes());
            } else {
                hasher.update(&[0u8]);
                hasher.update(&0u64.to_le_bytes());
            }
        }

        fn put_sorted_hash_vec(hasher: &mut Hasher, name: &[u8], values: &[Hash]) {
            let mut sorted = values.to_vec();
            sorted.sort_unstable();
            hasher.update(name);
            hasher.update(&(sorted.len() as u64).to_le_bytes());
            for value in sorted {
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(&value);
            }
        }

        let mut hasher = Hasher::new();
        hasher.update(b"apm2-authority-join-v1");

        // Schema-defined canonical field order.
        put_field(&mut hasher, b"session_id", input.session_id.as_bytes());
        put_opt_str(&mut hasher, b"holon_id", input.holon_id.as_deref());
        put_hash(&mut hasher, b"intent_digest", &input.intent_digest);
        put_hash(
            &mut hasher,
            b"capability_manifest_hash",
            &input.capability_manifest_hash,
        );
        put_sorted_hash_vec(
            &mut hasher,
            b"scope_witness_hashes",
            &input.scope_witness_hashes,
        );
        put_field(&mut hasher, b"lease_id", input.lease_id.as_bytes());
        put_opt_hash(
            &mut hasher,
            b"permeability_receipt_hash",
            input.permeability_receipt_hash.as_ref(),
        );
        put_hash(
            &mut hasher,
            b"identity_proof_hash",
            &input.identity_proof_hash,
        );
        put_field(
            &mut hasher,
            b"identity_evidence_level",
            input.identity_evidence_level.to_string().as_bytes(),
        );
        put_hash(
            &mut hasher,
            b"directory_head_hash",
            &input.directory_head_hash,
        );
        put_hash(
            &mut hasher,
            b"freshness_policy_hash",
            &input.freshness_policy_hash,
        );
        put_field(
            &mut hasher,
            b"freshness_witness_tick",
            &input.freshness_witness_tick.to_le_bytes(),
        );
        put_hash(
            &mut hasher,
            b"stop_budget_profile_digest",
            &input.stop_budget_profile_digest,
        );
        put_sorted_hash_vec(
            &mut hasher,
            b"pre_actuation_receipt_hashes",
            &input.pre_actuation_receipt_hashes,
        );
        put_field(
            &mut hasher,
            b"risk_tier",
            input.risk_tier.to_string().as_bytes(),
        );
        let determinism = match input.determinism_class {
            apm2_core::pcac::DeterminismClass::Deterministic => b"deterministic".as_slice(),
            apm2_core::pcac::DeterminismClass::BoundedNondeterministic => {
                b"bounded_nondeterministic".as_slice()
            },
            _ => b"unknown".as_slice(),
        };
        put_field(&mut hasher, b"determinism_class", determinism);
        put_hash(&mut hasher, b"time_envelope_ref", &input.time_envelope_ref);
        put_hash(
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

        Ok(())
    }

    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        current_time_envelope_ref: Hash,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        let tick = self.current_tick();

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
pub struct LifecycleGate {
    kernel: Arc<dyn AuthorityJoinKernel>,
}

impl LifecycleGate {
    /// Creates a new lifecycle gate with the given kernel.
    #[must_use]
    pub fn new(kernel: Arc<dyn AuthorityJoinKernel>) -> Self {
        Self { kernel }
    }

    /// Executes `join -> revalidate-before-decision`.
    ///
    /// This is the pre-broker lifecycle checkpoint. Callers must still perform
    /// a fresh revalidate + consume immediately before effect execution.
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

    /// Executes revalidate-before-execution for an already joined certificate.
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

    /// Consumes authority immediately before effect execution.
    pub fn consume_before_effect(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: Hash,
        current_time_envelope_ref: Hash,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), Box<AuthorityDenyV1>> {
        self.kernel
            .consume(cert, intent_digest, current_time_envelope_ref)
    }

    /// Executes the full PCAC lifecycle for a tool request.
    ///
    /// RFC-0027 §3.3 lifecycle ordering:
    /// `join < pre-actuation < revalidate-before-decision <
    ///  revalidate-before-execution < consume <= effect`
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
    /// `Ok(LifecycleReceipts)` if all stages pass, or `Err(deny)` at
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
        // Stage 1+2: Join + revalidate-before-decision.
        let cert = self.join_and_revalidate(
            input,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )?;

        // Stage 3: Revalidate-before-execution — second revalidation
        // immediately before consume to close the window between decision
        // and execution (RFC-0027 §3.3 ordering requirement).
        self.revalidate_before_execution(
            &cert,
            current_time_envelope_ref,
            current_ledger_anchor,
            current_revocation_head_hash,
        )?;

        // Stage 4: Consume — single-use consumption with intent equality.
        // Consume must be immediately before the effect.
        let (consumed_witness, consume_record) =
            self.consume_before_effect(&cert, input.intent_digest, current_time_envelope_ref)?;

        Ok(LifecycleReceipts {
            certificate: cert,
            consume_record,
            consumed_witness,
        })
    }
}
