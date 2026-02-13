//! FAC Broker service: local authority for actuation tokens and economics
//! envelopes.
//!
//! Implements TCK-00510: a local broker authority responsible for FAC actuation
//! authorization and economics/time authority.
//!
//! The broker is the **sole** issuer of:
//! - RFC-0028 `ChannelContextToken` bound to `job_spec_digest` + `lease_id`
//! - RFC-0029 `TimeAuthorityEnvelopeV1` for `boundary_id` + evaluation window
//! - TP-EIO29-002 freshness horizon refs and revocation frontier snapshots
//! - TP-EIO29-003 convergence horizon refs and convergence receipts
//!
//! The broker publishes its verifying key so workers can verify envelope
//! signatures with a real verifier (no `NoOpVerifier` in default mode).
//!
//! # Security Invariants
//!
//! - [INV-BRK-001] The broker signing key is never exposed outside the broker
//!   process boundary. Only the `VerifyingKey` is published.
//! - [INV-BRK-002] All issued tokens and envelopes are cryptographically signed
//!   with the broker's Ed25519 key.
//! - [INV-BRK-003] Fail-closed: missing, stale, or ambiguous authority state
//!   results in denial.
//! - [INV-BRK-004] All in-memory collections are bounded by hard `MAX_*` caps.
//! - [INV-BRK-005] Broker state persistence uses atomic write (temp+rename).
//! - [INV-BRK-006] Horizon hashes are replay-stable (non-zero) in local-only
//!   mode.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::channel::{
    ChannelBoundaryCheck, ChannelContextTokenError, ChannelSource, DeclassificationIntentScope,
    derive_channel_source_witness, issue_channel_context_token,
};
use crate::crypto::{Signer, VerifyingKey};
use crate::economics::queue_admission::{
    ConvergenceHorizonRef, ConvergenceReceipt, EnvelopeSignature, FreshnessHorizonRef,
    HtfEvaluationWindow, RevocationFrontierSnapshot, TimeAuthorityEnvelopeV1,
    envelope_signature_canonical_bytes,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of admitted policy digests tracked by the broker.
pub const MAX_ADMITTED_POLICY_DIGESTS: usize = 256;

/// Maximum number of convergence receipts the broker will serve.
pub const MAX_CONVERGENCE_RECEIPTS: usize = 64;

/// Maximum length for boundary identifiers.
pub const MAX_BOUNDARY_ID_LENGTH: usize = 256;

/// Maximum length for authority clock identifiers.
pub const MAX_AUTHORITY_CLOCK_LENGTH: usize = 256;

/// Maximum size in bytes for the persisted broker state file.
///
/// Rejects state files larger than 1 MiB before JSON parsing to prevent
/// OOM via a crafted state file with unbounded `Vec` payloads (RSK-1601).
pub const MAX_BROKER_STATE_FILE_SIZE: usize = 1_048_576;

/// Maximum TTL for time authority envelopes (in ticks).
pub const MAX_ENVELOPE_TTL_TICKS: u64 = 10_000;

/// Default TTL for time authority envelopes (in ticks).
pub const DEFAULT_ENVELOPE_TTL_TICKS: u64 = 1_000;

/// Domain separator for broker envelope content hashing.
const BROKER_ENVELOPE_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.envelope.v1";

/// Domain separator for broker horizon hashing.
const BROKER_HORIZON_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.horizon.v1";

/// Domain separator for broker frontier hashing.
const BROKER_FRONTIER_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.frontier.v1";

/// Domain separator for broker convergence hashing.
const BROKER_CONVERGENCE_HASH_DOMAIN: &[u8] = b"apm2.fac_broker.convergence.v1";

/// Schema identifier for persisted broker state.
const BROKER_STATE_SCHEMA_ID: &str = "apm2.fac_broker_state.v1";

/// Schema version for persisted broker state.
const BROKER_STATE_SCHEMA_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Hash type alias
// ---------------------------------------------------------------------------

/// 32-byte hash used throughout the broker.
pub type Hash = [u8; 32];

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by the FAC Broker service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// Boundary identifier is empty or exceeds maximum length.
    #[error("invalid boundary_id: {detail}")]
    InvalidBoundaryId {
        /// Detail about the validation failure.
        detail: String,
    },

    /// Authority clock identifier is empty or exceeds maximum length.
    #[error("invalid authority_clock: {detail}")]
    InvalidAuthorityClock {
        /// Detail about the validation failure.
        detail: String,
    },

    /// The requested TTL exceeds the broker maximum.
    #[error("ttl_ticks {requested} exceeds maximum {max}")]
    TtlExceedsMaximum {
        /// Requested TTL.
        requested: u64,
        /// Maximum allowed TTL.
        max: u64,
    },

    /// Tick range is inverted (start > end).
    #[error("inverted tick range: tick_start={tick_start} > tick_end={tick_end}")]
    InvertedTickRange {
        /// Start tick.
        tick_start: u64,
        /// End tick.
        tick_end: u64,
    },

    /// The requested TTL must be greater than zero.
    #[error("ttl_ticks must be greater than zero")]
    TtlMustBeNonZero,

    /// Channel context token issuance failed.
    #[error("channel token error: {0}")]
    ChannelToken(#[from] ChannelContextTokenError),

    /// Admitted policy digest store is at capacity.
    #[error("admitted policy digest store at capacity ({max})")]
    PolicyDigestStoreAtCapacity {
        /// Maximum capacity.
        max: usize,
    },

    /// Convergence receipt store is at capacity.
    #[error("convergence receipt store at capacity ({max})")]
    ConvergenceReceiptStoreAtCapacity {
        /// Maximum capacity.
        max: usize,
    },

    /// Persistence operation failed.
    #[error("persistence error: {detail}")]
    Persistence {
        /// Detail about the persistence failure.
        detail: String,
    },

    /// Deserialization of broker state failed.
    #[error("deserialization error: {detail}")]
    Deserialization {
        /// Detail about the deserialization failure.
        detail: String,
    },

    /// Serialized state file exceeds the maximum allowed size.
    #[error("state file size {size} exceeds maximum {max}")]
    StateTooLarge {
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// Job spec digest is zero (not bound).
    #[error("job_spec_digest is zero (not bound to a job)")]
    ZeroJobSpecDigest,

    /// Lease ID is empty.
    #[error("lease_id is empty")]
    EmptyLeaseId,

    /// Request ID is empty.
    #[error("request_id is empty")]
    EmptyRequestId,

    /// Requested policy digest is not admitted in broker state.
    #[error("policy digest is not admitted: {detail}")]
    UnadmittedPolicyDigest {
        /// Detail about the admission failure.
        detail: String,
    },

    /// Policy digest cannot be zero.
    #[error("policy digest cannot be zero")]
    ZeroPolicyDigest,

    /// Convergence receipt hash cannot be zero.
    #[error("convergence receipt contains zero hash: {field}")]
    ZeroConvergenceReceiptHash {
        /// Which field was zero.
        field: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Broker state (persisted)
// ---------------------------------------------------------------------------

/// Persisted broker state. Serialized to JSON for durable storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerState {
    /// Schema identifier for version checking.
    pub schema_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Monotonic tick counter used for envelope issuance.
    pub current_tick: u64,
    /// Tick end used for the active freshness horizon.
    pub freshness_horizon_tick_end: u64,
    /// Currently admitted policy digest set (bounded).
    pub admitted_policy_digests: Vec<Hash>,
    /// Freshness horizon hash for TP-EIO29-002.
    pub freshness_horizon_hash: Hash,
    /// Revocation frontier hash for TP-EIO29-002.
    pub revocation_frontier_hash: Hash,
    /// Convergence horizon hash for TP-EIO29-003.
    pub convergence_horizon_hash: Hash,
    /// Convergence receipts for TP-EIO29-003 (bounded).
    pub convergence_receipts: Vec<ConvergenceReceipt>,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            schema_id: BROKER_STATE_SCHEMA_ID.to_string(),
            schema_version: BROKER_STATE_SCHEMA_VERSION.to_string(),
            current_tick: 1,
            freshness_horizon_tick_end: 1,
            admitted_policy_digests: Vec::new(),
            freshness_horizon_hash: compute_initial_horizon_hash(),
            revocation_frontier_hash: compute_initial_frontier_hash(),
            convergence_horizon_hash: compute_initial_convergence_hash(),
            convergence_receipts: Vec::new(),
        }
    }
}

impl BrokerState {
    /// Validate state after deserialization.
    fn validate(&self) -> Result<(), BrokerError> {
        if self.schema_id != BROKER_STATE_SCHEMA_ID {
            return Err(BrokerError::Deserialization {
                detail: format!(
                    "schema_id mismatch: expected {BROKER_STATE_SCHEMA_ID}, got {}",
                    self.schema_id
                ),
            });
        }
        if self.schema_version != BROKER_STATE_SCHEMA_VERSION {
            return Err(BrokerError::Deserialization {
                detail: format!(
                    "schema_version mismatch: expected {BROKER_STATE_SCHEMA_VERSION}, got {}",
                    self.schema_version
                ),
            });
        }
        if self.current_tick == 0 {
            return Err(BrokerError::Deserialization {
                detail: "current_tick must be non-zero".to_string(),
            });
        }
        if self.freshness_horizon_tick_end == 0 {
            return Err(BrokerError::Deserialization {
                detail: "freshness_horizon_tick_end must be non-zero".to_string(),
            });
        }
        if self.admitted_policy_digests.len() > MAX_ADMITTED_POLICY_DIGESTS {
            return Err(BrokerError::Deserialization {
                detail: format!(
                    "admitted_policy_digests count {} exceeds max {MAX_ADMITTED_POLICY_DIGESTS}",
                    self.admitted_policy_digests.len()
                ),
            });
        }
        if is_zero_hash(&self.freshness_horizon_hash) {
            return Err(BrokerError::Deserialization {
                detail: "freshness_horizon_hash must be non-zero".to_string(),
            });
        }
        if is_zero_hash(&self.revocation_frontier_hash) {
            return Err(BrokerError::Deserialization {
                detail: "revocation_frontier_hash must be non-zero".to_string(),
            });
        }
        if is_zero_hash(&self.convergence_horizon_hash) {
            return Err(BrokerError::Deserialization {
                detail: "convergence_horizon_hash must be non-zero".to_string(),
            });
        }
        if self.admitted_policy_digests.iter().any(is_zero_hash) {
            return Err(BrokerError::Deserialization {
                detail: "admitted_policy_digests cannot include zero digests".to_string(),
            });
        }
        for receipt in &self.convergence_receipts {
            if is_zero_hash(&receipt.authority_set_hash) {
                return Err(BrokerError::Deserialization {
                    detail: "convergence_receipts includes zero authority_set_hash".to_string(),
                });
            }
            if is_zero_hash(&receipt.proof_hash) {
                return Err(BrokerError::Deserialization {
                    detail: "convergence_receipts includes zero proof_hash".to_string(),
                });
            }
        }
        if self.convergence_receipts.len() > MAX_CONVERGENCE_RECEIPTS {
            return Err(BrokerError::Deserialization {
                detail: format!(
                    "convergence_receipts count {} exceeds max {MAX_CONVERGENCE_RECEIPTS}",
                    self.convergence_receipts.len()
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deterministic initial hash computation
// ---------------------------------------------------------------------------

fn compute_initial_horizon_hash() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_HORIZON_HASH_DOMAIN);
    hasher.update(b"initial");
    *hasher.finalize().as_bytes()
}

fn compute_initial_frontier_hash() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_FRONTIER_HASH_DOMAIN);
    hasher.update(b"initial");
    *hasher.finalize().as_bytes()
}

fn compute_initial_convergence_hash() -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_CONVERGENCE_HASH_DOMAIN);
    hasher.update(b"initial");
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// FacBroker
// ---------------------------------------------------------------------------

/// FAC Broker authority service.
///
/// The broker is the sole local authority for issuing actuation tokens
/// (RFC-0028 `ChannelContextToken`) and economics/time authority envelopes
/// (RFC-0029 `TimeAuthorityEnvelopeV1`).
///
/// # Thread Safety
///
/// `FacBroker` is **not** internally synchronized. Callers must hold
/// appropriate locks (e.g., `Mutex`) when accessing from multiple threads.
/// This follows the pattern of `QueueSchedulerState` and `AntiEntropyBudget`
/// in the economics module.
pub struct FacBroker {
    /// Ed25519 signing key owned exclusively by the broker.
    signer: Signer,
    /// Mutable broker state (tick counter, admitted digests, horizons).
    state: BrokerState,
}

impl Default for FacBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl FacBroker {
    /// Creates a new broker with a freshly generated signing key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            signer: Signer::generate(),
            state: BrokerState::default(),
        }
    }

    /// Creates a broker from an existing signer and state.
    ///
    /// Used when loading persisted state from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the loaded state fails validation.
    pub fn from_signer_and_state(signer: Signer, state: BrokerState) -> Result<Self, BrokerError> {
        state.validate()?;
        Ok(Self { signer, state })
    }

    /// Returns the broker's verifying (public) key.
    ///
    /// Workers use this key to verify envelope signatures with a real
    /// verifier instead of `NoOpVerifier`.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    /// Returns the current broker tick.
    #[must_use]
    pub const fn current_tick(&self) -> u64 {
        self.state.current_tick
    }

    /// Returns a reference to the current broker state for persistence.
    #[must_use]
    pub const fn state(&self) -> &BrokerState {
        &self.state
    }

    /// Advances the broker tick by 1 (monotonic).
    ///
    /// Returns the new tick value.
    #[must_use]
    pub const fn advance_tick(&mut self) -> u64 {
        self.state.current_tick = self.state.current_tick.saturating_add(1);
        self.state.current_tick
    }

    // -----------------------------------------------------------------------
    // RFC-0028: ChannelContextToken issuance
    // -----------------------------------------------------------------------

    /// Issues an RFC-0028 `ChannelContextToken` bound to `job_spec_digest`
    /// and `lease_id`.
    ///
    /// The token encodes a fully-populated `ChannelBoundaryCheck` with
    /// `broker_verified = true` and all verification flags set, signed by
    /// the broker's Ed25519 key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `job_spec_digest` is all-zero (not bound to a job)
    /// - `lease_id` is empty
    /// - `request_id` is empty
    /// - Token serialization or signing fails
    pub fn issue_channel_context_token(
        &self,
        job_spec_digest: &Hash,
        lease_id: &str,
        request_id: &str,
    ) -> Result<String, BrokerError> {
        // Validate inputs (fail-closed)
        if bool::from(job_spec_digest.ct_eq(&[0u8; 32])) {
            return Err(BrokerError::ZeroJobSpecDigest);
        }
        if lease_id.is_empty() {
            return Err(BrokerError::EmptyLeaseId);
        }
        if request_id.is_empty() {
            return Err(BrokerError::EmptyRequestId);
        }
        let Some(policy_root_digest) = self.find_admitted_policy_digest(job_spec_digest) else {
            return Err(BrokerError::UnadmittedPolicyDigest {
                detail: "requested job_spec_digest has not been admitted".to_string(),
            });
        };

        let policy_ledger_verified = true;
        let canonicalizer_tuple_digest = compute_canonicalizer_tuple_digest(&policy_root_digest);
        let disclosure_policy_digest = compute_disclosure_policy_digest(&policy_root_digest);

        // Build a fully-verified boundary check (broker is the authority).
        // The job_spec_digest is embedded in the policy binding to bind
        // the token to the specific job.
        let check = ChannelBoundaryCheck {
            source: ChannelSource::TypedToolIntent,
            channel_source_witness: Some(derive_channel_source_witness(
                ChannelSource::TypedToolIntent,
            )),
            broker_verified: true,
            capability_verified: true,
            context_firewall_verified: true,
            policy_ledger_verified,
            taint_allow: true,
            classification_allow: true,
            declass_receipt_valid: true,
            declassification_intent: DeclassificationIntentScope::None,
            redundancy_declassification_receipt: None,
            boundary_flow_policy_binding: Some(crate::channel::BoundaryFlowPolicyBinding {
                policy_digest: *job_spec_digest,
                admitted_policy_root_digest: policy_root_digest,
                canonicalizer_tuple_digest,
                admitted_canonicalizer_tuple_digest: canonicalizer_tuple_digest,
            }),
            leakage_budget_receipt: Some(crate::channel::LeakageBudgetReceipt {
                leakage_bits: 0,
                budget_bits: 8,
                estimator_family:
                    crate::channel::LeakageEstimatorFamily::MutualInformationUpperBound,
                confidence_bps: 10_000,
                confidence_label: "broker-deterministic".to_string(),
            }),
            timing_channel_budget: Some(crate::channel::TimingChannelBudget {
                release_bucket_ticks: 10,
                observed_variance_ticks: 0,
                budget_ticks: 10,
            }),
            disclosure_policy_binding: Some(crate::channel::DisclosurePolicyBinding {
                required_for_effect: true,
                state_valid: policy_ledger_verified,
                active_mode: crate::disclosure::DisclosurePolicyMode::TradeSecretOnly,
                expected_mode: crate::disclosure::DisclosurePolicyMode::TradeSecretOnly,
                attempted_channel: crate::disclosure::DisclosureChannelClass::Internal,
                policy_snapshot_digest: disclosure_policy_digest,
                admitted_policy_epoch_root_digest: disclosure_policy_digest,
                policy_epoch: 1,
                phase_id: "broker_default".to_string(),
                state_reason: "policy_root_admitted".to_string(),
            }),
            leakage_budget_policy_max_bits: Some(8),
            declared_leakage_budget_bits: None,
            timing_budget_policy_max_ticks: Some(10),
            declared_timing_budget_ticks: None,
        };

        Ok(issue_channel_context_token(
            &check,
            lease_id,
            request_id,
            current_time_secs(),
            &self.signer,
        )?)
    }

    // -----------------------------------------------------------------------
    // RFC-0029: TimeAuthorityEnvelopeV1 issuance
    // -----------------------------------------------------------------------

    /// Issues an RFC-0029 `TimeAuthorityEnvelopeV1` for a given boundary
    /// and evaluation window.
    ///
    /// The envelope is signed by the broker's Ed25519 key with
    /// `deny_on_unknown = true` (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `boundary_id` is empty or exceeds `MAX_BOUNDARY_ID_LENGTH`
    /// - `authority_clock` is empty or exceeds `MAX_AUTHORITY_CLOCK_LENGTH`
    /// - `tick_start > tick_end` (inverted range)
    /// - `ttl_ticks` exceeds `MAX_ENVELOPE_TTL_TICKS`
    pub fn issue_time_authority_envelope(
        &mut self,
        boundary_id: &str,
        authority_clock: &str,
        tick_start: u64,
        tick_end: u64,
        ttl_ticks: u64,
    ) -> Result<TimeAuthorityEnvelopeV1, BrokerError> {
        // Validate inputs (fail-closed)
        validate_boundary_id(boundary_id)?;
        validate_authority_clock(authority_clock)?;

        if tick_start > tick_end {
            return Err(BrokerError::InvertedTickRange {
                tick_start,
                tick_end,
            });
        }
        if ttl_ticks > MAX_ENVELOPE_TTL_TICKS {
            return Err(BrokerError::TtlExceedsMaximum {
                requested: ttl_ticks,
                max: MAX_ENVELOPE_TTL_TICKS,
            });
        }
        if ttl_ticks == 0 {
            return Err(BrokerError::TtlMustBeNonZero);
        }

        // Compute content hash (domain-separated)
        let content_hash = compute_envelope_content_hash(
            boundary_id,
            authority_clock,
            tick_start,
            tick_end,
            ttl_ticks,
            self.state.current_tick,
        );

        // Sign the canonical bytes consumed by TP-EIO29 envelope validation.
        let mut envelope = TimeAuthorityEnvelopeV1 {
            boundary_id: boundary_id.to_string(),
            authority_clock: authority_clock.to_string(),
            tick_start,
            tick_end,
            ttl_ticks,
            deny_on_unknown: true,
            signature_set: Vec::new(),
            content_hash,
        };
        let canonical_bytes = envelope_signature_canonical_bytes(&envelope);
        let signature_bytes = self.signer.sign(&canonical_bytes);
        let envelope_signature = EnvelopeSignature {
            signer_id: self.signer.verifying_key().to_bytes(),
            signature: signature_bytes.to_bytes(),
        };

        // Advance tick for monotonicity
        let _ = self.advance_tick();

        envelope.signature_set.push(envelope_signature);
        Ok(envelope)
    }

    /// Issues a `TimeAuthorityEnvelopeV1` with default TTL.
    ///
    /// Convenience wrapper around [`Self::issue_time_authority_envelope`] using
    /// `DEFAULT_ENVELOPE_TTL_TICKS`.
    ///
    /// # Errors
    ///
    /// Same as [`Self::issue_time_authority_envelope`].
    pub fn issue_time_authority_envelope_default_ttl(
        &mut self,
        boundary_id: &str,
        authority_clock: &str,
        tick_start: u64,
        tick_end: u64,
    ) -> Result<TimeAuthorityEnvelopeV1, BrokerError> {
        self.issue_time_authority_envelope(
            boundary_id,
            authority_clock,
            tick_start,
            tick_end,
            DEFAULT_ENVELOPE_TTL_TICKS,
        )
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-002: Freshness horizon and revocation frontier
    // -----------------------------------------------------------------------

    /// Returns the current freshness horizon reference (TP-EIO29-002).
    ///
    /// The horizon is resolved and has a non-zero, replay-stable hash.
    #[must_use]
    pub const fn freshness_horizon(&self) -> FreshnessHorizonRef {
        FreshnessHorizonRef {
            horizon_hash: self.state.freshness_horizon_hash,
            tick_end: self.state.freshness_horizon_tick_end,
            resolved: true,
        }
    }

    /// Returns the current revocation frontier snapshot (TP-EIO29-002).
    ///
    /// The frontier is current with a non-zero, replay-stable hash.
    #[must_use]
    pub const fn revocation_frontier(&self) -> RevocationFrontierSnapshot {
        RevocationFrontierSnapshot {
            frontier_hash: self.state.revocation_frontier_hash,
            current: true,
        }
    }

    /// Advances the freshness horizon to a new tick, recomputing the hash.
    pub fn advance_freshness_horizon(&mut self, new_tick_end: u64) {
        let new_tick_end = new_tick_end.max(1);
        if new_tick_end <= self.state.freshness_horizon_tick_end {
            return;
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(BROKER_HORIZON_HASH_DOMAIN);
        hasher.update(&new_tick_end.to_le_bytes());
        hasher.update(&self.state.freshness_horizon_hash);
        self.state.freshness_horizon_tick_end = new_tick_end;
        self.state.freshness_horizon_hash = *hasher.finalize().as_bytes();
    }

    /// Advances the revocation frontier, recomputing the hash.
    pub fn advance_revocation_frontier(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(BROKER_FRONTIER_HASH_DOMAIN);
        hasher.update(&self.state.current_tick.to_le_bytes());
        hasher.update(&self.state.revocation_frontier_hash);
        self.state.revocation_frontier_hash = *hasher.finalize().as_bytes();
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-003: Convergence horizon and convergence receipts
    // -----------------------------------------------------------------------

    /// Returns the current convergence horizon reference (TP-EIO29-003).
    ///
    /// The horizon is resolved with a non-zero, replay-stable hash.
    #[must_use]
    pub const fn convergence_horizon(&self) -> ConvergenceHorizonRef {
        ConvergenceHorizonRef {
            horizon_hash: self.state.convergence_horizon_hash,
            resolved: true,
        }
    }

    /// Returns all current convergence receipts (TP-EIO29-003).
    ///
    /// In local-only mode, each receipt has a non-zero proof hash and
    /// `converged = true`.
    #[must_use]
    pub fn convergence_receipts(&self) -> &[ConvergenceReceipt] {
        &self.state.convergence_receipts
    }

    /// Adds a convergence receipt for a required authority set.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt store is at capacity.
    pub fn add_convergence_receipt(
        &mut self,
        authority_set_hash: Hash,
        proof_hash: Hash,
    ) -> Result<(), BrokerError> {
        if is_zero_hash(&authority_set_hash) {
            return Err(BrokerError::ZeroConvergenceReceiptHash {
                field: "authority_set_hash",
            });
        }
        if is_zero_hash(&proof_hash) {
            return Err(BrokerError::ZeroConvergenceReceiptHash {
                field: "proof_hash",
            });
        }
        if self.state.convergence_receipts.len() >= MAX_CONVERGENCE_RECEIPTS {
            return Err(BrokerError::ConvergenceReceiptStoreAtCapacity {
                max: MAX_CONVERGENCE_RECEIPTS,
            });
        }

        // Advance convergence horizon hash (chain)
        let mut hasher = blake3::Hasher::new();
        hasher.update(BROKER_CONVERGENCE_HASH_DOMAIN);
        hasher.update(&authority_set_hash);
        hasher.update(&proof_hash);
        hasher.update(&self.state.convergence_horizon_hash);
        self.state.convergence_horizon_hash = *hasher.finalize().as_bytes();

        self.state.convergence_receipts.push(ConvergenceReceipt {
            authority_set_hash,
            proof_hash,
            converged: true,
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Policy digest admission
    // -----------------------------------------------------------------------

    /// Admits a policy digest into the broker's tracked set.
    ///
    /// # Errors
    ///
    /// Returns an error if the digest store is at capacity.
    pub fn admit_policy_digest(&mut self, digest: Hash) -> Result<(), BrokerError> {
        if is_zero_hash(&digest) {
            return Err(BrokerError::ZeroPolicyDigest);
        }
        // Constant-time duplicate scan: examine ALL entries regardless of match
        // position to preserve INV-PC-001 timing invariant.
        let mut found = 0u8;
        for existing in &self.state.admitted_policy_digests {
            found |= u8::from(bool::from(existing.ct_eq(&digest)));
        }
        if found != 0 {
            return Ok(());
        }
        if self.state.admitted_policy_digests.len() >= MAX_ADMITTED_POLICY_DIGESTS {
            return Err(BrokerError::PolicyDigestStoreAtCapacity {
                max: MAX_ADMITTED_POLICY_DIGESTS,
            });
        }
        self.state.admitted_policy_digests.push(digest);
        Ok(())
    }

    /// Checks whether a policy digest is admitted.
    #[must_use]
    pub fn is_policy_digest_admitted(&self, digest: &Hash) -> bool {
        // Use non-short-circuiting fold for constant-time behavior.
        let mut found = 0u8;
        for existing in &self.state.admitted_policy_digests {
            found |= u8::from(bool::from(existing.ct_eq(digest)));
        }
        found != 0
    }

    /// Finds the exact admitted policy digest using constant-time scan
    /// (INV-PC-001: no short-circuit on match position).
    #[must_use]
    fn find_admitted_policy_digest(&self, digest: &Hash) -> Option<Hash> {
        let mut found = 0u8;
        for existing in &self.state.admitted_policy_digests {
            found |= u8::from(bool::from(existing.ct_eq(digest)));
        }
        if found != 0 { Some(*digest) } else { None }
    }

    // -----------------------------------------------------------------------
    // Evaluation window construction
    // -----------------------------------------------------------------------

    /// Constructs an `HtfEvaluationWindow` for the current broker state.
    ///
    /// # Errors
    ///
    /// Returns an error if inputs are invalid.
    pub fn build_evaluation_window(
        &self,
        boundary_id: &str,
        authority_clock: &str,
        tick_start: u64,
        tick_end: u64,
    ) -> Result<HtfEvaluationWindow, BrokerError> {
        validate_boundary_id(boundary_id)?;
        validate_authority_clock(authority_clock)?;

        if tick_start > tick_end {
            return Err(BrokerError::InvertedTickRange {
                tick_start,
                tick_end,
            });
        }

        Ok(HtfEvaluationWindow {
            boundary_id: boundary_id.to_string(),
            authority_clock: authority_clock.to_string(),
            tick_start,
            tick_end,
        })
    }

    // -----------------------------------------------------------------------
    // Health monitoring (TCK-00585)
    // -----------------------------------------------------------------------

    /// Performs a self-health check validating TP001/TP002/TP003 invariants
    /// against the broker's current state.
    ///
    /// The caller supplies:
    /// - `envelope`: a recently issued `TimeAuthorityEnvelopeV1` (or `None` if
    ///   the broker has not yet issued one)
    /// - `eval_window`: the evaluation window to check the envelope against
    /// - `required_authority_sets`: authority set hashes that must have
    ///   convergence receipts
    /// - `checker`: mutable reference to a
    ///   [`super::broker_health::BrokerHealthChecker`] that accumulates history
    ///
    /// Returns a signed [`super::broker_health::HealthReceiptV1`] capturing the
    /// aggregate health status.
    ///
    /// # Errors
    ///
    /// Returns [`super::broker_health::BrokerHealthError`] if input bounds
    /// are violated (e.g., too many required authority sets).
    pub fn check_health(
        &self,
        envelope: Option<&TimeAuthorityEnvelopeV1>,
        eval_window: &HtfEvaluationWindow,
        required_authority_sets: &[Hash],
        checker: &mut super::broker_health::BrokerHealthChecker,
    ) -> Result<super::broker_health::HealthReceiptV1, super::broker_health::BrokerHealthError>
    {
        let verifier = BrokerSignatureVerifier::new(self.verifying_key());
        let freshness = self.freshness_horizon();
        let frontier = self.revocation_frontier();
        let convergence = self.convergence_horizon();

        let input = super::broker_health::HealthCheckInput {
            envelope,
            eval_window,
            verifier: Some(&verifier),
            freshness_horizon: Some(&freshness),
            revocation_frontier: Some(&frontier),
            convergence_horizon: Some(&convergence),
            convergence_receipts: self.convergence_receipts(),
            required_authority_sets,
        };

        checker.check_health(&input, self.current_tick(), &self.signer)
    }

    // -----------------------------------------------------------------------
    // State serialization (for persistence)
    // -----------------------------------------------------------------------

    /// Serializes the broker state to canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn serialize_state(&self) -> Result<Vec<u8>, BrokerError> {
        serde_json::to_vec_pretty(&self.state).map_err(|e| BrokerError::Persistence {
            detail: e.to_string(),
        })
    }

    /// Deserializes broker state from JSON bytes.
    ///
    /// Enforces a strict size limit ([`MAX_BROKER_STATE_FILE_SIZE`]) on the
    /// input **before** passing to the JSON parser. This prevents
    /// memory-exhaustion attacks from a crafted state file containing
    /// unbounded `Vec` payloads (RSK-1601).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `bytes.len()` exceeds `MAX_BROKER_STATE_FILE_SIZE`
    /// - deserialization fails
    /// - post-deserialization validation fails
    pub fn deserialize_state(bytes: &[u8]) -> Result<BrokerState, BrokerError> {
        if bytes.len() > MAX_BROKER_STATE_FILE_SIZE {
            return Err(BrokerError::StateTooLarge {
                size: bytes.len(),
                max: MAX_BROKER_STATE_FILE_SIZE,
            });
        }
        let state: BrokerState =
            serde_json::from_slice(bytes).map_err(|e| BrokerError::Deserialization {
                detail: e.to_string(),
            })?;
        state.validate()?;
        Ok(state)
    }
}

// ---------------------------------------------------------------------------
// Broker-specific SignatureVerifier implementation
// ---------------------------------------------------------------------------

/// A signature verifier backed by the broker's public key.
///
/// Workers obtain this from the broker to verify `TimeAuthorityEnvelopeV1`
/// signatures with real cryptographic verification instead of `NoOpVerifier`.
pub struct BrokerSignatureVerifier {
    verifying_key: VerifyingKey,
}

impl BrokerSignatureVerifier {
    /// Creates a new verifier from the broker's public key.
    #[must_use]
    pub const fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Verifies a broker-signed envelope signature.
    ///
    /// Convenience method that checks the signer matches the broker key
    /// and the Ed25519 signature is valid over the provided message bytes.
    #[must_use]
    pub fn verify_broker_signature(
        &self,
        message: &[u8],
        signer_id: &Hash,
        signature: &[u8; 64],
    ) -> bool {
        use crate::economics::queue_admission::SignatureVerifier;
        self.verify(signer_id, message, signature).is_ok()
    }
}

impl crate::economics::queue_admission::SignatureVerifier for BrokerSignatureVerifier {
    fn verify(
        &self,
        signer_id: &Hash,
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), &'static str> {
        // Verify the signer matches the broker's public key (constant-time)
        if !bool::from(signer_id.ct_eq(&self.verifying_key.to_bytes())) {
            return Err("signer_id_mismatch");
        }

        // Parse and verify the signature
        let vk = VerifyingKey::from_bytes(signer_id).map_err(|_| "invalid_signer_public_key")?;
        let sig = crate::crypto::parse_signature(signature).map_err(|_| "malformed_signature")?;
        crate::crypto::verify_signature(&vk, message, &sig)
            .map_err(|_| "signature_verification_failed")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_boundary_id(boundary_id: &str) -> Result<(), BrokerError> {
    if boundary_id.is_empty() {
        return Err(BrokerError::InvalidBoundaryId {
            detail: "boundary_id is empty".to_string(),
        });
    }
    if boundary_id.len() > MAX_BOUNDARY_ID_LENGTH {
        return Err(BrokerError::InvalidBoundaryId {
            detail: format!(
                "boundary_id length {} exceeds max {MAX_BOUNDARY_ID_LENGTH}",
                boundary_id.len()
            ),
        });
    }
    Ok(())
}

fn validate_authority_clock(authority_clock: &str) -> Result<(), BrokerError> {
    if authority_clock.is_empty() {
        return Err(BrokerError::InvalidAuthorityClock {
            detail: "authority_clock is empty".to_string(),
        });
    }
    if authority_clock.len() > MAX_AUTHORITY_CLOCK_LENGTH {
        return Err(BrokerError::InvalidAuthorityClock {
            detail: format!(
                "authority_clock length {} exceeds max {MAX_AUTHORITY_CLOCK_LENGTH}",
                authority_clock.len()
            ),
        });
    }
    Ok(())
}

fn compute_envelope_content_hash(
    boundary_id: &str,
    authority_clock: &str,
    tick_start: u64,
    tick_end: u64,
    ttl_ticks: u64,
    broker_tick: u64,
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BROKER_ENVELOPE_HASH_DOMAIN);
    // Length-prefix framing for variable fields.
    // Lengths are bounded by MAX_BOUNDARY_ID_LENGTH and MAX_AUTHORITY_CLOCK_LENGTH
    // (both 256), so truncation cannot occur.
    #[allow(clippy::cast_possible_truncation)]
    let boundary_len = boundary_id.len() as u32;
    hasher.update(&boundary_len.to_le_bytes());
    hasher.update(boundary_id.as_bytes());
    #[allow(clippy::cast_possible_truncation)]
    let clock_len = authority_clock.len() as u32;
    hasher.update(&clock_len.to_le_bytes());
    hasher.update(authority_clock.as_bytes());
    hasher.update(&tick_start.to_le_bytes());
    hasher.update(&tick_end.to_le_bytes());
    hasher.update(&ttl_ticks.to_le_bytes());
    hasher.update(&broker_tick.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[allow(clippy::disallowed_methods)]
fn current_time_secs() -> u64 {
    // CTR-2501 deviation: uses wall-clock `SystemTime::now()` instead of
    // monotonic `Instant` or HTF tick. This is intentional — FAC token
    // minting and expiry policy are anchored to trusted process wall time
    // because `ChannelContextToken` encodes a Unix-epoch `issued_at`
    // timestamp that recipients compare against their own wall clock for
    // expiry checks. Adding an HTF dependency in broker-local issuance
    // logic is out of scope (see TCK-00594 scope.out_of_scope).
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_zero_hash(hash: &Hash) -> bool {
    bool::from(hash.ct_eq(&[0u8; 32]))
}

fn compute_canonicalizer_tuple_digest(job_spec_digest: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.fac_broker.canonicalizer.v1");
    hasher.update(job_spec_digest);
    *hasher.finalize().as_bytes()
}

fn compute_disclosure_policy_digest(job_spec_digest: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.fac_broker.disclosure_policy_digest.v1");
    hasher.update(job_spec_digest);
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{decode_channel_context_token, validate_channel_boundary};

    fn now_secs() -> u64 {
        std::time::UNIX_EPOCH
            .elapsed()
            .expect("current time should be after unix epoch")
            .as_secs()
    }

    // -----------------------------------------------------------------------
    // Construction and basic invariants
    // -----------------------------------------------------------------------

    #[test]
    fn broker_initializes_with_non_zero_hashes() {
        let broker = FacBroker::new();
        assert_ne!(broker.state.freshness_horizon_hash, [0u8; 32]);
        assert_ne!(broker.state.revocation_frontier_hash, [0u8; 32]);
        assert_ne!(broker.state.convergence_horizon_hash, [0u8; 32]);
        assert_eq!(broker.current_tick(), 1);
    }

    #[test]
    fn broker_advance_tick_is_monotonic() {
        let mut broker = FacBroker::new();
        let t1 = broker.current_tick();
        let t2 = broker.advance_tick();
        let t3 = broker.advance_tick();
        assert!(t2 > t1);
        assert!(t3 > t2);
    }

    // -----------------------------------------------------------------------
    // RFC-0028: Channel context token issuance + validation
    // -----------------------------------------------------------------------

    #[test]
    fn issue_and_decode_channel_context_token_roundtrip() {
        let mut broker = FacBroker::new();
        let job_digest = [0x42; 32];
        let lease_id = "lease-broker-001";
        let request_id = "REQ-001";
        broker
            .admit_policy_digest(job_digest)
            .expect("job digest should admit");

        let token = broker
            .issue_channel_context_token(&job_digest, lease_id, request_id)
            .expect("token issuance should succeed");

        // Decode with broker's verifying key
        let decode_now = now_secs();
        let decoded = decode_channel_context_token(
            &token,
            &broker.verifying_key(),
            lease_id,
            decode_now,
            request_id,
        )
        .expect("token decode should succeed");

        // Validate boundary check passes
        let defects = validate_channel_boundary(&decoded);
        assert!(
            defects.is_empty(),
            "broker-issued token should pass all boundary checks, got {defects:?}"
        );
    }

    #[test]
    fn issue_channel_context_token_rejects_zero_job_digest() {
        let broker = FacBroker::new();
        let result = broker.issue_channel_context_token(&[0u8; 32], "lease-1", "REQ-1");
        assert_eq!(result, Err(BrokerError::ZeroJobSpecDigest));
    }

    #[test]
    fn issue_channel_context_token_rejects_empty_lease_id() {
        let mut broker = FacBroker::new();
        broker
            .admit_policy_digest([0x11; 32])
            .expect("job digest should admit");
        let result = broker.issue_channel_context_token(&[0x11; 32], "", "REQ-1");
        assert_eq!(result, Err(BrokerError::EmptyLeaseId));
    }

    #[test]
    fn issue_channel_context_token_rejects_empty_request_id() {
        let mut broker = FacBroker::new();
        broker
            .admit_policy_digest([0x11; 32])
            .expect("job digest should admit");
        let result = broker.issue_channel_context_token(&[0x11; 32], "lease-1", "");
        assert_eq!(result, Err(BrokerError::EmptyRequestId));
    }

    #[test]
    fn issue_channel_context_token_rejects_unadmitted_job_digest() {
        let broker = FacBroker::new();
        let result = broker.issue_channel_context_token(&[0x11; 32], "lease-1", "REQ-1");
        assert!(matches!(
            result,
            Err(BrokerError::UnadmittedPolicyDigest { .. })
        ));
    }

    #[test]
    fn forged_token_rejected_by_different_key() {
        let mut broker = FacBroker::new();
        let mut attacker = FacBroker::new();
        let job_digest = [0x42; 32];
        broker
            .admit_policy_digest(job_digest)
            .expect("job digest should admit on verifier broker");
        attacker
            .admit_policy_digest(job_digest)
            .expect("job digest should admit on attacker broker");

        let forged_token = attacker
            .issue_channel_context_token(&job_digest, "lease-1", "REQ-1")
            .expect("attacker token should encode");
        let decode_now = now_secs();

        let result = decode_channel_context_token(
            &forged_token,
            &broker.verifying_key(),
            "lease-1",
            decode_now,
            "REQ-1",
        );
        assert!(
            result.is_err(),
            "forged token must be rejected by broker's key"
        );
    }

    // -----------------------------------------------------------------------
    // RFC-0029: TimeAuthorityEnvelopeV1 issuance + signature verification
    // -----------------------------------------------------------------------

    #[test]
    fn issue_time_authority_envelope_and_verify_signature() {
        let mut broker = FacBroker::new();
        let envelope = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope issuance should succeed");

        assert_eq!(envelope.boundary_id, "boundary-1");
        assert_eq!(envelope.authority_clock, "clock-1");
        assert_eq!(envelope.tick_start, 100);
        assert_eq!(envelope.tick_end, 200);
        assert_eq!(envelope.ttl_ticks, 500);
        assert!(envelope.deny_on_unknown);
        assert_eq!(envelope.signature_set.len(), 1);
        assert_ne!(envelope.content_hash, [0u8; 32]);

        // Verify signature using BrokerSignatureVerifier
        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &envelope.signature_set[0];
        let canonical = envelope_signature_canonical_bytes(&envelope);
        assert!(
            verifier.verify_broker_signature(&canonical, &sig.signer_id, &sig.signature,),
            "broker-signed envelope must verify"
        );
    }

    #[test]
    fn issue_time_authority_envelope_verifies_with_tp001() {
        let mut broker = FacBroker::new();
        let boundary_id = "boundary-1";
        let authority_clock = "clock-1";
        let envelope = broker
            .issue_time_authority_envelope(boundary_id, authority_clock, 100, 200, 500)
            .expect("envelope issuance should succeed");

        let eval_window = HtfEvaluationWindow {
            boundary_id: boundary_id.to_string(),
            authority_clock: authority_clock.to_string(),
            tick_start: 100,
            tick_end: 200,
        };
        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        assert!(
            crate::economics::queue_admission::validate_envelope_tp001(
                Some(&envelope),
                &eval_window,
                Some(&verifier),
            )
            .is_ok()
        );
    }

    #[test]
    fn issue_time_authority_envelope_rejects_empty_boundary_id() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope("", "clock-1", 100, 200, 500);
        assert!(matches!(result, Err(BrokerError::InvalidBoundaryId { .. })));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_oversized_boundary_id() {
        let mut broker = FacBroker::new();
        let long_id = "x".repeat(MAX_BOUNDARY_ID_LENGTH + 1);
        let result = broker.issue_time_authority_envelope(&long_id, "clock-1", 100, 200, 500);
        assert!(matches!(result, Err(BrokerError::InvalidBoundaryId { .. })));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_empty_authority_clock() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope("boundary-1", "", 100, 200, 500);
        assert!(matches!(
            result,
            Err(BrokerError::InvalidAuthorityClock { .. })
        ));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_inverted_tick_range() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope("boundary-1", "clock-1", 200, 100, 500);
        assert!(matches!(result, Err(BrokerError::InvertedTickRange { .. })));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_excessive_ttl() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope(
            "boundary-1",
            "clock-1",
            100,
            200,
            MAX_ENVELOPE_TTL_TICKS + 1,
        );
        assert!(matches!(result, Err(BrokerError::TtlExceedsMaximum { .. })));
    }

    #[test]
    fn issue_time_authority_envelope_rejects_zero_ttl() {
        let mut broker = FacBroker::new();
        let result = broker.issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 0);
        assert!(matches!(result, Err(BrokerError::TtlMustBeNonZero)));
    }

    #[test]
    fn envelope_tick_advances_after_issuance() {
        let mut broker = FacBroker::new();
        let tick_before = broker.current_tick();
        let _ = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope issuance should succeed");
        let tick_after = broker.current_tick();
        assert!(tick_after > tick_before, "tick must advance after issuance");
    }

    #[test]
    fn forged_envelope_rejected_by_verifier() {
        let broker = FacBroker::new();
        let mut attacker = FacBroker::new();

        let forged_envelope = attacker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("attacker envelope should encode");

        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &forged_envelope.signature_set[0];
        assert!(
            !verifier.verify_broker_signature(
                &envelope_signature_canonical_bytes(&forged_envelope),
                &sig.signer_id,
                &sig.signature,
            ),
            "forged envelope must be rejected by broker's verifier"
        );
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-002: Freshness horizon and revocation frontier
    // -----------------------------------------------------------------------

    #[test]
    fn freshness_horizon_is_resolved_and_non_zero() {
        let broker = FacBroker::new();
        let horizon = broker.freshness_horizon();
        assert!(horizon.resolved);
        assert_ne!(horizon.horizon_hash, [0u8; 32]);
        assert_eq!(horizon.tick_end, broker.state.freshness_horizon_tick_end);
        assert_eq!(horizon.tick_end, 1);
    }

    #[test]
    fn revocation_frontier_is_current_and_non_zero() {
        let broker = FacBroker::new();
        let frontier = broker.revocation_frontier();
        assert!(frontier.current);
        assert_ne!(frontier.frontier_hash, [0u8; 32]);
    }

    #[test]
    fn freshness_horizon_changes_after_advance() {
        let mut broker = FacBroker::new();
        let h1 = broker.freshness_horizon();
        broker.advance_freshness_horizon(100);
        let h2 = broker.freshness_horizon();
        assert_ne!(h1.horizon_hash, h2.horizon_hash);
        assert_eq!(h2.tick_end, 100);
        assert!(h2.tick_end > h1.tick_end);
    }

    #[test]
    fn revocation_frontier_changes_after_advance() {
        let mut broker = FacBroker::new();
        let f1 = broker.revocation_frontier();
        broker.advance_revocation_frontier();
        let f2 = broker.revocation_frontier();
        assert_ne!(f1.frontier_hash, f2.frontier_hash);
    }

    // -----------------------------------------------------------------------
    // TP-EIO29-003: Convergence horizon and receipts
    // -----------------------------------------------------------------------

    #[test]
    fn convergence_horizon_is_resolved_and_non_zero() {
        let broker = FacBroker::new();
        let horizon = broker.convergence_horizon();
        assert!(horizon.resolved);
        assert_ne!(horizon.horizon_hash, [0u8; 32]);
    }

    #[test]
    fn add_convergence_receipt_updates_horizon() {
        let mut broker = FacBroker::new();
        let h1 = broker.convergence_horizon();

        broker
            .add_convergence_receipt([0x11; 32], [0x22; 32])
            .expect("receipt should be added");

        let h2 = broker.convergence_horizon();
        assert_ne!(h1.horizon_hash, h2.horizon_hash);
        assert_eq!(broker.convergence_receipts().len(), 1);
        assert!(broker.convergence_receipts()[0].converged);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn convergence_receipt_store_cap_enforced() {
        let mut broker = FacBroker::new();
        for i in 1..=MAX_CONVERGENCE_RECEIPTS {
            broker
                .add_convergence_receipt([i as u8; 32], [i as u8; 32])
                .expect("receipt should be added");
        }

        let result = broker.add_convergence_receipt([0xFF; 32], [0xFF; 32]);
        assert!(matches!(
            result,
            Err(BrokerError::ConvergenceReceiptStoreAtCapacity { .. })
        ));
        assert_eq!(
            broker.convergence_receipts().len(),
            MAX_CONVERGENCE_RECEIPTS
        );
    }

    #[test]
    fn add_convergence_receipt_rejects_zero_authority_set_hash() {
        let mut broker = FacBroker::new();
        let result = broker.add_convergence_receipt([0u8; 32], [0x11; 32]);
        assert!(matches!(
            result,
            Err(BrokerError::ZeroConvergenceReceiptHash {
                field: "authority_set_hash"
            })
        ));
        assert!(broker.convergence_receipts().is_empty());
    }

    #[test]
    fn add_convergence_receipt_rejects_zero_proof_hash() {
        let mut broker = FacBroker::new();
        let result = broker.add_convergence_receipt([0x11; 32], [0u8; 32]);
        assert!(matches!(
            result,
            Err(BrokerError::ZeroConvergenceReceiptHash {
                field: "proof_hash"
            })
        ));
        assert!(broker.convergence_receipts().is_empty());
    }

    // -----------------------------------------------------------------------
    // Policy digest admission
    // -----------------------------------------------------------------------

    #[test]
    fn admit_and_check_policy_digest() {
        let mut broker = FacBroker::new();
        let digest = [0x42; 32];

        assert!(!broker.is_policy_digest_admitted(&digest));
        broker.admit_policy_digest(digest).expect("should admit");
        assert!(broker.is_policy_digest_admitted(&digest));
    }

    #[test]
    fn duplicate_policy_digest_is_idempotent() {
        let mut broker = FacBroker::new();
        let digest = [0x42; 32];

        broker.admit_policy_digest(digest).expect("first admit");
        broker.admit_policy_digest(digest).expect("second admit");
        assert_eq!(broker.state.admitted_policy_digests.len(), 1);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn policy_digest_store_cap_enforced() {
        let mut broker = FacBroker::new();
        for i in 1..=MAX_ADMITTED_POLICY_DIGESTS {
            let i = u16::try_from(i).expect("loop index must fit");
            let i_bytes = i.to_le_bytes();
            let mut digest = [0u8; 32];
            digest[0] = i_bytes[0];
            digest[1] = i_bytes[1];
            broker.admit_policy_digest(digest).expect("should admit");
        }

        let result = broker.admit_policy_digest([0xFF; 32]);
        assert!(matches!(
            result,
            Err(BrokerError::PolicyDigestStoreAtCapacity { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // State serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn state_serialization_roundtrip() {
        let mut broker = FacBroker::new();
        broker.admit_policy_digest([0x42; 32]).unwrap();
        broker
            .add_convergence_receipt([0x11; 32], [0x22; 32])
            .unwrap();
        let _ = broker.advance_tick();

        let bytes = broker.serialize_state().expect("serialize should succeed");
        let restored = FacBroker::deserialize_state(&bytes).expect("deserialize should succeed");

        assert_eq!(restored, broker.state);
    }

    #[test]
    fn deserialization_rejects_oversized_policy_digests() {
        let state = BrokerState {
            admitted_policy_digests: vec![[0u8; 32]; MAX_ADMITTED_POLICY_DIGESTS + 1],
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn deserialization_rejects_oversized_convergence_receipts() {
        let state = BrokerState {
            convergence_receipts: (0..=MAX_CONVERGENCE_RECEIPTS)
                .map(|i| ConvergenceReceipt {
                    authority_set_hash: [i as u8; 32],
                    proof_hash: [i as u8; 32],
                    converged: true,
                })
                .collect(),
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    fn deserialization_rejects_wrong_schema() {
        let state = BrokerState {
            schema_id: "wrong.schema".to_string(),
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    fn deserialization_rejects_wrong_schema_version() {
        let state = BrokerState {
            schema_version: "0.0.0".to_string(),
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    fn deserialization_rejects_zeroed_horizon_hashes() {
        let state = BrokerState {
            freshness_horizon_hash: [0u8; 32],
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    fn deserialization_rejects_zero_current_tick() {
        let state = BrokerState {
            current_tick: 0,
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    fn deserialization_rejects_zero_freshness_horizon_tick_end() {
        let state = BrokerState {
            freshness_horizon_tick_end: 0,
            ..BrokerState::default()
        };

        let bytes = serde_json::to_vec(&state).unwrap();
        let result = FacBroker::deserialize_state(&bytes);
        assert!(matches!(result, Err(BrokerError::Deserialization { .. })));
    }

    #[test]
    fn admit_policy_digest_rejects_zero_digest() {
        let mut broker = FacBroker::new();
        let result = broker.admit_policy_digest([0u8; 32]);
        assert!(matches!(result, Err(BrokerError::ZeroPolicyDigest)));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn admit_policy_digest_duplicate_is_idempotent_with_capacity_at_max() {
        let mut broker = FacBroker::new();
        for i in 0..MAX_ADMITTED_POLICY_DIGESTS {
            let i = u16::try_from(i + 1).expect("loop index must fit");
            let mut digest = [0u8; 32];
            digest[0] = i.to_le_bytes()[0];
            digest[1] = i.to_le_bytes()[1];
            broker.admit_policy_digest(digest).expect("should admit");
        }

        let mut duplicate = [0u8; 32];
        let duplicate_last = u16::try_from(MAX_ADMITTED_POLICY_DIGESTS).expect("fits u16");
        let duplicate_last = duplicate_last.to_le_bytes();
        duplicate[0] = duplicate_last[0];
        duplicate[1] = duplicate_last[1];
        let result = broker.admit_policy_digest(duplicate);
        assert!(
            result.is_ok(),
            "duplicate admission must not fail at capacity"
        );
    }

    // -----------------------------------------------------------------------
    // Deserialization size limit (DoS prevention)
    // -----------------------------------------------------------------------

    #[test]
    fn deserialization_rejects_oversized_input() {
        // Construct a byte slice just over MAX_BROKER_STATE_FILE_SIZE.
        let oversized = vec![0u8; MAX_BROKER_STATE_FILE_SIZE + 1];
        let result = FacBroker::deserialize_state(&oversized);
        assert!(
            matches!(
                result,
                Err(BrokerError::StateTooLarge { size, max })
                    if size == MAX_BROKER_STATE_FILE_SIZE + 1
                    && max == MAX_BROKER_STATE_FILE_SIZE
            ),
            "must reject input exceeding MAX_BROKER_STATE_FILE_SIZE"
        );
    }

    #[test]
    fn deserialization_accepts_input_at_size_limit() {
        // Valid broker state serialized should be well under the limit.
        let broker = FacBroker::new();
        let bytes = broker.serialize_state().expect("serialize should succeed");
        assert!(
            bytes.len() <= MAX_BROKER_STATE_FILE_SIZE,
            "default state should be under size limit"
        );
        let result = FacBroker::deserialize_state(&bytes);
        assert!(result.is_ok(), "valid state within limit must parse");
    }

    // -----------------------------------------------------------------------
    // Constant-time find_admitted_policy_digest
    // -----------------------------------------------------------------------

    #[test]
    fn find_admitted_policy_digest_returns_matching_digest() {
        let mut broker = FacBroker::new();
        let d1 = [0x11; 32];
        let d2 = [0x22; 32];
        let d3 = [0x33; 32];
        broker.admit_policy_digest(d1).unwrap();
        broker.admit_policy_digest(d2).unwrap();
        broker.admit_policy_digest(d3).unwrap();

        // Should find each digest regardless of position (tests that
        // non-short-circuiting iteration visits all entries).
        assert_eq!(broker.find_admitted_policy_digest(&d1), Some(d1));
        assert_eq!(broker.find_admitted_policy_digest(&d2), Some(d2));
        assert_eq!(broker.find_admitted_policy_digest(&d3), Some(d3));
        assert_eq!(broker.find_admitted_policy_digest(&[0xFF; 32]), None);
    }

    // -----------------------------------------------------------------------
    // BrokerSignatureVerifier
    // -----------------------------------------------------------------------

    #[test]
    fn broker_verifier_rejects_wrong_key() {
        let mut broker = FacBroker::new();
        let other = FacBroker::new();

        let envelope = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope should issue");

        let verifier = BrokerSignatureVerifier::new(other.verifying_key());
        let sig = &envelope.signature_set[0];
        assert!(
            !verifier.verify_broker_signature(
                &envelope_signature_canonical_bytes(&envelope),
                &sig.signer_id,
                &sig.signature,
            ),
            "must reject signature from different key"
        );
    }

    #[test]
    fn broker_verifier_rejects_tampered_content() {
        let mut broker = FacBroker::new();
        let envelope = broker
            .issue_time_authority_envelope("boundary-1", "clock-1", 100, 200, 500)
            .expect("envelope should issue");

        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &envelope.signature_set[0];
        let mut tampered_signature_message = envelope_signature_canonical_bytes(&envelope);
        tampered_signature_message[0] ^= 0xFF;
        assert!(
            !verifier.verify_broker_signature(
                &tampered_signature_message,
                &sig.signer_id,
                &sig.signature,
            ),
            "must reject tampered content hash"
        );
    }

    // -----------------------------------------------------------------------
    // Integration: end-to-end token + envelope + horizons
    // -----------------------------------------------------------------------

    #[test]
    fn end_to_end_broker_token_envelope_horizons() {
        let mut broker = FacBroker::new();
        let job_digest = [0x42; 32];
        let lease_id = "lease-e2e-001";
        let request_id = "REQ-E2E-001";
        broker
            .admit_policy_digest(job_digest)
            .expect("job digest should admit");

        // 1. Issue channel token
        let token = broker
            .issue_channel_context_token(&job_digest, lease_id, request_id)
            .expect("token should issue");
        let decode_now = now_secs();

        // 2. Decode and validate
        let decoded = decode_channel_context_token(
            &token,
            &broker.verifying_key(),
            lease_id,
            decode_now,
            request_id,
        )
        .expect("token should decode");
        let defects = validate_channel_boundary(&decoded);
        assert!(defects.is_empty(), "token must pass boundary checks");

        // 3. Issue envelope
        let envelope = broker
            .issue_time_authority_envelope("boundary-e2e", "clock-e2e", 10, 100, 500)
            .expect("envelope should issue");

        // 4. Verify signature
        let verifier = BrokerSignatureVerifier::new(broker.verifying_key());
        let sig = &envelope.signature_set[0];
        let canonical = envelope_signature_canonical_bytes(&envelope);
        assert!(verifier.verify_broker_signature(&canonical, &sig.signer_id, &sig.signature,));

        // 5. Check horizons are non-zero and resolved
        let fh = broker.freshness_horizon();
        assert!(fh.resolved);
        assert_ne!(fh.horizon_hash, [0u8; 32]);

        let rf = broker.revocation_frontier();
        assert!(rf.current);
        assert_ne!(rf.frontier_hash, [0u8; 32]);

        let ch = broker.convergence_horizon();
        assert!(ch.resolved);
        assert_ne!(ch.horizon_hash, [0u8; 32]);
    }
}
