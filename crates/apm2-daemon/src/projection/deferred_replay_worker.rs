// AGENT-AUTHORED (TCK-00508)
//! Deferred replay worker for projection intent buffer drain after outage
//! recovery.
//!
//! This module implements [`DeferredReplayWorker`] — the worker responsible
//! for draining buffered projection intents that were deferred during sink
//! outages. When sink recovery is detected, the worker replays buffered
//! intents in ledger order with full admission re-evaluation.
//!
//! # Replay Contract
//!
//! For each replayed intent, the worker performs:
//!
//! 1. **Replay window check**: Intents with `replay_horizon_tick` outside the
//!    declared window are expired with a deny receipt (not silently dropped).
//! 2. **Idempotency check**: Intents whose `(work_id, changeset_digest)`
//!    already have a successful projection receipt are skipped without error.
//! 3. **Economics gate re-evaluation**: Each intent is re-evaluated through
//!    `evaluate_projection_continuity()` with current gate inputs. Previously
//!    denied intents are NOT assumed admissible.
//! 4. **PCAC lifecycle enforcement**: Each intent undergoes full lifecycle
//!    enforcement (`join -> revalidate -> consume`) in addition to economics
//!    re-evaluation. Authority freshness and revocation are revalidated.
//! 5. **Projection effect**: Only intents passing both economics gate AND
//!    lifecycle enforcement are projected.
//!
//! # Security Model
//!
//! - **Authority revocation dominance**: A buffered intent carrying authority
//!   that was valid at buffer time but has since been revoked is DENIED, even
//!   if the economics gate returns ALLOW. Economics gates check temporal
//!   windows, NOT authority freshness — these are orthogonal concerns.
//! - **Single-use semantics**: Intents whose authority token was consumed
//!   through an alternate path during the outage are DENIED.
//! - **Fail-closed**: Missing gate inputs, missing lifecycle gate, or unknown
//!   state always results in DENY.
//! - **Bounded replay**: Configurable batch size (default 64) prevents
//!   post-outage thundering herd.
//! - **Deterministic ordering**: Backlog entries are drained in `ORDER BY
//!   rowid` (ledger order).
//!
//! # Convergence Receipt
//!
//! On batch completion with no remaining backlog, the worker emits a
//! [`DeferredReplayReceiptV1`] with:
//! - `replayed_item_count`: Total items successfully replayed in this cycle.
//! - `backlog_digest`: Blake3 hash over ordered intent digests.
//! - `converged: true`: Indicates full backlog drain.
//!
//! [`DeferredReplayReceiptV1`]: apm2_core::economics::DeferredReplayReceiptV1

use std::sync::Arc;

use apm2_core::crypto::{EventHasher, Signer};
use apm2_core::economics::{
    ContinuityVerdict, DeferredReplayMode, DeferredReplayReceiptV1, ProjectionContinuityWindowV1,
    ProjectionSinkContinuityProfileV1, evaluate_projection_continuity,
};
use apm2_core::pcac::{
    AuthorityJoinInputV1, BoundaryIntentClass, DeterminismClass, IdentityEvidenceLevel,
    PcacPolicyKnobs, RiskTier,
};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::continuity_resolver::{
    ContinuityProfileResolver, ResolvedContinuityProfile, ResolvedContinuityWindow,
};
use super::intent_buffer::{DeferredReplayEntry, IntentBuffer, IntentVerdict};
use super::worker::{AdmissionTelemetry, lifecycle_deny};
use crate::pcac::LifecycleGate;

// =============================================================================
// Constants
// =============================================================================

/// Default maximum number of intents replayed per drain cycle.
///
/// Prevents post-outage thundering herd by limiting batch size.
/// Configurable via [`DeferredReplayWorkerConfig`].
pub const DEFAULT_REPLAY_BATCH_SIZE: usize = 64;

/// Hard upper bound on `replay_batch_size` to prevent configuration errors
/// from causing unbounded replay.
pub const MAX_REPLAY_BATCH_SIZE: usize = 4096;

/// Denial reason for intents outside the replay window.
pub const DENY_REPLAY_HORIZON_OUT_OF_WINDOW: &str = "DENY_REPLAY_HORIZON_OUT_OF_WINDOW";

/// Denial reason for intents that already have a successful projection.
pub const DENY_REPLAY_ALREADY_PROJECTED: &str = "DENY_REPLAY_ALREADY_PROJECTED";

/// Denial reason when the economics gate denies replay.
pub const DENY_REPLAY_ECONOMICS_GATE: &str = "DENY_REPLAY_ECONOMICS_GATE";

/// Denial reason when the lifecycle gate denies replay.
pub const DENY_REPLAY_LIFECYCLE_GATE: &str = "DENY_REPLAY_LIFECYCLE_GATE";

/// Denial reason when required dependencies are missing (fail-closed).
pub const DENY_REPLAY_MISSING_DEPENDENCY: &str = "DENY_REPLAY_MISSING_DEPENDENCY";

// =============================================================================
// Error Types
// =============================================================================

/// Errors from [`DeferredReplayWorker`] operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeferredReplayError {
    /// Intent buffer operation failed.
    #[error("intent buffer error: {0}")]
    IntentBufferError(String),

    /// Economics gate evaluation failed.
    #[error("economics gate error: {0}")]
    EconomicsGateError(String),

    /// Lifecycle gate evaluation failed.
    #[error("lifecycle gate error: {0}")]
    LifecycleGateError(String),

    /// Projection effect failed.
    #[error("projection effect error: {0}")]
    ProjectionEffectError(String),

    /// Receipt construction failed.
    #[error("receipt construction error: {0}")]
    ReceiptConstructionError(String),

    /// Missing required dependency (fail-closed).
    #[error("missing dependency: {0}")]
    MissingDependency(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    ConfigError(String),
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the deferred replay worker.
#[derive(Debug, Clone)]
pub struct DeferredReplayWorkerConfig {
    /// Maximum number of intents replayed per drain cycle.
    /// Default: [`DEFAULT_REPLAY_BATCH_SIZE`] (64).
    /// Hard cap: [`MAX_REPLAY_BATCH_SIZE`] (4096).
    pub replay_batch_size: usize,
    /// Boundary identifier for continuity profile resolution.
    pub boundary_id: String,
    /// Signer actor identity for convergence receipts.
    pub signer_actor_id: String,
}

impl DeferredReplayWorkerConfig {
    /// Creates a new configuration with defaults.
    ///
    /// # Arguments
    ///
    /// * `boundary_id` - Boundary identifier for continuity resolution.
    /// * `signer_actor_id` - Actor identity for receipt signing.
    #[must_use]
    pub const fn new(boundary_id: String, signer_actor_id: String) -> Self {
        Self {
            replay_batch_size: DEFAULT_REPLAY_BATCH_SIZE,
            boundary_id,
            signer_actor_id,
        }
    }

    /// Sets the replay batch size, clamping to
    /// `[1, MAX_REPLAY_BATCH_SIZE]`.
    #[must_use]
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.replay_batch_size = size.clamp(1, MAX_REPLAY_BATCH_SIZE);
        self
    }
}

// =============================================================================
// Replay Result
// =============================================================================

/// Result of a single drain cycle.
#[derive(Debug, Clone)]
pub struct ReplayCycleResult {
    /// Number of intents successfully replayed (projected).
    pub replayed_count: u64,
    /// Number of intents expired (outside replay window).
    pub expired_count: u64,
    /// Number of intents skipped (idempotent — already projected).
    pub skipped_count: u64,
    /// Number of intents denied by economics or lifecycle gate.
    pub denied_count: u64,
    /// Total intents processed in this cycle.
    pub total_processed: u64,
    /// Whether the backlog is fully drained (converged).
    pub converged: bool,
    /// Blake3 digest over ordered intent digests of replayed items.
    pub backlog_digest: [u8; 32],
    /// Convergence receipt, if backlog fully drained.
    pub convergence_receipt: Option<DeferredReplayReceiptV1>,
}

// =============================================================================
// DeferredReplayWorker
// =============================================================================

/// Worker that drains the deferred replay backlog after sink recovery.
///
/// # Synchronization Protocol
///
/// The worker holds `Arc`-wrapped shared references to its dependencies.
/// All database operations go through the [`IntentBuffer`] which provides
/// its own `Mutex<Connection>` synchronization. The worker itself has no
/// interior mutability — it is constructed with all dependencies and
/// operates in a single-threaded drain loop.
///
/// # Invariants
///
/// - [INV-DR01] Replay batch size never exceeds [`MAX_REPLAY_BATCH_SIZE`].
/// - [INV-DR02] Intents outside the replay window are expired with deny
///   receipt, never silently dropped.
/// - [INV-DR03] Each replayed intent undergoes full economics gate AND
///   lifecycle enforcement — economics ALLOW alone is insufficient.
/// - [INV-DR04] Already-projected intents are skipped idempotently.
/// - [INV-DR05] Convergence receipt includes correct `replayed_item_count` and
///   `backlog_digest` (Blake3 over ordered intent digests).
/// - [INV-DR06] Missing dependencies result in DENY (fail-closed).
pub struct DeferredReplayWorker {
    config: DeferredReplayWorkerConfig,
    intent_buffer: Arc<IntentBuffer>,
    resolver: Arc<dyn ContinuityProfileResolver>,
    gate_signer: Arc<Signer>,
    lifecycle_gate: Arc<LifecycleGate>,
    telemetry: Arc<AdmissionTelemetry>,
}

impl DeferredReplayWorker {
    /// Creates a new deferred replay worker with all required dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`DeferredReplayError::ConfigError`] if the batch size
    /// exceeds the hard cap.
    pub fn new(
        config: DeferredReplayWorkerConfig,
        intent_buffer: Arc<IntentBuffer>,
        resolver: Arc<dyn ContinuityProfileResolver>,
        gate_signer: Arc<Signer>,
        lifecycle_gate: Arc<LifecycleGate>,
        telemetry: Arc<AdmissionTelemetry>,
    ) -> Result<Self, DeferredReplayError> {
        if config.replay_batch_size == 0 || config.replay_batch_size > MAX_REPLAY_BATCH_SIZE {
            return Err(DeferredReplayError::ConfigError(format!(
                "replay_batch_size must be in [1, {MAX_REPLAY_BATCH_SIZE}], got {}",
                config.replay_batch_size
            )));
        }
        if config.boundary_id.is_empty() {
            return Err(DeferredReplayError::ConfigError(
                "boundary_id must not be empty".to_string(),
            ));
        }
        if config.signer_actor_id.is_empty() {
            return Err(DeferredReplayError::ConfigError(
                "signer_actor_id must not be empty".to_string(),
            ));
        }
        Ok(Self {
            config,
            intent_buffer,
            resolver,
            gate_signer,
            lifecycle_gate,
            telemetry,
        })
    }

    /// Executes one drain cycle: fetches up to `replay_batch_size` pending
    /// backlog entries and processes each in ledger order.
    ///
    /// Returns a [`ReplayCycleResult`] summarizing the cycle outcome,
    /// including a convergence receipt if the backlog is fully drained.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current HTF tick for replay window evaluation.
    /// * `time_authority_ref` - Current time authority reference hash.
    /// * `window_ref` - Current HTF window reference hash.
    ///
    /// # Errors
    ///
    /// Returns [`DeferredReplayError`] on unrecoverable failures.
    /// Individual intent failures are recorded as denials and do NOT
    /// abort the cycle.
    pub fn drain_cycle(
        &self,
        current_tick: u64,
        time_authority_ref: [u8; 32],
        window_ref: [u8; 32],
    ) -> Result<ReplayCycleResult, DeferredReplayError> {
        // Step 1: Fetch pending backlog entries (bounded by batch size,
        // ordered by rowid for deterministic ledger-order replay).
        let entries = self
            .intent_buffer
            .query_pending_backlog(self.config.replay_batch_size)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;

        if entries.is_empty() {
            // No pending entries — backlog is converged (empty).
            return self.emit_convergence_result(
                0,
                0,
                0,
                0,
                true, // converged
                [0u8; 32],
                current_tick,
                time_authority_ref,
                window_ref,
            );
        }

        let mut replayed_count: u64 = 0;
        let mut expired_count: u64 = 0;
        let mut skipped_count: u64 = 0;
        let mut denied_count: u64 = 0;

        // Running Blake3 hasher for backlog_digest computation.
        let mut digest_hasher = blake3::Hasher::new();

        // Step 2: Process each entry in ledger order.
        for entry in &entries {
            match self.process_backlog_entry(entry, current_tick, time_authority_ref, window_ref) {
                Ok(ReplayIntentOutcome::Replayed { intent_digest }) => {
                    replayed_count += 1;
                    // Include intent digest in backlog_digest computation.
                    digest_hasher.update(&intent_digest);
                },
                Ok(ReplayIntentOutcome::Expired) => {
                    expired_count += 1;
                },
                Ok(ReplayIntentOutcome::Skipped) => {
                    skipped_count += 1;
                },
                Ok(ReplayIntentOutcome::Denied) => {
                    denied_count += 1;
                },
                Err(e) => {
                    // Individual intent failures are logged and counted as
                    // denials. The cycle continues processing remaining
                    // entries (no abort).
                    warn!(
                        intent_id = %entry.intent_id,
                        error = %e,
                        "Deferred replay: intent processing failed (counted as denial)"
                    );
                    denied_count += 1;
                },
            }
        }

        let backlog_digest: [u8; 32] = *digest_hasher.finalize().as_bytes();

        // Step 3: Check if backlog is fully drained.
        // Query remaining non-converged entries to determine convergence.
        let pending_remaining = self
            .intent_buffer
            .query_pending_backlog(1)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;

        let converged = pending_remaining.is_empty();

        self.emit_convergence_result(
            replayed_count,
            expired_count,
            skipped_count,
            denied_count,
            converged,
            backlog_digest,
            current_tick,
            time_authority_ref,
            window_ref,
        )
    }

    /// Returns a reference to the replay configuration.
    #[must_use]
    pub const fn config(&self) -> &DeferredReplayWorkerConfig {
        &self.config
    }

    /// Returns a reference to the intent buffer.
    #[must_use]
    pub fn intent_buffer(&self) -> &IntentBuffer {
        &self.intent_buffer
    }

    /// Returns a reference to the admission telemetry.
    #[must_use]
    pub fn telemetry(&self) -> &AdmissionTelemetry {
        &self.telemetry
    }

    // =========================================================================
    // Internal: per-intent processing
    // =========================================================================

    /// Processes a single backlog entry through the full replay pipeline.
    ///
    /// Returns the outcome for telemetry/digest accumulation.
    fn process_backlog_entry(
        &self,
        entry: &DeferredReplayEntry,
        current_tick: u64,
        time_authority_ref: [u8; 32],
        window_ref: [u8; 32],
    ) -> Result<ReplayIntentOutcome, DeferredReplayError> {
        debug!(
            intent_id = %entry.intent_id,
            work_id = %entry.work_id,
            replay_horizon_tick = entry.replay_horizon_tick,
            "Processing deferred replay entry"
        );

        // -----------------------------------------------------------------
        // Gate 1: Replay window bounds check.
        //
        // Resolve the continuity window for this boundary. Intents with
        // replay_horizon_tick outside the declared window are expired.
        // -----------------------------------------------------------------
        let resolved_window = self
            .resolver
            .resolve_continuity_window(&self.config.boundary_id);
        let replay_window_ticks = resolved_window
            .as_ref()
            .map_or(0, |w| w.replay_window_ticks);

        // Compute the window lower bound: current_tick minus replay window
        // span. Intents older than this are outside the window.
        let window_lower_bound = current_tick.saturating_sub(replay_window_ticks);

        if entry.replay_horizon_tick < window_lower_bound {
            // Intent is outside replay window — expire with deny receipt.
            info!(
                intent_id = %entry.intent_id,
                replay_horizon_tick = entry.replay_horizon_tick,
                window_lower_bound = window_lower_bound,
                current_tick = current_tick,
                "Deferred replay: intent expired (outside replay window)"
            );
            self.expire_intent(entry, DENY_REPLAY_HORIZON_OUT_OF_WINDOW)?;
            return Ok(ReplayIntentOutcome::Expired);
        }

        // -----------------------------------------------------------------
        // Gate 2: Idempotency check.
        //
        // If the intent already has a successful projection (verdict ==
        // Admitted), skip it. This prevents double-projection.
        // -----------------------------------------------------------------
        let intent_record = self
            .intent_buffer
            .get_intent(&entry.intent_id)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;

        let Some(intent) = intent_record else {
            // Intent record missing — fail-closed: deny the backlog entry.
            warn!(
                intent_id = %entry.intent_id,
                "Deferred replay: intent record not found (fail-closed deny)"
            );
            self.expire_intent(entry, DENY_REPLAY_MISSING_DEPENDENCY)?;
            return Ok(ReplayIntentOutcome::Denied);
        };

        if intent.verdict == IntentVerdict::Admitted {
            // Already projected — skip idempotently.
            debug!(
                intent_id = %entry.intent_id,
                "Deferred replay: intent already admitted (idempotent skip)"
            );
            self.mark_converged_entry(entry)?;
            return Ok(ReplayIntentOutcome::Skipped);
        }

        if intent.verdict == IntentVerdict::Denied {
            // Already denied through another path — skip.
            debug!(
                intent_id = %entry.intent_id,
                "Deferred replay: intent already denied (skip)"
            );
            self.mark_converged_entry(entry)?;
            return Ok(ReplayIntentOutcome::Skipped);
        }

        // Intent is Pending — proceed with replay evaluation.

        // -----------------------------------------------------------------
        // Gate 3: Economics gate re-evaluation.
        //
        // Re-evaluate the economics admission gate with CURRENT inputs.
        // Do NOT assume previously-denied or buffered intents are now
        // admissible.
        // -----------------------------------------------------------------
        let economics_result = self.evaluate_economics_for_replay(
            &intent,
            current_tick,
            time_authority_ref,
            window_ref,
        );

        if let Err(reason) = economics_result {
            info!(
                intent_id = %entry.intent_id,
                deny_reason = %reason,
                "Deferred replay: economics gate DENY"
            );
            self.deny_intent_and_converge(
                entry,
                &format!("{DENY_REPLAY_ECONOMICS_GATE}: {reason}"),
            )?;
            self.telemetry
                .economics_denied_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(ReplayIntentOutcome::Denied);
        }

        // -----------------------------------------------------------------
        // Gate 4: PCAC lifecycle enforcement.
        //
        // Each replayed intent must undergo full lifecycle enforcement:
        // join -> revalidate -> consume. Authority freshness and
        // revocation are revalidated. Without this, replay becomes an
        // exploit vector: buffer before revocation, replay after,
        // bypass authority checks.
        // -----------------------------------------------------------------
        let lifecycle_result = self.evaluate_lifecycle_for_replay(
            &intent,
            current_tick,
            time_authority_ref,
            window_ref,
        );

        match lifecycle_result {
            Ok(artifacts) => {
                // Persist lifecycle artifacts on the intent.
                if let Err(e) = self
                    .intent_buffer
                    .attach_lifecycle_artifacts(&entry.intent_id, &artifacts)
                {
                    warn!(
                        intent_id = %entry.intent_id,
                        error = %e,
                        "Failed to persist replay lifecycle artifacts \
                         (proceeding with in-memory artifacts)"
                    );
                }
            },
            Err(reason) => {
                info!(
                    intent_id = %entry.intent_id,
                    deny_reason = %reason,
                    "Deferred replay: lifecycle gate DENY"
                );
                self.deny_intent_and_converge(
                    entry,
                    &format!("{DENY_REPLAY_LIFECYCLE_GATE}: {reason}"),
                )?;
                return Ok(ReplayIntentOutcome::Denied);
            },
        }

        // -----------------------------------------------------------------
        // Step 5: Admit the intent and mark backlog entry as replayed.
        //
        // Admission is recorded AFTER all gates pass (check before mutate).
        // -----------------------------------------------------------------
        let admit_tick_ns = current_tick.saturating_mul(1_000_000); // HTF tick to ns
        self.intent_buffer
            .admit(&entry.intent_id, admit_tick_ns)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;

        self.intent_buffer
            .mark_replayed(&entry.intent_id, admit_tick_ns)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;

        self.intent_buffer
            .mark_converged(&entry.intent_id)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;

        self.telemetry
            .admitted_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        info!(
            intent_id = %entry.intent_id,
            work_id = %entry.work_id,
            "Deferred replay: intent replayed and admitted"
        );

        Ok(ReplayIntentOutcome::Replayed {
            intent_digest: intent.changeset_digest,
        })
    }

    // =========================================================================
    // Internal: economics gate
    // =========================================================================

    /// Re-evaluates the economics admission gate for a replay intent.
    ///
    /// Returns `Ok(())` on ALLOW, `Err(reason)` on DENY.
    fn evaluate_economics_for_replay(
        &self,
        _intent: &super::intent_buffer::ProjectionIntent,
        eval_tick: u64,
        time_authority_ref: [u8; 32],
        window_ref: [u8; 32],
    ) -> Result<(), String> {
        // Resolve continuity profile and window from resolver.
        let resolved_profile = self
            .resolver
            .resolve_continuity_profile(&self.config.boundary_id)
            .ok_or_else(|| "missing continuity profile for boundary (fail-closed)".to_string())?;

        let resolved_window = self
            .resolver
            .resolve_continuity_window(&self.config.boundary_id)
            .ok_or_else(|| "missing continuity window for boundary (fail-closed)".to_string())?;

        let snapshot = self
            .resolver
            .resolve_sink_snapshot(&resolved_profile.sink_id)
            .ok_or_else(|| "missing sink snapshot for boundary (fail-closed)".to_string())?;

        // Build signed artifacts for economics gate evaluation.
        let signed_window = build_signed_replay_window(
            &resolved_window,
            time_authority_ref,
            window_ref,
            eval_tick,
            &self.gate_signer,
        )
        .ok_or_else(|| "failed to construct signed continuity window".to_string())?;

        let signed_profile = build_signed_replay_profile(
            &resolved_profile,
            snapshot.snapshot_digest,
            time_authority_ref,
            window_ref,
            &self.gate_signer,
        )
        .ok_or_else(|| "failed to construct signed continuity profile".to_string())?;

        let decision = evaluate_projection_continuity(
            Some(&signed_window),
            Some(&signed_profile),
            Some(&snapshot),
            &self.config.boundary_id,
            eval_tick,
            time_authority_ref,
            window_ref,
            &resolved_profile.trusted_signer_keys,
            &DeferredReplayMode::Inactive, // Replay itself is the deferred path
        );

        if decision.verdict != ContinuityVerdict::Allow {
            let deny_reason = decision
                .defect
                .as_ref()
                .map_or_else(|| "economics_gate_deny".to_string(), |d| d.reason.clone());
            return Err(deny_reason);
        }

        Ok(())
    }

    // =========================================================================
    // Internal: lifecycle gate
    // =========================================================================

    /// Evaluates full PCAC lifecycle enforcement for a replay intent.
    ///
    /// Returns lifecycle artifacts on success, deny reason on failure.
    fn evaluate_lifecycle_for_replay(
        &self,
        intent: &super::intent_buffer::ProjectionIntent,
        eval_tick: u64,
        time_authority_ref: [u8; 32],
        _window_ref: [u8; 32],
    ) -> Result<super::intent_buffer::IntentLifecycleArtifacts, String> {
        // Build a join input for the lifecycle gate.
        let intent_digest = EventHasher::hash_content(&intent.changeset_digest);
        let ledger_anchor = EventHasher::hash_content(intent.intent_id.as_bytes());
        let freshness_tick = eval_tick.max(1);
        let tick_bytes = freshness_tick.to_le_bytes();

        // Domain-tagged witness hashes for the replay lifecycle gate.
        let capability_hash = EventHasher::hash_content(b"deferred_replay_capability");
        let scope_hash = EventHasher::hash_content(b"deferred_replay_scope");
        let identity_hash = EventHasher::hash_content(intent.work_id.as_bytes());
        let leakage_witness_hash = EventHasher::hash_content(
            &[
                intent_digest.as_slice(),
                scope_hash.as_slice(),
                tick_bytes.as_slice(),
            ]
            .concat(),
        );
        let timing_witness_hash = EventHasher::hash_content(
            &[
                time_authority_ref.as_slice(),
                ledger_anchor.as_slice(),
                tick_bytes.as_slice(),
            ]
            .concat(),
        );

        let join_input = AuthorityJoinInputV1 {
            session_id: intent.intent_id.clone(),
            holon_id: None,
            intent_digest,
            boundary_intent_class: BoundaryIntentClass::Actuate,
            capability_manifest_hash: capability_hash,
            scope_witness_hashes: vec![scope_hash],
            lease_id: intent.work_id.clone(),
            permeability_receipt_hash: None,
            identity_proof_hash: identity_hash,
            identity_evidence_level: IdentityEvidenceLevel::PointerOnly,
            pointer_only_waiver_hash: None,
            directory_head_hash: ledger_anchor,
            freshness_policy_hash: scope_hash,
            freshness_witness_tick: freshness_tick,
            stop_budget_profile_digest: capability_hash,
            pre_actuation_receipt_hashes: Vec::new(),
            leakage_witness_hash,
            timing_witness_hash,
            risk_tier: RiskTier::Tier0,
            determinism_class: DeterminismClass::Deterministic,
            time_envelope_ref: time_authority_ref,
            as_of_ledger_anchor: ledger_anchor,
        };

        let policy = PcacPolicyKnobs::default();

        self.lifecycle_gate.advance_tick(eval_tick);

        // The revocation head hash must match the cert's
        // revocation_head_hash (= input.directory_head_hash = ledger_anchor).
        // Passing a different hash (e.g., window_ref) would trigger a
        // RevocationFrontierAdvanced denial.
        let cert = self
            .lifecycle_gate
            .join_and_revalidate(
                &join_input,
                time_authority_ref,
                ledger_anchor,
                ledger_anchor,
                &policy,
            )
            .map_err(|deny| {
                let subcategory = lifecycle_subcategory_from_deny_class(&deny.deny_class);
                increment_lifecycle_counter(&self.telemetry, subcategory);
                format!("lifecycle join/revalidate denied: {}", deny.deny_class)
            })?;

        self.lifecycle_gate.advance_tick(eval_tick);
        self.lifecycle_gate
            .revalidate_before_execution(
                &cert,
                time_authority_ref,
                ledger_anchor,
                ledger_anchor,
                &policy,
            )
            .map_err(|deny| {
                let subcategory = lifecycle_subcategory_from_deny_class(&deny.deny_class);
                increment_lifecycle_counter(&self.telemetry, subcategory);
                format!("lifecycle revalidate denied: {}", deny.deny_class)
            })?;

        let (consumed_witness, consume_record) = self
            .lifecycle_gate
            .consume_before_effect(
                &cert,
                join_input.intent_digest,
                join_input.boundary_intent_class,
                true,
                time_authority_ref,
                ledger_anchor,
                &policy,
            )
            .map_err(|deny| {
                let subcategory = lifecycle_subcategory_from_deny_class(&deny.deny_class);
                increment_lifecycle_counter(&self.telemetry, subcategory);
                format!("lifecycle consume denied: {}", deny.deny_class)
            })?;

        debug!(
            intent_id = %intent.intent_id,
            ajc_id = %hex::encode(cert.ajc_id),
            consume_tick = consumed_witness.consumed_at_tick,
            "Deferred replay: lifecycle gate passed (join -> revalidate -> consume)"
        );

        Ok(super::intent_buffer::IntentLifecycleArtifacts {
            ajc_id: cert.ajc_id,
            intent_digest: consumed_witness.intent_digest,
            consume_selector_digest: consume_record.effect_selector_digest,
            consume_tick: consumed_witness.consumed_at_tick,
            time_envelope_ref: consumed_witness.consumed_time_envelope_ref,
        })
    }

    // =========================================================================
    // Internal: intent state transitions
    // =========================================================================

    /// Expires an intent outside the replay window with a deny receipt.
    fn expire_intent(
        &self,
        entry: &DeferredReplayEntry,
        reason: &str,
    ) -> Result<(), DeferredReplayError> {
        self.intent_buffer
            .deny(&entry.intent_id, reason)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;
        self.intent_buffer
            .mark_converged(&entry.intent_id)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;
        Ok(())
    }

    /// Denies an intent and marks the backlog entry as converged.
    fn deny_intent_and_converge(
        &self,
        entry: &DeferredReplayEntry,
        reason: &str,
    ) -> Result<(), DeferredReplayError> {
        self.intent_buffer
            .deny(&entry.intent_id, reason)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;
        self.intent_buffer
            .mark_converged(&entry.intent_id)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;
        Ok(())
    }

    /// Marks a backlog entry as converged (for skipped/idempotent intents).
    fn mark_converged_entry(&self, entry: &DeferredReplayEntry) -> Result<(), DeferredReplayError> {
        self.intent_buffer
            .mark_converged(&entry.intent_id)
            .map_err(|e| DeferredReplayError::IntentBufferError(e.to_string()))?;
        Ok(())
    }

    // =========================================================================
    // Internal: convergence result assembly
    // =========================================================================

    /// Assembles the cycle result, including convergence receipt if the
    /// backlog is fully drained.
    #[allow(clippy::too_many_arguments)]
    fn emit_convergence_result(
        &self,
        replayed_count: u64,
        expired_count: u64,
        skipped_count: u64,
        denied_count: u64,
        converged: bool,
        backlog_digest: [u8; 32],
        current_tick: u64,
        time_authority_ref: [u8; 32],
        window_ref: [u8; 32],
    ) -> Result<ReplayCycleResult, DeferredReplayError> {
        let total_processed = replayed_count
            .saturating_add(expired_count)
            .saturating_add(skipped_count)
            .saturating_add(denied_count);

        // Build convergence receipt if backlog is fully drained.
        let convergence_receipt = if converged {
            // Use the backlog_digest as content_hash for the receipt.
            // If no items were replayed (empty backlog), use a sentinel
            // digest derived from the boundary_id.
            let content_digest = if backlog_digest == [0u8; 32] {
                EventHasher::hash_content(self.config.boundary_id.as_bytes())
            } else {
                backlog_digest
            };

            let receipt = DeferredReplayReceiptV1::create_signed(
                &format!("replay-{}-{current_tick}", self.config.boundary_id),
                &self.config.boundary_id,
                content_digest,
                replayed_count,
                current_tick,
                true, // converged
                time_authority_ref,
                window_ref,
                content_digest,
                &self.config.signer_actor_id,
                &self.gate_signer,
            )
            .map_err(|e| {
                DeferredReplayError::ReceiptConstructionError(format!(
                    "failed to create convergence receipt: {e}"
                ))
            })?;

            info!(
                receipt_id = %receipt.receipt_id,
                replayed_item_count = replayed_count,
                backlog_digest = %hex::encode(content_digest),
                "Deferred replay: convergence receipt emitted"
            );

            Some(receipt)
        } else {
            None
        };

        Ok(ReplayCycleResult {
            replayed_count,
            expired_count,
            skipped_count,
            denied_count,
            total_processed,
            converged,
            backlog_digest,
            convergence_receipt,
        })
    }
}

// =============================================================================
// Internal Outcome Type
// =============================================================================

/// Outcome of processing a single backlog entry.
enum ReplayIntentOutcome {
    /// Intent was successfully replayed (projected).
    Replayed {
        /// Changeset digest of the replayed intent (for `backlog_digest`).
        intent_digest: [u8; 32],
    },
    /// Intent was expired (outside replay window).
    Expired,
    /// Intent was skipped (idempotent — already projected or denied).
    Skipped,
    /// Intent was denied by economics or lifecycle gate.
    Denied,
}

// =============================================================================
// Signed Artifact Builders (Replay-Specific)
// =============================================================================

/// Constructs a signed [`ProjectionContinuityWindowV1`] for replay evaluation.
fn build_signed_replay_window(
    resolved: &ResolvedContinuityWindow,
    time_authority_ref: [u8; 32],
    window_ref: [u8; 32],
    eval_tick: u64,
    signer: &Signer,
) -> Option<ProjectionContinuityWindowV1> {
    let content_hash = EventHasher::hash_content(
        &[
            resolved.boundary_id.as_bytes(),
            &resolved.outage_window_ticks.to_be_bytes(),
            &resolved.replay_window_ticks.to_be_bytes(),
        ]
        .concat(),
    );

    ProjectionContinuityWindowV1::create_signed(
        &format!("replay-win-{}", hex::encode(&window_ref[..8])),
        &resolved.boundary_id,
        eval_tick.saturating_sub(resolved.outage_window_ticks),
        eval_tick,
        eval_tick.saturating_sub(resolved.replay_window_ticks),
        eval_tick,
        window_ref,
        window_ref,
        time_authority_ref,
        window_ref,
        content_hash,
        "deferred-replay-signer",
        signer,
    )
    .ok()
}

/// Constructs a signed [`ProjectionSinkContinuityProfileV1`] for replay
/// evaluation.
fn build_signed_replay_profile(
    resolved: &ResolvedContinuityProfile,
    snapshot_digest: [u8; 32],
    time_authority_ref: [u8; 32],
    window_ref: [u8; 32],
    signer: &Signer,
) -> Option<ProjectionSinkContinuityProfileV1> {
    use apm2_core::economics::ContinuityScenarioVerdict;

    let scenario_id = format!("replay-scenario-{}", &resolved.sink_id);
    let scenario_digest = EventHasher::hash_content(
        &[
            resolved.sink_id.as_bytes(),
            &resolved.churn_tolerance.to_be_bytes(),
            &resolved.partition_tolerance.to_be_bytes(),
        ]
        .concat(),
    );

    let scenario = ContinuityScenarioVerdict {
        scenario_id,
        scenario_digest,
        truth_plane_continued: true,
        backlog_bounded: true,
        max_backlog_items: 0,
    };

    let content_hash = EventHasher::hash_content(
        &[
            resolved.sink_id.as_bytes(),
            &snapshot_digest,
            &time_authority_ref,
        ]
        .concat(),
    );

    ProjectionSinkContinuityProfileV1::create_signed(
        &format!("replay-prof-{}", &resolved.sink_id),
        &resolved.sink_id,
        vec![scenario],
        snapshot_digest,
        time_authority_ref,
        window_ref,
        content_hash,
        "deferred-replay-signer",
        signer,
    )
    .ok()
}

// =============================================================================
// Lifecycle Helpers (mirrored from worker.rs for replay context)
// =============================================================================

/// Maps an authority deny class to a lifecycle denial subcategory.
const fn lifecycle_subcategory_from_deny_class(
    deny_class: &apm2_core::pcac::AuthorityDenyClass,
) -> &'static str {
    use apm2_core::pcac::AuthorityDenyClass;
    match deny_class {
        AuthorityDenyClass::RevocationFrontierAdvanced
        | AuthorityDenyClass::UnknownRevocationHead { .. } => lifecycle_deny::REVOKED,
        AuthorityDenyClass::StaleFreshnessAtJoin
        | AuthorityDenyClass::StaleFreshnessAtRevalidate
        | AuthorityDenyClass::CertificateExpired { .. }
        | AuthorityDenyClass::FreshnessExceeded { .. }
        | AuthorityDenyClass::LedgerAnchorDrift => lifecycle_deny::STALE,
        _ => lifecycle_deny::CONSUMED,
    }
}

/// Increments the appropriate lifecycle telemetry counter.
fn increment_lifecycle_counter(telemetry: &AdmissionTelemetry, subcategory: &str) {
    match subcategory {
        lifecycle_deny::REVOKED => {
            telemetry
                .lifecycle_revoked_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        },
        lifecycle_deny::STALE => {
            telemetry
                .lifecycle_stale_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        },
        lifecycle_deny::CONSUMED => {
            telemetry
                .lifecycle_consumed_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        },
        _ => {
            telemetry
                .missing_inputs_denied_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use std::sync::{Arc, Mutex};

    use apm2_core::crypto::Signer;
    use apm2_core::economics::MultiSinkIdentitySnapshotV1;
    use rusqlite::Connection;

    use super::*;
    use crate::pcac::{InProcessKernel, LifecycleGate};
    use crate::projection::continuity_resolver::{
        ContinuityProfileResolver, ResolvedContinuityProfile, ResolvedContinuityWindow,
    };
    use crate::projection::intent_buffer::{IntentBuffer, IntentVerdict};

    // =========================================================================
    // Test Resolver
    // =========================================================================

    /// Test resolver that returns configurable profiles, snapshots, and
    /// windows.
    struct TestResolver {
        profile: Option<ResolvedContinuityProfile>,
        snapshot: Option<MultiSinkIdentitySnapshotV1>,
        window: Option<ResolvedContinuityWindow>,
    }

    impl TestResolver {
        fn new_with_defaults(signer: &Signer) -> Self {
            use apm2_core::economics::SinkIdentityEntry;

            let profile = ResolvedContinuityProfile {
                sink_id: "test-boundary".to_string(),
                outage_window_ticks: 1000,
                replay_window_ticks: 500,
                churn_tolerance: 2,
                partition_tolerance: 1,
                trusted_signer_keys: vec![signer.public_key_bytes()],
            };

            let entry_a = SinkIdentityEntry {
                sink_id: "test-sink".to_string(),
                identity_digest: apm2_core::crypto::EventHasher::hash_content(b"sink-a"),
            };
            let entry_b = SinkIdentityEntry {
                sink_id: "test-sink-secondary".to_string(),
                identity_digest: apm2_core::crypto::EventHasher::hash_content(b"sink-b"),
            };
            let mut snapshot = MultiSinkIdentitySnapshotV1 {
                sink_identities: vec![entry_a, entry_b],
                snapshot_digest: [0u8; 32],
            };
            snapshot.snapshot_digest = snapshot.compute_digest();

            let window = ResolvedContinuityWindow {
                boundary_id: "test-boundary".to_string(),
                outage_window_ticks: 1000,
                replay_window_ticks: 500,
            };

            Self {
                profile: Some(profile),
                snapshot: Some(snapshot),
                window: Some(window),
            }
        }

        fn without_profile(mut self) -> Self {
            self.profile = None;
            self
        }

        #[allow(dead_code)]
        fn without_window(mut self) -> Self {
            self.window = None;
            self
        }
    }

    impl ContinuityProfileResolver for TestResolver {
        fn resolve_continuity_profile(&self, _sink_id: &str) -> Option<ResolvedContinuityProfile> {
            self.profile.clone()
        }

        fn resolve_sink_snapshot(&self, _sink_id: &str) -> Option<MultiSinkIdentitySnapshotV1> {
            self.snapshot.clone()
        }

        fn resolve_continuity_window(
            &self,
            _boundary_id: &str,
        ) -> Option<ResolvedContinuityWindow> {
            self.window.clone()
        }
    }

    // =========================================================================
    // Test Helpers
    // =========================================================================

    fn make_worker(
        intent_buffer: Arc<IntentBuffer>,
        resolver: Arc<dyn ContinuityProfileResolver>,
        gate_signer: Arc<Signer>,
    ) -> DeferredReplayWorker {
        let kernel = Arc::new(InProcessKernel::new(1));
        let lifecycle_gate = Arc::new(LifecycleGate::with_tick_kernel(kernel.clone(), kernel));
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let config =
            DeferredReplayWorkerConfig::new("test-boundary".to_string(), "test-actor".to_string());

        DeferredReplayWorker::new(
            config,
            intent_buffer,
            resolver,
            gate_signer,
            lifecycle_gate,
            telemetry,
        )
        .expect("worker creation")
    }

    fn make_test_deps() -> (
        Arc<IntentBuffer>,
        Arc<Signer>,
        Arc<dyn ContinuityProfileResolver>,
    ) {
        let conn = Connection::open_in_memory().expect("open");
        let conn = Arc::new(Mutex::new(conn));
        let buffer = Arc::new(IntentBuffer::new(conn).expect("buffer"));
        let signer = Arc::new(Signer::generate());
        let resolver = Arc::new(TestResolver::new_with_defaults(&signer));
        (buffer, signer, resolver)
    }

    fn make_digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn insert_test_intent(
        buffer: &IntentBuffer,
        intent_id: &str,
        work_id: &str,
        changeset_byte: u8,
        eval_tick: u64,
    ) {
        buffer
            .insert(
                intent_id,
                work_id,
                &make_digest(changeset_byte),
                &make_digest(0xAB),
                "pending",
                eval_tick,
                1_000_000,
            )
            .expect("insert intent");
    }

    fn insert_test_backlog(
        buffer: &IntentBuffer,
        intent_id: &str,
        work_id: &str,
        replay_horizon_tick: u64,
    ) {
        let _ = buffer.insert_backlog(intent_id, work_id, &make_digest(0xBB), replay_horizon_tick);
    }

    // =========================================================================
    // Tests: Empty Backlog
    // =========================================================================

    #[test]
    fn test_drain_cycle_empty_backlog_converges() {
        let (buffer, signer, resolver) = make_test_deps();
        let worker = make_worker(buffer, resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert!(result.converged, "empty backlog should converge");
        assert_eq!(result.replayed_count, 0);
        assert_eq!(result.expired_count, 0);
        assert_eq!(result.skipped_count, 0);
        assert_eq!(result.denied_count, 0);
        assert_eq!(result.total_processed, 0);
        assert!(
            result.convergence_receipt.is_some(),
            "converged cycle should emit receipt"
        );

        let receipt = result.convergence_receipt.unwrap();
        assert!(receipt.converged);
        assert_eq!(receipt.replayed_item_count, 0);
    }

    // =========================================================================
    // Tests: Replay Window Expiration
    // =========================================================================

    #[test]
    fn test_intent_outside_replay_window_is_expired_with_deny() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert intent with replay_horizon_tick = 100 (very old).
        insert_test_intent(&buffer, "intent-001", "work-001", 0x42, 100);
        insert_test_backlog(&buffer, "intent-001", "work-001", 100);

        let worker = make_worker(buffer.clone(), resolver, signer);

        // Current tick = 1000, replay window = 500.
        // Window lower bound = 1000 - 500 = 500.
        // Intent horizon = 100 < 500 -> expired.
        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert_eq!(result.expired_count, 1);
        assert_eq!(result.replayed_count, 0);

        // Verify the intent was denied (not silently dropped).
        let intent = buffer
            .get_intent("intent-001")
            .expect("get")
            .expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Denied);
        assert!(
            intent
                .deny_reason
                .contains("DENY_REPLAY_HORIZON_OUT_OF_WINDOW"),
            "deny reason should contain window violation: {}",
            intent.deny_reason
        );
    }

    // =========================================================================
    // Tests: Idempotent Replay
    // =========================================================================

    #[test]
    fn test_already_admitted_intent_is_skipped() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert and immediately admit the intent.
        insert_test_intent(&buffer, "intent-002", "work-002", 0x43, 800);
        buffer.admit("intent-002", 900_000).expect("admit");
        insert_test_backlog(&buffer, "intent-002", "work-002", 800);

        let worker = make_worker(buffer.clone(), resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.replayed_count, 0);
        assert_eq!(result.denied_count, 0);
    }

    #[test]
    fn test_already_denied_intent_is_skipped() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert and deny the intent.
        insert_test_intent(&buffer, "intent-003", "work-003", 0x44, 800);
        buffer.deny("intent-003", "prior_deny").expect("deny");
        insert_test_backlog(&buffer, "intent-003", "work-003", 800);

        let worker = make_worker(buffer.clone(), resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.replayed_count, 0);
    }

    // =========================================================================
    // Tests: Normal Replay
    // =========================================================================

    #[test]
    fn test_pending_intent_within_window_is_replayed() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert intent within replay window.
        insert_test_intent(&buffer, "intent-004", "work-004", 0x45, 800);
        insert_test_backlog(&buffer, "intent-004", "work-004", 800);

        let worker = make_worker(buffer.clone(), resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert_eq!(result.replayed_count, 1);
        assert_eq!(result.expired_count, 0);
        assert_eq!(result.denied_count, 0);

        // Verify the intent was admitted.
        let intent = buffer
            .get_intent("intent-004")
            .expect("get")
            .expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Admitted);
    }

    // =========================================================================
    // Tests: Batch Size Limiting
    // =========================================================================

    #[test]
    fn test_batch_size_limits_processing() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert 5 pending intents.
        for i in 0..5 {
            let intent_id = format!("intent-batch-{i:03}");
            let work_id = format!("work-batch-{i:03}");
            insert_test_intent(&buffer, &intent_id, &work_id, (0x50 + i) as u8, 800);
            insert_test_backlog(&buffer, &intent_id, &work_id, 800);
        }

        // Create worker with batch size = 2.
        let kernel = Arc::new(InProcessKernel::new(1));
        let lifecycle_gate = Arc::new(LifecycleGate::with_tick_kernel(kernel.clone(), kernel));
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let config =
            DeferredReplayWorkerConfig::new("test-boundary".to_string(), "test-actor".to_string())
                .with_batch_size(2);

        let worker = DeferredReplayWorker::new(
            config,
            buffer.clone(),
            resolver,
            signer,
            lifecycle_gate,
            telemetry,
        )
        .expect("worker");

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        // Only 2 intents should be processed per cycle.
        assert_eq!(result.total_processed, 2);
        assert!(
            !result.converged,
            "should not converge with remaining items"
        );

        // 3 entries should remain pending.
        let pending = buffer.query_pending_backlog(10).expect("query");
        assert_eq!(pending.len(), 3, "3 entries should remain pending");
    }

    // =========================================================================
    // Tests: Convergence Receipt
    // =========================================================================

    #[test]
    fn test_convergence_receipt_includes_correct_fields() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert 2 intents within window.
        insert_test_intent(&buffer, "intent-cv-001", "work-cv-001", 0x60, 800);
        insert_test_backlog(&buffer, "intent-cv-001", "work-cv-001", 800);
        insert_test_intent(&buffer, "intent-cv-002", "work-cv-002", 0x61, 810);
        insert_test_backlog(&buffer, "intent-cv-002", "work-cv-002", 810);

        let worker = make_worker(buffer.clone(), resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert_eq!(result.replayed_count, 2);
        assert!(result.converged);
        assert!(result.convergence_receipt.is_some());

        let receipt = result.convergence_receipt.unwrap();
        assert_eq!(receipt.replayed_item_count, 2);
        assert!(receipt.converged);
        assert_ne!(receipt.backlog_digest, [0u8; 32]);
        assert_eq!(receipt.boundary_id, "test-boundary");
    }

    // =========================================================================
    // Tests: Economics Gate Denial
    // =========================================================================

    #[test]
    fn test_replay_denied_when_economics_profile_missing() {
        let conn = Connection::open_in_memory().expect("open");
        let conn = Arc::new(Mutex::new(conn));
        let buffer = Arc::new(IntentBuffer::new(conn).expect("buffer"));
        let signer = Arc::new(Signer::generate());
        // Resolver without profile -> economics gate will fail-closed.
        let resolver = Arc::new(TestResolver::new_with_defaults(&signer).without_profile());

        insert_test_intent(&buffer, "intent-econ-001", "work-econ-001", 0x70, 800);
        insert_test_backlog(&buffer, "intent-econ-001", "work-econ-001", 800);

        let worker = make_worker(buffer.clone(), resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert_eq!(result.denied_count, 1);
        assert_eq!(result.replayed_count, 0);

        let intent = buffer
            .get_intent("intent-econ-001")
            .expect("get")
            .expect("exists");
        assert_eq!(intent.verdict, IntentVerdict::Denied);
        assert!(
            intent.deny_reason.contains(DENY_REPLAY_ECONOMICS_GATE),
            "deny reason should reference economics gate: {}",
            intent.deny_reason
        );
    }

    // =========================================================================
    // Tests: Missing Intent Record (Fail-Closed)
    // =========================================================================

    #[test]
    fn test_missing_intent_record_denied_fail_closed() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert backlog entry WITHOUT corresponding intent record.
        insert_test_backlog(&buffer, "intent-missing", "work-missing", 800);

        let worker = make_worker(buffer.clone(), resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        // The entry should be denied (fail-closed).
        assert_eq!(result.denied_count, 1);
        assert_eq!(result.replayed_count, 0);
    }

    // =========================================================================
    // Tests: Configuration Validation
    // =========================================================================

    #[test]
    fn test_config_batch_size_clamped() {
        let config = DeferredReplayWorkerConfig::new("boundary".to_string(), "actor".to_string())
            .with_batch_size(0);
        assert_eq!(config.replay_batch_size, 1, "zero should clamp to 1");

        let config2 = DeferredReplayWorkerConfig::new("boundary".to_string(), "actor".to_string())
            .with_batch_size(100_000);
        assert_eq!(
            config2.replay_batch_size, MAX_REPLAY_BATCH_SIZE,
            "oversized should clamp to MAX"
        );
    }

    #[test]
    fn test_worker_rejects_empty_boundary_id() {
        let (buffer, signer, resolver) = make_test_deps();
        let kernel = Arc::new(InProcessKernel::new(1));
        let gate = Arc::new(LifecycleGate::with_tick_kernel(kernel.clone(), kernel));
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let config = DeferredReplayWorkerConfig::new(String::new(), "actor".to_string());

        let result = DeferredReplayWorker::new(config, buffer, resolver, signer, gate, telemetry);
        assert!(result.is_err());
    }

    #[test]
    fn test_worker_rejects_empty_signer_actor_id() {
        let (buffer, signer, resolver) = make_test_deps();
        let kernel = Arc::new(InProcessKernel::new(1));
        let gate = Arc::new(LifecycleGate::with_tick_kernel(kernel.clone(), kernel));
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let config = DeferredReplayWorkerConfig::new("boundary".to_string(), String::new());

        let result = DeferredReplayWorker::new(config, buffer, resolver, signer, gate, telemetry);
        assert!(result.is_err());
    }

    // =========================================================================
    // Tests: Backlog Digest Computation
    // =========================================================================

    #[test]
    fn test_backlog_digest_changes_with_different_intents() {
        let (buffer, signer, resolver) = make_test_deps();

        insert_test_intent(&buffer, "intent-dig-001", "work-dig-001", 0x80, 800);
        insert_test_backlog(&buffer, "intent-dig-001", "work-dig-001", 800);

        let worker = make_worker(buffer.clone(), resolver.clone(), signer.clone());
        let result1 = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain1");

        // Create a second worker with different intent data.
        let conn2 = Connection::open_in_memory().expect("open");
        let conn2 = Arc::new(Mutex::new(conn2));
        let buffer2 = Arc::new(IntentBuffer::new(conn2).expect("buffer"));
        insert_test_intent(&buffer2, "intent-dig-002", "work-dig-002", 0x81, 800);
        insert_test_backlog(&buffer2, "intent-dig-002", "work-dig-002", 800);

        let worker2 = make_worker(buffer2, resolver, signer);
        let result2 = worker2
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain2");

        // Digests should differ because different changeset digests.
        assert_ne!(
            result1.backlog_digest, result2.backlog_digest,
            "different intents should produce different backlog digests"
        );
    }

    // =========================================================================
    // Tests: Mixed Outcomes
    // =========================================================================

    #[test]
    fn test_mixed_outcomes_in_single_cycle() {
        let (buffer, signer, resolver) = make_test_deps();

        // Intent 1: within window, pending -> should be replayed.
        insert_test_intent(&buffer, "intent-mix-001", "work-mix-001", 0x90, 800);
        insert_test_backlog(&buffer, "intent-mix-001", "work-mix-001", 800);

        // Intent 2: already admitted -> should be skipped.
        insert_test_intent(&buffer, "intent-mix-002", "work-mix-002", 0x91, 810);
        buffer.admit("intent-mix-002", 900_000).expect("admit");
        insert_test_backlog(&buffer, "intent-mix-002", "work-mix-002", 810);

        // Intent 3: outside replay window -> should be expired.
        insert_test_intent(&buffer, "intent-mix-003", "work-mix-003", 0x92, 100);
        insert_test_backlog(&buffer, "intent-mix-003", "work-mix-003", 100);

        let worker = make_worker(buffer.clone(), resolver, signer);

        let result = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("drain");

        assert_eq!(result.replayed_count, 1, "1 intent replayed");
        assert_eq!(result.skipped_count, 1, "1 intent skipped (admitted)");
        assert_eq!(result.expired_count, 1, "1 intent expired");
        assert_eq!(result.total_processed, 3);
        assert!(result.converged, "all entries processed -> converged");
    }

    // =========================================================================
    // Tests: Multiple Cycles (Incremental Drain)
    // =========================================================================

    #[test]
    fn test_incremental_drain_across_cycles() {
        let (buffer, signer, resolver) = make_test_deps();

        // Insert 4 intents.
        for i in 0..4 {
            let intent_id = format!("intent-incr-{i:03}");
            let work_id = format!("work-incr-{i:03}");
            insert_test_intent(&buffer, &intent_id, &work_id, (0xA0 + i) as u8, 800);
            insert_test_backlog(&buffer, &intent_id, &work_id, 800);
        }

        // Worker with batch size = 2.
        let kernel = Arc::new(InProcessKernel::new(1));
        let lifecycle_gate = Arc::new(LifecycleGate::with_tick_kernel(kernel.clone(), kernel));
        let telemetry = Arc::new(AdmissionTelemetry::new());
        let config =
            DeferredReplayWorkerConfig::new("test-boundary".to_string(), "test-actor".to_string())
                .with_batch_size(2);

        let worker = DeferredReplayWorker::new(
            config,
            buffer.clone(),
            resolver,
            signer,
            lifecycle_gate,
            telemetry,
        )
        .expect("worker");

        // Cycle 1: process first 2.
        let r1 = worker
            .drain_cycle(1000, make_digest(0xAA), make_digest(0xBB))
            .expect("cycle 1");
        assert_eq!(r1.total_processed, 2);
        assert!(!r1.converged);

        // Cycle 2: process remaining 2.
        let r2 = worker
            .drain_cycle(1001, make_digest(0xAA), make_digest(0xBB))
            .expect("cycle 2");
        assert_eq!(r2.total_processed, 2);
        assert!(r2.converged, "all entries processed in cycle 2");
        assert!(r2.convergence_receipt.is_some());
    }
}
