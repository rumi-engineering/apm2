//! TCK-00416: Lifecycle authority bindings integration tests.
//!
//! Validates that authoritative lifecycle transitions carry explicit
//! delegated authority and boundary bindings per `REQ-HEF-0013`.
//!
//! # Acceptance Criteria Mapping
//!
//! - AC-1: Transitions into `CLAIMED`/`IN_PROGRESS`/`REVIEW`/`COMPLETED` are
//!   rejected when required authority bindings are missing.
//! - AC-2: Review and projection receipts include view commitment and
//!   evidence-index bindings sufficient for replay without ambient state.
//! - AC-3: All required hashes are CAS-resolvable at validation time (not
//!   deferred).
#![allow(clippy::doc_markdown)]
//! # Verification Commands
//!
//! ```sh
//! cargo test -p apm2-daemon --tests workobject_transition_authority_bindings -- --nocapture
//! ```

use std::sync::Arc;

use apm2_core::evidence::{ContentAddressedStore, MemoryCas};
use apm2_daemon::episode::envelope::StopConditions;
use apm2_daemon::protocol::dispatch::{
    PolicyResolution, ReviewOutcomeBindings, TransitionAuthorityBindings, TypedBudgetBindings,
    WorkClaim, derive_claim_transition_authority_bindings, derive_review_outcome_bindings,
    derive_transition_authority_bindings, store_authority_binding_artifacts,
    store_review_outcome_artifacts, typed_budgets_for_role,
    validate_and_store_transition_authority, validate_review_outcome_bindings,
    validate_transition_authority_bindings,
};
use apm2_daemon::protocol::messages::WorkRole;

// ============================================================================
// Test helpers
// ============================================================================

/// Creates a CAS with all authority binding artifacts pre-stored.
fn cas_with_stored_bindings(
    work_id: &str,
    bindings: &TransitionAuthorityBindings,
) -> Arc<MemoryCas> {
    let cas = Arc::new(MemoryCas::new());
    store_authority_binding_artifacts(work_id, bindings, cas.as_ref())
        .expect("CAS store should succeed");

    // Also store the capability_manifest and context_pack preimages so
    // CAS-resolvability succeeds. In production, these are stored before
    // the transition; in tests we store synthetic payloads whose hash
    // matches what the bindings declare.
    let manifest_payload = b"capability-manifest-content";
    let manifest_hash = *blake3::hash(manifest_payload).as_bytes();
    assert_eq!(
        manifest_hash, bindings.capability_manifest_hash,
        "test helper must use the same capability manifest content"
    );
    cas.store(manifest_payload)
        .expect("capability manifest CAS store");

    let context_payload = b"context-pack-content";
    let context_hash = *blake3::hash(context_payload).as_bytes();
    assert_eq!(
        context_hash, bindings.context_pack_hash,
        "test helper must use the same context pack content"
    );
    cas.store(context_payload).expect("context pack CAS store");

    cas
}

/// Derives valid bindings for testing using deterministic content.
fn valid_bindings(work_id: &str) -> TransitionAuthorityBindings {
    let capability_manifest_hash = *blake3::hash(b"capability-manifest-content").as_bytes();
    let context_pack_hash = *blake3::hash(b"context-pack-content").as_bytes();

    derive_transition_authority_bindings(
        work_id,
        "lease-test-001",
        "actor:test-agent",
        WorkRole::Implementer,
        "policy-ref-001",
        capability_manifest_hash,
        context_pack_hash,
        StopConditions::max_episodes(10),
    )
    .expect("valid bindings derivation should succeed")
}

/// Creates a CAS with review outcome artifacts pre-stored.
fn cas_with_outcome_bindings(bindings: &ReviewOutcomeBindings) -> Arc<MemoryCas> {
    let cas = Arc::new(MemoryCas::new());

    let view_content = b"view-commitment-snapshot";
    assert_eq!(
        *blake3::hash(view_content).as_bytes(),
        bindings.view_commitment_hash,
        "test helper view content hash must match"
    );
    cas.store(view_content).expect("view commitment CAS store");

    let tool_log_content = b"tool-log-index-entries";
    assert_eq!(
        *blake3::hash(tool_log_content).as_bytes(),
        bindings.tool_log_index_hash,
        "test helper tool log hash must match"
    );
    cas.store(tool_log_content)
        .expect("tool log index CAS store");

    let summary_content = b"summary-receipt-artifact";
    assert_eq!(
        *blake3::hash(summary_content).as_bytes(),
        bindings.summary_receipt_hash,
        "test helper summary receipt hash must match"
    );
    cas.store(summary_content)
        .expect("summary receipt CAS store");

    cas
}

fn valid_outcome_bindings() -> ReviewOutcomeBindings {
    ReviewOutcomeBindings {
        view_commitment_hash: *blake3::hash(b"view-commitment-snapshot").as_bytes(),
        tool_log_index_hash: *blake3::hash(b"tool-log-index-entries").as_bytes(),
        summary_receipt_hash: *blake3::hash(b"summary-receipt-artifact").as_bytes(),
    }
}

// ============================================================================
// AC-1: Transitions rejected when required authority bindings are missing
// ============================================================================

/// IT-00416-01: Valid authority bindings pass validation.
#[test]
fn test_valid_authority_bindings_pass_validation() {
    let work_id = "W-416-VALID";
    let bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &bindings);

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_ok(),
        "valid bindings must pass validation, got: {result:?}"
    );
}

/// IT-00416-02: Empty lease_id is rejected.
#[test]
fn test_empty_lease_id_rejected() {
    let work_id = "W-416-NOLEASE";
    let mut bindings = valid_bindings(work_id);
    bindings.lease_id = String::new();

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(result.is_err(), "empty lease_id must be rejected");

    let err = result.unwrap_err();
    assert!(
        err.violations.iter().any(|v| v.contains("lease_id")),
        "violation must mention lease_id: {err:?}"
    );
}

/// IT-00416-03: Empty actor_id is rejected.
#[test]
fn test_empty_actor_id_rejected() {
    let work_id = "W-416-NOACTOR";
    let mut bindings = valid_bindings(work_id);
    bindings.actor_id = String::new();

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(result.is_err(), "empty actor_id must be rejected");

    let err = result.unwrap_err();
    assert!(
        err.violations.iter().any(|v| v.contains("actor_id")),
        "violation must mention actor_id: {err:?}"
    );
}

/// IT-00416-04: Empty policy_resolved_ref is rejected.
#[test]
fn test_empty_policy_resolved_ref_rejected() {
    let work_id = "W-416-NOPOLICY";
    let mut bindings = valid_bindings(work_id);
    bindings.policy_resolved_ref = String::new();

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "empty policy_resolved_ref must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("policy_resolved_ref")),
        "violation must mention policy_resolved_ref: {err:?}"
    );
}

/// IT-00416-05: Zero permeability_receipt_hash is rejected.
#[test]
fn test_zero_permeability_receipt_hash_rejected() {
    let work_id = "W-416-NOPERM";
    let mut bindings = valid_bindings(work_id);
    bindings.permeability_receipt_hash = [0u8; 32];

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "zero permeability_receipt_hash must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("permeability_receipt_hash")),
        "violation must mention permeability_receipt_hash: {err:?}"
    );
}

/// IT-00416-06: Zero capability_manifest_hash is rejected.
#[test]
fn test_zero_capability_manifest_hash_rejected() {
    let work_id = "W-416-NOCAP";
    let mut bindings = valid_bindings(work_id);
    bindings.capability_manifest_hash = [0u8; 32];

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "zero capability_manifest_hash must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("capability_manifest_hash")),
        "violation must mention capability_manifest_hash: {err:?}"
    );
}

/// IT-00416-07: Zero context_pack_hash is rejected.
#[test]
fn test_zero_context_pack_hash_rejected() {
    let work_id = "W-416-NOCTX";
    let mut bindings = valid_bindings(work_id);
    bindings.context_pack_hash = [0u8; 32];

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(result.is_err(), "zero context_pack_hash must be rejected");

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("context_pack_hash")),
        "violation must mention context_pack_hash: {err:?}"
    );
}

/// IT-00416-08: Zero stop_condition_hash is rejected.
#[test]
fn test_zero_stop_condition_hash_rejected() {
    let work_id = "W-416-NOSTOP";
    let mut bindings = valid_bindings(work_id);
    bindings.stop_condition_hash = [0u8; 32];

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(result.is_err(), "zero stop_condition_hash must be rejected");

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("stop_condition_hash")),
        "violation must mention stop_condition_hash: {err:?}"
    );
}

/// IT-00416-09: Zero typed_budget_hash is rejected.
#[test]
fn test_zero_typed_budget_hash_rejected() {
    let work_id = "W-416-NOBUDGET";
    let mut bindings = valid_bindings(work_id);
    bindings.typed_budget_hash = [0u8; 32];

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(result.is_err(), "zero typed_budget_hash must be rejected");

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("typed_budget_hash")),
        "violation must mention typed_budget_hash: {err:?}"
    );
}

/// IT-00416-10: Unspecified role (all-zero budgets) is rejected.
#[test]
fn test_unspecified_role_budgets_rejected() {
    let work_id = "W-416-UNSPEC";
    let mut bindings = valid_bindings(work_id);
    bindings.typed_budgets = TypedBudgetBindings {
        max_tokens: 0,
        max_tool_calls: 0,
        max_wall_ms: 0,
    };

    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(result.is_err(), "all-zero typed budgets must be rejected");

    let err = result.unwrap_err();
    assert!(
        err.violations.iter().any(|v| v.contains("all-zero limits")),
        "violation must mention all-zero limits: {err:?}"
    );
}

/// IT-00416-11: Multiple missing bindings produce multiple violations.
#[test]
fn test_multiple_missing_bindings_all_reported() {
    let bindings = TransitionAuthorityBindings {
        lease_id: String::new(),
        actor_id: String::new(),
        permeability_receipt_hash: [0u8; 32],
        capability_manifest_hash: [0u8; 32],
        context_pack_hash: [0u8; 32],
        stop_condition_hash: [0u8; 32],
        stop_conditions: StopConditions::max_episodes(1),
        typed_budgets: TypedBudgetBindings {
            max_tokens: 0,
            max_tool_calls: 0,
            max_wall_ms: 0,
        },
        typed_budget_hash: [0u8; 32],
        policy_resolved_ref: String::new(),
    };

    let cas = MemoryCas::new();

    let result = validate_transition_authority_bindings(&bindings, &cas);
    assert!(result.is_err(), "all-missing bindings must be rejected");

    let err = result.unwrap_err();
    // We expect at least 9 violations: lease_id, actor_id,
    // policy_resolved_ref, 5 zero hashes, and all-zero budgets.
    assert!(
        err.violations.len() >= 9,
        "expected at least 9 violations for all-missing bindings, got {}: {:?}",
        err.violations.len(),
        err.violations
    );
}

// ============================================================================
// AC-3: CAS resolvability checks (not deferred)
// ============================================================================

/// IT-00416-12: Non-zero hash that is NOT in CAS is rejected.
#[test]
fn test_non_zero_hash_not_in_cas_rejected() {
    let work_id = "W-416-NOCAS";
    let bindings = valid_bindings(work_id);

    // Empty CAS: nothing stored => all CAS lookups fail
    let cas = MemoryCas::new();

    let result = validate_transition_authority_bindings(&bindings, &cas);
    assert!(
        result.is_err(),
        "CAS-unresolvable bindings must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("not resolvable in CAS")),
        "at least one violation must mention CAS resolvability: {err:?}"
    );
}

/// IT-00416-13: Tampered stop_condition_hash (mismatch) is detected.
#[test]
fn test_stop_condition_hash_mismatch_detected() {
    let work_id = "W-416-TAMPER-STOP";
    let mut bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &bindings);

    // Tamper: set stop_condition_hash to something that doesn't match
    // canonical bytes of the stop_conditions.
    bindings.stop_condition_hash = [0xAA; 32];

    // Store the tampered hash's preimage so CAS lookup succeeds
    // (we want to test the re-derivation check, not CAS absence).
    let _ = cas.store(&[0xAA; 32]);

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "tampered stop_condition_hash must be detected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("stop_condition_hash mismatch")),
        "violation must mention stop_condition_hash mismatch: {err:?}"
    );
}

/// IT-00416-14: Tampered typed_budget_hash (mismatch) is detected.
#[test]
fn test_typed_budget_hash_mismatch_detected() {
    let work_id = "W-416-TAMPER-BUDGET";
    let mut bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &bindings);

    // Tamper: set typed_budget_hash to a non-matching value.
    bindings.typed_budget_hash = [0xBB; 32];

    // Store the tampered hash preimage so CAS lookup passes.
    let _ = cas.store(&[0xBB; 32]);

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "tampered typed_budget_hash must be detected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("typed_budget_hash mismatch")),
        "violation must mention typed_budget_hash mismatch: {err:?}"
    );
}

// ============================================================================
// AC-2: Review/projection outcome bindings
// ============================================================================

/// IT-00416-15: Valid review outcome bindings pass validation.
#[test]
fn test_valid_review_outcome_bindings_pass_validation() {
    let bindings = valid_outcome_bindings();
    let cas = cas_with_outcome_bindings(&bindings);

    let result = validate_review_outcome_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_ok(),
        "valid outcome bindings must pass validation, got: {result:?}"
    );
}

/// IT-00416-16: Zero view_commitment_hash is rejected.
#[test]
fn test_zero_view_commitment_hash_rejected() {
    let mut bindings = valid_outcome_bindings();
    bindings.view_commitment_hash = [0u8; 32];

    let cas = cas_with_outcome_bindings(&valid_outcome_bindings());

    let result = validate_review_outcome_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "zero view_commitment_hash must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("view_commitment_hash")),
        "violation must mention view_commitment_hash: {err:?}"
    );
}

/// IT-00416-17: Zero tool_log_index_hash is rejected.
#[test]
fn test_zero_tool_log_index_hash_rejected() {
    let mut bindings = valid_outcome_bindings();
    bindings.tool_log_index_hash = [0u8; 32];

    let cas = cas_with_outcome_bindings(&valid_outcome_bindings());

    let result = validate_review_outcome_bindings(&bindings, cas.as_ref());
    assert!(result.is_err(), "zero tool_log_index_hash must be rejected");

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("tool_log_index_hash")),
        "violation must mention tool_log_index_hash: {err:?}"
    );
}

/// IT-00416-18: Zero summary_receipt_hash is rejected.
#[test]
fn test_zero_summary_receipt_hash_rejected() {
    let mut bindings = valid_outcome_bindings();
    bindings.summary_receipt_hash = [0u8; 32];

    let cas = cas_with_outcome_bindings(&valid_outcome_bindings());

    let result = validate_review_outcome_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "zero summary_receipt_hash must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("summary_receipt_hash")),
        "violation must mention summary_receipt_hash: {err:?}"
    );
}

/// IT-00416-19: All three outcome hashes missing produces three violations.
#[test]
fn test_all_outcome_hashes_missing_three_violations() {
    let bindings = ReviewOutcomeBindings {
        view_commitment_hash: [0u8; 32],
        tool_log_index_hash: [0u8; 32],
        summary_receipt_hash: [0u8; 32],
    };

    let cas = MemoryCas::new();

    let result = validate_review_outcome_bindings(&bindings, &cas);
    assert!(
        result.is_err(),
        "all-zero outcome bindings must be rejected"
    );

    let err = result.unwrap_err();
    assert_eq!(
        err.violations.len(),
        3,
        "expected exactly 3 violations for all-zero outcome bindings, got: {:?}",
        err.violations
    );
}

/// IT-00416-20: Outcome hash present but not in CAS is rejected.
#[test]
fn test_outcome_hash_not_in_cas_rejected() {
    let bindings = valid_outcome_bindings();

    // Empty CAS
    let cas = MemoryCas::new();

    let result = validate_review_outcome_bindings(&bindings, &cas);
    assert!(
        result.is_err(),
        "CAS-unresolvable outcome bindings must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("not resolvable in CAS")),
        "violation must mention CAS resolvability: {err:?}"
    );
}

// ============================================================================
// Binding derivation and builder correctness
// ============================================================================

/// IT-00416-21: `derive_transition_authority_bindings` produces consistent
/// hashes across invocations (deterministic).
#[test]
fn test_derive_bindings_deterministic() {
    let cap_hash = *blake3::hash(b"capability-manifest-content").as_bytes();
    let ctx_hash = *blake3::hash(b"context-pack-content").as_bytes();

    let bindings_a = derive_transition_authority_bindings(
        "W-DET-A",
        "lease-001",
        "actor:det",
        WorkRole::Implementer,
        "policy-001",
        cap_hash,
        ctx_hash,
        StopConditions::max_episodes(5),
    )
    .expect("derivation A");

    let bindings_b = derive_transition_authority_bindings(
        "W-DET-A",
        "lease-001",
        "actor:det",
        WorkRole::Implementer,
        "policy-001",
        cap_hash,
        ctx_hash,
        StopConditions::max_episodes(5),
    )
    .expect("derivation B");

    assert_eq!(
        bindings_a, bindings_b,
        "same inputs must produce identical authority bindings"
    );
}

/// IT-00416-22: `derive_claim_transition_authority_bindings` uses default
/// stop conditions and matches manual derivation.
#[test]
fn test_derive_claim_bindings_matches_manual() {
    let cap_hash = *blake3::hash(b"capability-manifest-content").as_bytes();
    let ctx_hash = *blake3::hash(b"context-pack-content").as_bytes();

    let claim = WorkClaim {
        work_id: "W-CLAIM-001".to_string(),
        lease_id: "lease-claim-001".to_string(),
        actor_id: "actor:claimer".to_string(),
        role: WorkRole::Reviewer,
        policy_resolution: PolicyResolution {
            policy_resolved_ref: "policy-claim-001".to_string(),
            pcac_policy: None,
            pointer_only_waiver: None,
            resolved_policy_hash: [0xAA; 32],
            capability_manifest_hash: cap_hash,
            context_pack_hash: ctx_hash,
            role_spec_hash: [0u8; 32],
            context_pack_recipe_hash: [0u8; 32],
            resolved_risk_tier: 1,
            resolved_scope_baseline: None,
            expected_adapter_profile_hash: None,
        },
        executor_custody_domains: vec![],
        author_custody_domains: vec![],
        permeability_receipt: None,
    };

    let claim_bindings =
        derive_claim_transition_authority_bindings(&claim).expect("claim derivation");

    let default_stop = StopConditions {
        max_episodes: 1,
        escalation_predicate: String::new(),
        goal_predicate: String::new(),
        failure_predicate: String::new(),
    };
    let manual_bindings = derive_transition_authority_bindings(
        &claim.work_id,
        &claim.lease_id,
        &claim.actor_id,
        claim.role,
        &claim.policy_resolution.policy_resolved_ref,
        claim.policy_resolution.capability_manifest_hash,
        claim.policy_resolution.context_pack_hash,
        default_stop,
    )
    .expect("manual derivation");

    assert_eq!(
        claim_bindings, manual_bindings,
        "claim-shorthand must produce same bindings as manual derivation"
    );
}

/// IT-00416-23: `typed_budgets_for_role` returns non-zero budgets for
/// production roles and all-zero for Unspecified.
#[test]
fn test_typed_budgets_for_role_production_nonzero() {
    let production_roles = [
        WorkRole::Implementer,
        WorkRole::GateExecutor,
        WorkRole::Reviewer,
        WorkRole::Coordinator,
    ];

    for role in &production_roles {
        let budgets = typed_budgets_for_role(*role);
        assert!(
            budgets.max_tokens > 0,
            "role {role:?} must have nonzero max_tokens",
        );
        assert!(
            budgets.max_tool_calls > 0,
            "role {role:?} must have nonzero max_tool_calls",
        );
        assert!(
            budgets.max_wall_ms > 0,
            "role {role:?} must have nonzero max_wall_ms",
        );
    }

    let unspec = typed_budgets_for_role(WorkRole::Unspecified);
    assert_eq!(
        unspec.max_tokens, 0,
        "Unspecified must have zero max_tokens"
    );
    assert_eq!(
        unspec.max_tool_calls, 0,
        "Unspecified must have zero max_tool_calls"
    );
    assert_eq!(
        unspec.max_wall_ms, 0,
        "Unspecified must have zero max_wall_ms"
    );
}

// ============================================================================
// CAS store helper correctness
// ============================================================================

/// IT-00416-24: `store_authority_binding_artifacts` stores all required
/// preimages such that CAS-resolvability passes.
#[test]
fn test_store_authority_binding_artifacts_enables_cas_resolution() {
    let work_id = "W-416-STORE";
    let bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &bindings);

    // All hash bindings must be CAS-resolvable now.
    assert!(
        cas.exists(&bindings.permeability_receipt_hash)
            .expect("CAS exists"),
        "permeability_receipt_hash must be CAS-resolvable"
    );
    assert!(
        cas.exists(&bindings.stop_condition_hash)
            .expect("CAS exists"),
        "stop_condition_hash must be CAS-resolvable"
    );
    assert!(
        cas.exists(&bindings.typed_budget_hash).expect("CAS exists"),
        "typed_budget_hash must be CAS-resolvable"
    );
    assert!(
        cas.exists(&bindings.capability_manifest_hash)
            .expect("CAS exists"),
        "capability_manifest_hash must be CAS-resolvable"
    );
    assert!(
        cas.exists(&bindings.context_pack_hash).expect("CAS exists"),
        "context_pack_hash must be CAS-resolvable"
    );
}

// ============================================================================
// Payload serialization helpers
// ============================================================================

/// IT-00416-25: `append_transition_authority_fields` embeds all required
/// fields into the JSON payload.
#[test]
fn test_append_transition_authority_fields_complete() {
    use apm2_daemon::protocol::dispatch::append_transition_authority_fields;

    let work_id = "W-416-APPEND";
    let bindings = valid_bindings(work_id);

    let mut payload = serde_json::Map::new();
    append_transition_authority_fields(&mut payload, &bindings);

    let required_keys = [
        "lease_id",
        "permeability_receipt_hash",
        "capability_manifest_hash",
        "context_pack_hash",
        "stop_condition_hash",
        "typed_budgets",
        "typed_budget_hash",
        "policy_resolved_ref",
    ];

    for key in &required_keys {
        assert!(
            payload.contains_key(*key),
            "payload must contain key '{key}' after append_transition_authority_fields"
        );
    }
}

/// IT-00416-26: `append_review_outcome_fields` embeds all required
/// outcome fields into the JSON payload.
#[test]
fn test_append_review_outcome_fields_complete() {
    use apm2_daemon::protocol::dispatch::append_review_outcome_fields;

    let bindings = valid_outcome_bindings();
    let mut payload = serde_json::Map::new();
    append_review_outcome_fields(&mut payload, &bindings);

    let required_keys = [
        "view_commitment_hash",
        "tool_log_index_hash",
        "summary_receipt_hash",
    ];

    for key in &required_keys {
        assert!(
            payload.contains_key(*key),
            "payload must contain key '{key}' after append_review_outcome_fields"
        );
    }
}

// ============================================================================
// Error display and structure
// ============================================================================

/// IT-00416-27: TransitionAuthorityError Display includes violation count.
#[test]
fn test_transition_authority_error_display() {
    use apm2_daemon::protocol::dispatch::TransitionAuthorityError;

    let err = TransitionAuthorityError {
        message: "authority binding validation failed with 3 violation(s)".to_string(),
        violations: vec![
            "lease_id is empty".to_string(),
            "actor_id is empty".to_string(),
            "policy_resolved_ref is empty".to_string(),
        ],
    };

    let display = format!("{err}");
    assert!(
        display.contains("3 violation"),
        "Display must mention violation count: {display}"
    );
}

// ============================================================================
// Fail-closed semantics: best-effort success is forbidden
// ============================================================================

/// IT-00416-28: Even a single missing binding causes full rejection.
/// There is no partial-pass mode.
#[test]
fn test_single_missing_binding_full_rejection() {
    let work_id = "W-416-SINGLE";
    let mut bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &bindings);

    // Clear only one field
    bindings.policy_resolved_ref = String::new();

    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "single missing binding must cause full rejection (no partial pass)"
    );
}

/// IT-00416-29: Serde round-trip preserves TransitionAuthorityBindings.
#[test]
fn test_bindings_serde_round_trip() {
    let work_id = "W-416-SERDE";
    let bindings = valid_bindings(work_id);

    let json = serde_json::to_string(&bindings).expect("serialize");
    let deserialized: TransitionAuthorityBindings =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(
        bindings, deserialized,
        "serde round-trip must preserve all binding fields"
    );
}

/// IT-00416-30: Serde round-trip preserves ReviewOutcomeBindings.
#[test]
fn test_outcome_bindings_serde_round_trip() {
    let bindings = valid_outcome_bindings();

    let json = serde_json::to_string(&bindings).expect("serialize");
    let deserialized: ReviewOutcomeBindings = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(
        bindings, deserialized,
        "serde round-trip must preserve all outcome binding fields"
    );
}

// ============================================================================
// Round 2: BLOCKER 1 - validate_and_store_transition_authority enforces
// non-zero capability_manifest_hash and context_pack_hash
// ============================================================================

/// IT-00416-31: `validate_and_store_transition_authority` rejects zero
/// `capability_manifest_hash`.
#[test]
fn test_validate_and_store_rejects_zero_capability_manifest_hash() {
    let work_id = "W-416-STORE-NOCAP";
    let mut bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    bindings.capability_manifest_hash = [0u8; 32];

    let result = validate_and_store_transition_authority(work_id, &bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "zero capability_manifest_hash must be rejected by validate_and_store_transition_authority"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("capability_manifest_hash")),
        "violation must mention capability_manifest_hash: {err:?}"
    );
}

/// IT-00416-32: `validate_and_store_transition_authority` rejects zero
/// `context_pack_hash`.
#[test]
fn test_validate_and_store_rejects_zero_context_pack_hash() {
    let work_id = "W-416-STORE-NOCTX";
    let mut bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &valid_bindings(work_id));

    bindings.context_pack_hash = [0u8; 32];

    let result = validate_and_store_transition_authority(work_id, &bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "zero context_pack_hash must be rejected by validate_and_store_transition_authority"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("context_pack_hash")),
        "violation must mention context_pack_hash: {err:?}"
    );
}

/// IT-00416-33: `validate_and_store_transition_authority` passes with valid
/// bindings (including non-zero capability_manifest_hash and
/// context_pack_hash).
#[test]
fn test_validate_and_store_passes_with_valid_bindings() {
    let work_id = "W-416-STORE-VALID";
    let bindings = valid_bindings(work_id);
    let cas = cas_with_stored_bindings(work_id, &bindings);

    let result = validate_and_store_transition_authority(work_id, &bindings, cas.as_ref());
    assert!(
        result.is_ok(),
        "valid bindings must pass validate_and_store_transition_authority, got: {result:?}"
    );
}

// ============================================================================
// Round 2: BLOCKER 2 + MAJOR - domain-tagged outcome binding derivation
// ============================================================================

/// IT-00416-34: `derive_review_outcome_bindings` produces three non-zero
/// independent hashes.
#[test]
fn test_derive_review_outcome_bindings_nonzero() {
    let changeset_digest = [0xAA; 32];
    let artifact_bundle_hash = [0xBB; 32];
    let receipt_id = "receipt-test-001";

    let bindings =
        derive_review_outcome_bindings(&changeset_digest, &artifact_bundle_hash, receipt_id);

    assert_ne!(
        bindings.view_commitment_hash, [0u8; 32],
        "view_commitment_hash must be non-zero"
    );
    assert_ne!(
        bindings.tool_log_index_hash, [0u8; 32],
        "tool_log_index_hash must be non-zero"
    );
    assert_ne!(
        bindings.summary_receipt_hash, [0u8; 32],
        "summary_receipt_hash must be non-zero"
    );
}

/// IT-00416-35: `derive_review_outcome_bindings` produces independent hashes
/// (no two are the same, no raw aliasing).
#[test]
fn test_derive_review_outcome_bindings_independent() {
    let changeset_digest = [0xAA; 32];
    let artifact_bundle_hash = [0xBB; 32];
    let receipt_id = "receipt-test-002";

    let bindings =
        derive_review_outcome_bindings(&changeset_digest, &artifact_bundle_hash, receipt_id);

    // All three hashes must be distinct (no aliasing)
    assert_ne!(
        bindings.view_commitment_hash, bindings.tool_log_index_hash,
        "view_commitment_hash and tool_log_index_hash must be independent"
    );
    assert_ne!(
        bindings.view_commitment_hash, bindings.summary_receipt_hash,
        "view_commitment_hash and summary_receipt_hash must be independent"
    );
    assert_ne!(
        bindings.tool_log_index_hash, bindings.summary_receipt_hash,
        "tool_log_index_hash and summary_receipt_hash must be independent"
    );

    // None should be raw changeset_digest
    assert_ne!(
        bindings.view_commitment_hash, changeset_digest,
        "view_commitment_hash must NOT be raw changeset_digest (MAJOR fix)"
    );

    // None should be raw artifact_bundle_hash
    assert_ne!(
        bindings.summary_receipt_hash, artifact_bundle_hash,
        "summary_receipt_hash must NOT be raw artifact_bundle_hash (MAJOR fix)"
    );
}

/// IT-00416-36: `derive_review_outcome_bindings` is deterministic.
#[test]
fn test_derive_review_outcome_bindings_deterministic() {
    let changeset_digest = [0xCC; 32];
    let artifact_bundle_hash = [0xDD; 32];
    let receipt_id = "receipt-det-001";

    let a = derive_review_outcome_bindings(&changeset_digest, &artifact_bundle_hash, receipt_id);
    let b = derive_review_outcome_bindings(&changeset_digest, &artifact_bundle_hash, receipt_id);

    assert_eq!(a, b, "same inputs must produce identical outcome bindings");
}

/// IT-00416-37: `store_review_outcome_artifacts` enables CAS resolution for
/// derived outcome bindings.
#[test]
fn test_store_review_outcome_artifacts_enables_cas_resolution() {
    let changeset_digest = [0xEE; 32];
    let artifact_bundle_hash = [0xFF; 32];
    let receipt_id = "receipt-cas-001";

    let cas = Arc::new(MemoryCas::new());
    store_review_outcome_artifacts(
        &changeset_digest,
        &artifact_bundle_hash,
        receipt_id,
        cas.as_ref(),
    )
    .expect("CAS store should succeed");

    let bindings =
        derive_review_outcome_bindings(&changeset_digest, &artifact_bundle_hash, receipt_id);

    // All three derived hashes must now be CAS-resolvable
    assert!(
        cas.exists(&bindings.view_commitment_hash)
            .expect("CAS exists"),
        "view_commitment_hash must be CAS-resolvable after store"
    );
    assert!(
        cas.exists(&bindings.tool_log_index_hash)
            .expect("CAS exists"),
        "tool_log_index_hash must be CAS-resolvable after store"
    );
    assert!(
        cas.exists(&bindings.summary_receipt_hash)
            .expect("CAS exists"),
        "summary_receipt_hash must be CAS-resolvable after store"
    );

    // Full validation must pass
    let result = validate_review_outcome_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_ok(),
        "derived + stored outcome bindings must pass full validation, got: {result:?}"
    );
}

// ============================================================================
// Round 2: BLOCKER 3 - authority fields persisted in signed event payloads
// ============================================================================

/// IT-00416-38: `emit_work_claimed` includes transition authority binding
/// fields in the signed event payload.
#[test]
fn test_emit_work_claimed_includes_authority_fields() {
    use apm2_daemon::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};

    let cap_hash = *blake3::hash(b"capability-manifest-content").as_bytes();
    let ctx_hash = *blake3::hash(b"context-pack-content").as_bytes();

    let claim = WorkClaim {
        work_id: "W-416-EMIT-CLAIM".to_string(),
        lease_id: "lease-emit-001".to_string(),
        actor_id: "actor:emit-test".to_string(),
        role: WorkRole::Implementer,
        policy_resolution: PolicyResolution {
            policy_resolved_ref: "policy-emit-001".to_string(),
            pcac_policy: None,
            pointer_only_waiver: None,
            resolved_policy_hash: [0xAA; 32],
            capability_manifest_hash: cap_hash,
            context_pack_hash: ctx_hash,
            role_spec_hash: [0u8; 32],
            context_pack_recipe_hash: [0u8; 32],
            resolved_risk_tier: 1,
            resolved_scope_baseline: None,
            expected_adapter_profile_hash: None,
        },
        executor_custody_domains: vec![],
        author_custody_domains: vec![],
        permeability_receipt: None,
    };

    let emitter = StubLedgerEventEmitter::new();
    let event = emitter
        .emit_work_claimed(&claim, 1_000_000)
        .expect("emit_work_claimed should succeed");

    // Parse the payload and verify authority binding fields are present
    let payload_str = std::str::from_utf8(&event.payload).expect("payload should be valid UTF-8");
    let payload_json: serde_json::Value =
        serde_json::from_str(payload_str).expect("payload should be valid JSON");

    let required_authority_fields = [
        "lease_id",
        "permeability_receipt_hash",
        "capability_manifest_hash",
        "context_pack_hash",
        "stop_condition_hash",
        "typed_budgets",
        "typed_budget_hash",
        "policy_resolved_ref",
    ];

    for field in &required_authority_fields {
        assert!(
            payload_json.get(field).is_some(),
            "signed event payload must contain authority field '{field}' \
             (TCK-00416 BLOCKER 3). Payload: {payload_str}"
        );
    }
}

/// IT-00416-39: `emit_review_receipt` includes review outcome binding
/// fields in the signed event payload.
#[test]
fn test_emit_review_receipt_includes_outcome_fields() {
    use apm2_daemon::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};

    let changeset_digest = [0x11; 32];
    let artifact_bundle_hash = [0x22; 32];
    let capability_manifest_hash = [0x23; 32];
    let context_pack_hash = [0x24; 32];
    let role_spec_hash = [0x25; 32];
    let identity_proof_hash = [0x33; 32];
    let receipt_id = "receipt-emit-001";

    let emitter = StubLedgerEventEmitter::new();
    let event = emitter
        .emit_review_receipt(
            "lease-001",
            "W-REVIEW-EMIT-001",
            receipt_id,
            &changeset_digest,
            &artifact_bundle_hash,
            &capability_manifest_hash,
            &context_pack_hash,
            &role_spec_hash,
            "actor:reviewer",
            2_000_000,
            &identity_proof_hash,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
        )
        .expect("emit_review_receipt should succeed");

    // Parse the payload and verify outcome binding fields are present
    let payload_str = std::str::from_utf8(&event.payload).expect("payload should be valid UTF-8");
    let payload_json: serde_json::Value =
        serde_json::from_str(payload_str).expect("payload should be valid JSON");

    let required_outcome_fields = [
        "view_commitment_hash",
        "tool_log_index_hash",
        "summary_receipt_hash",
    ];

    for field in &required_outcome_fields {
        assert!(
            payload_json.get(field).is_some(),
            "signed review receipt payload must contain outcome field '{field}' \
             (TCK-00416 BLOCKER 3). Payload: {payload_str}"
        );
    }

    // Verify outcome fields are non-zero hex strings (not aliased to raw source
    // fields)
    let view_hash = payload_json["view_commitment_hash"]
        .as_str()
        .expect("view_commitment_hash must be a string");
    let changeset_hex = hex::encode(changeset_digest);
    assert_ne!(
        view_hash, changeset_hex,
        "view_commitment_hash must NOT be raw changeset_digest (MAJOR aliasing fix)"
    );
}

/// IT-00416-40: `emit_review_blocked_receipt` includes review outcome binding
/// fields in the signed event payload.
#[test]
fn test_emit_review_blocked_receipt_includes_outcome_fields() {
    use apm2_daemon::protocol::dispatch::{LedgerEventEmitter, StubLedgerEventEmitter};

    let changeset_digest = [0x44; 32];
    let artifact_bundle_hash = [0x55; 32];
    let capability_manifest_hash = [0x56; 32];
    let context_pack_hash = [0x57; 32];
    let role_spec_hash = [0x58; 32];
    let blocked_log_hash = [0x66; 32];
    let identity_proof_hash = [0x77; 32];
    let receipt_id = "receipt-blocked-001";

    let emitter = StubLedgerEventEmitter::new();
    let event = emitter
        .emit_review_blocked_receipt(
            "lease-blocked-001",
            "W-REVIEW-BLOCKED-001",
            receipt_id,
            &changeset_digest,
            &artifact_bundle_hash,
            &capability_manifest_hash,
            &context_pack_hash,
            &role_spec_hash,
            1, // reason_code
            &blocked_log_hash,
            "actor:reviewer",
            3_000_000,
            &identity_proof_hash,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            None,
        )
        .expect("emit_review_blocked_receipt should succeed");

    // Parse the payload and verify outcome binding fields are present
    let payload_str = std::str::from_utf8(&event.payload).expect("payload should be valid UTF-8");
    let payload_json: serde_json::Value =
        serde_json::from_str(payload_str).expect("payload should be valid JSON");

    let required_outcome_fields = [
        "view_commitment_hash",
        "tool_log_index_hash",
        "summary_receipt_hash",
    ];

    for field in &required_outcome_fields {
        assert!(
            payload_json.get(field).is_some(),
            "signed blocked receipt payload must contain outcome field '{field}' \
             (TCK-00416 BLOCKER 3). Payload: {payload_str}"
        );
    }
}

/// IT-00416-41: Both standalone and handler-level validators enforce CAS
/// resolvability for capability_manifest_hash and context_pack_hash
/// (REQ-HEF-0013).
#[test]
fn test_standalone_validator_checks_cas_for_manifest_and_context() {
    let work_id = "W-416-CAS-CHECK";
    let bindings = valid_bindings(work_id);

    // Create CAS with only the self-derived artifacts (permeability, stop, budget)
    // but NOT the policy-provided ones (manifest, context).
    let cas = Arc::new(MemoryCas::new());
    store_authority_binding_artifacts(work_id, &bindings, cas.as_ref())
        .expect("self-derived CAS store should succeed");

    // The standalone validator checks CAS resolvability for ALL hashes
    // including policy-provided ones.
    let result = validate_transition_authority_bindings(&bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "missing manifest/context CAS artifacts must be rejected by standalone validator"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("capability_manifest_hash") && v.contains("not resolvable")),
        "violation must mention capability_manifest_hash CAS resolvability: {err:?}"
    );
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("context_pack_hash") && v.contains("not resolvable")),
        "violation must mention context_pack_hash CAS resolvability: {err:?}"
    );
}

// ============================================================================
// Handler-path negative tests: validate_and_store_transition_authority
// rejects non-zero hashes absent from CAS (REQ-HEF-0013)
// ============================================================================

/// IT-00416-42: `validate_and_store_transition_authority` rejects
/// `capability_manifest_hash` that is non-zero but absent from CAS.
///
/// This exercises the handler-level validator used by both `ClaimWork`
/// and `SpawnEpisode`. Self-derived hashes are stored by the function
/// itself, but policy-provided hashes MUST be pre-seeded by the caller.
/// When the manifest hash is absent, validation must fail.
#[test]
fn test_handler_validator_rejects_manifest_hash_absent_from_cas() {
    let work_id = "W-416-HANDLER-NOCAP";
    let bindings = valid_bindings(work_id);

    // Store ONLY self-derived artifacts + context_pack preimage,
    // but NOT the capability_manifest preimage.
    let cas = Arc::new(MemoryCas::new());
    store_authority_binding_artifacts(work_id, &bindings, cas.as_ref())
        .expect("self-derived CAS store should succeed");

    // Store context_pack preimage so it passes, isolating the manifest failure.
    let context_payload = b"context-pack-content";
    cas.store(context_payload).expect("context pack CAS store");

    let result = validate_and_store_transition_authority(work_id, &bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "handler-level validator must reject when capability_manifest_hash is absent from CAS"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("capability_manifest_hash") && v.contains("not resolvable")),
        "violation must mention capability_manifest_hash CAS absence: {err:?}"
    );
}

/// IT-00416-43: `validate_and_store_transition_authority` rejects
/// `context_pack_hash` that is non-zero but absent from CAS.
///
/// Same handler-level validator path. Capability manifest preimage IS
/// stored; only the context pack is missing.
#[test]
fn test_handler_validator_rejects_context_pack_hash_absent_from_cas() {
    let work_id = "W-416-HANDLER-NOCTX";
    let bindings = valid_bindings(work_id);

    // Store self-derived artifacts + capability_manifest preimage,
    // but NOT the context_pack preimage.
    let cas = Arc::new(MemoryCas::new());
    store_authority_binding_artifacts(work_id, &bindings, cas.as_ref())
        .expect("self-derived CAS store should succeed");

    // Store capability_manifest preimage so it passes.
    let manifest_payload = b"capability-manifest-content";
    cas.store(manifest_payload)
        .expect("capability manifest CAS store");

    let result = validate_and_store_transition_authority(work_id, &bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "handler-level validator must reject when context_pack_hash is absent from CAS"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("context_pack_hash") && v.contains("not resolvable")),
        "violation must mention context_pack_hash CAS absence: {err:?}"
    );
}

/// IT-00416-44: `validate_and_store_transition_authority` rejects when
/// BOTH `capability_manifest_hash` and `context_pack_hash` are non-zero
/// but absent from CAS. Both violations must be reported.
#[test]
fn test_handler_validator_rejects_both_policy_hashes_absent_from_cas() {
    let work_id = "W-416-HANDLER-BOTH";
    let bindings = valid_bindings(work_id);

    // Only store self-derived artifacts; no policy artifacts.
    let cas = Arc::new(MemoryCas::new());
    store_authority_binding_artifacts(work_id, &bindings, cas.as_ref())
        .expect("self-derived CAS store should succeed");

    let result = validate_and_store_transition_authority(work_id, &bindings, cas.as_ref());
    assert!(
        result.is_err(),
        "handler-level validator must reject when both policy hashes are absent from CAS"
    );

    let err = result.unwrap_err();
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("capability_manifest_hash") && v.contains("not resolvable")),
        "must report capability_manifest_hash CAS absence: {err:?}"
    );
    assert!(
        err.violations
            .iter()
            .any(|v| v.contains("context_pack_hash") && v.contains("not resolvable")),
        "must report context_pack_hash CAS absence: {err:?}"
    );
}
