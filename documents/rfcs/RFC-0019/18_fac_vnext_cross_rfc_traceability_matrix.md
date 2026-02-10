# RFC-0019 Addendum - FAC vNext Cross-RFC Traceability Matrix

Status: Draft
Purpose: provide a single cross-RFC mapping from theory laws to requirements, predicates, gates, and evidence for FAC vNext.

## 1. Matrix Rules

- References MUST be fully qualified (`RFC-XXXX::REQ-YYYY`, `RFC-XXXX::EVID-ZZZZ`).
- Every row MUST map to at least one machine predicate and one gate.
- Promotion-critical rows MUST include independent verifier evidence for Tier2+.
- Temporal claims MUST bind to typed contract fields (`TemporalSloProfileV1`, `ProjectionContinuityWindowV1`, `TimeAuthorityEnvelopeV1`).
- Temporal claims MUST include `baseline`, `target`, `boundary authority ref`, `falsification predicate`, `fail-closed mode`, and a signed time-authority artifact reference.
- Promotion-critical claims MUST declare CAC overlay fields: `schema_id`, `schema_major`, `contract_digest_set` membership, canonicalizer tuple, and Tier2+ fail-closed trigger conditions.

## 2. Traceability Matrix

| Claim ID | Theory Anchors | RFC Requirement Anchors | Machine Predicate(s) | Gate(s) | Evidence Anchors |
|---|---|---|---|---|---|
| `TRC-FAC-01` Authority continuity before effect | `LAW-01`, `LAW-15` | `RFC-0027::REQ-0001`, `RFC-0027::REQ-0002`, `RFC-0027::REQ-0018` | `pcac_join_valid`, `pcac_revalidate_valid`, `pcac_consume_valid`, `pcac_effect_guarded` | `GATE-PCAC-SNAPSHOT-VALIDITY`, `GATE-SIO28-LIFECYCLE` | `RFC-0027::EVID-0001`, `RFC-0027::EVID-0010` |
| `TRC-FAC-02` Revocation/freshness dominance | `LAW-09`, `LAW-20` | `RFC-0027::REQ-0003`, `RFC-0027::REQ-0008`, `RFC-0027::REQ-0010`, `RFC-0016::REQ-HTF-0003` | `pcac_revalidate_valid`, `pcac_revocation_dominant`, `revocation_frontier_monotone` | `GATE-SIO28-REVOCATION`, `GATE-EIO29-TEMPORAL-MONOTONICITY` | `RFC-0027::EVID-0008`, `RFC-0029::EVID-0009` |
| `TRC-FAC-03` Boundary information-flow safety | `LAW-05`, `LAW-16` | `RFC-0028::REQ-0004`, `RFC-0020::REQ-0029`, `RFC-0020::REQ-0030`, `RFC-0020::REQ-0032` | `boundary_flow_admissible` | `GATE-SIO28-BOUNDARY-FLOW` | `RFC-0028::EVID-0004` |
| `TRC-FAC-04` Projection non-interference | `LAW-03`, `LAW-16` | `RFC-0027::REQ-0006`, `RFC-0028::REQ-0006` | `projection_noninterference_valid` | `GATE-SIO28-PROJECTION-NONINTERFERENCE` | `RFC-0027::EVID-0006` |
| `TRC-FAC-05` Verifier independence | `LAW-19`, `LAW-08` | `RFC-0027::REQ-0011`, `RFC-0027::REQ-0014`, `RFC-0027::REQ-0016` | `correlation_risk_score <= threshold(risk_tier)` | `GATE-SIO28-VERIFIER-INDEPENDENCE` | `RFC-0027::EVID-0005`, `RFC-0027::EVID-0010` |
| `TRC-FAC-06` Safety-constrained optimization | `LAW-08`, `LAW-14` | `RFC-0029::REQ-0006`, `RFC-0029::REQ-0005` | `delta(C_total) < 0 => hard_safety_non_regression` | `GATE-EIO29-INTERLOCK`, `GATE-EIO29-COUNTERMETRICS` | `RFC-0029::EVID-0006` |
| `TRC-FAC-07` Queue and control-path stability | `LAW-14`, `LAW-06` | `RFC-0029::REQ-0004`, `RFC-0018::REQ-HEF-0018`, `RFC-0016::REQ-HTF-0003` | `rho < rho_max(risk_tier) && tick_floor_met(stop_revoke_lane, control_window_ref)` | `GATE-EIO29-QUEUE-STABILITY` | `RFC-0029::EVID-0004` |
| `TRC-FAC-08` Recoverability under adversarial loss | `LAW-10`, `LAW-15` | `RFC-0029::REQ-0005` | `recoverability_evidence_current` | `GATE-EIO29-REDUNDANCY-RECOVERABILITY` | `RFC-0029::EVID-0005` |
| `TRC-FAC-09` Constrained autonomic CVE closure | `LAW-01`, `LAW-08`, `LAW-19` | `RFC-0028::REQ-0006`, `RFC-0029::REQ-0006`, `RFC-0019::REQ-0014` | `vuln_class_allowlisted && canary_non_regression && independent_rerun_pass` | `GATE-FAC-AUTOREMEDIATION-CANARY`, `GATE-FAC-AUTOREMEDIATION-INDEPENDENT-RERUN` | `RFC-0027::EVID-0010`, `RFC-0029::EVID-0006` |
| `TRC-FAC-10` RoleSpec speciation with non-regression | `LAW-01`, `LAW-02`, `LAW-19` | `RFC-0027::REQ-0012`, `RFC-0027::REQ-0014`, `RFC-0019::REQ-0016`, `RFC-0019::REQ-0013`, `RFC-0019::REQ-0014` | `specialization_gain && pcac_consume_deny_correctness_not_worse && rolespec_context_injection_deterministic && rolespec_context_minimality_enforced` | `GATE-SIO28-VERIFIER-INDEPENDENCE`, `GATE-EIO29-INTERLOCK`, `GATE-EIO29-BOUNDS` | `RFC-0027::EVID-0009`, `RFC-0019::EVID-0012`, `RFC-0019::EVID-0014` |
| `TRC-FAC-11` Delegation meet exactness | `LAW-16`, `LAW-20` | `RFC-0027::REQ-0004`, `RFC-0028::REQ-0003` | `delegation_meet_exact_valid` | `GATE-SIO28-DELEGATION-MEET-EXACTNESS` | `RFC-0028::EVID-0003` |
| `TRC-FAC-12` Projection authority isolation | `LAW-05`, `LAW-15`, `LAW-20` | `RFC-0028::REQ-0008`, `RFC-0019::REQ-0007`, `RFC-0029::REQ-0008` | `pcac_projection_isolation_valid` | `GATE-SIO28-PROJECTION-ISOLATION`, `GATE-EIO29-PROJECTION-ISOLATION-INTERLOCK` | `RFC-0028::EVID-0008`, `RFC-0029::EVID-0008` |
| `TRC-FAC-13` Projection compromise non-propagation | `LAW-05`, `LAW-15`, `LAW-20` | `RFC-0028::REQ-0009` | `projection_compromise_contained` | `GATE-SIO28-PROJECTION-COMPROMISE-CONTAINMENT` | `RFC-0028::EVID-0009` |
| `TRC-FAC-14` Projection sink independence and outage continuity | `LAW-03`, `LAW-14`, `LAW-15` | `RFC-0029::REQ-0009`, `RFC-0016::REQ-HTF-0003`, `RFC-0016::REQ-HTF-0007` | `time_authority_envelope_valid && projection_sink_independence_valid && projection_multi_sink_continuity_valid && projection_backlog_replay_bounded` | `GATE-EIO29-TIME-AUTHORITY`, `GATE-EIO29-PROJECTION-SINK-CONTINUITY` | `RFC-0029::EVID-0009` |
| `TRC-FAC-15` Erasure+BFT reconstruction admissibility | `LAW-10`, `LAW-15`, `LAW-19` | `RFC-0029::REQ-0010`, `RFC-0016::REQ-HTF-0003` | `reconstruction_integrity_valid && recovery_receipt_valid` | `GATE-EIO29-RECONSTRUCTION-ADMISSIBILITY` | `RFC-0029::EVID-0010` |
| `TRC-FAC-16` Temporal monotonicity and ambiguity deny | `LAW-09`, `LAW-15`, `LAW-20` | `RFC-0029::REQ-0009`, `RFC-0029::REQ-0005`, `RFC-0016::REQ-HTF-0003` | `revocation_frontier_monotone && replay_idempotency_monotone && promotion_temporal_ambiguity == false` | `GATE-EIO29-TEMPORAL-MONOTONICITY`, `GATE-EIO29-INTERLOCK` | `RFC-0029::EVID-0005`, `RFC-0029::EVID-0009` |

### 2.1 Temporal Contract Overlay Matrix

Temporal contract namespace note:
- `TP-EIO29-*` IDs are shared promotion-critical temporal contracts anchored by RFC-0016 semantics and RFC-0019 snapshot contract ownership.
- RFC-0029 provides the temporal-economics evaluation profile for those IDs.

| Claim ID | Contract ID(s) | Baseline | Target | Boundary Authority Ref | Signed Time Authority Artifact | Falsification Predicate | Fail-Closed Mode | RFC-0016 Semantic Anchor |
|---|---|---|---|---|---|---|---|---|
| `TRC-FAC-07` | `TP-EIO29-001`, `TP-EIO29-002` | `TemporalSloProfileV1.baseline` for queue fairness | `tick_floor_met(stop_revoke_lane, control_window_ref) == true` | `TimeAuthorityEnvelopeV1(htf_boundary_id, authority_clock)` | `TimeAuthorityEnvelopeV1.signature_set` | `critical_path_wait_ticks > queue_budget.stop_revoke_max_wait_ticks` | deny `GATE-EIO29-QUEUE-STABILITY` | `RFC-0016::REQ-HTF-0003` |
| `TRC-FAC-14` | `TP-EIO29-001`, `TP-EIO29-003`, `TP-EIO29-004`, `TP-EIO29-005` | `ProjectionContinuityWindowV1.outage_window_ref` | `projection_multi_sink_continuity_valid == true` | `TimeAuthorityEnvelopeV1(htf_boundary_id, authority_clock)` | `TimeAuthorityEnvelopeV1.signature_set` | `exists scenario in sink_failure_set(N): authoritative_flow_continues == false` | deny `GATE-EIO29-PROJECTION-SINK-CONTINUITY` | `RFC-0016::REQ-HTF-0003`, `RFC-0016::REQ-HTF-0007` |
| `TRC-FAC-15` | `TP-EIO29-001`, `TP-EIO29-004` | `RecoveryAdmissibilityReceiptV1.window_ref` | `recovery_receipt_valid && reconstructed_digest_match` | `RecoveryAdmissibilityReceiptV1.time_authority_ref` | `RecoveryAdmissibilityReceiptV1.time_authority_ref -> TimeAuthorityEnvelopeV1.signature_set` | `!bft_quorum_recovery_valid || digest_mismatch || invalid_time_authority` | deny `GATE-EIO29-RECONSTRUCTION-ADMISSIBILITY` | `RFC-0016::REQ-HTF-0003` |
| `TRC-FAC-16` | `TP-EIO29-006`, `TP-EIO29-007`, `TP-EIO29-008` | adjacent HTF windows (`W_t`, `W_t+1`) | `revocation_frontier_monotone && replay_idempotency_monotone` | `TimeAuthorityEnvelopeV1(htf_boundary_id, authority_clock)` | `TimeAuthorityEnvelopeV1.signature_set` | `stale_window_outcome_dominates_fresh_window_outcome` | deny promotion via `GATE-EIO29-TEMPORAL-MONOTONICITY` | `RFC-0016::REQ-HTF-0003` |

### 2.2 CAC Contract Overlay Matrix (Promotion-Critical)

| Claim ID | CAC Schema Contracts (`schema_id`) | `contract_digest_set` Binding | Canonicalizer Binding | Tier2+ Fail-Closed Trigger |
|---|---|---|---|---|
| `TRC-FAC-01` | `apm2.pcac_snapshot_report.v1`, `apm2.authority_kernel_decision.v1` | lifecycle stage digests (`join`, `revalidate`, `consume`, `effect`) MUST be complete in one set | tuple MUST match snapshot canonicalizer tuple | any `CAC_DIGEST_SET_INCOMPLETE` or `CAC_DIGEST_MISMATCH` -> deny + freeze |
| `TRC-FAC-02` | `apm2.time_authority_envelope.v1`, `apm2.revocation_frontier_snapshot.v1` | adjacent-window frontier digests MUST bind to shared `time_authority_ref` | tuple mismatch across envelope/frontier is non-admissible | `CAC_SCHEMA_UNRESOLVED`, `CAC_INPUT_STALE`, or tuple mismatch -> deny + freeze |
| `TRC-FAC-07` | `apm2.temporal_slo_profile.v1`, `apm2.projection_continuity_window.v1`, `apm2.time_authority_envelope.v1` | queue/floor digests MUST bind to identical `boundary_id` + `authority_clock` | all three artifacts MUST share one canonicalizer tuple | unresolved schema or missing digest -> deny `GATE-EIO29-QUEUE-STABILITY` + freeze |
| `TRC-FAC-10` | `cac.holon_contract.v1`, `cac.context_pack_spec.v1`, `cac.context_pack_manifest.v1`, `cac.reasoning_selector.v1`, `cac.budget_profile.v1`, `cac.run_receipt.v1` | RoleSpec + context selector digest set MUST be complete and equal to run receipt bindings (`role_spec_hash`, `context_pack_manifest_hash`) | RoleSpec/context artifacts and run receipt MUST use canonicalizer vectors compatible with active snapshot tuple | selector closure mismatch or ambient context read evidence -> deny `GATE-EIO29-BOUNDS` + freeze |
| `TRC-FAC-12` | `apm2.projection_isolation_policy.v1`, `apm2.sink_identity_snapshot.v1` | authority-surface digest MUST chain to sink identity digest and trust snapshot | tuple mismatch between isolation policy and sink snapshot denies | any CAC defect on isolation inputs -> deny both isolation gates + freeze |
| `TRC-FAC-14` | `apm2.projection_sink_continuity_profile.v1`, `apm2.projection_continuity_window.v1`, `apm2.time_authority_envelope.v1` | outage/replay horizon digests MUST be complete and window-aligned | canonicalizer vectors MUST match active snapshot vectors | `CAC_VALIDATION_ORDER_VIOLATION` or missing digest -> deny + freeze |
| `TRC-FAC-15` | `apm2.erasure_recovery_receipt.v1`, `apm2.bft_recovery_quorum_certificate.v1`, `apm2.recovery_admissibility_receipt.v1`, `apm2.source_trust_snapshot.v1` | decode/quorum/digest-match/time-authority digests all required in one set | reconstruction artifacts MUST share canonicalizer tuple with trust snapshot | any missing reconstruction digest or signature defect -> deny + freeze |
| `TRC-FAC-16` | `apm2.revocation_frontier_snapshot.v1`, `apm2.replay_convergence_receipt.v1`, `apm2.temporal_disagreement_receipt.v1`, `apm2.temporal_arbitration_receipt.v1`, `apm2.temporal_predicate_evaluator.v1` | monotonicity verdict digests MUST cover `TP-EIO29-006..008` evaluator outputs and arbitration outcome | evaluator/disagreement/arbitration receipts MUST use identical canonicalizer vectors | ambiguity or arbitration unresolved at `cac_adjudication_deadline_window_ref` -> deny + freeze then halt escalation |

## 3. Necessity Matrix

### 3.1 If PCAC kernel is removed

- Authority continuity becomes path-specific and non-uniform.
- Single-consume and intent-equality proofs degrade to handler-local assumptions.
- Revocation/freshness behavior loses globally consistent fail-closed semantics.

### 3.2 If boundary-flow controls are removed

- Injection-to-actuation and exfiltration risks remain admissible under nominal capability checks.
- Confidentiality downgrades can occur without explicit declassification receipts.
- Projection-safe claims lose information-flow guarantees at external boundaries.

### 3.3 If PCAC and boundary-flow are both present but uncoupled

- Formally valid authority decisions can still externalize unsafe data.
- Security telemetry splits into non-composable proof surfaces.
- Promotion gates can pass while cross-boundary risk remains underconstrained.

## 4. Gate Ordering Contract

Mandatory order for FAC promotion-critical paths:
1. `GATE-PCAC-SNAPSHOT-VALIDITY`
2. `GATE-SIO28-TIME-AUTHORITY`
3. `GATE-SIO28-LIFECYCLE`
4. `GATE-SIO28-BOUNDARY-FLOW`
5. `GATE-SIO28-DELEGATION-MEET-EXACTNESS`
6. `GATE-SIO28-PROJECTION-ISOLATION`
7. `GATE-SIO28-PROJECTION-COMPROMISE-CONTAINMENT`
8. `GATE-SIO28-PROJECTION-NONINTERFERENCE`
9. `GATE-SIO28-VERIFIER-INDEPENDENCE`
10. `GATE-EIO29-INTERLOCK`
11. `GATE-EIO29-TIME-AUTHORITY`
12. `GATE-EIO29-PROJECTION-ISOLATION-INTERLOCK`
13. `GATE-EIO29-PROJECTION-SINK-CONTINUITY`
14. `GATE-EIO29-QUEUE-STABILITY`
15. `GATE-EIO29-TEMPORAL-MONOTONICITY`
16. `GATE-EIO29-REDUNDANCY-RECOVERABILITY`
17. `GATE-EIO29-RECONSTRUCTION-ADMISSIBILITY`
18. `GATE-EIO29-SCALE-TEMPORAL-STRESS`
19. `GATE-FAC-AUTOREMEDIATION-CANARY`
20. `GATE-FAC-AUTOREMEDIATION-INDEPENDENT-RERUN`
21. `GATE-SIO-PROFILE-SYNC`
22. `GATE-EIO-PROFILE-SYNC`

All gates fail closed.
Gate-order rationale: temporal-authority verification is evaluated before any security/economics gate that consumes timing semantics, ensuring ambiguous time input cannot influence admission.

### 4.1 Joint Security/Efficiency Mode Arbitration Contract

- runtime operating state is represented as `(S_i, D_j)` where `S_i` is RFC-0028 security mode and `D_j` is RFC-0029 efficiency mode.
- arbitration is fail-dominant with security precedence; effective mode index is `max(i, j)`.
- efficiency controls may further constrain throughput/workload, but cannot relax security constraints for the same mode index.
- promotion-critical progression requires effective mode to satisfy declared promotion envelope and zero unresolved temporal ambiguity.

### 4.2 Gate Activation Phasing for Evidence Bootstrap

Promotion-critical gates SHOULD support phased activation for pre-live evidence accumulation:
- `ADVISORY`: execute gate logic and emit signed defect/evidence telemetry; does not independently block promotion unless an explicit hard-safety gate fails.
- `SOFT_FAIL`: gate deny requires adjudication receipt to proceed; missing adjudication blocks Tier2+ promotion.
- `HARD_FAIL`: gate deny blocks promotion for all promotion-critical paths.
- `PRODUCTION`: fail-closed enforcement with mandatory freshness and independent verifier evidence.

Phase transition criteria MUST be evidence-bound:
- declared evidence artifact coverage exists for the gate contract surface.
- freshness SLA compliance is met for required evidence classes.
- independent verifier replay succeeds over declared adversarial test envelope.

### 4.3 Multi-Profile Composition Algebra

For profile set `P = {p1, p2, ..., pn}` with per-profile mode ladders:
- runtime state is product tuple `M = (m_1, m_2, ..., m_n)`.
- each profile declares severity order over its own ladder and a dominance rank across profiles.

Effective enforcement projection:
- `effective_mode = argmax_by(dominance_rank, severity_index)` over active profile modes.
- profile-local controls remain active even when not selected as `effective_mode`; no lower-ranked profile may relax higher-ranked constraints.

Admission rule:
- promotion-critical progression requires all hard constraints across all active profiles to hold.
- any unresolved cross-profile arbitration input is fail-closed with adjudication workflow, not silent override.

## 5. Vocabulary Alignment

Canonical terms used in this matrix:
- `htf_boundary`
- `authority_clock`
- `time_envelope`
- `tick_floor_met`
- `display_clock` (display-only)

## 6. Assumptions and Defaults

- RFC-0016 is the canonical temporal substrate for all matrix temporal clauses.
- Promotion remains fail-closed on temporal ambiguity.
- Dominance ordering is `containment/security > verification/correctness > liveness/progress`.
