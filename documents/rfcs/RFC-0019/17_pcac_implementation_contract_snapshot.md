# RFC-0019 Addendum - PCAC Implementation Contract Snapshot Baseline

Status: Draft (integration baseline)
Purpose: define the implementation-bound PCAC baseline that all FAC vNext security and efficiency profiles must import.

## 1. Contract IDs

- `PCAC-SNAPSHOT-BASELINE-ID`: `PCAC-SNAP-2026-02-09-v2`
- `PCAC-PROFILE-SECURITY-v1`: `PCAC-PROFILE-SECURITY-v1`
- `PCAC-PROFILE-EFFICIENCY-v1`: `PCAC-PROFILE-EFFICIENCY-v1`

These IDs are normative anchors for chapter 14, chapter 15, chapter 16, and the split profile RFCs.

## 2. Baseline Source Policy

This baseline is implementation-bound and MUST be derived from observed RFC-0027 contract artifacts only:

- Requirements:
  - `RFC-0027::REQ-0001 .. RFC-0027::REQ-0018`
  - source path: `documents/rfcs/RFC-0027/requirements/`
- Evidence shapes:
  - `RFC-0027::EVID-0001 .. RFC-0027::EVID-0010`
  - source path: `documents/rfcs/RFC-0027/evidence_artifacts/`
- Canonical lifecycle semantics:
  - source path: `documents/rfcs/RFC-0027/PROOF_CARRYING_AUTHORITY_CONTINUITY.md`

Companion imported baselines:
- `RFC-0020` boundary-flow and dual-lattice contracts
- `RFC-0016` HTF time-authority constraints for gate truth and economics windows

No downstream profile may assume future RFC-0027 semantics that are not represented in these snapshot sources.

## 3. Lifecycle Predicate Interface (normative)

### Stage predicates

- `pcac_join_valid`
  - true iff join-stage admission inputs and `AuthorityJoinReceipt` are valid for the flow.
  - anchors: `RFC-0027::REQ-0001`, `RFC-0027::REQ-0007`
- `pcac_revalidate_valid`
  - true iff revalidate-stage freshness/revocation/sovereignty constraints are valid.
  - anchors: `RFC-0027::REQ-0003`, `RFC-0027::REQ-0008`, `RFC-0027::REQ-0010`
- `pcac_consume_valid`
  - true iff consume-stage intent equality, single-consume, and prerequisite bindings hold.
  - anchors: `RFC-0027::REQ-0002`, `RFC-0027::REQ-0005`, `RFC-0027::REQ-0009`, `RFC-0027::REQ-0018`
- `pcac_effect_guarded`
  - true iff effect execution remains no-bypass and acceptance-fact complete.
  - anchors: `RFC-0027::REQ-0001`, `RFC-0027::REQ-0006`, `RFC-0027::REQ-0007`

### Cross-cutting predicates

- `pcac_single_consume_enforced`
  - anchors: `RFC-0027::REQ-0002`, `RFC-0027::REQ-0018`
- `pcac_intent_digest_equal`
  - anchors: `RFC-0027::REQ-0005`
- `pcac_revocation_dominant`
  - anchors: `RFC-0027::REQ-0008`
- `pcac_replay_complete`
  - anchors: `RFC-0027::REQ-0006`, `RFC-0027::REQ-0007`

### Profile-coupling predicates

- `boundary_flow_admissible`
  - true iff capability + taint + classification + declassification contracts pass for externalized outcomes.
  - anchors: `RFC-0020::REQ-0029`, `RFC-0020::REQ-0030`, `RFC-0020::REQ-0032`
- `projection_noninterference_valid`
  - true iff authoritative trace hash remains invariant under admissible projection toggles.
  - anchors: `RFC-0028::REQ-0006`, `RFC-0027::REQ-0006`
- `recoverability_evidence_current`
  - true iff declared recoverability profile has current decode/repair/replay evidence.
  - anchors: `RFC-0029::REQ-0005`, `RFC-0029::REQ-0006`
- `rolespec_context_injection_deterministic`
  - true iff injected role context is reconstructed only from hash-addressed RoleSpec and CAC context artifacts (`role_spec_hash`, `context_pack_spec_hash`, `context_pack_manifest_hash`, selector digest set) with deterministic closure.
  - anchors: `RFC-0019::REQ-0012`, `RFC-0019::REQ-0013`, `RFC-0019::REQ-0014`, `RFC-0029::REQ-0002`
- `rolespec_context_minimality_enforced`
  - true iff injected context equals required selector closure and includes no ambient/unplanned context reads.
  - anchors: `RFC-0019::REQ-0013`, `RFC-0019::REQ-0014`
- `delegation_meet_exact_valid`
  - true iff each admitted delegation vector equals canonical exact meet and independent verifier recomputation agrees.
  - anchors: `RFC-0028::REQ-0003`
- `pcac_projection_isolation_valid`
  - true iff production agent runtimes have no direct `gh`/GitHub API authority surface and all admissible external projections are receipt-bound to projection-worker execution.
  - anchors: `RFC-0028::REQ-0008`, `RFC-0019::REQ-0007`, `RFC-0029::REQ-0008`
- `time_authority_envelope_valid`
  - true iff signed `TimeAuthorityEnvelopeV1` is present, boundary/clock matched, and freshness TTL valid for the evaluated window.
  - anchors: `RFC-0016::REQ-HTF-0003`, `RFC-0016::REQ-HTF-0007`
- `projection_sink_independence_valid`
  - true iff authoritative FAC admission/effect decisions depend only on CAS+ledger truth plane and never on projection sink state.
  - anchors: `RFC-0029::REQ-0009`
- `projection_outage_continuity_valid`
  - true iff authoritative FAC progression remains live through declared projection-sink outage envelope and deferred replay remains bounded.
  - anchors: `RFC-0029::REQ-0009`
- `projection_multi_sink_continuity_valid`
  - true iff continuity holds under sink churn/partition/rate-limit/adversarial divergence scenarios for all sinks in scope.
  - anchors: `RFC-0029::REQ-0009`
- `projection_backlog_replay_bounded`
  - true iff deferred replay converges idempotently within declared replay horizon.
  - anchors: `RFC-0029::REQ-0009`
- `projection_compromise_contained`
  - true iff projection-surface compromise cannot alter authoritative outcomes and triggers quarantine + replay-safe recovery.
  - anchors: `RFC-0028::REQ-0009`
- `reconstruction_integrity_valid`
  - true iff mandatory source/evidence tier reconstruction has digest-match proof and valid BFT quorum certificate.
  - anchors: `RFC-0029::REQ-0010`
- `revocation_frontier_monotone`
  - true iff revocation frontier in later windows dominates prior windows for same authority scope.
  - anchors: `RFC-0029::REQ-0009`, `RFC-0027::REQ-0008`
- `replay_idempotency_monotone`
  - true iff replay in later windows cannot resurrect effects denied/revoked in prior windows.
  - anchors: `RFC-0029::REQ-0005`, `RFC-0029::REQ-0009`
- `promotion_temporal_ambiguity_absent`
  - true iff no promotion-critical path proceeds with unknown/stale/missing/invalid temporal authority.
  - anchors: `RFC-0016::REQ-HTF-0003`, `RFC-0019::REQ-0010`, `RFC-0029::REQ-0009`

Fail-closed rule:
- missing, stale, ambiguous, unverifiable, or unknown predicate state evaluates to `false`.

Temporal contract ownership note:
- `TP-EIO29-*` is the shared cross-profile temporal contract namespace for promotion-critical admission.
- canonical semantics are anchored by RFC-0016 and this RFC snapshot contract.
- RFC-0029 provides a profile-local evaluation mirror and economics coupling over the same contract IDs.
- cross-profile temporal predicate disagreements MUST emit `TemporalArbitrationReceiptV1`; unresolved arbitration remains fail-closed with adjudication workflow.

## 4. Snapshot Verification Contract

A profile import is valid only if all are true:

- `pcac_join_valid`
- `pcac_revalidate_valid`
- `pcac_consume_valid`
- `pcac_effect_guarded`
- `pcac_single_consume_enforced`
- `pcac_intent_digest_equal`
- `pcac_revocation_dominant`
- `pcac_replay_complete`
- `boundary_flow_admissible`
- `projection_noninterference_valid`
- `recoverability_evidence_current`
- `rolespec_context_injection_deterministic`
- `rolespec_context_minimality_enforced`
- `delegation_meet_exact_valid`
- `pcac_projection_isolation_valid`
- `time_authority_envelope_valid`
- `projection_sink_independence_valid`
- `projection_outage_continuity_valid`
- `projection_multi_sink_continuity_valid`
- `projection_backlog_replay_bounded`
- `projection_compromise_contained`
- `reconstruction_integrity_valid`
- `revocation_frontier_monotone`
- `replay_idempotency_monotone`
- `promotion_temporal_ambiguity_absent`

Any false value sets snapshot status to `BLOCKED`.

## 5. Drift and Compatibility Policy

### Drift rule

If any snapshot predicate fails after RFC-0027 or imported profile implementation updates, downstream profile gates MUST block promotion.

### Compatibility states

- `COMPATIBLE`: all predicates true.
- `SUSPECT`: predicates true but imported dependency versions changed and require adjudication.
- `BLOCKED`: one or more predicates false, unknown, or unevaluable.

### Rebaseline protocol

1. Re-run snapshot predicate suite.
2. Produce updated snapshot report bound to new baseline ID.
3. Re-evaluate security and efficiency profile gates.
4. Promote only if gates pass with independent verifier evidence.

### 5.1 Predicate Impact Graph and Partial Re-Evaluation

To reduce rebaseline coordination cost while preserving fail-closed semantics, snapshot implementations SHOULD maintain a predicate dependency graph:
- `predicate_dependency_graph`: directed edges from contract object or requirement surfaces to derived predicates.
- `impact_set(change_set)`: transitive closure of predicates potentially affected by changed upstream artifacts.

Optimization policy:
- partial re-evaluation MAY be used for pre-adjudication diagnostics when `impact_set(change_set)` is strict subset of snapshot predicates and canonicalizer tuple is unchanged.
- authoritative promotion decisions remain blocked until all predicates in `impact_set(change_set)` and their gate dependencies are re-evaluated with fresh signed receipts.
- full-suite rebaseline remains mandatory when canonicalizer vectors, schema-major versions, or temporal authority semantics change.

## 6. Signal Namespace Contract

- Security failure signals: `SIO-SIG-*`
- Economics failure signals: `EIO-SIG-*`
- Autonomic remediation signals: `AIO-SIG-*`
- Countermetrics: `XIO-CM-*`
- Temporal predicate contract IDs: `TP-EIO29-*` (shared namespace anchored by RFC-0016 + RFC-0019 snapshot contract)

Signal contracts must be machine-parseable and lifecycle-stage keyed.

## 7. Unified Gate Entry (Gate 1)

`GATE-PCAC-SNAPSHOT-VALIDITY`
- input: snapshot report for `PCAC-SNAPSHOT-BASELINE-ID`
- block condition: any required predicate false/unknown/unevaluable
- required evidence:
  - `RFC-0027::EVID-0009` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0009.yaml`)
  - `RFC-0027::EVID-0010` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0010.yaml`)

### 7.1 Activation Phase Contract

To support evidence bootstrapping before production hard-fail:
- `ADVISORY`: gate emits verdict and defect records but does not independently block promotion except for explicit hard-safety clauses.
- `SOFT_FAIL`: gate deny requires signed adjudication override to proceed in non-production tiers.
- `HARD_FAIL`: gate deny blocks promotion-critical progression.
- `PRODUCTION`: strict fail-closed behavior for all promotion-critical paths.

Phase transitions MUST be backed by:
- declared evidence coverage for gate-required contract surfaces.
- freshness and reproducibility evidence satisfying profile SLAs.
- independent verifier replay receipts for declared adversarial envelope.

## 8. Canonical Profile Sync Gates

To prevent semantic split-brain between RFC-0019 integration chapters and canonical split profile RFCs:

- `GATE-SIO-PROFILE-SYNC`
  - canonical source: `documents/rfcs/RFC-0028/HOLONIC_EXTERNAL_IO_SECURITY.md`
  - derived mirror: `documents/rfcs/RFC-0019/15_holonic_external_io_security_problem_landscape.md`
  - block condition: normalized profile-map mismatch.

- `GATE-EIO-PROFILE-SYNC`
  - canonical source: `documents/rfcs/RFC-0029/HOLONIC_EXTERNAL_IO_EFFICIENCY.md`
  - derived mirror: `documents/rfcs/RFC-0019/16_holonic_external_io_efficiency_problem_landscape.md`
  - block condition: normalized profile-map mismatch.

Both gates fail closed when diff evidence is missing, stale, ambiguous, or unverifiable.

### 8.1 Mirror Maintenance Workflow

Because RFC-0019 integration chapters are derived mirrors of canonical profile RFCs:
- canonical profile changes SHOULD include corresponding mirror updates in the same change window.
- profile sync gates are blocking integrity gates, not best-effort lint checks.
- repositories SHOULD automate mirror extraction/normalization to reduce maintenance latency and promotion-blocking drift during high-change periods.

## 9. Snapshot Object Surfaces (minimum CAC registry)

Snapshot report bundles MUST include `contract_object_registry[]` rows with:
- `object_id`
- `kind`
- `schema_id`
- `schema_major`
- `schema_stable_id`
- `object_digest`
- `canonicalizer_id`
- `canonicalizer_version`
- `canonicalizer_vectors_ref`
- `signature_set_ref` (if required by object kind)
- `window_or_ttl_ref` (if temporal freshness is required)

Required registry rows:

| Object ID | `kind` | `schema_id` | `schema_stable_id` family |
|---|---|---|---|
| `PCACSnapshotReportV1` | `snapshot.report` | `apm2.pcac_snapshot_report.v1` | `dcp://apm2.local/schemas/apm2.pcac_snapshot_report.v1@v1` |
| `AuthorityKernelDecisionV1` | `authority.kernel.decision` | `apm2.authority_kernel_decision.v1` | `dcp://apm2.local/schemas/apm2.authority_kernel_decision.v1@v1` |
| `BoundaryFlowPolicyV1` | `boundary.flow.policy` | `apm2.boundary_flow_policy.v1` | `dcp://apm2.local/schemas/apm2.boundary_flow_policy.v1@v1` |
| `ProjectionDiffProofV1` | `projection.diff.proof` | `apm2.projection_diff_proof.v1` | `dcp://apm2.local/schemas/apm2.projection_diff_proof.v1@v1` |
| `DelegationMeetComputationReceiptV1` | `delegation.meet.receipt` | `apm2.delegation_meet_computation_receipt.v1` | `dcp://apm2.local/schemas/apm2.delegation_meet_computation_receipt.v1@v1` |
| `DelegationSatisfiabilityReceiptV1` | `delegation.satisfiability.receipt` | `apm2.delegation_satisfiability_receipt.v1` | `dcp://apm2.local/schemas/apm2.delegation_satisfiability_receipt.v1@v1` |
| `EconomicsConstraintProfileV1` | `economics.constraint.profile` | `apm2.economics_constraint_profile.v1` | `dcp://apm2.local/schemas/apm2.economics_constraint_profile.v1@v1` |
| `RecoverabilityProfileV1` | `recoverability.profile` | `apm2.recoverability_profile.v1` | `dcp://apm2.local/schemas/apm2.recoverability_profile.v1@v1` |
| `AutonomicRemediationContractV1` | `autonomic.remediation.contract` | `apm2.autonomic_remediation_contract.v1` | `dcp://apm2.local/schemas/apm2.autonomic_remediation_contract.v1@v1` |
| `RoleSpecContractV1` | `role.spec.contract` | `cac.holon_contract.v1` | `dcp://apm2.local/schemas/cac.holon_contract.v1@v1` |
| `RoleContextPackSpecV1` | `context_pack.spec` | `cac.context_pack_spec.v1` | `dcp://apm2.local/schemas/cac.context_pack_spec.v1@v1` |
| `RoleContextPackManifestV1` | `context_pack.manifest` | `cac.context_pack_manifest.v1` | `dcp://apm2.local/schemas/cac.context_pack_manifest.v1@v1` |
| `RoleReasoningSelectorV1` | `reasoning.selector` | `cac.reasoning_selector.v1` | `dcp://apm2.local/schemas/cac.reasoning_selector.v1@v1` |
| `RoleBudgetProfileV1` | `budget.profile` | `cac.budget_profile.v1` | `dcp://apm2.local/schemas/cac.budget_profile.v1@v1` |
| `RoleRunReceiptV1` | `receipt.run` | `cac.run_receipt.v1` | `dcp://apm2.local/schemas/cac.run_receipt.v1@v1` |
| `ProjectionSinkContinuityProfileV1` | `projection.sink.continuity.profile` | `apm2.projection_sink_continuity_profile.v1` | `dcp://apm2.local/schemas/apm2.projection_sink_continuity_profile.v1@v1` |
| `TimeAuthorityEnvelopeV1` | `time.envelope` | `apm2.time_authority_envelope.v1` | `dcp://apm2.local/schemas/apm2.time_authority_envelope.v1@v1` |
| `TemporalSloProfileV1` | `temporal.slo.profile` | `apm2.temporal_slo_profile.v1` | `dcp://apm2.local/schemas/apm2.temporal_slo_profile.v1@v1` |
| `ProjectionContinuityWindowV1` | `projection.continuity.window` | `apm2.projection_continuity_window.v1` | `dcp://apm2.local/schemas/apm2.projection_continuity_window.v1@v1` |
| `ProjectionCompromiseSignalV1` | `projection.compromise.signal` | `apm2.projection_compromise_signal.v1` | `dcp://apm2.local/schemas/apm2.projection_compromise_signal.v1@v1` |
| `SourceTrustSnapshotV1` | `source.trust.snapshot` | `apm2.source_trust_snapshot.v1` | `dcp://apm2.local/schemas/apm2.source_trust_snapshot.v1@v1` |
| `CodebaseRecoveryProfileV1` | `codebase.recovery.profile` | `apm2.codebase_recovery_profile.v1` | `dcp://apm2.local/schemas/apm2.codebase_recovery_profile.v1@v1` |
| `ErasureRecoveryReceiptV1` | `erasure.recovery.receipt` | `apm2.erasure_recovery_receipt.v1` | `dcp://apm2.local/schemas/apm2.erasure_recovery_receipt.v1@v1` |
| `BftRecoveryQuorumCertificateV1` | `bft.recovery.quorum.certificate` | `apm2.bft_recovery_quorum_certificate.v1` | `dcp://apm2.local/schemas/apm2.bft_recovery_quorum_certificate.v1@v1` |
| `ReplayConvergenceReceiptV1` | `replay.convergence.receipt` | `apm2.replay_convergence_receipt.v1` | `dcp://apm2.local/schemas/apm2.replay_convergence_receipt.v1@v1` |
| `RecoveryAdmissibilityReceiptV1` | `recovery.admissibility.receipt` | `apm2.recovery_admissibility_receipt.v1` | `dcp://apm2.local/schemas/apm2.recovery_admissibility_receipt.v1@v1` |
| `TemporalPredicateEvaluatorV1` | `temporal.evaluator` | `apm2.temporal_predicate_evaluator.v1` | `dcp://apm2.local/schemas/apm2.temporal_predicate_evaluator.v1@v1` |
| `RevocationFrontierSnapshotV1` | `revocation.frontier.snapshot` | `apm2.revocation_frontier_snapshot.v1` | `dcp://apm2.local/schemas/apm2.revocation_frontier_snapshot.v1@v1` |
| `LocalMonotonicEmergencyTimeReceiptV1` | `local.time.emergency.receipt` | `apm2.local_monotonic_emergency_time_receipt.v1` | `dcp://apm2.local/schemas/apm2.local_monotonic_emergency_time_receipt.v1@v1` |
| `SemanticDiffReportV1` | `semantic.diff.report` | `apm2.semantic_diff_report.v1` | `dcp://apm2.local/schemas/apm2.semantic_diff_report.v1@v1` |
| `CryptoAgilityPolicyV1` | `crypto.agility.policy` | `apm2.crypto_agility_policy.v1` | `dcp://apm2.local/schemas/apm2.crypto_agility_policy.v1@v1` |
| `SinkIdentitySnapshotV1` | `sink.identity.snapshot` | `apm2.sink_identity_snapshot.v1` | `dcp://apm2.local/schemas/apm2.sink_identity_snapshot.v1@v1` |
| `ProjectionIsolationPolicyV1` | `projection.isolation.policy` | `apm2.projection_isolation_policy.v1` | `dcp://apm2.local/schemas/apm2.projection_isolation_policy.v1@v1` |
| `TradeSecretPolicyProfileV1` | `trade.secret.policy` | `apm2.trade_secret_policy_profile.v1` | `dcp://apm2.local/schemas/apm2.trade_secret_policy_profile.v1@v1` |
| `VerifierIndependenceProfileV1` | `verifier.independence.profile` | `apm2.verifier_independence_profile.v1` | `dcp://apm2.local/schemas/apm2.verifier_independence_profile.v1@v1` |
| `EvidenceQualityProfileV1` | `evidence.quality.profile` | `apm2.evidence_quality_profile.v1` | `dcp://apm2.local/schemas/apm2.evidence_quality_profile.v1@v1` |
| `EvidenceFreshnessSlaV1` | `evidence.freshness.sla` | `apm2.evidence_freshness_sla.v1` | `dcp://apm2.local/schemas/apm2.evidence_freshness_sla.v1@v1` |
| `CountermetricProfileV1` | `countermetric.profile` | `apm2.countermetric_profile.v1` | `dcp://apm2.local/schemas/apm2.countermetric_profile.v1@v1` |
| `HardwareTierEnvelopeV1` | `hardware.tier.envelope` | `apm2.hardware_tier_envelope.v1` | `dcp://apm2.local/schemas/apm2.hardware_tier_envelope.v1@v1` |
| `TemporalDisagreementReceiptV1` | `temporal.disagreement.receipt` | `apm2.temporal_disagreement_receipt.v1` | `dcp://apm2.local/schemas/apm2.temporal_disagreement_receipt.v1@v1` |
| `TemporalArbitrationReceiptV1` | `temporal.arbitration.receipt` | `apm2.temporal_arbitration_receipt.v1` | `dcp://apm2.local/schemas/apm2.temporal_arbitration_receipt.v1@v1` |
| `HaltStateReceiptV1` | `halt.state.receipt` | `apm2.halt_state_receipt.v1` | `dcp://apm2.local/schemas/apm2.halt_state_receipt.v1@v1` |
| `PostCompromiseRecoveryReceiptV1` | `post_compromise.recovery.receipt` | `apm2.post_compromise_recovery_receipt.v1` | `dcp://apm2.local/schemas/apm2.post_compromise_recovery_receipt.v1@v1` |
| `OperatorSafetyGuardProfileV1` | `operator.safety.guard` | `apm2.operator_safety_guard_profile.v1` | `dcp://apm2.local/schemas/apm2.operator_safety_guard_profile.v1@v1` |
| `AntiEntropyConvergenceReceiptV1` | `anti_entropy.convergence.receipt` | `apm2.anti_entropy_convergence_receipt.v1` | `dcp://apm2.local/schemas/apm2.anti_entropy_convergence_receipt.v1@v1` |

Any missing required object digest or schema resolution makes snapshot verification unevaluable and therefore blocked.

### 9.1 Bootstrap Topological Ordering (Pre-Live)

For cold-start realizability, implementations SHOULD materialize schema objects in dependency order:
1. canonicalization/time/evaluator roots (`time.envelope`, `temporal.evaluator`, canonicalizer vectors).
2. lifecycle authority roots (`authority.kernel.decision`, `boundary.flow.policy`, `projection.isolation.policy`).
3. delegation/revocation/replay continuity (`delegation.meet.receipt`, `delegation.satisfiability.receipt`, `revocation.frontier.snapshot`, `local.time.emergency.receipt` when fallback paths are used, `replay.convergence.receipt`).
4. projection/recoverability integrity (`sink.identity.snapshot`, `source.trust.snapshot`, `erasure.recovery.receipt`, `bft.recovery.quorum.certificate`).
5. economics/evidence/meta-governance (`economics.constraint.profile`, `evidence.quality.profile`, `evidence.freshness.sla`, `semantic.diff.report`).

Topological rule:
- objects in level `k` MUST NOT depend on unresolved objects in level `k+1` or later.
- unresolved dependency cycles are non-admissible and require schema graph adjudication before gate evaluation.

## 10. CAC Validation Order and Compatibility Defects

Snapshot validity checks MUST execute in this order:
1. `schema_id` and `schema_major` resolution for each `contract_object_registry[]` row.
2. canonicalizer tuple compatibility check against active snapshot baseline.
3. signature/freshness verification for signed and window-bound artifacts.
4. `contract_digest_set` completeness and declared digest-equality constraints.
5. predicate and gate-level semantic evaluation.

Defect classes (all fail-closed):
- `CAC_SCHEMA_UNRESOLVED`
- `CAC_SCHEMA_VERSION_INCOMPATIBLE`
- `CAC_SCHEMA_REGISTRY_DRIFT_AMBIGUOUS`
- `CAC_CANONICALIZER_UNRESOLVED`
- `CAC_CANONICALIZER_VECTOR_MISMATCH`
- `CAC_DIGEST_SET_INCOMPLETE`
- `CAC_DIGEST_MISMATCH`
- `CAC_SIGNATURE_INVALID`
- `CAC_INPUT_STALE`
- `CAC_VALIDATION_ORDER_VIOLATION`

Compatibility states refinement:
- `COMPATIBLE`: all checks pass; no CAC defects.
- `SUSPECT`: semantic inputs pass, but registry/canonicalizer drift requires adjudication.
- `BLOCKED`: any defect above is present, or any check is unknown/unevaluable.

## 11. Tiered Fail-Closed Behavior for CAC Defects

`GATE-PCAC-SNAPSHOT-VALIDITY` MUST deny on any CAC defect class listed above.

Tier policy:
- Tier0/Tier1: deny + emit `cac.defect_record.v1`.
- Tier2+: deny + freeze promotion path (`S3` in RFC-0028 and `D3` in RFC-0029), require adjudication before `cac_adjudication_deadline_window_ref`, and escalate to emergency halt (`S4`/`D4`) if unresolved at deadline.
