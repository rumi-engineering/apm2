# RFC-0019 Addendum - Holonic External I/O Efficiency Problem Landscape (PCAC-Profiled)

Status: Draft (problem-definition phase)
Primary objective: define external I/O efficiency constraints as lifecycle-stage economics over RFC-0027 PCAC states without weakening security correctness.

## 1. Baseline Import and Contracts

Imported baseline:
- `PCAC-SNAPSHOT-BASELINE-ID` (`documents/rfcs/RFC-0019/17_pcac_implementation_contract_snapshot.md`)

Imported profile ID:
- `PCAC-PROFILE-EFFICIENCY-v1`

Canonical lifecycle substrate:
- `RFC-0027::REQ-0001 .. RFC-0027::REQ-0018`

Canonical profile source:
- `documents/rfcs/RFC-0029/HOLONIC_EXTERNAL_IO_EFFICIENCY.md`

Derivation mode:
- one-way derivation from RFC-0029 into this RFC-0019 integration chapter.
- this chapter MUST NOT introduce profile semantics not present in RFC-0029.

Profile sync gate:
- `GATE-EIO-PROFILE-SYNC`
  - block condition: semantic drift between RFC-0029 canonical profile and this derived integration chapter.
  - minimum evidence: normalized profile-map diff artifact bound to current `PCAC-SNAPSHOT-BASELINE-ID`.

## 2. PCAC Stage Economics Model

Stage costs:
- `C_join`: cost of join-time parsing, canonicalization, identity/delegation admission.
- `C_revalidate`: cost of freshness/revocation/sovereignty reevaluation.
- `C_consume`: cost of intent-equality, uniqueness, and prerequisite checks.
- `C_effect`: cost of effect emission with acceptance-fact completeness.

Overlays:
- `C_replay`: deterministic replay/reverification cost.
- `C_recovery`: recovery cost under crash/partition/partial loss.

Aggregate:
- `C_total = C_join + C_revalidate + C_consume + C_effect + C_replay + C_recovery`

## 3. Temporal Contract Overlay (mirror of RFC-0029)

Required typed contracts:
- `TimeAuthorityEnvelopeV1` (`htf_boundary_id`, `authority_clock`, `tick_start`, `tick_end`, `signature_set`, `ttl`, `deny_on_unknown`)
- `TemporalSloProfileV1` (`objective_id`, `baseline`, `target`, `window_ref`, `owner_locus`, `falsification_predicate`, `countermetrics`, `boundary_authority_ref`, `fail_closed_mode`)
- `ProjectionContinuityWindowV1` (`outage_window_ref`, `continuity_predicate`, `replay_window_ref`, `queue_budget`, `critical_path_reservation`, `boundary_authority_ref`, `fail_closed_mode`)
- `ProjectionSinkContinuityProfileV1` (`outage_window_ref`, `continuity_window_ref`, `replay_window_ref`, `freshness_horizon_ref`, `anti_entropy_convergence_horizon_ref`, `replay_convergence_horizon_ref`, `queue_budget`, `critical_path_reservation`, `time_authority_ref`, `deny_on_unknown`)
- `ReplayConvergenceReceiptV1` (`time_authority_ref`, `window_ref`, `convergence_verdict`, `idempotency_verdict`, `verifier_replay_receipt_ref`)
- `RecoveryAdmissibilityReceiptV1` (`time_authority_ref`, `window_ref`, `digest_proof_ref`, `quorum_cert_ref`, `admissibility_verdict`)
- `TemporalPredicateEvaluatorV1` (`evaluator_id`, `predicate_id`, `contract_digest_set`, `time_authority_ref`, `window_ref`, `verdict`, `deny_reason`)

Mirror rule:
- prose-only SLO text is non-normative.
- all continuity/replay/recovery gate claims MUST reference typed fields above.
- temporal predicates MUST resolve to canonical IDs (`TP-EIO29-*`) and be evaluated by `temporal_predicate_evaluator_v1`.

### 3.1 Temporal Horizon Contract IDs (mirror of RFC-0029)

- `TP-EIO29-001`: `time_authority_envelope_valid`.
- `TP-EIO29-002`: `freshness_horizon_satisfied`.
- `TP-EIO29-003`: `anti_entropy_convergence_horizon_satisfied`.
- `TP-EIO29-004`: `replay_convergence_horizon_satisfied`.
- `TP-EIO29-005`: `projection_multi_sink_continuity_valid`.
- `TP-EIO29-006`: `revocation_frontier_monotone`.
- `TP-EIO29-007`: `replay_idempotency_monotone`.
- `TP-EIO29-008`: `promotion_temporal_ambiguity == false`.

### 3.2 Horizon Semantics (mirror of RFC-0029)

- `freshness_horizon_ref`: HTF window for freshness/revocation admissibility.
- `anti_entropy_convergence_horizon_ref`: HTF window for anti-entropy completion.
- `replay_convergence_horizon_ref`: HTF window for backlog replay convergence.

All horizon semantics are bound to `htf_boundary_id` and `authority_clock` through signed `TimeAuthorityEnvelopeV1`.

## 4. EIO Problem Remap to Lifecycle Stages

High-risk set for mandatory attacker-cost ratio reporting:
- `EIO-002`, `EIO-004`, `EIO-006`, `EIO-007`, `EIO-009`, `EIO-013`, `EIO-014`, `EIO-015`, `EIO-016`, `EIO-017`, `EIO-018`, `EIO-019`, `EIO-020`

### 4.1 Row-Level Hyperproperty Tag Registry (normative)

Each row in the EIO remap table MUST reference one or more `HP-EIO-R*` tags.

| Hyperproperty Tag | Predicate Class | Falsification Trigger | Evidence Family | Fail-Closed Rule |
|---|---|---|---|---|
| `HP-EIO-R01` | safety-constrained optimization | `delta(C_total) < 0` admitted with safety regression | KPI/countermetric gate receipts | unknown safety predicate denies |
| `HP-EIO-R02` | countermetric anti-Goodhart coupling | KPI improves while required countermetric regresses | KPI/countermetric pair reports | missing countermetric denies |
| `HP-EIO-R03` | queue stability monotonicity | queue pressure violates stop/revocation critical-path tick floors | queue stress telemetry + temporal SLO receipts | unknown queue state denies |
| `HP-EIO-R04` | recoverability envelope integrity | declared `(k,n,repair_slo,p_unrecoverable_max)` envelope violated | replay/recovery drills + decode/repair receipts | stale or missing drill evidence denies |
| `HP-EIO-R05` | cache-freshness safety | cache amortization admits stale/revoked authority outcomes | cache invalidation tests + freshness receipts | ambiguous freshness state denies |
| `HP-EIO-R06` | attacker-cost asymmetry bounds | Tier2+ path exceeds `ACR` threshold and remains promotable | adversarial load experiments + threshold policy digest | missing threshold proof denies |
| `HP-EIO-R07` | recursive amplification bounding | coordination fanout grows beyond declared envelope under adversarial trigger | recursion stress tests + backpressure receipts | unknown amplification state denies |
| `HP-EIO-R08` | authority-surface monotonicity | optimization increases production agent external authority surface or reintroduces direct `gh`/GitHub capability | capability-surface diff reports + optimization gate traces | missing/ambiguous surface evidence denies |
| `HP-EIO-R09` | projection sink independence + multi-sink continuity | authoritative decision depends on projection sink state or any sink-failure scenario halts authoritative FAC progression | outage drill traces + truth-plane liveness metrics + decision-lineage exclusion proofs + signed time-authority receipts | unknown continuity/independence state denies |
| `HP-EIO-R10` | deferred replay convergence | post-outage projection replay diverges, duplicates, or starves critical queues | `ReplayConvergenceReceiptV1` + idempotency checks + queue telemetry | missing replay evidence denies |
| `HP-EIO-R11` | reconstruction admissibility integrity | reconstructed source/evidence admitted without digest match/quorum/time-authority proof | erasure reconstruction receipts + `RecoveryAdmissibilityReceiptV1` + BFT quorum certificates + trust snapshot proofs | missing integrity/quorum proof denies |
| `HP-EIO-R12` | temporal monotonicity and ambiguity deny | revocation frontier regresses across adjacent windows or promotion occurs with temporal ambiguity | cross-window revocation receipts + ambiguity deny logs + verifier replay receipts | unknown monotonicity verdict denies |
| `HP-EIO-R13` | scale-envelope temporal admissibility | multi-exabyte replay/recovery or p99/p99.9 tick-space governance exceeds declared profile and remains promotable | scale stress profiles + percentile tick reports + gate adjudication traces | missing stress verdict denies |

| Problem | Primary Stage | Secondary Stage | Hyperproperty Tag(s) | Failure Signal | PCAC Requirement Anchor | Companion Requirement Anchor | Attacker Cost Ratio (high-risk only) |
|---|---|---|---|---|---|---|---|
| `EIO-001` missing canonical economics profile | `join` | `revalidate` | `HP-EIO-R01` | `EIO-SIG-001` | `RFC-0027::REQ-0012` | `RFC-0019::REQ-0014` | - |
| `EIO-002` transcript fan-out in control-plane paths | `effect` | `replay` | `HP-EIO-R02`, `HP-EIO-R06` | `EIO-SIG-002` | `RFC-0027::REQ-0011` | `RFC-0018::REQ-HEF-0018` | `ACR-002 = defender_verify_cost_per_message / attacker_send_cost_per_message` |
| `EIO-003` selector coverage/loss-profile incompleteness | `effect` | `replay` | `HP-EIO-R02` | `EIO-SIG-003` | `RFC-0027::REQ-0006` | `RFC-0019::REQ-0010` | - |
| `EIO-004` under-amortized verification work | `revalidate` | `consume` | `HP-EIO-R01`, `HP-EIO-R05`, `HP-EIO-R06` | `EIO-SIG-004` | `RFC-0027::REQ-0011` | `RFC-0020::REQ-0034` | `ACR-004 = defender_verify_cost_per_admission / attacker_trigger_cost` |
| `EIO-005` identity/freshness proof cache inefficiency | `revalidate` | `join` | `HP-EIO-R05` | `EIO-SIG-005` | `RFC-0027::REQ-0003` | `RFC-0020::REQ-0018` | - |
| `EIO-006` anti-entropy budget coupling gaps | `revalidate` | `effect` | `HP-EIO-R03`, `HP-EIO-R06`, `HP-EIO-R07` | `EIO-SIG-006` | `RFC-0027::REQ-0011` | `RFC-0020::REQ-0035` | `ACR-006 = defender_anti_entropy_cost / attacker_flood_cost` |
| `EIO-007` queue discipline not risk-aware enough | `consume` | `revalidate` | `HP-EIO-R03`, `HP-EIO-R06` | `EIO-SIG-007` | `RFC-0027::REQ-0011` | `RFC-0020::REQ-0035` | `ACR-007 = defender_critical_path_delay_cost / attacker_queue_pressure_cost` |
| `EIO-008` context rehydration over-fetch | `join` | `consume` | `HP-EIO-R02` | `EIO-SIG-008` | `RFC-0027::REQ-0006` | `RFC-0019::REQ-0014` | - |
| `EIO-009` replay/recovery cost cliffs | `replay` | `consume` | `HP-EIO-R04`, `HP-EIO-R06` | `EIO-SIG-009` | `RFC-0027::REQ-0006` | `RFC-0020::REQ-0035` | `ACR-009 = defender_recovery_cost_per_incident / attacker_disruption_cost` |
| `EIO-010` cross-cell dedup/idempotency inefficiency | `consume` | `effect` | `HP-EIO-R01`, `HP-EIO-R04` | `EIO-SIG-010` | `RFC-0027::REQ-0018` | `RFC-0020::REQ-0034` | - |
| `EIO-011` policy evaluation overhead drift | `join` | `revalidate` | `HP-EIO-R01`, `HP-EIO-R02` | `EIO-SIG-011` | `RFC-0027::REQ-0012` | `RFC-0020::REQ-0001` | - |
| `EIO-012` insufficient economics observability | `effect` | `replay` | `HP-EIO-R02` | `EIO-SIG-012` | `RFC-0027::REQ-0016` | `RFC-0019::REQ-0013` | - |
| `EIO-013` adversarial cost asymmetry attacker-favorable | `revalidate` | `consume` | `HP-EIO-R06` | `EIO-SIG-013` | `RFC-0027::REQ-0011` | `RFC-0020::REQ-0035` | `ACR-013 = defender_drop_or_verify_cost / attacker_trigger_cost` |
| `EIO-014` recursive coordination amplification | `effect` | `revalidate` | `HP-EIO-R07`, `HP-EIO-R06` | `EIO-SIG-014` | `RFC-0027::REQ-0011` | `RFC-0018::REQ-HEF-0018` | `ACR-014 = defender_coordination_cost_growth / attacker_amplification_cost` |
| `EIO-015` optimization-induced direct GitHub authority regression | `effect` | `consume` | `HP-EIO-R08`, `HP-EIO-R01` | `EIO-SIG-015` | `RFC-0027::REQ-0012` | `RFC-0029::REQ-0008` | `ACR-015 = defender_projection_broker_cost / attacker_direct_api_trigger_cost` |
| `EIO-016` projection sink multi-failure continuity gap | `effect` | `revalidate` | `HP-EIO-R09`, `HP-EIO-R03` | `EIO-SIG-016` | `RFC-0027::REQ-0011` | `RFC-0029::REQ-0009` | `ACR-016 = defender_outage_continuity_cost / attacker_sink_disruption_cost` |
| `EIO-017` deferred projection replay divergence | `replay` | `effect` | `HP-EIO-R10`, `HP-EIO-R04` | `EIO-SIG-017` | `RFC-0027::REQ-0006` | `RFC-0029::REQ-0009` | `ACR-017 = defender_replay_verification_cost / attacker_backlog_injection_cost` |
| `EIO-018` reconstruction admissibility integrity failure | `replay` | `consume` | `HP-EIO-R11`, `HP-EIO-R04` | `EIO-SIG-018` | `RFC-0027::REQ-0006` | `RFC-0029::REQ-0010` | `ACR-018 = defender_recovery_quorum_cost / attacker_corruption_cost` |
| `EIO-019` temporal monotonicity and ambiguity leakage | `revalidate` | `replay` | `HP-EIO-R12` | `EIO-SIG-019` | `RFC-0027::REQ-0008` | `RFC-0029::REQ-0009` | `ACR-019 = defender_temporal_verification_cost / attacker_time_ambiguity_cost` |
| `EIO-020` scale-envelope temporal stress underfit | `replay` | `effect` | `HP-EIO-R13`, `HP-EIO-R06` | `EIO-SIG-020` | `RFC-0027::REQ-0011` | `RFC-0029::REQ-0004`, `RFC-0029::REQ-0010` | `ACR-020 = defender_scale_stress_cost / attacker_scale_disruption_cost` |

## 5. Hard Guard: No Unsafe Optimization

No efficiency optimization is admissible if any condition fails:

- `pcac_receipt_completeness == 1.0`
- `pcac_consume_deny_correctness == 1.0`
- `pcac_projection_isolation_valid == true`
- `time_authority_envelope_valid == true`
- `projection_sink_independence_valid == true`
- `projection_multi_sink_continuity_valid == true`
- `revocation_frontier_monotone == true`
- `replay_idempotency_monotone == true`
- `promotion_temporal_ambiguity == false`

This guard is mandatory for profile conformance and promotion eligibility.

## 6. Efficiency Evidence Binding (path-qualified)

- `RFC-0027::EVID-0005` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0005.yaml`)
- `RFC-0027::EVID-0006` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0006.yaml`)
- `RFC-0027::EVID-0007` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0007.yaml`)
- `RFC-0027::EVID-0009` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0009.yaml`)
- `RFC-0027::EVID-0010` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0010.yaml`)
- `RFC-0029::EVID-0004` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0004.yaml`)
- `RFC-0029::EVID-0005` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0005.yaml`)
- `RFC-0029::EVID-0009` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0009.yaml`)
- `RFC-0029::EVID-0010` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0010.yaml`)

## 7. Profile Gates (efficiency)

- `GATE-EIO-PCAC-SNAPSHOT`
  - blocks when snapshot predicate set is stale/invalid.
- `GATE-EIO-TIME-AUTHORITY`
  - blocks on stale/unsigned/missing/invalid `TimeAuthorityEnvelopeV1` or unresolved temporal window references.
- `GATE-EIO-ECONOMICS-BOUNDS`
  - blocks on verifier-economics bound violations without admissible degraded-mode policy.
- `GATE-EIO-COUNTERMETRIC-INTEGRITY`
  - blocks if any KPI lacks paired countermetric (`XIO-CM-*`).
- `GATE-EIO-REPLAY-RECOVERY-BOUNDS`
  - blocks when replay/recovery HTF windows are exceeded.
- `GATE-EIO-UNSAFE-OPTIMIZATION`
  - blocks if receipt completeness, consume deny correctness, or temporal invariants regress.
- `GATE-EIO-PROJECTION-ISOLATION-INTERLOCK`
  - blocks if any optimization increases production agent external authority surface or reintroduces direct `gh`/GitHub capabilities.
- `GATE-EIO-PROJECTION-SINK-CONTINUITY`
  - blocks when projection-sink independence, multi-sink continuity, backlog bounds, or replay convergence evidence is missing/invalid.
- `GATE-EIO-TEMPORAL-MONOTONICITY`
  - blocks when revocation/replay monotonicity fails across adjacent HTF windows or ambiguity is promoted.
- `GATE-EIO-RECONSTRUCTION-ADMISSIBILITY`
  - blocks when mandatory-tier reconstruction evidence, digest match proofs, `RecoveryAdmissibilityReceiptV1`, or quorum certificates are missing/invalid.
- `GATE-EIO-SCALE-TEMPORAL-STRESS`
  - blocks when multi-exabyte replay/recovery stress profiles fail or lack signed temporal authority evidence.

All gates fail closed.
Gate-name mapping to canonical profile gates is one-to-one (`GATE-EIO-*` in this mirror corresponds to `GATE-EIO29-*` in RFC-0029).
Temporal authority rationale: `GATE-EIO-TIME-AUTHORITY` MUST execute before all continuity/replay/recovery/economics gates that consume temporal predicates.

## 8. Efficiency Profile Tests

- Time-authority denial tests: missing envelope, stale envelope, invalid signature set, malformed boundary ID, authority clock mismatch.
- Digest-first under load: control-plane remains within budget envelope.
- High-risk selector coverage: `== 1.0`.
- Pull-only anti-entropy budget controls preserve `tick_floor_met` and prevent queue collapse under adversarial load.
- Anti-entropy convergence horizon test: anti-entropy convergence must satisfy `anti_entropy_convergence_horizon_ref`.
- Replay/recovery cost remains within declared profile bounds for representative workloads.
- Countermetric checks reject Goodhart-style optimization attempts.
- Authority-surface monotonicity test rejects any optimization candidate that restores direct GitHub actuation capabilities.
- Projection-sink independence test: projection-surface state mutations do not alter authoritative FAC lifecycle outcomes.
- Window-bound outage drill: authoritative FAC progression continues through full declared `outage_window_ref` while projection backlog remains bounded.
- Post-outage replay drill: deferred projection replay converges idempotently within `replay_window_ref` without critical-path starvation.
- Cross-window monotonicity drill: revocation frontier in `W_t` dominates stale artifacts from `W_t-1`.
- Adversarial multi-sink projection drill: conflicting sink states cannot influence authoritative outcomes.
- Reconstruction drill: mandatory source/evidence tiers recover only with digest match + BFT quorum certificate + HTF-bound recovery receipt.
- Scale stress drill: exabyte-class receipt fanout + anti-entropy load preserve temporal gate correctness and fail-closed behavior.
- Display-clock isolation test: any use of wall clock in gate truth causes hard deny and emits temporal-authority defect.

## 9. HTF-Bound Claim Contract Registry

| Claim | Predicate | Falsification | Evidence Family ID(s) | Fail-Closed |
|---|---|---|---|---|
| Time authority mandatory | `time_authority_envelope_valid` | stale/unsigned/missing/mismatched boundary envelope accepted | `RFC-0029::EVID-0006`, `RFC-0029::EVID-0009` | deny all external-I/O gates |
| Multi-sink continuity | `projection_multi_sink_continuity_valid` | any sink-failure scenario halts authoritative progression | `RFC-0029::EVID-0009` | deny promotion |
| Replay convergence | `projection_backlog_replay_bounded` | replay diverges or starves critical path | `RFC-0029::EVID-0005`, `RFC-0029::EVID-0009` | deny replay gate |
| Queue fairness | `tick_floor_met(stop_revoke_lane, control_window_ref)` | stop/revocation delayed beyond bounded ticks | `RFC-0029::EVID-0004` | deny queue stability gate |
| Recovery admissibility | `reconstruction_integrity_valid` | quorum/digest/time-authority proof missing | `RFC-0029::EVID-0010` | deny reconstruction gate |
| Temporal monotonicity | `revocation_frontier_monotone && replay_idempotency_monotone` | stale windows dominate fresh windows | `RFC-0029::EVID-0005`, `RFC-0029::EVID-0009` | deny promotion |

## 10. Unified Gate Sequence Binding

This chapter implements Gate 3 of the unified sequence:
- Gate 1 snapshot validity (chapter 17)
- Gate 2 security profile conformance (chapter 15)
- Gate 3 efficiency profile conformance (this chapter), including time-authority, projection continuity, temporal monotonicity, and reconstruction admissibility.
- Gate 4 joint replay/revocation drills
- Gate 5 promotion readiness with uncertainty and independent verifier evidence

## 11. Vocabulary Alignment

Canonical terms adopted from RFC-0016:
- `htf_boundary`
- `authority_clock`
- `time_envelope`
- `tick_floor_met`
- `display_clock` (display-only)

Ambiguous natural-language duration terms are non-normative unless explicitly tagged display-only.

## 12. Assumptions and Defaults

- RFC-0016 remains canonical for normative temporal authority semantics.
- pre-live status allows strict semantic tightening where needed.
- promotion remains fail-closed on temporal ambiguity.
- default dominance policy is `containment/security > verification/correctness > liveness/progress` with HTF authority mandatory at each stage boundary.
