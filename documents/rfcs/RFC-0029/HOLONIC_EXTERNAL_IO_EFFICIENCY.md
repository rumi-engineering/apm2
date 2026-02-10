# RFC-0029 - Holonic External I/O Efficiency Profile over PCAC

Status: DRAFT (profile-definition phase)
Profile ID: `PCAC-PROFILE-EFFICIENCY-v1`
Primary objective: define efficiency and verifier-economics constraints over RFC-0027 lifecycle semantics without weakening security correctness.

## 1. Normative Import Set

Canonical lifecycle semantics:
- `RFC-0027::REQ-0001 .. RFC-0027::REQ-0018`
- source path: `documents/rfcs/RFC-0027/PROOF_CARRYING_AUTHORITY_CONTINUITY.md`

Imported baseline contract:
- `PCAC-SNAPSHOT-BASELINE-ID`
- source path: `documents/rfcs/RFC-0019/17_pcac_implementation_contract_snapshot.md`

Companion constraints:
- `RFC-0020::REQ-0001`, `RFC-0020::REQ-0003`, `RFC-0020::REQ-0004`, `RFC-0020::REQ-0034`, `RFC-0020::REQ-0035`
- `RFC-0018::REQ-HEF-0018`
- `RFC-0019::REQ-0010`, `RFC-0019::REQ-0011`, `RFC-0019::REQ-0013`, `RFC-0019::REQ-0014`
- `RFC-0016::REQ-HTF-0001`, `RFC-0016::REQ-HTF-0003`, `RFC-0016::REQ-HTF-0005`, `RFC-0016::REQ-HTF-0007`
- `RFC-0028::REQ-0007`, `RFC-0028::REQ-0008`, `RFC-0028::REQ-0009`, `RFC-0021::REQ-0013`

Fail-closed import rule:
- if any imported requirement is missing, stale, semantically ambiguous, or unverifiable, efficiency admission evaluates to `deny`.

## 2. Formal Model and Typed Domains

### 2.1 Core Symbols

- `W`: set of HTF windows.
- `w in W`: an HTF window object with fields:
  - `boundary_id`
  - `authority_clock`
  - `tick_start`
  - `tick_end`
- `S`: set of projection sinks.
- `R`: set of revocation scopes.
- `L`: queue lanes = `{stop_revoke, control, consume, replay, projection_replay, bulk}`.
- `T`: artifact tiers = `{TIER-CONTROL, TIER-EVIDENCE-HOT, TIER-EVIDENCE-BULK}`.

Lifecycle cost vector:
- `C = (C_join, C_revalidate, C_consume, C_effect, C_replay, C_recovery)`
- `C_total = sum(C)`

Verdict domain:
- `Verdict = {allow, deny, freeze, escalate}`

Unknown-state guard:
- `unknown(x)` is true if `x` is missing, parse-invalid, stale, unsigned where signature is mandatory, or semantically unresolved.
- mandatory fail-closed macro:
  - `fc(p) = deny` when `unknown(p)`.

### 2.2 Window Algebra

For windows `w_i`, `w_j` with equal `(boundary_id, authority_clock)`:
- `contains(w_i, t) := w_i.tick_start <= t <= w_i.tick_end`
- `adjacent(w_i, w_j) := w_i.tick_end + 1 == w_j.tick_start`
- `disjoint(w_i, w_j) := w_i.tick_end < w_j.tick_start or w_j.tick_end < w_i.tick_start`
- `partial_overlap(w_i, w_j) := !disjoint(w_i, w_j) and !(w_i == w_j) and !adjacent(w_i, w_j)`

Normative rule:
- temporal comparisons are admissible only for windows with the same `boundary_id` and `authority_clock`.
- cross-boundary or cross-clock comparisons are non-computable and fail closed.

## 3. TP-EIO29 Temporal Semantics (Normative)

All `TP-EIO29-*` predicates are machine-checkable contracts evaluated by `TemporalPredicateEvaluatorV1`.

Ownership boundary for temporal predicates:
- canonical semantic anchor: RFC-0016 temporal substrate semantics.
- canonical cross-profile contract anchor: RFC-0019 snapshot/matrix temporal contract surfaces.
- this RFC defines efficiency-plane evaluation and economics coupling for `TP-EIO29-*`; it does not override security-plane temporal ownership.

### 3.1 Predicate Definitions

`TP-EIO29-001` `time_authority_envelope_valid`
- inputs:
  - `TimeAuthorityEnvelopeV1 e`
  - expected `(boundary_id, authority_clock)`
  - evaluation window `w_eval`
- predicate:
  - `verify_signature_set(e.signature_set)`
  - `e.boundary_id == w_eval.boundary_id`
  - `e.authority_clock == w_eval.authority_clock`
  - `e.tick_start <= w_eval.tick_start and e.tick_end >= w_eval.tick_end`
  - `ttl_fresh(e.ttl, w_eval)`
  - `e.deny_on_unknown == true`
- falsification:
  - any accepted gate with stale/invalid/missing envelope.
- fail-closed:
  - `unknown(e) -> deny`.

`TP-EIO29-002` `freshness_horizon_satisfied`
- inputs:
  - `freshness_horizon_ref`
  - current window `w_now`
  - revocation frontier snapshot `rf_now`
- predicate:
  - `window_resolves(freshness_horizon_ref)`
  - `w_now.tick_end <= freshness_horizon_ref.tick_end`
  - `revocation_frontier_current(rf_now)`
- falsification:
  - admission when `w_now` exceeds freshness horizon or frontier is stale.
- fail-closed:
  - unresolved `freshness_horizon_ref` or frontier uncertainty denies.

`TP-EIO29-003` `anti_entropy_convergence_horizon_satisfied`
- inputs:
  - `anti_entropy_convergence_horizon_ref`
  - required authority-critical sets `A_required`
  - convergence receipts `R_converge`
- predicate:
  - `forall a in A_required, converged(a, anti_entropy_convergence_horizon_ref, R_converge)`
- falsification:
  - any required set non-converged beyond horizon.
- fail-closed:
  - missing receipts or unresolved required set denies.

`TP-EIO29-004` `replay_convergence_horizon_satisfied`
- inputs:
  - `replay_convergence_horizon_ref`
  - backlog state `B`
  - replay receipts `ReplayConvergenceReceiptV1`
- predicate:
  - `replay_converges_idempotently_within(B, replay_convergence_horizon_ref)`
- falsification:
  - backlog remains unresolved or diverges after horizon end.
- fail-closed:
  - missing replay receipt fields denies.

`TP-EIO29-005` `projection_multi_sink_continuity_valid`
- inputs:
  - sink set `S`
  - scenario generator `sink_failure_set(S)`
  - continuity profile `ProjectionSinkContinuityProfileV1`
- predicate:
  - `forall scenario in sink_failure_set(S), authoritative_truth_plane_progress(scenario) and bounded_projection_backlog(scenario)`
- falsification:
  - any scenario halts authoritative truth-plane progression.
- fail-closed:
  - unknown scenario verdict denies.

`TP-EIO29-006` `revocation_frontier_monotone`
- inputs:
  - adjacent windows `w_t`, `w_t1`
  - revocation frontiers `rf_t`, `rf_t1`
- predicate:
  - `adjacent(w_t, w_t1)`
  - `forall r in R, rf_t1[r] >= rf_t[r]`
- falsification:
  - any scope regresses in later window.
- fail-closed:
  - non-adjacent comparison or missing scope entry denies.

`TP-EIO29-007` `replay_idempotency_monotone`
- inputs:
  - adjacent windows `w_t`, `w_t1`
  - admitted effect sets `E_t`, `E_t1`
  - revoked set `Rev_t1`
- predicate:
  - `adjacent(w_t, w_t1)`
  - `forall e in Rev_t1, e notin E_t1`
  - `effects_in_later_window_do_not_duplicate_authoritative_outcome(E_t, E_t1)`
- falsification:
  - replay in `w_t1` resurrects revoked or already-accounted effect.
- fail-closed:
  - unresolved effect identity or dedup evidence denies.

`TP-EIO29-008` `promotion_temporal_ambiguity == false`
- inputs:
  - verdict bundle over `TP-EIO29-001..007`
  - window resolution status
  - evaluator disagreement status
- predicate:
  - no unknown temporal fields
  - no unresolved window reference
  - no unresolved evaluator disagreement
- falsification:
  - any promotion pass with unknown temporal state.
- fail-closed:
  - unresolved ambiguity denies promotion.

### 3.2 Canonical Evaluator and Disagreement Handling

Canonical evaluator tuple:
- `(evaluator_id, predicate_id, contract_digest_set, time_authority_ref, window_ref, verdict, deny_reason)`
- required `evaluator_id = temporal_predicate_evaluator_v1`

Determinism contract:
- for fixed tuple inputs, independent verifiers MUST return identical `verdict` and `deny_reason`.
- equality target is byte-identical canonicalized output payloads.
- promotion-critical temporal predicate execution is integer/tick-space only; floating-point arithmetic is non-admissible.

Disagreement contract:
- let `D = set of verifier verdicts`.
- if `|D| > 1`:
  - emit `TemporalDisagreementReceiptV1`
  - set `temporal_disagreement = true`
  - Tier2+ behavior: `freeze`
  - run cross-profile temporal arbitration and emit `TemporalArbitrationReceiptV1` with one of:
    - `ARBITRATION_AGREED_ALLOW`
    - `ARBITRATION_AGREED_DENY`
    - `ARBITRATION_DISAGREEMENT_TRANSIENT`
    - `ARBITRATION_DISAGREEMENT_PERSISTENT`
  - adjudication deadline: bounded by `adjudication_deadline_window_ref`
  - if deadline expires unresolved: escalate to `deny` for promotion.

### 3.3 Boundary-Case Truth Table

| Case | Condition | Allowed Temporal Inference | Gate Outcome |
|---|---|---|---|
| Exact match | `w_i == w_j` | full comparison | continue |
| Adjacent forward leap | `adjacent(w_i, w_j)` | monotonic checks allowed | continue |
| Partial overlap | `partial_overlap(w_i, w_j)` | only overlap-safe predicates | deny Tier2+ promotion unless explicitly modeled |
| Disjoint gap | `disjoint(w_i, w_j)` | no continuity inference | deny |
| Cross-boundary mismatch | `boundary_id` differs | none | deny |
| Cross-clock mismatch | `authority_clock` differs | none | deny |
| Unresolved window ref | lookup failure | none | deny |

### 3.3.1 Overlap-Safe Predicate Set

For `partial_overlap(w_i, w_j)`, only predicates that do not require adjacency/disjoint continuity assumptions are overlap-safe.

Normative overlap-safe set:
- `TP-EIO29-001` (`time_authority_envelope_valid`)
- `TP-EIO29-002` (`freshness_horizon_satisfied`)

Non-overlap-safe examples (must deny under partial overlap unless separately modeled):
- `TP-EIO29-006` (`revocation_frontier_monotone`) because it requires adjacent windows.
- `TP-EIO29-007` (`replay_idempotency_monotone`) because it requires adjacent-window replay continuity assumptions.

### 3.4 CAC Binding for `TP-EIO29-*` Predicates

Every `TP-EIO29-*` predicate MUST evaluate against CAC-resolved typed inputs and a canonical evaluator tuple:
- `(predicate_id, required_cac_inputs[], contract_digest_set, canonicalizer_tuple, time_authority_ref, window_ref, verdict, deny_reason)`

`canonicalizer_tuple = (canonicalizer_id, canonicalizer_version, canonicalizer_vectors_ref)`.

| Predicate | `required_cac_inputs[]` (`kind -> schema_id`) | Digest binding and fail-closed rule |
|---|---|---|
| `TP-EIO29-001` | `time.envelope -> apm2.time_authority_envelope.v1` | envelope digest MUST be present in `contract_digest_set`; missing/stale/invalid signature denies. |
| `TP-EIO29-002` | `temporal.slo.profile -> apm2.temporal_slo_profile.v1`, `revocation.frontier.snapshot -> apm2.revocation_frontier_snapshot.v1` | freshness horizon + frontier digests MUST resolve for `w_now`; any unresolved digest denies. |
| `TP-EIO29-003` | `anti_entropy.convergence.receipt -> apm2.anti_entropy_convergence_receipt.v1` | required authority-set convergence digests MUST all be present; any missing digest denies. |
| `TP-EIO29-004` | `replay.convergence.receipt -> apm2.replay_convergence_receipt.v1` | replay receipt digest MUST prove bounded idempotent convergence for referenced window. |
| `TP-EIO29-005` | `projection.sink.continuity.profile -> apm2.projection_sink_continuity_profile.v1`, `projection.continuity.window -> apm2.projection_continuity_window.v1`, `sink.identity.snapshot -> apm2.sink_identity_snapshot.v1` | scenario set digest, outage window digest, and sink identity digest MUST be jointly bound in one `contract_digest_set`. |
| `TP-EIO29-006` | `revocation.frontier.snapshot -> apm2.revocation_frontier_snapshot.v1`, `time.envelope -> apm2.time_authority_envelope.v1` | adjacent-window frontier digests MUST be present and monotone; non-adjacent or missing scope entries deny. |
| `TP-EIO29-007` | `replay.convergence.receipt -> apm2.replay_convergence_receipt.v1`, `authority.kernel.decision -> apm2.authority_kernel_decision.v1` | effect identity digests and replay dedup digests MUST be present; unresolved effect identity denies. |
| `TP-EIO29-008` | `temporal.disagreement.receipt -> apm2.temporal_disagreement_receipt.v1`, `temporal.arbitration.receipt -> apm2.temporal_arbitration_receipt.v1`, `temporal.evaluator -> apm2.temporal_predicate_evaluator.v1` | ambiguity verdict MUST be digest-bound to `TP-EIO29-001..007` verdict bundle and arbitration outcome; any unknown digest entry denies promotion. |

Schema resolution, digest checks, and canonicalizer checks are mandatory preconditions to predicate evaluation.

### 3.5 Deterministic Computational Model

Promotion-critical predicate evaluation MUST use:
- integer/tick-space arithmetic for temporal and budget computations.
- canonicalized payload bytes for equality checks (semantic-only equality is insufficient).
- schema/domain-separated hashing including `schema_id` + `schema_major`.

Fail-closed ambiguity classes:
- digest collision ambiguity
- non-canonical string encoding ambiguity
- non-replayable evaluator output ambiguity

Any ambiguity class above is non-admissible for promotion-critical outcomes.

## 4. Degraded-Mode Ladder and Halting Strategy

### 4.1 Modes

`D0` Nominal:
- all temporal/security predicates valid.
- full gate path enabled.

`D1` Constrained Degrade:
- bounded non-critical optimization features disabled.
- truth-plane and stop/revoke lanes fully active.
- projection replay may be rate-limited.

`D2` Continuity-Only:
- authoritative truth-plane progression only.
- external projection writes blocked except explicitly approved emergency sink.
- replay allowed only within control-safe slices.

`D3` Fail-Closed Freeze:
- promotion-critical operations frozen.
- only revocation propagation, stop orders, and recovery diagnostics allowed.
- bounded evidence-regeneration/time-authority-recovery workflows are admissible when they cannot authorize new external effects.

`D4` Emergency Halt:
- explicit halt of authority-bearing admissions.
- requires `HaltStateReceiptV1` and bounded recovery plan.

### 4.2 Transition and Escalation

Transition predicate:
- `mode_next = f(mode_current, predicate_vector, freeze_budget, halt_risk_budget)`

Mandatory bounds:
- `max_fail_closed_freeze_windows` is profile-declared.
- if `freeze_duration > max_fail_closed_freeze_windows`, automatic escalation to `D4` plus adjudication workflow.

Halt risk budget:
- `halt_risk_budget = (max_freeze_windows, max_blocked_promotions, max_control_path_delay_ticks)`
- promotion is denied if risk budget is consumed even when some efficiency KPIs improve.

Joint-state arbitration with security profile:
- operational state is evaluated as `(S_i, D_j)` where `S_i` is security mode and `D_j` is efficiency mode.
- arbitration uses typed dominance comparator (`mode_dominance_select`) over `(profile_id, mode_symbol, severity_class)` tuples; unresolved comparator state is fail-closed deny.
- security constraints dominate when policy interpretations differ; efficiency policy may only add restrictions.
- this 2-profile arbitration is a specialization of RFC-0019 multi-profile composition algebra.

### 4.3 Halt vs Deadlock Distinction

`halt_detected`:
- explicit stop order OR hard gate deny OR freeze budget exhaustion.

`deadlock_detected`:
- `halt_detected == false`
- enabled workset non-empty
- no authoritative progress for `deadlock_detection_window_ref`

Required behavior:
- `halt_detected` -> deterministic halt receipts and recovery workflow.
- `deadlock_detected` -> escalation to scheduler remediation; no silent stall allowed.

## 5. Economics, Queueing, and Anti-Entropy Contracts

### 5.1 Constrained Optimization Objective

Objective:
- `min C_total`

Hard constraints (non-regressible):
- `pcac_receipt_completeness == 1.0`
- `pcac_consume_deny_correctness == 1.0`
- `pcac_revocation_dominant == true`
- `pcac_single_consume_enforced == true`
- `boundary_flow_admissible == true`
- `disclosure_control_policy_preserved == true` (phase-qualified policy mode; current default mode: trade-secret-only)
- `projection_isolation_non_regression == true`
- `rolespec_context_injection_deterministic == true`
- `rolespec_context_minimality_enforced == true`
- `TP-EIO29-001..008 all true`

Any optimization with reduced `C_total` is non-admissible when any hard constraint regresses.

### 5.2 Queue Admission Math

For lane `l in L`:
- arrival rate `lambda_l`
- service rate `mu_l`
- utilization `rho_l = lambda_l / mu_l`
- lane budget `B_l`

Admission predicate:
- `temporal_lane_admit(req, l) = if l == stop_revoke then (TP-EIO29-001 or local_monotonic_emergency_time_valid(req)) else TP-EIO29-001`
- `admit(req, l) = temporal_lane_admit(req, l) and role_context_injection_admissible(req.role_spec_hash, req.context_pack_manifest_hash, req.required_selector_digest_set) and tokens(l) >= cost(req) and backlog(l) <= B_l and rho_l <= rho_max(l)`

Containment-priority carve-out:
- `local_monotonic_emergency_time_valid(req)` is admissible only for `stop_revoke` lane operations that reduce authority (revoke/stop) and MUST NOT authorize new external effects.
- if full envelope validity is unavailable, stop/revoke operations remain fail-closed to authority expansion and fail-open only to authority reduction actions.

Service discipline:
- strict priority for `stop_revoke`.
- weighted deficit round robin for remaining lanes with mandatory reservation:
  - `reservation(stop_revoke) >= R_stop_min`
  - `reservation(control) >= R_control_min`

### 5.3 Anti-Starvation Proof Obligations

Required invariants:
- `tick_floor_met(stop_revoke_lane, control_window_ref)`
- `critical_path_reservation_enforced == true`
- replay lane cannot starve stop/revoke or control lanes:
  - `wait_ticks(stop_revoke) <= W_stop_max`
  - `wait_ticks(control) <= W_control_max`
  - replay dispatch respects `queue_budget.replay_slice_ticks`

Mandatory negative tests:
- replay flood with sustained sink outage
- mixed control + replay adversarial bursts
- low-rate attacker traffic designed for defender-cost exhaustion

### 5.4 Pull-Only Anti-Entropy Bound

Anti-entropy must remain pull-only and budget-bound:
- no unsolicited authority acceptance from pushed data-plane payloads.
- oversized proof ranges or proof bytes are denied.
- bounded decoding applies pre-decode and post-decode.

### 5.5 RoleSpec Context Injection Contract (Primary Efficiency and Quality Lever)

For role `r` in iteration/window `w`:
- `ctx_injected(r, w)`: context atom set injected into role runtime.
- `ctx_required(r, w)`: deterministic selector closure from hash-addressed CAC artifacts.

Deterministic selector closure inputs:
- `role_spec_hash`
- `context_pack_spec_hash`
- `context_pack_manifest_hash`
- `reasoning_selector_hash`
- `budget_profile_hash`

Primary admissibility predicate:
- `role_context_injection_admissible(r, w) = (ctx_injected(r, w) == ctx_required(r, w)) and digest_set_complete(ctx_required) and canonicalizer_tuple_consistent(ctx_required) and no_unplanned_context_reads(r, w)`

Cost and quality coupling:
- `C_context(r, w) = bytes(ctx_injected(r, w)) + retrieval_cost(ctx_injected(r, w)) + verifier_cost(ctx_injected(r, w))`
- optimization is admissible only when `delta(C_context) < 0` and `role_context_injection_admissible` remains true.

Fail-closed:
- unresolved selector digest, unresolved context artifact hash, or any ambient read outside selector closure is non-admissible for promotion-critical paths.

## 6. Projection Sink Independence and Byzantine Model

### 6.1 Trust-Plane Separation

Authoritative decision inputs must be truth-plane only:
- truth-plane = CAS + ledger + policy roots + signed time authority.
- projection sink state is never an authority input.

Predicate:
- `projection_sink_independence_valid = authority_inputs subseteq truth_plane_inputs`

### 6.2 Byzantine Projection Worker Assumptions

Let projection worker set be `P` with `|P| = n` and byzantine bound `f`.

Admissibility assumptions:
- `n >= 3f + 1`
- projection effect certification requires quorum `q >= 2f + 1` over receipt chain and sink target digest.
- worker disagreement emits `ProjectionWorkerDisagreementReceiptV1` and fails closed for promotion-critical flows.

Explicit model scope:
- network model for liveness claims: partial synchrony with eventual synchrony.
- adversary model: static Byzantine up to `f` per declared window and failure-domain envelope.
- safety under persistent partitions remains fail-closed deny/freeze; no global liveness claim under permanent partition.
- the concrete protocol family (for example PBFT/HotStuff-class) MUST be declared by policy object and evidenced before Tier2+ promotion-critical admission.

Property-first admissibility rule:
- canonical requirement is property-level, not protocol-name-level: quorum safety, replayable certificate validation, and bounded liveness assumptions under declared network/adversary model.
- any BFT protocol family is admissible when these properties are evidenced for the active policy profile.

Current reference implementation profile:
- implementation instance: Chained HotStuff for quorum-certificate progression.
- safety evidence instance: 3-chain commit rule verification and valid quorum certificates over Ed25519 signer set.
- liveness assumption instance: eventual synchrony with bounded view-change progression under active pacemaker.
- complexity profile instance: steady-state linear message fanout in validator set size (`O(n)`) for proposal/prepare/commit propagation.

### 6.3 Sink Identity, Key Rotation, and DNS Attack Surface

Mandatory sink identity object:
- `SinkIdentitySnapshotV1` includes:
  - `sink_id`
  - endpoint digest(s)
  - signing key set digest
  - DNS binding proof digest
  - validity window

Rules:
- key rotation requires signed overlap window with old and new key sets.
- DNS changes require signed endpoint manifest update before actuation.
- endpoint mismatch or DNS proof failure marks sink compromised and quarantines projection lane.

## 7. Federation Semantics and Partition Tolerance

### 7.1 Partition Topology Truth Table

| Topology | Truth-plane quorum | Projection sinks | Admissible Operations | Promotion |
|---|---:|---:|---|---|
| A: projection-only partition | intact | partitioned | truth-plane progression, backlog buffering | blocked if continuity predicates unresolved |
| B: cross-cell anti-entropy lag | intact local, delayed remote | mixed | local authoritative actions with bounded import restrictions | blocked for cross-cell promotion |
| C: truth-plane quorum loss | lost | any | stop/revoke only, diagnostics | deny |
| D: split-brain truth planes | divergent | any | freeze + revocation propagation + adjudication | deny |
| E: full outage with recoverable logs | unknown temporary | down | continuity-only mode if temporal authority remains valid | deny promotion until recovery proof |

### 7.2 Revocation Under Split-Brain

Let `rf_a`, `rf_b` be frontiers from split partitions.

Merge law:
- `rf_merge(scope) = max(rf_a(scope), rf_b(scope))`

Safety rule:
- revocation wins over stale authorization.
- no promotion while any scope has unresolved frontier conflict.

Predicate:
- `split_brain_revocation_safe = frontier_merge_monotone and no_revoked_revival`

## 8. Recoverability and Reconstruction Admissibility

### 8.1 Tiered Redundancy Contract

Each tier declares:
- `(k, n, failure_domains, repair_slo, p_unrecoverable_max)`

Required policy:
- `TIER-CONTROL`: replication-first + low-latency retrieval.
- `TIER-EVIDENCE-HOT`: hybrid replication + erasure.
- `TIER-EVIDENCE-BULK`: erasure-preferred with bounded repair envelope.

Disclosure interaction rule:
- cross-trust-boundary fragment placement requires `redundancy_purpose_declassification_valid == true` with scoped receipt evidence.
- if active disclosure policy mode forbids required fragment placement, redundancy plan MUST stay trust-boundary-local or is non-admissible.

### 8.2 Erasure + BFT Reconstruction Admissibility Criterion

Reconstruction is admissible iff all hold:
- `erasure_decode_valid == true`
- `recovered_digest == expected_digest_from_source_trust_snapshot`
- `bft_quorum_recovery_valid == true`
- `RecoveryAdmissibilityReceiptV1.time_authority_ref` resolves to valid `TP-EIO29-001`

When `bft.recovery.quorum.certificate` references Chained HotStuff evidence, admissibility additionally requires:
- quorum certificate signer cardinality satisfies `>= 2f + 1` for declared validator set.
- 3-chain commit linkage is verifier-replayable from certified block ancestry.
- quorum certificate signature set verifies against active validator keyset and epoch.

Failure mode classification (diagnostic mandatory even when verdict is deny):
- `ERASURE_UNAVAILABLE_BFT_VALID`: data unavailable but trust quorum intact; remediation prioritizes redundancy repair.
- `ERASURE_VALID_BFT_INVALID`: data available but integrity/trust disagreement; remediation prioritizes quorum/integrity re-verification and trust-root checks.
- `ERASURE_UNAVAILABLE_BFT_INVALID`: data unavailable and untrusted; remediation requires both repair and trust reconstruction workflow.

Any missing component is fail-closed deny.

## 9. Cryptography and Compromise Response

### 9.1 Algorithm Agility and Downgrade Resistance

Policy object:
- `CryptoAgilityPolicyV1` with:
  - allowed signature algorithms by epoch
  - minimum security class by risk tier
  - forbidden downgrade transitions

Negotiation rule:
- choose strongest mutually admissible algorithm for the current epoch.
- unknown or unlisted algorithm for authority paths denies.

### 9.2 Key Compromise Response Windows

Compromise timeline windows:
- `W_detect`: max ticks to detect and classify suspected key compromise.
- `W_revoke`: max ticks from detection to revocation publication.
- `W_reseal`: max ticks to reseal mandatory artifacts under clean keys.

SLO predicate:
- `key_compromise_slo_met = detect_within(W_detect) and revoke_within(W_revoke) and reseal_within(W_reseal)`

### 9.3 Retroactive Trust Invalidation and Recovery

If key `K` is compromised at `compromise_epoch`:
- artifacts signed only by `K` after `compromise_epoch` are non-trusted until re-proven.
- artifacts before `compromise_epoch` remain conditionally trusted only with independent non-compromised verifier corroboration.
- post-compromise promotion requires replay under clean key epoch.

## 10. Security Economics as Repeated Game

Let attacker strategy at step `t` be `a_t`, defender policy `d_t`.

Per-window costs:
- `A_t = attacker_cost_lower_bound_estimate(a_t, observed_signals_t)`
- `D_t = defender_cost(d_t, a_t)`
- `ACR_t = D_t / max(A_t, epsilon)`
- `A_conf_t = confidence(attacker_cost_lower_bound_estimate)` in `[0.0, 1.0]`

Required evaluation horizon:
- thresholds are enforced on sequence `{ACR_t}` over `H` windows, not one-shot snapshots.
- `slope(ACR_t over H)` is computed using declared estimator profile (`ols` baseline) and minimum sample-size contract.
- `epsilon` MUST be policy-declared and evidence-bound for the active epoch.
- low-confidence handling: when `A_conf_t < A_conf_min`, policy MUST apply conservative bound inflation or freeze promotion-critical optimization decisions until confidence recovers.

Non-admissible conditions:
- sustained attacker-favorable trend: `slope(ACR_t over H) > 0` beyond policy threshold.
- defender-cost exhaustion risk above threshold under low-rate prolonged attacks.
- "economically safe but operationally brittle" state where ACR passes but stop/revoke tick floors, freeze budgets, or temporal predicates regress.
- unresolved attacker-cost confidence below policy minimum for `H_conf` consecutive windows.

## 11. Human and Organizational Failure Model

Modeled operator mistakes:
- misconfigured window reference
- wrong boundary ID or authority clock
- stale policy snapshot deployment
- display-clock value accidentally routed into authority field
- incorrect sink identity/endpoint mapping

Mandatory UX constraints:
- authority fields accept only typed HTF refs, never free-form wall-clock strings.
- boundary/clock changes require dual confirmation plus signed diff preview.
- promotion UI must display explicit `TP-EIO29-*` verdict vector and ambiguity status.

## 12. Evidence Quality and Freshness Contracts

### 12.1 Statistical Power Floors

For load, chaos, and adversarial stress claims:
- minimum statistical power: `>= 0.90`
- significance threshold: `alpha <= 0.01`
- required sample sizing evidence must be included in receipts.

### 12.2 Reproducibility Across Environments

Mandatory reproducibility matrix:
- at least three hardware/runtime classes per claim family.
- deterministic replay checks for each class.
- divergence classification with root-cause receipts.

### 12.3 Evidence Freshness SLA

`EvidenceFreshnessSlaV1` must declare max admissible age by evidence class.

Fail-closed rule:
- stale evidence auto-transitions gate state to `BLOCKED`.
- promotion cannot proceed with expired evidence receipts.

### 12.4 Evidence Throughput Dominance Invariant

For each promotion-critical evidence class `c`:
- `evidence_generation_throughput(c) > evidence_expiry_rate(c)` is required for steady-state promotability.

Violation handling:
- enter constrained degrade (`D1`) with prioritized evidence regeneration for violated classes.
- block optimization-class promotions until throughput dominance is restored.
- escalate to freeze/halt paths only if dominance violation persists beyond declared recovery budget.
- if already in `D3` due to correlated temporal disagreement and freshness failure, prioritized evidence regeneration remains admissible in bounded recovery lanes under no-authority-expansion constraints.

## 13. Physical and Infrastructure Assumptions

First-class scenarios:
- monotonic clock hardware fault
- VM pause/resume skew
- NTP turbulence
- leap-second and leap-smear mismatch
- power brownout
- network brownout/packet reordering storms
- partial storage corruption

Mandatory behavior:
- ambiguity in authority clock validity denies authority-bearing external I/O.
- recovery drills must include these scenarios with signed receipts.

### 13.1 Hardware Tier Envelopes

`HardwareTierEnvelopeV1`:
- `H1` dev class
- `H2` production class
- `H3` high-throughput class

Claims about exabyte or higher replay/recovery envelopes are admissible only with measured tier evidence and tier-specific queue/recovery bounds.

## 14. Inter-RFC Semantic Drift Detection

### 14.1 Contract Surfaces

Semantic compatibility contract includes objects from:
- RFC-0016: `TimeAuthorityEnvelopeV1` semantics
- RFC-0019: snapshot and gate-order contracts
- RFC-0028: security interlock predicates
- RFC-0029: economics and temporal predicates

### 14.2 Semantic Diff Classification

`SemanticDiffReportV1.class`:
- `NON_SEMANTIC`
- `SEMANTIC_SAFE`
- `SEMANTIC_RISKY`
- `AMBIGUOUS`

Gate policy:
- `SEMANTIC_RISKY` and `AMBIGUOUS` are non-promotable.
- `AMBIGUOUS` requires adjudication before `semantic_drift_deadline_window_ref`; timeout is fail-closed deny.

## 15. RFC-0029 Requirement Profile (Stable Namespace)

- `RFC-0029::REQ-0001` canonical economics profile and objective constraints.
- `RFC-0029::REQ-0002` digest-first selector completeness.
- `RFC-0029::REQ-0003` verification amortization and cache discipline.
- `RFC-0029::REQ-0004` budgeted anti-entropy and risk-aware queueing in HTF windows.
- `RFC-0029::REQ-0005` replay/recovery boundedness and idempotency closure.
- `RFC-0029::REQ-0006` observability and security-interlocked optimization gates.
- `RFC-0029::REQ-0007` disclosure-control interlock non-regression.
- `RFC-0029::REQ-0008` authority-surface monotonicity and direct-GitHub non-regression.
- `RFC-0029::REQ-0009` multi-sink outage continuity with bounded replay.
- `RFC-0029::REQ-0010` tiered erasure + BFT reconstruction admissibility.

This revision does not introduce new requirement IDs; it tightens semantics bound to the existing namespace.

## 16. Gate Registry and CAC Contract Binding

### 16.1 Gate Registry

- `GATE-EIO29-SNAPSHOT`
  - blocks on snapshot drift.
- `GATE-EIO29-TIME-AUTHORITY`
  - enforces `TP-EIO29-001`.
- `GATE-EIO29-BOUNDS`
  - blocks on verifier-economics bound violations and RoleSpec context-injection contract violations.
- `GATE-EIO29-COUNTERMETRICS`
  - blocks on missing/regressed KPI-countermetric pairs or missing context-injection quality counters.
- `GATE-EIO29-REPLAY-RECOVERY`
  - enforces `TP-EIO29-004` and reconstruction receipts.
- `GATE-EIO29-INTERLOCK`
  - hard security interlock.
- `GATE-EIO29-QUEUE-STABILITY`
  - enforces queue tick floors and anti-starvation invariants.
- `GATE-EIO29-TEMPORAL-MONOTONICITY`
  - enforces `TP-EIO29-006..008`.
- `GATE-EIO29-REDUNDANCY-RECOVERABILITY`
  - enforces tier recoverability envelope.
- `GATE-EIO29-TRADE-SECRET-INTERLOCK`
  - enforces non-regression on disclosure-control posture (default mode: trade-secret-only).
- `GATE-EIO29-PROJECTION-ISOLATION-INTERLOCK`
  - enforces authority-surface monotonicity for projection paths.
- `GATE-EIO29-PROJECTION-SINK-CONTINUITY`
  - enforces `TP-EIO29-005` plus backlog boundedness.
- `GATE-EIO29-RECONSTRUCTION-ADMISSIBILITY`
  - requires erasure + BFT + digest-match + valid temporal authority.
- `GATE-EIO29-SCALE-TEMPORAL-STRESS`
  - enforces scale stress conformance.
- `GATE-EIO29-DEGRADE-BUDGET`
  - blocks when freeze/halt risk budget exhausted.
- `GATE-EIO29-CRYPTO-AGILITY`
  - blocks on algorithm downgrade risk or stale key-epoch policy.
- `GATE-EIO29-EVIDENCE-QUALITY`
  - blocks on insufficient statistical power, reproducibility gaps, or stale evidence.
- `GATE-EIO29-SEMANTIC-DRIFT`
  - blocks on `SEMANTIC_RISKY` or `AMBIGUOUS` cross-RFC drift.

### 16.2 CAC Contract Registry (Temporal/Economics Plane)

Each gate MUST validate `required_cac_inputs[]` as:
- `(kind, schema_id, schema_major, canonicalizer_id, canonicalizer_version, digest, signature_set, window_or_ttl_ref)`

Schema IDs MUST resolve via CAC schema registry (`kind = schema.definition`) and canonicalizer tuple MUST match the active snapshot tuple for promotion-critical evaluation.

| Gate | `required_cac_inputs[]` (`kind -> schema_id`) | Digest and canonicalizer binding |
|---|---|---|
| `GATE-EIO29-SNAPSHOT` | `snapshot.report -> apm2.pcac_snapshot_report.v1` | snapshot digest MUST cover all required economics/temporal contract digests. |
| `GATE-EIO29-TIME-AUTHORITY` | `time.envelope -> apm2.time_authority_envelope.v1`, `temporal.evaluator -> apm2.temporal_predicate_evaluator.v1` | envelope + evaluator digests MUST be present and canonicalizer-compatible with snapshot. |
| `GATE-EIO29-BOUNDS` | `economics.constraint.profile -> apm2.economics_constraint_profile.v1`, `role.spec.contract -> cac.holon_contract.v1`, `context_pack.spec -> cac.context_pack_spec.v1`, `context_pack.manifest -> cac.context_pack_manifest.v1`, `reasoning.selector -> cac.reasoning_selector.v1`, `budget.profile -> cac.budget_profile.v1` | bounds profile digest and RoleSpec context selector digests MUST match active policy epoch root and canonicalizer tuple. |
| `GATE-EIO29-COUNTERMETRICS` | `economics.constraint.profile -> apm2.economics_constraint_profile.v1`, `countermetric.profile -> apm2.countermetric_profile.v1`, `receipt.run -> cac.run_receipt.v1` | KPI/countermetric pairing digests MUST be complete and signed; `receipt.run.context_pack_manifest_hash` MUST match the admitted manifest digest. |
| `GATE-EIO29-REPLAY-RECOVERY` | `replay.convergence.receipt -> apm2.replay_convergence_receipt.v1`, `recovery.admissibility.receipt -> apm2.recovery_admissibility_receipt.v1` | replay + recovery digests MUST bind to the same `window_ref` and `time_authority_ref`. |
| `GATE-EIO29-INTERLOCK` | `authority.kernel.decision -> apm2.authority_kernel_decision.v1`, `boundary.flow.policy -> apm2.boundary_flow_policy.v1` | interlock digest set MUST prove no hard-safety regression under optimization candidate. |
| `GATE-EIO29-QUEUE-STABILITY` | `temporal.slo.profile -> apm2.temporal_slo_profile.v1`, `projection.continuity.window -> apm2.projection_continuity_window.v1` | tick-floor and queue-budget digests MUST bind to identical HTF boundary and authority clock. |
| `GATE-EIO29-TEMPORAL-MONOTONICITY` | `revocation.frontier.snapshot -> apm2.revocation_frontier_snapshot.v1`, `replay.convergence.receipt -> apm2.replay_convergence_receipt.v1`, `temporal.disagreement.receipt -> apm2.temporal_disagreement_receipt.v1`, `temporal.arbitration.receipt -> apm2.temporal_arbitration_receipt.v1` | adjacent-window monotonicity digests MUST be complete and arbitration-bound; unresolved arbitration digest denies promotion. |
| `GATE-EIO29-REDUNDANCY-RECOVERABILITY` | `recoverability.profile -> apm2.recoverability_profile.v1`, `codebase.recovery.profile -> apm2.codebase_recovery_profile.v1` | tier envelope digests MUST match current `(k,n,failure_domains,repair_slo)` declaration. |
| `GATE-EIO29-TRADE-SECRET-INTERLOCK` | `trade.secret.policy -> apm2.trade_secret_policy_profile.v1` | trade-secret policy digest MUST match security-plane policy digest for same epoch. |
| `GATE-EIO29-PROJECTION-ISOLATION-INTERLOCK` | `projection.isolation.policy -> apm2.projection_isolation_policy.v1`, `sink.identity.snapshot -> apm2.sink_identity_snapshot.v1` | authority-surface digest and sink identity digest MUST cohere with truth-plane trust snapshot. |
| `GATE-EIO29-PROJECTION-SINK-CONTINUITY` | `projection.sink.continuity.profile -> apm2.projection_sink_continuity_profile.v1`, `projection.continuity.window -> apm2.projection_continuity_window.v1`, `time.envelope -> apm2.time_authority_envelope.v1` | outage/replay/queue-window digests MUST bind to one valid time-authority envelope. |
| `GATE-EIO29-RECONSTRUCTION-ADMISSIBILITY` | `erasure.recovery.receipt -> apm2.erasure_recovery_receipt.v1`, `bft.recovery.quorum.certificate -> apm2.bft_recovery_quorum_certificate.v1`, `recovery.admissibility.receipt -> apm2.recovery_admissibility_receipt.v1`, `source.trust.snapshot -> apm2.source_trust_snapshot.v1` | decode/quorum/digest-match/time-authority digests MUST all be present; any missing digest denies. |
| `GATE-EIO29-SCALE-TEMPORAL-STRESS` | `hardware.tier.envelope -> apm2.hardware_tier_envelope.v1`, `temporal.slo.profile -> apm2.temporal_slo_profile.v1`, `projection.sink.continuity.profile -> apm2.projection_sink_continuity_profile.v1` | stress verdict digest MUST include tier-tagged percentile/tick outputs and HTF window refs. |
| `GATE-EIO29-DEGRADE-BUDGET` | `halt.state.receipt -> apm2.halt_state_receipt.v1`, `temporal.disagreement.receipt -> apm2.temporal_disagreement_receipt.v1` | freeze/halt risk budget digest MUST be monotone and time-authority bound. |
| `GATE-EIO29-CRYPTO-AGILITY` | `crypto.agility.policy -> apm2.crypto_agility_policy.v1`, `time.envelope -> apm2.time_authority_envelope.v1` | algorithm policy digest MUST resolve for active epoch and authority window. |
| `GATE-EIO29-EVIDENCE-QUALITY` | `evidence.quality.profile -> apm2.evidence_quality_profile.v1`, `evidence.freshness.sla -> apm2.evidence_freshness_sla.v1` | quality and freshness digests MUST be current for all promotion-critical evidence classes. |
| `GATE-EIO29-SEMANTIC-DRIFT` | `semantic.diff.report -> apm2.semantic_diff_report.v1` | semantic diff digest MUST be signed and canonicalizer-compatible before classification. |

### 16.3 CAC Validation Order, Defect Classes, and Tier Behavior

Validation order for every `GATE-EIO29-*` evaluation:
1. schema resolution (`schema_id`, `schema_major`);
2. canonicalizer tuple compatibility check;
3. signature/freshness check for signed inputs;
4. `contract_digest_set` completeness and equality constraints;
5. gate predicate execution.

Defect classes:
- `CAC_SCHEMA_UNRESOLVED`
- `CAC_SCHEMA_VERSION_INCOMPATIBLE`
- `CAC_CANONICALIZER_UNRESOLVED`
- `CAC_CANONICALIZER_VECTOR_MISMATCH`
- `CAC_DIGEST_SET_INCOMPLETE`
- `CAC_DIGEST_MISMATCH`
- `CAC_SIGNATURE_INVALID`
- `CAC_INPUT_STALE`
- `CAC_VALIDATION_ORDER_VIOLATION`

Fail-closed policy:
- any defect class above denies the active gate immediately;
- Tier0/Tier1: deny + emit `cac.defect_record.v1`;
- Tier2+: deny + force `D3` freeze until adjudicated before `cac_adjudication_deadline_window_ref`; missed deadline escalates to `D4` emergency halt.

Gate-order safety rule:
- any gate consuming temporal predicates MUST execute after `GATE-EIO29-TIME-AUTHORITY` and before promotion decisions.

## 17. Evidence Registry

Local profile evidence:
- `RFC-0029::EVID-0001` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0001.yaml`)
- `RFC-0029::EVID-0002` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0002.yaml`)
- `RFC-0029::EVID-0003` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0003.yaml`)
- `RFC-0029::EVID-0004` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0004.yaml`)
- `RFC-0029::EVID-0005` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0005.yaml`)
- `RFC-0029::EVID-0006` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0006.yaml`)
- `RFC-0029::EVID-0007` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0007.yaml`)
- `RFC-0029::EVID-0008` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0029::EVID-0009` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0009.yaml`)
- `RFC-0029::EVID-0010` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0010.yaml`)

Imported anchor evidence:
- `RFC-0027::EVID-0005` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0005.yaml`)
- `RFC-0027::EVID-0007` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0007.yaml`)
- `RFC-0027::EVID-0010` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0010.yaml`)

## 18. Unified Gate Sequence Binding

This profile maps to unified Gate 3 (economics plane):
- Gate 1: snapshot validity (`GATE-PCAC-SNAPSHOT-VALIDITY`)
- Gate 2: security profile conformance (`GATE-SIO28-*`, RFC-0028)
- Gate 3: efficiency profile conformance (`GATE-EIO29-*`, this RFC)
- Gate 4: joint adversarial replay/revocation drills
- Gate 5: promotion readiness with uncertainty and independent verifier evidence

## 19. Theory Lineage and Stability Framing

### 19.1 Law and Principle Anchors

| Contract Surface | Theory Law Anchors | Principle Anchors |
|---|---|---|
| Temporal fail-closed authority | `LAW-09`, `LAW-15`, `LAW-20` | `PRIN-105`, `PRIN-122` |
| Queue/backpressure under attack | `LAW-12`, `LAW-14` | `PRIN-053`, `PRIN-101` |
| Projection sink independence | `LAW-03`, `LAW-16` | `PRIN-047`, `PRIN-107` |
| Verifier economics and anti-Goodhart | `LAW-08`, `LAW-14` | `PRIN-101`, `PRIN-106` |
| Recoverability and reconstruction trust | `LAW-10`, `LAW-15`, `LAW-19` | `PRIN-049`, `PRIN-121` |
| Revocation monotonicity | `LAW-18`, `LAW-20` | `PRIN-124` |

### 19.2 Control-Theory Formulation

Closed-loop state:
- `x_t = (queue_state, revocation_state, replay_state, sink_state, mode_state)`

Controller objective:
- keep safety invariants satisfied while minimizing `C_total`.

Adversarial disturbance:
- `d_t` includes sink outages, traffic pressure, partition, and compromise events.

Stability requirement:
- bounded-input bounded-output behavior for control lanes under declared disturbance envelope; violation is non-promotable.

### 19.3 Information Leakage Budget

Projection and observability must stay within leakage budget:
- `L_projection(window_ref) <= L_max(risk_tier)`

Typed leakage contract:
- `L_projection` unit: `leakage_bits` (integer upper bound per window).
- estimator family and confidence metadata MUST be bound in signed leakage receipts.
- unknown estimator semantics or unit ambiguity is non-admissible.

Budget overrun behavior:
- emit leakage defect
- block promotion-critical paths
- require declassification adjudication receipts before recovery.

## 20. Bottleneck Hotspots and Parallel Verification Plan

### 20.1 Gate Cascade Parallelization

To avoid serial bottlenecks:
- execute independent gate families in parallel groups:
  - group A: temporal authority + drift
  - group B: queue stability + replay/recovery
  - group C: projection continuity + projection isolation
- merge by fail-dominant reduction.

### 20.2 Authority Path Redundancy

Authority path redundancy blueprint:
- at least two independent time-authority verifier families for Tier2+.
- independent projection worker pools with non-overlapping failure domains.
- independent replay verifiers for reconstruction admissibility.

### 20.3 Evidence Budget Backpressure

Evidence generation itself is budgeted:
- `evidence_budget_profile` declares max verification overhead per window.
- when evidence workload threatens control-lane tick floors, system enters constrained degrade mode instead of silently dropping controls.

### 20.4 Promotion Gate Cost Model and Progress Envelope

Gate-evaluation latency decomposition:
- `T_gate_total = T_schema_resolve + T_canonicalizer_check + T_signature_freshness + T_digest_validation + T_predicate_eval`
- total promotion decision latency is the fail-dominant aggregation across required gates.
- end-to-end cascade latency includes evidence production/refresh cost:
  - `T_cascade_total = T_gate_total + T_evidence_generation + T_adjudication_overhead`

Mandatory evidence-backed feasibility claims:
- declare profile target bounds for `p50/p95/p99(T_gate_total)` under representative load.
- declare `p50/p95/p99(T_evidence_generation)` for promotion-critical evidence classes.
- include amortization policy for reusable verification artifacts across adjacent promotion attempts.
- include fail-fast ordering evidence that minimizes wasted downstream gate work after early deny.
- prove `T_cascade_total < min(TTL_promotion_critical_evidence_class)` under declared operating envelope.

Liveness/progress observables (must be policy-thresholded):
- `steady_state_deny_rate`
- `freeze_cascade_probability`
- `RTO_D3_to_D0`

Promotion is non-admissible when measured observables violate declared thresholds, even if point-in-time safety predicates pass.

## 21. Explicit Non-Goals and Supported Envelope

### 21.1 Non-Goals (Current Phase)

- no guarantee of global liveness under total truth-plane quorum loss.
- no attempt to make wall-clock authoritative for any gate input.
- no support for ambiguous temporal adjudication without bounded deadline.
- no claim of universal adversary resistance beyond declared threat model and envelope.

### 21.2 Probabilistic vs Absolute Guarantees

Absolute (fail-closed) guarantees:
- authority admission denies on missing/unknown/stale temporal authority.
- revocation monotonicity violations are non-admissible.

Probabilistic guarantees:
- queue latency and recovery envelopes are probabilistic and must include confidence intervals.
- attacker-cost asymmetry bounds depend on observed load distributions and evidence freshness.

### 21.3 Current Envelope Boundaries

- federation size, geography, and adversary sophistication are supported only within declared stress-tested profiles.
- claims beyond tested profile are non-authoritative until new evidence receipts are admitted.

## 22. Canonical Ownership Boundary

- RFC-0027 owns lifecycle semantics.
- RFC-0028 owns security profile constraints.
- RFC-0029 owns efficiency and temporal-economics execution constraints.
- RFC-0016 owns canonical temporal substrate semantics.
- RFC-0019 owns shared cross-profile temporal contract surfaces and gate-order binding for promotion-critical admission.
- RFC-0019 chapter 16 remains derived mirror only; canonical source is this RFC.

Mirror sync gate:
- `GATE-EIO-PROFILE-SYNC` enforces one-way sync from RFC-0029 to RFC-0019 chapter 16.

## 23. Assumptions and Defaults

- pre-live status allows semantic tightening without backward-compatibility overhead unless a concrete dependency explicitly requires compatibility.
- dominance order remains `containment/security > verification/correctness > liveness/progress`.
- all unknown or ambiguous authority-critical inputs are fail-closed.
