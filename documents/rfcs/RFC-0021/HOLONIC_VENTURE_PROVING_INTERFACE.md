# RFC-0021 — Holonic Venture Proving Interface (VPHI)
**Status:** DRAFT (2026-02-05)  
**Audience:** FAC, strategy, security, reliability, and product governance reviewers  
**Scope:** Cell-local enforcement is normative. Federation-ready shapes are specified for multi-cell extension.  
**Spine alignment:** VPHI extends FAC with a parallel strategic validation loop that turns venture operation into typed, replayable evidence for system improvement.  
**Normative foundation:** This RFC composes RFC-0015 (FAC hardening), RFC-0019 (automated FAC loop), RFC-0020 (HSI substrate discipline), and strategy v2 artifacts in `documents/strategy/*`.

---

## 0. Executive Summary (Non-Normative)

APM2 cannot claim autonomous software development maturity only from internal coding loops. It needs externalized pressure with real utility gradients.

VPHI introduces that pressure by running a **Venture Proving Holon (VPH)**: a bounded autonomous holon tasked with building a profitable software company while preserving containment and evidence rigor.

The VPH does not get special merge authority. It emits typed signals that enter APM2 via FAC-compatible contracts:

1. `DEFECT` signals: failures and regressions discovered in real operation.
2. `INTENT` signals: feature opportunities and product requests.
3. `DRIFT` signals: non-failure trend degradation (freshness, policy, runtime, economics).

All three are routed by an explicit **attention policy** into the existing SDLC/FAC stack:
- direct ticket,
- mini-PRD,
- PRD+RFC,
- adjudication/oracle.

For strategy-critical work, Stage 5 verification is extended with **AAT-BIZ**:
- hypotheses formed from venture signals,
- replay against business evidence,
- pass/fail predicates tied to strategy countermetrics,
- signed receipt artifacts in CAS.

This turns "build a profitable company" from narrative aspiration into a machine-checkable test harness for APM2.

---

## 0.1 Alien Engineering Protocol (Normative Reminder)

This RFC adopts the Alien Engineering Protocol as mandatory design discipline:

1. **Physics-first admissibility:** ambition is constrained by physical/computational law, not execution anxiety.
2. **Evidence-first authority:** no strategic or operational claim is authoritative without signed, replayable evidence.
3. **Fail-closed uncertainty:** unknown, stale, or ambiguous states deny promotion by default.
4. **Bounded search and escalation:** every loop has explicit budgets, stop conditions, and escalation targets.
5. **Compounding closure:** each failure must strengthen verifiers, contracts, or policies.
6. **Containment precedence:** `containment/security > verification/correctness > liveness/progress`.
7. **Interface minimalism:** typed, digest-first exchange; no chatty narrative coordination across boundaries.
8. **Anti-Goodhart controls:** every optimization KPI must be paired with countermetrics and independent oversight channels.

These are non-negotiable protocol constraints, not guidance.

---

## 0.2 Why A Parallel System Is Required (Normative)

The current strategy documents define business KPIs and SDLC gates, but they do not yet define a dedicated subsystem that continuously converts live venture operation into FAC-consumable improvement work.

Therefore VPHI requires a separate, parallel subsystem with these invariants:

- The VPH is **execution-separate** from core FAC governance domains.
- The VPH has **no direct promotion path** into trunk.
- The VPH can only influence system evolution by emitting typed, signed, evidence-bound signals.
- All resulting code changes still pass normal FAC gates plus AAT-BIZ when required.

## 0.3 Machine-Checkable Objective Contracts (Normative)

Every major VPHI objective MUST declare baseline, quantitative target, HTF boundary authority, owner locus, transition predicate, and evidence path.

| Objective ID | Baseline | Quantitative Target | Time Boundary | Owner / Decision Locus | Transition Predicate (Machine-Checkable) | Required Evidence Path |
|---|---|---|---|---|---|---|
| `OBJ-VPHI-01` Intake integrity | `signal_validation_pass_ratio = 0.970` at `VPHI-BL-2026-02-05` | `signal_validation_pass_ratio >= 0.995` | `HTF-BND-P1-SECURITY-CLOSE` | Security Council + Runtime Council quorum | `jq -e '.signal_validation_pass_ratio >= 0.995 and .signature_valid == true and .time_envelope_valid == true and .policy_snapshot_ttl_pass == true and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-01/summary.json` | `evidence/venture/kpi/VPHI-KPI-01/` |
| `OBJ-VPHI-02` Deterministic routing | `attention_route_override_rate = 0.180` at `VPHI-BL-2026-02-05` | `attention_route_override_rate <= 0.050` and `routing_replay_equivalence_ratio == 1.0` | `HTF-BND-P2-EARLY-CLOSE` | Governance Council + Reliability Council | `jq -e '.attention_route_override_rate <= 0.05 and .routing_replay_equivalence_ratio == 1.0 and .unauthorized_downgrade_count == 0 and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-02/summary.json` | `evidence/venture/kpi/VPHI-KPI-02/` |
| `OBJ-VPHI-03` FAC authority isolation | `tier2plus_promotions_without_terminal_receipt = 2` at `VPHI-BL-2026-02-05` | `tier2plus_promotions_without_terminal_receipt == 0` and `vph_direct_promotion_attempts == 0` | `HTF-BND-P1-CLOSE` | Security Council | `jq -e '.tier2plus_promotions_without_terminal_receipt == 0 and .vph_direct_promotion_attempts == 0 and .authority_graph_complete == true and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-05/summary.json` | `evidence/venture/kpi/VPHI-KPI-05/` |
| `OBJ-VPHI-04` AAT-BIZ mandatory coverage | `aat_biz_required_work_coverage = 0.000` at `VPHI-BL-2026-02-05` | `aat_biz_required_work_coverage == 1.0` and `aat_biz_false_pass_count == 0` | `HTF-BND-P2-CLOSE` | Verification Council + Product Council | `jq -e '.aat_biz_required_work_coverage == 1.0 and .aat_biz_false_pass_count == 0 and .required_countermetric_coverage == 1.0 and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-04/summary.json` | `evidence/venture/kpi/VPHI-KPI-04/` |
| `OBJ-VPHI-05` Strategy coupling | `strategy_claim_linkage_ratio = 0.000` at `VPHI-BL-2026-02-05` | `msc03_linkage_ratio == 1.0` and `msc05_linkage_ratio == 1.0` and `msc06_linkage_ratio == 1.0` | `HTF-BND-P3-CLOSE` | Company Board + Finance Council + Governance Council | `jq -e '.msc03_linkage_ratio == 1.0 and .msc05_linkage_ratio == 1.0 and .msc06_linkage_ratio == 1.0 and .aat_biz_required_paths_complete == true and .unknown_state_count == 0' evidence/venture/strategy_linkage/VPHI-STRAT-001/summary.json` | `evidence/venture/strategy_linkage/VPHI-STRAT-001/` |
| `OBJ-VPHI-06` Scale-envelope admissibility | `verification_compute_share = 0.520` and `anti_entropy_backlog_ticks_p95 = 2400` at `VPHI-BL-2026-02-05` | `verification_compute_share <= 0.45`, `anti_entropy_backlog_ticks_p95 <= 1200`, and `receipt_fanout_amplification <= 1.15` | `HTF-BND-P3-ECON-CLOSE` | Runtime Council + Platform Council | `jq -e '.verification_compute_share <= 0.45 and .anti_entropy_backlog_ticks_p95 <= 1200 and .receipt_fanout_amplification <= 1.15 and .tiered_retention_manifest_complete == true and .unknown_state_count == 0' evidence/venture/scale/VPHI-SCALE-001/summary.json` | `evidence/venture/scale/VPHI-SCALE-001/` |

All objective predicates fail closed: missing fields, parse errors, stale policy snapshots, invalid signatures, or unknown states are automatic deny outcomes.

## 0.4 Strategy Coupling Ledger (Normative)

VPHI coupling to strategy claims is mandatory and claim-specific. Narrative-only linkage is non-compliant.

| Signal Class | Primary Strategy Claim | Stage-5 AAT-BIZ Obligation | Promotion Block Condition | Evidence Path |
|---|---|---|---|---|
| `DEFECT:VERIFIER_DELTA` | `MSC-03` | Demonstrate replay-proven verifier delta tied to originating defect class | block if verifier delta receipt absent or replay confidence below policy floor | `evidence/strategy/phase2/MSC-03/` |
| `DRIFT:ORACLE_BOTTLENECK` | `MSC-05` | Demonstrate reduced oracle demand and oracle-to-primitive compilation gain | block if oracle countermetric fails or compiler SLA artifact missing | `evidence/strategy/phase2/MSC-05/` |
| `INTENT:REVENUE` or `DRIFT:ECONOMICS` | `MSC-06` | Demonstrate business predicate pass with required anti-gaming countermetrics | block if ARR/margin/retention predicates fail or any required countermetric fails | `evidence/strategy/phase3/MSC-06/` |

Each accepted Tier2+ signal MUST map to at least one of `MSC-03`, `MSC-05`, or `MSC-06`. Signals without valid mapping are admissible for planning only and are ineligible for promotion paths.

## 0.5 Dominance and Time Authority Execution Rule (Normative)

Gate truth MUST be evaluated in this exact order:
1. containment/security predicates,
2. verification/correctness predicates,
3. liveness/progress predicates.

If a higher-precedence layer fails, lower-precedence layers MUST NOT override the deny result.

Normative time rules:
- `time_envelope_ref` and HTF boundary artifacts are the only admissible time authority for gate truth.
- Wall-clock timestamps are display-only metadata and cannot satisfy, waive, or override gate predicates.
- Any missing, stale, unsigned, or parse-invalid HTF boundary artifact is an automatic deny.

Reference predicate:

```bash
jq -e '.dominance_order == ["containment_security","verification_correctness","liveness_progress"] and (.time_authority.boundary_id | startswith("HTF-BND-")) and .time_authority.authority_clock == "L" and .time_authority.signature_valid == true and .time_authority.tick_floor_met == true and .wall_clock_used_for_gate_truth == false' \
  evidence/venture/governance/VPHI-GOV-001/summary.json
```

## 0.6 Scale Envelope and Verifier Economics (Normative)

VPHI MUST remain admissible under globally distributed multi-exabyte to zettabyte evidence and coordination envelopes.

Required mechanics:
- Digest-first artifacts with canonicalization and content addressing for all signal and receipt payloads.
- Merkle-batched attestation and bounded anti-entropy pull ranges consistent with RFC-0020.
- Tiered evidence retention with replay-equivalence manifests for compacted corpora.
- Verifier economics controls bounded by policy for compute share, receipt fanout, and queue latency.

Fail-closed scale controls:
- Unknown evidence tier classification: deny.
- Anti-entropy boundedness proof missing: deny.
- Verification compute share breach across two contiguous HTF windows without quality gain: deny.
- Receipt fanout amplification above policy ceiling: deny.

## 0.7 AEP Clause Mechanization Matrix (Normative)

| AEP Clause | Mechanism Contract | Measurable Predicate | Evidence Path | Threat Mode Addressed |
|---|---|---|---|---|
| `AEP_01` Physics-first admissibility | Physics feasibility ledger with explicit falsification tests per objective | `physics_admissibility_ratio == 1.0` | `evidence/venture/physics/VPHI-PHY-001/` | execution-anxiety downscoping |
| `AEP_02` Only fundamental limits can block | Objection taxonomy with allowed blocker classes only | `disallowed_blocker_class_count == 0` | `evidence/venture/governance/VPHI-GOV-002/` | non-physical veto capture |
| `AEP_03` Novel engineering mandatory | Mechanism-level design delta required for accepted proposals | `accepted_without_mechanism_contract_count == 0` | `evidence/venture/novelty/VPHI-NOV-001/` | analogy-only design drift |
| `AEP_04` Compounding closure | Failure-to-verifier/policy delta binding | `failure_with_compounding_delta_ratio == 1.0` | `evidence/venture/closure/VPHI-CLOSURE-001/` | repeated unlearned failures |
| `AEP_05` Bounded search discipline | Explicit budget, stop condition, escalation receipts | `explorations_without_budget_or_stop == 0` | `evidence/venture/search/VPHI-SEARCH-001/` | unbounded exploration blowup |
| `AEP_06` Digest-first interfaces | Typed low-variety contract registry | `cross_boundary_payloads_off_contract == 0` | `evidence/venture/contracts/VPHI-CONTRACT-001/` | chatty/non-canonical coordination |
| `AEP_07` Anti-Goodhart posture | KPI + countermetric + independent oversight triplet requirement | `kpi_triplet_coverage == 1.0` | `evidence/venture/aat_biz/VPHI-GOODHART-001/` | proxy metric gaming |
| `AEP_08` Recursive semantic stability | Depth-bounded composition checks | `semantic_equivalence_pass_rate_depth_le_12 >= 0.99` | `evidence/venture/semantics/VPHI-SEM-001/` | compositional semantic drift |

---

## 1. Problem Statement (Normative)

### 1.1 Current Deficit

APM2 currently has:
- rigorous FAC event + receipt contracts,
- strategy metrics and phase gates,
- AAT verification for implementation-level correctness.

But APM2 lacks:
- a first-class runtime instrument that stress-tests the system against real market dynamics,
- a typed pipeline for converting externalized product signals into auditable work admission,
- strategic AAT predicates proving business-impact hypotheses without bypassing security/correctness constraints.

### 1.2 Consequence

Without VPHI, optimization pressure is biased toward local coding throughput and can miss:
- latent product-market defects,
- slow-burn drift in utility or economics,
- metric gaming that inflates development KPIs while degrading real outcomes.

### 1.3 Objective

Define a protocol layer that:
- ingests VPH signals,
- routes them via machine-checkable attention policy,
- binds resulting work to FAC,
- extends AAT to include business-domain replay for strategy-critical changes.

---

## 2. System Model

### 2.1 Components

1. **Venture Proving Holon (VPH)**
- Bounded autonomous system pursuing product growth/revenue objectives.
- Emits `DEFECT`, `INTENT`, and `DRIFT` artifacts.

2. **Signal Intake + Attention Router (SIAR)**
- Validates signal schema, signatures, freshness, and policy.
- Assigns attention tier and route type.

3. **FAC Core**
- Unchanged source of authoritative promotion.
- Consumes routed work through existing work/gate/receipt flow.

4. **AAT-BIZ Verifier**
- Strategic verification extension in Stage 5.
- Binds business hypotheses and pass/fail outputs into receipts.

### 2.2 Non-Negotiable Separation

- VPH MAY propose; VPH MUST NOT promote.
- SIAR MAY route; SIAR MUST NOT merge.
- FAC MAY promote only after gate receipts satisfy policy.

### 2.3 Loop Topology

The full loop is:

`VPH operation -> signal emission -> SIAR routing -> WorkOpened/PRD/RFC/Ticket -> FAC build+verify -> AAT-BIZ (if required) -> promotion or block -> updated venture outcomes -> new signals`

---

## 3. Protocol Objects and Schemas

All schemas below are normative shape contracts for implementation; final wire binding may be protobuf or canonical JSON with strict determinism rules.

### 3.1 `VentureSignalBundleV1`

```yaml
schema_id: apm2.venture_signal.v1
signal_id: string
signal_type: DEFECT | INTENT | DRIFT
source_holon_id: string
work_id_hint: string | null
strategy_claim_refs: [string]            # e.g., ["MSC-06"]
risk_preclass: LOW | MED | HIGH | CRITICAL
expected_value_score: float64            # bounded [0,1]
compounding_factor_score: float64        # bounded [0,1]
urgency_score: float64                   # bounded [0,1]
reversibility_score: float64             # bounded [0,1] where low = irreversible
evidence_strength: LOW | MED | HIGH | FORMAL
compute_cost_estimate_ticks: uint64
oracle_cost_estimate_ticks: uint64
summary_receipt_hash: bytes
evidence_manifest_hash: bytes
time_envelope_ref: TimeEnvelopeRef
clock_profile_hash: bytes
policy_hash: bytes
emitter_actor_id: string
emitter_signature: bytes
```

Validation rules:
- Missing required field: reject.
- Unknown enum value: reject.
- Invalid signature/time envelope: reject.
- Unknown strategy claim refs: reject for Tier2+ routing, warn-only for Tier0/1 planning.

### 3.2 `AttentionDecisionReceiptV1`

```yaml
schema_id: apm2.attention_decision.v1
decision_id: string
signal_id: string
attention_tier: A0 | A1 | A2 | A3
route_type: DIRECT_TICKET | MINI_PRD | PRD_RFC | ADJUDICATION
rationale_codes: [string]
risk_tier_ceiling: TIER0 | TIER1 | TIER2 | TIER3 | TIER4
required_gate_set: [string]
required_evidence_contracts: [string]
owner_holon_id: string
expires_at_tick: uint64
time_envelope_ref: TimeEnvelopeRef
policy_hash: bytes
resolver_actor_id: string
resolver_signature: bytes
```

Validation rules:
- `route_type` and `attention_tier` must be policy-consistent.
- Any down-tiering relative to signal risk is invalid without waiver artifact.
- Receipt expiration requires rerouting before work transition.

### 3.3 `AatBusinessReceiptV1`

```yaml
schema_id: apm2.aat_business_receipt.v1
receipt_id: string
work_id: string
changeset_digest: bytes
signal_ids: [string]
hypotheses: [string]
terminal_business_predicates: [string]
predicate_results: [bool]
countermetric_results: [bool]
kpi_window_ref: string
replay_corpus_hash: bytes
verifier_outputs_digest: bytes
time_envelope_ref: TimeEnvelopeRef
runner_attestation_hash: bytes
verifier_policy_hash: bytes
verifier_actor_id: string
verifier_signature: bytes
```

Acceptance semantics:
- PASS requires all terminal business predicates true and all required countermetrics true.
- Any unknown or missing predicate result is FAIL.
- Receipt must be linked from FAC GateReceipt payload hash.

---

## 4. Attention Allocation and Routing

### 4.1 Attention Tiers

| Tier | Profile | Allowed Route | Mandatory Controls |
|---|---|---|---|
| `A0` | Low risk, high reversibility, high evidence | `DIRECT_TICKET` | Standard FAC gates |
| `A1` | Medium uncertainty or medium blast radius | `MINI_PRD` | Explicit falsifiable requirements |
| `A2` | High impact or high uncertainty | `PRD_RFC` | Full RFC governance + stronger gate set |
| `A3` | Critical security/business irreversibility | `ADJUDICATION` first | Oracle/Adjudication before implementation |

### 4.2 Routing Rule (Normative)

Implementations MUST compute:

`attention_score = f(risk_preclass, urgency, expected_value, compounding_factor, reversibility, evidence_strength, compute_cost, oracle_cost)`

Policy MUST define deterministic thresholds for A0..A3. Any unresolved ambiguity in score computation is routed upward.

### 4.3 FAC Binding

For routed work, SIAR MUST emit:
- `WorkOpened` with type `TICKET`, `PRD_REFINEMENT`, or `RFC_REFINEMENT`.
- Strategy claim references in work metadata.
- `AttentionDecisionReceiptV1` hash in CAS and linked evidence record.

No routed work may proceed without a valid attention receipt.

---

## 5. FAC Integration Contract

### 5.1 Event-Level Integration

VPHI reuses existing kernel events where possible and proposes minimal additions.

Reused:
- `DefectRecorded`
- `WorkOpened`, `WorkTransitioned`
- `AdjudicationRequested`, `AdjudicationResolved`
- `PolicyResolvedForChangeSet`
- `ReviewReceiptRecorded`, `ReviewBlockedRecorded`

Proposed extensions:
1. Add `DEFECT_SOURCE_VENTURE_PROVING_HOLON` to `DefectSource` enum.
2. Add `VentureSignalPublished` event (optional optimization; equivalent info can be carried by evidence + work metadata in v0).

### 5.2 Admission State Overlay

`SIGNAL_INGESTED -> ATTENTION_RESOLVED -> WORK_OPENED -> FAC_POLICY_BOUND -> FAC_AUTHORITY_BOUND -> IMPLEMENTED -> VERIFIED -> PROMOTED|BLOCKED`

Invariant:
- `FAC_POLICY_BOUND` and onward follow existing FAC ordering invariants unchanged.

### 5.3 Transition Predicate

For any work item sourced from VPH signal:

`may_promote = fac_predicates_pass && attention_receipt_valid && (aat_biz_required -> aat_biz_pass)`

where `aat_biz_required` is true when either:
- signal strategy refs include `MSC-03`, `MSC-05`, `MSC-06`, or business countermetric classes, or
- risk tier >= Tier2 and route type from A2/A3.

---

## 6. AAT Coupling: `AAT-BIZ`

### 6.1 Purpose

AAT-BIZ verifies that changes derived from venture signals do not merely pass technical tests but satisfy bounded business-impact hypotheses under evidence discipline.

### 6.2 Mandatory Inputs

- Linked `VentureSignalBundleV1` set.
- Countermetric policy bundle for relevant strategy claim.
- Replay corpus for comparable historical outcomes.
- Terminal verifier policy for business predicates.

### 6.3 Hypothesis Contract

Each AAT-BIZ run MUST declare at least 3 hypotheses before execution:
1. expected beneficial outcome hypothesis,
2. non-regression hypothesis on containment/security,
3. non-gaming hypothesis against proxy optimization.

### 6.4 PASS/FAIL Rule

PASS requires:
- all mandatory technical AAT predicates pass,
- all declared business terminal predicates pass,
- all required strategy countermetrics pass,
- no security/containment countermetric failure.

Any missing artifact, unknown result, or stale policy is FAIL.

### 6.5 Artifact Paths (Normative)

- `evidence/venture/signals/<signal_id>/`
- `evidence/venture/attention/<decision_id>/`
- `evidence/venture/aat_biz/<receipt_id>/`
- `evidence/strategy/phase2/MSC-03/`
- `evidence/strategy/phase2/MSC-05/`
- `evidence/strategy/phase3/MSC-06/`

### 6.6 AAT-BIZ Coupling Ledger (Normative)

| Claim | Required Hypothesis Categories | Required Countermetric Classes | Required Independent Verifier Channel | Fail-Closed Trigger |
|---|---|---|---|---|
| `MSC-03` | verifier delta utility, containment non-regression, anti-gaming | replay quality, defect closure quality | Reliability Council verifier lane | any missing replay artifact or failed countermetric |
| `MSC-05` | oracle demand reduction, compilation quality, containment non-regression | oracle load, queue budget, policy integrity | Governance Council verifier lane | missing oracle SLO artifact or failed compilation countermetric |
| `MSC-06` | revenue impact, margin durability, containment/security non-regression | ARR/margin/retention + security anti-gaming counters | Finance Council + Security Council verifier lanes | missing business receipt, unknown predicate, or any failed countermetric |

---

## 7. Trust Boundaries and Security

### 7.1 Boundary Model

1. **Boundary A: VPH -> SIAR**
- Treat VPH outputs as untrusted claims until signature+schema+evidence validation.

2. **Boundary B: SIAR -> FAC**
- SIAR may open work but cannot bypass FAC policy or gate checks.

3. **Boundary C: FAC -> Promotion**
- Promotion remains receipt-bound and fail-closed.

### 7.2 Threat Classes

- Signal forgery (fake defects/intents)
- Signal flooding (attention DoS)
- KPI gaming via proxy optimization
- Policy downgrade to force low-scrutiny routes
- Cross-boundary data exfiltration via business evidence artifacts

### 7.3 Required Controls

- Strong signing and time-envelope validation for all VPH signals.
- Rate/budget limits on signal ingestion by source holon and class.
- Independent countermetric verifiers disjoint from optimization path.
- Anti-downgrade checks for attention policy and AAT-BIZ requirements.
- Evidence hygiene and classification enforcement before admission.

---

## 8. Governance and Gate Portfolio

### 8.1 New Gates

1. `GATE-VPH-SIGNAL-VALIDITY`
- Verifies schema/signature/freshness/evidence linkage for venture signals.

2. `GATE-VPH-ATTENTION-POLICY`
- Verifies deterministic routing and anti-downgrade enforcement.

3. `GATE-AAT-BIZ`
- Verifies business hypotheses and countermetrics for qualifying work.

### 8.2 Promotion Constraint

Tier2+ work sourced from VPH signal MUST pass all three gates above in addition to existing FAC gates.

### 8.3 Waiver Policy

- No waiver permitted for `GATE-VPH-SIGNAL-VALIDITY` on Tier2+.
- Temporary waiver allowed for `GATE-AAT-BIZ` only at Tier1 with explicit expiry and dual signoff.

### 8.4 Gate Evaluation Order and Fail-Closed Rule

`GATE-VPH-SIGNAL-VALIDITY` MUST execute before `GATE-VPH-ATTENTION-POLICY`, which MUST execute before `GATE-AAT-BIZ` when required.

A gate result is `DENY` when any of these conditions hold:
- required artifact missing or unreadable,
- schema invalid or parse error,
- signature invalid,
- HTF boundary invalid/stale/missing,
- predicate unknown or indeterminate.

Lower-precedence gates cannot override denies from higher-precedence containment/security checks.

---

## 9. Rollout Plan (Parallel Build)

### Stage 0: Schema + Passive Ingestion
- Deliver `VentureSignalBundleV1` and ingestion validation.
- No routing impact; shadow only.

### Stage 1: Attention Routing Shadow
- Generate `AttentionDecisionReceiptV1` in shadow mode.
- Compare shadow route vs human council route.

### Stage 2: Active Routing for A0/A1
- Enable direct routing for low/medium signals.
- Keep A2/A3 behind adjudication.

### Stage 3: AAT-BIZ Enforcement
- Enable mandatory AAT-BIZ for configured strategy claims.
- Block promotions on AAT-BIZ failure.

### Stage 4: Full Strategic Coupling
- Bind VPH outcomes into strategy gate evidence for Phase 2 and Phase 3 transitions (`MSC-03`, `MSC-05`, `MSC-06`).

---

## 10. Machine-Checkable KPI and Gate Predicates

### 10.1 VPHI Control KPIs

| KPI ID | Baseline | Quantitative Target | Time Boundary | Owner / Decision Locus | Predicate | Evidence Path |
|---|---|---|---|---|---|---|
| `VPHI-KPI-01` | `0.970` | `signal_validation_pass_ratio >= 0.995` | `HTF-BND-P1-SECURITY-CLOSE` | Security Council | `jq -e '.signal_validation_pass_ratio >= 0.995 and .policy_snapshot_ttl_pass == true and .signature_valid == true and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-01/summary.json` | `evidence/venture/kpi/VPHI-KPI-01/` |
| `VPHI-KPI-02` | `0.180` | `attention_route_override_rate <= 0.05` | `HTF-BND-P2-EARLY-CLOSE` | Governance Council | `jq -e '.attention_route_override_rate <= 0.05 and .routing_replay_equivalence_ratio == 1.0 and .unauthorized_downgrade_count == 0 and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-02/summary.json` | `evidence/venture/kpi/VPHI-KPI-02/` |
| `VPHI-KPI-03` | `240` ticks | `strategy_signal_to_work_open_tick_p95 <= policy_limit` | `HTF-BND-P2-CLOSE` | Runtime Council | `jq -e '.strategy_signal_to_work_open_tick_p95 <= .policy_limit and .time_authority_valid == true and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-03/summary.json` | `evidence/venture/kpi/VPHI-KPI-03/` |
| `VPHI-KPI-04` | `0.000` | `aat_biz_required_work_coverage == 1.0` | `HTF-BND-P2-CLOSE` | Verification Council | `jq -e '.aat_biz_required_work_coverage == 1.0 and .required_countermetric_coverage == 1.0 and .aat_biz_false_pass_count == 0 and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-04/summary.json` | `evidence/venture/kpi/VPHI-KPI-04/` |
| `VPHI-KPI-05` | `2` | `tier2plus_biz_source_promotions_without_aat_biz == 0` | `HTF-BND-P1-CLOSE` | Security Council + Product Council | `jq -e '.tier2plus_biz_source_promotions_without_aat_biz == 0 and .vph_direct_promotion_attempts == 0 and .authority_graph_complete == true and .unknown_state_count == 0' evidence/venture/kpi/VPHI-KPI-05/summary.json` | `evidence/venture/kpi/VPHI-KPI-05/` |
| `VPHI-KPI-06` | `0.520` | `verification_compute_share <= 0.45` with non-regressing quality trend | `HTF-BND-P3-ECON-CLOSE` | Runtime Council + Finance Council | `jq -e '.verification_compute_share <= 0.45 and .quality_regression == false and .anti_entropy_backlog_ticks_p95 <= 1200 and .receipt_fanout_amplification <= 1.15 and .unknown_state_count == 0' evidence/venture/scale/VPHI-SCALE-001/summary.json` | `evidence/venture/scale/VPHI-SCALE-001/` |

### 10.2 Example Gate Command

```bash
jq -e '.signal_validation_pass_ratio >= 0.995 and .policy_snapshot_ttl_pass == true and .signature_valid == true' \
  evidence/venture/kpi/VPHI-KPI-01/summary.json
```

Unknown/missing fields are hard fail.

---

## 11. Risks and Open Questions

1. **False novelty in intent signals**
- Risk: noisy growth ideas create churn.
- Mitigation: expected-value and compounding thresholds + replay confidence floor.

2. **Attention router policy brittleness**
- Risk: over/under-escalation.
- Mitigation: shadow calibration stage and bounded override audit.

3. **Business evidence privacy boundary**
- Risk: sensitive user/commercial data leakage.
- Mitigation: evidence classification, redaction profiles, tiered access enforcement.

4. **AAT-BIZ runtime cost inflation**
- Risk: verification economics degrade throughput.
- Mitigation: scope AAT-BIZ to strategy-critical changes and enforce cost SLOs.

5. **Council capture of strategic predicates**
- Risk: narrative pressure weakens gates.
- Mitigation: signed policy bundles and anti-downgrade invariants.

---

## 12. Initial Ticket Decomposition (Normative Seed)

1. `TCK-VPHI-0001` — Define and validate `VentureSignalBundleV1` schema + signing.
2. `TCK-VPHI-0002` — Implement SIAR deterministic attention policy engine.
3. `TCK-VPHI-0003` — Emit `AttentionDecisionReceiptV1` and bind to `WorkOpened`.
4. `TCK-VPHI-0004` — Implement kernel event extension for venture defect provenance.
5. `TCK-VPHI-0005` — Implement `AatBusinessReceiptV1` + terminal business verifier.
6. `TCK-VPHI-0006` — Wire `GATE-AAT-BIZ` into Stage-5 verification policy.
7. `TCK-VPHI-0007` — Implement evidence hygiene and classification controls.
8. `TCK-VPHI-0008` — Implement strategy exporter + coupling ledger for `MSC-03`, `MSC-05`, and `MSC-06`.
9. `TCK-VPHI-0009` — Implement dominance-order plus HTF time-authority gate evaluator.
10. `TCK-VPHI-0010` — Implement scale-envelope verifier-economics and anti-entropy controls.

---

## 13. Reference Set

- `documents/rfcs/RFC-0015/`
- `documents/rfcs/RFC-0019/`
- `documents/rfcs/RFC-0020/HOLONIC_SUBSTRATE_INTERFACE.md`
- `documents/strategy/MASTER_STRATEGY.json`
- `documents/strategy/BUSINESS_PLAN.json`
- `documents/strategy/ROADMAP.json`
- `documents/strategy/STRATEGY_BUSINESS_BUNDLE.json`
- `documents/strategy/STRATEGY_EXECUTION_REPORT.json`
- `proto/kernel_events.proto`

---

## 14. Acceptance Bar For RFC-0021 Advancement

To move from DRAFT to GROUNDED:

1. At least one end-to-end shadow run from VPH signal to FAC work admission is demonstrated with receipts.
2. `GATE-VPH-SIGNAL-VALIDITY` and `GATE-VPH-ATTENTION-POLICY` have deterministic verifier implementations.
3. `AAT-BIZ` demonstrates at least one true-positive and one true-negative replay on historical venture signals.
4. Security review confirms no direct promotion bypass from VPH to merge/projection paths.
