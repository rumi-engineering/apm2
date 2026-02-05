# RFC-0021 Refinement Report (Alien Engineering Protocol v1)

- kind: `refinement.report`
- schema: `cac.refinement_report.v1`
- stable_id: `dcp://apm2.local/reports/rfc_0021/refinement@v1`
- instruction_id: `dcp://apm2.local/instructions/rfc_0021/refinement@v1`
- generated_at: `2026-02-05`

## 1) Divergent Tracks and Synthesis

### Track A: Maximum ambition under physics
- Added explicit exabyte-to-zettabyte admissibility and verifier-economics constraints.
- Added anti-entropy boundedness and receipt-fanout ceilings as fail-closed controls.

### Track B: Maximum precision and testability
- Added objective contracts with baseline, target, HTF boundary, owner, predicate, evidence path.
- Added explicit dominance-order and HTF time-authority evaluation semantics.
- Added new requirements `REQ-0011` and `REQ-0012` with tests and evidence bindings.

### Track C: Maximum compounding velocity
- Expanded strategy coupling to `MSC-03`, `MSC-05`, and `MSC-06`.
- Added coupling ledger and decomposition updates (tickets/evidence/tests) for rapid implementation slicing.

### Synthesized dominant output
- Keep FAC authority unchanged.
- Increase mechanization density where gate ambiguity existed.
- Preserve rollout liveness via staged controls and bounded experiments.

## 2) Goal Coverage Matrix

| Goal | Mechanism | Predicate | Evidence Path | Owner / Locus | Status |
|---|---|---|---|---|---|
| `GOAL_VPH_PARALLEL` | Parallel subsystem invariants (`§0.2`) | `vph_direct_promotion_attempts == 0` | `evidence/venture/kpi/VPHI-KPI-05/` | Security Council | PASS |
| `GOAL_THREE_SOURCE_INTAKE` | Three-source intake + schema contract (`§3.1`, `DEC-0001`) | typed enum validation for `DEFECT|INTENT|DRIFT` | `evidence_artifacts/EVID-0001.yaml` | Runtime Council | PASS |
| `GOAL_FAC_AUTHORITY` | FAC-only promotion + transition predicate (`§5.3`) | `fac_predicates_pass && attention_receipt_valid && ...` | `evidence_artifacts/EVID-0003.yaml`, `EVID-0006.yaml` | Security Council | PASS |
| `GOAL_AAT_BIZ` | Mandatory Stage-5 business verifier (`§6`) | missing/unknown AAT-BIZ artifacts => FAIL | `evidence_artifacts/EVID-0005.yaml`, `EVID-0006.yaml` | Verification Council | PASS |
| `GOAL_STRATEGY_COUPLING` | Coupling ledger for `MSC-03/05/06` (`§0.4`, `§6.6`) | linkage ratios for all three claims must be `1.0` | `evidence_artifacts/EVID-0008.yaml` | Product + Governance + Finance | PASS |
| `GOAL_MACHINE_CHECKABLE` | Objective contract table + KPI table (`§0.3`, `§10.1`) | objective records include baseline/target/boundary/owner/predicate/evidence | `evidence/venture/strategy_linkage/VPHI-STRAT-001/` | Architecture Council | PASS |
| `GOAL_ANTI_GOODHART` | KPI/countermetric/independent-channel triplet (`AEP_07`, `§6.6`) | `kpi_triplet_coverage == 1.0` | `evidence/venture/aat_biz/VPHI-GOODHART-001/` | Product + Security | PASS |
| `GOAL_EVIDENCE_FIRST` | Signed, replayable contract bindings (`§3`, `§4`) | invalid signature or unknown fields => deny | `EVID-0001`..`EVID-0010` | Security Council | PASS |
| `GOAL_FAIL_CLOSED` | Fail-closed rules in gates + objectives (`§0.3`, `§8.4`) | missing/schema-invalid/unknown => DENY | `EVID-0006`, `EVID-0009`, `EVID-0010` | Security Council | PASS |
| `GOAL_DOMINANCE_ORDER` | Ordered gate execution contract (`§0.5`, `09_governance_and_gates.yaml`) | precedence list exactly enforced | `evidence_artifacts/EVID-0009.yaml` | Security Council | PASS |
| `GOAL_TIME_AUTHORITY` | HTF-bound authority; wall-clock display-only (`§0.5`) | wall-clock-only artifact rejected | `evidence_artifacts/EVID-0009.yaml` | Security Council | PASS |
| `GOAL_SCALE_ENVELOPE` | Scale controls + verifier economics (`§0.6`, `REQ-0012`) | compute/fanout/anti-entropy constraints in policy | `evidence_artifacts/EVID-0010.yaml` | Runtime + Platform Councils | PASS |

## 3) Gap Report (Blocker/Major/Minor)

| Severity | Gap | Status | Resolution |
|---|---|---|---|
| BLOCKER | Strategy coupling was MSC-06-centric and under-specified for MSC-03/MSC-05 | RESOLVED | Added coupling ledger + requirement/test/evidence updates (`REQ-0010`, `EVID-0008`) |
| BLOCKER | Major VPHI objectives lacked full machine-checkable contract fields | RESOLVED | Added objective contracts and expanded KPI contract table (`§0.3`, `§10.1`) |
| BLOCKER | Dominance order and HTF authority were not fully executable as gate semantics | RESOLVED | Added explicit execution rule and governance predicates (`§0.5`, `§8.4`, `REQ-0011`) |
| MAJOR | Scale envelope mechanics were mostly implied via RFC-0020 reference | RESOLVED | Added explicit scale controls + requirement/test/evidence (`§0.6`, `REQ-0012`, `EVID-0010`) |
| MAJOR | AEP clauses existed but were weakly tied to measurable contracts | RESOLVED | Added AEP mechanism matrix with predicates and evidence paths (`§0.7`) |
| MINOR | Upstream strategy file `documents/strategy/SDLC_PIPELINE.md` is deleted in current worktree | OPEN (non-blocking for this RFC patch set) | RFC references shifted to current strategy artifacts (`STRATEGY_BUSINESS_BUNDLE.json`, `STRATEGY_EXECUTION_REPORT.md`) |

## 4) Unified Diffs (Key Hunks)

### `documents/rfcs/RFC-0021/HOLONIC_VENTURE_PROVING_INTERFACE.md`
```diff
+## 0.3 Machine-Checkable Objective Contracts (Normative)
+| Objective ID | Baseline | Quantitative Target | Time Boundary | Owner / Decision Locus | Transition Predicate | Required Evidence Path |
+...
+## 0.4 Strategy Coupling Ledger (Normative)
+| DEFECT:VERIFIER_DELTA -> MSC-03 |
+| DRIFT:ORACLE_BOTTLENECK -> MSC-05 |
+| INTENT:REVENUE or DRIFT:ECONOMICS -> MSC-06 |
+...
+## 0.5 Dominance and Time Authority Execution Rule (Normative)
+## 0.6 Scale Envelope and Verifier Economics (Normative)
+## 0.7 AEP Clause Mechanization Matrix (Normative)
- signal strategy refs include `MSC-06` ...
+ signal strategy refs include `MSC-03`, `MSC-05`, `MSC-06` ...
```

### `documents/rfcs/RFC-0021/02_design_decisions.yaml`
```diff
+DEC-0006: claim-specific strategy coupling for MSC-03/05/06
+DEC-0007: executable dominance + HTF time authority semantics
+DEC-0008: explicit exabyte/zettabyte scale-envelope controls
```

### `documents/rfcs/RFC-0021/requirements/REQ-0010.yaml`
```diff
-title: "Strategy evidence exporter for phase and KPI gates"
+title: "Strategy coupling exporter for MSC-03/MSC-05/MSC-06"
+acceptance_criteria include baseline/target/boundary/owner/predicate/evidence fields
+acceptance_criteria include AAT-BIZ coupling ledger output
```

### `documents/rfcs/RFC-0021/requirements/REQ-0011.yaml`
```diff
+New requirement: dominance-order and HTF time-authority gate evaluation
+Fail-closed criteria for missing/invalid HTF artifacts and wall-clock misuse
```

### `documents/rfcs/RFC-0021/requirements/REQ-0012.yaml`
```diff
+New requirement: scale-envelope verifier-economics and anti-entropy controls
+Fail-closed criteria for unknown scale-control states
```

### `documents/rfcs/RFC-0021/07_test_and_evidence.yaml`
```diff
+UT-0005/UT-0006 for REQ-0011/REQ-0012
+IT-0005/IT-0006 for HTF authority and scale controls
+ADV-0004/ADV-0005 adversarial fail-closed tests
+EVID-0009 and EVID-0010 registry entries
```

### `documents/rfcs/RFC-0021/09_governance_and_gates.yaml`
```diff
+machine_predicate and evidence_path fields per governance gate
+GATE-RFC-SCALE
+gate_execution_contract with explicit precedence and fail_closed_conditions
```

## 5) Per-Hunk Rationale

| File | Why changed | Threat / failure mode addressed |
|---|---|---|
| `HOLONIC_VENTURE_PROVING_INTERFACE.md` | Move from prose to executable contracts for goals and AEP clauses | narrative-only governance, ambiguous gate truth, strategy drift |
| `02_design_decisions.yaml` | Record new non-optional architectural decisions for coupling/time/scale | silent regression to underspecified policy |
| `REQ-0010.yaml` | Enforce three-claim coupling and objective contract completeness | MSC coupling blind spots; unverifiable strategy progression |
| `REQ-0011.yaml` | Make dominance and HTF authority mechanically testable | stale/wall-clock based authorization bugs |
| `REQ-0012.yaml` | Formalize scale economics and anti-entropy bounds | verifier collapse and fanout instability at scale |
| `07_test_and_evidence.yaml` | Ensure each revised/new requirement has explicit test + evidence mapping | unverified requirement claims |
| `09_governance_and_gates.yaml` | Make governance gates executable and fail-closed | subjective gate outcomes and policy bypass |

## 6) Physics Feasibility Ledger

| Claim | Governing constraints | Falsification test | Status |
|---|---|---|---|
| Parallel VPH with no direct promotion authority | containment invariants + authority graph | any `vph_direct_promotion_attempts > 0` | ADMISSIBLE |
| Deterministic routing under bounded governance | bounded compute + deterministic canonicalization | replay-equivalence ratio `< 1.0` | ADMISSIBLE |
| AAT-BIZ for strategy-critical paths | finite verifier compute + countermetric coverage | required path passes without valid AAT-BIZ receipt | ADMISSIBLE |
| HTF time-authoritative gate truth | signed HTF boundaries + monotonic ordering | gate truth accepted from wall-clock-only artifact | ADMISSIBLE |
| Scale operation at exabyte-to-zettabyte envelope | anti-entropy boundedness + verifier-economics ceilings | compute/fanout/backlog exceed policy ceilings over HTF windows | ADMISSIBLE |
| Strategy-coupled venture proving (MSC-03/05/06) | claim-specific evidence linkage + countermetrics | any Tier2+ signal has no valid claim linkage | ADMISSIBLE |

## 7) AAT-BIZ Coupling Ledger

| Signal class | Strategy claim | Mandatory Stage-5 obligations | Promotion outcome if missing/failing |
|---|---|---|---|
| `DEFECT:VERIFIER_DELTA` | `MSC-03` | replay-proven verifier delta + containment non-regression + anti-gaming | BLOCKED |
| `DRIFT:ORACLE_BOTTLENECK` | `MSC-05` | oracle load countermetrics + compiler SLA evidence + containment non-regression | BLOCKED |
| `INTENT:REVENUE`, `DRIFT:ECONOMICS` | `MSC-06` | ARR/margin/retention predicates + security/business countermetrics | BLOCKED |

## 8) Fast Experiments (Bounded)

| Experiment | Budget | Stop condition | Escalation path | Evidence path |
|---|---|---|---|---|
| `EXP-VPHI-001` Dominance-order evaluator chaos test | 2 HTF windows, max 500 replay cases | any precedence violation or unknown-state non-deny | Security Council | `evidence/venture/experiments/EXP-VPHI-001/` |
| `EXP-VPHI-002` Strategy coupling completeness replay | 3 days, max 1000 signal samples | linkage ratio for any of MSC-03/05/06 below `1.0` | Product + Governance Councils | `evidence/venture/experiments/EXP-VPHI-002/` |
| `EXP-VPHI-003` Scale-envelope stress with bounded anti-entropy | 2 stages, max 4 load profiles | compute share > `0.45` or fanout > `1.15` without quality gain | Runtime + Platform Councils | `evidence/venture/experiments/EXP-VPHI-003/` |

## 9) Evidence Probe Summary

- E01, E02, E03, E04, E06, E07, E08, E09, E10, E11, E12: keyword probes PASS.
- E05: partial due deleted upstream file `documents/strategy/SDLC_PIPELINE.md` in current worktree; strategy coupling verified against active strategy artifacts.
- E13: satisfied by this report and JSON envelope.
