# RFC-0026: Recursive Self-Modification Protocol — Seed

## Required context files

Read all of these before generating output:

- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/strategy/MASTER_STRATEGY.json
- documents/rfcs/RFC-0020/HOLONIC_SUBSTRATE_INTERFACE.md
- documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
- documents/rfcs/RFC-0023/INSTRUCTION_LIFECYCLE.md
- documents/rfcs/RFC-0024/RESOURCE_PROVISIONING.md
- proto/kernel_events.proto

## Why this RFC matters

This is the capstone and the most dangerous RFC in the series. A system that can modify itself can improve itself — but it can also corrupt itself, drift from alignment, or amplify errors. This RFC must define the governance protocol for self-modification: how the system proposes changes to its own code, policies, and architecture; how those proposals are contained, reviewed, and approved; how modifications are verified during and after execution; and how alignment is continuously monitored. The key constraint is that self-modification must be strictly less powerful than principal sovereignty (RFC-0022) — the system can never modify away the principal's ability to control it. Draw from formal verification, proof-carrying code, sandboxed execution, and alignment research.

## Priority innovation vectors

- **Containment before modification**: every self-modification proposal must come with a containment proof bounding what it can affect — think capability-based sandboxing applied to the modification process itself.
- **Alignment as invariant preservation**: formalize alignment as a set of invariants (derived from theory/unified-theory-v2.json and theory/unified-theory-v2.json) that must be preserved across any modification, verified mechanically.
- **Modification as episode**: treat each self-modification as a contained episode with its own capability manifest, budget, stop conditions, and evidence trail — reuse the HSI substrate.
- **Anti-drift via bisimulation**: continuously verify that the post-modification system is bisimilar to the pre-modification system on all safety-critical behaviors.
- **Recursive modification governance**: self-modification of the self-modification protocol itself must require strictly higher authority than normal modifications — preventing the system from loosening its own constraints.

## Problem (PHY-05, PHY-06, PHY-07, INV-F-14)

The system's stated goal is recursive self-improvement (AEP GOAL_EVERGREEN). AEP_04 (Compounding Closure) mandates every subsystem feeds the recursive improvement loop. The FAC (RFC-0015, RFC-0019) gates code admission. The instruction lifecycle (RFC-0023) governs the system's governing rules. RFC-0022 gives the principal sovereignty.

But there is no normative protocol that defines the boundaries of permissible self-modification, proves modifications cannot compromise containment, establishes the modification loop itself, or provides continuous verification that the system's alignment constraints remain intact. Without this, the system's recursive improvement is either unconstrained (existential risk) or ad-hoc (no compounding guarantee).

This is the capstone RFC. It depends on all four preceding RFCs and must be the last to ship.

## What already exists

| Artifact | Provides | Gap |
|---|---|---|
| AEP_04 (Compounding Closure) | Axiom: every subsystem feeds recursive improvement | No protocol for HOW |
| FAC (RFC-0015, RFC-0019) | Code admission gating | Gates individual changes, doesn't model the modification loop as a whole |
| VPHI (RFC-0021) | Strategy verification | Verifies business alignment, not self-modification safety |
| MECH-REPETITION-DETECTION | Detect repetitive agent behavior | Detects loops, doesn't govern intentional self-modification |
| MECH-MONITOR-ISOLATION | Isolated monitoring | Monitors separately, not applied to self-modification verification |
| MECH-EVALUATOR-AUDIT | Evaluator auditing | Audits evaluators, doesn't cover self-modification scope |
| INV-F-14 | containment > verification > liveness | The constraint, not its enforcement during self-modification |
| RFC-0022 (this batch) | Principal sovereignty + containment proof | Provides the outer containment; this RFC defines the inner loop |
| RFC-0023 (this batch) | Instruction lifecycle | Governs instruction modification; this RFC governs ALL self-modification |

## Machine-checkable objectives

**OBJ-RSM-01**: Modification scope is declared: Every self-modification must declare its scope — which components it modifies, which invariants it preserves, and which invariants it cannot affect. Undeclared modifications are S0 defects.
- Predicate: `∀ modification: modification.scope ≠ {} ∧ modification.preserved_invariants ≠ {}`

**OBJ-RSM-02**: Sovereignty invariants are immutable: The set of invariants protecting principal sovereignty (RFC-0022) must not be modifiable by the system. Any modification attempt is an S0 defect triggering immediate freeze.
- Predicate: `∀ modification: modification.scope ∩ SOVEREIGNTY_INVARIANTS = {} ∨ system.state = FROZEN`

**OBJ-RSM-03**: Containment monotonicity: Self-modification must not weaken containment. Formally: the capability set after modification must be a subset of or equal to the capability set before, unless the principal explicitly approves expansion.
- Predicate: `∀ modification: post_capabilities ⊆ pre_capabilities ∨ principal_approval.present = true`

**OBJ-RSM-04**: Modification loop is gated: Each iteration of the self-modification loop must pass: (a) FAC admission for code changes, (b) instruction lifecycle gates for instruction changes, (c) containment proof renewal, (d) principal sovereignty proof verification. All four gates must pass; any failure halts the loop.
- Predicate: `∀ iteration: fac_gate ∧ instruction_gate ∧ containment_gate ∧ sovereignty_gate`

**OBJ-RSM-05**: Alignment binding is continuous: The system must continuously verify its alignment with declared goals (AEP GOAL_EVERGREEN + extropian principles). Alignment is measured, not assumed. Drift beyond a threshold triggers escalation to the principal.
- Predicate: `∀ epoch: alignment_score(epoch) ≥ threshold ∨ escalation.sent = true`

**OBJ-RSM-06**: Independent verification: Self-modification results must be verified by a process that was NOT modified in the same iteration. The verifier and the modified component must be in separate trust domains.
- Predicate: `∀ modification: verifier ∩ modified_components = {} ∧ verifier.trust_domain ≠ modified.trust_domain`

**OBJ-RSM-07**: Termination guarantee: The self-modification loop must have a declared termination condition. Infinite loops of self-modification are forbidden (LAW-12, INV-F-09).
- Predicate: `∀ loop: ∃ termination_condition: reachable(termination_condition) = true`

**OBJ-RSM-08**: Rollback to last-known-good: If any gate fails during self-modification, the system must be able to rollback to the state before the modification began. This rollback must be tested (not just theoretically possible).
- Predicate: `∀ modification: ∃ rollback_test: rollback_test.passed = true ∧ rollback_test.epoch = modification.start_epoch`

## Protocol objects (seed schemas)

These are starting points — refine, extend, or restructure as your analysis requires.

```
SelfModificationProposalV1 {
    proposal_id: CasDigest,
    proposing_holon: HolonIdV1,
    modification_scope: ModificationScopeV1,
    motivation: CasDigest,
    expected_invariant_impact: InvariantImpactV1,
    termination_condition: TerminationConditionV1,
    rollback_plan: RollbackPlanV1,
    proposed_at: TimeEnvelopeRef,
}

ModificationScopeV1 {
    modified_components: Vec<ComponentRefV1>,
    preserved_invariants: Vec<InvariantRefV1>,
    immutable_invariants: Vec<InvariantRefV1>,
    capability_delta: CapabilityDeltaV1,
    instruction_spec_changes: Vec<CasDigest>,
    code_changes: Vec<CasDigest>,
}

InvariantImpactV1 {
    invariant_id: str,
    pre_modification_status: InvariantStatus,
    expected_post_status: InvariantStatus,
    verification_method: VerificationMethod,
    goodhart_surface: str,
}

ModificationIterationReceiptV1 {
    proposal_digest: CasDigest,
    iteration_number: u32,
    fac_gate_result: GateReceiptV1,
    instruction_gate_result: GateReceiptV1,
    containment_proof: ContainmentProofV1,
    sovereignty_proof: HaltPathLivenessProofV1,
    independent_verification: IndependentVerificationV1,
    alignment_measurement: AlignmentMeasurementV1,
    rollback_test_result: GateReceiptV1,
    iteration_verdict: IterationVerdict,
    completed_at: TimeEnvelopeRef,
}

IndependentVerificationV1 {
    verifier_holon: HolonIdV1,
    verifier_trust_domain: str,
    modified_components: Vec<ComponentRefV1>,
    verification_results: Vec<VerificationResultV1>,
    verifier_seal: AuthoritySealV1,
    verified_at: TimeEnvelopeRef,
}

AlignmentMeasurementV1 {
    epoch: TimeEnvelopeRef,
    goal_alignment_scores: Vec<GoalAlignmentScoreV1>,
    aggregate_score: Quantity,
    drift_detected: bool,
    drift_magnitude: Option<Quantity>,
    measurement_method: str,
    goodhart_surface: str,
    measurement_seal: AuthoritySealV1,
}

GoalAlignmentScoreV1 {
    goal_ref: str,
    score: Quantity,
    evidence: Vec<CasDigest>,
    last_measured: TimeEnvelopeRef,
}

TerminationConditionV1 {
    max_iterations: u32,
    max_duration: Duration,
    success_predicate: str,
    failure_predicate: str,
    budget: ResourceBudgetV1,
}

RollbackPlanV1 {
    rollback_target: CasDigest,
    rollback_verification: str,
    last_tested: TimeEnvelopeRef,
    test_receipt: CasDigest,
}

ModificationLoopSummaryV1 {
    proposal_digest: CasDigest,
    total_iterations: u32,
    final_verdict: LoopVerdict,
    invariants_preserved: Vec<InvariantRefV1>,
    capability_delta_actual: CapabilityDeltaV1,
    alignment_trajectory: Vec<AlignmentMeasurementV1>,
    evidence_chain: Vec<CasDigest>,
    principal_review_required: bool,
    completed_at: TimeEnvelopeRef,
}

IterationVerdict { PROCEED | HALT | ROLLBACK | ESCALATE_TO_PRINCIPAL }
LoopVerdict { COMPLETED | HALTED_BY_GATE | ROLLED_BACK | TERMINATED_BY_PRINCIPAL | BUDGET_EXHAUSTED }
```

## Trust boundaries and threat model

Trust boundary: The self-modification loop runs within the system, but its verification runs OUTSIDE the modified component's trust domain (OBJ-RSM-06). The sovereignty invariants (RFC-0022) are in a strictly higher trust domain that the modification loop cannot reach. The principal stands above all of it.

```
PRINCIPAL (supreme authority, hardware-rooted)
  └── SOVEREIGNTY DOMAIN (RFC-0022, immutable by system)
       └── VERIFICATION DOMAIN (independent verifiers, RFC-0022 external verifier)
            └── MODIFICATION DOMAIN (where self-modification happens)
                 └── OPERATIONAL DOMAIN (where modified code runs)
```

Threats:
1. **Containment erosion (PHY-05, PHY-06)**: Individually-safe modifications that compose to weaken containment. Mitigation: containment monotonicity (OBJ-RSM-03) — the capability set can only shrink or stay equal without principal approval.
2. **Verifier capture (PHY-05)**: Modified system co-opts its own verifier. Mitigation: independent verification in separate trust domains; verifier cannot be modified in the same iteration it verifies.
3. **Alignment drift (PHY-03)**: Gradual drift from extropian goals through individually-aligned steps. Mitigation: continuous alignment measurement with aggregate scoring and drift detection.
4. **Infinite modification loop (PHY-06, PHY-07)**: System enters unbounded self-improvement loop. Mitigation: explicit termination conditions with max iterations, max duration, and budget (OBJ-RSM-07).
5. **Sovereignty invariant tampering (PHY-05)**: System modifies the rules that protect the principal. Mitigation: sovereignty invariants are immutable (OBJ-RSM-02); any attempt triggers immediate freeze.
6. **Rollback infeasibility (PHY-04)**: System state diverges so far that rollback is impossible. Mitigation: rollback is continuously tested, not just planned (OBJ-RSM-08).

## Dependency chain

```
RFC-0026 depends on:
  ├── RFC-0022 (Principal Sovereignty) — provides ContainmentProofV1, HaltPathLivenessProofV1, AutonomyLevel
  ├── RFC-0023 (Instruction Lifecycle) — provides SpecPromotionReceiptV1 for instruction modifications
  ├── RFC-0024 (Resource Provisioning) — provides ResourceBudgetV1 for modification budgets
  └── RFC-0025 (Service Operation) — provides DeploymentReceiptV1 for deploying modified components
```

## Theory bindings

- LAW-01 (Loop Closure): The modification loop IS a gated promotion loop
- LAW-05 (Dual-Axis Containment): Modification is contained along both integrity (what can change) and authority (who can approve) axes
- LAW-08 (Verifier Economics): Independent verification is economically separated
- LAW-12 (Bounded Search): Termination conditions bound the modification search space
- LAW-14 (Proportionality): Modification scope must be proportional to the evidence supporting it
- LAW-16 (Closure Under Composition): Modified components must still compose holonically
- INV-F-02 (No transition without gate receipt): Every modification iteration produces receipts
- INV-F-05 (Default-deny, time-bounded): Modifications are time-bounded, budget-bounded
- INV-F-09 (Budgets mandatory): The modification loop has a budget
- INV-F-10 (Only gate what you can defend): Alignment measurement declares its Goodhart surface
- INV-F-11 (All paths check stop): Modification loop checks sovereignty at every iteration
- INV-F-14 (containment > verification > liveness): The modification loop must not compromise containment to achieve improvement

## Rollout

- S0: ModificationScopeV1 and InvariantImpactV1 — declare modification boundaries (code-only modifications)
- S1: Four-gate verification loop — FAC + instruction lifecycle + containment proof + sovereignty check
- S2: Independent verification in separate trust domains
- S3: AlignmentMeasurementV1 with continuous scoring and drift detection
- S4: Rollback plan testing — automated rollback drills
- S5: Sovereignty invariant immutability enforcement — any attempt to modify sovereignty set triggers freeze
- S6: Full recursive self-modification loop with all 8 objectives enforced
- S7: Formal methods integration — TLA+/PlusCal specifications for the modification loop state machine
- S8: Multi-iteration optimization — the system can plan multi-step modification sequences with pre-verified invariant preservation
