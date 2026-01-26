title: RFC REVIEW Mode

decision_tree:
  entrypoint: REVIEW_AND_REFINE
  nodes[1]:
    - id: REVIEW_AND_REFINE
      purpose: "Execute formal review gates with iterative refinement and emit findings."
      steps[9]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <RFC_ID> and <PRD_ID> placeholders before running commands."
        - id: LOAD_INPUTS
          action: |
            Load RFC and ticket files:
            - RFC files: documents/rfcs/{RFC_ID}/*.yaml
            - Ticket files: documents/work/tickets/TCK-*.yaml (filter by rfc_id)
            - CCP: evidence/prd/{PRD_ID}/ccp/component_atlas.yaml
            - Previous Evidence: Load latest bundle if found in workflow.

            Extract:
            - requirement_ids from RFC
            - ticket_ids from ticket files
            - file_paths from tickets

        - id: ITERATIVE_GATE_EXECUTION
          action: |
            For each gate in the invariant order (1-7):
            1. Execute gate (TRUSTED -> DETERMINISTIC -> LLM-ASSISTED).
            2. If gate FAILS with BLOCKER/MAJOR findings:
               a. PROPOSE_EDITS: Generate remediations (TICKET_REWRITTEN, DEPENDENCY_FIXED, etc.).
               b. APPLY_EDITS: Modify tickets if substance test passes.
               c. DELTA_QUALITY_CHECK: Verify fix is not PROSE_ONLY.
               d. RE-RUN: Repeat gate check once to verify fix.
            3. Record final findings for the gate.

        - id: COMPUTE_DEPTH
          action: |
            If depth not already set, compute from impact:
            - ticket_count: count of tickets
            - cross_crate_changes: count unique crates in file_paths
            - net_new_files: count files_to_create across tickets

            STANDARD: ticket_count <= 15, cross_crate <= 2, net_new <= 10
            COUNCIL: any threshold exceeded OR --council flag

        - id: COUNCIL_PROTOCOL
          action: invoke_reference
          reference: references/COUNCIL_PROTOCOL.md
          condition: "depth is COUNCIL"

        - id: EMIT_BUNDLE
          action: |
            Produce NEW evidence bundle:
            - Path: evidence/rfc/{RFC_ID}/reviews/rfc_review_{timestamp}.yaml
            - Contents: gates, findings, verdict, council_metadata (if COUNCIL)
            - Note: Always emit a new bundle even if all gates pass initially.
      decisions[2]:
        - id: CRITICAL_FAILURE
          if: "any gate status is FAILED after refinement"
          then:
            stop: true
            verdict: REJECTED
        - id: COMPLETED
          if: "all gates executed and refined"
          then:
            stop: true
            verdict: compute_verdict()

---

## Verdict Computation

```python
def compute_verdict(findings):
    blockers = [f for f in findings if f.severity == "BLOCKER"]
    majors = [f for f in findings if f.severity == "MAJOR"]

    if blockers:
        return "REJECTED"
    elif len(majors) > 3:
        return "REJECTED"
    elif len(majors) > 0:
        return "APPROVED_WITH_REMEDIATION"
    else:
        return "APPROVED"
```

## Gate Execution Order

Gates execute in fixed order. Deterministic gates run before LLM-assisted gates to catch structural issues early.

1. **GATE-TCK-SCHEMA** (TRUSTED): Verify YAML parsing and schema conformance
2. **GATE-TCK-DEPENDENCY-ACYCLICITY** (DETERMINISTIC): Verify no cycles in dependency graph
3. **GATE-TCK-SCOPE-COVERAGE** (DETERMINISTIC): All requirements covered by tickets
4. **GATE-TCK-CCP-MAPPING** (DETERMINISTIC): File paths exist in CCP
5. **GATE-TCK-ATOMICITY** (LLM-ASSISTED): Each ticket completable in single PR
6. **GATE-TCK-IMPLEMENTABILITY** (LLM-ASSISTED): Agent can implement without clarification
7. **GATE-TCK-SECURITY-AND-INTEGRITY** (LLM-ASSISTED): Tickets preserve trust boundaries and mitigate threats
8. **GATE-TCK-REQUIREMENT-FIDELITY** (LLM-ASSISTED): Implementation content accurately fulfills PRD intent
9. **GATE-TCK-ANTI-COUSIN** (LLM-ASSISTED): No cousin abstractions introduced

## Evidence Bundle Schema

```yaml
schema_version: "1.0.0"
rfc_id: RFC-XXXX
review_timestamp: "2026-01-26T10:00:00Z"
review_depth: STANDARD | COUNCIL

gates:
  - gate_id: GATE-TCK-SCHEMA
    type: TRUSTED
    status: PASSED | FAILED
    findings: []
    evidence: {}

findings:
  - finding_id: FND-RFC-XXXX-001
    gate_id: GATE-TCK-IMPLEMENTABILITY
    category: IMPLEMENTABILITY_DEFECT
    subcategory: INCOMPLETE_PLAN
    severity: MAJOR
    location:
      file: documents/work/tickets/TCK-00101.yaml
      yaml_path: implementation.implementation_steps
    description: "Implementation steps missing error handling"
    remediation: "Add error handling steps for network failures"

verdict: APPROVED | APPROVED_WITH_REMEDIATION | REJECTED | NEEDS_ADJUDICATION
verdict_reason: "All gates passed"

# Only present for COUNCIL depth
council_metadata:
  session_id: COUNCIL-RFC-XXXX-20260126-100000
  subagents:
    - agent_id: SA-1
      emergent_role: Structural Rigorist
      selected_modes: [1, 6, 7, 43, 75]
  cycles_completed: 3
  quorum_achieved: true
```
