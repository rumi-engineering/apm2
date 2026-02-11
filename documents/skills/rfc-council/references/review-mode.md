title: RFC REVIEW Mode

decision_tree:
  entrypoint: REVIEW_AND_REFINE
  nodes[2]:
    - id: REVIEW_AND_REFINE
      purpose: "Execute formal review gates with iterative refinement and persist findings artifacts."
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
            For each gate in the invariant order (1-9):
            1. Execute gate (TRUSTED -> DETERMINISTIC -> LLM-ASSISTED).
            2. If gate FAILS with BLOCKER/MAJOR findings:
               a. **Mode 59 (Dialectical)**: Define Thesis (Requirement) vs Antithesis (Constraint).
               b. SYNTHESIZE: Generate a novel remediation that transcends the tension.
               c. APPLY_EDITS: Modify tickets/RFC.
               d. RE-RUN: Repeat gate check once to verify synthesis.
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
            Emit new evidence bundle to `evidence/rfc/{RFC_ID}/reviews/rfc_review_{timestamp}.yaml`.
            Include gates, findings, verdict, and council_metadata.
      decisions[2]:
        - id: CRITICAL_FAILURE
          if: "any gate status is FAILED after refinement"
          then:
            next: STOP
            verdict: REJECTED
        - id: COMPLETED
          if: "all gates executed and refined"
          then:
            next: STOP
            verdict: compute_verdict()

    - id: STOP
      purpose: "Terminate."
      steps[1]:
        - id: DONE
          action: "output DONE and nothing else, your task is complete."

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

1. **GATE-TCK-SCHEMA** (TRUSTED)
2. **GATE-TCK-DEPENDENCY-ACYCLICITY** (DETERMINISTIC)
3. **GATE-TCK-SCOPE-COVERAGE** (DETERMINISTIC)
4. **GATE-TCK-CCP-MAPPING** (DETERMINISTIC)
5. **GATE-TCK-ATOMICITY** (LLM-ASSISTED)
6. **GATE-TCK-IMPLEMENTABILITY** (LLM-ASSISTED)
7. **GATE-TCK-SECURITY-AND-INTEGRITY** (LLM-ASSISTED)
8. **GATE-TCK-REQUIREMENT-FIDELITY** (LLM-ASSISTED)
9. **GATE-TCK-ANTI-COUSIN** (LLM-ASSISTED)
