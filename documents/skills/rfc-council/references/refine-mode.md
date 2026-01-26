title: RFC REFINE Mode

decision_tree:
  entrypoint: REFINE_LOOP
  nodes[1]:
    - id: REFINE_LOOP
      purpose: "Iteratively run gates and remediate failures."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <RFC_ID> placeholders before running commands."
        - id: RUN_NEXT_GATE
          action: "Run the next gate in the invariant order (defined in rfc-council-workflow.md)."
        - id: DETECT_FAILURE
          if: "gate FAILS"
          action: "Identify blocker/major findings."
        - id: PROPOSE_EDITS
          action: "Propose minimal edits (TICKET_REWRITTEN, DEPENDENCY_FIXED, CCP_MAPPED, REQUIREMENT_COVERED)."
        - id: APPLY_EDITS
          action: "Apply edits if user confirms."
        - id: DELTA_QUALITY_CHECK
          action: "Verify fix is substantive (not PROSE_ONLY) before re-running gate."
          logic: |
            **Substance Test:**
            1. If the fix only adds prose (comments, rationale, notes) without changing a ticket field, dependency, implementation step, or verification command:
               - Fix is `PROSE_ONLY` and `INSUFFICIENT`.
               - If attempted 2+ times for same finding, escalate to `NEEDS_ADJUDICATION`.
            2. Valid Fix Types: `TICKET_REWRITTEN`, `DEPENDENCY_FIXED`, `CCP_MAPPED`, `REQUIREMENT_COVERED`, `TICKET_REMOVED`.
      decisions[2]:
        - id: GATE_STILL_FAILING
          if: "gate still fails after remediation"
          then:
            next_node: REFINE_LOOP
        - id: GATE_PASSED
          if: "gate passes"
          then:
            next_node: REFINE_LOOP
            condition: "more gates remain"
