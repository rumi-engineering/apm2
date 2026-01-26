# REFINE Mode

decision_tree:
  entrypoint: REFINE_LOOP
  nodes[1]:
    - id: REFINE_LOOP
      purpose: "Iteratively run gates and remediate failures."
      steps[5]:
        - id: RUN_NEXT_GATE
          action: "Run the next gate in the invariant order."
        - id: DETECT_FAILURE
          if: "gate FAILS"
          action: "Identify blocker findings."
        - id: PROPOSE_EDITS
          action: "Propose minimal edits (BOUND_ADDED, EVIDENCE_LINKED, CCP_MAPPED, CRITERION_REWRITTEN)."
        - id: APPLY_EDITS
          action: "Apply edits if user confirms."
        - id: DELTA_QUALITY_CHECK
          action: "Verify fix is substantive (not PROSE_ONLY) before re-running gate."
          logic: |
            **Substance Test:**
            1. If the fix only adds prose (comments, rationale, notes) without changing a quantitative bound, evidence artifact reference, CCP mapping, or test command:
               - Fix is `PROSE_ONLY` and `INSUFFICIENT`.
               - If attempted 2+ times for same finding, escalate to `NEEDS_ADJUDICATION`.
            2. Valid Fix Types: `BOUND_ADDED`, `EVIDENCE_LINKED`, `CCP_MAPPED`, `CRITERION_REWRITTEN`, `REQUIREMENT_REMOVED`.
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
