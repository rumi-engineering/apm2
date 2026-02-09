title: Blocked — Review SLA Breach

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Stop on 15m review SLA failure."
      steps[5]:
        - id: OUTPUT_BLOCKER
          action: "Output BlockerReport: Reviews stalled."
        - id: INCLUDE_EVIDENCE
          action: "Include: PR URL, SHA, reviewer_state summary, PIDs, log snippets."
        - id: SUGGEST_FALLBACK
          action: "Rerun reviews: `cargo xtask review <TYPE> <PR_URL>`. Stage-2 demotion (TCK-00419): projection-only by default; direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check`/`apm2 fac work status` for authoritative lifecycle state."
        - id: NOTE_SEQUENTIAL_BLOCK
          action: "Sequential policy prevents progress."
        - id: STOP
          action: "Stop workflow."
      decisions[0]: []
