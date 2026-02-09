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
          action: "Rerun reviews: `apm2 fac review dispatch <PR_URL> --type all`."
        - id: NOTE_SEQUENTIAL_BLOCK
          action: "Sequential policy prevents progress."
        - id: STOP
          action: "Stop workflow."
      decisions[0]: []
