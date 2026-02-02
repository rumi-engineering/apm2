title: Blocked — Dirty Repository

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Stop on uncommitted changes."
      steps[3]:
        - id: OUTPUT_BLOCKER
          action: "Output BlockerReport: repository has uncommitted changes."
        - id: INSTRUCTION
          action: "Commit/stash changes. Re-run."
        - id: STOP
          action: "Stop workflow."
      decisions[0]: []
