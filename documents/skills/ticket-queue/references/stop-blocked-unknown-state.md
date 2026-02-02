title: Blocked — Unknown State

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Stop on classification failure."
      steps[3]:
        - id: OUTPUT_BLOCKER
          action: "Output BlockerReport: classification failed. Include command outputs."
        - id: SUGGEST_DEBUG
          action: "Rerun status commands. Include results."
        - id: STOP
          action: "Stop workflow."
      decisions[0]: []
