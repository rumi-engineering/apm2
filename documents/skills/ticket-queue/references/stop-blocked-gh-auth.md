title: Blocked — GH Auth Missing

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Stop on missing auth."
      steps[3]:
        - id: OUTPUT_BLOCKER
          action: "Output BlockerReport: `gh auth status` failed."
        - id: INSTRUCTION
          action: "Run `gh auth login`. Re-run."
        - id: STOP
          action: "Stop workflow."
      decisions[0]: []
