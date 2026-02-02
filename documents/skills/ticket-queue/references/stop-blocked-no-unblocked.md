title: Blocked — No Unblocked Tickets

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Stop on dependency block."
      steps[5]:
        - id: OUTPUT_BLOCKER
          action: "Output BlockerReport: No unblocked tickets."
        - id: INCLUDE_EVIDENCE
          action: "Include summary of pending tickets and unmet dependencies."
        - id: LIST_BLOCKED_TICKETS
          action: "List blocked tickets."
        - id: NOTE_SEQUENTIAL_BLOCK
          action: "Sequential policy prevents progress."
        - id: STOP
          action: "Stop workflow."
      decisions[0]: []
