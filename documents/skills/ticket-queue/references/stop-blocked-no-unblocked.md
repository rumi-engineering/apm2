title: Blocked — No Unblocked Tickets (Dependencies)

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Stop when no unblocked tickets are found (dependency deadlock or unmet prerequisites)."
      steps[5]:
        - id: OUTPUT_BLOCKER
          action: "Output a BlockerReport: No unblocked tickets found due to dependencies."
        - id: INCLUDE_EVIDENCE
          action: "Include a summary of pending tickets and their unmet dependencies (checked against merged PR list)."
        - id: LIST_BLOCKED_TICKETS
          action: "List the blocked tickets and their unmet dependencies exactly as discovered."
        - id: NOTE_SEQUENTIAL_BLOCK
          action: "Note: sequential merge policy means the queue cannot proceed until dependencies are resolved (or tickets are reclassified/unblocked)."
        - id: STOP
          action: "Stop the workflow."
      decisions[0]: []