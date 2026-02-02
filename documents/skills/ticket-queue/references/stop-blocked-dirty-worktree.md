title: Blocked — Dirty Repository

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Stop when the repository is dirty (uncommitted changes). This policy is specific to the ticket-queue skill."
      steps[3]:
        - id: OUTPUT_BLOCKER
          action: "Output a BlockerReport: repository has uncommitted changes. Ticket queue requires a clean repository state to avoid accidental edits; other agents may proceed per repo policy."
        - id: INSTRUCTION
          action: "Ask the operator to commit/stash/discard changes, then re-run the ticket-queue skill."
        - id: STOP
          action: "Stop the workflow."
      decisions[0]: []