title: No Unblocked Ticket After Selection Attempt

decision_tree:
  entrypoint: CLASSIFY
  nodes[1]:
    - id: CLASSIFY
      purpose: "Handle the case where no new ticket could be started."
      steps[1]:
        - id: NOTE
          action: "Inspect the selection logs and classify whether: (a) all tickets are complete/in-progress, or (b) you are blocked by dependencies (no unblocked tickets)."
      decisions[3]:
        - id: BACK_TO_LOOP_IN_PROGRESS
          if: "All tickets are complete or in progress"
          then:
            next_reference: references/ticket-queue-loop.md
        - id: BLOCKED_BY_DEPENDENCIES
          if: "No unblocked tickets found (dependency block)"
          then:
            next_reference: references/stop-blocked-no-unblocked.md
        - id: UNKNOWN
          if: "otherwise"
          then:
            next_reference: references/stop-blocked-unknown-state.md