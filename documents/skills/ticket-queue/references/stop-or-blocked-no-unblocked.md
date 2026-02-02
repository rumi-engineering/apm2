title: No Unblocked Tickets

decision_tree:
  entrypoint: CLASSIFY
  nodes[1]:
    - id: CLASSIFY
      purpose: "Handle start failure."
      steps[1]:
        - id: NOTE
          action: "Classify: (a) tickets complete/in-progress, (b) dependency block."
      decisions[3]:
        - id: LOOP
          if: "Tickets complete/in-progress"
          then:
            next_reference: references/ticket-queue-loop.md
        - id: BLOCKED
          if: "Dependency block"
          then:
            next_reference: references/stop-blocked-no-unblocked.md
        - id: UNKNOWN
          if: "otherwise"
          then:
            next_reference: references/stop-blocked-unknown-state.md
