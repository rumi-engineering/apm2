title: Start and Process Next Unblocked Ticket

decision_tree:
  entrypoint: START
  nodes[1]:
    - id: START
      purpose: "Identify next ticket. Dispatch implementer. Monitor."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <START_TARGET_OPTIONAL>."
        - id: DERIVE_NEXT_TICKET
          action: "Use `gh pr list`. Identify numeric successor from `documents/work/tickets/`."
        - id: VERIFY_UNBLOCKED
          action: "Check `dependencies.tickets` in `documents/work/tickets/<TICKET_ID>.yaml`. Verify merged status."
        - id: DISPATCH_TO_MONITOR
          action: "Proceed to monitoring (60s loop). The monitor will handle implementer activation if needed."
      decisions[2]:
        - id: NO_TICKET
          if: "tickets complete OR no unblocked tickets"
          then:
            next_reference: references/stop-or-blocked-no-unblocked.md
        - id: MONITOR
          if: "always"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md