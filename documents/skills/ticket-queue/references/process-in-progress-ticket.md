title: Process In-Progress Ticket

decision_tree:
  entrypoint: RESUME
  nodes[1]:
    - id: RESUME
      purpose: "Resume in-progress ticket. Dispatch implementer. Monitor."
      steps[5]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID>, <BRANCH_NAME>."
        - id: PICK_LOWEST_IN_PROGRESS
          action: "Select lowest ID from in_progress_ticket_ids."
        - id: FIND_BRANCH_NAME
          action: command
          run: "git branch --all --format='%(refname:short)' | rg \"^(remotes/origin/)?ticket/.*/<TICKET_ID>$\" | head -n 1"
          capture_as: branch_name_maybe
        - id: NORMALIZE_BRANCH_NAME
          action: "Strip `remotes/origin/` prefix."
        - id: DISPATCH_TO_MONITOR
          action: "Proceed to monitoring (60s loop). The monitor will handle implementer activation if needed."
      decisions[1]:
        - id: MONITOR
          if: "always"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md