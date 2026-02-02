title: Start and Process Next Unblocked Ticket

decision_tree:
  entrypoint: START
  nodes[1]:
    - id: START
      purpose: "Start the next unblocked ticket (creates branch), then delegate to implementer subagent and monitor until merged."
      steps[8]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <START_TARGET_OPTIONAL> with $1 (or empty). This controls the initial selection only; you MUST continue until all tickets are merged."
        - id: DERIVE_NEXT_TICKET
          action: "If <START_TARGET_OPTIONAL> is empty, use `gh pr list` from `references/commands.md` (`list-recent-prs`) to observe the last 5-10 merged or open PRs. Derive the logical next TCK-XXXXX by identifying the highest numeric ticket ID currently in flight or recently merged, then selecting its immediate numeric successor from `documents/work/tickets/`."
        - id: VERIFY_UNBLOCKED
          action: "Check `dependencies.tickets` in `documents/work/tickets/<TICKET_ID>.yaml`. All MUST be in the 'Merged' list."
        - id: CREATE_BRANCH
          action: command
          run: "git checkout main && git pull && git checkout -b ticket/<TICKET_ID>"
          capture_as: branch_name
        - id: ASSERT_ON_TICKET_BRANCH
          action: command
          run: "git branch --show-current"
          capture_as: active_branch
        - id: DISPATCH_IMPLEMENTER
          action: "Dispatch an implementer subagent to implement the ticket and open the PR. The queue orchestrator MUST NOT modify code."
        - id: MONITOR_TO_MERGE
          action: "Proceed to monitoring (CI + reviews + SLA) until merged, then cleanup."
      decisions[2]:
        - id: NO_TICKET_AVAILABLE
          if: "all tickets are complete OR no unblocked tickets exist"
          then:
            next_reference: references/stop-or-blocked-no-unblocked.md
        - id: MONITOR
          if: "a ticket was identified and branch created"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md