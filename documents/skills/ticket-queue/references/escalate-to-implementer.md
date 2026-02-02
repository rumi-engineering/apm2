title: Escalate to Implementer

decision_tree:
  entrypoint: ESCALATE
  nodes[1]:
    - id: ESCALATE
      purpose: "Provide fix task to implementer."
      steps[5]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID>, <CHECK_OUTPUT_SNIPPET>."
        - id: PREPARE_ESCALATION
          action: "Summarize block. Include <CHECK_OUTPUT_SNIPPET>."
        - id: ISSUE_IMPLEMENTER_TASK
          action: "Task: fix block, `cargo xtask commit`, `cargo xtask push`. Report when green."
        - id: SUPERVISE_PROGRESS
          action: "Monitor log every 3m. Restart if no progress for 5m."
        - id: RECHECK
          action: command
          run: "gh pr view --json statusCheckRollup"
          capture_as: check_output
      decisions[1]:
        - id: BACK
          if: "always"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md
