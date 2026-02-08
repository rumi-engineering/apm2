title: Escalate to Implementer

decision_tree:
  entrypoint: ESCALATE
  nodes[1]:
    - id: ESCALATE
      purpose: "Provide fix task to implementer subagent."
      steps[5]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID>, <TASK_ID>, <CHECK_OUTPUT_SNIPPET>."
        - id: PREPARE_ESCALATION
          action: "Summarize block. Include <CHECK_OUTPUT_SNIPPET>."
        - id: ISSUE_IMPLEMENTER_TASK
          action: |
            If subagent still running:
              - Include escalation context in next supervision cycle.
            If subagent stopped:
              - Spawn new subagent via Task tool with escalation context:
                Task(subagent_type="general-purpose", description="Fix <TICKET_ID>", prompt="/ticket <TICKET_ID>\n\nESCALATION: <CHECK_OUTPUT_SNIPPET>\nTask: fix block, `cargo xtask commit`, `cargo xtask push`. Report when green.", run_in_background=true)
              - Stage-2 demotion (TCK-00419): `cargo xtask commit`/`cargo xtask push` are projection-only by default; direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check`/`apm2 fac work status` for authoritative lifecycle state.
        - id: SUPERVISE_PROGRESS
          action: "Monitor via TaskOutput every 3m. Use TaskStop and restart if no progress for 5m."
        - id: RECHECK
          action: command
          run: "gh pr view --json statusCheckRollup"
          capture_as: check_output
      decisions[1]:
        - id: BACK
          if: "always"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md
