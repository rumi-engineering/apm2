title: Implementer Supervision

decision_tree:
  entrypoint: SUPERVISE
  nodes[1]:
    - id: SUPERVISE
      purpose: "Supervise implementer. Ensure `/ticket` call. Monitor feedback."
      steps[11]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <IMPLEMENTER_PID>, <IMPLEMENTER_LOG_FILE>."
        - id: CHECK_CADENCE
          action: "Every 60s: check log mtime, tail lines, check PR comments."
        - id: VERIFY_SKILL
          action: "Ensure log shows `/ticket` initialization."
        - id: CHECK_LOG
          action: command
          run: "bash -lc 'set -euo pipefail; if [ -f \"<IMPLEMENTER_LOG_FILE>\" ]; then stat -c \"%y %n\" <IMPLEMENTER_LOG_FILE>; tail -n 120 <IMPLEMENTER_LOG_FILE> | rg -n \"tool|Tool|Bash\\(|Read\\(|Edit\\(|Write\\(|exec|command|skill|ticket\" || true; else echo \"Log file not yet created\"; fi'"
          capture_as: implementer_recent_activity
        - id: CHECK_FEEDBACK
          action: command
          run: "gh pr view --json comments"
          capture_as: pr_comments
        - id: CONGRUENCY
          action: |
            Expect:
            - PR comments -> read PR, apply changes.
            - CI fail -> fix (test/clippy/fmt).
            - No skill -> setup phase.
        - id: STUCK_DEF
          action: |
            STUCK if:
            (a) no log update >=5m
            (b) repeated errors/API loops
            (c) no skill call within 10m (startup allowance)
            (d) runtime >=15m.
        - id: WARM_HANDOFF_DEF
          action: "WARM HANDOFF: When restarting, provide the new implementer with the last 100 lines of the previous log and a summary of the current PR state."
        - id: MAX_RUNTIME_RESP
          action: "If >=15m: Terminate. Start NEW implementer with WARM HANDOFF to prevent context rot."
        - id: STUCK_RESP
          action: "If STUCK: Terminate. Restart with error snippet, ticket ID."
        - id: NO_SELF_FIX
          action: "DO NOT edit code or manage branches. Redirect implementer."
        - id: RETURN
          action: "Return to references/dispatch-and-monitor-ticket.md."
      decisions[1]:
        - id: BACK
          if: "always"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md