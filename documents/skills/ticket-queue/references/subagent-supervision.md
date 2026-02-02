title: Implementer Supervision

decision_tree:
  entrypoint: SUPERVISE
  nodes[1]:
    - id: SUPERVISE
      purpose: "Supervise implementer subagent. Ensure `/ticket` skill invocation. Monitor feedback."
      steps[11]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TASK_ID>, <OUTPUT_FILE>."
        - id: CHECK_CADENCE
          action: "Every 60s: check subagent status via TaskOutput, review output_file, check PR comments."
        - id: VERIFY_SKILL
          action: "Ensure output shows `/ticket` skill initialization."
        - id: CHECK_SUBAGENT_STATUS
          action: |
            Use TaskOutput(task_id=<TASK_ID>, block=false, timeout=5000) to check subagent status.
            Read output_file for recent activity.
          tool: TaskOutput
          parameters:
            task_id: "<TASK_ID>"
            block: false
            timeout: 5000
          capture_as: subagent_status
        - id: CHECK_OUTPUT_FILE
          action: |
            Read output_file (returned when Task was spawned) for recent activity:
            - Look for tool invocations (Bash, Read, Edit, Write)
            - Look for `/ticket` skill usage
            - Look for progress indicators
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
            (a) no output_file update >=5m
            (b) repeated errors/API loops in output
            (c) no skill call within 10m (startup allowance)
            (d) runtime >=15m
            (e) TaskOutput returns completed/failed status unexpectedly.
        - id: WARM_HANDOFF_DEF
          action: "WARM HANDOFF: When restarting, provide the new subagent with the last 100 lines of output_file and a summary of the current PR state in the Task prompt."
        - id: MAX_RUNTIME_RESP
          action: |
            If >=15m:
              1) Use TaskStop(task_id=<TASK_ID>) to terminate subagent.
              2) Start NEW subagent via Task tool with WARM HANDOFF context in prompt.
        - id: STUCK_RESP
          action: |
            If STUCK:
              1) Use TaskStop(task_id=<TASK_ID>) to terminate subagent.
              2) Restart via Task tool with error snippet and ticket ID in prompt.
        - id: NO_SELF_FIX
          action: "DO NOT edit code or manage branches. Redirect via new subagent prompt."
        - id: RETURN
          action: "Return to references/dispatch-and-monitor-ticket.md."
      decisions[1]:
        - id: BACK
          if: "always"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md