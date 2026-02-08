title: Dispatch Implementer and Monitor Until Merge

decision_tree:
  entrypoint: DISPATCH
  nodes[1]:
    - id: DISPATCH
      purpose: "Activate implementer, supervise progress, enforce SLA, loop until merge."
      steps[15]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID>, <TASK_ID>, <OUTPUT_FILE>."
        - id: CHECK_EXISTING_SUBAGENT
          action: |
            Check for existing subagent via TaskOutput (non-blocking):
            - If task_id stored from previous dispatch, query its status.
            - If no stored task_id, assume no active subagent.
          capture_as: existing_subagent_status
        - id: ESTABLISH_OR_RESUME_IMPLEMENTER_CONTRACT
          action: |
            If no active subagent:
              1) Spawn background implementer via Task tool:
                 Task(subagent_type="general-purpose", description="Implement <TICKET_ID>", prompt="/ticket <TICKET_ID>", run_in_background=true)
              2) Record task_id, output_file from response.
            Else:
              1) Use existing task_id and output_file for monitoring.
        - id: REQUIRE_OUTPUT_FILE
          action: "Subagent output available at output_file returned by Task tool."
        - id: VERIFY_SKILL_INVOCATION
          action: "Check output_file for `/ticket` skill invocation."
        - id: CHECK_CADENCE
          action: "Follow `references/subagent-supervision.md` (60s cadence; 5m stall; 15m limit). Use TaskOutput to check subagent progress."
        - id: FIND_BRANCH_NAME
          action: command
          run: "git branch --all --format='%(refname:short)' | rg \"TCK-[0-9]{5}\" | rg \"<TICKET_ID>\" | head -n 1"
          capture_as: derived_branch_name
        - id: PR_STATUS_CHECK
          action: command
          run: "gh pr view <derived_branch_name> --json state,reviewDecision,statusCheckRollup,headRefOid,url,comments || echo '{\"state\": \"PENDING_INITIALIZATION\"}'"
          capture_as: pr_status_json
        - id: REVIEW_GATE_STATUS_CHECK
          action: command
          run: |
            head_oid=$(echo '<pr_status_json>' | jq -r '.headRefOid // empty')
            if [ -n "$head_oid" ]; then
              gh api repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/commits/$head_oid/status --jq '.statuses[] | select(.context == "Review Gate Success") | "\(.context): \(.state)"'
            else
              echo "Review gate not yet evaluated"
            fi
          capture_as: review_gate_status
        - id: MONITOR_REVIEWER_FEEDBACK
          action: "Check `pr_status_json` for comments. Verify implementer log action."
        - id: VERIFY_REVIEWER_ALIGNMENT
          action: "Check `reviewer-state-show`. If `head_sha` mismatch or inactive, trigger reviews."
        - id: REVIEW_SLA_ENFORCEMENT
          action: "If reviews pending (per `review_gate_status`), enforce 15m SLA via reviewer PIDs, logs."
        - id: MERGE_WAIT
          action: "If CI/reviews pass, poll for merge."
        - id: RETURN_TO_LOOP
          action: "Once merged, return to the main loop (references/ticket-queue-loop.md)."
        - id: LOOP
          action: "Repeat check and supervision every 60s until stop."
      decisions[7]:
        - id: INITIALIZING
          if: "pr_status_json contains PENDING_INITIALIZATION"
          then:
            next_reference: references/subagent-supervision.md
        - id: MERGED
          if: "pr_status_json indicates MERGED"
          then:
            next_reference: references/ticket-queue-loop.md
        - id: NO_PR
          if: "pr_status_json is empty or error AND runtime > 5m"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: CI_FAILED
          if: "pr_status_json indicates FAILURE"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: CHANGES_REQUESTED
          if: "pr_status_json indicates reviewDecision is CHANGES_REQUESTED"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: REVIEWS_PENDING_OR_STUCK
          if: "review_gate_status indicates pending OR reviewer unhealthy OR SLA risk"
          then:
            next_reference: references/review-sla.md
        - id: CONTINUE
          if: "otherwise"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md