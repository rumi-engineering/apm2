title: Dispatch Implementer and Monitor Until Merge

decision_tree:
  entrypoint: DISPATCH
  nodes[1]:
    - id: DISPATCH
      purpose: "Activate implementer, supervise progress, enforce SLA, loop until merge."
      steps[15]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID>, <IMPLEMENTER_LOG_FILE>, <IMPLEMENTER_PID>."
        - id: CHECK_EXISTING_IMPLEMENTER
          action: command
          run: "pgrep -fa \"Follow ticket skill for <TICKET_ID>\" || true"
          capture_as: existing_implementer_ps
        - id: ESTABLISH_OR_RESUME_IMPLEMENTER_CONTRACT
          action: |
            If <existing_implementer_ps> is empty:
              1) Spawn background implementer via `start-claude-implementer-with-log`.
              2) Record PID, log path.
            Else:
              1) Identify PID and log path from <existing_implementer_ps> and existing log files.
        - id: REQUIRE_DEDICATED_LOG
          action: "Ensure log exists at `$HOME/.apm2/ticket-queue/logs/<TICKET_ID>.implementer.log`."
        - id: VERIFY_SKILL_INVOCATION
          action: "Check log for `/ticket` call."
        - id: CHECK_CADENCE
          action: "Follow `references/subagent-supervision.md` (60s cadence; 5m stall; 15m limit)."
        - id: FIND_BRANCH_NAME
          action: command
          run: "git branch --all --format='%(refname:short)' | rg \"TCK-[0-9]{5}\" | rg \"<TICKET_ID>\" | head -n 1"
          capture_as: derived_branch_name
        - id: PR_STATUS_CHECK
          action: command
          run: "gh pr view <derived_branch_name> --json state,reviewDecision,statusCheckRollup,headRefOid,url,comments || echo '{\"state\": \"PENDING_INITIALIZATION\"}'"
          capture_as: pr_status_json
        - id: AI_REVIEW_STATUS_CHECK
          action: command
          run: |
            head_oid=$(echo '<pr_status_json>' | jq -r '.headRefOid // empty')
            if [ -n "$head_oid" ]; then
              gh api repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/commits/$head_oid/status --jq '.statuses[] | select(.context | startswith("ai-review/")) | "\(.context): \(.state)"'
            else
              echo "AI reviews not yet triggered"
            fi
          capture_as: ai_review_statuses
        - id: MONITOR_REVIEWER_FEEDBACK
          action: "Check `pr_status_json` for comments. Verify implementer log action."
        - id: VERIFY_REVIEWER_ALIGNMENT
          action: "Check `reviewer-state-show`. If `head_sha` mismatch or inactive, trigger reviews."
        - id: REVIEW_SLA_ENFORCEMENT
          action: "If reviews pending (per `ai_review_statuses`), enforce 15m SLA via reviewer PIDs, logs."
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
          if: "ai_review_statuses indicate pending OR reviewer unhealthy OR SLA risk"
          then:
            next_reference: references/review-sla.md
        - id: CONTINUE
          if: "otherwise"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md