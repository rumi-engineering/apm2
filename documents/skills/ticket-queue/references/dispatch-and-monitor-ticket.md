title: Dispatch Implementer and Monitor Until Merge

decision_tree:
  entrypoint: DISPATCH
  nodes[1]:
    - id: DISPATCH
      purpose: "Ensure an implementer subagent is active for this ticket, supervise its progress, enforce review SLA, and keep looping until the PR is merged and cleaned up."
      steps[11]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID> and <BRANCH_NAME>. If known, replace <IMPLEMENTER_LOG_FILE> and <IMPLEMENTER_PID> for out-of-band supervision."
        - id: ESTABLISH_IMPLEMENTER_CONTRACT
          action: "Create/confirm an implementer subagent (separate process/session) that is allowed to edit code. Instruct the subagent to follow the `ticket` protocol (from `documents/skills/ticket/SKILL.md`) for the specific <TICKET_ID>. Do NOT execute that skill yourself; require the subagent to: implement, `cargo xtask commit`, `cargo xtask push`, respond to failures, and get to green."
        - id: REQUIRE_DEDICATED_LOG
          action: "The implementer MUST run with a durable log you can tail out-of-band. Prefer the exact commands in `references/commands.md` (`start-claude-implementer-with-log`). Record PID + log path."
        - id: CHECK_CADENCE
          action: "While implementer is running: follow `references/subagent-supervision.md` (3-minute cadence; STUCK threshold 5 minutes; restart on no-progress; 15-minute hard limit for context rot mitigation)."
        - id: PR_STATUS_CHECK
          action: command
          run: "gh pr view <BRANCH_NAME> --json state,reviewDecision,statusCheckRollup,headRefOid,url"
          capture_as: pr_status_json
        - id: VERIFY_REVIEWER_ALIGNMENT
          action: "Check `reviewer-state-show` from `references/commands.md`. If active reviewers are tracking a `head_sha` that differs from the PR's `headRefOid`, or if no reviewers are active for an open PR, manually trigger/re-trigger reviews using `trigger-reviews` from `references/commands.md`."
        - id: VERIFY_CI_LIVENESS
          action: "If `statusCheckRollup` is ambiguous (e.g., CI reported as 'PENDING' for a long time), use `gh api` from `references/commands.md` (`list-workflow-runs`) to verify if GitHub Actions are actually active and making progress on the branch."
        - id: REVIEW_SLA_ENFORCEMENT
          action: "If AI reviews are pending, enforce the 15-minute SLA using reviewer PIDs + logs. Do not allow pending reviews to persist beyond 15 minutes."
        - id: MERGE_WAIT
          action: "If CI/reviews are passing and auto-merge is enabled, keep polling until merged."
        - id: CLEANUP_AFTER_MERGE
          action: "When merged, run branch cleanup (`references/post-merge-cleanup.md`), then return to the main loop."
        - id: LOOP
          action: "Repeat PR_STATUS_CHECK + supervision until a stop/branch condition triggers."
      decisions[5]:
        - id: MERGED
          if: "pr_status_json indicates state is MERGED"
          then:
            next_reference: references/post-merge-cleanup.md
        - id: NO_PR
          if: "gh pr view fails or indicates no PR exists"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: CI_FAILED
          if: "pr_status_json indicates any status check conclusion is FAILURE"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: CHANGES_REQUESTED
          if: "pr_status_json indicates reviewDecision is CHANGES_REQUESTED"
          then:
            next_reference: references/escalate-to-implementer.md
        - id: REVIEWS_PENDING_OR_STUCK
          if: "pr_status_json indicates reviewDecision is REVIEW_REQUIRED OR reviewer health is stale/dead OR SLA risk"
          then:
            next_reference: references/review-sla.md