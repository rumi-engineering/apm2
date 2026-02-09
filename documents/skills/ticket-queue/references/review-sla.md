title: Review SLA Enforcement

decision_tree:
  entrypoint: ENFORCE
  nodes[1]:
    - id: ENFORCE
      purpose: "Ensure AI reviews update status within 15m."
      steps[12]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace <TICKET_ID>, <BRANCH_NAME>, <PR_URL>, <SEC_TASK_ID>, <QUAL_TASK_ID>, <headRefOid>."
        - id: GET_PR_METADATA
          action: command
          run: "gh pr view <BRANCH_NAME> --json url,headRefOid"
          capture_as: pr_meta
        - id: CHECK_REVIEW_GATE_STATUS
          action: command
          run: "gh api repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/commits/<headRefOid>/status --jq '.statuses[] | select(.context == \"Review Gate Success\") | \"\(.context): \(.state)\"'"
          capture_as: review_gate_status
        - id: LOAD_REVIEWER_STATE
          action: command
          run: "python3 - <<'PY'\nimport json, os, time\nfrom pathlib import Path\np = Path.home() / '.apm2' / 'reviewer_state.json'\nif p.exists():\n    data = json.loads(p.read_text())\n    for k,v in (data.get('reviewers') or {}).items():\n        print(f\"{k}\tpid={v.get('pid')}\tstarted_at={v.get('started_at')}\tlog_file={v.get('log_file')}\tpr_url={v.get('pr_url')}\")\nPY"
          capture_as: reviewer_state_summary
        - id: IDENTIFY_TASK_IDS
          action: "Identify reviewer task_ids from reviewer_state or previous dispatch records."
        - id: INSPECT_REVIEWER_STATUS
          action: |
            Use TaskOutput to check reviewer subagent status (if managed via Task tool):
              TaskOutput(task_id=<SEC_TASK_ID>, block=false, timeout=5000)
              TaskOutput(task_id=<QUAL_TASK_ID>, block=false, timeout=5000)
            Note: xtask reviews may run as direct processes; check reviewer_state for details.
          capture_as: reviewer_status
        - id: CHECK_REVIEWER_ACTIVITY
          action: |
            Review reviewer_state_summary for activity timestamps.
            If reviewers managed via Task tool, read output_files for recent activity.
          capture_as: reviewer_activity
        - id: TAIL_OUTPUTS
          action: "If output_files available, read last 80 lines for progress indicators."
          capture_as: reviewer_output_tail
        - id: ENFORCE_15M_DEADLINE
          action: "Verify `now - started_at < 900s`. If breach (per `review_gate_status`), restart reviews."
        - id: RESTART_IF_UNHEALTHY
          action: "If STALE/DEAD, trigger `cargo xtask review <TYPE> <PR_URL>`. Stage-2 demotion (TCK-00419): projection-only by default; direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check`/`apm2 fac work status` for authoritative lifecycle state."
        - id: ESCALATE_IF_REVIEWS_NOT_RUNNING
          action: "If state empty AND pending, escalate to implementer. `cargo xtask push --force-review`. Stage-2 demotion (TCK-00419): projection-only by default; direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check`/`apm2 fac work status` for authoritative lifecycle state."
        - id: LOOP_UNTIL_RESOLVED
          action: "Remediate until reviews finish."
      decisions[2]:
        - id: BACK_TO_MONITOR
          if: "reviews finished OR remediation attempted"
          then:
            next_reference: references/dispatch-and-monitor-ticket.md
        - id: STOP_ON_FAILURE
          if: "SLA breached AND remediation failed"
          then:
            next_reference: references/stop-blocked-review-sla.md
