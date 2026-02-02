title: Ticket Queue — Command Reference

commands[22]:
  - name: list-recent-prs
    command: "gh pr list --state all --limit 20 --json number,title,headRefName,updatedAt,state --jq 'map(select(.state == "MERGED" or .state == "OPEN")) | sort_by(.updatedAt) | reverse | .[0:10] | .[] | "\(.updatedAt) \(.state) \(.headRefName) \(.title)"'
    purpose: "List 10 modified OPEN/MERGED PRs."
  - name: list-ticket-ids-for-rfc
    command: "rg -l 'rfc_id: \"<RFC_ID>\"' documents/work/tickets/ | rg -o \"TCK-[0-9]{5}\" | sort"
    purpose: "List ticket IDs associated with RFC."
  - name: find-high-water-mark
    command: "gh pr list --state merged --limit 20 --json headRefName --jq '.[].headRefName' | rg -o \"TCK-[0-9]{5}\" | sort -r | head -n 1"
    purpose: "Identify highest numeric ticket ID merged to main."
  - name: list-completed-ticket-ids
    command: "timeout 30s gh pr list --state merged --limit 100 --json headRefName --jq '.[].headRefName' | rg -o \"TCK-[0-9]{5}\" | sort -u"
    purpose: "List completed ticket IDs."
  - name: list-active-ticket-branch-ids
    command: "(git branch --list \"*ticket/*TCK-*"; git branch -r --list \"*ticket/*TCK-*") | rg -o \"TCK-[0-9]{5}\" | sort -u"
    purpose: "List ticket IDs with branches."
  - name: check-pr-status
    command: "gh pr view <BRANCH_NAME> --json state,reviewDecision,statusCheckRollup,comments --jq '\"State: \(.state)\nReview: \(.reviewDecision)\nChecks: \" + (if .statusCheckRollup == null then \"None\" else ([.statusCheckRollup[] | \"\(.name):\(.conclusion // .status)\"] | join(\", \")) end)'"
    purpose: "Show PR state, review, CI, comments."
  - name: check-ai-reviews
    command: "gh api repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/commits/$(gh pr view <BRANCH_NAME> --json headRefOid --jq .headRefOid)/status --jq '.statuses[] | select(.context | startswith(\"ai-review/\")) | \"\(.context): \(.state)\"'"
    purpose: "Query custom AI review statuses directly via GitHub API."
  - name: trigger-reviews
    command: "cargo xtask review security <PR_URL> & cargo xtask review quality <PR_URL> &"
    purpose: "Trigger AI reviews."
  - name: cleanup-branch
    command: "git checkout main && git pull && git branch -D <BRANCH_NAME>"
    purpose: "Delete ticket branch."
  - name: reviewer-state-path
    command: "printf \"%s\n\" \"$HOME/.apm2/reviewer_state.json\""
    purpose: "Path to reviewer state."
  - name: reviewer-state-show
    command: "python3 - <<'PY'\nimport json, os, time\nfrom pathlib import Path\np = Path.home()/'.apm2'/'reviewer_state.json'\nif p.exists():\n    print(json.dumps(json.loads(p.read_text()), indent=2, sort_keys=True))\nPY"
    purpose: "Print reviewer state."
  - name: reviewer-log-tail
    command: "tail -n 120 <LOG_FILE>"
    purpose: "Tail reviewer output."
  - name: reviewer-log-mtime
    command: "stat -c \"%y %n\" <LOG_FILE>"
    purpose: "Reviewer log mtime."
  - name: pid-inspect
    command: "ps -p <PID> -o pid=,etime=,cmd="
    purpose: "Inspect process status."
  - name: find-ai-pids
    command: "pgrep -fa \"(gemini|codex|claude)\" || true"
    purpose: "Find AI PIDs."
  - name: log-tail-tool-ish-lines
    command: "tail -n 300 <LOG_FILE> | rg -n \"tool|Tool|Bash\(|Read\(|Edit\(|Write\(|exec|command\" || true"
    purpose: "Extract tool lines from log."
  - name: implementer-log-mtime
    command: "stat -c \"%y %n\" <IMPLEMENTER_LOG_FILE>"
    purpose: "Implementer log mtime."
  - name: implementer-log-tail
    command: "tail -n 200 <IMPLEMENTER_LOG_FILE>"
    purpose: "Tail implementer log."
  - name: safe-kill-pid
    command: "bash -lc 'set -euo pipefail; ps -p <PID> -o pid=,cmd=; kill -TERM <PID>; sleep 5; kill -KILL <PID> 2>/dev/null || true'"
    purpose: "Terminate PID."
  - name: claude-history-tail
    command: "tail -n 200 \"$HOME/.claude/history.jsonl\""
    purpose: "Tail Claude history."
  - name: start-claude-implementer-with-log
    command: "bash -lc 'set -euo pipefail; mkdir -p \"$HOME/.apm2/ticket-queue/logs\"; log=\"$HOME/.apm2/ticket-queue/logs/<TICKET_ID>.implementer.log\"; script -q \"$log\" -c \"claude --agent rust-developer --verbose \\\"Follow ticket skill for <TICKET_ID>\\\"\" & echo \"PID=$! LOG=$log\"'"
    purpose: "Spawn Claude implementer. Execute /ticket."
  - name: check-ticket-unblocked
    command: |
      deps=$(rg "tickets:" -A 10 "documents/work/tickets/<TICKET_ID>.yaml" | grep -o "TCK-[0-9]{5}")
      if [ -z "$deps" ]; then echo "UNBLOCKED"; exit 0; fi
      merged=$(gh pr list --state merged --limit 100 --json headRefName --jq '.[].headRefName' | rg -o "TCK-[0-9]{5}")
      for d in $deps; do
        if ! echo "$merged" | grep -q "$d"; then echo "BLOCKED_BY_$d"; exit 1; fi
      done
      echo "UNBLOCKED"
    purpose: "Verify all ticket dependencies are merged to main."
    purpose: "List GitHub Actions runs."