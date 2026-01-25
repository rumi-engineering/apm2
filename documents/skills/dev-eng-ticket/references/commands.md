title: Dev Ticket Command Reference

commands[12]:
  - name: start-ticket-default
    command: "cargo xtask start-ticket"
    purpose: "Setup dev environment for next unblocked ticket."
  - name: start-ticket-rfc
    command: "cargo xtask start-ticket RFC-XXXX"
    purpose: "Setup dev environment for next unblocked ticket in RFC."
  - name: start-ticket-ticket
    command: "cargo xtask start-ticket TCK-XXXXX"
    purpose: "Setup dev environment for a specific ticket."
  - name: start-ticket-print-path
    command: "cargo xtask start-ticket [target] --print-path"
    purpose: "Output only worktree path (use for cd)."
  - name: commit
    command: "cargo xtask commit \"<message>\""
    purpose: "Verify, sync with main, and commit."
  - name: push
    command: "cargo xtask push"
    purpose: "Push, create/update PR, run AI reviews, enable auto-merge."
  - name: push-force-review
    command: "cargo xtask push --force-review"
    purpose: "Force re-run reviews after addressing feedback."
  - name: check
    command: "timeout 30s cargo xtask check"
    purpose: "Check CI/review status and get next action."
  - name: check-watch
    command: "timeout 30s cargo xtask check --watch | tail -40"
    purpose: "Poll status continuously; show last 40 lines."
  - name: finish
    command: "cargo xtask finish"
    purpose: "Cleanup worktree and branch after PR merges."
  - name: security-review-approve
    command: "cargo xtask security-review-exec approve [TCK-XXXXX]"
    purpose: "Approve PR after security review."
  - name: security-review-deny
    command: "cargo xtask security-review-exec deny [TCK-XXXXX] --reason <reason>"
    purpose: "Deny PR with a reason after security review."
