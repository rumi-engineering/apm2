title: Dev Ticket Command Reference

commands[16]:
  - name: find-worktree
    command: "git worktree list | grep <TICKET_ID>"
    purpose: "Find the worktree for your assigned ticket."
  - name: enter-worktree
    command: "cd $(git worktree list | grep <TICKET_ID> | awk '{print $1}')"
    purpose: "Enter the worktree for your assigned ticket."
  - name: create-worktree
    command: "git worktree add /home/ubuntu/Projects/apm2-<TICKET_ID> -b ticket/<RFC_ID>/<TICKET_ID>"
    purpose: "Create a new worktree and branch for a ticket."
  - name: format
    command: "cargo fmt --all --check"
    purpose: "Verify formatting across all workspace members before committing."
  - name: lint
    command: "cargo clippy --fix --allow-dirty --all-targets --all-features -- -D warnings"
    purpose: "Fix linting issues and enforce quality standards before committing."
  - name: commit
    command: "cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings && git add -A && git commit -m \"<message>\""
    purpose: "Format, lint, and commit changes."
  - name: push
    command: "apm2 fac push"
    purpose: "Push, create/update PR, run AI reviews, enable auto-merge."
  - name: gate-status
    command: "gh api repos/guardian-intelligence/apm2/commits/<HEAD_SHA>/status --jq '.statuses[] | select(.context == \"Review Gate Success\") | \"\\(.context)=\\(.state): \\(.description)\"'"
    purpose: "Inspect required merge-gate status context bound to the exact commit SHA."
  - name: fac-status
    command: "apm2 fac review status --pr <PR_NUMBER>"
    purpose: "Primary FAC-local reviewer lifecycle view (active runs, recent NDJSON events, pulse files)."
  - name: fac-project
    command: "apm2 fac review project --pr <PR_NUMBER> --head-sha <HEAD_SHA> --emit-errors"
    purpose: "Primary FAC projection snapshot for one-line health plus structured ERROR lines."
  - name: fac-retrigger-cli
    command: "apm2 fac review retrigger --repo guardian-intelligence/apm2 --pr <PR_NUMBER>"
    purpose: "Projection-native retrigger path: dispatch Forge Admission Cycle workflow from apm2 CLI."
  - name: fac-rerun-all
    command: "gh workflow run forge-admission-cycle.yml --repo guardian-intelligence/apm2 -f pr_number=<PR_NUMBER>"
    purpose: "Fallback: retrigger Forge Admission Cycle for a PR."
  - name: fetch-latest-feedback
    command: "gh pr view <PR_URL> --json reviews,reviewThreads --jq '{latest_review: (.reviews[-1].body // \"N/A\"), unresolved_threads: [.reviewThreads[]? | select(.isResolved == false) | {path: .path, body: .comments[-1].body}]}'"
    purpose: "Get full review/comment bodies from GitHub (fallback surface until FAC projection exposes full comment text)."
  - name: finish
    command: "git worktree remove <WORKTREE_PATH>"
    purpose: "Cleanup worktree after PR merges."
  - name: dispatch-reviews
    command: "apm2 fac review dispatch <PR_URL> --type all"
    purpose: "Dispatch AI security and quality reviews for a PR."
  - name: fac-dispatch-review
    command: "apm2 fac review dispatch <PR_URL> --type <security|quality>"
    purpose: "Dispatch a specific type of AI review for a PR."
