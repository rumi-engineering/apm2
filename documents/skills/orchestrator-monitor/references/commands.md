title: Orchestrator Monitor Command Reference

purpose: "Exact commands for state polling and dispatch actions."

notes:
  - "NOTE_VARIABLE_SUBSTITUTION: references do not interpolate variables. Replace <...> placeholders before running commands."
  - "All commands that can hang should use timeout wrappers."
  - "Commands labeled side_effect=true modify external state."
  - "Use `apm2 fac push` as the canonical push workflow — it pushes, creates/updates the PR, enables auto-merge, and reviews auto-start via CI."
  - "Prefer FAC-native `apm2 fac review ...` commands for reviewer lifecycle state and `apm2 fac restart` for recovery operations."
  - "All GitHub interactions are available via `apm2 fac pr` subcommands — no direct `gh` usage required."
  - "Do NOT manually dispatch reviews after pushing — the Forge Admission Cycle CI workflow auto-dispatches them."

commands[17]:
  - name: resolve_repo_root
    command: "timeout 10s git rev-parse --show-toplevel"
    purpose: "Discover repository root."
    side_effect: false

  - name: auth_check
    command: "timeout 30s apm2 fac pr auth-check"
    purpose: "Verify GitHub auth before dispatch."
    side_effect: false

  - name: list_open_prs
    command: "timeout 30s apm2 fac pr list --state open --json number"
    purpose: "Discover open PR scope when user did not supply PR numbers."
    side_effect: false

  - name: fac_review_status
    command: "timeout 30s apm2 fac review status --pr <PR_NUMBER>"
    purpose: "Primary FAC-native lifecycle snapshot for reviewer state/events on one PR."
    side_effect: false

  - name: pr_state_json
    command: "timeout 30s apm2 fac pr view <PR_NUMBER> --json state,mergeable,headRefOid,isDraft,statusCheckRollup"
    purpose: "Fetch PR metadata (mergeable/state/head SHA)."
    side_effect: false

  - name: fac_review_project
    command: "timeout 30s apm2 fac review project --pr <PR_NUMBER> --head-sha <HEAD_SHA> --emit-errors"
    purpose: "Primary 1Hz FAC projection line with reviewer lifecycle states and terminal error hints."
    side_effect: false

  - name: commit_statuses
    command: "timeout 30s apm2 fac pr read-comments <PR_NUMBER>"
    purpose: "Cross-check projected status contexts on GitHub for exact HEAD SHA binding."
    side_effect: false

  - name: restart_fac_via_apm2
    command: "timeout 30s apm2 fac restart --pr <PR_NUMBER>"
    purpose: "Restart FAC review cycle from apm2 CLI."
    side_effect: true

  - name: fac_push
    command: "timeout 120s apm2 fac push --ticket <TICKET_YAML>"
    purpose: "Canonical push workflow: pushes branch, creates/updates PR from ticket YAML, enables auto-merge. Reviews auto-start via CI."
    side_effect: true

  - name: fac_review_tail
    command: "timeout 30s apm2 fac review tail --lines 30"
    purpose: "Tail FAC review NDJSON event stream for recent lifecycle events across all PRs."
    side_effect: false

  - name: fetch_full_review_comment_bodies
    command: "timeout 30s apm2 fac pr read-comments <PR_NUMBER>"
    purpose: "Fetch full review comment bodies for a PR."
    side_effect: false

  - name: enable_auto_merge
    command: "timeout 30s apm2 fac pr auto-merge <PR_NUMBER>"
    purpose: "Enable auto-merge after all merge gates pass."
    side_effect: true

  - name: refresh_main
    command: "timeout 60s git pull --ff-only origin main"
    purpose: "Refresh local main after merges before next dispatch wave."
    side_effect: true

  - name: list_review_processes
    command: "timeout 10s ps aux | rg '(codex exec|gemini -m|apm2 fac review)'"
    purpose: "Observe active FAC review process count for saturation/backpressure checks."
    side_effect: false

  - name: fetch_main
    command: "timeout 60s git fetch origin main"
    purpose: "Refresh local reference for latest main before fix-agent edits."
    side_effect: true

  - name: rebase_onto_main
    command: "timeout 120s git rebase origin/main"
    purpose: "Update branch to latest main with linear history before coding."
    side_effect: true

  - name: merge_main
    command: "timeout 120s git merge --no-edit origin/main"
    purpose: "Alternative to rebase when merge-based branch policy is required."
    side_effect: true

  - name: list_unmerged_conflicts
    command: "timeout 10s git diff --name-only --diff-filter=U"
    purpose: "Conservative conflict detector; expected to be empty before code changes."
    side_effect: false
