title: Orchestrator Monitor Command Reference

purpose: "Exact commands for state polling and dispatch actions."

notes:
  - "NOTE_VARIABLE_SUBSTITUTION: references do not interpolate variables. Replace <...> placeholders before running commands."
  - "All commands that can hang should use timeout wrappers."
  - "Commands labeled side_effect=true modify external state."

commands[17]:
  - name: resolve_repo_root
    command: "timeout 10s git rev-parse --show-toplevel"
    purpose: "Discover repository root for asset invocation."
    side_effect: false

  - name: auth_check
    command: "timeout 30s gh auth status"
    purpose: "Verify GitHub auth before dispatch."
    side_effect: false

  - name: list_open_prs
    command: "timeout 30s gh pr list --repo guardian-intelligence/apm2 --state open --json number --jq '.[].number'"
    purpose: "Discover open PR scope when user did not supply PR numbers."
    side_effect: false

  - name: poll_dashboard
    command: "timeout 90s bash <ROOT>/documents/skills/orchestrator-monitor/assets/poll-status.sh <PRS...>"
    purpose: "Generate human-readable status dashboard snapshot."
    side_effect: false

  - name: pr_state_json
    command: "timeout 30s gh pr view <PR_NUMBER> --repo guardian-intelligence/apm2 --json state,mergeable,headRefOid,isDraft,statusCheckRollup"
    purpose: "Fetch machine-readable PR state and CI rollup."
    side_effect: false

  - name: commit_statuses
    command: "timeout 30s gh api repos/guardian-intelligence/apm2/commits/<HEAD_SHA>/status"
    purpose: "Fetch Forge Admission Cycle status context for exact HEAD SHA binding."
    side_effect: false

  - name: retrigger_fac_via_apm2
    command: "timeout 30s apm2 fac review retrigger --repo guardian-intelligence/apm2 --pr <PR_NUMBER>"
    purpose: "Projection-native FAC retrigger path that dispatches Forge Admission Cycle from apm2 CLI."
    side_effect: true

  - name: launch_reviews
    command: "timeout 900s bash <ROOT>/documents/skills/orchestrator-monitor/assets/launch-reviews.sh <PR_NUMBER|PR_URL> [SCRATCHPAD_DIR]"
    purpose: "Launch FAC review dispatch (`apm2 fac review dispatch ... --type all`) and project 1Hz status via `apm2 fac review project`."
    side_effect: true

  - name: retrigger_review_stream
    command: "timeout 30s gh workflow run forge-admission-cycle.yml --repo guardian-intelligence/apm2 -f pr_number=<PR_NUMBER>"
    purpose: "Manual recovery path: retrigger Forge Admission Cycle for current PR head SHA."
    side_effect: true

  - name: check_review_progress
    command: "timeout 30s bash <ROOT>/documents/skills/orchestrator-monitor/assets/check-review.sh [PR_NUMBER|PR_URL]"
    purpose: "Read FAC review state/events/pulse files and print structured review progress."
    side_effect: false

  - name: enable_auto_merge
    command: "timeout 30s gh pr merge <PR_NUMBER> --repo guardian-intelligence/apm2 --auto --squash --delete-branch"
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
