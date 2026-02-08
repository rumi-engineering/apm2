title: RFC Orchestrator — Command Reference

## Ticket Discovery

```yaml
list-tickets-for-rfc:
  command: rg -l 'rfc_id: "<RFC_ID>"' documents/work/tickets/ | rg -o "TCK-[0-9]{5}" | sort
  purpose: List all ticket IDs for an RFC

list-merged-tickets:
  command: gh pr list --state merged --limit 100 --json headRefName --jq '.[].headRefName' | rg -o "TCK-[0-9]{5}" | sort -u
  purpose: List ticket IDs with merged PRs

list-open-ticket-prs:
  command: gh pr list --state open --json headRefName,number --jq '.[] | select(.headRefName | test("TCK-[0-9]{5}")) | "\(.headRefName) #\(.number)"'
  purpose: List open PRs for tickets

read-ticket-deps:
  command: rg "tickets:" -A 10 "documents/work/tickets/<TICKET_ID>.yaml" | grep -o "TCK-[0-9]\{5\}" || true
  purpose: Extract ticket dependencies
```

## Worktree Management

```yaml
list-worktrees:
  command: git worktree list
  purpose: Show all worktrees

create-worktree:
  command: git worktree add ~/.apm2/worktrees/<TICKET_ID> -b ticket/<TICKET_ID>
  purpose: Create worktree for ticket

update-worktree:
  command: git -C ~/.apm2/worktrees/<TICKET_ID> fetch origin && git -C ~/.apm2/worktrees/<TICKET_ID> rebase origin/main
  purpose: Sync worktree with main

remove-worktree:
  command: git worktree remove ~/.apm2/worktrees/<TICKET_ID> --force
  purpose: Clean up worktree after merge
```

## PR Status

```yaml
pr-status:
  command: gh pr view <BRANCH_NAME> --json state,reviewDecision,statusCheckRollup,comments,headRefOid,url
  purpose: Full PR status including comments

pr-state-only:
  command: gh pr view <BRANCH_NAME> --json state --jq .state
  purpose: Quick state check (OPEN/MERGED/CLOSED)

pr-checks:
  command: gh pr view <BRANCH_NAME> --json statusCheckRollup --jq '.statusCheckRollup[] | "\(.name): \(.conclusion // .status)"'
  purpose: CI check results

pr-comments-count:
  command: gh pr view <BRANCH_NAME> --json comments --jq '.comments | length'
  purpose: Number of PR comments
```

## AI Reviews

```yaml
check-review-gate-status:
  command: |
    head_sha=$(gh pr view <BRANCH_NAME> --json headRefOid --jq .headRefOid)
    gh api repos/$(gh repo view --json nameWithOwner -q .nameWithOwner)/commits/$head_sha/status \
      --jq '.statuses[] | select(.context == "Review Gate Success") | "\(.context): \(.state)"'
  purpose: Check Review Gate Success commit status

trigger-security-review:
  command: cargo xtask review security <PR_URL>
  note: "Stage-2 demotion (TCK-00419): projection-only by default. Direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check`/`apm2 fac work status` for authoritative lifecycle and gate state."
  purpose: Run security review (SYNCHRONOUS - no &)

trigger-quality-review:
  command: cargo xtask review quality <PR_URL>
  note: "Stage-2 demotion (TCK-00419): projection-only by default. Direct writes require XTASK_CUTOVER_POLICY=legacy. Prefer `apm2 fac check`/`apm2 fac work status` for authoritative lifecycle and gate state."
  purpose: Run quality review (SYNCHRONOUS - no &)
```

## Process Management

```yaml
find-reviewer-processes:
  command: pgrep -fa gemini || true
  purpose: Find all running reviewer agent processes

kill-reviewer-for-pr:
  command: pkill -f "gemini.*<PR_URL>" || true
  purpose: Kill reviewer agent processes for specific PR

kill-all-reviewers:
  command: pkill -f gemini || true
  purpose: Kill all reviewer agent processes (use after all PRs merged)

check-claude-processes:
  command: pgrep -fa claude || true
  purpose: Find Claude processes (for debugging)
```

## Main Repo Safety

```yaml
verify-main-clean:
  command: git -C . status --porcelain
  purpose: Ensure main repo has no uncommitted changes

verify-on-main:
  command: git -C . branch --show-current
  purpose: Confirm on main branch

pull-main:
  command: git -C . pull --ff-only origin main
  purpose: Fast-forward main to latest
```

## Subagent Management

```yaml
dispatch-fix-agent:
  tool: Task
  parameters:
    subagent_type: general-purpose
    model: opus
    description: "Fix <TICKET_ID>: <REASON>"
    prompt: |
      Working directory: ~/.apm2/worktrees/<TICKET_ID>
      Task: /ticket <TICKET_ID>
      Context: <REASON>
    run_in_background: false
  purpose: Dispatch synchronous fix agent

check-subagent-output:
  tool: TaskOutput
  parameters:
    task_id: "<TASK_ID>"
    block: false
    timeout: 5000
  purpose: Check subagent progress (non-blocking)
```
