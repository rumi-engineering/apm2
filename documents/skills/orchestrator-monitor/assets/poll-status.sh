#!/usr/bin/env bash
# poll-status.sh — Comprehensive PR orchestration status dashboard
# Usage: bash poll-status.sh [PR_NUMBERS...]
# Example: bash poll-status.sh 433 434 435 437
# If no PR numbers given, auto-discovers open PRs on current repo.
set -euo pipefail

REPO="rumi-engineering/apm2"
SCRATCHPAD="${SCRATCHPAD:-/tmp/claude-1000/-home-ubuntu-Projects-apm2/*/scratchpad}"

# Resolve scratchpad glob to actual path
SCRATCHPAD_DIR=$(echo $SCRATCHPAD)
if [[ ! -d "$SCRATCHPAD_DIR" ]]; then
  SCRATCHPAD_DIR=""
fi

# --- Color helpers (disabled if not a tty) ---
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
else
  GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''; BOLD=''
fi

# --- Determine which PRs to check ---
if [[ $# -gt 0 ]]; then
  PRS=("$@")
else
  mapfile -t PRS < <(gh pr list --repo "$REPO" --state open --json number --jq '.[].number' 2>/dev/null | sort -n)
fi

if [[ ${#PRS[@]} -eq 0 ]]; then
  echo "No open PRs found."
  exit 0
fi

echo -e "${BOLD}=== Orchestration Status Dashboard ===${NC}"
echo -e "Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo -e "PRs: ${PRS[*]}"
echo ""

# --- Section 1: PR Overview ---
echo -e "${BOLD}--- PR Status ---${NC}"
printf "%-6s %-10s %-10s %-12s %-40s\n" "PR" "State" "Mergeable" "CI" "HEAD"

for pr in "${PRS[@]}"; do
  json=$(gh pr view "$pr" --repo "$REPO" --json headRefOid,state,mergeable,statusCheckRollup 2>/dev/null || echo '{}')
  head=$(echo "$json" | jq -r '.headRefOid // "unknown"')
  state=$(echo "$json" | jq -r '.state // "?"')
  mergeable=$(echo "$json" | jq -r '.mergeable // "?"')

  # Count CI failures
  ci_fail=$(echo "$json" | jq '[.statusCheckRollup // [] | .[] | select(.conclusion == "FAILURE")] | length')
  ci_pending=$(echo "$json" | jq '[.statusCheckRollup // [] | .[] | select(.conclusion == "")] | length')

  if [[ "$state" == "MERGED" ]]; then
    ci_str="${GREEN}MERGED${NC}"
  elif [[ "$ci_fail" -gt 0 ]]; then
    ci_str="${RED}FAIL($ci_fail)${NC}"
  elif [[ "$ci_pending" -gt 0 ]]; then
    ci_str="${YELLOW}PENDING($ci_pending)${NC}"
  else
    ci_str="${GREEN}PASS${NC}"
  fi

  printf "%-6s %-10s %-10s " "#$pr" "$state" "$mergeable"
  echo -en "$ci_str"
  # Pad to reach HEAD column
  printf "%*s" $((12 - ${#ci_fail} - ${#ci_pending} - 4)) ""
  echo -e " ${head:0:12}"
done

echo ""

# --- Section 2: AI Review Statuses ---
echo -e "${BOLD}--- AI Review Statuses ---${NC}"
printf "%-6s %-22s %-10s %s\n" "PR" "Review" "State" "Description"

for pr in "${PRS[@]}"; do
  head=$(gh pr view "$pr" --repo "$REPO" --json headRefOid --jq '.headRefOid' 2>/dev/null)
  state=$(gh pr view "$pr" --repo "$REPO" --json state --jq '.state' 2>/dev/null)
  [[ "$state" == "MERGED" ]] && { printf "%-6s %s\n" "#$pr" "(merged)"; continue; }

  reviews=$(gh api "repos/$REPO/commits/$head/status" --jq '.statuses[] | select(.context | startswith("ai-review/")) | "\(.context)|\(.state)|\(.description)"' 2>/dev/null || true)

  if [[ -z "$reviews" ]]; then
    printf "%-6s %s\n" "#$pr" "(no reviews posted)"
  else
    while IFS='|' read -r ctx st desc; do
      review_name="${ctx#ai-review/}"
      if [[ "$st" == "success" ]]; then
        st_color="${GREEN}$st${NC}"
      else
        st_color="${RED}$st${NC}"
      fi
      printf "%-6s %-22s " "#$pr" "$review_name"
      echo -en "$st_color"
      printf "%*s" $((10 - ${#st})) ""
      echo " $desc"
    done <<< "$reviews"
  fi
done

echo ""

# --- Section 3: Latest PR Comments (last 2 per PR) ---
echo -e "${BOLD}--- Latest Comments (last 2 per PR) ---${NC}"
for pr in "${PRS[@]}"; do
  state=$(gh pr view "$pr" --repo "$REPO" --json state --jq '.state' 2>/dev/null)
  [[ "$state" == "MERGED" ]] && continue

  echo -e "${CYAN}PR #$pr:${NC}"
  gh api "repos/$REPO/issues/$pr/comments" --jq '.[(-2):] | .[] | "  [\(.created_at | split("T") | .[1] | split("Z") | .[0])] \(.user.login): \(.body | split("\n") | .[0] | .[0:120])"' 2>/dev/null || echo "  (no comments)"
done

echo ""

# --- Section 4: Running Codex Review Processes ---
echo -e "${BOLD}--- Running Codex Processes ---${NC}"
codex_procs=$(ps aux | grep 'codex exec' | grep -v grep | grep -v rfc || true)
if [[ -z "$codex_procs" ]]; then
  echo "(none)"
else
  echo "$codex_procs" | while read -r line; do
    pid=$(echo "$line" | awk '{print $2}')
    start=$(echo "$line" | awk '{print $9}')
    echo "  PID $pid (started $start)"
  done
fi

echo ""

# --- Section 5: Review Output Log Progress ---
if [[ -n "$SCRATCHPAD_DIR" ]]; then
  echo -e "${BOLD}--- Review Output Logs ---${NC}"
  for logfile in "$SCRATCHPAD_DIR"/*_output.log; do
    [[ -f "$logfile" ]] || continue
    basename=$(basename "$logfile")
    lines=$(wc -l < "$logfile" 2>/dev/null || echo 0)
    size=$(stat --printf="%s" "$logfile" 2>/dev/null || echo 0)

    # Check if process is still writing (file modified in last 30s)
    mod_age=$(( $(date +%s) - $(stat --printf="%Y" "$logfile" 2>/dev/null || echo 0) ))
    if [[ $mod_age -lt 30 ]]; then
      status="${YELLOW}ACTIVE${NC}"
    elif [[ $lines -gt 0 ]]; then
      status="${GREEN}DONE${NC}"
    else
      status="EMPTY"
    fi

    printf "  %-45s %6d lines  " "$basename" "$lines"
    echo -e "$status"
  done
fi

echo ""

# --- Section 6: Background Claude Agents ---
echo -e "${BOLD}--- Background Claude Agents ---${NC}"
agent_dir="/tmp/claude-1000/-home-ubuntu-Projects-apm2/tasks"
if [[ -d "$agent_dir" ]]; then
  for outfile in "$agent_dir"/a*.output; do
    [[ -f "$outfile" ]] || continue
    agent_id=$(basename "$outfile" .output)
    lines=$(wc -l < "$outfile" 2>/dev/null || echo 0)
    mod_age=$(( $(date +%s) - $(stat --printf="%Y" "$outfile" 2>/dev/null || echo 0) ))

    if [[ $mod_age -lt 60 ]]; then
      status="${YELLOW}ACTIVE${NC}"
    else
      status="${GREEN}IDLE${NC}"
    fi

    printf "  Agent %-10s %6d lines  " "$agent_id" "$lines"
    echo -e "$status (last write ${mod_age}s ago)"
  done
else
  echo "(no agent output directory)"
fi

echo ""
echo -e "${BOLD}=== End Dashboard ===${NC}"
