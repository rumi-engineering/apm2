title: Orchestrator Scaling Profiles (1-20 PRs)

purpose: "Define bounded concurrency, polling cadence, and anti-stall thresholds by scope size."

profile_selection:
  rule: "Pick profile by count of scoped open PRs at loop start; re-evaluate every tick."
  fail_closed: "If PR count is 0 or >20, stop with explicit reason and no dispatch side effects."

profiles[4]:
  - id: P1_SMALL
    pr_range: "1..2"
    heartbeat_seconds: 45
    max_implementors: 1
    max_review_batches: 1
    max_actions_per_tick: 1
    agent_idle_threshold_seconds: 240
    review_launch_policy: "Launch reviews once CI is at least pending and HEAD is unchanged for one tick."

  - id: P2_MEDIUM
    pr_range: "3..6"
    heartbeat_seconds: 30
    max_implementors: 2
    max_review_batches: 2
    max_actions_per_tick: 2
    agent_idle_threshold_seconds: 180
    review_launch_policy: "Launch reviews when CI is pending/pass and queue has review slots."

  - id: P3_LARGE
    pr_range: "7..12"
    heartbeat_seconds: 30
    max_implementors: 3
    max_review_batches: 3
    max_actions_per_tick: 3
    agent_idle_threshold_seconds: 150
    review_launch_policy: "Prioritize CI-pass PRs for review launch to avoid stale SHA churn."

  - id: P4_MAX
    pr_range: "13..20"
    heartbeat_seconds: 20
    max_implementors: 4
    max_review_batches: 4
    max_actions_per_tick: 4
    agent_idle_threshold_seconds: 120
    review_launch_policy: "Review launch only for CI-pass or conflict-free high-priority PRs to cap process fanout."

backpressure_rules[4]:
  - id: BP01_REVIEW_QUEUE
    condition: "queued_review_count > (2 * max_review_batches)"
    action: "Suspend launching new implementor agents until queued_review_count drops."

  - id: BP02_FAIL_SPIKE
    condition: "ci_failure_ratio_over_last_3_ticks >= 0.4"
    action: "Freeze net-new work; dispatch fixes only until failure ratio recovers."

  - id: BP03_STALE_SHA
    condition: "review started on SHA_X and current HEAD != SHA_X"
    action: "Mark review stale, stop trusting result, and requeue review for current HEAD."

  - id: BP04_SATURATION_GUARD
    condition: "active_codex_review_processes > (2 * max_review_batches + 2)"
    action: "Do not launch additional reviews this tick."

priority_order[7]:
  - "READY_TO_MERGE"
  - "PR_CONFLICTING"
  - "CI_FAILED"
  - "REVIEW_FAILED"
  - "REVIEW_MISSING"
  - "WAITING_CI"
  - "BLOCKED_UNKNOWN"

anti_goodhart_metrics:
  primary:
    - "merged_prs_per_24h"
    - "median_time_open_to_merge_minutes"
  countermetrics:
    - "reopened_pr_count_7d"
    - "post_merge_rollback_count_7d"
    - "repeat_blocker_rate (same signature within 3 review rounds)"

stop_conditions:
  success: "All scoped PRs are MERGED."
  partial_stop: "All remaining PRs are BLOCKED_UNKNOWN for >=3 consecutive ticks with no admissible action."
  hard_stop: "PR scope >20, missing auth, or repository mismatch."
