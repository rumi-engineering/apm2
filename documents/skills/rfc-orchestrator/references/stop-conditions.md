title: RFC Orchestrator — Stop Conditions

decision_tree:
  entrypoint: STOP_CONDITIONS_INDEX
  nodes[2]:
    - id: STOP_CONDITIONS_INDEX
      purpose: "Index of stop conditions. Only STOP_ALL_MERGED is a true stop — all other conditions are recoverable."
      true_stop_conditions[1]:
        - STOP_ALL_MERGED
      recoverable_conditions[4]:
        - "Location invariant violation → auto-recover via cd and git checkout"
        - "Auth failure → wait and retry"
        - "Dirty main → auto-stash and continue"
        - "All tickets blocked → wait for dependencies to merge"
      note: "The orchestrator should NEVER stop except when all tickets are merged. All other conditions are recoverable. There is NO iteration limit — 20+ rounds of implementer/reviewer iteration is normal and expected."

    - id: STOP_ALL_MERGED
      purpose: "SUCCESS — all tickets for TARGET_RFC have merged PRs. This is the ONLY true stop condition."
      detection:
        commands[3]:
          - id: LIST_ALL
            command: "rg -l 'rfc_id: \"<TARGET_RFC>\"' documents/work/tickets/ | rg -o 'TCK-[0-9]{5}' | sort"
          - id: LIST_MERGED
            command: "gh pr list --state merged --limit 100 --json headRefName --jq '.[].headRefName' | rg -o 'TCK-[0-9]{5}' | sort -u"
          - id: COMPUTE_REMAINING
            command: "comm -23 <(echo \"$all_tcks\") <(echo \"$merged_tcks\")"
        condition: "remaining is empty"
      actions[4]:
        - id: OUTPUT_LEDGER
          action: "Output MergeLedger: list of merged tickets with PR numbers"
        - id: CLEANUP
          command: "pkill -f gemini || true"
          purpose: "Cleanup orphaned reviewer agent processes"
        - id: OUTPUT_SUCCESS
          action: "Output: RFC <TARGET_RFC> complete. All tickets merged."
        - id: TERMINATE
          action: "STOP"

recoverable_states[4]:
  - id: LOCATION_VIOLATION
    description: "Orchestrator found itself in wrong directory or on wrong branch."
    recovery: "Auto-recover: cd to correct directory, git checkout main."
    see: "orchestrator-loop.md#CHECK_LOCATION"

  - id: AUTH_FAILURE
    description: "GitHub authentication failed or timed out."
    recovery: "Wait 60 seconds and retry. After 3 consecutive failures, wait 5 minutes and continue retrying indefinitely."
    see: "orchestrator-loop.md#CHECK_AUTH"

  - id: DIRTY_MAIN
    description: "Main repository has uncommitted changes."
    recovery: "Auto-stash changes with git stash --include-untracked and continue orchestration."
    see: "orchestrator-loop.md#CHECK_DIRTY"

  - id: ALL_BLOCKED
    description: "No unblocked tickets available — all remaining tickets are blocked by unmerged dependencies."
    recovery: "Wait and monitor. Blocked tickets become unblocked when their dependencies merge. Log blocker report for visibility."
    note: "This is NOT a stop condition. The orchestrator should continue monitoring open PRs and waiting for merges."

iteration_philosophy:
  note: "There is NO budget or limit on iterations. The orchestrator keeps dispatching implementers and triggering reviews until each ticket meets the quality bar and merges. 20+ rounds of iteration is normal and expected for high-quality code."
