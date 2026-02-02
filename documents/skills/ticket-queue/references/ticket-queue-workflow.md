title: Ticket Queue — Primary Decision Tree

decision_tree:
  entrypoint: INIT
  nodes[1]:
    - id: INIT
      purpose: "Initialize orchestration posture, then loop until all tickets are merged."
      context_files[3]:
        - path: documents/README.md
        - path: documents/skills/README.md
          purpose: "Root-level module index, repository-wide constraints, and canonical dev workflow."
        - path: documents/skills/ticket/SKILL.md
          purpose: "Instructions to be passed to the implementer subagent. The orchestrator MUST NOT execute this skill itself."
        - path: xtask/src/reviewer_state.rs
          purpose: "Reviewer state schema (PID + log file) and stale thresholds."
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace $1 with <START_TARGET_OPTIONAL> if you are filtering the initial selection. Default: empty (process all tickets)."
        - id: ESTABLISH_NO_EDIT_BOUNDARY
          action: "MUST NOT: edit files, implement fixes, commit, push. MUST: delegate all code changes to an implementer subagent and supervise only."
        - id: VERIFY_GH_AUTH
          action: command
          run: "timeout 30s gh auth status"
          capture_as: gh_auth_status
        - id: VERIFY_GIT_CLEAN
          action: command
          run: "git status --porcelain"
          capture_as: git_status_porcelain
        - id: VERIFY_CORE_TOOLS_PRESENT
          action: command
          run: "command -v cargo git gh rg timeout >/dev/null && echo OK"
          capture_as: core_tools_ok
        - id: OPERATIONAL_CONSTRAINTS
          action: |
            1) MAX_RUNTIME: Never allow a subagent to work continuously for >=15 minutes. Terminate and restart with warm handoff to prevent context rot.
            2) NO_WORKTREES: All work occurs in the primary clone. Use branch switching.
        - id: ENTER_QUEUE_LOOP
          action: "Invoke the queue loop and do not stop until stop conditions are satisfied."
      decisions[3]:
        - id: GH_NOT_AUTHED
          if: "gh_auth_status indicates not logged in or missing auth"
          then:
            next_reference: references/stop-blocked-gh-auth.md
        - id: DIRTY_REPO
          if: "git_status_porcelain is non-empty"
          then:
            next_reference: references/stop-blocked-dirty-worktree.md
        - id: LOOP
          if: "always"
          then:
            next_reference: references/ticket-queue-loop.md