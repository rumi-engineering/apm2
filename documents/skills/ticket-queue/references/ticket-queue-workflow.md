title: Ticket Queue — Decision Tree

decision_tree:
  entrypoint: INIT
  nodes[1]:
    - id: INIT
      purpose: "Initialize posture. Loop until merged."
      context_files[3]:
        - path: documents/README.md
        - path: documents/skills/README.md
        - path: documents/skills/ticket/SKILL.md
      steps[6]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace $1 with <TARGET_RFC>."
        - id: ESTABLISH_BOUNDARY
          action: "MUST NOT: edit files, manage branches, fix blocks. MUST: identify TCK-XXXXX, dispatch subagents."
        - id: VERIFY_GH
          action: command
          run: "timeout 30s gh auth status"
          capture_as: gh_auth_status
        - id: VERIFY_GIT
          action: command
          run: "git status --porcelain"
          capture_as: git_status_porcelain
        - id: OPERATIONAL_CONSTRAINTS
          action: |
            1) CADENCE: Check reviewer comments and activity every 60s.
            2) SKILL: Verify `/ticket` call in logs.
            3) RUNTIME: Restart subagents at 15m.
        - id: LOOP
          action: "Enter queue loop."
      decisions[3]:
        - id: AUTH_FAIL
          if: "gh_auth_status fail"
          then:
            next_reference: references/stop-blocked-gh-auth.md
        - id: DIRTY
          if: "git_status_porcelain non-empty"
          then:
            next_reference: references/stop-blocked-dirty-worktree.md
        - id: START
          if: "always"
          then:
            next_reference: references/ticket-queue-loop.md