title: Post-Merge Cleanup

steps[2]:
  - id: FINISH_WORKTREE
    action: command
    run: "git worktree remove <WORKTREE_PATH>"
  - id: CONTINUE
    action: "If more tickets remain, return to the main workflow and find the next worktree."
