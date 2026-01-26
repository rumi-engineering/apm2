title: Human Docs Update Command Reference

commands[13]:
  - name: check-git-state
    command: "git status --porcelain"
    purpose: "Show all uncommitted changes in machine-readable format."

  - name: check-branch
    command: "git branch --show-current"
    purpose: "Show current branch name."

  - name: create-feature-branch
    command: "git checkout -b <branch-name>"
    purpose: "Create and switch to a new feature branch."

  - name: run-precommit
    command: "pre-commit run --all-files"
    purpose: "Run all pre-commit hooks (formatting, linting, etc.)."

  - name: stage-files
    command: "git add <file1> <file2> ..."
    purpose: "Stage specific files for commit. Prefer explicit paths over -A."

  - name: commit-conventional
    command: "git commit -m \"<type>: <description>\""
    purpose: "Create a conventional commit."

  - name: sync-with-main
    command: "git fetch origin main && git rebase origin/main"
    purpose: "Fetch latest main and rebase current branch on it."

  - name: push-branch
    command: "git push -u origin <branch-name> --force-with-lease"
    purpose: "Push the current branch to origin with tracking, using force-with-lease to safely handle rebased history."

  - name: create-pr
    command: "gh pr create --title \"<title>\" --body \"<summary>\""
    purpose: "Create a pull request using GitHub CLI."

  - name: review-quality
    command: "cargo xtask review quality <PR_URL>"
    purpose: "Request an AI code quality review for the PR."

  - name: review-security
    command: "cargo xtask review security <PR_URL>"
    purpose: "Request an AI security review for the PR."

  - name: enable-auto-merge
    command: "gh pr merge --auto --squash"
    purpose: "Enable squash auto-merge for the current PR."

  - name: get-pr-url
    command: "gh pr view --json url -q .url"
    purpose: "Get the URL of the current PR."
