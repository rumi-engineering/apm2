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

  - name: run-local-hooks
    command: ".cargo-husky/hooks/pre-commit"
    purpose: "Run all local pre-commit hooks (formatting, linting, etc.)."

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

---

## Usage Examples

### Complete Workflow

```bash
# 1. Check current state
git status --porcelain
git branch --show-current

# 2. Create feature branch if on main
git checkout -b docs/update-readme

# 3. Run local checks
.cargo-husky/hooks/pre-commit

# 4. Stage and commit
git add documents/README.md
git commit -m "docs: update README with new examples"

# 5. Sync with main (may rewrite history)
git fetch origin main && git rebase origin/main

# 6. Push with force-with-lease (safe after rebase)
git push -u origin docs/update-readme --force-with-lease

# 7. Create PR and request reviews
gh pr create --title "docs: update README" --body "Add new examples"
PR_URL=$(gh pr view --json url -q .url)
cargo xtask review quality "$PR_URL"
cargo xtask review security "$PR_URL"

# 8. Enable auto-merge
gh pr merge --auto --squash
```

### Why force-with-lease?

After rebasing on origin/main, your local branch has different commits than the remote. A regular `git push` will fail because the histories diverge. Options:

| Command | Safety | Use Case |
|---------|--------|----------|
| `git push --force` | ❌ Dangerous | Never use - overwrites without checking |
| `git push --force-with-lease` | ✅ Safe | Use after rebase - fails if remote changed |
| `git push` | ✅ Safe | Only works if no rebase occurred |

`--force-with-lease` is the safe choice because it will fail if someone else pushed to your branch since you last fetched, preventing accidental overwrites.
