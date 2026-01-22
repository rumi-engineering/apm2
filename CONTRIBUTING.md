# Contributing to APM2

This guide defines the development workflow for AI agents contributing to APM2. It uses **trunk-based development** with **worktree isolation** to enable parallel, conflict-free contributions.

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AGENT WORKFLOW                               │
├─────────────────────────────────────────────────────────────────────┤
│  1. CLAIM    → Create branch, set up worktree                       │
│  2. DEVELOP  → Make changes in isolated worktree                    │
│  3. VERIFY   → Run full CI locally                                  │
│  4. SYNC     → Rebase on main, resolve conflicts                    │
│  5. PR       → Open PR, address review feedback                     │
│  6. MERGE    → Squash merge to main                                 │
│  7. CLEANUP  → Remove worktree and branch                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 1. Task Claiming and Worktree Setup

### Branch Naming Convention

```
<type>/<short-description>

Types: feat, fix, docs, refactor, test, perf, chore, ci
```

Examples:
- `feat/oauth-refresh-token`
- `fix/daemon-crash-on-startup`
- `refactor/credentials-module`

### Create Isolated Worktree

```bash
# From the main repository
cd /path/to/apm2

# Fetch latest main
git fetch origin main

# Create branch from latest main
git branch feat/my-feature origin/main

# Create worktree in separate directory
git worktree add ../apm2-feat-my-feature feat/my-feature

# Work in the isolated worktree
cd ../apm2-feat-my-feature
```

### Why Worktrees?

- **Isolation**: Each agent has its own working directory
- **No conflicts**: Agents don't interfere with each other's uncommitted changes
- **Easy cleanup**: Remove worktree without affecting other work
- **Parallel CI**: Each worktree can run its own test suite

---

## 2. Development Process

### Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**
| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code restructuring |
| `perf` | Performance improvement |
| `test` | Adding/updating tests |
| `build` | Build system changes |
| `ci` | CI configuration |
| `chore` | Maintenance tasks |

**Examples:**
```bash
git commit -m "feat(credentials): add OAuth token refresh"
git commit -m "fix(daemon): handle SIGTERM gracefully"
git commit -m "docs(readme): update installation instructions"
```

### Making Changes

1. **Small, focused commits** - Each commit should be a single logical change
2. **Keep PRs small** - Aim for <400 lines changed
3. **Test as you go** - Run relevant tests after each change

```bash
# Run tests for the crate you're modifying
cargo test -p apm2-core

# Quick format and lint check
cargo fmt --check
cargo clippy -- -D warnings
```

---

## 3. Local CI Verification

**Run the full CI suite before creating a PR.** This catches issues early and reduces review cycles.

### Required Checks

```bash
# Navigate to your worktree
cd /path/to/apm2-feat-my-feature

# 1. Format check
cargo fmt --all --check

# 2. Clippy lints (strict)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Build documentation (catches doc errors)
cargo doc --no-deps --document-private-items

# 4. Run all tests
cargo test --workspace --all-features

# 5. Dependency audit
cargo deny check

# 6. Security audit
cargo audit
```

### Quick CI Script

Create this alias or script for convenience:

```bash
#!/bin/bash
# ci-local.sh - Run full CI locally
set -e

echo "=== Format Check ==="
cargo fmt --all --check

echo "=== Clippy ==="
cargo clippy --all-targets --all-features -- -D warnings

echo "=== Documentation ==="
cargo doc --no-deps --document-private-items

echo "=== Tests ==="
cargo test --workspace --all-features

echo "=== Dependency Check ==="
cargo deny check

echo "=== Security Audit ==="
cargo audit

echo "=== All checks passed! ==="
```

### Handling CI Failures

| Failure | Resolution |
|---------|------------|
| Format errors | Run `cargo fmt --all` |
| Clippy warnings | Fix the lint or add `#[allow(...)]` with justification |
| Test failures | Debug and fix; don't skip tests |
| Doc errors | Fix documentation syntax |
| Audit failures | Update dependency or document exception |

---

## 4. Syncing with Main

### Before Creating PR

Always rebase on latest main to ensure clean merge:

```bash
# In your worktree
git fetch origin main

# Rebase your changes on top of latest main
git rebase origin/main

# If conflicts occur, resolve them:
# 1. Edit conflicted files
# 2. git add <resolved-files>
# 3. git rebase --continue

# Force push your rebased branch (safe for feature branches)
git push --force-with-lease origin feat/my-feature
```

### Conflict Resolution Guidelines

1. **Prefer main's version** for:
   - Dependency versions in Cargo.toml
   - CI configuration changes
   - Shared infrastructure code

2. **Prefer your version** for:
   - New code you're adding
   - Bug fixes (if main doesn't have them)

3. **Merge carefully** for:
   - Changes to the same function
   - Structural refactors

4. **Re-run CI** after resolving conflicts

---

## 5. Pull Request Process

### Creating the PR

```bash
# Push your branch
git push -u origin feat/my-feature

# Create PR via GitHub CLI
gh pr create \
  --title "feat(credentials): add OAuth token refresh" \
  --body "## Summary
- Implements OAuth token refresh before expiry
- Adds RefreshManager component
- Includes unit tests

## Test Plan
- [ ] Unit tests pass
- [ ] Manual test with expired token

## Checklist
- [x] Local CI passes
- [x] Documentation updated
- [x] Tests added"
```

### PR Requirements

- [ ] Title follows conventional commit format
- [ ] Description explains what and why
- [ ] All CI checks pass
- [ ] No merge conflicts with main
- [ ] Changes are focused and reviewable

### Addressing Review Feedback

```bash
# Make requested changes
# ... edit files ...

# Commit with descriptive message
git commit -m "fix(credentials): address review feedback

- Rename refresh_interval to refresh_before_expiry
- Add error handling for network failures"

# Push updates
git push origin feat/my-feature
```

---

## 6. Release Coordination

APM2 uses **release-plz** for automated release management. Agents do NOT manually bump versions or create releases.

### How It Works

1. **Merge to main** → release-plz analyzes commits
2. **Release PR created** → Bumps versions based on conventional commits
3. **Release PR merged** → Creates git tag
4. **Tag pushed** → Release workflow builds and publishes

### Version Bump Rules (Automatic)

| Commit Type | Version Bump |
|-------------|--------------|
| `feat` | Minor (0.x.0) |
| `fix`, `perf` | Patch (0.0.x) |
| `feat!`, `fix!` (breaking) | Major (x.0.0) |
| `docs`, `style`, `refactor`, `test`, `chore` | No bump |

### Agent Responsibilities

1. **Use correct commit types** - This determines version bumps
2. **Mark breaking changes** - Add `!` after type: `feat!: remove deprecated API`
3. **Don't modify versions** - Let release-plz handle Cargo.toml versions
4. **Don't create tags** - Release workflow handles this

### Breaking Changes

For breaking changes, include `BREAKING CHANGE:` in commit body:

```
feat!: redesign credentials API

BREAKING CHANGE: CredentialStore::get() now returns Result<Option<Credential>>
instead of Option<Credential>. Callers must handle the error case.

Migration: Replace `.get(key)` with `.get(key)?`
```

---

## 7. Worktree Cleanup

After PR is merged, clean up your worktree:

```bash
# From the main repository (not the worktree)
cd /path/to/apm2

# Remove the worktree
git worktree remove ../apm2-feat-my-feature

# Delete the local branch
git branch -d feat/my-feature

# Prune remote-tracking branches
git fetch --prune
```

---

## 8. Multi-Agent Coordination

When multiple agents work in parallel:

### Branch Naming Includes Agent ID

```
<type>/<agent-id>-<short-description>

Example: feat/agent-7a3b-oauth-refresh
```

### Avoiding Conflicts

1. **Claim files** - Comment on issue with files you'll modify
2. **Check for overlapping PRs** - `gh pr list` before starting
3. **Coordinate large refactors** - Only one agent should do cross-cutting changes at a time

### Rebasing Over Others' Merged Work

```bash
# Another agent's PR was merged, your branch has conflicts
git fetch origin main
git rebase origin/main

# Resolve any conflicts from their changes
# Test that your changes still work with theirs
cargo test --workspace
```

---

## 9. Test Invariants and Time Budgets

All contributions must maintain the following test coverage and performance invariants.

### Coverage Requirements

| Metric | Minimum |
|--------|---------|
| Line coverage | 90% |
| Branch coverage | 90% |

Coverage is enforced in CI. PRs that reduce coverage below the threshold will fail.

### Time Budgets

Tests must complete within these time limits:

| Test Type | Local | CI |
|-----------|-------|-----|
| Unit tests | 30s | 60s |
| E2E tests | 60s | 3 min |
| Benchmarks | 60s | 5 min |

**Notes:**
- Benchmarks run in parallel with other CI workflows
- Local times assume a modern development machine
- CI times account for shared runner variability

### Enforcement

```bash
# Run unit tests with timeout
timeout 30s cargo test --lib

# Run E2E tests with timeout
timeout 60s cargo test --test '*'

# Run benchmarks (parallel in CI)
timeout 60s cargo bench --no-run  # Local validation
```

### When Tests Exceed Budgets

1. **Profile the slow tests** - Use `cargo test -- --nocapture` to identify bottlenecks
2. **Consider test isolation** - Move slow tests to integration test files
3. **Optimize or split** - Large tests may need refactoring
4. **Document exceptions** - If a test legitimately needs more time, document why

---

## 10. Quick Reference

### Common Commands

```bash
# Setup
git worktree add ../apm2-<branch> <branch>

# Development
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test -p <crate>

# Sync
git fetch origin main
git rebase origin/main
git push --force-with-lease

# PR
gh pr create
gh pr view
gh pr checks

# Cleanup
git worktree remove ../apm2-<branch>
git branch -d <branch>
```

### CI Workflow Files

| Workflow | Runs On | Purpose |
|----------|---------|---------|
| `ci.yml` | PR, push to main | Format, lint, test, audit |
| `release-plz.yml` | Push to main | Create release PRs |
| `release.yml` | Tag push | Build, sign, publish |
| `docs.yml` | Push to main | Deploy documentation |
| `miri.yml` | Weekly, push | Undefined behavior detection |
| `fuzz.yml` | Weekly | Fuzzing for crashes |

### Security Documentation

See `/documents/security/` for:
- `RELEASE_PROCEDURE.md` - Full release checklist
- `SIGNING_AND_VERIFICATION.md` - Artifact verification
- `CI_SECURITY_GATES.md` - Required CI checks
