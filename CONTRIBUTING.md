# Contributing to APM2

Development workflow for AI agents using **trunk-based development** with **worktree isolation**.

```
┌─────────────────────────────────────────────────────────────────────┐
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

## 1. Worktree Setup

### Branch Naming

```
<type>/<short-description>
Types: feat, fix, docs, refactor, test, perf, chore, ci
```

### Create Worktree

```bash
git fetch origin main
git branch feat/my-feature origin/main
git worktree add ../apm2-feat-my-feature feat/my-feature
cd ../apm2-feat-my-feature
```

Worktrees provide isolation, prevent conflicts between agents, and enable parallel CI runs.

---

## 2. Development

### Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | Minor |
| `fix` | Bug fix | Patch |
| `perf` | Performance | Patch |
| `docs` | Documentation | None |
| `refactor` | Restructuring | None |
| `test` | Tests | None |
| `chore` | Maintenance | None |
| `ci` | CI config | None |

**Breaking changes**: Add `!` after type and include `BREAKING CHANGE:` in body:

```bash
git commit -m "feat!: redesign credentials API

BREAKING CHANGE: CredentialStore::get() now returns Result<Option<Credential>>"
```

### Guidelines

- Small, focused commits (one logical change each)
- PRs under 400 lines changed
- Test as you go: `cargo test -p <crate>`

---

## 3. Local CI

Run before creating a PR:

```bash
cargo fmt --all --check                              # Format
cargo clippy --all-targets --all-features -- -D warnings  # Lint
cargo doc --no-deps --document-private-items         # Docs
cargo test --workspace --all-features                # Tests
cargo deny check                                     # Dependencies
cargo audit                                          # Security
```

| Failure | Fix |
|---------|-----|
| Format | `cargo fmt --all` |
| Clippy | Fix lint or add `#[allow(...)]` with justification |
| Tests | Debug and fix |
| Audit | Update dependency or document exception |

See [`documents/coding/SAFE_RUST_PATTERNS.md`](documents/coding/SAFE_RUST_PATTERNS.md) for safe Rust guidelines.

---

## 4. Sync with Main

```bash
git fetch origin main
git rebase origin/main
# Resolve conflicts if needed, then:
git push --force-with-lease origin feat/my-feature
```

**Conflict resolution**: Prefer main for dependency versions and CI config; prefer yours for new code.

---

## 5. Pull Request

```bash
git push -u origin feat/my-feature

gh pr create \
  --title "feat(credentials): add OAuth token refresh" \
  --body "## Summary
- Implements OAuth token refresh

## Test Plan
- [ ] Unit tests pass

## Checklist
- [x] Local CI passes"
```

### Requirements

- Title follows conventional commit format
- All CI checks pass
- No merge conflicts

---

## 6. Releases

APM2 uses **release-plz** for automated releases. Agents do not manually bump versions or create tags.

**Agent responsibilities:**
1. Use correct commit types (determines version bumps)
2. Mark breaking changes with `!` suffix
3. Do not modify `Cargo.toml` versions
4. Do not create git tags

For release details, see:
- [`documents/releases/README.md`](documents/releases/README.md) — Channel overview and artifacts
- [`documents/releases/RELEASE_CHANNELS.md`](documents/releases/RELEASE_CHANNELS.md) — Dev/Beta/Stable pipeline
- [`documents/security/RELEASE_PROCEDURE.md`](documents/security/RELEASE_PROCEDURE.md) — Full release checklist

---

## 7. Cleanup

After PR merge:

```bash
cd /path/to/apm2
git worktree remove ../apm2-feat-my-feature
git branch -d feat/my-feature
git fetch --prune
```

---

## 8. Multi-Agent Coordination

For parallel work, include agent ID in branch name:

```
feat/agent-7a3b-oauth-refresh
```

- Check `gh pr list` before starting
- Claim files by commenting on issues
- Only one agent handles cross-cutting refactors at a time

---

## 9. Test Invariants

| Metric | Minimum |
|--------|---------|
| Line coverage | 90% |
| Branch coverage | 90% |

### Time Budgets

| Test Type | Local | CI |
|-----------|-------|-----|
| Unit tests | 30s | 60s |
| E2E tests | 60s | 3 min |
| Benchmarks | 60s | 5 min |

```bash
timeout 30s cargo test --lib
timeout 60s cargo test --test '*'
```

---

## 10. Quick Reference

```bash
# Setup
git worktree add ../apm2-<branch> <branch>

# Development
cargo fmt --all && cargo clippy --all-targets -- -D warnings
cargo test -p <crate>

# Sync
git fetch origin main && git rebase origin/main
git push --force-with-lease

# PR
gh pr create && gh pr checks

# Cleanup
git worktree remove ../apm2-<branch> && git branch -d <branch>
```

### CI Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR, main push | Format, lint, test, audit |
| `release-plz.yml` | main push | Create release PRs |
| `release.yml` | Tag push | Sign and publish |
| `miri.yml` | Weekly | UB detection |
| `fuzz.yml` | Weekly | Crash fuzzing |

### Documentation

| Topic | Location |
|-------|----------|
| Safe Rust patterns | [`documents/coding/SAFE_RUST_PATTERNS.md`](documents/coding/SAFE_RUST_PATTERNS.md) |
| Release pipeline | [`documents/releases/`](documents/releases/) |
| Security & signing | [`documents/security/`](documents/security/) |
