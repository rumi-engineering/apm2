# Contributing to APM2

Development workflow for AI agents using **trunk-based development** with **worktree isolation**. Ideally you shouldn't run git commands yourself, instead run `cargo xtask <common_dev_thing>` to accomplish every phase of the development loop.

See @documents/skills/dev-eng-ticket/SKILL.md for general instructions on how to develop within this code base.

## Releases

See @documents/security/RELEASE_PROCEDURE.md

---

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
# Start work on RFC (auto-detects next unblocked ticket, creates worktree)
cargo xtask start-ticket RFC-0001

# Development
cargo fmt --all && cargo clippy --all-targets -- -D warnings
cargo test -p <crate>
```

### CI Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR, main push | Format, lint, test, audit |
| `release-plz.yml` | main push | Create release PRs |
| `release.yml` | Tag push | Sign and publish |
| `miri.yml` | Weekly | UB detection |
| `fuzz.yml` | Weekly | Crash fuzzing |