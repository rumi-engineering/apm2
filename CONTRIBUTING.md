# Contributing to APM2

Development workflow for AI agents using **trunk-based development** with **worktree isolation**. Ideally you shouldn't run git commands yourself, instead run `cargo xtask <common_dev_thing>` to accomplish every phase of the development loop.

See @documents/skills/dev-eng-ticket/SKILL.md for general instructions on how to develop within this code base.

## Releases

See @documents/security/RELEASE_PROCEDURE.md

---

## Build Optimization

The project uses worktree-based development, which can lead to redundant
compilation across worktrees. These optimizations help reduce build times.

### Shared Compilation Cache (sccache)

[sccache](https://github.com/mozilla/sccache) caches compiled artifacts
and shares them across different Cargo target directories. This is
particularly useful for worktree-based development where each worktree
has its own `target/` directory.

**Installation:**
```bash
cargo install sccache
```

**Configuration:** Add to your shell profile (`~/.bashrc` or `~/.zshrc`):
```bash
export RUSTC_WRAPPER=sccache
```

**Verification:**
```bash
sccache --show-stats
```

**Benefits:**
- Compilation artifacts shared across all worktrees
- No file locking conflicts (unlike shared CARGO_TARGET_DIR)
- Automatic cache management
- Cache stored at `~/.cache/sccache`

**Troubleshooting:**
If you experience cache-related issues, clear the cache:
```bash
rm -rf ~/.cache/sccache
```

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