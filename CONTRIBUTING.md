# Contributing to APM2

Development workflow for AI agents using **trunk-based development** with **worktree isolation**. Ideally you should not run git commands yourself, instead run `cargo xtask <command>` to accomplish every phase of the development loop.

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

### Faster Test Runner (cargo-nextest)

[cargo-nextest](https://nexte.st/) is a next-generation test runner for Rust
that provides significantly faster test execution compared to `cargo test`.

**Installation:**
```bash
cargo install cargo-nextest
```

**Usage:**
```bash
# Run all tests
cargo nextest run

# Run tests for a specific crate
cargo nextest run -p apm2-core

# Run tests matching a pattern
cargo nextest run --filter-expr 'test(my_test_name)'
```

**Performance Benefits:**
- **Parallel execution**: Runs tests in parallel by default, with each test
  in its own process. This eliminates test pollution and enables better
  parallelism than `cargo test`.
- **Better output**: Provides cleaner, more readable test output with
  progress indicators and failure summaries.
- **Faster feedback**: Displays failing tests immediately rather than
  waiting for the entire suite to complete.
- **Retries**: Supports automatic test retries for flaky tests.

**When to use `cargo nextest run` vs `cargo test`:**
- Use `cargo nextest run` for local development (faster, better output)
- Use `cargo test` when you need `--doc` tests (nextest does not run doctests)

---

### CI vs Local Build Settings

CI and local development have different priorities. CI optimizes for
**reproducibility and cache efficiency**, while local development optimizes
for **iteration speed**. Do not blindly copy CI settings to your local
environment.

#### Why CI Uses CARGO_INCREMENTAL=0

The CI workflow sets `CARGO_INCREMENTAL=0` for several reasons:

1. **Reproducibility**: Incremental compilation can produce different binaries
   depending on build history. Disabling it ensures identical builds.
2. **Cache efficiency**: CI caches are shared across runs. Incremental artifacts
   are tied to specific compilation units and invalidate frequently, making
   them less effective for shared caches.
3. **Coverage accuracy**: Code coverage tools (cargo-llvm-cov) work more
   reliably with full rebuilds.

#### Why Local Development Should Use CARGO_INCREMENTAL=1

For local development, incremental compilation provides significant speedups:

- **Rebuild times**: Changes to a single file only recompile affected crates.
- **Edit-compile-test cycles**: 10-100x faster iteration on small changes.
- **Default behavior**: Rust enables incremental compilation by default in
  debug builds; CI explicitly disables it.

#### Recommended Local Shell Profile

Add the following to your shell profile (`~/.bashrc` or `~/.zshrc`):

```bash
# APM2 Rust development settings
# IMPORTANT: These differ from CI intentionally - see CONTRIBUTING.md

# Enable sccache for cross-worktree caching
export RUSTC_WRAPPER=sccache

# Enable incremental compilation (disabled in CI for reproducibility)
export CARGO_INCREMENTAL=1

# Optional: Increase parallelism for faster builds
# Adjust based on your CPU cores and available RAM
# export CARGO_BUILD_JOBS=8

# Optional: Enable backtraces for debugging
export RUST_BACKTRACE=1
```

After adding these settings, reload your shell:
```bash
source ~/.bashrc  # or source ~/.zshrc
```

#### Warning: Do Not Copy CI Settings Blindly

The CI workflow (`ci.yml`) uses settings optimized for CI runners:

| Setting | CI Value | Local Value | Reason |
|---------|----------|-------------|--------|
| `CARGO_INCREMENTAL` | 0 | 1 | CI needs reproducibility; local needs speed |
| `RUSTFLAGS` | `-D warnings` | (unset) | CI enforces warnings-as-errors; annoying locally during iteration |
| `RUSTC_WRAPPER` | (unset) | `sccache` | CI uses GitHub Actions cache; local benefits from sccache |

Copying `CARGO_INCREMENTAL=0` to your local environment will make your builds
significantly slower without providing any benefit.

---

### Time Budgets

| Test Type | Local | CI |
|-----------|-------|-----|
| Unit tests | 30s | 60s |
| E2E tests | 60s | 3 min |
| Benchmarks | 60s | 5 min |

```bash
timeout 30s cargo nextest run --lib
timeout 60s cargo nextest run --test '*'
```

---

## Quick Reference

```bash
# Start work on RFC (auto-detects next unblocked ticket, creates worktree)
cargo xtask start-ticket RFC-0001

# Development
cargo fmt --all && cargo clippy --all-targets -- -D warnings
cargo nextest run -p <crate>
```

### CI Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | PR, main push | Format, lint, test, audit |
| `release-plz.yml` | main push | Create release PRs |
| `release.yml` | Tag push | Sign and publish |
| `miri.yml` | Weekly | UB detection |
| `fuzz.yml` | Weekly | Crash fuzzing |
