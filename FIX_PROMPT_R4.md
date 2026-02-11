# Fix Task: PR #593 (TCK-00468) — Round 4

Branch: `ticket/RFC-0028/TCK-00468`, HEAD: `773dad26`

## QUALITY MAJOR: False-positive GitHub API detection in non-actuation commands

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2793`

**Problem:** `command_targets_github_api` treats any command segment containing `api.github.com` as a direct actuation attempt, even when it's in non-executing context like `echo "https://api.github.com/repos/example"`.

**Required Fix:**
1. Only flag `api.github.com` when it appears in a context that actually makes a network request
2. Check if the segment's primary executable is an HTTP client (`curl`, `wget`, `fetch`, `http`, `httpie`) or similar
3. Don't flag when the URL is inside `echo`, `printf`, `log`, or similar output-only commands
4. Add negative test: `echo "https://api.github.com/repos/example"` → ALLOW (not a deny)
5. Add positive test: `curl https://api.github.com/repos/owner/repo` → DENY

## SECURITY MAJOR: GH CLI bypass via env-resolved wrapper (`$SHELL -c "gh ..."`)

**Path:** `crates/apm2-daemon/src/protocol/session_dispatch.rs:2681,2731,2739`

**Problem:** `command_invokes_gh_cli_inner` only unwraps recognized literal wrappers. `$SHELL -c "gh api ..."` bypasses because `$shell` isn't recognized as a wrapper.

**Required Fix:**
1. Treat shell environment variable references (`$SHELL`, `$shell`, `${SHELL}`) as wrapper candidates
2. When the primary executable starts with `$` and a `-c` flag follows, inspect the inline command payload
3. Add tests:
   - `$SHELL -c "gh api /repos"` → DENY
   - `${SHELL} -c "gh pr view 123"` → DENY

## Pre-Commit Steps
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

## Push
```bash
git add -A && git commit -m "fix(TCK-00468): precise api.github.com detection, env-variable wrapper handling" && apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```
