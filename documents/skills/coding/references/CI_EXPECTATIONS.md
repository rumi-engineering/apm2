# CI Expectations

This document describes what CI checks, expected pass criteria, and how to fix common failures.

## What CI Checks

| Check | Command | What It Validates |
|-------|---------|-------------------|
| Format | `cargo fmt --all --check` | Code formatting matches rustfmt standards |
| Clippy | `cargo clippy --all-targets --all-features -- -D warnings` | No lint warnings or errors |
| Test | `cargo test --workspace` | All tests pass |
| Doc | `cargo doc --no-deps` | Documentation builds without errors |
| Deny | `cargo deny check` | No banned dependencies or license violations |
| Audit | `cargo audit` | No known security vulnerabilities |

---

## Local Verification (MANDATORY Before Commit)

Run these commands before every commit:

```bash
cargo fmt --all --check           # Must pass - if fails, run: cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings  # Must pass - fix all warnings
cargo test --workspace            # Must pass
```

**DO NOT commit until all three commands pass.** Fix any issues first:
- Format failures: `cargo fmt --all`
- Clippy warnings: Fix the code, do not just suppress warnings
- Test failures: Fix the failing tests

---

## CI Failure Handling Procedure

> **CRITICAL: Never wait for CI to complete before pulling logs.**
>
> Logs are available THE MOMENT a job fails. If you see "semver check failed" or any other failure, pull the logs immediately with `gh run view "$RUN_ID" --log-failed`. Do NOT say "let me wait for CI to finish" - the failed job's logs are already available.

### Step 1: Get the Latest Run ID

```bash
RUN_ID=$(gh run list --branch "$(git branch --show-current)" --limit 1 --json databaseId --jq '.[0].databaseId')
```

### Step 2: Poll for First Failure (every 10 seconds)

Do NOT wait for the entire CI run. Poll for the first failure:

```bash
gh run view "$RUN_ID" --json jobs --jq '.jobs[] | select(.conclusion == "failure") | .name' | head -1
```

**If this returns a job name:** A failure has occurred. **Immediately pull logs** (Step 4) - they are available NOW, not after CI completes.

**If empty and run is still in progress:** Wait 10 seconds and poll again:
```bash
gh run view "$RUN_ID" --json status --jq '.status'  # "in_progress", "completed", "queued"
```

### Step 3: Get All Failed Jobs (optional)

If you want details on which jobs/steps failed before pulling logs:

```bash
gh run view "$RUN_ID" --json jobs --jq '.jobs[] | select(.conclusion == "failure") | {name: .name, steps: [.steps[] | select(.conclusion == "failure") | .name]}'
```

### Step 4: Pull Failure Logs

Get logs from all failed steps only (most efficient):

```bash
gh run view "$RUN_ID" --log-failed
```

This outputs ONLY the logs from failed steps, making it easy to identify the issue.

### Step 5: Fix and Iterate

1. **Analyze the logs** - identify the root cause (compile error, test failure, lint issue, etc.)
2. **Fix the issue** in code
3. **Verify locally BEFORE committing** (same commands as above)
4. **Commit and push the fix**:
   ```bash
   git add -A && git commit -m "fix: <what was fixed>" && git push
   ```
5. **Return to Step 1** - get the new run ID and monitor again

### Step 6: Confirm CI Passes

Only proceed when CI is fully green:

```bash
gh run view "$RUN_ID" --json conclusion --jq '.conclusion'  # should be "success"
```

---

## Quick One-Liners

### Pull Failed Logs Immediately (Most Common)

Use this as soon as you know (or suspect) a job failed:

```bash
gh run view "$(gh run list --branch "$(git branch --show-current)" --limit 1 --json databaseId --jq '.[0].databaseId')" --log-failed
```

This works even while CI is still running - logs appear the moment each job fails.

### Check Current CI Status

```bash
gh run list --branch "$(git branch --show-current)" --limit 1 --json status,conclusion,databaseId --jq '.[0] | "\(.status) \(.conclusion // "pending") (run \(.databaseId))"'
```

---

## Common Failure Fixes

| Failure | Fix |
|---------|-----|
| `cargo fmt --check` failed | Run `cargo fmt --all` |
| Clippy warning | Fix the code (don't suppress with `#[allow(...)]` unless justified) |
| Test failure | Debug and fix the test or the code it's testing |
| Doc build failure | Fix documentation syntax or broken links |
| `cargo deny` failure | Update or replace the offending dependency |
| `cargo audit` failure | Update the vulnerable dependency or add exception with justification |
