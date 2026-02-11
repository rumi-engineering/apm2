# Commit and Push Task: PR #593 (TCK-00468)

Branch: `ticket/RFC-0028/TCK-00468`
The code changes from the fix round are already in the working tree but not committed.

## Steps

1. Run `cargo fmt --all`
2. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ANY errors
3. Run `cargo doc --workspace --no-deps` — fix ANY errors
4. Run `cargo test -p apm2-daemon` — must pass
5. Commit and push:
```bash
git add -A && git commit -m "fix(TCK-00468): background-operator bypass, subshell detection, authoritative receipt linkage" && apm2 fac push --ticket documents/work/tickets/TCK-00468.yaml
```

You MUST pass ALL CI checks. Fix all clippy/fmt/doc errors before committing.
