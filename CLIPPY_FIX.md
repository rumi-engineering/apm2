# Clippy Fix Task: PR #594 (TCK-00465)

Branch: `ticket/RFC-0028/TCK-00465`
The code changes from the previous fix round are already in the working tree but not yet committed. There are 9 clippy errors to fix before committing.

## Errors to Fix

1. **Too many arguments (8/7)**: One function has 8 args, clippy allows max 7. Refactor by combining related args into a struct or reducing the arg count.

2. **`map_err` should be `inspect_err`** (6 occurrences in `crates/apm2-daemon/src/ledger.rs`): When the closure in `map_err` only performs a side-effect and returns the same error, use `inspect_err` instead.

3. **Needless borrows** (2 occurrences): Remove unnecessary `&` on expressions that already implement the required traits. Likely `&expr.to_le_bytes()` should be `expr.to_le_bytes()`.

## Steps

1. Fix ALL 9 clippy errors
2. Run `cargo fmt --all`
3. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` (must pass with 0 errors)
4. Run `cargo doc --workspace --no-deps` (must pass)
5. Run `cargo test -p apm2-daemon` (must pass)
6. Commit and push:
```bash
git add -A && git commit -m "fix(TCK-00465): hash-chained ledger events and persistent receipt consumption" && apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

You MUST pass ALL CI checks. Do NOT skip any step.
