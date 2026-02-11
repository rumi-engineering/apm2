# Merge Conflict Resolution: PR #594 (TCK-00465)

Branch: `ticket/RFC-0028/TCK-00465`

## Context
PR #592 (TCK-00464) was just merged to main, modifying `crates/apm2-daemon/src/ledger.rs` and `crates/apm2-daemon/src/protocol/dispatch.rs`. Your branch has conflicts with the new main.

## Steps

1. Merge main into the branch:
```bash
git fetch origin main && git merge origin/main
```

2. Resolve ALL merge conflicts:
   - Keep BOTH sets of changes — the main branch changes from PR 592 AND this branch's changes
   - The conflict is in `crates/apm2-daemon/src/ledger.rs`
   - PR 592 added delegation lineage code; this PR added hash-chain ledger code
   - Both are needed — they are complementary features, not competing changes

3. After resolving conflicts:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

4. Complete the merge:
```bash
git add -A && git commit --no-edit
```

5. Push:
```bash
apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

You MUST pass ALL CI checks. Fix all errors before pushing.
