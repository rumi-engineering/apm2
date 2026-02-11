# Fix Task: PR #594 (TCK-00465) — Review Round 3

## Context
Branch: `ticket/RFC-0028/TCK-00465`
Worktree: `/home/ubuntu/Projects/apm2-TCK-00465`
Current HEAD: `f40560ac`

Security: PASS. Quality: FAIL — 1 BLOCKER, 1 MAJOR.

## BLOCKER: Fail-open compatibility path skips boundary-flow checks

**Paths:**
- `crates/apm2-core/src/channel/enforcement.rs:691`
- `crates/apm2-core/src/channel/enforcement.rs:702`
- `crates/apm2-core/src/channel/enforcement.rs:717`
- `crates/apm2-core/src/channel/enforcement.rs:1348`

**Problem:** `validate_channel_boundary` bypasses policy-binding, leakage-budget, and timing-budget validation when boundary-flow fields are absent (emitting only a warning). This creates a permissive fallback that conflicts with REQ-0004 fail-closed behavior.

**Required Fix:**
1. When boundary-flow evidence is absent, treat it as DENIAL (emit defects for missing policy binding + leakage/timing violations)
2. Do NOT skip the checks — missing evidence = fail-closed
3. Remove the permissive `warn!` + skip branch
4. If backward compatibility is absolutely needed, gate it behind an explicit `BOUNDARY_FLOW_LEGACY_COMPAT` flag that is OFF by default in production
5. Add test: missing boundary-flow fields → deny with appropriate defect classes

## MAJOR: Classification logic allows classification_allow=false when declass_receipt=true

**Path:** `crates/apm2-core/src/channel/enforcement.rs:768`

**Problem:** Classification failure is only emitted when BOTH `classification_allow` and `declass_receipt_valid` are false. But `classification_allow=false` with `declass_receipt_valid=true` should still be a defect — classification failure is independent of declassification receipt validity.

**Required Fix:**
1. Emit classification defect whenever `classification_allow == false`, regardless of `declass_receipt_valid`
2. The boundary-admit predicate is: `capability_allow AND taint_allow AND classification_allow AND declass_receipt_valid`
3. Each predicate is INDEPENDENT — failing any one should produce a defect
4. Add regression test: `classification_allow=false, declass_receipt_valid=true, declassification_intent=none` → DENY with classification defect

## MANDATORY Pre-Commit Steps (in this exact order)

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks.

## Push Workflow

```bash
git add -A
git commit -m "fix(TCK-00465): fail-closed on missing boundary-flow, independent classification check"
apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```
