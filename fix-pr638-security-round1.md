# Fix PR #638 Security Review Findings — Round 1

You are working in `/home/ubuntu/Projects/apm2-TCK-00594` (git worktree for PR #638).
Branch: `ticket/RFC-0019/TCK-00594`
Current HEAD: `e1e973f2786d4d22637da90d9e7d4ff26a5cd3c5`
PR URL: https://github.com/guardian-intelligence/apm2/pull/638

## Primary instruction source
Read and follow `@documents/skills/implementor-default/SKILL.md` and its `references[...]`.

## Required Fixes

### MAJOR: Unbounded Deserialization in BrokerState (DoS)
- **Location**: `BrokerState` deserialization in the FAC broker module
- **Problem**: `serde_json::from_slice` deserializes `Vec<Hash>` and `Vec<ConvergenceReceipt>` without bounds checking. An attacker writing to `$APM2_HOME/private/fac/broker/state.v1.json` can cause OOM.
- **Fix**: Implement either:
  (a) A strict I/O size limit (e.g., 1MB) on the state file BEFORE passing to JSON parser, OR
  (b) A bounded Visitor pattern for deserializing the Vec collections that enforces `MAX_ADMITTED_POLICY_DIGESTS` and `MAX_CONVERGENCE_RECEIPTS` during deserialization (not after)
- Option (a) is simpler and preferred.

### MINOR: Timing side-channel in `find_admitted_policy_digest`
- **Location**: `find_admitted_policy_digest` method
- **Problem**: Uses `.iter().find(|existing| bool::from(existing.ct_eq(digest)))` which short-circuits, creating timing leak
- **Fix**: Use a non-short-circuiting fold (like the pattern already in `is_policy_digest_admitted`) that iterates ALL entries

### NIT: Wall-clock dependency in `issue_channel_context_token`
- **Location**: `issue_channel_context_token`
- **Problem**: Uses `current_time_secs()` / `SystemTime::now()` instead of injected time source
- **Fix**: If feasible, inject a time source parameter. If this is an intentional design choice documented inline, add a brief comment noting CTR-2501 deviation and the rationale.

## Mandatory Pre-Commit Steps (IN ORDER — do NOT skip)
1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix ALL warnings
3. `cargo doc --workspace --no-deps` — fix any doc warnings/errors
4. `cargo test -p apm2-cli` — run relevant tests (FAC broker is in apm2-cli)

You MUST pass ALL CI checks. After all checks pass, push using:
```
apm2 fac push --ticket documents/work/tickets/TCK-00594.yaml
```

## Key Patterns (from review feedback)
- Transactional state mutations: check admission BEFORE mutating state
- Fail-closed semantics: never default to pass
- Wire production paths: no dead code / unused methods
- Binding test evidence: no zero-count assertions
