# Fix Task: PR #594 (TCK-00465) — Review Round 2

## Context
You are fixing review findings for PR #594 (TCK-00465: RFC-0028 REQ-0004 boundary-flow integrity and declassification receipt enforcement).

Branch: `ticket/RFC-0028/TCK-00465`
Worktree: `/home/ubuntu/Projects/apm2-TCK-00465`
Current HEAD: `e2f0b467`

## Review Results
- **Security Review: FAIL** — 2 MAJOR, 1 NIT
- **Code Quality Review: FAIL** — 2 MAJOR

## SECURITY MAJOR 1: Untrusted leakage/timing receipts bypass containment

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2338`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2371`

**Problem:** `build_boundary_flow_runtime_state` accepts `boundary_flow` values from untrusted request arguments. When hints are absent, it synthesizes permissive defaults (`leakage_bits=0`, `observed_variance_ticks=0`) that satisfy `validate_channel_boundary`. An attacker can omit hints or under-report metrics to avoid quarantine.

**Required Fix:**
1. When `boundary_flow` hints are absent for enforcement tiers, the default MUST be fail-closed (deny), NOT permissive pass-through
2. If no authoritative leakage/timing evidence is available, set values to MAX (most restrictive), not 0 (most permissive)
3. Add adversarial test: missing boundary_flow hints on enforcement-tier request → assert denial
4. Add adversarial test: forged-low leakage/timing values → assert denied (or at minimum, compare against authoritative instrumentation if available)

## SECURITY MAJOR 2: Policy binding check is tautological

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2030`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2173`

**Problem:** `tool_decision_policy_verified` is inferred from decision type (`Allow`/`DedupeCacheHit`) rather than independent proof. `derive_policy_binding` sets `admitted_policy_root_digest` equal to the presented digest when verified, and for dedupe paths derives synthetic hashes from request ID. This makes policy digest binding checks self-satisfying.

**Required Fix:**
1. Resolve admitted policy root from authoritative state (broker/policy authority) at dispatch time
2. Compare independently to the presented digest
3. For dedupe-hit paths, use the originally-admitted policy digest (from the first admission), not a synthetic hash
4. Fail-closed on missing or mismatched policy binding anchors

## QUALITY MAJOR 1: Token contract changed without schema/version migration

**Paths:**
- `crates/apm2-core/src/channel/enforcement.rs:19`
- `crates/apm2-core/src/channel/enforcement.rs:244`
- `crates/apm2-core/src/channel/enforcement.rs:687`

**Problem:** Token schema remains `apm2.channel_context_token.v1` but new boundary-flow fields are mandatory. Older v1 tokens decode but are denied with new defects, creating mixed-version rollout breakage.

**Required Fix:**
1. Provide a backward-compatible transition path: if boundary-flow fields are absent in a v1 token, apply legacy behavior (skip boundary-flow checks, emit deprecation warning) instead of hard deny
2. This preserves v1 token validity during rollout while new tokens include boundary-flow fields
3. Add a test: v1 token without boundary-flow fields → legacy path (no deny from missing fields)

## QUALITY MAJOR 2: Quarantine has no clearance/expiry/lifecycle reset path

**Paths:**
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2063`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2074`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:2936`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:4146`

**Problem:** A single leakage/timing violation permanently quarantines the `(session_id, tool_class)` channel with no recovery path. This is an availability regression.

**Required Fix:**
1. Clear quarantine state on session termination (automatic lifecycle reset)
2. Add a bounded TTL for quarantine (e.g., `QUARANTINE_TTL_SECS = 300`) — after TTL expires, allow re-evaluation
3. Add test: quarantined channel is cleared after session termination
4. Add test: quarantined channel is still blocked during TTL but clears after expiry

## MANDATORY Pre-Commit Steps (in this exact order)

You MUST run ALL of these and fix any issues BEFORE committing:
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
```

You MUST pass ALL CI checks. Do not push code that fails any of these.

## Push Workflow

After all pre-commit steps pass:
```bash
git add -A
git commit -m "fix(TCK-00465): fail-closed defaults, authoritative policy binding, quarantine lifecycle, v1 compat"
apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```
