# Fix Agent: PR #633 — TCK-00502 Anti-Rollback Anchoring (Round 6)

You are fixing review findings on PR #633 (branch `ticket/RFC-0019/TCK-00502`).

## Working Environment

- **Worktree**: `/home/ubuntu/Projects/apm2-TCK-00502`
- **Branch**: `ticket/RFC-0019/TCK-00502`
- **HEAD SHA**: `f8ad975db3d41ea060d34109c2e17f8683f6dff9`
- **Ticket YAML**: `documents/work/tickets/TCK-00502.yaml`
- **Primary instruction source**: `documents/skills/implementor-default/SKILL.md` and its `references[...]`

## CRITICAL FIRST STEP: Resolve Merge Conflicts

The PR is currently in CONFLICTING state. You MUST:
1. `cd /home/ubuntu/Projects/apm2-TCK-00502`
2. `git fetch origin main`
3. `git merge origin/main` and resolve ALL merge conflicts
4. Ensure zero conflicts before proceeding

## Review Findings to Fix

### SECURITY BLOCKER: Anti-rollback bootstrap bypass on missing anchor state (fail-open at fail-closed tier)

**Exploit path:**
- `DurableAntiRollbackAnchor::new` initializes `state=None` whenever `state_path` is missing (`crates/apm2-daemon/src/admission_kernel/trust_stack/mod.rs:1444`).
- `verify_committed` maps `state=None` to `TrustError::ExternalAnchorNotInitialized` (`crates/apm2-daemon/src/admission_kernel/trust_stack/mod.rs:1764`).
- `AdmissionKernel::verify_anti_rollback` explicitly treats `ExternalAnchorNotInitialized` as success for fail-closed requests (`crates/apm2-daemon/src/admission_kernel/mod.rs:1003`).
- Deleting/losing `anti_rollback_anchor.json` before restart lets a rolled-back ledger pass fail-closed admission once, then re-seeds the anchor from attacker-controlled local state.

**Required remediation:**
- Distinguish first-install bootstrap from unexpected anchor loss.
- Persist an explicit bootstrap receipt/flag in tamper-evident storage and allow `ExternalAnchorNotInitialized` only once at genesis.
- Treat missing anchor state after initialization as `ExternalAnchorUnavailable` and deny fail-closed flows.
- The key insight: after the first successful anchor commit, any subsequent `state=None` on construction should mean the file was deleted/corrupted, not bootstrap. Track this with a bootstrap marker file or ledger entry.

### SECURITY MAJOR: Post-effect anti-rollback commit uses pre-effect anchor

**Exploit path:**
- `AdmissionBundleV1` stores `ledger_anchor = plan.as_of_ledger_anchor` (pre-effect) (`crates/apm2-daemon/src/admission_kernel/mod.rs:602`).
- Finalization commits `result.bundle.ledger_anchor` in all three handlers:
  - `crates/apm2-daemon/src/protocol/session_dispatch.rs:8682`
  - `crates/apm2-daemon/src/protocol/session_dispatch.rs:11591`
  - `crates/apm2-daemon/src/protocol/session_dispatch.rs:11860`
- Trait contract requires committing the new ledger head after successful effects (`crates/apm2-daemon/src/admission_kernel/prerequisites.rs:341`).
- For `EmitEvent` (ledger-appending effect), this anchors pre-effect head, so rollback to that head may evade anti-rollback detection.

**Required remediation:**
- On successful effect completion, derive the current authoritative post-effect anchor (for `EmitEvent`, the new ledger tip) and pass that anchor to `finalize_anti_rollback()`.
- Keep the pre-effect anchor in the sealed bundle strictly as provenance.
- Add invariants/tests asserting `committed_anchor >= post_effect_anchor` on `EmitEvent`/authoritative write paths.

### CODE QUALITY MAJOR: Single-sink continuity configuration accepted at startup but denied at runtime

**Path:** `crates/apm2-core/src/config/mod.rs:463`, `crates/apm2-daemon/src/projection/continuity_resolver.rs:280`, `crates/apm2-core/src/economics/projection_continuity.rs:1184`

**Impact:** Config validation allows one sink, and resolver snapshots preserve one sink, while continuity gate validation requires at least two distinct sinks (`DENY_SINK_SNAPSHOT_INSUFFICIENT_SINKS`). This defers an invalid deployment state to runtime and forces fail-closed denials rather than failing startup.

**Required action:** Make startup/runtime contracts consistent by either enforcing `>=2` sinks in `validate_sink_profiles()` or explicitly supporting one-sink mode by changing `MultiSinkIdentitySnapshotV1::validate()` and documenting the guarantee change.

### SECURITY MINOR: Fail-closed circuit health probe mutates anchor state before effect

- Circuit-open pre-effect check calls `finalize_anti_rollback(...)` (`crates/apm2-daemon/src/protocol/session_dispatch.rs:1969`), which commits anchor state (state mutation) before effect.
- Commit path does `flush + sync_all + parent-dir sync_all` (`crates/apm2-daemon/src/admission_kernel/trust_stack/mod.rs:1639`) and is called from synchronous dispatch in async task.
- Replace pre-effect probe with non-mutating health verification (`verify_committed`/dedicated probe API).
- Run durability commits via `spawn_blocking` (or equivalent dedicated blocking executor).

## Implementation Guidance

### Anti-rollback bootstrap fix approach:
1. Add a `bootstrapped: bool` field (or similar) to `DurableAntiRollbackAnchor` that tracks whether the anchor has ever been successfully committed.
2. On first construction: if no state file exists AND no bootstrap marker exists → this is genesis, allow `ExternalAnchorNotInitialized` once.
3. After first successful `commit()`: persist a bootstrap marker alongside the state.
4. On subsequent construction: if no state file exists BUT bootstrap marker exists → the anchor was deleted/corrupted. Return `ExternalAnchorUnavailable` (not `ExternalAnchorNotInitialized`).
5. In `verify_anti_rollback`: only treat `ExternalAnchorNotInitialized` as success if bootstrap has not yet occurred. After bootstrap, missing anchor = hard deny.

### Post-effect anchor fix approach:
1. After successful effect execution (especially `EmitEvent`), capture the new ledger tip.
2. Pass the post-effect ledger tip to `finalize_anti_rollback()` instead of the pre-effect `bundle.ledger_anchor`.
3. The `AdmissionBundleV1.ledger_anchor` remains as-is for provenance; just don't use it for the anti-rollback commit.
4. Add tests verifying: after EmitEvent, committed anchor = post-effect tip, not pre-effect.

### Single-sink config fix approach:
- The simplest fix: enforce `>= 2` in `validate_sink_profiles()` at startup so invalid state is caught early rather than at runtime.

## Mandatory Pre-Commit Steps (IN ORDER)

You MUST run these before committing:
1. `cargo fmt --all` (actually format — not just --check)
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` (fix ALL warnings)
3. `cargo doc --workspace --no-deps` (fix any doc warnings/errors)
4. `cargo test -p apm2-daemon` (run daemon tests)
5. `cargo test -p apm2-core` (run core tests)

You MUST pass ALL CI checks.

## Push Workflow

After all fixes are committed:
```
timeout 180s apm2 fac push --ticket documents/work/tickets/TCK-00502.yaml
```

## Key Patterns (from review feedback)
- **Transactional state mutations**: check admission BEFORE mutating state
- **Fail-closed semantics**: NEVER default to pass — missing/unknown = deny
- **Wire production paths**: no dead code / unused methods
- **Binding test evidence**: no zero-count assertions — tests must actually exercise the paths
- **HTF timestamps**: never SystemTime::now in event paths

## IMPORTANT
- Read the AGENTS.md files for touched crates before editing
- Do NOT introduce any new `unwrap()` on untrusted input paths
- All collections tracking external state must have MAX_* bounds
- Every error path in anti-rollback logic must be fail-closed (deny on ambiguity)
