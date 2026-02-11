# Merge + Quality Fix Task: PR #594 (TCK-00465) — Round 10

Branch: `ticket/RFC-0028/TCK-00465`, HEAD: `9ba90a59`

## Step 1: Merge main (resolve conflicts)

PR 593 (TCK-00468) was just merged to main, causing a conflict in `session_dispatch.rs`.

```bash
git fetch origin main && git merge origin/main
```

Resolve ALL conflicts:
- The conflict is in `crates/apm2-daemon/src/protocol/session_dispatch.rs`
- Keep BOTH sets of changes — main's projection-isolation code AND this branch's boundary-flow code
- They are complementary features, not competing

After resolving:
```bash
git add -A && git commit --no-edit
```

## Step 2: Fix quality findings

### BLOCKER: Hash-chain checkpoint drift on lease registration writes

**Paths:**
- `crates/apm2-daemon/src/ledger.rs` — `register_full_lease_inner` and `register_lease_with_executor`
- `crates/apm2-daemon/src/ledger.rs` — `persist_signed_event` (correctly updates checkpoint)

**Problem:** Lease registration inserts `ledger_events` rows directly but never updates `ledger_metadata.hash_chain_tip_checkpoint_v1`. On next startup, checkpoint validation fails.

**Fix:**
1. After each INSERT into `ledger_events` in lease registration paths, update the checkpoint:
   ```sql
   INSERT OR REPLACE INTO ledger_metadata (key, value)
   VALUES ('hash_chain_tip_checkpoint_v1', ?new_event_hash);
   ```
2. Make this atomic within the same transaction.
3. Add regression test: register a lease, then validate checkpoint → PASS.

### MAJOR: Channel context token v1 backward-incompatible

**Paths:**
- `crates/apm2-core/src/channel/enforcement.rs` — `ChannelContextTokenPayloadV1`

**Problem:** New fields lack `#[serde(default)]`. Legacy tokens fail to deserialize.

**Fix:**
1. Add `#[serde(default)]` to ALL newly added fields
2. Defaults should be fail-closed: `false` for booleans, `None` for options
3. Add compatibility test: deserialize legacy v1 payload (without new fields) → succeeds

## Step 3: Pre-commit + push

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --no-deps
cargo test -p apm2-core -p apm2-daemon
git add -A && git commit -m "fix(TCK-00465): checkpoint-atomic lease registration, backward-compatible v1 tokens" && apm2 fac push --ticket documents/work/tickets/TCK-00465.yaml
```

You MUST pass ALL CI checks.
