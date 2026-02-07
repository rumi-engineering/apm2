title: Daemon Implementation Patterns — Required Reading for Implementor Agents
purpose: "Architecture-specific patterns for apm2-daemon. Read BEFORE writing code. Violations cause automatic BLOCKER findings."

## How to Use

This file contains patterns learned from 30+ review rounds on daemon PRs. Every pattern
listed here has caused at least one BLOCKER or MAJOR finding from Codex reviewers. Read
every section applicable to your changes BEFORE writing code.

---

## 1. Proto File Workflow

The file `crates/apm2-daemon/src/protocol/apm2.daemon.v1.rs` is AUTO-GENERATED.

**NEVER edit `apm2.daemon.v1.rs` directly.** CI runs Proto Verify which rebuilds from
source and diffs — if your committed file doesn't match, ALL CI checks fail (cascading
failure through clippy, test, doc, MSRV, release build).

**Correct workflow:**
1. Edit `proto/apm2d_runtime_v1.proto` only
2. Run `cargo build -p apm2-daemon` — build.rs regenerates `apm2.daemon.v1.rs`
3. Commit BOTH the `.proto` file AND the regenerated `.rs` file
4. Ensure the `.proto` file ends with a newline character

**Common mistake:** Agent edits `.proto`, forgets to rebuild, pushes stale `.rs` file.
CI fails on ALL 8+ checks because the generated structs don't match the code using them.

---

## 2. DispatcherState Production Wiring

`DispatcherState` (in `crates/apm2-daemon/src/state.rs`) is the production composition
root. It wires `PrivilegedDispatcher` and `UnprivilegedDispatcher` with all dependencies.

**Critical invariant:** Every `with_X()` builder method on any dispatcher MUST be called
in the corresponding `DispatcherState` builder chain.

**Key methods in state.rs:**
- `DispatcherState::new()` — base constructor, wires core dependencies
- `DispatcherState::with_persistence(sqlite_path)` — adds SqliteLeaseValidator
- `DispatcherState::with_gate_orchestrator(orchestrator)` — adds GateOrchestrator

**Common BLOCKER:** Adding `PrivilegedDispatcher::with_gate_orchestrator()` but NOT
calling it inside `DispatcherState::with_gate_orchestrator()`. The feature works in
tests (which manually inject) but is dead in production.

**Verification:**
```bash
# Check that your with_X() is used in state.rs
grep -n "with_your_method" crates/apm2-daemon/src/state.rs
# Must appear in at least one DispatcherState builder method
```

---

## 3. LeaseValidator Trait

`LeaseValidator` trait (in `dispatch.rs` ~line 3050-3080) provides default methods:
```rust
pub trait LeaseValidator: Send + Sync {
    fn get_lease_work_id(&self, lease_id: &str) -> Option<String> { None }
    fn get_gate_lease(&self, lease_id: &str) -> Option<GateLease> { None }
    // ... other methods with None defaults
}
```

**Critical invariant:** `SqliteLeaseValidator` (in `ledger.rs` ~line 1570) MUST override
every method that production code paths depend on. The default `None` return causes
fail-closed behavior (Tier4 fallback → rejection) which is secure but breaks valid
production flows.

**Common BLOCKER:** Adding a new `LeaseValidator` method, using it in a handler, but
only implementing it for the in-memory test validator. SqliteLeaseValidator inherits the
default `None`, production silently fails.

**Correct pattern:**
1. Add method with `None` default to trait
2. Implement real logic in `SqliteLeaseValidator` with indexed SQL query
3. Test with BOTH in-memory AND SqliteLeaseValidator paths

---

## 4. SQL Query Patterns for Ledger Lookups

The event ledger stores typed events in a single `events` table with JSON payloads.

**BLOCKER pattern — unbounded table scan:**
```rust
// BAD: O(N) scan with per-row JSON parse
let events = self.get_all_events()?;
for event in events {
    if let Ok(parsed) = serde_json::from_str(&event.payload) {
        if parsed.lease_id == target { return Some(parsed); }
    }
}
```

**Correct pattern — indexed lookup:**
```rust
// GOOD: Targeted query with ordering
let sql = "SELECT payload FROM events
           WHERE event_type = ?1
           AND json_extract(payload, '$.lease_id') = ?2
           ORDER BY rowid DESC LIMIT 1";
```

**Key rules:**
- Always filter by `event_type` first (reduces scan scope)
- Use `json_extract` for indexed field filtering when possible
- Use `ORDER BY rowid DESC LIMIT 1` for deterministic latest-row selection
- Never iterate all events when a targeted query suffices

---

## 5. IPC Message Type Addition Checklist

Adding a new `PrivilegedMessageType` variant requires 7 coordinated changes:

1. **Enum variant** — `PrivilegedMessageType::YourType` with unique tag byte
2. **from_tag()** — match arm mapping tag byte → variant
3. **tag()** — match arm mapping variant → tag byte
4. **build_frame()** — match arm constructing wire frame with correct header
5. **Handler function** — `handle_your_type(ctx, payload) -> Result<Vec<u8>>`
6. **privileged_dispatch()** — match arm routing incoming messages to handler
7. **Proto messages** — if structured request/response, add to `.proto` and rebuild

**Tag byte allocation:** Check existing tags in `from_tag()` to avoid collisions.
Current max tag is ~72 (DelegateSublease). Use next available sequential number.

---

## 6. Caller Authorization Pattern

Every handler that performs security-sensitive operations MUST verify caller identity.

**Available identity source:**
```rust
let caller_id = ctx.peer_credentials()
    .map(|creds| creds.effective_uid())
    .unwrap_or_else(|| return Err(unauthorized_error()));
```

**Authorization checks by handler type:**
- `DelegateSublease` — caller must be authorized to delegate from `parent_lease_id`
- `IngestReviewReceipt` — reviewer identity must match lease executor binding
- State mutations — caller must own or be authorized for the affected resource

**Common BLOCKER:** Handler validates structural fields (non-empty, format) but skips
authorization check (who is making this request?). Codex security review always catches
this as confused-deputy / capability laundering risk.

---

## 7. Serde Default Security

`#[serde(default)]` on security-critical enum fields is an automatic BLOCKER.

**BLOCKER example:**
```rust
#[derive(Deserialize)]
struct PolicyResolution {
    #[serde(default)]  // Defaults to first variant = Tier0 = LEAST restrictive!
    resolved_risk_tier: RiskTier,
}
```

**Correct pattern:** Use custom deserializer that defaults to MOST restrictive:
```rust
fn deserialize_risk_tier<'de, D>(d: D) -> Result<RiskTier, D::Error>
where D: Deserializer<'de> {
    Option::<RiskTier>::deserialize(d)
        .map(|opt| opt.unwrap_or(RiskTier::Tier4))  // Most restrictive default
}
```

---

## 8. Test Evidence Requirements

Tests must prove production wiring, not just local logic.

**BLOCKER — in-memory-only tests:**
```rust
// BAD: manually injects dependencies, doesn't prove production wiring
let dispatcher = PrivilegedDispatcher::new()
    .with_lease_validator(Arc::new(InMemoryValidator::new()));
```

**Correct — DispatcherState integration tests:**
```rust
// GOOD: uses production composition path
let state = DispatcherState::new(config)
    .with_persistence(&sqlite_path)
    .with_gate_orchestrator(orchestrator);
// Exercise through actual socket dispatch
```

**Additional requirements:**
- Negative tests: unauthorized caller → rejection
- Count assertions: specific non-zero literals (`assert_eq!(count, 3)`)
- Side-effect assertions: verify state changed, events emitted
- Never use `assert!(count > 0)` — proves nothing if count is always 0

---

## 9. Pre-Commit Steps (MANDATORY ORDER)

Every agent MUST run these before committing:

```bash
cargo fmt --all                                                    # Format
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Lint
cargo doc --workspace --no-deps                                     # Doc check
cargo test -p apm2-daemon                                           # Tests
cargo test -p apm2-core                                             # Tests
```

**If any step fails, FIX IT before committing.** Do not push broken code expecting
CI to catch it — each CI round-trip wastes 10+ minutes.

---

## Quick Pre-Implementation Checklist

Before writing code, verify your approach against these questions:

- [ ] Am I editing apm2.daemon.v1.rs directly? → STOP, edit .proto instead
- [ ] Am I adding a with_X() method? → Plan state.rs wiring NOW
- [ ] Am I adding a LeaseValidator method? → Plan SqliteLeaseValidator impl NOW
- [ ] Am I adding an IPC handler? → Plan authorization check NOW
- [ ] Am I using #[serde(default)] on an enum? → Use custom deserializer instead
- [ ] Are my tests using PrivilegedDispatcher::new()? → Use DispatcherState instead
- [ ] Am I querying all events? → Use targeted SQL with ORDER BY rowid
