# Resource

> Multi-dimensional budget tracking, time-bounded lease authorization, and scoped authority boundaries for holonic execution.

## Overview

The `resource` module implements Bounded Authority (Axiom III from Principia Holonica) through three core abstractions:

1. **Budget** (`budget.rs`): Multi-dimensional resource limits (episodes, tool calls, tokens, duration) with monotonic consumption and atomic multi-dimension deduction.
2. **Lease** (`lease.rs`): Time-bounded, scoped authorization combining identity, scope, budget, and expiration. Supports hierarchical derivation with budget conservation.
3. **LeaseScope** (`scope.rs`): Authority boundaries defining which work IDs, tools, and namespaces a lease holder can access. Includes path-aware prefix matching with traversal rejection.
4. **ResourceError** (`error.rs`): Error types for budget exhaustion, lease expiration, scope violations, and derivation failures.

When a holon spawns a sub-holon, it derives a child lease from its own. The derivation process enforces that the child scope is a subset, the child budget is bounded by and deducted from the parent's remaining budget, and the child expiration is at or before the parent's. This creates a hierarchy of decreasing authority that prevents privilege escalation and resource inflation.

## Key Types

### `Budget`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    initial_episodes: u64,
    remaining_episodes: u64,
    initial_tool_calls: u64,
    remaining_tool_calls: u64,
    initial_tokens: u64,
    remaining_tokens: u64,
    initial_duration_ms: u64,
    remaining_duration_ms: u64,
}
```

Tracks four resource dimensions (per REQ-3004): episodes, tool calls, tokens, and wall-clock duration.

**Invariants:**

- [INV-RS01] All remaining values are monotonically decreasing; once consumed, resources cannot be restored.
- [INV-RS02] `remaining_* <= initial_*` always holds (conservation law: `consumed_* + remaining_* == initial_*`).
- [INV-RS03] `is_exhausted()` returns `true` if and only if at least one dimension has `remaining == 0`.
- [INV-RS04] Failed deductions leave the budget completely unchanged (no partial application).

**Contracts:**

- [CTR-RS01] `deduct_episodes/tool_calls/tokens/duration_ms(amount)` returns `ResourceError::BudgetExhausted` if `amount > remaining` and leaves the budget unchanged.
- [CTR-RS02] `deduct(episodes, tool_calls, tokens, duration_ms)` is atomic: all four dimensions are checked before any are applied. If any single dimension is insufficient, no changes are made.
- [CTR-RS03] `derive_sub_budget(requested)` returns a new `Budget` where each dimension is `min(self.remaining_*, requested.initial_*)`.
- [CTR-RS04] `can_accommodate(requested)` returns `true` if and only if all four dimensions of `requested.initial_*` are `<= self.remaining_*`.
- [CTR-RS05] `exhausted_resource()` returns resources in priority order: episodes > tool_calls > tokens > duration.
- [CTR-RS06] `Budget::unlimited()` sets all dimensions to `u64::MAX`.
- [CTR-RS07] `Budget::default()` sets all dimensions to 0 (immediately exhausted).

### `Lease`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    id: String,
    issuer_id: String,
    holder_id: String,
    scope: LeaseScope,
    budget: Budget,
    issued_at_ns: u64,
    expires_at_ns: u64,
    parent_lease_id: Option<String>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}
```

Time-bounded, scoped authorization for a holon to perform work. The fundamental authorization mechanism in holonic coordination.

**Invariants:**

- [INV-RS05] `is_derived()` returns `true` if and only if `parent_lease_id.is_some()`.
- [INV-RS06] Derived leases have `expires_at_ns <= parent.expires_at_ns`.
- [INV-RS07] Derived leases have a scope that is a subset of the parent's scope.
- [INV-RS08] `signing_bytes()` produces deterministic JSON excluding the signature field, enabling sign-then-verify workflows.

**Contracts:**

- [CTR-RS08] `validate(current_time_ns)` returns `ResourceError::LeaseExpired` if `current_time_ns >= expires_at_ns`, and `ResourceError::BudgetExhausted` if any budget dimension is zero.
- [CTR-RS09] `validate_work_access(work_id)` returns `ResourceError::LeaseScopeViolation` if the scope does not authorize the work ID.
- [CTR-RS10] `validate_tool_access(tool)` returns `ResourceError::LeaseScopeViolation` if the scope does not authorize the tool.
- [CTR-RS11] `validate_namespace_access(path)` returns `ResourceError::LeaseScopeViolation` if the scope does not authorize the namespace path.
- [CTR-RS12] `derive()` validates: (1) child expiration does not exceed parent, (2) child scope is a subset of parent scope, (3) parent budget can accommodate child budget. On success, **deducts** the child budget from the parent (preventing resource inflation via multiple derivations) and returns a fresh child lease. On failure, returns `ResourceError::InvalidDerivation` and leaves the parent unchanged.
- [CTR-RS13] `signing_bytes()` and `compute_hash()` are deterministic and exclude the signature field.

### `LeaseBuilder`

```rust
#[derive(Debug, Default)]
pub struct LeaseBuilder { /* ... */ }
```

Builder for constructing `Lease` instances. Required fields: `lease_id`, `issuer_id`, `holder_id`, `scope`, `budget`, `expires_at_ns`. Optional: `issued_at_ns` (defaults to current time), `parent_lease_id`, `signature`.

**Contracts:**

- [CTR-RS14] `build()` returns `ResourceError::MissingField` if any required field is not set.

### `LeaseScope`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseScope {
    work_ids: BTreeSet<String>,
    tools: BTreeSet<String>,
    namespaces: BTreeSet<String>,
    #[serde(default)]
    unlimited: bool,
}
```

Authority boundaries defining what operations a lease holder can perform. Uses `BTreeSet` for deterministic serialization.

**Invariants:**

- [INV-RS09] An empty set for any dimension means "no access" (not "unlimited"). Only `unlimited == true` bypasses checks.
- [INV-RS10] Namespace matching uses path-aware prefix semantics: `"project/src"` allows `"project/src/main.rs"` but NOT `"project/srcfile"` or `"project/src_backup"`.
- [INV-RS11] Paths containing `..` traversal sequences are always rejected, even for unlimited scopes (defense in depth). Both `/` and `\` separators are checked.

**Contracts:**

- [CTR-RS15] `allows_work_id(id)` uses exact match against the `work_ids` set (or returns `true` if unlimited).
- [CTR-RS16] `allows_tool(tool)` uses exact match against the `tools` set (or returns `true` if unlimited).
- [CTR-RS17] `allows_namespace(path)` rejects paths with `..` traversal first, then checks path-aware prefix match: the path must equal or extend a namespace entry with a `/` separator.
- [CTR-RS18] `is_superset_of(other)` returns `true` if every permission in `other` is also present in `self`. An unlimited scope is a superset of all non-unlimited scopes.
- [CTR-RS19] `validate_derivation(requested)` returns `ResourceError::InvalidDerivation` if `requested` is not a subset of `self`.
- [CTR-RS20] `derive_sub_scope(requested)` returns the intersection of `self` and `requested`, using path-aware prefix matching for namespaces.
- [CTR-RS21] `LeaseScope::empty()` creates a scope that denies all operations.
- [CTR-RS22] `LeaseScope::unlimited()` creates a scope that permits all operations (except paths with traversal sequences).

### `LeaseScopeBuilder`

```rust
#[derive(Debug, Default)]
pub struct LeaseScopeBuilder { /* ... */ }
```

Builder for constructing `LeaseScope` instances. Supports both batch (`.work_ids(...)`, `.tools(...)`, `.namespaces(...)`) and single-item (`.work_id(...)`, `.tool(...)`, `.namespace(...)`) methods.

### `ResourceError`

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResourceError {
    BudgetExhausted { resource: String, requested: u64, remaining: u64 },
    LeaseExpired { lease_id: String, expired_at_ns: u64 },
    LeaseScopeViolation { reason: String },
    InvalidSignature { lease_id: String },
    InvalidDerivation { reason: String },
    MissingField { field: String },
    InvalidLeaseId { lease_id: String },
    OperationNotPermitted { reason: String },
}
```

Error types for resource management operations (8 variants).

**Contracts:**

- [CTR-RS23] `is_budget_exhausted()` returns `true` only for `BudgetExhausted`.
- [CTR-RS24] `is_lease_expired()` returns `true` only for `LeaseExpired`.
- [CTR-RS25] `is_recoverable()` always returns `false` -- all resource errors are non-recoverable without external intervention.
- [CTR-RS26] Factory methods (`budget_exhausted()`, `lease_expired()`, `scope_violation()`, etc.) accept `impl Into<String>` for ergonomic construction.

## Public API

| Function / Method | Description |
|---|---|
| `Budget::new(episodes, tool_calls, tokens, duration_ms)` | Creates a budget with the specified limits. |
| `Budget::unlimited()` | Creates a budget with `u64::MAX` for all dimensions. |
| `Budget::default()` | Creates a zero budget (immediately exhausted). |
| `Budget::deduct_episodes/tool_calls/tokens/duration_ms(amount)` | Deducts from a single dimension. |
| `Budget::deduct(episodes, tool_calls, tokens, duration_ms)` | Atomic multi-dimension deduction. |
| `Budget::is_exhausted()` | Returns `true` if any dimension is zero. |
| `Budget::exhausted_resource()` | Returns the name of the first exhausted resource. |
| `Budget::derive_sub_budget(requested)` | Creates a sub-budget capped at parent remaining. |
| `Budget::can_accommodate(requested)` | Checks if all requested dimensions fit. |
| `Budget::consumed_episodes/tool_calls/tokens/duration_ms()` | Returns amount consumed per dimension. |
| `Lease::builder()` | Returns a `LeaseBuilder`. |
| `Lease::validate(current_time_ns)` | Validates expiration and budget. |
| `Lease::validate_work_access(work_id)` | Checks scope for work ID. |
| `Lease::validate_tool_access(tool)` | Checks scope for tool. |
| `Lease::validate_namespace_access(path)` | Checks scope for namespace path. |
| `Lease::derive(child_id, holder_id, scope, budget, expires, issued)` | Derives a child lease (deducts from parent). |
| `Lease::signing_bytes()` | Returns deterministic canonical bytes for signing. |
| `Lease::budget_mut()` | Returns mutable budget reference for deductions. |
| `LeaseScope::empty()` | Creates a deny-all scope. |
| `LeaseScope::unlimited()` | Creates an allow-all scope. |
| `LeaseScope::builder()` | Returns a `LeaseScopeBuilder`. |
| `LeaseScope::allows_work_id(id)` | Exact-match permission check. |
| `LeaseScope::allows_tool(tool)` | Exact-match permission check. |
| `LeaseScope::allows_namespace(path)` | Path-aware prefix permission check. |
| `LeaseScope::is_superset_of(other)` | Subset relationship check. |
| `LeaseScope::validate_derivation(requested)` | Validates derivation is valid. |
| `LeaseScope::derive_sub_scope(requested)` | Intersects scopes for derivation. |
| `LeaseScope::intersect(other)` | Set intersection of two scopes. |

## Examples

### Creating a Lease with Budget

```rust
use apm2_holon::resource::{Budget, Lease, LeaseScope};

let scope = LeaseScope::builder()
    .work_ids(["work-001", "work-002"])
    .tools(["read", "write"])
    .namespaces(["project/src"])
    .build();

let budget = Budget::new(10, 100, 10_000, 60_000);

let lease = Lease::builder()
    .lease_id("lease-001")
    .issuer_id("registrar")
    .holder_id("agent-001")
    .scope(scope)
    .budget(budget)
    .expires_at_ns(2_000_000_000)
    .build()
    .unwrap();

assert!(!lease.is_expired_at(1_000_000_000));
assert!(lease.scope().allows_work_id("work-001"));
assert!(lease.scope().allows_namespace("project/src/main.rs"));
```

### Deriving a Child Lease

```rust
use apm2_holon::resource::{Budget, Lease, LeaseScope};

let mut parent = Lease::builder()
    .lease_id("parent-lease")
    .issuer_id("registrar")
    .holder_id("parent-agent")
    .scope(LeaseScope::builder()
        .work_ids(["work-001", "work-002"])
        .tools(["read", "write"])
        .build())
    .budget(Budget::new(10, 100, 10_000, 60_000))
    .expires_at_ns(2_000_000_000)
    .build()
    .unwrap();

let child = parent.derive(
    "child-lease",
    "child-agent",
    &LeaseScope::builder().work_ids(["work-001"]).tools(["read"]).build(),
    &Budget::new(5, 50, 5_000, 30_000),
    1_800_000_000,
    1_500_000_000,
).unwrap();

assert!(child.is_derived());
assert_eq!(child.parent_lease_id(), Some("parent-lease"));
// Parent budget was deducted to prevent resource inflation
assert_eq!(parent.budget().remaining_episodes(), 5); // 10 - 5
```

### Atomic Budget Deduction

```rust
use apm2_holon::resource::Budget;

let mut budget = Budget::new(10, 100, 10_000, 60_000);

// Atomic deduction: all-or-nothing
budget.deduct(1, 5, 500, 1000).unwrap();
assert_eq!(budget.remaining_episodes(), 9);

// If any dimension is insufficient, nothing changes
let result = budget.deduct(1, 5, 20_000, 1000); // tokens insufficient
assert!(result.is_err());
assert_eq!(budget.remaining_episodes(), 9); // unchanged
```

## Related Modules

- [Episode controller](../episode/AGENTS.md) - Deducts from lease budgets during episode execution
- [Ledger events](../ledger/AGENTS.md) - `LeaseIssued`, `BudgetConsumed`, `BudgetExhausted` event types
- [Orchestration](../orchestration/AGENTS.md) - `OrchestrationStateV1::as_budget()` converts orchestration resources to `Budget`
- [Holon trait (crate root)](../../AGENTS.md) - `EpisodeContext` carries lease and budget information

## References

- [RFC-0019] Automated FAC v0 - End-to-end ingestion, review episode, durable receipt, GitHub projection
- [REQ-3004] Multi-dimensional budget tracking (episodes, tool calls, tokens, duration)
- [Axiom III] Bounded Authority (Principia Holonica) - Scope and budget constraints
