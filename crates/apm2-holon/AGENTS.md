# apm2-holon

> Core trait contract and resource types for holonic AI coordination

## Overview

This crate defines the fundamental contract surface for agents participating in the APM2 holonic coordination framework. It implements the foundational axioms from the *Principia Holonica*:

- **Axiom I (Markov Blanket)**: Each holon defines a clear boundary through its trait contract
- **Axiom III (Bounded Authority)**: Leases constrain operations and resource consumption

The crate has no runtime dependencies on `apm2-core`, establishing a clean contract boundary that permits alternative runtime implementations. All types are `Send + Sync` for concurrent contexts.

**Crate path:** `apm2_holon`

---

## Module: traits

### `Holon` Trait

The core trait defining the contract surface for holonic agents.

```rust
pub trait Holon: Send + Sync {
    type Input: Send + Sync;
    type Output: Send + Sync;
    type State: Send + Sync;

    fn intake(&mut self, input: Self::Input, lease_id: &str) -> Result<(), HolonError>;
    fn execute_episode(&mut self, ctx: &EpisodeContext) -> Result<EpisodeResult<Self::Output>, HolonError>;
    fn emit_artifact(&self, artifact: Artifact) -> Result<(), HolonError>;
    fn escalate(&mut self, reason: &str) -> Result<(), HolonError>;
    fn should_stop(&self, ctx: &EpisodeContext) -> StopCondition;
    fn state(&self) -> &Self::State;

    // Default implementations
    fn holon_id(&self) -> Option<&str> { None }
    fn type_name(&self) -> &'static str { std::any::type_name::<Self>() }
}
```

**Associated Types:**
- `Input`: Work specification type accepted by `intake()`
- `Output`: Result type produced by completed episodes
- `State`: Internal state accessible via `state()` for checkpointing

**Invariants:**
- All associated types must implement `Send + Sync`
- `intake()` must validate the lease before preparing internal state
- `execute_episode()` must respect budget constraints in context
- `emit_artifact()` is called during execution to log evidence
- `escalate()` is called when work cannot be completed locally
- `should_stop()` must be deterministic given the same context

**Contracts:**
- `intake(input, lease_id)`: Validates and accepts work assignment. Returns `HolonError::InvalidInput` on validation failure, `HolonError::InvalidLease` if lease is invalid.
- `execute_episode(ctx)`: Executes one bounded episode. Returns `HolonError::EpisodeExecutionFailed` on failure, `HolonError::BudgetExhausted` if budget exceeded.
- `emit_artifact(artifact)`: Returns `HolonError::ArtifactEmissionFailed` if ledger write fails.
- `escalate(reason)`: Returns `HolonError::EscalationFailed` if escalation cannot be performed.

**Lifecycle:**
1. **Intake**: Holon receives work via `intake()`, validating the lease
2. **Execute**: Episodes are executed via `execute_episode()` until a stop condition
3. **Emit**: Artifacts are produced via `emit_artifact()` during execution
4. **Complete/Escalate**: Work either completes or is escalated via `escalate()`

### `MockHolon` (test-utils feature)

```rust
#[cfg(any(test, feature = "test-utils"))]
pub struct MockHolon {
    pub id: String,
    pub state: u64,
    pub intake_called: bool,
    pub episodes_executed: u64,
    pub episodes_until_complete: u64,
    pub fail_next_episode: bool,
    pub escalate_next_episode: bool,
    pub emitted_artifacts: Vec<Artifact>,
}
```

Used for testing holon-related code. Configurable for various test scenarios.

---

## Module: context

### `EpisodeContext`

Context for a single episode of holon execution. Provides identification, budget constraints, and progress state.

```rust
pub struct EpisodeContext {
    work_id: String,
    lease_id: String,
    episode_number: u64,
    max_episodes: Option<u64>,
    remaining_tokens: Option<u64>,
    remaining_time_ms: Option<u64>,
    goal_spec: Option<String>,
    progress_state: Option<String>,
    parent_holon_id: Option<String>,
    started_at_ns: u64,
}
```

**Builder Pattern:**
```rust
let ctx = EpisodeContext::builder()
    .work_id("work-123")
    .lease_id("lease-456")
    .episode_number(1)
    .max_episodes(10)
    .remaining_tokens(1000)
    .remaining_time_ms(60_000)
    .goal_spec("Complete the task")
    .progress_state("50% done")
    .parent_holon_id("parent-789")
    .build();
```

**Invariants:**
- `work_id` and `lease_id` are required (builder panics if missing)
- `episode_number` defaults to 1 if not specified
- `started_at_ns` defaults to current timestamp if not specified

**Key Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `is_first_episode()` | `bool` | True if `episode_number == 1` |
| `episode_limit_reached()` | `bool` | True if `episode_number >= max_episodes` |
| `tokens_exhausted()` | `bool` | True if `remaining_tokens == Some(0)` |
| `time_exhausted()` | `bool` | True if `remaining_time_ms == Some(0)` |
| `any_budget_exhausted()` | `bool` | True if any budget dimension is exhausted |
| `next_episode(tokens_used, time_used_ms)` | `EpisodeContext` | Derives context for next episode with decremented budgets |
| `with_progress(progress)` | `EpisodeContext` | Returns new context with updated progress state |

**Budget Decrement Behavior:**
- `next_episode()` uses `saturating_sub` for token and time deduction
- `None` values remain `None` (no budget tracking for that dimension)

---

## Module: result

### `EpisodeResult<T>`

Captures the outcome of a single episode of holon execution.

```rust
pub struct EpisodeResult<T> {
    outcome: EpisodeOutcome,
    output: Option<T>,
    tokens_consumed: u64,
    time_consumed_ms: u64,
    progress_update: Option<String>,
    artifact_count: u64,
}
```

**Factory Methods:**
```rust
EpisodeResult::completed(output)           // Goal achieved, output provided
EpisodeResult::continuation()              // More episodes needed
EpisodeResult::continue_with_progress(msg) // Continue with progress update
EpisodeResult::failed()                    // Recoverable failure
EpisodeResult::escalated()                 // Work escalated to supervisor
EpisodeResult::interrupted()               // Interrupted (e.g., budget exhausted)
```

**Builder Methods:**
```rust
result.with_tokens_consumed(100)
      .with_time_consumed_ms(5000)
      .with_progress("Step 1 complete")
      .with_artifact_count(2)
```

**State Queries:**

| Method | Returns | Description |
|--------|---------|-------------|
| `is_completed()` | `bool` | True for `Completed` outcome |
| `needs_continuation()` | `bool` | True for `NeedsContinuation` outcome |
| `is_failed()` | `bool` | True for `Failed` outcome |
| `is_escalated()` | `bool` | True for `Escalated` outcome |
| `is_interrupted()` | `bool` | True for `Interrupted` outcome |
| `is_terminal()` | `bool` | True for `Completed`, `Failed`, or `Escalated` |

### `EpisodeOutcome`

```rust
pub enum EpisodeOutcome {
    Completed,        // Work complete, no more episodes needed
    NeedsContinuation,// Episode finished but more work needed
    Failed,           // Episode failed with recoverable error
    Escalated,        // Work escalated to supervisor
    Interrupted,      // Episode interrupted (e.g., budget exhausted)
}
```

**Terminal Outcomes:** `Completed`, `Failed`, `Escalated`
**Non-Terminal Outcomes:** `NeedsContinuation`, `Interrupted`

---

## Module: stop

### `StopCondition`

Conditions under which a holon should stop executing episodes.

```rust
#[non_exhaustive]
pub enum StopCondition {
    Continue,
    GoalSatisfied,
    BudgetExhausted { resource: String },
    MaxEpisodesReached { count: u64 },
    TimeoutReached { limit_ms: u64 },
    ExternalSignal { signal: String },
    Stalled { reason: String },
    ErrorCondition { error: String },
    Escalated { reason: String },
    PolicyViolation { policy: String },
}
```

**Factory Methods:**
```rust
StopCondition::budget_exhausted("tokens")
StopCondition::max_episodes_reached(10)
StopCondition::timeout_reached(5000)
StopCondition::external_signal("SIGTERM")
StopCondition::stalled("no progress")
StopCondition::error("critical failure")
StopCondition::escalated("beyond scope")
StopCondition::policy_violation("no_unsafe_code")
```

**Classification Methods:**

| Method | Description |
|--------|-------------|
| `should_stop()` | True for all variants except `Continue` |
| `is_successful()` | True for `GoalSatisfied` or `Escalated` |
| `is_resource_limit()` | True for `BudgetExhausted`, `MaxEpisodesReached`, `TimeoutReached` |
| `is_error()` | True for `ErrorCondition` or `PolicyViolation` |
| `is_stalled()` | True for `Stalled` |

**Exit Codes (Unix conventions):**
| Code | Conditions |
|------|------------|
| 0 | `Continue`, `GoalSatisfied`, `Escalated` (success) |
| 1 | `ErrorCondition`, `Stalled` (general error) |
| 2 | `BudgetExhausted`, `MaxEpisodesReached`, `TimeoutReached` (resource limit) |
| 3 | `ExternalSignal` |
| 4 | `PolicyViolation` |

---

## Module: artifact

### `Artifact`

Evidence produced during holon execution and logged to the ledger.

```rust
pub struct Artifact {
    id: String,
    kind: String,
    work_id: String,
    episode_id: Option<String>,
    content: Option<String>,
    content_hash: Option<String>,
    mime_type: Option<String>,
    size_bytes: Option<u64>,
    path: Option<String>,
    created_at_ns: u64,
    metadata: Vec<(String, String)>,
}
```

**Builder Pattern:**
```rust
let artifact = Artifact::builder()
    .id("art-custom-123")       // Optional, auto-generated if omitted
    .kind("code_change")        // Required
    .work_id("work-456")        // Required
    .episode_id("ep-789")
    .content("Some content here")
    .content_hash("blake3:abc123")
    .mime_type("text/plain")
    .size_bytes(1024)
    .path("/tmp/artifact.txt")
    .created_at_ns(1_000_000_000)
    .metadata("author", "holon-1")
    .metadata("version", "1.0")
    .build();
```

**Invariants:**
- `kind` and `work_id` are required (builder panics if missing)
- `id` defaults to UUID-based format `art-{uuid}`
- `created_at_ns` defaults to current timestamp

### Predefined Artifact Kinds

```rust
pub mod kinds {
    pub const CODE_CHANGE: &str = "code_change";
    pub const DOCUMENT: &str = "document";
    pub const TEST_RESULT: &str = "test_result";
    pub const LOG: &str = "log";
    pub const CHECKPOINT: &str = "checkpoint";
    pub const DECISION: &str = "decision";
    pub const ERROR: &str = "error";
    pub const METRIC: &str = "metric";
}
```

---

## Module: error

### `HolonError`

Errors that can occur during holon lifecycle operations.

```rust
pub enum HolonError {
    InvalidLease { lease_id: String, reason: String },
    LeaseExpired { lease_id: String },
    BudgetExhausted { resource: String, used: u64, limit: u64 },
    InvalidInput { reason: String },
    EpisodeExecutionFailed { reason: String, recoverable: bool },
    ArtifactEmissionFailed { reason: String },
    EscalationFailed { reason: String },
    InvalidState { expected: String, actual: String },
    MissingContext { field: String },
    ResourceExhausted { reason: String },
    Internal(String),
}
```

**Factory Methods:**
```rust
HolonError::invalid_lease("lease-123", "not signed")
HolonError::lease_expired("lease-456")
HolonError::budget_exhausted("tokens", 1000, 500)
HolonError::invalid_input("empty prompt")
HolonError::episode_failed("timeout", true)  // recoverable
HolonError::episode_failed("critical failure", false)  // not recoverable
HolonError::artifact_failed("ledger unavailable")
HolonError::escalation_failed("no supervisor")
HolonError::invalid_state("Ready", "Running")
HolonError::missing_context("work_id")
HolonError::resource_exhausted("max attempts exceeded")
HolonError::internal("unexpected panic")
```

**Classification Methods:**

| Method | Description |
|--------|-------------|
| `is_recoverable()` | True only for recoverable `EpisodeExecutionFailed` and `ArtifactEmissionFailed` |
| `should_escalate()` | True for non-recoverable errors requiring supervisor intervention |
| `error_class()` | Returns `ErrorClass` enum for metrics/monitoring |

### `ErrorClass`

```rust
pub enum ErrorClass {
    Lease,          // InvalidLease, LeaseExpired
    Budget,         // BudgetExhausted, ResourceExhausted
    Validation,     // InvalidInput, MissingContext
    Execution,      // EpisodeExecutionFailed
    Infrastructure, // ArtifactEmissionFailed, EscalationFailed, InvalidState, Internal
}
```

---

## Module: work

### `WorkObject`

A work object representing a unit of work in the holonic coordination framework.

```rust
pub struct WorkObject {
    id: WorkId,
    title: String,
    lifecycle: WorkLifecycle,
    version: u64,
    lease_id: Option<String>,
    requirement_ids: Vec<RequirementId>,
    artifact_ids: Vec<ArtifactId>,
    attempts: Vec<AttemptRecord>,
    created_at_ns: u64,
    updated_at_ns: u64,
    parent_work_id: Option<WorkId>,
    state_reason: Option<String>,
    metadata: Vec<(String, String)>,
}
```

**Limits (DoS prevention):**
```rust
pub const MAX_ATTEMPTS: usize = 100;
pub const MAX_METADATA_ENTRIES: usize = 50;
```

**Construction:**
```rust
let work = WorkObject::new("work-123", "Implement feature X");
let work = WorkObject::new_with_timestamp("work-123", "Test", 1000);  // For testing
```

**Key Methods:**

| Method | Description |
|--------|-------------|
| `version()` | Monotonically increasing version for optimistic concurrency |
| `is_terminal()` | True if in `Completed`, `Failed`, or `Cancelled` |
| `is_successful()` | True if in `Completed` |
| `attempt_count()` | Number of attempts made |
| `current_attempt()` | Most recent attempt record, if any |
| `bind_requirement(id)` | Adds requirement binding (deduplicates) |
| `add_artifact(id)` | Adds artifact reference |
| `set_metadata(key, value)` | Adds/updates metadata (enforces limit) |

### `WorkLifecycle`

State machine for work lifecycle.

```rust
pub enum WorkLifecycle {
    Created,     // Work created but not yet assigned
    Leased,      // Work assigned to a holon via lease
    InProgress,  // Work actively being executed
    Blocked,     // Work waiting for external dependencies
    Completed,   // Work finished successfully (terminal)
    Failed,      // Work failed and cannot be retried (terminal)
    Escalated,   // Work escalated to supervisor
    Cancelled,   // Work cancelled (terminal)
}
```

**State Machine Transitions:**

```
Created -----> Leased -----> InProgress -----> Completed (terminal)
   |              |              |
   |              |              +-----> Failed (terminal)
   |              |              |
   |              |              +-----> Escalated -----> InProgress
   |              |              |           |
   |              |              |           +-----> Cancelled (terminal)
   |              |              |
   |              |              +-----> Blocked -----> InProgress
   |              |                          |
   |              |                          +-----> Escalated
   |              |                          |
   |              |                          +-----> Cancelled (terminal)
   |              |
   |              +-----> Cancelled (terminal)
   |
   +-----> Cancelled (terminal)
```

**Valid Transitions:**

| From | Valid Targets |
|------|---------------|
| `Created` | `Leased`, `Cancelled` |
| `Leased` | `InProgress`, `Cancelled` |
| `InProgress` | `Blocked`, `Completed`, `Failed`, `Escalated` |
| `Blocked` | `InProgress`, `Escalated`, `Cancelled` |
| `Escalated` | `InProgress`, `Cancelled` |
| `Completed` | (none - terminal) |
| `Failed` | (none - terminal) |
| `Cancelled` | (none - terminal) |

**State Query Methods:**

| Method | Description |
|--------|-------------|
| `is_terminal()` | True for `Completed`, `Failed`, `Cancelled` |
| `is_successful()` | True for `Completed` |
| `is_active()` | True for `InProgress` |
| `is_waiting()` | True for `Created`, `Leased`, `Blocked`, `Escalated` |
| `valid_transitions()` | Returns valid target states |
| `can_transition_to(target)` | True if transition is valid |

**Transition Methods:**
```rust
work.transition_to_leased("lease-456")?;
work.transition_to_in_progress()?;
work.transition_to_blocked("waiting for dependency")?;
work.transition_to_completed()?;
work.transition_to_failed("timeout")?;
work.transition_to_escalated("beyond scope")?;
work.transition_to_cancelled("abandoned")?;

// With explicit timestamps (for testing/replay)
work.transition_to_leased_at("lease-456", timestamp_ns)?;
```

**Invariants:**
- Version increments on every state transition or mutation
- Invalid transitions return `HolonError::InvalidState`
- Terminal states allow no further transitions
- `transition_to_cancelled()` clears the lease_id
- `transition_to_in_progress()` clears the state_reason

### `AttemptRecord`

Record of a single execution attempt on a work object.

```rust
pub struct AttemptRecord {
    attempt_id: String,
    episode_id: EpisodeId,
    lease_id: String,
    started_at_ns: u64,
    ended_at_ns: Option<u64>,
    outcome: AttemptOutcome,
    tokens_consumed: u64,
    artifact_ids: Vec<ArtifactId>,
    error_message: Option<String>,
}
```

**Construction:**
```rust
let attempt = AttemptRecord::new("att-1", "ep-1", "lease-1", started_at_ns);
```

**Mutation Methods:**
```rust
attempt.complete(ended_at_ns, tokens_consumed);
attempt.fail(ended_at_ns, "timeout");
attempt.interrupt(ended_at_ns, tokens_consumed);
attempt.escalate(ended_at_ns);
attempt.add_artifact("art-1");
attempt.add_tokens(100);
```

### `AttemptOutcome`

```rust
pub enum AttemptOutcome {
    InProgress,  // Attempt still running
    Completed,   // Attempt completed successfully
    Failed,      // Attempt failed with recoverable error
    Interrupted, // Attempt interrupted (e.g., budget exhausted)
    Escalated,   // Attempt resulted in escalation
}
```

### `WorkLifecycleEvent`

Event emitted when a work object transitions state (for ledger recording).

```rust
pub struct WorkLifecycleEvent {
    pub work_id: WorkId,
    pub from_state: WorkLifecycle,
    pub to_state: WorkLifecycle,
    pub timestamp_ns: u64,
    pub lease_id: Option<String>,
    pub reason: Option<String>,
    pub attempt_id: Option<String>,
}
```

---

## Module: skill

Skill frontmatter parsing and holon configuration.

### `SkillFrontmatter`

Parsed YAML content from skill markdown files.

```rust
pub struct SkillFrontmatter {
    pub name: String,
    pub description: String,
    pub user_invocable: bool,  // defaults to true
    pub holon: Option<HolonConfig>,
}
```

### `HolonConfig`

Configuration for a skill operating as a holon.

```rust
#[serde(deny_unknown_fields)]
pub struct HolonConfig {
    pub contract: HolonContract,
    pub stop_conditions: StopConditionsConfig,
    pub tools: Option<Vec<String>>,  // None = no tools permitted (fail-close)
}
```

**Security:** Uses `deny_unknown_fields` to prevent fail-open behavior from typos.

**Tool Access Semantics:**
- `None` (omitted): No tools permitted (maximum restriction)
- `Some([])` (empty): No tools permitted
- `Some([...])`: Only listed tools permitted

### `HolonContract`

```rust
#[serde(deny_unknown_fields)]
pub struct HolonContract {
    pub input_type: String,
    pub output_type: String,
    pub state_type: Option<String>,  // None = stateless
}
```

### `StopConditionsConfig`

```rust
#[serde(deny_unknown_fields)]
pub struct StopConditionsConfig {
    pub max_episodes: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub budget: HashMap<String, u64>,
    pub max_stall_episodes: Option<u64>,
}
```

**Invariants:**
- At least one stop condition must be configured
- All values must be > 0 if specified
- Empty budget resource names are rejected

### Parsing Functions

```rust
// Parse from string content
pub fn parse_frontmatter(content: &str) -> Result<(SkillFrontmatter, &str), SkillParseError>;

// Parse from file path
pub fn parse_skill_file(path: &Path) -> Result<(SkillFrontmatter, String), SkillParseError>;
```

**Frontmatter Format:**
```yaml
---
name: my-skill
description: A skill that does something useful
user-invocable: true
holon:
  contract:
    input_type: TaskRequest
    output_type: TaskResult
  stop_conditions:
    max_episodes: 10
    timeout_ms: 300000
    budget:
      tokens: 100000
  tools:
    - read_file
    - write_file
---

# Skill Content
...
```

### `SkillParseError`

```rust
pub enum SkillParseError {
    IoError(std::io::Error),
    InvalidFrontmatter(String),
    YamlError(serde_yaml::Error),
    InvalidHolonConfig(String),
}
```

---

## Module: resource

Resource management for holonic execution implementing Axiom III (Bounded Authority).

### Submodule: budget

#### `Budget`

Multi-dimensional resource limits with monotonic depletion.

```rust
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

**Construction:**
```rust
let budget = Budget::new(10, 100, 10_000, 60_000);  // episodes, tool_calls, tokens, duration_ms
let budget = Budget::unlimited();  // All dimensions set to u64::MAX
let budget = Budget::default();    // All dimensions set to 0 (exhausted)
```

**Invariants:**
- All remaining values are monotonically decreasing
- Remaining values never exceed initial values
- Exhaustion is permanent once any dimension reaches zero

**Deduction Methods:**
```rust
budget.deduct_episodes(1)?;
budget.deduct_tool_calls(5)?;
budget.deduct_tokens(500)?;
budget.deduct_duration_ms(1000)?;

// Atomic multi-deduction (all-or-nothing)
budget.deduct(episodes, tool_calls, tokens, duration_ms)?;
```

**Exhaustion Checks:**

| Method | Description |
|--------|-------------|
| `is_exhausted()` | True if any dimension is zero |
| `episodes_exhausted()` | True if episodes are zero |
| `tool_calls_exhausted()` | True if tool calls are zero |
| `tokens_exhausted()` | True if tokens are zero |
| `duration_exhausted()` | True if duration is zero |
| `exhausted_resource()` | Returns name of first exhausted resource |

**Derivation:**
```rust
// Creates sub-budget bounded by parent's remaining values
let sub = parent.derive_sub_budget(&requested);

// Check if parent can accommodate requested budget
let can = parent.can_accommodate(&requested);
```

### Submodule: lease

#### `Lease`

Time-bounded, scoped authorization for a holon to perform work.

```rust
pub struct Lease {
    id: String,
    issuer_id: String,
    holder_id: String,
    scope: LeaseScope,
    budget: Budget,
    issued_at_ns: u64,
    expires_at_ns: u64,
    parent_lease_id: Option<String>,
    signature: Vec<u8>,
}
```

**Builder Pattern:**
```rust
let lease = Lease::builder()
    .lease_id("lease-001")           // Required
    .issuer_id("registrar-001")      // Required
    .holder_id("agent-001")          // Required
    .scope(scope)                    // Required
    .budget(budget)                  // Required
    .expires_at_ns(2_000_000_000)    // Required
    .issued_at_ns(1_000_000_000)     // Optional, defaults to now
    .parent_lease_id("parent-lease") // Optional
    .signature(sig_bytes)            // Optional
    .build()?;
```

**Invariants:**
- Leases have finite lifetimes (`expires_at_ns` required)
- Child leases cannot exceed parent scope or budget
- Child expiration cannot exceed parent expiration
- Derivation deducts budget from parent (prevents resource inflation)

**Validation:**
```rust
lease.validate(current_time_ns)?;           // Checks expiration and budget
lease.validate_work_access("work-001")?;    // Checks scope for work ID
lease.validate_tool_access("read_file")?;   // Checks scope for tool
lease.validate_namespace_access("project/src/file.rs")?;  // Checks namespace
```

**Derivation:**
```rust
// Derives child lease with reduced permissions
// IMPORTANT: This deducts the budget from the parent
let child = parent.derive(
    "child-lease",
    "child-agent",
    &requested_scope,
    &requested_budget,
    requested_expires_at_ns,
    issued_at_ns,
)?;
```

**Signing:**
```rust
let bytes = lease.signing_bytes();  // Canonical JSON for signing
let is_signed = lease.is_signed();
```

### Submodule: scope

#### `LeaseScope`

Authority boundaries for lease operations.

```rust
pub struct LeaseScope {
    work_ids: BTreeSet<String>,
    tools: BTreeSet<String>,
    namespaces: BTreeSet<String>,
    unlimited: bool,
}
```

**Construction:**
```rust
let scope = LeaseScope::empty();      // No permissions
let scope = LeaseScope::unlimited();  // All permissions

let scope = LeaseScope::builder()
    .work_ids(["work-001", "work-002"])
    .tools(["read_file", "write_file"])
    .namespaces(["project/src"])
    .build();

// Single-item methods
let scope = LeaseScope::builder()
    .work_id("work-001")
    .tool("read_file")
    .namespace("project/src")
    .build();
```

**Invariants:**
- Empty sets mean "no access" (not "unlimited")
- Only `unlimited: true` bypasses permission checks
- Path traversal (`..`) is always rejected, even for unlimited scopes

**Permission Checks:**
```rust
scope.allows_work_id("work-001")    // Exact match
scope.allows_tool("read_file")      // Exact match
scope.allows_namespace("project/src/main.rs")  // Path-aware prefix match
```

**Namespace Matching Rules:**
- `"project/src"` allows `"project/src"` (exact match)
- `"project/src"` allows `"project/src/main.rs"` (subpath)
- `"project/src"` denies `"project/src_backup"` (not a path separator)
- `"project/src"` denies `"project/../secret"` (path traversal)

**Security:** Path traversal sequences (`..`) are always rejected to prevent scope escape attacks.

**Set Operations:**
```rust
let is_super = parent.is_superset_of(&child);
let is_sub = child.is_subset_of(&parent);
let intersection = scope1.intersect(&scope2);
let derived = parent.derive_sub_scope(&requested);
```

**Derivation Validation:**
```rust
parent.validate_derivation(&requested)?;  // Returns InvalidDerivation if requested > parent
```

### Submodule: error

#### `ResourceError`

Errors for resource management operations.

```rust
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

**Factory Methods:**
```rust
ResourceError::budget_exhausted("tokens", 1000, 500)
ResourceError::lease_expired("lease-123", 1_000_000_000)
ResourceError::scope_violation("cannot access tool X")
ResourceError::invalid_signature("lease-456")
ResourceError::invalid_derivation("scope exceeds parent")
ResourceError::missing_field("issuer_id")
ResourceError::invalid_lease_id("bad-id")
ResourceError::operation_not_permitted("lease already expired")
```

**Classification:**
```rust
error.is_budget_exhausted()  // True for BudgetExhausted
error.is_lease_expired()     // True for LeaseExpired
error.is_recoverable()       // Always false (all resource errors are non-recoverable)
```

---

## Cross-Module Relationships

```
                    +-----------------+
                    |     Holon       |
                    |     (trait)     |
                    +--------+--------+
                             |
         +-------------------+-------------------+
         |                   |                   |
         v                   v                   v
+----------------+  +----------------+  +----------------+
| EpisodeContext |  | EpisodeResult  |  |   Artifact     |
|                |  |                |  |                |
| - work_id      |  | - outcome      |  | - work_id      |
| - lease_id     |  | - output       |  | - content_hash |
| - budget info  |  | - consumption  |  | - metadata     |
+-------+--------+  +-------+--------+  +----------------+
        |                   |
        v                   v
+----------------+  +----------------+
| StopCondition  |  |  HolonError    |
|                |  |                |
| - Continue     |  | - InvalidLease |
| - GoalSatisfied|  | - BudgetExh'd  |
| - Budget...    |  | - ...          |
+----------------+  +----------------+

+----------------+          +----------------+
|   WorkObject   | -------> | AttemptRecord  |
|                |          |                |
| - lifecycle    |          | - outcome      |
| - lease_id     |          | - tokens_used  |
| - attempts[]   |          | - artifacts[]  |
+-------+--------+          +----------------+
        |
        v
+----------------+
| WorkLifecycle  |
|                |
| State Machine  |
+----------------+

+----------------+          +----------------+
|     Lease      | -------> |   LeaseScope   |
|                |          |                |
| - scope        |          | - work_ids     |
| - budget       |          | - tools        |
| - expires_at   |          | - namespaces   |
+-------+--------+          +----------------+
        |
        v
+----------------+
|     Budget     |
|                |
| - episodes     |
| - tool_calls   |
| - tokens       |
| - duration_ms  |
+----------------+

+----------------+
|SkillFrontmatter| -------> HolonConfig --> StopConditionsConfig
|                |              |
| - name         |              v
| - holon config |        HolonContract
+----------------+
```

**Key Relationships:**
1. `Holon` trait uses `EpisodeContext`, `EpisodeResult`, `Artifact`, `StopCondition`, `HolonError`
2. `WorkObject` contains `WorkLifecycle` state and `AttemptRecord` history
3. `Lease` contains `LeaseScope` and `Budget`
4. Lease derivation creates parent-child relationships with budget deduction
5. `SkillFrontmatter` optionally contains `HolonConfig` for holon-enabled skills
6. `spawn_holon` orchestrates the full lifecycle: work creation, lease issuance, episode execution

---

## Module: spawn

Holon spawning and orchestration functions.

### `spawn_holon`

Main orchestration function that ties together all components to execute a holon.

```rust
pub fn spawn_holon<H, F>(
    holon: &mut H,
    input: H::Input,
    config: SpawnConfig,
    clock: F,
) -> Result<SpawnResult<H::Output>, HolonError>
where
    H: Holon,
    F: FnMut() -> u64;
```

**Lifecycle Steps:**
1. Creates `WorkObject` to track work
2. Issues `Lease` authorizing execution
3. Calls `Holon::intake` with input
4. Runs episode loop via `EpisodeController`
5. Emits ledger events for work and lease lifecycle
6. Handles escalation and forwards to caller
7. Returns `SpawnResult` with final state

### `SpawnConfig`

Configuration for spawning a holon.

```rust
pub struct SpawnConfig {
    pub work_id: String,
    pub work_title: String,
    pub issuer_id: String,
    pub holder_id: String,
    pub scope: LeaseScope,
    pub budget: Budget,
    pub expires_at_ns: Option<u64>,
    pub goal_spec: Option<String>,
    pub episode_config: EpisodeControllerConfig,
}
```

**Builder Pattern:**
```rust
let config = SpawnConfig::builder()
    .work_id("work-001")
    .work_title("Process task")
    .issuer_id("registrar")
    .holder_id("agent")
    .scope(LeaseScope::unlimited())
    .budget(Budget::new(10, 100, 10_000, 60_000))
    .expires_at_ns(1_000_000_000)
    .goal_spec("Complete the task")
    .build()?;
```

### `SpawnResult<T>`

Result of spawning and executing a holon.

```rust
pub struct SpawnResult<T> {
    pub work: WorkObject,
    pub outcome: SpawnOutcome,
    pub events: Vec<LedgerEvent>,
    pub episode_events: Vec<EpisodeEvent>,
    pub output: Option<T>,
    pub episodes_executed: u64,
    pub tokens_consumed: u64,
}
```

**Query Methods:**
| Method | Returns | Description |
|--------|---------|-------------|
| `is_successful()` | `bool` | True if outcome is `Completed` |
| `is_escalated()` | `bool` | True if outcome is `Escalated` |
| `is_error()` | `bool` | True if outcome is `Error` |
| `escalation_reason()` | `Option<&str>` | Escalation reason if applicable |

### `SpawnOutcome`

```rust
pub enum SpawnOutcome {
    Completed,
    BudgetExhausted { resource: String },
    MaxEpisodesReached,
    Blocked { reason: String },
    Escalated { reason: String },
    Error { error: String, recoverable: bool },
}
```

**Invariants:**
- `spawn_holon` always creates valid `WorkObject` and `Lease`
- Episode loop runs until a terminal condition
- All lifecycle transitions emit corresponding ledger events
- Escalation reasons are preserved and propagated to caller
- Budget exhaustion keeps work in `InProgress` for potential continuation

---

## References

- [rust-textbook: 04_ownership_borrowing_model.md] - Ownership patterns for state management
- [rust-textbook: 06_traits_generics_coherence.md] - Trait design with associated types
- [rust-textbook: 07_errors_panics_diagnostics.md] - Error type design with `thiserror`
- [rust-textbook: 12_api_design_stdlib_quality.md] - Builder pattern, method naming conventions
- [rust-textbook: 17_testing_fuzz_miri_evidence.md] - Property-based testing for invariants
- [rust-textbook: 25_time_monotonicity_determinism.md] - Timestamp handling and monotonic invariants
