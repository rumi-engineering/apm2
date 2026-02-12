# Policy Module

> Default-deny policy evaluation engine with content-addressed YAML rules, dual-lattice taint enforcement, and authority delegation meet.

## Overview

The `apm2_core::policy` module implements the policy evaluation infrastructure for APM2 (RFC-0001). Policies are YAML documents that define rules governing agent behavior through a **default-deny** model. All policies are content-addressed via BLAKE3, ensuring deterministic evaluation: same hash guarantees same decisions.

```text
YAML Policy Document --> parse_policy() --> LoadedPolicy (content_hash)
                                               |
                                        validate_policy()
                                               |
                                   PolicyEngine::evaluate(request)
                                               |
                                       EvaluationResult (decision + rule_id)
```

The module also provides three security enforcement layers beyond basic rule evaluation:

1. **Taint/Classification** (`taint`): Dual-lattice propagation for data flow integrity and confidentiality.
2. **Attestation Floor** (`attestation_floor`): Monotonic tightening of attestation requirements across gate boundaries.
3. **Permeability** (`permeability`): Authority delegation meet for narrowing authority across holon boundaries.

### Trust Boundaries

- **Parse boundary**: YAML deserialization rejects unknown fields and malformed structure. Policy validation enforces unique rule IDs, non-empty rule lists, valid version format, and rule-type-specific field requirements.
- **Evaluation boundary**: Path patterns containing `..` are always rejected. Budget checks are a fail-closed gate evaluated before policy rules. Context firewall (CONSUME mode) restricts reads to manifest allowlists.
- **Content-address boundary**: Policy hash is computed over canonical YAML bytes via BLAKE3, enabling tamper detection and deterministic policy identity.

## Key Types

### `PolicyEngine`

```rust
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy: Arc<LoadedPolicy>,
}
```

Evaluates tool requests against a loaded policy following a default-deny model. Rules are evaluated in order; the first matching rule determines the decision.

**Invariants:**

- [INV-PO01] **Default-deny**: Unmatched requests are always denied. The `default_decision` field in the policy MUST be `Deny`.
- [INV-PO02] **Fail-closed**: Any evaluation error (missing tool, invalid path) results in denial.
- [INV-PO03] **Deterministic**: Same policy content hash + same request always produces the same decision.
- [INV-PO04] **Path traversal protection**: Paths containing `..` are always rejected before rule evaluation.

**Contracts:**

- [CTR-PO01] `evaluate(request) -> EvaluationResult` returns `decision`, `rule_id`, `rationale_code`, and `policy_hash` for every evaluation. The `rule_id` is either a matching rule's ID or `DEFAULT_DENY_RULE_ID`.
- [CTR-PO02] `evaluate_with_budget(request, tracker)` checks budget before policy rules. Budget exhaustion produces `BUDGET_EXCEEDED_RULE_ID`.
- [CTR-PO03] `evaluate_with_manifest(request, manifest, mode)` validates CONSUME-mode file reads against manifest allowlist. Context miss produces `CONTEXT_MISS_RULE_ID`.

### `LoadedPolicy`

```rust
pub struct LoadedPolicy {
    pub policy: Policy,
    pub validated: ValidatedPolicy,
    pub content_hash: [u8; 32],
}
```

A parsed, validated, and content-hashed policy ready for evaluation.

**Contracts:**

- [CTR-PO04] `LoadedPolicy::from_yaml(yaml)` parses YAML, validates structure, and computes BLAKE3 content hash. Returns `Err(PolicyError)` on any failure.

### `PolicyDocument` / `Policy` / `Rule`

```rust
pub struct PolicyDocument {
    pub policy: Policy,
}

pub struct Policy {
    pub version: String,
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<Rule>,
    pub default_decision: Decision,
}

pub struct Rule {
    pub id: String,
    pub rule_type: RuleType,
    pub decision: Decision,
    pub tool: Option<String>,
    pub paths: Vec<String>,
    pub commands: Vec<String>,
    pub budget_type: Option<BudgetType>,
    pub limit: Option<u64>,
    pub hosts: Vec<String>,
    pub ports: Vec<u16>,
    pub stable_ids: Vec<String>,
    pub condition: Option<String>,
    pub rationale_code: Option<String>,
    pub reason: Option<String>,
}
```

**Invariants:**

- [INV-PO05] **Rule ID uniqueness**: No two rules in a policy may share the same `id`.
- [INV-PO06] **Non-empty policy**: A policy MUST contain at least one rule.

### `RuleType` (enum)

```rust
pub enum RuleType {
    ToolAllow,
    ToolDeny,
    Budget,
    Network,
    Filesystem,
    Secrets,
    Inference,
    ConsumptionMode,
}
```

### `Decision` (enum)

```rust
pub enum Decision {
    Allow,
    Deny,  // default
}
```

### `PolicyError` (enum)

```rust
pub enum PolicyError {
    ReadError { path, source },
    ParseError(serde_yaml::Error),
    ValidationError { message },
    InvalidVersion { version },
    InvalidRuleType { value },
    InvalidDecision { value },
    InvalidBudgetType { value },
    DuplicateRuleId { rule_id },
    EmptyPolicy,
    MissingField { field },
    InvalidGlobPattern { rule_id, pattern, reason },
    CircularDependency { rule_id },
}
```

### `TaintEnforcementGuard` (taint submodule)

Dual-lattice enforcement for data flow integrity. Implements both taint propagation (upward lattice) and confidentiality classification (downward lattice). Declassification requires a `DeclassificationReceipt` with cryptographic preimage.

**Invariants:**

- [INV-PO07] **Lattice monotonicity**: Taint levels can only increase; classification levels can only decrease (through explicit declassification).
- [INV-PO08] **Declassification receipt**: Downgrading classification requires a valid `DeclassificationReceipt` with matching preimage.

### `AttestationFloorGuard` (attestation_floor submodule)

Enforces monotonically tightening attestation requirements across gate boundaries. Attestation levels form a total order: `None < Soft < Strong < HumanCosign`.

**Invariants:**

- [INV-PO09] **Floor monotonicity**: Attestation floor can only tighten (increase). Any attempt to weaken the floor is rejected.
- [INV-PO10] **Tier-based enforcement**: Higher risk tiers require higher minimum attestation levels.

### `AuthorityVector` / `PermeabilityReceipt` (permeability submodule)

Authority delegation meet across holon boundaries. An `AuthorityVector` has six facet dimensions, and `lattice_meet()` computes the component-wise minimum (narrowing).

**Invariants:**

- [INV-PO11] **Delegation narrowing**: `lattice_meet(parent, child)` MUST produce a vector where each facet is `<= min(parent, child)`. Authority can never widen through delegation.
- [INV-PO12] **Receipt binding**: `PermeabilityReceipt` cryptographically binds the meet result to the delegator and delegatee.

## Public API

### Parsing and Loading

- `parse_policy(yaml) -> Result<PolicyDocument, PolicyError>`
- `parse_and_validate_policy(yaml) -> Result<(PolicyDocument, ValidatedPolicy), PolicyError>`
- `LoadedPolicy::from_yaml(yaml) -> Result<LoadedPolicy, PolicyError>`
- `load_policy_from_file(path) -> Result<LoadedPolicy, PolicyError>`
- `compute_policy_hash(yaml) -> [u8; 32]`
- `validate_policy(doc) -> Result<ValidatedPolicy, PolicyError>`

### Evaluation

- `PolicyEngine::new(policy) -> PolicyEngine`
- `PolicyEngine::evaluate(request) -> EvaluationResult`
- `PolicyEngine::evaluate_with_budget(request, tracker) -> EvaluationResult`
- `PolicyEngine::evaluate_with_manifest(request, manifest, mode) -> ManifestEvaluationResult`

### Events

- `create_policy_loaded_event(loaded) -> PolicyEvent`

### Taint

- `propagate_taint(source_level, target_level) -> TaintLevel`
- `propagate_classification(source, target) -> ConfidentialityLevel`

## Examples

### Loading and Evaluating a Policy

```rust
use apm2_core::policy::{LoadedPolicy, PolicyEngine};

let yaml = r#"
policy:
  version: "1.0.0"
  name: "workspace-policy"
  rules:
    - id: "allow-workspace-read"
      type: tool_allow
      tool: "fs.read"
      paths:
        - "/workspace/**"
      decision: allow
    - id: "deny-secrets"
      type: secrets
      decision: deny
  default_decision: deny
"#;

let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
println!("Policy hash: {}", loaded.content_hash_hex());

let engine = PolicyEngine::new(&loaded);
let result = engine.evaluate(&request);

if result.is_allowed() {
    println!("Allowed by rule: {}", result.rule_id);
} else {
    println!("Denied by rule: {}", result.rule_id);
}
```

### Budget-Gated Evaluation

```rust
use apm2_core::policy::{PolicyEngine, BUDGET_EXCEEDED_RULE_ID};
use apm2_core::budget::BudgetTracker;

let result = engine.evaluate_with_budget(&request, &tracker);
if result.rule_id == BUDGET_EXCEEDED_RULE_ID {
    // Budget exceeded -- emit BudgetExceeded event and terminate
}
```

## Related Modules

- [`apm2_core::pcac`](../pcac/AGENTS.md) - PCAC authority lifecycle (consumes `PcacPolicyKnobs` from resolved policy)
- [`apm2_core::syscall`](../syscall/AGENTS.md) - Filesystem handler (executes operations authorized by policy)
- [`apm2_core::fac`](../fac/AGENTS.md) - Forge Admission Cycle (policy resolution for changesets)
- [`apm2_core::budget`](../budget/) - Budget tracking (consumed by `evaluate_with_budget`)
- [`apm2_core::context`](../context/) - Context pack manifest and firewall (consumed by `evaluate_with_manifest`)

## References

- [RFC-0001] APM2 Kernel Architecture -- default-deny policy model, content-addressed policies
- [RFC-0015] Forge Admission Cycle -- CONSUME mode context firewall
- [APM2 Rust Standards] [Testing Evidence and CI](/documents/skills/rust-standards/references/20_testing_evidence_and_ci.md) - Property-based testing patterns
