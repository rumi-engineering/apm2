# Policy

**Agent-Native Definition**: **Policy** is "Governance as Code". It is the system of rules that constrains and authorizes agent behavior. Implemented via a **Default-Deny** model, policies ensure that agents can only perform actions (file access, network requests, tool usage) that are explicitly explicitly allowed.

Policies are not just guidelines; they are executable code enforced by the `PolicyEngine` at runtime.

## Core Concepts

### Default-Deny Model
The foundational security principle. By default, an agent has **zero** permissions. A policy must explicitly grant permission for every capability:
*   **Tools**: Which tools can be invoked?
*   **Filesystem**: Which paths can be read/written?
*   **Network**: Which hosts/ports can be accessed?
*   **Resources**: What is the budget (tokens, time)?
*   **Selectors/Artifacts**: Which stable IDs / content hashes can be fetched (hermetic consumption)?

### Policy Engine
The `PolicyEngine` is the kernel component that evaluates every agent action against the active policy. It is:
*   **Deterministic**: The same policy and same action always yield the same decision.
*   **Fail-Closed**: If the policy is invalid or evaluation fails, the action is denied.

### Conflict Handling (Precedence)
When constraints conflict, the system must have a deterministic rule rather than ad hoc exceptions. APM2's default precedence is:

`Security/Containment > Verification/Correctness > Liveness/Progress`

Practically: if the smallest sufficient context/capability set violates policy, the system must fail-closed and force decomposition/escalation, recording a decision/defect.

### Policy Lifecycle
1.  **Definition**: Policies are defined in YAML.
2.  **Loading**: `LoadedPolicy` validates the YAML and computes a hash.
3.  **Enforcement**: The engine creates `PolicyEvent`s (e.g., `PolicyLoaded`) and enforces rules during episodes.

## Data Structure References
*   **`PolicyEngine`**: The runtime enforcer.
*   **`PolicyDocument`**: The YAML schema for defining rules.
*   **`Decision`**: The evaluation result (`allow` or `deny`).

## See Also
*   **Episode**: The execution context constrained by policy.
*   **Gate**: Policies can define which gates must pass.
*   **Content Resolver**: enables scoped reads without ambient filesystem authority.
