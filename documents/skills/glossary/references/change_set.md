# ChangeSet

**Agent-Native Definition**: A **ChangeSet** is the atomic unit of code evolution in the Work Substrate. It represents a proposed transition of the codebase from state A to state B, strictly bound to a **Plan** (intent) and validated by **Gates**. Unlike a Git branch, a ChangeSet is a first-class ledger object with a stable identity independent of the underlying version control mechanism.

## Core Concepts

### Atomic Evolution
A ChangeSet encapsulates a single logical change. It is not merely a collection of file edits but a state transition that must satisfy a set of invariants. The ChangeSet lifecycle (Open -> Submitted -> Reviewing -> Merged/Abandoned) is tracked on the ledger, ensuring that every code change has a complete audit trail.

### Plan Binding
Every ChangeSet must trace back to a **Plan-of-Record**. This binding ensures that no code is written without a specified intent. The ChangeSet carries a reference to the Plan's spec snapshot hash, allowing verification that the implementation matches the approved requirements.

### Ledger Integration
ChangeSets decouple work tracking from the forge (e.g., GitHub). While a ChangeSet may currently map to a Git commit range, its identity is maintained in the internal ledger. This allows agents to reason about work states without polling external APIs.

## Mapping to Git (Concrete)

In today's implementation, ChangeSets are often transported via Git primitives, but Git is treated as a projection:

- **Base**: the pinned commit/tree the change is intended to apply to (do not rely on a moving branch name).
- **Patch**: a commit range or patch-set whose identity can be represented by a stable digest (e.g., a canonical patch encoding hash).
- **Tip**: the resulting commit(s) in a forge/branch. This is a transport artifact until a **Merge Receipt** binds the promoted result.

Important distinction: Git `HEAD` is "what is currently checked out"; a ChangeSet is "what is proposed to change," and may be reviewed/verified without being `HEAD` in any working copy.

## Data Structure References

*   **`apm2_core::work::Work`** (`crates/apm2-core/src/work/state.rs`): The underlying data structure for all work items. A ChangeSet is a `Work` instance (often with `WorkType::Ticket` or a specialized type) that tracks the lifecycle of the code change.
*   **`apm2_holon::work::WorkObject`** (`crates/apm2-holon/src/work.rs`): The agent-side representation of work, providing methods for state transitions and attempt tracking.
*   **`apm2_core::work::WorkType`** (`crates/apm2-core/src/work/state.rs`): The enumeration distinguishing ChangeSets from other work types (e.g., Plans/Refinement).

## See Also

*   **[Plan](plan.md)**: The intent specification that justifies the ChangeSet.
*   **[Work Substrate](work_substrate.md)**: The broader system in which ChangeSets operate.
*   **[Gate](gate.md)**: The verification mechanism that must pass before a ChangeSet can be merged.
