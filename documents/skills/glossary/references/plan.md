# Plan

**Agent-Native Definition**: A **Plan** is the intent structure that precedes and justifies a **ChangeSet**. It serves as the "Spec-of-Record," capturing the requirements, constraints, and design decisions for a unit of work. A Plan is immutable once approved (becoming a "Plan-of-Record"), providing a stable reference against which implementation and verification are measured.

## Core Concepts

### Intent Specification
A Plan transforms abstract goals into concrete specifications. It is not just a "todo list" item but a structured artifact containing requirements, acceptance criteria, and context. Agents generate Plans during the refinement phase (e.g., `WorkType::PrdRefinement`) before any code is written.

### Traceability
The Plan connects the "Why" (Business Goals/PRDs) to the "How" (ChangeSets). By requiring every ChangeSet to reference a Plan-of-Record, the system enforces full traceability from the initial request down to the specific lines of code changed.

### Immutability
To prevent "drift," a Plan is hashed upon approval. Any change to the requirements necessitates a new Plan or a formal revision, ensuring that the implementation target is always clear and agreed upon.

## Data Structure References

*   **`apm2_core::work::Work`** (`crates/apm2-core/src/work/state.rs`): The underlying data structure. A Plan is a `Work` instance (typically `WorkType::PrdRefinement` or `RfcRefinement`) that produces a spec snapshot.
*   **`apm2_core::work::Work::spec_snapshot_hash`** (`crates/apm2-core/src/work/state.rs`): The field that stores the cryptographic hash of the approved specification.
*   **`apm2_holon::work::WorkObject`** (`crates/apm2-holon/src/work.rs`): The agent-side wrapper used to manage the Plan's lifecycle.

## See Also

*   **[ChangeSet](change_set.md)**: The implementation unit that satisfies the Plan.
*   **[Artifact](artifact.md)**: The concrete output (e.g., a PRD document) referenced by the Plan.
*   **[Work Substrate](work_substrate.md)**: The lifecycle system managing Plans.
