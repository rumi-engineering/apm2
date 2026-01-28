# Context Compilation

**Definition:** The upstream process of gathering, pruning, and indexing the specific artifacts required for a task, resulting in a **ContextPack**.

**The Shift from Discovery to Compilation:**
Traditional agent workflows rely on the agent to "find" the relevant files. **Context Compilation** moves this complexity to an earlier stage in the SDLC. A "Planner Holon" or "Compiler Holon" uses requirements and repository graphs to assemble a bounded context before the "Worker Holon" is spawned.

## Key Principles
- **Pruning:** Removing irrelevant boilerplate to fit within a `ContextBudget`.
- **Content Addressing:** Binding the context to specific hashes to prevent "drift by update."
- **Sufficiency (role-relative):** The compiled pack must be sufficient for the task *within the agent's granted capabilities*. If the smallest sufficient pack violates containment policy, the system must fail-closed and decompose/escalate.
- **Commitment + addressability:** Packs carry a **View Commitment** and **Selectors** so omitted referenced facts remain auditable.

## See Also
- **ContextPack**: The output of compilation.
- **View Commitment**: how bounded packs stay synchronized with an unbounded ledger.
- **Selector**: how omitted referenced facts remain retrievable.
- **Zero-Tool Ideal (ZTI)**: The design goal.
