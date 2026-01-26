# Holon

**Definition:** A recursive unit of organization that functions simultaneously as an autonomous whole and as a dependent part of a larger aggregate (a Holarchy).

**Key Properties:**

-   **Janus Dualism:** Looks "up" to supervisors (submitting to constraints/budgets) and "down" to subordinates (imposing order/goals).
-   **Markov Blanket:** A statistical boundary separating internal state from external states. Interaction occurs *only* through:
    -   **Active States:** Outputs (Artifacts, Tool Requests).
    -   **Sensory States:** Inputs (Events, Work Objects).
    -   *Internal State is ephemeral and opaque.*
-   **Autonomy:** Operates within a bounded context (`EpisodeContext`) and resource limits (`Budget`).

## Codebase Implementation

-   **`apm2-holon` Crate:**
    -   Defines the `Holon` trait which all agents must implement.
    -   Provides `EpisodeContext` to scope execution (prevent infinite loops).
    -   Defines `WorkLifecycle` (Pending -> InProgress -> Verified).
-   **`apm2-daemon`:**
    -   Acts as the "Kernel Holon" or Supervisor.
    -   Manages the event ledger and enforces budgets on child holons (CLI processes).
-   **Adapters:**
    -   External agents (Claude Code, Gemini CLI) are wrapped in `Adapter` structs that normalize their I/O into the Holonic protocol.

## SDLC Interaction

-   **Agent Execution:** Every agent invocation (e.g., resolving a ticket) is treated as a **Holonic Episode**.
-   **Crash-Only Design:** If an agent gets confused or stuck, the Holon Envelope terminates the process. The state is recovered from the durable `Ledger`, not from the process memory.
-   **Recursive Planning:** A "Planner Holon" receives a high-level goal (PRD) and decomposes it into sub-goals (Tickets) for "Worker Holons."