# Codebase Context Pack (CCP)

**Definition:** A structured, machine-readable index of the repository's current state, serving as the "Repository Truth" for agentic operations.

**Purpose:** Prevents agents from hallucinating extension points or architectural components by providing a deterministic map of what exists.

## Component Breakdown

1.  **Component Atlas** (`component_atlas.yaml`):
    -   Defines the physical and logical boundaries of software modules (crates, services).
    -   Used by `Idea Compiler` to map PRD requirements to specific implementation locations.
2.  **Public API Inventory** (`public_api_inventory.yaml`):
    -   Lists all `pub` functions, structs, and traits exposed by components.
    -   Used by `RFC Frame` stage to valid imports and detect breaking changes.
3.  **Crate Graph** (`crate_graph.json`):
    -   Machine-readable output of `cargo metadata`.
    -   Used to detect circular dependencies and architectural violations.
4.  **Decision Index** (`prior_decisions_index.yaml`):
    -   Index of `documents/reviews/` and accepted RFCs.
    -   Used to ensure new plans do not litigate settled architectural decisions.
5.  **Hotspots** (`hotspots.yaml`):
    -   Heatmap of recent churn and complexity (from `gix` and `rust-code-analysis`).
    -   Used by `Refactor Radar` to suggest maintenance work.

## SDLC Interaction

-   **Generation:** Produced by the CLI command `apm2 factory ccp build`. This scans the current `git` working tree and emits artifacts to `evidence/prd/<PRD-ID>/ccp/`.
-   **Consumption (Planning):** The `Idea Compiler` (specifically `Impact_Map` and `RFC_Frame` stages) loads the CCP to ground high-level intents in concrete file paths.
-   **Consumption (Coding):** Coding agents (like `dev-eng-ticket`) read the CCP to understand available tools and libraries before writing code.
-   **Invariant:** "No Plan without Truth." A CCP must be generated before an RFC can be drafted.