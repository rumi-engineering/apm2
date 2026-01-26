# Impact Map

**Definition:** A deterministic mapping artifact that links high-level Requirements (from a PRD) to specific Codebase Components and Extension Points (from the CCP).

**Purpose:**
-   **Reuse-by-Default:** Forces agents to verify if functionality already exists before creating new files.
-   **Drift Prevention:** Ensures that implementation plans are grounded in the *actual* codebase state, not a hallucinated one.
-   **Machine-Checkable Design:** Allows static analysis of a plan before code is written (e.g., detecting if a plan modifies a frozen component).

## Structure

A YAML file containing:
-   **Requirement ID:** (e.g., `REQ-001`)
-   **Component ID:** (e.g., `crates/apm2-core`)
-   **Extension Point:** (e.g., `impl Reducer for X`)
-   **Rationale:** Why this component was chosen.
-   **Risk:** Duplication risk or breaking change risk.

**Context:**
Produced by the `Idea Compiler` stage `Impact_Map`.
Required input for the `RFC_Frame` stage.
