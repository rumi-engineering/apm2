# Agent Acceptance Testing (AAT)

**Definition:** A formal verification gate where an independent agent validates that a change meets its specified intent using hypothesis-driven evidence.

**Purpose:**
-   **Trust Separation:** Distinct from unit/integration tests (which verify the code works); AAT verifies the *intent* was satisfied.
-   **Falsifiability:** Uses explicit hypotheses to attempt to disprove the correctness of the implementation.
-   **Recurrence Prevention:** Failed AAT runs generate `Finding` objects that drive factory improvements.

## Core Concepts

-   **Hypothesis:** A falsifiable statement derived from the PRD/Ticket (e.g., "If I run command X with input Y, it should output Z within 5 seconds").
-   **Finding:** A structured defect report containing a `FindingSignature` (hash of the issue type) to track recurrence across the factory.
-   **FindingSignature:** Allows the factory to say "We have seen this specific type of failure 5 times this week" and trigger a `Countermeasure`.

## SDLC Interaction

-   **Trigger:** Runs automatically after `cargo test` passes in the `Ticket_Emit` or `Review` stages.
-   **Execution:**
    -   Invoked via `apm2 factory gate run --type aat`.
    -   The AAT Agent reads the `Plan-of-Record` and the modified code.
    -   It generates an `EvidenceBundle` containing logs, screenshots, or terminal captures.
-   **Blocking:** A ChangeSet cannot be merged (converted to a `Merge Receipt`) until the AAT Gate passes.
-   **Feedback Loop:** Findings from AAT are fed back into the `Refactor Radar` to improve future prompts and lint rules.