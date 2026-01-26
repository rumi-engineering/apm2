# Countermeasure

**Definition:** A specific type of `WorkObject` generated automatically when a `FindingSignature` recurs frequently enough to cross a policy threshold.

**Purpose:**
-   **Systematic Improvement:** Shifts focus from "fixing bugs" (local, ephemeral) to "improving the factory" (global, durable).
-   **Feedback Loop:** Aims to modify guardrails (Templates, Lint Rules, Gate Rubrics) so the defect class cannot recur.

## Lifecycle

1.  **Detection:** `RecurrenceReducer` counts findings by signature.
2.  **Trigger:** Count > Threshold (e.g., 5 in 7 days).
3.  **Creation:** System emits `CountermeasureProposed` event.
4.  **Implementation:** Agent claims work to implement a *preventive* fix (e.g., "Add `clippy` rule", "Update `SKILL.md`").
5.  **Validation:** `CountermeasureValidation` gate requires evidence that the fix would have caught the past instances (Corpus Replay).

**Key Differentiator:** A Bug Fix repairs the code; a Countermeasure repairs the *process* that produced the code.
