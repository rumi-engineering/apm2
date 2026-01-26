# Work Substrate

**Definition:** The authoritative coordination plane for the software factory, consisting of Work Objects, a durable Event Ledger, and deterministic Projections.

**Core Doctrine:**
-   **Spec/State Separation:** Specification content (YAML files in `documents/work/`) is distinct from workflow state (derived from the Ledger).
-   **Event Authority:** Truth is defined by the append-only event log (SQLite WAL), not by mutable database tables or external tools (GitHub/Jira).

## Work Object Types

-   **Plan:** High-level intent/specification (PRD).
-   **ChangeSet:** Proposed modifications (Patches/Commits).
-   **GateRun:** Execution of verification protocols (AAT, Lint, Security).
-   **Finding:** Structured defect report with severity and location.
-   **EvidenceBundle:** Content-addressed proofs (logs, artifacts) hashed with BLAKE3.
-   **Decision:** Governed adjudication (e.g., "Accept Risk", "Approve Plan").

## Data Structure References

-   **`WorkObject`** (`crates/apm2-holon/src/work.rs`): The unit of work being tracked, containing lifecycle state and attempt history.
-   **`WorkLifecycle`** (`crates/apm2-holon/src/work.rs`): The state machine for work (e.g., `Created`, `InProgress`, `Completed`).
-   **`AttemptRecord`** (`crates/apm2-holon/src/work.rs`): A record of a single execution attempt on a work object.

## SDLC Interaction

-   **Transition from GitHub:** The Work Substrate replaces "Pull Requests" with "ChangeSets" and "Issues" with "Tickets".
-   **Flow:**
    1.  User creates a `Plan` (YAML).
    2.  `Idea Compiler` compiles it into `Tickets` (YAML).
    3.  Agent accepts a `Ticket` -> `WorkStarted` event.
    4.  Agent submits `ChangeSet` -> `WorkSubmitted` event.
    5.  `AAT` verifies -> `GatePassed` event.
    6.  Merge -> `MergeReceipt` event.