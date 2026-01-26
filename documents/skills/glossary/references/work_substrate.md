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

## Codebase Implementation

-   **`apm2-core`:**
    -   Implements the `Ledger` (append-only log).
    -   Defines `Event` enums (protobuf) for all state transitions.
    -   Provides `Reducer` traits to compute current state from history.
-   **Storage:**
    -   **Ledger:** SQLite in WAL mode.
    -   **Artifacts:** Content-Addressed Storage (CAS) on disk.

## SDLC Interaction

-   **Transition from GitHub:** The Work Substrate replaces "Pull Requests" with "ChangeSets" and "Issues" with "Tickets".
-   **Flow:**
    1.  User creates a `Plan` (YAML).
    2.  `Idea Compiler` compiles it into `Tickets` (YAML).
    3.  Agent accepts a `Ticket` -> `WorkStarted` event.
    4.  Agent submits `ChangeSet` -> `WorkSubmitted` event.
    5.  `AAT` verifies -> `GatePassed` event.
    6.  Merge -> `MergeReceipt` event.