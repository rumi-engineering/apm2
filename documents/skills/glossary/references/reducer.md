# Reducer

**Definition:** A pure function that transitions state by applying an `Event` to a previous `State`.

**Purpose:**
-   **Determinism:** Replaying the same sequence of events (`Ledger`) always produces the exact same state (`Projection`).
-   **Auditability:** Every state change can be traced back to the specific signed event that caused it.
-   **Crash Recovery:** Agents do not persist state in memory or mutable files; they rebuild it from the ledger on startup.

## Core Codebase Traits

-   **`Reducer`** (`crates/apm2-core/src/reducer/traits.rs`): The pure function trait that transitions state by applying an `Event`.
-   **`CheckpointableReducer`**:
    -   Allows snapshots of the state to be saved to SQLite to avoid replaying from genesis every time.

## Known Reducers

1.  **SessionReducer:** Tracks process lifecycle (Started, Terminated, Quarantined).
2.  **WorkReducer:** Tracks `WorkObject` lifecycle (Plan -> Ticket -> ChangeSet).
3.  **LeaseReducer:** Tracks resource leases and expiration.
4.  **EvidenceReducer:** Tracks content-addressed artifacts and verification bundles.
5.  **RecurrenceReducer:** Tracks `FindingSignature` counts to trigger `Countermeasures`.
