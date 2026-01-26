# Ledger

**Agent-Native Definition**: The **Ledger** is the "Topology of Truth" for the APM2 system. It is an append-only, cryptographically verifiable log of all significant events in the factory. It serves as the single source of truth for the state of agents, work, and the system as a whole.

The ledger replaces mutable databases with an immutable event stream, enabling perfect auditability and "time-travel" debugging.

## Core Concepts

### Append-Only & Immutable
Events can only be added to the end of the ledger. Existing events cannot be modified or deleted. This guarantees that history is preserved exactly as it happened. The system physics enforces this through sequential sequence IDs (`seq_id`).

### Hash-Chained Integrity
Integrity is maintained through cryptographic chaining. Each `EventRecord` (except the genesis event) contains a `prev_hash` field that stores the hash of the preceding event. This creates a chain where modifying any historical event would invalidate all subsequent signatures.

### Storage Architecture
*   **SQLite WAL**: The ledger uses `SQLite` in Write-Ahead Log (WAL) mode. This allows for high-concurrency performance, enabling multiple `LedgerReader` instances (agents observing state) to operate concurrently with a single writer.
*   **EventRecord**: The atomic unit of storage. It contains the event payload, timestamp, sequence number, and actor ID, along with cryptographic hashes and signatures.

### Artifact References
To keep the ledger lightweight, large data blobs (Artifacts) are stored in Content-Addressable Storage (CAS), and the ledger stores only an `ArtifactRef`. This maintains a clean separation between the "control plane" (ledger) and "data plane" (CAS).

## Data Structure References
*   **`Ledger`** (`crates/apm2-core/src/ledger/storage.rs`): The main storage engine managing the `SQLite` connection and WAL mode.
*   **`EventRecord`** (`crates/apm2-core/src/ledger/storage.rs`): The schema for a single event, containing payload, `seq_id`, `event_hash`, `prev_hash`, and `signature`.
*   **`LedgerReader`** (`crates/apm2-core/src/ledger/storage.rs`): A read-only view of the ledger for concurrent access.

## See Also
*   **Artifact**: Large data referenced by the ledger.
*   **Evidence**: High-level cryptographic proofs whose publication is recorded in the ledger.