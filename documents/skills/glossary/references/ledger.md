# Ledger

**Agent-Native Definition**: The **Ledger** is the "Topology of Truth" for the APM2 system. It is an append-only, cryptographically verifiable log of all significant events in the factory. It serves as the single source of truth for the state of agents, work, and the system as a whole.

The ledger replaces mutable databases with an immutable event stream, enabling perfect auditability and "time-travel" debugging.

## Core Concepts

### Append-Only & Immutable
Events can only be added to the end of the ledger. Existing events cannot be modified or deleted. This guarantees that history is preserved exactly as it happened. The system physics enforces this through sequential sequence IDs (`seq_id`).

### Hash-Chained Integrity
Integrity is maintained through cryptographic chaining. Each `EventRecord` (except the genesis event) contains a `prev_hash` field that stores the hash of the preceding event. This creates a chain where modifying any historical event would invalidate all subsequent signatures.

### Ledger Head, Checkpoints, and Commitments

- **Ledger head**: the latest authoritative position in the ledger (practically: `(seq_id, event_hash)` of the most recent `EventRecord`, or a canonical checkpoint event hash). This is the anchor used by bounded views.
- **Checkpoint (event)**: a normal ledger event emitted during work to persist progress (intent-to-act, tool outputs, intermediate decisions).
- **Snapshot (derived artifact)**: a content-addressed derived acceleration that summarizes a range of history while preserving provenance via hash-links and replay-equivalence evidence.

Bounded views (ContextPacks, Summary Receipts, Snapshots) are synchronized by carrying a **View Commitment** to a ledger head/checkpoint, not by embedding the full ledger in-window.

### Inference Trace Integrity
To resolve the paradox of deterministic reconstruction from probabilistic models, the ledger MAY store or reference an **Inference Trace**. This captures the exact model outputs, seeds, and metadata required to verify the *reasoning* that led to a commitment.

### Storage Architecture
*   **SQLite WAL**: The ledger uses `SQLite` in Write-Ahead Log (WAL) mode. This allows for high-concurrency performance, enabling multiple `LedgerReader` instances (agents observing state) to operate concurrently with a single writer.
*   **EventRecord**: The atomic unit of storage. It contains the event payload, timestamp, sequence number, and actor ID, along with cryptographic hashes and signatures.

### Artifact References
To keep the ledger lightweight, large data blobs (Artifacts) are stored in Content-Addressable Storage (CAS), and the ledger stores only an `ArtifactRef`. This maintains a clean separation between the "control plane" (ledger) and "data plane" (CAS).

## Mapping to Git (Concrete)

The ledger is often compared to Git history, but they differ in important ways:

- **Ledger head vs Git HEAD**: the ledger head is a cryptographic commitment to the latest event; Git `HEAD` is a symbolic reference to the currently checked out commit.
- **Append-only vs rewritable**: ledger history is immutable by design; Git history can be rewritten locally (rebase, filter-repo). Git becomes authoritative only when pinned by digest and recorded in receipts/events.
- **Event truth vs code truth**: the ledger records *workflow facts* (what was verified/approved/ran); Git records *source state*. A View Commitment typically carries both: a ledger head and a pinned Git commit/tree selector.

## Data Structure References
*   **`Ledger`** (`crates/apm2-core/src/ledger/storage.rs`): The main storage engine managing the `SQLite` connection and WAL mode.
*   **`EventRecord`** (`crates/apm2-core/src/ledger/storage.rs`): The schema for a single event, containing payload, `seq_id`, `event_hash`, `prev_hash`, and `signature`.
*   **`LedgerReader`** (`crates/apm2-core/src/ledger/storage.rs`): A read-only view of the ledger for concurrent access.

## See Also
*   **Artifact**: Large data referenced by the ledger.
*   **Evidence**: High-level cryptographic proofs whose publication is recorded in the ledger.
*   **View Commitment**: how bounded views synchronize to the ledger head/checkpoint.
*   **Git Digest Conventions**: how Git state is pinned in receipts alongside ledger commitments.
