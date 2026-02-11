# Ledger Module

> Append-only event ledger with SQLite WAL storage and cryptographic hash chaining for audit-grade event sourcing.

## Overview

The `apm2_core::ledger` module provides the persistence layer for APM2's event-sourced architecture. All kernel state changes are recorded as immutable events in this ledger, enabling complete audit trails, crash recovery, and state reconstruction through reducer replay.

The ledger uses SQLite with Write-Ahead Logging (WAL) mode to achieve concurrent read access while writes are in progress. In the SQLite daemon emitter, events form a cryptographic hash chain using SHA-256, with optional Ed25519 signatures for tamper-evident logging.

### Architectural Position

```
CLI (apm2-cli)
      |
      v
Daemon (apm2-daemon)
      |
      v
+-----+-----+
|  Ledger   | <-- You are here
+-----+-----+
      |
      v
Reducers --> Projections (SessionState, LeaseState, etc.)
```

The ledger sits at the foundation of the event-sourcing stack:
1. Events are appended to the ledger
2. Reducers consume events to build projections
3. Checkpoints serialize reducer state for fast recovery

## Key Types

### `EventRecord`

```rust
#[non_exhaustive]
pub struct EventRecord {
    pub seq_id: Option<u64>,
    pub event_type: String,
    pub session_id: String,
    pub actor_id: String,
    pub record_version: u32,
    pub payload: Vec<u8>,
    pub timestamp_ns: u64,
    pub prev_hash: Option<Vec<u8>>,
    pub event_hash: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,

    // RFC-0014 Consensus fields (all optional for backward compatibility)
    pub consensus_epoch: Option<u64>,
    pub consensus_round: Option<u64>,
    pub quorum_cert: Option<Vec<u8>>,
    pub schema_digest: Option<Vec<u8>>,
    pub canonicalizer_id: Option<String>,
    pub canonicalizer_version: Option<String>,
    pub hlc_wall_time: Option<u64>,
    pub hlc_counter: Option<u32>,
}
```

**Invariants:**
- [INV-LED-001] Events are immutable once appended; the ledger is append-only
- [INV-LED-002] Sequence IDs are monotonically increasing and gap-free (SQLite AUTOINCREMENT)
- [INV-LED-003] Hash chain integrity: `event_hash = SHA-256(event_domain || prev_hash || event_metadata || payload || signature)`
- [INV-LED-007] RFC-0014 consensus fields are nullable for backward compatibility with pre-consensus events

**Contracts:**
- [CTR-LED-001] `record_version` must equal `CURRENT_RECORD_VERSION` for new events
- [CTR-LED-002] `timestamp_ns` is nanoseconds since Unix epoch (will not overflow until year 2554)
- [CTR-LED-003] `payload` is typically JSON but stored as opaque bytes for flexibility
- [CTR-LED-010] RFC-0014 consensus fields (`consensus_epoch`, `consensus_round`, `quorum_cert`, `schema_digest`, `canonicalizer_id`, `canonicalizer_version`, `hlc_wall_time`, `hlc_counter`) default to `None` and are nullable in the database
- [CTR-LED-011] `quorum_cert` contains serialized protobuf `QuorumCertificate` when present
- [CTR-LED-012] `schema_digest` is BLAKE3 hash of the schema definition for this event type
- [CTR-LED-013] `hlc_wall_time` and `hlc_counter` together form a Hybrid Logical Clock timestamp for causal ordering

### `CURRENT_RECORD_VERSION`

```rust
pub const CURRENT_RECORD_VERSION: u32 = 1;
```

**Contract:** [CTR-LED-004] Schema evolution uses version fields; all events carry their schema version for backward compatibility.

### `Ledger`

```rust
pub struct Ledger {
    conn: Arc<std::sync::Mutex<Connection>>,
    path: Option<std::path::PathBuf>,
}
```

**Invariants:**
- [INV-LED-004] WAL mode is enabled for all file-backed ledgers
- [INV-LED-005] Foreign keys are enforced (`PRAGMA foreign_keys = ON`)
- [INV-LED-006] `Arc<Mutex<Connection>>` ensures single-writer semantics

**Contracts:**
- [CTR-LED-005] All writes go through the Mutex-protected connection
- [CTR-LED-006] Readers can be created via `open_reader()` for concurrent access

### `LedgerReader`

```rust
pub struct LedgerReader {
    conn: Arc<std::sync::Mutex<Connection>>,
}
```

A read-only view of the ledger for concurrent reads. WAL mode allows readers to operate independently of writers.

### `ArtifactRef`

```rust
pub struct ArtifactRef {
    pub id: Option<u64>,
    pub event_seq_id: u64,
    pub content_hash: Vec<u8>,
    pub content_type: String,
    pub size_bytes: u64,
    pub storage_path: String,
    pub created_at_ns: u64,
}
```

Links events to content-addressed storage. Large payloads are stored in CAS with only hash references in the ledger.

**Contracts:**
- [CTR-LED-007] `content_hash` is SHA-256 of the artifact content
- [CTR-LED-008] `storage_path` points to the CAS location

### `LedgerError`

```rust
#[non_exhaustive]
pub enum LedgerError {
    Database(rusqlite::Error),
    Io(std::io::Error),
    AppendOnlyViolation { seq_id: u64 },
    InvalidCursor { cursor: u64 },
    EventNotFound { seq_id: u64 },
    HashChainBroken { seq_id: u64, details: String },
    SignatureInvalid { seq_id: u64, details: String },
    Crypto(String),
}
```

**Contract:** [CTR-LED-009] Error variants are structured for programmatic handling; callers can branch on cause.

### `LedgerStats`

```rust
pub struct LedgerStats {
    pub event_count: u64,
    pub artifact_count: u64,
    pub max_seq_id: u64,
    pub db_size_bytes: u64,
}
```

## Public API

### `Ledger::open(path) -> Result<Self, LedgerError>`

Opens or creates a ledger at the specified filesystem path. Initializes schema and enables WAL mode.

### `Ledger::in_memory() -> Result<Self, LedgerError>`

Creates an in-memory ledger for testing. Note: `open_reader()` is not supported for in-memory databases.

### `Ledger::append(event) -> Result<u64, LedgerError>`

Appends a single event and returns its assigned sequence ID.

### `Ledger::append_batch(events) -> Result<Vec<u64>, LedgerError>`

Appends multiple events atomically in a single transaction. Returns sequence IDs in order. On error, no events are inserted.

### `Ledger::append_signed(event, hasher_fn, sign_fn) -> Result<u64, LedgerError>`

Appends an event with full cryptographic integration:
1. Fetches previous event hash (or genesis hash)
2. Computes event hash via `hasher_fn`
3. Signs hash via `sign_fn`
4. Appends with all crypto fields populated

### `Ledger::read_from(cursor, limit) -> Result<Vec<EventRecord>, LedgerError>`

Reads up to `limit` events with `seq_id >= cursor`. Primary interface for reducer replay.

### `Ledger::read_one(seq_id) -> Result<EventRecord, LedgerError>`

Reads a single event by sequence ID. Returns `EventNotFound` if absent.

### `Ledger::read_session(session_id, limit) -> Result<Vec<EventRecord>, LedgerError>`

Reads events for a specific session in sequence order.

### `Ledger::read_by_type(event_type, cursor, limit) -> Result<Vec<EventRecord>, LedgerError>`

Reads events filtered by type.

### `Ledger::last_event_hash() -> Result<Vec<u8>, LedgerError>`

Returns the hash of the last event, or genesis hash (32 zero bytes) if empty. Used for hash chain continuation.

### `Ledger::verify_chain(verify_hash_fn, verify_sig_fn) -> Result<(), LedgerError>`

Verifies the entire hash chain from genesis. Returns `HashChainBroken` or `SignatureInvalid` on failure.

### `Ledger::open_reader() -> Result<LedgerReader, LedgerError>`

Creates a read-only connection for concurrent reads. Not supported for in-memory databases.

### `Ledger::stats() -> Result<LedgerStats, LedgerError>`

Returns ledger statistics including event/artifact counts and database size.

### `Ledger::verify_wal_mode() -> Result<bool, LedgerError>`

Returns true if WAL mode is enabled.

## Hash Chain Mechanics

Events form a cryptographic hash chain for tamper evidence:

```
Genesis Hash (32 zero bytes)
       |
       v
Event 1: event_hash = SHA-256(payload_1 || genesis_hash)
       |
       v
Event 2: event_hash = SHA-256(payload_2 || event_hash_1)
       |
       v
Event N: event_hash = SHA-256(payload_N || event_hash_(N-1))
```

**Verification:** `verify_chain()` walks all events and recomputes hashes. Any tampering breaks the chain.

**Signatures:** Optional Ed25519 signatures over event hashes provide non-repudiation.

## SQLite WAL Storage

The ledger uses SQLite with these pragmas:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
```

**WAL benefits:**
- Readers do not block writers
- Writers do not block readers
- Crash recovery is automatic
- Concurrent read connections via `open_reader()`

**Schema** (see `schema.sql`):
- `events` table: append-only event storage
- `artifact_refs` table: CAS references with foreign key to events
- Indexes on session_id, timestamp, event_type, actor_id

## Examples

### Basic Usage

```rust
use apm2_core::ledger::{EventRecord, Ledger};

// Open or create ledger
let ledger = Ledger::open("/path/to/ledger.db")?;

// Append an event
let event = EventRecord::new(
    "session.start",
    "session-123",
    "actor-456",
    b"{\"user\": \"alice\"}".to_vec(),
);
let seq_id = ledger.append(&event)?;

// Read events from cursor
let events = ledger.read_from(0, 100)?;
```

### Signed Append with Hash Chain

```rust
use apm2_core::ledger::{EventRecord, Ledger};

let ledger = Ledger::open("/path/to/ledger.db")?;

let event = EventRecord::new(
    "tool.request",
    "session-123",
    "actor-456",
    b"{\"tool\": \"file_read\"}".to_vec(),
);

// Append with cryptographic signing
let seq_id = ledger.append_signed(
    event,
    |payload, prev_hash| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(payload);
        hasher.update(prev_hash);
        hasher.finalize().as_bytes().to_vec()
    },
    |hash| {
        // Sign hash with Ed25519 keypair
        signing_key.sign(hash).to_bytes().to_vec()
    },
)?;
```

### Concurrent Reads

```rust
use std::thread;

let ledger = Ledger::open("/path/to/ledger.db")?;
let reader = ledger.open_reader()?;

// Reader thread
let handle = thread::spawn(move || {
    loop {
        let events = reader.read_from(0, 100)?;
        // Process events...
    }
});

// Writer continues in main thread
ledger.append(&event)?;
```

## BFT Ledger Backend

The `BftLedgerBackend` wraps the SQLite storage with BFT consensus integration for distributed deployments.

### `BftLedgerBackend<R: SchemaRegistry>`

```rust
pub struct BftLedgerBackend<R: SchemaRegistry = NoOpSchemaRegistry> {
    storage: Arc<SqliteLedgerBackend>,
    schema_registry: Option<Arc<R>>,
    // ... consensus-related fields
}
```

**Constructors:**
- `BftLedgerBackend::new(storage, timeout)` - Without schema validation
- `BftLedgerBackend::with_schema_registry(storage, timeout, registry)` - With schema validation (TCK-00194)

### Schema Validation (TCK-00194)

Events can include a `schema_digest` field referencing a registered schema in the schema registry. The `BftLedgerBackend` validates this digest on append with a **fail-closed** security posture:

**Validation Rules:**
- If `schema_digest` is `None`: validation passes (backward compatible)
- If `schema_registry` is `None`: validation passes (no registry configured)
- If `schema_digest` is `Some` and registered: validation passes
- If `schema_digest` is `Some` but NOT registered: **REJECT** with `SchemaMismatch`

**Invariants:**
- [INV-LED-008] Schema validation happens BEFORE any storage operation (prevent corrupted events)
- [INV-LED-009] Fail-closed: unknown schemas are rejected, not accepted

**Error:**
```rust
BftLedgerError::SchemaMismatch { digest: String }
```

**Example:**
```rust
use apm2_core::ledger::{BftLedgerBackend, SqliteLedgerBackend};
use apm2_core::schema_registry::InMemorySchemaRegistry;
use std::sync::Arc;
use std::time::Duration;

let storage = SqliteLedgerBackend::in_memory().unwrap();
let registry = Arc::new(InMemorySchemaRegistry::new());

// Register schemas first
registry.register(&my_schema_entry).await.unwrap();

// Create backend with schema validation
let backend = BftLedgerBackend::with_schema_registry(
    storage,
    Duration::from_secs(30),
    registry,
);

// Events with unknown schema_digest will be rejected
```

**References:**
- RFC-0014 DD-0004: "Unknown schemas trigger rejection (fail-closed)"
- RFC-0014 TCK-00194: "Integrate Schema Validation into Append Path"

## Related Modules

- [`apm2_core::reducer`](../reducer/AGENTS.md) - Consumes ledger events to build projections
- [`apm2_core::evidence`](../evidence/AGENTS.md) - Uses ledger for evidence publication
- [`apm2_core::session`](../session/AGENTS.md) - Session state derived from ledger events
- [`apm2_core::lease`](../lease/AGENTS.md) - Lease state derived from ledger events
- [`apm2_core::schema_registry`](../schema_registry/AGENTS.md) - Schema registration and lookup

## References

### Rust Textbook Chapters

- [Chapter 07: Errors, Panics, Diagnostics](/documents/skills/rust-standards/references/15_errors_panics_diagnostics.md)
  - [CTR-0703] Error types are structured for programmatic handling
  - [RSK-0701] Database errors return `Result`, not panics

- [Chapter 10: Concurrency, Atomics, Memory Ordering](/documents/skills/rust-standards/references/21_concurrency_atomics_memory_order.md)
  - [INV-1001] `Arc<Mutex<Connection>>` provides data race freedom
  - [CTR-1001] `Ledger` is `Send + Sync` via interior mutability

- [Chapter 16: I/O and Protocol Boundaries](/documents/skills/rust-standards/references/31_io_protocol_boundaries.md)
  - [CTR-1601] Frame format is explicit (length-prefixed SQLite rows)
  - [CTR-1602] Schema versioned via `record_version` field

- [Chapter 19: Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md)
  - [CTR-1901] Threat model includes DoS via large payloads
  - [RSK-1906] Timestamp determinism via explicit nanosecond fields

### External Documentation

- [SQLite WAL Mode](https://www.sqlite.org/wal.html)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Ed25519 Signatures](https://ed25519.cr.yp.to/)
