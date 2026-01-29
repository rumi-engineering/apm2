-- APM2 Ledger Schema
-- Implements append-only event storage with WAL mode for concurrent reads

-- Enable WAL mode for better concurrent read performance
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- Events table: append-only ledger of all kernel events
-- Each event has a monotonic sequence number for ordering
CREATE TABLE IF NOT EXISTS events (
    -- Auto-incrementing sequence number (monotonic, gap-free)
    seq_id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Event type identifier (e.g., "session.start", "tool.request")
    event_type TEXT NOT NULL,

    -- Session identifier this event belongs to
    session_id TEXT NOT NULL,

    -- Actor ID that signed this event (signer identity)
    actor_id TEXT NOT NULL,

    -- Record version for schema compatibility (current: 1)
    record_version INTEGER NOT NULL DEFAULT 1,

    -- Event payload as JSON (flexible schema per event type)
    payload BLOB NOT NULL,

    -- Timestamp when event was recorded (nanoseconds since Unix epoch)
    timestamp_ns INTEGER NOT NULL,

    -- Hash of the previous event (for hash chaining)
    -- NULL for the first event in the ledger
    prev_hash BLOB,

    -- Hash of this event's content
    event_hash BLOB,

    -- Ed25519 signature over the event
    signature BLOB,

    -- RFC-0014 Consensus columns (nullable for backward compatibility)
    -- Consensus epoch number (NULL for non-consensus events)
    consensus_epoch INTEGER,

    -- Consensus round within epoch (NULL for non-consensus events)
    consensus_round INTEGER,

    -- Quorum certificate as serialized protobuf (NULL for non-consensus events)
    quorum_cert BLOB,

    -- BLAKE3 digest of the schema definition for this event type
    schema_digest BLOB,

    -- Canonicalizer identifier used to serialize the payload
    canonicalizer_id TEXT,

    -- Canonicalizer version for reproducible canonicalization
    canonicalizer_version TEXT,

    -- Hybrid Logical Clock wall time (nanoseconds since Unix epoch)
    hlc_wall_time INTEGER,

    -- Hybrid Logical Clock counter for causal ordering within same wall time
    hlc_counter INTEGER
);

-- Index for efficient session-based queries
CREATE INDEX IF NOT EXISTS idx_events_session
ON events (session_id, seq_id);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON events (timestamp_ns);

-- Index for event type queries
CREATE INDEX IF NOT EXISTS idx_events_type
ON events (event_type, seq_id);

-- Index for actor-based queries
CREATE INDEX IF NOT EXISTS idx_events_actor
ON events (actor_id, seq_id);

-- Artifact references table: content-addressable storage references
-- Links events to their associated artifacts stored in CAS
CREATE TABLE IF NOT EXISTS artifact_refs (
    -- Reference identifier
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Event this artifact is associated with
    event_seq_id INTEGER NOT NULL,

    -- Content hash (SHA-256) of the artifact
    content_hash BLOB NOT NULL,

    -- MIME type of the artifact
    content_type TEXT NOT NULL,

    -- Size in bytes
    size_bytes INTEGER NOT NULL,

    -- Storage location/path in CAS
    storage_path TEXT NOT NULL,

    -- Timestamp when reference was created
    created_at_ns INTEGER NOT NULL,

    FOREIGN KEY (event_seq_id) REFERENCES events(seq_id)
);

-- Index for looking up artifacts by content hash
CREATE INDEX IF NOT EXISTS idx_artifact_refs_hash
ON artifact_refs (content_hash);

-- Index for looking up artifacts by event
CREATE INDEX IF NOT EXISTS idx_artifact_refs_event
ON artifact_refs (event_seq_id);

-- ============================================================================
-- RFC-0014 Migration: Add consensus columns to existing databases
-- These ALTER TABLE statements are idempotent - they will silently fail
-- if the columns already exist (using IF NOT EXISTS simulation via pragma check)
-- ============================================================================

-- Migration is handled programmatically in storage.rs::migrate_consensus_columns()
-- to ensure proper error handling and idempotency.
