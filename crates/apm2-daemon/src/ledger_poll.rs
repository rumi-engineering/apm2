//! Shared freeze-aware ledger polling module (TCK-00675).
//!
//! Consolidates the duplicated SQL query logic for polling events from both the
//! legacy `ledger_events` table and the canonical `events` table introduced by
//! RFC-0032 freeze mode. Both [`crate::projection::worker::LedgerTailer`] and
//! `SqliteTimeoutLedgerReader` (in `crate::gate::timeout_kernel`) delegate to
//! this module, eliminating ~600 lines of duplicated per-type SQL.
//!
//! ## Cursor semantics
//!
//! The composite cursor `(timestamp_ns, event_id)` handles timestamp
//! collisions using the predicate
//! `timestamp_ns > ?cursor_ts OR (timestamp_ns = ?cursor_ts AND event_id >
//! ?cursor_event_id)`.
//!
//! ## Canonical event IDs
//!
//! Canonical rows use a synthesised event ID: `"canonical-{seq_id:020}"` --
//! zero-padded to 20 digits so that lexicographic ordering matches numeric
//! `seq_id ASC` ordering. Without padding, `"canonical-10"` sorts before
//! `"canonical-9"` in string comparison, causing cursor skips.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::protocol::dispatch::SignedLedgerEvent;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prefix for canonical synthetic event IDs.
pub const CANONICAL_EVENT_ID_PREFIX: &str = "canonical-";

/// Fixed width (digit count) for zero-padded canonical event IDs.
pub const CANONICAL_EVENT_ID_WIDTH: usize = 20;

/// Hard limit on events returned per poll call to prevent unbounded memory
/// growth from a single query (denial-of-service prevention).
///
/// Each `SignedLedgerEvent` payload can be up to ~1 MiB, so this cap limits a
/// single poll to ~1 GiB peak allocation -- tolerable on production hosts
/// while preventing the ~10 GiB spike that a 10,000-event cap would allow.
const MAX_POLL_LIMIT: usize = 1_000;

/// SQL zero-pad constant -- 20 zeros for `SUBSTR` padding in canonical queries.
const SQL_ZERO_PAD: &str = "00000000000000000000";

// ---------------------------------------------------------------------------
// canonical_event_id
// ---------------------------------------------------------------------------

/// Returns `"canonical-{seq_id:020}"` -- zero-padded to 20 digits for
/// lexicographic ordering that matches numeric `seq_id ASC`.
///
/// # Examples
///
/// ```
/// # use apm2_daemon::ledger_poll::canonical_event_id;
/// assert_eq!(canonical_event_id(0), "canonical-00000000000000000000");
/// assert_eq!(canonical_event_id(42), "canonical-00000000000000000042");
/// assert!(canonical_event_id(9) < canonical_event_id(10));
/// ```
#[must_use]
pub fn canonical_event_id(seq_id: i64) -> String {
    format!("{CANONICAL_EVENT_ID_PREFIX}{seq_id:0CANONICAL_EVENT_ID_WIDTH$}")
}

/// Parses the numeric `seq_id` from a canonical event ID string.
///
/// Returns `None` if the string does not start with the canonical prefix or
/// the numeric portion is not a valid `i64`.
#[must_use]
pub fn parse_canonical_event_id(event_id: &str) -> Option<i64> {
    event_id
        .strip_prefix(CANONICAL_EVENT_ID_PREFIX)?
        .parse::<i64>()
        .ok()
}

/// Normalizes a cursor event ID to fixed-width canonical representation.
///
/// If the event ID is a canonical ID (padded or unpadded), it is re-formatted
/// to fixed width. Non-canonical IDs are returned unchanged.
#[must_use]
pub fn normalize_canonical_cursor_event_id(cursor_event_id: &str) -> String {
    parse_canonical_event_id(cursor_event_id)
        .map_or_else(|| cursor_event_id.to_string(), canonical_event_id)
}

// ---------------------------------------------------------------------------
// Canonical table detection
// ---------------------------------------------------------------------------

/// Detects whether the canonical `events` table exists in the database.
///
/// Returns `true` if the table exists in `sqlite_master`. The result should
/// be cached by callers to avoid repeated schema queries.
fn detect_canonical_table(conn: &Connection) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = 'events')",
        [],
        |row| row.get(0),
    )
    .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// poll_events_blocking -- core shared poll
// ---------------------------------------------------------------------------

/// Blocking freeze-aware poll: merges legacy `ledger_events` + canonical
/// `events`.
///
/// Cursor predicate:
/// `timestamp_ns > cursor_ts_ns OR (timestamp_ns == cursor_ts_ns AND event_id >
/// cursor_event_id)`.
///
/// Returns events sorted by `(timestamp_ns ASC, event_id ASC)`, truncated to
/// `limit`.
///
/// `event_id` for canonical rows uses [`canonical_event_id`].
///
/// Uses a dynamic `IN (?,?,...)` clause for `event_types` so callers can poll
/// multiple types in a single query instead of issuing per-type queries.
///
/// ## Resource bounds
///
/// `limit` is clamped to `MAX_POLL_LIMIT` (1,000) to prevent unbounded
/// memory allocation from a single call.
///
/// # Errors
///
/// Returns `Err(String)` on `SQLite` failures or if `limit` exceeds `i64`
/// range.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
pub fn poll_events_blocking(
    conn: &Connection,
    event_types: &[&str],
    cursor_ts_ns: i64,
    cursor_event_id: &str,
    limit: usize,
) -> Result<Vec<SignedLedgerEvent>, String> {
    if event_types.is_empty() || limit == 0 {
        return Ok(Vec::new());
    }

    // Normalize canonical cursor IDs up-front so that legacy/unpadded cursors
    // (e.g. "canonical-9") are converted to fixed-width
    // ("canonical-00000000000000000009") before any SQL predicate uses them for
    // lexicographic comparison.
    let cursor_event_id = normalize_canonical_cursor_event_id(cursor_event_id);

    let limit = limit.min(MAX_POLL_LIMIT);
    let limit_i64 = i64::try_from(limit).map_err(|_| "poll limit exceeds i64 range".to_string())?;

    // Build the dynamic IN clause for event_types.
    let placeholders = build_in_placeholders(event_types.len());

    // --- Legacy ledger_events query ---
    let mut events = poll_legacy(
        conn,
        event_types,
        &placeholders,
        cursor_ts_ns,
        &cursor_event_id,
        limit_i64,
    )?;

    // --- Canonical events query (if table exists) ---
    // Bound the canonical query to `limit - legacy_count` so the combined
    // vector never exceeds `limit` entries, avoiding a transient 2x memory
    // spike when both tables return a full batch.
    if detect_canonical_table(conn) {
        let remaining = limit.saturating_sub(events.len());
        let remaining_i64 =
            i64::try_from(remaining).map_err(|_| "poll remaining exceeds i64 range".to_string())?;
        if remaining_i64 > 0 {
            let canonical = poll_canonical(
                conn,
                event_types,
                &placeholders,
                cursor_ts_ns,
                &cursor_event_id,
                remaining_i64,
            )?;
            if !canonical.is_empty() {
                events.extend(canonical);
                // Merge-sort by (timestamp_ns, event_id) and truncate.
                events.sort_by(|a, b| {
                    a.timestamp_ns
                        .cmp(&b.timestamp_ns)
                        .then_with(|| a.event_id.cmp(&b.event_id))
                });
                events.truncate(limit);
            }
        }
    }

    Ok(events)
}

/// Async wrapper -- offloads to `tokio::task::spawn_blocking`.
///
/// # Errors
///
/// Returns `Err(String)` on mutex poisoning, spawn failure, or `SQLite` errors.
pub async fn poll_events_async(
    conn: Arc<Mutex<Connection>>,
    event_types: Vec<String>,
    cursor_ts_ns: i64,
    cursor_event_id: String,
    limit: usize,
) -> Result<Vec<SignedLedgerEvent>, String> {
    tokio::task::spawn_blocking(move || {
        let guard = conn
            .lock()
            .map_err(|e| format!("ledger_poll: mutex poisoned: {e}"))?;
        let type_refs: Vec<&str> = event_types.iter().map(String::as_str).collect();
        poll_events_blocking(&guard, &type_refs, cursor_ts_ns, &cursor_event_id, limit)
    })
    .await
    .map_err(|e| format!("ledger_poll: spawn_blocking failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Builds a SQL `IN (?,?,...)` fragment with `count` placeholders.
fn build_in_placeholders(count: usize) -> String {
    let parts: Vec<String> = (0..count).map(|_| "?".to_string()).collect();
    parts.join(", ")
}

/// Builds the common parameter vector for event type + cursor + limit.
///
/// Both `poll_legacy` and `poll_canonical` share this logic: first push all
/// event type strings, then push cursor parameters (`timestamp_ns`, optionally
/// duplicated `timestamp_ns` and `cursor_event_id` for the composite
/// predicate), and finally the limit.
fn build_params(
    event_types: &[&str],
    cursor_ts_ns: i64,
    cursor_event_id: &str,
    limit_i64: i64,
) -> Vec<Box<dyn rusqlite::types::ToSql>> {
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    for et in event_types {
        params_vec.push(Box::new(et.to_string()));
    }
    params_vec.push(Box::new(cursor_ts_ns));
    if !cursor_event_id.is_empty() {
        params_vec.push(Box::new(cursor_ts_ns));
        params_vec.push(Box::new(cursor_event_id.to_string()));
    }
    params_vec.push(Box::new(limit_i64));
    params_vec
}

/// Polls the legacy `ledger_events` table.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn poll_legacy(
    conn: &Connection,
    event_types: &[&str],
    in_clause: &str,
    cursor_ts_ns: i64,
    cursor_event_id: &str,
    limit_i64: i64,
) -> Result<Vec<SignedLedgerEvent>, String> {
    // Build the query dynamically since the number of event types varies.
    let query = if cursor_event_id.is_empty() {
        format!(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type IN ({in_clause}) AND timestamp_ns > ? \
             ORDER BY timestamp_ns ASC, event_id ASC \
             LIMIT ?"
        )
    } else {
        format!(
            "SELECT event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns \
             FROM ledger_events \
             WHERE event_type IN ({in_clause}) AND ( \
                 timestamp_ns > ? OR \
                 (timestamp_ns = ? AND event_id > ?) \
             ) \
             ORDER BY timestamp_ns ASC, event_id ASC \
             LIMIT ?"
        )
    };

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| format!("ledger_poll: legacy prepare failed: {e}"))?;

    let params_vec = build_params(event_types, cursor_ts_ns, cursor_event_id, limit_i64);
    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(AsRef::as_ref).collect();

    let rows = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(SignedLedgerEvent {
                event_id: row.get(0)?,
                event_type: row.get(1)?,
                work_id: row.get(2)?,
                actor_id: row.get(3)?,
                payload: row.get(4)?,
                signature: row.get(5)?,
                timestamp_ns: row.get::<_, i64>(6)? as u64,
            })
        })
        .map_err(|e| format!("ledger_poll: legacy query failed: {e}"))?;

    let events: Vec<_> = rows.filter_map(Result::ok).collect();
    Ok(events)
}

/// Polls the canonical `events` table.
///
/// Caller must have already verified that the table exists.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn poll_canonical(
    conn: &Connection,
    event_types: &[&str],
    in_clause: &str,
    cursor_ts_ns: i64,
    cursor_event_id: &str,
    limit_i64: i64,
) -> Result<Vec<SignedLedgerEvent>, String> {
    // Defensive normalization: ensure any canonical cursor is fixed-width even
    // if the caller forgot to normalize at the top level.
    let cursor_event_id = normalize_canonical_cursor_event_id(cursor_event_id);
    let cursor_event_id = cursor_event_id.as_str();

    let query = if cursor_event_id.is_empty() {
        format!(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events \
             WHERE event_type IN ({in_clause}) AND timestamp_ns > ? \
             ORDER BY timestamp_ns ASC, seq_id ASC \
             LIMIT ?"
        )
    } else {
        format!(
            "SELECT seq_id, event_type, session_id, actor_id, payload, \
                    COALESCE(signature, X''), timestamp_ns \
             FROM events \
             WHERE event_type IN ({in_clause}) AND ( \
                 timestamp_ns > ? OR \
                 (timestamp_ns = ? AND \
                  ('canonical-' || SUBSTR('{SQL_ZERO_PAD}', 1, \
                      20 - LENGTH(CAST(seq_id AS TEXT))) || CAST(seq_id AS TEXT)) > ?) \
             ) \
             ORDER BY timestamp_ns ASC, seq_id ASC \
             LIMIT ?"
        )
    };

    let mut stmt = conn
        .prepare(&query)
        .map_err(|e| format!("ledger_poll: canonical prepare failed: {e}"))?;

    let params_vec = build_params(event_types, cursor_ts_ns, cursor_event_id, limit_i64);
    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        params_vec.iter().map(AsRef::as_ref).collect();

    let rows = stmt
        .query_map(param_refs.as_slice(), |row| {
            let seq_id: i64 = row.get(0)?;
            Ok(SignedLedgerEvent {
                event_id: canonical_event_id(seq_id),
                event_type: row.get(1)?,
                work_id: row.get(2)?,
                actor_id: row.get(3)?,
                payload: row.get(4)?,
                signature: row.get(5)?,
                timestamp_ns: row.get::<_, i64>(6)? as u64,
            })
        })
        .map_err(|e| format!("ledger_poll: canonical query failed: {e}"))?;

    let events: Vec<_> = rows.filter_map(Result::ok).collect();
    Ok(events)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;

    /// Helper: creates an in-memory `SQLite` DB with both legacy and canonical
    /// tables matching the production schema.
    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(
            "CREATE TABLE ledger_events (
                 event_id   TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 work_id    TEXT NOT NULL DEFAULT '',
                 actor_id   TEXT NOT NULL DEFAULT '',
                 payload    BLOB NOT NULL DEFAULT X'',
                 signature  BLOB NOT NULL DEFAULT X'',
                 timestamp_ns INTEGER NOT NULL
             );
             CREATE TABLE events (
                 seq_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_type  TEXT NOT NULL,
                 session_id  TEXT NOT NULL DEFAULT '',
                 actor_id    TEXT NOT NULL DEFAULT '',
                 payload     BLOB NOT NULL DEFAULT X'',
                 signature   BLOB,
                 timestamp_ns INTEGER NOT NULL
             );",
        )
        .expect("create tables");
        conn
    }

    #[test]
    fn test_canonical_event_id_lexical_ordering() {
        let id_9 = canonical_event_id(9);
        let id_10 = canonical_event_id(10);
        let id_100 = canonical_event_id(100);
        assert!(
            id_9 < id_10,
            "canonical_event_id(9) must sort before canonical_event_id(10): {id_9} < {id_10}"
        );
        assert!(
            id_10 < id_100,
            "canonical_event_id(10) must sort before canonical_event_id(100): {id_10} < {id_100}"
        );
        assert_eq!(id_9, "canonical-00000000000000000009");
        assert_eq!(id_10, "canonical-00000000000000000010");
        assert_eq!(id_100, "canonical-00000000000000000100");
    }

    #[test]
    fn test_canonical_event_id_roundtrip() {
        for seq in [0, 1, 42, 999_999_999, i64::MAX] {
            let id = canonical_event_id(seq);
            assert_eq!(
                parse_canonical_event_id(&id),
                Some(seq),
                "roundtrip failed for seq={seq}"
            );
        }
        assert_eq!(parse_canonical_event_id("not-canonical"), None);
        assert_eq!(parse_canonical_event_id("canonical-abc"), None);
    }

    #[test]
    fn test_normalize_canonical_cursor_event_id() {
        // Unpadded legacy cursor should be normalized to fixed-width.
        assert_eq!(
            normalize_canonical_cursor_event_id("canonical-9"),
            "canonical-00000000000000000009"
        );
        // Already padded should be unchanged.
        assert_eq!(
            normalize_canonical_cursor_event_id("canonical-00000000000000000042"),
            "canonical-00000000000000000042"
        );
        // Non-canonical IDs passed through unchanged.
        assert_eq!(
            normalize_canonical_cursor_event_id("legacy-event-abc"),
            "legacy-event-abc"
        );
    }

    #[test]
    fn test_poll_events_cursor_advancement() {
        let conn = setup_test_db();

        // Insert legacy events with identical timestamps (collision scenario).
        for i in 1..=5 {
            conn.execute(
                "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
                 VALUES (?1, 'test_event', 'w1', 'a1', X'7B7D', X'', 1000)",
                params![format!("evt-{i:03}")],
            )
            .expect("insert legacy event");
        }

        // Insert canonical events at the same timestamp.
        for _i in 0..3 {
            conn.execute(
                "INSERT INTO events (event_type, session_id, actor_id, payload, timestamp_ns)
                 VALUES ('test_event', 'w1', 'a1', X'7B7D', 1000)",
                [],
            )
            .expect("insert canonical event");
        }

        // Poll from start -- should get all 8 events merged and sorted.
        let events = poll_events_blocking(&conn, &["test_event"], 0, "", 100).expect("poll all");
        assert_eq!(
            events.len(),
            8,
            "expected 8 total events (5 legacy + 3 canonical)"
        );

        // Verify stable ordering: 'c' < 'e' so canonical IDs sort first.
        let mut prev_cursor = (0u64, String::new());
        for event in &events {
            let cursor = (event.timestamp_ns, event.event_id.clone());
            assert!(
                cursor >= prev_cursor,
                "events must be sorted by (timestamp_ns, event_id): {cursor:?} >= {prev_cursor:?}",
            );
            prev_cursor = cursor;
        }

        // Poll with mid-point cursor: after the 4th event.
        let mid_event = &events[3];
        #[allow(clippy::cast_possible_wrap)]
        let mid_ts = mid_event.timestamp_ns as i64;
        let mid_id = &mid_event.event_id;
        let remaining = poll_events_blocking(&conn, &["test_event"], mid_ts, mid_id, 100)
            .expect("poll from mid-point");
        assert_eq!(
            remaining.len(),
            4,
            "expected 4 events after mid-point cursor (8 - 4 = 4)"
        );

        // Verify no skips: the first remaining event must be right after mid-point.
        assert!(
            remaining[0].event_id > *mid_id || remaining[0].timestamp_ns > mid_event.timestamp_ns,
            "first remaining event must be strictly after cursor"
        );
    }

    #[test]
    fn test_poll_events_empty_types() {
        let conn = setup_test_db();
        let events = poll_events_blocking(&conn, &[], 0, "", 100).expect("empty types");
        assert!(events.is_empty());
    }

    #[test]
    fn test_poll_events_zero_limit() {
        let conn = setup_test_db();
        let events = poll_events_blocking(&conn, &["test_event"], 0, "", 0).expect("zero limit");
        assert!(events.is_empty());
    }

    #[test]
    fn test_poll_events_multi_type() {
        let conn = setup_test_db();

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES ('e1', 'type_a', 'w1', 'a1', X'7B7D', X'', 100)",
            [],
        )
        .expect("insert type_a");

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES ('e2', 'type_b', 'w1', 'a1', X'7B7D', X'', 200)",
            [],
        )
        .expect("insert type_b");

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES ('e3', 'type_c', 'w1', 'a1', X'7B7D', X'', 300)",
            [],
        )
        .expect("insert type_c");

        // Poll for type_a and type_b only.
        let events = poll_events_blocking(&conn, &["type_a", "type_b"], 0, "", 100)
            .expect("poll multi-type");
        assert_eq!(events.len(), 2, "expected 2 events for type_a + type_b");
        assert_eq!(events[0].event_type, "type_a");
        assert_eq!(events[1].event_type, "type_b");
    }

    #[test]
    fn test_poll_events_limit_truncation() {
        let conn = setup_test_db();

        for i in 1..=10 {
            conn.execute(
                "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
                 VALUES (?1, 'test_event', 'w1', 'a1', X'7B7D', X'', ?2)",
                params![format!("evt-{i:03}"), i * 100],
            )
            .expect("insert event");
        }

        let events =
            poll_events_blocking(&conn, &["test_event"], 0, "", 3).expect("poll with limit");
        assert_eq!(events.len(), 3, "limit should truncate to 3");
    }

    #[test]
    fn test_poll_events_legacy_only_when_no_canonical_table() {
        // Create a DB with only the legacy table (no canonical `events` table).
        let conn = Connection::open_in_memory().expect("open in-memory db");
        conn.execute_batch(
            "CREATE TABLE ledger_events (
                 event_id   TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 work_id    TEXT NOT NULL DEFAULT '',
                 actor_id   TEXT NOT NULL DEFAULT '',
                 payload    BLOB NOT NULL DEFAULT X'',
                 signature  BLOB NOT NULL DEFAULT X'',
                 timestamp_ns INTEGER NOT NULL
             );",
        )
        .expect("create legacy table");

        conn.execute(
            "INSERT INTO ledger_events (event_id, event_type, work_id, actor_id, payload, signature, timestamp_ns)
             VALUES ('e1', 'test_event', 'w1', 'a1', X'7B7D', X'', 100)",
            [],
        )
        .expect("insert legacy event");

        let events =
            poll_events_blocking(&conn, &["test_event"], 0, "", 100).expect("poll legacy only");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "e1");
    }

    /// Regression test: resuming from an *unpadded* canonical cursor must NOT
    /// skip padded canonical rows at the same timestamp.
    ///
    /// Without normalization, `"canonical-9"` >
    /// `"canonical-00000000000000000010"` lexicographically, so the SQL
    /// `event_id > ?` predicate would wrongly exclude `seq_id` 10..15.  After
    /// the fix, `poll_events_blocking` normalizes the cursor to
    /// `"canonical-00000000000000000009"` before querying.
    #[test]
    fn test_unpadded_canonical_cursor_does_not_skip_padded_rows() {
        let conn = setup_test_db();

        // Insert 15 canonical events all at the same timestamp (ts = 5000).
        // seq_ids will be 1..=15 via AUTOINCREMENT.
        for _ in 0..15 {
            conn.execute(
                "INSERT INTO events (event_type, session_id, actor_id, payload, timestamp_ns)
                 VALUES ('test_event', 's1', 'a1', X'7B7D', 5000)",
                [],
            )
            .expect("insert canonical event");
        }

        // Resume from an UNPADDED cursor "canonical-9" at the same timestamp.
        // This simulates a legacy or manually-injected cursor that was persisted
        // without zero-padding.
        let events = poll_events_blocking(
            &conn,
            &["test_event"],
            5000,          // same timestamp as all rows
            "canonical-9", // unpadded -- the bug trigger
            100,
        )
        .expect("poll with unpadded cursor");

        // We should get seq_ids 10..=15  (6 events).
        assert_eq!(
            events.len(),
            6,
            "expected 6 canonical events after seq_id 9, got {}: {:?}",
            events.len(),
            events.iter().map(|e| &e.event_id).collect::<Vec<_>>()
        );

        // Verify the first returned event is seq_id 10.
        assert_eq!(
            events[0].event_id,
            canonical_event_id(10),
            "first event after cursor must be seq_id 10"
        );

        // Verify the last returned event is seq_id 15.
        assert_eq!(
            events[5].event_id,
            canonical_event_id(15),
            "last event must be seq_id 15"
        );

        // Verify all returned events are strictly after the normalized cursor.
        let normalized_cursor = normalize_canonical_cursor_event_id("canonical-9");
        for event in &events {
            assert!(
                event.event_id > normalized_cursor,
                "event_id {} must be > normalized cursor {}",
                event.event_id,
                normalized_cursor
            );
        }
    }
}
